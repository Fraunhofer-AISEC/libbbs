#include "bbs.h"
#include "bbs_util.h"
#include <stdbool.h>

/* This function should be availale in <unistd.h> on POSIX systems. We declare
 * it here to allow simple linking when <unistd.h> is not available. */
int getentropy(void *buffer, size_t length);

/* Helper */
static inline void ep_mult_scalar(blst_p1 *out, const blst_p1 *p, const blst_scalar *s, size_t _ignored) {
	(void)_ignored;
	blst_p1_mult(out, p, s->b, 255);
}

// Checks e(A,W) * e(B,-BP2) = identity
// This differs slightly from the spec, which checks the equivalent e(-B,BP2)
static int bbs_check_sig_eqn(
	blst_p1 *A,
	blst_p1 *B,
	const bbs_public_key  pk
	)
{
	blst_fp12 paired;
	blst_p1_affine Aa, Ba;
	blst_p2_affine pka;
	const blst_p1_affine *lhsp[] = { &Aa,  &Ba };
	const blst_p2_affine *rhsp[] = { &pka, &BLS12_381_NEG_G2 };

	if(BLST_SUCCESS != blst_p2_uncompress(&pka, pk)) return BBS_ERROR;
	blst_p1_to_affine(&Aa, A);
	blst_p1_to_affine(&Ba, B);
	blst_miller_loop_n(&paired, rhsp, lhsp, 2);
	blst_final_exp(&paired, &paired);

	return blst_fp12_is_one(&paired) ? BBS_OK : BBS_ERROR;
}

// Accumulates onto B and T2 and keeps track of the challenge
typedef struct {
	bbs_cipher_suite_t   *cipher_suite;
	uint64_t disclosed_ctr;
	uint64_t undisclosed_ctr;
	uint8_t generator_ctx[48 + 8]; // Generators
	blst_p1 Q_1;                   // First generator
	blst_p1 Bv; // Accumulates visible messages
	blst_p1 Bh; // Accumulates hidden messages
	blst_p1 T2; // Accumulates random scalars for hidden messages
	union bbs_hash_context dom_ctx; // Domain calculation
	union bbs_hash_context ch_ctx;  // Running challenge hash
	bbs_bn_prf           *prf;        // Generate random scalars
	void                 *prf_cookie; // Generate random scalars
} bbs_compressed_proof_gen_ctx;
// TODO: provide space to store undisclosed msg_scalars


static void
bbs_compressed_proof_verify_init (
	bbs_proof_gen_ctx *ctx,
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_public_key  pk,
	uint64_t              num_messages,
	uint64_t              num_disclosed
	)
{
	ctx->cipher_suite = s;
	ctx->disclosed_ctr = 0;
	ctx->undisclosed_ctr = 0;

	// Calculate Q_1 and initialize domain calculation
	create_generator_init (s, ctx->generator_ctx);
	create_generator_next (s, ctx->generator_ctx, &ctx->Q_1);
	calculate_domain_init (s, &ctx->dom_ctx, pk, num_messages);
	calculate_domain_update (s, &ctx->dom_ctx, &ctx->Q_1);

	// Initialize Bv to P1
	ep_read_bbs (&ctx->Bv, s->p1);

	// Initialize T2 and Bh to the identity.
	(void)bbs_memset(&ctx->T2.z, 0, sizeof(ctx->T2.z));
	(void)bbs_memset(&ctx->Bh.z, 0, sizeof(ctx->Bh.z));

	// Initialize first challenge Calculation
	hash_to_scalar_init (cipher_suite, &ctx->ch_ctx);
	uint64_t be_buffer = htobe64 (num_disclosed);
	hash_to_scalar_update (cipher_suite, &ctx->ch_ctx, (uint8_t*) &be_buffer, 8);
}

// Not static, to allow Fixture tests
void
bbs_compressed_proof_gen_init (
	bbs_proof_gen_ctx *ctx,
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_public_key  pk,
	uint64_t              num_messages,
	uint64_t              num_disclosed,
	bbs_bn_prf            prf,
	void                 *prf_cookie
	)
{
	ctx->prf = prf;
	ctx->prf_cookie = prf_cookie;
	bbs_proof_verify_init(ctx, cipher_suite, pk, num_messages, num_disclosed);
}

// Not static, to allow Fixture tests
void
bbs_compressed_proof_gen_update (
	bbs_proof_gen_ctx *ctx,
	uint8_t *proof,
	uint8_t *msg,
	uint64_t msg_len,
	bool disclosed
	)
{
	bbs_cipher_suite_t *s = ctx->cipher_suite;
	blst_p1 H_i, tmp_p1;
	blst_scalar msg_scalar;
	uint8_t scalar_buffer[BBS_SCALAR_LEN];

	// Calculate H_i
	create_generator_next (ctx->cipher_suite, ctx->generator_ctx, &H_i);
	calculate_domain_update (ctx->cipher_suite, &ctx->dom_ctx, &H_i);

	// Calculate msg_scalar (oneshot)
	hash_to_scalar (s, &msg_scalar, s->map_dst, s->map_dst_len, 1, msg, msg_len);

	if(disclosed) {
		// Update Bv
		ep_mult_scalar (&tmp_p1, &H_i, &msg_scalar, 255);
		blst_p1_add_or_double (&ctx->Bv, &ctx->Bv, &tmp_p1);

		// Update the challenge hash
		bn_write_bbs (scalar_buffer, &msg_scalar);
		uint64_t be_buffer = htobe64 (ctx->disclosed_ctr + ctx->undisclosed_ctr);
		hash_to_scalar_update(s, &ctx->ch_ctx, (uint8_t*) &be_buffer, 8);
		hash_to_scalar_update(s, &ctx->ch_ctx, scalar_buffer, BBS_SCALAR_LEN);
		ctx->disclosed_ctr++;
	}
	else {
		// Update Bh
		ep_mult_scalar (&tmp_p1, &H_i, &msg_scalar, 255);
		blst_p1_add_or_double (&ctx->Bh, &ctx->Bh, &tmp_p1);

		// Derive new random scalar for T2
		ctx->prf (s, &msg_scalar, 0, ctx->undisclosed_ctr + 3, ctx->prf_cookie);
		ep_mult_scalar (&tmp_p1, &H_i, &msg_scalar, 255);
		blst_p1_add_or_double (&ctx->T2, &ctx->T2, &tmp_p1);
		ctx->undisclosed_ctr++;
	}
}

static void
bbs_compressed_proof_verify_update (
	bbs_proof_gen_ctx *ctx,
	const uint8_t *proof,
	uint8_t *msg,
	uint64_t msg_len,
	bool disclosed
	)
{
	bbs_cipher_suite_t *s = ctx->cipher_suite;
	blst_p1 H_i;
	blst_scalar msg_scalar;
	uint8_t scalar_buffer[BBS_SCALAR_LEN];

	// Calculate H_i
	create_generator_next (ctx->cipher_suite, ctx->generator_ctx, &H_i);
	calculate_domain_update (ctx->cipher_suite, &ctx->dom_ctx, &H_i);

	if (disclosed) {
		// Calculate msg_scalar (oneshot)
		hash_to_scalar (s, &msg_scalar, s->map_dst, s->map_dst_len, 1, msg, msg_len);

		// Update Bv
		ep_mult_scalar (&H_i, &H_i, &msg_scalar, 255);
		blst_p1_add_or_double (&Bv, &Bv, &H_i);

		// Hash i and msg_scalar into the challenge
		bn_write_bbs (scalar_buffer, &msg_scalar);
		uint64_t be_buffer = htobe64 (ctx->disclosed_ctr + ctx->undisclosed_ctr);
		hash_to_scalar_update (s, &ctx->ch_ctx, (uint8_t*) &be_buffer, 8);
		hash_to_scalar_update (s, &ctx->ch_ctx, scalar_buffer, BBS_SCALAR_LEN);
		ctx->disclosed_ctr++;
	}
	else {
		ctx->undisclosed_ctr++;
	}
}

// Not static, to allow Fixture tests
int
bbs_compressed_proof_gen_finalize (
	bbs_proof_gen_ctx *ctx,
	const bbs_signature   signature,
	uint8_t              *proof,
	const uint8_t        *header,
	uint64_t              header_len,
	const uint8_t        *presentation_header,
	uint64_t              presentation_header_len,
	uint64_t              num_messages,
	uint64_t              num_disclosed,
	blst_scalar          *witness_buf,
	blst_p1              *comp_gens
	)
{
	bbs_cipher_suite_t *s = ctx->cipher_suite;
	blst_scalar e, r1, r3, e_tilde, r1_tilde, challenge, tmp_scalar
	blst_p1 D, Abar, Bbar, Q, A, B, tmp_p1;
	uint8_t challenge_buf[BBS_SCALAR_LEN], T_buffer[BBS_G1_ELEM_LEN];
	uint8_t *proof_ptr = proof;

	// Sanity check. If any indices for disclosed messages were out of order
	// or invalid, we fail here.
	uint64_t num_undisclosed = num_messages - num_disclosed;
	if (ctx->disclosed_ctr != num_disclosed || ctx->undisclosed_ctr != num_undisclosed)
	{
		return BBS_ERROR;
	}

	if (! header) header_len = 0;

	// Finish domain calculation (stored in challenge) and ctx->Bv
	calculate_domain_finalize (s, &ctx->dom_ctx, &challenge, header, header_len);
	ep_mult_scalar (&ctx->Q_1, &ctx->Q_1, &challenge, 255);
	blst_p1_add_or_double (&ctx->Bv, &ctx->Bv, &ctx->Q_1);

	// Parse the signature
	if(BBS_OK != ep_read_bbs (&A, signature)) return BBS_ERROR;
	if(BBS_OK != bn_read_bbs (&e, signature + BBS_G1_ELEM_LEN)) return BBS_ERROR;

	//
	// PROOF PART 0: Rerandomizing the signature
	//

	// Proof Message: P -> V: ABar, BBar, D
	ctx->prf (s, &r1, 1, 0, ctx->prf_cookie);
	ctx->prf (s, &r3, 2, 0, ctx->prf_cookie); // Temporarily r2=r3^-1
	blst_p1_add_or_double (&B, &ctx->Bv, &ctx->Bh);
	ep_mult_scalar (&D,          &B,    &r3, 255);
	ep_mult_scalar (&Abar,       &A,    &r1, 255);
	ep_mult_scalar (&Abar,       &Abar, &r3, 255);
	ep_mult_scalar (&Bbar,       &D,    &r1, 255);
	ep_mult_scalar (&tmp_p1, &Abar, &e,  255);
	blst_p1_cneg (&tmp_p1, 1);
	blst_p1_add_or_double (&Bbar, &Bbar, &tmp_p1);
	ep_write_bbs (proof_ptr, &Abar);
	proof_ptr += BBS_G1_ELEM_LEN;
	ep_write_bbs (proof_ptr, &Bbar);
	proof_ptr += BBS_G1_ELEM_LEN;
	ep_write_bbs (proof_ptr, &D);
	proof_ptr += BBS_G1_ELEM_LEN;

	// Turn r2 into r3 and copy to witness_buf for compression
	blst_sk_inverse (&r3, &r3);
	witness_buf[0] = r3;

	//
	// PROOF PART 1: ZKPoK for undisclosed messages relating to D
	//

	// Proof Message: P -> V: Commitment T2
	ctx->prf (s, &r3, 0, 2, ctx->prf_cookie);
	ep_mult_scalar (&tmp_p1, &D, &r3, 255);
	blst_p1_add_or_double (&ctx->T2, &ctx->T2, &tmp_p1);
	ep_write_bbs (proof_ptr, &ctx->T2);
	proof_ptr += BBS_G1_ELEM_LEN;

	// Proof Message: V -> P: Challenge (includes statement, T2, domain and presentation_header)
	hash_to_scalar_update (s, &ctx->ch_ctx, proof, 4 * BBS_G1_ELEM_LEN);
	bn_write_bbs (challenge_buf, &challenge); // domain
	hash_to_scalar_update (s, &ctx->ch_ctx, challenge_buf, BBS_SCALAR_LEN);
	uint64_t be_buffer = htobe64 (presentation_header ? presentation_header_len : 0);
	hash_to_scalar_update (s, &ctx->ch_ctx, (uint8_t*) &be_buffer, 8);
        hash_to_scalar_update(s, &ctx->ch_ctx, presentation_header, presentation_header_len);
        hash_to_scalar_finalize(s, &ctx->ch_ctx, &challenge, (uint8_t *)s->challenge_dst, s->challenge_dst_len);

	// Set Q <- T2 + ch * C_J(m), and initialize r3_hat and mj_hat
	ep_mult_scalar (&ctx->Bv, &ctx->Bv, &challenge, 255);
	blst_p1_add_or_double (&Q, &ctx->T2, &ctx->Bv);
	ctx->prf (s, &tmp_scalar, 0, 0, ctx->prf_cookie);
	blst_sk_mul_n_check(&witness_buf[0], &witness_buf[0], &challenge);
	blst_sk_add_n_check (&witness_buf[0], &tmp_scalar, &witness_buf[0]);
	for(size_t i=1; i <= num_undisclosed; i++) {
		ctx->prf (s, &tmp_scalar, 0, i, ctx->prf_cookie);
		blst_sk_mul_n_check(&witness_buf[i], &witness_buf[i], &challenge);
		blst_sk_sub_n_check (&witness_buf[i], &tmp_scalar, &witness_buf[i]);
	}
	
	if(num_undisclosed + 1 > 4) {
		//
		// PROOF PART 2: Proof Compression for PART 1
		//

		// Round (num_undisclosed+1) to the next power of two
		// https://graphics.stanford.edu/%7Eseander/bithacks.html#RoundUpPowerOf2
		uint64_t num_gens = num_undisclosed;
		for(int i = 0; i < 6; i++) num_gens |= num_gens >> (1 << i);
		num_gens++;

		// TODO: Ensure enough generators are present
		while(num_gens > 4) {
			num_gens >>= 1; // Number we are reducing TO

			// Proof Message: P -> V: A, B
			(void)bbs_memset(&A.z, 0, sizeof(A.z)); // A <- identity
			(void)bbs_memset(&B.z, 0, sizeof(B.z)); // B <- identity
			for(uint64_t i=0; i < num_gens; i++) {
				ep_mult_scalar (&tmp_p1, &comp_gens[num_gens+i], &witness_buf[i], 255);
				blst_p1_add_or_double (&A, &A, &tmp_p1);
				if(num_gens+i > num_undisclosed) continue;
				ep_mult_scalar (&tmp_p1, &comp_gens[i], &witness_buf[num_gens+i], 255);
				blst_p1_add_or_double (&B, &B, &tmp_p1);
			}
			ep_write_bbs (proof_ptr, &A);
			proof_ptr += BBS_G1_ELEM_LEN;
			ep_write_bbs (proof_ptr, &B);
			proof_ptr += BBS_G1_ELEM_LEN;

			// Proof Message: V -> P: challenge
			hash_to_scalar_init (s, &ctx->ch_ctx);
			bn_write_bbs (challenge_buf, &challenge); // reuse for previous challenge
			hash_to_scalar_update (s, &ctx->ch_ctx, challenge_buf, BBS_SCALAR_LEN);
			hash_to_scalar_update (s, &ctx->ch_ctx, proof_ptr - 2 * BBS_G1_ELEM_LEN, 2 * BBS_G1_ELEM_LEN);
        		hash_to_scalar_finalize(s, &ctx->ch_ctx, &challenge, (uint8_t *)s->challenge_dst, s->challenge_dst_len);

			// Update generators, witnesses, and Q <- A + ch*Q + ch^2*B
			for(uint64_t i=0; i < num_gens; i++) {
				ep_mult_scalar (&tmp_p1, &comp_gens[i], &challenge, 255);
				blst_p1_add_or_double (&comp_gens[i], &comp_gens[i], &comp_gens[num_gens+i]);
				if(num_gens+i > num_undisclosed) continue;
				blst_sk_mul_n_check(&witness_buf[num_gens+i], &witness_buf[num_gens+i], &challenge);
				blst_sk_add_n_check (&witness_buf[i], &witness_buf[i], &witness_buf[num_gens+i]);
			}
			ep_mult_scalar (&tmp_p1, &B, &challenge, 255);
			blst_p1_add_or_double (&tmp_p1, &tmp_p1, &Q);
			ep_mult_scalar (&tmp_p1, &tmp1, &challenge, 255);
			blst_p1_add_or_double (&Q, &tmp_p1, &A);
		}

		num_undisclosed = 3; // Compression done!
	}

	//
	// PROOF PART 3: ZKPoK for the relation between ABar, BBar and D
	//

	// Proof message: P -> V: Commitment T1 (not written to proof)
	ctx->prf (s, &e_tilde,  0, 0, ctx->prf_cookie);
	ctx->prf (s, &r1_tilde, 0, 1, ctx->prf_cookie);
	ep_mult_scalar (&ctx->T2, &D,    &r1_tilde, 255); // Reuse T2 as T1
	ep_mult_scalar (&tmp_p1,  &Abar, &e_tilde,  255);
	blst_p1_add_or_double (&ctx->T2, &ctx->T2, &tmp_p1);
	ep_write_bbs (T_buffer, &ctx->T2);

	// Proof Message: V -> P: challenge
	hash_to_scalar_init (s, &ctx->ch_ctx);
	bn_write_bbs (challenge_buf, &challenge); // reuse for previous challenge
	hash_to_scalar_update (s, &ctx->ch_ctx, challenge_buf, BBS_SCALAR_LEN);
	hash_to_scalar_update (s, &ctx->ch_ctx, T_buffer, BBS_G1_ELEM_LEN);
	hash_to_scalar_finalize(s, &ctx->ch_ctx, &challenge, (uint8_t *)s->challenge_dst, s->challenge_dst_len);

	// initialize e_hat and r1_hat
	blst_sk_mul_n_check(&e, &e, &challenge);
	blst_sk_add_n_check (&e_tilde, &e_tilde, &e);
	blst_sk_mul_n_check(&r3, &r3, &challenge);
	blst_sk_sub_n_check (&r3_tilde, &r3_tilde, &r3);

	//
	// PROOF PART 4: Final reveal
	//

        // Proof Message: P -> V: witness_buf, e_hat, r1_hat
	// We include the final challenge instead of T1 in the NIZK. Saves 16 bytes.
	for(int i=0; i < num_undisclosed + 1; i++) {
		bn_write_bbs (proof_ptr, &witness_buf[i]);
		proof_ptr += BBS_SCALAR_LEN;
	}
	bn_write_bbs (proof_ptr, &e_tilde);
	proof_ptr += BBS_SCALAR_LEN;
	bn_write_bbs (proof_ptr, &r1_tilde);
	proof_ptr += BBS_SCALAR_LEN;
	bn_write_bbs (proof_ptr, &challenge);
	proof_ptr += BBS_SCALAR_LEN;

	return BBS_OK;
}

static int
bbs_compressed_proof_verify_finalize (
	bbs_proof_gen_ctx *ctx,
	const bbs_public_key  pk,
	const uint8_t        *proof,
	const uint8_t        *header,
	uint64_t              header_len,
	const uint8_t        *presentation_header,
	uint64_t              presentation_header_len,
	uint64_t              num_messages,
	uint64_t              num_disclosed
	)
{
	bbs_cipher_suite_t *s = ctx->acc.cipher_suite;
	blst_scalar e, r1, r3, challenge, challenge_prime;
	blst_p1 D, Abar, Bbar;
	uint8_t domain_buffer[BBS_SCALAR_LEN], T_buffer[2*BBS_G1_ELEM_LEN];
	const uint8_t *proof_ptr  = proof;

	// Sanity check. If any indices for disclosed messages were out of order
	// or invalid, we fail here.
	uint64_t num_undisclosed = num_messages - num_disclosed;
	if (ctx->disclosed_ctr != num_disclosed || ctx->undisclosed_ctr != num_undisclosed)
	{
		return BBS_ERROR;
	}

	if (! header) header_len = 0;

	// Finish domain calculation (uses ctx->msg_scalar) and ctx->B
	calculate_domain_finalize (s, &ctx->dom_ctx, &ctx->msg_scalar, header, header_len);
	ep_mult_scalar (&ctx->Q_1, &ctx->Q_1, &ctx->msg_scalar, 255);
	blst_p1_add_or_double (&ctx->B, &ctx->B, &ctx->Q_1);

	// Write out the domain. We reuse scalar_buffer
	bn_write_bbs (domain_buffer, &ctx->acc.msg_scalar);

	// Parse the remainder of the statement and response
	// The parsing here is injective.
	if(BBS_OK != ep_read_bbs (&Abar,  proof_ptr)) return BBS_ERROR;
	proof_ptr += BBS_G1_ELEM_LEN;
	if(BBS_OK != ep_read_bbs (&Bbar, proof_ptr)) return BBS_ERROR;
	proof_ptr += BBS_G1_ELEM_LEN;
	if(BBS_OK != ep_read_bbs (&D,    proof_ptr)) return BBS_ERROR;
	proof_ptr += BBS_G1_ELEM_LEN;
	if(BBS_OK != bn_read_bbs (&e,    proof_ptr)) return BBS_ERROR;
	proof_ptr += BBS_SCALAR_LEN;
	if(BBS_OK != bn_read_bbs (&r1,   proof_ptr)) return BBS_ERROR;
	proof_ptr += BBS_SCALAR_LEN;
	if(BBS_OK != bn_read_bbs (&r3,   proof_ptr)) return BBS_ERROR;
	proof_ptr += BBS_SCALAR_LEN;
	if(BBS_OK != bn_read_bbs (&challenge, proof + BBS_PROOF_LEN (num_undisclosed) - BBS_SCALAR_LEN)) return BBS_ERROR;

	// Proof Message 1: Commitment (recovered from Message 3)
	ep_mult_scalar (&ctx->acc.B, &ctx->acc.B, &challenge, 255);
	blst_p1_add_or_double (&ctx->T2, &ctx->T2, &ctx->acc.B);
	ep_mult_scalar (&ctx->acc.B, &D, &r3, 255);
	blst_p1_add_or_double (&ctx->T2, &ctx->T2, &ctx->acc.B);
	ep_write_bbs (T_buffer + BBS_G1_ELEM_LEN, &ctx->T2);
	ep_mult_scalar (&ctx->acc.B, &Bbar, &challenge, 255);
	ep_mult_scalar (&ctx->T2, &Abar, &e, 255);
	blst_p1_add_or_double (&ctx->acc.B, &ctx->acc.B, &ctx->T2);
	ep_mult_scalar (&ctx->T2, &D, &r1, 255);
	blst_p1_add_or_double (&ctx->acc.B, &ctx->acc.B, &ctx->T2);
	ep_write_bbs (T_buffer, &ctx->acc.B);

	// Proof Message 2: Challenge
	if (! presentation_header) presentation_header_len = 0;
	hash_to_scalar_update (s, &ctx->ch_ctx, proof, 3 * BBS_G1_ELEM_LEN);
	hash_to_scalar_update (s, &ctx->ch_ctx, T_buffer, 2 * BBS_G1_ELEM_LEN);
	hash_to_scalar_update (s, &ctx->ch_ctx, domain_buffer, BBS_SCALAR_LEN);
	uint64_t be_buffer = htobe64 (presentation_header_len);
	hash_to_scalar_update (s, &ctx->ch_ctx, (uint8_t*) &be_buffer, 8);
        hash_to_scalar_update(s, &ctx->ch_ctx, presentation_header,
                              presentation_header_len);
        hash_to_scalar_finalize(s, &ctx->ch_ctx, &challenge_prime,
                                (uint8_t *)s->challenge_dst,
                                s->challenge_dst_len);

        // Verification Step 1: The PoK was valid. TODO: This should be simpler
	if (blst_sk_sub_n_check (&challenge, &challenge, &challenge_prime))
	{
		return BBS_ERROR;
	}

	// Verification Step 2: The original signature was valid
	return bbs_check_sig_eqn(&Abar, &Bbar, pk);
}

static void
bbs_proof_prf (
	bbs_cipher_suite_t *cipher_suite,
	blst_scalar        *out,
	uint8_t             input_type,
	uint64_t            input,
	void               *seed
	)
{
	// All these have length 17
	static uint8_t *prf_dsts[] = {
		(uint8_t*) "random proof sclr",
		(uint8_t*) "random r_1 scalar",
		(uint8_t*) "random r_3 scalar",
	};

        hash_to_scalar(cipher_suite, out, prf_dsts[input_type], 17, 2, seed, 32, &input, 8);
}

int
bbs_compressed_proof_gen_nva (
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_public_key  pk,
	const bbs_signature   signature,
	uint8_t              *proof,
	const uint8_t        *header,
	uint64_t              header_len,
	const uint8_t        *presentation_header,
	uint64_t              presentation_header_len,
	const uint64_t       *disclosed_indexes,
	uint64_t              disclosed_indexes_len,
	uint64_t              num_messages,
	uint8_t**             messages,
  uint32_t*             messages_lens
	)
{
	uint8_t seed[32];
	bbs_proof_gen_ctx ctx;
	uint64_t di_idx = 0;
	bool disclosed;

	// Gather randomness. The seed is used for any randomness within this
	// function. In particular, this implies that we do not need to store
	// intermediate derivations. Currently, we derive new values via
	// hash_to_scalar, but we might want to exchange that for
	// something faster later on.
	getentropy(seed, 32);

	bbs_proof_gen_init(&ctx, cipher_suite, pk, num_messages, disclosed_indexes_len, bbs_proof_prf, seed);
	for(uint64_t i=0; i< num_messages; i++) {
		disclosed = di_idx < disclosed_indexes_len && disclosed_indexes[di_idx] == i;
		bbs_proof_gen_update(&ctx, proof, messages[i], messages_lens[i], disclosed);
		if(disclosed) di_idx++;
	}

	return bbs_proof_gen_finalize(&ctx, signature, proof, header, header_len, presentation_header, presentation_header_len, num_messages, disclosed_indexes_len);
}

int
bbs_proof_verify_nva (
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_public_key  pk,
	const uint8_t        *proof,
	uint64_t              proof_len,
	const uint8_t        *header,
	uint64_t              header_len,
	const uint8_t        *presentation_header,
	uint64_t              presentation_header_len,
	const uint64_t       *disclosed_indexes,
	uint64_t              disclosed_indexes_len,
	uint64_t              num_messages,
	uint8_t**             messages,
  uint32_t*             messages_lens
	)
{
	bbs_proof_gen_ctx ctx;
	uint64_t di_idx = 0;
	bool disclosed;

	// Sanity check
	if(proof_len != BBS_PROOF_LEN(num_messages - disclosed_indexes_len)) return BBS_ERROR;

	bbs_proof_verify_init(&ctx, cipher_suite, pk, num_messages, disclosed_indexes_len);
	for(uint64_t i=0; i< num_messages; i++) {
		disclosed = di_idx < disclosed_indexes_len && disclosed_indexes[di_idx] == i;
		if(disclosed) {
			di_idx++;
		}
		bbs_proof_verify_update(&ctx, proof, messages[i], messages_lens[i], disclosed);
	}

	return bbs_proof_verify_finalize(&ctx, pk, proof, header, header_len, presentation_header, presentation_header_len, num_messages, disclosed_indexes_len);
}

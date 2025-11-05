#include "bbs.h"
#include "bbs_util.h"
#include <stdbool.h>
#include <stdio.h>

/* This function should be availale in <unistd.h> on newer POSIX systems. We declare
 * it here to allow simple linking when <unistd.h> is not available. */
int getentropy(void *buffer, size_t length);

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
	blst_scalar          *witness_buf; // Space to store witnesses
	blst_p1              *comp_gens;   // Space to store generators
} bbs_compressed_proof_gen_ctx;

// A helper to calculate 2^ceil(log2(x)). Works for 1 <= x <= 2^63.
// Credit: https://graphics.stanford.edu/%7Eseander/bithacks.html#RoundUpPowerOf2
static inline uint64_t round_up_to_power_of_2(uint64_t x) {
	x--;
	for(int i = 0; i < 6; i++) x |= x >> (1 << i);
	return x + 1;

}

static void
bbs_compressed_proof_verify_init (
	bbs_compressed_proof_gen_ctx *ctx,
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_public_key  pk,
	uint64_t              num_messages,
	uint64_t              num_disclosed,
	blst_p1              *comp_gens
	)
{
	ctx->cipher_suite = cipher_suite;
	ctx->disclosed_ctr = 0;
	ctx->undisclosed_ctr = 0;
	ctx->comp_gens = comp_gens;

	// Calculate Q_1 and initialize domain calculation
	create_generator_init (cipher_suite, ctx->generator_ctx);
	create_generator_next (cipher_suite, ctx->generator_ctx, &ctx->Q_1);
	calculate_domain_init (cipher_suite, &ctx->dom_ctx, pk, num_messages);
	calculate_domain_update (cipher_suite, &ctx->dom_ctx, &ctx->Q_1);

	// Initialize Bv to P1
	ep_read_bbs (&ctx->Bv, cipher_suite->p1);

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
	bbs_compressed_proof_gen_ctx *ctx,
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_public_key  pk,
	uint64_t              num_messages,
	uint64_t              num_disclosed,
	blst_p1              *comp_gens,
	blst_scalar          *witness_buf,
	bbs_bn_prf            prf,
	void                 *prf_cookie
	)
{
	ctx->witness_buf = witness_buf;
	ctx->prf = prf;
	ctx->prf_cookie = prf_cookie;
	bbs_compressed_proof_verify_init(ctx, cipher_suite, pk, num_messages, num_disclosed, comp_gens);
}

// Not static, to allow Fixture tests
void
bbs_compressed_proof_gen_update (
	bbs_compressed_proof_gen_ctx *ctx,
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
		blst_p1_mult (&tmp_p1, &H_i, msg_scalar.b, 255);
		blst_p1_add_or_double (&ctx->Bv, &ctx->Bv, &tmp_p1);

		// Update the challenge hash
		bn_write_bbs (scalar_buffer, &msg_scalar);
		uint64_t be_buffer = htobe64 (ctx->disclosed_ctr + ctx->undisclosed_ctr);
		hash_to_scalar_update(s, &ctx->ch_ctx, (uint8_t*) &be_buffer, 8);
		hash_to_scalar_update(s, &ctx->ch_ctx, scalar_buffer, BBS_SCALAR_LEN);
		ctx->disclosed_ctr++;
	}
	else {
		// Save H_i and msg_scalar for compression during the proof
		ctx->comp_gens[ctx->undisclosed_ctr + 1] = H_i;
		ctx->witness_buf[ctx->undisclosed_ctr + 1] = msg_scalar;

		// Update Bh
		blst_p1_mult (&tmp_p1, &H_i, msg_scalar.b, 255);
		blst_p1_add_or_double (&ctx->Bh, &ctx->Bh, &tmp_p1);

		// Derive new random scalar for T2
		ctx->prf (s, &msg_scalar, 0, ctx->undisclosed_ctr + 3, ctx->prf_cookie);
		blst_p1_mult (&tmp_p1, &H_i, msg_scalar.b, 255);
		blst_p1_add_or_double (&ctx->T2, &ctx->T2, &tmp_p1);
		ctx->undisclosed_ctr++;
	}
}

static void
bbs_compressed_proof_verify_update (
	bbs_compressed_proof_gen_ctx *ctx,
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
		blst_p1_mult (&H_i, &H_i, msg_scalar.b, 255);
		blst_p1_add_or_double (&ctx->Bv, &ctx->Bv, &H_i);

		// Hash i and msg_scalar into the challenge
		bn_write_bbs (scalar_buffer, &msg_scalar);
		uint64_t be_buffer = htobe64 (ctx->disclosed_ctr + ctx->undisclosed_ctr);
		hash_to_scalar_update (s, &ctx->ch_ctx, (uint8_t*) &be_buffer, 8);
		hash_to_scalar_update (s, &ctx->ch_ctx, scalar_buffer, BBS_SCALAR_LEN);
		ctx->disclosed_ctr++;
	}
	else {
		// Save H_i for compression during the proof
		ctx->comp_gens[ctx->undisclosed_ctr + 1] = H_i;
		ctx->undisclosed_ctr++;
	}
}

void debug_check_Q(const blst_p1 *Q, blst_p1 *gens, blst_scalar *wits, uint64_t num) {
	uint8_t buf[BBS_G1_ELEM_LEN];
	blst_p1 acc, tmp;

	ep_write_bbs(buf, Q);
	DEBUG("CHECK A", buf, BBS_G1_ELEM_LEN);
	(void)bbs_memset(&acc.z, 0, sizeof(acc.z)); // acc <- identity
	for(uint64_t i=0; i < num; i++) {
		blst_p1_mult(&tmp, &gens[i], wits[i].b, 255);
		blst_p1_add_or_double(&acc, &acc, &tmp);
	}
	ep_write_bbs(buf, &acc);
	DEBUG("CHECK B", buf, BBS_G1_ELEM_LEN);
}

// Not static, to allow Fixture tests
int
bbs_compressed_proof_gen_finalize (
	bbs_compressed_proof_gen_ctx *ctx,
	const bbs_signature   signature,
	uint8_t              *proof,
	const uint8_t        *header,
	uint64_t              header_len,
	const uint8_t        *presentation_header,
	uint64_t              presentation_header_len,
	uint64_t              num_messages,
	uint64_t              num_disclosed
	)
{
	bbs_cipher_suite_t *s = ctx->cipher_suite;
	blst_scalar e, r1, r3, e_tilde, r1_tilde, challenge, tmp_scalar;
	blst_p1 D, Abar, Bbar, Q, A, B, tmp_p1;
	uint8_t challenge_buf[BBS_SCALAR_LEN], T_buffer[BBS_G1_ELEM_LEN];
	uint8_t *proof_ptr = proof;
	uint8_t debug_buf[BBS_G1_ELEM_LEN];

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
	blst_p1_mult (&ctx->Q_1, &ctx->Q_1, challenge.b, 255);
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
	blst_p1_mult (&D,          &B,    r3.b, 255);
	blst_p1_mult (&Abar,       &A,    r1.b, 255);
	blst_p1_mult (&Abar,       &Abar, r3.b, 255);
	blst_p1_mult (&Bbar,       &D,    r1.b, 255);
	blst_p1_mult (&tmp_p1,     &Abar, e.b,  255);
	blst_p1_cneg (&tmp_p1, 1);
	blst_p1_add_or_double (&Bbar, &Bbar, &tmp_p1);
	ep_write_bbs (proof_ptr, &Abar);
	proof_ptr += BBS_G1_ELEM_LEN;
	ep_write_bbs (proof_ptr, &Bbar);
	proof_ptr += BBS_G1_ELEM_LEN;
	ep_write_bbs (proof_ptr, &D);
	proof_ptr += BBS_G1_ELEM_LEN;

	// Turn r2 into r3 and copy to ctx->witness_buf for compression
	blst_sk_inverse (&r3, &r3);
	ctx->witness_buf[0] = r3;
	ctx->comp_gens[0] = D;

	// DEBUG TODO: Remove
	// Negate all message scalars
	blst_scalar zero; blst_sk_sub_n_check(&zero, &r3, &r3);
	for(uint64_t i=1; i <= num_undisclosed; i++) {
		blst_sk_sub_n_check(&ctx->witness_buf[i], &zero, &ctx->witness_buf[i]);
	}
	debug_check_Q(&ctx->Bv, ctx->comp_gens, ctx->witness_buf, num_undisclosed+1);
	for(uint64_t i=1; i <= num_undisclosed; i++) {
		blst_sk_sub_n_check(&ctx->witness_buf[i], &zero, &ctx->witness_buf[i]);
	}

	//
	// PROOF PART 1: ZKPoK for undisclosed messages relating to D
	//

	// Proof Message: P -> V: Commitment T2
	ctx->prf (s, &r3, 0, 2, ctx->prf_cookie);
	blst_p1_mult (&tmp_p1, &D, r3.b, 255);
	blst_p1_add_or_double (&ctx->T2, &ctx->T2, &tmp_p1);
	ep_write_bbs (proof_ptr, &ctx->T2);
	proof_ptr += BBS_G1_ELEM_LEN;

	// Proof Message: V -> P: Challenge (includes statement, T2, domain and presentation_header)
	hash_to_scalar_update (s, &ctx->ch_ctx, proof, 4 * BBS_G1_ELEM_LEN);
	bn_write_bbs (challenge_buf, &challenge); // domain
	DEBUG("Domain", challenge_buf, sizeof(challenge_buf));
	hash_to_scalar_update (s, &ctx->ch_ctx, challenge_buf, BBS_SCALAR_LEN);
	uint64_t be_buffer = htobe64 (presentation_header ? presentation_header_len : 0);
	hash_to_scalar_update (s, &ctx->ch_ctx, (uint8_t*) &be_buffer, 8);
        hash_to_scalar_update(s, &ctx->ch_ctx, presentation_header, presentation_header_len);
        hash_to_scalar_finalize(s, &ctx->ch_ctx, &challenge, (uint8_t *)s->challenge_dst, s->challenge_dst_len);

	// Set Q <- T2 + ch * C_J(m), and initialize r3_hat and mj_hat
	blst_p1_mult (&ctx->Bv, &ctx->Bv, challenge.b, 255);
	blst_p1_add_or_double (&Q, &ctx->T2, &ctx->Bv);
	//ctx->prf (s, &tmp_scalar, 0, 2, ctx->prf_cookie);
	blst_sk_mul_n_check(&ctx->witness_buf[0], &ctx->witness_buf[0], &challenge);
	blst_sk_add_n_check (&ctx->witness_buf[0], &r3, &ctx->witness_buf[0]);
	for(size_t i=1; i <= num_undisclosed; i++) {
		ctx->prf (s, &tmp_scalar, 0, i+2, ctx->prf_cookie);
		blst_sk_mul_n_check(&ctx->witness_buf[i], &ctx->witness_buf[i], &challenge);
		blst_sk_sub_n_check (&ctx->witness_buf[i], &tmp_scalar, &ctx->witness_buf[i]);
	}

	debug_check_Q(&Q, ctx->comp_gens, ctx->witness_buf, num_undisclosed+1);
	
	if(num_undisclosed + 1 > 4) {
		//
		// PROOF PART 2: Proof Compression for PART 1
		//

		// Round (num_undisclosed+1) to the next power of two
		// https://graphics.stanford.edu/%7Eseander/bithacks.html#RoundUpPowerOf2
		uint64_t num_gens = round_up_to_power_of_2(num_undisclosed+1);

		// Fill up ctx->comp_gens
		for(uint64_t i = num_undisclosed+1; i < num_gens; i++) {
			create_generator_next (ctx->cipher_suite, ctx->generator_ctx, &ctx->comp_gens[i]);
			ctx->witness_buf[i] = zero; // DEBUG TODO: Remove
		}

		debug_check_Q(&Q, ctx->comp_gens, ctx->witness_buf, num_gens);
		while(num_gens > 4) {
			num_gens >>= 1; // Number we are reducing TO

			// Proof Message: P -> V: A, B
			(void)bbs_memset(&A.z, 0, sizeof(A.z)); // A <- identity
			(void)bbs_memset(&B.z, 0, sizeof(B.z)); // B <- identity
			for(uint64_t i=0; i < num_gens; i++) {
				blst_p1_mult (&tmp_p1, &ctx->comp_gens[num_gens+i], ctx->witness_buf[i].b, 255);
				blst_p1_add_or_double (&A, &A, &tmp_p1);
				//if(num_gens+i > num_undisclosed) continue;
				blst_p1_mult (&tmp_p1, &ctx->comp_gens[i], ctx->witness_buf[num_gens+i].b, 255);
				blst_p1_add_or_double (&B, &B, &tmp_p1);
			}
			ep_write_bbs (proof_ptr, &A);
			proof_ptr += BBS_G1_ELEM_LEN;
			ep_write_bbs (proof_ptr, &B);
			proof_ptr += BBS_G1_ELEM_LEN;

			// Proof Message: V -> P: challenge
			hash_to_scalar_init (s, &ctx->ch_ctx);
			bn_write_bbs (challenge_buf, &challenge); // reuse for previous challenge
			DEBUG("Challenge", challenge_buf, sizeof(challenge_buf));
			hash_to_scalar_update (s, &ctx->ch_ctx, challenge_buf, BBS_SCALAR_LEN);
			hash_to_scalar_update (s, &ctx->ch_ctx, proof_ptr - 2 * BBS_G1_ELEM_LEN, 2 * BBS_G1_ELEM_LEN);
        		hash_to_scalar_finalize(s, &ctx->ch_ctx, &challenge, (uint8_t *)s->challenge_dst, s->challenge_dst_len);

			// Update generators, witnesses, and Q <- A + ch*Q + ch^2*B
			for(uint64_t i=0; i < num_gens; i++) {
				blst_p1_mult (&ctx->comp_gens[i], &ctx->comp_gens[i], challenge.b, 255);
				blst_p1_add_or_double (&ctx->comp_gens[i], &ctx->comp_gens[i], &ctx->comp_gens[num_gens+i]);
				//if(num_gens+i > num_undisclosed) continue;
				blst_sk_mul_n_check(&ctx->witness_buf[num_gens+i], &ctx->witness_buf[num_gens+i], &challenge);
				blst_sk_add_n_check (&ctx->witness_buf[i], &ctx->witness_buf[i], &ctx->witness_buf[num_gens+i]);
			}
			blst_p1_mult (&tmp_p1, &B, challenge.b, 255);
			blst_p1_add_or_double (&tmp_p1, &tmp_p1, &Q);
			blst_p1_mult (&tmp_p1, &tmp_p1, challenge.b, 255);
			blst_p1_add_or_double (&Q, &tmp_p1, &A);

			debug_check_Q(&Q, ctx->comp_gens, ctx->witness_buf, num_gens);
		}

		num_undisclosed = 3; // Compression done!
	}
	ep_write_bbs(debug_buf, &Q);
	DEBUG("Final Q", debug_buf, BBS_G1_ELEM_LEN);
	debug_check_Q(&Q, ctx->comp_gens, ctx->witness_buf, num_undisclosed+1);

	//
	// PROOF PART 3: ZKPoK for the relation between ABar, BBar and D
	//

	// Proof message: P -> V: Commitment T1 (not written to proof)
	ctx->prf (s, &e_tilde,  0, 0, ctx->prf_cookie);
	ctx->prf (s, &r1_tilde, 0, 1, ctx->prf_cookie);
	blst_p1_mult (&ctx->T2, &D,    r1_tilde.b, 255); // Reuse T2 as T1
	blst_p1_mult (&tmp_p1,  &Abar, e_tilde.b,  255);
	blst_p1_add_or_double (&ctx->T2, &ctx->T2, &tmp_p1);
	ep_write_bbs (T_buffer, &ctx->T2);

	// Proof Message: V -> P: challenge
	hash_to_scalar_init (s, &ctx->ch_ctx);
	bn_write_bbs (challenge_buf, &challenge); // reuse for previous challenge
	DEBUG("Final comp challenge", challenge_buf, sizeof(challenge_buf));
	hash_to_scalar_update (s, &ctx->ch_ctx, challenge_buf, BBS_SCALAR_LEN);
	hash_to_scalar_update (s, &ctx->ch_ctx, T_buffer, BBS_G1_ELEM_LEN);
	hash_to_scalar_finalize(s, &ctx->ch_ctx, &challenge, (uint8_t *)s->challenge_dst, s->challenge_dst_len);

	// initialize e_hat and r1_hat
	blst_sk_mul_n_check(&e, &e, &challenge);
	blst_sk_add_n_check (&e_tilde, &e_tilde, &e);
	blst_sk_mul_n_check(&r1, &r1, &challenge);
	blst_sk_sub_n_check (&r1_tilde, &r1_tilde, &r1);

	//
	// PROOF PART 4: Final reveal
	//

        // Proof Message: P -> V: e_hat, r1_hat, compressed witnesses
	// We include the final challenge instead of T1 in the NIZK. Saves 16 bytes.
	bn_write_bbs (proof_ptr, &challenge);
	DEBUG("Final challenge", proof_ptr, sizeof(challenge_buf));
	proof_ptr += BBS_SCALAR_LEN;
	bn_write_bbs (proof_ptr, &e_tilde);
	proof_ptr += BBS_SCALAR_LEN;
	bn_write_bbs (proof_ptr, &r1_tilde);
	proof_ptr += BBS_SCALAR_LEN;
	for(uint64_t i=0; i < num_undisclosed + 1; i++) {
		ep_write_bbs(debug_buf, &ctx->comp_gens[i]);
		DEBUG("Generator", debug_buf, BBS_G1_ELEM_LEN);

		bn_write_bbs (proof_ptr, &ctx->witness_buf[i]);
		proof_ptr += BBS_SCALAR_LEN;
	}

	return BBS_OK;
}

static int
bbs_compressed_proof_verify_finalize (
	bbs_compressed_proof_gen_ctx *ctx,
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
	bbs_cipher_suite_t *s = ctx->cipher_suite;
	blst_scalar e, r1, challenge, challenge_prime, comp_exp;
	blst_p1 D, Abar, Bbar, Q, A, B, tmp_p1;
	uint8_t challenge_buf[BBS_SCALAR_LEN], T_buffer[2*BBS_G1_ELEM_LEN];
	const uint8_t *proof_ptr  = proof;
	uint8_t debug_buf[BBS_G1_ELEM_LEN];

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
	blst_p1_mult (&ctx->Q_1, &ctx->Q_1, challenge.b, 255);
	blst_p1_add_or_double (&ctx->Bv, &ctx->Bv, &ctx->Q_1);

	//
	// PROOF PART 0: Rerandomizing the signature
	//

	// Proof Message: P -> V: ABar, BBar, D
	if(BBS_OK != ep_read_bbs (&Abar, proof_ptr)) return BBS_ERROR;
	proof_ptr += BBS_G1_ELEM_LEN;
	if(BBS_OK != ep_read_bbs (&Bbar, proof_ptr)) return BBS_ERROR;
	proof_ptr += BBS_G1_ELEM_LEN;
	if(BBS_OK != ep_read_bbs (&D,    proof_ptr)) return BBS_ERROR;
	proof_ptr += BBS_G1_ELEM_LEN;

	// Store D as first generator
	ctx->comp_gens[0] = D;

	//
	// PROOF PART 1: ZKPoK for undisclosed messages relating to D
	//

	// Proof Message: P -> V: Commitment T2
	if(BBS_OK != ep_read_bbs (&ctx->T2, proof_ptr)) return BBS_ERROR;
	proof_ptr += BBS_G1_ELEM_LEN;

	// Proof Message: V -> P: Challenge (includes statement, T2, domain and presentation_header)
	hash_to_scalar_update (s, &ctx->ch_ctx, proof, 4 * BBS_G1_ELEM_LEN);
	bn_write_bbs (challenge_buf, &challenge); // domain
	DEBUG("Domain", challenge_buf, sizeof(challenge_buf));
	hash_to_scalar_update (s, &ctx->ch_ctx, challenge_buf, BBS_SCALAR_LEN);
	uint64_t be_buffer = htobe64 (presentation_header ? presentation_header_len : 0);
	hash_to_scalar_update (s, &ctx->ch_ctx, (uint8_t*) &be_buffer, 8);
        hash_to_scalar_update(s, &ctx->ch_ctx, presentation_header, presentation_header_len);
        hash_to_scalar_finalize(s, &ctx->ch_ctx, &challenge, (uint8_t *)s->challenge_dst, s->challenge_dst_len);

	// Set Q <- T2 + ch * C_J(m)
	blst_p1_mult (&ctx->Bv, &ctx->Bv, challenge.b, 255);
	blst_p1_add_or_double (&Q, &ctx->T2, &ctx->Bv);
	
	if(num_undisclosed + 1 > 4) {
		//
		// PROOF PART 2: Proof Compression for PART 1
		//

		// Round (num_undisclosed+1) to the next power of two
		// https://graphics.stanford.edu/%7Eseander/bithacks.html#RoundUpPowerOf2
		uint64_t num_gens = round_up_to_power_of_2(num_undisclosed+1);

		// Fill up ctx->comp_gens
		for(uint64_t i = num_undisclosed+1; i < num_gens; i++) {
			create_generator_next (ctx->cipher_suite, ctx->generator_ctx, &ctx->comp_gens[i]);
		}

		while(num_gens > 4) {
			num_gens >>= 1; // Number we are reducing TO

			// Proof Message: P -> V: A, B
			if(BBS_OK != ep_read_bbs (&A, proof_ptr)) return BBS_ERROR;
			proof_ptr += BBS_G1_ELEM_LEN;
			if(BBS_OK != ep_read_bbs (&B, proof_ptr)) return BBS_ERROR;
			proof_ptr += BBS_G1_ELEM_LEN;

			// Proof Message: V -> P: challenge
			hash_to_scalar_init (s, &ctx->ch_ctx);
			bn_write_bbs (challenge_buf, &challenge); // reuse for previous challenge
			DEBUG("Challenge", challenge_buf, sizeof(challenge_buf));
			hash_to_scalar_update (s, &ctx->ch_ctx, challenge_buf, BBS_SCALAR_LEN);
			hash_to_scalar_update (s, &ctx->ch_ctx, proof_ptr - 2 * BBS_G1_ELEM_LEN, 2 * BBS_G1_ELEM_LEN);
        		hash_to_scalar_finalize(s, &ctx->ch_ctx, &challenge, (uint8_t *)s->challenge_dst, s->challenge_dst_len);

			// Update generators, and Q <- A + ch*Q + ch^2*B
			for(uint64_t i=0; i < num_gens; i++) {
				blst_p1_mult (&ctx->comp_gens[i], &ctx->comp_gens[i], challenge.b, 255);
				blst_p1_add_or_double (&ctx->comp_gens[i], &ctx->comp_gens[i], &ctx->comp_gens[num_gens+i]);
			}
			blst_p1_mult (&tmp_p1, &B, challenge.b, 255);
			blst_p1_add_or_double (&tmp_p1, &tmp_p1, &Q);
			blst_p1_mult (&tmp_p1, &tmp_p1, challenge.b, 255);
			blst_p1_add_or_double (&Q, &tmp_p1, &A);
		}

		num_undisclosed = 3; // Compression done!
	}

	//
	// PROOF PART 3: ZKPoK for the relation between ABar, BBar and D
	//

	// Proof message: P -> V: Commitment T1 (recovered from challenge and PART 4)
	if(BBS_OK != bn_read_bbs (&challenge_prime, proof_ptr)) return BBS_ERROR;
	DEBUG("Final challenge", proof_ptr, sizeof(challenge_buf));
	proof_ptr += BBS_SCALAR_LEN;
	if(BBS_OK != bn_read_bbs (&e,         proof_ptr)) return BBS_ERROR;
	proof_ptr += BBS_SCALAR_LEN;
	if(BBS_OK != bn_read_bbs (&r1,        proof_ptr)) return BBS_ERROR;
	proof_ptr += BBS_SCALAR_LEN;
	blst_p1_mult (&ctx->T2, &Bbar, challenge_prime.b, 255); // Reuse T2 as T1
	blst_p1_mult (&tmp_p1, &Abar, e.b, 255);
	blst_p1_add_or_double (&ctx->T2, &ctx->T2, &tmp_p1);
	blst_p1_mult (&tmp_p1, &D, r1.b, 255);
	blst_p1_add_or_double (&ctx->T2, &ctx->T2, &tmp_p1);

	// Proof Message: V -> P: challenge
	hash_to_scalar_init (s, &ctx->ch_ctx);
	bn_write_bbs (challenge_buf, &challenge); // reuse for previous challenge
	DEBUG("Final comp challenge", challenge_buf, sizeof(challenge_buf));
	hash_to_scalar_update (s, &ctx->ch_ctx, challenge_buf, BBS_SCALAR_LEN);
	ep_write_bbs (T_buffer, &ctx->T2);
	hash_to_scalar_update (s, &ctx->ch_ctx, T_buffer, BBS_G1_ELEM_LEN);
	hash_to_scalar_finalize(s, &ctx->ch_ctx, &challenge, (uint8_t *)s->challenge_dst, s->challenge_dst_len);

	//
	// PROOF PART 4: Final reveal
	//
	// Note: Some of these checks can be moved further up. They are here for clarity.

	puts("DEBUG1");
	ep_write_bbs(debug_buf, &Q);
	DEBUG("Final Q", debug_buf, BBS_G1_ELEM_LEN);
        // Proof Message: P -> V: e_hat, r1_hat, compressed witnesses
	blst_p1_cneg(&Q, 1);
	for(size_t i=0; i < num_undisclosed + 1; i++) {
		puts("DEBUG1.5");
		ep_write_bbs(debug_buf, &ctx->comp_gens[i]);
		DEBUG("Generator", debug_buf, BBS_G1_ELEM_LEN);
		if(BBS_OK != bn_read_bbs (&comp_exp, proof_ptr)) return BBS_ERROR;
		proof_ptr += BBS_SCALAR_LEN;
		blst_p1_mult (&tmp_p1, &ctx->comp_gens[i], comp_exp.b, 255);
		blst_p1_add_or_double (&Q, &Q, &tmp_p1);
	}
	puts("DEBUG2");

        // Verification Step 1: The PoK was valid.

	puts("DEBUG2.5");
	if(!blst_p1_is_inf(&Q) || blst_sk_sub_n_check (&challenge, &challenge, &challenge_prime))
	{
		return BBS_ERROR;
	}

	puts("DEBUG3");
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
	bbs_compressed_proof_gen_ctx ctx;
	uint64_t di_idx = 0;
	bool disclosed;

	uint64_t num_gens = round_up_to_power_of_2(num_messages - disclosed_indexes_len);
	// FIXME: This requires quite some stack space...
	blst_scalar witness_buf[num_gens];
	blst_p1 comp_gens[num_gens];

	// Gather randomness. The seed is used for any randomness within this
	// function. In particular, this implies that we do not need to store
	// intermediate derivations. Currently, we derive new values via
	// hash_to_scalar, but we might want to exchange that for
	// something faster later on.
	getentropy(seed, 32);

	bbs_compressed_proof_gen_init(&ctx, cipher_suite, pk, num_messages, disclosed_indexes_len, comp_gens, witness_buf, bbs_proof_prf, seed);
	for(uint64_t i=0; i< num_messages; i++) {
		disclosed = di_idx < disclosed_indexes_len && disclosed_indexes[di_idx] == i;
		bbs_compressed_proof_gen_update(&ctx, messages[i], messages_lens[i], disclosed);
		if(disclosed) di_idx++;
	}

	return bbs_compressed_proof_gen_finalize(&ctx, signature, proof, header, header_len, presentation_header, presentation_header_len, num_messages, disclosed_indexes_len);
}

int
bbs_compressed_proof_verify_nva (
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
	bbs_compressed_proof_gen_ctx ctx;
	uint64_t di_idx = 0;
	bool disclosed;
	(void)proof_len; // TODO: Check

	uint64_t num_gens = round_up_to_power_of_2(num_messages - disclosed_indexes_len);
	// FIXME: This requires quite some stack space...
	blst_p1 comp_gens[num_gens];

	bbs_compressed_proof_verify_init(&ctx, cipher_suite, pk, num_messages, disclosed_indexes_len, comp_gens);
	for(uint64_t i=0; i< num_messages; i++) {
		disclosed = di_idx < disclosed_indexes_len && disclosed_indexes[di_idx] == i;
		bbs_compressed_proof_verify_update(&ctx, disclosed ? messages[di_idx] : NULL, disclosed ? messages_lens[di_idx] : 0, disclosed);
		if(disclosed) {
			di_idx++;
		}
	}

	return bbs_compressed_proof_verify_finalize(&ctx, pk, proof, header, header_len, presentation_header, presentation_header_len, num_messages, disclosed_indexes_len);
}

uint64_t bbs_compressed_proof_len(uint64_t num_undisclosed) {
	if(num_undisclosed+1 <= 4) return (num_undisclosed+4)*BBS_SCALAR_LEN + 4*BBS_G1_ELEM_LEN; // PART 2 skipped
	uint64_t log = 1; // To be ceil(log2(num_undisclosed + 1))
	while(num_undisclosed >>= 1) log++;
	return log * 2 * BBS_G1_ELEM_LEN + 7*BBS_SCALAR_LEN;
}

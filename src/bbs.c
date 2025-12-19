#include "bbs.h"
#include "bbs_util.h"
#include <stdbool.h>

/* This function should be availale in <unistd.h> on POSIX systems. We declare
 * it here to allow simple linking when <unistd.h> is not available, or for when
 * _some_ vendor decides to place it in another header. */
int getentropy(void *buffer, size_t length);

/* Helper */
static inline void ep_mult_scalar(blst_p1 *out, const blst_p1 *p, const blst_scalar *s, size_t _ignored) {
	(void)_ignored;
	blst_p1_mult(out, p, s->b, 255);
}

int
bbs_keygen_full (
	const bbs_ciphersuite *cipher_suite,
	bbs_secret_key      sk,
	bbs_public_key      pk
	)
{
	static uint8_t seed[32];

	// Gather randomness
	if(getentropy(seed, 32)) return BBS_ERROR;
	// Generate the secret key (cannot fail)
	bbs_keygen (cipher_suite, sk, seed, 32, 0, 0, 0, 0);
	// Generate the public key (unlikely to fail)
	bbs_sk_to_pk (cipher_suite, sk, pk);

	return BBS_OK;
}


int
bbs_keygen (
	const bbs_ciphersuite *cipher_suite,
	bbs_secret_key  sk,
	const void  *key_material,
	size_t          key_material_len,
	const void  *key_info,
	size_t          key_info_len,
	const void  *key_dst,
	size_t          key_dst_len
	)
{
	blst_scalar     sk_n;
	uint16_t key_info_len_be = htobe16((uint16_t)key_info_len);

	// Sanity check: Make sure we are at least given 16 bytes of (hopefully
	// random) key material
	if (! key_material || key_material_len < 16) return BBS_ERROR;
	if (key_info_len >= 0x10000) return BBS_ERROR;
	if (! key_info) key_info_len = 0;
	if (! key_dst)
	{
		key_dst     = cipher_suite->default_key_dst;
		key_dst_len = cipher_suite->default_key_dst_len;
	}

	hash_to_scalar (cipher_suite,
				      &sk_n,
				      key_dst,
				      key_dst_len,
				      3,
				      key_material,
				      key_material_len,
				      &key_info_len_be,
				      2,
				      key_info,
				      key_info_len);

	// Serialize
	bn_write_bbs (sk, &sk_n);

	return BBS_OK;
}

int
bbs_sk_to_pk (
	const bbs_ciphersuite *cipher_suite,
	const bbs_secret_key      sk,
	bbs_public_key            pk
	)
{
	(void)cipher_suite; // Might be used in the future. Keep API compat...
	blst_scalar  sk_n;
	blst_p2 pk_p;

	if(BBS_OK != bn_read_bbs (&sk_n, sk)) return BBS_ERROR;
	blst_sk_to_pk_in_g2 (&pk_p, &sk_n);
	ep2_write_bbs (pk, &pk_p);

	return BBS_OK;
}

// Accumulates onto B
typedef struct {
	const bbs_ciphersuite   *cipher_suite;
	uint8_t                generator_ctx[48 + 8];
	union bbs_hash_context dom_ctx;
	blst_p1 Q_1;
	// Final output
	blst_p1 B;
	// Temporary outputs
	blst_p1 H_i;
	blst_scalar msg_scalar; // Also used for domain
} bbs_acc_ctx;

typedef struct {
	bbs_acc_ctx acc;
	union bbs_hash_context ch_ctx;
} bbs_sign_ctx;

static void
bbs_acc_init (
	bbs_acc_ctx *ctx,
	const bbs_ciphersuite   *s,
	const bbs_public_key  pk,
	size_t              n
	)
{
	ctx->cipher_suite = s;
	// Initialize B to P1
	ep_read_bbs (&ctx->B, s->p1);

	// Calculate Q_1 and initialize domain calculation
	create_generator_init (s, ctx->generator_ctx);
	create_generator_next (s, ctx->generator_ctx, &ctx->Q_1);
	calculate_domain_init (s, &ctx->dom_ctx, pk, n);
	calculate_domain_update (s, &ctx->dom_ctx, &ctx->Q_1);
}

static inline void
bbs_acc_update_undisclosed (
	bbs_acc_ctx *ctx
	)
{
	// Calculate H_i
	create_generator_next (ctx->cipher_suite, ctx->generator_ctx, &ctx->H_i);
	calculate_domain_update (ctx->cipher_suite, &ctx->dom_ctx, &ctx->H_i);
}

static void
bbs_acc_update (
	bbs_acc_ctx   *ctx,
	const void *msg,
	size_t         msg_len
	)
{
	const bbs_ciphersuite *s = ctx->cipher_suite;
	blst_p1                H_i;

	bbs_acc_update_undisclosed (ctx);

	// Calculate msg_scalar (oneshot)
	hash_to_scalar (s, &ctx->msg_scalar, s->map_dst, s->map_dst_len, 1, msg, msg_len);
	// Update B
	ep_mult_scalar (&H_i, &ctx->H_i, &ctx->msg_scalar, 255);
	blst_p1_add_or_double (&ctx->B, &ctx->B, &H_i);
}

static void
bbs_acc_finalize (
	bbs_acc_ctx *ctx,
	const void        *header,
	size_t              header_len
	)
{
	const bbs_ciphersuite *s = ctx->cipher_suite;

	if (! header) header_len = 0;

	// Finish domain calculation (uses ctx->msg_scalar) and ctx->B
	calculate_domain_finalize (s, &ctx->dom_ctx, &ctx->msg_scalar, header, header_len);
	ep_mult_scalar (&ctx->Q_1, &ctx->Q_1, &ctx->msg_scalar, 255);
	blst_p1_add_or_double (&ctx->B, &ctx->B, &ctx->Q_1);
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

static void
bbs_sign_init (
	bbs_sign_ctx *ctx,
	const bbs_ciphersuite *cipher_suite,
	const bbs_secret_key  sk,
	const bbs_public_key  pk,
	size_t              n
	)
{
	hash_to_scalar_init (cipher_suite, &ctx->ch_ctx);
	// Future: We can add some randomness to ctx->ch_ctx. This breaks the
	// testvectors but not interop, and is heuristically more secure against
	// fault injection.
	hash_to_scalar_update (cipher_suite, &ctx->ch_ctx, sk, BBS_SK_LEN);
	bbs_acc_init(&ctx->acc, cipher_suite, pk, n);
}

static void
bbs_sign_update (
	bbs_sign_ctx *ctx,
	const void *msg,
	size_t msg_len
	)
{
	const bbs_ciphersuite *s = ctx->acc.cipher_suite;
	uint8_t             buffer[BBS_SCALAR_LEN];

	bbs_acc_update(&ctx->acc, msg, msg_len);
	// Serialize msg_scalar for hashing into e
	bn_write_bbs (buffer, &ctx->acc.msg_scalar);
	hash_to_scalar_update (s, &ctx->ch_ctx, buffer, BBS_SCALAR_LEN);
}

static int
bbs_sign_finalize (
	bbs_sign_ctx *ctx,
	bbs_signature         signature,
	const bbs_secret_key  sk,
	const void        *header,
	size_t              header_len
	)
{
	const bbs_ciphersuite *s = ctx->acc.cipher_suite;
	uint8_t             buffer[BBS_SCALAR_LEN];
	blst_scalar                   e, sk_n;

	bbs_acc_finalize(&ctx->acc, header, header_len);

	// Derive e
	bn_write_bbs (buffer, &ctx->acc.msg_scalar);
	hash_to_scalar_update (s, &ctx->ch_ctx, buffer, BBS_SCALAR_LEN);
	hash_to_scalar_finalize (s, &ctx->ch_ctx, &e, s->signature_dst, s->signature_dst_len);

	// Calculate A=B^(1/(sk+e))
	if(BBS_OK != bn_read_bbs (&sk_n, sk)) return BBS_ERROR;
	blst_sk_add_n_check (&sk_n, &sk_n, &e); // sk_n reused
	blst_sk_inverse (&sk_n, &sk_n);
	ep_mult_scalar (&ctx->acc.B, &ctx->acc.B, &sk_n, 255); // ctx->acc.B reused for A

	// Serialize (A,e)
	ep_write_bbs (signature, &ctx->acc.B);
	bn_write_bbs (signature + BBS_G1_ELEM_LEN, &e);

	return BBS_OK;
}

#define bbs_verify_init bbs_acc_init
#define bbs_verify_update bbs_acc_update

static int
bbs_verify_finalize (
	bbs_acc_ctx *ctx,
	const bbs_signature         signature,
	const bbs_public_key  pk,
	const void        *header,
	size_t              header_len
	)
{
	bbs_acc_finalize(ctx, header, header_len);

	// Reuse ctx->Q_1 as A, ctx->msg_scalar as e, ctx->H_i as A*e
	if(BBS_OK != ep_read_bbs(&ctx->Q_1, signature)) return BBS_ERROR;
	if(BBS_OK != bn_read_bbs(&ctx->msg_scalar, signature + BBS_G1_ELEM_LEN)) return BBS_ERROR;
	ep_mult_scalar(&ctx->H_i, &ctx->Q_1, &ctx->msg_scalar, 255);
	blst_p1_cneg(&ctx->H_i, 1);
	blst_p1_add_or_double(&ctx->B, &ctx->B, &ctx->H_i);

	return bbs_check_sig_eqn(&ctx->Q_1, &ctx->B, pk);
}

int
bbs_sign_v (
	const bbs_ciphersuite   *cipher_suite,
	const bbs_secret_key  sk,
	const bbs_public_key  pk,
	bbs_signature         signature,
	const void        *header,
	size_t              header_len,
	size_t              n,
	...
	)
{
	bbs_sign_ctx ctx;
	const void *msg;
	size_t msg_len;
	va_list                ap;

	va_start (ap, n);
	bbs_sign_init(&ctx, cipher_suite, sk, pk, n);
	for(size_t i=0; i< n; i++) {
		msg = va_arg (ap, const void*);
		msg_len = va_arg (ap, size_t);
		bbs_sign_update(&ctx, msg, msg_len);
	}
	va_end(ap);

	return bbs_sign_finalize(&ctx, signature, sk, header, header_len);
}

int
bbs_sign (
	const bbs_ciphersuite   *cipher_suite,
	const bbs_secret_key  sk,
	const bbs_public_key  pk,
	bbs_signature         signature,
	const void        *header,
	size_t                header_len,
	size_t                n,
	const void *const *messages,
	const size_t         *messages_lens
	)
{
	bbs_sign_ctx ctx;

	bbs_sign_init(&ctx, cipher_suite, sk, pk, n);
	for(size_t i=0; i< n; i++) {
		bbs_sign_update(&ctx, messages[i], messages_lens[i]);
	}

	return bbs_sign_finalize(&ctx, signature, sk, header, header_len);
}

int
bbs_verify_v (
	const bbs_ciphersuite   *cipher_suite,
	const bbs_public_key  pk,
	const bbs_signature   signature,
	const void        *header,
	size_t              header_len,
	size_t              n,
	...
	)
{
	bbs_acc_ctx ctx;
	const void *msg;
	size_t msg_len;
	va_list                ap;

	va_start (ap, n);
	bbs_verify_init(&ctx, cipher_suite, pk, n);
	for(size_t i=0; i< n; i++) {
		msg = va_arg (ap, const void*);
		msg_len = va_arg (ap, size_t);
		bbs_verify_update(&ctx, msg, msg_len);
	}
	va_end(ap);

	return bbs_verify_finalize(&ctx, signature, pk, header, header_len);
}

int
bbs_verify (
	const bbs_ciphersuite   *cipher_suite,
	const bbs_public_key  pk,
	const bbs_signature   signature,
	const void        *header,
	size_t                header_len,
	size_t              n,
	const void *const *messages,
	const size_t         *messages_lens
	)
{
	bbs_acc_ctx ctx;

	bbs_verify_init(&ctx, cipher_suite, pk, n);
	for(size_t i=0; i< n; i++) {
		bbs_verify_update(&ctx, messages[i], messages_lens[i]);
	}

	return bbs_verify_finalize(&ctx, signature, pk, header, header_len);
}

// Selective Disclosure overview:
// Valid signatures have e(A, W) = e(B-A*e, BP2).
// This does not change when multiplying the lefthand sides of e(.,.) by
// r1*r3^-1. The resulting values are ABar and BBar.
// Revealing D=B^(r3^-1), we prove that D^r3=Bv*Bh (where Bv is disclosed and
// visible, while Bh is undisclosed and hidden) as well as D^r1=BBar/ABar^e.
// Together, this implies that we rerandomized correctly a signature on the
// revealed messages.
// More technically, given statement (ABar,BBar,D,mi...), where mi are the
// disclosed message scalars for Bv, we prove knowledge of witness
// (e,r1,r3,mj...), where mj are the undisclosed message scalars for Bh. The
// proof itself is a straightforward linear proof.

// Accumulates onto B and T2 and keeps track of the challenge
typedef struct {
	bbs_acc_ctx acc;
	blst_p1 T2;
	union bbs_hash_context ch_ctx;
	uint64_t disclosed_ctr;
	uint64_t undisclosed_ctr;
	bbs_bn_prf           *prf;
	void                 *prf_cookie;
} bbs_proof_gen_ctx;


// TODO: Verify proof length as a sanity check
static void
bbs_proof_verify_init (
	bbs_proof_gen_ctx *ctx,
	const bbs_ciphersuite   *cipher_suite,
	const bbs_public_key     pk,
	size_t                   n,
	size_t                   num_disclosed
	)
{
	bbs_acc_init(&ctx->acc, cipher_suite, pk, n);
	ctx->disclosed_ctr = ctx->undisclosed_ctr = 0;

	// Initialize T2 to the identity. FIXME: Should there be an API for
	// this in BLST?
	(void)bbs_memset(&ctx->T2.z, 0, sizeof(ctx->T2.z));

	// Initialize Challenge Calculation
	hash_to_scalar_init (cipher_suite, &ctx->ch_ctx);
	uint64_t be_buffer = htobe64 (num_disclosed);
	hash_to_scalar_update (cipher_suite, &ctx->ch_ctx, &be_buffer, 8);
}

// Not static, to allow Fixture tests
void
bbs_proof_gen_init (
	bbs_proof_gen_ctx *ctx,
	const bbs_ciphersuite   *cipher_suite,
	const bbs_public_key  pk,
	size_t                n,
	size_t                num_disclosed,
	bbs_bn_prf            prf,
	void                 *prf_cookie
	)
{
	bbs_proof_verify_init(ctx, cipher_suite, pk, n, num_disclosed);
	ctx->prf = prf;
	ctx->prf_cookie = prf_cookie;
}

// Not static, to allow Fixture tests
void
bbs_proof_gen_update (
	bbs_proof_gen_ctx *ctx,
	void *proof,
	const void *msg,
	size_t msg_len,
	bool disclosed
	)
{
	const bbs_ciphersuite *s = ctx->acc.cipher_suite;
	uint8_t *proof_ptr = (uint8_t*)proof + 3 * BBS_G1_ELEM_LEN + (3 + ctx->undisclosed_ctr) * BBS_SCALAR_LEN;
	bbs_acc_update(&ctx->acc, msg, msg_len);

	// Write msg_scalar to the proof. This is not an overflow.
	bn_write_bbs (proof_ptr, &ctx->acc.msg_scalar);

	if(disclosed) {
		// This message is disclosed. Update the challenge hash
		uint64_t be_buffer = htobe64 (ctx->disclosed_ctr + ctx->undisclosed_ctr);
		hash_to_scalar_update(s, &ctx->ch_ctx, &be_buffer, 8);
		hash_to_scalar_update(s, &ctx->ch_ctx, proof_ptr, BBS_SCALAR_LEN);
		ctx->disclosed_ctr++;
	}
	else
	{
		// This message is undisclosed. Derive new random scalar
		// and accumulate it onto commitment T2
		ctx->prf (s, &ctx->acc.msg_scalar, 0, ctx->undisclosed_ctr + 3, ctx->prf_cookie);

		// Update T2
		ep_mult_scalar (&ctx->acc.H_i, &ctx->acc.H_i, &ctx->acc.msg_scalar, 255);
		blst_p1_add_or_double (&ctx->T2, &ctx->T2, &ctx->acc.H_i);
		ctx->undisclosed_ctr++; // Implicitly keep msg_scalar for later
	}
}

static int
bbs_proof_verify_update (
	bbs_proof_gen_ctx *ctx,
	const void *proof,
	const void *msg,
	size_t msg_len,
	bool disclosed
	)
{
	const bbs_ciphersuite *s = ctx->acc.cipher_suite;
	const uint8_t *proof_ptr = (uint8_t*)proof + 3 * BBS_G1_ELEM_LEN + (3 + ctx->undisclosed_ctr) * BBS_SCALAR_LEN;
	uint8_t scalar_buffer[BBS_SCALAR_LEN];

	if (disclosed)
	{
		// This message is disclosed.
		bbs_acc_update(&ctx->acc, msg, msg_len);
		bn_write_bbs (scalar_buffer, &ctx->acc.msg_scalar);

		// Hash i and msg_scalar into the challenge
		size_t be_buffer = htobe64 (ctx->disclosed_ctr + ctx->undisclosed_ctr);
		hash_to_scalar_update (s, &ctx->ch_ctx, &be_buffer, 8);
		hash_to_scalar_update (s, &ctx->ch_ctx, scalar_buffer, BBS_SCALAR_LEN);
		ctx->disclosed_ctr++;
	}
	else
	{
		// This message is undisclosed.
		// Read a msg_scalar_hat value from the proof and
		// accumulate it onto T2 instead of B
		bbs_acc_update_undisclosed (&ctx->acc);

		// Update T2.
		if(BBS_OK != bn_read_bbs (&ctx->acc.msg_scalar, proof_ptr)) return BBS_ERROR;
		ep_mult_scalar (&ctx->acc.H_i, &ctx->acc.H_i, &ctx->acc.msg_scalar, 255);
		blst_p1_add_or_double (&ctx->T2, &ctx->T2, &ctx->acc.H_i);
		ctx->undisclosed_ctr++;
	}
	return BBS_OK;
}

// Not static, to allow Fixture tests
int
bbs_proof_gen_finalize (
	bbs_proof_gen_ctx *ctx,
	const bbs_signature   signature,
	void              *proof,
	const void        *header,
	size_t                header_len,
	const void        *presentation_header,
	size_t                presentation_header_len,
	size_t                n,
	size_t                num_disclosed
	)
{
	const bbs_ciphersuite *s = ctx->acc.cipher_suite;
	blst_scalar e, r1, r3, challenge;
	blst_p1 D, Abar, Bbar;
	uint8_t domain_buffer[BBS_SCALAR_LEN], T_buffer[2*BBS_G1_ELEM_LEN];
	uint8_t *proof_ptr = (uint8_t*)proof;

	// Sanity check. If any indices for disclosed messages were out of order
	// or invalid, we fail here.
	uint64_t num_undisclosed = n - num_disclosed;
	if (ctx->disclosed_ctr != num_disclosed || ctx->undisclosed_ctr != num_undisclosed)
	{
		return BBS_ERROR;
	}

	bbs_acc_finalize(&ctx->acc, header, header_len);

	// Write out the domain
	bn_write_bbs (domain_buffer, &ctx->acc.msg_scalar);

	// Parse the signature
	if(BBS_OK != ep_read_bbs (&Abar, signature)) return BBS_ERROR; // Reuse Abar as A
	if(BBS_OK != bn_read_bbs (&e, signature + BBS_G1_ELEM_LEN)) return BBS_ERROR;

	// Generate rerandomization scalars.
	ctx->prf (s, &r1, 1, 0, ctx->prf_cookie);
	ctx->prf (s, &r3, 2, 0, ctx->prf_cookie); // Temporarily r2=r3^-1

	// Calculate the statement (excluding messages): D, ABar, BBar.
	// B is used as a temporary variable from now on.
	ep_mult_scalar (&D,          &ctx->acc.B, &r3, 255);
	ep_mult_scalar (&Abar,       &Abar,       &r1, 255);
	ep_mult_scalar (&Abar,       &Abar,       &r3, 255);
	ep_mult_scalar (&Bbar,       &D,          &r1, 255);
	ep_mult_scalar (&ctx->acc.B, &Abar,       &e,  255);
	blst_p1_cneg (&ctx->acc.B, 1);
	blst_p1_add_or_double (&Bbar, &Bbar, &ctx->acc.B);

	// Turn r2 into r3
	blst_sk_inverse (&r3, &r3);

	// Write statement and witness out (witness to be overwritten)
	// Part of the witness has been written out already
	ep_write_bbs (proof_ptr, &Abar);
	proof_ptr += BBS_G1_ELEM_LEN;
	ep_write_bbs (proof_ptr, &Bbar);
	proof_ptr += BBS_G1_ELEM_LEN;
	ep_write_bbs (proof_ptr, &D);
	proof_ptr += BBS_G1_ELEM_LEN;
	bn_write_bbs (proof_ptr, &e);
	proof_ptr += BBS_SCALAR_LEN;
	bn_write_bbs (proof_ptr, &r1);
	proof_ptr += BBS_SCALAR_LEN;
	bn_write_bbs (proof_ptr, &r3);
	proof_ptr += BBS_SCALAR_LEN;

	// Proof Message 1: Commitment (T1,T2)
	ctx->prf (s, &e,  0, 0, ctx->prf_cookie);
	ctx->prf (s, &r1, 0, 1, ctx->prf_cookie);
	ctx->prf (s, &r3, 0, 2, ctx->prf_cookie);
	ep_mult_scalar (&ctx->acc.B, &D, &r3, 255);
	blst_p1_add_or_double (&ctx->T2, &ctx->T2, &ctx->acc.B);
	ep_write_bbs (T_buffer + BBS_G1_ELEM_LEN, &ctx->T2);
	ep_mult_scalar (&ctx->T2,    &D,    &r1, 255); // Reuse T2 as T1
	ep_mult_scalar (&ctx->acc.B, &Abar, &e,  255);
	blst_p1_add_or_double (&ctx->T2, &ctx->T2, &ctx->acc.B);
	ep_write_bbs (T_buffer, &ctx->T2);

	// Proof Message 2: Challenge
	if (! presentation_header) presentation_header_len = 0;
	hash_to_scalar_update (s, &ctx->ch_ctx, proof, 3 * BBS_G1_ELEM_LEN);
	hash_to_scalar_update (s, &ctx->ch_ctx, T_buffer, 2 * BBS_G1_ELEM_LEN);
	hash_to_scalar_update (s, &ctx->ch_ctx, domain_buffer, BBS_SCALAR_LEN);
	uint64_t be_buffer = htobe64 (presentation_header_len);
	hash_to_scalar_update (s, &ctx->ch_ctx, &be_buffer, 8);
        hash_to_scalar_update(s, &ctx->ch_ctx, presentation_header, presentation_header_len);
        hash_to_scalar_finalize(s, &ctx->ch_ctx, &challenge, s->challenge_dst, s->challenge_dst_len);
	bn_write_bbs ((uint8_t*)proof + BBS_PROOF_LEN (num_undisclosed) - BBS_SCALAR_LEN, &challenge);

        // Proof Message 3: Response
	// We overwrite the witness and reuse e for the tilde values
	proof_ptr = (uint8_t*)proof + 3 * BBS_G1_ELEM_LEN;
	for (uint64_t witness_idx = 0; witness_idx < num_undisclosed + 3; witness_idx++)
	{
		ctx->prf (s, &e, 0, witness_idx, ctx->prf_cookie);

		bn_read_bbs (&ctx->acc.msg_scalar, proof_ptr); // Cannot fail
		blst_sk_mul_n_check(&ctx->acc.msg_scalar, &ctx->acc.msg_scalar, &challenge);
		if(1 == witness_idx || 2 == witness_idx) // r1 and r3 are subtracted
			blst_sk_sub_n_check (&e, &e, &ctx->acc.msg_scalar);
		else
			blst_sk_add_n_check (&e, &e, &ctx->acc.msg_scalar);
		bn_write_bbs (proof_ptr, &e);
		proof_ptr += BBS_SCALAR_LEN;
	}

	return BBS_OK;
}

static int
bbs_proof_verify_finalize (
	bbs_proof_gen_ctx *ctx,
	const bbs_public_key  pk,
	const void        *proof,
	const void        *header,
	size_t                header_len,
	const void        *presentation_header,
	size_t                presentation_header_len,
	size_t                n,
	size_t                num_disclosed
	)
{
	const bbs_ciphersuite *s = ctx->acc.cipher_suite;
	blst_scalar e, r1, r3, challenge, challenge_prime;
	blst_p1 D, Abar, Bbar;
	uint8_t domain_buffer[BBS_SCALAR_LEN], T_buffer[2*BBS_G1_ELEM_LEN];
	const uint8_t *proof_ptr  = (const uint8_t*)proof;

	// Sanity check. If any indices for disclosed messages were out of order
	// or invalid, we fail here.
	uint64_t num_undisclosed = n - num_disclosed;
	if (ctx->disclosed_ctr != num_disclosed || ctx->undisclosed_ctr != num_undisclosed)
	{
		return BBS_ERROR;
	}

	bbs_acc_finalize(&ctx->acc, header, header_len);

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
	if(BBS_OK != bn_read_bbs (&challenge, (const uint8_t*)proof + BBS_PROOF_LEN (num_undisclosed) - BBS_SCALAR_LEN)) return BBS_ERROR;

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
	hash_to_scalar_update (s, &ctx->ch_ctx, &be_buffer, 8);
        hash_to_scalar_update(s, &ctx->ch_ctx, presentation_header,
                              presentation_header_len);
        hash_to_scalar_finalize(s, &ctx->ch_ctx, &challenge_prime, s->challenge_dst, s->challenge_dst_len);

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
	const bbs_ciphersuite *cipher_suite,
	blst_scalar              *out,
	uint8_t             input_type,
	uint64_t            input,
	void               *seed
	)
{
	// All these have length 17
	static char *prf_dsts[] = {
		"random proof sclr",
		"random r_1 scalar",
		"random r_3 scalar",
	};

        hash_to_scalar(cipher_suite, out, prf_dsts[input_type], 17, 2, seed, 32, &input, 8);
}

int
bbs_proof_gen_v (
	const bbs_ciphersuite   *cipher_suite,
	const bbs_public_key  pk,
	const bbs_signature   signature,
	void              *proof,
	const void        *header,
	size_t                header_len,
	const void        *presentation_header,
	size_t                presentation_header_len,
	const size_t         *disclosed_indexes,
	size_t                disclosed_indexes_len,
	size_t                n,
	...
	)
{
	va_list ap;
	uint8_t seed[32];
	bbs_proof_gen_ctx ctx;
	size_t di_idx = 0;
	const void *msg;
	size_t msg_len;
	bool disclosed;

	// Gather randomness. The seed is used for any randomness within this
	// function. In particular, this implies that we do not need to store
	// intermediate derivations. Currently, we derive new values via
	// hash_to_scalar, but we might want to exchange that for
	// something faster later on.
	if(getentropy(seed, 32)) return BBS_ERROR;

	va_start (ap, n);
	bbs_proof_gen_init(&ctx, cipher_suite, pk, n, disclosed_indexes_len, bbs_proof_prf, seed);
	for(size_t i=0; i< n; i++) {
		disclosed = di_idx < disclosed_indexes_len && disclosed_indexes[di_idx] == i;
		msg = va_arg (ap, const void*);
		msg_len = va_arg (ap, size_t);
		bbs_proof_gen_update(&ctx, proof, msg, msg_len, disclosed);
		if(disclosed) di_idx++;
	}
	va_end(ap);

	return bbs_proof_gen_finalize(&ctx, signature, proof, header, header_len, presentation_header, presentation_header_len, n, disclosed_indexes_len);
}

int
bbs_proof_gen (
	const bbs_ciphersuite   *cipher_suite,
	const bbs_public_key  pk,
	const bbs_signature   signature,
	void              *proof,
	const void        *header,
	size_t                header_len,
	const void        *presentation_header,
	size_t                presentation_header_len,
	const size_t       *disclosed_indexes,
	size_t                disclosed_indexes_len,
	size_t                n,
	const void *const *messages,
	const size_t         *messages_lens
	)
{
	uint8_t seed[32];
	bbs_proof_gen_ctx ctx;
	size_t di_idx = 0;
	bool disclosed;

	// Gather randomness. The seed is used for any randomness within this
	// function. In particular, this implies that we do not need to store
	// intermediate derivations. Currently, we derive new values via
	// hash_to_scalar, but we might want to exchange that for
	// something faster later on.
	if(getentropy(seed, 32)) return BBS_ERROR;

	bbs_proof_gen_init(&ctx, cipher_suite, pk, n, disclosed_indexes_len, bbs_proof_prf, seed);
	for(size_t i=0; i< n; i++) {
		disclosed = di_idx < disclosed_indexes_len && disclosed_indexes[di_idx] == i;
		bbs_proof_gen_update(&ctx, proof, messages[i], messages_lens[i], disclosed);
		if(disclosed) di_idx++;
	}

	return bbs_proof_gen_finalize(&ctx, signature, proof, header, header_len, presentation_header, presentation_header_len, n, disclosed_indexes_len);
}

int
bbs_proof_verify_v (
	const bbs_ciphersuite   *cipher_suite,
	const bbs_public_key        pk,
	const void              *proof,
	size_t                      proof_len,
	const void              *header,
	size_t                      header_len,
	const void              *presentation_header,
	size_t                      presentation_header_len,
	const size_t               *disclosed_indexes,
	size_t                      disclosed_indexes_len,
	size_t                      n,
	...
	)
{
	va_list                ap;
	bbs_proof_gen_ctx ctx;
	size_t di_idx = 0;
	const void *msg = NULL;
	size_t msg_len = 0;
	bool disclosed;

	// Sanity check
	if(proof_len != BBS_PROOF_LEN(n - disclosed_indexes_len)) return BBS_ERROR;

	va_start (ap, n);
	bbs_proof_verify_init(&ctx, cipher_suite, pk, n, disclosed_indexes_len);
	for(size_t i=0; i< n; i++) {
		disclosed = di_idx < disclosed_indexes_len && disclosed_indexes[di_idx] == i;
		if(disclosed) {
			di_idx++;
			msg = va_arg (ap, const void*);
			msg_len = va_arg (ap, size_t);
		}
		bbs_proof_verify_update(&ctx, proof, msg, msg_len, disclosed);
	}
	va_end(ap);

	return bbs_proof_verify_finalize(&ctx, pk, proof, header, header_len, presentation_header, presentation_header_len, n, disclosed_indexes_len);
}

int
bbs_proof_verify (
	const bbs_ciphersuite *cipher_suite,
	const bbs_public_key   pk,
	const void            *proof,
	size_t                 proof_len,
	const void            *header,
	size_t                 header_len,
	const void            *presentation_header,
	size_t                 presentation_header_len,
	const size_t          *disclosed_indexes,
	size_t                 disclosed_indexes_len,
	size_t                 n,
	const void *const     *messages,
	const size_t          *messages_lens
	)
{
	bbs_proof_gen_ctx ctx;
	size_t di_idx = 0;
	bool disclosed;

	// Sanity check
	if(proof_len != BBS_PROOF_LEN(n - disclosed_indexes_len)) return BBS_ERROR;

	bbs_proof_verify_init(&ctx, cipher_suite, pk, n, disclosed_indexes_len);
	for(size_t i=0; i< n; i++) {
		disclosed = di_idx < disclosed_indexes_len && disclosed_indexes[di_idx] == i;
		bbs_proof_verify_update(&ctx, proof, messages[di_idx], messages_lens[di_idx], disclosed);
		if(disclosed) di_idx++;
	}

	return bbs_proof_verify_finalize(&ctx, pk, proof, header, header_len, presentation_header, presentation_header_len, n, disclosed_indexes_len);
}

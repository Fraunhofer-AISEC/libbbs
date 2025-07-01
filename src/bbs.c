#include "bbs.h"
#include "bbs_util.h"
#include <relic.h>
#include <stdbool.h>

int
bbs_init (void)
{
	if (core_init () != RLC_OK || pc_param_set_any () != RLC_OK)
	{
		core_clean ();
		return BBS_ERROR;
	}
	return BBS_OK;
}

int
bbs_deinit (void)
{
	core_clean ();
	return BBS_OK;
}

int
bbs_keygen_full (
	bbs_cipher_suite_t *cipher_suite,
	bbs_secret_key      sk,
	bbs_public_key      pk
	)
{
	static uint8_t seed[32];

	// Gather randomness
	RLC_TRY {
		rand_bytes (seed, 32);
	}
	RLC_CATCH_ANY {
		return BBS_ERROR;
	}

	// Generate the secret key (cannot fail)
	bbs_keygen (cipher_suite, sk, seed, 32, 0, 0, 0, 0);
	// Generate the public key (cannot fail)
	bbs_sk_to_pk (cipher_suite, sk, pk);

	return BBS_OK;
}


int
bbs_keygen (
	bbs_cipher_suite_t *cipher_suite,
	bbs_secret_key      sk,
	const uint8_t      *key_material,
	uint16_t            key_material_len,
	const uint8_t      *key_info,
	uint16_t            key_info_len,
	const uint8_t      *key_dst,
	uint8_t             key_dst_len
	)
{
	bn_t     sk_n;
	uint16_t key_info_len_be = ((key_info_len & 0x00FFu) << 8) | (key_info_len >> 8);

	// Sanity check: Make sure we are at least given 16 bytes of (hopefully
	// random) key material
	if (! key_material || key_material_len < 16) return BBS_ERROR;
	if (! key_info) key_info_len = 0;
	if (! key_dst)
	{
		key_dst     = (uint8_t*) cipher_suite->default_key_dst;
		key_dst_len = cipher_suite->default_key_dst_len;
	}

	hash_to_scalar (cipher_suite,
				      sk_n,
				      key_dst,
				      key_dst_len,
				      3,
				      key_material,
				      (uint32_t) key_material_len,
				      &key_info_len_be,
				      (uint32_t) 2,
				      key_info,
				      (uint32_t) key_info_len);

	// Serialize
	RLC_ASSERT(bn_write_bin (sk, BBS_SK_LEN, sk_n));

	return BBS_OK;
}

int
bbs_sk_to_pk (
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_secret_key  sk,
	bbs_public_key        pk
	)
{
	bn_t  sk_n;
	ep2_t pk_p;

	RLC_TRY {
		bn_read_bbs (sk_n, sk);
		ep2_mul_gen (pk_p, sk_n);
		ep2_write_bbs (pk, pk_p);
	}
	RLC_CATCH_ANY {
		return BBS_ERROR;
	}

	return BBS_OK;
}

// Accumulates onto B
typedef struct {
	bbs_cipher_suite_t   *cipher_suite;
	uint8_t                generator_ctx[48 + 8];
	union bbs_hash_context dom_ctx;
	ep_t Q_1;
	// Final output
	ep_t B;
	// Temporary outputs
	ep_t H_i;
	bn_t msg_scalar; // Also used for domain
} bbs_acc_ctx;

typedef struct {
	bbs_acc_ctx acc;
	union bbs_hash_context ch_ctx;
} bbs_sign_ctx;

static void
bbs_acc_init (
	bbs_acc_ctx *ctx,
	bbs_cipher_suite_t   *s,
	const bbs_public_key  pk,
	uint64_t              num_messages
	)
{
	ctx->cipher_suite = s;
	// Initialize B to P1
	RLC_ASSERT(ep_read_bbs (ctx->B, s->p1));

	// Calculate Q_1 and initialize domain calculation
	create_generator_init (s, ctx->generator_ctx);
	create_generator_next (s, ctx->generator_ctx, ctx->Q_1);
	calculate_domain_init (s, &ctx->dom_ctx, pk, num_messages);
	calculate_domain_update (s, &ctx->dom_ctx, ctx->Q_1);
}

static inline void
bbs_acc_update_undisclosed (
	bbs_acc_ctx *ctx
	)
{
	// Calculate H_i
	create_generator_next (ctx->cipher_suite, ctx->generator_ctx, ctx->H_i);
	calculate_domain_update (ctx->cipher_suite, &ctx->dom_ctx, ctx->H_i);
}

static void
bbs_acc_update (
	bbs_acc_ctx *ctx,
	uint8_t *msg,
	uint32_t msg_len
	)
{
	bbs_cipher_suite_t *s = ctx->cipher_suite;
	ep_t                H_i;

	bbs_acc_update_undisclosed (ctx);

	// Calculate msg_scalar (oneshot)
	hash_to_scalar (s, ctx->msg_scalar, s->map_dst, s->map_dst_len, 1, msg, msg_len);
	RLC_ASSERT(
		// Update B
		ep_mul (H_i, ctx->H_i, ctx->msg_scalar);
		ep_add (ctx->B, ctx->B, H_i);
	);
}

static void
bbs_acc_finalize (
	bbs_acc_ctx *ctx,
	const uint8_t        *header,
	uint64_t              header_len
	)
{
	bbs_cipher_suite_t *s = ctx->cipher_suite;

	if (! header) header_len = 0;

	// Finish domain calculation (uses ctx->msg_scalar) and ctx->B
	calculate_domain_finalize (s, &ctx->dom_ctx, ctx->msg_scalar, header, header_len);
	RLC_ASSERT(
		ep_mul (ctx->Q_1, ctx->Q_1, ctx->msg_scalar);
		ep_add (ctx->B, ctx->B, ctx->Q_1);
	);
}

// Checks e(A,W') * e(B,-BP2) = identity
// Alters W'
static int bbs_check_sig_eqn(
	ep_t A,
	ep_t B,
	ep2_t Wprime
	)
{
	fp12_t                 paired1, paired2;

	RLC_ASSERT(
		pp_map_oatep_k12 (paired1, A, Wprime);

		ep2_curve_get_gen (Wprime); // Reuse Wprime
		ep2_neg (Wprime, Wprime);
		pp_map_oatep_k12 (paired2, B, Wprime);

		fp12_mul (paired1, paired1, paired2);
	);

	return (RLC_EQ != fp12_cmp_dig (paired1, 1)) ? BBS_ERROR : BBS_OK;
}

static void
bbs_sign_init (
	bbs_sign_ctx *ctx,
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_secret_key  sk,
	const bbs_public_key  pk,
	uint64_t              num_messages
	)
{
	hash_to_scalar_init (cipher_suite, &ctx->ch_ctx);
	// Future: We can add some randomness to ctx->ch_ctx. This breaks the
	// testvectors but not interop, and is heuristically more secure against
	// fault injection.
	hash_to_scalar_update (cipher_suite, &ctx->ch_ctx, sk, BBS_SK_LEN);
	bbs_acc_init(&ctx->acc, cipher_suite, pk, num_messages);
}

static void
bbs_sign_update (
	bbs_sign_ctx *ctx,
	uint8_t *msg,
	uint32_t msg_len
	)
{
	bbs_cipher_suite_t *s = ctx->acc.cipher_suite;
	uint8_t             buffer[BBS_SCALAR_LEN];

	bbs_acc_update(&ctx->acc, msg, msg_len);
	// Serialize msg_scalar for hashing into e
	RLC_ASSERT(bn_write_bbs (buffer, ctx->acc.msg_scalar));
	hash_to_scalar_update (s, &ctx->ch_ctx, buffer, BBS_SCALAR_LEN);
}

static int
bbs_sign_finalize (
	bbs_sign_ctx *ctx,
	bbs_signature         signature,
	const bbs_secret_key  sk,
	const uint8_t        *header,
	uint64_t              header_len
	)
{
	bbs_cipher_suite_t *s = ctx->acc.cipher_suite;
	uint8_t             buffer[BBS_SCALAR_LEN];
	bn_t                   e, sk_n;

	bbs_acc_finalize(&ctx->acc, header, header_len);

	// Derive e
	RLC_ASSERT(bn_write_bbs (buffer, ctx->acc.msg_scalar));
	hash_to_scalar_update (s, &ctx->ch_ctx, buffer, BBS_SCALAR_LEN);
	hash_to_scalar_finalize (s, &ctx->ch_ctx, e, s->signature_dst, s->signature_dst_len);

	RLC_TRY {
		// Calculate A=B^(1/(sk+e))
		bn_read_bbs (sk_n, sk);
		bn_add (sk_n, sk_n, e); // sk_n reused
		bn_mod_inv (sk_n, sk_n, &(core_get ()->ep_r));
		ep_mul (ctx->acc.B, ctx->acc.B, sk_n); // ctx->acc.B reused for A

		// Serialize (A,e)
		ep_write_bbs (signature, ctx->acc.B);
		bn_write_bbs (signature + BBS_G1_ELEM_LEN, e);
	}
	RLC_CATCH_ANY {
		// This can happen when A=identity (unlikely) or sk was corrupted
		return BBS_ERROR;
	}

	return BBS_OK;
}

#define bbs_verify_init bbs_acc_init
#define bbs_verify_update bbs_acc_update

static int
bbs_verify_finalize (
	bbs_acc_ctx *ctx,
	const bbs_signature         signature,
	const bbs_public_key  pk,
	const uint8_t        *header,
	uint64_t              header_len
	)
{
	bbs_cipher_suite_t *s = ctx->cipher_suite;
	ep2_t                  W, Wprime;

	bbs_acc_finalize(ctx, header, header_len);

	RLC_TRY {
		// Reuse ctx->Q_1 as A, ctx->msg_scalar as e
		ep_read_bbs(ctx->Q_1, signature);
		bn_read_bbs(ctx->msg_scalar, signature + BBS_G1_ELEM_LEN);
		ep2_read_bbs(W, pk);

		// We need to check e(A, W + BP2 * e) * e(B, -BP2)
		// One could instead check e(A, W) = e(B-A*e, BP2)
		ep2_mul_gen (Wprime, ctx->msg_scalar);
		ep2_add (Wprime, W, Wprime);
	}
	RLC_CATCH_ANY {
		return BBS_ERROR;
	}

	return bbs_check_sig_eqn(ctx->Q_1, ctx->B, Wprime);
}

int
bbs_sign (
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_secret_key  sk,
	const bbs_public_key  pk,
	bbs_signature         signature,
	const uint8_t        *header,
	uint64_t              header_len,
	uint64_t              num_messages,
	...
	)
{
	bbs_sign_ctx ctx;
	uint8_t *msg;
	uint32_t msg_len;
	va_list                ap;

	va_start (ap, num_messages);
	bbs_sign_init(&ctx, cipher_suite, sk, pk, num_messages);
	for(int i=0; i< num_messages; i++) {
		msg = va_arg (ap, uint8_t*);
		msg_len = va_arg (ap, uint32_t);
		bbs_sign_update(&ctx, msg, msg_len);
	}
	va_end(ap);

	return bbs_sign_finalize(&ctx, signature, sk, header, header_len);
}

int
bbs_verify (
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_public_key  pk,
	const bbs_signature   signature,
	const uint8_t        *header,
	uint64_t              header_len,
	uint64_t              num_messages,
	...
	)
{
	bbs_acc_ctx ctx;
	uint8_t *msg;
	uint32_t msg_len;
	va_list                ap;

	va_start (ap, num_messages);
	bbs_verify_init(&ctx, cipher_suite, pk, num_messages);
	for(int i=0; i< num_messages; i++) {
		msg = va_arg (ap, uint8_t*);
		msg_len = va_arg (ap, uint32_t);
		bbs_verify_update(&ctx, msg, msg_len);
	}
	va_end(ap);

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
	ep_t T2;
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
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_public_key  pk,
	uint64_t              num_messages,
	uint64_t              num_disclosed
	)
{
	bbs_acc_init(&ctx->acc, cipher_suite, pk, num_messages);
	ctx->disclosed_ctr = ctx->undisclosed_ctr = 0;

	// Initialize T2 to the identity
	RLC_ASSERT(ep_set_infty (ctx->T2));

	// Initialize Challenge Calculation
	hash_to_scalar_init (cipher_suite, &ctx->ch_ctx);
	uint64_t be_buffer = UINT64_H2BE (num_disclosed);
	hash_to_scalar_update (cipher_suite, &ctx->ch_ctx, (uint8_t*) &be_buffer, 8);
}

// Not static, to allow Fixture tests
void
bbs_proof_gen_init (
	bbs_proof_gen_ctx *ctx,
	bbs_cipher_suite_t   *cipher_suite,
	const bbs_public_key  pk,
	uint64_t              num_messages,
	uint64_t              num_disclosed,
	bbs_bn_prf            prf,
	void                 *prf_cookie
	)
{
	bbs_proof_verify_init(ctx, cipher_suite, pk, num_messages, num_disclosed);
	ctx->prf = prf;
	ctx->prf_cookie = prf_cookie;
}

// Not static, to allow Fixture tests
void
bbs_proof_gen_update (
	bbs_proof_gen_ctx *ctx,
	uint8_t *proof,
	uint8_t *msg,
	uint64_t msg_len,
	bool disclosed
	)
{
	bbs_cipher_suite_t *s = ctx->acc.cipher_suite;
	uint8_t *proof_ptr = proof + 3 * BBS_G1_ELEM_LEN + (3 + ctx->undisclosed_ctr) * BBS_SCALAR_LEN;
	bbs_acc_update(&ctx->acc, msg, msg_len);

	// Write msg_scalar to the proof. This is not an overflow.
	RLC_ASSERT(bn_write_bbs (proof_ptr, ctx->acc.msg_scalar));

	if(disclosed) {
		// This message is disclosed. Update the challenge hash
		uint64_t be_buffer = UINT64_H2BE (ctx->disclosed_ctr + ctx->undisclosed_ctr);
		hash_to_scalar_update(s, &ctx->ch_ctx, (uint8_t*) &be_buffer, 8);
		hash_to_scalar_update(s, &ctx->ch_ctx, proof_ptr, BBS_SCALAR_LEN);
		ctx->disclosed_ctr++;
	}
	else
	{
		// This message is undisclosed. Derive new random scalar
		// and accumulate it onto commitment T2
		ctx->prf (s, ctx->acc.msg_scalar, 0, ctx->undisclosed_ctr + 3, ctx->prf_cookie);

		// Update T2
		RLC_ASSERT(
			ep_mul (ctx->acc.H_i, ctx->acc.H_i, ctx->acc.msg_scalar);
			ep_add (ctx->T2, ctx->T2, ctx->acc.H_i);
		);
		ctx->undisclosed_ctr++; // Implicitly keep msg_scalar for later
	}
}

static int
bbs_proof_verify_update (
	bbs_proof_gen_ctx *ctx,
	const uint8_t *proof,
	uint8_t *msg,
	uint64_t msg_len,
	bool disclosed
	)
{
	bbs_cipher_suite_t *s = ctx->acc.cipher_suite;
	const uint8_t *proof_ptr = proof + 3 * BBS_G1_ELEM_LEN + (3 + ctx->undisclosed_ctr) * BBS_SCALAR_LEN;
	uint8_t scalar_buffer[BBS_SCALAR_LEN];

	if (disclosed)
	{
		// This message is disclosed.
		bbs_acc_update(&ctx->acc, msg, msg_len);
		RLC_ASSERT(bn_write_bbs (scalar_buffer, ctx->acc.msg_scalar));

		// Hash i and msg_scalar into the challenge
		uint64_t be_buffer = UINT64_H2BE (ctx->disclosed_ctr + ctx->undisclosed_ctr);
		hash_to_scalar_update (s, &ctx->ch_ctx, (uint8_t*) &be_buffer, 8);
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
		RLC_TRY {
			bn_read_bbs (ctx->acc.msg_scalar, proof_ptr);
			ep_mul (ctx->acc.H_i, ctx->acc.H_i, ctx->acc.msg_scalar);
			ep_add (ctx->T2, ctx->T2, ctx->acc.H_i);
		}
		RLC_CATCH_ANY {
			return BBS_ERROR;
		}
		ctx->undisclosed_ctr++;
	}
	return BBS_OK;
}

// Not static, to allow Fixture tests
int
bbs_proof_gen_finalize (
	bbs_proof_gen_ctx *ctx,
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
	bbs_cipher_suite_t *s = ctx->acc.cipher_suite;
	bn_t e, r1, r3, challenge;
	ep_t D, Abar, Bbar;
	uint8_t domain_buffer[BBS_SCALAR_LEN], T_buffer[2*BBS_G1_ELEM_LEN];
	uint8_t *proof_ptr = proof;

	// Sanity check. If any indices for disclosed messages were out of order
	// or invalid, we fail here.
	uint64_t num_undisclosed = num_messages - num_disclosed;
	if (ctx->disclosed_ctr != num_disclosed || ctx->undisclosed_ctr != num_undisclosed)
	{
		return BBS_ERROR;
	}

	bbs_acc_finalize(&ctx->acc, header, header_len);

	RLC_TRY {
		// Write out the domain
		bn_write_bbs (domain_buffer, ctx->acc.msg_scalar);

		// Parse the signature
		ep_read_bbs (Abar, signature); // Reuse Abar as A
		bn_read_bbs (e, signature + BBS_G1_ELEM_LEN);

		// Generate rerandomization scalars.
		ctx->prf (s, r1, 1, 0, ctx->prf_cookie);
		ctx->prf (s, r3, 2, 0, ctx->prf_cookie); // Temporarily r2=r3^-1
	
		// Calculate the statement (excluding messages): D, ABar, BBar.
		// B is used as a temporary variable from now on.
		ep_mul (D, ctx->acc.B, r3);
		ep_mul (Abar, Abar,    r1);
		ep_mul (Abar, Abar, r3);
		ep_mul (Bbar, D,    r1);
		ep_mul (ctx->acc.B,    Abar, e);
		ep_neg (ctx->acc.B, ctx->acc.B);
		ep_add (Bbar, Bbar, ctx->acc.B);

		// Turn r2 into r3
		bn_mod_inv (r3, r3, &(core_get ()->ep_r));

		// Write statement and witness out (witness to be overwritten)
		// Part of the witness has been written out already
		ep_write_bbs (proof_ptr, Abar);
		proof_ptr += BBS_G1_ELEM_LEN;
		ep_write_bbs (proof_ptr, Bbar);
		proof_ptr += BBS_G1_ELEM_LEN;
		ep_write_bbs (proof_ptr, D);
		proof_ptr += BBS_G1_ELEM_LEN;
		bn_write_bbs (proof_ptr, e);
		proof_ptr += BBS_SCALAR_LEN;
		bn_write_bbs (proof_ptr, r1);
		proof_ptr += BBS_SCALAR_LEN;
		bn_write_bbs (proof_ptr, r3);
		proof_ptr += BBS_SCALAR_LEN;

		// Proof Message 1: Commitment (T1,T2)
		ctx->prf (s, e,  0, 0, ctx->prf_cookie);
		ctx->prf (s, r1, 0, 1, ctx->prf_cookie);
		ctx->prf (s, r3, 0, 2, ctx->prf_cookie);
		ep_mul (ctx->acc.B, D, r3);
		ep_add (ctx->T2,ctx->T2, ctx->acc.B);
		ep_write_bbs (T_buffer + BBS_G1_ELEM_LEN, ctx->T2);
		ep_mul (ctx->T2, D, r1); // Reuse T2 as T1
		ep_mul (ctx->acc.B,  Abar, e);
		ep_add (ctx->T2, ctx->T2, ctx->acc.B);
		ep_write_bbs (T_buffer, ctx->T2);
	}
	RLC_CATCH_ANY {
		// This can happen if the signature is corrupted
		return BBS_ERROR;
	}

	// Proof Message 2: Challenge
	if (! presentation_header) presentation_header_len = 0;
	hash_to_scalar_update (s, &ctx->ch_ctx, proof, 3 * BBS_G1_ELEM_LEN);
	hash_to_scalar_update (s, &ctx->ch_ctx, T_buffer, 2 * BBS_G1_ELEM_LEN);
	hash_to_scalar_update (s, &ctx->ch_ctx, domain_buffer, BBS_SCALAR_LEN);
	uint64_t be_buffer = UINT64_H2BE (presentation_header_len);
	hash_to_scalar_update (s, &ctx->ch_ctx, (uint8_t*) &be_buffer, 8);
        hash_to_scalar_update(s, &ctx->ch_ctx, presentation_header, presentation_header_len);
        hash_to_scalar_finalize(s, &ctx->ch_ctx, challenge,
			(uint8_t *)s->challenge_dst, s->challenge_dst_len);
	RLC_ASSERT(bn_write_bbs (proof + BBS_PROOF_LEN (num_undisclosed) - BBS_SCALAR_LEN, challenge));

        // Proof Message 3: Response
	// We overwrite the witness and reuse e for the tilde values
	proof_ptr = proof + 3 * BBS_G1_ELEM_LEN;
	for (uint64_t witness_idx = 0; witness_idx < num_undisclosed + 3; witness_idx++)
	{
		ctx->prf (s, e, 0, witness_idx, ctx->prf_cookie);

		RLC_ASSERT(
			bn_read_bbs (ctx->acc.msg_scalar, proof_ptr);
			bn_mul (ctx->acc.msg_scalar, ctx->acc.msg_scalar, challenge);
			if(1 == witness_idx || 2 == witness_idx) // r1 and r3 are subtracted
				bn_neg (ctx->acc.msg_scalar, ctx->acc.msg_scalar);
			bn_add (e, e, ctx->acc.msg_scalar);
			bn_mod (e, e, &(core_get ()->ep_r));
			bn_write_bbs (proof_ptr, e);
			proof_ptr += BBS_SCALAR_LEN;
		);
	}

	return BBS_OK;
}

static int
bbs_proof_verify_finalize (
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
	bn_t e, r1, r3, challenge, challenge_prime;
	ep_t D, Abar, Bbar;
	ep2_t W;
	uint8_t domain_buffer[BBS_SCALAR_LEN], T_buffer[2*BBS_G1_ELEM_LEN];
	const uint8_t *proof_ptr  = proof;

	// Sanity check. If any indices for disclosed messages were out of order
	// or invalid, we fail here.
	uint64_t num_undisclosed = num_messages - num_disclosed;
	if (ctx->disclosed_ctr != num_disclosed || ctx->undisclosed_ctr != num_undisclosed)
	{
		return BBS_ERROR;
	}

	bbs_acc_finalize(&ctx->acc, header, header_len);

	RLC_TRY {
		// Write out the domain. We reuse scalar_buffer
		bn_write_bbs (domain_buffer, ctx->acc.msg_scalar);

		// Parse pk
		ep2_read_bbs (W, pk);

		// Parse the remainder of the statement and response
		// The parsing here is injective.
		ep_read_bbs (Abar, proof_ptr);
		proof_ptr += BBS_G1_ELEM_LEN;
		ep_read_bbs (Bbar, proof_ptr);
		proof_ptr += BBS_G1_ELEM_LEN;
		ep_read_bbs (D,    proof_ptr);
		proof_ptr += BBS_G1_ELEM_LEN;
		bn_read_bbs (e,     proof_ptr);
		proof_ptr += BBS_SCALAR_LEN;
		bn_read_bbs (r1,    proof_ptr);
		proof_ptr += BBS_SCALAR_LEN;
		bn_read_bbs (r3,    proof_ptr);
		proof_ptr += BBS_SCALAR_LEN;
		bn_read_bbs (challenge, proof + BBS_PROOF_LEN (num_undisclosed) - BBS_SCALAR_LEN);

		// Proof Message 1: Commitment (recovered from Message 3)
		ep_mul (ctx->acc.B, ctx->acc.B, challenge);
		ep_add (ctx->T2, ctx->T2, ctx->acc.B);
		ep_mul (ctx->acc.B, D, r3);
		ep_add (ctx->T2, ctx->T2, ctx->acc.B);
		ep_write_bbs (T_buffer + BBS_G1_ELEM_LEN, ctx->T2);
		ep_mul (ctx->acc.B, Bbar, challenge);
		ep_mul (ctx->T2, Abar, e);
		ep_add (ctx->acc.B, ctx->acc.B, ctx->T2);
		ep_mul (ctx->T2, D, r1);
		ep_add (ctx->acc.B, ctx->acc.B, ctx->T2);
		ep_write_bbs (T_buffer, ctx->acc.B);
	}
	RLC_CATCH_ANY {
		return BBS_ERROR;
	}

	// Proof Message 2: Challenge
	if (! presentation_header) presentation_header_len = 0;
	hash_to_scalar_update (s, &ctx->ch_ctx, proof, 3 * BBS_G1_ELEM_LEN);
	hash_to_scalar_update (s, &ctx->ch_ctx, T_buffer, 2 * BBS_G1_ELEM_LEN);
	hash_to_scalar_update (s, &ctx->ch_ctx, domain_buffer, BBS_SCALAR_LEN);
	uint64_t be_buffer = UINT64_H2BE (presentation_header_len);
	hash_to_scalar_update (s, &ctx->ch_ctx, (uint8_t*) &be_buffer, 8);
        hash_to_scalar_update(s, &ctx->ch_ctx, presentation_header,
                              presentation_header_len);
        hash_to_scalar_finalize(s, &ctx->ch_ctx, challenge_prime,
                                (uint8_t *)s->challenge_dst,
                                s->challenge_dst_len);

        // Verification Step 1: The PoK was valid
	if (RLC_EQ != bn_cmp (challenge, challenge_prime))
	{
		return BBS_ERROR;
	}

	// Verification Step 2: The original signature was valid
	if(BBS_OK != bbs_check_sig_eqn(Abar, Bbar, W))
	{
		return BBS_ERROR;
	}
	return BBS_OK;
}

static void
bbs_proof_prf (
	bbs_cipher_suite_t *cipher_suite,
	bn_t                out,
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
bbs_proof_gen (
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
	...
	)
{
	va_list ap;
	uint8_t seed[32];
	bbs_proof_gen_ctx ctx;
	uint64_t di_idx = 0;
	uint8_t *msg;
	uint32_t msg_len;
	bool disclosed;

	// Gather randomness. The seed is used for any randomness within this
	// function. In particular, this implies that we do not need to store
	// intermediate derivations. Currently, we derive new values via
	// hash_to_scalar, but we might want to exchange that for
	// something faster later on.
	RLC_TRY {
		rand_bytes (seed, 32);
	}
	RLC_CATCH_ANY {
		return BBS_ERROR;
	}

	va_start (ap, num_messages);
	bbs_proof_gen_init(&ctx, cipher_suite, pk, num_messages, disclosed_indexes_len, bbs_proof_prf, seed);
	for(uint64_t i=0; i< num_messages; i++) {
		disclosed = di_idx < disclosed_indexes_len && disclosed_indexes[di_idx] == i;
		msg = va_arg (ap, uint8_t*);
		msg_len = va_arg (ap, uint32_t);
		bbs_proof_gen_update(&ctx, proof, msg, msg_len, disclosed);
		if(disclosed) di_idx++;
	}
	va_end(ap);

	return bbs_proof_gen_finalize(&ctx, signature, proof, header, header_len, presentation_header, presentation_header_len, num_messages, disclosed_indexes_len);
}


int
bbs_proof_verify (
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
	...
	)
{
	va_list                ap;
	bbs_proof_gen_ctx ctx;
	uint64_t di_idx = 0;
	uint8_t *msg;
	uint32_t msg_len;
	bool disclosed;

	va_start (ap, num_messages);
	bbs_proof_verify_init(&ctx, cipher_suite, pk, num_messages, disclosed_indexes_len);
	for(uint64_t i=0; i< num_messages; i++) {
		disclosed = di_idx < disclosed_indexes_len && disclosed_indexes[di_idx] == i;
		if(disclosed) {
			di_idx++;
			msg = va_arg (ap, uint8_t*);
			msg_len = va_arg (ap, uint32_t);
		}
		bbs_proof_verify_update(&ctx, proof, msg, msg_len, disclosed);
	}
	va_end(ap);

	return bbs_proof_verify_finalize(&ctx, pk, proof, header, header_len, presentation_header, presentation_header_len, num_messages, disclosed_indexes_len);
}

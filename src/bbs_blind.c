#include "bbs_blind.h"
#include "bbs_util.h"
#include "blst.h"

//#include <stdio.h>

#define BBS_BLIND_API_ID_PREFIX "BLIND_"

// forward definitions
int getentropy(void *buffer, size_t length);

int bbs_check_sig_eqn(blst_p1 *A, blst_p1 *B, const bbs_public_key pk);

// omit size from mult call
static inline void
ep_mult_scalar(blst_p1 *out, const blst_p1 *p, const blst_scalar *s, size_t _ignored) {
	(void)_ignored;
	blst_p1_mult(out, p, s->b, 255);
}

// COMMIT
typedef struct {
	const bbs_ciphersuite   *s;
    union bbs_hash_context  hc;
	uint8_t                 generator_ctx[48 + 8];
	blst_p1                 C, Cbar, Q_2;
    blst_scalar             challenge, spb, st;
    bbs_bn_prf              *prf;
	void                    *prf_cookie;
} bbs_commit_ctx;

void
bbs_commit_init(
    bbs_commit_ctx *ctx,
    size_t          num_messages
) {
    uint8_t buffer[BBS_G1_ELEM_LEN];
    uint64_t num_messages_be = htobe64(num_messages);

    // init C and Cbar to infinity
    (void)bbs_memset(&ctx->C.z, 0, sizeof(ctx->C.z));
    (void)bbs_memset(&ctx->Cbar.z, 0, sizeof(ctx->Cbar.z));

	// create blind generators and save q2
	create_generator_init(ctx->s, ctx->generator_ctx, (uint8_t*)BBS_BLIND_API_ID_PREFIX, 6);
	create_generator_next(ctx->s, ctx->generator_ctx, &ctx->Q_2, (uint8_t*)BBS_BLIND_API_ID_PREFIX, 6);

    //{ uint8_t b[48]; blst_p1_compress(b, &ctx->Q_2); printf("Q_2: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // init hash_to_scalar for calculate_blind_challenge
    hash_to_scalar_init(ctx->s, &ctx->hc);
    hash_to_scalar_update(ctx->s, &ctx->hc, (uint8_t*) &num_messages_be, 8);
    ep_write_bbs(buffer, &ctx->Q_2);
    hash_to_scalar_update(ctx->s, &ctx->hc, buffer, BBS_G1_ELEM_LEN);

    // generate random secret_prover_blind and s~
    //{ printf("prf_cookie: "); for(int i=0; i<32; i++) printf("%02x", ((uint8_t*)ctx->prf_cookie)[i]); printf("\n"); }
    ctx->prf(ctx->s, &ctx->spb, 0, 1, ctx->prf_cookie);
    //{ uint8_t b[32]; blst_bendian_from_scalar(b, &ctx->spb); printf("secret_prover_blind: "); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }
    ctx->prf(ctx->s, &ctx->st, 1, 2, ctx->prf_cookie);
    //{ uint8_t b[32]; blst_bendian_from_scalar(b, &ctx->st); printf("s~: "); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }
}

void
commit_update_with_scalar(
    bbs_commit_ctx     *ctx,
    blst_scalar        *sc,
    size_t              msg_index,
    uint8_t            *scalar_tmp
) {
    blst_p1 J_i, tmp;
    uint8_t buffer[BBS_G1_ELEM_LEN];

	create_generator_next(ctx->s, ctx->generator_ctx, &J_i, (uint8_t*)BBS_BLIND_API_ID_PREFIX, 6);

    //{ uint8_t b[48]; blst_p1_compress(b, &J_i); printf("J_%ld: ", msg_index); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // C = ... + J_i * msg_i + ...
    ep_mult_scalar(&tmp, &J_i, sc, 255);
	blst_p1_add_or_double (&ctx->C, &ctx->C, &tmp);

    // at this point sc contains msg_i, save this in output buffer for later for m^_i, this is not an overflow
    blst_lendian_from_scalar(scalar_tmp, sc);

    // Cbar = ... + J_i * m~_i + ...
    ctx->prf(ctx->s, sc, 2, msg_index, ctx->prf_cookie);
    //{ uint8_t b[32]; blst_bendian_from_scalar(b, sc); printf("m~%ld: ", msg_index); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }

    ep_mult_scalar(&tmp, &J_i, sc, 255);
	blst_p1_add_or_double (&ctx->Cbar, &ctx->Cbar, &tmp);

    // update to challenge calculation
	ep_write_bbs(buffer, &J_i);
	hash_to_scalar_update(ctx->s, &ctx->hc, buffer, BBS_G1_ELEM_LEN);
}

void
bbs_commit_update(
	bbs_commit_ctx *ctx,
	const void     *msg,
	size_t          msg_len,
    size_t          msg_index,
    uint8_t        *scalar_tmp
) {
    blst_scalar sc;

    hash_to_scalar(ctx->s, &sc, ctx->s->map_dst, ctx->s->map_dst_len, 1, msg, msg_len);
    commit_update_with_scalar(ctx, &sc, msg_index, scalar_tmp);
}

#define CWP_SCALAR_PTR(cwp, i) \
    ((uint8_t *)(cwp) + BBS_G1_ELEM_LEN + (1 + (i)) * BBS_SCALAR_LEN)

void
bbs_commit_finalize(
    bbs_commit_ctx *ctx,
    uint8_t        *secret_prover_blind,
    uint8_t        *cwp,
    size_t          num_messages
) {
    uint8_t buffer[BBS_G1_ELEM_LEN];
    blst_p1 tmp;
    blst_scalar tmp_sc;

    // C = C + Q_2 * secret_prover_blind
    ep_mult_scalar(&tmp, &ctx->Q_2, &ctx->spb, 255);
	blst_p1_add_or_double(&ctx->C, &ctx->C, &tmp);
    ep_write_bbs(&cwp[0], &ctx->C);

    //{ uint8_t b[48]; blst_p1_compress(b, &ctx->C); printf("C: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // Cbar = Cbar + Q_2 * s~
    ep_mult_scalar(&tmp, &ctx->Q_2, &ctx->st, 255);
	blst_p1_add_or_double(&ctx->Cbar, &ctx->Cbar, &tmp);

    //{ uint8_t b[48]; blst_p1_compress(b, &ctx->Cbar); printf("Cbar: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // finalize challenge calculation with C and Cbar
	hash_to_scalar_update(ctx->s, &ctx->hc, &cwp[0], BBS_G1_ELEM_LEN); // read directly from c_w_p
    ep_write_bbs(buffer, &ctx->Cbar);
	hash_to_scalar_update(ctx->s, &ctx->hc, buffer, BBS_G1_ELEM_LEN);

    const uint8_t *api_id = (uint8_t*) ctx->s->api_id;
	uint8_t api_id_len = ctx->s->api_id_len;
	uint8_t domain_dst[api_id_len + 4];

    bbs_memcpy(domain_dst, api_id, api_id_len);
    bbs_memcpy(domain_dst + api_id_len, "H2S_", 4);

    hash_to_scalar_finalize(ctx->s, &ctx->hc, &ctx->challenge, domain_dst, api_id_len + 4);
    bn_write_bbs(CWP_SCALAR_PTR(cwp, num_messages), &ctx->challenge);

    // s^ = s~ + secret_prover_blind * challenge
    blst_sk_mul_n_check(&tmp_sc, &ctx->spb, &ctx->challenge);
    // write secret_prover_blind to output
    bn_write_bbs(&secret_prover_blind[0], &ctx->spb);

    blst_sk_add_n_check(&ctx->spb, &ctx->st, &tmp_sc);
    // serialize s^
    bn_write_bbs(&cwp[BBS_G1_ELEM_LEN], &ctx->spb);

    // m^_i = m~_i + msg_i * challenge
    for (size_t i = 0; i < num_messages; i++) {
        // get scalar from tmp storage in output
        blst_scalar msg_scalar, mh_i, mt_i;
        blst_scalar_from_lendian(&msg_scalar, CWP_SCALAR_PTR(cwp, i));

        // regenerate m~_i
        ctx->prf(ctx->s, &mt_i, 2, i, ctx->prf_cookie);

        blst_sk_mul_n_check(&tmp_sc, &msg_scalar, &ctx->challenge);
        blst_sk_add_n_check(&mh_i, &mt_i, &tmp_sc);

        // serialize into final output
        bn_write_bbs(CWP_SCALAR_PTR(cwp, i), &mh_i);
    }
}

#undef CWP_SCALAR_PTR

void
bbs_blind_commit_prf(
    const bbs_ciphersuite *cipher_suite,
    blst_scalar           *out,
    uint8_t                input_type,
    uint64_t               input,
    void                  *seed
) {
	// All these have length 17
	static uint8_t *prf_dsts[] = {
		(uint8_t*) "random spb scalar",
		(uint8_t*) "random stl scalar",
		(uint8_t*) "random msg scalar",
	};

    hash_to_scalar(cipher_suite, out, prf_dsts[input_type], 17, 2, seed, (size_t)32, &input, (size_t)8);
}

int
bbs_blind_commit_with_nym_inner(
    const bbs_ciphersuite  *cipher_suite,
    uint8_t                *commitment_with_proof,
    uint8_t                *secret_prover_blind,
    size_t                  num_messages,
    const void *const      *messages,
    const size_t           *messages_lens,
    size_t                  num_prover_nyms,
    const void *const      *prover_nyms,
    bbs_bn_prf              prf,
    void                   *prf_cookie
);

int
bbs_blind_commit(
    const bbs_ciphersuite  *cipher_suite,
    void                   *commitment_with_proof,   // OUT
    uint8_t                *secret_prover_blind,     // OUT
    size_t                  num_messages,
    const void *const      *messages,
    const size_t           *message_lens
) {
    uint8_t seed[32];
    getentropy(seed, sizeof(seed));
    return bbs_blind_commit_with_nym_inner(
        cipher_suite,
        commitment_with_proof,
        secret_prover_blind,
        num_messages,
        messages,
        message_lens,
        0,
        NULL,
        bbs_blind_commit_prf,
        seed
    );
}

// SIGNATURE

int
deserialize_and_verify_commitment(
    const bbs_ciphersuite  *s,
    const uint8_t          *commitment_with_proof,
    size_t                  commitment_with_proof_len,
    blst_p1                *commitment,             // OUT
    size_t                 *num_messages            // OUT
) {
    union bbs_hash_context hc;

    blst_scalar s_hat, challenge_proof, challenge_verify, m_h;
    blst_p1 Cbar, Q_2, J_i, tmp;
	uint8_t generator_ctx[48 + 8], buf[BBS_G1_ELEM_LEN];

    // empty commitment is not invalid
    if (commitment_with_proof == NULL && commitment_with_proof_len == 0) {
        bbs_memset(&commitment->z, 0, sizeof(commitment->z));
        *num_messages = 0;
        return BBS_OK;
    }

    *num_messages =
        (commitment_with_proof_len - BBS_BLIND_COMMITMENT_WITH_PROOF_BASE_LEN) / BBS_SCALAR_LEN;

    // init Cbar to inf
    (void)bbs_memset(&Cbar.z, 0, sizeof(Cbar.z));

    // commitment_with_proof = (commitment, (s^, (m^_1, ..., m^_M), challenge))
    // read s^ and challenge from proof
    bn_read_bbs(&s_hat, &commitment_with_proof[BBS_G1_ELEM_LEN]);
    bn_read_bbs(&challenge_proof, &commitment_with_proof[commitment_with_proof_len - BBS_SCALAR_LEN]);

    //{ uint8_t b[32]; blst_bendian_from_scalar(b, &s_hat); printf("s^: "); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }
    //{ uint8_t b[32]; blst_bendian_from_scalar(b, &challenge_proof); printf("challenge_proof: "); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }

    // init generators
    create_generator_init(s, generator_ctx, (uint8_t*)BBS_BLIND_API_ID_PREFIX, 6);
	create_generator_next(s, generator_ctx, &Q_2, (uint8_t*)BBS_BLIND_API_ID_PREFIX, 6);

    //{ uint8_t b[48]; blst_p1_compress(b, &Q_2); printf("Q_2: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // seed the challenge hash with (num_messages || Q_2 || ...)
    uint64_t n_be = htobe64(*num_messages);
    hash_to_scalar_init(s, &hc);
    hash_to_scalar_update(s, &hc, &n_be, 8);
    ep_write_bbs(buf, &Q_2);
    hash_to_scalar_update(s, &hc, buf, BBS_G1_ELEM_LEN);

    // calculate challenge_verify and Cbar
    for (size_t i = 0; i < *num_messages; i++) {
        // read m^_i and create next generator J_i
        size_t off = BBS_G1_ELEM_LEN + BBS_SCALAR_LEN + i * BBS_SCALAR_LEN;
        bn_read_bbs(&m_h, commitment_with_proof + off);
        create_generator_next(s, generator_ctx, &J_i, (uint8_t *)BBS_BLIND_API_ID_PREFIX, 6);

        // Cbar = Cbar + J_i * m^_i
        ep_mult_scalar(&tmp, &J_i, &m_h, 255);
        blst_p1_add_or_double(&Cbar, &Cbar, &tmp);

        // serialize generator J_i and add to challenge_verify calculation
        ep_write_bbs(buf, &J_i);
        hash_to_scalar_update(s, &hc, buf, BBS_G1_ELEM_LEN);
    }

    // Cbar = Cbar + Q_2 * s^
    ep_mult_scalar(&tmp, &Q_2, &s_hat, 255);
    blst_p1_add_or_double(&Cbar, &Cbar, &tmp);

    // Cbar = Cbar + C * (-challenge_proof)
    ep_read_bbs(commitment, commitment_with_proof);
    ep_mult_scalar(&tmp, commitment, &challenge_proof, 255);
    blst_p1_cneg(&tmp, 1);
    blst_p1_add_or_double(&Cbar, &Cbar, &tmp);

    // finalize challenge hash ( ... || C || Cbar)
    ep_write_bbs(buf, commitment);
    hash_to_scalar_update(s, &hc, buf, BBS_G1_ELEM_LEN);
    ep_write_bbs(buf, &Cbar);
    hash_to_scalar_update(s, &hc, buf, BBS_G1_ELEM_LEN);

    // could be refactored to use already existing generator_ctx buffer
	uint8_t domain_dst[s->api_id_len + 4];
    bbs_memcpy(domain_dst, s->api_id, s->api_id_len);
    bbs_memcpy(domain_dst + s->api_id_len, "H2S_", 4);
    hash_to_scalar_finalize(s, &hc, &challenge_verify, domain_dst, s->api_id_len + 4);

    unsigned int diff = 0;
    for (int i = 0; i < BBS_SCALAR_LEN; i++)
        diff |= challenge_proof.b[i] ^ challenge_verify.b[i];

    // returns BBS_OK if all bits are equal and BBS_ERROR if they're not
    return diff ? BBS_ERROR : BBS_OK;
}

int
bbs_blind_sign(
    const bbs_ciphersuite  *s,
    const bbs_secret_key    sk,
    const bbs_public_key    pk,
    bbs_signature           out,                     // OUT
    const void             *header,
    size_t                  header_len,
    const void             *commitment_with_proof,
    size_t                  commitment_with_proof_len,
    size_t                  num_messages,
    const void *const      *messages,
    const size_t           *message_lens
) {
	union bbs_hash_context h_ctx;

    uint8_t generator_ctx[48 + 8], buf[BBS_G1_ELEM_LEN];
    blst_p1 commitment, B, Q_1, H_i, res;
    blst_scalar tmp, sk_n;
    size_t m = 0;

    if (deserialize_and_verify_commitment(
            s,
            commitment_with_proof,
            commitment_with_proof_len,
            &commitment,
            &m) != BBS_OK) {
        return BBS_ERROR;
    }

    //{ uint8_t b[48]; blst_p1_compress(b, &commitment); printf("commitment: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

	// calc Q_1 and save Q_1
	create_generator_init(s, generator_ctx, nullptr, 0);
	create_generator_next(s, generator_ctx, &Q_1, nullptr, 0);

    // init B to P1
    ep_read_bbs(&B, s->p1);

    // init domain calculation with pk and Q_1
    //printf("initialising domain calculation with %llu messages\n", num_messages + 1 + m);
    calculate_domain_init(s, &h_ctx, pk, num_messages + 1 + m); // generators + Q_2 + blind_generators
    calculate_domain_update(s, &h_ctx, &Q_1);

    for (size_t i = 0; i < num_messages; i++) {
        // get next generator and convert message to scalar
	    create_generator_next(s, generator_ctx, &H_i, nullptr, 0);
        hash_to_scalar(s, &tmp, s->map_dst, s->map_dst_len, 1, messages[i], message_lens[i]);

        //{ uint8_t b[48]; blst_p1_compress(b, &H_i); printf("H_i: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }
        //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("msg_i: "); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }

        // B = B + H_i * msg_i
	    ep_mult_scalar(&res, &H_i, &tmp, 255);
	    blst_p1_add_or_double(&B, &B, &res);

        // update domain calculation
        calculate_domain_update(s, &h_ctx, &H_i);
    }

    // B = B + commitment
    blst_p1_add_or_double(&B, &B, &commitment);

    //{ uint8_t b[48]; blst_p1_compress(b, &B); printf("B (p1+c): "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // init blind_generators, reuse context
    bbs_memset(generator_ctx, 0, 48 + 8);
    create_generator_init(s, generator_ctx, (uint8_t*)BBS_BLIND_API_ID_PREFIX, 6);
	create_generator_next(s, generator_ctx, &H_i, (uint8_t*)BBS_BLIND_API_ID_PREFIX, 6);

    // add Q_2 to domain calculation
    calculate_domain_update(s, &h_ctx, &H_i);

    for (size_t i = 0; i < m; i++) {
        // update domain calculation with blind generators
	    create_generator_next(s, generator_ctx, &H_i, (uint8_t*)BBS_BLIND_API_ID_PREFIX, 6);
        //{ uint8_t b[48]; blst_p1_compress(b, &H_i); printf("J_i: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }
        calculate_domain_update(s, &h_ctx, &H_i);
    }

    calculate_domain_finalize(s, &h_ctx, &tmp, header, header_len);

    //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("domain: "); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }

    // B = B + Q_1 * domain
	ep_mult_scalar(&res, &Q_1, &tmp, 255);
    blst_p1_add_or_double(&B, &B, &res);

    //{ uint8_t b[48]; blst_p1_compress(b, &B); printf("B: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // e = hash_to_scalar(SK || B)
    uint8_t dst[s->api_id_len + 4];
    bbs_memcpy(dst, s->api_id, s->api_id_len);
    bbs_memcpy(dst + s->api_id_len, "H2S_", 4);

    ep_write_bbs(buf, &B);
    hash_to_scalar_init(s, &h_ctx);
    hash_to_scalar_update(s, &h_ctx, sk, BBS_SK_LEN);
    hash_to_scalar_update(s, &h_ctx, buf, BBS_G1_ELEM_LEN);
    hash_to_scalar_finalize(s, &h_ctx, &tmp, dst, s->api_id_len + 4);

    //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("e: "); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }

    // A = B * (1 / (SK + e))
    // tmp contains e, B gets reused for A
    if(BBS_OK != bn_read_bbs(&sk_n, sk)) return BBS_ERROR;
	blst_sk_add_n_check(&sk_n, &sk_n, &tmp); // sk_n reused
	blst_sk_inverse(&sk_n, &sk_n);
	ep_mult_scalar(&B, &B, &sk_n, 255);

	// serialize (A,e)
	ep_write_bbs(out, &B);
	bn_write_bbs(out + BBS_G1_ELEM_LEN, &tmp);

    return BBS_OK;
}

int
bbs_blind_verify(
    const bbs_ciphersuite  *s,
    const bbs_public_key    pk,
    const bbs_signature     signature,
    const void             *header,
    size_t                  header_len,
    size_t                  num_messages,
    const void *const      *messages,
    const size_t           *message_lens,
    size_t                  num_committed_messages,
    const void *const      *committed_messages,
    const size_t           *committed_message_lens,
    const uint8_t          *secret_prover_blind      // optional, NULL = zero
) {
    union bbs_hash_context h_ctx;

    // prepare_parameters essentially does this
    // message_scalars = msg_0, ..., msg_L, secret_prover_blind, c_msg_0, ..., c_msg_L
    // generators = Q_1, H_0, ..., H_L, Q_2, J_0, ..., J_L
    // Q_1 is treated seperately and then every generator maps to a scalar, H_i to msg_i, Q_2 to secret_prover_blind, J_i to c_msg_i

    uint8_t generator_ctx[48 + 8];
    blst_scalar tmp;
    blst_p1 B, Q_1, H_i, res;

    // init B to P1
    ep_read_bbs(&B, s->p1);

    // calc Q_1 and save Q_1
	create_generator_init(s, generator_ctx, nullptr, 0);
	create_generator_next(s, generator_ctx, &Q_1, nullptr, 0);

    // init domain calculation with pk and Q_1
    //printf("initialising domaing calculation with %llu messages\n", num_messages + 1 + num_commited_messages);
    calculate_domain_init(s, &h_ctx, pk, num_messages + 1 + num_committed_messages); // generators + Q_2 + blind_generators
    calculate_domain_update(s, &h_ctx, &Q_1);

    for(size_t i = 0; i < num_messages; i++) {
        // get next generator and convert message to scalar
	    create_generator_next(s, generator_ctx, &H_i, nullptr, 0);
        hash_to_scalar(s, &tmp, s->map_dst, s->map_dst_len, 1, messages[i], message_lens[i]);

        //{ uint8_t b[48]; blst_p1_compress(b, &H_i); printf("H_i: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }
        //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("msg_i: "); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }

        // B = B + H_i * msg_i
	    ep_mult_scalar(&res, &H_i, &tmp, 255);
	    blst_p1_add_or_double(&B, &B, &res);

        // update domain calculation
        calculate_domain_update(s, &h_ctx, &H_i);
    }

    // init blind_generators, reuse context
    bbs_memset(generator_ctx, 0, 48 + 8);
    create_generator_init(s, generator_ctx, (uint8_t*)BBS_BLIND_API_ID_PREFIX, 6);
	create_generator_next(s, generator_ctx, &H_i, (uint8_t*)BBS_BLIND_API_ID_PREFIX, 6);

    // add Q_2 to domain calculation
    calculate_domain_update(s, &h_ctx, &H_i);

    // B = B + Q_2 * secret_prover_blind
    // dont return on an invalid secret_prover_blind, it defaults to 0
    if (BBS_OK != bn_read_bbs(&tmp, secret_prover_blind)) bbs_memset(&tmp, 0, sizeof(tmp));
    ep_mult_scalar(&res, &H_i, &tmp, 255);
    blst_p1_add_or_double(&B, &B, &res);

    for (size_t i = 0; i < num_committed_messages; i++) {
        // get next generator and convert commited message to scalar
	    create_generator_next(s, generator_ctx, &H_i, (uint8_t*)BBS_BLIND_API_ID_PREFIX, 6);
        hash_to_scalar(s, &tmp, s->map_dst, s->map_dst_len, 1, committed_messages[i], committed_message_lens[i]);

        // B = B + J_i * c_msg_i
	    ep_mult_scalar(&res, &H_i, &tmp, 255);
	    blst_p1_add_or_double(&B, &B, &res);

        // update domain calculation
        calculate_domain_update(s, &h_ctx, &H_i);
    }

    calculate_domain_finalize(s, &h_ctx, &tmp, header, header_len);

    //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("domain: "); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }

    // B = B + Q_1 * domain
	ep_mult_scalar(&res, &Q_1, &tmp, 255);
    blst_p1_add_or_double(&B, &B, &res);

    //{ uint8_t b[48]; blst_p1_compress(b, &B); printf("B: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // Reuse Q_1 as A, tmp as e, H_i as A*e
	if(BBS_OK != ep_read_bbs(&Q_1, signature)) return BBS_ERROR;
	if(BBS_OK != bn_read_bbs(&tmp, signature + BBS_G1_ELEM_LEN)) return BBS_ERROR;
	ep_mult_scalar(&H_i, &Q_1, &tmp, 255);
	blst_p1_cneg(&H_i, 1);
	blst_p1_add_or_double(&B, &B, &H_i);

    //{ printf("pk: "); for(int i=0; i<96; i++) printf("%02x", pk[i]); printf("\n"); }

    return bbs_check_sig_eqn(&Q_1, &B, pk);
}

// PROOFS

// ptr to the i-th undisclosed scalar in the proof
#define PROOF_SCALAR_PTR(proof, i) \
    ((uint8_t *)(proof) + 3 * BBS_G1_ELEM_LEN + (3 + (i)) * BBS_SCALAR_LEN)

int
bbs_blind_proof_gen_inner(
    const bbs_ciphersuite  *s,
    const bbs_public_key    pk,
    const bbs_signature     signature,
    void                   *proof,                   // output
    const void             *header,
    size_t                  header_len,
    const void             *presentation_header,
    size_t                  presentation_header_len,
    size_t                  num_messages,
    const void *const      *messages,
    const size_t           *message_lens,
    size_t                  num_committed_messages,
    const void *const      *committed_messages,
    const size_t           *committed_message_lens,
    size_t                  num_disclosed_indexes,
    const size_t           *disclosed_indexes,
    size_t                  num_disclosed_committed_indexes,
    const size_t           *disclosed_committed_indexes,
    const uint8_t          *secret_prover_blind,     // optional, NULL = zero
    bbs_bn_prf              prf,
    void                   *prf_cookie
) {
    if (num_disclosed_indexes > num_messages) return BBS_ERROR;
    if (num_disclosed_committed_indexes > num_committed_messages) return BBS_ERROR;

    // prepare_parameters essentially does this
    // message_scalars = msg_0, ..., msg_L, secret_prover_blind, c_msg_0, ..., c_msg_L
    // generators = Q_1, H_0, ..., H_L, Q_2, J_0, ..., J_L
    // Q_1 is treated seperately and then every generator maps to a scalar, H_i to msg_i, Q_2 to secret_prover_blind, J_i to c_msg_i

    // indexes is essentially disclosed_indexes + [for i in disclosed_commitment_indexes: indexes.append(j + L + 1)]

    union bbs_hash_context d_ctx; // domain_hash_context
    union bbs_hash_context c_ctx; // challenge_hash_context

    uint8_t generator_ctx[48 + 8], sbuf[BBS_G1_ELEM_LEN];
    blst_p1 B, Q_1, H_i, D, Abar, Bbar, T1, T2, res;
    blst_scalar domain, tmp, z;
    size_t disclosed_idx = 0, undisclosed_idx = 0;

    // init T2, pseudonym
    (void)bbs_memset(&T2.z, 0, sizeof(T2.z));

    // init B to P1
    ep_read_bbs(&B, s->p1);

    //printf("init domain calc in proof init with n = %llu\n", num_messages + 1 + num_commited_messages);
    calculate_domain_init(s, &d_ctx, pk, num_messages + 1 + num_committed_messages);

    // init challenge calculation
    uint64_t be_buffer = htobe64(num_disclosed_indexes + num_disclosed_committed_indexes);
    hash_to_scalar_init(s, &c_ctx);
	hash_to_scalar_update(s, &c_ctx, &be_buffer, 8);
    //printf("init challenge calc with %ld disclosed messages\n", disclosed_indexes_len + disclosed_commitment_indexes_len);

    // calc Q_1 and save Q_1
	create_generator_init(s, generator_ctx, nullptr, 0);
	create_generator_next(s, generator_ctx, &Q_1, nullptr, 0);
    calculate_domain_update(s, &d_ctx, &Q_1);

    // loop over messages
    for (size_t i = 0; i < num_messages; i++) {
        bool is_disclosed = (disclosed_idx < num_disclosed_indexes && disclosed_indexes[disclosed_idx] == i);
        if (is_disclosed) disclosed_idx++;

        // get next generator and convert message to scalar
	    create_generator_next(s, generator_ctx, &H_i, nullptr, 0);
        hash_to_scalar(s, &tmp, s->map_dst, s->map_dst_len, 1, messages[i], message_lens[i]);

        // B = B + H_i * msg_i
	    ep_mult_scalar(&res, &H_i, &tmp, 255);
	    blst_p1_add_or_double(&B, &B, &res);

        // save message to proof and undisclosed ptr, if disclosed it will get overwritten eventually
        uint8_t *ptr = PROOF_SCALAR_PTR(proof, undisclosed_idx);
        //printf("writing msg scalar at offset: %ld\n", 3 * BBS_G1_ELEM_LEN + (3 + undisclosed_idx) * BBS_SCALAR_LEN);
        bn_write_bbs(ptr, &tmp);

        if (is_disclosed) {
            // message disclosed, update challenge
            //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("discl. msg scalar (m_%lld): ", i); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }
            uint64_t be_buffer = htobe64(i);
		    hash_to_scalar_update(s, &c_ctx, &be_buffer, 8);
		    hash_to_scalar_update(s, &c_ctx, ptr, BBS_SCALAR_LEN);
        } else {
            // if undisclosed: T2 = T2 + H_ji * m~_ji
            prf(s, &tmp, 1, undisclosed_idx++, prf_cookie);
            //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("undiscl. msg random scalar (m~_j%ld): ", prf_undisclosed_msg_index); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }

            // T2 = T2 + H_ji * m~_ji
	        ep_mult_scalar(&res, &H_i, &tmp, 255);
	        blst_p1_add_or_double(&T2, &T2, &res);
        }

        //{ uint8_t b[48]; blst_p1_compress(b, &H_i); printf("H_i: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }
        // update domain calculation
        calculate_domain_update(s, &d_ctx, &H_i);
    }

    // init blind_generators, reuse context
    bbs_memset(generator_ctx, 0, 48 + 8);
    create_generator_init(s, generator_ctx, (uint8_t*)BBS_BLIND_API_ID_PREFIX, 6);
	create_generator_next(s, generator_ctx, &H_i, (uint8_t*)BBS_BLIND_API_ID_PREFIX, 6);
    calculate_domain_update(s, &d_ctx, &H_i);

    // B = B + H_i * msg_i (special case: H_i = Q_2, msg_i = secret_prover_blind)
    if (BBS_OK != bn_read_bbs(&tmp, secret_prover_blind))  bbs_memset(&tmp, 0, sizeof(tmp));
	ep_mult_scalar(&res, &H_i, &tmp, 255);
	blst_p1_add_or_double(&B, &B, &res);

    // secret_prover_blind counts as undisclosed, pre-save to proof for proof finalization
    //printf("writing msg scalar (spb) at offset: %ld\n", 3 * BBS_G1_ELEM_LEN + (3 + prf_undisclosed_msg_index) * BBS_SCALAR_LEN);
    bn_write_bbs((uint8_t*)proof + 3 * BBS_G1_ELEM_LEN + (3 + undisclosed_idx) * BBS_SCALAR_LEN, &tmp);

    // secret_prover_blind counts as undisclosed so its accumulated onto T2
    prf(s, &tmp, 1, undisclosed_idx++, prf_cookie);
    //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("m~_%ld: ", prf_undisclosed_msg_index); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }
    // T2 = T2 + H_ji * m~_ji (H_ji = Q_2, m^_ji = secret_prover_blind)
	ep_mult_scalar(&res, &H_i, &tmp, 255);
	blst_p1_add_or_double(&T2, &T2, &res);

    // loop over commited messages
    disclosed_idx = 0;
    for (size_t i = 0; i < num_committed_messages; i++) {
        bool is_disclosed = (disclosed_idx < num_disclosed_committed_indexes &&
                             disclosed_committed_indexes[disclosed_idx] == i);
        if (is_disclosed) disclosed_idx++;

        // get next generator and convert commited message to scalar
        create_generator_next(s, generator_ctx, &H_i, (uint8_t*)BBS_BLIND_API_ID_PREFIX, 6);
        hash_to_scalar(s, &tmp, s->map_dst, s->map_dst_len, 1, committed_messages[i], committed_message_lens[i]);

        // B = B + J_i * c_msg_i
	    ep_mult_scalar(&res, &H_i, &tmp, 255);
	    blst_p1_add_or_double(&B, &B, &res);

        // save commited message to proof, if disclosed it will get overwritten eventually
        uint8_t *ptr = PROOF_SCALAR_PTR(proof, undisclosed_idx);
        //printf("writing commited msg scalar at offset: %ld\n", 3 * BBS_G1_ELEM_LEN + (3 + undisclosed_idx) * BBS_SCALAR_LEN);
        bn_write_bbs(ptr, &tmp);

        if (is_disclosed) {
            // commited message disclosed, update challenge, disclosed message index must account for normal messages too
            // remember, the indexes for the commited_messages are calculated as such: [for i in disclosed_commitment_indexes: indexes.append(j + L + 1)] (L = num_messages)
            //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("discl. msg scalar (m_%lld): ", num_messages + i + 1); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }
            uint64_t be_buffer = htobe64(num_messages + i + 1);
		    hash_to_scalar_update(s, &c_ctx, &be_buffer, 8);
		    hash_to_scalar_update(s, &c_ctx, ptr, BBS_SCALAR_LEN);
        } else {
            // if undisclosed: T2 = T2 + H_ji * m~_ji
            prf(s, &tmp, 1, undisclosed_idx++, prf_cookie);

            //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("undiscl. commited msg random scalar (m~_j%ld): ", prf_undisclosed_msg_index); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }

            // T2 = T2 + H_ji * m~_ji
	        ep_mult_scalar(&res, &H_i, &tmp, 255);
	        blst_p1_add_or_double(&T2, &T2, &res);
        }

        //{ uint8_t b[48]; blst_p1_compress(b, &H_i); printf("H_i: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }
        // update domain calculation
        calculate_domain_update(s, &d_ctx, &H_i);
    }

    // B = B + Q_1 * domain
    calculate_domain_finalize(s, &d_ctx, &domain, header, header_len);
	ep_mult_scalar(&res, &Q_1, &domain, 255);
    blst_p1_add_or_double(&B, &B, &res);

    //{ uint8_t b[32]; blst_bendian_from_scalar(b, &domain); printf("domain: "); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }
    //{ uint8_t b[48]; blst_p1_compress(b, &B); printf("B: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // generate r2, D = B * r2
    prf(s, &tmp, 0, 1, prf_cookie); // r2
    blst_sk_inverse(&z, &tmp);
    bn_write_bbs((uint8_t*)proof + 3 * BBS_G1_ELEM_LEN + 2 * BBS_SCALAR_LEN, &z); // write r3 into output
    //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("r2: "); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }
	ep_mult_scalar(&D, &B, &tmp, 255);

    //{ uint8_t b[48]; blst_p1_compress(b, &D); printf("D: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // write D to output proof
    ep_write_bbs((uint8_t*)proof + 2 * BBS_G1_ELEM_LEN, &D);

    // read in A from signature, Abar = A * (r1 * r2)
    if (BBS_OK != ep_read_bbs(&Abar, signature)) return BBS_ERROR; // Reuse Abar as A
    ep_mult_scalar(&Abar, &Abar, &tmp, 255); // Abar = A * r2
    prf(s, &tmp, 0, 0, prf_cookie); // r1
    ep_mult_scalar(&Abar, &Abar, &tmp, 255); // Abar = A * r1

    //{ uint8_t b[48]; blst_p1_compress(b, &Abar); printf("Abar: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // write Abar to output proof and add to challenge calculation
    ep_write_bbs(proof, &Abar);
    hash_to_scalar_update(s, &c_ctx, proof, BBS_G1_ELEM_LEN);

    // Bbar = D * r1 - Abar * e
    ep_mult_scalar(&Bbar, &D, &tmp, 255); // Bbar = D * r1
    bn_write_bbs((uint8_t*)proof + 3 * BBS_G1_ELEM_LEN + BBS_SCALAR_LEN, &tmp); // write r1 into output
    if (BBS_OK != bn_read_bbs(&tmp, signature + BBS_G1_ELEM_LEN)) return BBS_ERROR; // overwrite tmp as e
    ep_mult_scalar(&res, &Abar, &tmp, 255); // res = Abar * e
    blst_p1_cneg(&res, 1); // res = -res
    blst_p1_add_or_double(&Bbar, &Bbar, &res);

    bn_write_bbs((uint8_t*)proof + 3 * BBS_G1_ELEM_LEN, &tmp); // write e into output

    //{ uint8_t b[48]; blst_p1_compress(b, &Bbar); printf("Bbar: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // write Bbar to output proof and add to challenge calculation
    ep_write_bbs((uint8_t*)proof + BBS_G1_ELEM_LEN, &Bbar);
    hash_to_scalar_update(s, &c_ctx, (uint8_t*)proof + BBS_G1_ELEM_LEN, BBS_G1_ELEM_LEN);

    // add D to challenge calculation
    hash_to_scalar_update(s, &c_ctx, (uint8_t*)proof + 2 * BBS_G1_ELEM_LEN, BBS_G1_ELEM_LEN);

    prf(s, &tmp, 0, 2, prf_cookie); // e~
    ep_mult_scalar(&T1, &Abar, &tmp, 255); // T1 = Abar * e~
    prf(s, &tmp, 0, 3, prf_cookie); // r1~
    ep_mult_scalar(&res, &D, &tmp, 255); // res = D * r1~
    blst_p1_add_or_double(&T1, &T1, &res);

    //{ uint8_t b[48]; blst_p1_compress(b, &T1); printf("T1: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // add T1 to challenge calculation
    ep_write_bbs(sbuf, &T1);
    hash_to_scalar_update(s, &c_ctx, sbuf, BBS_G1_ELEM_LEN);

    prf(s, &tmp, 0, 4, prf_cookie); // r3~
    ep_mult_scalar(&res, &D, &tmp, 255); // res = D * r3~
    blst_p1_add_or_double(&T2, &T2, &res);

    //{ uint8_t b[48]; blst_p1_compress(b, &T2); printf("T2: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // add T2 to challenge calculation
    ep_write_bbs(sbuf, &T2);
    hash_to_scalar_update(s, &c_ctx, sbuf, BBS_G1_ELEM_LEN);

    // add domain to challenge calculation
    bn_write_bbs(sbuf, &domain);
    hash_to_scalar_update(s, &c_ctx, sbuf, BBS_SCALAR_LEN);

    // add (I2OSP(length(ph), 8) || ph) to challenge calculation
    be_buffer = htobe64(presentation_header_len);
    hash_to_scalar_update(s, &c_ctx, &be_buffer, 8);
    hash_to_scalar_update(s, &c_ctx, presentation_header, presentation_header_len);

    // finalize challenge calculation
    hash_to_scalar_finalize(s, &c_ctx, &tmp, s->challenge_dst, s->challenge_dst_len);

    //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("challenge: "); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }

    //printf("writing challenge at offset: %lu\n", 3 * BBS_G1_ELEM_LEN + 3 * BBS_SCALAR_LEN + prf_undisclosed_msg_index * BBS_SCALAR_LEN);
    // write challenge into proof
    bn_write_bbs((uint8_t*)proof + 3 * BBS_G1_ELEM_LEN + 3 * BBS_SCALAR_LEN + undisclosed_idx * BBS_SCALAR_LEN, &tmp);

    uint8_t *proof_ptr = (uint8_t*)proof + 3 * BBS_G1_ELEM_LEN;
    // seperate loop for e^, r1^, and r3^
    for (uint64_t i = 0; i < 3; i++) {
        prf(s, &z, 0, i + 2, prf_cookie);
        bn_read_bbs(&domain, proof_ptr);
		blst_sk_mul_n_check(&domain, &domain, &tmp);
        if (i == 0) {
			blst_sk_add_n_check(&z, &z, &domain);
        } else {
			blst_sk_sub_n_check(&z, &z, &domain);
        }
        bn_write_bbs(proof_ptr, &z);
		proof_ptr += BBS_SCALAR_LEN;
    }

	for (uint64_t i = 0; i < undisclosed_idx; i++) {
		prf(s, &z, 1, i, prf_cookie);
		bn_read_bbs(&domain, proof_ptr); // reuse domain var, cannot fail
		blst_sk_mul_n_check(&domain, &domain, &tmp);
		blst_sk_add_n_check(&z, &z, &domain);
		bn_write_bbs(proof_ptr, &z);
		proof_ptr += BBS_SCALAR_LEN;
	}

    return BBS_OK;
}

#undef PROOF_SCALAR_PTR

static void bbs_blind_proof_gen_prf(
	const bbs_ciphersuite  *cipher_suite,
	blst_scalar            *out,
	uint8_t                 input_type,
	uint64_t                input,
	void                   *seed
) {
    // input_type 0: input=0=r1 input=1=r2 input=2=e~ input=3=r1~ input=4=r2~
    // input_type 1: input=i=m~_i

	// All these have length 17
	static uint8_t *prf_dsts[] = {
		(uint8_t*) "random rnd scalar",
		(uint8_t*) "random msg scalar",
	};

    hash_to_scalar(cipher_suite, out, prf_dsts[input_type], 17, 2, seed, (size_t)32, &input, (size_t)8);
}

int bbs_blind_proof_gen(
    const bbs_ciphersuite  *cipher_suite,
    const bbs_public_key    pk,
    const bbs_signature     signature,
    void                   *proof,                   // output
    const void             *header,
    size_t                  header_len,
    const void             *presentation_header,
    size_t                  presentation_header_len,
    size_t                  num_messages,
    const void *const      *messages,
    const size_t           *message_lens,
    size_t                  num_committed_messages,
    const void *const      *committed_messages,
    const size_t           *committed_message_lens,
    size_t                  num_disclosed_indexes,
    const size_t           *disclosed_indexes,
    size_t                  num_disclosed_committed_indexes,
    const size_t           *disclosed_committed_indexes,
    const uint8_t          *secret_prover_blind      // optional, NULL = zero
) {
    int ret = BBS_OK;

    // generate single random seed for random scalar generation
    uint8_t seed[32];
    getentropy(seed, 32);

    ret = bbs_blind_proof_gen_inner(
        cipher_suite,
        pk,
        signature,
        proof,
        header,
	    header_len,
	    presentation_header,
	    presentation_header_len,
        num_messages,
        messages,
        message_lens,
        num_committed_messages,
        committed_messages,
        committed_message_lens,
        num_disclosed_indexes,
        disclosed_indexes,
        num_disclosed_committed_indexes,
        disclosed_committed_indexes,
        secret_prover_blind,
        bbs_blind_proof_gen_prf,
        seed
    );

    return ret;
}

int
bbs_blind_proof_verify(
    const bbs_ciphersuite  *s,
    const bbs_public_key    pk,
    const void             *proof,
    size_t                  proof_len,
    const void             *header,
    size_t                  header_len,
    const void             *presentation_header,
    size_t                  presentation_header_len,
    size_t                  num_signer_known_messages,
    size_t                  num_disclosed_messages,
    const void *const      *disclosed_messages,
    const size_t           *disclosed_message_lens,
    const size_t           *disclosed_indexes,
    size_t                  num_disclosed_committed_messages,
    const void *const      *disclosed_committed_messages,
    const size_t           *disclosed_committed_message_lens,
    const size_t           *disclosed_committed_indexes
) {
    // sanity checks
    const size_t floor = 3 * BBS_G1_ELEM_LEN + 4 * BBS_SCALAR_LEN;
    if (proof_len < floor) return BBS_ERROR;
    if ((proof_len - floor) % BBS_SCALAR_LEN != 0) return BBS_ERROR;

    const size_t U = (proof_len - floor) / BBS_SCALAR_LEN;
    if (U == 0) return BBS_ERROR;

    // L = signer-known messages; M = blind messages (all, disclosed + hidden)
    const size_t L = num_signer_known_messages;
    const size_t M = (num_disclosed_messages + num_disclosed_committed_messages + U - 1) - L;

    union bbs_hash_context d_ctx, c_ctx; // domain_hash context and challenge_hash context
    uint8_t generator_ctx[48 + 8], sbuf[BBS_G1_ELEM_LEN];
    blst_p1 B, Q_1, H_i, Abar, Bbar, T1, T2, res;
    blst_scalar domain, tmp;
    size_t disclosed_idx = 0, undisclosed = 0;

    bbs_memset(&T1.z, 0, sizeof(T1.z));
    bbs_memset(&T2.z, 0, sizeof(T2.z));

    // init B to P1
    ep_read_bbs(&B, s->p1);

    //printf("init domain calc in proof init with n = %lu\n", L + 1 + M);
    calculate_domain_init(s, &d_ctx, pk, L + 1 + M);

    // init challenge calculation
    //printf("init challenge calc with %ld disclosed messages\n", num_disclosed_messages + num_disclosed_committed_messages);
    uint64_t be_buffer = htobe64(num_disclosed_messages + num_disclosed_committed_messages);
    hash_to_scalar_init(s, &c_ctx);
	hash_to_scalar_update(s, &c_ctx, &be_buffer, 8);

    // calc Q_1 and save Q_1
	create_generator_init(s, generator_ctx, nullptr, 0);
	create_generator_next(s, generator_ctx, &Q_1, nullptr, 0);
    calculate_domain_update(s, &d_ctx, &Q_1);

    // base ptr into proof to where commitments start
    const uint8_t *proof_scs = (const uint8_t *)proof + 3 * BBS_G1_ELEM_LEN + 3 * BBS_SCALAR_LEN;

    // loop over disclosed messages
    for (size_t i = 0; i < L; i++) {
        bool is_disclosed = (disclosed_idx < num_disclosed_messages && disclosed_indexes[disclosed_idx] == i);
        if (is_disclosed) disclosed_idx++;

        // get next generator
	    create_generator_next(s, generator_ctx, &H_i, nullptr, 0);
        //{ uint8_t b[48]; blst_p1_compress(b, &H_i); printf("H_i: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

        if (is_disclosed) {
            // convert message to scalar
            hash_to_scalar(s, &tmp, s->map_dst, s->map_dst_len, 1, disclosed_messages[disclosed_idx-1], disclosed_message_lens[disclosed_idx-1]);

            // B = B + H_i * msg_i
	        ep_mult_scalar(&res, &H_i, &tmp, 255);
	        blst_p1_add_or_double(&B, &B, &res);

            // message disclosed, update challenge
            //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("discl. msg scalar (m_%lld): ", i); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }
            uint64_t be_buffer = htobe64(i);
		    hash_to_scalar_update(s, &c_ctx, &be_buffer, 8);

            // update challenge calculation
            bn_write_bbs(sbuf, &tmp);
		    hash_to_scalar_update(s, &c_ctx, sbuf, BBS_SCALAR_LEN);
        } else {
            // read m^_ji from proof
            bn_read_bbs(&tmp, proof_scs + undisclosed++ * BBS_SCALAR_LEN);
            //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("undiscl. msg scalar (m^_j%ld): ", undisclosed_msg_index); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }

            // T2 = T2 + H_ji * m^_ji
	        ep_mult_scalar(&res, &H_i, &tmp, 255);
	        blst_p1_add_or_double(&T2, &T2, &res);
        }

        // update domain calculation
        calculate_domain_update(s, &d_ctx, &H_i);
    }

    // init blind_generators, reuse context, add Q_2 to domain
    bbs_memset(generator_ctx, 0, 48 + 8);
    create_generator_init(s, generator_ctx, (uint8_t*)BBS_BLIND_API_ID_PREFIX, 6);
	create_generator_next(s, generator_ctx, &H_i, (uint8_t*)BBS_BLIND_API_ID_PREFIX, 6);
    calculate_domain_update(s, &d_ctx, &H_i);

    // secret_prover_blind counts as undisclosed so its accumulated onto T2
    bn_read_bbs(&tmp, proof_scs + undisclosed++ * BBS_SCALAR_LEN);
    //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("undiscl. msg scalar (m^_%ld): ", undisclosed_msg_index); for(int i=0; i<32; i++) printf("%02x", b[i]); printf(" (special = secret_prover_blind)\n"); }

    // T2 = T2 + H_ji * m^_ji (H_ji = Q_2, m^_ji = secret_prover_blind)
	ep_mult_scalar(&res, &H_i, &tmp, 255);
	blst_p1_add_or_double(&T2, &T2, &res);

    disclosed_idx = 0;
    for (uint64_t i = 0; i < M; i++) {
        bool is_disclosed = (disclosed_idx < num_disclosed_committed_messages && disclosed_committed_indexes[disclosed_idx] == i);
        if (is_disclosed) disclosed_idx++;

        // get next generator and convert commited message to scalar
        create_generator_next(s, generator_ctx, &H_i, (uint8_t*)BBS_BLIND_API_ID_PREFIX, 6);
        //{ uint8_t b[48]; blst_p1_compress(b, &H_i); printf("J_i: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

        if (is_disclosed) {
            hash_to_scalar(s, &tmp, s->map_dst, s->map_dst_len, 1, disclosed_committed_messages[disclosed_idx-1], disclosed_committed_message_lens[disclosed_idx-1]);

            // B = B + J_i * c_msg_i
            ep_mult_scalar(&res, &H_i, &tmp, 255);
            blst_p1_add_or_double(&B, &B, &res);

            // commited message disclosed, update challenge, disclosed message index must account for normal messages too
            // remember, the indices for the commited_messages are calculated as such: [for i in disclosed_commitment_indexes: indexes.append(j + L + 1)] (L = num_messages)
            //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("discl. msg scalar (m_%lld): ", L + i + 1); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }
            uint64_t be_buffer = htobe64(L + i + 1);
		    hash_to_scalar_update(s, &c_ctx, &be_buffer, 8);

            // update challenge calculation directly from proof
            bn_write_bbs(sbuf, &tmp);
		    hash_to_scalar_update(s, &c_ctx, sbuf, BBS_SCALAR_LEN);
        } else {
            // read m^_ji from proof
            bn_read_bbs(&tmp, proof_scs + undisclosed++ * BBS_SCALAR_LEN);
            //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("undiscl. commited msg random scalar (m^_j%ld): ", undisclosed_msg_index); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }

            // T2 = T2 + H_ji * m^_ji
	        ep_mult_scalar(&res, &H_i, &tmp, 255);
	        blst_p1_add_or_double(&T2, &T2, &res);
        }

        // update domain calculation
        calculate_domain_update(s, &d_ctx, &H_i);
    }

    // ProofChallengeCalculate
    // add (Abar, Bbar, D, ...) directly from proof to challenge
    //{ printf("[challenge add] Abar: "); for(int i=0; i<48; i++) printf("%02x", ((uint8_t*)proof)[i]); printf("\n"); }
    hash_to_scalar_update(s, &c_ctx, (uint8_t*)proof, BBS_G1_ELEM_LEN); // Abar
    //{ printf("[challenge add] Bbar: "); for(int i=48; i<96; i++) printf("%02x", ((uint8_t*)proof)[i]); printf("\n"); }
    hash_to_scalar_update(s, &c_ctx, (uint8_t*)proof + BBS_G1_ELEM_LEN, BBS_G1_ELEM_LEN); // Bbar
    //{ printf("[challenge add] D: "); for(int i=96; i<144; i++) printf("%02x", ((uint8_t*)proof)[i]); printf("\n"); }
    hash_to_scalar_update(s, &c_ctx, (uint8_t*)proof + 2 * BBS_G1_ELEM_LEN, BBS_G1_ELEM_LEN); // D

    // B = B + Q_1 * domain
    calculate_domain_finalize(s, &d_ctx, &domain, header, header_len);
	ep_mult_scalar(&res, &Q_1, &domain, 255);
    blst_p1_add_or_double(&B, &B, &res);

    //{ uint8_t b[32]; blst_bendian_from_scalar(b, &domain); printf("domain: "); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }
    //{ uint8_t b[48]; blst_p1_compress(b, &B); printf("B: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // load challenge
    bn_read_bbs(&tmp, (uint8_t*)proof + proof_len - BBS_SCALAR_LEN);
    //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("(prime) challenge: "); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }

    // T2 = T2 + B * challenge
    ep_mult_scalar(&res, &B, &tmp, 255);
    blst_p1_add_or_double(&T2, &T2, &res);

    // load Bbar
    ep_read_bbs(&Bbar, (uint8_t*)proof + BBS_G1_ELEM_LEN);
    //{ uint8_t b[48]; blst_p1_compress(b, &Bbar); printf("Bbar: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // T1 = T1 + Bbar * challenge
    ep_mult_scalar(&res, &Bbar, &tmp, 255);
    blst_p1_add_or_double(&T1, &T1, &res);

    // load Abar
    ep_read_bbs(&Abar, (uint8_t*)proof);
    //{ uint8_t b[48]; blst_p1_compress(b, &Abar); printf("Abar: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // load e^
    bn_read_bbs(&tmp, (uint8_t*)proof + 3 * BBS_G1_ELEM_LEN);
    //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("e^: "); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }

    // T1 = T1 + Abar * e^
    ep_mult_scalar(&res, &Abar, &tmp, 255);
    blst_p1_add_or_double(&T1, &T1, &res);

    // load D, reuse Q_1
    ep_read_bbs(&Q_1, (uint8_t*)proof + 2 * BBS_G1_ELEM_LEN);
    //{ uint8_t b[48]; blst_p1_compress(b, &Q_1); printf("Abar: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // load r1^
    bn_read_bbs(&tmp, (uint8_t*)proof + 3 * BBS_G1_ELEM_LEN + BBS_SCALAR_LEN);
    //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("r1^: "); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }

    // T1 = T1 + D * r1^
    ep_mult_scalar(&res, &Q_1, &tmp, 255);
    blst_p1_add_or_double(&T1, &T1, &res);
    //{ uint8_t b[48]; blst_p1_compress(b, &T1); printf("T1: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // load r3^
    bn_read_bbs(&tmp, (uint8_t*)proof + 3 * BBS_G1_ELEM_LEN + 2 * BBS_SCALAR_LEN);
    //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("r3^: "); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }

    // T2 = T2 + D * r3^
    ep_mult_scalar(&res, &Q_1, &tmp, 255);
    blst_p1_add_or_double(&T2, &T2, &res);
    //{ uint8_t b[48]; blst_p1_compress(b, &T2); printf("T2: "); for(int i=0; i<48; i++) printf("%02x", b[i]); printf("\n"); }

    // ProofChallengeCalculate
    // add (..., T1, T2, ...) to challenge
    ep_write_bbs(sbuf, &T1);
    //{ printf("[challenge add] T1: "); for(int i=0; i<48; i++) printf("%02x", sbuf[i]); printf("\n"); }
    hash_to_scalar_update(s, &c_ctx, sbuf, BBS_G1_ELEM_LEN);
    ep_write_bbs(sbuf, &T2);
    //{ printf("[challenge add] T2: "); for(int i=0; i<48; i++) printf("%02x", sbuf[i]); printf("\n"); }
    hash_to_scalar_update(s, &c_ctx, sbuf, BBS_G1_ELEM_LEN);

    bn_write_bbs(sbuf, &domain);
    //{ printf("[challenge add] domain: "); for(int i=0; i<32; i++) printf("%02x", sbuf[i]); printf("\n"); }
    hash_to_scalar_update(s, &c_ctx, sbuf, BBS_SCALAR_LEN);

    // add (I2OSP(length(ph), 8) || ph) to challenge calculation
    be_buffer = htobe64(presentation_header_len);
    hash_to_scalar_update(s, &c_ctx, &be_buffer, 8);
    hash_to_scalar_update(s, &c_ctx, presentation_header, presentation_header_len);

    // finalize challenge calculation
    hash_to_scalar_finalize(s, &c_ctx, &tmp, s->challenge_dst, s->challenge_dst_len);
    //{ uint8_t b[32]; blst_bendian_from_scalar(b, &tmp); printf("challenge: "); for(int i=0; i<32; i++) printf("%02x", b[i]); printf("\n"); }

    // VERIFICATION
    bn_write_bbs(sbuf,  &tmp); // tmp = challenge (recalculated)

    uint8_t* challenge_ptr = (uint8_t*)proof + proof_len - BBS_SCALAR_LEN;
    unsigned int err = 0;
    for (int i = 0; i < BBS_SCALAR_LEN; i++)
        err |= sbuf[i] ^ challenge_ptr[i];

    err |= bbs_check_sig_eqn(&Abar, &Bbar, pk);

    return err; // if err = 0 => BBS_OK otherwise BBS_ERROR
}


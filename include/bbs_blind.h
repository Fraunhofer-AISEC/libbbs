/**
 * (C) 2026 Fraunhofer AISEC
 */

/**
 * @file bbs_blind.h
 * @author Christoph Britsch
 * @date 10 March 2026
 * @brief BBS blind signatures. Extends the BBS signature scheme by allowing messages
 * that are unknown to the signer to be signed by including them in a commitment.
 * Considerations from the base BBS scheme, such as keeping the signature secret
 * still apply. For an introduction to BBS, see bbs(7), for an introduction to
 * BBS with blinded messages, see bbs_blind(7).
 */

#ifndef BBS_BLIND_H
#define BBS_BLIND_H

#include "bbs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BBS_BLIND_COMMITMENT_WITH_PROOF_BASE_LEN 112

#define BBS_BLIND_COMMITMENT_LEN(num_committed_messages) \
    BBS_BLIND_COMMITMENT_WITH_PROOF_BASE_LEN + num_committed_messages * 32

#define BBS_BLIND_SECRET_PROVER_BLIND_LEN 32

int bbs_blind_commit(
    const bbs_ciphersuite  *cipher_suite,
    void                   *commitment_with_proof,   // OUT
    uint8_t                *secret_prover_blind,     // OUT
    size_t                  num_messages,
    const void *const      *messages,
    const size_t           *message_lens
);

int bbs_blind_sign(
    const bbs_ciphersuite  *cipher_suite,
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
);

int bbs_blind_verify(
    const bbs_ciphersuite  *cipher_suite,
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
);

int bbs_blind_proof_gen(
    const bbs_ciphersuite  *cipher_suite,
    const bbs_public_key    pk,
    const bbs_signature     signature,
    void                   *proof,                   // OUT
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
);

int bbs_blind_proof_verify(
    const bbs_ciphersuite  *cipher_suite,
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
);

/* Cipher Suites */
extern const bbs_ciphersuite *const bbs_blind_sha256_ciphersuite;
extern const bbs_ciphersuite *const bbs_blind_shake256_ciphersuite;

#ifdef __cplusplus
}
#endif

#endif

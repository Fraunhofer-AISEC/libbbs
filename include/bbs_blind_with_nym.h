/**
 * (C) 2026 Fraunhofer AISEC
 */

/**
 * @file bbs_blind_with_nym.h
 * @author Christoph Britsch
 * @date 14 March 2026
 * @brief BBS blind signatures with per-verifier pseudonyms. Extends blind BBS
 * by binding one or more prover-controlled secrets into the signature, from
 * which a pseudonym is derived per verifier context. The pseudonym is stable
 * for a given prover and context, enabling verifier-controlled linkability
 * without revealing the prover's identity. For an introduction to BBS, see
 * bbs(7), for an introduction to blind BBS, see bbs_blind(7), and for an
 * introduction to per-verifier pseudonyms, see bbs_blind_with_nym(7).
 */

#ifndef BBS_BLIND_WITH_NYM_H
#define BBS_BLIND_WITH_NYM_H

#include "bbs_blind.h"

// TODO add symbols to versions.map file
// TODO use same types and order for len and data fields

#ifdef __cplusplus
extern "C" {
#endif

// TODO revise definitions

/*int bbs_blind_commit_with_nym(
    const bbs_ciphersuite *cipher_suite,
    uint8_t *commitment_with_proof,
    uint8_t *secret_prover_blind,
    uint64_t num_blinded_messages,
    const void *const *messages,
    const size_t *messages_lens,
    uint64_t num_prover_nyms,
    const void *const *prover_nyms
);*/

int bbs_blind_commit_with_nym(
    const bbs_ciphersuite  *cipher_suite,
    void                   *commitment_with_proof,
    uint8_t                *secret_prover_blind,
    size_t                  num_messages,
    const void *const      *messages,
    const size_t           *messages_lens,
    size_t                  num_prover_nyms,
    const void *const      *prover_nyms
);

int bbs_blind_sign_with_nym(
    const bbs_ciphersuite *cipher_suite,
    const bbs_secret_key sk,
    const bbs_public_key pk,
    const void* signer_nym_entropy,
    uint64_t length_nym_vector,
    bbs_signature signature,
    uint64_t commitment_with_proof_length,
    const uint8_t *commitment_with_proof,
    uint64_t header_len,
    const uint8_t *header,
    uint64_t num_messages,
    const void *const *messages,
    const size_t *messages_lens
);

int bbs_blind_verify_with_nym(
    const bbs_ciphersuite *cipher_suite,
    const bbs_public_key pk,
    const bbs_signature signature,
    uint64_t header_len,
    const uint8_t *header,
    uint64_t num_messages,
    const void *const *messages,
    const size_t *messages_lens,
    uint64_t num_commited_messages,
    const void *const *comitted_messages,
    const size_t *comitted_messages_lens,
    const uint8_t *secret_prover_blind,
    const void* signer_nym_entropy,
    uint64_t num_pseudonyms,
    const void *const *prover_nyms,
    void *const *nym_secrets
);

int bbs_blind_proof_gen_with_nym(
    const bbs_ciphersuite *cipher_suite,
    const bbs_public_key pk,
    const bbs_signature signature,
    void *proof,
    const void *header,
	size_t header_len,
	const void *presentation_header,
	size_t presentation_header_len,
    uint64_t num_nym_secrets,
    const void *const *nym_secrets,
    const void *context_id,
    size_t context_id_len,
    uint64_t num_messages,
    const void *const *messages,
    const size_t *messages_lens,
    uint64_t num_commited_messages,
    const void *const *comitted_messages,
    const size_t *comitted_messages_lens,
    const size_t *disclosed_indexes,
	size_t disclosed_indexes_len,
    const size_t *disclosed_commitment_indexes,
	size_t disclosed_commitment_indexes_len,
    const uint8_t *secret_prover_blind
);

int bbs_blind_proof_verify_with_nym(
    const bbs_ciphersuite *cipher_suite,
    const bbs_public_key pk,
    const void *proof,
	size_t proof_len,
    const uint8_t *pseudonym,
    const void *context_id,
    size_t context_id_len,
    uint64_t length_nym_vector,
    uint64_t num_signer_known_messages,
    const void *header,
	size_t header_len,
	const void *presentation_header,
	size_t presentation_header_len,
    const void *const *disclosed_messages,
    const size_t *disclosed_messages_lens,
    uint64_t num_disclosed_messages,
    const void *const *disclosed_committed_messages,
    const size_t *disclosed_comitted_messages_lens,
    uint64_t num_disclosed_committed_messages,
    const size_t *disclosed_indexes,
	size_t num_disclosed_indexes,
    const size_t *disclosed_committed_indexes,
	size_t num_disclosed_committed_indexes
);

/* Cipher Suites */
extern const bbs_ciphersuite *const bbs_blind_nym_sha256_ciphersuite;
extern const bbs_ciphersuite *const bbs_blind_nym_shake256_ciphersuite;

#ifdef __cplusplus
}
#endif

#endif

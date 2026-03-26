// SPDX-License-Identifier: Apache-2.0
#include "fixtures.h"
#include <string.h>

int
bbs_e2e_blind_with_nym(void)
{
    const bbs_ciphersuite *suite = *fixture_ciphersuite;

    bbs_secret_key sk;
    bbs_public_key pk;
    if (BBS_OK != bbs_keygen_full(suite, sk, pk)) {
        puts("Error during key generation");
        return 1;
    }

    static const char *header = "e2e blind nym header";
    static const char *ph = "e2e presentation nonce";
    static const char *context_id = "verifier-domain-A";

    // signer-known messages
    static const char *msg0 = "signer message 0";
    static const char *msg1 = "signer message 1";
    const void *msgs[] = { msg0, msg1 };
    const size_t msg_lens[] = { strlen(msg0), strlen(msg1) };

    // committed messages
    static const char *cmsg0 = "committed message 0";
    static const char *cmsg1 = "committed message 1";
    const void *cmsgs[] = { cmsg0, cmsg1 };
    const size_t cmsg_lens[] = { strlen(cmsg0), strlen(cmsg1) };

    // nym secrets
    static const char *nym0 = "nym secret 0";
    static const char *nym1 = "nym secret 1";
    const void *nyms[] = { nym0, nym1 };

    static const uint8_t entropy[32] = {
        0x3d,0x40,0x96,0x1f,0xce,0x6c,0x09,0xee,
        0xc2,0x4a,0x37,0x13,0x22,0x73,0x29,0x32,
        0x50,0x3b,0x45,0x8d,0x7a,0x4c,0xf7,0x89,
        0x1b,0xda,0xa7,0x65,0xb3,0x00,0x27,0xc5,
    };

    // prover commits to committed messages and nym secrets
    uint8_t cwp[BBS_BLIND_COMMITMENT_LEN(4)]; // 2 cmsgs + 2 nyms
    uint8_t spb[BBS_BLIND_SECRET_PROVER_BLIND_LEN];

    if (BBS_OK != bbs_blind_commit_with_nym(suite, cwp, spb,
                                            2, cmsgs, cmsg_lens,
                                            2, nyms)) {
        puts("Error during commit with nym");
        return 1;
    }

    // signer blind-signs with nym entropy
    bbs_signature sig;
    if (BBS_OK != bbs_blind_sign_with_nym(suite, sk, pk, sig,
                                          entropy, 2,
                                          header, strlen(header),
                                          cwp, sizeof(cwp),
                                          2, msgs, msg_lens)) {
        puts("Error during blind sign with nym");
        return 1;
    }

    // prover verifies and recovers nym secrets
    uint8_t recovered0[32], recovered1[32];
    void *const recovered[] = { recovered0, recovered1 };

    if (BBS_OK != bbs_blind_verify_with_nym(suite, pk, sig,
                                            header, strlen(header),
                                            2, msgs, msg_lens,
                                            2, cmsgs, cmsg_lens,
                                            spb,
                                            entropy, 2, nyms,
                                            recovered)) {
        puts("Error during blind verify with nym");
        return 1;
    }

    // prover generates a proof, disclosing msg0 and cmsg0
    // undisclosed: msg1, cmsg1, spb, nym0, nym1
    uint8_t proof[BBS_PROOF_LEN(5)];
    bbs_pseudonym pseudonym;

    const size_t disclosed_signer[]    = { 0 };   // msg0
    const size_t disclosed_committed[] = { 0 };   // cmsg0

    if (BBS_OK != bbs_blind_proof_gen_with_nym(suite, pk, sig, proof, pseudonym,
                                               header, strlen(header),
                                               ph, strlen(ph),
                                               context_id, strlen(context_id),
                                               2, msgs, msg_lens,
                                               2, cmsgs, cmsg_lens,
                                               1, disclosed_signer,
                                               1, disclosed_committed,
                                               spb,
                                               2, (const void *const *)recovered)) {
        puts("Error during blind proof gen with nym");
        return 1;
    }

    // verifier checks the proof and pseudonym
    const void   *disc_msgs[]      = { msg0 };
    const size_t  disc_msg_lens[]  = { strlen(msg0) };
    const void   *disc_cmsgs[]     = { cmsg0 };
    const size_t  disc_cmsg_lens[] = { strlen(cmsg0) };

    if (BBS_OK != bbs_blind_proof_verify_with_nym(suite, pk, pseudonym,
                                                   proof, sizeof(proof),
                                                   header, strlen(header),
                                                   ph, strlen(ph),
                                                   context_id, strlen(context_id),
                                                   2,  // length_nym_vector
                                                   2,  // num_signer_known_messages
                                                   1, disc_msgs, disc_msg_lens,
                                                   disclosed_signer,
                                                   1, disc_cmsgs, disc_cmsg_lens,
                                                   disclosed_committed)) {
        puts("Error during blind proof verify with nym");
        return 1;
    }

    // same prover, same context_id -> same pseudonym
    // generate a second proof and confirm the pseudonym is stable
    uint8_t proof2[BBS_PROOF_LEN(5)];
    bbs_pseudonym pseudonym2;

    if (BBS_OK != bbs_blind_proof_gen_with_nym(suite, pk, sig, proof2, pseudonym2,
                                               header, strlen(header),
                                               ph, strlen(ph),
                                               context_id, strlen(context_id),
                                               2, msgs, msg_lens,
                                               2, cmsgs, cmsg_lens,
                                               1, disclosed_signer,
                                               1, disclosed_committed,
                                               spb,
                                               2, (const void *const *)recovered)) {
        puts("Error during second blind proof gen with nym");
        return 1;
    }

    if (memcmp(pseudonym, pseudonym2, BBS_PSEUDONYM_LEN) != 0) {
        puts("Error: pseudonym is not stable across presentations");
        return 1;
    }

    // different context_id -> different pseudonym
    static const char *context_id_b = "verifier-domain-B";
    uint8_t proof3[BBS_PROOF_LEN(5)];
    bbs_pseudonym pseudonym3;

    if (BBS_OK != bbs_blind_proof_gen_with_nym(suite, pk, sig, proof3, pseudonym3,
                                               header, strlen(header),
                                               ph, strlen(ph),
                                               context_id_b, strlen(context_id_b),
                                               2, msgs, msg_lens,
                                               2, cmsgs, cmsg_lens,
                                               1, disclosed_signer,
                                               1, disclosed_committed,
                                               spb,
                                               2, (const void *const *)recovered)) {
        puts("Error during third blind proof gen with nym");
        return 1;
    }

    if (memcmp(pseudonym, pseudonym3, BBS_PSEUDONYM_LEN) == 0) {
        puts("Error: pseudonym did not change across different context_ids");
        return 1;
    }

    // should be memset_explicit in production env
    memset(sk, 0, sizeof(sk));
    memset(sig, 0, sizeof(sig));
    memset(spb, 0, sizeof(spb));
    memset(recovered0, 0, sizeof(recovered0));
    memset(recovered1, 0, sizeof(recovered1));

    return 0;
}

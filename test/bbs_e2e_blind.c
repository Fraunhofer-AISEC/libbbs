// SPDX-License-Identifier: Apache-2.0
#include "fixtures.h"
#include <string.h>

int
bbs_e2e_blind(void)
{
    const bbs_ciphersuite *suite = *fixture_ciphersuite;

    bbs_secret_key sk;
    bbs_public_key pk;
    if (BBS_OK != bbs_keygen_full(suite, sk, pk)) {
        puts("Error during key generation");
        return 1;
    }

    static const char *header = "e2e blind header";
    static const char *ph     = "e2e presentation nonce";

    // signer-known messages
    static const char *msg0 = "signer message 0";
    static const char *msg1 = "signer message 1";
    const void   *msgs[]     = { msg0, msg1 };
    const size_t  msg_lens[] = { strlen(msg0), strlen(msg1) };

    // committed messages (hidden from signer)
    static const char *cmsg0 = "committed message 0";
    static const char *cmsg1 = "committed message 1";
    const void   *cmsgs[]     = { cmsg0, cmsg1 };
    const size_t  cmsg_lens[] = { strlen(cmsg0), strlen(cmsg1) };

    // prover commits to committed messages
    uint8_t cwp[BBS_BLIND_COMMITMENT_LEN(2)];
    uint8_t spb[BBS_BLIND_SECRET_PROVER_BLIND_LEN];

    if (BBS_OK != bbs_blind_commit(suite, cwp, spb,
                                   2, cmsgs, cmsg_lens)) {
        puts("Error during blind commit");
        return 1;
    }

    // signer blind-signs
    bbs_signature sig;
    if (BBS_OK != bbs_blind_sign(suite, sk, pk, sig,
                                 header, strlen(header),
                                 cwp, sizeof(cwp),
                                 2, msgs, msg_lens)) {
        puts("Error during blind sign");
        return 1;
    }

    // prover verifies the blind signature
    if (BBS_OK != bbs_blind_verify(suite, pk, sig,
                                   header, strlen(header),
                                   2, msgs, msg_lens,
                                   2, cmsgs, cmsg_lens,
                                   spb)) {
        puts("Error during blind verify");
        return 1;
    }

    // prover generates a proof, disclosing msg0 and cmsg0
    uint8_t proof[BBS_PROOF_LEN(3)];

    const size_t disclosed_signer[]    = { 0 };   // msg0
    const size_t disclosed_committed[] = { 0 };   // cmsg0

    if (BBS_OK != bbs_blind_proof_gen(suite, pk, sig, proof,
                                      header, strlen(header),
                                      ph, strlen(ph),
                                      2, msgs, msg_lens,
                                      2, cmsgs, cmsg_lens,
                                      1, disclosed_signer,
                                      1, disclosed_committed,
                                      spb)) {
        puts("Error during blind proof gen");
        return 1;
    }

    // verifier verifies the proof
    const void   *disc_msgs[]      = { msg0 };
    const size_t  disc_msg_lens[]  = { strlen(msg0) };
    const void   *disc_cmsgs[]     = { cmsg0 };
    const size_t  disc_cmsg_lens[] = { strlen(cmsg0) };

    if (BBS_OK != bbs_blind_proof_verify(suite, pk,
                                          proof, sizeof(proof),
                                          header, strlen(header),
                                          ph, strlen(ph),
                                          2,   // num_signer_known_messages
                                          1, disc_msgs, disc_msg_lens,
                                          disclosed_signer,
                                          1, disc_cmsgs, disc_cmsg_lens,
                                          disclosed_committed)) {
        puts("Error during blind proof verify");
        return 1;
    }

    memset(sk,  0, sizeof(sk));
    memset(sig, 0, sizeof(sig));
    memset(spb, 0, sizeof(spb));

    return 0;
}

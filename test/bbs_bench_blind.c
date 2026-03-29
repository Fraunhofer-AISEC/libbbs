// SPDX-License-Identifier: Apache-2.0
#include "fixtures.h"
#include <bbs_blind.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define WARMUP     1000
#define ITERATIONS 10000
#define MSG_LEN    64
#define NONCE_LEN  23
#define NUM_MSGS   2
#define NUM_CMSGS  2

struct result {
    const char *name;
    double      min;
    double      avg;
    double      max;
    double      stddev;
};

static void print_results(struct result *r, size_t n) {
    size_t name_len = 9;
    for (size_t i = 0; i < n; i++)
        if (name_len < strlen(r[i].name)) name_len = strlen(r[i].name);
    printf("| %-*s | %8s | %8s | %8s | %8s |\n",
           (int)name_len, "Operation", "min (ms)", "avg (ms)", "max (ms)", "std (ms)");
    printf("| %.*s | -------- | -------- | -------- | -------- |\n",
           (int)name_len, "--------------------------------------------");
    for (size_t i = 0; i < n; i++)
        printf("| %-*s | %8.3f | %8.3f | %8.3f | %8.3f |\n",
               (int)name_len, r[i].name,
               r[i].min, r[i].avg, r[i].max, r[i].stddev);
}

#define BBS_BENCH(_name, _code)                                                 \
    results[results_idx].name = (_name);                                        \
    printf("Benchmarking %s... ", results[results_idx].name);                   \
    fflush(stdout);                                                             \
    {                                                                           \
        double _min = 0, _max = 0, _mean = 0, _M2 = 0;                          \
        for (int _ii = -WARMUP; _ii < ITERATIONS; _ii++) {                      \
            double _t0 = clock();                                               \
            if (BBS_OK != (_code)) { puts("ERROR!"); return 1; }                \
            double _t1  = clock();                                              \
            double _t = (((double)(_t1 - _t0) * 1000.0) / CLOCKS_PER_SEC);      \
            if (_ii < 0) continue;                                              \
            if (!_ii || _t < _min) _min = _t;                                   \
            if (!_ii || _t > _max) _max = _t;                                   \
            double _delta = _t - _mean;                                         \
            _mean += _delta / (_ii + 1);                                        \
            _M2   += _delta * (_t - _mean);                                     \
        }                                                                       \
        results[results_idx].min = _min;                                        \
        results[results_idx].avg = _mean;                                       \
        results[results_idx].max = _max;                                        \
        results[results_idx].stddev = sqrt(_M2 / (ITERATIONS - 1));             \
    }                                                                           \
    results_idx++;                                                              \
    puts("Done!");


int
bbs_bench_blind(void)
{
    const bbs_ciphersuite *suite = *fixture_ciphersuite;

    bbs_secret_key sk;
    bbs_public_key pk;
    bbs_signature  sig;

    char msg_buf[NUM_MSGS][MSG_LEN];
    char cmsg_buf[NUM_CMSGS][MSG_LEN];
    char nonce[NONCE_LEN];
    static const char header[] = "benchmark blind header";

    for (int i = 0; i < NUM_MSGS;  i++)
        for (int j = 0; j < MSG_LEN; j++) msg_buf[i][j]  = (char)rand();
    for (int i = 0; i < NUM_CMSGS; i++)
        for (int j = 0; j < MSG_LEN; j++) cmsg_buf[i][j] = (char)rand();
    for (int j = 0; j < NONCE_LEN; j++) nonce[j] = (char)rand();

    const void   *msgs[]      = { msg_buf[0],  msg_buf[1]  };
    const size_t  msg_lens[]  = { MSG_LEN, MSG_LEN };
    const void   *cmsgs[]     = { cmsg_buf[0], cmsg_buf[1] };
    const size_t  cmsg_lens[] = { MSG_LEN, MSG_LEN };

    uint8_t cwp[BBS_BLIND_COMMITMENT_LEN(NUM_CMSGS)];
    uint8_t spb[BBS_BLIND_SECRET_PROVER_BLIND_LEN];

    uint8_t proof[BBS_PROOF_LEN(3)];

    static const size_t disclosed_signer[]    = { 0 };
    static const size_t disclosed_committed[] = { 0 };

    const void   *disc_msgs[]      = { msg_buf[0]  };
    const size_t  disc_msg_lens[]  = { MSG_LEN };
    const void   *disc_cmsgs[]     = { cmsg_buf[0] };
    const size_t  disc_cmsg_lens[] = { MSG_LEN };

    struct result results[8];
    size_t        results_idx = 0;

    int title_len = printf("Blind BBS Benchmark for Ciphersuite %s\n", fixture_ciphersuite_name);
    while (--title_len) printf("=");
    puts("");
    printf("- %d measured iterations, %d warmup\n", ITERATIONS, WARMUP);
    printf("- %d signer messages, %d committed messages, each %d bytes\n",
           NUM_MSGS, NUM_CMSGS, MSG_LEN);
    printf("- 1 signer message and 1 committed message disclosed\n\n");

    if (BBS_OK != bbs_keygen_full(suite, sk, pk)) return 1;

    BBS_BENCH("Blind Commit",
        bbs_blind_commit(suite, cwp, spb,
                         NUM_CMSGS, cmsgs, cmsg_lens));

    if (BBS_OK != bbs_blind_commit(suite, cwp, spb,
                                    NUM_CMSGS, cmsgs, cmsg_lens)) return 1;

    BBS_BENCH("Blind Sign",
        bbs_blind_sign(suite, sk, pk, sig,
                       header, sizeof(header) - 1,
                       cwp, sizeof(cwp),
                       NUM_MSGS, msgs, msg_lens));

    if (BBS_OK != bbs_blind_sign(suite, sk, pk, sig,
                                  header, sizeof(header) - 1,
                                  cwp, sizeof(cwp),
                                  NUM_MSGS, msgs, msg_lens)) return 1;

    BBS_BENCH("Blind Verify",
        bbs_blind_verify(suite, pk, sig,
                         header, sizeof(header) - 1,
                         NUM_MSGS, msgs, msg_lens,
                         NUM_CMSGS, cmsgs, cmsg_lens,
                         spb));

    BBS_BENCH("Blind Proof Generation",
        bbs_blind_proof_gen(suite, pk, sig, proof,
                            header, sizeof(header) - 1,
                            nonce, NONCE_LEN,
                            NUM_MSGS,  msgs,  msg_lens,
                            NUM_CMSGS, cmsgs, cmsg_lens,
                            1, disclosed_signer,
                            1, disclosed_committed,
                            spb));

    if (BBS_OK != bbs_blind_proof_gen(suite, pk, sig, proof,
                                       header, sizeof(header) - 1,
                                       nonce, NONCE_LEN,
                                       NUM_MSGS,  msgs,  msg_lens,
                                       NUM_CMSGS, cmsgs, cmsg_lens,
                                       1, disclosed_signer,
                                       1, disclosed_committed,
                                       spb)) return 1;

    BBS_BENCH("Blind Proof Verification",
        bbs_blind_proof_verify(suite, pk,
                               proof, BBS_PROOF_LEN(3),
                               header, sizeof(header) - 1,
                               nonce, NONCE_LEN,
                               NUM_MSGS,
                               1, disc_msgs,  disc_msg_lens,  disclosed_signer,
                               1, disc_cmsgs, disc_cmsg_lens, disclosed_committed));

    puts("");
    print_results(results, results_idx);
    puts("");
    return 0;
}

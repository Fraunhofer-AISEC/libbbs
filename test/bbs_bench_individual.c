// SPDX-License-Identifier: Apache-2.0
#include "fixtures.h"
#include <time.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define WARMUP     1000
#define ITERATIONS 10000
#define MSG_LEN    64
#define NONCE_LEN  23

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
bbs_bench_individual(void)
{
    const bbs_ciphersuite *suite = *fixture_ciphersuite;

    bbs_secret_key sk;
    bbs_public_key pk;
    bbs_signature  sig;
    uint8_t        proof[BBS_PROOF_LEN(1)];

    char msg1[MSG_LEN], msg2[MSG_LEN], nonce[NONCE_LEN];
    static const char header[] = "benchmark header";
    static const size_t disclosed[] = { 0 };

    for (int j = 0; j < MSG_LEN; j++) msg1[j] = (char)rand();
    for (int j = 0; j < MSG_LEN; j++) msg2[j] = (char)rand();
    for (int j = 0; j < NONCE_LEN; j++) nonce[j] = (char)rand();

    const void *msgs[] = { msg1, msg2 };
    const size_t msg_lens[] = { MSG_LEN, MSG_LEN };

    struct result results[8];
    size_t results_idx = 0;

    int title_len = printf("Benchmark for Ciphersuite %s\n", fixture_ciphersuite_name);
    while (--title_len) printf("=");
    puts("");
    printf("- %d measured iterations, %d warmup\n", ITERATIONS, WARMUP);
    printf("- 2 messages of %d bytes, 1 disclosed\n\n", MSG_LEN);

    BBS_BENCH("Key Generation", bbs_keygen_full(suite, sk, pk));

    if (BBS_OK != bbs_keygen_full(suite, sk, pk)) return 1;

    BBS_BENCH("Signature Generation",
        bbs_sign(suite, sk, pk, sig,
                 header, sizeof(header) - 1,
                 2, msgs, msg_lens));

    if (BBS_OK != bbs_sign(suite, sk, pk, sig,
                            header, sizeof(header) - 1,
                            2, msgs, msg_lens)) return 1;

    BBS_BENCH("Signature Verification",
        bbs_verify(suite, pk, sig,
                   header, sizeof(header) - 1,
                   2, msgs, msg_lens));

    BBS_BENCH("Proof Generation",
        bbs_proof_gen(suite, pk, sig, proof,
                      header, sizeof(header) - 1,
                      nonce, NONCE_LEN,
                      disclosed, 1,
                      2, msgs, msg_lens));

    if (BBS_OK != bbs_proof_gen(suite, pk, sig, proof,
                                 header, sizeof(header) - 1,
                                 nonce, NONCE_LEN,
                                 disclosed, 1,
                                 2, msgs, msg_lens)) return 1;

    BBS_BENCH("Proof Verification",
        bbs_proof_verify(suite, pk, proof, BBS_PROOF_LEN(1),
                         header, sizeof(header) - 1,
                         nonce, NONCE_LEN,
                         disclosed, 1,
                         2, (const void *const[]){ msg1 },
                            (const size_t[]){ MSG_LEN }));

    puts("");
    print_results(results, results_idx);
    puts("");
    return 0;
}

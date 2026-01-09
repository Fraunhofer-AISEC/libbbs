// SPDX-License-Identifier: Apache-2.0
#include "fixtures.h"
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

struct result {
	const char *name;
	double      min;
	double      avg;
	double      max;
};

/* Print a markdown table of results */
static void print_results(struct result *r, size_t n) {
	size_t name_len = 9; /* Length of "Operation" */
	for(size_t i=0; i<n; i++)
		if(name_len < strlen(r[i].name)) name_len = strlen(r[i].name);
	printf("| %-*s | %s | %s | %s |\n",
			(int)name_len, "Operation", "min (ms)", "avg (ms)", "max (ms)");
	printf("| %.*s | -------- | -------- | -------- |\n",
			(int)name_len, "----------------------------------------");
	for(size_t i=0; i<n; i++)
		printf("| %-*s | %8.3f | %8.3f | %8.3f |\n",
			(int)name_len, r[i].name, r[i].min, r[i].avg, r[i].max);
}

int
bbs_bench_individual ()
{
	#define WARMUP 100
	#define ITERATIONS 1000
	#define MSG_LEN 64
	#define NONCE_LEN 23

	clock_t clk; /* Because clock_gettime is POSIX-only */
	double timing, sum; /* recorded in ms */
	struct result results[10];
	size_t results_idx = 0;

	const bbs_ciphersuite *cipher_suite = *fixture_ciphersuite;
	bbs_secret_key sk;
	bbs_public_key pk;
	char           msg1[MSG_LEN];
	char           msg2[MSG_LEN];
	bbs_signature  sig;
	char           header[] = "But I am a header!";
	size_t         header_len = strlen(header);
	uint8_t        proof[BBS_PROOF_LEN (1)];
	size_t         disclosed_indexes[] = {0};
	char           random_nonces[NONCE_LEN];

	for (int j = 0; j < MSG_LEN;   j++) msg1[j]          = (char) rand ();
	for (int j = 0; j < MSG_LEN;   j++) msg2[j]          = (char) rand ();
	for (int j = 0; j < NONCE_LEN; j++) random_nonces[j] = (char) rand ();

#define BBS_BENCH(_name, _code) \
	results[results_idx].name = _name; \
	printf("Benchmarking %s... ", results[results_idx].name); \
	sum = 0.0; \
	for(int ii = -WARMUP; ii < ITERATIONS; ii++) { \
		clk = clock(); \
		if(BBS_OK != _code) { puts("ERROR!"); return 1; } \
		timing = ((double)(clock() - clk)/CLOCKS_PER_SEC) * 1000; \
		if(ii < 0) continue; \
		sum += timing; \
		if(!ii || results[results_idx].min > timing) \
			results[results_idx].min = timing; \
		if(!ii || results[results_idx].max < timing) \
			results[results_idx].max = timing; \
	} \
	results[results_idx++].avg = sum / ITERATIONS; \
	puts("Done!");
	
	if(CLOCKS_PER_SEC < 1000000) {
		printf("WARNING: CLOCKS_PER_SEC is too low for accurate "
				"measurements (is %ld)\n", (long)CLOCKS_PER_SEC);
	}

	int title_len = printf("Benchmark for Ciphersuite %s\n", fixture_ciphersuite_name);
	while(--title_len) printf("=");
	puts("");

	puts("Configuration:");
	printf("- %d measured iterations, %d round of warmup\n", ITERATIONS, WARMUP);
	printf("- %d messages, each of length %d bytes\n", 2, MSG_LEN);
	printf("- %d messages disclosed\n", 1);
	printf("- header of length %zu bytes\n", header_len);
	printf("- presentation header of length %d bytes\n\n", NONCE_LEN);

	BBS_BENCH ("Key Generation",
		bbs_keygen_full (cipher_suite, sk, pk));

	BBS_BENCH ("Signature Generation",
		bbs_sign_v (cipher_suite, sk, pk, sig,
				header, header_len, 2,
				msg1, MSG_LEN, msg2, MSG_LEN));

	BBS_BENCH ("Signature Verification",
		bbs_verify_v (cipher_suite, pk, sig,
				header, header_len, 2,
				msg1, MSG_LEN, msg2, MSG_LEN));

	BBS_BENCH ("Proof Generation",
		bbs_proof_gen_v (cipher_suite, pk, sig, proof,
				header, header_len,
				random_nonces, NONCE_LEN,
				disclosed_indexes, 1, 2,
				msg1, MSG_LEN, msg2, MSG_LEN));

	BBS_BENCH ("Proof Verification",
		bbs_proof_verify_v (cipher_suite, pk, proof, BBS_PROOF_LEN (1),
				header, strlen (header),
				random_nonces, NONCE_LEN,
				disclosed_indexes, 1, 2,
				msg1, MSG_LEN));

	puts("");
	print_results(results, results_idx);
	puts("");
	return 0;
}

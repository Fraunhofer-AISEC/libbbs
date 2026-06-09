// SPDX-License-Identifier: Apache-2.0
// Parses the JSON fixtures in fixture_data/ to generate C source files from
// which the tests may read the fixtures. We generate one source file per
// ciphersuite.
//
// The fixture data is taken verbatim from
// https://github.com/decentralized-identity/bbs-signature/tree/main/tooling/fixtures/fixture_data
// For the most part, these are the vectors from the BBS draft.
//
// Included below is a *very* minimalistic JSON parser to avoid additional build
// dependencies. It is only useful for guaranteed correct JSON, such as the test
// vectors.

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

// gljp - The Good Luck JSON Parser (pronounced "gilschp" and just as good).
// Crashes on invalid inputs. NEVER use on unknown or even untrusted data!
enum json_type { JSON_NULL, JSON_TRUE, JSON_FALSE, JSON_STRING, JSON_NUMBER, JSON_OBJECT, JSON_ARRAY };
struct json { enum json_type type; size_t len; const char *string; struct json *value; struct json *next; };
void _json_parse_internal(const char **input, struct json **out, int chain_mode) {
	*input += strspn(*input, " \t\n\r,"); // Comma for tail calls
	if(!**input || **input == ']' || **input == '}')
		{ *input += 1; *out = NULL; return; } // For recursive calls
	*out = calloc(1,sizeof(struct json));
	switch(*(*input)++) {
	case 't': (*out)->type = JSON_TRUE;  *input += 3; break;
	case 'f': (*out)->type = JSON_FALSE; *input += 4; break;
	case 'n': (*out)->type = JSON_NULL;  *input += 3; break;
	case '-': case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		(*out)->type = JSON_NUMBER;
		(*out)->string = *input - 1; // Undecoded number of length len
		*input += strspn(*input, "+-.eE0123456789");
		(*out)->len = *input - (*out)->string;
		break;
	case '"':
		(*out)->type = JSON_STRING;
		(*out)->string = *input; // Undecoded string of length len
		do { *input = strchr(*input, '"') + 1; } while(*(*input-2) == '\\');
		(*out)->len = *input - (*out)->string - 1;
		if(chain_mode != 2) break; // Chain Mode 2 for "key : value"
		*input += strspn(*input, " \t\n\r") + 1;
		_json_parse_internal(input, &(*out)->value, 0);
		break;
	case '[':
		(*out)->type = JSON_ARRAY;
		_json_parse_internal(input, &(*out)->value, 1); // Chain Mode 1 for "value"
		break;
	case '{':
		(*out)->type = JSON_OBJECT;
		_json_parse_internal(input, &(*out)->value, 2); // Chain Mode 2 for "key:value"
		break;
	}
	if(chain_mode) _json_parse_internal(input, &(*out)->next, chain_mode); // Tail recursion
}
void json_parse(const char *input, struct json **out) { _json_parse_internal(&input, out, 0); }
void json_free(struct json *j) { if(j) { json_free(j->next); json_free(j->value); free(j); } }

[[noreturn]] void fail(const char *loc) { perror(loc); exit(1); }

struct json *json_object_get(struct json *j, const char *key) {
	for(struct json *k = j->value; k; k = k->next)
		if(strlen(key) == k->len && !strncmp(key, k->string, k->len)) return k->value;
	fail(key);
}
size_t json_array_len(struct json *j) {
	size_t res = 0;
	for(struct json *k = j->value; k; k = k->next) res++;
	return res;
}

void print_hex_str(struct json *string, FILE *out) {
    if(!string->len) { fprintf(out, "{0}"); return; }
    size_t i = 0;
    if(string->len % 2) { // for odd length hex strings, a 0 needs to be PREpended
        fprintf(out, "{0x0%c", string->string[i++]);
    } else {
        fprintf(out, "{0x%.2s", string->string);
        i = 2;
    }
    for(; i < string->len; i += 2)
        fprintf(out, ",0x%.2s", string->string + i);
    fprintf(out, "}");
}

int existsat(int dirfd, const char *path) {
	int fd = openat(dirfd, path, O_RDONLY);
	if(-1 != fd) { if(-1 == close(fd)) fail("close"); return 1; }
	if(errno != ENOENT) fail("openat");
	return 0;
}

char *read_file(int dirfd, const char *path) {
	FILE *f;
	int fd;
	char *res = NULL;

	if(-1 == (fd = openat(dirfd, path, O_RDONLY))) fail("openat");
	if(!(f = fdopen(fd, "r"))) fail("fdopen");
	for(int i=0; !i || !feof(f); i++) {
		if(!(res = realloc(res, 1 + (i+1) * 1000))) fail("realloc");
		res[i*1000 + fread(res + i*1000, 1, 1000, f)] = 0;
		if(ferror(f)) fail("fread");
	}
	if(fclose(f)) fail("fclose");
	return res;
}

void parse_blind_with_nym_fixtures(FILE* out, int dirfd) {
    int i = 0 ,filenum = 0;
	char filename[256];
    struct json *j, *tmp;

    // blind with nym generators
    char *f = read_file(dirfd, "generators.json");
    json_parse(f, &j);
    struct json *signer_gen = json_object_get(j, "generators");
    struct json *prover_gen = json_object_get(j, "blindGenerators");

    fprintf(out, "static const uint8_t blind_nym_signer_generators[][48] = {\n\t");
    print_hex_str(json_object_get(signer_gen, "Q1"), out);
    i = 1;
    for(struct json *k = json_object_get(signer_gen, "MsgGenerators")->value; k; k = k->next) {
        fprintf(out, ",\n\t"); print_hex_str(k, out); i++;
    }
    int signer_count = i;
    fprintf(out, "\n};\n");

    fprintf(out, "static const uint8_t blind_nym_prover_generators[][48] = {\n\t");
    print_hex_str(json_object_get(prover_gen, "Q1"), out);
    i = 1;
    for(struct json *k = json_object_get(prover_gen, "MsgGenerators")->value; k; k = k->next) {
        fprintf(out, ",\n\t"); print_hex_str(k, out); i++;
    }
    int prover_count = i;
    fprintf(out, "\n};\n");

    fprintf(out, "static const struct blind_with_nym_fixture_generators _vectors_blind_with_nym_generators[] = {\n");
    fprintf(out, "\t{ .signer_result = blind_nym_signer_generators, .signer_result_len = %d,\n", signer_count);
    fprintf(out, "\t  .prover_result  = blind_nym_prover_generators, .prover_result_len  = %d }\n", prover_count);
    fprintf(out, "};\n");
    fprintf(out, "const struct blind_with_nym_fixture_generators *const vectors_blind_with_nym_generators = _vectors_blind_with_nym_generators;\n");
    fprintf(out, "const size_t vectors_blind_with_nym_generators_len = 1;\n\n");
    json_free(j); free(f);

    // Blind Commits with Pseudonym
    fprintf(out, "static const struct blind_with_nym_fixture_commit _vectors_blind_with_nym_commit[] = {\n");
    for(filenum = 1; 1; filenum++) {
        sprintf(filename, "commit/nymCommit%03d.json", filenum);
        if(!existsat(dirfd, filename)) break;
        f = read_file(dirfd, filename);
        json_parse(f, &j);

        struct json *mock   = json_object_get(j, "mockRngParameters");
        struct json *commit = json_object_get(mock, "commit");
        struct json *cms    = json_object_get(j, "committedMessages");
        struct json *nyms   = json_object_get(j, "proverNyms");

        fprintf(out, "\t{\n");

        tmp = json_object_get(mock, "SEED");
        fprintf(out, "\t\t.mocking_seed = (const uint8_t[]){");
        for(size_t si = 0; si < tmp->len; si++)
            fprintf(out, "%s0x%02x", si ? "," : "", (unsigned char)tmp->string[si]);
        fprintf(out, "}, .mocking_seed_len = %zu,\n", tmp->len);

        tmp = json_object_get(commit, "DST");
        fprintf(out, "\t\t.mocking_dst = (const uint8_t[]){");
        for(size_t si = 0; si < tmp->len; si++)
            fprintf(out, "%s0x%02x", si ? "," : "", (unsigned char)tmp->string[si]);
        fprintf(out, "}, .mocking_dst_len = %zu,\n", tmp->len);

        // committed messages
        i = 0;
        for(struct json *k = cms->value; k; k = k->next) i++;
        fprintf(out, "\t\t.num_committed_messages = %d,\n", i);
        if(i == 0) {
            fprintf(out, "\t\t.committed_msgs = NULL, .committed_msg_lens = NULL,\n");
        } else {
            fprintf(out, "\t\t.committed_msgs = (const void *const[]){\n");
            for(struct json *k = cms->value; k; k = k->next) {
                fprintf(out, "\t\t\t(const uint8_t[])"); print_hex_str(k, out); fprintf(out, ",\n");
            }
            fprintf(out, "\t\t},\n\t\t.committed_msg_lens = (const size_t[]){");
            for(struct json *k = cms->value; k; k = k->next)
                fprintf(out, "%zu, ", k->len / 2);
            fprintf(out, "},\n");
        }

        // prover nyms
        i = 0;
        for(struct json *k = nyms->value; k; k = k->next) i++;
        fprintf(out, "\t\t.num_prover_nyms = %d,\n", i);
        fprintf(out, "\t\t.prover_nyms = (const void *const[]){\n");
        for(struct json *k = nyms->value; k; k = k->next) {
            fprintf(out, "\t\t\t(const uint8_t[])"); print_hex_str(k, out); fprintf(out, ",\n");
        }
        fprintf(out, "\t\t},\n");

        fprintf(out, "\t\t.prover_blind = ");
        print_hex_str(json_object_get(j, "proverBlind"), out);
        fprintf(out, ",\n");

        tmp = json_object_get(j, "commitmentWithProof");
        fprintf(out, "\t\t.result = (const uint8_t[])");
        print_hex_str(tmp, out);
        fprintf(out, ", .result_len = %zu,\n", tmp->len / 2);

        tmp = json_object_get(j, "result");
        fprintf(out, "\t\t.result_valid = %d\n", JSON_TRUE == json_object_get(tmp, "valid")->type);

        fprintf(out, "\t},\n");
        json_free(j); free(f);
    }
    fprintf(out, "};\n");
    fprintf(out, "const struct blind_with_nym_fixture_commit *const vectors_blind_with_nym_commit = _vectors_blind_with_nym_commit;\n");
    fprintf(out, "const size_t vectors_blind_with_nym_commit_len = %d;\n\n", --filenum);

    // Blind Signatures with Pseudonyms
    fprintf(out, "static const struct blind_with_nym_fixture_signature _vectors_blind_with_nym_signature[] = {\n");
    for(filenum = 1; 1; filenum++) {
        sprintf(filename, "signature/nymSignature%03d.json", filenum);
        if(!existsat(dirfd, filename)) break;
        f = read_file(dirfd, filename);
        json_parse(f, &j);

        struct json *kp   = json_object_get(j, "signerKeyPair");
        struct json *cwp  = json_object_get(j, "commitmentWithProof");
        struct json *pb   = json_object_get(j, "proverBlind");
        struct json *cm   = json_object_get(j, "committedMessages");
        struct json *msgs = json_object_get(j, "messages");
        struct json *nyms = json_object_get(j, "proverNyms");
        struct json *nsec = json_object_get(j, "nym_secrets");

        fprintf(out, "\t{\n");

        fprintf(out, "\t\t.sk = ");
        print_hex_str(json_object_get(kp, "secretKey"), out);
        fprintf(out, ",\n\t\t.pk = ");
        print_hex_str(json_object_get(kp, "publicKey"), out);
        fprintf(out, ",\n");

        fprintf(out, "\t\t.signer_nym_entropy = ");
        print_hex_str(json_object_get(j, "signer_nym_entropy"), out);
        fprintf(out, ",\n");

        tmp = json_object_get(j, "header");
        fprintf(out, "\t\t.header = (const uint8_t[])");
        print_hex_str(tmp, out);
        fprintf(out, ", .header_len = %zu,\n", tmp->len / 2);

        // commitmentWithProof
        if(cwp->type == JSON_NULL) {
            fprintf(out, "\t\t.commitment_with_proof = NULL, .commitment_with_proof_len = 0,\n");
        } else {
            fprintf(out, "\t\t.commitment_with_proof = (const uint8_t[])");
            print_hex_str(cwp, out);
            fprintf(out, ", .commitment_with_proof_len = %zu,\n", cwp->len / 2);
        }

        // signer messages
        i = 0;
        for(struct json *k = msgs->value; k; k = k->next) i++;
        fprintf(out, "\t\t.num_messages = %d,\n", i);
        if(i == 0) {
            fprintf(out, "\t\t.msgs = NULL, .msg_lens = NULL,\n");
        } else {
            fprintf(out, "\t\t.msgs = (const void *const[]){");
            for(struct json *k = msgs->value; k; k = k->next) {
                fprintf(out, "(const uint8_t[])"); print_hex_str(k, out); fprintf(out, ", ");
            }
            fprintf(out, "},\n\t\t.msg_lens = (const size_t[]){");
            for(struct json *k = msgs->value; k; k = k->next)
                fprintf(out, "%zu, ", k->len / 2);
            fprintf(out, "},\n");
        }

        // committed messages
        if(cwp->type == JSON_NULL) {
            fprintf(out, "\t\t.num_committed_messages = 0,\n");
            fprintf(out, "\t\t.committed_msgs = NULL, .committed_msg_lens = NULL,\n");
        } else {
            i = 0;
            if(cm->type != JSON_NULL)
                for(struct json *k = cm->value; k; k = k->next) i++;
            fprintf(out, "\t\t.num_committed_messages = %d,\n", i);
            if(i == 0) {
                fprintf(out, "\t\t.committed_msgs = NULL, .committed_msg_lens = NULL,\n");
            } else {
                fprintf(out, "\t\t.committed_msgs = (const void *const[]){");
                for(struct json *k = cm->value; k; k = k->next) {
                    fprintf(out, "(const uint8_t[])"); print_hex_str(k, out); fprintf(out, ", ");
                }
                fprintf(out, "},\n\t\t.committed_msg_lens = (const size_t[]){");
                for(struct json *k = cm->value; k; k = k->next)
                    fprintf(out, "%zu, ", k->len / 2);
                fprintf(out, "},\n");
            }
        }

        // prover nyms
        i = 0;
        for(struct json *k = nyms->value; k; k = k->next) i++;
        fprintf(out, "\t\t.num_prover_nyms = %d,\n", i);
        fprintf(out, "\t\t.prover_nyms = (const void *const[]){\n");
        for(struct json *k = nyms->value; k; k = k->next) {
            fprintf(out, "\t\t\t(const uint8_t[])"); print_hex_str(k, out); fprintf(out, ",\n");
        }
        fprintf(out, "},\n");

        // nym secrets
        i = 0;
        for(struct json *k = nsec->value; k; k = k->next) i++;
        fprintf(out, "\t\t.num_nym_secrets = %d,\n", i);
        fprintf(out, "\t\t.nym_secrets = (const void *const[]){\n");
        for(struct json *k = nsec->value; k; k = k->next) {
            fprintf(out, "\t\t\t(const uint8_t[])"); print_hex_str(k, out); fprintf(out, ",\n");
        }
        fprintf(out, "},\n");

        // prover blind
        fprintf(out, "\t\t.prover_blind = ");
        if(pb->type == JSON_NULL) fprintf(out, "{0}");
        else print_hex_str(pb, out);
        fprintf(out, ",\n");

        fprintf(out, "\t\t.result = ");
        print_hex_str(json_object_get(j, "signature"), out);
        fprintf(out, ",\n");

        tmp = json_object_get(j, "result");
        fprintf(out, "\t\t.result_valid = %d\n",
            JSON_TRUE == json_object_get(tmp, "valid")->type);

        fprintf(out, "\t},\n");
        json_free(j); free(f);
    }
    fprintf(out, "};\n");
    fprintf(out, "const struct blind_with_nym_fixture_signature *const vectors_blind_with_nym_signature = _vectors_blind_with_nym_signature;\n");
    fprintf(out, "const size_t vectors_blind_with_nym_signature_len = %d;\n\n", --filenum);

    // Blind Proofs with Pseudonyms
    fprintf(out, "static const struct blind_with_nym_fixture_proof _vectors_blind_with_nym_proof[] = {\n");
    for(filenum = 1; 1; filenum++) {
        sprintf(filename, "proof/nymProof%03d.json", filenum);
        if(!existsat(dirfd, filename)) break;
        f = read_file(dirfd, filename);
        json_parse(f, &j);

        struct json *mock = json_object_get(j, "mockRngParameters");
        struct json *proof_rng = json_object_get(mock, "proof");
        struct json *cwp  = json_object_get(j, "commitmentWithProof");
        struct json *pb  = json_object_get(j, "proverBlind");
        struct json *all_msgs = json_object_get(j, "messages");
        struct json *all_committed = json_object_get(j, "committedMessages");
        struct json *revealed = json_object_get(j, "revealedMessages");
        struct json *revealed_committed = json_object_get(j, "revealedCommittedMessages");
        struct json *nyms = json_object_get(j, "proverNyms");
        struct json *nsec = json_object_get(j, "nym_secrets");

        // count all messages
        int n_msgs = 0;
        for(struct json *k = all_msgs->value; k; k = k->next) n_msgs++;
        int n_committed = 0;
        if(all_committed && all_committed->type != JSON_NULL)
            for(struct json *k = all_committed->value; k; k = k->next) n_committed++;

        // count disclosed
        int n_disclosed = 0;
        if(revealed->type != JSON_NULL)
            for(struct json *k = revealed->value; k; k = k->next) n_disclosed++;
        int n_disclosed_committed = 0;
        if(revealed_committed && revealed_committed->type != JSON_NULL)
            for(struct json *k = revealed_committed->value; k; k = k->next) n_disclosed_committed++;

        // count nyms
        int n_nyms = 0;
        for(struct json *k = nyms->value; k; k = k->next) n_nyms++;
        int n_nsec = 0;
        for(struct json *k = nsec->value; k; k = k->next) n_nsec++;

        fprintf(out, "\t{\n");

        fprintf(out, "\t\t.pk = ");
        print_hex_str(json_object_get(j, "signerPublicKey"), out);
        fprintf(out, ",\n\t\t.signature = ");
        print_hex_str(json_object_get(j, "signature"), out);
        fprintf(out, ",\n");

        fprintf(out, "\t\t.signer_nym_entropy = ");
        print_hex_str(json_object_get(j, "signer_nym_entropy"), out);
        fprintf(out, ",\n");

        tmp = json_object_get(j, "header");
        fprintf(out, "\t\t.header = (const uint8_t[])");
        print_hex_str(tmp, out);
        fprintf(out, ", .header_len = %zu,\n", tmp->len / 2);

        tmp = json_object_get(j, "presentationHeader");
        fprintf(out, "\t\t.presentation_header = (const uint8_t[])");
        print_hex_str(tmp, out);
        fprintf(out, ", .presentation_header_len = %zu,\n", tmp->len / 2);

        tmp = json_object_get(j, "context_id");
        fprintf(out, "\t\t.context_id = (const uint8_t[])");
        print_hex_str(tmp, out);
        fprintf(out, ", .context_id_len = %zu,\n", tmp->len / 2);

        fprintf(out, "\t\t.pseudonym = ");
        print_hex_str(json_object_get(j, "pseudonym"), out);
        fprintf(out, ",\n");

        // commitmentWithProof
        if(cwp->type == JSON_NULL) {
            fprintf(out, "\t\t.commitment_with_proof = NULL, .commitment_with_proof_len = 0,\n");
        } else {
            fprintf(out, "\t\t.commitment_with_proof = (const uint8_t[])");
            print_hex_str(cwp, out);
            fprintf(out, ", .commitment_with_proof_len = %zu,\n", cwp->len / 2);
        }

        fprintf(out, "\t\t.prover_blind = ");
        if(pb->type == JSON_NULL) fprintf(out, "{0}");
        else print_hex_str(pb, out);
        fprintf(out, ",\n");

        // all signer messages
        fprintf(out, "\t\t.num_messages = %d,\n", n_msgs);
        if(n_msgs == 0) {
            fprintf(out, "\t\t.msgs = NULL, .msg_lens = NULL,\n");
        } else {
            fprintf(out, "\t\t.msgs = (const void *const[]){\n");
            for(struct json *k = all_msgs->value; k; k = k->next) {
                fprintf(out, "\t\t\t(const uint8_t[])"); print_hex_str(k, out); fprintf(out, ",\n");
            }
            fprintf(out, "\t\t},\n\t\t.msg_lens = (const size_t[]){");
            for(struct json *k = all_msgs->value; k; k = k->next)
                fprintf(out, "%zu, ", k->len / 2);
            fprintf(out, "},\n");
        }

        // all committed messages
        if(cwp->type == JSON_NULL) {
            fprintf(out, "\t\t.num_committed_messages = 0,\n");
            fprintf(out, "\t\t.committed_msgs = NULL, .committed_msg_lens = NULL,\n");
        } else {
            fprintf(out, "\t\t.num_committed_messages = %d,\n", n_committed);
            if(n_committed == 0) {
                fprintf(out, "\t\t.committed_msgs = NULL, .committed_msg_lens = NULL,\n");
            } else {
                fprintf(out, "\t\t.committed_msgs = (const void *const[]){\n");
                for(struct json *k = all_committed->value; k; k = k->next) {
                    fprintf(out, "\t\t\t(const uint8_t[])"); print_hex_str(k, out); fprintf(out, ",\n");
                }
                fprintf(out, "\t\t},\n\t\t.committed_msg_lens = (const size_t[]){");
                for(struct json *k = all_committed->value; k; k = k->next)
                    fprintf(out, "%zu, ", k->len / 2);
                fprintf(out, "},\n");
            }
        }

        // prover nyms
        fprintf(out, "\t\t.num_prover_nyms = %d,\n", n_nyms);
        fprintf(out, "\t\t.prover_nyms = (const void *const[]){\n");
        for(struct json *k = nyms->value; k; k = k->next) {
            fprintf(out, "\t\t\t(const uint8_t[])"); print_hex_str(k, out); fprintf(out, ",\n");
        }
        fprintf(out, "\t\t},\n");

        // nym secrets
        fprintf(out, "\t\t.num_nym_secrets = %d,\n", n_nsec);
        fprintf(out, "\t\t.nym_secrets = (const void *const[]){\n");
        for(struct json *k = nsec->value; k; k = k->next) {
            fprintf(out, "\t\t\t(const uint8_t[])"); print_hex_str(k, out); fprintf(out, ",\n");
        }
        fprintf(out, "\t\t},\n");

        // disclosed signer indexes and messages
        fprintf(out, "\t\t.disclosed_indexes_len = %d,\n", n_disclosed);
        if(n_disclosed == 0) {
            fprintf(out, "\t\t.disclosed_indexes = NULL,\n");
            fprintf(out, "\t\t.disclosed_msgs = NULL, .disclosed_msg_lens = NULL,\n");
        } else {
            fprintf(out, "\t\t.disclosed_indexes = (const size_t[]){");
            int idx = 0;
            for(struct json *k = revealed->value; k; k = k->next, idx++)
                fprintf(out, "%s%.*s", idx ? ", " : "", (int)k->len, k->string);
            fprintf(out, "},\n");
            fprintf(out, "\t\t.disclosed_msgs = (const void *const[]){\n");
            for(struct json *k = revealed->value; k; k = k->next) {
                fprintf(out, "\t\t\t(const uint8_t[])"); print_hex_str(k->value, out); fprintf(out, ",\n");
            }
            fprintf(out, "\t\t},\n\t\t.disclosed_msg_lens = (const size_t[]){");
            for(struct json *k = revealed->value; k; k = k->next)
                fprintf(out, "%zu, ", k->value->len / 2);
            fprintf(out, "},\n");
        }

        // disclosed committed indexes and messages
        fprintf(out, "\t\t.disclosed_committed_indexes_len = %d,\n", n_disclosed_committed);
        if(n_disclosed_committed == 0) {
            fprintf(out, "\t\t.disclosed_committed_indexes = NULL,\n");
            fprintf(out, "\t\t.disclosed_committed_msgs = NULL, .disclosed_committed_msg_lens = NULL,\n");
        } else {
            fprintf(out, "\t\t.disclosed_committed_indexes = (const size_t[]){");
            int idx = 0;
            for(struct json *k = revealed_committed->value; k; k = k->next, idx++)
                fprintf(out, "%s%.*s", idx ? ", " : "", (int)k->len, k->string);
            fprintf(out, "},\n");
            fprintf(out, "\t\t.disclosed_committed_msgs = (const void *const[]){\n");
            for(struct json *k = revealed_committed->value; k; k = k->next) {
                fprintf(out, "\t\t\t(const uint8_t[])"); print_hex_str(k->value, out); fprintf(out, ",\n");
            }
            fprintf(out, "\t\t},\n\t\t.disclosed_committed_msg_lens = (const size_t[]){");
            for(struct json *k = revealed_committed->value; k; k = k->next)
                fprintf(out, "%zu, ", k->value->len / 2);
            fprintf(out, "},\n");
        }

        tmp = json_object_get(j, "L");
        fprintf(out, "\t\t.L = %.*s,\n", (int)tmp->len, tmp->string);

        // proof mocking
        tmp = json_object_get(mock, "SEED");
        fprintf(out, "\t\t.proof_mocking_seed = (const uint8_t[]){");
        for(size_t si = 0; si < tmp->len; si++)
            fprintf(out, "%s0x%02x", si ? "," : "", (unsigned char)tmp->string[si]);
        fprintf(out, "}, .proof_mocking_seed_len = %zu,\n", tmp->len);
        tmp = json_object_get(proof_rng, "DST");
        fprintf(out, "\t\t.proof_mocking_dst = (const uint8_t[]){");
        for(size_t si = 0; si < tmp->len; si++)
            fprintf(out, "%s0x%02x", si ? "," : "", (unsigned char)tmp->string[si]);
        fprintf(out, "}, .proof_mocking_dst_len = %zu,\n", tmp->len);

        tmp = json_object_get(j, "proof");
        fprintf(out, "\t\t.result = (const uint8_t[])");
        print_hex_str(tmp, out);
        fprintf(out, ", .result_len = %zu,\n", tmp->len / 2);

        tmp = json_object_get(j, "result");
        fprintf(out, "\t\t.result_valid = %d\n",
            JSON_TRUE == json_object_get(tmp, "valid")->type);

        fprintf(out, "\t},\n");
        json_free(j); free(f);
    }
    fprintf(out, "};\n");
    fprintf(out, "const struct blind_with_nym_fixture_proof *const vectors_blind_with_nym_proof = _vectors_blind_with_nym_proof;\n");
    fprintf(out, "const size_t vectors_blind_with_nym_proof_len = %d;\n\n", --filenum);
}

int main(int argc, char **argv) {
	FILE *out;
	char filename[100];
	char *cipher_suite;
	char *f, *f2;
	struct json *j, *j2, *tmp;
	int dirfd, i, filenum, is_blind = 0;
	size_t mocked_seed_len, mocked_dst_len;

	// Argument parsing
	if(argc != 3) { printf("Usage: %s <ciphersuite> <source_dir>\n", argv[0]); exit(0); }
	if (!strcmp(argv[1], "bls12-381-sha-256"))
        { cipher_suite = "bbs_sha256_ciphersuite"; }
	else if(!strcmp(argv[1], "bls12-381-shake-256"))
        { cipher_suite = "bbs_shake256_ciphersuite"; }
    else if(!strcmp(argv[1], "bls12-381-blind-sha-256"))
        { cipher_suite = "bbs_blind_sha256_ciphersuite"; is_blind = 1; }
	else if(!strcmp(argv[1], "bls12-381-blind-shake-256"))
		{ cipher_suite = "bbs_blind_shake256_ciphersuite"; is_blind = 1; }
    else if(!strcmp(argv[1], "bls12-381-blind-with-nym-sha-256"))
        { cipher_suite = "bbs_blind_nym_sha256_ciphersuite"; is_blind = 2; }
    else if(!strcmp(argv[1], "bls12-381-blind-with-nym-shake-256"))
        { cipher_suite = "bbs_blind_nym_shake256_ciphersuite"; is_blind = 2; }
	else fail("Invalid Cipher Suite");

    // Open directory and outfile.
	sprintf(filename, "fixtures_%s.c", argv[1]);
	if(!(out = fopen(filename, "w"))) fail("fopen");
	if(-1 == chdir(argv[2])) fail("chdir");

    if(is_blind == 1) {
        sprintf(filename, "blind_fixtures_data/%s",
            !strcmp(argv[1], "bls12-381-blind-sha-256")
                ? "bls12-381-sha-256" : "bls12-381-shake-256");
    } else if(is_blind == 2) {
        sprintf(filename, "blind_with_pseudonym_fixtures_data/%s",
            !strcmp(argv[1], "bls12-381-blind-with-nym-sha-256")
                ? "bls12-381-sha-256" : "bls12-381-shake-256");
    } else {
        sprintf(filename, "fixtures_data/%s", argv[1]);
    }

	if(-1 == (dirfd = open(filename, O_RDONLY | O_DIRECTORY))) fail("open");

	// Header
	fprintf(out, "// Generated by %s. DO NOT EDIT!\n\n", argv[0]);
	fprintf(out, "#include \"fixtures.h\"\n\n");

	// Ciphersuite
	fprintf(out, "const bbs_ciphersuite *const *const fixture_ciphersuite = &%s; \n\n", cipher_suite);
	fprintf(out, "const char *const fixture_ciphersuite_name = \"%s\"; \n\n", argv[1]);

    if (is_blind == 1) {
		// Blind Generators
		f = read_file(dirfd, "generators.json");
		json_parse(f, &j);
		struct json *signer_gen = json_object_get(j, "generators");
		struct json *prover_gen = json_object_get(j, "blindGenerators");

		fprintf(out, "static const uint8_t blind_signer_generators[][48] = {\n\t");
		print_hex_str(json_object_get(signer_gen, "Q1"), out);
		i = 1;
		for(struct json *k = json_object_get(signer_gen, "MsgGenerators")->value; k; k = k->next) {
			fprintf(out, ",\n\t");
			print_hex_str(k, out);
			i++;
		}
		int signer_count = i;
		fprintf(out, "\n};\n");

		fprintf(out, "static const uint8_t blind_prover_generators[][48] = {\n\t");
		print_hex_str(json_object_get(prover_gen, "Q1"), out);
		i = 1;
		for(struct json *k = json_object_get(prover_gen, "MsgGenerators")->value; k; k = k->next) {
			fprintf(out, ",\n\t");
			print_hex_str(k, out);
			i++;
		}
		int prover_count = i;
		fprintf(out, "\n};\n");

		fprintf(out, "static const struct blind_fixture_generators _vectors_blind_generators[] = {\n");
		fprintf(out, "\t{ .signer_result = blind_signer_generators, .signer_result_len = %d,\n", signer_count);
		fprintf(out, "\t  .prover_result  = blind_prover_generators, .prover_result_len  = %d }\n", prover_count);
		fprintf(out, "};\n");
		fprintf(out, "const struct blind_fixture_generators *const vectors_blind_generators = _vectors_blind_generators;\n");
		fprintf(out, "const size_t vectors_blind_generators_len = 1;\n\n");
		json_free(j);
		free(f);

        // Blind Commit
        fprintf(out, "static const struct blind_fixture_commit _vectors_blind_commit[] = {\n");
        for(filenum = 1; 1; filenum++) {
            sprintf(filename, "commit/commit%03d.json", filenum);
            if(!existsat(dirfd, filename)) break;
            f = read_file(dirfd, filename);
            json_parse(f, &j);

            struct json *mock   = json_object_get(j, "mockRngParameters");
            struct json *commit = json_object_get(mock, "commit");

            fprintf(out, "\t{\n");

            tmp = json_object_get(mock, "SEED");
            fprintf(out, "\t\t.mocking_seed = (const uint8_t[]){");
            for(size_t si = 0; si < tmp->len; si++)
                fprintf(out, "%s0x%02x", si ? "," : "", (unsigned char)tmp->string[si]);
            fprintf(out, "},\n\t\t.mocking_seed_len = %zu,\n", tmp->len);

            tmp = json_object_get(commit, "DST");
            fprintf(out, "\t\t.mocking_dst = (const uint8_t[]){");
            for(size_t si = 0; si < tmp->len; si++)
                fprintf(out, "%s0x%02x", si ? "," : "", (unsigned char)tmp->string[si]);
            fprintf(out, "},\n\t\t.mocking_dst_len = %zu,\n", tmp->len);

            tmp = json_object_get(commit, "count");
            fprintf(out, "\t\t.mocking_count = %.*s,\n", (int)tmp->len, tmp->string);

            i = 0;
            for(struct json *k = json_object_get(j, "committedMessages")->value; k; k = k->next) i++;
            fprintf(out, "\t\t.num_committed_messages = %d,\n", i);

            if (i == 0) { // print array as NULL if empty
                fprintf(out, "\t\t.committed_msgs = NULL,\n");
                fprintf(out, "\t\t.committed_msg_lens = NULL,\n");
            } else {
                fprintf(out, "\t\t.committed_msgs = (const void *const[]){");
                for(struct json *k = json_object_get(j, "committedMessages")->value; k; k = k->next) {
                    fprintf(out, "(const uint8_t[])");
                    print_hex_str(k, out);
                    fprintf(out, ", ");
                }
                fprintf(out, "},\n");

                fprintf(out, "\t\t.committed_msg_lens = (const size_t[]){");
                for(struct json *k = json_object_get(j, "committedMessages")->value; k; k = k->next)
                    fprintf(out, "%zu, ", k->len / 2);
                fprintf(out, "},\n");
            }

            fprintf(out, "\t\t.prover_blind = ");
            print_hex_str(json_object_get(j, "proverBlind"), out);
            fprintf(out, ",\n");

            tmp = json_object_get(j, "commitmentWithProof");
            fprintf(out, "\t\t.result = (const uint8_t[])");
            print_hex_str(tmp, out);
            fprintf(out, ", .result_len = %zu,\n", tmp->len / 2);

            tmp = json_object_get(j, "result");
            fprintf(out, "\t\t.result_valid = %d\n", JSON_TRUE == json_object_get(tmp, "valid")->type);

            fprintf(out, "\t},\n");
            json_free(j); free(f);
        }
        fprintf(out, "};\n");
        fprintf(out, "const struct blind_fixture_commit *const vectors_blind_commit = _vectors_blind_commit;\n");
        fprintf(out, "const size_t vectors_blind_commit_len = %d;\n\n", --filenum);

        // Blind Signatures
        fprintf(out, "static const struct blind_fixture_signature _vectors_blind_signature[] = {\n");
        for(filenum = 1; 1; filenum++) {
            sprintf(filename, "signature/signature%03d.json", filenum);
            if(!existsat(dirfd, filename)) break;
            f = read_file(dirfd, filename);
            json_parse(f, &j);

            struct json *kp  = json_object_get(j, "signerKeyPair");
            struct json *cwp = json_object_get(j, "commitmentWithProof");
            struct json *pb  = json_object_get(j, "proverBlind");
            struct json *cm  = json_object_get(j, "committedMessages");
            struct json *msgs = json_object_get(j, "messages");

            fprintf(out, "\t{\n");

            fprintf(out, "\t\t.sk = ");
            print_hex_str(json_object_get(kp, "secretKey"), out);
            fprintf(out, ",\n\t\t.pk = ");
            print_hex_str(json_object_get(kp, "publicKey"), out);
            fprintf(out, ",\n");

            tmp = json_object_get(j, "header");
            fprintf(out, "\t\t.header = (const uint8_t[])");
            print_hex_str(tmp, out);
            fprintf(out, ", .header_len = %zu,\n", tmp->len / 2);

            // commitmentWithProof
            if(cwp->type == JSON_NULL) {
                fprintf(out, "\t\t.commitment_with_proof = NULL, .commitment_with_proof_len = 0,\n");
            } else {
                fprintf(out, "\t\t.commitment_with_proof = (const uint8_t[])");
                print_hex_str(cwp, out);
                fprintf(out, ", .commitment_with_proof_len = %zu,\n", cwp->len / 2);
            }

            // signer messages
            i = 0;
            for(struct json *k = msgs->value; k; k = k->next) i++;
            fprintf(out, "\t\t.num_messages = %d,\n", i);
            if(i == 0) {
                fprintf(out, "\t\t.msgs = NULL, .msg_lens = NULL,\n");
            } else {
                fprintf(out, "\t\t.msgs = (const void *const[]){");
                for(struct json *k = msgs->value; k; k = k->next) {
                    fprintf(out, "(const uint8_t[])");
                    print_hex_str(k, out);
                    fprintf(out, ", ");
                }
                fprintf(out, "},\n\t\t.msg_lens = (const size_t[]){");
                for(struct json *k = msgs->value; k; k = k->next)
                    fprintf(out, "%zu, ", k->len / 2);
                fprintf(out, "},\n");
            }

            // committed messages
            i = 0;
            if(cm->type != JSON_NULL)
                for(struct json *k = cm->value; k; k = k->next) i++;
            fprintf(out, "\t\t.num_committed_messages = %d,\n", i);
            if(i == 0) {
                fprintf(out, "\t\t.committed_msgs = NULL, .committed_msg_lens = NULL,\n");
            } else {
                fprintf(out, "\t\t.committed_msgs = (const void *const[]){");
                for(struct json *k = cm->value; k; k = k->next) {
                    fprintf(out, "(const uint8_t[])");
                    print_hex_str(k, out);
                    fprintf(out, ", ");
                }
                fprintf(out, "},\n\t\t.committed_msg_lens = (const size_t[]){");
                for(struct json *k = cm->value; k; k = k->next)
                    fprintf(out, "%zu, ", k->len / 2);
                fprintf(out, "},\n");
            }

            // proverBlind
            fprintf(out, "\t\t.prover_blind = ");
            if(pb->type == JSON_NULL)
                fprintf(out, "{0}");
            else
                print_hex_str(pb, out);
            fprintf(out, ",\n");

            fprintf(out, "\t\t.result = ");
            print_hex_str(json_object_get(j, "signature"), out);
            fprintf(out, ",\n");

            tmp = json_object_get(j, "result");
            fprintf(out, "\t\t.result_valid = %d\n",
                JSON_TRUE == json_object_get(tmp, "valid")->type);

            fprintf(out, "\t},\n");
            json_free(j); free(f);
        }
        fprintf(out, "};\n");
        fprintf(out, "const struct blind_fixture_signature *const vectors_blind_signature = _vectors_blind_signature;\n");
        fprintf(out, "const size_t vectors_blind_signature_len = %d;\n\n", --filenum);

        // read messages and committed messages once from messages.json as those are all the same for all test vectors
        f = read_file(dirfd, "../messages.json");
        json_parse(f, &j2);
        struct json *all_msgs = json_object_get(j2, "messages");
        struct json *all_committed = json_object_get(j2, "committedMessages");
        int n_msgs = 0;
        for(struct json *k = all_msgs->value; k; k = k->next) n_msgs++;
        int n_committed = 0;
        for(struct json *k = all_committed->value; k; k = k->next) n_committed++;

        // Blind Proofs
        fprintf(out, "static const struct blind_fixture_proof _vectors_blind_proof[] = {\n");
        for(filenum = 1; 1; filenum++) {
            sprintf(filename, "proof/proof%03d.json", filenum);
            if(!existsat(dirfd, filename)) break;
            f = read_file(dirfd, filename);
            json_parse(f, &j);

            struct json *mock = json_object_get(j, "mockRngParameters");
            struct json *proof_rng = json_object_get(mock, "proof");
            struct json *pb = json_object_get(j, "proverBlind");
            struct json *revealed = json_object_get(j, "revealedMessages");
            struct json *revealed_committed = json_object_get(j, "revealedCommittedMessages");

            // count disclosed
            int n_disclosed = 0;
            if(revealed->type != JSON_NULL)
                for(struct json *k = revealed->value; k; k = k->next) n_disclosed++;
            int n_disclosed_committed = 0;
            if(revealed_committed && revealed_committed->type != JSON_NULL)
                for(struct json *k = revealed_committed->value; k; k = k->next) n_disclosed_committed++;

            fprintf(out, "\t{\n");

            // pk and signature
            fprintf(out, "\t\t.pk = ");
            print_hex_str(json_object_get(j, "signerPublicKey"), out);
            fprintf(out, ",\n\t\t.signature = ");
            print_hex_str(json_object_get(j, "signature"), out);
            fprintf(out, ",\n");

            // header and presentation header
            tmp = json_object_get(j, "header");
            fprintf(out, "\t\t.header = (const uint8_t[])");
            print_hex_str(tmp, out);
            fprintf(out, ", .header_len = %zu,\n", tmp->len / 2);
            tmp = json_object_get(j, "presentationHeader");
            fprintf(out, "\t\t.presentation_header = (const uint8_t[])");
            print_hex_str(tmp, out);
            fprintf(out, ", .presentation_header_len = %zu,\n", tmp->len / 2);

            // proverBlind
            fprintf(out, "\t\t.prover_blind = ");
            if(pb->type == JSON_NULL) fprintf(out, "{0}");
            else print_hex_str(pb, out);
            fprintf(out, ",\n");

            // all messages (from messages.json)
            fprintf(out, "\t\t.num_messages = %d,\n", n_msgs);
            fprintf(out, "\t\t.msgs = (const void *const[]){");
            for(struct json *k = all_msgs->value; k; k = k->next) {
                fprintf(out, "(const uint8_t[])"); print_hex_str(k, out); fprintf(out, ", ");
            }
            fprintf(out, "},\n\t\t.msg_lens = (const size_t[]){");
            for(struct json *k = all_msgs->value; k; k = k->next)
                fprintf(out, "%zu, ", k->len / 2);
            fprintf(out, "},\n");

            // all committed messages, if there is no committmentWithProof in the test vector there is also
            // no committed messages
            if(pb->type == JSON_NULL) {
                fprintf(out, "\t\t.num_committed_messages = 0,\n");
                fprintf(out, "\t\t.committed_msgs = NULL, .committed_msg_lens = NULL,\n");
            } else {
                fprintf(out, "\t\t.num_committed_messages = %d,\n", n_committed);
                fprintf(out, "\t\t.committed_msgs = (const void *const[]){");
                for(struct json *k = all_committed->value; k; k = k->next) {
                    fprintf(out, "(const uint8_t[])"); print_hex_str(k, out); fprintf(out, ", ");
                }
                fprintf(out, "},\n\t\t.committed_msg_lens = (const size_t[]){");
                for(struct json *k = all_committed->value; k; k = k->next)
                    fprintf(out, "%zu, ", k->len / 2);
                fprintf(out, "},\n");
            }

            // revealedMessages
            fprintf(out, "\t\t.disclosed_indexes_len = %d,\n", n_disclosed);
            if(n_disclosed == 0) {
                fprintf(out, "\t\t.disclosed_indexes = NULL,\n");
                fprintf(out, "\t\t.disclosed_msgs = NULL, .disclosed_msg_lens = NULL,\n");
                fprintf(out, "\t\t.disclosed_msgs_len = 0,\n");
            } else {
                fprintf(out, "\t\t.disclosed_indexes = (const size_t[]){");
                for(struct json *k = revealed->value; k; k = k->next)
                    fprintf(out, "%.*s, ", (int)k->len, k->string);
                fprintf(out, "},\n");
                fprintf(out, "\t\t.disclosed_msgs = (const void *const[]){");
                for(struct json *k = revealed->value; k; k = k->next) {
                    fprintf(out, "(const uint8_t[])"); print_hex_str(k->value, out); fprintf(out, ", ");
                }
                fprintf(out, "},\n\t\t.disclosed_msg_lens = (const size_t[]){");
                for(struct json *k = revealed->value; k; k = k->next)
                    fprintf(out, "%zu, ", k->value->len / 2);
                fprintf(out, "},\n");
                fprintf(out, "\t\t.disclosed_msgs_len = %d,\n", n_disclosed);
            }

            // revealedCommittedMessages
            fprintf(out, "\t\t.disclosed_committed_indexes_len = %d,\n", n_disclosed_committed);
            if(n_disclosed_committed == 0) {
                fprintf(out, "\t\t.disclosed_committed_indexes = NULL,\n");
                fprintf(out, "\t\t.disclosed_committed_msgs = NULL, .disclosed_committed_msg_lens = NULL,\n");
                fprintf(out, "\t\t.disclosed_committed_msgs_len = 0,\n");
            } else {
                fprintf(out, "\t\t.disclosed_committed_indexes = (const size_t[]){");
                for(struct json *k = revealed_committed->value; k; k = k->next)
                    fprintf(out, "%.*s, ", (int)k->len, k->string);
                fprintf(out, "},\n");
                fprintf(out, "\t\t.disclosed_committed_msgs = (const void *const[]){");
                for(struct json *k = revealed_committed->value; k; k = k->next) {
                    fprintf(out, "(const uint8_t[])"); print_hex_str(k->value, out); fprintf(out, ", ");
                }
                fprintf(out, "},\n\t\t.disclosed_committed_msg_lens = (const size_t[]){");
                for(struct json *k = revealed_committed->value; k; k = k->next)
                    fprintf(out, "%zu, ", k->value->len / 2);
                fprintf(out, "},\n");
                fprintf(out, "\t\t.disclosed_committed_msgs_len = %d,\n", n_disclosed_committed);
            }

            // L
            tmp = json_object_get(j, "L");
            fprintf(out, "\t\t.L = %.*s,\n", (int)tmp->len, tmp->string);

            // proof mocking
            tmp = json_object_get(mock, "SEED");
            fprintf(out, "\t\t.proof_mocking_seed = (const uint8_t[]){");
            for(size_t si = 0; si < tmp->len; si++)
                fprintf(out, "%s0x%02x", si ? "," : "", (unsigned char)tmp->string[si]);
            fprintf(out, "}, .proof_mocking_seed_len = %zu,\n", tmp->len);
            tmp = json_object_get(proof_rng, "DST");
            fprintf(out, "\t\t.proof_mocking_dst = (const uint8_t[]){");
            for(size_t si = 0; si < tmp->len; si++)
                fprintf(out, "%s0x%02x", si ? "," : "", (unsigned char)tmp->string[si]);
            fprintf(out, "}, .proof_mocking_dst_len = %zu,\n", tmp->len);

            // result
            tmp = json_object_get(j, "proof");
            fprintf(out, "\t\t.result = (const uint8_t[])");
            print_hex_str(tmp, out);
            fprintf(out, ", .result_len = %zu,\n", tmp->len / 2);
            tmp = json_object_get(j, "result");
            fprintf(out, "\t\t.result_valid = %d\n",
                JSON_TRUE == json_object_get(tmp, "valid")->type);

            fprintf(out, "\t},\n");
            json_free(j); free(f);
        }
        fprintf(out, "};\n");
        fprintf(out, "const struct blind_fixture_proof *const vectors_blind_proof = _vectors_blind_proof;\n");
        fprintf(out, "const size_t vectors_blind_proof_len = %d;\n\n", --filenum);
    } else if (is_blind == 2) {
        // BLIND WITH NYM
        parse_blind_with_nym_fixtures(out, dirfd);
    } else {
        // Hash to Scalar
        f = read_file(dirfd, "MapMessageToScalarAsHash.json");
        json_parse(f, &j);
        f2 = read_file(dirfd, "h2s.json");
        json_parse(f2, &j2);
        fprintf(out, "static const uint8_t h2s_message%d[] = ", i = 0);
        tmp = json_object_get(j2, "message");
        print_hex_str(tmp, out);
        fprintf(out, ";\nstatic const uint8_t h2s_dst%d[] = ", i++);
        tmp = json_object_get(j2, "dst");
        print_hex_str(tmp, out);
        fprintf(out, ";\n");
        for(struct json *k=json_object_get(j, "cases")->value; k; k = k->next) {
            fprintf(out, "static const uint8_t h2s_message%d[] = ", i);
            tmp = json_object_get(k, "message");
            print_hex_str(tmp, out);
            fprintf(out, ";\nstatic const uint8_t h2s_dst%d[] = ", i++);
            tmp = json_object_get(j, "dst");
            print_hex_str(tmp, out);
            fprintf(out, ";\n");
        }
        fprintf(out, "static const struct fixture_hash_to_scalar _vectors_hash_to_scalar[] = {\n");
        tmp = json_object_get(j2, "message");
        fprintf(out, "\t{ .msg = h2s_message%d, .msg_len = %zu, ", i = 0, tmp->len / 2);
        tmp = json_object_get(j2, "dst");
        fprintf(out, ".dst = h2s_dst%d, .dst_len = %zu, .result = ", i++, tmp->len / 2);
        tmp = json_object_get(j2, "scalar");
        print_hex_str(tmp, out);
        fprintf(out, "},\n");
        for(struct json *k=json_object_get(j, "cases")->value; k; k = k->next) {
            tmp = json_object_get(k, "message");
            fprintf(out, "\t{ .msg = h2s_message%d, .msg_len = %zu, ", i, tmp->len / 2);
            tmp = json_object_get(j, "dst");
            fprintf(out, ".dst = h2s_dst%d, .dst_len = %zu, .result = ", i++, tmp->len / 2);
            tmp = json_object_get(k, "scalar");
            print_hex_str(tmp, out);
            fprintf(out, "},\n");
        }
        fprintf(out, "};\n");
        fprintf(out, "const struct fixture_hash_to_scalar *const vectors_hash_to_scalar = _vectors_hash_to_scalar;\n");
        fprintf(out, "const size_t vectors_hash_to_scalar_len = %d;\n\n", i);
        json_free(j2);
        free(f2);
        json_free(j);
        free(f);

        // Generators
        f = read_file(dirfd, "generators.json");
        json_parse(f, &j);
        fprintf(out, "static const uint8_t generators[][48] = {\n\t");
        print_hex_str(json_object_get(j, "Q1"), out);
        i=1;
        for(struct json *k=json_object_get(j, "MsgGenerators")->value; k; k = k->next) {
            fprintf(out, ",\n\t");
            print_hex_str(k, out);
            i++;
        }
        fprintf(out, "\n};\n");
        fprintf(out, "static const struct fixture_generators _vectors_generators[] = {\n");
        fprintf(out, "\t{ .result = generators, .result_len = %d }\n", i);
        fprintf(out, "};\n");
        fprintf(out, "const struct fixture_generators *const vectors_generators = _vectors_generators;\n");
        fprintf(out, "const size_t vectors_generators_len = %d;\n\n", 1);
        json_free(j);
        free(f);

        // Keygen
        f = read_file(dirfd, "keypair.json");
        json_parse(f, &j);
        fprintf(out, "static const uint8_t keygen_material[] = ");
        print_hex_str(json_object_get(j, "keyMaterial"), out);
        fprintf(out, ";\nstatic const uint8_t keygen_info[] = ");
        print_hex_str(json_object_get(j, "keyInfo"), out);
        fprintf(out, ";\nstatic const uint8_t keygen_dst[] = ");
        print_hex_str(json_object_get(j, "keyDst"), out);
        fprintf(out, ";\nstatic const struct fixture_keygen _vectors_keygen[] = {\n");
        fprintf(out, "\t{ .key_material = keygen_material, .key_material_len = %zu, ", json_object_get(j, "keyMaterial")->len/2);
        fprintf(out, ".key_info = keygen_info, .key_info_len = %zu, ", json_object_get(j, "keyInfo")->len/2);
        fprintf(out, ".key_dst = keygen_dst, .key_dst_len = %zu, ", json_object_get(j, "keyDst")->len/2);
        tmp = json_object_get(j, "keyPair");
        fprintf(out, ".result_sk = ");
        print_hex_str(json_object_get(tmp, "secretKey"), out);
        fprintf(out, ", .result_pk = ");
        print_hex_str(json_object_get(tmp, "publicKey"), out);
        fprintf(out, "}\n};\n");
        fprintf(out, "const struct fixture_keygen *const vectors_keygen = _vectors_keygen;\n");
        fprintf(out, "const size_t vectors_keygen_len = %d;\n\n", 1);
        json_free(j);
        free(f);

        // Signatures
        for(filenum = 1; 1; filenum++) {
            sprintf(filename, "signature/signature%03d.json", filenum);
            if(!existsat(dirfd, filename)) break;

            f = read_file(dirfd, filename);
            json_parse(f, &j);
            fprintf(out, "static const uint8_t signature%d_header[] = ", filenum);
            print_hex_str(json_object_get(j, "header"), out);
            i = 0;
            for(struct json *k=json_object_get(j, "messages")->value; k; k = k->next) {
                fprintf(out, ";\nstatic const uint8_t signature%d_msg%d[] = ", filenum, i++);
                print_hex_str(k, out);
            }
            fprintf(out, ";\nstatic const void *const signature%d_msgs[] = {", filenum);
            for(int ii=0; ii<i; ii++) fprintf(out, "signature%d_msg%d, ", filenum, ii);
            fprintf(out, "};\nstatic const size_t signature%d_msg_lens[] = {", filenum);
            for(struct json *k=json_object_get(j, "messages")->value; k; k = k->next) {
                fprintf(out, "%zu, ", k->len/2);
            }
            fprintf(out, "};\n");
            json_free(j);
            free(f);
        }
        fprintf(out, "static const struct fixture_signature _vectors_signature[] = {\n");
        for(filenum = 1; 1; filenum++) {
            sprintf(filename, "signature/signature%03d.json", filenum);
            if(!existsat(dirfd, filename)) break;

            f = read_file(dirfd, filename);
            json_parse(f, &j);
            fprintf(out, "\t{ .sk = ");
            tmp = json_object_get(j, "signerKeyPair");
            print_hex_str(json_object_get(tmp, "secretKey"), out);
            fprintf(out, ", .pk = ");
            print_hex_str(json_object_get(tmp, "publicKey"), out);
            tmp = json_object_get(j, "header");
            fprintf(out, ", .header = signature%d_header, .header_len = %zu", filenum, tmp->len/2);
            fprintf(out, ", .num_messages = %zu", json_array_len(json_object_get(j, "messages")));
            fprintf(out, ", .msgs = signature%d_msgs, .msg_lens = signature%d_msg_lens", filenum, filenum);
            fprintf(out, ", .result = ");
            print_hex_str(json_object_get(j, "signature"), out);
            tmp = json_object_get(j, "result");
            fprintf(out, ", .result_valid = %d },\n", JSON_TRUE == json_object_get(tmp, "valid")->type);
            json_free(j);
            free(f);
        }
        fprintf(out, "};\n");
        fprintf(out, "const struct fixture_signature *const vectors_signature = _vectors_signature;\n");
        fprintf(out, "const size_t vectors_signature_len = %d;\n\n", --filenum);

        // Mocked Scalars
        f = read_file(dirfd, "mockedRng.json");
        json_parse(f, &j);
        fprintf(out, "static const uint8_t mocked_seed[] = ");
        tmp = json_object_get(j, "seed");
        print_hex_str(tmp, out);
        mocked_seed_len = tmp->len/2;
        fprintf(out, ";\nstatic const uint8_t mocked_dst[] = ");
        tmp = json_object_get(j, "dst");
        print_hex_str(tmp, out);
        mocked_dst_len = tmp->len/2;
        fprintf(out, ";\nstatic const uint8_t mocked_scalars[][32] = {\n");
        i=0;
        for(struct json *k=json_object_get(j, "mockedScalars")->value; k; k = k->next) {
            fprintf(out, "\t");
            print_hex_str(k, out);
            fprintf(out, ",\n");
            i++;
        }
        fprintf(out, "};\n");
        fprintf(out, "static const struct fixture_mocked_scalars _vectors_mocked_scalars[] = {\n");
        fprintf(out, "\t{ .seed = mocked_seed, .seed_len = %zu", mocked_seed_len);
        fprintf(out, ", .dst = mocked_dst, .dst_len = %zu", mocked_dst_len);
        fprintf(out, ", .result = mocked_scalars, .result_len = %d }\n", i);
        fprintf(out, "};\n");
        fprintf(out, "const struct fixture_mocked_scalars *const vectors_mocked_scalars = _vectors_mocked_scalars;\n");
        fprintf(out, "const size_t vectors_mocked_scalars_len = %d;\n\n", 1);
        json_free(j);
        free(f);

        // Proofs
        for(filenum = 1; 1; filenum++) {
            sprintf(filename, "proof/proof%03d.json", filenum);
            if(!existsat(dirfd, filename)) break;

            f = read_file(dirfd, filename);
            json_parse(f, &j);
            fprintf(out, "static const uint8_t proof%d_header[] = ", filenum);
            print_hex_str(json_object_get(j, "header"), out);
            fprintf(out, ";\nstatic const uint8_t proof%d_presentation_header[] = ", filenum);
            print_hex_str(json_object_get(j, "presentationHeader"), out);
            i = 0;
            for(struct json *k=json_object_get(j, "messages")->value; k; k = k->next) {
                fprintf(out, ";\nstatic const uint8_t proof%d_msg%d[] = ", filenum, i++);
                print_hex_str(k, out);
            }
            fprintf(out, ";\nstatic const void *const proof%d_msgs[] = {", filenum);
            for(int ii=0; ii<i; ii++) fprintf(out, "proof%d_msg%d, ", filenum, ii);
            fprintf(out, "};\nstatic const size_t proof%d_msg_lens[] = {", filenum);
            for(struct json *k=json_object_get(j, "messages")->value; k; k = k->next) {
                fprintf(out, "%zu, ", k->len/2);
            }
            fprintf(out, "};\nstatic const size_t proof%d_disclosed_indexes[] = {", filenum);
            for(struct json *k=json_object_get(j, "disclosedIndexes")->value; k; k = k->next) {
                fprintf(out, "%.*s, ", (int)k->len, k->string);
            }
            fprintf(out, "};\nstatic const uint8_t proof%d_proof[] = ", filenum);
            print_hex_str(json_object_get(j, "proof"), out);
            fprintf(out, ";\n");
            json_free(j);
            free(f);
        }
        fprintf(out, "static const struct fixture_proof _vectors_proof[] = {\n");
        for(filenum = 1; 1; filenum++) {
            sprintf(filename, "proof/proof%03d.json", filenum);
            if(!existsat(dirfd, filename)) break;

            f = read_file(dirfd, filename);
            json_parse(f, &j);
            fprintf(out, "\t{ .pk = ");
            print_hex_str(json_object_get(j, "signerPublicKey"), out);
            fprintf(out, ", .signature = ");
            print_hex_str(json_object_get(j, "signature"), out);
            tmp = json_object_get(j, "header");
            fprintf(out, ", .header = proof%d_header, .header_len = %zu", filenum, tmp->len/2);
            tmp = json_object_get(j, "presentationHeader");
            fprintf(out, ", .presentation_header = proof%d_presentation_header, .presentation_header_len = %zu", filenum, tmp->len/2);
            fprintf(out, ", .num_messages = %zu", json_array_len(json_object_get(j, "messages")));
            fprintf(out, ", .msgs = proof%d_msgs, .msg_lens = proof%d_msg_lens", filenum, filenum);
            fprintf(out, ", .disclosed_indexes = proof%d_disclosed_indexes", filenum);
            fprintf(out, ", .disclosed_indexes_len = %zu", json_array_len(json_object_get(j, "disclosedIndexes")));
            fprintf(out, ", .mocking_seed = mocked_seed, .mocking_seed_len = %zu", mocked_seed_len);
            fprintf(out, ", .mocking_dst = mocked_dst, .mocking_dst_len = %zu", mocked_dst_len);
            tmp = json_object_get(j, "proof");
            fprintf(out, ", .result = proof%d_proof, .result_len = %zu", filenum, tmp->len/2);
            tmp = json_object_get(j, "result");
            fprintf(out, ", .result_valid = %d },\n", JSON_TRUE == json_object_get(tmp, "valid")->type);
            json_free(j);
            free(f);
        }
        fprintf(out, "};\n");
        fprintf(out, "const struct fixture_proof *const vectors_proof = _vectors_proof;\n");
        fprintf(out, "const size_t vectors_proof_len = %d;\n\n", --filenum);
    }

	if(fclose(out)) fail("fclose");
	return 0;
}

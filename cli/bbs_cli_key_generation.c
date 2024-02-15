#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include "bbs_cli_key_generation.h"
#include "bbs_key_generation.h"

struct arguments {
    char* key_material;
    char* key_info;
    char* key_dst;
};

static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    struct arguments* arguments = state->input;

    switch (key) {
        case 'm': arguments->key_material = arg; break;
        case 'i': arguments->key_info = arg; break;
        case 'd': arguments->key_dst = arg; break;
        default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

void key_gen_cli(int argc, char* argv[]) {
    static struct argp_option options[] = {
        {"key_material", 'm', "KEY_MATERIAL", 0, "Secret octet string (REQUIRED)"},
        {"key_info", 'i', "KEY_INFO", OPTION_ARG_OPTIONAL, "Octet string (OPTIONAL)"},
        {"key_dst", 'd', "KEY_DST", OPTION_ARG_OPTIONAL, "Domain separation tag (OPTIONAL)"},
        {0}};
    static char doc[] = "KeyGen -- a tool for generating a secret key";
    static char args_doc[] = "";

    static struct argp argp = {options, parse_opt, args_doc, doc};

    struct arguments arguments;

    // Default values
    arguments.key_info = "";
    arguments.key_dst = "ciphersuite_id || KEYGEN_DST_";

    // Parse arguments
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    printf("KeyGen called with arguments: key_material=%s, key_info=%s, key_dst=%s\n", arguments.key_material,
           arguments.key_info, arguments.key_dst);

    // KeyGen(arguments.key_material, arguments.key_info, arguments.key_dst);
}

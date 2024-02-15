#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "bbs_cli_key_generation.h"

// Named bbs command
struct commands {
    char* name;
    void (*func)(int argc, char* argv[]);
};

/*
 * Print available commands
 *
 * @param commands: array of commands terminated by NULL entry
 */
void print_commands(struct commands commands[]) {
    printf("Usage: bbs <command> [<args>]\n");
    printf("Available commands:\n");
    for (int i = 0; commands[i].name != NULL; i++) {
        printf("  %s\n", commands[i].name);
    }
}

int main(int argc, char* argv[]) {
    static struct commands commands[] = {
        {"keygen", key_gen_cli},
        {NULL, NULL},
    };

    if (argc < 2) {
        print_commands(commands);
        return 1;
    }
    for (int i = 0; commands[i].name != NULL; i++) {
        if (strcmp(argv[1], commands[i].name) == 0) {
            commands[i].func(argc - 1, argv + 1);
            return 0;
        }
    }
    print_commands(commands);
    return 1;
}

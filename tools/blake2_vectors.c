#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blake2.h"

typedef struct {
    size_t digest_length;
    unsigned char key[BLAKE2B_KEYBYTES];
    size_t key_length;
    unsigned char salt[BLAKE2B_SALTBYTES];
    size_t salt_length;
    unsigned char personal[BLAKE2B_PERSONALBYTES];
    size_t personal_length;
    unsigned char message[2048];
    size_t message_length;
} blake2_case;

static size_t unhex(const char *text, unsigned char *out, size_t capacity)
{
    size_t length = strcmp(text, "-") == 0 ? 0 : strlen(text) / 2;

    if (length > capacity) {
        exit(1);
    }

    for (size_t i = 0; i < length; i++) {
        unsigned int byte;

        if (sscanf(text + 2 * i, "%2x", &byte) != 1) {
            exit(1);
        }

        out[i] = (unsigned char)byte;
    }

    return length;
}

// The parameter block is filled here, as the reference code's own init functions set no salt or
// personalization; a key is then absorbed as one zero-padded block, as blake2b_init_key does.
static int blake2b_case(unsigned char *out, const blake2_case *c)
{
    blake2b_param param;

    blake2b_state state;

    unsigned char block[BLAKE2B_BLOCKBYTES] = {0};

    memset(&param, 0, sizeof param);

    param.digest_length = (uint8_t)c->digest_length;

    param.key_length = (uint8_t)c->key_length;

    param.fanout = 1;

    param.depth = 1;

    memcpy(param.salt, c->salt, c->salt_length);

    memcpy(param.personal, c->personal, c->personal_length);

    if (blake2b_init_param(&state, &param) != 0) {
        return 1;
    }

    if (c->key_length > 0) {
        memcpy(block, c->key, c->key_length);

        blake2b_update(&state, block, sizeof block);
    }

    blake2b_update(&state, c->message, c->message_length);

    return blake2b_final(&state, out, c->digest_length) != 0;
}

static int blake2s_case(unsigned char *out, const blake2_case *c)
{
    blake2s_param param;

    blake2s_state state;

    unsigned char block[BLAKE2S_BLOCKBYTES] = {0};

    memset(&param, 0, sizeof param);

    param.digest_length = (uint8_t)c->digest_length;

    param.key_length = (uint8_t)c->key_length;

    param.fanout = 1;

    param.depth = 1;

    memcpy(param.salt, c->salt, c->salt_length);

    memcpy(param.personal, c->personal, c->personal_length);

    if (blake2s_init_param(&state, &param) != 0) {
        return 1;
    }

    if (c->key_length > 0) {
        memcpy(block, c->key, c->key_length);

        blake2s_update(&state, block, sizeof block);
    }

    blake2s_update(&state, c->message, c->message_length);

    return blake2s_final(&state, out, c->digest_length) != 0;
}

// One case per input line: "b" or "s", the digest length, then the key, salt, personalization
// and message in hexadecimal ("-" when empty). Prints the digest of each case on its own line.
int main(void)
{
    static char line[8192], function[8], key[256], salt[64], personal[64], message[4096];

    static blake2_case c;

    static unsigned char out[BLAKE2B_OUTBYTES];

    unsigned int digest_length;

    while (fgets(line, sizeof line, stdin)) {
        int fields = sscanf(line, "%7s %u %255s %63s %63s %4095s", function, &digest_length, key, salt,
                            personal, message);

        int b = strcmp(function, "b") == 0;

        if (fields != 6 || (!b && strcmp(function, "s") != 0)) {
            return 1;
        }

        if (digest_length < 1 || digest_length > (b ? BLAKE2B_OUTBYTES : BLAKE2S_OUTBYTES)) {
            return 1;
        }

        c.digest_length = digest_length;

        c.key_length = unhex(key, c.key, b ? BLAKE2B_KEYBYTES : BLAKE2S_KEYBYTES);

        c.salt_length = unhex(salt, c.salt, b ? BLAKE2B_SALTBYTES : BLAKE2S_SALTBYTES);

        c.personal_length = unhex(personal, c.personal, b ? BLAKE2B_PERSONALBYTES : BLAKE2S_PERSONALBYTES);

        c.message_length = unhex(message, c.message, sizeof c.message);

        if (b ? blake2b_case(out, &c) : blake2s_case(out, &c)) {
            return 1;
        }

        for (size_t i = 0; i < c.digest_length; i++) {
            printf("%02x", out[i]);
        }

        printf("\n");
    }

    return 0;
}

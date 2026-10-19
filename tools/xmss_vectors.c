#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "params.h"
#include "utils.h"
#include "xmss_core.h"

static void print_hex(const char *key, const unsigned char *data, unsigned long long length)
{
    printf("%s = ", key);

    for (unsigned long long i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }

    printf("\n");
}

static int vector(const char *name, int multi_tree, uint32_t oid, unsigned long long index)
{
    xmss_params params;

    if ((multi_tree ? xmssmt_parse_oid(&params, oid) : xmss_parse_oid(&params, oid)) != 0) {
        return 1;
    }

    unsigned char seed[3 * 64];

    unsigned char pk[4 + 2 * 64];

    unsigned char sk[8 + 4 * 64];

    unsigned char message[33];

    static unsigned char sm[200000];

    unsigned long long smlen = 0;

    for (unsigned int i = 0; i < 3 * params.n; i++) {
        seed[i] = (unsigned char)(7 * i + oid);
    }

    for (unsigned int i = 0; i < sizeof message; i++) {
        message[i] = (unsigned char)(3 * i + index);
    }

    ull_to_bytes(pk, 4, oid);

    xmssmt_core_seed_keypair(&params, pk + 4, sk, seed);

    ull_to_bytes(sk, params.index_bytes, index);

    if (xmssmt_core_sign(&params, sk, sm, &smlen, message, sizeof message) != 0) {
        return 1;
    }

    printf("name = %s\n", name);

    print_hex("seed", seed, 3 * params.n);

    printf("index = %llu\n", index);

    print_hex("message", message, sizeof message);

    print_hex("publicKey", pk, 4 + 2 * params.n);

    print_hex("signature", sm, params.sig_bytes);

    printf("\n");

    return 0;
}

struct set {
    const char *name;
    int multi_tree;
    uint32_t oid;
    unsigned int height;
};

// The sets of vectors/xmss/xmss.txt.
static const struct set base[] = {
    {"XMSS-SHA2_10_256", 0, 0x01, 10},
    {"XMSS-SHA2_10_192", 0, 0x0d, 10},
    {"XMSS-SHAKE256_10_256", 0, 0x10, 10},
    {"XMSS-SHAKE256_10_192", 0, 0x13, 10},
    {"XMSSMT-SHA2_20/2_256", 1, 0x01, 20},
    {"XMSSMT-SHA2_20/4_256", 1, 0x02, 20},
    {"XMSSMT-SHA2_40/4_256", 1, 0x04, 40},
    {"XMSSMT-SHA2_40/8_256", 1, 0x05, 40},
    {"XMSSMT-SHA2_60/6_256", 1, 0x07, 60},
    {"XMSSMT-SHA2_60/12_256", 1, 0x08, 60},
    {"XMSSMT-SHA2_20/4_192", 1, 0x22, 20},
    {"XMSSMT-SHA2_60/12_192", 1, 0x28, 60},
    {"XMSSMT-SHAKE256_20/4_256", 1, 0x2a, 20},
    {"XMSSMT-SHAKE256_60/12_256", 1, 0x30, 60},
    {"XMSSMT-SHAKE256_20/4_192", 1, 0x32, 20},
    {"XMSSMT-SHAKE256_60/12_192", 1, 0x38, 60},
};

// The sets of vectors/xmss/xmss-extra.txt: the other SP 800-208 sets whose trees have at most
// 2^16 leaves.
static const struct set extra[] = {
    {"XMSS-SHA2_16_256", 0, 0x02, 16},
    {"XMSS-SHA2_16_192", 0, 0x0e, 16},
    {"XMSS-SHAKE256_16_256", 0, 0x11, 16},
    {"XMSS-SHAKE256_16_192", 0, 0x14, 16},
    {"XMSSMT-SHA2_20/2_192", 1, 0x21, 20},
    {"XMSSMT-SHA2_40/4_192", 1, 0x24, 40},
    {"XMSSMT-SHA2_40/8_192", 1, 0x25, 40},
    {"XMSSMT-SHA2_60/6_192", 1, 0x27, 60},
    {"XMSSMT-SHAKE256_20/2_256", 1, 0x29, 20},
    {"XMSSMT-SHAKE256_40/4_256", 1, 0x2c, 40},
    {"XMSSMT-SHAKE256_40/8_256", 1, 0x2d, 40},
    {"XMSSMT-SHAKE256_60/6_256", 1, 0x2f, 60},
    {"XMSSMT-SHAKE256_20/2_192", 1, 0x31, 20},
    {"XMSSMT-SHAKE256_40/4_192", 1, 0x34, 40},
    {"XMSSMT-SHAKE256_40/8_192", 1, 0x35, 40},
    {"XMSSMT-SHAKE256_60/6_192", 1, 0x37, 60},
};

// The sets of vectors/xmss/xmss-large.txt: the twelve SP 800-208 sets whose trees have 2^20
// leaves. The reference builds every tree of a signature's path for each signature, an hour and
// more per set, so these get two signatures each.
static const struct set large[] = {
    {"XMSS-SHA2_20_256", 0, 0x03, 20},
    {"XMSS-SHA2_20_192", 0, 0x0f, 20},
    {"XMSS-SHAKE256_20_256", 0, 0x12, 20},
    {"XMSS-SHAKE256_20_192", 0, 0x15, 20},
    {"XMSSMT-SHA2_40/2_256", 1, 0x03, 40},
    {"XMSSMT-SHA2_60/3_256", 1, 0x06, 60},
    {"XMSSMT-SHA2_40/2_192", 1, 0x23, 40},
    {"XMSSMT-SHA2_60/3_192", 1, 0x26, 60},
    {"XMSSMT-SHAKE256_40/2_256", 1, 0x2b, 40},
    {"XMSSMT-SHAKE256_60/3_256", 1, 0x2e, 60},
    {"XMSSMT-SHAKE256_40/2_192", 1, 0x33, 40},
    {"XMSSMT-SHAKE256_60/3_192", 1, 0x36, 60},
};

static int vectors(const struct set *set, int few)
{
    unsigned long long last = (1ULL << set->height) - 1;

    // The reference wipes the key before signing at the last index, so its final signature is not
    // valid; 2^h - 2 is the largest index used here.
    unsigned long long all[] = {0, 1, last / 3, last - 1};

    unsigned long long two[] = {0, last - 1};

    const unsigned long long *indices = few ? two : all;

    unsigned int count = few ? 2 : 4;

    for (unsigned int j = 0; j < count; j++) {
        if (vector(set->name, set->multi_tree, set->oid, indices[j]) != 0) {
            fprintf(stderr, "%s: failed\n", set->name);

            return 1;
        }
    }

    return 0;
}

// Without arguments, every base set; with "extra" or "large" and a number, that set alone, so
// that the slow ones can run side by side.
int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "extra") == 0) {
        unsigned long i = strtoul(argv[2], NULL, 10);

        return i < sizeof extra / sizeof extra[0] ? vectors(&extra[i], 0) : 2;
    }

    if (argc == 3 && strcmp(argv[1], "large") == 0) {
        unsigned long i = strtoul(argv[2], NULL, 10);

        return i < sizeof large / sizeof large[0] ? vectors(&large[i], 1) : 2;
    }

    if (argc != 1) {
        return 2;
    }

    for (unsigned int i = 0; i < sizeof base / sizeof base[0]; i++) {
        if (vectors(&base[i], 0) != 0) {
            return 1;
        }
    }

    return 0;
}

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
// 2^16 leaves. The twelve sets with trees of 2^20 leaves are left to the weekly job.
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

static int vectors(const struct set *set)
{
    unsigned long long last = (1ULL << set->height) - 1;

    // The reference wipes the key before signing at the last index, so its final signature is not
    // valid; 2^h - 2 is the largest index used here.
    unsigned long long indices[] = {0, 1, last / 3, last - 1};

    for (unsigned int j = 0; j < sizeof indices / sizeof indices[0]; j++) {
        if (vector(set->name, set->multi_tree, set->oid, indices[j]) != 0) {
            fprintf(stderr, "%s: failed\n", set->name);

            return 1;
        }
    }

    return 0;
}

// Without arguments, every base set; with "extra" and a number, that extra set alone, so that the
// slow ones can run side by side.
int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "extra") == 0) {
        unsigned long i = strtoul(argv[2], NULL, 10);

        return i < sizeof extra / sizeof extra[0] ? vectors(&extra[i]) : 2;
    }

    if (argc != 1) {
        return 2;
    }

    for (unsigned int i = 0; i < sizeof base / sizeof base[0]; i++) {
        if (vectors(&base[i]) != 0) {
            return 1;
        }
    }

    return 0;
}

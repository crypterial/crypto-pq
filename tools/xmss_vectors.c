#include <stdint.h>
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

int main(void)
{
    static const struct {
        const char *name;
        int multi_tree;
        uint32_t oid;
        unsigned int height;
    } sets[] = {
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

    for (unsigned int i = 0; i < sizeof sets / sizeof sets[0]; i++) {
        unsigned long long last = (1ULL << sets[i].height) - 1;

        // The reference wipes the key before signing at the last index, so its final signature
        // is not valid; 2^h - 2 is the largest index used here.
        unsigned long long indices[] = {0, 1, last / 3, last - 1};

        for (unsigned int j = 0; j < sizeof indices / sizeof indices[0]; j++) {
            if (vector(sets[i].name, sets[i].multi_tree, sets[i].oid, indices[j]) != 0) {
                fprintf(stderr, "%s: failed\n", sets[i].name);

                return 1;
            }
        }
    }

    return 0;
}

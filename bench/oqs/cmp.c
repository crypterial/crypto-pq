// liboqs timed with crypto-pq's loop: batches grow until one second has passed and the mean per
// operation is reported. Keys come from the seeds crypto-pq's harnesses use: KEM key generation
// and encapsulation through the derandomized calls, signature key generation and signing through a
// registered deterministic randomness source, so ML-DSA signs with rnd = 0 (the deterministic
// variant) and SLH-DSA with opt_rand = PK.seed. Every output is printed as an FP line (SHA3-256 of
// keys, ciphertexts, secrets and signatures; digests in full), which must equal crypto-pq's.
#define _GNU_SOURCE
#include <oqs/oqs.h>
#include <oqs/sha2.h>
#include <oqs/sha3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MESSAGES 16

static double now_ns(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static volatile uint8_t sink;

typedef double (*batch_fn)(void *ctx, uint64_t count);

static void measure(batch_fn batch, void *ctx, uint64_t *iterations_out, double *micros_out) {
    uint64_t iterations = 0, count = 1;

    double elapsed = 0;

    while (elapsed < 1e9) {
        elapsed += batch(ctx, count);

        iterations += count;

        double per_operation = elapsed / (double)iterations;

        double remaining = elapsed < 1e9 ? 1e9 - elapsed : 0;

        double next = remaining / per_operation;

        count = (uint64_t)(next + 0.999999);

        if (count < 1) count = 1;

        if (count > 10 * iterations) count = 10 * iterations;
    }

    *iterations_out = iterations;

    *micros_out = elapsed / 1000.0 / (double)iterations;
}

// Deterministic randomness: a fixed byte source (rewound before each operation) or zeros.
static const uint8_t *rng_source;

static size_t rng_length, rng_offset;

static int rng_zero;

static void deterministic_randombytes(uint8_t *out, size_t length) {
    if (rng_zero) {
        memset(out, 0, length);

        return;
    }

    for (size_t i = 0; i < length; i++) out[i] = rng_source[(rng_offset + i) % rng_length];

    rng_offset += length;
}

static void rng_from(const uint8_t *source, size_t length) {
    rng_zero = 0;

    rng_source = source;

    rng_length = length;

    rng_offset = 0;
}

static void rng_zeros(void) {
    rng_zero = 1;
}

static void sequence(uint8_t *out, size_t length) {
    for (size_t i = 0; i < length; i++) out[i] = (uint8_t)i;
}

static char messages[MESSAGES][64];

static size_t message_lengths[MESSAGES];

static void print_hex(const char *label, const uint8_t *data, size_t length) {
    printf("FP %s ", label);

    for (size_t i = 0; i < length; i++) printf("%02x", data[i]);

    printf("\n");
}

static void fingerprint(const char *label, const uint8_t *data, size_t length) {
    uint8_t digest[32];

    OQS_SHA3_sha3_256(digest, data, length);

    print_hex(label, digest, 32);
}

typedef struct {
    OQS_KEM *kem;
    uint8_t *pk, *sk, *ct, *ss;
    uint8_t seed[128], m[128];
    size_t seed_length, m_length;
} kem_ctx;

static double kem_keygen(void *p, uint64_t count) {
    kem_ctx *c = p;

    double start = now_ns();

    for (uint64_t i = 0; i < count; i++) {
        OQS_KEM_keypair_derand(c->kem, c->pk, c->sk, c->seed);

        sink ^= c->pk[0];
    }

    return now_ns() - start;
}

static double kem_encaps(void *p, uint64_t count) {
    kem_ctx *c = p;

    double start = now_ns();

    for (uint64_t i = 0; i < count; i++) {
        OQS_KEM_encaps_derand(c->kem, c->ct, c->ss, c->pk, c->m);

        sink ^= c->ct[0];
    }

    return now_ns() - start;
}

// FrodoKEM in liboqs has no derandomized calls (they return OQS_ERROR): key generation and
// encapsulation draw s || seedSE || z and u || salt from the registered deterministic source.
static double kem_keygen_rng(void *p, uint64_t count) {
    kem_ctx *c = p;

    double start = now_ns();

    for (uint64_t i = 0; i < count; i++) {
        rng_from(c->seed, c->seed_length);

        OQS_KEM_keypair(c->kem, c->pk, c->sk);

        sink ^= c->pk[0];
    }

    return now_ns() - start;
}

static double kem_encaps_rng(void *p, uint64_t count) {
    kem_ctx *c = p;

    double start = now_ns();

    for (uint64_t i = 0; i < count; i++) {
        rng_from(c->m, c->m_length);

        OQS_KEM_encaps(c->kem, c->ct, c->ss, c->pk);

        sink ^= c->ct[0];
    }

    return now_ns() - start;
}

static double kem_decaps(void *p, uint64_t count) {
    kem_ctx *c = p;

    uint8_t ss[64];

    double start = now_ns();

    for (uint64_t i = 0; i < count; i++) {
        OQS_KEM_decaps(c->kem, ss, c->ct, c->sk);

        sink ^= ss[0];
    }

    return now_ns() - start;
}

typedef struct {
    OQS_SIG *sig;
    uint8_t *pk, *sk;
    uint8_t *sigs[MESSAGES];
    size_t sig_lengths[MESSAGES];
    uint8_t seed[96];
    size_t seed_length;
    int slh, used;
    uint64_t next;
    uint8_t *scratch;
} sig_ctx;

static double sig_keygen(void *p, uint64_t count) {
    sig_ctx *c = p;

    double start = now_ns();

    for (uint64_t i = 0; i < count; i++) {
        rng_from(c->seed, c->seed_length);

        OQS_SIG_keypair(c->sig, c->pk, c->sk);

        sink ^= c->pk[0];
    }

    return now_ns() - start;
}

static void sign_one(sig_ctx *c, int index, uint8_t *out, size_t *out_length) {
    size_t n = c->seed_length / 3;

    if (c->slh) {
        rng_from(c->seed + 2 * n, n);
    } else {
        rng_zeros();
    }

    OQS_SIG_sign(c->sig, out, out_length, (const uint8_t *)messages[index], message_lengths[index], c->sk);
}

static double sig_sign(void *p, uint64_t count) {
    sig_ctx *c = p;

    size_t length;

    double start = now_ns();

    for (uint64_t i = 0; i < count; i++) {
        int index = (int)(c->next++ % (uint64_t)c->used);

        sign_one(c, index, c->scratch, &length);

        sink ^= c->scratch[0];
    }

    return now_ns() - start;
}

static double sig_verify(void *p, uint64_t count) {
    sig_ctx *c = p;

    double start = now_ns();

    for (uint64_t i = 0; i < count; i++) {
        int index = (int)(c->next++ % (uint64_t)c->used);

        if (OQS_SIG_verify(c->sig, (const uint8_t *)messages[index], message_lengths[index], c->sigs[index], c->sig_lengths[index], c->pk) != OQS_SUCCESS) {
            fprintf(stderr, "verify failed\n");

            exit(1);
        }
    }

    return now_ns() - start;
}

typedef struct {
    int kind;
    size_t length;
    uint8_t data[1024];
} hash_ctx;

static void hash_one(int kind, uint8_t *out, const uint8_t *data, size_t length) {
    switch (kind) {
        case 0: OQS_SHA2_sha256(out, data, length); break;
        case 1: OQS_SHA2_sha512(out, data, length); break;
        case 2: OQS_SHA3_sha3_256(out, data, length); break;
        case 3: OQS_SHA3_shake128(out, 32, data, length); break;
        default: OQS_SHA3_shake256(out, 64, data, length); break;
    }
}

static double hash_batch(void *p, uint64_t count) {
    hash_ctx *c = p;

    uint8_t out[64];

    double start = now_ns();

    for (uint64_t i = 0; i < count; i++) {
        hash_one(c->kind, out, c->data, c->length);

        sink ^= out[0];
    }

    return now_ns() - start;
}

typedef struct {
    char name[64];
    batch_fn batch;
    void *ctx;
} entry;

static entry entries[256];

static int entry_count;

static int filter_count;

static char **filters;

static int wanted(const char *name) {
    if (filter_count == 0) return 1;

    for (int i = 0; i < filter_count; i++) {
        if (strstr(name, filters[i])) return 1;
    }

    return 0;
}

static void add(const char *name, batch_fn batch, void *ctx) {
    if (!wanted(name)) return;

    snprintf(entries[entry_count].name, sizeof entries[entry_count].name, "%s", name);

    entries[entry_count].batch = batch;

    entries[entry_count].ctx = ctx;

    entry_count++;
}

static void kem_case_any(const char *alg, const char *label, size_t seed_length, size_t m_length) {
    OQS_KEM *kem = OQS_KEM_new(alg);

    if (!kem) {
        fprintf(stderr, "missing %s\n", alg);

        return;
    }

    kem_ctx *c = calloc(1, sizeof *c);

    c->kem = kem;

    c->pk = malloc(kem->length_public_key);

    c->sk = malloc(kem->length_secret_key);

    c->ct = malloc(kem->length_ciphertext);

    c->ss = malloc(kem->length_shared_secret);

    c->seed_length = seed_length;

    c->m_length = m_length;

    sequence(c->seed, seed_length);

    sequence(c->m, m_length ? m_length : 32);

    if (m_length) {
        rng_from(c->seed, seed_length);

        if (OQS_KEM_keypair(kem, c->pk, c->sk) != OQS_SUCCESS) exit(2);

        rng_from(c->m, m_length);

        if (OQS_KEM_encaps(kem, c->ct, c->ss, c->pk) != OQS_SUCCESS) exit(3);
    } else {
        if (OQS_KEM_keypair_derand(kem, c->pk, c->sk, c->seed) != OQS_SUCCESS) exit(2);

        if (OQS_KEM_encaps_derand(kem, c->ct, c->ss, c->pk, c->m) != OQS_SUCCESS) exit(3);
    }

    uint8_t ss[64];

    if (OQS_KEM_decaps(kem, ss, c->ct, c->sk) != OQS_SUCCESS || memcmp(ss, c->ss, kem->length_shared_secret)) exit(4);

    char text[96];

    snprintf(text, sizeof text, "%s/ek", label);

    fingerprint(text, c->pk, kem->length_public_key);

    snprintf(text, sizeof text, "%s/ct", label);

    fingerprint(text, c->ct, kem->length_ciphertext);

    snprintf(text, sizeof text, "%s/ss", label);

    fingerprint(text, c->ss, kem->length_shared_secret);

    snprintf(text, sizeof text, "%s/keygen", label);

    add(text, m_length ? kem_keygen_rng : kem_keygen, c);

    snprintf(text, sizeof text, "%s/encaps", label);

    add(text, m_length ? kem_encaps_rng : kem_encaps, c);

    snprintf(text, sizeof text, "%s/decaps", label);

    add(text, kem_decaps, c);
}

static void kem_case(const char *alg, const char *label) {
    kem_case_any(alg, label, 64, 0);
}

static void sig_case(const char *alg, const char *label, size_t seed_length, int slh) {
    OQS_SIG *sig = OQS_SIG_new(alg);

    if (!sig) {
        fprintf(stderr, "missing %s\n", alg);

        return;
    }

    sig_ctx *c = calloc(1, sizeof *c);

    c->sig = sig;

    c->pk = malloc(sig->length_public_key);

    c->sk = malloc(sig->length_secret_key);

    c->scratch = malloc(sig->length_signature);

    c->seed_length = seed_length;

    c->slh = slh;

    c->used = slh ? 1 : MESSAGES;

    sequence(c->seed, seed_length);

    rng_from(c->seed, seed_length);

    if (OQS_SIG_keypair(sig, c->pk, c->sk) != OQS_SUCCESS) exit(5);

    char text[96];

    snprintf(text, sizeof text, "%s/pk", label);

    fingerprint(text, c->pk, sig->length_public_key);

    for (int i = 0; i < c->used; i++) {
        c->sigs[i] = malloc(sig->length_signature);

        sign_one(c, i, c->sigs[i], &c->sig_lengths[i]);

        snprintf(text, sizeof text, "%s/sig%d", label, i);

        fingerprint(text, c->sigs[i], c->sig_lengths[i]);
    }

    snprintf(text, sizeof text, "%s/keygen", label);

    add(text, sig_keygen, c);

    snprintf(text, sizeof text, "%s/sign", label);

    add(text, sig_sign, c);

    snprintf(text, sizeof text, "%s/verify", label);

    add(text, sig_verify, c);
}

int main(int argc, char **argv) {
    int rounds = 1, offset = 0, check_only = 0;

    const char *impl = getenv("IMPL") ? getenv("IMPL") : "liboqs";

    filters = calloc((size_t)argc, sizeof *filters);

    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "--rounds=", 9)) {
            rounds = atoi(argv[i] + 9);
        } else if (!strncmp(argv[i], "--offset=", 9)) {
            offset = atoi(argv[i] + 9);
        } else if (!strcmp(argv[i], "--check")) {
            check_only = 1;
        } else if (strncmp(argv[i], "--", 2)) {
            filters[filter_count++] = argv[i];
        }
    }

    OQS_init();

    OQS_randombytes_custom_algorithm(deterministic_randombytes);

    for (int i = 0; i < MESSAGES; i++) {
        message_lengths[i] = (size_t)snprintf(messages[i], sizeof messages[i], "crypto-pq benchmark message %d", i);
    }

    static const char *hash_names[5] = {"sha-256", "sha-512", "sha3-256", "shake128", "shake256"};

    static const size_t hash_sizes[5] = {32, 64, 32, 32, 64};

    static hash_ctx hashes[10];

    for (int k = 0; k < 5; k++) {
        for (int s = 0; s < 2; s++) {
            hash_ctx *h = &hashes[2 * k + s];

            h->kind = k;

            h->length = s ? 1024 : 64;

            sequence(h->data, sizeof h->data);

            char text[64];

            snprintf(text, sizeof text, "%s/%s", hash_names[k], s ? "1KiB" : "64B");

            uint8_t out[64];

            hash_one(k, out, h->data, h->length);

            print_hex(text, out, hash_sizes[k]);

            add(text, hash_batch, h);
        }
    }

    kem_case(OQS_KEM_alg_ml_kem_512, "ML-KEM-512");

    kem_case(OQS_KEM_alg_ml_kem_768, "ML-KEM-768");

    kem_case(OQS_KEM_alg_ml_kem_1024, "ML-KEM-1024");

    kem_case_any(OQS_KEM_alg_frodokem_976_aes, "FrodoKEM-976-AES", 88, 72);

    kem_case_any(OQS_KEM_alg_frodokem_976_shake, "FrodoKEM-976-SHAKE", 88, 72);

    kem_case_any(OQS_KEM_alg_frodokem_1344_aes, "FrodoKEM-1344-AES", 112, 96);

    kem_case_any(OQS_KEM_alg_frodokem_1344_shake, "FrodoKEM-1344-SHAKE", 112, 96);

    kem_case_any(OQS_KEM_alg_efrodokem_976_aes, "eFrodoKEM-976-AES", 64, 24);

    kem_case_any(OQS_KEM_alg_efrodokem_976_shake, "eFrodoKEM-976-SHAKE", 64, 24);

    kem_case_any(OQS_KEM_alg_efrodokem_1344_aes, "eFrodoKEM-1344-AES", 80, 32);

    kem_case_any(OQS_KEM_alg_efrodokem_1344_shake, "eFrodoKEM-1344-SHAKE", 80, 32);

    sig_case(OQS_SIG_alg_ml_dsa_44, "ML-DSA-44", 32, 0);

    sig_case(OQS_SIG_alg_ml_dsa_65, "ML-DSA-65", 32, 0);

    sig_case(OQS_SIG_alg_ml_dsa_87, "ML-DSA-87", 32, 0);

    sig_case(OQS_SIG_alg_slh_dsa_pure_sha2_128s, "SLH-DSA-SHA2-128s", 48, 1);

    sig_case(OQS_SIG_alg_slh_dsa_pure_sha2_128f, "SLH-DSA-SHA2-128f", 48, 1);

    sig_case(OQS_SIG_alg_slh_dsa_pure_sha2_192s, "SLH-DSA-SHA2-192s", 72, 1);

    sig_case(OQS_SIG_alg_slh_dsa_pure_sha2_192f, "SLH-DSA-SHA2-192f", 72, 1);

    sig_case(OQS_SIG_alg_slh_dsa_pure_sha2_256s, "SLH-DSA-SHA2-256s", 96, 1);

    sig_case(OQS_SIG_alg_slh_dsa_pure_sha2_256f, "SLH-DSA-SHA2-256f", 96, 1);

    sig_case(OQS_SIG_alg_slh_dsa_pure_shake_128s, "SLH-DSA-SHAKE-128s", 48, 1);

    sig_case(OQS_SIG_alg_slh_dsa_pure_shake_128f, "SLH-DSA-SHAKE-128f", 48, 1);

    sig_case(OQS_SIG_alg_slh_dsa_pure_shake_192s, "SLH-DSA-SHAKE-192s", 72, 1);

    sig_case(OQS_SIG_alg_slh_dsa_pure_shake_192f, "SLH-DSA-SHAKE-192f", 72, 1);

    sig_case(OQS_SIG_alg_slh_dsa_pure_shake_256s, "SLH-DSA-SHAKE-256s", 96, 1);

    sig_case(OQS_SIG_alg_slh_dsa_pure_shake_256f, "SLH-DSA-SHAKE-256f", 96, 1);

    printf("CHECKS entries=%d\n", entry_count);

    fflush(stdout);

    if (check_only) return 0;

    for (int r = 0; r < rounds; r++) {
        for (int i = 0; i < entry_count; i++) {
            uint64_t iterations;

            double micros;

            if (strstr(entries[i].name, "/sign") || strstr(entries[i].name, "/verify")) ((sig_ctx *)entries[i].ctx)->next = 0;

            measure(entries[i].batch, entries[i].ctx, &iterations, &micros);

            printf("R%d\t%s\t%s\t%llu\t%.4f\n", r + offset + 1, entries[i].name, impl, (unsigned long long)iterations, micros);

            fflush(stdout);
        }
    }

    OQS_destroy();

    return 0;
}

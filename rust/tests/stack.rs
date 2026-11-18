// No secret of SLH-DSA is left on the dead stack (SPEC 14.5 item 1, D-76). The stack below the
// caller is zeroed, one operation runs, and the same region is searched for the seeds of the key
// and for secret values of FORS, which the test derives itself (FIPS 205, Algorithms 14 and 19).
// The lanes of the F chains were once moved before their wipe: the copy was wiped, and the
// original kept SK.seed or the sixteen FORS values that it hashed last, on every target.
//
// On Linux and macOS, where a thread's stack is mapped as a whole, and on the two architectures
// whose stack pointer the test reads.
#![cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos"),
    not(miri)
))]

use std::hint::black_box;

use crypto_pq::{
    KeyFormat, SHA_256, SHA_512, SHAKE256, SLH_DSA_SHA2_128F, SLH_DSA_SHA2_128S, SLH_DSA_SHA2_192F,
    SLH_DSA_SHA2_192S, SLH_DSA_SHA2_256F, SLH_DSA_SHA2_256S, SLH_DSA_SHAKE_128F,
    SLH_DSA_SHAKE_128S, SLH_DSA_SHAKE_192F, SLH_DSA_SHAKE_192S, SLH_DSA_SHAKE_256F,
    SLH_DSA_SHAKE_256S, SignOptions, SignatureAlgorithm, hazmat,
};

// The dead stack that is cleared and read: more than any operation here uses, and well inside a
// test thread's stack.
const SPAN: usize = 1 << 17;

const MESSAGE: &[u8] = b"crypto-pq dead stack check";

// Zeros over the SPAN bytes below the stack pointer.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn clear() {
    // SAFETY: the bytes below the stack pointer are frames of calls that have returned, on a
    // stack mapped beyond SPAN; the block is not nostack, so the compiler keeps nothing of this
    // function there, and it restores the direction flag's cleared state by not changing it.
    unsafe {
        core::arch::asm!(
            "lea rdi, [rsp - {span}]",
            "mov rcx, {span}",
            "xor eax, eax",
            "rep stosb",
            span = const SPAN,
            out("rdi") _,
            out("rcx") _,
            out("rax") _,
        );
    }
}

// The SPAN bytes below the stack pointer into `copy`, lowest address first.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn read(copy: &mut [u8; SPAN]) {
    // SAFETY: as in clear, for reads; copy is writable for SPAN bytes.
    unsafe {
        core::arch::asm!(
            "lea rsi, [rsp - {span}]",
            "mov rcx, {span}",
            "rep movsb",
            span = const SPAN,
            inout("rdi") copy.as_mut_ptr() => _,
            out("rsi") _,
            out("rcx") _,
        );
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(never)]
fn clear() {
    // SAFETY: as on x86-64; SPAN is a multiple of sixteen.
    unsafe {
        core::arch::asm!(
            "sub {p}, sp, #{span}",
            "mov {n}, #{span}",
            "2:",
            "stp xzr, xzr, [{p}], #16",
            "subs {n}, {n}, #16",
            "b.ne 2b",
            span = const SPAN,
            p = out(reg) _,
            n = out(reg) _,
        );
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(never)]
fn read(copy: &mut [u8; SPAN]) {
    // SAFETY: as on x86-64.
    unsafe {
        core::arch::asm!(
            "sub {s}, sp, #{span}",
            "mov {n}, #{span}",
            "2:",
            "ldp {a}, {b}, [{s}], #16",
            "stp {a}, {b}, [{d}], #16",
            "subs {n}, {n}, #16",
            "b.ne 2b",
            span = const SPAN,
            s = out(reg) _,
            n = out(reg) _,
            a = out(reg) _,
            b = out(reg) _,
            d = inout(reg) copy.as_mut_ptr() => _,
        );
    }
}

// What `operation` returns, and the dead stack that it left. Out of line, so that the three calls
// start from one stack pointer.
#[inline(never)]
fn dead_stack_after<R>(operation: impl FnOnce() -> R) -> (R, Box<[u8; SPAN]>) {
    let mut copy: Box<[u8; SPAN]> = vec![0; SPAN]
        .into_boxed_slice()
        .try_into()
        .expect("SPAN bytes");

    clear();

    let result = black_box(operation());

    read(&mut copy);

    (result, copy)
}

// Whether eight bytes in a row of `secret` lie in the stack copy.
fn holds(stack: &[u8], secret: &[u8]) -> bool {
    secret
        .windows(8)
        .any(|part| stack.windows(8).any(|window| window == part))
}

struct Rng(u64);

impl Rng {
    fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length)
            .map(|_| {
                self.0 ^= self.0 << 13;

                self.0 ^= self.0 >> 7;

                self.0 ^= self.0 << 17;

                (self.0 >> 24) as u8
            })
            .collect()
    }
}

// A function that leaves its argument in its frame, as the search must find it.
#[inline(never)]
fn careless(secret: &[u8; 32]) -> u8 {
    let mut local = [0u8; 32];

    local.copy_from_slice(secret);

    black_box(&mut local);

    local[31]
}

#[test]
fn the_search_finds_a_value_left_in_a_frame() {
    let secret: [u8; 32] = Rng(0x9E37_79B9_7F4A_7C15)
        .bytes(32)
        .try_into()
        .expect("32 bytes");

    let (_, stack) = dead_stack_after(|| careless(black_box(&secret)));

    assert!(
        holds(&stack[..], &secret),
        "a value left in a frame is found"
    );

    let (_, stack) = dead_stack_after(|| black_box(secret[0]));

    assert!(
        !holds(&stack[..], &secret),
        "and nothing where none was left"
    );
}

// FIPS 205, Table 2: n, h, d, a, k, m.
fn sizes(algorithm: &SignatureAlgorithm) -> [usize; 6] {
    let name = algorithm.name();

    match &name[name.len() - 4..] {
        "128s" => [16, 63, 7, 12, 14, 30],
        "128f" => [16, 66, 22, 6, 33, 34],
        "192s" => [24, 63, 7, 14, 17, 39],
        "192f" => [24, 66, 22, 8, 33, 42],
        "256s" => [32, 64, 8, 14, 22, 47],
        "256f" => [32, 68, 17, 9, 35, 49],
        _ => unreachable!("an SLH-DSA parameter set"),
    }
}

fn shake256(parts: &[&[u8]], length: usize) -> Vec<u8> {
    let mut xof = SHAKE256.create();

    for part in parts {
        xof.update(part).expect("absorbing");
    }

    xof.read(length).expect("squeezing")
}

fn bits_of(bytes: &[u8], bits: usize) -> u64 {
    let value = bytes
        .iter()
        .fold(0u128, |value, &byte| (value << 8) | u128::from(byte));

    (value & ((1u128 << bits) - 1)) as u64
}

// The secret values of the last sixteen leaves of the last FORS tree of a signature, which the
// signer computes last, without the one that the signature reveals (FIPS 205, Algorithm 14: PRF
// under the FORS_PRF address of the key pair that Algorithm 19 takes from the message digest).
fn last_fors_secrets(
    algorithm: &SignatureAlgorithm,
    seed: &[u8],
    public: &[u8],
    signature: &[u8],
) -> Vec<Vec<u8>> {
    let [n, h, d, a, k, m] = sizes(algorithm);

    let shake = algorithm.name().contains("SHAKE");

    let (sk_seed, pk_seed, pk_root) = (&seed[..n], &public[..n], &public[n..]);

    // Pure signing with an empty context: M' = 0 || 0 || M.
    let message = [&[0, 0][..], MESSAGE].concat();

    let r = &signature[..n];

    let digest = if shake {
        shake256(&[r, pk_seed, pk_root, &message], m)
    } else {
        let hash = if n == 16 { SHA_256 } else { SHA_512 };

        let inner = hash.digest(&[r, pk_seed, pk_root, &message[..]].concat());

        let mgf_seed = [r, pk_seed, &inner[..]].concat();

        let mut mask = Vec::new();

        for counter in 0u32.. {
            if mask.len() >= m {
                break;
            }

            mask.extend(hash.digest(&[&mgf_seed[..], &counter.to_be_bytes()].concat()));
        }

        mask.truncate(m);

        mask
    };

    let md_size = (k * a).div_ceil(8);

    let (tree_bits, leaf_bits) = (h - h / d, h / d);

    let tree_size = tree_bits.div_ceil(8);

    let tree = bits_of(&digest[md_size..md_size + tree_size], tree_bits);

    let leaf = bits_of(
        &digest[md_size + tree_size..][..leaf_bits.div_ceil(8)],
        leaf_bits,
    ) as u32;

    let index_of = |i: usize| -> usize {
        (0..a).fold(0, |value, bit| {
            let position = i * a + bit;

            (value << 1) | usize::from((digest[position / 8] >> (7 - position % 8)) & 1)
        })
    };

    let secret_of = |index: u32| -> Vec<u8> {
        let mut adrs = [0u8; 32];

        adrs[8..16].copy_from_slice(&tree.to_be_bytes());

        adrs[16..20].copy_from_slice(&6u32.to_be_bytes());

        adrs[20..24].copy_from_slice(&leaf.to_be_bytes());

        adrs[28..32].copy_from_slice(&index.to_be_bytes());

        if shake {
            return shake256(&[pk_seed, &adrs, sk_seed], n);
        }

        // PK.seed and its zero padding to a block, the compressed address, SK.seed.
        let mut input = pk_seed.to_vec();

        input.resize(64, 0);

        input.push(adrs[3]);

        input.extend_from_slice(&adrs[8..16]);

        input.push(adrs[19]);

        input.extend_from_slice(&adrs[20..]);

        input.extend_from_slice(sk_seed);

        SHA_256.digest(&input)[..n].to_vec()
    };

    // The signature's first FORS value is the secret value of tree 0 at its index.
    assert_eq!(
        secret_of(index_of(0) as u32),
        &signature[n..2 * n],
        "the test derives the FORS secret values of {}",
        algorithm.name()
    );

    let revealed = index_of(k - 1);

    ((1 << a) - 16..1 << a)
        .filter(|&j| j != revealed)
        .map(|j| secret_of((((k - 1) << a) + j) as u32))
        .collect()
}

// Whether the stack copy holds an n-byte value as the lanes of the F chains hold it: as bytes,
// as the big-endian words of a row of sixteen lanes each (the digests), or as those words two
// bytes further, where the block of the next step has them after the compressed address.
fn holds_node(stack: &[u8], value: &[u8]) -> bool {
    let n = value.len();

    let words = n / 4;

    let word = |t: usize| {
        [
            value[4 * t + 3],
            value[4 * t + 2],
            value[4 * t + 1],
            value[4 * t],
        ]
    };

    let straddle = |t: usize| {
        [
            value[4 * t + 1],
            value[4 * t],
            value[4 * t - 1],
            value[4 * t - 2],
        ]
    };

    let rows = 64 * words;

    stack.windows(n).any(|window| window == value)
        || (0..stack.len() - rows).any(|o| (0..words).all(|t| stack[o + 64 * t..][..4] == word(t)))
        || (64..stack.len() - rows).any(|o| {
            (1..words).all(|t| stack[o + 64 * (t - 1)..][..4] == straddle(t))
                && stack[o - 64..][..2] == [value[1], value[0]]
                && stack[o + 64 * (words - 1) + 2..][..2] == [value[n - 1], value[n - 2]]
        })
}

fn check(algorithm: SignatureAlgorithm) {
    let name = algorithm.name();

    let n = algorithm.public_key_size() / 2;

    let mut rng = Rng(0x243F_6A88_85A3_08D3 ^ name.bytes().map(u64::from).sum::<u64>());

    let seed = rng.bytes(3 * n);

    let randomness = rng.bytes(n);

    let (pair, stack) = dead_stack_after(|| {
        hazmat::generate_signature_key_pair(algorithm, black_box(&seed)).expect("a key pair")
    });

    assert!(
        !holds(&stack[..], &seed[..n]),
        "{name}: SK.seed after key generation"
    );

    assert!(
        !holds(&stack[..], &seed[n..2 * n]),
        "{name}: SK.prf after key generation"
    );

    let options = SignOptions::default();

    let (signature, stack) = dead_stack_after(|| {
        hazmat::sign(
            &pair.private_key,
            black_box(MESSAGE),
            black_box(&randomness),
            &options,
        )
        .expect("a signature")
    });

    assert!(
        !holds(&stack[..], &seed[..n]),
        "{name}: SK.seed after signing"
    );

    assert!(
        !holds(&stack[..], &seed[n..2 * n]),
        "{name}: SK.prf after signing"
    );

    let public = pair
        .public_key
        .export_key(KeyFormat::Raw)
        .expect("a raw key");

    let left = last_fors_secrets(&algorithm, &seed, &public, &signature)
        .iter()
        .filter(|secret| holds_node(&stack[..], secret))
        .count();

    assert_eq!(left, 0, "{name}: secret values of FORS after signing");
}

#[test]
fn slh_dsa_sha2_leaves_no_secret_on_the_stack() {
    for algorithm in [
        SLH_DSA_SHA2_128F,
        SLH_DSA_SHA2_192F,
        SLH_DSA_SHA2_256F,
        SLH_DSA_SHA2_128S,
        SLH_DSA_SHA2_192S,
        SLH_DSA_SHA2_256S,
    ] {
        check(algorithm);
    }
}

#[test]
fn slh_dsa_shake_leaves_no_secret_on_the_stack() {
    for algorithm in [
        SLH_DSA_SHAKE_128F,
        SLH_DSA_SHAKE_192F,
        SLH_DSA_SHAKE_256F,
        SLH_DSA_SHAKE_128S,
        SLH_DSA_SHAKE_192S,
        SLH_DSA_SHAKE_256S,
    ] {
        check(algorithm);
    }
}

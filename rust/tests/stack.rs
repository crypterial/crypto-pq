// No secret of an operation on a private key is left on the dead stack (SPEC 14.5 item 1, D-76,
// D-115, D-116). The stack below the caller is painted, one operation runs, and the same region is
// searched for the seeds and the shared secrets that the operation handled, and for SLH-DSA for
// secret values of FORS, which the test derives itself (FIPS 205, Algorithms 14 and 19). The
// lanes of SLH-DSA's F chains were once moved before their wipe: the copy was wiped, and the
// original kept SK.seed or the sixteen FORS values that it hashed last, on every target. A kernel
// can also leave a value that it held in a register in its frame, so the operations end by
// writing zeros over the stack under them, and the test checks that these zeros lie where the
// operation went deepest: a call that went deeper would have its frame under them.
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

// The dead stack that is painted and read: more than any operation here uses, and well inside a
// test thread's stack.
const SPAN: usize = 1 << 17;

const MESSAGE: &[u8] = b"crypto-pq dead stack check";

// What the dead stack holds before an operation. Not zero, so that the zeros that the library
// writes are told from the bytes that nothing wrote.
const PAINT: u8 = 0xA5;

// The fewest zeros in a row that key generation and signing leave under them: the smallest size
// of D-115, less what the calls after the zeros write at their top.
const ZEROS: usize = 15 << 10;

// How far above the deepest byte that an operation wrote its zeros may begin: the frames of the
// calls that write them, at most 106 bytes in the builds measured (opt-level 0; 6 at 3 on x86-64,
// the return address of memset, and none on ARM64).
const SLACK: usize = 256;

// PAINT over the SPAN bytes below the stack pointer.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn paint() {
    // SAFETY: the bytes below the stack pointer are frames of calls that have returned, on a
    // stack mapped beyond SPAN; the block is not nostack, so the compiler keeps nothing of this
    // function there, and it restores the direction flag's cleared state by not changing it.
    unsafe {
        core::arch::asm!(
            "lea rdi, [rsp - {span}]",
            "mov rcx, {span}",
            "rep stosb",
            span = const SPAN,
            out("rdi") _,
            out("rcx") _,
            in("al") PAINT,
        );
    }
}

// The SPAN bytes below the stack pointer into `copy`, lowest address first.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn read(copy: &mut [u8; SPAN]) {
    // SAFETY: as in paint, for reads; copy is writable for SPAN bytes.
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
fn paint() {
    // SAFETY: as on x86-64; SPAN is a multiple of sixteen.
    unsafe {
        core::arch::asm!(
            "sub {p}, sp, #{span}",
            "mov {n}, #{span}",
            "2:",
            "stp {v}, {v}, [{p}], #16",
            "subs {n}, {n}, #16",
            "b.ne 2b",
            span = const SPAN,
            p = out(reg) _,
            n = out(reg) _,
            v = in(reg) u64::from_ne_bytes([PAINT; 8]),
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

    paint();

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

    assert!(
        zeros_under(&stack[..]) < ZEROS,
        "and its frame is not taken for the zeros of the library"
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

// Where the stack copy holds an n-byte value as the lanes of the F chains hold it, by depth under
// the caller: as bytes, as the big-endian words of a row of sixteen lanes each (the digests), or
// as those words two bytes further, where the block of the next step has them after the
// compressed address.
fn node_places(stack: &[u8], value: &[u8]) -> Vec<String> {
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

    let mut places = Vec::new();

    for (o, window) in stack.windows(n).enumerate() {
        if window == value {
            places.push(format!("bytes at depth {}", stack.len() - o));
        }
    }

    for o in 0..stack.len() - rows {
        if (0..words).all(|t| stack[o + 64 * t..][..4] == word(t)) {
            places.push(format!("digest rows at depth {}", stack.len() - o));
        }
    }

    for o in 64..stack.len() - rows {
        if (1..words).all(|t| stack[o + 64 * (t - 1)..][..4] == straddle(t))
            && stack[o - 64..][..2] == [value[1], value[0]]
            && stack[o + 64 * (words - 1) + 2..][..2] == [value[n - 1], value[n - 2]]
        {
            places.push(format!("block rows at depth {}", stack.len() - o));
        }
    }

    places
}

// The lowest byte that the operation wrote, as an index into the stack copy.
fn lowest(stack: &[u8]) -> usize {
    stack
        .iter()
        .position(|&byte| byte != PAINT)
        .unwrap_or(stack.len())
}

// How deep the operation went: the bytes from the lowest one that it wrote to the caller.
fn depth(stack: &[u8]) -> usize {
    stack.len() - lowest(stack)
}

// The longest run of zeros that begins within SLACK bytes above the lowest byte that the
// operation wrote: the zeros that it ended with, if no call went deeper than they reach.
fn zeros_under(stack: &[u8]) -> usize {
    let mut longest = 0;

    let mut start = lowest(stack);

    let end = (start + SLACK).min(stack.len());

    while start < end {
        let run = stack[start..].iter().take_while(|&&byte| byte == 0).count();

        longest = longest.max(run);

        start += run + 1;
    }

    longest
}

// The processor, for the message of a failure: what a kernel leaves depends on the kernel, and so
// on the processor that selects it.
fn processor() -> String {
    let info = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();

    let field = |name: &str| {
        info.lines()
            .find(|line| line.starts_with(name))
            .and_then(|line| line.split(':').nth(1))
            .map_or("", str::trim)
    };

    let flags = [field("flags"), field("Features")].concat();

    let kernels: Vec<&str> = ["avx2", "avx512vl", "sha_ni", "vaes", "sha3", "sha512"]
        .into_iter()
        .filter(|flag| flags.split(' ').any(|have| have == *flag))
        .collect();

    format!("{} {kernels:?}", field("model name"))
}

// What one parameter set left on the stack, each find as a line.
fn check(algorithm: SignatureAlgorithm) -> Vec<String> {
    let name = algorithm.name();

    let n = algorithm.public_key_size() / 2;

    let mut rng = Rng(0x243F_6A88_85A3_08D3 ^ name.bytes().map(u64::from).sum::<u64>());

    let seed = rng.bytes(3 * n);

    let randomness = rng.bytes(n);

    let mut found = Vec::new();

    let (pair, stack) = dead_stack_after(|| {
        hazmat::generate_signature_key_pair(algorithm, black_box(&seed)).expect("a key pair")
    });

    for (secret, bytes) in [("SK.seed", &seed[..n]), ("SK.prf", &seed[n..2 * n])] {
        if holds(&stack[..], bytes) {
            found.push(format!("{name}: {secret} after key generation"));
        }
    }

    if zeros_under(&stack[..]) < ZEROS {
        found.push(format!(
            "{name}: a call of key generation went deeper than its zeros, {} bytes of {}",
            zeros_under(&stack[..]),
            depth(&stack[..])
        ));
    }

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

    for (secret, bytes) in [("SK.seed", &seed[..n]), ("SK.prf", &seed[n..2 * n])] {
        if holds(&stack[..], bytes) {
            found.push(format!("{name}: {secret} after signing"));
        }
    }

    if zeros_under(&stack[..]) < ZEROS {
        found.push(format!(
            "{name}: a call of signing went deeper than its zeros, {} bytes of {}",
            zeros_under(&stack[..]),
            depth(&stack[..])
        ));
    }

    let public = pair
        .public_key
        .export_key(KeyFormat::Raw)
        .expect("a raw key");

    for (i, secret) in last_fors_secrets(&algorithm, &seed, &public, &signature)
        .iter()
        .enumerate()
    {
        for place in node_places(&stack[..], secret) {
            found.push(format!(
                "{name}: FORS secret value {i} after signing, as {place} of {}",
                depth(&stack[..])
            ));
        }
    }

    found
}

fn check_all(algorithms: [SignatureAlgorithm; 6]) {
    let found: Vec<String> = algorithms.into_iter().flat_map(check).collect();

    assert!(
        found.is_empty(),
        "left on the stack on {}:\n{}",
        processor(),
        found.join("\n")
    );
}

#[test]
fn slh_dsa_sha2_leaves_no_secret_on_the_stack() {
    check_all([
        SLH_DSA_SHA2_128F,
        SLH_DSA_SHA2_192F,
        SLH_DSA_SHA2_256F,
        SLH_DSA_SHA2_128S,
        SLH_DSA_SHA2_192S,
        SLH_DSA_SHA2_256S,
    ]);
}

#[test]
fn slh_dsa_shake_leaves_no_secret_on_the_stack() {
    check_all([
        SLH_DSA_SHAKE_128F,
        SLH_DSA_SHAKE_192F,
        SLH_DSA_SHAKE_256F,
        SLH_DSA_SHAKE_128S,
        SLH_DSA_SHAKE_192S,
        SLH_DSA_SHAKE_256S,
    ]);
}

// The other schemes end their operations on a private key the same way (D-116), each with the
// sizes of its own calls. What an operation left: the secrets given, and whether the zeros lie
// where it went deepest, with `least` the smallest of its zeros less what later calls write at
// their top.
#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    all(
        not(any(crypto_pq_optimized, crypto_pq_unoptimized)),
        feature = "hmac",
        feature = "hkdf",
        feature = "blake2",
        feature = "blake3"
    )
))]
fn inspect(
    found: &mut Vec<String>,
    name: &str,
    operation: &str,
    stack: &[u8],
    secrets: &[(&str, &[u8])],
    least: usize,
) {
    for (what, bytes) in secrets {
        if holds(stack, bytes) {
            found.push(format!("{name}: {what} after {operation}"));
        }
    }

    if zeros_under(stack) < least {
        found.push(format!(
            "{name}: a call of {operation} went deeper than its zeros, {} bytes of {}",
            zeros_under(stack),
            depth(stack)
        ));
    }
}

#[cfg(feature = "ml-kem")]
#[test]
fn ml_kem_leaves_no_secret_on_the_stack() {
    use crypto_pq::{ML_KEM_512, ML_KEM_768, ML_KEM_1024};

    // Under K-PKE's key generation and encryption at opt-level 3.
    const LEAST: usize = 5 << 10;

    let mut found = Vec::new();

    for algorithm in [ML_KEM_512, ML_KEM_768, ML_KEM_1024] {
        let name = algorithm.name();

        let mut rng = Rng(0x1319_8A2E_0370_7344 ^ name.bytes().map(u64::from).sum::<u64>());

        let seed = rng.bytes(64);

        let randomness = rng.bytes(32);

        let (pair, stack) = dead_stack_after(|| {
            hazmat::generate_kem_key_pair(algorithm, black_box(&seed)).expect("a key pair")
        });

        inspect(
            &mut found,
            name,
            "key generation",
            &stack[..],
            &[("d", &seed[..32]), ("z", &seed[32..])],
            LEAST,
        );

        let (encapsulation, stack) = dead_stack_after(|| {
            hazmat::encapsulate(&pair.public_key, black_box(&randomness)).expect("a ciphertext")
        });

        inspect(
            &mut found,
            name,
            "encapsulation",
            &stack[..],
            &[
                ("m", &randomness),
                ("the shared secret", &encapsulation.shared_secret),
            ],
            LEAST,
        );

        let (shared, stack) = dead_stack_after(|| {
            pair.private_key
                .decapsulate(black_box(&encapsulation.ciphertext))
                .expect("a shared secret")
        });

        inspect(
            &mut found,
            name,
            "decapsulation",
            &stack[..],
            &[("m", &randomness), ("the shared secret", &shared)],
            LEAST,
        );
    }

    assert!(
        found.is_empty(),
        "left on the stack on {}:\n{}",
        processor(),
        found.join("\n")
    );
}

#[cfg(feature = "ml-dsa")]
#[test]
fn ml_dsa_leaves_no_secret_on_the_stack() {
    use crypto_pq::{ML_DSA_44, ML_DSA_65, ML_DSA_87};

    const LEAST: usize = 9 << 10;

    let mut found = Vec::new();

    for (algorithm, k, l) in [(ML_DSA_44, 4, 4), (ML_DSA_65, 6, 5), (ML_DSA_87, 8, 7)] {
        let name = algorithm.name();

        let mut rng = Rng(0xA409_3822_299F_31D0 ^ name.bytes().map(u64::from).sum::<u64>());

        let seed = rng.bytes(32);

        let randomness = rng.bytes(32);

        // FIPS 204, Algorithm 6: rho, rho' and K from H(xi || k || l).
        let expanded = shake256(&[&seed, &[k, l]], 128);

        let secrets = [
            ("xi", &seed[..]),
            ("rho'", &expanded[32..96]),
            ("K", &expanded[96..]),
        ];

        let (pair, stack) = dead_stack_after(|| {
            hazmat::generate_signature_key_pair(algorithm, black_box(&seed)).expect("a key pair")
        });

        inspect(
            &mut found,
            name,
            "key generation",
            &stack[..],
            &secrets,
            LEAST,
        );

        let options = SignOptions::default();

        let (_, stack) = dead_stack_after(|| {
            hazmat::sign(
                &pair.private_key,
                black_box(MESSAGE),
                black_box(&randomness),
                &options,
            )
            .expect("a signature")
        });

        inspect(&mut found, name, "signing", &stack[..], &secrets, LEAST);
    }

    assert!(
        found.is_empty(),
        "left on the stack on {}:\n{}",
        processor(),
        found.join("\n")
    );
}

#[cfg(feature = "frodokem")]
#[test]
fn frodokem_leaves_no_secret_on_the_stack() {
    use crypto_pq::{
        EFRODOKEM_976_AES, EFRODOKEM_976_SHAKE, EFRODOKEM_1344_AES, EFRODOKEM_1344_SHAKE,
        FRODOKEM_976_AES, FRODOKEM_976_SHAKE, FRODOKEM_1344_AES, FRODOKEM_1344_SHAKE,
    };

    const LEAST: usize = 13 << 10;

    let mut found = Vec::new();

    for algorithm in [
        FRODOKEM_976_AES,
        FRODOKEM_976_SHAKE,
        FRODOKEM_1344_AES,
        FRODOKEM_1344_SHAKE,
        EFRODOKEM_976_AES,
        EFRODOKEM_976_SHAKE,
        EFRODOKEM_1344_AES,
        EFRODOKEM_1344_SHAKE,
    ] {
        let name = algorithm.name();

        // The seed is s || seedSE || z and the draw of encapsulation u || salt; the ephemeral
        // sets have a seedSE of half the size and no salt.
        let secret = if name.contains("976") { 24 } else { 32 };

        let (seed_se, salt) = if name.starts_with('e') {
            (secret, 0)
        } else {
            (2 * secret, 2 * secret)
        };

        let mut rng = Rng(0x082E_FA98_EC4E_6C89 ^ name.bytes().map(u64::from).sum::<u64>());

        let seed = rng.bytes(secret + seed_se + 16);

        let randomness = rng.bytes(secret + salt);

        let (pair, stack) = dead_stack_after(|| {
            hazmat::generate_kem_key_pair(algorithm, black_box(&seed)).expect("a key pair")
        });

        inspect(
            &mut found,
            name,
            "key generation",
            &stack[..],
            &[
                ("s", &seed[..secret]),
                ("seedSE", &seed[secret..secret + seed_se]),
            ],
            LEAST,
        );

        let (encapsulation, stack) = dead_stack_after(|| {
            hazmat::encapsulate(&pair.public_key, black_box(&randomness)).expect("a ciphertext")
        });

        inspect(
            &mut found,
            name,
            "encapsulation",
            &stack[..],
            &[
                ("u", &randomness[..secret]),
                ("the shared secret", &encapsulation.shared_secret),
            ],
            LEAST,
        );

        let (shared, stack) = dead_stack_after(|| {
            pair.private_key
                .decapsulate(black_box(&encapsulation.ciphertext))
                .expect("a shared secret")
        });

        inspect(
            &mut found,
            name,
            "decapsulation",
            &stack[..],
            &[
                ("u", &randomness[..secret]),
                ("the shared secret", &shared),
                ("s", &seed[..secret]),
            ],
            LEAST,
        );
    }

    assert!(
        found.is_empty(),
        "left on the stack on {}:\n{}",
        processor(),
        found.join("\n")
    );
}

// At the opt-levels between 0 and 3 a keyed hash and a KDF in one call end with zeros too: there
// their kernels pass arrays of key words through memory (D-116). build.rs gives this crate the
// level as it gives it to the library.
#[cfg(all(
    not(any(crypto_pq_optimized, crypto_pq_unoptimized)),
    feature = "hmac",
    feature = "hkdf",
    feature = "blake2",
    feature = "blake3"
))]
#[test]
fn keyed_hashes_leave_no_key_on_the_stack() {
    use crypto_pq::{
        BLAKE2B_MAC, BLAKE3_MAC, HKDF_SHA_256, HKDF_SHA_512, HMAC_SHA_256, HMAC_SHA_512, KMAC256,
        KdfOptions,
    };

    const LEAST: usize = 15 << 10;

    let mut found = Vec::new();

    let mut rng = Rng(0x4528_21E6_38D0_1377);

    let data = rng.bytes(100);

    for algorithm in [HMAC_SHA_256, HMAC_SHA_512, KMAC256, BLAKE2B_MAC, BLAKE3_MAC] {
        let key = rng.bytes(32);

        let mut tag = vec![0; algorithm.digest_size()];

        let ((), stack) = dead_stack_after(|| {
            algorithm
                .digest_into(black_box(&key), black_box(&data), &mut tag)
                .expect("a tag");
        });

        inspect(
            &mut found,
            algorithm.name(),
            "the MAC",
            &stack[..],
            &[("the key", &key)],
            LEAST,
        );
    }

    for (algorithm, name) in [
        (HKDF_SHA_256, "HKDF-SHA-256"),
        (HKDF_SHA_512, "HKDF-SHA-512"),
    ] {
        let ikm = rng.bytes(32);

        let salt = rng.bytes(16);

        let options = KdfOptions::default().with_salt(&salt).with_info(b"stack");

        for length in [32, 200] {
            let (okm, stack) = dead_stack_after(|| {
                algorithm
                    .derive(black_box(&ikm), length, &options)
                    .expect("a key")
            });

            inspect(
                &mut found,
                name,
                "the derivation",
                &stack[..],
                &[("the input keying material", &ikm), ("the output", &okm)],
                LEAST,
            );
        }
    }

    assert!(
        found.is_empty(),
        "left on the stack on {}:\n{}",
        processor(),
        found.join("\n")
    );
}

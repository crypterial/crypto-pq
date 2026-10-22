// Untrusted input gets only the defined errors: random and mutated encodings, signatures,
// ciphertexts, state blobs and tree caches go through every parsing path, accepted inputs must
// round-trip, and nothing may panic or allocate what a length field claims before checking it. A deterministic
// generator keeps every run reproducible; CRYPTO_PQ_FUZZ=1 runs many more rounds.

mod vectors;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::{Arc, Barrier, Mutex};

use crypto_pq::{
    EFRODOKEM_976_AES, EFRODOKEM_976_SHAKE, EFRODOKEM_1344_AES, EFRODOKEM_1344_SHAKE, Error,
    FRODOKEM_976_AES, FRODOKEM_976_SHAKE, FRODOKEM_1344_AES, FRODOKEM_1344_SHAKE, HMAC_SHA_256,
    HSS_LMS, HashAlgorithm, KemAlgorithm, KemPrivateKey, KemPublicKey, KeyFormat, ML_DSA_44,
    ML_DSA_65, ML_DSA_87, ML_KEM_512, ML_KEM_768, ML_KEM_1024, PreHash, SHA_224, SHA_256, SHA_384,
    SHA_512, SHA_512_224, SHA_512_256, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256,
    SLH_DSA_SHA2_128F, SLH_DSA_SHA2_128S, SLH_DSA_SHA2_192F, SLH_DSA_SHA2_192S, SLH_DSA_SHA2_256F,
    SLH_DSA_SHA2_256S, SLH_DSA_SHAKE_128F, SLH_DSA_SHAKE_128S, SLH_DSA_SHAKE_192F,
    SLH_DSA_SHAKE_192S, SLH_DSA_SHAKE_256F, SLH_DSA_SHAKE_256S, SignOptions, SignatureAlgorithm,
    SignaturePrivateKey, SignaturePublicKey, StateStore, StatefulKeyGenOptions,
    StatefulLoadOptions, StatefulParameters, StatefulSignatureAlgorithm, VerifyOptions, XMSS,
    XMSS_MT, XofAlgorithm, hazmat,
};

// Counts the bytes that each thread holds, so that a test can bound what one call allocates.
struct Tracking;

thread_local! {
    static LIVE: Cell<usize> = const { Cell::new(0) };

    static PEAK: Cell<usize> = const { Cell::new(0) };
}

#[global_allocator]
static ALLOCATOR: Tracking = Tracking;

fn grow(size: usize) {
    let _ = LIVE.try_with(|live| {
        live.set(live.get() + size);

        let _ = PEAK.try_with(|peak| peak.set(peak.get().max(live.get())));
    });
}

fn shrink(size: usize) {
    let _ = LIVE.try_with(|live| live.set(live.get().saturating_sub(size)));
}

unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };

        if !pointer.is_null() {
            grow(layout.size());
        }

        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };

        if !pointer.is_null() {
            grow(layout.size());
        }

        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };

        shrink(layout.size());
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, size) };

        if !moved.is_null() {
            shrink(layout.size());

            grow(size);
        }

        moved
    }
}

// The most memory the calling thread holds at once during run, beyond what it held before.
fn peak_allocation(run: impl FnOnce()) -> usize {
    let before = LIVE.with(Cell::get);

    PEAK.with(|peak| peak.set(before));

    run();

    PEAK.with(Cell::get) - before
}

fn fuzz() -> bool {
    std::env::var_os("CRYPTO_PQ_FUZZ").is_some_and(|value| !value.is_empty())
}

fn scale() -> usize {
    if fuzz() { 50 } else { 1 }
}

// SplitMix64, the generator of every implementation's robustness tests.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);

        let mut z = self.0;

        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);

        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);

        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn bytes(&mut self, size: usize) -> Vec<u8> {
        (0..size).map(|_| self.next() as u8).collect()
    }

    fn choice<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

fn pattern(size: usize, first: u8) -> Vec<u8> {
    (0..size).map(|i| first.wrapping_add(i as u8)).collect()
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}

const TAGS: [u8; 8] = [0x02, 0x03, 0x04, 0x06, 0x30, 0x80, 0x81, 0xA0];

// Indefinite, gigabytes, non-minimal, five bytes long, and plain wrong lengths.
const LENGTHS: [&[u8]; 12] = [
    &[0x80],
    &[0x84, 0xFF, 0xFF, 0xFF, 0xFF],
    &[0x84, 0x7F, 0xFF, 0xFF, 0xFF],
    &[0x83, 0xFF, 0xFF, 0xFF],
    &[0x82, 0xFF, 0xFF],
    &[0x81, 0x05],
    &[0x81, 0x7F],
    &[0x82, 0x00, 0x80],
    &[0x85, 0x01, 0x00, 0x00, 0x00, 0x00],
    &[0x00],
    &[0x01],
    &[0x7F],
];

const SPACES: [&[u8]; 6] = [b" ", b"\t", b"\n", b"\r\n", b"\x0b", b"\x0c"];

// The OIDs of every algorithm and of SHA-256, those of the stateful schemes, and broken ones.
fn oids() -> Vec<Vec<u8>> {
    let nist = |category: u8, arc: u8| {
        vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, category, arc,
        ]
    };

    let mut out: Vec<Vec<u8>> = (1..=4).map(|arc| nist(4, arc)).collect();

    out.extend((16..48).map(|arc| nist(3, arc)));

    out.push(nist(2, 1));

    out.push(vec![
        0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x11,
    ]);

    out.push(vec![
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x22,
    ]);

    out.push(vec![
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x23,
    ]);

    out.extend([
        vec![0x06, 0x00],
        vec![0x06, 0x01, 0x00],
        vec![0x06, 0x81, 0x01, 0x2A],
    ]);

    out
}

fn tag_position(rng: &mut Random, data: &[u8]) -> Option<usize> {
    (0..16)
        .map(|_| rng.below(data.len()))
        .find(|&position| TAGS.contains(&data[position]) && position + 1 < data.len())
}

fn oid_position(rng: &mut Random, data: &[u8]) -> Option<usize> {
    let starts: Vec<usize> = (0..data.len().saturating_sub(1))
        .filter(|&i| {
            data[i] == 0x06 && data[i + 1] < 0x10 && i + 2 + usize::from(data[i + 1]) <= data.len()
        })
        .collect();

    (!starts.is_empty()).then(|| *rng.choice(&starts))
}

// One random edit: bits, bytes, insertions, deletions, truncation, DER length fields (huge,
// indefinite, non-minimal), tags, OIDs, or a slice of another valid encoding.
fn mutate(rng: &mut Random, data: &[u8], others: &[Vec<u8>]) -> Vec<u8> {
    if data.is_empty() {
        let size = rng.below(16);

        return rng.bytes(size);
    }

    let mut data = data.to_vec();

    let operation = rng.below(11);

    let position = rng.below(data.len());

    // An edit that does not apply (no tag, no OID, nothing to splice from) duplicates a slice.
    let header = if operation == 6 || operation == 7 {
        tag_position(rng, &data)
    } else {
        None
    };

    let oid = if operation == 8 {
        oid_position(rng, &data)
    } else {
        None
    };

    match (operation, header, oid) {
        (0, _, _) => data[position] ^= 1 << rng.below(8),
        (1, _, _) => {
            let random = rng.below(256) as u8;

            data[position] = *rng.choice(&[0x00, 0x01, 0x7F, 0x80, 0xFF, random]);
        }
        (2, _, _) => {
            let size = 1 + rng.below(4);

            let inserted = rng.bytes(size);

            data.splice(position..position, inserted);
        }
        (3, _, _) => {
            let end = data.len().min(position + 1 + rng.below(4));

            data.drain(position..end);
        }
        (4, _, _) => data.truncate(position),
        (5, _, _) => {
            let size = 1 + rng.below(32);

            data.extend(rng.bytes(size));
        }
        (6, Some(header), _) => {
            let first = data[header + 1];

            let size = 1 + if first & 0x80 != 0 {
                usize::from(first & 0x7F)
            } else {
                0
            };

            let end = data.len().min(header + 1 + size);

            let length = if rng.below(2) == 1 {
                rng.choice(&LENGTHS).to_vec()
            } else {
                vec![rng.below(256) as u8]
            };

            data.splice(header + 1..end, length);
        }
        (7, Some(header), _) => {
            let random = rng.below(256) as u8;

            data[header] = if rng.below(2) == 1 {
                *rng.choice(&TAGS)
            } else {
                random
            };
        }
        (8, _, Some(start)) => {
            let end = start + 2 + usize::from(data[start + 1]);

            let replacement = rng.choice(&oids()).clone();

            data.splice(start..end, replacement);
        }
        (9, _, _) if !others.is_empty() => {
            let other = rng.choice(others).clone();

            let start = rng.below(other.len() + 1);

            let piece = other[start..other.len().min(start + rng.below(64))].to_vec();

            let end = data.len().min(position + rng.below(64));

            data.splice(position..end, piece);
        }
        _ => {
            let end = data.len().min(position + 1 + rng.below(16));

            let copy = data[position..end].to_vec();

            data.splice(position..position, copy);
        }
    }

    data
}

fn mutate_pem(rng: &mut Random, text: &[u8]) -> Vec<u8> {
    let mut text = text.to_vec();

    let operation = rng.below(8);

    let position = rng.below(text.len() + 1);

    match operation {
        0 => {
            let space = rng.choice(&SPACES).repeat(1 + rng.below(3));

            text.splice(position..position, space);
        }
        1 => {
            let byte = 0x80 + rng.below(128) as u8;

            text.insert(position, byte);
        }
        2 => text.insert(position, b'='),
        3 => {
            let swap = String::from_utf8_lossy(&text).replace("PUBLIC", "PRIVATE");

            text = swap.into_bytes();
        }
        4 => text.retain(|&byte| byte != b'\n'),
        5 => {
            let width = 1 + rng.below(80);

            let compact: Vec<u8> = text
                .iter()
                .copied()
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect();

            text = compact.chunks(width).collect::<Vec<_>>().join(&b'\n');
        }
        _ => text = mutate(rng, &text, &[]),
    }

    text
}

fn inputs(rng: &mut Random, seeds: &[Vec<u8>], rounds: usize) -> Vec<Vec<u8>> {
    (0..rounds)
        .map(|_| {
            if rng.below(8) == 0 {
                let size = rng.below(96);

                return rng.bytes(size);
            }

            let mut data = rng.choice(seeds).clone();

            for _ in 0..1 + rng.below(3) {
                data = mutate(rng, &data, seeds);
            }

            data
        })
        .collect()
}

fn expect_codes<T>(
    result: Result<T, Error>,
    codes: &[Error],
    what: &str,
    data: &[u8],
) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            assert!(codes.contains(&error), "{what}: {error} for {}", hex(data));

            None
        }
    }
}

const FORMATS: [KeyFormat; 3] = [KeyFormat::Raw, KeyFormat::Der, KeyFormat::Pem];

const KEMS: [KemAlgorithm; 11] = [
    ML_KEM_512,
    ML_KEM_768,
    ML_KEM_1024,
    FRODOKEM_976_AES,
    FRODOKEM_976_SHAKE,
    FRODOKEM_1344_AES,
    FRODOKEM_1344_SHAKE,
    EFRODOKEM_976_AES,
    EFRODOKEM_976_SHAKE,
    EFRODOKEM_1344_AES,
    EFRODOKEM_1344_SHAKE,
];

fn is_frodo(algorithm: KemAlgorithm) -> bool {
    algorithm.name().contains("FrodoKEM")
}

const SIGNATURES: [SignatureAlgorithm; 15] = [
    ML_DSA_44,
    ML_DSA_65,
    ML_DSA_87,
    SLH_DSA_SHA2_128S,
    SLH_DSA_SHA2_128F,
    SLH_DSA_SHA2_192S,
    SLH_DSA_SHA2_192F,
    SLH_DSA_SHA2_256S,
    SLH_DSA_SHA2_256F,
    SLH_DSA_SHAKE_128S,
    SLH_DSA_SHAKE_128F,
    SLH_DSA_SHAKE_192S,
    SLH_DSA_SHAKE_192F,
    SLH_DSA_SHAKE_256S,
    SLH_DSA_SHAKE_256F,
];

const HASHES: [HashAlgorithm; 10] = [
    SHA_224,
    SHA_256,
    SHA_384,
    SHA_512,
    SHA_512_224,
    SHA_512_256,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
];

fn is_ml_dsa(algorithm: SignatureAlgorithm) -> bool {
    algorithm.name().starts_with("ML-DSA")
}

// The sizes of the deterministic inputs: seeds and randomness.
fn kem_sizes(algorithm: KemAlgorithm) -> (usize, usize) {
    let secret = algorithm.shared_secret_size();

    match algorithm.name() {
        name if name.starts_with("eFrodoKEM") => (2 * secret + 16, secret),
        name if name.starts_with("FrodoKEM") => (3 * secret + 16, 3 * secret),
        _ => (64, 32),
    }
}

fn signature_sizes(algorithm: SignatureAlgorithm) -> (usize, usize, usize) {
    if is_ml_dsa(algorithm) {
        return (32, 32, 0);
    }

    let n = algorithm.public_key_size() / 2;

    (3 * n, n, n)
}

// (collision strength, pre-hash) of every choice, and the strength each algorithm requires.
fn pre_hashes() -> Vec<(usize, PreHash)> {
    let strengths = [112, 128, 192, 256, 112, 128, 112, 128, 192, 256];

    let mut out: Vec<(usize, PreHash)> = HASHES
        .iter()
        .zip(strengths)
        .map(|(&hash, strength)| (strength, hash.into()))
        .collect();

    out.push((128, SHAKE128.into()));

    out.push((256, SHAKE256.into()));

    out
}

fn strength(algorithm: SignatureAlgorithm) -> usize {
    match algorithm.name() {
        "ML-DSA-44" => 128,
        "ML-DSA-65" => 192,
        "ML-DSA-87" => 256,
        _ => 4 * algorithm.public_key_size(),
    }
}

fn kem_codes(algorithm: KemAlgorithm, format: KeyFormat, check: Error) -> Vec<Error> {
    match format {
        KeyFormat::Raw => vec![Error::InvalidLength, check],
        _ if is_frodo(algorithm) => vec![Error::Unsupported],
        _ => vec![Error::InvalidEncoding, Error::AlgorithmMismatch, check],
    }
}

fn signature_codes(format: KeyFormat, check: Error) -> Vec<Error> {
    match format {
        KeyFormat::Raw => vec![Error::InvalidLength, check],
        _ => vec![Error::InvalidEncoding, Error::AlgorithmMismatch, check],
    }
}

// The DER inside a PEM input, so that encodings that differ only in whitespace or in the text
// around the block compare equal; the PEM decoder is internal, so this one is written out here.
fn pem_body(data: &[u8]) -> Vec<u8> {
    let find = |data: &[u8], pattern: &[u8]| {
        data.windows(pattern.len())
            .position(|window| window == pattern)
            .expect("an imported PEM block")
    };

    let rest = &data[find(data, b"-----BEGIN ") + 11..];

    let rest = &rest[find(rest, b"-----") + 5..];

    let text = &rest[..find(rest, b"-----END ")];

    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut bits = 0u32;

    let mut count = 0;

    let mut out = Vec::new();

    for &byte in text {
        if let Some(value) = alphabet.iter().position(|&c| c == byte) {
            bits = (bits << 6) | value as u32;

            count += 6;

            if count >= 8 {
                count -= 8;

                out.push((bits >> count) as u8);
            }
        }
    }

    out
}

fn same_encoding(exported: &[u8], data: &[u8], format: KeyFormat) {
    if format == KeyFormat::Pem {
        assert_eq!(
            pem_body(exported),
            pem_body(data),
            "PEM round trip of {}",
            hex(data)
        );
    } else {
        assert_eq!(exported, data, "round trip");
    }
}

fn kem_fixtures() -> Vec<(KemAlgorithm, KemPrivateKey, Vec<u8>, Vec<u8>)> {
    KEMS.iter()
        .map(|&algorithm| {
            let (seed, randomness) = kem_sizes(algorithm);

            let pair = hazmat::generate_kem_key_pair(algorithm, &pattern(seed, 0)).expect("key");

            let encapsulation = hazmat::encapsulate(&pair.public_key, &pattern(randomness, 0x80))
                .expect("encapsulation");

            (
                algorithm,
                pair.private_key,
                encapsulation.ciphertext,
                encapsulation.shared_secret.to_vec(),
            )
        })
        .collect()
}

fn check_kem_public(algorithm: KemAlgorithm, data: &[u8], format: KeyFormat) {
    let Some(key) = expect_codes(
        algorithm.import_public_key(data, format),
        &kem_codes(algorithm, format, Error::InvalidPublicKey),
        algorithm.name(),
        data,
    ) else {
        return;
    };

    same_encoding(&key.export_key(format).expect("export"), data, format);

    stable_kem_public(algorithm, &key);

    let (_, randomness) = kem_sizes(algorithm);

    let encapsulation = hazmat::encapsulate(&key, &vec![0; randomness]).expect("encapsulation");

    assert_eq!(encapsulation.ciphertext.len(), algorithm.ciphertext_size());
}

fn stable_kem_public(algorithm: KemAlgorithm, key: &KemPublicKey) {
    for format in FORMATS {
        if let Ok(exported) = key.export_key(format) {
            assert_eq!(
                &algorithm
                    .import_public_key(&exported, format)
                    .expect("re-import"),
                key
            );
        }
    }
}

fn check_kem_private(algorithm: KemAlgorithm, data: &[u8], format: KeyFormat) {
    let Some(key) = expect_codes(
        algorithm.import_private_key(data, format),
        &kem_codes(algorithm, format, Error::InvalidPrivateKey),
        algorithm.name(),
        data,
    ) else {
        return;
    };

    if format == KeyFormat::Raw {
        assert_eq!(*key.export_key(format).expect("export"), *data);
    }

    for format in FORMATS {
        if let Ok(exported) = key.export_key(format) {
            let again = algorithm
                .import_private_key(&exported, format)
                .expect("re-import");

            assert_eq!(
                *again.export_key(KeyFormat::Raw).expect("export"),
                *key.export_key(KeyFormat::Raw).expect("export")
            );
        }
    }

    // A key from a seed decapsulates what its public key encapsulates. FIPS 203 checks only the
    // hash of the public part of an expanded key, so one with another secret vector is accepted
    // and gives the implicit rejection, SHAKE256(z || c); FrodoKEM checks pkh and gives
    // SHAKE256(c || s) with another S^T.
    let (seed, randomness) = kem_sizes(algorithm);

    let encapsulation =
        hazmat::encapsulate(&key.public_key(), &vec![0; randomness]).expect("encapsulation");

    let secret = key
        .decapsulate(&encapsulation.ciphertext)
        .expect("decapsulation");

    if *secret != *encapsulation.shared_secret {
        let raw = key.export_key(KeyFormat::Raw).expect("export");

        assert_ne!(raw.len(), seed);

        let size = algorithm.shared_secret_size();

        let rejection = if is_frodo(algorithm) {
            [&encapsulation.ciphertext, &raw[..size]].concat()
        } else {
            [&raw[raw.len() - 32..], &encapsulation.ciphertext].concat()
        };

        assert_eq!(*secret, *SHAKE256.digest(&rejection, size).unwrap());
    }
}

// The expanded private key of the first ACVP key generation record of an ML-KEM parameter set.
fn expanded_key(algorithm: KemAlgorithm) -> Vec<u8> {
    vectors::first("acvp/ML-KEM-keyGen.txt", algorithm.name(), "dk")
}

// FIPS 203 checks only the hash of the public part of an expanded key, so one whose secret vector
// was changed passes them; the pairwise test of the import refuses it (SPEC 8.1.4 check (4)).
#[test]
fn inconsistent_expanded_kem_key() {
    for algorithm in [ML_KEM_512, ML_KEM_768, ML_KEM_1024] {
        let mut dk = expanded_key(algorithm);

        dk[0] ^= 1;

        assert_eq!(
            algorithm.import_private_key(&dk, KeyFormat::Raw).err(),
            Some(Error::InvalidPrivateKey)
        );
    }
}

#[test]
fn kem_import() {
    let mut rng = Random(3);

    for (algorithm, private_key, _, _) in kem_fixtures() {
        let public_key = private_key.public_key();

        let expanded = (!is_frodo(algorithm)).then(|| {
            algorithm
                .import_private_key(&expanded_key(algorithm), KeyFormat::Raw)
                .expect("expanded key")
        });

        for private in [false, true] {
            for format in FORMATS {
                let mut seeds = vec![
                    match (private, format) {
                        (_, KeyFormat::Der | KeyFormat::Pem) if is_frodo(algorithm) => {
                            public_key.export_key(KeyFormat::Raw)
                        }
                        (true, _) => private_key.export_key(format).map(|key| key.to_vec()),
                        (false, _) => public_key.export_key(format),
                    }
                    .expect("export"),
                ];

                if let (true, Some(expanded)) = (private, &expanded) {
                    seeds.push(expanded.export_key(format).expect("export").to_vec());
                }

                for data in inputs(&mut rng, &seeds, 25 * scale()) {
                    if private {
                        check_kem_private(algorithm, &data, format);
                    } else {
                        check_kem_public(algorithm, &data, format);
                    }
                }
            }
        }
    }
}

fn check_signature_public(algorithm: SignatureAlgorithm, data: &[u8], format: KeyFormat) {
    let Some(key) = expect_codes(
        algorithm.import_public_key(data, format),
        &signature_codes(format, Error::InvalidLength),
        algorithm.name(),
        data,
    ) else {
        return;
    };

    same_encoding(&key.export_key(format).expect("export"), data, format);

    for format in FORMATS {
        let exported = key.export_key(format).expect("export");

        assert_eq!(
            algorithm
                .import_public_key(&exported, format)
                .expect("re-import"),
            key
        );
    }

    assert!(!key.verify(
        &vec![0; algorithm.signature_size()],
        b"",
        &VerifyOptions::default()
    ));
}

fn check_signature_private(algorithm: SignatureAlgorithm, data: &[u8], format: KeyFormat) {
    let Some(key) = expect_codes(
        algorithm.import_private_key(data, format),
        &signature_codes(format, Error::InvalidPrivateKey),
        algorithm.name(),
        data,
    ) else {
        return;
    };

    if format == KeyFormat::Raw {
        assert_eq!(*key.export_key(format).expect("export"), *data);
    }

    for format in FORMATS {
        let exported = key.export_key(format).expect("export");

        let again = algorithm
            .import_private_key(&exported, format)
            .expect("re-import");

        assert_eq!(
            *again.export_key(KeyFormat::Raw).expect("export"),
            *key.export_key(KeyFormat::Raw).expect("export")
        );
    }

    let (_, _, n) = signature_sizes(algorithm);

    if !is_ml_dsa(algorithm) {
        let raw = key.export_key(KeyFormat::Raw).expect("export");

        assert_eq!(
            raw[2 * n..],
            key.public_key().export_key(KeyFormat::Raw).expect("export")
        );

        return;
    }

    let signature =
        hazmat::sign(&key, b"accepted", &[0; 32], &SignOptions::default()).expect("signature");

    assert!(
        key.public_key()
            .verify(&signature, b"accepted", &VerifyOptions::default())
    );
}

// The fast sets by default; every set in a long run, where an SLH-DSA private key, whose import
// builds a tree, gets fewer rounds.
fn signature_algorithms() -> Vec<SignatureAlgorithm> {
    SIGNATURES
        .iter()
        .copied()
        .filter(|algorithm| fuzz() || is_ml_dsa(*algorithm) || algorithm.name().ends_with('f'))
        .collect()
}

#[test]
fn signature_import() {
    let mut rng = Random(4);

    for algorithm in signature_algorithms() {
        let (seed, _, _) = signature_sizes(algorithm);

        let pair = hazmat::generate_signature_key_pair(algorithm, &pattern(seed, 0)).expect("key");

        let rounds = if is_ml_dsa(algorithm) { 25 } else { 4 } * scale();

        for private in [false, true] {
            for format in FORMATS {
                let encoded = if private {
                    pair.private_key.export_key(format).map(|key| key.to_vec())
                } else {
                    pair.public_key.export_key(format)
                };

                for data in inputs(&mut rng, &[encoded.expect("export")], rounds) {
                    if private {
                        check_signature_private(algorithm, &data, format);
                    } else {
                        check_signature_public(algorithm, &data, format);
                    }
                }
            }
        }
    }
}

// PEM edits: whitespace anywhere, non-ASCII bytes, padding, the other label, other line widths.
#[test]
fn pem_import() {
    let mut rng = Random(10);

    let kem = hazmat::generate_kem_key_pair(ML_KEM_768, &pattern(64, 0)).expect("key");

    let dsa = hazmat::generate_signature_key_pair(ML_DSA_44, &pattern(32, 0)).expect("key");

    let seeds = [
        kem.public_key.export_key(KeyFormat::Pem).expect("export"),
        kem.private_key
            .export_key(KeyFormat::Pem)
            .expect("export")
            .to_vec(),
        dsa.public_key.export_key(KeyFormat::Pem).expect("export"),
        dsa.private_key
            .export_key(KeyFormat::Pem)
            .expect("export")
            .to_vec(),
    ];

    for _ in 0..300 * scale() {
        let choice = rng.below(seeds.len());

        let mut text = seeds[choice].clone();

        for _ in 0..1 + rng.below(3) {
            text = mutate_pem(&mut rng, &text);
        }

        match choice {
            0 => check_kem_public(ML_KEM_768, &text, KeyFormat::Pem),
            1 => check_kem_private(ML_KEM_768, &text, KeyFormat::Pem),
            2 => check_signature_public(ML_DSA_44, &text, KeyFormat::Pem),
            _ => check_signature_private(ML_DSA_44, &text, KeyFormat::Pem),
        }
    }
}

fn stateful_seeds() -> Vec<(StatefulSignatureAlgorithm, Vec<u8>)> {
    let key = |prefix: &[u8], size: usize| [prefix, &pattern(size, 0)].concat();

    vec![
        (HSS_LMS, key(&[0, 0, 0, 1, 0, 0, 0, 10, 0, 0, 0, 5], 40)),
        (
            HSS_LMS,
            key(&[0, 0, 0, 8, 0, 0, 0, 0x14, 0, 0, 0, 0x10], 40),
        ),
        (XMSS, key(&[0, 0, 0, 1], 64)),
        (XMSS, key(&[0, 0, 0, 0x15], 48)),
        (XMSS_MT, key(&[0, 0, 0, 0x31], 48)),
        (XMSS_MT, key(&[0, 0, 0, 8], 64)),
    ]
}

#[test]
fn stateful_import() {
    let mut rng = Random(5);

    for (algorithm, raw) in stateful_seeds() {
        let key = algorithm
            .import_public_key(&raw, KeyFormat::Raw)
            .expect("key");

        for format in FORMATS {
            for data in inputs(
                &mut rng,
                &[key.export_key(format).expect("export")],
                150 * scale(),
            ) {
                let codes = if format == KeyFormat::Raw {
                    vec![Error::InvalidPublicKey]
                } else {
                    vec![
                        Error::InvalidEncoding,
                        Error::AlgorithmMismatch,
                        Error::InvalidPublicKey,
                    ]
                };

                let Some(imported) = expect_codes(
                    algorithm.import_public_key(&data, format),
                    &codes,
                    algorithm.name(),
                    &data,
                ) else {
                    continue;
                };

                same_encoding(&imported.export_key(format).expect("export"), &data, format);

                for format in FORMATS {
                    let exported = imported.export_key(format).expect("export");

                    assert_eq!(
                        algorithm
                            .import_public_key(&exported, format)
                            .expect("re-import"),
                        imported
                    );
                }

                assert!(!imported.verify(&[0; 64], b""));
            }
        }
    }
}

// An algorithm, a public key, a message, its signature and whether the key is real.
type SignatureFixture = (
    SignatureAlgorithm,
    SignaturePublicKey,
    Vec<u8>,
    Vec<u8>,
    bool,
);

// SLH-DSA keys are expensive to make, so verification gets a public key of the right size, which
// is all that it checks, and an all-zero signature.
fn signature_fixtures() -> Vec<SignatureFixture> {
    signature_algorithms()
        .into_iter()
        .map(|algorithm| {
            if !is_ml_dsa(algorithm) {
                let key = algorithm
                    .import_public_key(&pattern(algorithm.public_key_size(), 0x20), KeyFormat::Raw)
                    .expect("key");

                return (
                    algorithm,
                    key,
                    Vec::new(),
                    vec![0; algorithm.signature_size()],
                    false,
                );
            }

            let pair =
                hazmat::generate_signature_key_pair(algorithm, &pattern(32, 0)).expect("key");

            let message = b"crypto-pq robustness".to_vec();

            let options = SignOptions::default().with_context(b"context");

            let signature = hazmat::sign(&pair.private_key, &message, &pattern(32, 0x60), &options)
                .expect("signature");

            (algorithm, pair.public_key, message, signature, true)
        })
        .collect()
}

#[test]
fn verify_signatures() {
    let mut rng = Random(6);

    let choices = pre_hashes();

    for (algorithm, public_key, message, signature, real) in signature_fixtures() {
        let size = algorithm.signature_size();

        for _ in 0..if real { 60 } else { 6 } * scale() {
            let mut candidate = if rng.below(8) != 0 {
                let mut candidate = signature.clone();

                for _ in 0..1 + rng.below(2) {
                    candidate = mutate(&mut rng, &candidate, &[]);
                }

                candidate
            } else {
                let length = rng.below(size + 2);

                rng.bytes(length)
            };

            if rng.below(2) == 1 {
                candidate.resize(size, 0);
            }

            let text = if rng.below(2) == 1 {
                mutate(&mut rng, &message, &[])
            } else {
                message.clone()
            };

            let length = rng.below(300);

            let random_context = rng.bytes(length);

            let context = rng
                .choice(&[
                    b"context".to_vec(),
                    Vec::new(),
                    random_context,
                    vec![0; 255],
                    vec![0; 256],
                ])
                .clone();

            let choice = rng.below(choices.len() + 1);

            let pre_hash = choices.get(choice).map(|&(_, pre_hash)| pre_hash);

            let policy = rng.below(4) != 0;

            let mut options = VerifyOptions::default().with_context(&context);

            options.pre_hash = pre_hash;

            let valid = if policy {
                public_key.verify(&candidate, &text, &options)
            } else {
                hazmat::verify(&public_key, &candidate, &text, &options)
            };

            let weak = policy
                && choices
                    .get(choice)
                    .is_some_and(|&(bits, _)| bits < strength(algorithm));

            if valid {
                assert!(!weak && context.len() <= 255 && candidate.len() == size);

                assert!(
                    real && candidate == signature
                        && text == message
                        && context == b"context"
                        && pre_hash.is_none(),
                    "{} accepted {}",
                    algorithm.name(),
                    hex(&candidate)
                );
            }
        }
    }
}

#[derive(Clone, Default)]
struct MemoryStore(Arc<Mutex<Option<Vec<u8>>>>);

impl MemoryStore {
    fn holding(state: &[u8]) -> Self {
        Self(Arc::new(Mutex::new(Some(state.to_vec()))))
    }

    fn state(&self) -> Option<Vec<u8>> {
        self.0.lock().expect("lock").clone()
    }
}

impl StateStore for MemoryStore {
    fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.state())
    }

    fn update(&mut self, previous: Option<&[u8]>, next: &[u8]) -> Result<bool, Error> {
        let mut state = self.0.lock().expect("lock");

        if state.as_deref() != previous {
            return Ok(false);
        }

        *state = Some(next.to_vec());

        Ok(true)
    }
}

#[test]
fn verify_stateful() {
    let mut rng = Random(7);

    let levels = [
        ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W2"),
        ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W1"),
    ];

    let mut pair = hazmat::generate_stateful_key_pair(
        HSS_LMS,
        &pattern(40, 0),
        33,
        StatefulParameters::Levels(&levels),
        MemoryStore::default(),
        &StatefulKeyGenOptions::default(),
    )
    .expect("key");

    let message = b"crypto-pq robustness".to_vec();

    let mut cases = vec![(
        HSS_LMS,
        pair.public_key.export_key(KeyFormat::Raw).expect("export"),
        pair.private_key.sign(&message).expect("signature"),
    )];

    let mut mt = hazmat::generate_stateful_key_pair(
        XMSS_MT,
        &pattern(72, 0),
        7,
        StatefulParameters::Name("XMSSMT-SHA2_20/4_192"),
        MemoryStore::default(),
        &StatefulKeyGenOptions::default(),
    )
    .expect("key");

    cases.push((
        XMSS_MT,
        mt.public_key.export_key(KeyFormat::Raw).expect("export"),
        mt.private_key.sign(&message).expect("signature"),
    ));

    cases.push((
        XMSS,
        [&[0, 0, 0, 0x0D][..], &pattern(48, 0)].concat(),
        vec![0; 4 + 24 + (51 + 10) * 24],
    ));

    for (algorithm, raw, signature) in &cases {
        let public_key = algorithm
            .import_public_key(raw, KeyFormat::Raw)
            .expect("key");

        for _ in 0..60 * scale() {
            let candidate = if rng.below(8) != 0 {
                mutate(&mut rng, signature, &[])
            } else {
                let length = rng.below(signature.len() + 2);

                rng.bytes(length)
            };

            let text = if rng.below(2) == 1 {
                mutate(&mut rng, &message, &[])
            } else {
                message.clone()
            };

            if public_key.verify(&candidate, &text) {
                assert!(
                    &candidate == signature && text == message,
                    "{} accepted {}",
                    algorithm.name(),
                    hex(&candidate)
                );
            }
        }
    }

    let raws: Vec<Vec<u8>> = cases.iter().map(|(_, raw, _)| raw.clone()).collect();

    for _ in 0..300 * scale() {
        let algorithm = *rng.choice(&[HSS_LMS, XMSS, XMSS_MT]);

        let base = rng.choice(&raws).clone();

        let raw = mutate(&mut rng, &base, &[]);

        if let Some(public_key) = expect_codes(
            algorithm.import_public_key(&raw, KeyFormat::Raw),
            &[Error::InvalidPublicKey],
            algorithm.name(),
            &raw,
        ) {
            let length = rng.below(4096);

            public_key.verify(&rng.bytes(length), b"");
        }
    }
}

#[test]
fn decapsulation() {
    let mut rng = Random(8);

    for (algorithm, private_key, ciphertext, secret) in kem_fixtures() {
        let size = algorithm.ciphertext_size();

        for _ in 0..60 * scale() {
            let mut candidate = if rng.below(8) != 0 {
                mutate(&mut rng, &ciphertext, &[])
            } else {
                let length = rng.below(size + 2);

                rng.bytes(length)
            };

            if rng.below(2) == 1 {
                candidate.resize(size, 0);
            }

            match private_key.decapsulate(&candidate) {
                Err(error) => assert!(error == Error::InvalidLength && candidate.len() != size),
                Ok(shared) => {
                    assert_eq!(candidate.len(), size);

                    assert_eq!(shared.len(), algorithm.shared_secret_size());

                    // Implicit rejection: any other ciphertext gives a different secret.
                    assert_eq!(
                        shared[..] == secret[..],
                        candidate == ciphertext,
                        "{}",
                        hex(&candidate)
                    );
                }
            }
        }
    }
}

const XMSS_SHAPES: [(u32, u32); 8] = [
    (20, 2),
    (20, 4),
    (40, 2),
    (40, 4),
    (40, 8),
    (60, 3),
    (60, 6),
    (60, 12),
];

// (n, h, d) of an XMSS (multi = false) or XMSS^MT code point.
fn xmss_parameters(multi: bool, oid: u32) -> Option<(usize, u32, u32)> {
    let families: [(u32, usize); 4] = if multi {
        [(0x01, 32), (0x21, 24), (0x29, 32), (0x31, 24)]
    } else {
        [(0x01, 32), (0x0D, 24), (0x10, 32), (0x13, 24)]
    };

    families.iter().find_map(|&(base, n)| {
        let offset = oid.checked_sub(base)? as usize;

        if multi {
            XMSS_SHAPES.get(offset).map(|&(h, d)| (n, h, d))
        } else {
            [10, 16, 20].get(offset).map(|&h| (n, h, 1))
        }
    })
}

// (n, w or h) of an LM-OTS or LMS type code, with the family that has to match across levels.
fn ots_type(code: u32) -> Option<(usize, u32, u32)> {
    let index = code.checked_sub(1).filter(|&index| index < 16)?;

    Some((
        [32, 24, 32, 24][(index / 4) as usize],
        [1, 2, 4, 8][(index % 4) as usize],
        index / 4,
    ))
}

fn lms_type(code: u32) -> Option<(usize, u32, u32)> {
    let index = code.checked_sub(5).filter(|&index| index < 20)?;

    Some((
        [32, 24, 32, 24][(index / 5) as usize],
        [5, 10, 15, 20, 25][(index % 5) as usize],
        index / 5,
    ))
}

fn ots_p(n: usize, w: u32) -> usize {
    let u = (8 * n).div_ceil(w as usize);

    let v = (usize::BITS - (((1usize << w) - 1) * u).leading_zeros()).div_ceil(w) as usize;

    u + v
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(data[offset..offset + 4].try_into().expect("four bytes"))
}

// A state record of version 2 (SPEC 11.7) read by the format rules alone.
#[derive(PartialEq, Eq)]
struct ParsedState {
    // The height of each level, top first, the type codes that its tree is built with (HSS: LMS
    // and LM-OTS type, XMSS: the OID) and the hash calls that building its tree takes.
    heights: Vec<u32>,
    codes: Vec<u64>,
    costs: Vec<u64>,
    next: u64,
    top: Vec<u8>,
    public_key: Vec<u8>,
    // Each lower level's tree, and its secrets, root and parent signature once signed.
    records: Vec<(u64, Option<Vec<u8>>)>,
}

impl ParsedState {
    fn capacity(&self) -> u64 {
        1 << self.heights.iter().sum::<u32>()
    }

    fn below(&self, level: usize) -> u32 {
        self.heights[level..].iter().sum()
    }

    fn tree(&self, index: u64, level: usize) -> u64 {
        if level == 0 {
            0
        } else {
            index >> self.below(level)
        }
    }

    fn current(&self, level: usize, index: u64) -> bool {
        (1..=level).all(|l| {
            let (tree, signed) = &self.records[l - 1];

            signed.is_some() && *tree == self.tree(index, l)
        })
    }

    // SPEC 11.9 item 4.
    fn resume(&self) -> Result<u64, Error> {
        let mut index = self.next;

        for level in 1..self.heights.len() {
            let (tree, signed) = &self.records[level - 1];

            let expected = self.tree(index, level);

            if *tree > expected {
                return Err(Error::InvalidPrivateKey);
            }

            if *tree == expected {
                if signed.is_none() {
                    index = ((tree + 1) << self.below(level)).min(self.capacity());
                } else if !self.current(level - 1, index) {
                    return Err(Error::InvalidPrivateKey);
                }
            }
        }

        Ok(index)
    }
}

// SPEC 11.9 items 2 and 3.
fn parse_state(algorithm: StatefulSignatureAlgorithm, state: &[u8]) -> Result<ParsedState, Error> {
    let invalid = Error::InvalidPrivateKey;

    if state.len() < 18 {
        return Err(invalid);
    }

    let (body, checksum) = state.split_at(state.len() - 16);

    if SHA_256.digest(body)[..16] != *checksum || body[0] != 2 {
        return Err(invalid);
    }

    let kind = [HSS_LMS, XMSS, XMSS_MT]
        .iter()
        .position(|&other| other == algorithm)
        .expect("kind") as u8
        + 1;

    if body[1] != kind {
        return Err(Error::AlgorithmMismatch);
    }

    let mut at = 2;

    let mut take = |size: usize| {
        let field = body.get(at..at + size).ok_or(invalid)?;

        at += size;

        Ok::<&[u8], Error>(field)
    };

    // The heights and costs of the levels, the sizes of the top secrets, the public key, a child's
    // secrets and root, the parent signature of each lower level, and the public key bytes that
    // the top secrets give.
    let (heights, codes, costs, top_size, key_size, child, node, signatures, pattern);

    if algorithm == HSS_LMS {
        let count = usize::from(take(1)?[0]);

        let types = take(8 * count)?;

        let mut levels = Vec::new();

        for code in types.chunks(8) {
            let lms = lms_type(read_u32(code, 0)).ok_or(invalid)?;

            let ots = ots_type(read_u32(code, 4)).ok_or(invalid)?;

            levels.push((lms, ots));
        }

        let family = levels.first().ok_or(invalid)?.0;

        let mixed = levels
            .iter()
            .any(|&((m, _, lms_family), (n, _, ots_family))| {
                (m, lms_family) != (family.0, family.2) || (n, ots_family) != (family.0, family.2)
            });

        heights = levels.iter().map(|((_, h, _), _)| *h).collect::<Vec<_>>();

        codes = types
            .chunks(8)
            .map(|code| u64::from_be_bytes(code.try_into().expect("eight bytes")))
            .collect();

        if mixed || count > 8 || heights.iter().sum::<u32>() > 60 {
            return Err(invalid);
        }

        let m = family.0;

        costs = levels
            .iter()
            .map(|&((n, h, _), (_, w, _))| (ots_p(n, w) as u64) << (h + w))
            .collect::<Vec<_>>();

        signatures = levels
            .iter()
            .map(|&((n, h, _), (_, w, _))| 12 + n * (ots_p(n, w) + 1) + h as usize * n)
            .collect::<Vec<_>>();

        (top_size, key_size, child, node) = (16 + m, 28 + m, 16 + m, m);

        pattern = [&(count as u32).to_be_bytes()[..], &types[..8]].concat();
    } else {
        let oid = take(4)?;

        let (n, h, d) = xmss_parameters(algorithm == XMSS_MT, read_u32(oid, 0)).ok_or(invalid)?;

        let height = h / d;

        heights = vec![height; d as usize];

        codes = vec![u64::from(read_u32(oid, 0)); d as usize];

        costs = vec![((2 * n as u64 + 3) * 16) << height; d as usize];

        signatures = vec![(2 * n + 3 + height as usize) * n; d as usize];

        (top_size, key_size, child, node) = (3 * n, 4 + 2 * n, n, n);

        pattern = oid.to_vec();
    }

    let flags = take(1)?[0];

    let next = u64::from_be_bytes(take(8)?.try_into().expect("eight bytes"));

    let top = take(top_size)?.to_vec();

    let public_key = take(key_size)?.to_vec();

    let mut records = Vec::new();

    for signature in &signatures[..signatures.len() - 1] {
        let tree = u64::from_be_bytes(take(8)?.try_into().expect("eight bytes"));

        let signed = match take(1)?[0] {
            0 => None,
            1 => Some(take(child + node + signature)?.to_vec()),
            _ => return Err(invalid),
        };

        records.push((tree, signed));
    }

    let parsed = ParsedState {
        heights,
        codes,
        costs,
        next,
        top,
        public_key,
        records,
    };

    if at != body.len() || flags > 1 || next > parsed.capacity() {
        return Err(invalid);
    }

    // The public key bytes that the top secrets give: the HSS level count, top types and I, or the
    // XMSS OID and SEED.
    let given = if algorithm == HSS_LMS {
        parsed.public_key[..12] == pattern[..] && parsed.public_key[12..28] == parsed.top[..16]
    } else {
        let n = node;

        parsed.public_key[..4] == pattern[..] && parsed.public_key[4 + n..] == parsed.top[2 * n..]
    };

    if next != parsed.capacity() && !given {
        return Err(invalid);
    }

    Ok(parsed)
}

// What loading a state record must give: the error, or the index, the capacity and the hash calls
// that building its trees takes. A record that the format accepts but whose current trees differ
// from those of `original`, which a key stored, may also fail the root or signature checks of the
// load: `exact` is false then.
struct Expected {
    index: u64,
    capacity: u64,
    cost: u64,
    exact: bool,
}

fn expected_state(
    algorithm: StatefulSignatureAlgorithm,
    state: &[u8],
    original: &[u8],
) -> Result<Expected, Error> {
    let parsed = parse_state(algorithm, state)?;

    let index = parsed.resume()?;

    let capacity = parsed.capacity();

    if index == capacity {
        return Ok(Expected {
            index,
            capacity,
            cost: 0,
            exact: true,
        });
    }

    let current = (0..parsed.heights.len())
        .take_while(|&level| parsed.current(level, index))
        .count();

    let cost = parsed.costs[..current].iter().sum();

    // The fields that the current trees are built and checked from, as the key stored them: a
    // lower level's types are not part of the public key, and changing its LM-OTS type keeps every
    // length.
    let same = parse_state(algorithm, original).is_ok_and(|original| {
        parsed.heights == original.heights
            && parsed.codes[..current] == original.codes[..current]
            && parsed.top == original.top
            && parsed.public_key == original.public_key
            && (1..current).all(|level| parsed.records[level - 1] == original.records[level - 1])
    });

    Ok(Expected {
        index,
        capacity,
        cost,
        exact: same,
    })
}

fn sealed(body: &[u8]) -> Vec<u8> {
    [body, &SHA_256.digest(body)[..16]].concat()
}

// Where a state record holds the flags, then next: after the version, the kind and the
// parameters.
fn flags_offset(state: &[u8]) -> usize {
    if state[1] == 1 {
        3 + 8 * usize::from(state[2])
    } else {
        6
    }
}

// Random edits of a state record, mostly resealed so that they reach the parser behind the
// checksum: level counts, type codes, flags, the bound next at and beyond the capacity, the tree
// numbers and statuses of the level records, and byte edits.
fn mutate_state(rng: &mut Random, state: &[u8]) -> Vec<u8> {
    let mut body = state[..state.len() - 16].to_vec();

    let flags = if body.len() > 2 {
        flags_offset(&body)
    } else {
        body.len()
    };

    match rng.below(8) {
        0 if body.len() > 2 => body[2] = *rng.choice(&[0, 1, 2, 3, 8, 9, 0x80, 0xFF]),
        1 if body.len() > 6 => {
            let offset = if body[1] == 1 {
                3 + 8 * rng.below(usize::from(body[2]).max(1)) + 4 * rng.below(2)
            } else {
                2
            };

            let small = rng.below(48) as u32;

            let large = rng.next() as u32;

            let value = *rng.choice(&[small, large, 0]);

            if offset + 4 <= body.len() {
                body[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            }
        }
        2 if body.len() >= flags + 9 => {
            let height = *rng.choice(&[5u32, 10, 15, 20, 40, 60, 64]);

            let top = 1u64.checked_shl(height).unwrap_or(0);

            let value = *rng.choice(&[
                0,
                1,
                33,
                63,
                64,
                1023,
                1024,
                top.wrapping_sub(1),
                top,
                top.wrapping_add(1),
                u64::MAX,
            ]);

            body[flags + 1..flags + 9].copy_from_slice(&value.to_be_bytes());
        }
        3 if body.len() > flags => body[flags] = *rng.choice(&[0, 1, 2, 0x80]),
        // A level record: its tree number or its status, found from the first record of the
        // original layout, which follows the top secrets and the public key.
        4 | 5 if body.len() > flags + 9 => {
            let at = rng.below(body.len() - flags - 9) + flags + 9;

            if rng.below(2) == 0 {
                body[at] = *rng.choice(&[0, 1, 2, 0xFF]);
            } else if at + 8 <= body.len() {
                let value = *rng.choice(&[0u64, 1, 2, 31, 32, 33, 1 << 20, u64::MAX]);

                body[at..at + 8].copy_from_slice(&value.to_be_bytes());
            }
        }
        _ => body = mutate(rng, &body, &[]),
    }

    if rng.below(4) != 0 {
        sealed(&body)
    } else {
        [&body, &state[state.len() - 16..]].concat()
    }
}

fn hss_state(levels: &[(&str, &str)], seed: &[u8], index: u64) -> Vec<u8> {
    let store = MemoryStore::default();

    hazmat::generate_stateful_key_pair(
        HSS_LMS,
        seed,
        index,
        StatefulParameters::Levels(levels),
        store.clone(),
        &StatefulKeyGenOptions::default(),
    )
    .expect("key");

    store.state().expect("state")
}

fn xmss_state(algorithm: StatefulSignatureAlgorithm, name: &str, index: u64) -> Vec<u8> {
    let store = MemoryStore::default();

    let n = if name.ends_with("_192") { 24 } else { 32 };

    hazmat::generate_stateful_key_pair(
        algorithm,
        &pattern(3 * n, 0),
        index,
        StatefulParameters::Name(name),
        store.clone(),
        &StatefulKeyGenOptions::default(),
    )
    .expect("key");

    store.state().expect("state")
}

fn check_state(algorithm: StatefulSignatureAlgorithm, state: &[u8], original: &[u8], budget: u64) {
    let load =
        || algorithm.load_private_key(MemoryStore::holding(state), &StatefulLoadOptions::default());

    let expected = match expected_state(algorithm, state, original) {
        Err(code) => {
            assert_eq!(
                load().err(),
                Some(code),
                "{} loaded {}",
                algorithm.name(),
                hex(state)
            );

            return;
        }
        Ok(expected) => expected,
    };

    if expected.cost > budget {
        return;
    }

    let store = MemoryStore::holding(state);

    let loaded = algorithm.load_private_key(store.clone(), &StatefulLoadOptions::default());

    let mut key = match loaded {
        Ok(key) => key,
        Err(error) => {
            assert!(
                !expected.exact
                    && matches!(error, Error::InvalidPrivateKey | Error::SelfTestFailed),
                "{}: {error} for {}",
                algorithm.name(),
                hex(state)
            );

            return;
        }
    };

    assert_eq!(
        key.remaining_signatures(),
        expected.capacity - expected.index
    );

    if expected.index == expected.capacity {
        assert_eq!(key.sign(b"m").err(), Some(Error::KeyExhausted));

        return;
    }

    // A signature that the key releases verifies; a key whose trees changed may refuse to sign.
    match key.sign(b"m") {
        Ok(signature) => assert!(key.public_key().verify(&signature, b"m")),
        Err(error) => assert!(!expected.exact, "{error} for {}", hex(state)),
    }

    let reloaded = algorithm
        .load_private_key(store.clone(), &StatefulLoadOptions::default())
        .map(|key| key.remaining_signatures());

    if expected.exact {
        assert_eq!(reloaded, Ok(expected.capacity - expected.index - 1));
    }
}

#[test]
fn random_states() {
    let mut rng = Random(9);

    let seeds = vec![
        hss_state(
            &[("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1")],
            &pattern(40, 0),
            3,
        ),
        hss_state(
            &[
                ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"),
                ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"),
            ],
            &pattern(40, 0),
            3,
        ),
        xmss_state(XMSS, "XMSS-SHA2_10_256", 3),
        xmss_state(XMSS_MT, "XMSSMT-SHAKE256_20/4_192", 3),
    ];

    for _ in 0..400 * scale() {
        let original = rng.choice(&seeds).clone();

        let mut state = original.clone();

        for _ in 0..1 + rng.below(2) {
            state = if state.len() >= 18 {
                mutate_state(&mut rng, &state)
            } else {
                let length = rng.below(160);

                rng.bytes(length)
            };
        }

        // Mostly the algorithm the blob names, so that more blobs get past the kind check.
        let all = [HSS_LMS, XMSS, XMSS_MT];

        let named = state
            .get(1)
            .and_then(|&kind| all.get(usize::from(kind).wrapping_sub(1)));

        let algorithm = match named {
            Some(&named) if rng.below(4) != 0 => named,
            _ => *rng.choice(&all),
        };

        check_state(algorithm, &state, &original, 1 << 18);
    }
}

// The record that a long run of random_states found: the two-level seed with the bottom level's
// LM-OTS type changed from LMOTS_SHA256_N24_W1 to LMOTS_SHA256_N24_W2, sealed again. Every length
// stays exact, but the bottom tree built from the record is not the tree whose key the stored
// parent signature signs, so the load fails (SPEC 11.9 item 6).
#[test]
fn changed_lower_level_type() {
    let original = hss_state(
        &[
            ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"),
            ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"),
        ],
        &pattern(40, 0),
        3,
    );

    let mut body = original[..original.len() - 16].to_vec();

    // The low byte of level 1's LM-OTS type: after the version, the kind, L and level 0's types.
    body[18] = 6;

    let state = sealed(&body);

    assert_eq!(
        hex(&SHA_256.digest(&state)),
        "04ad4dcf0040b1fcabc39911c8c620ae738d9c661317a5c769d1bcab07f276a5"
    );

    let expected = expected_state(HSS_LMS, &state, &original).expect("format");

    assert!(!expected.exact);

    let loaded = HSS_LMS.load_private_key(
        MemoryStore::holding(&state),
        &StatefulLoadOptions::default(),
    );

    assert!(matches!(
        loaded.err(),
        Some(Error::InvalidPrivateKey | Error::SelfTestFailed)
    ));

    check_state(HSS_LMS, &state, &original, 1 << 18);
}

#[test]
fn claimed_state_sizes() {
    let state = hss_state(&[("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1")], &[0; 40], 0);

    let body = &state[..state.len() - 16];

    for count in [0, 2, 9, 0xFF] {
        let mut claimed = body.to_vec();

        claimed[2] = count;

        assert_eq!(
            HSS_LMS
                .load_private_key(
                    MemoryStore::holding(&sealed(&claimed)),
                    &StatefulLoadOptions::default()
                )
                .err(),
            Some(Error::InvalidPrivateKey)
        );

        if count != 2 {
            let padded = [
                &claimed[..3],
                &[0, 0, 0, 10, 0, 0, 0, 5].repeat(usize::from(count)),
                &claimed[11..],
            ]
            .concat();

            assert_eq!(
                HSS_LMS
                    .load_private_key(
                        MemoryStore::holding(&sealed(&padded)),
                        &StatefulLoadOptions::default()
                    )
                    .err(),
                Some(Error::InvalidPrivateKey)
            );
        }
    }

    let tall = [
        &b"\x02\x01\x03"[..],
        &[0, 0, 0, 14, 0, 0, 0, 5].repeat(3),
        &[0; 48],
    ]
    .concat();

    assert_eq!(
        HSS_LMS
            .load_private_key(
                MemoryStore::holding(&sealed(&tall)),
                &StatefulLoadOptions::default()
            )
            .err(),
        Some(Error::InvalidPrivateKey)
    );

    let next = flags_offset(body) + 1;

    for index in [33, u64::MAX] {
        let beyond = [&body[..next], &index.to_be_bytes()[..], &body[next + 8..]].concat();

        assert_eq!(
            HSS_LMS
                .load_private_key(
                    MemoryStore::holding(&sealed(&beyond)),
                    &StatefulLoadOptions::default()
                )
                .err(),
            Some(Error::InvalidPrivateKey)
        );
    }

    let state = xmss_state(XMSS_MT, "XMSSMT-SHA2_60/12_256", 0);

    for index in [(1u64 << 60) + 1, u64::MAX] {
        let beyond = [
            &state[..7],
            &index.to_be_bytes()[..],
            &state[15..state.len() - 16],
        ]
        .concat();

        assert_eq!(
            XMSS_MT
                .load_private_key(
                    MemoryStore::holding(&sealed(&beyond)),
                    &StatefulLoadOptions::default()
                )
                .err(),
            Some(Error::InvalidPrivateKey)
        );
    }

    for value in [Vec::new(), vec![1; 17], vec![0; 18]] {
        assert_eq!(
            XMSS_MT
                .load_private_key(
                    MemoryStore::holding(&value),
                    &StatefulLoadOptions::default()
                )
                .err(),
            Some(Error::InvalidPrivateKey)
        );
    }

    assert_eq!(
        XMSS_MT
            .load_private_key(MemoryStore::default(), &StatefulLoadOptions::default())
            .err(),
        Some(Error::InvalidPrivateKey)
    );
}

// A tree cache body closed by its tag (SPEC 11.10 item 2), under the key that the top secrets
// give; those of a hazmat key are its seed.
fn seal_cache(body: &[u8], seed: &[u8]) -> Vec<u8> {
    let key = HMAC_SHA_256
        .digest(b"crypto-pq tree cache v1", seed)
        .expect("key");

    [body, &HMAC_SHA_256.digest(&key, body).expect("tag")].concat()
}

// Where a field or a tree lies in a tree cache: its offset and size.
type Span = (usize, usize);

// A key's state and the tree cache it exported, with what a load of the state alone gives (the
// remaining signatures and the next signature), the most memory that a load with or without the
// cache held, and the layout of the cache.
struct CacheFixture {
    algorithm: StatefulSignatureAlgorithm,
    seed: Vec<u8>,
    state: Vec<u8>,
    cache: Vec<u8>,
    remaining: u64,
    signature: Vec<u8>,
    peak: usize,
    fields: Vec<Span>,
    trees: Vec<Span>,
}

fn cache_fixture(
    algorithm: StatefulSignatureAlgorithm,
    parameters: StatefulParameters,
    seed: Vec<u8>,
    index: u64,
) -> CacheFixture {
    let store = MemoryStore::default();

    let mut pair = hazmat::generate_stateful_key_pair(
        algorithm,
        &seed,
        index,
        parameters,
        store.clone(),
        &StatefulKeyGenOptions::default(),
    )
    .expect("key");

    pair.private_key.sign(b"first").expect("signature");

    let cache = pair.private_key.export_tree_cache().expect("cache");

    let state = store.state().expect("state");

    let mut loaded = None;

    let plain = peak_allocation(|| {
        loaded = Some(algorithm.load_private_key(
            MemoryStore::holding(&state),
            &StatefulLoadOptions::default(),
        ));
    });

    let mut key = loaded.expect("load").expect("key");

    let cached = peak_allocation(|| {
        let options = StatefulLoadOptions::default().with_tree_cache(&cache);

        drop(algorithm.load_private_key(MemoryStore::holding(&state), &options));
    });

    let (fields, trees) = cache_layout(&cache);

    CacheFixture {
        algorithm,
        seed,
        remaining: key.remaining_signatures(),
        signature: key.sign(b"m").expect("signature"),
        state,
        cache,
        peak: plain.max(cached),
        fields,
        trees,
    }
}

// The fields of a valid tree cache as (offset, size): version, kind, the parameters, the public key
// length, the tree count and the six header fields of each tree; and the span of each tree.
fn cache_layout(cache: &[u8]) -> (Vec<Span>, Vec<Span>) {
    let end = flags_offset(cache);

    let mut fields = vec![(0, 1), (1, 1)];

    if cache[1] == 1 {
        fields.push((2, 1));

        fields.extend((3..end).step_by(4).map(|at| (at, 4)));
    } else {
        fields.push((2, 4));
    }

    let size = read_u32(cache, end) as usize;

    let count = end + 4 + size;

    fields.extend([(end, 4), (count, 1)]);

    let mut trees = Vec::new();

    let mut at = count + 1;

    for _ in 0..cache[count] {
        fields.extend([
            (at, 1),
            (at + 1, 8),
            (at + 9, 1),
            (at + 10, 1),
            (at + 11, 1),
            (at + 12, 4),
        ]);

        let length = 16 + usize::from(cache[at + 11]) * read_u32(cache, at + 12) as usize;

        trees.push((at, length));

        at += length;
    }

    assert_eq!(at + 32, cache.len());

    (fields, trees)
}

// A value for a field of `size` bytes: zero, one, one more or less than it holds, the largest, the
// top bit alone, or random.
fn field_value(rng: &mut Random, size: usize, current: u64) -> u64 {
    let bits = 8 * size as u32;

    let mask = u64::MAX >> (64 - bits);

    let value = match rng.below(7) {
        0 => 0,
        1 => 1,
        2 => current.wrapping_add(1),
        3 => current.wrapping_sub(1),
        4 => mask,
        5 => 1 << (bits - 1),
        _ => rng.next(),
    };

    value & mask
}

// Random edits of a tree cache body: its fields, whole trees dropped, repeated or swapped, the end
// cut or extended, and byte edits.
fn mutate_cache(rng: &mut Random, fixture: &CacheFixture, others: &[Vec<u8>]) -> Vec<u8> {
    let mut body = fixture.cache[..fixture.cache.len() - 32].to_vec();

    for _ in 0..1 + rng.below(2) {
        match rng.below(8) {
            0..=3 => {
                let &(at, size) = rng.choice(&fixture.fields);

                if at + size <= body.len() {
                    let current = body[at..at + size]
                        .iter()
                        .fold(0, |value, &byte| value << 8 | u64::from(byte));

                    let value = field_value(rng, size, current);

                    body[at..at + size].copy_from_slice(&value.to_be_bytes()[8 - size..]);
                }
            }
            4 => {
                let &(at, length) = rng.choice(&fixture.trees);

                if at + length <= body.len() {
                    let tree = body[at..at + length].to_vec();

                    match rng.below(3) {
                        0 => drop(body.drain(at..at + length)),
                        1 => drop(body.splice(at..at, tree)),
                        _ => {
                            let &(other, size) = rng.choice(&fixture.trees);

                            if other + size <= body.len() && other > at {
                                let second = body[other..other + size].to_vec();

                                body.splice(other..other + size, tree);

                                body.splice(at..at + length, second);
                            }
                        }
                    }
                }
            }
            5 => {
                if rng.below(2) == 0 {
                    let length = rng.below(body.len() + 1);

                    body.truncate(length);
                } else {
                    let length = 1 + rng.below(48);

                    body.extend(rng.bytes(length));
                }
            }
            _ => body = mutate(rng, &body, others),
        }
    }

    if rng.below(4) == 0 {
        [&body[..], &fixture.cache[fixture.cache.len() - 32..]].concat()
    } else {
        seal_cache(&body, &fixture.seed)
    }
}

// SPEC 11.10 items 3 and 4: a cache is refused with INVALID_ENCODING or ALGORITHM_MISMATCH, or the
// key loads and signs as one that built its trees. Neither allocates what a field claims. Returns
// the refusal.
fn check_cache(fixture: &CacheFixture, cache: &[u8]) -> Option<Error> {
    let name = fixture.algorithm.name();

    let options = StatefulLoadOptions::default().with_tree_cache(cache);

    let mut loaded = None;

    let peak = peak_allocation(|| {
        loaded = Some(
            fixture
                .algorithm
                .load_private_key(MemoryStore::holding(&fixture.state), &options),
        );
    });

    assert!(
        peak <= fixture.peak + 2 * cache.len() + (64 << 10),
        "{name}: {peak} bytes for {}",
        hex(cache)
    );

    match loaded.expect("load") {
        Ok(mut key) => {
            assert_eq!(key.remaining_signatures(), fixture.remaining, "{name}");

            assert_eq!(
                key.sign(b"m").as_ref(),
                Ok(&fixture.signature),
                "{name}: {}",
                hex(cache)
            );

            None
        }
        Err(error) => {
            assert!(
                matches!(error, Error::InvalidEncoding | Error::AlgorithmMismatch),
                "{name}: {error} for {}",
                hex(cache)
            );

            Some(error)
        }
    }
}

// Random and mutated tree caches, most sealed again with the tag key of the state so that they
// reach the checks behind the tag, and the caches of the other keys as they were exported.
#[test]
fn random_tree_caches() {
    let mut rng = Random(11);

    let fixtures = [
        cache_fixture(
            HSS_LMS,
            StatefulParameters::Levels(&[
                ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"),
                ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"),
            ]),
            pattern(40, 0),
            3,
        ),
        cache_fixture(
            HSS_LMS,
            StatefulParameters::Levels(&[("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W2")]),
            pattern(40, 1),
            30,
        ),
        cache_fixture(
            XMSS,
            StatefulParameters::Name("XMSS-SHA2_10_256"),
            pattern(96, 0),
            3,
        ),
        cache_fixture(
            XMSS_MT,
            StatefulParameters::Name("XMSSMT-SHAKE256_20/4_192"),
            pattern(72, 0),
            0x12345,
        ),
    ];

    let caches: Vec<Vec<u8>> = fixtures
        .iter()
        .map(|fixture| fixture.cache.clone())
        .collect();

    for fixture in &fixtures {
        assert_eq!(check_cache(fixture, &fixture.cache), None);

        assert_eq!(check_cache(fixture, &[]), None);
    }

    let mut outcomes = Vec::new();

    for _ in 0..300 * scale() {
        let fixture = rng.choice(&fixtures);

        let cache = match rng.below(16) {
            0 => {
                let length = rng.below(200);

                rng.bytes(length)
            }
            1 => rng.choice(&caches).clone(),
            _ => mutate_cache(&mut rng, fixture, &caches),
        };

        outcomes.push(check_cache(fixture, &cache));
    }

    // The edits reach every outcome: loads, and both refusals.
    for outcome in [
        None,
        Some(Error::InvalidEncoding),
        Some(Error::AlgorithmMismatch),
    ] {
        assert!(outcomes.contains(&outcome), "{outcome:?}");
    }
}

// The message whose byte i is i mod 251, and its digests from an independent implementation.
fn large_message() -> Vec<u8> {
    (0..16 << 20).map(|i: u32| (i % 251) as u8).collect()
}

const DIGESTS: [&str; 10] = [
    "81e763ef9866bdefa03f5c58819e12ba2bc7dd6913eb36e8ec666036",
    "287507f403176f1f5b22b9a4d9cb49f7d7f88ac19e406b5ae87ce109564846bd",
    "4bc9798cec40d12e4f7198b89e0a5d4b7e7474ec255f3280b126bd3bc141103ca9a906d12fa05c0c5eb50f2bef840908",
    "ef9941360046598bd9a89eb56a4440e46255bfa79529f9d3a8813aa899d5c64d8cc75f0c023b8d82ec41cc60ae69d311a80fb9ad372bf3d149574a87bc195c08",
    "181650285d94081ca60b6dad6cb501607c0b47b793d95f4b3fe703ef",
    "61fb65258a2a6ca095a709e2d1026483ef0d5dab44e374f55599d867e0d5d2f9",
    "3e121e54d1b7d67d8a6489426c33d7a5078089e9f7ff736786fc2cf3",
    "acade24d564f1dae78e26ca4615bc8061dda3835de1bb7afde3ef0d32a931191",
    "4934100bb50d9a97d1463c521a58ca562a59e07b6753076e45a824d8545df2358c346274ad7809ffeaac2e56a9cef7fb",
    "314cd6d2e1cc05dfc4c8429541a2877becd82e9def2333f26a4eb7f72cffe758289f9185ddae4bb5017ad7019933404f241787ac650e505530f2973d3233a88d",
];

#[test]
fn large_hashes() {
    let message = large_message();

    for (algorithm, expected) in HASHES.iter().zip(DIGESTS) {
        assert_eq!(
            hex(&algorithm.digest(&message)),
            expected,
            "{}",
            algorithm.name()
        );

        let mut hasher = algorithm.create();

        for chunk in message.chunks(1_000_003) {
            hasher.update(chunk);
        }

        assert_eq!(hex(&hasher.digest()), expected);
    }

    let xofs: [(XofAlgorithm, &str); 2] = [
        (
            SHAKE128,
            "8a38dce3e6592d50867536f5f352abd74e486bdbfe48c43b8372d55e6547110a",
        ),
        (
            SHAKE256,
            "525fa10737fa7538afe5df929cfadb606e52a2b2e2f0e4c5626510e720319b7366c387167707535aa23a5d027a155150fe5c73c329f2113d1220a8d9d7b9a5e3",
        ),
    ];

    for (algorithm, expected) in xofs {
        assert_eq!(
            hex(&algorithm.digest(&message, expected.len() / 2).unwrap()),
            expected
        );
    }

    let tag = HMAC_SHA_256.digest(&pattern(32, 0), &message).unwrap();

    assert_eq!(
        hex(&tag),
        "e9fb7e5b1f5d2702eba341df5e51ec9e4ed48db395f66dff93e30808b88f0750"
    );
}

#[test]
fn large_and_empty_messages() {
    let message = large_message();

    let mut changed = message.clone();

    *changed.last_mut().expect("message") ^= 1;

    for algorithm in [ML_DSA_44, SLH_DSA_SHA2_128F, SLH_DSA_SHAKE_128F] {
        let (seed, _, _) = signature_sizes(algorithm);

        let private_key: SignaturePrivateKey =
            hazmat::generate_signature_key_pair(algorithm, &pattern(seed, 0))
                .expect("key")
                .private_key;

        let public_key = private_key.public_key();

        let range_context: Vec<u8> = (0..255).collect();

        let cases: [(&[u8], &[u8], Option<PreHash>); 4] = [
            (&message, b"", None),
            (b"", &[0; 255], None),
            (&message, &range_context, Some(SHA_512.into())),
            (b"", b"", Some(SHAKE256.into())),
        ];

        for (text, context, pre_hash) in cases {
            let mut options = SignOptions::default()
                .with_context(context)
                .with_deterministic(true);

            options.pre_hash = pre_hash;

            let signature = private_key.sign(text, &options).expect("signature");

            let mut verify = VerifyOptions::default().with_context(context);

            verify.pre_hash = pre_hash;

            assert!(public_key.verify(&signature, text, &verify));

            assert!(!public_key.verify(
                &signature,
                if text.is_empty() { b"\x00" } else { &changed },
                &verify
            ));

            let longer = [context, b"\x00"].concat();

            verify.context = &longer;

            assert!(!public_key.verify(&signature, text, &verify));
        }

        let long = SignOptions::default().with_context(&[0; 256]);

        assert_eq!(
            private_key.sign(b"", &long).err(),
            Some(Error::InvalidContext)
        );
    }

    let mut hss = HSS_LMS
        .generate_key_pair(
            StatefulParameters::Levels(&[("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1")]),
            MemoryStore::default(),
            &StatefulKeyGenOptions::default(),
        )
        .expect("key");

    let mut mt = XMSS_MT
        .generate_key_pair(
            StatefulParameters::Name("XMSSMT-SHA2_20/4_192"),
            MemoryStore::default(),
            &StatefulKeyGenOptions::default(),
        )
        .expect("key");

    for text in [&message[..], b""] {
        let other: &[u8] = if text.is_empty() { b"\x00" } else { &changed };

        let signature = hss.private_key.sign(text).expect("signature");

        assert!(
            hss.public_key.verify(&signature, text) && !hss.public_key.verify(&signature, other)
        );

        let signature = mt.private_key.sign(text).expect("signature");

        assert!(mt.public_key.verify(&signature, text) && !mt.public_key.verify(&signature, other));
    }
}

fn base64(data: &[u8]) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = Vec::new();

    for chunk in data.chunks(3) {
        let value = chunk.iter().enumerate().fold(0u32, |value, (i, &byte)| {
            value | u32::from(byte) << (16 - 8 * i)
        });

        for i in 0..4 {
            out.push(if i <= chunk.len() {
                alphabet[(value >> (18 - 6 * i)) as usize & 0x3F]
            } else {
                b'='
            });
        }
    }

    out
}

#[test]
fn pem_layouts() {
    // The header and the footer share their dashes, leaving no body between them.
    let overlap = b"-----BEGIN PUBLIC KEY-----END PUBLIC KEY-----";

    assert_eq!(
        ML_KEM_768.import_public_key(overlap, KeyFormat::Pem).err(),
        Some(Error::InvalidEncoding)
    );

    assert_eq!(
        ML_DSA_44
            .import_private_key(
                b"-----BEGIN PRIVATE KEY-----END PRIVATE KEY-----",
                KeyFormat::Pem
            )
            .err(),
        Some(Error::InvalidEncoding)
    );

    // The last base64 quantum of an ML-DSA-44 key carries two unused bits, which must be zero.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let dsa = hazmat::generate_signature_key_pair(ML_DSA_44, &pattern(32, 0)).expect("key");

    let mut pem = dsa.public_key.export_key(KeyFormat::Pem).expect("export");

    let last = pem.iter().rposition(|&byte| byte == b'=').expect("padding") - 1;

    pem[last] = alphabet[alphabet
        .iter()
        .position(|&c| c == pem[last])
        .expect("base64")
        ^ 1];

    assert_eq!(
        ML_DSA_44.import_public_key(&pem, KeyFormat::Pem).err(),
        Some(Error::InvalidEncoding)
    );

    let pair = hazmat::generate_kem_key_pair(ML_KEM_768, &pattern(64, 0)).expect("key");

    let body = base64(&pair.public_key.export_key(KeyFormat::Der).expect("export"));

    let narrow: Vec<u8> = [
        &b"-----BEGIN PUBLIC KEY-----\n"[..],
        &body.chunks(1).collect::<Vec<_>>().join(&b'\n'),
        b"\n-----END PUBLIC KEY-----\n",
    ]
    .concat();

    assert_eq!(
        ML_KEM_768
            .import_public_key(&narrow, KeyFormat::Pem)
            .expect("narrow"),
        pair.public_key
    );

    // SPEC D-67: a body on a boundary line is text on that line.
    let wide = [
        &b"-----BEGIN PUBLIC KEY-----"[..],
        &body,
        b"-----END PUBLIC KEY-----",
    ]
    .concat();

    assert_eq!(
        ML_KEM_768.import_public_key(&wide, KeyFormat::Pem).err(),
        Some(Error::InvalidEncoding)
    );

    let huge = base64(&[&[0x30, 0x84, 0x00, 0xFF, 0xFF, 0xFF][..], &vec![0; 4 << 20]].concat());

    for text in [&huge[..], &huge[..huge.len() - 1]] {
        let pem = [
            &b"-----BEGIN PUBLIC KEY-----\n"[..],
            text,
            b"\n-----END PUBLIC KEY-----\n",
        ]
        .concat();

        assert_eq!(
            ML_KEM_768.import_public_key(&pem, KeyFormat::Pem).err(),
            Some(Error::InvalidEncoding)
        );
    }
}

// A length field that claims gigabytes is refused before anything that large is allocated; one
// with a needless leading zero byte, and a PKCS#8 version above 1, are refused too.
#[test]
fn claimed_der_lengths() {
    let pair = hazmat::generate_signature_key_pair(ML_DSA_65, &pattern(32, 0)).expect("key");

    let public = pair.public_key.export_key(KeyFormat::Der).expect("export");

    let private = pair.private_key.export_key(KeyFormat::Der).expect("export");

    let cases = [
        [&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF][..], &public[4..]].concat(),
        [&[0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF][..], &public[4..]].concat(),
        [
            &public[..4],
            &[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xF0],
            &public[6..],
        ]
        .concat(),
        [
            &public[..17],
            &[0x03, 0x84, 0xFF, 0xFF, 0xFF, 0xFF],
            &public[21..],
        ]
        .concat(),
        [&private[..4], &[2], &private[5..]].concat(),
        [&private[..2], &[0x02, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]].concat(),
        [
            &private[..20],
            &[0x04, 0x84, 0x40, 0x00, 0x00, 0x00],
            &private[22..],
        ]
        .concat(),
        [
            &[0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00][..],
            &public[4..],
        ]
        .concat(),
        [&[0x30, 0x80][..], &public[4..], &[0, 0]].concat(),
        [&[0x30, 0x83, 0x00, 0x07, 0xB2][..], &public[4..]].concat(),
        [
            &[0x30, 0x82, 0x07, 0xB3][..],
            &public[4..17],
            &[0x03, 0x83, 0x00, 0x07, 0xA1],
            &public[21..],
        ]
        .concat(),
    ];

    for data in &cases {
        let peak = peak_allocation(|| {
            assert_eq!(
                ML_DSA_65.import_public_key(data, KeyFormat::Der).err(),
                Some(Error::InvalidEncoding)
            );

            assert_eq!(
                ML_DSA_65.import_private_key(data, KeyFormat::Der).err(),
                Some(Error::InvalidEncoding)
            );

            let pem = [
                &b"-----BEGIN PUBLIC KEY-----\n"[..],
                &base64(data),
                b"\n-----END PUBLIC KEY-----\n",
            ]
            .concat();

            assert_eq!(
                ML_DSA_65.import_public_key(&pem, KeyFormat::Pem).err(),
                Some(Error::InvalidEncoding)
            );
        });

        assert!(peak < 64 << 10, "{peak} bytes for {}", hex(&data[..8]));
    }
}

const LEVELS: [(&str, &str); 1] = [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1")];

fn signature_index(signature: &[u8]) -> u32 {
    read_u32(signature, 4)
}

// One key shared by many threads through a mutex: every index is used once.
#[test]
fn concurrent_shared_key() {
    let store = MemoryStore::default();

    let pair = HSS_LMS
        .generate_key_pair(
            StatefulParameters::Levels(&LEVELS),
            store.clone(),
            &StatefulKeyGenOptions::default(),
        )
        .expect("key");

    let key = Arc::new(Mutex::new(pair.private_key));

    let results: Vec<Result<Vec<u8>, Error>> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..40)
            .map(|i: u8| {
                let key = Arc::clone(&key);

                scope.spawn(move || key.lock().expect("lock").sign(&[i]))
            })
            .collect();

        workers
            .into_iter()
            .map(|worker| worker.join().expect("thread"))
            .collect()
    });

    let mut indices: Vec<u32> = results
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .map(|signature| signature_index(signature))
        .collect();

    indices.sort_unstable();

    assert_eq!(indices, (0..32).collect::<Vec<_>>());

    assert!(
        results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .all(|&error| error == Error::KeyExhausted)
    );

    assert_eq!(
        HSS_LMS
            .load_private_key(store, &StatefulLoadOptions::default())
            .expect("key")
            .remaining_signatures(),
        0
    );
}

// Keys loaded from one store in different threads: the compare-and-swap lets one of them use
// each index; the others get StateConflict and reload.
#[test]
fn concurrent_keys_sharing_a_store() {
    let store = MemoryStore::default();

    HSS_LMS
        .generate_key_pair(
            StatefulParameters::Levels(&LEVELS),
            store.clone(),
            &StatefulKeyGenOptions::default(),
        )
        .expect("key");

    let barrier = Barrier::new(6);

    let results: Vec<Vec<Result<Vec<u8>, Error>>> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..6)
            .map(|_| {
                let store = store.clone();

                let barrier = &barrier;

                scope.spawn(move || {
                    let mut key = HSS_LMS
                        .load_private_key(store.clone(), &StatefulLoadOptions::default())
                        .expect("key");

                    barrier.wait();

                    (0..8)
                        .map(|_| {
                            let result = key.sign(b"m");

                            if result.as_ref().err() == Some(&Error::StateConflict) {
                                key = HSS_LMS
                                    .load_private_key(
                                        store.clone(),
                                        &StatefulLoadOptions::default(),
                                    )
                                    .expect("key");
                            }

                            result
                        })
                        .collect()
                })
            })
            .collect();

        workers
            .into_iter()
            .map(|worker| worker.join().expect("thread"))
            .collect()
    });

    let results: Vec<&Result<Vec<u8>, Error>> = results.iter().flatten().collect();

    let mut indices: Vec<u32> = results
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .map(|signature| signature_index(signature))
        .collect();

    indices.sort_unstable();

    assert_eq!(indices, (0..indices.len() as u32).collect::<Vec<_>>());

    assert!(
        results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .all(|&error| error == Error::StateConflict || error == Error::KeyExhausted)
    );

    assert_eq!(
        HSS_LMS
            .load_private_key(store, &StatefulLoadOptions::default())
            .expect("key")
            .remaining_signatures(),
        32 - indices.len() as u64
    );
}

// These rounds run on inputs made by a fixed generator from byte-identical keys and hash each
// input with its outcome: an error code, true or false, or OK and the result. The digests are
// fixed, so every build and platform, and every port that runs the same rounds, must accept,
// refuse and compute alike on untrusted input.
const TRANSCRIPT_ROUNDS: usize = 96;

const TRANSCRIPT_BUDGET: u64 = 1 << 14;

// Each case is known by its number, which also seeds its generator. Cases 0, 1, 3 and 5 follow the
// import rules of SPEC 1.0 (the text around a PEM block, the OID before the rest of the DER, the
// ML-KEM secret-vector check and pairwise test); case 10 edits state records of version 2 (SPEC
// 11.7) and loads them by the rules of SPEC 11.9.
const TRANSCRIPT_CASES: [u64; 10] = [0, 1, 3, 4, 5, 6, 7, 8, 9, 10];

const TRANSCRIPTS: [&str; 10] = [
    "ed99902d3b962fb9924d9607f9b14de5865d906cd1e005bd84b548c9b35dd398",
    "8f4fc6ce6187f007b6a52ae1709492f85558a06b89df5368b4f2bedca8b2266e",
    "439c5953c821ec35d4f8c6dee1acc2f1b63b724e911d0ce69765cf6f171069fc",
    "14d657260a5c207db5e73e9dbaac6d3458b0ba16e507f256bea8fac9fd0f2a0a",
    "083bba1bf00d26e73459e61b0ad4ea59a28a0e7eacd1b4826c85a315bfcc0c4e",
    "38a35f3547d4414788484ce0b4b836a27f72fba19931a9f3680cbcadd6d5d97a",
    "7b468ce2966d2edd458ed4a62183bf6d4c06e182509a7773c505a3cb2ae12e58",
    "b2ecff951172fdfdd464c3b4bed07055c3041b64d0c11dc6c9bc62eae7cc0b0e",
    "57986f97a5d291a67f8a875f558d59a535f2157155e13b83b364a6a1cca5dc7d",
    "70ec2aea4f3cd771ebbbb9ca2af7aa26d9211ec5f1ea82a0ff87232324750d65",
];

struct Transcript(crypto_pq::Hasher);

impl Transcript {
    fn new() -> Self {
        Self(SHA_256.create())
    }

    fn add(&mut self, data: &[u8], selector: u8, code: &str, output: &[u8]) {
        for part in [data, &[selector], code.as_bytes(), output] {
            self.0.update(&(part.len() as u32).to_be_bytes());

            self.0.update(part);
        }
    }

    fn hex(&self) -> String {
        hex(&self.0.digest())
    }
}

fn outcome<T>(result: Result<T, Error>) -> (&'static str, Option<T>) {
    match result {
        Ok(value) => ("OK", Some(value)),
        Err(error) => (error.code(), None),
    }
}

// Random bytes, or the seed with up to three edits, so that some inputs stay valid.
fn edited(rng: &mut Random, seed: &[u8], others: &[Vec<u8>]) -> Vec<u8> {
    if rng.below(8) == 0 {
        let size = rng.below(96);

        return rng.bytes(size);
    }

    let mut data = seed.to_vec();

    for _ in 0..rng.below(4) {
        data = mutate(rng, &data, others);
    }

    data
}

fn resized(rng: &mut Random, mut data: Vec<u8>, size: usize) -> Vec<u8> {
    if rng.below(2) == 1 {
        data.resize(size, 0);
    }

    data
}

type Import<'a> = &'a dyn Fn(&[u8], KeyFormat) -> Result<Vec<u8>, Error>;

fn import_case(
    rng: &mut Random,
    transcript: &mut Transcript,
    seeds: &[(Vec<u8>, usize, usize)],
    imports: &[Import],
) {
    let others: Vec<Vec<u8>> = seeds
        .iter()
        .map(|(encoding, _, _)| encoding.clone())
        .collect();

    for _ in 0..TRANSCRIPT_ROUNDS {
        let (encoding, function, mut format) = seeds[rng.below(seeds.len())].clone();

        let data = edited(rng, &encoding, &others);

        if rng.below(4) == 0 {
            format = rng.below(3);
        }

        let (code, raw) = outcome(imports[function](&data, FORMATS[format]));

        transcript.add(
            &data,
            (3 * function + format) as u8,
            code,
            &raw.unwrap_or_default(),
        );
    }
}

fn signature_case(
    rng: &mut Random,
    transcript: &mut Transcript,
    signature: &[u8],
    verify: &dyn Fn(&[u8], &[u8]) -> bool,
) {
    for _ in 0..TRANSCRIPT_ROUNDS {
        let data = edited(rng, signature, &[signature.to_vec()]);

        let data = resized(rng, data, signature.len());

        let context: &[u8] = if rng.below(2) == 0 { b"context" } else { b"" };

        transcript.add(
            &data,
            context.len() as u8,
            if verify(&data, context) {
                "true"
            } else {
                "false"
            },
            &[],
        );
    }
}

fn exports(
    encode: impl Fn(KeyFormat) -> Result<Vec<u8>, Error>,
    function: usize,
) -> Vec<(Vec<u8>, usize, usize)> {
    FORMATS
        .iter()
        .enumerate()
        .map(|(number, &format)| (encode(format).expect("export"), function, number))
        .collect()
}

#[test]
fn transcripts() {
    let message = b"crypto-pq transcript";

    let kem = hazmat::generate_kem_key_pair(ML_KEM_768, &pattern(64, 0)).expect("key");

    let encapsulation =
        hazmat::encapsulate(&kem.public_key, &pattern(32, 0x80)).expect("encapsulation");

    let dsa = hazmat::generate_signature_key_pair(ML_DSA_44, &pattern(32, 0)).expect("key");

    let options = SignOptions::default().with_context(b"context");

    let signature =
        hazmat::sign(&dsa.private_key, message, &pattern(32, 0x60), &options).expect("signature");

    let slh = hazmat::generate_signature_key_pair(SLH_DSA_SHA2_128F, &pattern(48, 0)).expect("key");

    let levels = [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"); 2];

    let mut hss = hazmat::generate_stateful_key_pair(
        HSS_LMS,
        &pattern(40, 0),
        33,
        StatefulParameters::Levels(&levels),
        MemoryStore::default(),
        &StatefulKeyGenOptions::default(),
    )
    .expect("key");

    let hss_signature = hss.private_key.sign(message).expect("signature");

    let state = hss_state(&levels[..1], &pattern(40, 0), 3);

    let raw = KeyFormat::Raw;

    let kem_public = |data: &[u8], format| {
        ML_KEM_768
            .import_public_key(data, format)
            .map(|key| key.export_key(raw).expect("export"))
    };

    let kem_private = |data: &[u8], format| {
        ML_KEM_768
            .import_private_key(data, format)
            .map(|key| key.export_key(raw).expect("export").to_vec())
    };

    let dsa_public = |data: &[u8], format| {
        ML_DSA_44
            .import_public_key(data, format)
            .map(|key| key.export_key(raw).expect("export"))
    };

    let dsa_private = |data: &[u8], format| {
        ML_DSA_44
            .import_private_key(data, format)
            .map(|key| key.export_key(raw).expect("export").to_vec())
    };

    let slh_public = |data: &[u8], format| {
        SLH_DSA_SHA2_128F
            .import_public_key(data, format)
            .map(|key| key.export_key(raw).expect("export"))
    };

    let slh_private = |data: &[u8], format| {
        SLH_DSA_SHA2_128F
            .import_private_key(data, format)
            .map(|key| key.export_key(raw).expect("export").to_vec())
    };

    let stateful = [HSS_LMS, XMSS, XMSS_MT];

    let stateful_imports: Vec<_> = stateful
        .iter()
        .map(|&algorithm| {
            move |data: &[u8], format| {
                algorithm
                    .import_public_key(data, format)
                    .map(|key| key.export_key(raw).expect("export"))
            }
        })
        .collect();

    let xmss_public = [&[0, 0, 0, 1][..], &pattern(64, 0)].concat();

    let xmss_mt_public = [&[0, 0, 0, 0x31][..], &pattern(48, 0)].concat();

    let xmss_mt_der = XMSS_MT
        .import_public_key(&xmss_mt_public, raw)
        .expect("key")
        .export_key(KeyFormat::Der)
        .expect("export");

    let mut stateful_seeds = exports(|format| hss.public_key.export_key(format), 0);

    stateful_seeds.extend([
        (xmss_public, 1, 0),
        (xmss_mt_public, 2, 0),
        (xmss_mt_der, 2, 1),
    ]);

    let mut slh_seeds = exports(|format| slh.public_key.export_key(format), 0);

    slh_seeds.extend(exports(
        |format| slh.private_key.export_key(format).map(|key| key.to_vec()),
        1,
    ));

    let digests: Vec<String> = TRANSCRIPT_CASES
        .iter()
        .map(|&case| {
            let mut rng = Random(101 + case);

            let mut transcript = Transcript::new();

            let t = &mut transcript;

            match case {
                0 => import_case(
                    &mut rng,
                    t,
                    &exports(|format| kem.public_key.export_key(format), 0),
                    &[&kem_public],
                ),
                1 => import_case(
                    &mut rng,
                    t,
                    &exports(
                        |format| kem.private_key.export_key(format).map(|key| key.to_vec()),
                        0,
                    ),
                    &[&kem_private],
                ),
                3 => import_case(
                    &mut rng,
                    t,
                    &exports(|format| dsa.public_key.export_key(format), 0),
                    &[&dsa_public],
                ),
                4 => import_case(
                    &mut rng,
                    t,
                    &exports(
                        |format| dsa.private_key.export_key(format).map(|key| key.to_vec()),
                        0,
                    ),
                    &[&dsa_private],
                ),
                5 => import_case(&mut rng, t, &slh_seeds, &[&slh_public, &slh_private]),
                6 => import_case(
                    &mut rng,
                    t,
                    &stateful_seeds,
                    &[
                        &stateful_imports[0],
                        &stateful_imports[1],
                        &stateful_imports[2],
                    ],
                ),
                7 => signature_case(&mut rng, t, &signature, &|data, context| {
                    dsa.public_key.verify(
                        data,
                        message,
                        &VerifyOptions::default().with_context(context),
                    )
                }),
                8 => {
                    let ciphertext = &encapsulation.ciphertext;

                    for _ in 0..TRANSCRIPT_ROUNDS {
                        let data = edited(&mut rng, ciphertext, std::slice::from_ref(ciphertext));

                        let data = resized(&mut rng, data, ciphertext.len());

                        let (code, secret) = outcome(
                            kem.private_key
                                .decapsulate(&data)
                                .map(|secret| secret.to_vec()),
                        );

                        t.add(&data, 0, code, &secret.unwrap_or_default());
                    }
                }
                9 => signature_case(&mut rng, t, &hss_signature, &|data, context| {
                    hss.public_key
                        .verify(data, &[&message[..], context].concat())
                }),
                _ => state_case(&mut rng, t, &state),
            }

            transcript.hex()
        })
        .collect();

    assert_eq!(digests, TRANSCRIPTS);
}

// Loading builds the key's trees, so a valid state of a key larger than the budget is only
// recorded as skipped.
fn state_case(rng: &mut Random, transcript: &mut Transcript, base: &[u8]) {
    let stateful = [HSS_LMS, XMSS, XMSS_MT];

    for _ in 0..TRANSCRIPT_ROUNDS {
        let mut state = base.to_vec();

        for _ in 0..1 + rng.below(2) {
            state = if state.len() >= 18 {
                mutate_state(rng, &state)
            } else {
                let length = rng.below(160);

                rng.bytes(length)
            };
        }

        let named = state
            .get(1)
            .map(|&kind| usize::from(kind))
            .filter(|kind| (1..=3).contains(kind));

        let choice = match named {
            Some(kind) if rng.below(4) != 0 => kind - 1,
            _ => rng.below(3),
        };

        let algorithm = stateful[choice];

        if expected_state(algorithm, &state, base).is_ok_and(|e| e.cost > TRANSCRIPT_BUDGET) {
            transcript.add(&state, choice as u8, "SKIP", &[]);

            continue;
        }

        let (code, key) = outcome(algorithm.load_private_key(
            MemoryStore::holding(&state),
            &StatefulLoadOptions::default(),
        ));

        let output = key.map_or_else(Vec::new, |key| {
            [
                key.public_key().export_key(KeyFormat::Raw).expect("export"),
                key.remaining_signatures().to_be_bytes().to_vec(),
            ]
            .concat()
        });

        transcript.add(&state, choice as u8, code, &output);
    }
}

// Structures that random edits rarely build: an HSS signature cut inside a field or inside a
// signed child key, counts and leaf indices beyond their range, and hint sections that claim more
// than omega hints, repeat an index or leave padding. Verification refuses every one.
#[test]
fn edge_structures() {
    let message = b"crypto-pq edge";

    let levels = [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"); 2];

    let mut pair = hazmat::generate_stateful_key_pair(
        HSS_LMS,
        &pattern(40, 0),
        33,
        StatefulParameters::Levels(&levels),
        MemoryStore::default(),
        &StatefulKeyGenOptions::default(),
    )
    .expect("key");

    let signature = pair.private_key.sign(message).expect("signature");

    // Nspk, then the first LMS signature (4956 bytes), the signed child key (48) and the second.
    let end = 4 + 4956;

    for length in [0, 1, 3, 4, 5, 8, 12, signature.len() - 1]
        .into_iter()
        .chain(end - 1..end + 50)
    {
        assert!(
            !pair.public_key.verify(&signature[..length], message),
            "{length} bytes"
        );
    }

    assert!(pair.public_key.verify(&signature, message));

    assert!(
        !pair
            .public_key
            .verify(&[&signature[..], &[0]].concat(), message)
    );

    for (offset, value) in [
        (0, 0),
        (0, 2),
        (0, 0x7FFF_FFFF),
        (0, u32::MAX),
        (4, 32),
        (4, u32::MAX),
        (end + 48, 32),
        (end + 48, u32::MAX),
    ] {
        let mut edited = signature.clone();

        edited[offset..offset + 4].copy_from_slice(&value.to_be_bytes());

        assert!(
            !pair.public_key.verify(&edited, message),
            "{value} at {offset}"
        );
    }

    // Level counts outside 1 to 8 make a malformed public key.
    let public = pair.public_key.export_key(KeyFormat::Raw).expect("export");

    for count in [0u32, 9, u32::MAX] {
        let raw = [&count.to_be_bytes()[..], &public[4..]].concat();

        assert_eq!(
            HSS_LMS.import_public_key(&raw, KeyFormat::Raw).err(),
            Some(Error::InvalidPublicKey)
        );
    }

    let dsa = hazmat::generate_signature_key_pair(ML_DSA_44, &pattern(32, 0)).expect("key");

    let valid = hazmat::sign(&dsa.private_key, message, &[0; 32], &SignOptions::default())
        .expect("signature");

    // ML-DSA-44: omega = 80 hint positions, then k = 4 cumulative counts.
    for counts in [
        [81, 82, 83, 84],
        [200, 201, 202, 203],
        [80; 4],
        [255; 4],
        [5, 3, 3, 3],
        [0; 4],
    ] {
        for repeat in [false, true] {
            let mut edited = valid.clone();

            let hints = edited.len() - 84;

            for i in 0..80 {
                edited[hints + i] = i as u8;
            }

            if repeat {
                edited[hints + 1] = 0;
            }

            edited[hints + 80..].copy_from_slice(&counts);

            assert!(
                !dsa.public_key
                    .verify(&edited, message, &VerifyOptions::default()),
                "{counts:?}"
            );
        }
    }

    // The valid signature with a nonzero byte after its last hint: the encoding must be canonical.
    let used = usize::from(valid[valid.len() - 1]);

    if used < 80 {
        let mut edited = valid.clone();

        let at = edited.len() - 84 + used;

        edited[at] = 1;

        assert!(
            dsa.public_key
                .verify(&valid, message, &VerifyOptions::default())
        );

        assert!(
            !dsa.public_key
                .verify(&edited, message, &VerifyOptions::default())
        );
    }

    let xmss: [(StatefulSignatureAlgorithm, u32, usize, &[u8]); 4] = [
        (XMSS, 0x0D, 4 + 24 + 61 * 24, &[0, 0, 4, 0]),
        (XMSS, 0x0D, 4 + 24 + 61 * 24, &[0xFF; 4]),
        (XMSS_MT, 0x22, 3 + 24 + (4 * 51 + 20) * 24, &[0x10, 0, 0]),
        (XMSS_MT, 0x22, 3 + 24 + (4 * 51 + 20) * 24, &[0xFF; 3]),
    ];

    for (algorithm, oid, size, index) in xmss {
        let key = algorithm
            .import_public_key(
                &[&oid.to_be_bytes()[..], &pattern(48, 0)].concat(),
                KeyFormat::Raw,
            )
            .expect("key");

        let mut edited = vec![0; size];

        edited[..index.len()].copy_from_slice(index);

        assert!(
            !key.verify(&edited, message),
            "{} index {index:?}",
            algorithm.name()
        );
    }
}

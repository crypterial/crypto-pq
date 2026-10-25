// The constant-time check, built with RUSTFLAGS="--cfg crypto_pq_ct" and run under valgrind's
// memcheck. Seeds and hazmat randomness are marked uninitialised here, and the library marks the
// operating system's random bytes the same way, so memcheck reports every branch and memory
// index that depends on a secret. The library declassifies only what the specifications make
// public; results are declassified here before they are compared.
#![cfg(crypto_pq_ct)]

mod vectors;

use crypto_pq::ct_check::{aes_encrypt, declassify, secret};
use crypto_pq::{
    ASCON_CXOF128, ASCON_HASH256, ASCON_XOF128, BLAKE2B_256, BLAKE2B_MAC, BLAKE2S_256, BLAKE2S_MAC,
    BLAKE3, BLAKE3_256, BLAKE3_KDF, BLAKE3_MAC, CSHAKE128, CSHAKE256, EFRODOKEM_976_AES,
    EFRODOKEM_976_SHAKE, EFRODOKEM_1344_AES, EFRODOKEM_1344_SHAKE, Error, FRODOKEM_976_AES,
    FRODOKEM_976_SHAKE, FRODOKEM_1344_AES, FRODOKEM_1344_SHAKE, HKDF_SHA_256, HKDF_SHA_384,
    HKDF_SHA_512, HMAC_SHA_256, HMAC_SHA_384, HSS_LMS, HashOptions, KMAC128, KMAC256, KdfOptions,
    KemAlgorithm, KemPrivateKey, KemPublicKey, KeyFormat, KeyGenOptions, ML_DSA_44, ML_DSA_65,
    ML_DSA_87, ML_KEM_512, ML_KEM_768, ML_KEM_1024, MacAlgorithm, MacOptions, SLH_DSA_SHA2_192F,
    SLH_DSA_SHAKE_128F, SignOptions, SignatureAlgorithm, SignaturePrivateKey, SignaturePublicKey,
    StateStore, StatefulKeyGenOptions, StatefulLoadOptions, StatefulParameters,
    StatefulSignatureAlgorithm, VerifyOptions, XMSS_MT, XofOptions, hazmat,
};
use vectors::first;

const MESSAGE: &[u8] = b"crypto-pq constant-time check";

fn secret_bytes(length: usize, first: u8) -> Vec<u8> {
    let bytes: Vec<u8> = (0..length).map(|i| first.wrapping_add(i as u8)).collect();

    secret(&bytes);

    bytes
}

fn same(a: &[u8], b: &[u8]) -> bool {
    declassify(a);

    declassify(b);

    a == b
}

fn kem(algorithm: KemAlgorithm, seed_size: usize, randomness_size: usize) {
    let pair = hazmat::generate_kem_key_pair(algorithm, &secret_bytes(seed_size, 1)).unwrap();

    let randomness = secret_bytes(randomness_size, 2);

    let encapsulation = hazmat::encapsulate(&pair.public_key, &randomness).unwrap();

    let shared_secret = pair
        .private_key
        .decapsulate(&encapsulation.ciphertext)
        .unwrap();

    // Implicit rejection takes the same path: a changed ciphertext gives an unrelated secret.
    let mut changed = encapsulation.ciphertext.clone();

    changed[0] ^= 1;

    let rejected = pair.private_key.decapsulate(&changed).unwrap();

    assert!(same(&shared_secret, &encapsulation.shared_secret));

    assert!(!same(&rejected, &shared_secret));

    // A public key imported from its bytes builds its cached form itself.
    let imported = algorithm
        .import_public_key(
            &pair.public_key.export_key(KeyFormat::Raw).unwrap(),
            KeyFormat::Raw,
        )
        .unwrap();

    let again = hazmat::encapsulate(&imported, &randomness).unwrap();

    assert!(same(&again.shared_secret, &encapsulation.shared_secret));

    let generated = algorithm
        .generate_key_pair(&KeyGenOptions::default())
        .unwrap();

    let fresh = generated.public_key.encapsulate().unwrap();

    let decapsulated = generated
        .private_key
        .decapsulate(&fresh.ciphertext)
        .unwrap();

    assert!(same(&decapsulated, &fresh.shared_secret));
}

#[test]
fn kems() {
    for algorithm in [ML_KEM_512, ML_KEM_768, ML_KEM_1024] {
        kem(algorithm, 64, 32);
    }
}

const FRODO: [(KemAlgorithm, usize, usize); 8] = [
    (FRODOKEM_976_AES, 88, 72),
    (FRODOKEM_976_SHAKE, 88, 72),
    (FRODOKEM_1344_AES, 112, 96),
    (FRODOKEM_1344_SHAKE, 112, 96),
    (EFRODOKEM_976_AES, 64, 24),
    (EFRODOKEM_976_SHAKE, 64, 24),
    (EFRODOKEM_1344_AES, 80, 32),
    (EFRODOKEM_1344_SHAKE, 80, 32),
];

// Sampling S and E, the products with the secret matrices, the re-encryption of decapsulation, its
// comparison and the choice between k' and s; matrix A comes from the public seedA.
#[test]
fn frodokem() {
    for (algorithm, seed_size, randomness_size) in FRODO {
        kem(algorithm, seed_size, randomness_size);
    }
}

// A FrodoKEM private key from outside is secret as a whole: the import declassifies only its public
// key and pkh, and of the range check of S^T only its outcome, which refuses an entry beyond it.
#[test]
fn imported_frodokem_keys() {
    for (algorithm, seed_size, _) in FRODO {
        let pair = hazmat::generate_kem_key_pair(algorithm, &secret_bytes(seed_size, 7)).unwrap();

        let sk = pair.private_key.export_key(KeyFormat::Raw).unwrap();

        secret(&sk);

        let imported = algorithm.import_private_key(&sk, KeyFormat::Raw).unwrap();

        // The high byte of the last entry of S^T, just before pkh.
        let mut beyond = sk.to_vec();

        let at = beyond.len() - algorithm.shared_secret_size() - 1;

        beyond[at] ^= 0x40;

        secret(&beyond);

        assert_eq!(
            algorithm.import_private_key(&beyond, KeyFormat::Raw).err(),
            Some(Error::InvalidPrivateKey)
        );

        for decapsulator in [&pair.private_key, &imported] {
            let encapsulation = imported.public_key().encapsulate().unwrap();

            let shared_secret = decapsulator.decapsulate(&encapsulation.ciphertext).unwrap();

            assert!(same(&shared_secret, &encapsulation.shared_secret));
        }
    }
}

fn signature(algorithm: SignatureAlgorithm, seed_size: usize, randomness_size: usize) {
    let pair = hazmat::generate_signature_key_pair(algorithm, &secret_bytes(seed_size, 3)).unwrap();

    let randomness = secret_bytes(randomness_size, 4);

    let signed = hazmat::sign(
        &pair.private_key,
        MESSAGE,
        &randomness,
        &SignOptions::default(),
    )
    .unwrap();

    assert!(
        pair.public_key
            .verify(&signed, MESSAGE, &VerifyOptions::default())
    );

    // Key generation signs and verifies once more as its pairwise self-test.
    let generated = algorithm
        .generate_key_pair(&KeyGenOptions::default())
        .unwrap();

    for deterministic in [false, true] {
        let options = SignOptions::default()
            .with_context(b"context")
            .with_deterministic(deterministic);

        let signed = generated.private_key.sign(MESSAGE, &options).unwrap();

        let options = VerifyOptions::default().with_context(b"context");

        assert!(generated.public_key.verify(&signed, MESSAGE, &options));
    }
}

#[test]
fn ml_dsa() {
    for algorithm in [ML_DSA_44, ML_DSA_65, ML_DSA_87] {
        signature(algorithm, 32, 32);
    }
}

#[test]
fn slh_dsa() {
    for algorithm in [SLH_DSA_SHA2_192F, SLH_DSA_SHAKE_128F] {
        let n = algorithm.public_key_size() / 2;

        signature(algorithm, 3 * n, n);
    }
}

// SPEC 10.4 item 4 and D-67: a PEM private key from outside is secret as a whole, its boundary
// lines included. The import declassifies its layout (line ends, whitespace, dashes, padding),
// the comparison of each boundary line with the expected one and the DER structure (tags,
// lengths, version, OID), nothing of a base64 digit. Each key comes in its exported layout and in
// one with explanatory text, CRLF line ends and whitespace inside the body.
fn pem_variants(key: &[u8]) -> [Vec<u8>; 2] {
    let text = std::str::from_utf8(key).unwrap();

    let spaced = text.replace('\n', " \t\r\n").replacen("\r\n", "\n", 1);

    let mut lines: Vec<&str> = spaced.split('\n').collect();

    let middle = lines.len() / 2;

    lines.insert(middle, "\x0b \x0c");

    let laid_out = format!("explanatory text\r\n{}trailing text\n", lines.join("\n"));

    let variants = [key.to_vec(), laid_out.into_bytes()];

    for variant in &variants {
        secret(variant);
    }

    variants
}

#[test]
fn imported_pem_kem_keys() {
    let ml_kem = hazmat::generate_kem_key_pair(ML_KEM_768, &secret_bytes(64, 8)).unwrap();

    let dk = first("acvp/ML-KEM-keyGen.txt", "ML-KEM-768", "dk");

    secret(&dk);

    let expanded = ML_KEM_768.import_private_key(&dk, KeyFormat::Raw).unwrap();

    for key in [&ml_kem.private_key, &expanded] {
        let pem = key.export_key(KeyFormat::Pem).unwrap();

        declassify(&pem[..]);

        for variant in pem_variants(&pem) {
            let imported = ML_KEM_768
                .import_private_key(&variant, KeyFormat::Pem)
                .unwrap();

            let encapsulation = key.public_key().encapsulate().unwrap();

            let shared_secret = imported.decapsulate(&encapsulation.ciphertext).unwrap();

            assert!(same(&shared_secret, &encapsulation.shared_secret));
        }
    }
}

#[test]
fn imported_pem_signature_keys() {
    let ml_dsa = hazmat::generate_signature_key_pair(ML_DSA_65, &secret_bytes(32, 9)).unwrap();

    let sk = first("acvp/ML-DSA-keyGen.txt", "ML-DSA-65", "sk");

    secret(&sk);

    let expanded = ML_DSA_65.import_private_key(&sk, KeyFormat::Raw).unwrap();

    let slh_dsa =
        hazmat::generate_signature_key_pair(SLH_DSA_SHAKE_128F, &secret_bytes(48, 9)).unwrap();

    for (algorithm, key) in [
        (ML_DSA_65, &ml_dsa.private_key),
        (ML_DSA_65, &expanded),
        (SLH_DSA_SHAKE_128F, &slh_dsa.private_key),
    ] {
        let pem = key.export_key(KeyFormat::Pem).unwrap();

        declassify(&pem[..]);

        for variant in pem_variants(&pem) {
            let imported = algorithm
                .import_private_key(&variant, KeyFormat::Pem)
                .unwrap();

            let signed = imported.sign(MESSAGE, &SignOptions::default()).unwrap();

            let verified = key
                .public_key()
                .verify(&signed, MESSAGE, &VerifyOptions::default());

            assert!(verified);
        }
    }
}

// Each key also goes out and back in as DER; PEM is only exported here.
fn reimported_kem(algorithm: KemAlgorithm, key: &KemPrivateKey, public_key: &KemPublicKey) {
    key.export_key(KeyFormat::Pem).unwrap();

    let again = algorithm
        .import_private_key(&key.export_key(KeyFormat::Der).unwrap(), KeyFormat::Der)
        .unwrap();

    for decapsulator in [key, &again] {
        for encapsulator in [public_key, &decapsulator.public_key()] {
            let encapsulation = encapsulator.encapsulate().unwrap();

            let shared_secret = decapsulator.decapsulate(&encapsulation.ciphertext).unwrap();

            assert!(same(&shared_secret, &encapsulation.shared_secret));
        }
    }
}

// A private key from outside is secret as a whole: the library declassifies only what it holds
// of the public key.
#[test]
fn imported_kem_keys() {
    for algorithm in [ML_KEM_512, ML_KEM_768, ML_KEM_1024] {
        let expanded = first("acvp/ML-KEM-keyGen.txt", algorithm.name(), "dk");

        let public_key = algorithm
            .import_public_key(
                &first("acvp/ML-KEM-keyGen.txt", algorithm.name(), "ek"),
                KeyFormat::Raw,
            )
            .unwrap();

        // Coefficient 0 of ŝ set to another canonical value, which leaves s outside [-eta1, eta1]:
        // only the outcome of the range check is declassified.
        let mut beyond = expanded.clone();

        beyond[0] = u8::from(beyond[0] == 0 && beyond[1] & 0x0F == 0);

        beyond[1] &= 0xF0;

        secret(&beyond);

        assert_eq!(
            algorithm.import_private_key(&beyond, KeyFormat::Raw).err(),
            Some(Error::InvalidPrivateKey)
        );

        secret(&expanded);

        let imported = algorithm
            .import_private_key(&expanded, KeyFormat::Raw)
            .unwrap();

        reimported_kem(algorithm, &imported, &public_key);

        let pair = hazmat::generate_kem_key_pair(algorithm, &secret_bytes(64, 6)).unwrap();

        reimported_kem(algorithm, &pair.private_key, &pair.public_key);
    }
}

fn reimported_signature(
    algorithm: SignatureAlgorithm,
    key: &SignaturePrivateKey,
    public_key: &SignaturePublicKey,
) {
    key.export_key(KeyFormat::Pem).unwrap();

    let again = algorithm
        .import_private_key(&key.export_key(KeyFormat::Der).unwrap(), KeyFormat::Der)
        .unwrap();

    for signer in [key, &again] {
        let signed = signer.sign(MESSAGE, &SignOptions::default()).unwrap();

        for verifier in [public_key, &signer.public_key()] {
            assert!(verifier.verify(&signed, MESSAGE, &VerifyOptions::default()));
        }
    }
}

#[test]
fn imported_signature_keys() {
    for algorithm in [ML_DSA_44, ML_DSA_65, ML_DSA_87] {
        let expanded = first("acvp/ML-DSA-keyGen.txt", algorithm.name(), "sk");

        let public_key = algorithm
            .import_public_key(
                &first("acvp/ML-DSA-keyGen.txt", algorithm.name(), "pk"),
                KeyFormat::Raw,
            )
            .unwrap();

        secret(&expanded);

        let imported = algorithm
            .import_private_key(&expanded, KeyFormat::Raw)
            .unwrap();

        reimported_signature(algorithm, &imported, &public_key);

        let pair = hazmat::generate_signature_key_pair(algorithm, &secret_bytes(32, 7)).unwrap();

        reimported_signature(algorithm, &pair.private_key, &pair.public_key);
    }

    for algorithm in [SLH_DSA_SHA2_192F, SLH_DSA_SHAKE_128F] {
        let n = algorithm.public_key_size() / 2;

        let pair = hazmat::generate_signature_key_pair(algorithm, &secret_bytes(3 * n, 7)).unwrap();

        let raw = pair.private_key.export_key(KeyFormat::Raw).unwrap();

        secret(&raw);

        let imported = algorithm.import_private_key(&raw, KeyFormat::Raw).unwrap();

        reimported_signature(algorithm, &imported, &pair.public_key);
    }
}

// A store with a single writer: its states hold secret seeds, so it never compares them.
#[derive(Default)]
struct Store {
    state: Option<Vec<u8>>,
}

impl StateStore for Store {
    fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.state.clone())
    }

    fn update(&mut self, _: Option<&[u8]>, next: &[u8]) -> Result<bool, Error> {
        self.state = Some(next.to_vec());

        Ok(true)
    }
}

// The deterministic key starts at `start`: at 31 its second signature moves the lower levels to
// their next trees, with the claim and signed writes, a child tree built from derived secrets and
// signed by its parent, and the verification before release; at 28 for one tree of height 5 its
// fourth signature exhausts it and erases its secrets. The public key generation draws the child
// secrets and randomizers from the entropy source.
fn stateful(
    algorithm: StatefulSignatureAlgorithm,
    parameters: StatefulParameters,
    seed_size: usize,
    start: u64,
) {
    let mut store = Store::default();

    let seed = secret_bytes(seed_size, 5);

    let public_key = {
        let mut pair = hazmat::generate_stateful_key_pair(
            algorithm,
            &seed,
            start,
            parameters,
            &mut store,
            &StatefulKeyGenOptions::default(),
        )
        .unwrap();

        for _ in 0..2 {
            let signed = pair.private_key.sign(MESSAGE).unwrap();

            assert!(pair.public_key.verify(&signed, MESSAGE));
        }

        pair.public_key
    };

    // Loading checks the record against its checksum and the public key, rebuilds the current
    // trees from the secrets in it and verifies the signatures that it holds.
    let mut loaded = algorithm
        .load_private_key(&mut store, &StatefulLoadOptions::default())
        .unwrap();

    let signed = loaded.sign(MESSAGE).unwrap();

    assert!(public_key.verify(&signed, MESSAGE));

    // A tree cache is public, and its tag key comes from the top secrets: loading with it checks
    // the tag and the nodes, and restores the trees that the stored index still signs with.
    let cache = loaded.export_tree_cache().unwrap();

    drop(loaded);

    let options = StatefulLoadOptions::default().with_tree_cache(&cache);

    let mut restored = algorithm.load_private_key(&mut store, &options).unwrap();

    let signed = restored.sign(MESSAGE).unwrap();

    assert!(public_key.verify(&signed, MESSAGE));

    let mut generated = algorithm
        .generate_key_pair(
            parameters,
            Store::default(),
            &StatefulKeyGenOptions::default(),
        )
        .unwrap();

    let signed = generated.private_key.sign(MESSAGE).unwrap();

    assert!(generated.public_key.verify(&signed, MESSAGE));
}

#[test]
fn hss_lms() {
    let levels = [
        ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"),
        ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W2"),
    ];

    stateful(HSS_LMS, StatefulParameters::Levels(&levels), 16 + 24, 31);

    let levels = [("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W4")];

    stateful(HSS_LMS, StatefulParameters::Levels(&levels), 16 + 32, 28);
}

#[test]
fn xmss_mt() {
    stateful(
        XMSS_MT,
        StatefulParameters::Name("XMSSMT-SHA2_20/4_256"),
        3 * 32,
        31,
    );

    stateful(
        XMSS_MT,
        StatefulParameters::Name("XMSSMT-SHAKE256_20/4_192"),
        3 * 24,
        31,
    );
}

// Every MAC under a secret key, one-shot and incremental, over a message that spans blocks, and
// its verification of the right tag and of a changed one: the verdict is public, the tag is not.
// AES-128 and AES-256 on a secret key and secret blocks, one to nine of them, through the AES
// instructions where the CPU has them and through the bitsliced code.
#[test]
fn aes() {
    for key_size in [16, 32] {
        let key = secret_bytes(key_size, 4);

        for count in 1..10 {
            let data = secret_bytes(16 * count, 8);

            let mut blocks: Vec<[u8; 16]> =
                data.chunks(16).map(|b| b.try_into().unwrap()).collect();

            let mut portable = blocks.clone();

            aes_encrypt(&key, &mut blocks, true);

            aes_encrypt(&key, &mut portable, false);

            assert!(same(blocks.as_flattened(), portable.as_flattened()));
        }
    }
}

fn mac(algorithm: MacAlgorithm, key_size: usize) {
    let key = secret_bytes(key_size, 9);

    let message: Vec<u8> = (0..300).map(|i| i as u8).collect();

    let tag = algorithm.digest(&key, &message).unwrap();

    let mut incremental = algorithm.create(&key).unwrap();

    incremental.update(&message[..77]);

    incremental.update(&message[77..]);

    assert!(same(&incremental.digest(), &tag));

    assert!(algorithm.verify(&key, &message, &tag));

    assert!(incremental.verify(&tag));

    let mut changed = tag.clone();

    declassify(&changed);

    changed[0] ^= 1;

    assert!(!algorithm.verify(&key, &message, &changed));

    assert!(!incremental.verify(&changed));
}

#[test]
fn macs() {
    for (algorithm, key_size) in [
        (HMAC_SHA_256, 32),
        (HMAC_SHA_384, 200),
        (KMAC128, 32),
        (KMAC256, 64),
        (BLAKE2B_MAC, 64),
        (BLAKE2S_MAC, 32),
        (BLAKE3_MAC, 32),
    ] {
        mac(algorithm, key_size);
    }

    // KMACXOF with a customization and a tag longer than a comparison chunk, and BLAKE2 with a
    // short key, salt and personalization.
    let options = MacOptions::default()
        .with_length(100)
        .with_customization(b"ct")
        .with_xof(true);

    mac(KMAC128.configure(&options).unwrap(), 16);

    let options = MacOptions::default()
        .with_length(20)
        .with_salt(b"salt")
        .with_personalization(b"person");

    mac(BLAKE2B_MAC.configure(&options).unwrap(), 5);

    mac(BLAKE2S_MAC.configure(&options).unwrap(), 1);

    // HMAC tags truncated to their leftmost bytes, one-shot and streaming.
    for (algorithm, length) in [(HMAC_SHA_256, 16), (HMAC_SHA_384, 4)] {
        let options = MacOptions::default().with_length(length);

        mac(algorithm.configure(&options).unwrap(), 40);
    }
}

// HKDF from a secret IKM, and Expand from the secret PRK, with outputs of one block and of several,
// and an info too long for the message buffer.
#[test]
fn hkdf() {
    for kdf in [HKDF_SHA_256, HKDF_SHA_384, HKDF_SHA_512] {
        let ikm = secret_bytes(32, 3);

        let long_info = vec![7; 300];

        for info in [&b"info"[..], &long_info] {
            let options = KdfOptions::default().with_salt(b"salt").with_info(info);

            let okm = kdf.derive(&ikm, 200, &options).unwrap();

            let short = kdf.derive(&ikm, 16, &options).unwrap();

            assert!(same(&short, &okm[..16]));

            let prk = kdf
                .extract(&ikm, &KdfOptions::default().with_salt(b"salt"))
                .unwrap();

            let expanded = kdf
                .expand(&prk, 200, &KdfOptions::default().with_info(info))
                .unwrap();

            assert!(same(&expanded, &okm));
        }
    }
}

// BLAKE3: keyed_hash under a secret key and derive_key from secret key material, over more than
// two chunks, whose chaining values merge into parents, over ten, which the kernels hash eight
// and more at a time, and over a partial block; the hash and the XOF of the same secret input,
// whose sixteen output blocks the kernels compute side by side.
#[test]
fn blake3() {
    let key = secret_bytes(32, 5);

    let long = secret_bytes(9 * 1024 + 100, 6);

    for data in [&long[..2100], &long[..], &long[..10]] {
        let tag = BLAKE3_MAC.digest(&key, data).unwrap();

        let mut incremental = BLAKE3_MAC.create(&key).unwrap();

        incremental.update(&data[..data.len() / 3]);

        incremental.update(&data[data.len() / 3..]);

        assert!(same(&incremental.digest(), &tag));

        assert!(BLAKE3_MAC.verify(&key, data, &tag));

        assert!(incremental.verify(&tag));

        let options = KdfOptions::default().with_info(b"context");

        let okm = BLAKE3_KDF.derive(data, 1030, &options).unwrap();

        let short = BLAKE3_KDF.derive(data, 32, &options).unwrap();

        assert!(same(&short, &okm[..32]));

        let output = BLAKE3.digest(data, 1030).unwrap();

        let mut xof = BLAKE3.create();

        xof.update(data).unwrap();

        let mut read = xof.read(1).unwrap();

        read.extend(xof.read(1029).unwrap());

        assert!(same(&read, &output));

        let mut hasher = BLAKE3_256.create();

        hasher.update(data);

        assert!(same(&hasher.digest(), &BLAKE3_256.digest(data)));
    }
}

// The hash functions on secret input, as a KDF or a MAC built on them would feed it: one-shot and
// incremental, configured and not.
#[test]
fn hashes_of_secrets() {
    let data = secret_bytes(300, 11);

    let options = HashOptions::default()
        .with_salt(b"salt")
        .with_personalization(b"me");

    for algorithm in [
        BLAKE2B_256,
        BLAKE2S_256,
        BLAKE2B_256.configure(&options).unwrap(),
        ASCON_HASH256,
    ] {
        let digest = algorithm.digest(&data);

        let mut hasher = algorithm.create();

        hasher.update(&data[..100]);

        hasher.update(&data[100..]);

        assert!(same(&hasher.digest(), &digest));
    }

    let customized = XofOptions::default().with_customization(b"ct");

    for algorithm in [
        CSHAKE128.configure(&customized).unwrap(),
        CSHAKE256,
        ASCON_XOF128,
        ASCON_CXOF128.configure(&customized).unwrap(),
    ] {
        let output = algorithm.digest(&data, 70).unwrap();

        let mut xof = algorithm.create();

        xof.update(&data).unwrap();

        assert!(same(&xof.read(70).unwrap(), &output));
    }
}

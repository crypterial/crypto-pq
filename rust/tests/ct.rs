// The constant-time check, built with RUSTFLAGS="--cfg crypto_pq_ct" and run under valgrind's
// memcheck. Seeds and hazmat randomness are marked uninitialised here, and the library marks the
// operating system's random bytes the same way, so memcheck reports every branch and memory
// index that depends on a secret. The library declassifies only what the specifications make
// public; results are declassified here before they are compared.
#![cfg(crypto_pq_ct)]

use crypto_pq::ct_check::{declassify, secret, x25519};
use crypto_pq::{
    Error, HSS_LMS, KemAlgorithm, KemPrivateKey, KemPublicKey, KeyFormat, KeyGenOptions, ML_DSA_44,
    ML_DSA_65, ML_DSA_87, ML_KEM_512, ML_KEM_768, ML_KEM_1024, SLH_DSA_SHA2_192F,
    SLH_DSA_SHAKE_128F, SignOptions, SignatureAlgorithm, SignaturePrivateKey, SignaturePublicKey,
    StateStore, StatefulParameters, StatefulSignatureAlgorithm, VerifyOptions, X_WING, XMSS_MT,
    hazmat,
};

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

    kem(X_WING, 32, 64);
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

// RFC 7748, section 6.1, with both private keys secret.
#[test]
fn x25519_alone() {
    let alice = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");

    let bob = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

    secret(&alice);

    secret(&bob);

    let mut base = [0; 32];

    base[0] = 9;

    let alice_public = x25519(&alice, &base);

    declassify(&alice_public);

    let shared = x25519(&bob, &alice_public);

    declassify(&shared);

    assert_eq!(
        shared.to_vec(),
        unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    );
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
        let options = SignOptions {
            context: b"context",
            deterministic,
            ..SignOptions::default()
        };

        let signed = generated.private_key.sign(MESSAGE, &options).unwrap();

        let options = VerifyOptions {
            context: b"context",
            ..VerifyOptions::default()
        };

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

// The first value of `key` under the parameter set's header of an ACVP vector file.
fn vector(file: &str, parameter_set: &str, key: &str) -> Vec<u8> {
    let path = format!("{}/../vectors/acvp/{file}", env!("CARGO_MANIFEST_DIR"));

    let text = std::fs::read_to_string(&path).unwrap();

    let start = text
        .find(&format!("[parameterSet = {parameter_set}]"))
        .unwrap();

    let prefix = format!("{key} = ");

    let line = text[start..]
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap();

    unhex(&line[prefix.len()..])
}

// Each key also goes out and back in as DER; PEM is only exported.
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
        let expanded = vector("ML-KEM-keyGen.txt", algorithm.name(), "dk");

        let public_key = algorithm
            .import_public_key(
                &vector("ML-KEM-keyGen.txt", algorithm.name(), "ek"),
                KeyFormat::Raw,
            )
            .unwrap();

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
        let expanded = vector("ML-DSA-keyGen.txt", algorithm.name(), "sk");

        let public_key = algorithm
            .import_public_key(
                &vector("ML-DSA-keyGen.txt", algorithm.name(), "pk"),
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

fn stateful(
    algorithm: StatefulSignatureAlgorithm,
    parameters: StatefulParameters,
    seed_size: usize,
) {
    let mut store = Store::default();

    let seed = secret_bytes(seed_size, 5);

    let public_key = {
        let mut pair =
            hazmat::generate_stateful_key_pair(algorithm, parameters, &seed, 0, &mut store)
                .unwrap();

        let signed = pair.private_key.sign(MESSAGE).unwrap();

        assert!(pair.public_key.verify(&signed, MESSAGE));

        pair.public_key
    };

    // Loading rebuilds the trees from the seeds in the stored state.
    let mut loaded = algorithm.load_private_key(&mut store).unwrap();

    let signed = loaded.sign(MESSAGE).unwrap();

    assert!(public_key.verify(&signed, MESSAGE));

    let mut generated = algorithm
        .generate_key_pair(parameters, Store::default())
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

    stateful(HSS_LMS, StatefulParameters::Levels(&levels), 16 + 24);

    let levels = [("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W4")];

    stateful(HSS_LMS, StatefulParameters::Levels(&levels), 16 + 32);
}

#[test]
fn xmss_mt() {
    stateful(
        XMSS_MT,
        StatefulParameters::Name("XMSSMT-SHA2_20/4_256"),
        3 * 32,
    );

    stateful(
        XMSS_MT,
        StatefulParameters::Name("XMSSMT-SHAKE256_20/4_192"),
        3 * 24,
    );
}

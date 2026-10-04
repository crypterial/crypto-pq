mod vectors;

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Mutex;

use crypto_pq::{
    Error, HSS_LMS, KemAlgorithm, KeyFormat, ML_DSA_44, ML_DSA_65, ML_DSA_87, ML_KEM_512,
    ML_KEM_768, ML_KEM_1024, PreHash, SHA_224, SHA_256, SHA_384, SHA_512, SHA_512_224, SHA_512_256,
    SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256, SLH_DSA_SHA2_128F,
    SLH_DSA_SHA2_128S, SLH_DSA_SHA2_192F, SLH_DSA_SHA2_192S, SLH_DSA_SHA2_256F, SLH_DSA_SHA2_256S,
    SLH_DSA_SHAKE_128F, SLH_DSA_SHAKE_128S, SLH_DSA_SHAKE_192F, SLH_DSA_SHAKE_192S,
    SLH_DSA_SHAKE_256F, SLH_DSA_SHAKE_256S, SignOptions, SignatureAlgorithm, StateStore,
    StatefulParameters, StatefulSignatureAlgorithm, VerifyOptions, X_WING, XMSS, XMSS_MT, hazmat,
};
use vectors::{Fields, der, parallel, records, unhex};

// The vectors under vectors/cross were computed by the Python reference: keys and their
// encodings, hazmat signatures with every pre-hash, implicit rejection, state blobs, and the
// error code of every malformed input.
const KEMS: [KemAlgorithm; 4] = [ML_KEM_512, ML_KEM_768, ML_KEM_1024, X_WING];

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

const STATEFUL: [StatefulSignatureAlgorithm; 3] = [HSS_LMS, XMSS, XMSS_MT];

const ENCODINGS: [(KeyFormat, &str); 2] = [(KeyFormat::Der, "Der"), (KeyFormat::Pem, "Pem")];

#[derive(Clone, Copy)]
enum Algorithm {
    Kem(KemAlgorithm),
    Signature(SignatureAlgorithm),
    Stateful(StatefulSignatureAlgorithm),
}

fn algorithm(name: &str) -> Algorithm {
    let kem = KEMS
        .iter()
        .find(|a| a.name() == name)
        .map(|&a| Algorithm::Kem(a));

    let signature = || {
        SIGNATURES
            .iter()
            .find(|a| a.name() == name)
            .map(|&a| Algorithm::Signature(a))
    };

    let stateful = || {
        STATEFUL
            .iter()
            .find(|a| a.name() == name)
            .map(|&a| Algorithm::Stateful(a))
    };

    kem.or_else(signature)
        .or_else(stateful)
        .unwrap_or_else(|| panic!("unknown algorithm {name}"))
}

fn kem_algorithm(name: &str) -> KemAlgorithm {
    match algorithm(name) {
        Algorithm::Kem(algorithm) => algorithm,
        _ => panic!("{name} is not a KEM"),
    }
}

fn signature_algorithm(name: &str) -> SignatureAlgorithm {
    match algorithm(name) {
        Algorithm::Signature(algorithm) => algorithm,
        _ => panic!("{name} is not a signature algorithm"),
    }
}

fn stateful_algorithm(name: &str) -> StatefulSignatureAlgorithm {
    match algorithm(name) {
        Algorithm::Stateful(algorithm) => algorithm,
        _ => panic!("{name} is not a stateful algorithm"),
    }
}

fn pre_hash(name: &str) -> Option<PreHash> {
    Some(match name {
        "none" => return None,
        "SHA2-224" => SHA_224.into(),
        "SHA2-256" => SHA_256.into(),
        "SHA2-384" => SHA_384.into(),
        "SHA2-512" => SHA_512.into(),
        "SHA2-512/224" => SHA_512_224.into(),
        "SHA2-512/256" => SHA_512_256.into(),
        "SHA3-224" => SHA3_224.into(),
        "SHA3-256" => SHA3_256.into(),
        "SHA3-384" => SHA3_384.into(),
        "SHA3-512" => SHA3_512.into(),
        "SHAKE-128" => SHAKE128.into(),
        "SHAKE-256" => SHAKE256.into(),
        _ => panic!("unknown pre-hash {name}"),
    })
}

fn key_format(name: &str) -> KeyFormat {
    match name {
        "raw" => KeyFormat::Raw,
        "der" => KeyFormat::Der,
        "pem" => KeyFormat::Pem,
        _ => panic!("unknown format {name}"),
    }
}

fn field(record: &Fields, name: &str) -> Vec<u8> {
    record
        .get(name)
        .map(|value| unhex(value))
        .unwrap_or_default()
}

// The HSS levels of a record: comma-separated LMS and LM-OTS type names.
fn levels(record: &Fields) -> Vec<(&str, &str)> {
    match (record.get("lms"), record.get("ots")) {
        (Some(lms), Some(ots)) => lms.split(',').zip(ots.split(',')).collect(),
        _ => Vec::new(),
    }
}

fn parameters<'a>(record: &'a Fields, levels: &'a [(&'a str, &'a str)]) -> StatefulParameters<'a> {
    match record.get("parameters") {
        Some(name) => StatefulParameters::Name(name),
        None => StatefulParameters::Levels(levels),
    }
}

// A store that the test keeps a handle to, to read the state the key wrote.
#[derive(Clone, Default)]
struct MemoryStore(Rc<RefCell<Option<Vec<u8>>>>);

impl MemoryStore {
    fn holding(state: &[u8]) -> Self {
        Self(Rc::new(RefCell::new(Some(state.to_vec()))))
    }

    fn state(&self) -> Option<Vec<u8>> {
        self.0.borrow().clone()
    }
}

impl StateStore for MemoryStore {
    fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.state())
    }

    fn update(&mut self, previous: Option<&[u8]>, next: &[u8]) -> Result<bool, Error> {
        let mut state = self.0.borrow_mut();

        if state.as_deref() != previous {
            return Ok(false);
        }

        *state = Some(next.to_vec());

        Ok(true)
    }
}

#[test]
fn kem() {
    parallel(&records("cross/kem.txt", "seed"), |(header, record)| {
        let algorithm = kem_algorithm(&header["algorithm"]);

        let context = format!("{} tcId {}", algorithm.name(), record["tcId"]);

        let (seed, public) = (field(record, "seed"), field(record, "publicKey"));

        let pair = hazmat::generate_kem_key_pair(algorithm, &seed).unwrap();

        assert_eq!(
            pair.public_key.export_key(KeyFormat::Raw).unwrap(),
            public,
            "{context}"
        );

        assert_eq!(
            pair.private_key.export_key(KeyFormat::Raw).unwrap(),
            seed,
            "{context}"
        );

        let imported = algorithm
            .import_public_key(&public, KeyFormat::Raw)
            .unwrap();

        assert_eq!(imported, pair.public_key, "{context}");

        let mut keys = vec![algorithm.import_private_key(&seed, KeyFormat::Raw).unwrap()];

        if record.contains_key("expandedKey") {
            for (format, suffix) in ENCODINGS {
                let encoded = field(record, &format!("publicKey{suffix}"));

                assert_eq!(
                    pair.public_key.export_key(format).unwrap(),
                    encoded,
                    "{context}"
                );

                let imported = algorithm.import_public_key(&encoded, format).unwrap();

                assert_eq!(imported, pair.public_key, "{context}");

                let encoded = field(record, &format!("privateKey{suffix}"));

                assert_eq!(
                    pair.private_key.export_key(format).unwrap(),
                    encoded,
                    "{context}"
                );

                let imported = algorithm.import_private_key(&encoded, format).unwrap();

                assert_eq!(
                    imported.export_key(KeyFormat::Raw).unwrap(),
                    seed,
                    "{context}"
                );
            }

            // PKCS#8 holds the seed as [0] IMPLICIT OCTET STRING, the last element.
            let private_der = field(record, "privateKeyDer");

            assert!(private_der.ends_with(&der(0x80, &seed)), "{context}");

            let expanded = field(record, "expandedKey");

            let key = algorithm
                .import_private_key(&expanded, KeyFormat::Raw)
                .unwrap();

            assert_eq!(
                key.export_key(KeyFormat::Raw).unwrap(),
                expanded,
                "{context}"
            );

            assert_eq!(key.public_key(), pair.public_key, "{context}");

            for (format, suffix) in ENCODINGS {
                let encoded = field(record, &format!("expandedKey{suffix}"));

                assert_eq!(key.export_key(format).unwrap(), encoded, "{context}");

                let imported = algorithm.import_private_key(&encoded, format).unwrap();

                assert_eq!(
                    imported.export_key(KeyFormat::Raw).unwrap(),
                    expanded,
                    "{context}"
                );
            }

            let both = algorithm
                .import_private_key(&field(record, "bothKeyDer"), KeyFormat::Der)
                .unwrap();

            assert_eq!(
                both.export_key(KeyFormat::Der).unwrap(),
                private_der,
                "{context}"
            );

            keys.push(key);
        }

        let encapsulation =
            hazmat::encapsulate(&pair.public_key, &field(record, "randomness")).unwrap();

        assert_eq!(
            encapsulation.ciphertext,
            field(record, "ciphertext"),
            "{context}"
        );

        let shared_secret = field(record, "sharedSecret");

        assert_eq!(encapsulation.shared_secret, shared_secret, "{context}");

        keys.push(pair.private_key);

        for key in &keys {
            let decapsulated = key.decapsulate(&encapsulation.ciphertext).unwrap();

            assert_eq!(decapsulated, shared_secret, "{context}");

            let rejected = key
                .decapsulate(&field(record, "tamperedCiphertext"))
                .unwrap();

            assert_eq!(rejected, field(record, "rejectedSecret"), "{context}");
        }
    });
}

fn check_signatures(name: &str) {
    parallel(&records(name, "signature"), |(header, record)| {
        let algorithm = signature_algorithm(&header["algorithm"]);

        let seed = field(header, "seed");

        let pair = hazmat::generate_signature_key_pair(algorithm, &seed).unwrap();

        if !record.contains_key("signature") {
            check_signature_key(algorithm, &pair, &seed, record);

            return;
        }

        let context = format!(
            "{} {} {}",
            algorithm.name(),
            record["mode"],
            record["preHash"]
        );

        let (message, context_bytes) = (field(record, "message"), field(record, "context"));

        let pre_hash = pre_hash(&record["preHash"]);

        let options = SignOptions {
            context: &context_bytes,
            deterministic: true,
            pre_hash,
        };

        let signature = if record["mode"] == "hazmat" {
            let randomness = field(record, "randomness");

            hazmat::sign(&pair.private_key, &message, &randomness, &options).unwrap()
        } else {
            pair.private_key.sign(&message, &options).unwrap()
        };

        assert_eq!(signature, field(record, "signature"), "{context}");

        let options = VerifyOptions {
            context: &context_bytes,
            pre_hash,
        };

        assert!(
            hazmat::verify(&pair.public_key, &signature, &message, &options),
            "{context}"
        );

        let verified = pair.public_key.verify(&signature, &message, &options);

        assert_eq!(verified, record["publicVerify"] == "true", "{context}");
    });
}

fn check_signature_key(
    algorithm: SignatureAlgorithm,
    pair: &crypto_pq::SignatureKeyPair,
    seed: &[u8],
    record: &Fields,
) {
    let context = format!("{} key", algorithm.name());

    let public = field(record, "publicKey");

    assert_eq!(
        pair.public_key.export_key(KeyFormat::Raw).unwrap(),
        public,
        "{context}"
    );

    let imported = algorithm
        .import_public_key(&public, KeyFormat::Raw)
        .unwrap();

    assert_eq!(imported, pair.public_key, "{context}");

    // ML-DSA keeps its seed as the raw private key; SLH-DSA has the 4n-byte key.
    let private = record
        .get("privateKey")
        .map_or_else(|| seed.to_vec(), |value| unhex(value));

    assert_eq!(
        pair.private_key.export_key(KeyFormat::Raw).unwrap(),
        private,
        "{context}"
    );

    let imported = algorithm
        .import_private_key(&private, KeyFormat::Raw)
        .unwrap();

    assert_eq!(imported.public_key(), pair.public_key, "{context}");

    for (format, suffix) in ENCODINGS {
        let encoded = field(record, &format!("publicKey{suffix}"));

        assert_eq!(
            pair.public_key.export_key(format).unwrap(),
            encoded,
            "{context}"
        );

        let imported = algorithm.import_public_key(&encoded, format).unwrap();

        assert_eq!(imported, pair.public_key, "{context}");

        let encoded = field(record, &format!("privateKey{suffix}"));

        assert_eq!(
            pair.private_key.export_key(format).unwrap(),
            encoded,
            "{context}"
        );

        let imported = algorithm.import_private_key(&encoded, format).unwrap();

        assert_eq!(
            imported.export_key(KeyFormat::Raw).unwrap(),
            private,
            "{context}"
        );
    }

    if !record.contains_key("expandedKey") {
        return;
    }

    let private_der = field(record, "privateKeyDer");

    assert!(private_der.ends_with(&der(0x80, seed)), "{context}");

    let expanded = field(record, "expandedKey");

    let key = algorithm
        .import_private_key(&expanded, KeyFormat::Raw)
        .unwrap();

    assert_eq!(
        key.export_key(KeyFormat::Raw).unwrap(),
        expanded,
        "{context}"
    );

    assert_eq!(key.public_key(), pair.public_key, "{context}");

    for (format, suffix) in ENCODINGS {
        let encoded = field(record, &format!("expandedKey{suffix}"));

        assert_eq!(key.export_key(format).unwrap(), encoded, "{context}");

        let imported = algorithm.import_private_key(&encoded, format).unwrap();

        assert_eq!(
            imported.export_key(KeyFormat::Raw).unwrap(),
            expanded,
            "{context}"
        );
    }

    let both = algorithm
        .import_private_key(&field(record, "bothKeyDer"), KeyFormat::Der)
        .unwrap();

    assert_eq!(
        both.export_key(KeyFormat::Der).unwrap(),
        private_der,
        "{context}"
    );
}

#[test]
fn mldsa() {
    check_signatures("cross/mldsa.txt");
}

#[test]
fn slhdsa() {
    check_signatures("cross/slhdsa.txt");
}

fn check_stateful(name: &str) {
    parallel(&records(name, "stateAfter"), |(header, record)| {
        let algorithm = stateful_algorithm(&header["algorithm"]);

        let context = format!("{} tcId {}", algorithm.name(), record["tcId"]);

        let levels = levels(record);

        let (public, message) = (field(record, "publicKey"), field(record, "message"));

        let (signature, state) = (field(record, "signature"), field(record, "state"));

        let index: u64 = record["index"].parse().unwrap();

        let remaining: u64 = record["remaining"].parse().unwrap();

        let store = MemoryStore::default();

        let seed = field(record, "seed");

        let mut pair = hazmat::generate_stateful_key_pair(
            algorithm,
            parameters(record, &levels),
            &seed,
            index,
            store.clone(),
        )
        .unwrap();

        assert_eq!(store.state(), Some(state.clone()), "{context}");

        assert_eq!(
            pair.public_key.export_key(KeyFormat::Raw).unwrap(),
            public,
            "{context}"
        );

        let imported = algorithm
            .import_public_key(&public, KeyFormat::Raw)
            .unwrap();

        assert_eq!(imported, pair.public_key, "{context}");

        for (format, suffix) in ENCODINGS {
            let encoded = field(record, &format!("publicKey{suffix}"));

            assert_eq!(
                pair.public_key.export_key(format).unwrap(),
                encoded,
                "{context}"
            );

            let imported = algorithm.import_public_key(&encoded, format).unwrap();

            assert_eq!(imported, pair.public_key, "{context}");
        }

        assert_eq!(
            pair.private_key.remaining_signatures(),
            remaining,
            "{context}"
        );

        assert_eq!(
            pair.private_key.sign(&message).unwrap(),
            signature,
            "{context}"
        );

        let after = field(record, "stateAfter");

        assert_eq!(store.state(), Some(after.clone()), "{context}");

        assert_eq!(
            pair.private_key.remaining_signatures(),
            remaining - 1,
            "{context}"
        );

        assert!(pair.public_key.verify(&signature, &message), "{context}");

        // The key loaded from the first state signs at the same index, the same way.
        let store = MemoryStore::holding(&state);

        let mut loaded = algorithm.load_private_key(store.clone()).unwrap();

        assert_eq!(loaded.public_key(), pair.public_key, "{context}");

        assert_eq!(loaded.remaining_signatures(), remaining, "{context}");

        assert_eq!(loaded.sign(&message).unwrap(), signature, "{context}");

        assert_eq!(store.state(), Some(after), "{context}");

        assert_eq!(loaded.remaining_signatures(), remaining - 1, "{context}");
    });
}

#[test]
fn hss() {
    check_stateful("cross/hss.txt");
}

#[test]
fn xmss() {
    check_stateful("cross/xmss.txt");
}

// The result of one error-table record: "ok", "true", "false" or an error code, with the output
// and remaining signatures it produced.
struct Outcome {
    result: String,
    output: Option<Vec<u8>>,
    remaining: Option<u64>,
}

fn finished(result: Result<Vec<u8>, Error>) -> Outcome {
    match result {
        Ok(output) => Outcome {
            result: "ok".into(),
            output: Some(output),
            remaining: None,
        },
        Err(error) => Outcome {
            result: error.code().into(),
            output: None,
            remaining: None,
        },
    }
}

fn answered(value: bool) -> Outcome {
    Outcome {
        result: value.to_string(),
        output: None,
        remaining: None,
    }
}

fn counted(result: Result<(Vec<u8>, u64), Error>) -> Outcome {
    match result {
        Ok((output, remaining)) => Outcome {
            remaining: Some(remaining),
            ..finished(Ok(output))
        },
        Err(error) => finished(Err(error)),
    }
}

fn execute(header: &Fields, record: &Fields) -> Outcome {
    let operation = record["operation"].as_str();

    let format = || key_format(&record["format"]);

    let (data, key) = (field(record, "input"), field(record, "key"));

    let (message, context) = (field(record, "message"), field(record, "context"));

    let randomness = field(record, "randomness");

    let pre_hash = record.get("preHash").and_then(|name| pre_hash(name));

    let sign_options = SignOptions {
        context: &context,
        deterministic: true,
        pre_hash,
    };

    let verify_options = VerifyOptions {
        context: &context,
        pre_hash,
    };

    match (algorithm(&header["algorithm"]), operation) {
        (Algorithm::Kem(a), "importPublicKey") => finished(
            a.import_public_key(&data, format())
                .and_then(|k| k.export_key(KeyFormat::Raw)),
        ),
        (Algorithm::Kem(a), "importPrivateKey") => finished(
            a.import_private_key(&data, format())
                .and_then(|k| k.public_key().export_key(KeyFormat::Raw)),
        ),
        (Algorithm::Kem(a), "exportPublicKey") => finished(
            hazmat::generate_kem_key_pair(a, &key).and_then(|p| p.public_key.export_key(format())),
        ),
        (Algorithm::Kem(a), "exportPrivateKey") => finished(
            hazmat::generate_kem_key_pair(a, &key).and_then(|p| p.private_key.export_key(format())),
        ),
        (Algorithm::Kem(a), "generate") => finished(
            hazmat::generate_kem_key_pair(a, &data)
                .and_then(|p| p.public_key.export_key(KeyFormat::Raw)),
        ),
        (Algorithm::Kem(a), "encapsulate") => finished(
            a.import_public_key(&key, KeyFormat::Raw)
                .and_then(|k| hazmat::encapsulate(&k, &randomness))
                .map(|e| [e.shared_secret, e.ciphertext].concat()),
        ),
        (Algorithm::Kem(a), "decapsulate") => finished(
            a.import_private_key(&key, KeyFormat::Raw)
                .and_then(|k| k.decapsulate(&data)),
        ),
        (Algorithm::Signature(a), "importPublicKey") => finished(
            a.import_public_key(&data, format())
                .and_then(|k| k.export_key(KeyFormat::Raw)),
        ),
        (Algorithm::Signature(a), "importPrivateKey") => finished(
            a.import_private_key(&data, format())
                .and_then(|k| k.public_key().export_key(KeyFormat::Raw)),
        ),
        (Algorithm::Signature(a), "generate") => finished(
            hazmat::generate_signature_key_pair(a, &data)
                .and_then(|p| p.public_key.export_key(KeyFormat::Raw)),
        ),
        (Algorithm::Signature(a), "sign") => finished(
            a.import_private_key(&key, KeyFormat::Raw)
                .and_then(|k| k.sign(&message, &sign_options)),
        ),
        (Algorithm::Signature(a), "hazmatSign") => finished(
            a.import_private_key(&key, KeyFormat::Raw)
                .and_then(|k| hazmat::sign(&k, &message, &randomness, &sign_options)),
        ),
        (Algorithm::Signature(a), "verify") => {
            let public_key = a.import_public_key(&key, KeyFormat::Raw).unwrap();

            answered(public_key.verify(&data, &message, &verify_options))
        }
        (Algorithm::Signature(a), "hazmatVerify") => {
            let public_key = a.import_public_key(&key, KeyFormat::Raw).unwrap();

            answered(hazmat::verify(
                &public_key,
                &data,
                &message,
                &verify_options,
            ))
        }
        (Algorithm::Stateful(a), "importPublicKey") => finished(
            a.import_public_key(&data, format())
                .and_then(|k| k.export_key(KeyFormat::Raw)),
        ),
        (Algorithm::Stateful(a), "generate") => {
            let levels = levels(record);

            let index = record["index"].parse().unwrap();

            let store = MemoryStore::default();

            counted(
                hazmat::generate_stateful_key_pair(
                    a,
                    parameters(record, &levels),
                    &data,
                    index,
                    store,
                )
                .map(|p| {
                    (
                        p.public_key.export_key(KeyFormat::Raw).unwrap(),
                        p.private_key.remaining_signatures(),
                    )
                }),
            )
        }
        (Algorithm::Stateful(a), "loadPrivateKey") => {
            counted(a.load_private_key(MemoryStore::holding(&data)).map(|k| {
                (
                    k.public_key().export_key(KeyFormat::Raw).unwrap(),
                    k.remaining_signatures(),
                )
            }))
        }
        (Algorithm::Stateful(a), "sign") => finished(
            a.load_private_key(MemoryStore::holding(&data))
                .and_then(|mut k| k.sign(&message)),
        ),
        (Algorithm::Stateful(a), "verify") => {
            let public_key = a.import_public_key(&key, KeyFormat::Raw).unwrap();

            answered(public_key.verify(&data, &message))
        }
        (_, operation) => panic!("unknown operation {operation}"),
    }
}

// Every disagreement is collected, so that one run lists them all.
#[test]
fn errors() {
    let failures = Mutex::new(Vec::new());

    let cases = records("cross/errors.txt", "result");

    parallel(&cases, |(header, record)| {
        let outcome = execute(header, record);

        let expected_output = record.get("output").map(|value| unhex(value));

        let expected_remaining = record.get("remaining").map(|value| value.parse().unwrap());

        let mismatched = outcome.result != record["result"]
            || expected_output.is_some_and(|output| outcome.output.as_ref() != Some(&output))
            || expected_remaining.is_some_and(|remaining| outcome.remaining != Some(remaining));

        if mismatched {
            failures.lock().unwrap().push(format!(
                "{}: {}: got {}, expected {}",
                header["algorithm"], record["name"], outcome.result, record["result"]
            ));
        }
    });

    let failures = failures.into_inner().unwrap();

    assert!(
        failures.is_empty(),
        "{} of {} cases disagree:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

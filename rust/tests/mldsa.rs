mod vectors;

use crypto_pq::{
    Error, KeyFormat, KeyGenOptions, ML_DSA_44, ML_DSA_65, ML_DSA_87, PreHash, SHA_224, SHA_256,
    SHA_384, SHA_512, SHA_512_224, SHA_512_256, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128,
    SHAKE256, SignOptions, SignatureAlgorithm, VerifyOptions, hazmat,
};
use vectors::{Fields, der, parallel, records, unhex};

const ALGORITHMS: [(&str, SignatureAlgorithm); 3] = [
    ("ML-DSA-44", ML_DSA_44),
    ("ML-DSA-65", ML_DSA_65),
    ("ML-DSA-87", ML_DSA_87),
];

const PRE_HASHES: [&str; 12] = [
    "SHA2-224",
    "SHA2-256",
    "SHA2-384",
    "SHA2-512",
    "SHA2-512/224",
    "SHA2-512/256",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "SHAKE-128",
    "SHAKE-256",
];

fn algorithm(name: &str) -> SignatureAlgorithm {
    ALGORITHMS
        .iter()
        .find(|(known, _)| *known == name)
        .map(|&(_, algorithm)| algorithm)
        .unwrap_or_else(|| panic!("unknown parameter set {name}"))
}

fn named_pre_hash(label: &str) -> PreHash {
    match label {
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
        _ => panic!("unknown hash {label}"),
    }
}

fn pre_hash(header: &Fields, record: &Fields) -> Option<PreHash> {
    (header["preHash"] != "pure").then(|| named_pre_hash(&record["hashAlg"]))
}

fn oid(algorithm: SignatureAlgorithm) -> Vec<u8> {
    let arc = ALGORITHMS
        .iter()
        .position(|&(_, known)| known == algorithm)
        .expect("ML-DSA") as u8;

    der(
        0x06,
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 17 + arc],
    )
}

fn pkcs8(algorithm: SignatureAlgorithm, private_key: &[u8]) -> Vec<u8> {
    let body = [
        der(0x02, &[0]),
        der(0x30, &oid(algorithm)),
        der(0x04, private_key),
    ];

    der(0x30, &body.concat())
}

#[test]
fn acvp_key_generation() {
    parallel(
        &records("acvp/ML-DSA-keyGen.txt", "sk"),
        |(header, record)| {
            let algorithm = algorithm(&header["parameterSet"]);

            let (seed, pk, sk) = (
                unhex(&record["seed"]),
                unhex(&record["pk"]),
                unhex(&record["sk"]),
            );

            let context = format!("tcId {}", record["tcId"]);

            let pair = hazmat::generate_signature_key_pair(algorithm, &seed).unwrap();

            assert_eq!(
                pair.public_key.export_key(KeyFormat::Raw).unwrap(),
                pk,
                "{context}"
            );

            assert_eq!(
                pair.private_key.export_key(KeyFormat::Raw).unwrap(),
                seed,
                "{context}"
            );

            let expanded = algorithm.import_private_key(&sk, KeyFormat::Raw).unwrap();

            assert_eq!(expanded.public_key(), pair.public_key, "{context}");

            assert_eq!(
                expanded.export_key(KeyFormat::Raw).unwrap(),
                sk,
                "{context}"
            );

            let both = pkcs8(
                algorithm,
                &der(0x30, &[der(0x04, &seed), der(0x04, &sk)].concat()),
            );

            let imported = algorithm.import_private_key(&both, KeyFormat::Der).unwrap();

            assert_eq!(
                imported.export_key(KeyFormat::Raw).unwrap(),
                seed,
                "{context}"
            );

            let mut corrupted = sk.clone();

            *corrupted.last_mut().unwrap() ^= 1;

            let result = algorithm.import_private_key(&corrupted, KeyFormat::Raw);

            assert_eq!(result.err(), Some(Error::InvalidPrivateKey), "{context}");
        },
    );
}

#[test]
fn acvp_signature_generation() {
    parallel(
        &records("acvp/ML-DSA-sigGen.txt", "signature"),
        |(header, record)| {
            let algorithm = algorithm(&header["parameterSet"]);

            let context = format!("tcId {}", record["tcId"]);

            let private_key = if header["keyFormat"] == "seed" {
                hazmat::generate_signature_key_pair(algorithm, &unhex(&record["seed"]))
                    .unwrap()
                    .private_key
            } else {
                algorithm
                    .import_private_key(&unhex(&record["sk"]), KeyFormat::Raw)
                    .unwrap()
            };

            let pk = private_key.public_key().export_key(KeyFormat::Raw).unwrap();

            assert_eq!(pk, unhex(&record["pk"]), "{context}");

            let randomness = if header["deterministic"] == "true" {
                vec![0; 32]
            } else {
                unhex(&record["rnd"])
            };

            let (message, context_bytes) = (unhex(&record["message"]), unhex(&record["context"]));

            let options = SignOptions {
                context: &context_bytes,
                pre_hash: pre_hash(header, record),
                ..SignOptions::default()
            };

            let signature = hazmat::sign(&private_key, &message, &randomness, &options).unwrap();

            assert_eq!(signature, unhex(&record["signature"]), "{context}");

            let options = VerifyOptions {
                context: &context_bytes,
                pre_hash: pre_hash(header, record),
            };

            let public_key = private_key.public_key();

            assert!(
                hazmat::verify(&public_key, &signature, &message, &options),
                "{context}"
            );
        },
    );
}

#[test]
fn acvp_signature_verification() {
    parallel(
        &records("acvp/ML-DSA-sigVer.txt", "signature"),
        |(header, record)| {
            let public_key = algorithm(&header["parameterSet"])
                .import_public_key(&unhex(&record["pk"]), KeyFormat::Raw)
                .unwrap();

            let context = unhex(&record["context"]);

            let options = VerifyOptions {
                context: &context,
                pre_hash: pre_hash(header, record),
            };

            let result = hazmat::verify(
                &public_key,
                &unhex(&record["signature"]),
                &unhex(&record["message"]),
                &options,
            );

            let expected = record["testPassed"] == "true";

            assert_eq!(
                result, expected,
                "tcId {} {}",
                record["tcId"], record["reason"]
            );
        },
    );
}

#[test]
fn wycheproof_verification() {
    parallel(
        &records("wycheproof/mldsa_verify.txt", "tcId"),
        |(header, record)| {
            let algorithm = algorithm(&header["parameterSet"]);

            let key = unhex(&header["publicKey"]);

            let context = format!("tcId {} {}", record["tcId"], header["parameterSet"]);

            if key.len() != algorithm.public_key_size() {
                let result = algorithm.import_public_key(&key, KeyFormat::Raw);

                assert_eq!(result.err(), Some(Error::InvalidLength), "{context}");

                return;
            }

            let public_key = algorithm.import_public_key(&key, KeyFormat::Raw).unwrap();

            if !header["publicKeyDer"].is_empty() {
                let from_der = algorithm
                    .import_public_key(&unhex(&header["publicKeyDer"]), KeyFormat::Der)
                    .unwrap();

                assert_eq!(from_der, public_key, "{context}");
            }

            let context_bytes = unhex(record.get("ctx").map_or("", String::as_str));

            let options = VerifyOptions {
                context: &context_bytes,
                ..VerifyOptions::default()
            };

            let result =
                public_key.verify(&unhex(&record["sig"]), &unhex(&record["msg"]), &options);

            assert_eq!(result, record["result"] == "valid", "{context}");
        },
    );
}

#[test]
fn wycheproof_deterministic_signing() {
    let found = records("wycheproof/mldsa_sign_seed.txt", "tcId");

    let signing: Vec<_> = found
        .iter()
        .filter(|(_, record)| record.contains_key("msg"))
        .collect();

    parallel(&signing, |(header, record)| {
        let algorithm = algorithm(&header["parameterSet"]);

        let seed = unhex(&header["privateSeed"]);

        let context_bytes = unhex(record.get("ctx").map_or("", String::as_str));

        let flags = record.get("flags").map_or("", String::as_str);

        let context = format!("tcId {} {}", record["tcId"], header["parameterSet"]);

        if flags.contains("IncorrectPrivateKeyLength") {
            let result = hazmat::generate_signature_key_pair(algorithm, &seed);

            assert_eq!(result.err(), Some(Error::InvalidLength), "{context}");

            return;
        }

        let private_key = if header["privateKeyPkcs8"].is_empty() {
            hazmat::generate_signature_key_pair(algorithm, &seed)
                .unwrap()
                .private_key
        } else {
            algorithm
                .import_private_key(&unhex(&header["privateKeyPkcs8"]), KeyFormat::Der)
                .unwrap()
        };

        let pk = private_key.public_key().export_key(KeyFormat::Raw).unwrap();

        assert_eq!(pk, unhex(&header["publicKey"]), "{context}");

        let message = unhex(&record["msg"]);

        if flags.contains("InvalidContext") {
            let options = SignOptions {
                context: &context_bytes,
                ..SignOptions::default()
            };

            let result = private_key.sign(&message, &options);

            assert_eq!(result.err(), Some(Error::InvalidContext), "{context}");
        } else if flags.contains("Randomized") {
            let options = VerifyOptions {
                context: &context_bytes,
                ..VerifyOptions::default()
            };

            let public_key = private_key.public_key();

            assert!(
                public_key.verify(&unhex(&record["sig"]), &message, &options),
                "{context}"
            );
        } else {
            let options = SignOptions {
                context: &context_bytes,
                deterministic: true,
                ..SignOptions::default()
            };

            let signature = private_key.sign(&message, &options).unwrap();

            assert_eq!(signature, unhex(&record["sig"]), "{context}");
        }
    });
}

#[test]
fn round_trip() {
    for (_, algorithm) in ALGORITHMS {
        let pair = algorithm
            .generate_key_pair(&KeyGenOptions::default())
            .unwrap();

        let (private_key, public_key) = (&pair.private_key, &pair.public_key);

        let message = b"message";

        let with_context = SignOptions {
            context: b"context",
            ..SignOptions::default()
        };

        let verify_context = VerifyOptions {
            context: b"context",
            ..VerifyOptions::default()
        };

        let plain = VerifyOptions::default();

        let signature = private_key.sign(message, &with_context).unwrap();

        assert_eq!(signature.len(), algorithm.signature_size());

        assert!(public_key.verify(&signature, message, &verify_context));

        assert!(!public_key.verify(&signature, message, &plain));

        assert!(!public_key.verify(&signature, b"other", &verify_context));

        let truncated = &signature[..signature.len() - 1];

        assert!(!public_key.verify(truncated, message, &verify_context));

        let long = [0; 256];

        let long_context = VerifyOptions {
            context: &long,
            ..VerifyOptions::default()
        };

        assert!(!public_key.verify(&signature, message, &long_context));

        let long_signing = SignOptions {
            context: &long,
            ..SignOptions::default()
        };

        assert_eq!(
            private_key.sign(message, &long_signing).err(),
            Some(Error::InvalidContext)
        );

        let deterministic = SignOptions {
            deterministic: true,
            ..SignOptions::default()
        };

        let first = private_key.sign(message, &deterministic).unwrap();

        assert_eq!(first, private_key.sign(message, &deterministic).unwrap());

        let randomized = SignOptions::default();

        assert_ne!(
            private_key.sign(message, &randomized).unwrap(),
            private_key.sign(message, &randomized).unwrap()
        );

        let hashed_options = SignOptions {
            pre_hash: Some(SHA_512.into()),
            ..SignOptions::default()
        };

        let hashed = private_key.sign(message, &hashed_options).unwrap();

        let verify_hashed = VerifyOptions {
            pre_hash: Some(SHA_512.into()),
            ..VerifyOptions::default()
        };

        assert!(public_key.verify(&hashed, message, &verify_hashed));

        assert!(!public_key.verify(&hashed, message, &plain));

        let weak = SignOptions {
            pre_hash: Some(SHA_224.into()),
            ..SignOptions::default()
        };

        assert_eq!(
            private_key.sign(message, &weak).err(),
            Some(Error::InvalidOption)
        );

        let weak_and_long = SignOptions {
            context: &long,
            pre_hash: Some(SHA_224.into()),
            ..SignOptions::default()
        };

        assert_eq!(
            private_key.sign(message, &weak_and_long).err(),
            Some(Error::InvalidOption)
        );
    }
}

#[test]
fn pre_hash_strength() {
    let allowed: [(&str, &[&str]); 3] = [
        (
            "ML-DSA-44",
            &[
                "SHA2-256",
                "SHA2-384",
                "SHA2-512",
                "SHA2-512/256",
                "SHA3-256",
                "SHA3-384",
                "SHA3-512",
                "SHAKE-128",
                "SHAKE-256",
            ],
        ),
        (
            "ML-DSA-65",
            &["SHA2-384", "SHA2-512", "SHA3-384", "SHA3-512", "SHAKE-256"],
        ),
        ("ML-DSA-87", &["SHA2-512", "SHA3-512", "SHAKE-256"]),
    ];

    for (name, permitted) in allowed {
        let private_key = hazmat::generate_signature_key_pair(algorithm(name), &[0; 32])
            .unwrap()
            .private_key;

        let public_key = private_key.public_key();

        for label in PRE_HASHES {
            let sign_options = SignOptions {
                pre_hash: Some(named_pre_hash(label)),
                ..SignOptions::default()
            };

            let verify_options = VerifyOptions {
                pre_hash: Some(named_pre_hash(label)),
                ..VerifyOptions::default()
            };

            if permitted.contains(&label) {
                let signature = private_key.sign(b"m", &sign_options).unwrap();

                assert!(
                    public_key.verify(&signature, b"m", &verify_options),
                    "{name} {label}"
                );
            } else {
                let result = private_key.sign(b"m", &sign_options);

                assert_eq!(result.err(), Some(Error::InvalidOption), "{name} {label}");

                let signature = hazmat::sign(&private_key, b"m", &[0; 32], &sign_options).unwrap();

                assert!(
                    hazmat::verify(&public_key, &signature, b"m", &verify_options),
                    "{name} {label}"
                );

                assert!(
                    !public_key.verify(&signature, b"m", &verify_options),
                    "{name} {label}"
                );
            }
        }
    }
}

#[test]
fn formats() {
    for (name, algorithm) in ALGORITHMS {
        let pair = algorithm
            .generate_key_pair(&KeyGenOptions { self_test: false })
            .unwrap();

        for format in [KeyFormat::Raw, KeyFormat::Der, KeyFormat::Pem] {
            let exported = pair.public_key.export_key(format).unwrap();

            let public_key = algorithm.import_public_key(&exported, format).unwrap();

            assert_eq!(public_key, pair.public_key, "{name}");

            let exported = pair.private_key.export_key(format).unwrap();

            let private_key = algorithm.import_private_key(&exported, format).unwrap();

            assert_eq!(
                private_key.export_key(KeyFormat::Raw).unwrap(),
                pair.private_key.export_key(KeyFormat::Raw).unwrap(),
                "{name}"
            );
        }

        let private_der = pair.private_key.export_key(KeyFormat::Der).unwrap();

        assert_eq!(private_der[private_der.len() - 34..][..2], [0x80, 0x20]);

        let seed = pair.private_key.export_key(KeyFormat::Raw).unwrap();

        let regenerated = hazmat::generate_signature_key_pair(algorithm, &seed).unwrap();

        assert_eq!(regenerated.public_key, pair.public_key);

        let other = if algorithm == ML_DSA_44 {
            ML_DSA_65
        } else {
            ML_DSA_44
        };

        let public_der = pair.public_key.export_key(KeyFormat::Der).unwrap();

        assert_eq!(
            other.import_public_key(&public_der, KeyFormat::Der).err(),
            Some(Error::AlgorithmMismatch)
        );

        assert_eq!(
            algorithm.import_private_key(&[0; 33], KeyFormat::Raw).err(),
            Some(Error::InvalidLength)
        );
    }
}

#[test]
fn expanded_keys() {
    let found = records("acvp/ML-DSA-keyGen.txt", "sk");

    let (header, record) = &found[0];

    let algorithm = algorithm(&header["parameterSet"]);

    let (seed, sk) = (unhex(&record["seed"]), unhex(&record["sk"]));

    let expanded_der = pkcs8(algorithm, &der(0x04, &sk));

    let expanded = algorithm
        .import_private_key(&expanded_der, KeyFormat::Der)
        .unwrap();

    assert_eq!(expanded.export_key(KeyFormat::Der).unwrap(), expanded_der);

    assert_eq!(
        expanded.public_key().export_key(KeyFormat::Raw).unwrap(),
        unhex(&record["pk"])
    );

    let deterministic = SignOptions {
        deterministic: true,
        ..SignOptions::default()
    };

    let from_seed = hazmat::generate_signature_key_pair(algorithm, &seed)
        .unwrap()
        .private_key;

    assert_eq!(
        expanded.sign(b"m", &deterministic).unwrap(),
        from_seed.sign(b"m", &deterministic).unwrap()
    );

    let mut other_seed = seed.clone();

    other_seed[0] ^= 1;

    let mismatched = der(0x30, &[der(0x04, &other_seed), der(0x04, &sk)].concat());

    assert_eq!(
        algorithm
            .import_private_key(&pkcs8(algorithm, &mismatched), KeyFormat::Der)
            .err(),
        Some(Error::InvalidPrivateKey)
    );

    let mut out_of_range = sk.clone();

    out_of_range[128] = 0xFF;

    assert_eq!(
        algorithm
            .import_private_key(&out_of_range, KeyFormat::Raw)
            .err(),
        Some(Error::InvalidPrivateKey)
    );

    let invalid = [
        pkcs8(algorithm, &der(0x04, &sk[1..])),
        pkcs8(algorithm, &der(0x80, &seed[1..])),
        pkcs8(algorithm, &der(0x30, &der(0x04, &seed))),
    ];

    for data in invalid {
        assert_eq!(
            algorithm.import_private_key(&data, KeyFormat::Der).err(),
            Some(Error::InvalidEncoding)
        );
    }

    let public_key = expanded.public_key();

    let raw = public_key.export_key(KeyFormat::Raw).unwrap();

    let short = der(
        0x30,
        &[
            der(0x30, &oid(algorithm)),
            der(0x03, &[&[0][..], &raw[1..]].concat()),
        ]
        .concat(),
    );

    assert_eq!(
        algorithm.import_public_key(&short, KeyFormat::Der).err(),
        Some(Error::InvalidEncoding)
    );

    assert_eq!(
        algorithm.import_public_key(&raw[1..], KeyFormat::Raw).err(),
        Some(Error::InvalidLength)
    );
}

#[test]
fn properties() {
    let sizes = [
        (ML_DSA_44, "ML-DSA-44", 1312, 2420),
        (ML_DSA_65, "ML-DSA-65", 1952, 3309),
        (ML_DSA_87, "ML-DSA-87", 2592, 4627),
    ];

    for (algorithm, name, public_key_size, signature_size) in sizes {
        assert_eq!(algorithm.name(), name);

        assert_eq!(algorithm.public_key_size(), public_key_size);

        assert_eq!(algorithm.signature_size(), signature_size);
    }

    let pair = hazmat::generate_signature_key_pair(ML_DSA_65, &[1; 32]).unwrap();

    assert_eq!(
        format!("{:?}", pair.private_key),
        "SignaturePrivateKey { algorithm: SignatureAlgorithm(\"ML-DSA-65\"), .. }"
    );

    assert_eq!(pair.private_key.algorithm(), ML_DSA_65);

    assert_eq!(
        hazmat::generate_signature_key_pair(ML_DSA_65, &[1; 31]).err(),
        Some(Error::InvalidLength)
    );

    let options = SignOptions::default();

    assert_eq!(
        hazmat::sign(&pair.private_key, b"m", &[0; 31], &options).err(),
        Some(Error::InvalidLength)
    );
}

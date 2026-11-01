mod vectors;

use crypto_pq::{
    Error, KeyFormat, KeyGenOptions, ML_DSA_44, ML_DSA_65, ML_DSA_87, PreHash, SHA_224, SHA_256,
    SHA_384, SHA_512, SHA_512_224, SHA_512_256, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128,
    SHAKE256, SignOptions, SignatureAlgorithm, SignaturePrivateKey, VerifyOptions, hazmat,
};
use vectors::{Fields, der, example_keys, parallel, records, unhex};

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
                *pair.private_key.export_key(KeyFormat::Raw).unwrap(),
                *seed,
                "{context}"
            );

            let expanded = algorithm.import_private_key(&sk, KeyFormat::Raw).unwrap();

            assert_eq!(expanded.public_key(), pair.public_key, "{context}");

            assert_eq!(
                *expanded.export_key(KeyFormat::Raw).unwrap(),
                *sk,
                "{context}"
            );

            let both = pkcs8(
                algorithm,
                &der(0x30, &[der(0x04, &seed), der(0x04, &sk)].concat()),
            );

            let imported = algorithm.import_private_key(&both, KeyFormat::Der).unwrap();

            assert_eq!(
                *imported.export_key(KeyFormat::Raw).unwrap(),
                *seed,
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
    check_signature_generation("acvp/ML-DSA-sigGen.txt");
}

// Every external signing test of ACVP, in both key formats, and the older projection, whose keys
// are expanded only.
#[test]
#[ignore = "weekly (fuzz.yml): the full ACVP set"]
fn acvp_full_signature_generation() {
    check_signature_generation("acvp-full/ML-DSA-sigGen.txt");

    check_signature_generation("acvp-full/ML-DSA-sigGen-v1.txt");

    check_internal_signature_generation("acvp-full/ML-DSA-sigGen-internal.txt");

    check_internal_signature_generation("acvp-full/ML-DSA-sigGen-v1-internal.txt");
}

// The key of an ACVP signing test, from its seed or its expanded form, checked against pk.
fn signing_key(header: &Fields, record: &Fields) -> SignaturePrivateKey {
    let algorithm = algorithm(&header["parameterSet"]);

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

    assert_eq!(pk, unhex(&record["pk"]), "tcId {}", record["tcId"]);

    private_key
}

// rnd, which the deterministic variant fixes to zero (FIPS 204, Algorithm 2).
fn signing_randomness(header: &Fields, record: &Fields) -> Vec<u8> {
    if header["deterministic"] == "true" {
        vec![0; 32]
    } else {
        unhex(&record["rnd"])
    }
}

fn check_signature_generation(name: &str) {
    parallel(&records(name, "signature"), |(header, record)| {
        let context = format!("tcId {}", record["tcId"]);

        let private_key = signing_key(header, record);

        let randomness = signing_randomness(header, record);

        let (message, context_bytes) = (unhex(&record["message"]), unhex(&record["context"]));

        let mut options = SignOptions::default().with_context(&context_bytes);

        options.pre_hash = pre_hash(header, record);

        let signature = hazmat::sign(&private_key, &message, &randomness, &options).unwrap();

        assert_eq!(signature, unhex(&record["signature"]), "{context}");

        let mut options = VerifyOptions::default().with_context(&context_bytes);

        options.pre_hash = pre_hash(header, record);

        let public_key = private_key.public_key();

        assert!(
            hazmat::verify(&public_key, &signature, &message, &options),
            "{context}"
        );
    });
}

// The groups of the internal interface that take M' (SPEC D-65); those that take mu are listed by
// their test numbers only, and counted as the omission SPEC 19.4 permits.
fn internal_records(name: &str) -> Vec<(Fields, Fields)> {
    let (omitted, run): (Vec<_>, Vec<_>) = records(name, "signature")
        .into_iter()
        .partition(|(header, _)| header["externalMu"] == "true");

    assert!(
        omitted.iter().all(|(_, record)| record.len() == 1),
        "{name}: an external-mu test carries data"
    );

    assert!(
        run.iter()
            .all(|(header, _)| header["signatureInterface"] == "internal"),
        "{name}: a test of another interface"
    );

    eprintln!(
        "{name}: {} internal tests run, {} external-mu tests left out (SPEC 19.4)",
        run.len(),
        omitted.len()
    );

    run
}

#[test]
fn acvp_internal_signature_generation() {
    check_internal_signature_generation("acvp/ML-DSA-sigGen-internal.txt");
}

fn check_internal_signature_generation(name: &str) {
    parallel(&internal_records(name), |(header, record)| {
        let context = format!("tcId {}", record["tcId"]);

        let private_key = signing_key(header, record);

        let randomness = signing_randomness(header, record);

        let message = unhex(&record["message"]);

        let signature = hazmat::sign_internal(&private_key, &message, &randomness).unwrap();

        assert_eq!(signature, unhex(&record["signature"]), "{context}");

        let public_key = private_key.public_key();

        assert!(
            hazmat::verify_internal(&public_key, &signature, &message),
            "{context}"
        );
    });
}

#[test]
fn acvp_internal_signature_verification() {
    parallel(
        &internal_records("acvp/ML-DSA-sigVer-internal.txt"),
        |(header, record)| {
            let public_key = algorithm(&header["parameterSet"])
                .import_public_key(&unhex(&record["pk"]), KeyFormat::Raw)
                .unwrap();

            let result = hazmat::verify_internal(
                &public_key,
                &unhex(&record["signature"]),
                &unhex(&record["message"]),
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

// M' = 0 || |ctx| || ctx || M is the pure interface (FIPS 204, Algorithm 2), so the internal one
// gives the same signature; it checks the lengths as hazmat::sign does.
#[test]
fn internal_interface() {
    for (_, algorithm) in ALGORITHMS {
        let pair = hazmat::generate_signature_key_pair(algorithm, &[7; 32]).unwrap();

        let (private_key, public_key) = (&pair.private_key, &pair.public_key);

        let representative = [&[0, 7][..], b"context", b"message"].concat();

        let options = SignOptions::default().with_context(b"context");

        let rnd = [9; 32];

        let pure = hazmat::sign(private_key, b"message", &rnd, &options).unwrap();

        let internal = hazmat::sign_internal(private_key, &representative, &rnd).unwrap();

        assert_eq!(pure, internal);

        assert!(hazmat::verify_internal(
            public_key,
            &internal,
            &representative
        ));

        assert!(!hazmat::verify_internal(public_key, &internal, b"message"));

        assert!(!hazmat::verify_internal(
            public_key,
            &internal[1..],
            &representative
        ));

        assert_eq!(
            hazmat::sign_internal(private_key, &representative, &rnd[1..]).err(),
            Some(Error::InvalidLength)
        );
    }
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

            let mut options = VerifyOptions::default().with_context(&context);

            options.pre_hash = pre_hash(header, record);

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

            let options = VerifyOptions::default().with_context(&context_bytes);

            let result =
                public_key.verify(&unhex(&record["sig"]), &unhex(&record["msg"]), &options);

            assert_eq!(result, record["result"] == "valid", "{context}");
        },
    );
}

// The tests that give only mu are external-mu signing, which crypto-pq does not expose (SPEC
// 9.1.5); SPEC 19.4 permits leaving them out if they are counted and reported.
fn without_external_mu<'a>(
    name: &str,
    found: &'a [(Fields, Fields)],
    expected: usize,
) -> Vec<&'a (Fields, Fields)> {
    let (signing, external_mu): (Vec<_>, Vec<_>) = found
        .iter()
        .partition(|(_, record)| record.contains_key("msg"));

    println!("{name}: {} external-mu tests left out", external_mu.len());

    assert_eq!(external_mu.len(), expected, "{name}");

    assert!(
        external_mu
            .iter()
            .all(|(_, record)| record.contains_key("mu"))
    );

    signing
}

#[test]
fn wycheproof_deterministic_signing() {
    let name = "wycheproof/mldsa_sign_seed.txt";

    let found = records(name, "tcId");

    let signing = without_external_mu(name, &found, 42);

    parallel(&signing, |(header, record)| {
        let algorithm = algorithm(&header["parameterSet"]);

        let seed = unhex(&header["privateSeed"]);

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

        check_wycheproof_signing(&private_key, header, record, &context);
    });
}

// Signing with expanded private keys.
#[test]
fn wycheproof_expanded_key_signing() {
    let name = "wycheproof/mldsa_sign_noseed.txt";

    let found = records(name, "tcId");

    let signing = without_external_mu(name, &found, 27);

    parallel(&signing, |(header, record)| {
        let algorithm = algorithm(&header["parameterSet"]);

        let key = unhex(&header["privateKey"]);

        let flags = record.get("flags").map_or("", String::as_str);

        let context = format!("tcId {} {}", record["tcId"], header["parameterSet"]);

        let imported = algorithm.import_private_key(&key, KeyFormat::Raw);

        if flags.contains("IncorrectPrivateKeyLength") {
            assert_eq!(imported.err(), Some(Error::InvalidLength), "{context}");

            return;
        }

        if flags.contains("InvalidPrivateKey") {
            assert_eq!(imported.err(), Some(Error::InvalidPrivateKey), "{context}");

            return;
        }

        let private_key = imported.unwrap_or_else(|error| panic!("{context}: {error}"));

        check_wycheproof_signing(&private_key, header, record, &context);
    });
}

// The public key, then by the flags: a refused context, a randomized signature that verifies, or
// the deterministic signature.
fn check_wycheproof_signing(
    private_key: &SignaturePrivateKey,
    header: &Fields,
    record: &Fields,
    context: &str,
) {
    let pk = private_key.public_key().export_key(KeyFormat::Raw).unwrap();

    assert_eq!(pk, unhex(&header["publicKey"]), "{context}");

    let message = unhex(&record["msg"]);

    let context_bytes = unhex(record.get("ctx").map_or("", String::as_str));

    let flags = record.get("flags").map_or("", String::as_str);

    if flags.contains("InvalidContext") {
        let options = SignOptions::default().with_context(&context_bytes);

        let result = private_key.sign(&message, &options);

        assert_eq!(result.err(), Some(Error::InvalidContext), "{context}");
    } else if flags.contains("Randomized") {
        let options = VerifyOptions::default().with_context(&context_bytes);

        assert!(
            private_key
                .public_key()
                .verify(&unhex(&record["sig"]), &message, &options),
            "{context}"
        );
    } else {
        let options = SignOptions::default()
            .with_context(&context_bytes)
            .with_deterministic(true);

        let signature = private_key.sign(&message, &options).unwrap();

        assert_eq!(signature, unhex(&record["sig"]), "{context}");
    }
}

// RFC 9881, Appendix C: every example key, its public key and what it exports as; the
// inconsistent seed and expanded keys of C.4 must be refused.
#[test]
fn rfc9881_example_keys() {
    example_keys("rfc/mldsa_keys.txt", |record, data, format| {
        let algorithm = algorithm(&record["algorithm"]);

        if record["kind"] == "public" {
            let key = algorithm.import_public_key(data, format)?;

            Ok((
                key.export_key(KeyFormat::Raw)?,
                key.export_key(KeyFormat::Der)?,
            ))
        } else {
            let key = algorithm.import_private_key(data, format)?;

            Ok((
                key.public_key().export_key(KeyFormat::Raw)?,
                key.export_key(KeyFormat::Der)?.to_vec(),
            ))
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

        let with_context = SignOptions::default().with_context(b"context");

        let verify_context = VerifyOptions::default().with_context(b"context");

        let plain = VerifyOptions::default();

        let signature = private_key.sign(message, &with_context).unwrap();

        assert_eq!(signature.len(), algorithm.signature_size());

        assert!(public_key.verify(&signature, message, &verify_context));

        assert!(!public_key.verify(&signature, message, &plain));

        assert!(!public_key.verify(&signature, b"other", &verify_context));

        let truncated = &signature[..signature.len() - 1];

        assert!(!public_key.verify(truncated, message, &verify_context));

        let long = [0; 256];

        let long_context = VerifyOptions::default().with_context(&long);

        assert!(!public_key.verify(&signature, message, &long_context));

        let long_signing = SignOptions::default().with_context(&long);

        assert_eq!(
            private_key.sign(message, &long_signing).err(),
            Some(Error::InvalidContext)
        );

        let deterministic = SignOptions::default().with_deterministic(true);

        let first = private_key.sign(message, &deterministic).unwrap();

        assert_eq!(first, private_key.sign(message, &deterministic).unwrap());

        let randomized = SignOptions::default();

        assert_ne!(
            private_key.sign(message, &randomized).unwrap(),
            private_key.sign(message, &randomized).unwrap()
        );

        let hashed_options = SignOptions::default().with_pre_hash(SHA_512);

        let hashed = private_key.sign(message, &hashed_options).unwrap();

        let verify_hashed = VerifyOptions::default().with_pre_hash(SHA_512);

        assert!(public_key.verify(&hashed, message, &verify_hashed));

        assert!(!public_key.verify(&hashed, message, &plain));

        let weak = SignOptions::default().with_pre_hash(SHA_224);

        assert_eq!(
            private_key.sign(message, &weak).err(),
            Some(Error::InvalidOption)
        );

        let weak_and_long = SignOptions::default()
            .with_context(&long)
            .with_pre_hash(SHA_224);

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
            let sign_options = SignOptions::default().with_pre_hash(named_pre_hash(label));

            let verify_options = VerifyOptions::default().with_pre_hash(named_pre_hash(label));

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
            .generate_key_pair(&KeyGenOptions::default().with_self_test(false))
            .unwrap();

        for format in [KeyFormat::Raw, KeyFormat::Der, KeyFormat::Pem] {
            let exported = pair.public_key.export_key(format).unwrap();

            let public_key = algorithm.import_public_key(&exported, format).unwrap();

            assert_eq!(public_key, pair.public_key, "{name}");

            let exported = pair.private_key.export_key(format).unwrap();

            let private_key = algorithm.import_private_key(&exported, format).unwrap();

            assert_eq!(
                *private_key.export_key(KeyFormat::Raw).unwrap(),
                *pair.private_key.export_key(KeyFormat::Raw).unwrap(),
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

    assert_eq!(*expanded.export_key(KeyFormat::Der).unwrap(), *expanded_der);

    assert_eq!(
        expanded.public_key().export_key(KeyFormat::Raw).unwrap(),
        unhex(&record["pk"])
    );

    let deterministic = SignOptions::default().with_deterministic(true);

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

fn shareable<T: Send + Sync>() {}

// Keys computed by no one yet are used by many threads at once: whichever thread fills a cache,
// every deterministic signature must be the same and verify.
#[test]
fn concurrent_first_use() {
    shareable::<crypto_pq::SignaturePublicKey>();

    shareable::<crypto_pq::SignaturePrivateKey>();

    let options = SignOptions::default().with_deterministic(true);

    for algorithm in [ML_DSA_44, ML_DSA_87] {
        let pair = hazmat::generate_signature_key_pair(algorithm, &[9; 32]).unwrap();

        let expected = pair.private_key.sign(b"threads", &options).unwrap();

        let public = pair.public_key.export_key(KeyFormat::Raw).unwrap();

        let private = pair.private_key.export_key(KeyFormat::Der).unwrap();

        for _ in 0..10 {
            let public_key = algorithm
                .import_public_key(&public, KeyFormat::Raw)
                .unwrap();

            let private_key = algorithm
                .import_private_key(&private, KeyFormat::Der)
                .unwrap();

            let barrier = std::sync::Barrier::new(8);

            std::thread::scope(|scope| {
                for thread in 0..8 {
                    let (public_key, private_key, barrier) = (&public_key, &private_key, &barrier);

                    let (expected, options) = (&expected, &options);

                    scope.spawn(move || {
                        barrier.wait();

                        if thread % 2 == 0 {
                            assert!(public_key.verify(
                                expected,
                                b"threads",
                                &VerifyOptions::default()
                            ));
                        } else {
                            assert_eq!(&private_key.sign(b"threads", options).unwrap(), expected);
                        }
                    });
                }
            });
        }
    }
}

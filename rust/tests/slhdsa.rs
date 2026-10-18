mod vectors;

use crypto_pq::{
    Error, HASH_SLH_DSA_SHA2_128F_WITH_SHA256, HASH_SLH_DSA_SHA2_128S_WITH_SHA256,
    HASH_SLH_DSA_SHA2_192F_WITH_SHA512, HASH_SLH_DSA_SHA2_192S_WITH_SHA512,
    HASH_SLH_DSA_SHA2_256F_WITH_SHA512, HASH_SLH_DSA_SHA2_256S_WITH_SHA512,
    HASH_SLH_DSA_SHAKE_128F_WITH_SHAKE128, HASH_SLH_DSA_SHAKE_128S_WITH_SHAKE128,
    HASH_SLH_DSA_SHAKE_192F_WITH_SHAKE256, HASH_SLH_DSA_SHAKE_192S_WITH_SHAKE256,
    HASH_SLH_DSA_SHAKE_256F_WITH_SHAKE256, HASH_SLH_DSA_SHAKE_256S_WITH_SHAKE256, KeyFormat,
    KeyGenOptions, PreHash, SHA_224, SHA_256, SHA_384, SHA_512, SHA_512_224, SHA_512_256, SHA3_224,
    SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256, SLH_DSA_SHA2_128F, SLH_DSA_SHA2_128S,
    SLH_DSA_SHA2_192F, SLH_DSA_SHA2_192S, SLH_DSA_SHA2_256F, SLH_DSA_SHA2_256S, SLH_DSA_SHAKE_128F,
    SLH_DSA_SHAKE_128S, SLH_DSA_SHAKE_192F, SLH_DSA_SHAKE_192S, SLH_DSA_SHAKE_256F,
    SLH_DSA_SHAKE_256S, SignOptions, SignatureAlgorithm, VerifyOptions, hazmat,
};
use vectors::{Fields, der, parallel, records, unhex};

const ALGORITHMS: [SignatureAlgorithm; 12] = [
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

fn algorithm(name: &str) -> SignatureAlgorithm {
    ALGORITHMS
        .into_iter()
        .find(|algorithm| algorithm.name() == name)
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

#[test]
fn acvp_key_generation() {
    parallel(
        &records("acvp/SLH-DSA-keyGen.txt", "sk"),
        |(header, record)| {
            let algorithm = algorithm(&header["parameterSet"]);

            let context = format!("tcId {} {}", record["tcId"], header["parameterSet"]);

            let seed = [
                unhex(&record["skSeed"]),
                unhex(&record["skPrf"]),
                unhex(&record["pkSeed"]),
            ]
            .concat();

            let sk = unhex(&record["sk"]);

            let pair = hazmat::generate_signature_key_pair(algorithm, &seed).unwrap();

            let pk = pair.public_key.export_key(KeyFormat::Raw).unwrap();

            assert_eq!(pk, unhex(&record["pk"]), "{context}");

            assert_eq!(
                *pair.private_key.export_key(KeyFormat::Raw).unwrap(),
                *sk,
                "{context}"
            );

            let imported = algorithm.import_private_key(&sk, KeyFormat::Raw).unwrap();

            assert_eq!(imported.public_key(), pair.public_key, "{context}");

            let mut corrupted = sk.clone();

            *corrupted.last_mut().unwrap() ^= 1;

            let result = algorithm.import_private_key(&corrupted, KeyFormat::Raw);

            assert_eq!(result.err(), Some(Error::InvalidPrivateKey), "{context}");
        },
    );
}

#[test]
fn acvp_signature_generation() {
    check_signature_generation("acvp/SLH-DSA-sigGen.txt");
}

#[test]
fn acvp_signature_verification() {
    check_signature_verification("acvp/SLH-DSA-sigVer.txt");
}

#[test]
fn acvp_internal_signature_generation() {
    check_internal_signature_generation("acvp/SLH-DSA-sigGen-internal.txt");
}

#[test]
fn acvp_internal_signature_verification() {
    check_internal_signature_verification("acvp/SLH-DSA-sigVer-internal.txt");
}

// Every test of ACVP, external and internal.
#[test]
#[ignore = "weekly (fuzz.yml): the full ACVP set"]
fn acvp_full_signatures() {
    check_signature_generation("acvp-full/SLH-DSA-sigGen.txt");

    check_signature_verification("acvp-full/SLH-DSA-sigVer.txt");

    check_internal_signature_generation("acvp-full/SLH-DSA-sigGen-internal.txt");

    check_internal_signature_verification("acvp-full/SLH-DSA-sigVer-internal.txt");
}

fn internal_records(name: &str) -> Vec<(Fields, Fields)> {
    let found = records(name, "signature");

    assert!(
        found
            .iter()
            .all(|(header, _)| header["signatureInterface"] == "internal"),
        "{name}: a test of another interface"
    );

    eprintln!("{name}: {} internal tests run", found.len());

    found
}

// opt_rand is PK.seed for the deterministic variant (FIPS 205, Algorithm 19).
fn check_internal_signature_generation(name: &str) {
    parallel(&internal_records(name), |(header, record)| {
        let algorithm = algorithm(&header["parameterSet"]);

        let context = format!("tcId {} {}", record["tcId"], header["parameterSet"]);

        let sk = unhex(&record["sk"]);

        let private_key = algorithm.import_private_key(&sk, KeyFormat::Raw).unwrap();

        let n = sk.len() / 4;

        let randomness = if header["deterministic"] == "true" {
            sk[2 * n..3 * n].to_vec()
        } else {
            unhex(&record["additionalRandomness"])
        };

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

fn check_internal_signature_verification(name: &str) {
    parallel(&internal_records(name), |(header, record)| {
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
            "tcId {} {} {}",
            record["tcId"], header["parameterSet"], record["reason"]
        );
    });
}

// M' = 0 || |ctx| || ctx || M is the pure interface (FIPS 205, Algorithm 22), so the internal
// one gives the same signature; a HashSLH-DSA key, which signs pre-hashed messages alone, refuses
// it.
#[test]
fn internal_interface() {
    for (hashed, pure, _, _) in hash_slh_dsa() {
        if !hashed.name().contains("128f") {
            continue;
        }

        let n = pure.public_key_size() / 2;

        let seed = vec![7; 3 * n];

        let pair = hazmat::generate_signature_key_pair(pure, &seed).unwrap();

        let (private_key, public_key) = (&pair.private_key, &pair.public_key);

        let representative = [&[0, 7][..], b"context", b"message"].concat();

        let options = SignOptions::default().with_context(b"context");

        let randomness = vec![9; n];

        let signature = hazmat::sign(private_key, b"message", &randomness, &options).unwrap();

        assert_eq!(
            hazmat::sign_internal(private_key, &representative, &randomness).unwrap(),
            signature
        );

        assert!(hazmat::verify_internal(
            public_key,
            &signature,
            &representative
        ));

        assert!(!hazmat::verify_internal(public_key, &signature, b"message"));

        assert!(!hazmat::verify_internal(
            public_key,
            &signature[1..],
            &representative
        ));

        assert_eq!(
            hazmat::sign_internal(private_key, &representative, &randomness[1..]).err(),
            Some(Error::InvalidLength)
        );

        let hashed_pair = hazmat::generate_signature_key_pair(hashed, &seed).unwrap();

        assert_eq!(
            hazmat::sign_internal(&hashed_pair.private_key, &representative, &randomness).err(),
            Some(Error::InvalidOption)
        );

        assert!(!hazmat::verify_internal(
            &hashed_pair.public_key,
            &signature,
            &representative
        ));
    }
}

fn check_signature_generation(name: &str) {
    parallel(&records(name, "signature"), |(header, record)| {
        let algorithm = algorithm(&header["parameterSet"]);

        let context = format!("tcId {} {}", record["tcId"], header["parameterSet"]);

        let sk = unhex(&record["sk"]);

        let private_key = algorithm.import_private_key(&sk, KeyFormat::Raw).unwrap();

        let n = sk.len() / 4;

        let randomness = if header["deterministic"] == "true" {
            sk[2 * n..3 * n].to_vec()
        } else {
            unhex(&record["additionalRandomness"])
        };

        let (message, context_bytes) = (unhex(&record["message"]), unhex(&record["context"]));

        let mut options = SignOptions::default().with_context(&context_bytes);

        options.pre_hash = pre_hash(header, record);

        let signature = hazmat::sign(&private_key, &message, &randomness, &options).unwrap();

        assert_eq!(signature, unhex(&record["signature"]), "{context}");
    });
}

fn check_signature_verification(name: &str) {
    parallel(&records(name, "signature"), |(header, record)| {
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
    });
}

#[test]
fn round_trip() {
    let algorithm = SLH_DSA_SHAKE_128F;

    let pair = algorithm
        .generate_key_pair(&KeyGenOptions::default().with_self_test(false))
        .unwrap();

    let options = SignOptions::default()
        .with_context(b"context")
        .with_deterministic(true);

    let signature = pair.private_key.sign(b"message", &options).unwrap();

    assert_eq!(
        signature,
        pair.private_key.sign(b"message", &options).unwrap()
    );

    let with_context = VerifyOptions::default().with_context(b"context");

    assert!(
        pair.public_key
            .verify(&signature, b"message", &with_context)
    );

    assert!(
        !pair
            .public_key
            .verify(&signature, b"message", &VerifyOptions::default())
    );

    let truncated = &signature[..signature.len() - 1];

    assert!(!pair.public_key.verify(truncated, b"message", &with_context));

    for format in [KeyFormat::Raw, KeyFormat::Der, KeyFormat::Pem] {
        let exported = pair.public_key.export_key(format).unwrap();

        let public_key = algorithm.import_public_key(&exported, format).unwrap();

        assert_eq!(public_key, pair.public_key);

        let exported = pair.private_key.export_key(format).unwrap();

        let private_key = algorithm.import_private_key(&exported, format).unwrap();

        assert_eq!(
            *private_key.export_key(KeyFormat::Raw).unwrap(),
            *pair.private_key.export_key(KeyFormat::Raw).unwrap()
        );
    }

    let raw = pair.private_key.export_key(KeyFormat::Raw).unwrap();

    assert_eq!(raw.len(), 64);

    let weak = SignOptions::default().with_pre_hash(SHA_224);

    assert_eq!(
        pair.private_key.sign(b"m", &weak).err(),
        Some(Error::InvalidOption)
    );

    let strong = SignOptions::default().with_pre_hash(SHAKE128);

    let hashed = pair.private_key.sign(b"m", &strong).unwrap();

    let verify_hashed = VerifyOptions::default().with_pre_hash(SHAKE128);

    assert!(pair.public_key.verify(&hashed, b"m", &verify_hashed));

    let checked = algorithm
        .generate_key_pair(&KeyGenOptions::default())
        .unwrap();

    assert_eq!(checked.public_key.algorithm(), algorithm);
}

#[test]
fn encodings() {
    let algorithm = SLH_DSA_SHAKE_128F;

    let pair = hazmat::generate_signature_key_pair(algorithm, &[3; 48]).unwrap();

    let raw = pair.private_key.export_key(KeyFormat::Raw).unwrap();

    let oid = der(0x06, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 27]);

    let pkcs8 = |key: &[u8]| {
        der(
            0x30,
            &[der(0x02, &[0]), der(0x30, &oid), der(0x04, key)].concat(),
        )
    };

    assert_eq!(
        *pair.private_key.export_key(KeyFormat::Der).unwrap(),
        *pkcs8(&raw)
    );

    assert_eq!(
        algorithm
            .import_private_key(&pkcs8(&raw[1..]), KeyFormat::Der)
            .err(),
        Some(Error::InvalidEncoding)
    );

    assert_eq!(
        algorithm
            .import_private_key(&raw[1..], KeyFormat::Raw)
            .err(),
        Some(Error::InvalidLength)
    );

    let mut wrong_root = raw.to_vec();

    wrong_root[63] ^= 1;

    assert_eq!(
        algorithm
            .import_private_key(&pkcs8(&wrong_root), KeyFormat::Der)
            .err(),
        Some(Error::InvalidPrivateKey)
    );

    assert_eq!(
        SLH_DSA_SHA2_128F
            .import_private_key(&pkcs8(&raw), KeyFormat::Der)
            .err(),
        Some(Error::AlgorithmMismatch)
    );

    assert_eq!(
        hazmat::generate_signature_key_pair(algorithm, &[3; 64]).err(),
        Some(Error::InvalidLength)
    );

    let options = SignOptions::default();

    assert_eq!(
        hazmat::sign(&pair.private_key, b"m", &[0; 32], &options).err(),
        Some(Error::InvalidLength)
    );

    let sizes: Vec<_> = ALGORITHMS
        .iter()
        .map(|algorithm| (algorithm.public_key_size(), algorithm.signature_size()))
        .collect();

    assert_eq!(
        sizes,
        [
            (32, 7856),
            (32, 17088),
            (48, 16224),
            (48, 35664),
            (64, 29792),
            (64, 49856),
            (32, 7856),
            (32, 17088),
            (48, 16224),
            (48, 35664),
            (64, 29792),
            (64, 49856),
        ]
    );
}

// RFC 9909, Appendix C: an SLH-DSA-SHA2-128s private key in PKCS#8.
#[test]
fn rfc9909_private_key() {
    let pem = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MFICAQAwCwYJYIZIAWUDBAMUBECiJjvKRYYINlIxYASVI9YhZ3+tkNUetgZ6Mn4N\n",
        "HmSlASuBCex3fKpOHwJMz8+Ul9mRgFCSgPQlavKwevgCibSU\n",
        "-----END PRIVATE KEY-----\n",
    );

    let private_key = SLH_DSA_SHA2_128S
        .import_private_key(pem.as_bytes(), KeyFormat::Pem)
        .unwrap();

    assert_eq!(
        *private_key.export_key(KeyFormat::Pem).unwrap(),
        *pem.as_bytes()
    );
}

// RFC 9909, Appendix C.1 and C.3: the example public key, and the self-signed certificate whose
// signature it verifies over the TBSCertificate.
#[test]
fn rfc9909_certificate() {
    for (_, record) in records("rfc/slhdsa_certificate.txt", "spki") {
        let public_key = algorithm(&record["name"])
            .import_public_key(&unhex(&record["spki"]), KeyFormat::Der)
            .unwrap();

        let (tbs, signature) = (unhex(&record["tbs"]), unhex(&record["signature"]));

        assert!(
            public_key.verify(&signature, &tbs, &VerifyOptions::default()),
            "RFC 9909 C.3"
        );

        let mut altered = tbs.clone();

        *altered.last_mut().unwrap() ^= 1;

        assert!(!public_key.verify(&signature, &altered, &VerifyOptions::default()));
    }
}

// RFC 9909: each HashSLH-DSA value, the pure value of its set, its fixed pre-hash and the last arc
// of its OID 2.16.840.1.101.3.4.3.x.
fn hash_slh_dsa() -> [(SignatureAlgorithm, SignatureAlgorithm, PreHash, u8); 12] {
    [
        (
            HASH_SLH_DSA_SHA2_128S_WITH_SHA256,
            SLH_DSA_SHA2_128S,
            SHA_256.into(),
            35,
        ),
        (
            HASH_SLH_DSA_SHA2_128F_WITH_SHA256,
            SLH_DSA_SHA2_128F,
            SHA_256.into(),
            36,
        ),
        (
            HASH_SLH_DSA_SHA2_192S_WITH_SHA512,
            SLH_DSA_SHA2_192S,
            SHA_512.into(),
            37,
        ),
        (
            HASH_SLH_DSA_SHA2_192F_WITH_SHA512,
            SLH_DSA_SHA2_192F,
            SHA_512.into(),
            38,
        ),
        (
            HASH_SLH_DSA_SHA2_256S_WITH_SHA512,
            SLH_DSA_SHA2_256S,
            SHA_512.into(),
            39,
        ),
        (
            HASH_SLH_DSA_SHA2_256F_WITH_SHA512,
            SLH_DSA_SHA2_256F,
            SHA_512.into(),
            40,
        ),
        (
            HASH_SLH_DSA_SHAKE_128S_WITH_SHAKE128,
            SLH_DSA_SHAKE_128S,
            SHAKE128.into(),
            41,
        ),
        (
            HASH_SLH_DSA_SHAKE_128F_WITH_SHAKE128,
            SLH_DSA_SHAKE_128F,
            SHAKE128.into(),
            42,
        ),
        (
            HASH_SLH_DSA_SHAKE_192S_WITH_SHAKE256,
            SLH_DSA_SHAKE_192S,
            SHAKE256.into(),
            43,
        ),
        (
            HASH_SLH_DSA_SHAKE_192F_WITH_SHAKE256,
            SLH_DSA_SHAKE_192F,
            SHAKE256.into(),
            44,
        ),
        (
            HASH_SLH_DSA_SHAKE_256S_WITH_SHAKE256,
            SLH_DSA_SHAKE_256S,
            SHAKE256.into(),
            45,
        ),
        (
            HASH_SLH_DSA_SHAKE_256F_WITH_SHAKE256,
            SLH_DSA_SHAKE_256F,
            SHAKE256.into(),
            46,
        ),
    ]
}

// SPEC 9.4: the keys, sizes and raw formats of the pure set, the OIDs of RFC 9909 in DER, and the
// fixed pre-hash, which the preHash option may only name again, in the public and hazmat sign
// and verify alike.
#[test]
fn hash_slh_dsa_values() {
    for (hashed, pure, fixed, arc) in hash_slh_dsa() {
        let name = hashed.name();

        assert!(name.starts_with("HashSLH-DSA-") && name.contains(&pure.name()[8..]));

        assert_eq!(hashed.public_key_size(), pure.public_key_size());

        assert_eq!(hashed.signature_size(), pure.signature_size());

        let n = pure.public_key_size() / 2;

        let seed: Vec<u8> = (0..3 * n as u8).collect();

        let pair = hazmat::generate_signature_key_pair(hashed, &seed).unwrap();

        let reference = hazmat::generate_signature_key_pair(pure, &seed).unwrap();

        let raw = pair.public_key.export_key(KeyFormat::Raw).unwrap();

        assert_eq!(
            raw,
            reference.public_key.export_key(KeyFormat::Raw).unwrap()
        );

        assert_eq!(
            *pair.private_key.export_key(KeyFormat::Raw).unwrap(),
            *reference.private_key.export_key(KeyFormat::Raw).unwrap()
        );

        let oid = der(0x06, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, arc]);

        let public_der = pair.public_key.export_key(KeyFormat::Der).unwrap();

        let private_der = pair.private_key.export_key(KeyFormat::Der).unwrap();

        for der in [&public_der[..], &private_der] {
            assert!(der.windows(oid.len()).any(|window| window == oid), "{name}");
        }

        for format in [KeyFormat::Der, KeyFormat::Pem] {
            let public = pair.public_key.export_key(format).unwrap();

            let private = pair.private_key.export_key(format).unwrap();

            assert_eq!(
                hashed.import_public_key(&public, format).unwrap(),
                pair.public_key
            );

            assert_eq!(
                hashed
                    .import_private_key(&private, format)
                    .unwrap()
                    .public_key(),
                pair.public_key
            );

            let pure_public = reference.public_key.export_key(format).unwrap();

            let pure_private = reference.private_key.export_key(format).unwrap();

            for (algorithm, public, private) in [
                (hashed, &pure_public, &pure_private[..]),
                (pure, &public, &private[..]),
            ] {
                assert_eq!(
                    algorithm.import_public_key(public, format).err(),
                    Some(Error::AlgorithmMismatch),
                    "{name}"
                );

                assert_eq!(
                    algorithm.import_private_key(private, format).err(),
                    Some(Error::AlgorithmMismatch),
                    "{name}"
                );
            }
        }

        // Any other pre-hash, even one the strength rule allows, is refused.
        let other: PreHash = if fixed == SHA_512.into() {
            SHA3_512.into()
        } else {
            SHA_512.into()
        };

        let randomness = vec![1; n];

        let refused = SignOptions::default().with_pre_hash(other);

        assert_eq!(
            pair.private_key.sign(b"message", &refused).err(),
            Some(Error::InvalidOption),
            "{name}"
        );

        assert_eq!(
            hazmat::sign(&pair.private_key, b"message", &randomness, &refused).err(),
            Some(Error::InvalidOption),
            "{name}"
        );

        let signature = vec![0; hashed.signature_size()];

        let other = VerifyOptions::default().with_pre_hash(other);

        assert!(!pair.public_key.verify(&signature, b"message", &other));

        assert!(!hazmat::verify(
            &pair.public_key,
            &signature,
            b"message",
            &other
        ));
    }
}

// A HashSLH-DSA signature is the HashSLH-DSA signature of the pure value with the fixed pre-hash,
// whether the option is absent or names the same function, and verifies only as such.
#[test]
fn hash_slh_dsa_signatures() {
    for (hashed, pure, fixed, _) in hash_slh_dsa() {
        if !hashed.name().contains("128") && !hashed.name().ends_with("f-with-SHAKE256") {
            continue;
        }

        let n = pure.public_key_size() / 2;

        let seed = vec![7; 3 * n];

        let pair = hazmat::generate_signature_key_pair(hashed, &seed).unwrap();

        let reference = hazmat::generate_signature_key_pair(pure, &seed).unwrap();

        let deterministic = SignOptions::default()
            .with_context(b"context")
            .with_deterministic(true);

        let signature = pair.private_key.sign(b"message", &deterministic).unwrap();

        let named = deterministic.with_pre_hash(fixed);

        assert_eq!(
            pair.private_key.sign(b"message", &named).unwrap(),
            signature
        );

        assert_eq!(
            reference.private_key.sign(b"message", &named).unwrap(),
            signature
        );

        let randomness = vec![3; n];

        assert_eq!(
            hazmat::sign(&pair.private_key, b"message", &randomness, &deterministic).unwrap(),
            hazmat::sign(&reference.private_key, b"message", &randomness, &named).unwrap()
        );

        let context = VerifyOptions::default().with_context(b"context");

        for options in [context, context.with_pre_hash(fixed)] {
            assert!(pair.public_key.verify(&signature, b"message", &options));

            assert!(hazmat::verify(
                &pair.public_key,
                &signature,
                b"message",
                &options
            ));
        }

        assert!(
            !reference
                .public_key
                .verify(&signature, b"message", &context)
        );

        assert!(
            reference
                .public_key
                .verify(&signature, b"message", &context.with_pre_hash(fixed))
        );

        if hashed.name().contains("128f") {
            let generated = hashed.generate_key_pair(&KeyGenOptions::default()).unwrap();

            let hedged = generated
                .private_key
                .sign(b"message", &SignOptions::default())
                .unwrap();

            assert!(
                generated
                    .public_key
                    .verify(&hedged, b"message", &VerifyOptions::default())
            );
        }
    }
}

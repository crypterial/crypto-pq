mod vectors;

use crypto_pq::{
    Error, KeyFormat, KeyGenOptions, PreHash, SHA_224, SHA_256, SHA_384, SHA_512, SHA_512_224,
    SHA_512_256, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256, SLH_DSA_SHA2_128F,
    SLH_DSA_SHA2_128S, SLH_DSA_SHA2_192F, SLH_DSA_SHA2_192S, SLH_DSA_SHA2_256F, SLH_DSA_SHA2_256S,
    SLH_DSA_SHAKE_128F, SLH_DSA_SHAKE_128S, SLH_DSA_SHAKE_192F, SLH_DSA_SHAKE_192S,
    SLH_DSA_SHAKE_256F, SLH_DSA_SHAKE_256S, SignOptions, SignatureAlgorithm, VerifyOptions, hazmat,
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
                pair.private_key.export_key(KeyFormat::Raw).unwrap(),
                sk,
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
    parallel(
        &records("acvp/SLH-DSA-sigGen.txt", "signature"),
        |(header, record)| {
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

            let options = SignOptions {
                context: &context_bytes,
                pre_hash: pre_hash(header, record),
                ..SignOptions::default()
            };

            let signature = hazmat::sign(&private_key, &message, &randomness, &options).unwrap();

            assert_eq!(signature, unhex(&record["signature"]), "{context}");
        },
    );
}

#[test]
fn acvp_signature_verification() {
    parallel(
        &records("acvp/SLH-DSA-sigVer.txt", "signature"),
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
fn round_trip() {
    let algorithm = SLH_DSA_SHAKE_128F;

    let pair = algorithm
        .generate_key_pair(&KeyGenOptions { self_test: false })
        .unwrap();

    let options = SignOptions {
        context: b"context",
        deterministic: true,
        ..SignOptions::default()
    };

    let signature = pair.private_key.sign(b"message", &options).unwrap();

    assert_eq!(
        signature,
        pair.private_key.sign(b"message", &options).unwrap()
    );

    let with_context = VerifyOptions {
        context: b"context",
        ..VerifyOptions::default()
    };

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
            private_key.export_key(KeyFormat::Raw).unwrap(),
            pair.private_key.export_key(KeyFormat::Raw).unwrap()
        );
    }

    let raw = pair.private_key.export_key(KeyFormat::Raw).unwrap();

    assert_eq!(raw.len(), 64);

    let weak = SignOptions {
        pre_hash: Some(SHA_224.into()),
        ..SignOptions::default()
    };

    assert_eq!(
        pair.private_key.sign(b"m", &weak).err(),
        Some(Error::InvalidOption)
    );

    let strong = SignOptions {
        pre_hash: Some(SHAKE128.into()),
        ..SignOptions::default()
    };

    let hashed = pair.private_key.sign(b"m", &strong).unwrap();

    let verify_hashed = VerifyOptions {
        pre_hash: Some(SHAKE128.into()),
        ..VerifyOptions::default()
    };

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
        pair.private_key.export_key(KeyFormat::Der).unwrap(),
        pkcs8(&raw)
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

    let mut wrong_root = raw.clone();

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
        private_key.export_key(KeyFormat::Pem).unwrap(),
        pem.as_bytes()
    );
}

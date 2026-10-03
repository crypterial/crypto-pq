mod vectors;

use crypto_pq::{
    Error, KemAlgorithm, KeyFormat, KeyGenOptions, ML_KEM_512, ML_KEM_768, ML_KEM_1024, X_WING,
    hazmat,
};
use vectors::{der, parallel, records, unhex};

const ALGORITHMS: [(&str, KemAlgorithm); 3] = [
    ("ML-KEM-512", ML_KEM_512),
    ("ML-KEM-768", ML_KEM_768),
    ("ML-KEM-1024", ML_KEM_1024),
];

const FORMATS: [KeyFormat; 3] = [KeyFormat::Raw, KeyFormat::Der, KeyFormat::Pem];

fn algorithm(name: &str) -> KemAlgorithm {
    ALGORITHMS
        .iter()
        .find(|(known, _)| *known == name)
        .map(|&(_, algorithm)| algorithm)
        .unwrap_or_else(|| panic!("unknown parameter set {name}"))
}

fn oid(algorithm: KemAlgorithm) -> Vec<u8> {
    let arc = ALGORITHMS
        .iter()
        .position(|&(_, known)| known == algorithm)
        .expect("ML-KEM") as u8;

    der(
        0x06,
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, arc + 1],
    )
}

fn pkcs8(algorithm: KemAlgorithm, private_key: &[u8]) -> Vec<u8> {
    let body = [
        der(0x02, &[0]),
        der(0x30, &oid(algorithm)),
        der(0x04, private_key),
    ];

    der(0x30, &body.concat())
}

fn spki(algorithm: KemAlgorithm, bits: &[u8]) -> Vec<u8> {
    der(
        0x30,
        &[der(0x30, &oid(algorithm)), der(0x03, bits)].concat(),
    )
}

#[test]
fn acvp_key_generation() {
    for (header, record) in records("acvp/ML-KEM-keyGen.txt", "dk") {
        let algorithm = algorithm(&header["parameterSet"]);

        let seed = [unhex(&record["d"]), unhex(&record["z"])].concat();

        let (ek, dk) = (unhex(&record["ek"]), unhex(&record["dk"]));

        let context = format!("tcId {}", record["tcId"]);

        let pair = hazmat::generate_kem_key_pair(algorithm, &seed).unwrap();

        assert_eq!(
            pair.public_key.export_key(KeyFormat::Raw).unwrap(),
            ek,
            "{context}"
        );

        assert_eq!(
            pair.private_key.export_key(KeyFormat::Raw).unwrap(),
            seed,
            "{context}"
        );

        let expanded = algorithm.import_private_key(&dk, KeyFormat::Raw).unwrap();

        assert_eq!(
            expanded.public_key().export_key(KeyFormat::Raw).unwrap(),
            ek,
            "{context}"
        );

        assert_eq!(
            expanded.export_key(KeyFormat::Raw).unwrap(),
            dk,
            "{context}"
        );

        let both = pkcs8(
            algorithm,
            &der(0x30, &[der(0x04, &seed), der(0x04, &dk)].concat()),
        );

        let imported = algorithm.import_private_key(&both, KeyFormat::Der).unwrap();

        assert_eq!(
            imported.export_key(KeyFormat::Raw).unwrap(),
            seed,
            "{context}"
        );
    }
}

#[test]
fn acvp_encapsulation_and_decapsulation() {
    for (header, record) in records("acvp/ML-KEM-encapDecap.txt", "tcId") {
        let algorithm = algorithm(&header["parameterSet"]);

        let context = format!("tcId {} {}", record["tcId"], header["function"]);

        match header["function"].as_str() {
            "encapsulation" => {
                let public_key = algorithm
                    .import_public_key(&unhex(&record["ek"]), KeyFormat::Raw)
                    .unwrap();

                let result = hazmat::encapsulate(&public_key, &unhex(&record["m"])).unwrap();

                assert_eq!(result.ciphertext, unhex(&record["c"]), "{context}");

                assert_eq!(result.shared_secret, unhex(&record["k"]), "{context}");
            }
            "decapsulation" => {
                let private_key = if header["keyFormat"] == "seed" {
                    let seed = [unhex(&record["d"]), unhex(&record["z"])].concat();

                    hazmat::generate_kem_key_pair(algorithm, &seed)
                        .unwrap()
                        .private_key
                } else {
                    algorithm
                        .import_private_key(&unhex(&record["dk"]), KeyFormat::Raw)
                        .unwrap()
                };

                let shared_secret = private_key.decapsulate(&unhex(&record["c"])).unwrap();

                assert_eq!(shared_secret, unhex(&record["k"]), "{context}");
            }
            "encapsulationKeyCheck" => {
                let result = algorithm.import_public_key(&unhex(&record["ek"]), KeyFormat::Raw);

                assert_eq!(result.is_ok(), record["testPassed"] == "true", "{context}");
            }
            "decapsulationKeyCheck" => {
                let result = algorithm.import_private_key(&unhex(&record["dk"]), KeyFormat::Raw);

                assert_eq!(result.is_ok(), record["testPassed"] == "true", "{context}");
            }
            function => panic!("unknown function {function}"),
        }
    }
}

#[test]
fn wycheproof_decapsulation() {
    parallel(
        &records("wycheproof/mlkem.txt", "tcId"),
        |(header, record)| {
            let algorithm = algorithm(&header["parameterSet"]);

            let (seed, c) = (unhex(&record["seed"]), unhex(&record["c"]));

            let context = format!("tcId {} {}", record["tcId"], header["parameterSet"]);

            if record["result"] == "valid" {
                let pair = hazmat::generate_kem_key_pair(algorithm, &seed).unwrap();

                let ek = pair.public_key.export_key(KeyFormat::Raw).unwrap();

                assert_eq!(ek, unhex(&record["ek"]), "{context}");

                let shared_secret = pair.private_key.decapsulate(&c).unwrap();

                assert_eq!(shared_secret, unhex(&record["K"]), "{context}");
            } else if seed.len() != 64 {
                let result = hazmat::generate_kem_key_pair(algorithm, &seed);

                assert_eq!(result.err(), Some(Error::InvalidLength), "{context}");
            } else {
                let pair = hazmat::generate_kem_key_pair(algorithm, &seed).unwrap();

                let result = pair.private_key.decapsulate(&c);

                assert_eq!(result.err(), Some(Error::InvalidLength), "{context}");
            }
        },
    );
}

#[test]
fn wycheproof_encapsulation() {
    parallel(
        &records("wycheproof/mlkem_encaps.txt", "tcId"),
        |(header, record)| {
            let algorithm = algorithm(&header["parameterSet"]);

            let ek = unhex(&record["ek"]);

            let context = format!("tcId {} {}", record["tcId"], header["parameterSet"]);

            if record["result"] == "valid" {
                let public_key = algorithm.import_public_key(&ek, KeyFormat::Raw).unwrap();

                let result = hazmat::encapsulate(&public_key, &unhex(&record["m"])).unwrap();

                assert_eq!(result.ciphertext, unhex(&record["c"]), "{context}");

                assert_eq!(result.shared_secret, unhex(&record["K"]), "{context}");
            } else {
                let code = if ek.len() != algorithm.public_key_size() {
                    Error::InvalidLength
                } else {
                    Error::InvalidPublicKey
                };

                let result = algorithm.import_public_key(&ek, KeyFormat::Raw);

                assert_eq!(result.err(), Some(code), "{context}");
            }
        },
    );
}

#[test]
fn wycheproof_expanded_decapsulation() {
    for (header, record) in records("wycheproof/mlkem_semi_expanded_decaps.txt", "tcId") {
        let algorithm = algorithm(&header["parameterSet"]);

        let (dk, c) = (unhex(&record["dk"]), unhex(&record["c"]));

        let flags = record.get("flags").map_or("", String::as_str);

        let context = format!("tcId {} {}", record["tcId"], header["parameterSet"]);

        let imported = algorithm.import_private_key(&dk, KeyFormat::Raw);

        if record["result"] == "valid" {
            let private_key = imported.unwrap();

            let ek = private_key.public_key().export_key(KeyFormat::Raw).unwrap();

            assert_eq!(ek, unhex(&record["ek"]), "{context}");

            assert_eq!(
                private_key.decapsulate(&c).unwrap(),
                unhex(&record["K"]),
                "{context}"
            );
        } else if flags.contains("IncorrectCiphertextLength") {
            let result = imported.unwrap().decapsulate(&c);

            assert_eq!(result.err(), Some(Error::InvalidLength), "{context}");
        } else if flags.contains("IncorrectDecapsulationKeyLength") {
            assert_eq!(imported.err(), Some(Error::InvalidLength), "{context}");
        } else {
            assert_eq!(imported.err(), Some(Error::InvalidPrivateKey), "{context}");
        }
    }
}

#[test]
fn round_trip() {
    for algorithm in [ML_KEM_512, ML_KEM_768, ML_KEM_1024, X_WING] {
        let pair = algorithm
            .generate_key_pair(&KeyGenOptions::default())
            .unwrap();

        let encapsulation = pair.public_key.encapsulate().unwrap();

        let ciphertext = &encapsulation.ciphertext;

        assert_eq!(ciphertext.len(), algorithm.ciphertext_size());

        assert_eq!(
            encapsulation.shared_secret.len(),
            algorithm.shared_secret_size()
        );

        assert_eq!(
            pair.private_key.decapsulate(ciphertext).unwrap(),
            encapsulation.shared_secret
        );

        let mut tampered = ciphertext.clone();

        tampered[0] ^= 1;

        assert_ne!(
            pair.private_key.decapsulate(&tampered).unwrap(),
            encapsulation.shared_secret
        );

        let truncated = pair
            .private_key
            .decapsulate(&ciphertext[..ciphertext.len() - 1]);

        assert_eq!(truncated.err(), Some(Error::InvalidLength));

        let raw = pair.public_key.export_key(KeyFormat::Raw).unwrap();

        assert_eq!(raw.len(), algorithm.public_key_size());

        let unchecked = algorithm
            .generate_key_pair(&KeyGenOptions { self_test: false })
            .unwrap();

        assert_eq!(unchecked.public_key.algorithm(), algorithm);

        assert_eq!(pair.private_key.algorithm(), algorithm);
    }
}

#[test]
fn formats() {
    for (_, algorithm) in ALGORITHMS {
        let pair = algorithm
            .generate_key_pair(&KeyGenOptions::default())
            .unwrap();

        for format in FORMATS {
            let exported = pair.public_key.export_key(format).unwrap();

            let public = algorithm.import_public_key(&exported, format).unwrap();

            assert_eq!(public, pair.public_key);

            let exported = pair.private_key.export_key(format).unwrap();

            let private = algorithm.import_private_key(&exported, format).unwrap();

            assert_eq!(private.public_key(), pair.public_key);
        }

        let pem = pair.public_key.export_key(KeyFormat::Pem).unwrap();

        assert!(pem.starts_with(b"-----BEGIN PUBLIC KEY-----\n"));

        assert!(pem.ends_with(b"\n-----END PUBLIC KEY-----\n"));

        assert!(pem.split(|&c| c == b'\n').all(|line| line.len() <= 64));

        let private_pem = pair.private_key.export_key(KeyFormat::Pem).unwrap();

        assert!(private_pem.starts_with(b"-----BEGIN PRIVATE KEY-----\n"));

        let private_der = pair.private_key.export_key(KeyFormat::Der).unwrap();

        assert_eq!(private_der[private_der.len() - 66..][..2], [0x80, 0x40]);

        let public_der = pair.public_key.export_key(KeyFormat::Der).unwrap();

        let trailing = [public_der.as_slice(), &[0]].concat();

        assert_eq!(
            algorithm.import_public_key(&trailing, KeyFormat::Der).err(),
            Some(Error::InvalidEncoding)
        );

        assert_eq!(
            algorithm
                .import_public_key(&private_pem, KeyFormat::Pem)
                .err(),
            Some(Error::InvalidEncoding)
        );

        assert_eq!(
            algorithm.import_private_key(&[0; 63], KeyFormat::Raw).err(),
            Some(Error::InvalidLength)
        );
    }

    let pair = ML_KEM_768
        .generate_key_pair(&KeyGenOptions::default())
        .unwrap();

    let public_der = pair.public_key.export_key(KeyFormat::Der).unwrap();

    assert_eq!(
        ML_KEM_512
            .import_public_key(&public_der, KeyFormat::Der)
            .err(),
        Some(Error::AlgorithmMismatch)
    );

    let private_pem = pair.private_key.export_key(KeyFormat::Pem).unwrap();

    assert_eq!(
        ML_KEM_1024
            .import_private_key(&private_pem, KeyFormat::Pem)
            .err(),
        Some(Error::AlgorithmMismatch)
    );
}

#[test]
fn strict_encodings() {
    let algorithm = ML_KEM_512;

    let found = records("acvp/ML-KEM-keyGen.txt", "dk");

    let (header, record) = &found[0];

    assert_eq!(header["parameterSet"], "ML-KEM-512");

    let seed = [unhex(&record["d"]), unhex(&record["z"])].concat();

    let (raw, dk) = (unhex(&record["ek"]), unhex(&record["dk"]));

    let public_key = algorithm.import_public_key(&raw, KeyFormat::Raw).unwrap();

    let bits = [&[0][..], &raw].concat();

    let canonical = spki(algorithm, &bits);

    assert_eq!(public_key.export_key(KeyFormat::Der).unwrap(), canonical);

    let with_parameters = der(
        0x30,
        &[
            der(0x30, &[oid(algorithm), der(0x05, &[])].concat()),
            der(0x03, &bits),
        ]
        .concat(),
    );

    let body = &canonical[4..];

    let long_form = [
        &[0x30, 0x83, 0x00, (body.len() >> 8) as u8, body.len() as u8][..],
        body,
    ]
    .concat();

    let invalid = [
        with_parameters,
        long_form,
        spki(algorithm, &[&[1][..], &raw].concat()),
        spki(algorithm, &bits[..bits.len() - 1]),
        canonical[..canonical.len() - 1].to_vec(),
    ];

    for data in invalid {
        assert_eq!(
            algorithm.import_public_key(&data, KeyFormat::Der).err(),
            Some(Error::InvalidEncoding)
        );
    }

    let expanded_der = pkcs8(algorithm, &der(0x04, &dk));

    let expanded = algorithm
        .import_private_key(&expanded_der, KeyFormat::Der)
        .unwrap();

    assert_eq!(expanded.public_key(), public_key);

    assert_eq!(expanded.export_key(KeyFormat::Raw).unwrap(), dk);

    assert_eq!(expanded.export_key(KeyFormat::Der).unwrap(), expanded_der);

    let seed_der = pkcs8(algorithm, &der(0x80, &seed));

    let seeded = algorithm
        .import_private_key(&seed_der, KeyFormat::Der)
        .unwrap();

    assert_eq!(seeded.export_key(KeyFormat::Der).unwrap(), seed_der);

    let mut other_seed = seed.clone();

    other_seed[0] ^= 1;

    let mut damaged = dk.clone();

    damaged[768 * 2 + 40] ^= 1;

    let mismatched = der(0x30, &[der(0x04, &other_seed), der(0x04, &dk)].concat());

    assert_eq!(
        algorithm
            .import_private_key(&pkcs8(algorithm, &mismatched), KeyFormat::Der)
            .err(),
        Some(Error::InvalidPrivateKey)
    );

    assert_eq!(
        algorithm.import_private_key(&damaged, KeyFormat::Raw).err(),
        Some(Error::InvalidPrivateKey)
    );

    let one_asymmetric_key = |version: u8, public: &[u8]| {
        let body = [
            der(0x02, &[version]),
            der(0x30, &oid(algorithm)),
            der(0x04, &der(0x80, &seed)),
            der(0xA0, &[]),
            der(0x81, &[&[0][..], public].concat()),
        ];

        der(0x30, &body.concat())
    };

    let imported = algorithm
        .import_private_key(&one_asymmetric_key(1, &raw), KeyFormat::Der)
        .unwrap();

    assert_eq!(imported.public_key(), public_key);

    let mut wrong_public = raw.clone();

    wrong_public[0] ^= 1;

    assert_eq!(
        algorithm
            .import_private_key(&one_asymmetric_key(1, &wrong_public), KeyFormat::Der)
            .err(),
        Some(Error::InvalidPrivateKey)
    );

    let invalid = [
        one_asymmetric_key(0, &raw),
        one_asymmetric_key(2, &raw),
        pkcs8(algorithm, &der(0x80, &seed[..63])),
        pkcs8(algorithm, &der(0x81, &seed)),
        pkcs8(algorithm, &[der(0x80, &seed), vec![0]].concat()),
    ];

    for data in invalid {
        assert_eq!(
            algorithm.import_private_key(&data, KeyFormat::Der).err(),
            Some(Error::InvalidEncoding)
        );
    }

    let pem = String::from_utf8(public_key.export_key(KeyFormat::Pem).unwrap()).unwrap();

    let lines: Vec<&str> = pem.lines().collect();

    let base64 = lines[1..lines.len() - 1].concat();

    let rewrapped: Vec<&str> = base64
        .as_bytes()
        .chunks(76)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();

    let accepted = [
        format!(" \t\r\n{pem}\n\n"),
        format!(
            "{}\r\n{}\r\n{}",
            lines[0],
            rewrapped.join("\r\n"),
            lines[lines.len() - 1]
        ),
    ];

    for data in accepted {
        let imported = algorithm
            .import_public_key(data.as_bytes(), KeyFormat::Pem)
            .unwrap();

        assert_eq!(imported, public_key);
    }

    let rejected = [
        pem.replacen('A', "*", 1),
        pem.replacen('A', "\u{e9}", 1),
        pem[..pem.len() - 2].to_owned(),
        format!("x{pem}"),
        pem.replace("PUBLIC", "PRIVATE"),
    ];

    for data in rejected {
        assert_eq!(
            algorithm
                .import_public_key(data.as_bytes(), KeyFormat::Pem)
                .err(),
            Some(Error::InvalidEncoding)
        );
    }
}

#[test]
fn x_wing() {
    for (_, record) in records("xwing/test-vectors.txt", "seed") {
        let pair = hazmat::generate_kem_key_pair(X_WING, &unhex(&record["seed"])).unwrap();

        let context = format!("seed {}", &record["seed"][..16]);

        let pk = pair.public_key.export_key(KeyFormat::Raw).unwrap();

        assert_eq!(pk, unhex(&record["pk"]), "{context}");

        let sk = pair.private_key.export_key(KeyFormat::Raw).unwrap();

        assert_eq!(sk, unhex(&record["sk"]), "{context}");

        let result = hazmat::encapsulate(&pair.public_key, &unhex(&record["eseed"])).unwrap();

        assert_eq!(result.ciphertext, unhex(&record["ct"]), "{context}");

        assert_eq!(result.shared_secret, unhex(&record["ss"]), "{context}");

        let shared_secret = pair.private_key.decapsulate(&result.ciphertext).unwrap();

        assert_eq!(shared_secret, result.shared_secret, "{context}");
    }

    let pair = X_WING.generate_key_pair(&KeyGenOptions::default()).unwrap();

    for format in [KeyFormat::Der, KeyFormat::Pem] {
        assert_eq!(
            pair.public_key.export_key(format).err(),
            Some(Error::Unsupported)
        );

        assert_eq!(
            pair.private_key.export_key(format).err(),
            Some(Error::Unsupported)
        );

        assert_eq!(
            X_WING.import_private_key(b"", format).err(),
            Some(Error::Unsupported)
        );

        assert_eq!(
            X_WING.import_public_key(b"", format).err(),
            Some(Error::Unsupported)
        );
    }

    let raw = pair.private_key.export_key(KeyFormat::Raw).unwrap();

    let imported = X_WING.import_private_key(&raw, KeyFormat::Raw).unwrap();

    assert_eq!(imported.public_key(), pair.public_key);

    assert_eq!(
        X_WING.import_private_key(&raw[1..], KeyFormat::Raw).err(),
        Some(Error::InvalidLength)
    );

    let pk = pair.public_key.export_key(KeyFormat::Raw).unwrap();

    assert_eq!(
        X_WING.import_public_key(&pk[1..], KeyFormat::Raw).err(),
        Some(Error::InvalidLength)
    );

    let mut overflow = pk.clone();

    overflow[0] = 0xFF;

    overflow[1] |= 0x0F;

    assert_eq!(
        X_WING.import_public_key(&overflow, KeyFormat::Raw).err(),
        Some(Error::InvalidPublicKey)
    );

    let hazmat_result = hazmat::encapsulate(&pair.public_key, &[0; 32]);

    assert_eq!(hazmat_result.err(), Some(Error::InvalidLength));
}

#[test]
fn errors_and_debug() {
    assert_eq!(Error::InvalidLength.code(), "INVALID_LENGTH");

    assert_eq!(
        Error::StatePersistFailed.to_string(),
        "STATE_PERSIST_FAILED"
    );

    let pair = hazmat::generate_kem_key_pair(ML_KEM_768, &[1; 64]).unwrap();

    assert_eq!(
        format!("{:?}", pair.private_key),
        "KemPrivateKey { algorithm: KemAlgorithm(\"ML-KEM-768\"), .. }"
    );

    assert_eq!(ML_KEM_768.name(), "ML-KEM-768");

    assert_eq!(X_WING.name(), "X-Wing");

    assert_eq!(
        (X_WING.public_key_size(), X_WING.ciphertext_size()),
        (1216, 1120)
    );

    assert_eq!(
        hazmat::generate_kem_key_pair(ML_KEM_768, &[1; 32]).err(),
        Some(Error::InvalidLength)
    );
}

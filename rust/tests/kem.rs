mod vectors;

use crypto_pq::{
    Error, KemAlgorithm, KeyFormat, KeyGenOptions, ML_KEM_512, ML_KEM_768, ML_KEM_1024, hazmat,
};
use vectors::{der, example_keys, parallel, records, unhex};

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
            *pair.private_key.export_key(KeyFormat::Raw).unwrap(),
            *seed,
            "{context}"
        );

        let expanded = algorithm.import_private_key(&dk, KeyFormat::Raw).unwrap();

        assert_eq!(
            expanded.public_key().export_key(KeyFormat::Raw).unwrap(),
            ek,
            "{context}"
        );

        assert_eq!(
            *expanded.export_key(KeyFormat::Raw).unwrap(),
            *dk,
            "{context}"
        );

        let both = pkcs8(
            algorithm,
            &der(0x30, &[der(0x04, &seed), der(0x04, &dk)].concat()),
        );

        let imported = algorithm.import_private_key(&both, KeyFormat::Der).unwrap();

        assert_eq!(
            *imported.export_key(KeyFormat::Raw).unwrap(),
            *seed,
            "{context}"
        );
    }
}

#[test]
fn acvp_encapsulation_and_decapsulation() {
    check_encapsulation_and_decapsulation("acvp/ML-KEM-encapDecap.txt");
}

// The older ACVP projection, whose decapsulation tests carry expanded keys only.
#[test]
#[ignore = "weekly (fuzz.yml): the full ACVP set"]
fn acvp_full_encapsulation_and_decapsulation() {
    check_encapsulation_and_decapsulation("acvp-full/ML-KEM-encapDecap-v1.txt");
}

fn check_encapsulation_and_decapsulation(name: &str) {
    for (header, record) in records(name, "tcId") {
        let algorithm = algorithm(&header["parameterSet"]);

        let context = format!("tcId {} {}", record["tcId"], header["function"]);

        match header["function"].as_str() {
            "encapsulation" => {
                let public_key = algorithm
                    .import_public_key(&unhex(&record["ek"]), KeyFormat::Raw)
                    .unwrap();

                let result = hazmat::encapsulate(&public_key, &unhex(&record["m"])).unwrap();

                assert_eq!(result.ciphertext, unhex(&record["c"]), "{context}");

                assert_eq!(*result.shared_secret, *unhex(&record["k"]), "{context}");
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

                assert_eq!(*shared_secret, *unhex(&record["k"]), "{context}");
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

// The key pair of each seed, and its expanded decapsulation key, which must agree with the seed
// when both come in one private key.
#[test]
fn wycheproof_key_generation_from_seed() {
    parallel(
        &records("wycheproof/mlkem_keygen_seed.txt", "tcId"),
        |(header, record)| {
            let algorithm = algorithm(&header["parameterSet"]);

            let (seed, ek, dk) = (
                unhex(&record["seed"]),
                unhex(&record["ek"]),
                unhex(&record["dk"]),
            );

            let context = format!("tcId {} {}", record["tcId"], header["parameterSet"]);

            assert_eq!(record["result"], "valid", "{context}");

            let pair = hazmat::generate_kem_key_pair(algorithm, &seed).unwrap();

            assert_eq!(
                pair.public_key.export_key(KeyFormat::Raw).unwrap(),
                ek,
                "{context}"
            );

            let expanded = algorithm.import_private_key(&dk, KeyFormat::Raw).unwrap();

            assert_eq!(
                expanded.public_key().export_key(KeyFormat::Raw).unwrap(),
                ek,
                "{context}"
            );

            let both = pkcs8(
                algorithm,
                &der(0x30, &[der(0x04, &seed), der(0x04, &dk)].concat()),
            );

            algorithm
                .import_private_key(&both, KeyFormat::Der)
                .unwrap_or_else(|error| panic!("{context}: {error}"));
        },
    );
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

                assert_eq!(*shared_secret, *unhex(&record["K"]), "{context}");
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

                assert_eq!(*result.shared_secret, *unhex(&record["K"]), "{context}");
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
                *private_key.decapsulate(&c).unwrap(),
                *unhex(&record["K"]),
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
    for algorithm in [ML_KEM_512, ML_KEM_768, ML_KEM_1024] {
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
            *pair.private_key.decapsulate(ciphertext).unwrap(),
            *encapsulation.shared_secret
        );

        let mut tampered = ciphertext.clone();

        tampered[0] ^= 1;

        assert_ne!(
            *pair.private_key.decapsulate(&tampered).unwrap(),
            *encapsulation.shared_secret
        );

        let truncated = pair
            .private_key
            .decapsulate(&ciphertext[..ciphertext.len() - 1]);

        assert_eq!(truncated.err(), Some(Error::InvalidLength));

        let raw = pair.public_key.export_key(KeyFormat::Raw).unwrap();

        assert_eq!(raw.len(), algorithm.public_key_size());

        let unchecked = algorithm
            .generate_key_pair(&KeyGenOptions::default().with_self_test(false))
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

    assert_eq!(*expanded.export_key(KeyFormat::Raw).unwrap(), *dk);

    assert_eq!(*expanded.export_key(KeyFormat::Der).unwrap(), *expanded_der);

    let seed_der = pkcs8(algorithm, &der(0x80, &seed));

    let seeded = algorithm
        .import_private_key(&seed_der, KeyFormat::Der)
        .unwrap();

    assert_eq!(*seeded.export_key(KeyFormat::Der).unwrap(), *seed_der);

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

    // SPEC 10.4 item 3: text before the BEGIN line and after the END line is ignored, even
    // non-ASCII text or a boundary that starts no line; spaces and tabs may follow a boundary on
    // its line (D-67, the *WSP of RFC 7468).
    let accepted = [
        format!(" \t\r\n{pem}\n\n"),
        format!("Subject: test key\n\u{e9}\n{pem}-----END PUBLIC KEY-----\ntrailing \u{e9}"),
        format!("see -----BEGIN PUBLIC KEY----- below\n{pem}"),
        pem.replacen("-----\n", "----- \t \n", 1),
        format!("{} \t\r\n", pem.trim_end()),
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
        pem.replacen("END PUBLIC", "END PRIVATE", 1),
        format!("{pem}{pem}"),
        format!("{pem}text\n-----BEGIN PUBLIC KEY-----\n"),
        format!("{}x\n", pem.trim_end()),
        pem.replacen("\n", "\nx\n", 1),
        // D-67: a boundary starts its line and is all the line holds.
        format!("  {pem}"),
        format!("\x0b{pem}"),
        pem.replacen("-----\n", "----- x\n", 1),
        pem.replacen("-----\n", "-----\x0b\n", 1),
        pem.replacen("-----\n", "----- \t\x0c\n", 1),
        format!("{}\x0b\n", pem.trim_end()),
        pem.replacen("-----\n", "-----", 1),
        pem.replacen("\n-----END", "-----END", 1),
        pem.replacen("\n-----END", "\n -----END", 1),
        format!("{pem}-----BEGIN PUBLIC KEY-----\n"),
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

// SPEC 10.6 item 4: the structure up to the algorithm identifier, then the OID, then the rest:
// an encoding of another algorithm is a mismatch even when its later fields are malformed too.
#[test]
fn import_order() {
    let pair = hazmat::generate_kem_key_pair(ML_KEM_768, &[5; 64]).unwrap();

    let raw = pair.public_key.export_key(KeyFormat::Raw).unwrap();

    let seed = pair.private_key.export_key(KeyFormat::Raw).unwrap();

    let bits = [&[0][..], &raw].concat();

    let other_public = spki(ML_KEM_512, &[&[1][..], &raw].concat());

    let other_private = der(
        0x30,
        &[
            der(0x02, &[2]),
            der(0x30, &oid(ML_KEM_512)),
            der(0x04, &der(0x80, &seed)),
        ]
        .concat(),
    );

    let same_private = der(
        0x30,
        &[
            der(0x02, &[2]),
            der(0x30, &oid(ML_KEM_768)),
            der(0x04, &der(0x80, &seed)),
        ]
        .concat(),
    );

    assert_eq!(
        ML_KEM_768
            .import_public_key(&other_public, KeyFormat::Der)
            .err(),
        Some(Error::AlgorithmMismatch)
    );

    assert_eq!(
        ML_KEM_768
            .import_public_key(&[spki(ML_KEM_768, &bits), vec![0]].concat(), KeyFormat::Der)
            .err(),
        Some(Error::InvalidEncoding)
    );

    assert_eq!(
        ML_KEM_768
            .import_private_key(&other_private, KeyFormat::Der)
            .err(),
        Some(Error::AlgorithmMismatch)
    );

    assert_eq!(
        ML_KEM_768
            .import_private_key(&same_private, KeyFormat::Der)
            .err(),
        Some(Error::InvalidEncoding)
    );
}

#[test]
fn errors_and_debug() {
    assert_eq!(Error::InvalidLength.code(), "INVALID_LENGTH");

    assert_eq!(
        Error::StatePersistFailed.to_string(),
        "STATE_PERSIST_FAILED: the state store failed"
    );

    let pair = hazmat::generate_kem_key_pair(ML_KEM_768, &[1; 64]).unwrap();

    assert_eq!(
        format!("{:?}", pair.private_key),
        "KemPrivateKey { algorithm: KemAlgorithm(\"ML-KEM-768\"), .. }"
    );

    // SecretBytes prints its length alone (SPEC 6.7 item 3, 23.1 item 6).
    let encapsulation = pair.public_key.encapsulate().unwrap();

    assert_eq!(
        format!("{:?}", encapsulation.shared_secret),
        "SecretBytes(32 bytes, redacted)"
    );

    assert!(!format!("{encapsulation:?}").contains("SecretBytes"));

    assert_eq!(ML_KEM_768.name(), "ML-KEM-768");

    assert_eq!(
        (ML_KEM_768.public_key_size(), ML_KEM_768.ciphertext_size()),
        (1184, 1088)
    );

    assert_eq!(
        hazmat::generate_kem_key_pair(ML_KEM_768, &[1; 32]).err(),
        Some(Error::InvalidLength)
    );
}

fn shareable<T: Send + Sync>() {}

// Keys computed by no one yet are used by many threads at once: whichever thread fills a cache,
// every result must match, and the keys stay usable from any thread.
#[test]
fn concurrent_first_use() {
    shareable::<crypto_pq::KemPublicKey>();

    shareable::<crypto_pq::KemPrivateKey>();

    let algorithm = ML_KEM_768;

    let pair = hazmat::generate_kem_key_pair(algorithm, &[8; 64]).unwrap();

    let encapsulations: Vec<_> = (0..4)
        .map(|_| pair.public_key.encapsulate().unwrap())
        .collect();

    let public = pair.public_key.export_key(KeyFormat::Raw).unwrap();

    let private = pair.private_key.export_key(KeyFormat::Raw).unwrap();

    for _ in 0..20 {
        let public_key = algorithm
            .import_public_key(&public, KeyFormat::Raw)
            .unwrap();

        let private_key = algorithm
            .import_private_key(&private, KeyFormat::Raw)
            .unwrap();

        let barrier = std::sync::Barrier::new(8);

        std::thread::scope(|scope| {
            for thread in 0..8 {
                let (public_key, private_key, barrier) = (&public_key, &private_key, &barrier);

                let (encapsulation, original) = (&encapsulations[thread % 4], &pair.private_key);

                scope.spawn(move || {
                    barrier.wait();

                    if thread % 2 == 0 {
                        let fresh = public_key.encapsulate().unwrap();

                        assert_eq!(
                            *original.decapsulate(&fresh.ciphertext).unwrap(),
                            *fresh.shared_secret
                        );
                    } else {
                        assert_eq!(
                            *private_key.decapsulate(&encapsulation.ciphertext).unwrap(),
                            *encapsulation.shared_secret
                        );
                    }
                });
            }
        });
    }
}

// RFC 9935, Appendix C: every example key, its public key and what it exports as; the
// inconsistent seed and expanded keys of C.4 must be refused, example 2 (a changed secret vector
// under a valid H(ek)) by the checks of the secret vector, SPEC 8.1.4 checks (4) and (5).
#[test]
fn rfc9935_example_keys() {
    example_keys("rfc/mlkem_keys.txt", |record, data, format| {
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

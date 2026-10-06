mod vectors;

use crypto_pq::{
    CSHAKE128, CSHAKE256, Error, KMAC128, KMAC256, MacAlgorithm, MacOptions, SHAKE128, SHAKE256,
    XofAlgorithm, XofOptions, hazmat,
};
use vectors::{records, unhex};

// Uneven sizes reach every buffering path: empty updates, partial blocks and whole blocks.
const PIECES: [usize; 8] = [0, 1, 135, 136, 137, 168, 7, 300];

fn pieces(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();

    let mut offset = 0;

    for size in PIECES.iter().cycle() {
        if offset >= data.len() {
            break;
        }

        let end = (offset + size).min(data.len());

        out.push(&data[offset..end]);

        offset = end;
    }

    out
}

fn cshake(name: &str) -> XofAlgorithm {
    match name {
        "cSHAKE128" => CSHAKE128,
        "cSHAKE256" => CSHAKE256,
        _ => panic!("unknown parameter set {name}"),
    }
}

fn kmac(name: &str) -> MacAlgorithm {
    match name {
        "KMAC128" => KMAC128,
        "KMAC256" => KMAC256,
        _ => panic!("unknown parameter set {name}"),
    }
}

fn check_xof(algorithm: XofAlgorithm, data: &[u8], expected: &[u8], context: &str) {
    assert_eq!(
        algorithm.digest(data, expected.len()),
        expected,
        "{context}"
    );

    let mut out = vec![0; expected.len()];

    algorithm.digest_into(data, &mut out);

    assert_eq!(out, expected, "{context} into");

    let mut xof = algorithm.create();

    for piece in pieces(data) {
        xof.update(piece);
    }

    let mut out = xof.read(1.min(expected.len()));

    out.extend(xof.read(expected.len() - out.len()));

    assert_eq!(out, expected, "{context} streamed");
}

// A KMAC of the tag's length, with the record's customization and mode.
fn configured(name: &str, customization: &[u8], xof: bool, length: usize) -> MacAlgorithm {
    kmac(name)
        .configure(&MacOptions {
            length: Some(length),
            customization,
            xof,
            ..MacOptions::default()
        })
        .unwrap()
}

fn check_mac(algorithm: MacAlgorithm, key: &[u8], data: &[u8], expected: &[u8], context: &str) {
    assert_eq!(algorithm.digest(key, data), expected, "{context}");

    assert!(algorithm.verify(key, data, expected), "{context} verify");

    let mut mac = algorithm.create(key);

    for piece in pieces(data) {
        mac.update(piece);
    }

    assert_eq!(mac.digest(), expected, "{context} streamed");

    assert!(mac.verify(expected), "{context} streamed verify");

    for index in [0, expected.len() - 1] {
        let mut changed = expected.to_vec();

        changed[index] ^= 1;

        assert!(!algorithm.verify(key, data, &changed), "{context} changed");

        assert!(!mac.verify(&changed), "{context} streamed changed");
    }
}

// The NIST examples: cSHAKE samples 1-4, KMAC samples 1-6 and KMACXOF samples 1-6.
#[test]
fn nist_examples() {
    let mut tested = 0;

    for (header, record) in records("nist-examples/cSHAKE.txt", "md") {
        assert!(record["functionName"].is_empty(), "{}", record["name"]);

        let customization = unhex(&record["customization"]);

        let algorithm = cshake(&header["parameterSet"])
            .configure(&XofOptions {
                customization: &customization,
            })
            .unwrap();

        check_xof(
            algorithm,
            &unhex(&record["msg"]),
            &unhex(&record["md"]),
            &record["name"],
        );

        tested += 1;
    }

    for (header, record) in records("nist-examples/KMAC.txt", "mac") {
        let expected = unhex(&record["mac"]);

        let algorithm = configured(
            &header["parameterSet"],
            &unhex(&record["customization"]),
            header["xof"] == "true",
            expected.len(),
        );

        check_mac(
            algorithm,
            &unhex(&record["key"]),
            &unhex(&record["msg"]),
            &expected,
            &record["name"],
        );

        tested += 1;
    }

    assert_eq!(tested, 4 + 12);
}

// The ACVP cSHAKE tests on whole bytes; all of them set a function name, which hazmat takes.
#[test]
fn acvp_cshake() {
    let mut tested = 0;

    for (header, record) in records("acvp/cSHAKE.txt", "md") {
        let algorithm = hazmat::configure_cshake(
            cshake(&header["parameterSet"]),
            &unhex(&record["functionName"]),
            &unhex(&record["customization"]),
        )
        .unwrap();

        check_xof(
            algorithm,
            &unhex(&record["msg"]),
            &unhex(&record["md"]),
            &format!("{} tcId {}", header["parameterSet"], record["tcId"]),
        );

        tested += 1;
    }

    assert_eq!(tested, 5);
}

// The ACVP KMAC tests on whole bytes and the KDF-KMAC tests of SP 800-108r1; a tag marked as not
// passing must not verify.
#[test]
fn acvp_kmac() {
    let (mut passed, mut failed) = (0, 0);

    for (header, record) in records("acvp/KMAC.txt", "mac") {
        let expected = unhex(&record["mac"]);

        let algorithm = configured(
            &header["parameterSet"],
            &unhex(&record["customization"]),
            header["xof"] == "true",
            expected.len(),
        );

        let (key, data) = (unhex(&record["key"]), unhex(&record["msg"]));

        let context = format!(
            "{} {} tcId {}",
            header["parameterSet"], header["source"], record["tcId"]
        );

        match record["testPassed"].as_str() {
            "true" => {
                check_mac(algorithm, &key, &data, &expected, &context);

                passed += 1;
            }
            "false" => {
                assert!(!algorithm.verify(&key, &data, &expected), "{context}");

                assert_ne!(algorithm.digest(&key, &data), expected, "{context}");

                failed += 1;
            }
            other => panic!("{context}: testPassed {other}"),
        }
    }

    assert_eq!((passed, failed), (101, 2));
}

// Wycheproof KMAC without customization: valid tags verify, modified ones do not.
#[test]
fn wycheproof_kmac() {
    let (mut valid, mut invalid) = (0, 0);

    for (header, record) in records("wycheproof/kmac.txt", "tag") {
        let tag = unhex(&record["tag"]);

        let bits: usize = header["tagSize"].parse().expect("tagSize");

        assert_eq!(8 * tag.len(), bits);

        let algorithm = configured(&header["parameterSet"], b"", false, tag.len());

        let (key, data) = (unhex(&record["key"]), unhex(&record["msg"]));

        let context = format!("{} tcId {}", header["parameterSet"], record["tcId"]);

        match record["result"].as_str() {
            "valid" => {
                check_mac(algorithm, &key, &data, &tag, &context);

                valid += 1;
            }
            "invalid" => {
                assert!(!algorithm.verify(&key, &data, &tag), "{context}");

                assert!(!algorithm.create(&key).verify(&tag), "{context} streamed");

                invalid += 1;
            }
            other => panic!("{context}: result {other}"),
        }
    }

    assert_eq!((valid, invalid), (165, 270));
}

// SP 800-185, 3.3: with N and S empty, cSHAKE is SHAKE; the public configure never sets N.
#[test]
fn empty_cshake_is_shake() {
    for (cshake, shake) in [(CSHAKE128, SHAKE128), (CSHAKE256, SHAKE256)] {
        assert_eq!(cshake.digest(b"abc", 200), shake.digest(b"abc", 200));

        let empty = hazmat::configure_cshake(cshake, b"", b"").unwrap();

        assert_eq!(empty.digest(b"abc", 50), shake.digest(b"abc", 50));

        let configured = cshake
            .configure(&XofOptions {
                customization: b"Email Signature",
            })
            .unwrap();

        assert_ne!(configured.digest(b"abc", 32), shake.digest(b"abc", 32));

        // Options replace those set before.
        assert_eq!(configured.configure(&XofOptions::default()), Ok(cshake));

        assert_eq!(
            shake.configure(&XofOptions {
                customization: b"x"
            }),
            Err(Error::InvalidOption)
        );

        assert_eq!(shake.configure(&XofOptions::default()), Ok(shake));

        assert_eq!(
            hazmat::configure_cshake(shake, b"KMAC", b""),
            Err(Error::InvalidOption)
        );
    }
}

// A long customization string spans several blocks of the prefix.
#[test]
fn long_customization() {
    let customization: Vec<u8> = (0..1000).map(|i| (i * 13) as u8).collect();

    for algorithm in [CSHAKE128, CSHAKE256] {
        let configured = algorithm
            .configure(&XofOptions {
                customization: &customization,
            })
            .unwrap();

        let data: Vec<u8> = (0..500).map(|i| i as u8).collect();

        let expected = configured.digest(&data, 300);

        check_xof(configured, &data, &expected, algorithm.name());
    }
}

#[test]
fn kmac_options() {
    for (algorithm, default) in [(KMAC128, 32), (KMAC256, 64)] {
        assert_eq!(algorithm.digest_size(), default);

        assert_eq!(algorithm.configure(&MacOptions::default()), Ok(algorithm));

        // SP 800-185, 8.4.2: no tag under 32 bits.
        for length in [0, 3] {
            let options = MacOptions {
                length: Some(length),
                ..MacOptions::default()
            };

            assert_eq!(algorithm.configure(&options), Err(Error::InvalidOption));
        }

        let short = algorithm
            .configure(&MacOptions {
                length: Some(4),
                ..MacOptions::default()
            })
            .unwrap();

        assert_eq!(short.digest(b"key", b"data").len(), 4);

        for options in [
            MacOptions {
                salt: b"x",
                ..MacOptions::default()
            },
            MacOptions {
                personalization: b"x",
                ..MacOptions::default()
            },
        ] {
            assert_eq!(algorithm.configure(&options), Err(Error::InvalidOption));
        }

        // KMACXOF outputs are prefixes of one another; KMAC binds the length.
        let xof = |length| {
            algorithm
                .configure(&MacOptions {
                    length: Some(length),
                    xof: true,
                    ..MacOptions::default()
                })
                .unwrap()
        };

        let long = xof(200).digest(b"key", b"data");

        assert_eq!(xof(40).digest(b"key", b"data"), long[..40]);

        let fixed = |length| {
            algorithm
                .configure(&MacOptions {
                    length: Some(length),
                    ..MacOptions::default()
                })
                .unwrap()
        };

        assert_ne!(
            fixed(40).digest(b"key", b"data"),
            fixed(200).digest(b"key", b"data")[..40]
        );

        // Keys of any length, an empty one and one longer than a block included.
        for key in [&[][..], &[7; 1000]] {
            let tag = algorithm.digest(key, b"data");

            assert!(algorithm.verify(key, b"data", &tag));
        }

        // A long tag is compared in chunks.
        let tag = fixed(200).digest(b"key", b"data");

        check_mac(fixed(200), b"key", b"data", &tag, "200-byte tag");
    }
}

#[test]
fn properties() {
    assert_eq!(CSHAKE128.name(), "cSHAKE128");

    assert_eq!(CSHAKE256.name(), "cSHAKE256");

    assert_eq!(KMAC128.name(), "KMAC128");

    assert_eq!(KMAC256.name(), "KMAC256");

    let tag = KMAC128.digest(b"key", b"data");

    assert!(!KMAC128.verify(b"key", b"data", &tag[..31]));

    assert!(!KMAC128.verify(b"kez", b"data", &tag));
}

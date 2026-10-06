mod vectors;

use crypto_pq::{Error, HKDF_SHA_256, HKDF_SHA_384, HKDF_SHA_512, KdfAlgorithm, KdfOptions};
use vectors::{records, unhex};

fn algorithm(name: &str) -> KdfAlgorithm {
    match name {
        "HKDF-SHA-256" => HKDF_SHA_256,
        "HKDF-SHA-384" => HKDF_SHA_384,
        "HKDF-SHA-512" => HKDF_SHA_512,
        _ => panic!("unknown parameter set {name}"),
    }
}

// derive, derive_into, and extract followed by expand, all equal to okm.
fn check_derive(
    kdf: KdfAlgorithm,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    okm: &[u8],
    context: &str,
) {
    let options = KdfOptions { salt, info };

    assert_eq!(
        kdf.derive(ikm, okm.len(), &options).unwrap(),
        okm,
        "{context}"
    );

    let mut out = vec![0; okm.len()];

    kdf.derive_into(ikm, &mut out, &options).unwrap();

    assert_eq!(out, okm, "{context} into");

    let prk = kdf
        .extract(
            ikm,
            &KdfOptions {
                salt,
                ..KdfOptions::default()
            },
        )
        .unwrap();

    let expanded = kdf
        .expand(
            &prk,
            okm.len(),
            &KdfOptions {
                info,
                ..KdfOptions::default()
            },
        )
        .unwrap();

    assert_eq!(expanded, okm, "{context} extract and expand");
}

// RFC 5869, A.1 to A.3, with the PRK of each.
#[test]
fn rfc5869() {
    let mut tested = 0;

    for (header, record) in records("rfc/hkdf.txt", "okm") {
        let kdf = algorithm(&header["parameterSet"]);

        let field = |key: &str| unhex(&record[key]);

        let (ikm, salt, info, okm) = (field("ikm"), field("salt"), field("info"), field("okm"));

        assert_eq!(
            okm.len(),
            record["length"].parse::<usize>().expect("length")
        );

        let prk = kdf
            .extract(
                &ikm,
                &KdfOptions {
                    salt: &salt,
                    ..KdfOptions::default()
                },
            )
            .unwrap();

        assert_eq!(prk, field("prk"), "{}", record["name"]);

        let mut into = vec![0; kdf.prk_size()];

        kdf.extract_into(
            &ikm,
            &mut into,
            &KdfOptions {
                salt: &salt,
                ..KdfOptions::default()
            },
        )
        .unwrap();

        assert_eq!(into, prk, "{} into", record["name"]);

        check_derive(kdf, &ikm, &salt, &info, &okm, &record["name"]);

        tested += 1;
    }

    assert_eq!(tested, 3);
}

// Wycheproof: lengths up to 255 HashLen derive the given OKM, and longer ones are refused.
#[test]
fn wycheproof() {
    let (mut valid, mut invalid) = (0, 0);

    for (header, record) in records("wycheproof/hkdf.txt", "okm") {
        let kdf = algorithm(&header["parameterSet"]);

        let field = |key: &str| unhex(&record[key]);

        let (ikm, salt, info) = (field("ikm"), field("salt"), field("info"));

        let size: usize = record["size"].parse().expect("size");

        let context = format!("{} tcId {}", header["parameterSet"], record["tcId"]);

        match record["result"].as_str() {
            "valid" => {
                let okm = field("okm");

                assert_eq!(okm.len(), size, "{context}");

                check_derive(kdf, &ikm, &salt, &info, &okm, &context);

                valid += 1;
            }
            "invalid" => {
                assert!(size > 255 * kdf.prk_size(), "{context}");

                let options = KdfOptions {
                    salt: &salt,
                    info: &info,
                };

                assert_eq!(
                    kdf.derive(&ikm, size, &options),
                    Err(Error::InvalidLength),
                    "{context}"
                );

                invalid += 1;
            }
            other => panic!("{context}: result {other}"),
        }
    }

    assert_eq!((valid, invalid), (243, 9));
}

// ACVP KDA-HKDF of SP 800-56C r1 and r2 as plain HKDF: one extract, then one expand for each of
// the comma-separated info and OKM values.
#[test]
fn acvp() {
    let (mut tests, mut expansions) = (0, 0);

    vectors::parallel(&records("acvp/KDA-HKDF.txt", "okm"), |(header, record)| {
        let kdf = algorithm(&header["parameterSet"]);

        let (ikm, salt) = (unhex(&record["ikm"]), unhex(&record["salt"]));

        let length: usize = record["length"].parse().expect("length");

        let context = format!(
            "{} {} tcId {}",
            header["parameterSet"], header["revision"], record["tcId"]
        );

        let prk = kdf
            .extract(
                &ikm,
                &KdfOptions {
                    salt: &salt,
                    ..KdfOptions::default()
                },
            )
            .unwrap();

        for (info, okm) in record["info"].split(',').zip(record["okm"].split(',')) {
            let (info, okm) = (unhex(info), unhex(okm));

            assert_eq!(okm.len(), length, "{context}");

            let options = KdfOptions {
                info: &info,
                ..KdfOptions::default()
            };

            assert_eq!(
                kdf.expand(&prk, length, &options).unwrap(),
                okm,
                "{context}"
            );

            let options = KdfOptions {
                salt: &salt,
                info: &info,
            };

            assert_eq!(
                kdf.derive(&ikm, length, &options).unwrap(),
                okm,
                "{context}"
            );
        }
    });

    for (_, record) in records("acvp/KDA-HKDF.txt", "okm") {
        tests += 1;

        expansions += record["okm"].split(',').count();
    }

    assert_eq!((tests, expansions), (450, 764));
}

#[test]
fn limits() {
    for kdf in [HKDF_SHA_256, HKDF_SHA_384, HKDF_SHA_512] {
        let size = kdf.prk_size();

        let options = KdfOptions {
            salt: b"salt",
            info: b"info",
        };

        for length in [0, 255 * size + 1] {
            assert_eq!(
                kdf.derive(b"ikm", length, &options),
                Err(Error::InvalidLength)
            );

            assert_eq!(
                kdf.expand(&[1; 64][..size], length, &KdfOptions::default()),
                Err(Error::InvalidLength)
            );
        }

        assert_eq!(
            kdf.derive_into(b"ikm", &mut [], &options),
            Err(Error::InvalidLength)
        );

        // The longest output, and its prefixes: T(i) does not depend on L.
        let longest = kdf.derive(b"ikm", 255 * size, &options).unwrap();

        for length in [1, size - 1, size, size + 1, 3 * size + 5] {
            assert_eq!(
                kdf.derive(b"ikm", length, &options).unwrap(),
                longest[..length]
            );
        }

        // A PRK shorter than HashLen is refused; a longer one, even longer than a block, is a key.
        let prk = kdf.extract(b"ikm", &KdfOptions::default()).unwrap();

        assert_eq!(prk.len(), size);

        let info = KdfOptions {
            info: b"info",
            ..KdfOptions::default()
        };

        assert_eq!(
            kdf.expand(&prk[..size - 1], 32, &info),
            Err(Error::InvalidLength)
        );

        for long in [&[9; 100][..], &[9; 300]] {
            let okm = kdf.expand(long, 2 * size, &info).unwrap();

            assert_eq!(okm.len(), 2 * size);
        }

        // Extract takes no info and Expand no salt.
        assert_eq!(kdf.extract(b"ikm", &options), Err(Error::InvalidOption));

        assert_eq!(kdf.expand(&prk, 32, &options), Err(Error::InvalidOption));

        assert_eq!(
            kdf.extract_into(b"ikm", &mut vec![0; size + 1], &KdfOptions::default()),
            Err(Error::InvalidLength)
        );

        // RFC 5869, 2.2: a missing salt is HashLen zero bytes, as is an empty one.
        let zeros = vec![0; size];

        let zero_salt = KdfOptions {
            salt: &zeros,
            ..KdfOptions::default()
        };

        assert_eq!(kdf.extract(b"ikm", &zero_salt).unwrap(), prk);

        // A long info goes through the general path, which must agree with derive's.
        let info = vec![0x42; 300];

        let long = KdfOptions {
            salt: b"salt",
            info: &info,
        };

        let okm = kdf.derive(b"ikm", size, &long).unwrap();

        assert_eq!(kdf.derive(b"ikm", 2 * size, &long).unwrap()[..size], okm);
    }
}

#[test]
fn properties() {
    for (kdf, name, size) in [
        (HKDF_SHA_256, "HKDF-SHA-256", 32),
        (HKDF_SHA_384, "HKDF-SHA-384", 48),
        (HKDF_SHA_512, "HKDF-SHA-512", 64),
    ] {
        assert_eq!(kdf.name(), name);

        assert_eq!(kdf.prk_size(), size);
    }
}

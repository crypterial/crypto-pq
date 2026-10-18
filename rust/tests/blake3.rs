mod vectors;

use crypto_pq::{
    BLAKE3, BLAKE3_256, BLAKE3_KDF, BLAKE3_MAC, Error, HashOptions, KdfOptions, MacOptions,
    XofOptions, hazmat,
};
use vectors::{Fields, records, unhex};

// Uneven sizes reach every buffering path: empty updates, partial blocks, whole blocks and chunks.
const PIECES: [usize; 9] = [0, 1, 63, 64, 65, 1024, 7, 1025, 200];

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

fn input(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i % 251) as u8).collect()
}

// Every case of the BLAKE3 team's vectors: the 131-byte extended output of each mode, its first
// 32 bytes as the default output, one-shot, streamed and read in pieces.
#[test]
fn official_vectors() {
    let found = records("blake3/test_vectors.txt", "hash");

    for (header, record) in &found {
        let key = unhex(&header["key"]);

        let context = unhex(&header["context_string"]);

        let length: usize = record["input_len"].parse().expect("input_len");

        let data = input(length);

        let hash = unhex(&record["hash"]);

        assert_eq!(BLAKE3_256.digest(&data), hash[..32], "{length}");

        assert_eq!(BLAKE3.digest(&data, hash.len()), hash, "{length} xof");

        let mut hasher = BLAKE3_256.create();

        let mut xof = BLAKE3.create();

        for piece in pieces(&data) {
            hasher.update(piece);

            xof.update(piece);
        }

        assert_eq!(hasher.digest(), hash[..32], "{length} streamed");

        let mut read = xof.read(1);

        read.extend(xof.read(64));

        read.extend(xof.read(hash.len() - 65));

        assert_eq!(read, hash, "{length} read");

        let keyed = unhex(&record["keyed_hash"]);

        assert_eq!(
            BLAKE3_MAC.digest(&key, &data),
            keyed[..32],
            "{length} keyed"
        );

        assert!(BLAKE3_MAC.verify(&key, &data, &keyed[..32]));

        let mut mac = BLAKE3_MAC.create(&key);

        for piece in pieces(&data) {
            mac.update(piece);
        }

        assert_eq!(mac.digest(), keyed[..32], "{length} keyed streamed");

        assert!(mac.verify(&keyed[..32]));

        let mut changed = keyed[..32].to_vec();

        changed[31] ^= 1;

        assert!(!BLAKE3_MAC.verify(&key, &data, &changed));

        assert!(!mac.verify(&changed));

        let derived = unhex(&record["derive_key"]);

        let options = KdfOptions {
            info: &context,
            ..KdfOptions::default()
        };

        assert_eq!(
            BLAKE3_KDF.derive(&data, derived.len(), &options),
            Ok(derived.clone()),
            "{length} derive_key"
        );

        let mut out = [0; 32];

        BLAKE3_KDF.derive_into(&data, &mut out, &options).unwrap();

        assert_eq!(out, derived[..32]);
    }

    assert_eq!(found.len(), 35);
}

#[test]
fn reads_from_any_offset() {
    let data = input(2200);

    let whole = BLAKE3.digest(&data, 700);

    for sizes in [
        &[0, 1, 63, 64, 65, 507][..],
        &[64, 64, 572],
        &[700],
        &[3, 61, 128, 1, 507],
    ] {
        let mut xof = BLAKE3.create();

        xof.update(&data);

        let mut read = Vec::new();

        for &size in sizes {
            read.extend(xof.read(size));
        }

        assert_eq!(read, whole);
    }

    assert!(BLAKE3.digest(&data, 0).is_empty());
}

#[test]
fn options() {
    assert_eq!(BLAKE3_256.name(), "BLAKE3-256");

    assert_eq!(BLAKE3.name(), "BLAKE3");

    assert_eq!(
        (BLAKE3_MAC.name(), BLAKE3_MAC.digest_size()),
        ("BLAKE3-MAC", 32)
    );

    assert_eq!(
        (BLAKE3_KDF.name(), BLAKE3_KDF.prk_size()),
        ("BLAKE3-KDF", 32)
    );

    assert_eq!(
        BLAKE3_256.configure(&HashOptions::default()),
        Ok(BLAKE3_256)
    );

    let salt = HashOptions {
        salt: b"s",
        ..HashOptions::default()
    };

    assert_eq!(BLAKE3_256.configure(&salt), Err(Error::InvalidOption));

    let customization = XofOptions {
        customization: b"c",
    };

    assert_eq!(BLAKE3.configure(&customization), Err(Error::InvalidOption));

    assert_eq!(BLAKE3_MAC.configure(&MacOptions::default()), Ok(BLAKE3_MAC));

    for options in [
        MacOptions {
            length: Some(32),
            ..MacOptions::default()
        },
        MacOptions {
            customization: b"c",
            ..MacOptions::default()
        },
        MacOptions {
            salt: b"s",
            ..MacOptions::default()
        },
        MacOptions {
            xof: true,
            ..MacOptions::default()
        },
    ] {
        assert_eq!(BLAKE3_MAC.configure(&options), Err(Error::InvalidOption));
    }
}

#[test]
fn mac_keys() {
    let tag = BLAKE3_MAC.digest(&[7; 32], b"data");

    for size in [0, 1, 31, 33, 64] {
        assert!(!BLAKE3_MAC.verify(&vec![7; size], b"data", &tag));
    }

    assert!(!BLAKE3_MAC.verify(&[7; 32], b"data", &tag[..31]));
}

#[test]
#[should_panic(expected = "INVALID_LENGTH")]
fn mac_short_key() {
    BLAKE3_MAC.digest(&[0; 31], b"data");
}

#[test]
#[should_panic(expected = "INVALID_LENGTH")]
fn mac_long_key_create() {
    BLAKE3_MAC.create(&[0; 33]);
}

#[test]
fn kdf() {
    let context = KdfOptions {
        info: b"context",
        ..KdfOptions::default()
    };

    let okm = BLAKE3_KDF.derive(b"key material", 1000, &context).unwrap();

    assert_eq!(
        BLAKE3_KDF.derive(b"key material", 33, &context).unwrap(),
        okm[..33]
    );

    assert_ne!(
        BLAKE3_KDF
            .derive(b"key material", 32, &KdfOptions::default())
            .unwrap(),
        okm[..32]
    );

    assert_eq!(
        BLAKE3_KDF.derive(b"ikm", 0, &context),
        Err(Error::InvalidLength)
    );

    let salted = KdfOptions {
        salt: b"s",
        info: b"context",
    };

    assert_eq!(
        BLAKE3_KDF.derive(b"ikm", 32, &salted),
        Err(Error::InvalidOption)
    );

    assert_eq!(
        BLAKE3_KDF.extract(b"ikm", &KdfOptions::default()),
        Err(Error::Unsupported)
    );

    assert_eq!(
        BLAKE3_KDF.expand(&[0; 32], 32, &context),
        Err(Error::Unsupported)
    );

    let mut out = [0; 32];

    assert_eq!(
        BLAKE3_KDF.expand_into(&[0; 32], &mut out, &context),
        Err(Error::Unsupported)
    );

    assert_eq!(
        BLAKE3_KDF.extract_into(b"ikm", &mut out, &KdfOptions::default()),
        Err(Error::Unsupported)
    );
}

#[test]
#[should_panic(expected = "UNSUPPORTED")]
fn update_after_read() {
    let mut xof = BLAKE3.create();

    xof.read(1);

    xof.update(b"more");
}

// One record of the BLAKE3 groups of vectors/cross/blake3.txt (its format is described in
// tools/cross_vectors.py): the result and the output. A MAC key of another length is a programming
// error for digest, which panics; the record names it INVALID_LENGTH.
fn cross(name: &str, record: &Fields) -> (String, Option<Vec<u8>>) {
    let get = |key: &str| {
        record
            .get(key)
            .map(|value| unhex(value))
            .unwrap_or_default()
    };

    let length = || record["outputLength"].parse().expect("outputLength");

    let done = |result: Result<Vec<u8>, Error>| match result {
        Ok(output) => ("ok".to_owned(), Some(output)),
        Err(error) => (error.code().to_owned(), None),
    };

    let (salt, personalization, customization) =
        (get("salt"), get("personalization"), get("customization"));

    let (message, key) = (get("message"), get("key"));

    match name {
        "BLAKE3-256" => {
            let options = HashOptions {
                salt: &salt,
                personalization: &personalization,
            };

            done(
                BLAKE3_256
                    .configure(&options)
                    .map(|algorithm| algorithm.digest(&message)),
            )
        }
        "BLAKE3" => {
            let configured = if record.contains_key("functionName") {
                hazmat::configure_cshake(BLAKE3, &get("functionName"), &customization)
            } else {
                BLAKE3.configure(&XofOptions {
                    customization: &customization,
                })
            };

            done(configured.map(|algorithm| algorithm.digest(&message, length())))
        }
        "BLAKE3-MAC" => {
            let options = MacOptions {
                length: record
                    .get("length")
                    .map(|value| value.parse().expect("length")),
                customization: &customization,
                xof: record.get("xof").is_some_and(|value| value == "true"),
                salt: &salt,
                personalization: &personalization,
            };

            let algorithm = match BLAKE3_MAC.configure(&options) {
                Ok(algorithm) => algorithm,
                Err(error) => return (error.code().to_owned(), None),
            };

            if record["operation"] == "verify" {
                return (
                    algorithm.verify(&key, &message, &get("tag")).to_string(),
                    None,
                );
            }

            if key.len() != 32 {
                return ("INVALID_LENGTH".to_owned(), None);
            }

            done(Ok(algorithm.digest(&key, &message)))
        }
        "BLAKE3-KDF" => {
            let (ikm, info) = (get("ikm"), get("info"));

            let options = KdfOptions {
                salt: &salt,
                info: &info,
            };

            done(match record["operation"].as_str() {
                "derive" => BLAKE3_KDF.derive(&ikm, length(), &options),
                "extract" => BLAKE3_KDF.extract(&ikm, &options),
                "expand" => BLAKE3_KDF.expand(&get("prk"), length(), &options),
                operation => panic!("unknown operation {operation}"),
            })
        }
        _ => panic!("unknown algorithm {name}"),
    }
}

// The cross-language agreement: the Python reference computed these records, every port checks
// them.
#[test]
fn cross_vectors() {
    let mut tested = 0;

    for (header, record) in records("cross/blake3.txt", "result") {
        let name = header["algorithm"].as_str();

        if !name.starts_with("BLAKE3") {
            continue;
        }

        let (result, output) = cross(name, &record);

        assert_eq!(result, record["result"], "{name}: {}", record["name"]);

        if let Some(expected) = record.get("output") {
            assert_eq!(output, Some(unhex(expected)), "{name}: {}", record["name"]);
        }

        tested += 1;
    }

    assert_eq!(tested, 110);
}

mod vectors;

use crypto_pq::{
    BLAKE2B_160, BLAKE2B_256, BLAKE2B_384, BLAKE2B_512, BLAKE2B_MAC, BLAKE2S_128, BLAKE2S_160,
    BLAKE2S_224, BLAKE2S_256, BLAKE2S_MAC, Error, HashAlgorithm, HashOptions, MacAlgorithm,
    MacOptions, SHA_256,
};
use vectors::{records, unhex};

const HASHES: [HashAlgorithm; 8] = [
    BLAKE2B_160,
    BLAKE2B_256,
    BLAKE2B_384,
    BLAKE2B_512,
    BLAKE2S_128,
    BLAKE2S_160,
    BLAKE2S_224,
    BLAKE2S_256,
];

// Uneven sizes reach every buffering path: empty updates, partial blocks and whole blocks.
const PIECES: [usize; 8] = [0, 1, 63, 64, 65, 128, 7, 200];

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

// The function of a header name and digest length: the hash at an RFC 7693 size, or the MAC.
fn hash(name: &str, digest_length: usize) -> HashAlgorithm {
    let prefix = match name {
        "BLAKE2b" => "BLAKE2b-",
        "BLAKE2s" => "BLAKE2s-",
        _ => panic!("unknown function {name}"),
    };

    HASHES
        .into_iter()
        .find(|algorithm| {
            algorithm.name().starts_with(prefix) && algorithm.digest_size() == digest_length
        })
        .unwrap_or_else(|| panic!("no {name} at {digest_length} bytes"))
}

fn mac(name: &str) -> MacAlgorithm {
    match name {
        "BLAKE2b" => BLAKE2B_MAC,
        "BLAKE2s" => BLAKE2S_MAC,
        _ => panic!("unknown function {name}"),
    }
}

// The hash of data in one call, in one update and in uneven pieces.
fn check_hash(algorithm: HashAlgorithm, data: &[u8], expected: &[u8], context: &str) {
    assert_eq!(algorithm.digest(data), expected, "{context}");

    let mut out = vec![0; algorithm.digest_size()];

    algorithm.digest_into(data, &mut out);

    assert_eq!(out, expected, "{context} into");

    let mut hasher = algorithm.create();

    for piece in pieces(data) {
        hasher.update(piece);
    }

    assert_eq!(hasher.digest(), expected, "{context} streamed");
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

    let mut changed = expected.to_vec();

    changed[expected.len() / 2] ^= 0x10;

    assert!(!algorithm.verify(key, data, &changed), "{context} changed");
}

#[test]
fn rfc7693_examples() {
    let mut tested = 0;

    for (header, record) in records("rfc/blake2.txt", "out") {
        if header["kind"] != "example" {
            continue;
        }

        let algorithm = match record["hash"].as_str() {
            "BLAKE2b-512" => BLAKE2B_512,
            "BLAKE2s-256" => BLAKE2S_256,
            other => panic!("unknown hash {other}"),
        };

        check_hash(
            algorithm,
            &unhex(&record["in"]),
            &unhex(&record["out"]),
            &record["name"],
        );

        tested += 1;
    }

    assert_eq!(tested, 2);
}

// RFC 7693, Appendix E: selftest_seq(length, seed).
fn selftest_seq(length: usize, seed: u32) -> Vec<u8> {
    let mut a = 0xDEAD_4BADu32.wrapping_mul(seed);

    let mut b = 1u32;

    (0..length)
        .map(|_| {
            let t = a.wrapping_add(b);

            a = b;

            b = t;

            (t >> 24) as u8
        })
        .collect()
}

#[test]
fn rfc7693_self_test() {
    let mut tested = 0;

    for (header, record) in records("rfc/blake2.txt", "out") {
        if header["kind"] != "selftest" {
            continue;
        }

        let name = record["hash"].as_str();

        let list = |key: &str| -> Vec<usize> {
            record[key]
                .split(',')
                .map(|value| value.parse().expect("length"))
                .collect()
        };

        let mut grand = hash(name, 32).create();

        for digest_length in list("digestLengths") {
            let keyed = mac(name)
                .configure(&MacOptions {
                    length: Some(digest_length),
                    ..MacOptions::default()
                })
                .unwrap();

            for input_length in list("inputLengths") {
                let data = selftest_seq(input_length, input_length as u32);

                grand.update(&hash(name, digest_length).digest(&data));

                let key = selftest_seq(digest_length, digest_length as u32);

                grand.update(&keyed.digest(&key, &data));
            }
        }

        assert_eq!(grand.digest(), unhex(&record["out"]), "{}", record["name"]);

        tested += 1;
    }

    assert_eq!(tested, 2);
}

// The reference KATs: 256 unkeyed hashes and 256 under the longest key, at full length.
#[test]
fn reference_kats() {
    for (file, hash, mac, key_size) in [
        ("blake2/blake2b.txt", BLAKE2B_512, BLAKE2B_MAC, 64),
        ("blake2/blake2s.txt", BLAKE2S_256, BLAKE2S_MAC, 32),
    ] {
        let (mut unkeyed, mut keyed) = (0, 0);

        for (_, record) in records(file, "out") {
            let data = unhex(&record["in"]);

            let key = unhex(&record["key"]);

            let expected = unhex(&record["out"]);

            let context = format!("{file} in {} key {}", data.len(), key.len());

            if key.is_empty() {
                check_hash(hash, &data, &expected, &context);

                unkeyed += 1;
            } else {
                assert_eq!(key.len(), key_size, "{context}");

                check_mac(mac, &key, &data, &expected, &context);

                keyed += 1;
            }
        }

        assert_eq!((unkeyed, keyed), (256, 256), "{file}");
    }
}

// Salt and personalization, which no standard covers: hashlib's values, which the BLAKE2
// reference code confirms, at the RFC 7693 sizes (unkeyed) and MAC lengths 1, half and full.
#[test]
fn derived_salt_and_personalization() {
    let (mut unkeyed, mut keyed) = (0, 0);

    for (header, record) in records("derived/blake2.txt", "out") {
        let name = header["hash"].as_str();

        let length: usize = record["digestLength"].parse().expect("digestLength");

        let field = |key: &str| unhex(&record[key]);

        let (key, salt, personalization) = (field("key"), field("salt"), field("personalization"));

        let (data, expected) = (field("in"), field("out"));

        let context = format!(
            "{name} length {length} key {} salt {} personalization {} in {}",
            key.len(),
            salt.len(),
            personalization.len(),
            data.len()
        );

        if key.is_empty() {
            let algorithm = hash(name, length)
                .configure(&HashOptions {
                    salt: &salt,
                    personalization: &personalization,
                })
                .unwrap();

            check_hash(algorithm, &data, &expected, &context);

            unkeyed += 1;
        } else {
            let algorithm = mac(name)
                .configure(&MacOptions {
                    length: Some(length),
                    salt: &salt,
                    personalization: &personalization,
                    ..MacOptions::default()
                })
                .unwrap();

            assert_eq!(algorithm.digest_size(), length, "{context}");

            check_mac(algorithm, &key, &data, &expected, &context);

            keyed += 1;
        }
    }

    assert_eq!((unkeyed, keyed), (200, 300));
}

// Exact-length salt and personalization equal the shorter values zero-padded.
#[test]
fn short_fields_are_zero_padded() {
    for (algorithm, size) in [(BLAKE2B_512, 16), (BLAKE2S_256, 8)] {
        let short = algorithm
            .configure(&HashOptions {
                salt: b"salt",
                personalization: b"me",
            })
            .unwrap();

        let mut salt = vec![0; size];

        salt[..4].copy_from_slice(b"salt");

        let mut personalization = vec![0; size];

        personalization[..2].copy_from_slice(b"me");

        let padded = algorithm
            .configure(&HashOptions {
                salt: &salt,
                personalization: &personalization,
            })
            .unwrap();

        assert_eq!(short, padded);

        assert_eq!(short.digest(b"data"), padded.digest(b"data"));

        assert_ne!(short.digest(b"data"), algorithm.digest(b"data"));
    }
}

static LONG: [u8; 17] = [0; 17];

#[test]
fn configure_rejects_invalid_options() {
    let long = &LONG;

    for (algorithm, size) in [(BLAKE2B_256, 16), (BLAKE2S_128, 8)] {
        let options = |salt: &'static [u8], personalization: &'static [u8]| HashOptions {
            salt,
            personalization,
        };

        assert!(
            algorithm
                .configure(&options(&long[..size], &long[..size]))
                .is_ok()
        );

        assert_eq!(
            algorithm.configure(&options(&long[..size + 1], b"")),
            Err(Error::InvalidOption)
        );

        assert_eq!(
            algorithm.configure(&options(b"", &long[..size + 1])),
            Err(Error::InvalidOption)
        );

        // Options replace those set before, and none give the algorithm itself.
        let configured = algorithm.configure(&options(b"salt", b"")).unwrap();

        assert_eq!(configured.configure(&HashOptions::default()), Ok(algorithm));
    }

    assert_eq!(
        SHA_256.configure(&HashOptions {
            salt: b"salt",
            ..HashOptions::default()
        }),
        Err(Error::InvalidOption)
    );

    assert_eq!(SHA_256.configure(&HashOptions::default()), Ok(SHA_256));

    for (algorithm, maximum, field) in [(BLAKE2B_MAC, 64, 16), (BLAKE2S_MAC, 32, 8)] {
        for length in [0, maximum + 1] {
            let options = MacOptions {
                length: Some(length),
                ..MacOptions::default()
            };

            assert_eq!(algorithm.configure(&options), Err(Error::InvalidOption));
        }

        for options in [
            MacOptions {
                customization: b"x",
                ..MacOptions::default()
            },
            MacOptions {
                xof: true,
                ..MacOptions::default()
            },
            MacOptions {
                salt: &long[..field + 1],
                ..MacOptions::default()
            },
            MacOptions {
                personalization: &long[..field + 1],
                ..MacOptions::default()
            },
        ] {
            assert_eq!(algorithm.configure(&options), Err(Error::InvalidOption));
        }

        assert_eq!(algorithm.configure(&MacOptions::default()), Ok(algorithm));
    }
}

#[test]
fn properties() {
    let names = [
        "BLAKE2b-160",
        "BLAKE2b-256",
        "BLAKE2b-384",
        "BLAKE2b-512",
        "BLAKE2s-128",
        "BLAKE2s-160",
        "BLAKE2s-224",
        "BLAKE2s-256",
    ];

    for (algorithm, name) in HASHES.into_iter().zip(names) {
        assert_eq!(algorithm.name(), name);

        assert_eq!(algorithm.digest(b"").len(), algorithm.digest_size());
    }

    assert_eq!(BLAKE2B_MAC.name(), "BLAKE2b-MAC");

    assert_eq!(BLAKE2S_MAC.name(), "BLAKE2s-MAC");

    assert_eq!(BLAKE2B_MAC.digest_size(), 64);

    assert_eq!(BLAKE2S_MAC.digest_size(), 32);

    // A tag of another length never verifies.
    let tag = BLAKE2S_MAC.digest(b"key", b"data");

    assert!(!BLAKE2S_MAC.verify(b"key", b"data", &tag[..31]));

    assert!(
        !BLAKE2S_MAC
            .create(b"key")
            .verify(&[tag.as_slice(), &[0]].concat())
    );
}

// verify has a result for it: a key of another length verifies nothing.
#[test]
fn verify_refuses_other_key_lengths() {
    let tag = BLAKE2B_MAC.digest(&[1; 64], b"data");

    for key in [&[][..], &[1; 65]] {
        assert!(!BLAKE2B_MAC.verify(key, b"data", &tag));
    }

    let tag = BLAKE2S_MAC.digest(&[1; 32], b"data");

    for key in [&[][..], &[1; 33]] {
        assert!(!BLAKE2S_MAC.verify(key, b"data", &tag));
    }
}

#[test]
#[should_panic(expected = "INVALID_LENGTH")]
fn empty_key_is_refused() {
    BLAKE2B_MAC.digest(b"", b"data");
}

#[test]
#[should_panic(expected = "INVALID_LENGTH")]
fn long_key_is_refused() {
    BLAKE2S_MAC.create(&[0; 33]);
}

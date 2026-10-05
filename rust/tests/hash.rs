use std::collections::HashMap;
use std::path::Path;

use crypto_pq::{
    HMAC_SHA_224, HMAC_SHA_256, HMAC_SHA_384, HMAC_SHA_512, HashAlgorithm, HmacAlgorithm, SHA_224,
    SHA_256, SHA_384, SHA_512, SHA_512_224, SHA_512_256, SHA3_224, SHA3_256, SHA3_384, SHA3_512,
    SHAKE128, SHAKE256, XofAlgorithm,
};

type Fields = HashMap<String, String>;

const HASHES: [(&str, &str, HashAlgorithm); 10] = [
    ("SHA224", "SHA-224", SHA_224),
    ("SHA256", "SHA-256", SHA_256),
    ("SHA384", "SHA-384", SHA_384),
    ("SHA512", "SHA-512", SHA_512),
    ("SHA512_224", "SHA-512/224", SHA_512_224),
    ("SHA512_256", "SHA-512/256", SHA_512_256),
    ("SHA3_224", "SHA3-224", SHA3_224),
    ("SHA3_256", "SHA3-256", SHA3_256),
    ("SHA3_384", "SHA3-384", SHA3_384),
    ("SHA3_512", "SHA3-512", SHA3_512),
];

const XOFS: [(&str, XofAlgorithm); 2] = [("SHAKE128", SHAKE128), ("SHAKE256", SHAKE256)];

// HMAC.rsp labels each group by digest length in bytes; L=20 is SHA-1, which is out of scope.
const HMACS: [(&str, &str, HmacAlgorithm); 4] = [
    ("28", "HMAC-SHA-224", HMAC_SHA_224),
    ("32", "HMAC-SHA-256", HMAC_SHA_256),
    ("48", "HMAC-SHA-384", HMAC_SHA_384),
    ("64", "HMAC-SHA-512", HMAC_SHA_512),
];

// Uneven sizes reach every buffering path: empty updates, partial blocks and whole blocks.
const PIECES: [usize; 10] = [0, 1, 3, 64, 7, 136, 128, 168, 0, 200];

fn records(name: &str, field: &str) -> Vec<(Fields, Fields)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../vectors/cavp")
        .join(name);

    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));

    let mut header = Fields::new();

    let mut record = Fields::new();

    let mut found = Vec::new();

    for line in text.lines().chain([""]) {
        let line = line.trim();

        if let Some(inner) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            let (key, value) = inner.split_once('=').unwrap_or((inner, ""));

            header.insert(key.trim().to_owned(), value.trim().to_owned());
        } else if let Some((key, value)) = line.split_once('=').filter(|_| !line.starts_with('#')) {
            record.insert(key.trim().to_owned(), value.trim().to_owned());
        } else if !record.is_empty() {
            found.push((header.clone(), std::mem::take(&mut record)));
        }
    }

    let prefix = format!("{field} =");

    let expected = text
        .lines()
        .filter(|line| line.starts_with(&prefix))
        .count();

    let parsed = found
        .iter()
        .filter(|(_, record)| record.contains_key(field))
        .count();

    assert!(
        expected > 0 && parsed == expected,
        "{name}: parsed {parsed} records, expected {expected}"
    );

    found
}

fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "odd hex length");

    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn message(record: &Fields) -> Vec<u8> {
    let bits: usize = record["Len"].parse().expect("Len");

    assert_eq!(bits % 8, 0, "bit-oriented message");

    let mut data = hex(&record["Msg"]);

    data.truncate(bits / 8);

    data
}

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

#[test]
fn hash_vectors() {
    for (prefix, _, algorithm) in HASHES {
        for kind in ["ShortMsg", "LongMsg"] {
            for (_, record) in records(&format!("{prefix}{kind}.rsp"), "MD") {
                let data = message(&record);

                let expected = hex(&record["MD"]);

                assert_eq!(
                    algorithm.digest(&data),
                    expected,
                    "{prefix}{kind} Len = {}",
                    record["Len"]
                );

                let mut hasher = algorithm.create();

                for piece in pieces(&data) {
                    hasher.update(piece);
                }

                assert_eq!(
                    hasher.digest(),
                    expected,
                    "{prefix}{kind} Len = {} streamed",
                    record["Len"]
                );
            }
        }
    }
}

// SHAVS 6.4 and SHA3VS 6.2.3: each checkpoint chains 1000 digests from the previous one.
#[test]
fn hash_monte_carlo() {
    for (prefix, _, algorithm) in HASHES {
        let found = records(&format!("{prefix}Monte.rsp"), "MD");

        let mut seed = hex(&found[0].1["Seed"]);

        for (_, record) in &found[1..] {
            if prefix.starts_with("SHA3_") {
                for _ in 0..1000 {
                    seed = algorithm.digest(&seed);
                }
            } else {
                let mut md = [seed.clone(), seed.clone(), seed];

                for _ in 0..1000 {
                    let next = algorithm.digest(&md.concat());

                    md.rotate_left(1);

                    md[2] = next;
                }

                seed = md[2].clone();
            }

            assert_eq!(
                seed,
                hex(&record["MD"]),
                "{prefix}Monte COUNT = {}",
                record["COUNT"]
            );
        }
    }
}

#[test]
fn hash_digest_is_repeatable() {
    for (_, _, algorithm) in HASHES {
        let mut hasher = algorithm.create();

        hasher.update(b"abc");

        let first = hasher.digest();

        assert_eq!(hasher.digest(), first);

        assert_eq!(first, algorithm.digest(b"abc"));

        hasher.update(b"def");

        assert_eq!(hasher.digest(), algorithm.digest(b"abcdef"));
    }
}

// The _into forms write what the allocating forms return, for messages around every block size,
// and refuse a buffer of any other size.
#[test]
fn digest_into_matches_digest() {
    let data: Vec<u8> = (0..300).map(|i| (i * 7 + 3) as u8).collect();

    for length in [
        0, 1, 55, 56, 63, 64, 111, 112, 127, 128, 135, 136, 167, 168, 300,
    ] {
        let message = &data[..length];

        for (_, _, algorithm) in HASHES {
            let mut out = vec![0; algorithm.digest_size()];

            algorithm.digest_into(message, &mut out);

            assert_eq!(out, algorithm.digest(message));

            let mut hasher = algorithm.create();

            hasher.update(message);

            let mut streamed = vec![0; algorithm.digest_size()];

            hasher.digest_into(&mut streamed);

            assert_eq!(streamed, out);
        }

        for (_, algorithm) in XOFS {
            let mut out = [0; 200];

            algorithm.digest_into(message, &mut out);

            assert_eq!(out.as_slice(), algorithm.digest(message, 200));

            let mut xof = algorithm.create();

            xof.update(message);

            let mut read = [0; 200];

            xof.read_into(&mut read[..77]);

            xof.read_into(&mut read[77..]);

            assert_eq!(read, out);
        }

        for (_, _, algorithm) in HMACS {
            let mut out = vec![0; algorithm.digest_size()];

            algorithm.digest_into(b"key", message, &mut out);

            assert_eq!(out, algorithm.digest(b"key", message));

            let mut hmac = algorithm.create(b"key");

            hmac.update(message);

            let mut streamed = vec![0; algorithm.digest_size()];

            hmac.digest_into(&mut streamed);

            assert_eq!(streamed, out);
        }
    }
}

#[test]
#[should_panic(expected = "INVALID_LENGTH")]
fn digest_into_rejects_another_size() {
    SHA_256.digest_into(b"abc", &mut [0; 31]);
}

#[test]
#[should_panic(expected = "INVALID_LENGTH")]
fn hmac_digest_into_rejects_another_size() {
    HMAC_SHA_512.digest_into(b"key", b"abc", &mut [0; 65]);
}

#[test]
fn hash_properties() {
    for (_, name, algorithm) in HASHES {
        assert_eq!(algorithm.name(), name);

        assert_eq!(algorithm.digest(b"").len(), algorithm.digest_size());
    }
}

#[test]
fn xof_vectors() {
    for (prefix, algorithm) in XOFS {
        for kind in ["ShortMsg", "LongMsg"] {
            for (header, record) in records(&format!("{prefix}{kind}.rsp"), "Output") {
                let data = message(&record);

                let expected = hex(&record["Output"]);

                assert_eq!(
                    header["Outputlen"].parse::<usize>().expect("Outputlen"),
                    8 * expected.len()
                );

                assert_eq!(
                    algorithm.digest(&data, expected.len()),
                    expected,
                    "{prefix}{kind} Len = {}",
                    record["Len"]
                );

                let mut xof = algorithm.create();

                for piece in pieces(&data) {
                    xof.update(piece);
                }

                let mut out = xof.read(1);

                out.extend(xof.read(expected.len() - 1));

                assert_eq!(
                    out, expected,
                    "{prefix}{kind} Len = {} streamed",
                    record["Len"]
                );
            }
        }

        for (_, record) in records(&format!("{prefix}VariableOut.rsp"), "Output") {
            let expected = hex(&record["Output"]);

            assert_eq!(
                record["Outputlen"].parse::<usize>().expect("Outputlen"),
                8 * expected.len()
            );

            assert_eq!(
                algorithm.digest(&hex(&record["Msg"]), expected.len()),
                expected,
                "{prefix}VariableOut COUNT = {}",
                record["COUNT"]
            );
        }
    }
}

// SHA3VS 6.3.3: the next input is the first 16 output bytes, zero-padded, and the last two
// output bytes pick the next output length.
#[test]
fn xof_monte_carlo() {
    for (prefix, algorithm) in XOFS {
        let found = records(&format!("{prefix}Monte.rsp"), "Output");

        let (header, first) = &found[0];

        let bits = |key: &str| header[key].parse::<usize>().expect(key);

        let minimum = bits("Minimum Output Length (bits)") / 8;

        let maximum = bits("Maximum Output Length (bits)") / 8;

        let mut output = hex(&first["Msg"]);

        let mut length = maximum;

        for (_, record) in &found[1..] {
            for _ in 0..1000 {
                let mut message = [0u8; 16];

                let n = output.len().min(16);

                message[..n].copy_from_slice(&output[..n]);

                output = algorithm.digest(&message, length);

                let last = u16::from_be_bytes([output[output.len() - 2], output[output.len() - 1]]);

                length = minimum + usize::from(last) % (maximum - minimum + 1);
            }

            assert_eq!(
                output,
                hex(&record["Output"]),
                "{prefix}Monte COUNT = {}",
                record["COUNT"]
            );

            assert_eq!(
                8 * output.len(),
                record["Outputlen"].parse::<usize>().expect("Outputlen")
            );
        }
    }
}

#[test]
fn xof_streaming_read() {
    for (_, algorithm) in XOFS {
        let mut xof = algorithm.create();

        xof.update(b"abc");

        let out: Vec<u8> = [0, 1, 135, 1, 167, 200, 496]
            .iter()
            .flat_map(|&n| xof.read(n))
            .collect();

        assert_eq!(out, algorithm.digest(b"abc", 1000));
    }
}

#[test]
#[should_panic(expected = "UNSUPPORTED")]
fn xof_update_after_read() {
    let mut xof = SHAKE128.create();

    xof.read(1);

    xof.update(b"x");
}

#[test]
fn xof_properties() {
    assert_eq!(SHAKE128.name(), "SHAKE128");

    assert_eq!(SHAKE256.name(), "SHAKE256");

    assert_eq!(SHAKE256.digest(b"", 0), Vec::<u8>::new());
}

#[test]
fn hmac_vectors() {
    let mut tested = 0;

    for (header, record) in records("HMAC.rsp", "Mac") {
        if header["L"] == "20" {
            continue;
        }

        let (_, _, algorithm) = HMACS
            .iter()
            .find(|(length, _, _)| *length == header["L"])
            .expect("digest length");

        let key = hex(&record["Key"]);

        let data = hex(&record["Msg"]);

        let mac = hex(&record["Mac"]);

        let context = format!("L = {} Count = {}", header["L"], record["Count"]);

        assert_eq!(
            key.len(),
            record["Klen"].parse::<usize>().expect("Klen"),
            "{context}"
        );

        assert_eq!(
            mac.len(),
            record["Tlen"].parse::<usize>().expect("Tlen"),
            "{context}"
        );

        let tag = algorithm.digest(&key, &data);

        assert_eq!(tag[..mac.len()], mac, "{context}");

        let mut hmac = algorithm.create(&key);

        for piece in pieces(&data) {
            hmac.update(piece);
        }

        assert_eq!(hmac.digest(), tag, "{context} streamed");

        assert!(hmac.verify(&tag), "{context}");

        assert!(algorithm.verify(&key, &data, &tag), "{context}");

        tested += 1;
    }

    assert_eq!(tested, 1275);
}

#[test]
fn hmac_verify_rejects() {
    let tag = HMAC_SHA_256.digest(b"key", b"data");

    assert!(!HMAC_SHA_256.verify(b"key", b"data", &tag[..tag.len() - 1]));

    assert!(!HMAC_SHA_256.verify(b"key", b"data", &[tag.as_slice(), &[0]].concat()));

    assert!(!HMAC_SHA_256.verify(b"kez", b"data", &tag));

    for index in 0..tag.len() {
        let mut flipped = tag.clone();

        flipped[index] ^= 0x80;

        assert!(!HMAC_SHA_256.verify(b"key", b"data", &flipped));
    }
}

#[test]
fn hmac_properties() {
    for (_, name, algorithm) in HMACS {
        assert_eq!(algorithm.name(), name);

        assert_eq!(algorithm.digest(b"k", b"").len(), algorithm.digest_size());
    }
}

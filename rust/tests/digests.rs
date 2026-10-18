mod vectors;

use crypto_pq::{
    HMAC_SHA_224, HMAC_SHA_256, HMAC_SHA_384, HMAC_SHA_512, HashAlgorithm, MacAlgorithm, SHA_224,
    SHA_256, SHA_384, SHA_512, SHA_512_224, SHA_512_256, SHA3_224, SHA3_256, SHA3_384, SHA3_512,
    SHAKE128, SHAKE256, XofAlgorithm,
};
use vectors::{Fields, parallel, records, unhex};

const HASHES: [(&str, HashAlgorithm); 10] = [
    ("SHA2-224", SHA_224),
    ("SHA2-256", SHA_256),
    ("SHA2-384", SHA_384),
    ("SHA2-512", SHA_512),
    ("SHA2-512/224", SHA_512_224),
    ("SHA2-512/256", SHA_512_256),
    ("SHA3-224", SHA3_224),
    ("SHA3-256", SHA3_256),
    ("SHA3-384", SHA3_384),
    ("SHA3-512", SHA3_512),
];

const XOFS: [(&str, XofAlgorithm); 2] = [("SHAKE-128", SHAKE128), ("SHAKE-256", SHAKE256)];

const MACS: [(&str, MacAlgorithm); 4] = [
    ("HMAC-SHA2-224", HMAC_SHA_224),
    ("HMAC-SHA2-256", HMAC_SHA_256),
    ("HMAC-SHA2-384", HMAC_SHA_384),
    ("HMAC-SHA2-512", HMAC_SHA_512),
];

// Uneven sizes reach every buffering path: empty updates, partial blocks and whole blocks.
const PIECES: [usize; 10] = [0, 1, 3, 64, 7, 136, 128, 168, 0, 200];

fn find<T: Copy>(table: &[(&str, T)], name: &str) -> T {
    table
        .iter()
        .find(|(known, _)| *known == name)
        .map(|&(_, value)| value)
        .unwrap_or_else(|| panic!("unknown algorithm {name}"))
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

fn context(header: &Fields, record: &Fields) -> String {
    format!(
        "{} {} tcId {}",
        header["algorithm"], header["testType"], record["tcId"]
    )
}

// SHAVS 6.4: each checkpoint chains 1000 digests of the last three. The alternate procedure of
// ACVP keeps every message at the length of the seed, cut or padded with zeros.
fn sha2_monte_carlo(algorithm: HashAlgorithm, seed: Vec<u8>, alternate: bool) -> Vec<Vec<u8>> {
    let length = seed.len();

    let mut md = [seed.clone(), seed.clone(), seed];

    let mut checkpoints = Vec::new();

    for _ in 0..100 {
        for _ in 0..1000 {
            let mut message = md.concat();

            if alternate {
                message.resize(length, 0);
            }

            let next = algorithm.digest(&message);

            md.rotate_left(1);

            md[2] = next;
        }

        checkpoints.push(md[2].clone());

        md = [md[2].clone(), md[2].clone(), md[2].clone()];
    }

    checkpoints
}

// SHA3VS 6.2.3: each checkpoint chains 1000 digests from the previous one.
fn sha3_monte_carlo(algorithm: HashAlgorithm, mut seed: Vec<u8>) -> Vec<Vec<u8>> {
    let mut checkpoints = Vec::new();

    for _ in 0..100 {
        for _ in 0..1000 {
            seed = algorithm.digest(&seed);
        }

        checkpoints.push(seed.clone());
    }

    checkpoints
}

// SHA3VS 6.3.3 in bytes: each message is the first 16 bytes of the previous output, and the next
// output length comes from its last 16 bits, within the group's bounds.
fn shake_monte_carlo(algorithm: XofAlgorithm, seed: Vec<u8>, header: &Fields) -> Vec<Vec<u8>> {
    let minimum = header["minOutLen"].parse::<usize>().expect("minOutLen") / 8;

    let maximum = header["maxOutLen"].parse::<usize>().expect("maxOutLen") / 8;

    let range = maximum - minimum + 1;

    let mut length = maximum;

    let mut output = seed;

    let mut checkpoints = Vec::new();

    for _ in 0..100 {
        for _ in 0..1000 {
            let mut message = [0u8; 16];

            let used = output.len().min(16);

            message[..used].copy_from_slice(&output[..used]);

            output = algorithm.digest(&message, length);

            let last = u16::from_be_bytes([output[output.len() - 2], output[output.len() - 1]]);

            length = minimum + usize::from(last) % range;
        }

        checkpoints.push(output.clone());
    }

    checkpoints
}

fn expected_checkpoints(record: &Fields) -> Vec<Vec<u8>> {
    record["results"]
        .split(',')
        .map(|result| unhex(result.split_once(':').map_or(result, |(md, _)| md)))
        .collect()
}

// ACVP SHA2 and SHA3, the groups whose lengths are whole bytes: AFT one-shot and streamed, and
// the Monte Carlo chains.
#[test]
fn acvp_hashes() {
    let mut found = records("acvp/SHA2.txt", "tcId");

    found.extend(records("acvp/SHA3.txt", "tcId"));

    parallel(&found, |(header, record)| {
        let algorithm = find(&HASHES, &header["algorithm"]);

        let context = context(header, record);

        let message = unhex(&record["msg"]);

        match header["testType"].as_str() {
            "AFT" => {
                let expected = unhex(&record["md"]);

                assert_eq!(algorithm.digest(&message), expected, "{context}");

                let mut hasher = algorithm.create();

                for piece in pieces(&message) {
                    hasher.update(piece);
                }

                assert_eq!(hasher.digest(), expected, "{context} streamed");
            }
            "MCT" => {
                let checkpoints = if header["algorithm"].starts_with("SHA3") {
                    sha3_monte_carlo(algorithm, message)
                } else {
                    sha2_monte_carlo(algorithm, message, header["mctVersion"] == "alternate")
                };

                assert_eq!(checkpoints, expected_checkpoints(record), "{context}");
            }
            kind => panic!("unknown test type {kind}"),
        }
    });
}

// ACVP SHAKE: AFT and VOT one-shot and streamed in two reads, and the Monte Carlo chains.
#[test]
fn acvp_xofs() {
    parallel(&records("acvp/SHAKE.txt", "tcId"), |(header, record)| {
        let algorithm = find(&XOFS, &header["algorithm"]);

        let context = context(header, record);

        let message = unhex(&record["msg"]);

        match header["testType"].as_str() {
            "AFT" | "VOT" => {
                let expected = unhex(&record["md"]);

                let length: usize = record["outLen"].parse().expect("outLen");

                assert_eq!(length, 8 * expected.len(), "{context}");

                assert_eq!(
                    algorithm.digest(&message, expected.len()),
                    expected,
                    "{context}"
                );

                let mut xof = algorithm.create();

                for piece in pieces(&message) {
                    xof.update(piece);
                }

                let mut output = xof.read(expected.len() / 3);

                output.extend(xof.read(expected.len() - output.len()));

                assert_eq!(output, expected, "{context} streamed");
            }
            "MCT" => {
                let checkpoints = shake_monte_carlo(algorithm, message, header);

                let expected = expected_checkpoints(record);

                let bits: Vec<usize> = record["results"]
                    .split(',')
                    .map(|result| result.split_once(':').expect("md:bits").1.parse().unwrap())
                    .collect();

                let lengths: Vec<usize> = checkpoints.iter().map(|md| 8 * md.len()).collect();

                assert_eq!(lengths, bits, "{context}");

                assert_eq!(checkpoints, expected, "{context}");
            }
            kind => panic!("unknown test type {kind}"),
        }
    });
}

fn check_hmac(header: &Fields, record: &Fields, context: &str) {
    let algorithm = find(&MACS, &header["algorithm"]);

    let (key, message, expected) = (
        unhex(&record["key"]),
        unhex(&record["msg"]),
        unhex(&record["mac"]),
    );

    let tag = algorithm.digest(&key, &message);

    assert_eq!(tag[..expected.len()], expected[..], "{context}");

    let mut mac = algorithm.create(&key);

    for piece in pieces(&message) {
        mac.update(piece);
    }

    assert_eq!(mac.digest(), tag, "{context} streamed");

    assert!(algorithm.verify(&key, &message, &tag), "{context} verify");
}

// ACVP HMAC-SHA2, whose tags may be truncated: the computed tag must start with the expected one.
#[test]
fn acvp_hmac() {
    parallel(&records("acvp/HMAC.txt", "tcId"), |(header, record)| {
        check_hmac(header, record, &context(header, record));
    });
}

// RFC 4231, Section 4: test cases 1 to 7, case 5 with a tag truncated to 128 bits.
#[test]
fn rfc4231() {
    for (header, record) in records("rfc/hmac.txt", "tcId") {
        let context = format!("RFC 4231 {} case {}", header["algorithm"], record["tcId"]);

        check_hmac(&header, &record, &context);
    }
}

// ACVP large-data tests: the content repeats to 1, 2, 4 and 8 GiB, hashed in 1 MiB pieces.
#[test]
#[ignore = "weekly (fuzz.yml): hashes 150 GiB"]
fn acvp_large_data() {
    parallel(
        &records("acvp-full/large-data.txt", "tcId"),
        |(header, record)| {
            let algorithm = find(&HASHES, &header["algorithm"]);

            let content = unhex(&record["content"]);

            let chunk: Vec<u8> = content.iter().copied().cycle().take(1 << 20).collect();

            assert_eq!(chunk.len() % content.len(), 0);

            let mut left: u64 = record["length"].parse().expect("length");

            let mut hasher = algorithm.create();

            while left > 0 {
                let size = left.min(chunk.len() as u64) as usize;

                hasher.update(&chunk[..size]);

                left -= size as u64;
            }

            assert_eq!(
                hasher.digest(),
                unhex(&record["md"]),
                "{} tcId {}",
                header["algorithm"],
                record["tcId"]
            );
        },
    );
}

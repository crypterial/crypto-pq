mod vectors;

use crypto_pq::{
    ASCON_CXOF128, ASCON_HASH256, ASCON_XOF128, BLAKE2B_512, BLAKE2S_256, CSHAKE128, CSHAKE256,
    Error, HMAC_SHA_224, HMAC_SHA_256, HMAC_SHA_384, HMAC_SHA_512, HashAlgorithm, HashOptions,
    ML_DSA_65, MacAlgorithm, MacOptions, PreHash, SHA_224, SHA_256, SHA_384, SHA_512, SHA_512_224,
    SHA_512_256, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256, SLH_DSA_SHAKE_128F,
    SignOptions, VerifyOptions, XofAlgorithm, XofOptions, hazmat,
};
use vectors::{Fields, parallel, pieces, records, unhex};

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
const HMACS: [(&str, &str, MacAlgorithm); 4] = [
    ("28", "HMAC-SHA-224", HMAC_SHA_224),
    ("32", "HMAC-SHA-256", HMAC_SHA_256),
    ("48", "HMAC-SHA-384", HMAC_SHA_384),
    ("64", "HMAC-SHA-512", HMAC_SHA_512),
];

// Uneven sizes reach every buffering path: empty updates, partial blocks and whole blocks.
const PIECES: [usize; 10] = [0, 1, 3, 64, 7, 136, 128, 168, 0, 200];

fn message(record: &Fields) -> Vec<u8> {
    let bits: usize = record["Len"].parse().expect("Len");

    assert_eq!(bits % 8, 0, "bit-oriented message");

    let mut data = unhex(&record["Msg"]);

    data.truncate(bits / 8);

    data
}

#[test]
fn hash_vectors() {
    for (prefix, _, algorithm) in HASHES {
        for kind in ["ShortMsg", "LongMsg"] {
            for (_, record) in records(&format!("cavp/{prefix}{kind}.rsp"), "MD") {
                let data = message(&record);

                let expected = unhex(&record["MD"]);

                assert_eq!(
                    algorithm.digest(&data),
                    expected,
                    "{prefix}{kind} Len = {}",
                    record["Len"]
                );

                let mut hasher = algorithm.create();

                for piece in pieces(&data, &PIECES) {
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

// SHAVS 6.4 and SHA3VS 6.2.3, the 100 checkpoints of each chain.
#[test]
fn hash_monte_carlo() {
    for (prefix, _, algorithm) in HASHES {
        let found = records(&format!("cavp/{prefix}Monte.rsp"), "MD");

        let seed = unhex(&found[0].1["Seed"]);

        let checkpoints = if prefix.starts_with("SHA3_") {
            sha3_monte_carlo(algorithm, seed)
        } else {
            sha2_monte_carlo(algorithm, seed, false)
        };

        let expected: Vec<_> = found[1..]
            .iter()
            .map(|(_, record)| unhex(&record["MD"]))
            .collect();

        assert_eq!(checkpoints, expected, "{prefix}Monte");
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

            algorithm.digest_into(message, &mut out).unwrap();

            assert_eq!(out, algorithm.digest(message));

            let mut hasher = algorithm.create();

            hasher.update(message);

            let mut streamed = vec![0; algorithm.digest_size()];

            hasher.digest_into(&mut streamed).unwrap();

            assert_eq!(streamed, out);
        }

        for (_, algorithm) in XOFS {
            let mut out = [0; 200];

            algorithm.digest_into(message, &mut out).unwrap();

            assert_eq!(out.as_slice(), algorithm.digest(message, 200).unwrap());

            let mut xof = algorithm.create();

            xof.update(message).unwrap();

            let mut read = [0; 200];

            xof.read_into(&mut read[..77]).unwrap();

            xof.read_into(&mut read[77..]).unwrap();

            assert_eq!(read, out);
        }

        for (_, _, algorithm) in HMACS {
            let mut out = vec![0; algorithm.digest_size()];

            algorithm.digest_into(b"key", message, &mut out).unwrap();

            assert_eq!(out, algorithm.digest(b"key", message).unwrap());

            let mut hmac = algorithm.create(b"key").unwrap();

            hmac.update(message);

            let mut streamed = vec![0; algorithm.digest_size()];

            hmac.digest_into(&mut streamed).unwrap();

            assert_eq!(streamed, out);
        }
    }
}

// A buffer of another size is an error, not a panic, and is left as it was.
#[test]
fn digest_into_rejects_another_size() {
    for size in [0, 31, 33] {
        let mut out = vec![7; size];

        assert_eq!(
            SHA_256.digest_into(b"abc", &mut out),
            Err(Error::InvalidLength)
        );

        assert_eq!(
            SHA_256.create().digest_into(&mut out),
            Err(Error::InvalidLength)
        );

        assert_eq!(
            HMAC_SHA_256.digest_into(b"key", b"abc", &mut out),
            Err(Error::InvalidLength)
        );

        assert_eq!(
            HMAC_SHA_256.create(b"key").unwrap().digest_into(&mut out),
            Err(Error::InvalidLength)
        );

        assert_eq!(out, vec![7; size]);
    }
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
            for (header, record) in records(&format!("cavp/{prefix}{kind}.rsp"), "Output") {
                let data = message(&record);

                let expected = unhex(&record["Output"]);

                assert_eq!(
                    header["Outputlen"].parse::<usize>().expect("Outputlen"),
                    8 * expected.len()
                );

                assert_eq!(
                    algorithm.digest(&data, expected.len()).unwrap(),
                    expected,
                    "{prefix}{kind} Len = {}",
                    record["Len"]
                );

                let mut xof = algorithm.create();

                for piece in pieces(&data, &PIECES) {
                    xof.update(piece).unwrap();
                }

                let mut out = xof.read(1).unwrap();

                out.extend(xof.read(expected.len() - 1).unwrap());

                assert_eq!(
                    out, expected,
                    "{prefix}{kind} Len = {} streamed",
                    record["Len"]
                );
            }
        }

        for (_, record) in records(&format!("cavp/{prefix}VariableOut.rsp"), "Output") {
            let expected = unhex(&record["Output"]);

            assert_eq!(
                record["Outputlen"].parse::<usize>().expect("Outputlen"),
                8 * expected.len()
            );

            assert_eq!(
                algorithm
                    .digest(&unhex(&record["Msg"]), expected.len())
                    .unwrap(),
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
        let found = records(&format!("cavp/{prefix}Monte.rsp"), "Output");

        let (header, first) = &found[0];

        let bits = |key: &str| header[key].parse::<usize>().expect(key);

        let checkpoints = shake_monte_carlo(
            algorithm,
            unhex(&first["Msg"]),
            bits("Minimum Output Length (bits)") / 8,
            bits("Maximum Output Length (bits)") / 8,
        );

        let expected: Vec<_> = found[1..]
            .iter()
            .map(|(_, record)| unhex(&record["Output"]))
            .collect();

        assert_eq!(checkpoints, expected, "{prefix}Monte");
    }
}

#[test]
fn xof_streaming_read() {
    for (_, algorithm) in XOFS {
        let mut xof = algorithm.create();

        xof.update(b"abc").unwrap();

        let out: Vec<u8> = [0, 1, 135, 1, 167, 200, 496]
            .iter()
            .flat_map(|&n| xof.read(n).unwrap())
            .collect();

        assert_eq!(out, algorithm.digest(b"abc", 1000).unwrap());
    }
}

// Any read ends absorbing, even of no bytes (SPEC 12.2); a later update fails and changes
// nothing.
#[test]
fn xof_update_after_read() {
    for (_, algorithm) in XOFS {
        let mut xof = algorithm.create();

        xof.update(b"abc").unwrap();

        assert_eq!(xof.read(0), Ok(Vec::new()));

        assert_eq!(xof.update(b"x"), Err(Error::Unsupported));

        let mut out = xof.read(10).unwrap();

        assert_eq!(xof.update(b"x"), Err(Error::Unsupported));

        out.extend(xof.read(10).unwrap());

        assert_eq!(out, algorithm.digest(b"abc", 20).unwrap());
    }
}

// SPEC 12.8: at most 2^32 - 1 bytes per call, refused before anything is allocated.
#[cfg(target_pointer_width = "64")]
#[test]
fn xof_output_limit() {
    let beyond = u32::MAX as usize + 1;

    for (_, algorithm) in XOFS {
        assert_eq!(algorithm.digest(b"", beyond), Err(Error::InvalidLength));

        let mut xof = algorithm.create();

        assert_eq!(xof.read(beyond), Err(Error::InvalidLength));

        assert_eq!(xof.update(b"abc"), Ok(()));
    }
}

#[test]
fn xof_properties() {
    assert_eq!(SHAKE128.name(), "SHAKE128");

    assert_eq!(SHAKE256.name(), "SHAKE256");

    assert_eq!(SHAKE256.digest(b"", 0).unwrap(), Vec::<u8>::new());
}

#[test]
fn hmac_vectors() {
    let mut tested = 0;

    for (header, record) in records("cavp/HMAC.rsp", "Mac") {
        if header["L"] == "20" {
            continue;
        }

        let (_, _, algorithm) = HMACS
            .iter()
            .find(|(length, _, _)| *length == header["L"])
            .expect("digest length");

        let key = unhex(&record["Key"]);

        let data = unhex(&record["Msg"]);

        let mac = unhex(&record["Mac"]);

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

        let tag = algorithm.digest(&key, &data).unwrap();

        assert_eq!(tag[..mac.len()], mac, "{context}");

        let mut hmac = algorithm.create(&key).unwrap();

        for piece in pieces(&data, &PIECES) {
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
    let tag = HMAC_SHA_256.digest(b"key", b"data").unwrap();

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

        assert_eq!(
            algorithm.digest(b"k", b"").unwrap().len(),
            algorithm.digest_size()
        );
    }
}

// HMAC takes a length alone (SPEC 6.5): 4 bytes to the hash output, the leftmost bytes of the
// full tag (FIPS 198-1, 5), which verify compares in full.
#[test]
fn hmac_configure() {
    for (_, _, algorithm) in HMACS {
        let size = algorithm.digest_size();

        assert_eq!(algorithm.configure(&MacOptions::default()), Ok(algorithm));

        let full = algorithm.digest(b"key", b"data").unwrap();

        for length in [4, 16, size - 1, size] {
            let truncated = algorithm
                .configure(&MacOptions::default().with_length(length))
                .unwrap();

            assert_eq!(truncated.digest_size(), length);

            let tag = truncated.digest(b"key", b"data").unwrap();

            assert_eq!(tag, full[..length]);

            let mut mac = truncated.create(b"key").unwrap();

            mac.update(b"da");

            mac.update(b"ta");

            assert_eq!(mac.digest(), tag);

            assert!(mac.verify(&tag) && truncated.verify(b"key", b"data", &tag));

            if length < size {
                assert!(!truncated.verify(b"key", b"data", &full));
            }

            assert!(!truncated.verify(b"key", b"data", &full[..length - 1]));

            assert_eq!(truncated.configure(&MacOptions::default()), Ok(algorithm));
        }

        for options in [
            MacOptions::default().with_length(3),
            MacOptions::default().with_length(size + 1),
            MacOptions::default().with_customization(b"x"),
            MacOptions::default().with_xof(true),
            MacOptions::default().with_salt(b"x"),
            MacOptions::default().with_personalization(b"x"),
        ] {
            assert_eq!(algorithm.configure(&options), Err(Error::InvalidOption));
        }
    }

    for (_, _, algorithm) in HASHES {
        assert_eq!(algorithm.configure(&HashOptions::default()), Ok(algorithm));

        let options = HashOptions::default().with_personalization(b"x");

        assert_eq!(algorithm.configure(&options), Err(Error::InvalidOption));
    }
}

// FIPS 204 and FIPS 205 pre-hash only with the hash functions that have a NIST identifier, so
// BLAKE2, Ascon and cSHAKE are refused by sign (hazmat included) and fail verification.
#[test]
fn unapproved_pre_hashes_are_refused() {
    for algorithm in [ML_DSA_65, SLH_DSA_SHAKE_128F] {
        let seed = vec![7; 3 * algorithm.public_key_size() / 2];

        let seed = &seed[..if algorithm == ML_DSA_65 { 32 } else { 48 }];

        let pair = hazmat::generate_signature_key_pair(algorithm, seed).unwrap();

        let customized = CSHAKE256
            .configure(&XofOptions::default().with_customization(b"x"))
            .unwrap();

        let refused: [PreHash; 7] = [
            BLAKE2B_512.into(),
            BLAKE2S_256.into(),
            ASCON_HASH256.into(),
            CSHAKE128.into(),
            customized.into(),
            ASCON_XOF128.into(),
            ASCON_CXOF128.into(),
        ];

        let randomness = vec![1; if algorithm == ML_DSA_65 { 32 } else { 16 }];

        for pre_hash in refused {
            let options = SignOptions::default().with_pre_hash(pre_hash);

            assert_eq!(
                pair.private_key.sign(b"message", &options),
                Err(Error::InvalidOption),
                "{pre_hash:?}"
            );

            assert_eq!(
                hazmat::sign(&pair.private_key, b"message", &randomness, &options),
                Err(Error::InvalidOption),
                "{pre_hash:?}"
            );

            // A signature over the pre-hash of an approved function never verifies under it.
            let signed = pair
                .private_key
                .sign(b"message", &SignOptions::default().with_pre_hash(SHA_512))
                .unwrap();

            let options = VerifyOptions::default().with_pre_hash(pre_hash);

            assert!(!pair.public_key.verify(&signed, b"message", &options));
        }

        // An approved function configured with no options is that function.
        let same = SHA_512.configure(&HashOptions::default()).unwrap();

        let options = SignOptions::default().with_pre_hash(same);

        let signed = pair.private_key.sign(b"message", &options).unwrap();

        let options = VerifyOptions::default().with_pre_hash(same);

        assert!(pair.public_key.verify(&signed, b"message", &options));
    }
}

// ACVP names the SHA-2 functions SHA2-*, and SHAKE with a hyphen.
fn acvp_hash(name: &str) -> HashAlgorithm {
    let name = name.replacen("SHA2-", "SHA-", 1);

    HASHES
        .iter()
        .find(|(_, known, _)| *known == name)
        .map(|&(_, _, algorithm)| algorithm)
        .unwrap_or_else(|| panic!("unknown algorithm {name}"))
}

fn acvp_xof(name: &str) -> XofAlgorithm {
    let name = name.replace('-', "");

    XOFS.iter()
        .find(|(known, _)| *known == name)
        .map(|&(_, algorithm)| algorithm)
        .unwrap_or_else(|| panic!("unknown algorithm {name}"))
}

fn acvp_mac(name: &str) -> MacAlgorithm {
    let name = name.replacen("SHA2-", "SHA-", 1);

    HMACS
        .iter()
        .find(|(_, known, _)| *known == name)
        .map(|&(_, _, algorithm)| algorithm)
        .unwrap_or_else(|| panic!("unknown algorithm {name}"))
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
fn shake_monte_carlo(
    algorithm: XofAlgorithm,
    seed: Vec<u8>,
    minimum: usize,
    maximum: usize,
) -> Vec<Vec<u8>> {
    let range = maximum - minimum + 1;

    let mut length = maximum;

    let mut output = seed;

    let mut checkpoints = Vec::new();

    for _ in 0..100 {
        for _ in 0..1000 {
            let mut message = [0u8; 16];

            let used = output.len().min(16);

            message[..used].copy_from_slice(&output[..used]);

            output = algorithm.digest(&message, length).unwrap();

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
        let algorithm = acvp_hash(&header["algorithm"]);

        let context = context(header, record);

        let message = unhex(&record["msg"]);

        match header["testType"].as_str() {
            "AFT" => {
                let expected = unhex(&record["md"]);

                assert_eq!(algorithm.digest(&message), expected, "{context}");

                let mut hasher = algorithm.create();

                for piece in pieces(&message, &PIECES) {
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
        let algorithm = acvp_xof(&header["algorithm"]);

        let context = context(header, record);

        let message = unhex(&record["msg"]);

        match header["testType"].as_str() {
            "AFT" | "VOT" => {
                let expected = unhex(&record["md"]);

                let length: usize = record["outLen"].parse().expect("outLen");

                assert_eq!(length, 8 * expected.len(), "{context}");

                assert_eq!(
                    algorithm.digest(&message, expected.len()).unwrap(),
                    expected,
                    "{context}"
                );

                let mut xof = algorithm.create();

                for piece in pieces(&message, &PIECES) {
                    xof.update(piece).unwrap();
                }

                let mut output = xof.read(expected.len() / 3).unwrap();

                output.extend(xof.read(expected.len() - output.len()).unwrap());

                assert_eq!(output, expected, "{context} streamed");
            }
            "MCT" => {
                let bits = |key: &str| header[key].parse::<usize>().expect(key);

                let checkpoints = shake_monte_carlo(
                    algorithm,
                    message,
                    bits("minOutLen") / 8,
                    bits("maxOutLen") / 8,
                );

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
    let algorithm = acvp_mac(&header["algorithm"]);

    let (key, message, expected) = (
        unhex(&record["key"]),
        unhex(&record["msg"]),
        unhex(&record["mac"]),
    );

    let tag = algorithm.digest(&key, &message).unwrap();

    assert_eq!(tag[..expected.len()], expected[..], "{context}");

    let mut mac = algorithm.create(&key).unwrap();

    for piece in pieces(&message, &PIECES) {
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
            let algorithm = acvp_hash(&header["algorithm"]);

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

// The generator of the records of vectors/cross that SPEC 1.0 decided after the earlier generator
// wrote the files: the results of the error cases that a rule of 1.0 changed, every state record
// (version 2, SPEC 11.7) with the cases built on one, the whole of treecache.txt, and the
// HashSLH-DSA sections of slhdsa.txt and errors.txt with the records that the SLH-DSA sections of
// errors.txt gain from them (SPEC 9.4). Every other record is a frozen fixture and is kept byte
// for byte. Each case is built as the earlier generator built it, from the same splitmix64
// streams, and states the result it is built to reach; the generator fails if the crate gives
// another. See vectors::fixture for how it writes.

use std::collections::HashSet;

use crypto_pq::{
    HASH_SLH_DSA_SHA2_128F_WITH_SHA256, HASH_SLH_DSA_SHA2_128S_WITH_SHA256,
    HASH_SLH_DSA_SHA2_192F_WITH_SHA512, HASH_SLH_DSA_SHA2_192S_WITH_SHA512,
    HASH_SLH_DSA_SHA2_256F_WITH_SHA512, HASH_SLH_DSA_SHA2_256S_WITH_SHA512,
    HASH_SLH_DSA_SHAKE_128F_WITH_SHAKE128, HASH_SLH_DSA_SHAKE_128S_WITH_SHAKE128,
    HASH_SLH_DSA_SHAKE_192F_WITH_SHAKE256, HASH_SLH_DSA_SHAKE_192S_WITH_SHAKE256,
    HASH_SLH_DSA_SHAKE_256F_WITH_SHAKE256, HASH_SLH_DSA_SHAKE_256S_WITH_SHAKE256, HMAC_SHA_256,
    HSS_LMS, KeyFormat, SHA_256, SLH_DSA_SHA2_128F, SLH_DSA_SHA2_128S, SLH_DSA_SHA2_192F,
    SLH_DSA_SHA2_192S, SLH_DSA_SHA2_256F, SLH_DSA_SHA2_256S, SLH_DSA_SHAKE_128F,
    SLH_DSA_SHAKE_128S, SLH_DSA_SHAKE_192F, SLH_DSA_SHAKE_192S, SLH_DSA_SHAKE_256F,
    SLH_DSA_SHAKE_256S, SignOptions, SignatureAlgorithm, SignatureKeyPair, StatefulKeyGenOptions,
    StatefulLoadOptions, StatefulParameters, StatefulSignatureAlgorithm, XMSS, XMSS_MT, hazmat,
};

use super::vectors::{Fields, Group, Record, der, fixture, get, groups, header, hex, remove, set};
use super::{MemoryStore, execute};

// splitmix64, the fixed generator of the inputs of the earlier files; the same seed gives the same
// bytes, eight per step, little-endian.
struct Stream(u64);

impl Stream {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);

        let mut z = self.0;

        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);

        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);

        z ^ (z >> 31)
    }

    fn bytes(&mut self, length: usize) -> Vec<u8> {
        let mut out = Vec::new();

        while out.len() < length {
            out.extend_from_slice(&self.next().to_le_bytes());
        }

        out.truncate(length);

        out
    }
}

fn flip(data: &[u8], position: usize) -> Vec<u8> {
    let mut out = data.to_vec();

    out[position] ^= 1;

    out
}

fn replaced(data: &[u8], position: usize, value: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();

    out[position..position + value.len()].copy_from_slice(value);

    out
}

fn u32_bytes(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

// The type codes of SPEC 5.3: the LMS types count 5 to 24 and the LM-OTS types 1 to 16, family by
// family (SHA-256 m = 32, SHA-256 m = 24, SHAKE m = 32, SHAKE m = 24).
const FAMILIES: [(&str, &str); 4] = [
    ("SHA256_M32", "SHA256_N32"),
    ("SHA256_M24", "SHA256_N24"),
    ("SHAKE_M32", "SHAKE_N32"),
    ("SHAKE_M24", "SHAKE_N24"),
];

fn lms_code(name: &str) -> u32 {
    for (family, (lms, _)) in FAMILIES.iter().enumerate() {
        for (step, height) in [5, 10, 15, 20, 25].iter().enumerate() {
            if name == format!("LMS_{lms}_H{height}") {
                return (5 + 5 * family + step) as u32;
            }
        }
    }

    panic!("unknown LMS type {name}")
}

fn ots_code(name: &str) -> u32 {
    for (family, (_, ots)) in FAMILIES.iter().enumerate() {
        for (step, width) in [1, 2, 4, 8].iter().enumerate() {
            if name == format!("LMOTS_{ots}_W{width}") {
                return (1 + 4 * family + step) as u32;
            }
        }
    }

    panic!("unknown LM-OTS type {name}")
}

type Levels = [(&'static str, &'static str)];

fn pair_codes(lms: &str, ots: &str) -> Vec<u8> {
    [u32_bytes(lms_code(lms)), u32_bytes(ots_code(ots))].concat()
}

// The parameters field of an HSS state record or tree cache (SPEC 11.7).
fn hss_section(levels: &Levels) -> Vec<u8> {
    let mut out = vec![levels.len() as u8];

    for (lms, ots) in levels {
        out.extend(pair_codes(lms, ots));
    }

    out
}

// The XMSS and XMSS^MT OIDs that the cases use (SPEC 5.3).
const XMSS_SHA2_10_256: u32 = 0x01;

const XMSS_SHAKE256_10_192: u32 = 0x13;

const XMSSMT_SHA2_20_4_192: u32 = 0x22;

const XMSSMT_SHAKE256_20_4_192: u32 = 0x32;

// The checksum of a state record: the first 16 bytes of SHA-256 of the body (SPEC 11.7).
fn seal(body: &[u8]) -> Vec<u8> {
    [body, &SHA_256.digest(body)[..16]].concat()
}

fn edited(state: &[u8], edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut body = state[..state.len() - 16].to_vec();

    edit(&mut body);

    seal(&body)
}

// Where the flags of a version 2 record start: after the HSS level count and type codes, or after
// the OID.
fn flags_at(state: &[u8]) -> usize {
    if state[1] == 1 {
        3 + 8 * usize::from(state[2])
    } else {
        6
    }
}

fn top_secrets_at(state: &[u8]) -> usize {
    flags_at(state) + 9
}

fn with_next(state: &[u8], next: u64) -> Vec<u8> {
    edited(state, |body| {
        let at = flags_at(body) + 1;

        body[at..at + 8].copy_from_slice(&next.to_be_bytes());
    })
}

// A level record claimed for tree 0: a tree number and status 0x00 (SPEC 11.7).
const CLAIMED: [u8; 9] = [0; 9];

// The layout of crypto-pq before 1.0, which 1.0 refuses (SPEC 11.8): version 1, the kind, the
// parameters, then for HSS the seed and the index, for XMSS and XMSS^MT the index and the seed.
fn version_1_hss(levels: &Levels, seed: &[u8], next: u64) -> Vec<u8> {
    seal(&[&[1, 1][..], &hss_section(levels), seed, &next.to_be_bytes()].concat())
}

fn version_1_xmss(kind: u8, oid: u32, seed: &[u8], next: u64) -> Vec<u8> {
    seal(&[&[1, kind][..], &u32_bytes(oid), &next.to_be_bytes(), seed].concat())
}

#[derive(Clone, Copy)]
enum Parameters {
    Levels(&'static Levels),
    Name(&'static str),
}

impl Parameters {
    fn stateful(self) -> StatefulParameters<'static> {
        match self {
            Self::Levels(levels) => StatefulParameters::Levels(levels),
            Self::Name(name) => StatefulParameters::Name(name),
        }
    }

    fn fields(self) -> Record {
        match self {
            Self::Levels(levels) => vec![
                ("lms".into(), join(levels.iter().map(|(lms, _)| *lms))),
                ("ots".into(), join(levels.iter().map(|(_, ots)| *ots))),
            ],
            Self::Name(name) => vec![("parameters".into(), name.into())],
        }
    }
}

fn join<'a>(names: impl Iterator<Item = &'a str>) -> String {
    names.collect::<Vec<_>>().join(",")
}

type Pair = crypto_pq::StatefulKeyPair<MemoryStore>;

// A hazmat key at `index` and the store that holds what it wrote.
fn generate(
    algorithm: StatefulSignatureAlgorithm,
    parameters: Parameters,
    seed: &[u8],
    index: u64,
) -> (Pair, MemoryStore) {
    let store = MemoryStore::default();

    let pair = hazmat::generate_stateful_key_pair(
        algorithm,
        seed,
        index,
        parameters.stateful(),
        store.clone(),
        &StatefulKeyGenOptions::default(),
    )
    .unwrap_or_else(|error| panic!("{}: {error}", algorithm.name()));

    (pair, store)
}

// The state record that a hazmat key at `index` stores: next = index and, at every level, the tree
// that is current for index (SPEC 11.14, D-64 item 1).
fn generated_state(
    algorithm: StatefulSignatureAlgorithm,
    parameters: Parameters,
    seed: &[u8],
    index: u64,
) -> Vec<u8> {
    generate(algorithm, parameters, seed, index)
        .1
        .state()
        .unwrap()
}

fn record(entries: &[(&str, String)]) -> Record {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

fn fields(record: &Record) -> Fields {
    record.iter().cloned().collect()
}

// Runs a record as the runner does and writes its result, output and remaining signatures.
fn run_into(algorithm: &str, record: &mut Record, expected: &str) {
    let header = Fields::from([("algorithm".to_owned(), algorithm.to_owned())]);

    let outcome = execute(&header, &fields(record));

    let name = get(record, "name").unwrap().to_owned();

    assert_eq!(outcome.result, expected, "{algorithm}: {name}");

    set(record, "result", outcome.result);

    match outcome.output {
        Some(output) => set(record, "output", hex(&output)),
        None => remove(record, "output"),
    }

    match outcome.remaining {
        Some(remaining) => set(record, "remaining", remaining.to_string()),
        None => remove(record, "remaining"),
    }
}

// The error cases whose result a rule of SPEC 1.0 decided after the earlier generator wrote them,
// by case name in every algorithm that has the case, with that result.
const DECIDED: [(&str, &str); 24] = [
    // 7.3: the options, the context included, are checked before the lengths.
    (
        "hazmat sign short randomness and long context",
        "INVALID_CONTEXT",
    ),
    // 10.6 item 4: the OID is checked before the rest of the structure.
    (
        "public key der other algorithm and unused bits",
        "ALGORITHM_MISMATCH",
    ),
    (
        "public key der other algorithm and trailing data inside",
        "ALGORITHM_MISMATCH",
    ),
    (
        "private key der other algorithm and trailing data inside",
        "ALGORITHM_MISMATCH",
    ),
    (
        "private key der public key with version 0 and other algorithm",
        "ALGORITHM_MISMATCH",
    ),
    // 11.14 item 4 [D-68]: a hazmat start index at the capacity is refused.
    ("generate index at the capacity", "INVALID_OPTION"),
    // 10.4 item 3 [D-67]: each boundary line starts a line and holds nothing but the boundary,
    // so neither whitespace before BEGIN on its line nor a body on a boundary line is accepted.
    ("public key pem surrounding whitespace", "INVALID_ENCODING"),
    ("public key pem no line breaks", "INVALID_ENCODING"),
    ("private key pem surrounding whitespace", "INVALID_ENCODING"),
    ("private key pem no line breaks", "INVALID_ENCODING"),
    (
        "private key with attributes pem surrounding whitespace",
        "INVALID_ENCODING",
    ),
    (
        "private key with attributes pem no line breaks",
        "INVALID_ENCODING",
    ),
    // 10.4 item 3 [D-32]: text before the BEGIN line and after the END line is ignored.
    ("public key pem text before begin", "ok"),
    ("public key pem text after end", "ok"),
    ("public key pem high byte after end", "ok"),
    ("private key pem text before begin", "ok"),
    ("private key pem text after end", "ok"),
    ("private key pem high byte after end", "ok"),
    ("private key with attributes pem text before begin", "ok"),
    ("private key with attributes pem text after end", "ok"),
    ("private key with attributes pem high byte after end", "ok"),
    // 8.1.4 check (3) [D-61]: every coefficient of the secret vector is below q.
    (
        "private key raw secret coefficient 4095",
        "INVALID_PRIVATE_KEY",
    ),
    (
        "decapsulate with secret coefficients 4095",
        "INVALID_PRIVATE_KEY",
    ),
    (
        "decapsulate with a secret coefficient stored as c + q",
        "INVALID_PRIVATE_KEY",
    ),
];

// The loadPrivateKey and sign cases of one stateful algorithm: a case name, the state record and
// the message to sign, and the result the case is built to reach.
type StateCase = (&'static str, Vec<u8>, Option<Vec<u8>>, &'static str);

fn state_records(algorithm: &str, cases: Vec<StateCase>) -> Vec<Record> {
    cases
        .into_iter()
        .map(|(name, input, message, expected)| {
            let operation = if message.is_some() {
                "sign"
            } else {
                "loadPrivateKey"
            };

            let mut entries = vec![
                ("name", name.to_owned()),
                ("operation", operation.to_owned()),
                ("input", hex(&input)),
            ];

            if let Some(message) = message {
                entries.push(("message", hex(&message)));
            }

            let mut out = record(&entries);

            run_into(algorithm, &mut out, expected);

            out
        })
        .collect()
}

const SMALL: &Levels = &[("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4")];

const EIGHT: &Levels = &[SMALL[0]; 8];

const WIDE: (&str, &str) = ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8");

const TALL: &Levels = &[
    ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W8"),
    ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W8"),
    ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W8"),
];

// SPEC 11.8 and 11.9: the load checks of an HSS record of version 2, in the order of the cases of
// the earlier generator, with version 1 now one of the refused versions.
fn hss_states(seed_check: &str) -> Vec<StateCase> {
    let mut stream = Stream(800);

    let seed = stream.bytes(40);

    assert_eq!(hex(&seed), seed_check, "HSS/LMS seed");

    let message = stream.bytes(20);

    let other_size = stream.bytes(48);

    let state = generated_state(HSS_LMS, Parameters::Levels(SMALL), &seed, 5);

    let body = state[..state.len() - 16].to_vec();

    let secrets = top_secrets_at(&state);

    let eight = generated_state(HSS_LMS, Parameters::Levels(EIGHT), &seed, 5);

    let nine = edited(&eight, |body| {
        body[2] = 9;

        body.splice(67..67, pair_codes(SMALL[0].0, SMALL[0].1));

        body.extend_from_slice(&CLAIMED);
    });

    let two_sizes = edited(&state, |body| {
        body[2] = 2;

        body.splice(11..11, pair_codes(WIDE.0, WIDE.1));

        body.extend_from_slice(&CLAIMED);
    });

    let tall = edited(&state, |body| {
        body[2] = 3;

        body.splice(
            3..11,
            TALL.iter().flat_map(|(lms, ots)| pair_codes(lms, ots)),
        );

        body.extend_from_slice(&[CLAIMED, CLAIMED].concat());
    });

    let other_shake = u32_bytes(ots_code("LMOTS_SHAKE_N24_W4"));

    let invalid = "INVALID_PRIVATE_KEY";

    let mismatch = "ALGORITHM_MISMATCH";

    vec![
        ("load valid", state.clone(), None, "ok"),
        (
            "load index zero",
            generated_state(HSS_LMS, Parameters::Levels(SMALL), &seed, 0),
            None,
            "ok",
        ),
        (
            "load index at the capacity",
            with_next(&state, 32),
            None,
            "ok",
        ),
        (
            "load index beyond the capacity",
            with_next(&state, 33),
            None,
            invalid,
        ),
        (
            "load index of all ones",
            with_next(&state, u64::MAX),
            None,
            invalid,
        ),
        (
            "load checksum changed",
            flip(&state, state.len() - 1),
            None,
            invalid,
        ),
        ("load body changed", flip(&state, 20), None, invalid),
        (
            "load version 1",
            version_1_hss(SMALL, &seed, 5),
            None,
            invalid,
        ),
        (
            "load version 3",
            edited(&state, |b| b[0] = 3),
            None,
            invalid,
        ),
        (
            "load version 0",
            edited(&state, |b| b[0] = 0),
            None,
            invalid,
        ),
        (
            "load xmss kind",
            edited(&state, |b| b[1] = 2),
            None,
            mismatch,
        ),
        (
            "load xmss^mt kind",
            edited(&state, |b| b[1] = 3),
            None,
            mismatch,
        ),
        ("load kind 0", edited(&state, |b| b[1] = 0), None, mismatch),
        ("load kind 4", edited(&state, |b| b[1] = 4), None, mismatch),
        (
            "load version 3 and xmss kind",
            edited(&state, |b| b[..2].copy_from_slice(&[3, 2])),
            None,
            invalid,
        ),
        ("load empty", Vec::new(), None, invalid),
        ("load 17 bytes", state[..17].to_vec(), None, invalid),
        ("load checksum only", seal(&[2, 1]), None, invalid),
        ("load level count only", seal(&[2, 1, 1]), None, invalid),
        (
            "load one byte cut",
            state[..state.len() - 1].to_vec(),
            None,
            invalid,
        ),
        (
            "load one byte appended",
            [&state[..], &[0]].concat(),
            None,
            invalid,
        ),
        (
            "load body one byte short",
            seal(&body[..body.len() - 1]),
            None,
            invalid,
        ),
        (
            "load body one byte long",
            seal(&[&body[..], &[0]].concat()),
            None,
            invalid,
        ),
        (
            "load seed of the other output size",
            edited(&state, |b| {
                b.splice(secrets..secrets + 40, other_size.iter().copied());
            }),
            None,
            invalid,
        ),
        (
            "load zero levels",
            edited(&state, |b| {
                b[2] = 0;

                b.drain(3..11);
            }),
            None,
            invalid,
        ),
        (
            "load level count beyond the body",
            edited(&state, |b| b[2] = 2),
            None,
            invalid,
        ),
        (
            "load level count 255",
            edited(&state, |b| b[2] = 255),
            None,
            invalid,
        ),
        ("load nine levels", nine, None, invalid),
        ("load eight levels", eight, None, "ok"),
        (
            "load unknown lms type",
            edited(&state, |b| b[3..7].copy_from_slice(&u32_bytes(4))),
            None,
            invalid,
        ),
        (
            "load unknown lm-ots type",
            edited(&state, |b| b[7..11].copy_from_slice(&u32_bytes(0))),
            None,
            invalid,
        ),
        (
            "load lm-ots of another hash function",
            edited(&state, |b| b[7..11].copy_from_slice(&other_shake)),
            None,
            invalid,
        ),
        ("load levels of two output sizes", two_sizes, None, invalid),
        ("load total height 65", tall, None, invalid),
        (
            "sign at the capacity",
            with_next(&state, 32),
            Some(message.clone()),
            "KEY_EXHAUSTED",
        ),
        ("sign", state, Some(message), "ok"),
    ]
}

fn xmss_mt_states(seed_check: &str) -> Vec<StateCase> {
    let mut stream = Stream(900);

    let seed = stream.bytes(72);

    assert_eq!(hex(&seed), seed_check, "XMSS^MT seed");

    let message = stream.bytes(30);

    let wide_seed = stream.bytes(96);

    let name = Parameters::Name("XMSSMT-SHAKE256_20/4_192");

    let state = generated_state(XMSS_MT, name, &seed, 0x12345);

    let secrets = top_secrets_at(&state);

    let capacity = 1 << 20;

    let invalid = "INVALID_PRIVATE_KEY";

    let mismatch = "ALGORITHM_MISMATCH";

    vec![
        ("load valid", state.clone(), None, "ok"),
        (
            "load index at the capacity",
            with_next(&state, capacity),
            None,
            "ok",
        ),
        (
            "load index beyond the capacity",
            with_next(&state, capacity + 1),
            None,
            invalid,
        ),
        (
            "load index of all ones",
            with_next(&state, u64::MAX),
            None,
            invalid,
        ),
        (
            "load checksum changed",
            flip(&state, state.len() - 1),
            None,
            invalid,
        ),
        ("load seed changed", flip(&state, 30), None, invalid),
        (
            "load version 1",
            version_1_xmss(3, XMSSMT_SHAKE256_20_4_192, &seed, 0x12345),
            None,
            invalid,
        ),
        (
            "load version 3",
            edited(&state, |b| b[0] = 3),
            None,
            invalid,
        ),
        (
            "load xmss kind",
            edited(&state, |b| b[1] = 2),
            None,
            mismatch,
        ),
        (
            "load hss kind",
            edited(&state, |b| b[1] = 1),
            None,
            mismatch,
        ),
        (
            "load xmss oid",
            edited(&state, |b| {
                b[2..6].copy_from_slice(&u32_bytes(XMSS_SHAKE256_10_192));
            }),
            None,
            invalid,
        ),
        (
            "load unknown oid",
            edited(&state, |b| b[2..6].copy_from_slice(&u32_bytes(0))),
            None,
            invalid,
        ),
        (
            "load seed one byte short",
            edited(&state, |b| {
                b.remove(secrets + 71);
            }),
            None,
            invalid,
        ),
        (
            "load seed one byte long",
            edited(&state, |b| b.insert(secrets + 72, 0)),
            None,
            invalid,
        ),
        (
            "load seed of a 256-bit set",
            edited(&state, |b| {
                b.splice(secrets..secrets + 72, wide_seed.iter().copied());
            }),
            None,
            invalid,
        ),
        ("load oid cut", seal(&[2, 3, 0, 0]), None, invalid),
        ("load checksum only", seal(&[2, 3]), None, invalid),
        ("load 17 bytes", state[..17].to_vec(), None, invalid),
        ("load empty", Vec::new(), None, invalid),
        (
            "load one byte appended",
            [&state[..], &[0]].concat(),
            None,
            invalid,
        ),
        (
            "sign at the capacity",
            with_next(&state, capacity),
            Some(message),
            "KEY_EXHAUSTED",
        ),
    ]
}

fn xmss_states(seed_check: &str) -> Vec<StateCase> {
    let mut stream = Stream(901);

    let seed = stream.bytes(96);

    assert_eq!(hex(&seed), seed_check, "XMSS seed");

    let state = generated_state(XMSS, Parameters::Name("XMSS-SHA2_10_256"), &seed, 0);

    let secrets = top_secrets_at(&state);

    let hss = generated_state(HSS_LMS, Parameters::Levels(&[WIDE]), &seed[..48], 0);

    let invalid = "INVALID_PRIVATE_KEY";

    vec![
        (
            "load version 1",
            version_1_xmss(2, XMSS_SHA2_10_256, &seed, 0),
            None,
            invalid,
        ),
        (
            "load version 3",
            edited(&state, |b| b[0] = 3),
            None,
            invalid,
        ),
        (
            "load xmss^mt kind",
            edited(&state, |b| b[1] = 3),
            None,
            "ALGORITHM_MISMATCH",
        ),
        (
            "load xmss^mt oid",
            edited(&state, |b| {
                b[2..6].copy_from_slice(&u32_bytes(XMSSMT_SHA2_20_4_192));
            }),
            None,
            invalid,
        ),
        (
            "load seed one byte short",
            edited(&state, |b| {
                b.remove(secrets + 95);
            }),
            None,
            invalid,
        ),
        ("load checksum changed", flip(&state, 5), None, invalid),
        ("load hss state", hss, None, "ALGORITHM_MISMATCH"),
    ]
}

fn is_state_case(record: &Record) -> bool {
    matches!(get(record, "operation"), Some("loadPrivateKey" | "sign"))
}

fn input_of(group: &Group, name: &str) -> String {
    group
        .records
        .iter()
        .find(|record| get(record, "name") == Some(name))
        .and_then(|record| get(record, "input"))
        .unwrap_or_else(|| panic!("no case {name}"))
        .to_owned()
}

fn regenerate_errors(keys: &[HashGroup]) {
    let name = "cross/errors.txt";

    let mut found = groups(name);

    let mut decided = HashSet::new();

    let mut written = 0;

    for group in &mut found {
        let algorithm = header(group, "algorithm").to_owned();

        for record in &mut group.records {
            let case = get(record, "name").unwrap().to_owned();

            if let Some(&(_, result)) = DECIDED.iter().find(|(name, _)| *name == case) {
                run_into(&algorithm, record, result);

                decided.insert(case);

                written += 1;
            }
        }

        let cases = match algorithm.as_str() {
            "HSS/LMS" => hss_states(&input_of(group, "generate valid")),
            "XMSS^MT" => xmss_mt_states(&input_of(group, "generate valid")),
            "XMSS" => xmss_states(&input_of(group, "generate xmss^mt name")),
            _ => continue,
        };

        let first = group.records.iter().position(is_state_case).unwrap();

        let count = group.records[first..]
            .iter()
            .take_while(|record| is_state_case(record))
            .count();

        assert!(
            group.records[first + count..]
                .iter()
                .all(|record| !is_state_case(record)),
            "{algorithm}: the state cases are not together"
        );

        group
            .records
            .splice(first..first + count, state_records(&algorithm, cases));
    }

    assert_eq!(decided.len(), DECIDED.len(), "a decided case is missing");

    println!("{name}: {written} decided records");

    regenerate_hash_slh_dsa_errors(&mut found, keys);

    fixture(name, &found);
}

// hss.txt and xmss.txt: the state record a key stores at generation and after its signature.
fn regenerate_signatures(name: &str) {
    let mut found = groups(name);

    for group in &mut found {
        let algorithm = super::stateful_algorithm(header(group, "algorithm"));

        for record in &mut group.records {
            let fields = fields(record);

            let levels = super::levels(&fields);

            let seed = super::field(&fields, "seed");

            let index = fields["index"].parse().unwrap();

            let store = MemoryStore::default();

            let mut pair = hazmat::generate_stateful_key_pair(
                algorithm,
                &seed,
                index,
                super::parameters(&fields, &levels),
                store.clone(),
                &StatefulKeyGenOptions::default(),
            )
            .unwrap();

            set(record, "state", hex(&store.state().unwrap()));

            let signature = pair
                .private_key
                .sign(&super::field(&fields, "message"))
                .unwrap();

            assert_eq!(hex(&signature), fields["signature"], "{name}");

            set(record, "stateAfter", hex(&store.state().unwrap()));
        }
    }

    fixture(name, &found);
}

// A tree cache split into its fields (SPEC 11.10 item 2), to change some and seal it again.
#[derive(Clone)]
struct Tree {
    position: u8,
    tree: u64,
    low: u8,
    height: u8,
    size: u8,
    count: u32,
    nodes: Vec<u8>,
}

#[derive(Clone)]
struct Cache {
    version: u8,
    kind: u8,
    parameters: Vec<u8>,
    public_key: Vec<u8>,
    trees: Vec<Tree>,
}

fn be32(data: &[u8]) -> u32 {
    u32::from_be_bytes(data[..4].try_into().unwrap())
}

fn parse_cache(data: &[u8]) -> Cache {
    let end = if data[1] == 1 {
        3 + 8 * usize::from(data[2])
    } else {
        6
    };

    let size = be32(&data[end..]) as usize;

    let mut trees = Vec::new();

    let mut at = end + 5 + size;

    for _ in 0..data[end + 4 + size] {
        let (size, count) = (data[at + 11], be32(&data[at + 12..]));

        let length = usize::from(size) * count as usize;

        trees.push(Tree {
            position: data[at],
            tree: u64::from_be_bytes(data[at + 1..at + 9].try_into().unwrap()),
            low: data[at + 9],
            height: data[at + 10],
            size,
            count,
            nodes: data[at + 16..at + 16 + length].to_vec(),
        });

        at += 16 + length;
    }

    assert_eq!(data.len(), at + 32);

    Cache {
        version: data[0],
        kind: data[1],
        parameters: data[2..end].to_vec(),
        public_key: data[end + 4..end + 4 + size].to_vec(),
        trees,
    }
}

const TREE_CACHE_LABEL: &[u8] = b"crypto-pq tree cache v1";

// The tag is HMAC-SHA-256 under K = HMAC-SHA-256(label, top secrets) (SPEC 11.10 item 2); a
// change sealed again reaches the checks after the tag, as only the key's holder could make it.
fn seal_cache(cache: &Cache, seed: &[u8]) -> Vec<u8> {
    let mut body = vec![cache.version, cache.kind];

    body.extend_from_slice(&cache.parameters);

    body.extend_from_slice(&u32_bytes(cache.public_key.len() as u32));

    body.extend_from_slice(&cache.public_key);

    body.push(cache.trees.len() as u8);

    for tree in &cache.trees {
        body.push(tree.position);

        body.extend_from_slice(&tree.tree.to_be_bytes());

        body.extend_from_slice(&[tree.low, tree.height, tree.size]);

        body.extend_from_slice(&u32_bytes(tree.count));

        body.extend_from_slice(&tree.nodes);
    }

    let key = HMAC_SHA_256.digest(TREE_CACHE_LABEL, seed).unwrap();

    let tag = HMAC_SHA_256.digest(&key, &body).unwrap();

    [body, tag].concat()
}

// Where the nodes of tree i of a cache start.
fn nodes_at(data: &[u8], i: usize) -> usize {
    let cache = parse_cache(data);

    let before = 7 + cache.parameters.len() + cache.public_key.len();

    before
        + cache.trees[..i]
            .iter()
            .map(|tree| 16 + tree.nodes.len())
            .sum::<usize>()
        + 16
}

type Edit = Box<dyn Fn(&mut Cache)>;

fn sealed(data: &[u8], seed: &[u8], edits: Vec<Edit>) -> Vec<u8> {
    let mut cache = parse_cache(data);

    for edit in edits {
        edit(&mut cache);
    }

    seal_cache(&cache, seed)
}

fn set_tree_number(i: usize, tree: u64) -> Edit {
    Box::new(move |cache| cache.trees[i].tree = tree)
}

fn set_position(i: usize, position: u8) -> Edit {
    Box::new(move |cache| cache.trees[i].position = position)
}

fn change_node(i: usize, position: usize) -> Edit {
    Box::new(move |cache| cache.trees[i].nodes[position] ^= 1)
}

// A tree of another shape, with as many node bytes as its header claims.
fn reshape(i: usize, low: u8, height: u8, size: u8, count: u32) -> Edit {
    Box::new(move |cache| {
        let tree = &mut cache.trees[i];

        let length = usize::from(size) * count as usize;

        tree.nodes = tree.nodes.iter().copied().cycle().take(length).collect();

        (tree.low, tree.height, tree.size, tree.count) = (low, height, size, count);
    })
}

fn keep_trees(order: &'static [usize]) -> Edit {
    Box::new(move |cache| cache.trees = order.iter().map(|&i| cache.trees[i].clone()).collect())
}

fn change_public_key(edit: fn(&[u8]) -> Vec<u8>) -> Edit {
    Box::new(move |cache| cache.public_key = edit(&cache.public_key))
}

fn set_version(version: u8) -> Edit {
    Box::new(move |cache| cache.version = version)
}

fn set_kind(kind: u8) -> Edit {
    Box::new(move |cache| cache.kind = kind)
}

fn set_parameters(parameters: Vec<u8>) -> Edit {
    Box::new(move |cache| cache.parameters = parameters.clone())
}

// The tree cache records of one algorithm: exports, then loads with their outcome. A key that
// loads signs the message when it has an index left, so that restored trees give the same
// signature as built ones.
struct CacheTable {
    algorithm: StatefulSignatureAlgorithm,
    records: Vec<Record>,
    names: HashSet<String>,
}

impl CacheTable {
    fn new(algorithm: StatefulSignatureAlgorithm) -> Self {
        Self {
            algorithm,
            records: Vec::new(),
            names: HashSet::new(),
        }
    }

    fn export(
        &mut self,
        name: &'static str,
        parameters: Parameters,
        seed: &[u8],
        index: u64,
        signed: bool,
        message: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let (mut pair, store) = generate(self.algorithm, parameters, seed, index);

        if signed {
            pair.private_key.sign(message).unwrap();
        }

        let cache = pair.private_key.export_tree_cache().unwrap();

        let state = store.state().unwrap();

        // The parameters are those of the state record, byte for byte.
        let parsed = parse_cache(&cache);

        assert_eq!(parsed.parameters, state[2..2 + parsed.parameters.len()]);

        assert_eq!(seal_cache(&parsed, seed), cache);

        let mut entries = vec![
            ("name".into(), name.into()),
            ("operation".into(), "export".into()),
        ];

        entries.extend(parameters.fields());

        entries.extend(record(&[
            ("seed", hex(seed)),
            ("index", index.to_string()),
            ("signed", signed.to_string()),
        ]));

        self.add(entries, &state, &cache, "ok", Some(message));

        (state, cache)
    }

    fn load(
        &mut self,
        name: &'static str,
        state: &[u8],
        cache: &[u8],
        expected: &str,
        message: Option<&[u8]>,
    ) {
        let entries = record(&[("name", name.into()), ("operation", "load".into())]);

        self.add(entries, state, cache, expected, message);
    }

    fn add(
        &mut self,
        mut record: Record,
        state: &[u8],
        cache: &[u8],
        expected: &str,
        message: Option<&[u8]>,
    ) {
        let name = get(&record, "name").unwrap().to_owned();

        assert!(self.names.insert(name.clone()), "duplicate case {name}");

        set(&mut record, "state", hex(state));

        set(&mut record, "treeCache", hex(cache));

        let options = StatefulLoadOptions::default().with_tree_cache(cache);

        match self
            .algorithm
            .load_private_key(MemoryStore::holding(state), &options)
        {
            Err(error) => set(&mut record, "result", error.code().into()),
            Ok(mut key) => {
                set(&mut record, "result", "ok".into());

                let public_key = key.public_key().export_key(KeyFormat::Raw).unwrap();

                set(&mut record, "publicKey", hex(&public_key));

                set(
                    &mut record,
                    "remaining",
                    key.remaining_signatures().to_string(),
                );

                if let Some(message) = message.filter(|_| key.remaining_signatures() > 0) {
                    set(&mut record, "message", hex(message));

                    set(&mut record, "signature", hex(&key.sign(message).unwrap()));
                }
            }
        }

        assert_eq!(
            get(&record, "result"),
            Some(expected),
            "{}: {name}",
            self.algorithm.name()
        );

        self.records.push(record);
    }

    fn group(self) -> Group {
        Group {
            header: vec![format!("[algorithm = {}]", self.algorithm.name())],
            records: self.records,
        }
    }
}

fn fresh_cache(
    algorithm: StatefulSignatureAlgorithm,
    parameters: Parameters,
    seed: &[u8],
) -> Vec<u8> {
    generate(algorithm, parameters, seed, 0)
        .0
        .private_key
        .export_tree_cache()
        .unwrap()
}

const TWO: &Levels = &[
    ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W2"),
    ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W4"),
];

const ONE: &Levels = &[("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W2")];

// The same seed with other types below the top level: the same public key and tag key, told apart
// by the parameters only.
const OTHER_OTS: &Levels = &[TWO[0], ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8")];

const OTHER_LMS: &Levels = &[TWO[0], ("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W4")];

const SWAPPED: &Levels = &[TWO[1], TWO[0]];

fn tree_cache_hss() -> Group {
    let mut table = CacheTable::new(HSS_LMS);

    let mut stream = Stream(1000);

    let (seed, message) = (stream.bytes(40), stream.bytes(20));

    table.export(
        "one level before signing",
        Parameters::Levels(&[("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4")]),
        &seed,
        5,
        false,
        &message,
    );

    let (seed, message) = (stream.bytes(48), stream.bytes(20));

    table.export(
        "one level of shake",
        Parameters::Levels(&[("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W2")]),
        &seed,
        30,
        true,
        &message,
    );

    let (seed, message) = (stream.bytes(40), stream.bytes(20));

    table.export(
        "three levels",
        Parameters::Levels(&[
            ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W2"),
            ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W4"),
            ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W1"),
        ]),
        &seed,
        5000,
        true,
        &message,
    );

    let (seed, message) = (stream.bytes(48), stream.bytes(20));

    let two = Parameters::Levels(TWO);

    // Index 40 signs with tree 1 of level 1; index 64 has moved on to tree 2.
    let (state, cache) = table.export("two levels", two, &seed, 40, true, &message);

    assert_eq!(state, generated_state(HSS_LMS, two, &seed, 41));

    let later = generated_state(HSS_LMS, two, &seed, 64);

    let capacity = with_next(&state, 1024);

    let (top, lower) = (nodes_at(&cache, 0), nodes_at(&cache, 1));

    // The public key length follows the version, the kind and the parameters, a level count and
    // two pairs of type codes.
    let key_at = 2 + hss_section(TWO).len();

    let count_at = key_at + 4 + parse_cache(&cache).public_key.len();

    let other_mt = fresh_cache(
        XMSS_MT,
        Parameters::Name("XMSSMT-SHA2_20/4_192"),
        &stream.bytes(72),
    );

    let other_key = fresh_cache(HSS_LMS, two, &stream.bytes(48));

    let encoding = "INVALID_ENCODING";

    let w8 = u32_bytes(ots_code("LMOTS_SHA256_N32_W8"));

    // A kind of the other layout misreads the parameters, and no other kind has a layout: such a
    // cache is malformed. Only a cache made for another algorithm is ALGORITHM_MISMATCH.
    let changed: Vec<(&'static str, Vec<u8>, &str)> = vec![
        ("level 0 node changed", flip(&cache, top + 3), encoding),
        ("level 1 node changed", flip(&cache, lower + 40), encoding),
        (
            "first tag byte changed",
            flip(&cache, cache.len() - 32),
            encoding,
        ),
        (
            "last tag byte changed",
            flip(&cache, cache.len() - 1),
            encoding,
        ),
        ("version 0", replaced(&cache, 0, &[0]), encoding),
        ("version 2", replaced(&cache, 0, &[2]), encoding),
        ("xmss kind", replaced(&cache, 1, &[2]), encoding),
        ("xmss^mt kind", replaced(&cache, 1, &[3]), encoding),
        ("kind 0", replaced(&cache, 1, &[0]), encoding),
        ("kind 4", replaced(&cache, 1, &[4]), encoding),
        (
            "version 2 and xmss kind",
            replaced(&cache, 0, &[2, 2]),
            encoding,
        ),
        (
            "xmss kind and one byte cut",
            replaced(&cache, 1, &[2])[..cache.len() - 1].to_vec(),
            encoding,
        ),
        (
            "xmss kind and one byte appended",
            [replaced(&cache, 1, &[2]), vec![0]].concat(),
            encoding,
        ),
        ("xmss^mt cache", other_mt, "ALGORITHM_MISMATCH"),
        ("another key", other_key, encoding),
        // SPEC 6.3 item 2 [D-64 item 3]: an empty tree cache means no cache.
        ("empty", Vec::new(), "ok"),
        ("version only", cache[..1].to_vec(), encoding),
        ("version and kind only", cache[..2].to_vec(), encoding),
        ("cut in the parameters", cache[..10].to_vec(), encoding),
        (
            "cut in the public key length",
            cache[..key_at + 2].to_vec(),
            encoding,
        ),
        (
            "cut in the public key",
            cache[..key_at + 24].to_vec(),
            encoding,
        ),
        (
            "cut before the tree count",
            cache[..count_at].to_vec(),
            encoding,
        ),
        ("cut in a tree header", cache[..top - 5].to_vec(), encoding),
        ("cut in the nodes", cache[..lower + 100].to_vec(), encoding),
        (
            "cut before the tag",
            cache[..cache.len() - 32].to_vec(),
            encoding,
        ),
        ("one byte cut", cache[..cache.len() - 1].to_vec(), encoding),
        ("one byte appended", [&cache[..], &[0]].concat(), encoding),
        (
            "tag appended again",
            [&cache[..], &cache[cache.len() - 32..]].concat(),
            encoding,
        ),
        (
            "parameter level count zero",
            replaced(&cache, 2, &[0]),
            encoding,
        ),
        (
            "parameter level count 255",
            replaced(&cache, 2, &[0xFF]),
            encoding,
        ),
        (
            "lower-level LM-OTS type changed",
            replaced(&cache, 15, &w8),
            encoding,
        ),
        (
            "public key length beyond the cache",
            replaced(&cache, key_at, &u32_bytes(u32::MAX)),
            encoding,
        ),
        (
            "public key length zero",
            replaced(&cache, key_at, &u32_bytes(0)),
            encoding,
        ),
        (
            "tree count one more",
            replaced(&cache, count_at, &[3]),
            encoding,
        ),
        (
            "tree count one less",
            replaced(&cache, count_at, &[1]),
            encoding,
        ),
        (
            "node count beyond the cache",
            replaced(&cache, top - 4, &u32_bytes(u32::MAX)),
            encoding,
        ),
    ];

    for (name, data, expected) in changed {
        table.load(name, &state, &data, expected, Some(&message));
    }

    let mt_seed = stream.bytes(72);

    let other_seed = [&seed[..16], &stream.bytes(32)].concat();

    let invalid = "INVALID_PRIVATE_KEY";

    let states: Vec<(&'static str, Vec<u8>, &str)> = vec![
        ("stale level 1", later.clone(), "ok"),
        ("at the capacity", capacity.clone(), "ok"),
        (
            "index beyond the capacity",
            with_next(&state, 1025),
            invalid,
        ),
        ("damaged state", flip(&state, 10), invalid),
        (
            "xmss^mt state",
            generated_state(
                XMSS_MT,
                Parameters::Name("XMSSMT-SHA2_20/4_192"),
                &mt_seed,
                0,
            ),
            "ALGORITHM_MISMATCH",
        ),
        (
            "same I and another SEED",
            generated_state(HSS_LMS, two, &other_seed, 41),
            encoding,
        ),
        (
            "one level of the same seed",
            generated_state(HSS_LMS, Parameters::Levels(ONE), &seed, 5),
            encoding,
        ),
        (
            "same seed with another lower-level LM-OTS type",
            generated_state(HSS_LMS, Parameters::Levels(OTHER_OTS), &seed, 41),
            encoding,
        ),
        (
            "same seed with another lower-level LMS type",
            generated_state(HSS_LMS, Parameters::Levels(OTHER_LMS), &seed, 41),
            encoding,
        ),
    ];

    for (name, data, expected) in states {
        table.load(name, &data, &cache, expected, Some(&message));
    }

    let root = 62 * 32;

    let flip_last: fn(&[u8]) -> Vec<u8> = |key| flip(key, key.len() - 1);

    let sealed_cases: Vec<(&'static str, Vec<Edit>, &[u8], &str)> = vec![
        (
            "sealed level 1 node changed",
            vec![change_node(1, 40)],
            &state,
            encoding,
        ),
        (
            "sealed level 1 root changed",
            vec![change_node(1, root + 31)],
            &state,
            encoding,
        ),
        (
            "sealed level 0 leaf changed",
            vec![change_node(0, 0)],
            &state,
            encoding,
        ),
        (
            "sealed level 0 root changed",
            vec![change_node(0, root)],
            &state,
            encoding,
        ),
        (
            "sealed public key root changed",
            vec![change_public_key(flip_last)],
            &state,
            encoding,
        ),
        (
            "sealed public key one byte longer",
            vec![change_public_key(|key| [key, &[0u8][..]].concat())],
            &state,
            encoding,
        ),
        (
            "sealed public key one byte shorter",
            vec![change_public_key(|key| key[..key.len() - 1].to_vec())],
            &state,
            encoding,
        ),
        (
            "sealed public key of three levels",
            vec![change_public_key(|key| replaced(key, 0, &u32_bytes(3)))],
            &state,
            encoding,
        ),
        (
            "sealed public key of another lms type",
            vec![change_public_key(|key| {
                replaced(key, 4, &u32_bytes(lms_code("LMS_SHA256_M32_H10")))
            })],
            &state,
            encoding,
        ),
        (
            "sealed public key of another I",
            vec![change_public_key(|key| flip(key, 12))],
            &state,
            encoding,
        ),
        (
            "sealed public key empty",
            vec![change_public_key(|_| Vec::new())],
            &state,
            encoding,
        ),
        ("sealed version 2", vec![set_version(2)], &state, encoding),
        ("sealed xmss kind", vec![set_kind(2)], &state, encoding),
        (
            "sealed parameters of another lower-level LM-OTS type",
            vec![set_parameters(hss_section(OTHER_OTS))],
            &state,
            encoding,
        ),
        (
            "sealed parameters of another lower-level LMS type",
            vec![set_parameters(hss_section(OTHER_LMS))],
            &state,
            encoding,
        ),
        (
            "sealed parameters of one level",
            vec![set_parameters(hss_section(ONE))],
            &state,
            encoding,
        ),
        (
            "sealed parameters of the levels swapped",
            vec![set_parameters(hss_section(SWAPPED))],
            &state,
            encoding,
        ),
        (
            "sealed parameters of no level",
            vec![set_parameters(vec![0])],
            &state,
            encoding,
        ),
        ("sealed no trees", vec![keep_trees(&[])], &state, "ok"),
        ("sealed level 0 only", vec![keep_trees(&[0])], &state, "ok"),
        ("sealed level 1 only", vec![keep_trees(&[1])], &state, "ok"),
        (
            "sealed levels swapped",
            vec![keep_trees(&[1, 0])],
            &state,
            encoding,
        ),
        (
            "sealed level 0 twice",
            vec![keep_trees(&[0, 0])],
            &state,
            encoding,
        ),
        (
            "sealed level 1 twice",
            vec![keep_trees(&[0, 1, 1])],
            &state,
            encoding,
        ),
        ("sealed level 2", vec![set_position(1, 2)], &state, encoding),
        (
            "sealed level 255",
            vec![set_position(1, 255)],
            &state,
            encoding,
        ),
        (
            "sealed height 6",
            vec![reshape(1, 0, 6, 32, 127)],
            &state,
            encoding,
        ),
        (
            "sealed height 4",
            vec![reshape(1, 0, 4, 32, 31)],
            &state,
            encoding,
        ),
        (
            "sealed n 24",
            vec![reshape(1, 0, 5, 24, 63)],
            &state,
            encoding,
        ),
        (
            "sealed n 0",
            vec![reshape(1, 0, 5, 0, 63)],
            &state,
            encoding,
        ),
        (
            "sealed lowest height 1",
            vec![reshape(1, 1, 5, 32, 31)],
            &state,
            encoding,
        ),
        (
            "sealed lowest height above the height",
            vec![reshape(1, 6, 5, 32, 0)],
            &state,
            encoding,
        ),
        (
            "sealed one node less",
            vec![reshape(1, 0, 5, 32, 62)],
            &state,
            encoding,
        ),
        (
            "sealed one node more",
            vec![reshape(1, 0, 5, 32, 64)],
            &state,
            encoding,
        ),
        (
            "sealed no nodes",
            vec![reshape(1, 0, 5, 32, 0)],
            &state,
            encoding,
        ),
        (
            "sealed top tree 1",
            vec![set_tree_number(0, 1)],
            &state,
            "ok",
        ),
        (
            "sealed top tree of all ones",
            vec![set_tree_number(0, u64::MAX)],
            &state,
            "ok",
        ),
        (
            "sealed level 1 as tree 2",
            vec![set_tree_number(1, 2)],
            &state,
            "ok",
        ),
        (
            "sealed level 1 as tree 2 at index 64",
            vec![set_tree_number(1, 2)],
            &later,
            encoding,
        ),
        (
            "sealed stale level 1 changed",
            vec![change_node(1, 40)],
            &later,
            "ok",
        ),
        (
            "sealed stale level 1 of another height",
            vec![set_tree_number(1, 0), reshape(1, 0, 6, 32, 127)],
            &later,
            encoding,
        ),
        // SPEC 11.9 item 5: a load at the capacity ignores the tree cache.
        (
            "sealed top node changed at the capacity",
            vec![change_node(0, 5)],
            &capacity,
            "ok",
        ),
        (
            "sealed top tree 1 changed at the capacity",
            vec![set_tree_number(0, 1), change_node(0, 5)],
            &capacity,
            "ok",
        ),
        (
            "sealed level 1 as tree 32 at the capacity",
            vec![set_tree_number(1, 32), change_node(1, 5)],
            &capacity,
            "ok",
        ),
    ];

    for (name, edits, at, expected) in sealed_cases {
        table.load(
            name,
            at,
            &sealed(&cache, &seed, edits),
            expected,
            Some(&message),
        );
    }

    table.group()
}

fn tree_cache_xmss_mt() -> Group {
    let mut table = CacheTable::new(XMSS_MT);

    let mut stream = Stream(1001);

    let (seed, message) = (stream.bytes(96), stream.bytes(20));

    table.export(
        "four layers before signing",
        Parameters::Name("XMSSMT-SHAKE256_20/4_256"),
        &seed,
        0,
        false,
        &message,
    );

    let (seed, message) = (stream.bytes(96), stream.bytes(20));

    table.export(
        "eight layers",
        Parameters::Name("XMSSMT-SHA2_40/8_256"),
        &seed,
        0x0012_3456_789A,
        true,
        &message,
    );

    let (seed, message) = (stream.bytes(72), stream.bytes(20));

    table.export(
        "twelve layers",
        Parameters::Name("XMSSMT-SHAKE256_60/12_192"),
        &seed,
        0x0FED_CBA9_8765_4321,
        true,
        &message,
    );

    let name = Parameters::Name("XMSSMT-SHA2_20/4_192");

    let (seed, message) = (stream.bytes(72), stream.bytes(20));

    // Index 0x12345 signs with tree 2330 of layer 0; 0x12360 with tree 2331 and the same trees above.
    let (state, cache) = table.export("four layers", name, &seed, 0x12345, true, &message);

    assert_eq!(state, generated_state(XMSS_MT, name, &seed, 0x12346));

    let later = generated_state(XMSS_MT, name, &seed, 0x12360);

    let capacity = with_next(&state, 1 << 20);

    let (top, bottom) = (nodes_at(&cache, 0), nodes_at(&cache, 3));

    let other_hss = fresh_cache(HSS_LMS, Parameters::Levels(SMALL), &stream.bytes(40));

    let other_key = fresh_cache(XMSS_MT, name, &stream.bytes(72));

    let encoding = "INVALID_ENCODING";

    let changed: Vec<(&'static str, Vec<u8>, &str)> = vec![
        ("layer 0 node changed", flip(&cache, bottom + 50), encoding),
        ("top layer node changed", flip(&cache, top + 7), encoding),
        ("tag byte changed", flip(&cache, cache.len() - 9), encoding),
        ("version 2", replaced(&cache, 0, &[2]), encoding),
        ("hss kind", replaced(&cache, 1, &[1]), encoding),
        ("xmss kind", replaced(&cache, 1, &[2]), "ALGORITHM_MISMATCH"),
        ("kind 0", replaced(&cache, 1, &[0]), encoding),
        ("kind 4", replaced(&cache, 1, &[4]), encoding),
        (
            "oid changed",
            replaced(&cache, 2, &u32_bytes(0x21)),
            encoding,
        ),
        ("hss cache", other_hss, "ALGORITHM_MISMATCH"),
        ("another key", other_key, encoding),
        ("one byte cut", cache[..cache.len() - 1].to_vec(), encoding),
        ("one byte appended", [&cache[..], &[0]].concat(), encoding),
        // SPEC 6.3 item 2 [D-64 item 3]: an empty tree cache means no cache.
        ("empty", Vec::new(), "ok"),
    ];

    for (label, data, expected) in changed {
        table.load(label, &state, &data, expected, Some(&message));
    }

    let other_secrets = [&stream.bytes(48)[..], &seed[48..]].concat();

    let states: Vec<(&'static str, Vec<u8>, &str)> = vec![
        ("stale layer 0", later.clone(), "ok"),
        ("at the capacity", capacity.clone(), "ok"),
        (
            "same public seed and other secret seeds",
            generated_state(XMSS_MT, name, &other_secrets, 0x12346),
            encoding,
        ),
        (
            "another parameter set of the same seed",
            generated_state(
                XMSS_MT,
                Parameters::Name("XMSSMT-SHA2_20/2_192"),
                &seed,
                0x12346,
            ),
            encoding,
        ),
    ];

    for (label, data, expected) in states {
        table.load(label, &data, &cache, expected, Some(&message));
    }

    let root = 62 * 24;

    let sealed_cases: Vec<(&'static str, Vec<Edit>, &[u8], &str)> = vec![
        (
            "sealed layer 0 node changed",
            vec![change_node(3, 40)],
            &state,
            encoding,
        ),
        (
            "sealed layer 2 root changed",
            vec![change_node(1, root)],
            &state,
            encoding,
        ),
        (
            "sealed stale layer 0 node changed",
            vec![change_node(3, 40)],
            &later,
            "ok",
        ),
        (
            "sealed layer 0 as tree 2331",
            vec![set_tree_number(3, 2331)],
            &later,
            encoding,
        ),
        (
            "sealed layers swapped",
            vec![keep_trees(&[0, 2, 1, 3])],
            &state,
            encoding,
        ),
        (
            "sealed layer 2 twice",
            vec![keep_trees(&[0, 1, 1, 2, 3])],
            &state,
            encoding,
        ),
        ("sealed layer 4", vec![set_position(0, 4)], &state, encoding),
        (
            "sealed top layer only",
            vec![keep_trees(&[0])],
            &state,
            "ok",
        ),
        (
            "sealed no top layer",
            vec![keep_trees(&[1, 2, 3])],
            &state,
            "ok",
        ),
        ("sealed layer 0 only", vec![keep_trees(&[3])], &state, "ok"),
        (
            "sealed top tree 1",
            vec![set_tree_number(0, 1)],
            &state,
            "ok",
        ),
        // SPEC 11.9 item 5: a load at the capacity ignores the tree cache.
        (
            "sealed top node changed at the capacity",
            vec![change_node(0, 9)],
            &capacity,
            "ok",
        ),
        (
            "sealed top tree 1 changed at the capacity",
            vec![set_tree_number(0, 1), change_node(0, 9)],
            &capacity,
            "ok",
        ),
        (
            "sealed public seed changed",
            vec![change_public_key(|key| flip(key, key.len() - 1))],
            &state,
            encoding,
        ),
        (
            "sealed root changed",
            vec![change_public_key(|key| flip(key, 4))],
            &state,
            encoding,
        ),
        (
            "sealed oid of another set",
            vec![change_public_key(|key| replaced(key, 0, &u32_bytes(0x32)))],
            &state,
            encoding,
        ),
        (
            "sealed height 10",
            vec![reshape(2, 0, 10, 24, 2047)],
            &state,
            encoding,
        ),
        (
            "sealed n 32",
            vec![reshape(2, 0, 5, 32, 63)],
            &state,
            encoding,
        ),
        ("sealed hss kind", vec![set_kind(1)], &state, encoding),
        (
            "sealed xmss kind",
            vec![set_kind(2)],
            &state,
            "ALGORITHM_MISMATCH",
        ),
        (
            "sealed parameters of another set",
            vec![set_parameters(u32_bytes(0x21).to_vec())],
            &state,
            encoding,
        ),
    ];

    for (label, edits, at, expected) in sealed_cases {
        table.load(
            label,
            at,
            &sealed(&cache, &seed, edits),
            expected,
            Some(&message),
        );
    }

    table.group()
}

fn tree_cache_xmss() -> Group {
    let mut table = CacheTable::new(XMSS);

    let mut stream = Stream(1002);

    let name = Parameters::Name("XMSS-SHA2_10_192");

    let (seed, message) = (stream.bytes(72), stream.bytes(20));

    let (state, cache) = table.export("one tree", name, &seed, 1000, true, &message);

    assert_eq!(state, generated_state(XMSS, name, &seed, 1001));

    let other_mt = fresh_cache(
        XMSS_MT,
        Parameters::Name("XMSSMT-SHA2_20/4_192"),
        &stream.bytes(72),
    );

    let encoding = "INVALID_ENCODING";

    let changed: Vec<(&'static str, Vec<u8>, &str)> = vec![
        (
            "node changed",
            flip(&cache, nodes_at(&cache, 0) + 77),
            encoding,
        ),
        ("tag byte changed", flip(&cache, cache.len() - 2), encoding),
        (
            "xmss^mt kind",
            replaced(&cache, 1, &[3]),
            "ALGORITHM_MISMATCH",
        ),
        ("hss kind", replaced(&cache, 1, &[1]), encoding),
        ("xmss^mt cache", other_mt, "ALGORITHM_MISMATCH"),
    ];

    for (label, data, expected) in changed {
        table.load(label, &state, &data, expected, Some(&message));
    }

    table.load(
        "at the capacity",
        &with_next(&state, 1024),
        &cache,
        "ok",
        None,
    );

    let sealed_cases: Vec<(&'static str, Vec<Edit>, &str)> = vec![
        (
            "sealed root changed",
            vec![change_node(0, 2046 * 24)],
            encoding,
        ),
        (
            "sealed public seed changed",
            vec![change_public_key(|key| flip(key, key.len() - 1))],
            encoding,
        ),
        ("sealed layer 1", vec![set_position(0, 1)], encoding),
        (
            "sealed parameters of another set",
            vec![set_parameters(u32_bytes(XMSS_SHA2_10_256).to_vec())],
            encoding,
        ),
    ];

    for (label, edits, expected) in sealed_cases {
        table.load(
            label,
            &state,
            &sealed(&cache, &seed, edits),
            expected,
            Some(&message),
        );
    }

    table.group()
}

// SPEC 9.4: each HashSLH-DSA value, its pure SLH-DSA value, the ACVP names of its fixed pre-hash
// and of another pre-hash that the strength rule of 9.1.3 item 3 permits, and the last arc of its
// OID (RFC 9909, 3).
struct HashSlhDsa {
    algorithm: SignatureAlgorithm,
    pure: SignatureAlgorithm,
    fixed: &'static str,
    other: &'static str,
    arc: u8,
}

const fn hash_slh_dsa(
    algorithm: SignatureAlgorithm,
    pure: SignatureAlgorithm,
    fixed: &'static str,
    other: &'static str,
    arc: u8,
) -> HashSlhDsa {
    HashSlhDsa {
        algorithm,
        pure,
        fixed,
        other,
        arc,
    }
}

const HASH_SLH_DSA: [HashSlhDsa; 12] = [
    hash_slh_dsa(
        HASH_SLH_DSA_SHA2_128S_WITH_SHA256,
        SLH_DSA_SHA2_128S,
        "SHA2-256",
        "SHA3-256",
        35,
    ),
    hash_slh_dsa(
        HASH_SLH_DSA_SHA2_128F_WITH_SHA256,
        SLH_DSA_SHA2_128F,
        "SHA2-256",
        "SHA3-256",
        36,
    ),
    hash_slh_dsa(
        HASH_SLH_DSA_SHA2_192S_WITH_SHA512,
        SLH_DSA_SHA2_192S,
        "SHA2-512",
        "SHA3-512",
        37,
    ),
    hash_slh_dsa(
        HASH_SLH_DSA_SHA2_192F_WITH_SHA512,
        SLH_DSA_SHA2_192F,
        "SHA2-512",
        "SHA3-512",
        38,
    ),
    hash_slh_dsa(
        HASH_SLH_DSA_SHA2_256S_WITH_SHA512,
        SLH_DSA_SHA2_256S,
        "SHA2-512",
        "SHA3-512",
        39,
    ),
    hash_slh_dsa(
        HASH_SLH_DSA_SHA2_256F_WITH_SHA512,
        SLH_DSA_SHA2_256F,
        "SHA2-512",
        "SHA3-512",
        40,
    ),
    hash_slh_dsa(
        HASH_SLH_DSA_SHAKE_128S_WITH_SHAKE128,
        SLH_DSA_SHAKE_128S,
        "SHAKE-128",
        "SHAKE-256",
        41,
    ),
    hash_slh_dsa(
        HASH_SLH_DSA_SHAKE_128F_WITH_SHAKE128,
        SLH_DSA_SHAKE_128F,
        "SHAKE-128",
        "SHAKE-256",
        42,
    ),
    hash_slh_dsa(
        HASH_SLH_DSA_SHAKE_192S_WITH_SHAKE256,
        SLH_DSA_SHAKE_192S,
        "SHAKE-256",
        "SHA2-512",
        43,
    ),
    hash_slh_dsa(
        HASH_SLH_DSA_SHAKE_192F_WITH_SHAKE256,
        SLH_DSA_SHAKE_192F,
        "SHAKE-256",
        "SHA2-512",
        44,
    ),
    hash_slh_dsa(
        HASH_SLH_DSA_SHAKE_256S_WITH_SHAKE256,
        SLH_DSA_SHAKE_256S,
        "SHAKE-256",
        "SHA2-512",
        45,
    ),
    hash_slh_dsa(
        HASH_SLH_DSA_SHAKE_256F_WITH_SHAKE256,
        SLH_DSA_SHAKE_256F,
        "SHAKE-256",
        "SHA2-512",
        46,
    ),
];

const HASH_SLH_DSA_PREFIX: &str = "HashSLH-DSA-";

// The records that the generator adds to each SLH-DSA section of errors.txt: the keys of the
// HashSLH-DSA value of the same set, which the pure value refuses (SPEC 9.4 item 3).
const PURE_REFUSALS: [&str; 4] = [
    "public key der of the pre-hash algorithm",
    "public key pem of the pre-hash algorithm",
    "private key der of the pre-hash algorithm",
    "private key pem of the pre-hash algorithm",
];

// The DER of SPEC 10.2 and 10.3 for an RFC 9909 OID, built here rather than by the crate.
fn identifier(arc: u8) -> Vec<u8> {
    der(
        0x30,
        &der(0x06, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, arc]),
    )
}

fn spki(arc: u8, public_key: &[u8]) -> Vec<u8> {
    let key = der(0x03, &[&[0][..], public_key].concat());

    der(0x30, &[identifier(arc), key].concat())
}

fn pkcs8(arc: u8, private_key: &[u8]) -> Vec<u8> {
    let key = der(0x04, private_key);

    der(0x30, &[vec![2, 1, 0], identifier(arc), key].concat())
}

// One key group of a HashSLH-DSA value: the key pair from its seed, and the deterministic
// signature of a message with a context.
struct HashGroup {
    seed: Vec<u8>,
    pair: SignatureKeyPair,
    message: Vec<u8>,
    context: Vec<u8>,
    signature: Vec<u8>,
}

fn hash_group(value: &HashSlhDsa, number: u64) -> HashGroup {
    let mut stream = Stream(0x9909_0000 + number);

    let n = value.algorithm.public_key_size() / 2;

    let seed = stream.bytes(3 * n);

    let length = 1 + (stream.next() % 64) as usize;

    let message = stream.bytes(length);

    let length = 1 + (stream.next() % 255) as usize;

    let context = stream.bytes(length);

    let pair = hazmat::generate_signature_key_pair(value.algorithm, &seed).unwrap();

    let options = SignOptions::default()
        .with_context(&context)
        .with_deterministic(true);

    let signature = pair.private_key.sign(&message, &options).unwrap();

    // SPEC 9.4 item 3: the signature of the pure value of the same key with the fixed pre-hash.
    let pure = hazmat::generate_signature_key_pair(value.pure, &seed).unwrap();

    let mut fixed = options;

    fixed.pre_hash = super::pre_hash(value.fixed);

    assert_eq!(pure.private_key.sign(&message, &fixed).unwrap(), signature);

    // SPEC 9.1.2 item 2: the deterministic variant is opt_rand = PK.seed.
    let public = pair.public_key.export_key(KeyFormat::Raw).unwrap();

    assert_eq!(
        hazmat::sign(&pair.private_key, &message, &public[..n], &fixed).unwrap(),
        signature
    );

    HashGroup {
        seed,
        pair,
        message,
        context,
        signature,
    }
}

fn exported(pair: &SignatureKeyPair, format: KeyFormat) -> (Vec<u8>, Vec<u8>) {
    (
        pair.public_key.export_key(format).unwrap(),
        pair.private_key.export_key(format).unwrap().to_vec(),
    )
}

// The section of slhdsa.txt: the keys in every format, with the OID checked against SPEC 10.2 and
// 10.3, and the deterministic signature, which the runner signs again and verifies.
fn hash_signature_group(value: &HashSlhDsa, group: &HashGroup) -> Group {
    let pair = &group.pair;

    let (public, private) = exported(pair, KeyFormat::Raw);

    let (public_der, private_der) = exported(pair, KeyFormat::Der);

    let (public_pem, private_pem) = exported(pair, KeyFormat::Pem);

    assert_eq!(public_der, spki(value.arc, &public));

    assert_eq!(private_der, pkcs8(value.arc, &private));

    assert_eq!(private[private.len() - public.len()..], public);

    let keys = record(&[
        ("publicKey", hex(&public)),
        ("publicKeyDer", hex(&public_der)),
        ("publicKeyPem", hex(&public_pem)),
        ("privateKey", hex(&private)),
        ("privateKeyDer", hex(&private_der)),
        ("privateKeyPem", hex(&private_pem)),
    ]);

    let signature = record(&[
        ("mode", "deterministic".into()),
        ("message", hex(&group.message)),
        ("context", hex(&group.context)),
        ("preHash", "none".into()),
        ("signature", hex(&group.signature)),
        ("publicVerify", "true".into()),
    ]);

    let name = value.algorithm.name();

    let header = Fields::from([
        ("algorithm".to_owned(), name.to_owned()),
        ("seed".to_owned(), hex(&group.seed)),
    ]);

    super::check_signature_record(&header, &fields(&keys));

    super::check_signature_record(&header, &fields(&signature));

    Group {
        header: vec![
            format!("[algorithm = {name}]"),
            format!("[seed = {}]", hex(&group.seed)),
        ],
        records: vec![keys, signature],
    }
}

// The section of errors.txt: SPEC 9.4 items 2 and 3, and 13 item 3 [D-65].
fn hash_error_group(value: &HashSlhDsa, group: &HashGroup) -> Group {
    let name = value.algorithm.name();

    let pure = hazmat::generate_signature_key_pair(value.pure, &group.seed).unwrap();

    let (public, private) = exported(&group.pair, KeyFormat::Raw);

    let n = public.len() / 2;

    let (message, context) = (hex(&group.message), hex(&group.context));

    let long = hex(&[0x63; 256]);

    let mut records = Vec::new();

    for (format, label) in [(KeyFormat::Der, "der"), (KeyFormat::Pem, "pem")] {
        let (public_key, private_key) = exported(&pure, format);

        records.push(record(&[
            ("name", format!("public key {label} of the pure algorithm")),
            ("operation", "importPublicKey".into()),
            ("format", label.into()),
            ("input", hex(&public_key)),
        ]));

        records.push(record(&[
            ("name", format!("private key {label} of the pure algorithm")),
            ("operation", "importPrivateKey".into()),
            ("format", label.into()),
            ("input", hex(&private_key)),
        ]));
    }

    let sign = |name: &str, context: &str, pre_hash: &str| {
        record(&[
            ("name", name.into()),
            ("operation", "sign".into()),
            ("key", hex(&private)),
            ("message", message.clone()),
            ("context", context.into()),
            ("preHash", pre_hash.into()),
        ])
    };

    records.push(sign("sign other pre-hash", &context, value.other));

    records.push(sign(
        "sign other pre-hash and long context",
        &long,
        value.other,
    ));

    records.push(sign(
        "sign fixed pre-hash and long context",
        &long,
        value.fixed,
    ));

    let hazmat_sign = |name: &str, pre_hash: &str, randomness: &[u8]| {
        record(&[
            ("name", name.into()),
            ("operation", "hazmatSign".into()),
            ("key", hex(&private)),
            ("message", message.clone()),
            ("context", context.clone()),
            ("preHash", pre_hash.into()),
            ("randomness", hex(randomness)),
        ])
    };

    let randomness = vec![0x5a; n];

    records.push(hazmat_sign(
        "hazmat sign other pre-hash",
        value.other,
        &randomness,
    ));

    // hazmat.sign skips the strength rule, not the fixed pre-hash.
    records.push(hazmat_sign(
        "hazmat sign weak pre-hash",
        "SHA2-224",
        &randomness,
    ));

    records.push(hazmat_sign(
        "hazmat sign fixed pre-hash and short randomness",
        value.fixed,
        &randomness[1..],
    ));

    // M' of the pure interface for the same message and context (SPEC 9.1.4).
    let representative = [
        &[0, group.context.len() as u8][..],
        &group.context,
        &group.message,
    ]
    .concat();

    records.push(record(&[
        ("name", "hazmat sign internal".into()),
        ("operation", "hazmatSignInternal".into()),
        ("key", hex(&private)),
        ("message", hex(&representative)),
        ("randomness", hex(&randomness)),
    ]));

    let verify = |name: &str, operation: &str, signature: &[u8], pre_hash: &str| {
        record(&[
            ("name", name.into()),
            ("operation", operation.into()),
            ("key", hex(&public)),
            ("input", hex(signature)),
            ("message", message.clone()),
            ("context", context.clone()),
            ("preHash", pre_hash.into()),
        ])
    };

    records.push(verify(
        "verify changed signature",
        "verify",
        &flip(&group.signature, group.signature.len() / 2),
        "none",
    ));

    records.push(verify(
        "verify other pre-hash",
        "verify",
        &group.signature,
        value.other,
    ));

    records.push(verify(
        "hazmat verify other pre-hash",
        "hazmatVerify",
        &group.signature,
        value.other,
    ));

    for record in &mut records {
        let expected = match get(record, "name").unwrap() {
            "sign fixed pre-hash and long context" => "INVALID_CONTEXT",
            "hazmat sign fixed pre-hash and short randomness" => "INVALID_LENGTH",
            case if case.starts_with("verify") || case.starts_with("hazmat verify") => "false",
            case if case.contains("pure algorithm") => "ALGORITHM_MISMATCH",
            _ => "INVALID_OPTION",
        };

        run_into(name, record, expected);
    }

    Group {
        header: vec![format!("[algorithm = {name}]")],
        records,
    }
}

// The keys of a HashSLH-DSA value, imported through its pure value (SPEC 9.4 item 3).
fn pure_refusals(pure: &str, group: &HashGroup) -> Vec<Record> {
    let mut records = Vec::new();

    for (format, label) in [(KeyFormat::Der, "der"), (KeyFormat::Pem, "pem")] {
        let (public_key, private_key) = exported(&group.pair, format);

        records.push(record(&[
            (
                "name",
                format!("public key {label} of the pre-hash algorithm"),
            ),
            ("operation", "importPublicKey".into()),
            ("format", label.into()),
            ("input", hex(&public_key)),
        ]));

        records.push(record(&[
            (
                "name",
                format!("private key {label} of the pre-hash algorithm"),
            ),
            ("operation", "importPrivateKey".into()),
            ("format", label.into()),
            ("input", hex(&private_key)),
        ]));
    }

    for record in &mut records {
        run_into(pure, record, "ALGORITHM_MISMATCH");
    }

    records
}

fn is_hash_slh_dsa(group: &Group) -> bool {
    header(group, "algorithm").starts_with(HASH_SLH_DSA_PREFIX)
}

// Puts the HashSLH-DSA sections after the last SLH-DSA section, replacing those of an earlier run.
fn place_hash_groups(found: &mut Vec<Group>, groups: Vec<Group>) {
    found.retain(|group| !is_hash_slh_dsa(group));

    let last = found
        .iter()
        .rposition(|group| header(group, "algorithm").starts_with("SLH-DSA-"))
        .unwrap();

    found.splice(last + 1..last + 1, groups);
}

fn hash_groups() -> Vec<HashGroup> {
    HASH_SLH_DSA
        .iter()
        .zip(0..)
        .map(|(value, number)| hash_group(value, number))
        .collect()
}

fn regenerate_hash_slh_dsa_errors(found: &mut Vec<Group>, keys: &[HashGroup]) {
    for (value, group) in HASH_SLH_DSA.iter().zip(keys) {
        let pure = value.pure.name();

        let section = found
            .iter_mut()
            .find(|found| header(found, "algorithm") == pure)
            .unwrap();

        section
            .records
            .retain(|record| !PURE_REFUSALS.contains(&get(record, "name").unwrap()));

        section.records.extend(pure_refusals(pure, group));
    }

    let sections = HASH_SLH_DSA
        .iter()
        .zip(keys)
        .map(|(value, group)| hash_error_group(value, group))
        .collect();

    place_hash_groups(found, sections);
}

// slhdsa.txt: the SLH-DSA sections are frozen; the HashSLH-DSA sections follow them.
fn regenerate_hash_slh_dsa_signatures(keys: &[HashGroup]) {
    let name = "cross/slhdsa.txt";

    let mut found = groups(name);

    let sections = HASH_SLH_DSA
        .iter()
        .zip(keys)
        .map(|(value, group)| hash_signature_group(value, group))
        .collect();

    place_hash_groups(&mut found, sections);

    fixture(name, &found);
}

#[test]
#[ignore = "generator of the stateful, decided and HashSLH-DSA records of vectors/cross"]
fn regenerate_cross() {
    let keys = hash_groups();

    regenerate_errors(&keys);

    regenerate_hash_slh_dsa_signatures(&keys);

    regenerate_signatures("cross/hss.txt");

    regenerate_signatures("cross/xmss.txt");

    fixture(
        "cross/treecache.txt",
        &[tree_cache_hss(), tree_cache_xmss_mt(), tree_cache_xmss()],
    );
}

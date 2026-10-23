mod vectors;

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use crypto_pq::{
    Error, HMAC_SHA_256, HSS_LMS, KeyFormat, SHA_256, StateStore, StatefulKeyGenOptions,
    StatefulLoadOptions, StatefulParameters, StatefulPrivateKey, StatefulSignatureAlgorithm, XMSS,
    XMSS_MT, hazmat,
};
use vectors::{Fields, der, parallel, records, unhex};

const SMALL: [(&str, &str); 1] = [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1")];

const HSS_OID: [u8; 13] = [
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x11,
];

// (code, name, m, h) of the LMS types and (code, name, n, p) of the LM-OTS types.
const LMS_TYPES: [(u32, &str, usize, u32); 20] = [
    (5, "LMS_SHA256_M32_H5", 32, 5),
    (6, "LMS_SHA256_M32_H10", 32, 10),
    (7, "LMS_SHA256_M32_H15", 32, 15),
    (8, "LMS_SHA256_M32_H20", 32, 20),
    (9, "LMS_SHA256_M32_H25", 32, 25),
    (10, "LMS_SHA256_M24_H5", 24, 5),
    (11, "LMS_SHA256_M24_H10", 24, 10),
    (12, "LMS_SHA256_M24_H15", 24, 15),
    (13, "LMS_SHA256_M24_H20", 24, 20),
    (14, "LMS_SHA256_M24_H25", 24, 25),
    (15, "LMS_SHAKE_M32_H5", 32, 5),
    (16, "LMS_SHAKE_M32_H10", 32, 10),
    (17, "LMS_SHAKE_M32_H15", 32, 15),
    (18, "LMS_SHAKE_M32_H20", 32, 20),
    (19, "LMS_SHAKE_M32_H25", 32, 25),
    (20, "LMS_SHAKE_M24_H5", 24, 5),
    (21, "LMS_SHAKE_M24_H10", 24, 10),
    (22, "LMS_SHAKE_M24_H15", 24, 15),
    (23, "LMS_SHAKE_M24_H20", 24, 20),
    (24, "LMS_SHAKE_M24_H25", 24, 25),
];

const OTS_TYPES: [(u32, &str, usize, usize); 16] = [
    (1, "LMOTS_SHA256_N32_W1", 32, 265),
    (2, "LMOTS_SHA256_N32_W2", 32, 133),
    (3, "LMOTS_SHA256_N32_W4", 32, 67),
    (4, "LMOTS_SHA256_N32_W8", 32, 34),
    (5, "LMOTS_SHA256_N24_W1", 24, 200),
    (6, "LMOTS_SHA256_N24_W2", 24, 101),
    (7, "LMOTS_SHA256_N24_W4", 24, 51),
    (8, "LMOTS_SHA256_N24_W8", 24, 26),
    (9, "LMOTS_SHAKE_N32_W1", 32, 265),
    (10, "LMOTS_SHAKE_N32_W2", 32, 133),
    (11, "LMOTS_SHAKE_N32_W4", 32, 67),
    (12, "LMOTS_SHAKE_N32_W8", 32, 34),
    (13, "LMOTS_SHAKE_N24_W1", 24, 200),
    (14, "LMOTS_SHAKE_N24_W2", 24, 101),
    (15, "LMOTS_SHAKE_N24_W4", 24, 51),
    (16, "LMOTS_SHAKE_N24_W8", 24, 26),
];

type Level = (
    (u32, &'static str, usize, u32),
    (u32, &'static str, usize, usize),
);

fn slow() -> bool {
    std::env::var_os("CRYPTO_PQ_SLOW").is_some_and(|value| !value.is_empty())
}

#[derive(Default)]
struct MemoryStore {
    state: Option<Vec<u8>>,
    writes: usize,
}

impl MemoryStore {
    fn holding(state: &[u8]) -> Self {
        Self {
            state: Some(state.to_vec()),
            writes: 0,
        }
    }
}

impl StateStore for MemoryStore {
    fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.state.clone())
    }

    fn update(&mut self, previous: Option<&[u8]>, next: &[u8]) -> Result<bool, Error> {
        if self.state.as_deref() != previous {
            return Ok(false);
        }

        self.state = Some(next.to_vec());

        self.writes += 1;

        Ok(true)
    }
}

// One store seen by several keys, like a file that two processes open.
#[derive(Clone, Default)]
struct SharedStore(Rc<RefCell<MemoryStore>>);

impl SharedStore {
    // The bound `next` of the stored record.
    fn index(&self) -> u64 {
        let store = self.0.borrow();

        let state = store.state.as_deref().expect("a stored state");

        let at = next_offset(state);

        u64::from_be_bytes(state[at..at + 8].try_into().unwrap())
    }

    fn writes(&self) -> usize {
        self.0.borrow().writes
    }
}

impl StateStore for SharedStore {
    fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.0.borrow_mut().read()
    }

    fn update(&mut self, previous: Option<&[u8]>, next: &[u8]) -> Result<bool, Error> {
        self.0.borrow_mut().update(previous, next)
    }
}

// Accepts the new key, then fails every write, like a full disk; reads can fail too.
#[derive(Default)]
struct BrokenStore {
    inner: MemoryStore,
    unreadable: bool,
}

impl StateStore for BrokenStore {
    fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if self.unreadable {
            return Err(Error::Unsupported);
        }

        self.inner.read()
    }

    fn update(&mut self, previous: Option<&[u8]>, next: &[u8]) -> Result<bool, Error> {
        if previous.is_none() {
            return self.inner.update(previous, next);
        }

        Err(Error::Unsupported)
    }
}

// Where a state record (SPEC 11.7) holds `next`: after the version, the kind, the parameters (an HSS
// level count and 8 bytes per level, or an OID) and the flags.
fn next_offset(state: &[u8]) -> usize {
    let parameters = if state[1] == 1 {
        1 + 8 * usize::from(state[2])
    } else {
        4
    };

    3 + parameters
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn lms_type(code: u32) -> (u32, &'static str, usize, u32) {
    *LMS_TYPES.iter().find(|t| t.0 == code).expect("LMS type")
}

fn ots_type(code: u32) -> (u32, &'static str, usize, usize) {
    *OTS_TYPES.iter().find(|t| t.0 == code).expect("LM-OTS type")
}

// RFC 8554: q, the LM-OTS signature (type, C and p chains), the LMS type and the path.
fn lms_signature_size(level: &Level) -> usize {
    let ((_, _, m, h), (_, _, n, p)) = *level;

    8 + 4 + n * (p + 1) + h as usize * m
}

// The parameters of every level, read from the public key and the signed child keys.
fn levels(public: &[u8], signature: &[u8]) -> Vec<Level> {
    let count = read_u32(public, 0);

    let mut key = &public[4..];

    let mut offset = 4;

    let mut found = Vec::new();

    for level in 0..count {
        found.push((lms_type(read_u32(key, 0)), ots_type(read_u32(key, 4))));

        if level + 1 < count {
            offset += lms_signature_size(found.last().unwrap());

            let child = lms_type(read_u32(signature, offset));

            key = &signature[offset..offset + 24 + child.2];

            offset += 24 + child.2;
        }
    }

    found
}

fn index(levels: &[Level], signature: &[u8]) -> u64 {
    let mut offset = 4;

    let mut index = 0;

    for level in levels {
        index = (index << level.0.3) | u64::from(read_u32(signature, offset));

        offset += lms_signature_size(level) + 24 + level.0.2;
    }

    index
}

#[test]
fn hss_acvp_key_generation() {
    parallel(
        &records("acvp/LMS-keyGen.txt", "publicKey"),
        |(header, record)| {
            let seed = [unhex(&record["i"]), unhex(&record["seed"])].concat();

            let levels = [(header["lmsMode"].as_str(), header["lmOtsMode"].as_str())];

            let pair = hazmat::generate_stateful_key_pair(
                HSS_LMS,
                &seed,
                0,
                StatefulParameters::Levels(&levels),
                MemoryStore::default(),
                &StatefulKeyGenOptions::default(),
            )
            .unwrap();

            let expected = [&[0, 0, 0, 1][..], &unhex(&record["publicKey"])].concat();

            let public = pair.public_key.export_key(KeyFormat::Raw).unwrap();

            assert_eq!(public, expected, "tcId {}", record["tcId"]);
        },
    );
}

#[test]
fn hss_acvp_verification() {
    parallel(
        &records("acvp/LMS-sigVer.txt", "signature"),
        |(header, record)| {
            let public = [&[0, 0, 0, 1][..], &unhex(&header["publicKey"])].concat();

            let public_key = HSS_LMS.import_public_key(&public, KeyFormat::Raw).unwrap();

            let signature = [&[0, 0, 0, 0][..], &unhex(&record["signature"])].concat();

            let result = public_key.verify(&signature, &unhex(&record["message"]));

            let expected = record["testPassed"] == "true";

            assert_eq!(
                result, expected,
                "tcId {} {}",
                record["tcId"], record["reason"]
            );
        },
    );
}

#[test]
fn hss_rfc_vectors() {
    let mut reproduced = 0;

    for (_, record) in records("rfc/hss.txt", "signature") {
        let name = &record["name"];

        let public = unhex(&record["publicKey"]);

        let (message, signature) = (unhex(&record["message"]), unhex(&record["signature"]));

        let public_key = HSS_LMS.import_public_key(&public, KeyFormat::Raw).unwrap();

        assert!(public_key.verify(&signature, &message), "{name}");

        let mut tampered = signature.clone();

        *tampered.last_mut().unwrap() ^= 1;

        assert!(!public_key.verify(&tampered, &message), "{name}");

        assert!(
            !public_key.verify(&signature, &[&message[..], &[0]].concat()),
            "{name}"
        );

        if !record.contains_key("seed") {
            continue;
        }

        let levels = levels(&public, &signature);

        let index = index(&levels, &signature);

        // RFC 9858 A.4 has a height-20 tree: 2^20 one-time keys to build.
        if levels.iter().map(|level| level.0.3).sum::<u32>() > 15 && !slow() {
            continue;
        }

        let names: Vec<(&str, &str)> = levels.iter().map(|(lms, ots)| (lms.1, ots.1)).collect();

        let seed = [unhex(&record["i"]), unhex(&record["seed"])].concat();

        let mut pair = hazmat::generate_stateful_key_pair(
            HSS_LMS,
            &seed,
            index,
            StatefulParameters::Levels(&names),
            MemoryStore::default(),
            &StatefulKeyGenOptions::default(),
        )
        .unwrap();

        assert_eq!(
            pair.public_key.export_key(KeyFormat::Raw).unwrap(),
            public,
            "{name}"
        );

        assert_eq!(
            pair.private_key.sign(&message).unwrap(),
            signature,
            "{name}"
        );

        reproduced += 1;
    }

    assert_eq!(reproduced, if slow() { 5 } else { 4 });
}

#[test]
fn hss_state_handling() {
    let store = SharedStore::default();

    let mut pair = HSS_LMS
        .generate_key_pair(
            StatefulParameters::Levels(&SMALL),
            store.clone(),
            &StatefulKeyGenOptions::default(),
        )
        .unwrap();

    assert_eq!(pair.private_key.remaining_signatures(), 32);

    let first = pair.private_key.sign(b"one").unwrap();

    let second = pair.private_key.sign(b"two").unwrap();

    assert!(pair.public_key.verify(&first, b"one"));

    assert!(pair.public_key.verify(&second, b"two"));

    assert!(!pair.public_key.verify(&first, b"two"));

    assert_eq!(pair.private_key.remaining_signatures(), 30);

    let mut loaded = HSS_LMS
        .load_private_key(store.clone(), &StatefulLoadOptions::default())
        .unwrap();

    assert_eq!(loaded.public_key(), pair.public_key);

    assert_eq!(loaded.remaining_signatures(), 30);

    let third = loaded.sign(b"three").unwrap();

    assert_eq!(read_u32(&third, 4), 2);

    assert_eq!(
        pair.private_key.sign(b"stale").err(),
        Some(Error::StateConflict)
    );

    assert_eq!(pair.private_key.remaining_signatures(), 30);

    while loaded.remaining_signatures() > 0 {
        loaded.sign(b"m").unwrap();
    }

    assert_eq!(loaded.sign(b"m").err(), Some(Error::KeyExhausted));

    assert_eq!(
        HSS_LMS
            .generate_key_pair(
                StatefulParameters::Levels(&SMALL),
                store.clone(),
                &StatefulKeyGenOptions::default()
            )
            .err()
            .map(|error| error.code()),
        Some("STATE_CONFLICT")
    );

    let reloaded = HSS_LMS
        .load_private_key(store, &StatefulLoadOptions::default())
        .unwrap();

    assert_eq!(reloaded.remaining_signatures(), 0);
}

#[test]
fn hss_store_failures() {
    let mut broken = BrokenStore::default();

    let mut pair = HSS_LMS
        .generate_key_pair(
            StatefulParameters::Levels(&SMALL),
            &mut broken,
            &StatefulKeyGenOptions::default(),
        )
        .unwrap();

    assert_eq!(
        pair.private_key.sign(b"m").err(),
        Some(Error::StatePersistFailed)
    );

    assert_eq!(pair.private_key.remaining_signatures(), 32);

    drop(pair);

    let state = broken.inner.state.clone().unwrap();

    let mut damaged = state.clone();

    let position = damaged.len() - 20;

    damaged[position] ^= 1;

    for store in [MemoryStore::holding(&damaged), MemoryStore::default()] {
        assert_eq!(
            HSS_LMS
                .load_private_key(store, &StatefulLoadOptions::default())
                .err(),
            Some(Error::InvalidPrivateKey)
        );
    }

    assert_eq!(
        XMSS.load_private_key(
            MemoryStore::holding(&state),
            &StatefulLoadOptions::default()
        )
        .err(),
        Some(Error::AlgorithmMismatch)
    );

    broken.unreadable = true;

    assert_eq!(
        HSS_LMS
            .load_private_key(&mut broken, &StatefulLoadOptions::default())
            .err(),
        Some(Error::StatePersistFailed)
    );

    let mut truncated = state[..state.len() - 17].to_vec();

    let checksum = SHA_256.digest(&truncated);

    truncated.extend_from_slice(&checksum[..16]);

    assert_eq!(
        HSS_LMS
            .load_private_key(
                MemoryStore::holding(&truncated),
                &StatefulLoadOptions::default()
            )
            .err(),
        Some(Error::InvalidPrivateKey)
    );
}

#[test]
fn hss_parameters() {
    let nine = [SMALL[0]; 9];

    let too_high = [
        ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W8"),
        ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W8"),
        ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W8"),
    ];

    let invalid = [
        StatefulParameters::Levels(&[]),
        StatefulParameters::Levels(&nine),
        StatefulParameters::Levels(&[("LMS_SHA256_M32_H5", "LMOTS_SHA256_N24_W1")]),
        StatefulParameters::Levels(&[("LMS_SHA256_M24_H5", "LMOTS_SHAKE_N24_W1")]),
        StatefulParameters::Levels(&[
            ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"),
            ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W1"),
        ]),
        StatefulParameters::Name("LMS_SHA256_M24_H5"),
        StatefulParameters::Levels(&[("LMS_X", "LMOTS_SHA256_N24_W1")]),
        StatefulParameters::Levels(&too_high),
    ];

    for parameters in invalid {
        let result = HSS_LMS.generate_key_pair(
            parameters,
            MemoryStore::default(),
            &StatefulKeyGenOptions::default(),
        );

        assert_eq!(result.err(), Some(Error::InvalidOption), "{parameters:?}");
    }

    let seed = [0; 40];

    let small = StatefulParameters::Levels(&SMALL);

    let mut store = MemoryStore::default();

    assert_eq!(
        hazmat::generate_stateful_key_pair(
            HSS_LMS,
            &seed[..39],
            0,
            small,
            &mut store,
            &StatefulKeyGenOptions::default()
        )
        .err(),
        Some(Error::InvalidLength)
    );

    // SPEC D-68: a start index at or beyond the capacity of 32 is refused.
    for index in [32, 33] {
        assert_eq!(
            hazmat::generate_stateful_key_pair(
                HSS_LMS,
                &seed,
                index,
                small,
                &mut store,
                &StatefulKeyGenOptions::default()
            )
            .err(),
            Some(Error::InvalidOption)
        );
    }

    assert!(store.state.is_none());

    let mut exhausted = hazmat::generate_stateful_key_pair(
        HSS_LMS,
        &seed,
        31,
        small,
        store,
        &StatefulKeyGenOptions::default(),
    )
    .unwrap();

    assert_eq!(exhausted.private_key.remaining_signatures(), 1);

    exhausted.private_key.sign(b"m").unwrap();

    assert_eq!(exhausted.private_key.remaining_signatures(), 0);

    assert_eq!(
        exhausted.private_key.sign(b"m").err(),
        Some(Error::KeyExhausted)
    );
}

#[test]
fn hss_tree_boundary() {
    let levels = [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"); 2];

    let mut pair = hazmat::generate_stateful_key_pair(
        HSS_LMS,
        &[0; 40],
        31,
        StatefulParameters::Levels(&levels),
        MemoryStore::default(),
        &StatefulKeyGenOptions::default(),
    )
    .unwrap();

    let signatures: Vec<Vec<u8>> = (0..2u8)
        .map(|i| pair.private_key.sign(&[i]).unwrap())
        .collect();

    for (i, signature) in signatures.iter().enumerate() {
        assert!(pair.public_key.verify(signature, &[i as u8]));
    }

    assert_ne!(signatures[0][4..8], signatures[1][4..8]);
}

#[test]
fn hss_formats() {
    let pair = HSS_LMS
        .generate_key_pair(
            StatefulParameters::Levels(&SMALL),
            MemoryStore::default(),
            &StatefulKeyGenOptions::default(),
        )
        .unwrap();

    for format in [KeyFormat::Raw, KeyFormat::Der, KeyFormat::Pem] {
        let exported = pair.public_key.export_key(format).unwrap();

        let public_key = HSS_LMS.import_public_key(&exported, format).unwrap();

        assert_eq!(public_key, pair.public_key);
    }

    let der_key = pair.public_key.export_key(KeyFormat::Der).unwrap();

    assert!(
        der_key
            .windows(HSS_OID.len())
            .any(|window| window == HSS_OID)
    );

    let raw = pair.public_key.export_key(KeyFormat::Raw).unwrap();

    let nine_levels = [&[0, 0, 0, 9][..], &raw[4..]].concat();

    let short_der = der(
        0x30,
        &[
            der(0x30, &HSS_OID),
            der(0x03, &[&[0][..], &raw[1..]].concat()),
        ]
        .concat(),
    );

    let malformed = [
        (nine_levels, KeyFormat::Raw),
        (raw[..raw.len() - 1].to_vec(), KeyFormat::Raw),
        (short_der, KeyFormat::Der),
    ];

    for (data, format) in malformed {
        assert_eq!(
            HSS_LMS.import_public_key(&data, format).err(),
            Some(Error::InvalidPublicKey)
        );
    }

    assert_eq!(
        XMSS.import_public_key(&der_key, KeyFormat::Der).err(),
        Some(Error::AlgorithmMismatch)
    );

    assert_eq!(HSS_LMS.name(), "HSS/LMS");

    assert_eq!(
        format!("{:?}", pair.private_key),
        "StatefulPrivateKey { algorithm: StatefulSignatureAlgorithm(\"HSS/LMS\"), .. }"
    );
}

// The vectors of the RFC 8391 reference implementation (tools/xmss_vectors.py): the base sets,
// and the other SP 800-208 sets whose trees have at most 2^16 leaves. Every signature verifies;
// a key is made again from its seed and signs the same bytes when its trees have at most 2^10
// leaves here, and for the XMSS sets of height 16 in the weekly job (SPEC 19.4).
fn xmss_vectors(tall: bool) {
    let found = [
        records("xmss/xmss.txt", "signature"),
        records("xmss/xmss-extra.txt", "signature"),
    ]
    .concat();

    assert_eq!(found.len(), 128);

    parallel(&found, |(_, record)| {
        let name = record["name"].as_str();

        let algorithm = if name.starts_with("XMSSMT") {
            XMSS_MT
        } else {
            XMSS
        };

        let index: u64 = record["index"].parse().unwrap();

        let message = unhex(&record["message"]);

        let (public, signature) = (unhex(&record["publicKey"]), unhex(&record["signature"]));

        let context = format!("{name} index {index}");

        if name.contains("_16_") != tall {
            return;
        }

        let public_key = algorithm
            .import_public_key(&public, KeyFormat::Raw)
            .unwrap();

        assert!(public_key.verify(&signature, &message), "{context}");

        let mut tampered = signature.clone();

        *tampered.last_mut().unwrap() ^= 1;

        assert!(!public_key.verify(&tampered, &message), "{context}");

        let mut pair = hazmat::generate_stateful_key_pair(
            algorithm,
            &unhex(&record["seed"]),
            index,
            StatefulParameters::Name(name),
            MemoryStore::default(),
            &StatefulKeyGenOptions::default(),
        )
        .unwrap();

        assert_eq!(
            pair.public_key.export_key(KeyFormat::Raw).unwrap(),
            public,
            "{context}"
        );

        assert_eq!(
            pair.private_key.sign(&message).unwrap(),
            signature,
            "{context}"
        );
    });
}

#[test]
fn xmss_reference_vectors() {
    xmss_vectors(false);

    // The XMSS sets of height 16 verify on every push.
    for (_, record) in records("xmss/xmss-extra.txt", "signature") {
        if record["name"].contains("_16_") {
            let public_key = XMSS
                .import_public_key(&unhex(&record["publicKey"]), KeyFormat::Raw)
                .unwrap();

            let (signature, message) = (unhex(&record["signature"]), unhex(&record["message"]));

            assert!(
                public_key.verify(&signature, &message),
                "{}",
                record["name"]
            );
        }
    }
}

#[test]
#[ignore = "builds trees of 2^16 leaves; runs in the weekly job"]
fn xmss_reference_vectors_of_height_16() {
    xmss_vectors(true);
}

// The twelve SP 800-208 sets whose trees have 2^20 leaves, from the same reference (xmss-large.txt),
// with signatures at indices 0 and 2^h - 2. Every signature verifies on every push; the weekly job
// makes each key again from its seed at index 0, which builds its trees of 2^20 leaves, and signs
// the same bytes.
fn xmss_large_vectors() -> Vec<(Fields, Fields)> {
    let found = records("xmss/xmss-large.txt", "signature");

    assert_eq!(found.len(), 24);

    found
}

fn xmss_algorithm(name: &str) -> StatefulSignatureAlgorithm {
    if name.starts_with("XMSSMT") {
        XMSS_MT
    } else {
        XMSS
    }
}

#[test]
fn xmss_reference_vectors_of_height_20() {
    parallel(&xmss_large_vectors(), |(_, record)| {
        let name = record["name"].as_str();

        let context = format!("{name} index {}", record["index"]);

        let public_key = xmss_algorithm(name)
            .import_public_key(&unhex(&record["publicKey"]), KeyFormat::Raw)
            .unwrap();

        let (mut signature, message) = (unhex(&record["signature"]), unhex(&record["message"]));

        assert!(public_key.verify(&signature, &message), "{context}");

        *signature.last_mut().unwrap() ^= 1;

        assert!(!public_key.verify(&signature, &message), "{context}");
    });
}

#[test]
#[ignore = "builds trees of 2^20 leaves; runs in the weekly job"]
fn xmss_reference_keys_of_height_20() {
    let first: Vec<_> = xmss_large_vectors()
        .into_iter()
        .filter(|(_, record)| record["index"] == "0")
        .collect();

    assert_eq!(first.len(), 12);

    parallel(&first, |(_, record)| {
        let name = record["name"].as_str();

        let mut pair = hazmat::generate_stateful_key_pair(
            xmss_algorithm(name),
            &unhex(&record["seed"]),
            0,
            StatefulParameters::Name(name),
            MemoryStore::default(),
            &StatefulKeyGenOptions::default(),
        )
        .unwrap();

        assert_eq!(
            pair.public_key.export_key(KeyFormat::Raw).unwrap(),
            unhex(&record["publicKey"]),
            "{name}"
        );

        assert_eq!(
            pair.private_key.sign(&unhex(&record["message"])).unwrap(),
            unhex(&record["signature"]),
            "{name}"
        );
    });
}

#[test]
fn xmss_state_handling() {
    let mut store = MemoryStore::default();

    let parameters = StatefulParameters::Name("XMSSMT-SHAKE256_20/4_192");

    let mut pair = XMSS_MT
        .generate_key_pair(parameters, &mut store, &StatefulKeyGenOptions::default())
        .unwrap();

    let signature = pair.private_key.sign(b"message").unwrap();

    assert!(pair.public_key.verify(&signature, b"message"));

    assert!(!pair.public_key.verify(&signature, b"other"));

    drop(pair);

    let loaded = XMSS_MT
        .load_private_key(&mut store, &StatefulLoadOptions::default())
        .unwrap();

    assert_eq!(loaded.remaining_signatures(), (1 << 20) - 1);

    let public_key = loaded.public_key();

    for format in [KeyFormat::Raw, KeyFormat::Der, KeyFormat::Pem] {
        let exported = public_key.export_key(format).unwrap();

        assert_eq!(
            XMSS_MT.import_public_key(&exported, format).unwrap(),
            public_key
        );
    }

    let invalid = [
        (XMSS, StatefulParameters::Name("XMSSMT-SHAKE256_20/4_192")),
        (XMSS_MT, StatefulParameters::Name("XMSS-SHA2_10_256")),
        (XMSS, StatefulParameters::Levels(&SMALL)),
        (XMSS, StatefulParameters::Name("XMSS-SHA2_10_512")),
    ];

    for (algorithm, parameters) in invalid {
        assert_eq!(
            algorithm
                .generate_key_pair(
                    parameters,
                    MemoryStore::default(),
                    &StatefulKeyGenOptions::default()
                )
                .err(),
            Some(Error::InvalidOption)
        );
    }

    let raw = public_key.export_key(KeyFormat::Raw).unwrap();

    assert_eq!(
        XMSS.import_public_key(&raw, KeyFormat::Raw).err(),
        Some(Error::InvalidPublicKey)
    );

    assert_eq!(
        XMSS_MT
            .import_public_key(&raw[..raw.len() - 1], KeyFormat::Raw)
            .err(),
        Some(Error::InvalidPublicKey)
    );

    assert_eq!(
        XMSS.load_private_key(&mut store, &StatefulLoadOptions::default())
            .err(),
        Some(Error::AlgorithmMismatch)
    );

    assert_eq!((XMSS.name(), XMSS_MT.name()), ("XMSS", "XMSS^MT"));
}

// A level record of a state record (SPEC 11.7); the last three are empty while it is claimed.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LevelRecord {
    tree: u64,
    status: u8,
    secrets: Vec<u8>,
    root: Vec<u8>,
    signature: Vec<u8>,
}

// A state record taken apart, so that a test can read or change a field and seal it again.
#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    version: u8,
    kind: u8,
    parameters: Vec<u8>,
    flags: u8,
    next: u64,
    top: Vec<u8>,
    public_key: Vec<u8>,
    levels: Vec<LevelRecord>,
}

// (n, h, d) of the XMSS and XMSS^MT sets.
fn xmss_shape(kind: u8, oid: u32) -> (usize, u32, u32) {
    const MT: [(u32, u32); 8] = [
        (20, 2),
        (20, 4),
        (40, 2),
        (40, 4),
        (40, 8),
        (60, 3),
        (60, 6),
        (60, 12),
    ];

    match (kind, oid) {
        (2, 0x01..=0x03 | 0x10..=0x12) => (32, [10, 16, 20][(oid as usize - 1) % 3], 1),
        (2, 0x0D..=0x0F | 0x13..=0x15) => (24, [10, 16, 20][(oid as usize - 0x0D) % 3], 1),
        (3, 0x01..=0x08) => (32, MT[oid as usize - 1].0, MT[oid as usize - 1].1),
        (3, 0x21..=0x28) => (24, MT[oid as usize - 0x21].0, MT[oid as usize - 0x21].1),
        (3, 0x29..=0x30) => (32, MT[oid as usize - 0x29].0, MT[oid as usize - 0x29].1),
        (3, 0x31..=0x38) => (24, MT[oid as usize - 0x31].0, MT[oid as usize - 0x31].1),
        _ => panic!("unknown set {kind} {oid}"),
    }
}

impl State {
    fn parse(data: &[u8]) -> Self {
        let (body, checksum) = data.split_at(data.len() - 16);

        assert_eq!(SHA_256.digest(body)[..16], *checksum);

        let kind = body[1];

        let end = next_offset(body) - 1;

        let parameters = body[2..end].to_vec();

        let mut at = end + 9;

        let mut take = |size: usize| {
            at += size;

            body[at - size..at].to_vec()
        };

        // The sizes of the top secrets, the public key, a child's secrets and root, and the
        // signature of the key of level l by level l - 1.
        let (top, public, child, node, signatures): (usize, usize, usize, usize, Vec<usize>) =
            if kind == 1 {
                let levels: Vec<Level> = parameters[1..]
                    .chunks(8)
                    .map(|chunk| (lms_type(read_u32(chunk, 0)), ots_type(read_u32(chunk, 4))))
                    .collect();

                let m = levels[0].0.2;

                let signatures = levels.iter().map(lms_signature_size).collect();

                (16 + m, 28 + m, 16 + m, m, signatures)
            } else {
                let (n, h, d) = xmss_shape(kind, read_u32(&parameters, 0));

                let layer = (2 * n + 3 + (h / d) as usize) * n;

                (3 * n, 4 + 2 * n, n, n, vec![layer; d as usize])
            };

        let top = take(top);

        let public_key = take(public);

        let mut levels = Vec::new();

        for signature in &signatures[..signatures.len() - 1] {
            let tree = u64::from_be_bytes(take(8).try_into().unwrap());

            let status = take(1)[0];

            let signed = status == 1;

            let mut part = |size| if signed { take(size) } else { Vec::new() };

            levels.push(LevelRecord {
                tree,
                status,
                secrets: part(child),
                root: part(node),
                signature: part(*signature),
            });
        }

        assert_eq!(at, body.len());

        Self {
            version: body[0],
            kind,
            parameters,
            flags: body[end],
            next: u64::from_be_bytes(body[end + 1..end + 9].try_into().unwrap()),
            top,
            public_key,
            levels,
        }
    }

    fn seal(&self) -> Vec<u8> {
        let mut body = vec![self.version, self.kind];

        body.extend_from_slice(&self.parameters);

        body.push(self.flags);

        body.extend_from_slice(&self.next.to_be_bytes());

        body.extend_from_slice(&self.top);

        body.extend_from_slice(&self.public_key);

        for level in &self.levels {
            body.extend_from_slice(&level.tree.to_be_bytes());

            body.push(level.status);

            body.extend_from_slice(&level.secrets);

            body.extend_from_slice(&level.root);

            body.extend_from_slice(&level.signature);
        }

        let checksum = SHA_256.digest(&body);

        [&body[..], &checksum[..16]].concat()
    }
}

// SHA-256 truncated to 24 bytes, the hash of the M24 types.
fn sha256_192(parts: &[&[u8]]) -> Vec<u8> {
    SHA_256.digest(&parts.concat())[..24].to_vec()
}

// SPEC 11.7, field by field: an HSS key at index 40 that has signed there holds tree 1 at level 1,
// with the I and SEED that the deterministic mode derives for leaf 1 of the top tree (SPEC 11.14
// item 2), and the root and parent signature that its signature carries.
#[test]
fn state_record_layout() {
    let seed: Vec<u8> = (0..40).collect();

    let store = SharedStore::default();

    let mut pair = hazmat::generate_stateful_key_pair(
        HSS_LMS,
        &seed,
        40,
        StatefulParameters::Levels(&TWO),
        store.clone(),
        &StatefulKeyGenOptions::default(),
    )
    .unwrap();

    let signature = pair.private_key.sign(b"crypto-pq").unwrap();

    let state = store.0.borrow().state.clone().unwrap();

    let (i, top_seed) = (&seed[..16], &seed[16..]);

    let child = |tag: [u8; 2]| sha256_192(&[i, &1u32.to_be_bytes(), &tag, &[0xFF], top_seed]);

    let child_secrets = [&child([0xFF, 0xFF])[..16], &child([0xFF, 0xFE])].concat();

    // u32(L - 1), the top LMS signature of the child's key, the child's key, the bottom signature.
    let top_signature = lms_signature_size(&(lms_type(10), ots_type(7)));

    let child_key = &signature[4 + top_signature..4 + top_signature + 48];

    assert_eq!(child_key[8..24], child_secrets[..16]);

    let expected = State {
        version: 2,
        kind: 1,
        parameters: unhex("020000000a000000070000000a00000006"),
        flags: 1,
        next: 41,
        top: seed.clone(),
        public_key: pair.public_key.export_key(KeyFormat::Raw).unwrap(),
        levels: vec![LevelRecord {
            tree: 1,
            status: 1,
            secrets: child_secrets,
            root: child_key[24..].to_vec(),
            signature: signature[4..4 + top_signature].to_vec(),
        }],
    };

    assert_eq!(State::parse(&state), expected);

    assert_eq!(expected.seal(), state);

    // XMSS^MT at 0x12345: the trees 0x12345 >> 15, >> 10 and >> 5 of levels 1 to 3, each with the
    // top S_XMSS (SPEC 11.14 item 3) and the layer of the signature that signs its root.
    let seed: Vec<u8> = (0..72).collect();

    let store = SharedStore::default();

    let mut pair = hazmat::generate_stateful_key_pair(
        XMSS_MT,
        &seed,
        0x12345,
        MT,
        store.clone(),
        &StatefulKeyGenOptions::default(),
    )
    .unwrap();

    // D-64 item 1: the generated record already holds the trees that the start index uses, so the
    // first signature only reserves its index.
    let generated = State::parse(&store.0.borrow().state.clone().unwrap());

    assert_eq!(generated.next, 0x12345);

    let signature = pair.private_key.sign(b"crypto-pq").unwrap();

    let parts = State::parse(&store.0.borrow().state.clone().unwrap());

    assert_eq!((store.writes(), &parts.levels), (2, &generated.levels));

    assert_eq!(
        (
            parts.version,
            parts.kind,
            &parts.parameters[..],
            parts.flags
        ),
        (2, 3, &[0, 0, 0, 0x22][..], 1)
    );

    assert_eq!((parts.next, &parts.top), (0x12346, &seed));

    let layer = (51 + 5) * 24;

    for (level, record) in (1..).zip(&parts.levels) {
        assert_eq!(record.tree, 0x12345 >> (5 * (4 - level)));

        assert_eq!((record.status, &record.secrets[..]), (1, &seed[..24]));

        let at = 3 + 24 + (4 - level) * layer;

        assert_eq!(record.signature, signature[at..at + layer]);
    }

    assert_eq!(parts.levels.len(), 3);

    // XMSS has no level records.
    let state = xmss_state(XMSS, "XMSS-SHA2_10_256", 3);

    let parts = State::parse(&state);

    assert_eq!((parts.kind, parts.next, parts.levels.len()), (2, 3, 0));
}

// SPEC 11.8: a version 1 record, the earlier layout, is refused and left as it is; so is every
// other version.
#[test]
fn version_1_records_are_refused() {
    // A version 1 HSS record.
    let version_1 = unhex(concat!(
        "0101010000000a00000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
        "1d1e1f2021222324252627000000000000000332b414e1d42dc2866aeed26f724a5be7",
    ));

    let state = xmss_state(XMSS_MT, "XMSSMT-SHAKE256_20/4_192", 3);

    let mut records = vec![(HSS_LMS, version_1)];

    for version in [0, 1, 3, 0xFF] {
        let mut parts = State::parse(&state);

        parts.version = version;

        records.push((XMSS_MT, parts.seal()));
    }

    for (algorithm, record) in records {
        let mut store = MemoryStore::holding(&record);

        assert_eq!(
            algorithm
                .load_private_key(&mut store, &StatefulLoadOptions::default())
                .err(),
            Some(Error::InvalidPrivateKey)
        );

        assert_eq!(
            (store.state.as_deref(), store.writes),
            (Some(&record[..]), 0)
        );
    }
}

// Fails the update numbered `failing` with `failure`, without storing it; every other one works.
struct FailingStore {
    inner: Rc<RefCell<MemoryStore>>,
    updates: usize,
    failing: usize,
    failure: Result<bool, Error>,
}

impl FailingStore {
    fn new(failing: usize, failure: Result<bool, Error>) -> Self {
        Self {
            inner: Rc::default(),
            updates: 0,
            failing,
            failure,
        }
    }
}

impl StateStore for FailingStore {
    fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.inner.borrow_mut().read()
    }

    fn update(&mut self, previous: Option<&[u8]>, next: &[u8]) -> Result<bool, Error> {
        self.updates += 1;

        if self.updates == self.failing {
            return self.failure;
        }

        self.inner.borrow_mut().update(previous, next)
    }
}

// A record whose secrets are all zero and which otherwise equals `before` at next = N.
fn assert_erased(state: &[u8], before: &[u8], capacity: u64) {
    let (erased, before) = (State::parse(state), State::parse(before));

    assert_eq!(erased.next, capacity);

    assert!(erased.top.iter().all(|&byte| byte == 0));

    for (record, kept) in erased.levels.iter().zip(&before.levels) {
        assert!(record.secrets.iter().all(|&byte| byte == 0));

        assert_eq!(record.secrets.len(), kept.secrets.len());

        assert_eq!(
            (record.tree, record.status, &record.root, &record.signature),
            (kept.tree, kept.status, &kept.root, &kept.signature)
        );
    }

    assert_eq!(
        (
            erased.kind,
            &erased.parameters,
            erased.flags,
            &erased.public_key
        ),
        (
            before.kind,
            &before.parameters,
            before.flags,
            &before.public_key
        )
    );
}

// The record that a deterministic key of a named XMSS or XMSS^MT set stores at index.
fn xmss_state(algorithm: StatefulSignatureAlgorithm, name: &str, index: u64) -> Vec<u8> {
    let mut store = MemoryStore::default();

    let seed: Vec<u8> = (0..96).collect();

    let size = if name.ends_with("_192") { 72 } else { 96 };

    hazmat::generate_stateful_key_pair(
        algorithm,
        &seed[..size],
        index,
        StatefulParameters::Name(name),
        &mut store,
        &StatefulKeyGenOptions::default(),
    )
    .unwrap();

    store.state.unwrap()
}

// SPEC 11.12: the signature that exhausts a key stores a final record without its secrets; the key
// refuses to sign or export a cache, and the public key still verifies. A failed final write
// does not fail the signature and is retried by the next sign or load.
#[test]
fn exhaustion_erases_the_secrets() {
    let seed: Vec<u8> = (0..40).collect();

    let two = StatefulParameters::Levels(&TWO);

    let options = StatefulKeyGenOptions::default();

    // The keys sign 1022 and 1023: update 1 stores the key with tree 31 of level 1 (D-64 item 1),
    // 2 and 3 reserve 1022 and 1023, and 4 is the final write.
    for failing in [0, 4] {
        let store = FailingStore::new(failing, Err(Error::Unsupported));

        let stored = Rc::clone(&store.inner);

        let state = || stored.borrow().state.clone().unwrap();

        let mut pair =
            hazmat::generate_stateful_key_pair(HSS_LMS, &seed, 1022, two, store, &options).unwrap();

        let first = pair.private_key.sign(b"a").unwrap();

        let before = state();

        let last = pair.private_key.sign(b"b").unwrap();

        assert_eq!(pair.private_key.remaining_signatures(), 0);

        assert_eq!(
            pair.private_key.export_tree_cache().err(),
            Some(Error::KeyExhausted)
        );

        if failing == 4 {
            // The record still holds the secrets, and the next sign retries the final write.
            let kept = State::parse(&state());

            assert_eq!((kept.next, &kept.top), (1024, &seed));

            assert_eq!(pair.private_key.sign(b"c").err(), Some(Error::KeyExhausted));
        }

        assert_erased(&state(), &before, 1024);

        assert!(pair.public_key.verify(&first, b"a"));

        assert!(pair.public_key.verify(&last, b"b"));

        let mut loaded = HSS_LMS
            .load_private_key(
                MemoryStore::holding(&state()),
                &StatefulLoadOptions::default(),
            )
            .unwrap();

        assert_eq!(loaded.remaining_signatures(), 0);

        assert_eq!(loaded.public_key(), pair.public_key);

        assert_eq!(loaded.sign(b"c").err(), Some(Error::KeyExhausted));

        assert_eq!(loaded.export_tree_cache().err(), Some(Error::KeyExhausted));
    }

    // A load that finds next = N with the secrets stores the final record, or retries it at the
    // next sign when that write fails.
    let mut at_capacity = State::parse(&xmss_state(XMSS, "XMSS-SHA2_10_256", 3));

    at_capacity.next = 1024;

    let record = at_capacity.seal();

    for failing in [0, 1] {
        let store = FailingStore::new(failing, Ok(false));

        *store.inner.borrow_mut() = MemoryStore::holding(&record);

        let stored = Rc::clone(&store.inner);

        let state = || stored.borrow().state.clone().unwrap();

        let mut key = XMSS
            .load_private_key(store, &StatefulLoadOptions::default())
            .unwrap();

        assert_eq!(key.remaining_signatures(), 0);

        if failing == 1 {
            assert_eq!(state(), record);

            assert_eq!(key.sign(b"m").err(), Some(Error::KeyExhausted));
        }

        assert_erased(&state(), &record, 1024);
    }
}

// SPEC 11.9 item 4: a level that a crash left claimed for the tree that the index uses is skipped
// with its subtree; a record ahead of the index, or signed under a level that is not current, is
// refused.
#[test]
fn a_claimed_level_is_skipped() {
    let seed: Vec<u8> = (0..48).collect();

    let store = SharedStore::default();

    let mut pair = hazmat::generate_stateful_key_pair(
        HSS_LMS,
        &seed,
        40,
        StatefulParameters::Levels(&THREE),
        store.clone(),
        &StatefulKeyGenOptions::default(),
    )
    .unwrap();

    pair.private_key.sign(b"m").unwrap();

    drop(pair.private_key);

    let state = State::parse(&store.0.borrow().state.clone().unwrap());

    assert_eq!(
        (state.next, state.levels[0].tree, state.levels[1].tree),
        (41, 0, 1)
    );

    let load = |state: &State| {
        HSS_LMS
            .load_private_key(
                MemoryStore::holding(&state.seal()),
                &StatefulLoadOptions::default(),
            )
            .map(|key| key.remaining_signatures())
    };

    let capacity = 1 << 15;

    // Level 2 claimed for tree 2, as a crash between the claim and the signed write at index 64
    // leaves it: the key resumes at the next tree of level 2, index 96.
    let mut claimed = state.clone();

    claimed.next = 64;

    claimed.levels[1] = LevelRecord {
        tree: 2,
        status: 0,
        secrets: Vec::new(),
        root: Vec::new(),
        signature: Vec::new(),
    };

    assert_eq!(load(&claimed), Ok(capacity - 96));

    let mut key = HSS_LMS
        .load_private_key(
            MemoryStore::holding(&claimed.seal()),
            &StatefulLoadOptions::default(),
        )
        .unwrap();

    let signature = key.sign(b"m").unwrap();

    assert!(pair.public_key.verify(&signature, b"m"));

    // Level 1 claimed for tree 1 at index 1024: the subtree of tree 1, to index 2048, is skipped.
    let mut upper = claimed.clone();

    upper.next = 1024;

    upper.levels[0] = LevelRecord {
        tree: 1,
        ..claimed.levels[1].clone()
    };

    assert_eq!(load(&upper), Ok(capacity - 2048));

    // A claim for a tree that the index has passed is not skipped.
    let mut passed = claimed.clone();

    passed.next = 96;

    assert_eq!(load(&passed), Ok(capacity - 96));

    // A claim, or a signed record, ahead of the index.
    let mut ahead = claimed.clone();

    ahead.next = 63;

    assert_eq!(load(&ahead), Err(Error::InvalidPrivateKey));

    let mut ahead = state.clone();

    ahead.levels[1].tree = 2;

    assert_eq!(load(&ahead), Err(Error::InvalidPrivateKey));

    // Level 2 signed for the tree that index 1056 uses, under a level 1 still at tree 0.
    let mut orphan = state.clone();

    orphan.next = 1056;

    orphan.levels[1].tree = 33;

    assert_eq!(load(&orphan), Err(Error::InvalidPrivateKey));

    // The claim of the last subtree leaves the key exhausted, and the load erases its secrets.
    let mut last = claimed.clone();

    last.next = capacity - 1;

    last.levels[0].tree = 31;

    last.levels[1].tree = 1023;

    let mut store = MemoryStore::holding(&last.seal());

    let key = HSS_LMS
        .load_private_key(&mut store, &StatefulLoadOptions::default())
        .unwrap();

    assert_eq!(key.remaining_signatures(), 0);

    drop(key);

    assert_erased(store.state.as_deref().unwrap(), &last.seal(), capacity);
}

// SPEC 11.5.2 step 3.5: when the signed write fails after the claim, the key object moves past
// the subtree of the claimed level, to the index that a load of the claim gives, and both sign the
// same way from there.
#[test]
fn a_failure_after_the_claim_skips_the_subtree() {
    let seed: Vec<u8> = (0..40).collect();

    // Index 31 is signed with update 2; index 32 claims tree 1 of level 1 with update 3 and
    // stores it signed with update 4.
    for failure in [Ok(false), Err(Error::Unsupported)] {
        let store = FailingStore::new(4, failure);

        let stored = Rc::clone(&store.inner);

        let mut pair = hazmat::generate_stateful_key_pair(
            HSS_LMS,
            &seed,
            31,
            StatefulParameters::Levels(&TWO),
            store,
            &StatefulKeyGenOptions::default(),
        )
        .unwrap();

        pair.private_key.sign(b"31").unwrap();

        let expected = if failure.is_ok() {
            Error::StateConflict
        } else {
            Error::StatePersistFailed
        };

        assert_eq!(pair.private_key.sign(b"32").err(), Some(expected));

        assert_eq!(pair.private_key.remaining_signatures(), 1024 - 64);

        let claim = stored.borrow().state.clone().unwrap();

        let parts = State::parse(&claim);

        assert_eq!(
            (parts.next, parts.levels[0].tree, parts.levels[0].status),
            (32, 1, 0)
        );

        let mut loaded = HSS_LMS
            .load_private_key(
                MemoryStore::holding(&claim),
                &StatefulLoadOptions::default(),
            )
            .unwrap();

        assert_eq!(loaded.remaining_signatures(), 1024 - 64);

        let from_load = loaded.sign(b"64").unwrap();

        assert_eq!(pair.private_key.sign(b"64").unwrap(), from_load);

        // Index 64 uses leaf 2 of the top tree; leaf 1, which the claim covered, signed nothing
        // that was kept.
        assert_eq!(read_u32(&from_load, 4), 2);
    }
}

// SPEC 11.4: a key from generate_key_pair draws a fresh I and SEED for each child tree, a fresh
// randomizer C for each LMS signature, and a fresh S_XMSS for each XMSS^MT tree; none of them is
// the value that the deterministic mode derives.
#[test]
fn fresh_randomness() {
    let store = SharedStore::default();

    let mut pair = HSS_LMS
        .generate_key_pair(
            StatefulParameters::Levels(&TWO),
            store.clone(),
            &StatefulKeyGenOptions::default(),
        )
        .unwrap();

    let signatures: Vec<Vec<u8>> = (0..3u8)
        .map(|i| pair.private_key.sign(&[i]).unwrap())
        .collect();

    let state = State::parse(&store.0.borrow().state.clone().unwrap());

    assert_eq!(state.flags, 0);

    let (i, seed) = (&state.top[..16], &state.top[16..]);

    let derived = |q: u32, tag: [u8; 2]| sha256_192(&[i, &q.to_be_bytes(), &tag, &[0xFF], seed]);

    let child = &state.levels[0].secrets;

    assert_ne!(child[..16], derived(0, [0xFF, 0xFF])[..16]);

    assert_ne!(child[16..], derived(0, [0xFF, 0xFE]));

    let top_signature = lms_signature_size(&(lms_type(10), ots_type(7)));

    // C of the signature of the child's key by leaf 0, then C of each bottom signature.
    let parent_c = &state.levels[0].signature[8..32];

    assert_ne!(parent_c, &derived(0, [0xFF, 0xFD])[..]);

    let bottom = 4 + top_signature + 48;

    let randomizers: Vec<&[u8]> = signatures
        .iter()
        .map(|signature| &signature[bottom + 8..bottom + 32])
        .collect();

    let (child_i, child_seed) = (&child[..16], &child[16..]);

    for (q, c) in (0u32..).zip(&randomizers) {
        let derived_c = sha256_192(&[
            child_i,
            &q.to_be_bytes(),
            &[0xFF, 0xFD],
            &[0xFF],
            child_seed,
        ]);

        assert_ne!(*c, &derived_c[..]);
    }

    assert!(randomizers[0] != randomizers[1] && randomizers[1] != randomizers[2]);

    let store = SharedStore::default();

    XMSS_MT
        .generate_key_pair(MT, store.clone(), &StatefulKeyGenOptions::default())
        .unwrap();

    let state = State::parse(&store.0.borrow().state.clone().unwrap());

    let mut seeds: Vec<&[u8]> = state
        .levels
        .iter()
        .map(|level| &level.secrets[..])
        .collect();

    seeds.push(&state.top[..24]);

    seeds.sort();

    seeds.dedup();

    assert_eq!((state.flags, seeds.len()), (0, 4));
}

fn generating(reserve: u64) -> StatefulKeyGenOptions {
    StatefulKeyGenOptions::default().with_reserve(reserve)
}

fn loading(reserve: u64) -> StatefulLoadOptions<'static> {
    StatefulLoadOptions::default().with_reserve(reserve)
}

// The LMS leaf index q of a one-level HSS signature.
fn leaf(signature: &[u8]) -> u32 {
    read_u32(signature, 4)
}

#[test]
fn reserve_claims_indices_ahead() {
    let store = SharedStore::default();

    let small = StatefulParameters::Levels(&SMALL);

    let mut key = HSS_LMS
        .generate_key_pair(small, store.clone(), &generating(4))
        .unwrap()
        .private_key;

    assert_eq!((store.index(), store.writes()), (0, 1));

    let mut stored = Vec::new();

    for i in 0..10u8 {
        let signature = key.sign(&[i]).unwrap();

        assert_eq!(leaf(&signature), u32::from(i));

        assert_eq!(key.remaining_signatures(), 31 - u64::from(i));

        stored.push(store.index());
    }

    assert_eq!(stored, [4, 4, 4, 4, 8, 8, 8, 8, 12, 12]);

    assert_eq!(store.writes(), 4);
}

// Indices reserved but not used before a stop are skipped: loading starts after them.
#[test]
fn reload_skips_the_reserved_range() {
    let store = SharedStore::default();

    let small = StatefulParameters::Levels(&SMALL);

    let mut pair = HSS_LMS
        .generate_key_pair(small, store.clone(), &generating(5))
        .unwrap();

    for message in [b"a", b"b"] {
        pair.private_key.sign(message).unwrap();
    }

    drop(pair);

    let mut loaded = HSS_LMS
        .load_private_key(store.clone(), &StatefulLoadOptions::default())
        .unwrap();

    assert_eq!(loaded.remaining_signatures(), 27);

    assert_eq!(leaf(&loaded.sign(b"c").unwrap()), 5);

    assert_eq!((store.index(), store.writes()), (6, 3));
}

// Two keys on one store hold disjoint reservations. A key that runs out of its own cannot claim
// more once the store has moved on.
#[test]
fn reservations_never_overlap() {
    let store = SharedStore::default();

    let small = StatefulParameters::Levels(&SMALL);

    let mut first = HSS_LMS
        .generate_key_pair(small, store.clone(), &generating(4))
        .unwrap()
        .private_key;

    assert_eq!(leaf(&first.sign(b"0").unwrap()), 0);

    let mut second = HSS_LMS
        .load_private_key(store.clone(), &loading(4))
        .unwrap();

    assert_eq!(leaf(&second.sign(b"4").unwrap()), 4);

    for q in 1..4 {
        assert_eq!(leaf(&first.sign(b"own").unwrap()), q);
    }

    assert_eq!(first.sign(b"4 again").err(), Some(Error::StateConflict));

    assert_eq!(first.remaining_signatures(), 28);

    assert_eq!(store.index(), 8);
}

// Reservation never changes what is signed: the same seed and index give the same bytes,
// across a boundary of the lower HSS trees and of the XMSS^MT layers.
#[test]
fn reserve_keeps_the_signatures() {
    let hss_seed: Vec<u8> = (0..40).collect();

    let levels = [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"); 2];

    let xmss_seed: Vec<u8> = (0..72).collect();

    let cases = [
        (HSS_LMS, StatefulParameters::Levels(&levels), &hss_seed, 29),
        (
            XMSS_MT,
            StatefulParameters::Name("XMSSMT-SHA2_20/4_192"),
            &xmss_seed,
            1021,
        ),
    ];

    for (algorithm, parameters, seed, first) in cases {
        let signatures = |reserve| {
            let mut key = hazmat::generate_stateful_key_pair(
                algorithm,
                seed,
                first,
                parameters,
                MemoryStore::default(),
                &generating(reserve),
            )
            .unwrap()
            .private_key;

            (0..6u8)
                .map(|i| key.sign(&[i]).unwrap())
                .collect::<Vec<_>>()
        };

        let expected = signatures(1);

        for reserve in [2, 5, u64::MAX] {
            assert_eq!(signatures(reserve), expected, "{reserve}");
        }
    }
}

// A reservation stops at the capacity, even a reservation as large as u64::MAX.
#[test]
fn reserve_stops_at_the_capacity() {
    for reserve in [100, u64::MAX] {
        let store = SharedStore::default();

        let small = StatefulParameters::Levels(&SMALL);

        let mut key = HSS_LMS
            .generate_key_pair(small, store.clone(), &generating(reserve))
            .unwrap()
            .private_key;

        for q in 0..32 {
            assert_eq!(leaf(&key.sign(b"m").unwrap()), q);
        }

        assert_eq!(key.sign(b"m").err(), Some(Error::KeyExhausted));

        // The key, the reservation of every index, and the final record of SPEC 11.12.
        assert_eq!((store.index(), store.writes()), (32, 3));

        let loaded = HSS_LMS
            .load_private_key(store, &StatefulLoadOptions::default())
            .unwrap();

        assert_eq!(loaded.remaining_signatures(), 0);
    }
}

#[test]
fn reserve_must_be_positive() {
    let small = StatefulParameters::Levels(&SMALL);

    let mut store = MemoryStore::default();

    assert_eq!(
        HSS_LMS
            .generate_key_pair(small, &mut store, &generating(0))
            .err(),
        Some(Error::InvalidOption)
    );

    assert_eq!(
        hazmat::generate_stateful_key_pair(HSS_LMS, &[0; 40], 0, small, &mut store, &generating(0))
            .err(),
        Some(Error::InvalidOption)
    );

    assert!(store.state.is_none());

    HSS_LMS
        .generate_key_pair(small, &mut store, &StatefulKeyGenOptions::default())
        .unwrap();

    assert_eq!(
        HSS_LMS.load_private_key(&mut store, &loading(0)).err(),
        Some(Error::InvalidOption)
    );

    assert_eq!(StatefulKeyGenOptions::default(), generating(1));

    assert_eq!(StatefulLoadOptions::default(), loading(1));
}

type KeySlot = Rc<RefCell<Option<StatefulPrivateKey<ReachingStore>>>>;

// A store that tries to sign with the key it serves, from inside update.
struct ReachingStore {
    inner: MemoryStore,
    key: KeySlot,
    refused: Rc<Cell<usize>>,
}

impl StateStore for ReachingStore {
    fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.inner.read()
    }

    fn update(&mut self, previous: Option<&[u8]>, next: &[u8]) -> Result<bool, Error> {
        match self.key.try_borrow_mut() {
            Ok(mut key) => {
                if let Some(key) = key.as_mut() {
                    key.sign(b"from the store")?;
                }
            }
            Err(_) => {
                assert!(self.key.try_borrow().is_err());

                self.refused.set(self.refused.get() + 1);
            }
        }

        self.inner.update(previous, next)
    }
}

// sign holds the key exclusively while the store runs, so a store cannot reach the key that is
// signing, even when it holds the key itself: the borrow is refused, and no index is used twice.
#[test]
fn the_store_cannot_reach_the_signing_key() {
    let slot: KeySlot = Rc::default();

    let refused = Rc::new(Cell::new(0));

    let store = ReachingStore {
        inner: MemoryStore::default(),
        key: Rc::clone(&slot),
        refused: Rc::clone(&refused),
    };

    let small = StatefulParameters::Levels(&SMALL);

    let pair = HSS_LMS
        .generate_key_pair(small, store, &StatefulKeyGenOptions::default())
        .unwrap();

    *slot.borrow_mut() = Some(pair.private_key);

    for q in 0..3 {
        let signature = slot.borrow_mut().as_mut().unwrap().sign(b"m").unwrap();

        assert_eq!(leaf(&signature), q);

        assert!(pair.public_key.verify(&signature, b"m"));
    }

    assert_eq!(refused.get(), 3);

    slot.borrow_mut().take();
}

// The upper XMSS^MT layers keep their part of the signature: a running key must sign exactly as
// fresh keys at the same indices, across boundaries of the first and second layers.
#[test]
fn xmss_mt_kept_layers_match_fresh_keys() {
    let seed: Vec<u8> = (0..72).collect();

    let parameters = StatefulParameters::Name("XMSSMT-SHA2_20/4_192");

    let options = StatefulKeyGenOptions::default();

    let fresh = |index| {
        hazmat::generate_stateful_key_pair(
            XMSS_MT,
            &seed,
            index,
            parameters,
            MemoryStore::default(),
            &options,
        )
        .unwrap()
    };

    for first in [30, 1022] {
        let mut running = fresh(first);

        for index in first..first + 4 {
            let signature = running.private_key.sign(b"m").unwrap();

            assert!(running.public_key.verify(&signature, b"m"));

            assert_eq!(
                fresh(index).private_key.sign(b"m").unwrap(),
                signature,
                "{index}"
            );
        }
    }
}

// Tree caches.
const TWO: [(&str, &str); 2] = [
    ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"),
    ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W2"),
];

const THREE: [(&str, &str); 3] = [
    ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W2"),
    ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W1"),
    ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W2"),
];

const MT: StatefulParameters<'static> = StatefulParameters::Name("XMSSMT-SHA2_20/4_192");

// The state that a key at `index` stored, its raw public key and the tree cache it exports, after
// a signature there when `sign` is set.
struct Exported {
    state: Vec<u8>,
    public_key: Vec<u8>,
    cache: Vec<u8>,
}

fn export_cache(
    algorithm: StatefulSignatureAlgorithm,
    parameters: StatefulParameters,
    seed: &[u8],
    index: u64,
    sign: bool,
) -> Exported {
    let store = SharedStore::default();

    let options = StatefulKeyGenOptions::default();

    let mut pair = hazmat::generate_stateful_key_pair(
        algorithm,
        seed,
        index,
        parameters,
        store.clone(),
        &options,
    )
    .unwrap();

    if sign {
        pair.private_key.sign(b"first").unwrap();
    }

    let cache = pair.private_key.export_tree_cache().unwrap();

    let state = store.0.borrow().state.clone().unwrap();

    Exported {
        state,
        public_key: pair.public_key.export_key(KeyFormat::Raw).unwrap(),
        cache,
    }
}

// A copy of a state with another index, sealed again.
fn with_index(state: &[u8], index: u64) -> Vec<u8> {
    let mut out = state.to_vec();

    let at = next_offset(&out);

    out[at..at + 8].copy_from_slice(&index.to_be_bytes());

    let end = out.len() - 16;

    let digest = SHA_256.digest(&out[..end]);

    out[end..].copy_from_slice(&digest[..16]);

    out
}

fn flipped(data: &[u8], position: usize, mask: u8) -> Vec<u8> {
    let mut out = data.to_vec();

    out[position] ^= mask;

    out
}

// A cache body closed by its tag under the key derived from `seed`, as only the key's holder can.
fn seal_cache(body: &[u8], seed: &[u8]) -> Vec<u8> {
    let key = HMAC_SHA_256
        .digest(b"crypto-pq tree cache v1", seed)
        .unwrap();

    [body, &HMAC_SHA_256.digest(&key, body).unwrap()].concat()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CacheTree {
    level: u8,
    tree: u64,
    low: u8,
    height: u8,
    n: u8,
    count: u32,
    nodes: Vec<u8>,
}

// A tree cache taken apart, so that a test can change a field and seal the cache again: only then
// do the checks after the tag see the change.
#[derive(Clone)]
struct Cache {
    version: u8,
    kind: u8,
    parameters: Vec<u8>,
    public_key: Vec<u8>,
    trees: Vec<CacheTree>,
}

impl Cache {
    fn parse(data: &[u8]) -> Self {
        let end = if data[1] == 1 {
            3 + 8 * usize::from(data[2])
        } else {
            6
        };

        let size = read_u32(data, end) as usize;

        let mut offset = end + 5 + size;

        let mut trees = Vec::new();

        for _ in 0..data[end + 4 + size] {
            let header = &data[offset..offset + 16];

            let (n, count) = (header[11], read_u32(header, 12));

            let nodes = data[offset + 16..][..count as usize * usize::from(n)].to_vec();

            offset += 16 + nodes.len();

            trees.push(CacheTree {
                level: header[0],
                tree: u64::from_be_bytes(header[1..9].try_into().unwrap()),
                low: header[9],
                height: header[10],
                n,
                count,
                nodes,
            });
        }

        Self {
            version: data[0],
            kind: data[1],
            parameters: data[2..end].to_vec(),
            public_key: data[end + 4..end + 4 + size].to_vec(),
            trees,
        }
    }

    // Where the nodes of tree i start.
    fn nodes_at(&self, i: usize) -> usize {
        let before: usize = self.trees[..i]
            .iter()
            .map(|tree| 16 + tree.nodes.len())
            .sum();

        7 + self.parameters.len() + self.public_key.len() + before + 16
    }

    fn seal(&self, seed: &[u8]) -> Vec<u8> {
        let mut body = vec![self.version, self.kind];

        body.extend_from_slice(&self.parameters);

        body.extend_from_slice(&(self.public_key.len() as u32).to_be_bytes());

        body.extend_from_slice(&self.public_key);

        body.push(self.trees.len() as u8);

        for tree in &self.trees {
            body.push(tree.level);

            body.extend_from_slice(&tree.tree.to_be_bytes());

            body.extend_from_slice(&[tree.low, tree.height, tree.n]);

            body.extend_from_slice(&tree.count.to_be_bytes());

            body.extend_from_slice(&tree.nodes);
        }

        seal_cache(&body, seed)
    }
}

fn load_cached(
    algorithm: StatefulSignatureAlgorithm,
    state: &[u8],
    cache: &[u8],
) -> Result<StatefulPrivateKey<MemoryStore>, Error> {
    let options = StatefulLoadOptions::default().with_tree_cache(cache);

    algorithm.load_private_key(MemoryStore::holding(state), &options)
}

fn refusal(algorithm: StatefulSignatureAlgorithm, state: &[u8], cache: &[u8]) -> Option<Error> {
    load_cached(algorithm, state, cache).err()
}

// A key loaded with the cache matches one loaded without it: the same public key and count, and
// the same next signature.
fn assert_loads(algorithm: StatefulSignatureAlgorithm, state: &[u8], cache: &[u8]) {
    let mut cached = load_cached(algorithm, state, cache).unwrap();

    let mut plain = algorithm
        .load_private_key(MemoryStore::holding(state), &StatefulLoadOptions::default())
        .unwrap();

    assert_eq!(cached.public_key(), plain.public_key());

    assert_eq!(cached.remaining_signatures(), plain.remaining_signatures());

    if plain.remaining_signatures() > 0 {
        assert_eq!(cached.sign(b"next").unwrap(), plain.sign(b"next").unwrap());
    }
}

// A key loaded with its cache signs as the key that exported it and as one that built its trees,
// and exports the same cache.
#[test]
fn tree_cache_round_trip() {
    let seed: Vec<u8> = (0..72).collect();

    let cases = [
        (HSS_LMS, StatefulParameters::Levels(&TWO), 40, 40),
        (HSS_LMS, StatefulParameters::Levels(&THREE), 48, 5000),
        (XMSS_MT, MT, 72, 0x12345),
        (XMSS, StatefulParameters::Name("XMSS-SHA2_10_192"), 72, 1000),
    ];

    for (algorithm, parameters, size, index) in cases {
        let store = SharedStore::default();

        let options = StatefulKeyGenOptions::default();

        let mut pair = hazmat::generate_stateful_key_pair(
            algorithm,
            &seed[..size],
            index,
            parameters,
            store.clone(),
            &options,
        )
        .unwrap();

        pair.private_key.sign(b"first").unwrap();

        let cache = pair.private_key.export_tree_cache().unwrap();

        let state = store.0.borrow().state.clone().unwrap();

        let mut loaded = load_cached(algorithm, &state, &cache).unwrap();

        let mut plain = algorithm
            .load_private_key(
                MemoryStore::holding(&state),
                &StatefulLoadOptions::default(),
            )
            .unwrap();

        assert_eq!(loaded.public_key(), pair.public_key);

        assert_eq!(loaded.export_tree_cache().unwrap(), cache);

        for message in [&b"second"[..], b"third"] {
            let signature = loaded.sign(message).unwrap();

            assert!(pair.public_key.verify(&signature, message));

            assert_eq!(signature, plain.sign(message).unwrap());
        }

        assert_eq!(
            loaded.export_tree_cache().unwrap(),
            plain.export_tree_cache().unwrap()
        );
    }
}

// The fields of a cache, which lists every tree that the key holds, top first, and its tag under
// the key derived from the seed.
#[test]
fn tree_cache_layout() {
    let seed: Vec<u8> = (0..72).collect();

    let hss = export_cache(
        HSS_LMS,
        StatefulParameters::Levels(&TWO),
        &seed[..40],
        40,
        true,
    );

    let parts = Cache::parse(&hss.cache);

    assert_eq!((parts.version, parts.kind), (1, 1));

    assert_eq!(
        parts.parameters,
        unhex("020000000a000000070000000a00000006")
    );

    assert_eq!(parts.public_key, hss.public_key);

    let shapes: Vec<_> = parts
        .trees
        .iter()
        .map(|tree| {
            (
                tree.level,
                tree.tree,
                tree.low,
                tree.height,
                tree.n,
                tree.count,
            )
        })
        .collect();

    assert_eq!(shapes, [(0, 0, 0, 5, 24, 63), (1, 1, 0, 5, 24, 63)]);

    assert_eq!(
        parts.trees[0].nodes[62 * 24..],
        hss.public_key[hss.public_key.len() - 24..]
    );

    assert_eq!(parts.seal(&seed[..40]), hss.cache);

    let fresh = export_cache(
        HSS_LMS,
        StatefulParameters::Levels(&TWO),
        &seed[..40],
        40,
        false,
    );

    // A key holds the trees of its start index from its generation on (D-64 item 1).
    assert_eq!(Cache::parse(&fresh.cache).trees, parts.trees);

    let mt = export_cache(XMSS_MT, MT, &seed, 0x12345, true);

    let parts = Cache::parse(&mt.cache);

    assert_eq!(
        (parts.kind, parts.parameters.as_slice()),
        (3, &[0, 0, 0, 0x22][..])
    );

    let shapes: Vec<_> = parts
        .trees
        .iter()
        .map(|tree| {
            (
                tree.level,
                tree.tree,
                tree.low,
                tree.height,
                tree.n,
                tree.count,
            )
        })
        .collect();

    assert_eq!(
        shapes,
        [
            (3, 0, 0, 5, 24, 63),
            (2, 2, 0, 5, 24, 63),
            (1, 72, 0, 5, 24, 63),
            (0, 2330, 0, 5, 24, 63)
        ]
    );

    assert_eq!(parts.trees[0].nodes[62 * 24..], mt.public_key[4..28]);

    assert_eq!(parts.seal(&seed), mt.cache);
}

// The checks before the tag and of the state: each fails, and a stale tree is skipped.
#[test]
fn tree_cache_rejections() {
    let seed: Vec<u8> = (0..40).collect();

    let Exported { state, cache, .. } =
        export_cache(HSS_LMS, StatefulParameters::Levels(&TWO), &seed, 40, true);

    let parts = Cache::parse(&cache);

    let invalid = [
        flipped(&cache, parts.nodes_at(0) + 5, 1),
        flipped(&cache, parts.nodes_at(1) + 30, 1),
        flipped(&cache, cache.len() - 32, 1),
        flipped(&cache, cache.len() - 1, 1),
        flipped(&cache, 0, 1),
        flipped(&cache, 0, 3),
        flipped(&flipped(&cache, 0, 3), 1, 3),
        flipped(&cache, 1, 3)[..cache.len() - 1].to_vec(),
        cache[..10].to_vec(),
        [&cache[..], &[0]].concat(),
        [&cache[..], &cache[cache.len() - 32..]].concat(),
        export_cache(
            HSS_LMS,
            StatefulParameters::Levels(&TWO),
            &[0; 40],
            40,
            true,
        )
        .cache,
    ];

    for data in &invalid {
        assert_eq!(refusal(HSS_LMS, &state, data), Some(Error::InvalidEncoding));
    }

    // An empty cache is no cache (SPEC 6.3 item 2).
    assert_loads(HSS_LMS, &state, &[]);

    for length in 1..cache.len() {
        assert_eq!(
            refusal(HSS_LMS, &state, &cache[..length]),
            Some(Error::InvalidEncoding),
            "{length}"
        );
    }

    // Another kind reads the HSS parameters with its own layout, or with none, and finds the
    // cache malformed; a cache made for another algorithm is AlgorithmMismatch.
    for kind in [0, 2, 3, 4] {
        let data = flipped(&cache, 1, 1 ^ kind);

        assert_eq!(
            refusal(HSS_LMS, &state, &data),
            Some(Error::InvalidEncoding)
        );
    }

    let seed72: Vec<u8> = (0..72).collect();

    let mt = export_cache(XMSS_MT, MT, &seed72, 0x12345, true);

    assert_eq!(
        refusal(HSS_LMS, &state, &mt.cache),
        Some(Error::AlgorithmMismatch)
    );

    assert_eq!(
        refusal(XMSS_MT, &mt.state, &cache),
        Some(Error::AlgorithmMismatch)
    );

    // The same seed with another type below the top: the public key and the tag key are the same,
    // and only the parameters tell the keys apart.
    for lower in [
        ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W8"),
        ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W2"),
    ] {
        let levels = [TWO[0], lower];

        let other = export_cache(
            HSS_LMS,
            StatefulParameters::Levels(&levels),
            &seed,
            41,
            false,
        );

        assert_eq!(
            refusal(HSS_LMS, &other.state, &cache),
            Some(Error::InvalidEncoding)
        );
    }

    // The same I with another SEED: the bytes of the public key that the state gives match, the
    // tag does not.
    let other_seed = [&seed[..16], &[0; 24]].concat();

    let other = export_cache(
        HSS_LMS,
        StatefulParameters::Levels(&TWO),
        &other_seed,
        41,
        false,
    );

    assert_eq!(
        refusal(HSS_LMS, &other.state, &cache),
        Some(Error::InvalidEncoding)
    );

    // The state is checked before the cache.
    assert_eq!(
        refusal(HSS_LMS, &state[..state.len() - 1], &cache),
        Some(Error::InvalidPrivateKey)
    );

    assert_eq!(
        refusal(HSS_LMS, &with_index(&state, 1025), &cache),
        Some(Error::InvalidPrivateKey)
    );

    assert_loads(HSS_LMS, &with_index(&state, 1024), &cache);

    // Index 64 has left tree 1 of level 1, which the next signature builds.
    assert_loads(HSS_LMS, &with_index(&state, 64), &cache);

    assert_loads(HSS_LMS, &state, &cache);
}

// Changes sealed with the key's seed, which only the checks after the tag can catch.
#[test]
fn tree_cache_sealed_changes() {
    let seed: Vec<u8> = (0..72).collect();

    let hss = export_cache(
        HSS_LMS,
        StatefulParameters::Levels(&TWO),
        &seed[..40],
        40,
        true,
    );

    // Index 64 has left tree 1 of level 1; at the capacity no lower tree is needed.
    let later = with_index(&hss.state, 64);

    let capacity = with_index(&hss.state, 1024);

    let original = Cache::parse(&hss.cache);

    let changed = |edit: &dyn Fn(&mut Cache)| {
        let mut parts = original.clone();

        edit(&mut parts);

        parts.seal(&seed[..40])
    };

    let node = |tree: usize, position: usize| {
        move |parts: &mut Cache| parts.trees[tree].nodes[position] ^= 1
    };

    let refused = |state: &[u8], data: &[u8]| refusal(HSS_LMS, state, data);

    let invalid = Some(Error::InvalidEncoding);

    assert_eq!(refused(&hss.state, &changed(&node(1, 7))), invalid);

    assert_loads(HSS_LMS, &later, &changed(&node(1, 7)));

    assert_eq!(refused(&hss.state, &changed(&node(1, 62 * 24))), invalid);

    assert_eq!(refused(&hss.state, &changed(&node(0, 0))), invalid);

    // Tree 1 claimed as tree 2: stale at index 41, checked against tree 2 at index 64.
    let renumbered = changed(&|parts| parts.trees[1].tree = 2);

    assert_loads(HSS_LMS, &hss.state, &renumbered);

    assert_eq!(refused(&later, &renumbered), invalid);

    // A level out of order, twice or unknown, or a tree of another shape, stale or not.
    assert_eq!(
        refused(&hss.state, &changed(&|parts| parts.trees.swap(0, 1))),
        invalid
    );

    assert_eq!(
        refused(
            &hss.state,
            &changed(&|parts| parts.trees[1] = parts.trees[0].clone())
        ),
        invalid
    );

    assert_eq!(
        refused(&hss.state, &changed(&|parts| parts.trees[1].level = 2)),
        invalid
    );

    let taller = |parts: &mut Cache| {
        parts.trees[1] = CacheTree {
            level: 1,
            tree: 0,
            low: 0,
            height: 6,
            n: 24,
            count: 127,
            nodes: vec![1; 127 * 24],
        };
    };

    assert_eq!(refused(&later, &changed(&taller)), invalid);

    let shorter = |parts: &mut Cache| {
        parts.trees[1].count = 62;

        parts.trees[1].nodes.truncate(62 * 24);
    };

    assert_eq!(refused(&hss.state, &changed(&shorter)), invalid);

    // No trees, the top only and level 1 only all load.
    for kept in [0..0, 0..1, 1..2] {
        assert_loads(
            HSS_LMS,
            &hss.state,
            &changed(&|parts| parts.trees = parts.trees[kept.clone()].to_vec()),
        );
    }

    // A top tree numbered 1 is stale. At the capacity no tree is built and the cache is ignored
    // (SPEC 11.9 item 5).
    let stale_top = |parts: &mut Cache| {
        parts.trees[0].nodes[5] ^= 1;

        parts.trees[0].tree = 1;
    };

    assert_loads(HSS_LMS, &hss.state, &changed(&stale_top));

    assert_loads(HSS_LMS, &capacity, &changed(&node(0, 5)));

    assert_loads(HSS_LMS, &capacity, b"not a cache");

    // The public key and the parameters are checked against the state.
    let root = |parts: &mut Cache| *parts.public_key.last_mut().unwrap() ^= 1;

    assert_eq!(refused(&hss.state, &changed(&root)), invalid);

    assert_eq!(
        refused(
            &hss.state,
            &changed(&|parts| {
                parts.public_key.pop();
            })
        ),
        invalid
    );

    for hex in [
        "020000000a000000070000000a00000008",
        "010000000a00000007",
        "020000000a000000060000000a00000007",
    ] {
        let parameters = |parts: &mut Cache| parts.parameters = unhex(hex);

        assert_eq!(refused(&hss.state, &changed(&parameters)), invalid);
    }

    assert_eq!(changed(&|_| {}), hss.cache);

    // XMSS^MT: a changed node of a needed layer, a stale layer 0, no top layer, and the
    // parameters and kind of other sets.
    let mt = export_cache(XMSS_MT, MT, &seed, 0x12345, true);

    let mt_later = with_index(&mt.state, 0x12360);

    let mt_original = Cache::parse(&mt.cache);

    let mt_changed = |edit: &dyn Fn(&mut Cache)| {
        let mut parts = mt_original.clone();

        edit(&mut parts);

        parts.seal(&seed)
    };

    let bottom = mt_changed(&|parts| parts.trees[3].nodes[40] ^= 1);

    assert_eq!(refusal(XMSS_MT, &mt.state, &bottom), invalid);

    assert_loads(XMSS_MT, &mt_later, &bottom);

    assert_loads(
        XMSS_MT,
        &mt.state,
        &mt_changed(&|parts| {
            parts.trees.remove(0);
        }),
    );

    let other_set = mt_changed(&|parts| parts.parameters = vec![0, 0, 0, 0x21]);

    assert_eq!(refusal(XMSS_MT, &mt.state, &other_set), invalid);

    assert_eq!(
        refusal(XMSS_MT, &mt.state, &mt_changed(&|parts| parts.kind = 2)),
        Some(Error::AlgorithmMismatch)
    );
}

// Every change of one byte is refused: the kind byte becomes 0 or 0x81, no kind at all.
#[test]
fn tree_cache_refuses_every_changed_byte() {
    let seed: Vec<u8> = (0..40).collect();

    let one = [TWO[0]];

    let exported = export_cache(HSS_LMS, StatefulParameters::Levels(&one), &seed, 5, true);

    for position in 0..exported.cache.len() {
        for mask in [0x01, 0x80] {
            let data = flipped(&exported.cache, position, mask);

            assert_eq!(
                refusal(HSS_LMS, &exported.state, &data),
                Some(Error::InvalidEncoding),
                "{position} {mask}"
            );
        }
    }
}

type ExportSlot = Rc<RefCell<Option<StatefulPrivateKey<ExportingStore>>>>;

// A store that tries to export the cache of the key it serves, from inside update.
struct ExportingStore {
    inner: MemoryStore,
    key: ExportSlot,
    refused: Rc<Cell<usize>>,
}

impl StateStore for ExportingStore {
    fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.inner.read()
    }

    fn update(&mut self, previous: Option<&[u8]>, next: &[u8]) -> Result<bool, Error> {
        match self.key.try_borrow() {
            Ok(key) => {
                if let Some(key) = key.as_ref() {
                    key.export_tree_cache()?;
                }
            }
            Err(_) => self.refused.set(self.refused.get() + 1),
        }

        self.inner.update(previous, next)
    }
}

// sign holds the key exclusively while the store runs, so the store cannot export the trees that
// are changing: the borrow is refused, where the other languages give StateConflict.
#[test]
fn tree_cache_export_cannot_overlap_a_signature() {
    let slot: ExportSlot = Rc::default();

    let refused = Rc::new(Cell::new(0));

    let store = ExportingStore {
        inner: MemoryStore::default(),
        key: Rc::clone(&slot),
        refused: Rc::clone(&refused),
    };

    let small = StatefulParameters::Levels(&SMALL);

    let pair = HSS_LMS
        .generate_key_pair(small, store, &StatefulKeyGenOptions::default())
        .unwrap();

    *slot.borrow_mut() = Some(pair.private_key);

    let signature = slot.borrow_mut().as_mut().unwrap().sign(b"m").unwrap();

    assert!(pair.public_key.verify(&signature, b"m"));

    assert_eq!(refused.get(), 1);

    let cache = slot.borrow().as_ref().unwrap().export_tree_cache().unwrap();

    assert_eq!(
        Cache::parse(&cache).public_key,
        pair.public_key.export_key(KeyFormat::Raw).unwrap()
    );

    slot.borrow_mut().take();
}

// The load that the cache saves for one tree of height 10, with its 1024 leaves, against the
// parents alone.
#[test]
fn tree_cache_load_time() {
    let levels = [("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W2")];

    let exported = export_cache(
        HSS_LMS,
        StatefulParameters::Levels(&levels),
        &[0; 40],
        0,
        false,
    );

    let start = std::time::Instant::now();

    let plain = HSS_LMS
        .load_private_key(
            MemoryStore::holding(&exported.state),
            &StatefulLoadOptions::default(),
        )
        .unwrap();

    let middle = std::time::Instant::now();

    let cached = load_cached(HSS_LMS, &exported.state, &exported.cache).unwrap();

    let end = std::time::Instant::now();

    assert_eq!(cached.public_key(), plain.public_key());

    assert!(
        4 * (end - middle) < middle - start,
        "{:?} without the cache, {:?} with it",
        middle - start,
        end - middle
    );
}

// Random changes sealed with the seed, so that they pass the tag: a cache that still loads gives
// the signatures of a key that built its trees, and any other is refused as malformed or as a
// cache of another algorithm.
#[test]
fn tree_cache_random_sealed_changes() {
    let seed: Vec<u8> = (0..72).collect();

    let mut random = 0x9E37_79B9_7F4A_7C15_u64;

    let mut next = |bound: usize| {
        random ^= random << 13;

        random ^= random >> 7;

        random ^= random << 17;

        (random % bound as u64) as usize
    };

    let mut loads = 0;

    for (algorithm, parameters, size, index, later) in [
        (HSS_LMS, StatefulParameters::Levels(&TWO), 40, 40, 64),
        (XMSS_MT, MT, 72, 0x12345, 0x12360),
    ] {
        let exported = export_cache(algorithm, parameters, &seed[..size], index, true);

        let states = [exported.state.clone(), with_index(&exported.state, later)];

        let expected: Vec<Vec<u8>> = states
            .iter()
            .map(|state| {
                algorithm
                    .load_private_key(MemoryStore::holding(state), &StatefulLoadOptions::default())
                    .unwrap()
                    .sign(b"next")
                    .unwrap()
            })
            .collect();

        let body = &exported.cache[..exported.cache.len() - 32];

        for _ in 0..150 {
            let mut changed = body.to_vec();

            for _ in 0..1 + next(3) {
                let position = next(changed.len());

                match next(4) {
                    0 => changed[position] ^= 1 << next(8),
                    1 => changed[position] = next(256) as u8,
                    2 => {
                        changed.remove(position);
                    }
                    _ => changed.insert(position, next(256) as u8),
                }
            }

            let which = next(states.len());

            match load_cached(
                algorithm,
                &states[which],
                &seal_cache(&changed, &seed[..size]),
            ) {
                Ok(mut key) => {
                    loads += 1;

                    assert_eq!(key.sign(b"next").unwrap(), expected[which]);
                }
                Err(error) => assert!(
                    matches!(error, Error::InvalidEncoding | Error::AlgorithmMismatch),
                    "{error:?}"
                ),
            }
        }
    }

    assert!(loads > 0);
}

// RFC 9802, Appendices A to C: the self-signed certificates of an HSS/LMS, an XMSS and an XMSS^MT
// key; each public key, imported from its SubjectPublicKeyInfo, verifies the TBSCertificate.
#[test]
fn rfc9802_certificates() {
    let found = records("rfc/stateful_certificates.txt", "spki");

    assert_eq!(found.len(), 3);

    for (_, record) in found {
        let algorithm = match record["name"].as_str() {
            "HSS-LMS" => HSS_LMS,
            "XMSS" => XMSS,
            "XMSS-MT" => XMSS_MT,
            name => panic!("unknown algorithm {name}"),
        };

        let context = format!("RFC 9802 {}", record["name"]);

        let public_key = algorithm
            .import_public_key(&unhex(&record["spki"]), KeyFormat::Der)
            .unwrap_or_else(|error| panic!("{context}: {error}"));

        let (tbs, signature) = (unhex(&record["tbs"]), unhex(&record["signature"]));

        assert!(public_key.verify(&signature, &tbs), "{context}");

        let mut altered = tbs.clone();

        *altered.last_mut().unwrap() ^= 1;

        assert!(
            !public_key.verify(&signature, &altered),
            "{context} altered"
        );
    }
}

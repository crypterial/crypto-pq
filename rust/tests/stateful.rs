mod vectors;

use std::cell::RefCell;
use std::rc::Rc;

use crypto_pq::{
    Error, HSS_LMS, KeyFormat, SHA_256, StateStore, StatefulParameters, XMSS, XMSS_MT, hazmat,
};
use vectors::{der, parallel, records, unhex};

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
}

impl MemoryStore {
    fn holding(state: &[u8]) -> Self {
        Self {
            state: Some(state.to_vec()),
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

        Ok(true)
    }
}

// One store seen by several keys, like a file that two processes open.
#[derive(Clone, Default)]
struct SharedStore(Rc<RefCell<MemoryStore>>);

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
                StatefulParameters::Levels(&levels),
                &seed,
                0,
                MemoryStore::default(),
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
            StatefulParameters::Levels(&names),
            &seed,
            index,
            MemoryStore::default(),
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
        .generate_key_pair(StatefulParameters::Levels(&SMALL), store.clone())
        .unwrap();

    assert_eq!(pair.private_key.remaining_signatures(), 32);

    let first = pair.private_key.sign(b"one").unwrap();

    let second = pair.private_key.sign(b"two").unwrap();

    assert!(pair.public_key.verify(&first, b"one"));

    assert!(pair.public_key.verify(&second, b"two"));

    assert!(!pair.public_key.verify(&first, b"two"));

    assert_eq!(pair.private_key.remaining_signatures(), 30);

    let mut loaded = HSS_LMS.load_private_key(store.clone()).unwrap();

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
            .generate_key_pair(StatefulParameters::Levels(&SMALL), store.clone())
            .err()
            .map(|error| error.code()),
        Some("STATE_CONFLICT")
    );

    let reloaded = HSS_LMS.load_private_key(store).unwrap();

    assert_eq!(reloaded.remaining_signatures(), 0);
}

#[test]
fn hss_store_failures() {
    let mut broken = BrokenStore::default();

    let mut pair = HSS_LMS
        .generate_key_pair(StatefulParameters::Levels(&SMALL), &mut broken)
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
            HSS_LMS.load_private_key(store).err(),
            Some(Error::InvalidPrivateKey)
        );
    }

    assert_eq!(
        XMSS.load_private_key(MemoryStore::holding(&state)).err(),
        Some(Error::AlgorithmMismatch)
    );

    broken.unreadable = true;

    assert_eq!(
        HSS_LMS.load_private_key(&mut broken).err(),
        Some(Error::StatePersistFailed)
    );

    let mut truncated = state[..state.len() - 17].to_vec();

    let checksum = SHA_256.digest(&truncated);

    truncated.extend_from_slice(&checksum[..16]);

    assert_eq!(
        HSS_LMS
            .load_private_key(MemoryStore::holding(&truncated))
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
        let result = HSS_LMS.generate_key_pair(parameters, MemoryStore::default());

        assert_eq!(result.err(), Some(Error::InvalidOption), "{parameters:?}");
    }

    let seed = [0; 40];

    let small = StatefulParameters::Levels(&SMALL);

    let mut store = MemoryStore::default();

    assert_eq!(
        hazmat::generate_stateful_key_pair(HSS_LMS, small, &seed[..39], 0, &mut store).err(),
        Some(Error::InvalidLength)
    );

    assert_eq!(
        hazmat::generate_stateful_key_pair(HSS_LMS, small, &seed, 33, &mut store).err(),
        Some(Error::InvalidOption)
    );

    assert!(store.state.is_none());

    let mut exhausted =
        hazmat::generate_stateful_key_pair(HSS_LMS, small, &seed, 32, store).unwrap();

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
        StatefulParameters::Levels(&levels),
        &[0; 40],
        31,
        MemoryStore::default(),
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
        .generate_key_pair(StatefulParameters::Levels(&SMALL), MemoryStore::default())
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

#[test]
fn xmss_reference_vectors() {
    parallel(&records("xmss/xmss.txt", "signature"), |(_, record)| {
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

        let public_key = algorithm
            .import_public_key(&public, KeyFormat::Raw)
            .unwrap();

        assert!(public_key.verify(&signature, &message), "{context}");

        let mut tampered = signature.clone();

        *tampered.last_mut().unwrap() ^= 1;

        assert!(!public_key.verify(&tampered, &message), "{context}");

        let mut pair = hazmat::generate_stateful_key_pair(
            algorithm,
            StatefulParameters::Name(name),
            &unhex(&record["seed"]),
            index,
            MemoryStore::default(),
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
fn xmss_state_handling() {
    let mut store = MemoryStore::default();

    let parameters = StatefulParameters::Name("XMSSMT-SHAKE256_20/4_192");

    let mut pair = XMSS_MT.generate_key_pair(parameters, &mut store).unwrap();

    let signature = pair.private_key.sign(b"message").unwrap();

    assert!(pair.public_key.verify(&signature, b"message"));

    assert!(!pair.public_key.verify(&signature, b"other"));

    drop(pair);

    let loaded = XMSS_MT.load_private_key(&mut store).unwrap();

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
                .generate_key_pair(parameters, MemoryStore::default())
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
        XMSS.load_private_key(&mut store).err(),
        Some(Error::AlgorithmMismatch)
    );

    assert_eq!((XMSS.name(), XMSS_MT.name()), ("XMSS", "XMSS^MT"));
}

// State blobs computed with the Python reference: every implementation must write the same bytes.
#[test]
fn cross_language_state() {
    let hss_seed: Vec<u8> = (0..40).collect();

    let mut store = MemoryStore::default();

    let mut pair = hazmat::generate_stateful_key_pair(
        HSS_LMS,
        StatefulParameters::Levels(&SMALL),
        &hss_seed,
        3,
        &mut store,
    )
    .unwrap();

    let hss_state = unhex(concat!(
        "0101010000000a00000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
        "1d1e1f2021222324252627000000000000000332b414e1d42dc2866aeed26f724a5be7",
    ));

    let hss_public = unhex(concat!(
        "000000010000000a00000005000102030405060708090a0b0c0d0e0f224f2491ed07b8b55134c2b6",
        "ea3163d0e60e423ce46b051b",
    ));

    assert_eq!(
        pair.public_key.export_key(KeyFormat::Raw).unwrap(),
        hss_public
    );

    let signature = pair.private_key.sign(b"crypto-pq").unwrap();

    assert!(pair.public_key.verify(&signature, b"crypto-pq"));

    drop(pair);

    let next_state = unhex(concat!(
        "0101010000000a00000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
        "1d1e1f202122232425262700000000000000047bc402dcf96640ca1c7126fe316fef60",
    ));

    assert_eq!(store.state.as_deref(), Some(&next_state[..]));

    assert_eq!(
        SHA_256.digest(&signature),
        unhex("07cb93b630cdd6b575402bcdbce2024b6a88bfdb419d9c7b920c250d7273a5a6")
    );

    for state in [&hss_state, &next_state] {
        let loaded = HSS_LMS
            .load_private_key(MemoryStore::holding(state))
            .unwrap();

        assert_eq!(
            loaded.public_key().export_key(KeyFormat::Raw).unwrap(),
            hss_public
        );
    }

    let xmss_seed: Vec<u8> = (0..72).collect();

    let mut store = MemoryStore::default();

    let pair = hazmat::generate_stateful_key_pair(
        XMSS_MT,
        StatefulParameters::Name("XMSSMT-SHAKE256_20/4_192"),
        &xmss_seed,
        5,
        &mut store,
    )
    .unwrap();

    let xmss_state = unhex(concat!(
        "0103000000320000000000000005000102030405060708090a0b0c0d0e0f10111213141516171819",
        "1a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041",
        "424344454647e0dc0d3f343f3dbd989a24e2ad453440",
    ));

    let xmss_public = unhex(concat!(
        "00000032296d594ddd9688b47a9c461c70e3d9f29e901b8cedcaaa4c303132333435363738393a3b",
        "3c3d3e3f4041424344454647",
    ));

    let public_key = pair.public_key.clone();

    drop(pair);

    assert_eq!(public_key.export_key(KeyFormat::Raw).unwrap(), xmss_public);

    assert_eq!(store.state.as_deref(), Some(&xmss_state[..]));

    let loaded = XMSS_MT
        .load_private_key(MemoryStore::holding(&xmss_state))
        .unwrap();

    assert_eq!(loaded.public_key(), public_key);
}

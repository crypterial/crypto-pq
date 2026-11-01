mod vectors;

use crypto_pq::{
    BLAKE3, BLAKE3_256, BLAKE3_KDF, BLAKE3_MAC, Error, HashOptions, KdfOptions, MacOptions,
    XofOptions,
};
use vectors::{pieces, records, unhex};

// Uneven sizes reach every buffering path: empty updates, partial blocks, whole blocks and chunks.
const PIECES: [usize; 9] = [0, 1, 63, 64, 65, 1024, 7, 1025, 200];

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

        assert_eq!(
            BLAKE3.digest(&data, hash.len()).unwrap(),
            hash,
            "{length} xof"
        );

        let mut hasher = BLAKE3_256.create();

        let mut xof = BLAKE3.create();

        for piece in pieces(&data, &PIECES) {
            hasher.update(piece);

            xof.update(piece).unwrap();
        }

        assert_eq!(hasher.digest(), hash[..32], "{length} streamed");

        let mut read = xof.read(1).unwrap();

        read.extend(xof.read(64).unwrap());

        read.extend(xof.read(hash.len() - 65).unwrap());

        assert_eq!(read, hash, "{length} read");

        let keyed = unhex(&record["keyed_hash"]);

        assert_eq!(
            BLAKE3_MAC.digest(&key, &data).unwrap(),
            keyed[..32],
            "{length} keyed"
        );

        assert!(BLAKE3_MAC.verify(&key, &data, &keyed[..32]));

        let mut mac = BLAKE3_MAC.create(&key).unwrap();

        for piece in pieces(&data, &PIECES) {
            mac.update(piece);
        }

        assert_eq!(mac.digest(), keyed[..32], "{length} keyed streamed");

        assert!(mac.verify(&keyed[..32]));

        let mut changed = keyed[..32].to_vec();

        changed[31] ^= 1;

        assert!(!BLAKE3_MAC.verify(&key, &data, &changed));

        assert!(!mac.verify(&changed));

        let derived = unhex(&record["derive_key"]);

        let options = KdfOptions::default().with_info(&context);

        assert_eq!(
            BLAKE3_KDF
                .derive(&data, derived.len(), &options)
                .ok()
                .map(|s| s.to_vec()),
            Some(derived.clone().to_vec()),
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

    let whole = BLAKE3.digest(&data, 700).unwrap();

    for sizes in [
        &[0, 1, 63, 64, 65, 507][..],
        &[64, 64, 572],
        &[700],
        &[3, 61, 128, 1, 507],
    ] {
        let mut xof = BLAKE3.create();

        xof.update(&data).unwrap();

        let mut read = Vec::new();

        for &size in sizes {
            read.extend(xof.read(size).unwrap());
        }

        assert_eq!(read, whole);
    }

    assert!(BLAKE3.digest(&data, 0).unwrap().is_empty());
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

    let salt = HashOptions::default().with_salt(b"s");

    assert_eq!(BLAKE3_256.configure(&salt), Err(Error::InvalidOption));

    let customization = XofOptions::default().with_customization(b"c");

    assert_eq!(BLAKE3.configure(&customization), Err(Error::InvalidOption));

    assert_eq!(BLAKE3_MAC.configure(&MacOptions::default()), Ok(BLAKE3_MAC));

    for options in [
        MacOptions::default().with_length(32),
        MacOptions::default().with_customization(b"c"),
        MacOptions::default().with_salt(b"s"),
        MacOptions::default().with_xof(true),
    ] {
        assert_eq!(BLAKE3_MAC.configure(&options), Err(Error::InvalidOption));
    }
}

#[test]
fn mac_keys() {
    let tag = BLAKE3_MAC.digest(&[7; 32], b"data").unwrap();

    for size in [0, 1, 31, 33, 64] {
        assert!(!BLAKE3_MAC.verify(&vec![7; size], b"data", &tag));
    }

    assert!(!BLAKE3_MAC.verify(&[7; 32], b"data", &tag[..31]));
}

#[test]
fn mac_key_lengths() {
    for key in [&[0; 31][..], &[0; 33], &[]] {
        assert_eq!(BLAKE3_MAC.digest(key, b"data"), Err(Error::InvalidLength));

        assert_eq!(
            BLAKE3_MAC.digest_into(key, b"data", &mut [0; 32]),
            Err(Error::InvalidLength)
        );

        assert!(BLAKE3_MAC.create(key).is_err());

        assert!(!BLAKE3_MAC.verify(key, b"data", &[0; 32]));
    }
}

#[test]
fn kdf() {
    let context = KdfOptions::default().with_info(b"context");

    let okm = BLAKE3_KDF.derive(b"key material", 1000, &context).unwrap();

    assert_eq!(
        *BLAKE3_KDF.derive(b"key material", 33, &context).unwrap(),
        okm[..33]
    );

    assert_ne!(
        *BLAKE3_KDF
            .derive(b"key material", 32, &KdfOptions::default())
            .unwrap(),
        okm[..32]
    );

    assert_eq!(
        BLAKE3_KDF.derive(b"ikm", 0, &context).err(),
        Some(Error::InvalidLength)
    );

    let salted = KdfOptions::default().with_salt(b"s").with_info(b"context");

    assert_eq!(
        BLAKE3_KDF.derive(b"ikm", 32, &salted).err(),
        Some(Error::InvalidOption)
    );

    assert_eq!(
        BLAKE3_KDF.extract(b"ikm", &KdfOptions::default()).err(),
        Some(Error::Unsupported)
    );

    assert_eq!(
        BLAKE3_KDF.expand(&[0; 32], 32, &context).err(),
        Some(Error::Unsupported)
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
fn update_after_read() {
    let mut xof = BLAKE3.create();

    xof.read(1).unwrap();

    assert_eq!(xof.update(b"more"), Err(Error::Unsupported));
}

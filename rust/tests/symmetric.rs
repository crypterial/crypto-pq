mod vectors;

use crypto_pq::{
    ASCON_CXOF128, ASCON_HASH256, ASCON_XOF128, BLAKE2B_160, BLAKE2B_256, BLAKE2B_384, BLAKE2B_512,
    BLAKE2B_MAC, BLAKE2S_128, BLAKE2S_160, BLAKE2S_224, BLAKE2S_256, BLAKE2S_MAC, BLAKE3,
    BLAKE3_256, BLAKE3_KDF, BLAKE3_MAC, CSHAKE128, CSHAKE256, Error, HKDF_SHA_256, HKDF_SHA_384,
    HKDF_SHA_512, HMAC_SHA_224, HMAC_SHA_256, HMAC_SHA_384, HMAC_SHA_512, HashAlgorithm,
    HashOptions, KMAC128, KMAC256, KdfAlgorithm, KdfOptions, MacAlgorithm, MacOptions, SHA_224,
    SHA_256, SHA_384, SHA_512, SHA_512_224, SHA_512_256, SHA3_224, SHA3_256, SHA3_384, SHA3_512,
    SHAKE128, SHAKE256, XofAlgorithm, XofOptions, hazmat,
};
use vectors::{Fields, records, unhex};

// The runner of vectors/cross/symmetric.txt and vectors/cross/blake3.txt (SPEC 19.3; the format is
// described in tools/cross_vectors.py): each record configures its algorithm with the options it
// has, runs one operation and compares the result and the output.
#[derive(Clone, Copy)]
enum Algorithm {
    Hash(HashAlgorithm),
    Xof(XofAlgorithm),
    Mac(MacAlgorithm),
    Kdf(KdfAlgorithm),
}

const HASHES: [HashAlgorithm; 20] = [
    SHA_224,
    SHA_256,
    SHA_384,
    SHA_512,
    SHA_512_224,
    SHA_512_256,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    BLAKE2B_160,
    BLAKE2B_256,
    BLAKE2B_384,
    BLAKE2B_512,
    BLAKE2S_128,
    BLAKE2S_160,
    BLAKE2S_224,
    BLAKE2S_256,
    ASCON_HASH256,
    BLAKE3_256,
];

const XOFS: [XofAlgorithm; 7] = [
    SHAKE128,
    SHAKE256,
    CSHAKE128,
    CSHAKE256,
    ASCON_XOF128,
    ASCON_CXOF128,
    BLAKE3,
];

const MACS: [MacAlgorithm; 9] = [
    HMAC_SHA_224,
    HMAC_SHA_256,
    HMAC_SHA_384,
    HMAC_SHA_512,
    KMAC128,
    KMAC256,
    BLAKE2B_MAC,
    BLAKE2S_MAC,
    BLAKE3_MAC,
];

const KDFS: [KdfAlgorithm; 4] = [HKDF_SHA_256, HKDF_SHA_384, HKDF_SHA_512, BLAKE3_KDF];

// Every key the dictionary of SPEC 19.3 gives these files; zeroAbsentResult is for Go alone.
const KEYS: [&str; 18] = [
    "name",
    "operation",
    "result",
    "zeroAbsentResult",
    "output",
    "message",
    "key",
    "tag",
    "salt",
    "personalization",
    "customization",
    "functionName",
    "length",
    "xof",
    "outputLength",
    "ikm",
    "prk",
    "info",
];

fn algorithm(name: &str) -> Algorithm {
    let hash = HASHES
        .iter()
        .find(|a| a.name() == name)
        .map(|&a| Algorithm::Hash(a));

    let xof = || {
        XOFS.iter()
            .find(|a| a.name() == name)
            .map(|&a| Algorithm::Xof(a))
    };

    let mac = || {
        MACS.iter()
            .find(|a| a.name() == name)
            .map(|&a| Algorithm::Mac(a))
    };

    let kdf = || {
        KDFS.iter()
            .find(|a| a.name() == name)
            .map(|&a| Algorithm::Kdf(a))
    };

    hash.or_else(xof)
        .or_else(mac)
        .or_else(kdf)
        .unwrap_or_else(|| panic!("unknown algorithm {name}"))
}

fn bytes(record: &Fields, key: &str) -> Vec<u8> {
    record
        .get(key)
        .map(|value| unhex(value))
        .unwrap_or_default()
}

fn number(record: &Fields, key: &str) -> usize {
    record[key].parse().unwrap_or_else(|_| panic!("{key}"))
}

// An option of the record that the algorithm's options cannot hold must be empty (SPEC 6.3 item 4:
// an option the algorithm does not take is accepted at its default only).
fn only(record: &Fields, taken: &[&str]) -> Result<(), Error> {
    let foreign = ["salt", "personalization", "customization"]
        .iter()
        .filter(|key| !taken.contains(key))
        .any(|key| record.get(*key).is_some_and(|value| !value.is_empty()));

    let numeric = ["length", "xof"]
        .iter()
        .filter(|key| !taken.contains(key))
        .any(|key| record.contains_key(*key));

    if foreign || numeric {
        Err(Error::InvalidOption)
    } else {
        Ok(())
    }
}

fn mac_options<'a>(
    record: &Fields,
    salt: &'a [u8],
    personalization: &'a [u8],
    customization: &'a [u8],
) -> MacOptions<'a> {
    let mut options = MacOptions::default()
        .with_salt(salt)
        .with_personalization(personalization)
        .with_customization(customization)
        .with_xof(record.get("xof").is_some_and(|value| value == "true"));

    if record.contains_key("length") {
        options = options.with_length(number(record, "length"));
    }

    options
}

// The result of a record: "ok" with the output, "true" or "false", or an error code.
fn run(algorithm: Algorithm, record: &Fields) -> Result<(String, Option<Vec<u8>>), Error> {
    let operation = record["operation"].as_str();

    let (salt, personalization, customization) = (
        bytes(record, "salt"),
        bytes(record, "personalization"),
        bytes(record, "customization"),
    );

    let (message, key) = (bytes(record, "message"), bytes(record, "key"));

    let output = match (algorithm, operation) {
        (Algorithm::Hash(hash), "digest") => {
            only(record, &["salt", "personalization"])?;

            let options = HashOptions::default()
                .with_salt(&salt)
                .with_personalization(&personalization);

            hash.configure(&options)?.digest(&message)
        }
        (Algorithm::Xof(xof), "digest") => {
            only(record, &["customization"])?;

            let configured = if record.contains_key("functionName") {
                hazmat::configure_cshake(xof, &bytes(record, "functionName"), &customization)?
            } else {
                xof.configure(&XofOptions::default().with_customization(&customization))?
            };

            configured.digest(&message, number(record, "outputLength"))?
        }
        (Algorithm::Mac(mac), "digest" | "verify") => {
            let options = mac_options(record, &salt, &personalization, &customization);

            let configured = mac.configure(&options)?;

            if operation == "verify" {
                let valid = configured.verify(&key, &message, &bytes(record, "tag"));

                return Ok((valid.to_string(), None));
            }

            configured.digest(&key, &message)?
        }
        (Algorithm::Kdf(kdf), "derive" | "extract" | "expand") => {
            only(record, &["salt"])?;

            let info = bytes(record, "info");

            let options = KdfOptions::default().with_salt(&salt).with_info(&info);

            let secret = match operation {
                "derive" => kdf.derive(
                    &bytes(record, "ikm"),
                    number(record, "outputLength"),
                    &options,
                )?,
                "extract" => kdf.extract(&bytes(record, "ikm"), &options)?,
                _ => kdf.expand(
                    &bytes(record, "prk"),
                    number(record, "outputLength"),
                    &options,
                )?,
            };

            secret.to_vec()
        }
        _ => panic!("operation {operation} on {}", record["name"]),
    };

    Ok(("ok".to_owned(), Some(output)))
}

// Records whose expected result predates a rule of SPEC 1.0 that the reference generator does not
// apply yet, by file, function and case; each is listed with the rule and checked against it. An
// entry that no record of its file needs any more, because the record is gone or already has the
// new result, fails the check, so that it is removed when the file is regenerated.
const SYMMETRIC: &str = "cross/symmetric.txt";

const PENDING: [(&str, &str, &str, &str); 8] = [
    // SPEC 12.2 item 5 [D-34]: the one-shot Ascon XOFs refuse L = 0.
    (
        SYMMETRIC,
        "Ascon-CXOF128",
        "0-byte customization, 0-byte output",
        "INVALID_LENGTH",
    ),
    (
        SYMMETRIC,
        "Ascon-CXOF128",
        "1-byte customization, 0-byte output",
        "INVALID_LENGTH",
    ),
    (
        SYMMETRIC,
        "Ascon-CXOF128",
        "7-byte customization, 0-byte output",
        "INVALID_LENGTH",
    ),
    (
        SYMMETRIC,
        "Ascon-CXOF128",
        "8-byte customization, 0-byte output",
        "INVALID_LENGTH",
    ),
    (
        SYMMETRIC,
        "Ascon-CXOF128",
        "9-byte customization, 0-byte output",
        "INVALID_LENGTH",
    ),
    (
        SYMMETRIC,
        "Ascon-CXOF128",
        "255-byte customization, 0-byte output",
        "INVALID_LENGTH",
    ),
    (
        SYMMETRIC,
        "Ascon-CXOF128",
        "256-byte customization, 0-byte output",
        "INVALID_LENGTH",
    ),
    // SPEC 12.6 item 1 [D-33]: HMAC takes a length of 4 to the hash output size.
    (SYMMETRIC, "HMAC-SHA-256", "length", "ok"),
];

fn check(file: &str, expected_records: usize) {
    let found = records(file, "result");

    assert_eq!(found.len(), expected_records, "{file}");

    let mut used = [false; PENDING.len()];

    for (header, record) in &found {
        for key in record.keys() {
            assert!(KEYS.contains(&key.as_str()), "{file}: unknown key {key}");
        }

        let name = &header["algorithm"];

        let context = format!("{file}: {name}: {}", record["name"]);

        let (result, output) =
            run(algorithm(name), record).unwrap_or_else(|error| (error.code().to_owned(), None));

        let expected = match PENDING
            .iter()
            .position(|(pending_file, algorithm, case, _)| {
                *pending_file == file && algorithm == name && *case == record["name"]
            }) {
            Some(index) if PENDING[index].3 != record["result"] => {
                used[index] = true;

                PENDING[index].3.to_owned()
            }
            _ => record["result"].clone(),
        };

        assert_eq!(result, expected, "{context}");

        if let (Some(expected), true) = (record.get("output"), result == record["result"]) {
            assert_eq!(output, Some(unhex(expected)), "{context}");
        }
    }

    let stale: Vec<_> = PENDING
        .iter()
        .zip(used)
        .filter(|((pending_file, ..), used)| *pending_file == file && !used)
        .map(|(entry, _)| entry)
        .collect();

    assert!(
        stale.is_empty(),
        "{file}: pending entries no record needs: {stale:?}"
    );

    println!(
        "{file}: {} records, {} with a pending regeneration",
        found.len(),
        used.iter().filter(|&&used| used).count()
    );
}

#[test]
fn cross_symmetric() {
    check(SYMMETRIC, 505);
}

#[test]
fn cross_blake3() {
    check("cross/blake3.txt", 110);
}

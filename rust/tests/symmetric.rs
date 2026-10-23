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
use vectors::{Fields, fixture, get, groups, header, hex, records, remove, set, unhex};

// The runner of vectors/cross/symmetric.txt and vectors/cross/blake3.txt (SPEC 19.3 gives the
// format and the operations): each record configures its algorithm with the options it has, runs
// one operation and compares the result and the output.
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

// Every key the dictionary of SPEC 19.3 gives these files.
const KEYS: [&str; 17] = [
    "name",
    "operation",
    "result",
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

const SYMMETRIC: &str = "cross/symmetric.txt";

fn check(file: &str, expected_records: usize) {
    let found = records(file, "result");

    assert_eq!(found.len(), expected_records, "{file}");

    for (header, record) in &found {
        for key in record.keys() {
            assert!(KEYS.contains(&key.as_str()), "{file}: unknown key {key}");
        }

        let name = &header["algorithm"];

        let context = format!("{file}: {name}: {}", record["name"]);

        let (result, output) =
            run(algorithm(name), record).unwrap_or_else(|error| (error.code().to_owned(), None));

        assert_eq!(result, record["result"], "{context}");

        assert_eq!(
            output,
            record.get("output").map(|value| unhex(value)),
            "{context}"
        );
    }
}

// The records of symmetric.txt whose result SPEC 1.0 decided after the earlier generator wrote
// them, by algorithm and case, with that result. The generator runs each, checks the result and
// writes it with its output; every other record is kept as it is.
const DECIDED: [(&str, &str, &str); 8] = [
    // SPEC 12.2 item 5 [D-34]: the one-shot Ascon XOFs refuse L = 0.
    (
        "Ascon-CXOF128",
        "0-byte customization, 0-byte output",
        "INVALID_LENGTH",
    ),
    (
        "Ascon-CXOF128",
        "1-byte customization, 0-byte output",
        "INVALID_LENGTH",
    ),
    (
        "Ascon-CXOF128",
        "7-byte customization, 0-byte output",
        "INVALID_LENGTH",
    ),
    (
        "Ascon-CXOF128",
        "8-byte customization, 0-byte output",
        "INVALID_LENGTH",
    ),
    (
        "Ascon-CXOF128",
        "9-byte customization, 0-byte output",
        "INVALID_LENGTH",
    ),
    (
        "Ascon-CXOF128",
        "255-byte customization, 0-byte output",
        "INVALID_LENGTH",
    ),
    (
        "Ascon-CXOF128",
        "256-byte customization, 0-byte output",
        "INVALID_LENGTH",
    ),
    // SPEC 12.6 item 1 [D-33]: HMAC takes a length of 4 to the hash output size.
    ("HMAC-SHA-256", "length", "ok"),
];

// The generator of the decided records (see vectors::fixture).
#[test]
#[ignore = "generator of vectors/cross/symmetric.txt"]
fn regenerate_symmetric() {
    let mut found = groups(SYMMETRIC);

    let mut written = 0;

    for group in &mut found {
        let name = header(group, "algorithm").to_owned();

        for record in &mut group.records {
            let case = get(record, "name").unwrap();

            let Some(&(_, _, decided)) = DECIDED
                .iter()
                .find(|(algorithm, decided, _)| *algorithm == name && *decided == case)
            else {
                continue;
            };

            let fields: Fields = record.iter().cloned().collect();

            let (result, output) = run(algorithm(&name), &fields)
                .unwrap_or_else(|error| (error.code().to_owned(), None));

            assert_eq!(result, decided, "{name}: {case}");

            set(record, "result", result);

            match output {
                Some(output) => set(record, "output", hex(&output)),
                None => remove(record, "output"),
            }

            written += 1;
        }
    }

    assert_eq!(written, DECIDED.len());

    fixture(SYMMETRIC, &found);
}

#[test]
fn cross_symmetric() {
    check(SYMMETRIC, 505);
}

#[test]
fn cross_blake3() {
    check("cross/blake3.txt", 110);
}

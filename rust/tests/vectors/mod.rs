// Each test crate uses the part of these helpers that its vectors need.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use crypto_pq::{Error, KeyFormat};

pub type Fields = HashMap<String, String>;

// Checks the items on every core; a failed assertion in any worker fails the test.
pub fn parallel<T: Sync>(items: &[T], check: impl Fn(&T) + Sync) {
    let next = AtomicUsize::new(0);

    let workers = std::thread::available_parallelism().map_or(1, usize::from);

    std::thread::scope(|scope| {
        for _ in 0..workers.min(items.len()) {
            scope.spawn(|| {
                while let Some(item) = items.get(next.fetch_add(1, Ordering::Relaxed)) {
                    check(item);
                }
            });
        }
    });
}

// The shared format: [key = value] header lines persist until replaced, records are key = value
// lines separated by blank lines, and # starts a comment.
pub fn records(name: &str, field: &str) -> Vec<(Fields, Fields)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../vectors")
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

// The field `key` of the first record of a parameter set in a vector file.
pub fn first(name: &str, parameter_set: &str, key: &str) -> Vec<u8> {
    let found = records(name, key);

    let (_, record) = found
        .iter()
        .find(|(header, _)| header["parameterSet"] == parameter_set)
        .unwrap_or_else(|| panic!("{name}: no {parameter_set}"));

    unhex(&record[key])
}

pub fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "odd hex length");

    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

// A minimal DER writer, so that tests can build encodings the library itself never produces.
pub fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let length = content.len();

    let mut out = vec![tag];

    if length < 0x80 {
        out.push(length as u8);
    } else {
        let bytes = length.to_be_bytes();

        let skip = bytes.iter().take_while(|&&byte| byte == 0).count();

        out.push(0x80 | (bytes.len() - skip) as u8);

        out.extend_from_slice(&bytes[skip..]);
    }

    out.extend_from_slice(content);

    out
}

// A PEM document from a label and the base64 lines of a vector file, which joins them with '|'.
pub fn pem(label: &str, lines: &str) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.replace('|', "\n")
    )
}

// Cuts data into pieces of the given sizes, repeated, for streaming tests.
pub fn pieces<'a>(data: &'a [u8], sizes: &[usize]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();

    let mut offset = 0;

    for size in sizes.iter().cycle() {
        if offset >= data.len() {
            break;
        }

        let end = (offset + size).min(data.len());

        out.push(&data[offset..end]);

        offset = end;
    }

    out
}

// The example keys of an RFC appendix (RFC 9935, RFC 9881), each in DER and PEM. `import` imports
// one as the algorithm and kind of its record and gives the raw public key and the DER export;
// the keys marked reject must fail with INVALID_PRIVATE_KEY.
pub fn example_keys(
    name: &str,
    import: impl Fn(&Fields, &[u8], KeyFormat) -> Result<(Vec<u8>, Vec<u8>), Error>,
) {
    for (_, record) in records(name, "der") {
        let context = format!("{name}: {}", record["name"]);

        let pem_key = pem(&record["label"], &record["pem"]);

        for (data, format) in [
            (unhex(&record["der"]), KeyFormat::Der),
            (pem_key.into_bytes(), KeyFormat::Pem),
        ] {
            let result = import(&record, &data, format);

            if record["expect"] == "reject" {
                assert_eq!(result.err(), Some(Error::InvalidPrivateKey), "{context}");

                continue;
            }

            let (public, exported) = result.unwrap_or_else(|error| panic!("{context}: {error}"));

            assert_eq!(public, unhex(&record["public"]), "{context}");

            assert_eq!(exported, unhex(&record["exportDer"]), "{context}");
        }
    }
}

// Each test crate uses the part of these helpers that its vectors need.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

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

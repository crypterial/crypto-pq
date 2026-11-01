// base (main) against new and an A/A copy of new, in one process. The inputs and the output buffer
// of a hash, MAC or KDF row are allocated once and shared by the three sides. Each round times the
// three sides of every row back to back with the same count, in one of the six orders, which turns
// from round to round and from row to row. Before timing, every row's outputs (public keys and
// first signatures for the signature rows) must match across the sides.
// Line: AB round row count base new aa base/new aa/new (times in us per operation; above 1: new
// takes less time). Usage: ab4-bench [--rounds=N] [--ms=M] [filters...]; a filter is a row name or
// a prefix ending in '*'; rows are timed in the order of the filters, all rows without filters.

use std::hint::black_box;
use std::time::{Duration, Instant};

type Op = Box<dyn FnMut(u64, &mut [u8]) -> Duration>;

#[derive(Clone, Copy)]
enum Kind {
    Hash(&'static str),
    Stream(&'static str),
    Mac(&'static str),
    // A MAC object: create, update, digest_into.
    MacObject(&'static str),
    // Two messages under one key: create, digest_into, create, update, digest_into (new and aa:
    // key, then two MACs from the key).
    MacTwice(&'static str),
    Kdf(&'static str),
    Lms(&'static [(&'static str, &'static str)], &'static str),
    Xmss(&'static str, &'static str),
    Slh(&'static str, &'static str),
}

// A row's inputs, shared by the three sides.
struct Row {
    name: String,
    kind: Kind,
    data: &'static [u8],
    key: &'static [u8],
    salt: &'static [u8],
    info: &'static [u8],
    out: usize,
}

fn timed(count: u64, out: &mut [u8], mut operation: impl FnMut(&mut [u8])) -> Duration {
    let start = Instant::now();

    for _ in 0..count {
        operation(&mut *out);

        black_box(&mut *out);
    }

    start.elapsed()
}

fn leak(bytes: &[u8]) -> &'static [u8] {
    Box::leak(bytes.to_vec().into_boxed_slice())
}

fn material(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(13).wrapping_add(7)).collect()
}

fn messages() -> Vec<Vec<u8>> {
    (0..16u8).map(|j| (0..64u8).map(|i| i.wrapping_mul(3).wrapping_add(j)).collect()).collect()
}

fn seed(n: usize, a: u8, b: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(a).wrapping_add(b)).collect()
}

fn s(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

const HASHES: [(&str, usize); 6] = [
    ("sha224", 28),
    ("sha256", 32),
    ("sha384", 48),
    ("sha512", 64),
    ("sha512_224", 28),
    ("sha512_256", 32),
];

fn rows() -> Vec<Row> {
    let m = material(16384);

    let key: &'static [u8] = leak(&seed(32, 7, 3));

    let none: &'static [u8] = &[];

    let mut rows = Vec::new();

    let push = |rows: &mut Vec<Row>, name: String, kind: Kind, data: &'static [u8], out: usize| {
        rows.push(Row { name, kind, data, key: none, salt: none, info: none, out });
    };

    push(&mut rows, "AA-sha3_256/64B".into(), Kind::Hash("sha3_256"), leak(&m[..64]), 32);

    for (hash, size) in HASHES {
        for (length, suffix) in [(0, "0B"), (64, "64B"), (1024, "1KiB"), (16384, "16KiB")] {
            push(&mut rows, format!("{hash}/{suffix}"), Kind::Hash(hash), leak(&m[..length]), size);
        }

        for (length, suffix) in [(1024, "1KiB"), (16384, "16KiB")] {
            push(&mut rows, format!("{hash}/stream64/{suffix}"), Kind::Stream(hash), leak(&m[..length]), size);
        }
    }

    for (bits, size) in [(224, 28), (256, 32), (384, 48), (512, 64)] {
        for (length, suffix) in [(64, "64B"), (1024, "1KiB"), (16384, "16KiB")] {
            rows.push(Row {
                name: format!("hmac-sha{bits}/{suffix}"),
                kind: Kind::Mac(s(format!("{bits}"))),
                data: leak(&m[..length]),
                key,
                salt: none,
                info: none,
                out: size,
            });
        }
    }

    for bits in [256, 384, 512] {
        let hash = bits / 8;

        for (suffix, ikm, salt, info, okm) in [
            ("rfc1", 22, 13, 10, 42),
            ("rfc3", 22, 0, 0, 42),
            ("tls-okm32", 32, hash, 22 + hash, 32),
        ] {
            rows.push(Row {
                name: format!("hkdf-sha{bits}/{suffix}"),
                kind: Kind::Kdf(s(format!("{bits}"))),
                data: leak(&m[..ikm]),
                key: none,
                salt: leak(&m[100..100 + salt]),
                info: leak(&m[100 + salt..100 + salt + info]),
                out: okm,
            });
        }
    }

    let stateful = |rows: &mut Vec<Row>, label: String, kind: &dyn Fn(&'static str) -> Kind, operations: &[&'static str]| {
        for operation in operations {
            rows.push(Row {
                name: format!("{label}/{operation}"),
                kind: kind(operation),
                data: none,
                key: none,
                salt: none,
                info: none,
                out: 0,
            });
        }
    };

    for (m, h, w, operations) in [
        (32, 5, 8, &["keygen", "verify", "sign"][..]),
        (32, 10, 1, &["verify"][..]),
        (32, 10, 4, &["keygen", "sign"][..]),
        (24, 10, 8, &["verify", "sign"][..]),
    ] {
        let levels: &'static [(&'static str, &'static str)] =
            Box::leak(Box::new([(s(format!("LMS_SHA256_M{m}_H{h}")), s(format!("LMOTS_SHA256_N{m}_W{w}")))]));

        stateful(&mut rows, format!("LMS-SHA256-M{m}-H{h}-W{w}"), &|op| Kind::Lms(levels, op), operations);
    }

    let hss: &'static [(&'static str, &'static str)] =
        &[("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8"), ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8")];

    stateful(&mut rows, "HSS2-SHA256-M32-H5W8-H5W8".into(), &|op| Kind::Lms(hss, op), &["verify", "sign"]);

    for (name, operations) in [
        ("XMSS-SHA2_10_256", &["keygen", "verify", "sign"][..]),
        ("XMSSMT-SHA2_20/2_256", &["verify", "sign"][..]),
        ("XMSSMT-SHA2_20/4_256", &["verify", "sign"][..]),
    ] {
        stateful(&mut rows, name.into(), &|op| Kind::Xmss(name, op), operations);
    }

    for (name, operations) in [
        ("SLH-DSA-SHA2-128f", &["keygen", "sign", "verify"][..]),
        ("SLH-DSA-SHA2-192f", &["sign", "verify"][..]),
        ("SLH-DSA-SHA2-256f", &["sign", "verify"][..]),
        ("SLH-DSA-SHA2-128s", &["keygen", "verify"][..]),
        ("SLH-DSA-SHA2-192s", &["verify"][..]),
        ("SLH-DSA-SHA2-256s", &["verify"][..]),
    ] {
        stateful(&mut rows, name.into(), &|op| Kind::Slh(name, op), operations);
    }

    for (name, size) in [
        ("kmac128", 32),
        ("kmac256", 64),
        ("blake2b-mac", 64),
        ("blake2s-mac", 32),
        ("hmac-sha256", 32),
        ("hmac-sha512", 64),
    ] {
        for (length, suffix) in [(0, "0B"), (64, "64B"), (1024, "1KiB")] {
            rows.push(Row {
                name: format!("obj-{name}/{suffix}"),
                kind: Kind::MacObject(name),
                data: leak(&m[..length]),
                key,
                salt: none,
                info: none,
                out: size,
            });
        }

        rows.push(Row {
            name: format!("obj-{name}/twice-64B"),
            kind: Kind::MacTwice(name),
            data: leak(&m[..64]),
            key,
            salt: none,
            info: none,
            out: size,
        });
    }

    push(&mut rows, "AA-sha3_256/16KiB".into(), Kind::Hash("sha3_256"), leak(&m[..16384]), 32);

    rows
}

// The operation of a row in one crate, and its check bytes; the same code for the three.
macro_rules! side {
    ($module:ident, $krate:ident, $twice:expr) => {
        mod $module {
            use super::*;

            use ::$krate as cpq;

            use cpq::{
                Error, KdfOptions, KeyFormat, SignOptions, StateStore, StatefulKeyGenOptions,
                StatefulParameters, StatefulPrivateKey, StatefulSignatureAlgorithm, VerifyOptions,
                hazmat,
            };

            #[derive(Default)]
            struct MemoryStore(Option<Vec<u8>>);

            impl StateStore for MemoryStore {
                fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
                    Ok(self.0.clone())
                }

                fn update(&mut self, _: Option<&[u8]>, next: &[u8]) -> Result<bool, Error> {
                    self.0 = Some(next.to_vec());

                    Ok(true)
                }
            }

            fn mac(name: &str) -> cpq::MacAlgorithm {
                match name {
                    "kmac128" => cpq::KMAC128,
                    "kmac256" => cpq::KMAC256,
                    "blake2b-mac" => cpq::BLAKE2B_MAC,
                    "blake2s-mac" => cpq::BLAKE2S_MAC,
                    "hmac-sha256" => cpq::HMAC_SHA_256,
                    _ => cpq::HMAC_SHA_512,
                }
            }

            fn hash(name: &str) -> cpq::HashAlgorithm {
                match name {
                    "sha224" => cpq::SHA_224,
                    "sha256" => cpq::SHA_256,
                    "sha384" => cpq::SHA_384,
                    "sha512" => cpq::SHA_512,
                    "sha512_224" => cpq::SHA_512_224,
                    "sha512_256" => cpq::SHA_512_256,
                    "sha3_256" => cpq::SHA3_256,
                    _ => unreachable!(),
                }
            }

            fn keygen(
                algorithm: StatefulSignatureAlgorithm,
                parameters: StatefulParameters<'static>,
                seed: &[u8],
            ) -> (StatefulPrivateKey<MemoryStore>, Vec<u8>) {
                let pair = hazmat::generate_stateful_key_pair(
                    algorithm,
                    seed,
                    0,
                    parameters,
                    MemoryStore::default(),
                    &StatefulKeyGenOptions::default(),
                )
                .unwrap();

                let public = pair.public_key.export_key(KeyFormat::Raw).unwrap();

                (pair.private_key, public)
            }

            fn stateful(
                algorithm: StatefulSignatureAlgorithm,
                parameters: StatefulParameters<'static>,
                seed: Vec<u8>,
                operation: &str,
            ) -> (Op, Vec<u8>) {
                let messages = messages();

                let (mut key, public) = keygen(algorithm, parameters, &seed);

                let signature = key.sign(&messages[0]).unwrap();

                let mut check = public.clone();

                check.extend_from_slice(&signature);

                let op: Op = match operation {
                    "keygen" => Box::new(move |n, out| timed(n, out, |_| {
                        black_box(keygen(algorithm, parameters, black_box(&seed)));
                    })),
                    "verify" => {
                        let key = algorithm.import_public_key(&public, KeyFormat::Raw).unwrap();

                        Box::new(move |n, out| timed(n, out, |_| {
                            assert!(key.verify(black_box(&signature), black_box(&messages[0])));
                        }))
                    }
                    "sign" => {
                        let mut key: Option<StatefulPrivateKey<MemoryStore>> = None;

                        let mut next = 0;

                        // An exhausted key is replaced outside the measured time.
                        Box::new(move |n, _| {
                            let mut elapsed = Duration::ZERO;

                            for _ in 0..n {
                                if key.as_ref().is_none_or(|k| k.remaining_signatures() == 0) {
                                    key = Some(keygen(algorithm, parameters, &seed).0);
                                }

                                let k = key.as_mut().unwrap();

                                let message = &messages[next % messages.len()];

                                next += 1;

                                let start = Instant::now();

                                black_box(k.sign(black_box(message)).unwrap());

                                elapsed += start.elapsed();
                            }

                            elapsed
                        })
                    }
                    _ => unreachable!(),
                };

                (op, check)
            }

            fn slh(name: &str, operation: &str) -> (Op, Vec<u8>) {
                let (algorithm, n) = match name {
                    "SLH-DSA-SHA2-128f" => (cpq::SLH_DSA_SHA2_128F, 16),
                    "SLH-DSA-SHA2-128s" => (cpq::SLH_DSA_SHA2_128S, 16),
                    "SLH-DSA-SHA2-192f" => (cpq::SLH_DSA_SHA2_192F, 24),
                    "SLH-DSA-SHA2-192s" => (cpq::SLH_DSA_SHA2_192S, 24),
                    "SLH-DSA-SHA2-256f" => (cpq::SLH_DSA_SHA2_256F, 32),
                    "SLH-DSA-SHA2-256s" => (cpq::SLH_DSA_SHA2_256S, 32),
                    _ => unreachable!(),
                };

                let seed = seed(3 * n, 41, 9);

                let pair = hazmat::generate_signature_key_pair(algorithm, &seed).unwrap();

                let public = pair.public_key.export_key(KeyFormat::Raw).unwrap();

                let mut options = SignOptions::default();

                options.deterministic = true;

                let message = messages()[0].clone();

                let signature = pair.private_key.sign(&message, &options).unwrap();

                let mut check = public.clone();

                check.extend_from_slice(&signature);

                let op: Op = match operation {
                    "keygen" => Box::new(move |n, out| timed(n, out, |_| {
                        black_box(hazmat::generate_signature_key_pair(algorithm, black_box(&seed)).unwrap());
                    })),
                    "sign" => {
                        let private = pair.private_key;

                        Box::new(move |n, out| timed(n, out, |_| {
                            black_box(private.sign(black_box(&message), &options).unwrap());
                        }))
                    }
                    "verify" => {
                        let key = pair.public_key;

                        Box::new(move |n, out| timed(n, out, |_| {
                            assert!(key.verify(black_box(&signature), black_box(&message), &VerifyOptions::default()));
                        }))
                    }
                    _ => unreachable!(),
                };

                (op, check)
            }

            pub fn op(row: &Row) -> (Op, Vec<u8>) {
                let Row { kind, data, key, salt, info, out, .. } = *row;

                let (mut op, check): (Op, Vec<u8>) = match kind {
                    Kind::Hash(name) => {
                        let algorithm = hash(name);

                        (Box::new(move |n, out| timed(n, out, |out| {
                            algorithm.digest_into(black_box(data), out).unwrap();
                        })), Vec::new())
                    }
                    Kind::Stream(name) => {
                        let algorithm = hash(name);

                        (Box::new(move |n, out| timed(n, out, |out| {
                            let mut h = algorithm.create();

                            for chunk in black_box(data).chunks(64) {
                                h.update(chunk);
                            }

                            h.digest_into(out).unwrap();
                        })), Vec::new())
                    }
                    Kind::MacObject(name) => {
                        let algorithm = mac(name);

                        (Box::new(move |n, out| timed(n, out, |out| {
                            let mut mac = algorithm.create(black_box(key)).unwrap();

                            mac.update(black_box(data));

                            mac.digest_into(out).unwrap();
                        })), Vec::new())
                    }
                    Kind::MacTwice(name) => {
                        let algorithm = mac(name);

                        let twice: fn(cpq::MacAlgorithm, &[u8], &[u8], &mut [u8]) = $twice;

                        (Box::new(move |n, out| timed(n, out, |out| {
                            twice(algorithm, black_box(key), black_box(data), out);
                        })), Vec::new())
                    }
                    Kind::Mac(bits) => {
                        let algorithm = match bits {
                            "224" => cpq::HMAC_SHA_224,
                            "256" => cpq::HMAC_SHA_256,
                            "384" => cpq::HMAC_SHA_384,
                            _ => cpq::HMAC_SHA_512,
                        };

                        (Box::new(move |n, out| timed(n, out, |out| {
                            algorithm.digest_into(black_box(key), black_box(data), out).unwrap();
                        })), Vec::new())
                    }
                    Kind::Kdf(bits) => {
                        let algorithm = match bits {
                            "256" => cpq::HKDF_SHA_256,
                            "384" => cpq::HKDF_SHA_384,
                            _ => cpq::HKDF_SHA_512,
                        };

                        (Box::new(move |n, out| timed(n, out, |out| {
                            let options = KdfOptions::default().with_salt(salt).with_info(info);

                            algorithm.derive_into(black_box(data), out, &options).unwrap();
                        })), Vec::new())
                    }
                    Kind::Lms(levels, operation) => stateful(
                        cpq::HSS_LMS,
                        StatefulParameters::Levels(levels),
                        seed(16 + if levels[0].0.contains("M24") { 24 } else { 32 }, 29, 11),
                        operation,
                    ),
                    Kind::Xmss(name, operation) => stateful(
                        if name.starts_with("XMSSMT") { cpq::XMSS_MT } else { cpq::XMSS },
                        StatefulParameters::Name(name),
                        seed(96, 37, 5),
                        operation,
                    ),
                    Kind::Slh(name, operation) => slh(name, operation),
                };

                // The check of a hash, MAC or KDF row is its first output.
                if out > 0 {
                    let mut bytes = vec![0u8; out];

                    op(1, &mut bytes);

                    return (op, bytes);
                }

                (op, check)
            }
        }
    };
}

side!(side_base, base, |algorithm, key, data, out| {
    let mac = algorithm.create(key).unwrap();

    mac.digest_into(&mut *out).unwrap();

    black_box(&mut *out);

    let mut mac = algorithm.create(key).unwrap();

    mac.update(data);

    mac.digest_into(out).unwrap();
});

side!(side_new, new, |algorithm, key, data, out| {
    let keyed = algorithm.key(key).unwrap();

    let mac = keyed.create();

    mac.digest_into(&mut *out).unwrap();

    black_box(&mut *out);

    let mut mac = keyed.create();

    mac.update(data);

    mac.digest_into(out).unwrap();
});

#[cfg(feature = "aa-create")]
side!(side_aa, aa, |algorithm, key, data, out| {
    let mac = algorithm.create(key).unwrap();

    mac.digest_into(&mut *out).unwrap();

    black_box(&mut *out);

    let mut mac = algorithm.create(key).unwrap();

    mac.update(data);

    mac.digest_into(out).unwrap();
});

#[cfg(not(feature = "aa-create"))]
side!(side_aa, aa, |algorithm, key, data, out| {
    let keyed = algorithm.key(key).unwrap();

    let mac = keyed.create();

    mac.digest_into(&mut *out).unwrap();

    black_box(&mut *out);

    let mut mac = keyed.create();

    mac.update(data);

    mac.digest_into(out).unwrap();
});

const ORDERS: [[usize; 3]; 6] = [[0, 1, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0], [0, 2, 1], [1, 0, 2]];

fn main() {
    let mut rounds = 16;

    let mut ms = 20u64;

    let mut filters: Vec<String> = Vec::new();

    for arg in std::env::args().skip(1) {
        if let Some(v) = arg.strip_prefix("--rounds=") {
            rounds = v.parse().unwrap();
        } else if let Some(v) = arg.strip_prefix("--ms=") {
            ms = v.parse().unwrap();
        } else {
            filters.push(arg);
        }
    }

    let rank = |name: &str| {
        filters.iter().position(|f| match f.strip_suffix('*') {
            Some(prefix) => name.starts_with(prefix),
            None => name == f,
        })
    };

    let mut selected: Vec<Row> = rows()
        .into_iter()
        .filter(|r| filters.is_empty() || rank(&r.name).is_some())
        .collect();

    selected.sort_by_key(|r| rank(&r.name));

    let target = Duration::from_millis(ms);

    let mut table = Vec::new();

    for row in selected {
        let sides = [side_base::op(&row), side_new::op(&row), side_aa::op(&row)];

        if sides[1].1 != sides[0].1 || sides[2].1 != sides[0].1 {
            println!("MISMATCH\t{}", row.name);
        }

        let mut ops = sides.map(|(op, _)| op);

        let mut out = vec![0u8; row.out].into_boxed_slice();

        ops[0](1, &mut out);

        ops[2](1, &mut out);

        // The count that takes about the target time on new.
        let mut count = 1u64;

        loop {
            let elapsed = ops[1](count, &mut out);

            if elapsed >= target / 4 || count >= 1 << 30 {
                // The least of three, so that one preempted sample does not set the count.
                let least = elapsed.min(ops[1](count, &mut out)).min(ops[1](count, &mut out));

                let per = least.as_secs_f64() / count as f64;

                count = ((target.as_secs_f64() / per).ceil() as u64).max(1);

                break;
            }

            count *= 4;
        }

        table.push((row.name, ops, out, count));
    }

    println!("ROWS\t{}\tROUNDS\t{rounds}\tMS\t{ms}", table.len());

    for round in 0..rounds {
        for (i, (name, ops, out, count)) in table.iter_mut().enumerate() {
            let mut times = [0.0; 3];

            for side in ORDERS[(round + i) % 6] {
                times[side] = ops[side](*count, out).as_secs_f64() * 1e6 / *count as f64;
            }

            println!(
                "AB\t{round}\t{name}\t{count}\t{:.4}\t{:.4}\t{:.4}\t{:.5}\t{:.5}",
                times[0],
                times[1],
                times[2],
                times[0] / times[1],
                times[2] / times[1]
            );
        }
    }
}

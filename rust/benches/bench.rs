use std::hint::black_box;
use std::time::{Duration, Instant};

use crypto_pq::{
    Error, HSS_LMS, KemAlgorithm, ML_DSA_44, ML_DSA_65, ML_DSA_87, ML_KEM_512, ML_KEM_768,
    ML_KEM_1024, SHA_256, SHA_512, SHA3_256, SHAKE128, SHAKE256, SLH_DSA_SHA2_128F,
    SLH_DSA_SHA2_128S, SLH_DSA_SHA2_192F, SLH_DSA_SHA2_192S, SLH_DSA_SHA2_256F, SLH_DSA_SHA2_256S,
    SLH_DSA_SHAKE_128F, SLH_DSA_SHAKE_128S, SLH_DSA_SHAKE_192F, SLH_DSA_SHAKE_192S,
    SLH_DSA_SHAKE_256F, SLH_DSA_SHAKE_256S, SignOptions, SignatureAlgorithm, StateStore,
    StatefulKeyGenOptions, StatefulLoadOptions, StatefulParameters, StatefulPrivateKey,
    StatefulSignatureAlgorithm, VerifyOptions, X_WING, XMSS, XMSS_MT, hazmat,
};

const MIN_TIME: Duration = Duration::from_secs(1);

// ML-DSA signing loops a message-dependent number of times, so its cases rotate through these.
const MESSAGES: usize = 16;

const SLH_DSA: [SignatureAlgorithm; 12] = [
    SLH_DSA_SHA2_128S,
    SLH_DSA_SHA2_128F,
    SLH_DSA_SHA2_192S,
    SLH_DSA_SHA2_192F,
    SLH_DSA_SHA2_256S,
    SLH_DSA_SHA2_256F,
    SLH_DSA_SHAKE_128S,
    SLH_DSA_SHAKE_128F,
    SLH_DSA_SHAKE_192S,
    SLH_DSA_SHAKE_192F,
    SLH_DSA_SHAKE_256S,
    SLH_DSA_SHAKE_256F,
];

#[derive(Default)]
struct MemoryStore(Option<Vec<u8>>);

impl StateStore for MemoryStore {
    fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.0.clone())
    }

    fn update(&mut self, previous: Option<&[u8]>, next: &[u8]) -> Result<bool, Error> {
        if self.0.as_deref() != previous {
            return Ok(false);
        }

        self.0 = Some(next.to_vec());

        Ok(true)
    }
}

struct Runner {
    filter: Option<String>,
}

impl Runner {
    fn selects(&self, name: &str) -> bool {
        self.filter
            .as_ref()
            .is_none_or(|filter| name.contains(filter.as_str()))
    }

    // batch(count) runs the operation count times and returns the time to count. The batches
    // grow until MIN_TIME is reached, so a slow case still runs once.
    fn case(&self, name: &str, mut batch: impl FnMut(u64) -> Duration) {
        if !self.selects(name) {
            return;
        }

        let mut iterations = 0;

        let mut elapsed = Duration::ZERO;

        let mut count = 1;

        while elapsed < MIN_TIME {
            elapsed += batch(count);

            iterations += count;

            let per_operation = elapsed.as_secs_f64() / iterations as f64;

            let remaining = MIN_TIME.saturating_sub(elapsed).as_secs_f64();

            count = ((remaining / per_operation).ceil() as u64).clamp(1, 10 * iterations);
        }

        let micros = elapsed.as_secs_f64() * 1e6 / iterations as f64;

        println!("{name:<32}  {iterations:>9}  {micros:>14.3}");
    }
}

fn timed(count: u64, mut operation: impl FnMut()) -> Duration {
    let start = Instant::now();

    for _ in 0..count {
        operation();
    }

    start.elapsed()
}

fn bytes(length: usize) -> Vec<u8> {
    (0..length).map(|i| i as u8).collect()
}

fn messages() -> Vec<Vec<u8>> {
    (0..MESSAGES)
        .map(|i| format!("crypto-pq benchmark message {i}").into_bytes())
        .collect()
}

fn names(algorithm: &str, operations: [&str; 3]) -> [String; 3] {
    operations.map(|operation| format!("{algorithm}/{operation}"))
}

fn hashes(runner: &Runner) {
    let data = bytes(1024);

    runner.case("sha-256/64B", |count| {
        timed(count, || {
            black_box(SHA_256.digest(black_box(&data[..64])));
        })
    });

    runner.case("sha-256/1KiB", |count| {
        timed(count, || {
            black_box(SHA_256.digest(black_box(&data)));
        })
    });

    runner.case("sha-512/1KiB", |count| {
        timed(count, || {
            black_box(SHA_512.digest(black_box(&data)));
        })
    });

    runner.case("sha3-256/1KiB", |count| {
        timed(count, || {
            black_box(SHA3_256.digest(black_box(&data)));
        })
    });

    runner.case("shake128/1KiB", |count| {
        timed(count, || {
            black_box(SHAKE128.digest(black_box(&data), 32));
        })
    });

    runner.case("shake256/1KiB", |count| {
        timed(count, || {
            black_box(SHAKE256.digest(black_box(&data), 64));
        })
    });
}

fn kem(runner: &Runner, algorithm: KemAlgorithm, seed_size: usize, randomness_size: usize) {
    let [keygen, encaps, decaps] = names(algorithm.name(), ["keygen", "encaps", "decaps"]);

    let seed = bytes(seed_size);

    runner.case(&keygen, |count| {
        timed(count, || {
            black_box(hazmat::generate_kem_key_pair(algorithm, black_box(&seed)).unwrap());
        })
    });

    if !runner.selects(&encaps) && !runner.selects(&decaps) {
        return;
    }

    let pair = hazmat::generate_kem_key_pair(algorithm, &seed).unwrap();

    let randomness = bytes(randomness_size);

    runner.case(&encaps, |count| {
        timed(count, || {
            black_box(hazmat::encapsulate(&pair.public_key, black_box(&randomness)).unwrap());
        })
    });

    let ciphertext = hazmat::encapsulate(&pair.public_key, &randomness)
        .unwrap()
        .ciphertext;

    runner.case(&decaps, |count| {
        timed(count, || {
            black_box(
                pair.private_key
                    .decapsulate(black_box(&ciphertext))
                    .unwrap(),
            );
        })
    });
}

// SLH-DSA signing costs the same for every message, so its cases use one message; ML-DSA rotates.
fn signature(runner: &Runner, algorithm: SignatureAlgorithm, seed_size: usize, rotate: bool) {
    let [keygen, sign, verify] = names(algorithm.name(), ["keygen", "sign", "verify"]);

    let seed = bytes(seed_size);

    runner.case(&keygen, |count| {
        timed(count, || {
            black_box(hazmat::generate_signature_key_pair(algorithm, black_box(&seed)).unwrap());
        })
    });

    if !runner.selects(&sign) && !runner.selects(&verify) {
        return;
    }

    let pair = hazmat::generate_signature_key_pair(algorithm, &seed).unwrap();

    let mut messages = messages();

    if !rotate {
        messages.truncate(1);
    }

    let options = SignOptions {
        deterministic: true,
        ..SignOptions::default()
    };

    let mut next = 0;

    runner.case(&sign, |count| {
        timed(count, || {
            let message = &messages[next % messages.len()];

            next += 1;

            black_box(pair.private_key.sign(black_box(message), &options).unwrap());
        })
    });

    if !runner.selects(&verify) {
        return;
    }

    let signed: Vec<(&Vec<u8>, Vec<u8>)> = messages
        .iter()
        .map(|message| (message, pair.private_key.sign(message, &options).unwrap()))
        .collect();

    let options = VerifyOptions::default();

    let mut next = 0;

    runner.case(&verify, |count| {
        timed(count, || {
            let (message, signature) = &signed[next % signed.len()];

            next += 1;

            assert!(
                pair.public_key
                    .verify(black_box(signature), message, &options)
            );
        })
    });
}

fn stateful(
    runner: &Runner,
    name: &str,
    algorithm: StatefulSignatureAlgorithm,
    parameters: StatefulParameters,
    seed_size: usize,
) {
    let [keygen, sign, verify] = names(name, ["keygen", "sign", "verify"]);

    let seed = bytes(seed_size);

    let generate = || {
        hazmat::generate_stateful_key_pair(
            algorithm,
            parameters,
            &seed,
            0,
            MemoryStore::default(),
            &StatefulKeyGenOptions::default(),
        )
        .unwrap()
    };

    runner.case(&keygen, |count| {
        timed(count, || {
            black_box(generate());
        })
    });

    let messages = messages();

    let mut key: Option<StatefulPrivateKey<MemoryStore>> = None;

    let mut next = 0;

    // An exhausted key is replaced outside the measured time.
    runner.case(&sign, |count| {
        let mut elapsed = Duration::ZERO;

        for _ in 0..count {
            if key
                .as_ref()
                .is_none_or(|key| key.remaining_signatures() == 0)
            {
                key = Some(generate().private_key);
            }

            let key = key.as_mut().unwrap();

            let message = &messages[next % MESSAGES];

            next += 1;

            let start = Instant::now();

            black_box(key.sign(black_box(message)).unwrap());

            elapsed += start.elapsed();
        }

        elapsed
    });

    if !runner.selects(&verify) {
        return;
    }

    let mut pair = generate();

    let signed: Vec<(&Vec<u8>, Vec<u8>)> = messages
        .iter()
        .map(|message| (message, pair.private_key.sign(message).unwrap()))
        .collect();

    let mut next = 0;

    runner.case(&verify, |count| {
        timed(count, || {
            let (message, signature) = &signed[next % MESSAGES];

            next += 1;

            assert!(pair.public_key.verify(black_box(signature), message));
        })
    });
}

// Loading a key builds its trees from the leaves; with a tree cache it recomputes the parents of
// the cached nodes instead.
fn load(
    runner: &Runner,
    name: &str,
    algorithm: StatefulSignatureAlgorithm,
    parameters: StatefulParameters,
    seed_size: usize,
) {
    let (plain, cached) = (format!("{name}/load"), format!("{name}/load+cache"));

    if !runner.selects(&plain) && !runner.selects(&cached) {
        return;
    }

    let mut store = MemoryStore::default();

    let cache = hazmat::generate_stateful_key_pair(
        algorithm,
        parameters,
        &bytes(seed_size),
        0,
        &mut store,
        &StatefulKeyGenOptions::default(),
    )
    .and_then(|pair| pair.private_key.export_tree_cache())
    .unwrap();

    for (name, tree_cache) in [(plain, None), (cached, Some(&cache[..]))] {
        let options = StatefulLoadOptions {
            tree_cache,
            ..StatefulLoadOptions::default()
        };

        runner.case(&name, |count| {
            timed(count, || {
                black_box(algorithm.load_private_key(&mut store, &options).unwrap());
            })
        });
    }
}

fn main() {
    let runner = Runner {
        filter: std::env::args().skip(1).find(|arg| !arg.starts_with("--")),
    };

    hashes(&runner);

    for algorithm in [ML_KEM_512, ML_KEM_768, ML_KEM_1024] {
        kem(&runner, algorithm, 64, 32);
    }

    kem(&runner, X_WING, 32, 64);

    for algorithm in [ML_DSA_44, ML_DSA_65, ML_DSA_87] {
        signature(&runner, algorithm, 32, true);
    }

    for algorithm in SLH_DSA {
        let n = algorithm.public_key_size() / 2;

        signature(&runner, algorithm, 3 * n, false);
    }

    stateful(
        &runner,
        "HSS-H10-W4",
        HSS_LMS,
        StatefulParameters::Levels(&[("LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W4")]),
        48,
    );

    stateful(
        &runner,
        "HSS-H5H5-W8",
        HSS_LMS,
        StatefulParameters::Levels(&[
            ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8"),
            ("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8"),
        ]),
        48,
    );

    stateful(
        &runner,
        "XMSS-SHA2_10_256",
        XMSS,
        StatefulParameters::Name("XMSS-SHA2_10_256"),
        96,
    );

    stateful(
        &runner,
        "XMSSMT-SHA2_20/4_256",
        XMSS_MT,
        StatefulParameters::Name("XMSSMT-SHA2_20/4_256"),
        96,
    );

    load(
        &runner,
        "HSS-H15-W4",
        HSS_LMS,
        StatefulParameters::Levels(&[("LMS_SHA256_M32_H15", "LMOTS_SHA256_N32_W4")]),
        48,
    );

    // A tree of height 20 takes tens of seconds to build, so it runs only when a filter selects it.
    if runner.filter.is_some() {
        load(
            &runner,
            "HSS-H20-W4",
            HSS_LMS,
            StatefulParameters::Levels(&[("LMS_SHA256_M32_H20", "LMOTS_SHA256_N32_W4")]),
            48,
        );
    }
}

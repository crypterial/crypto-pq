// FrodoKEM A/B: crypto-pq main (7267bf3) against the PR, every set and operation, through the
// hazmat calls of the 1.0 harness (h/rust10: keygen from the seed, encaps from the randomness,
// decaps). Outputs of both are compared byte for byte first. Each round runs every case, main and
// PR back to back, the order alternating with the round; batches grow to MIN_TIME; the minimum
// over rounds is what counts. Usage: fbench [--rounds=N] [--min-ms=M] [filter...]

use std::hint::black_box;
use std::time::{Duration, Instant};

fn bytes(length: usize) -> Vec<u8> {
    (0..length).map(|i| i as u8).collect()
}

fn measure(min: Duration, mut batch: impl FnMut(u64) -> Duration) -> (u64, f64) {
    let (mut iterations, mut elapsed, mut count) = (0u64, Duration::ZERO, 1u64);

    while elapsed < min {
        elapsed += batch(count);

        iterations += count;

        let per = elapsed.as_secs_f64() / iterations as f64;

        let remaining = min.saturating_sub(elapsed).as_secs_f64();

        count = ((remaining / per).ceil() as u64).clamp(1, 10 * iterations);
    }

    (iterations, elapsed.as_secs_f64() * 1e6 / iterations as f64)
}

macro_rules! algorithm {
    ($krate:ident, $name:expr) => {
        [
            $krate::FRODOKEM_976_AES,
            $krate::FRODOKEM_976_SHAKE,
            $krate::FRODOKEM_1344_AES,
            $krate::FRODOKEM_1344_SHAKE,
            $krate::EFRODOKEM_976_AES,
            $krate::EFRODOKEM_976_SHAKE,
            $krate::EFRODOKEM_1344_AES,
            $krate::EFRODOKEM_1344_SHAKE,
        ]
        .into_iter()
        .find(|a| a.name() == $name)
        .unwrap_or_else(|| panic!("unknown set {}", $name))
    };
}

fn timed(count: u64, mut f: impl FnMut()) -> Duration {
    let start = Instant::now();

    for _ in 0..count {
        f();
    }

    start.elapsed()
}

type Case = (String, [Box<dyn FnMut(u64) -> Duration>; 2]);

macro_rules! cases {
    ($cases:ident, $krate:ident, $index:expr, $sets:expr) => {{
        for (k, (name, seed_size, randomness_size)) in $sets.iter().enumerate() {
            let algorithm = algorithm!($krate, *name);

            let seed = bytes(*seed_size);

            let m = bytes(*randomness_size);

            let pair = $krate::hazmat::generate_kem_key_pair(algorithm, &seed).unwrap();

            let encapsulation = $krate::hazmat::encapsulate(&pair.public_key, &m).unwrap();

            let ct = encapsulation.ciphertext.clone();

            let public_key = pair.public_key.clone();

            let private_key = pair.private_key;

            let s1 = seed.clone();

            $cases[3 * k].1[$index] = Box::new(move |n| timed(n, || {
                black_box($krate::hazmat::generate_kem_key_pair(algorithm, black_box(&s1)).unwrap());
            }));

            $cases[3 * k + 1].1[$index] = Box::new(move |n| timed(n, || {
                black_box($krate::hazmat::encapsulate(&public_key, black_box(&m)).unwrap());
            }));

            $cases[3 * k + 2].1[$index] = Box::new(move |n| timed(n, || {
                black_box(private_key.decapsulate(black_box(&ct)).unwrap());
            }));
        }
    }};
}

fn fingerprint_pr(name: &str, seed: usize, randomness: usize) -> Vec<Vec<u8>> {
    use pr::KeyFormat;

    let algorithm = algorithm!(pr, name);

    let pair = pr::hazmat::generate_kem_key_pair(algorithm, &bytes(seed)).unwrap();

    let e = pr::hazmat::encapsulate(&pair.public_key, &bytes(randomness)).unwrap();

    let mut changed = e.ciphertext.clone();

    changed[7] ^= 1;

    vec![
        pair.public_key.export_key(KeyFormat::Raw).unwrap().to_vec(),
        pair.private_key.export_key(KeyFormat::Raw).unwrap().to_vec(),
        e.ciphertext.clone(),
        e.shared_secret.to_vec(),
        pair.private_key.decapsulate(&e.ciphertext).unwrap().to_vec(),
        pair.private_key.decapsulate(&changed).unwrap().to_vec(),
    ]
}

fn fingerprint_main(name: &str, seed: usize, randomness: usize) -> Vec<Vec<u8>> {
    use main::KeyFormat;

    let algorithm = algorithm!(main, name);

    let pair = main::hazmat::generate_kem_key_pair(algorithm, &bytes(seed)).unwrap();

    let e = main::hazmat::encapsulate(&pair.public_key, &bytes(randomness)).unwrap();

    let mut changed = e.ciphertext.clone();

    changed[7] ^= 1;

    vec![
        pair.public_key.export_key(KeyFormat::Raw).unwrap().to_vec(),
        pair.private_key.export_key(KeyFormat::Raw).unwrap().to_vec(),
        e.ciphertext.clone(),
        e.shared_secret.to_vec(),
        pair.private_key.decapsulate(&e.ciphertext).unwrap().to_vec(),
        pair.private_key.decapsulate(&changed).unwrap().to_vec(),
    ]
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let rounds: usize = args.iter().find_map(|a| a.strip_prefix("--rounds=")).map_or(3, |v| v.parse().unwrap());

    let min = Duration::from_millis(args.iter().find_map(|a| a.strip_prefix("--min-ms=")).map_or(1000, |v| v.parse().unwrap()));

    let filters: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();

    let sets = [
        ("FrodoKEM-976-AES", 88, 72),
        ("FrodoKEM-976-SHAKE", 88, 72),
        ("FrodoKEM-1344-AES", 112, 96),
        ("FrodoKEM-1344-SHAKE", 112, 96),
        ("eFrodoKEM-976-AES", 64, 24),
        ("eFrodoKEM-976-SHAKE", 64, 24),
        ("eFrodoKEM-1344-AES", 80, 32),
        ("eFrodoKEM-1344-SHAKE", 80, 32),
    ];

    for (name, seed, randomness) in sets {
        let same = fingerprint_pr(name, seed, randomness) == fingerprint_main(name, seed, randomness);

        println!("CHECK\t{name}\t{}", if same { "identical" } else { "DIFFERENT" });

        let outputs = fingerprint_pr(name, seed, randomness);

        for (label, data) in [("ek", &outputs[0]), ("ct", &outputs[2]), ("ss", &outputs[3])] {
            let digest: String = pr::SHA3_256.digest(data).iter().map(|b| format!("{b:02x}")).collect();

            println!("FP {name}/{label} {digest}");
        }

        assert!(same, "{name}: the PR's outputs differ from main's");
    }

    let mut cases: Vec<Case> = sets
        .iter()
        .flat_map(|(name, _, _)| ["keygen", "encaps", "decaps"].map(|op| format!("{name}/{op}")))
        .map(|label| -> Case {
            (label, [Box::new(|_| Duration::ZERO), Box::new(|_| Duration::ZERO)])
        })
        .collect();

    cases!(cases, main, 0, sets);

    cases!(cases, pr, 1, sets);

    let labels = ["crypto-pq main", "crypto-pq PR"];

    for round in 1..=rounds {
        for (label, impls) in cases.iter_mut() {
            if !filters.is_empty() && !filters.iter().any(|f| label.contains(f.as_str())) {
                continue;
            }

            for i in 0..2 {
                let which = (i + round) % 2;

                let (iterations, us) = measure(min, &mut impls[which]);

                println!("R{round}\t{label}\t{}\t{iterations}\t{us:.4}", labels[which]);
            }
        }
    }
}

// SLH-DSA recount, in one process: crypto-pq new, base (main) and an A/A copy of new, and the
// counted rival crates (rule 17) as they build by default. Before timing, every variant must give
// the same public key and deterministic signature as crypto-pq new for the same seed, verify that
// signature and reject a flipped one. Every round times one sample of each variant, the order
// rotating, and a ratio is taken per round against new.
// Usage: slh-rc <ab|rivals|stack> [rounds] [set filter]
use std::hint::black_box;
use std::time::Instant;

const SETS: [(&str, usize); 12] = [
    ("SHA2-128s", 16),
    ("SHA2-128f", 16),
    ("SHA2-192s", 24),
    ("SHA2-192f", 24),
    ("SHA2-256s", 32),
    ("SHA2-256f", 32),
    ("SHAKE-128s", 16),
    ("SHAKE-128f", 16),
    ("SHAKE-192s", 24),
    ("SHAKE-192f", 24),
    ("SHAKE-256s", 32),
    ("SHAKE-256f", 32),
];

const MESSAGE: &[u8] = b"crypto-pq SLH-DSA recount message";

const SAMPLE_NS: f64 = 2e6;

// One variant's operations on one set, its keys prepared outside the timed calls.
struct Ops {
    keygen: Box<dyn Fn()>,
    sign: Box<dyn Fn() -> Vec<u8>>,
    verify: Box<dyn Fn(&[u8]) -> bool>,
    fresh: Box<dyn Fn(&[u8]) -> bool>,
    pk: Vec<u8>,
}

macro_rules! cpq {
    ($module:ident, $krate:ident) => {
        mod $module {
            use $krate::*;

            pub fn ops(set: usize, seed: &[u8]) -> super::Ops {
                let algorithm = [
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
                ][set];

                let deterministic = || SignOptions::default().with_deterministic(true);

                let pair = hazmat::generate_signature_key_pair(algorithm, seed).unwrap();

                let pk = pair.public_key.export_key(KeyFormat::Raw).unwrap();

                let seed = seed.to_vec();

                let private_key = pair.private_key;

                let public_key = pair.public_key;

                let encoded = pk.clone();

                super::Ops {
                    keygen: Box::new(move || {
                        std::hint::black_box(hazmat::generate_signature_key_pair(algorithm, std::hint::black_box(&seed)).unwrap());
                    }),
                    sign: Box::new(move || private_key.sign(super::MESSAGE, &deterministic()).unwrap().to_vec()),
                    verify: Box::new(move |sig| public_key.verify(sig, super::MESSAGE, &VerifyOptions::default())),
                    fresh: Box::new(move |sig| {
                        algorithm
                            .import_public_key(std::hint::black_box(&encoded), KeyFormat::Raw)
                            .is_ok_and(|key| key.verify(sig, super::MESSAGE, &VerifyOptions::default()))
                    }),
                    pk,
                }
            }
        }
    };
}

cpq!(v_new, cpq_new);

cpq!(v_base, cpq_base);

cpq!(v_aa, cpq_aa);

// RustCrypto slh-dsa: slh_keygen_internal from the three seeds; opt_rand None is the deterministic
// variant. Its VerifyingKey is the two public halves, so the fresh row decodes inside the call.
fn rustcrypto<P: rustcrypto_slh::ParameterSet + 'static>(seed: &[u8]) -> Ops {
    use rustcrypto_slh::{Signature, SigningKey, VerifyingKey};

    let n = seed.len() / 3;

    let seed = seed.to_vec();

    let sk = SigningKey::<P>::slh_keygen_internal(&seed[..n], &seed[n..2 * n], &seed[2 * n..]);

    let vk: VerifyingKey<P> = sk.as_ref().clone();

    let pk = vk.to_bytes().to_vec();

    let encoded = pk.clone();

    Ops {
        keygen: Box::new(move || {
            let seed = black_box(&seed);

            black_box(SigningKey::<P>::slh_keygen_internal(&seed[..n], &seed[n..2 * n], &seed[2 * n..]));
        }),
        sign: Box::new(move || sk.try_sign_with_context(MESSAGE, &[], None).unwrap().to_bytes().to_vec()),
        verify: Box::new(move |sig| {
            Signature::<P>::try_from(sig).is_ok_and(|sig| vk.try_verify_with_context(MESSAGE, &[], &sig).is_ok())
        }),
        fresh: Box::new(move |sig| {
            let key = VerifyingKey::<P>::try_from(black_box(encoded.as_slice())).unwrap();

            Signature::<P>::try_from(sig).is_ok_and(|sig| key.try_verify_with_context(MESSAGE, &[], &sig).is_ok())
        }),
        pk,
    }
}

// fips205 (integritychain): keygen_from_seed; try_sign(.., hedged = false) is the deterministic
// variant. Its PublicKey is the two halves; the fresh row decodes inside the call.
macro_rules! fips205_ops {
    ($module:ident, $seed:expr) => {{
        use fips205::$module as imp;
        use fips205::traits::{KeyGen, SerDes, Signer, Verifier};

        const N: usize = imp::PK_LEN / 2;

        let seed: &[u8] = $seed;

        let part = |i: usize| -> [u8; N] { seed[i * N..(i + 1) * N].try_into().unwrap() };

        let (s0, s1, s2) = (part(0), part(1), part(2));

        let (pk, sk) = imp::KG::keygen_from_seed(&s0, &s1, &s2);

        let encoded = pk.clone().into_bytes();

        Ops {
            keygen: Box::new(move || {
                black_box(imp::KG::keygen_from_seed(black_box(&s0), &s1, &s2));
            }),
            sign: Box::new(move || sk.try_sign(MESSAGE, &[], false).unwrap().to_vec()),
            verify: Box::new(move |sig| {
                <&[u8; imp::SIG_LEN]>::try_from(sig).is_ok_and(|sig| pk.verify(MESSAGE, sig, &[]))
            }),
            fresh: Box::new(move |sig| {
                let key = imp::PublicKey::try_from_bytes(black_box(&encoded).clone()).unwrap();

                <&[u8; imp::SIG_LEN]>::try_from(sig).is_ok_and(|sig| key.verify(MESSAGE, sig, &[]))
            }),
            pk: encoded.to_vec(),
        }
    }};
}

// slhdsa-c-rs (PQCA slhdsa-c, portable C at -O3): the wrapper has random key generation only, so
// keygen from the seeds goes through the crate's public ffi::slh_keygen_internal. try_sign_with_ctx
// passes no addrnd: the deterministic variant. The fresh row decodes the key inside the call.
#[cfg(pb_c)]
fn slhdsa_c<P: slhdsa_c_rs::ParameterSet + 'static>(seed: &[u8], prm: &'static slhdsa_c_rs::ffi::slh_param_s) -> Ops {
    use slhdsa_c_rs::{Signature, SigningKey, VerifyingKey};

    let n = seed.len() / 3;

    let seed = seed.to_vec();

    let keygen = move |seed: &[u8]| -> (Vec<u8>, Vec<u8>) {
        let mut sk = vec![0u8; 4 * n];

        let mut pk = vec![0u8; 2 * n];

        // SAFETY: sk and pk have the lengths of the parameter set, the seeds n bytes each.
        let ret = unsafe {
            slhdsa_c_rs::ffi::slh_keygen_internal(
                sk.as_mut_ptr(),
                pk.as_mut_ptr(),
                seed.as_ptr(),
                seed[n..].as_ptr(),
                seed[2 * n..].as_ptr(),
                prm,
            )
        };

        assert_eq!(ret, 0, "slh_keygen_internal");

        (sk, pk)
    };

    let (sk_bytes, pk) = keygen(&seed);

    let sk = SigningKey::<P>::try_from(sk_bytes.as_slice()).unwrap();

    let vk = VerifyingKey::<P>::try_from(pk.as_slice()).unwrap();

    let encoded = pk.clone();

    Ops {
        keygen: Box::new(move || {
            black_box(keygen(black_box(&seed)));
        }),
        sign: Box::new(move || sk.try_sign_with_ctx(MESSAGE, &[]).unwrap().as_ref().to_vec()),
        verify: Box::new(move |sig| {
            Signature::<P>::try_from(sig).is_ok_and(|sig| vk.verify_with_ctx(MESSAGE, &[], &sig).is_ok())
        }),
        fresh: Box::new(move |sig| {
            let key = VerifyingKey::<P>::try_from(black_box(encoded.as_slice())).unwrap();

            Signature::<P>::try_from(sig).is_ok_and(|sig| key.verify_with_ctx(MESSAGE, &[], &sig).is_ok())
        }),
        pk,
    }
}

// lattice-slh-dsa: byte-string API (keygen_seed, sign = deterministic, verify); no key objects, so
// the key is decoded in every call and the reused-key row equals the fresh one.
fn lattice(seed: &[u8], mode: lattice_slh::SlhDsaMode) -> Ops {
    let seed = seed.to_vec();

    let (pk, sk) = lattice_slh::keygen_seed(mode, &seed);

    let (vk, fk) = (pk.clone(), pk.clone());

    Ops {
        keygen: Box::new(move || {
            black_box(lattice_slh::keygen_seed(mode, black_box(&seed)));
        }),
        sign: Box::new(move || lattice_slh::sign(&sk, MESSAGE, mode)),
        verify: Box::new(move |sig| lattice_slh::verify(&vk, sig, MESSAGE, mode)),
        fresh: Box::new(move |sig| lattice_slh::verify(black_box(&fk), sig, MESSAGE, mode)),
        pk,
    }
}

#[cfg(pb_c)]
fn slhdsa_c_set(set: usize, seed: &[u8]) -> Ops {
    use slhdsa_c_rs::ffi as c;

    // SAFETY: the parameter sets are immutable C statics.
    match set {
        0 => slhdsa_c::<slhdsa_c_rs::SLH_DSA_SHA2_128s>(seed, unsafe { &c::slh_dsa_sha2_128s }),
        1 => slhdsa_c::<slhdsa_c_rs::SLH_DSA_SHA2_128f>(seed, unsafe { &c::slh_dsa_sha2_128f }),
        2 => slhdsa_c::<slhdsa_c_rs::SLH_DSA_SHA2_192s>(seed, unsafe { &c::slh_dsa_sha2_192s }),
        3 => slhdsa_c::<slhdsa_c_rs::SLH_DSA_SHA2_192f>(seed, unsafe { &c::slh_dsa_sha2_192f }),
        4 => slhdsa_c::<slhdsa_c_rs::SLH_DSA_SHA2_256s>(seed, unsafe { &c::slh_dsa_sha2_256s }),
        5 => slhdsa_c::<slhdsa_c_rs::SLH_DSA_SHA2_256f>(seed, unsafe { &c::slh_dsa_sha2_256f }),
        6 => slhdsa_c::<slhdsa_c_rs::SLH_DSA_SHAKE_128s>(seed, unsafe { &c::slh_dsa_shake_128s }),
        7 => slhdsa_c::<slhdsa_c_rs::SLH_DSA_SHAKE_128f>(seed, unsafe { &c::slh_dsa_shake_128f }),
        8 => slhdsa_c::<slhdsa_c_rs::SLH_DSA_SHAKE_192s>(seed, unsafe { &c::slh_dsa_shake_192s }),
        9 => slhdsa_c::<slhdsa_c_rs::SLH_DSA_SHAKE_192f>(seed, unsafe { &c::slh_dsa_shake_192f }),
        10 => slhdsa_c::<slhdsa_c_rs::SLH_DSA_SHAKE_256s>(seed, unsafe { &c::slh_dsa_shake_256s }),
        _ => slhdsa_c::<slhdsa_c_rs::SLH_DSA_SHAKE_256f>(seed, unsafe { &c::slh_dsa_shake_256f }),
    }
}

fn rival(variant: &str, set: usize, seed: &[u8]) -> Ops {
    use lattice_slh as l;

    match (variant, set) {
        #[cfg(pb_c)]
        ("slhdsa-c", _) => slhdsa_c_set(set, seed),
        ("RustCrypto", 0) => rustcrypto::<rustcrypto_slh::Sha2_128s>(seed),
        ("RustCrypto", 1) => rustcrypto::<rustcrypto_slh::Sha2_128f>(seed),
        ("RustCrypto", 2) => rustcrypto::<rustcrypto_slh::Sha2_192s>(seed),
        ("RustCrypto", 3) => rustcrypto::<rustcrypto_slh::Sha2_192f>(seed),
        ("RustCrypto", 4) => rustcrypto::<rustcrypto_slh::Sha2_256s>(seed),
        ("RustCrypto", 5) => rustcrypto::<rustcrypto_slh::Sha2_256f>(seed),
        ("RustCrypto", 6) => rustcrypto::<rustcrypto_slh::Shake128s>(seed),
        ("RustCrypto", 7) => rustcrypto::<rustcrypto_slh::Shake128f>(seed),
        ("RustCrypto", 8) => rustcrypto::<rustcrypto_slh::Shake192s>(seed),
        ("RustCrypto", 9) => rustcrypto::<rustcrypto_slh::Shake192f>(seed),
        ("RustCrypto", 10) => rustcrypto::<rustcrypto_slh::Shake256s>(seed),
        ("RustCrypto", 11) => rustcrypto::<rustcrypto_slh::Shake256f>(seed),
        ("fips205", 0) => fips205_ops!(slh_dsa_sha2_128s, seed),
        ("fips205", 1) => fips205_ops!(slh_dsa_sha2_128f, seed),
        ("fips205", 2) => fips205_ops!(slh_dsa_sha2_192s, seed),
        ("fips205", 3) => fips205_ops!(slh_dsa_sha2_192f, seed),
        ("fips205", 4) => fips205_ops!(slh_dsa_sha2_256s, seed),
        ("fips205", 5) => fips205_ops!(slh_dsa_sha2_256f, seed),
        ("fips205", 6) => fips205_ops!(slh_dsa_shake_128s, seed),
        ("fips205", 7) => fips205_ops!(slh_dsa_shake_128f, seed),
        ("fips205", 8) => fips205_ops!(slh_dsa_shake_192s, seed),
        ("fips205", 9) => fips205_ops!(slh_dsa_shake_192f, seed),
        ("fips205", 10) => fips205_ops!(slh_dsa_shake_256s, seed),
        ("fips205", 11) => fips205_ops!(slh_dsa_shake_256f, seed),
        ("lattice", _) => lattice(
            seed,
            [
                l::params::SLH_DSA_SHA2_128S,
                l::params::SLH_DSA_SHA2_128F,
                l::params::SLH_DSA_SHA2_192S,
                l::params::SLH_DSA_SHA2_192F,
                l::params::SLH_DSA_SHA2_256S,
                l::params::SLH_DSA_SHA2_256F,
                l::params::SLH_DSA_SHAKE_128S,
                l::params::SLH_DSA_SHAKE_128F,
                l::params::SLH_DSA_SHAKE_192S,
                l::params::SLH_DSA_SHAKE_192F,
                l::params::SLH_DSA_SHAKE_256S,
                l::params::SLH_DSA_SHAKE_256F,
            ][set],
        ),
        _ => unreachable!("{variant}"),
    }
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);

    let n = values.len();

    if n % 2 == 1 { values[n / 2] } else { (values[n / 2 - 1] + values[n / 2]) / 2.0 }
}

// Rounds of one sample per variant, the order rotating (and reversed every other round); per row:
// new's median time and, per other variant, the median and range of its per-round time over new's.
fn rounds(count: usize, label: &str, names: &[&str], op: &dyn Fn(usize)) {
    let k = names.len();

    let start = Instant::now();

    op(0);

    let per = ((SAMPLE_NS / start.elapsed().as_nanos() as f64) as u64).clamp(1, 100_000);

    let sample = |v: usize| {
        let start = Instant::now();

        for _ in 0..per {
            op(v);
        }

        start.elapsed().as_nanos() as f64 / per as f64
    };

    for v in 0..k {
        black_box(sample(v));
    }

    let mut times = vec![vec![0.0; k]; count];

    for (round, row) in times.iter_mut().enumerate() {
        for i in 0..k {
            let i = if round % 2 == 1 { k - 1 - i } else { i };

            let v = (i + round / 2) % k;

            row[v] = sample(v);
        }

        let raw: Vec<String> = row.iter().map(|t| format!("{t:.1}")).collect();

        println!("RAW {label} {round} {}", raw.join(" "));
    }

    let mut new: Vec<f64> = times.iter().map(|t| t[0]).collect();

    let mut line = format!("ROW {label:26} new {:13.1} ns", median(&mut new));

    for (v, name) in names.iter().enumerate().skip(1) {
        let mut ratios: Vec<f64> = times.iter().map(|t| t[v] / t[0]).collect();

        let (lo, hi) = (ratios.iter().copied().fold(f64::MAX, f64::min), ratios.iter().copied().fold(0.0, f64::max));

        line += &format!("  {name}/new {:.4} [{lo:.4}..{hi:.4}]", median(&mut ratios));
    }

    println!("{line}");
}

// f with the stack of the caller grown by K bytes, so that every frame below moves by K.
#[inline(never)]
fn at_offset<const K: usize>(f: &dyn Fn()) {
    let pad = [0u8; K];

    black_box(&pad);

    f();

    black_box(&pad);
}

macro_rules! offsets {
    ($($k:literal)*) => { [$((($k), at_offset::<$k> as fn(&dyn Fn()))),*] };
}

// Stack placement: new and base at 64 stack offsets (0 to 4032 bytes), per offset the minimum of
// ROUNDS samples of each, alternating; prints ns of each and base/new per offset.
fn stack(count: usize, filter: Option<&str>) {
    let table = offsets!(0 64 128 192 256 320 384 448 512 576 640 704 768 832 896 960 1024 1088 1152 1216 1280 1344 1408 1472 1536 1600 1664 1728 1792 1856 1920 1984 2048 2112 2176 2240 2304 2368 2432 2496 2560 2624 2688 2752 2816 2880 2944 3008 3072 3136 3200 3264 3328 3392 3456 3520 3584 3648 3712 3776 3840 3904 3968 4032);

    for (set, &(label, n)) in SETS.iter().enumerate() {
        if !filter.is_some_and(|f| label.contains(f)) {
            continue;
        }

        let seed: Vec<u8> = (0..3 * n).map(|i| (i as u8).wrapping_mul(29).wrapping_add(11)).collect();

        let ops = [v_new::ops(set, &seed), v_base::ops(set, &seed), v_aa::ops(set, &seed)];

        let signature = (ops[0].sign)();

        for row in ["keygen", "verify", "verify-fresh"] {
            let op = |v: usize| match row {
                "keygen" => (ops[v].keygen)(),
                "verify" => assert!((ops[v].verify)(black_box(&signature))),
                _ => assert!((ops[v].fresh)(black_box(&signature))),
            };

            let start = Instant::now();

            op(0);

            let per = ((SAMPLE_NS / start.elapsed().as_nanos() as f64) as u64).clamp(1, 100_000);

            let mut ratios = Vec::new();

            let mut aas = Vec::new();

            for &(k, call) in &table {
                let mut best = [f64::MAX; 3];

                for round in 0..count {
                    for i in 0..3 {
                        let v = (i + round) % 3;

                        let start = Instant::now();

                        call(&|| {
                            for _ in 0..per {
                                op(v);
                            }
                        });

                        best[v] = best[v].min(start.elapsed().as_nanos() as f64 / per as f64);
                    }
                }

                ratios.push(best[1] / best[0]);

                println!("STACK {label}/{row} off {k:4} new {:12.1} base {:12.1} aa {:12.1} base/new {:.4} aa/new {:.4}", best[0], best[1], best[2], best[1] / best[0], best[2] / best[0]);

                aas.push(best[2] / best[0]);
            }

            let (lo, hi) = (ratios.iter().copied().fold(f64::MAX, f64::min), ratios.iter().copied().fold(0.0, f64::max));

            println!("STACKSUM {label}/{row} base/new median {:.4} [{lo:.4}..{hi:.4}] aa/new median {:.4}", median(&mut ratios), median(&mut aas));
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mode = args.get(1).map_or("ab", String::as_str);

    let count: usize = args.get(2).map_or(10, |r| r.parse().unwrap());

    let filter = args.get(3).cloned();

    if mode == "stack" {
        return stack(count, filter.as_deref());
    }

    // port: new, its A/A copy and every rival that builds for the target.
    let port: Vec<&str> = ["new", "aa", "RustCrypto", "fips205", "slhdsa-c", "lattice"]
        .into_iter()
        .filter(|&name| cfg!(pb_c) || name != "slhdsa-c")
        .collect();

    let names: &[&str] = match mode {
        "ab" => &["new", "base", "aa"],
        "rivals" => &["new", "RustCrypto", "fips205", "slhdsa-c", "lattice"],
        "port" => &port,
        _ => panic!("mode: ab, rivals or port"),
    };

    for (set, &(label, n)) in SETS.iter().enumerate() {
        if filter.as_deref().is_some_and(|f| !label.contains(f)) {
            continue;
        }

        let seed: Vec<u8> = (0..3 * n).map(|i| (i as u8).wrapping_mul(29).wrapping_add(11)).collect();

        let ops: Vec<Ops> = names
            .iter()
            .map(|&name| match name {
                "new" => v_new::ops(set, &seed),
                "base" => v_base::ops(set, &seed),
                "aa" => v_aa::ops(set, &seed),
                _ => rival(name, set, &seed),
            })
            .collect();

        let signature = (ops[0].sign)();

        let mut flipped = signature.clone();

        flipped[signature.len() / 2] ^= 1;

        for (name, o) in names.iter().zip(&ops) {
            assert!(o.pk == ops[0].pk, "{label}: {name} public key differs");

            assert!((o.sign)() == signature, "{label}: {name} deterministic signature differs");

            assert!((o.verify)(&signature) && (o.fresh)(&signature), "{label}: {name} rejects the signature");

            assert!(!(o.verify)(&flipped) && !(o.fresh)(&flipped), "{label}: {name} accepts a flipped signature");
        }

        println!("CHECK {label} ok: {} variants, public {} B, signature {} B", names.len(), ops[0].pk.len(), signature.len());

        // PB_CHECK=1: the output checks only.
        if std::env::var_os("PB_CHECK").is_some() {
            continue;
        }

        rounds(count, &format!("{label}/keygen"), names, &|v| (ops[v].keygen)());

        rounds(count, &format!("{label}/sign"), names, &|v| {
            black_box((ops[v].sign)());
        });

        rounds(count, &format!("{label}/verify"), names, &|v| assert!((ops[v].verify)(black_box(&signature))));

        rounds(count, &format!("{label}/verify-fresh"), names, &|v| assert!((ops[v].fresh)(black_box(&signature))));
    }
}

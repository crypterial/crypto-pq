// kem-rab (kem-eng, never shipped): crypto-pq new, base and an A/A copy of new beside liboqs as the
// oqs crate builds it (0.13.0, default features) and, with cfg rab_v16, liboqs 0.16.0 as the earlier
// harness built it, in one process. Per round each column of a row times a batch of about 1 ms, the
// column order rotating every round; the paired ratio is the column's time over new's (above 1: new
// takes less time). Rows:
//   keygen        derandomized key generation (oqs: Kem::keypair_derand; oqs-raw: the same C call
//                 into fixed buffers; v16: liboqs 0.16.0)
//   fresh         import of the encoded key plus derandomized encapsulation (oqs13-int: liboqs
//                 0.13.0's internal mlkem-native enc_derand, x86 only, no crate API; v16)
//   fresh-public  the public random APIs: import plus encapsulate() against Kem::encapsulate
//   keygen-public the public random APIs: generate_key_pair (self-test off) against Kem::keypair
use std::hint::black_box;
use std::time::Instant;

use oqs::ffi::kem as ffi;

type Op = Box<dyn FnMut()>;

macro_rules! tree {
    ($c:ident, $alg:ident) => {{
        use $c::{KeyFormat, KeyGenOptions, hazmat};

        let algorithm = $c::$alg;

        let seed: [u8; 64] = core::array::from_fn(|i| i as u8 ^ 0x5a);

        let m = [9u8; 32];

        let pair = hazmat::generate_kem_key_pair(algorithm, &seed).unwrap();

        let ek = pair.public_key.export_key(KeyFormat::Raw).unwrap();

        let fresh = algorithm.import_public_key(&ek, KeyFormat::Raw).unwrap();

        let f = hazmat::encapsulate(&fresh, &m).unwrap();

        let public = fresh.encapsulate().unwrap();

        let checks = (ek.clone(), f.ciphertext.clone(), f.shared_secret.to_vec(), public.ciphertext.clone(), public.shared_secret.to_vec());

        let ek2 = ek.clone();

        let ek3 = ek.clone();

        let ops: [Op; 4] = [
            Box::new(move || {
                black_box(hazmat::generate_kem_key_pair(algorithm, black_box(&seed)).unwrap());
            }),
            Box::new(move || {
                let key = algorithm.import_public_key(black_box(&ek2), KeyFormat::Raw).unwrap();

                black_box(hazmat::encapsulate(&key, black_box(&m)).unwrap());
            }),
            Box::new(move || {
                let key = algorithm.import_public_key(black_box(&ek3), KeyFormat::Raw).unwrap();

                black_box(key.encapsulate().unwrap());
            }),
            Box::new(move || {
                black_box(algorithm.generate_key_pair(&KeyGenOptions::default().with_self_test(false)).unwrap());
            }),
        ];

        (ops, checks)
    }};
}

#[cfg(rab_v16)]
unsafe extern "C" {
    fn v16_OQS_KEM_ml_kem_512_keypair_derand(pk: *mut u8, sk: *mut u8, seed: *const u8) -> i32;
    fn v16_OQS_KEM_ml_kem_768_keypair_derand(pk: *mut u8, sk: *mut u8, seed: *const u8) -> i32;
    fn v16_OQS_KEM_ml_kem_1024_keypair_derand(pk: *mut u8, sk: *mut u8, seed: *const u8) -> i32;
    fn v16_OQS_KEM_ml_kem_512_encaps_derand(ct: *mut u8, ss: *mut u8, pk: *const u8, m: *const u8) -> i32;
    fn v16_OQS_KEM_ml_kem_768_encaps_derand(ct: *mut u8, ss: *mut u8, pk: *const u8, m: *const u8) -> i32;
    fn v16_OQS_KEM_ml_kem_1024_encaps_derand(ct: *mut u8, ss: *mut u8, pk: *const u8, m: *const u8) -> i32;
}

#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn PQCP_MLKEM_NATIVE_MLKEM512_X86_64_enc_derand(ct: *mut u8, ss: *mut u8, pk: *const u8, m: *const u8) -> i32;
    fn PQCP_MLKEM_NATIVE_MLKEM768_X86_64_enc_derand(ct: *mut u8, ss: *mut u8, pk: *const u8, m: *const u8) -> i32;
    fn PQCP_MLKEM_NATIVE_MLKEM1024_X86_64_enc_derand(ct: *mut u8, ss: *mut u8, pk: *const u8, m: *const u8) -> i32;
}

type KeypairDerand = unsafe extern "C" fn(*mut u8, *mut u8, *const u8) -> i32;

type RawKeypair = unsafe extern "C" fn(*mut u8, *mut u8, *const u8) -> ffi::OQS_STATUS;

type EncapsDerand = unsafe extern "C" fn(*mut u8, *mut u8, *const u8, *const u8) -> i32;

struct Rival {
    alg: oqs::kem::Algorithm,
    raw_keypair: RawKeypair,
    v16: Option<(KeypairDerand, EncapsDerand)>,
    int_enc: Option<EncapsDerand>,
}

fn rival(size: &str) -> Rival {
    let x86 = cfg!(target_arch = "x86_64") && avx2_bmi2();

    match size {
        "512" => Rival {
            alg: oqs::kem::Algorithm::MlKem512,
            raw_keypair: ffi::OQS_KEM_ml_kem_512_keypair_derand as RawKeypair,
            #[cfg(rab_v16)]
            v16: Some((v16_OQS_KEM_ml_kem_512_keypair_derand, v16_OQS_KEM_ml_kem_512_encaps_derand)),
            #[cfg(not(rab_v16))]
            v16: None,
            #[cfg(target_arch = "x86_64")]
            int_enc: x86.then_some(PQCP_MLKEM_NATIVE_MLKEM512_X86_64_enc_derand as EncapsDerand),
            #[cfg(not(target_arch = "x86_64"))]
            int_enc: x86.then_some(unreachable_enc as EncapsDerand),
        },
        "768" => Rival {
            alg: oqs::kem::Algorithm::MlKem768,
            raw_keypair: ffi::OQS_KEM_ml_kem_768_keypair_derand as RawKeypair,
            #[cfg(rab_v16)]
            v16: Some((v16_OQS_KEM_ml_kem_768_keypair_derand, v16_OQS_KEM_ml_kem_768_encaps_derand)),
            #[cfg(not(rab_v16))]
            v16: None,
            #[cfg(target_arch = "x86_64")]
            int_enc: x86.then_some(PQCP_MLKEM_NATIVE_MLKEM768_X86_64_enc_derand as EncapsDerand),
            #[cfg(not(target_arch = "x86_64"))]
            int_enc: x86.then_some(unreachable_enc as EncapsDerand),
        },
        _ => Rival {
            alg: oqs::kem::Algorithm::MlKem1024,
            raw_keypair: ffi::OQS_KEM_ml_kem_1024_keypair_derand as RawKeypair,
            #[cfg(rab_v16)]
            v16: Some((v16_OQS_KEM_ml_kem_1024_keypair_derand, v16_OQS_KEM_ml_kem_1024_encaps_derand)),
            #[cfg(not(rab_v16))]
            v16: None,
            #[cfg(target_arch = "x86_64")]
            int_enc: x86.then_some(PQCP_MLKEM_NATIVE_MLKEM1024_X86_64_enc_derand as EncapsDerand),
            #[cfg(not(target_arch = "x86_64"))]
            int_enc: x86.then_some(unreachable_enc as EncapsDerand),
        },
    }
}

#[cfg(not(target_arch = "x86_64"))]
unsafe extern "C" fn unreachable_enc(_: *mut u8, _: *mut u8, _: *const u8, _: *const u8) -> i32 {
    unreachable!()
}

fn avx2_bmi2() -> bool {
    #[cfg(target_arch = "x86_64")]
    return std::is_x86_feature_detected!("avx2") && std::is_x86_feature_detected!("bmi2") && std::is_x86_feature_detected!("popcnt");

    #[cfg(not(target_arch = "x86_64"))]
    false
}

fn batch(op: &mut Op, n: u32) -> f64 {
    let t = Instant::now();

    for _ in 0..n {
        op();
    }

    t.elapsed().as_nanos() as f64 / f64::from(n)
}

fn quantile(v: &[f64], q: f64) -> f64 {
    let mut v = v.to_vec();

    v.sort_by(|a, b| a.partial_cmp(b).unwrap());

    v[((v.len() - 1) as f64 * q).round() as usize]
}

fn run(title: &str, mut cols: Vec<(&'static str, Op)>, rounds: usize) {
    let warm = 5;

    let mut n = 1;

    while batch(&mut cols[0].1, n) * f64::from(n) < 1e6 {
        n *= 2;
    }

    let k = cols.len();

    let mut times = vec![vec![]; k];

    for r in 0..rounds + warm {
        for i in 0..k {
            let c = (r + i) % k;

            let ns = batch(&mut cols[c].1, n);

            if r >= warm {
                times[c].push(ns);
            }
        }
    }

    let mut line = format!("AB {title}\tns");

    for (c, t) in cols.iter().zip(&times) {
        line += &format!(" {} {:.0}", c.0, quantile(t, 0.5));
    }

    for c in 1..k {
        let v: Vec<f64> = times[c].iter().zip(&times[0]).map(|(x, y)| x / y).collect();

        line += &format!(
            "\t{}/new med {:.4} p10 {:.4} p90 {:.4}",
            cols[c].0,
            quantile(&v, 0.5),
            quantile(&v, 0.1),
            quantile(&v, 0.9)
        );
    }

    println!("{line}");
}

pub fn main() {
    oqs::init();

    let rounds: usize = std::env::args().nth(1).map_or(101, |r| r.parse().unwrap());

    for size in ["512", "768", "1024"] {
        let (a, b, c) = match size {
            "512" => (tree!(cpq_new, ML_KEM_512), tree!(cpq_base, ML_KEM_512), tree!(cpq_aa, ML_KEM_512)),
            "768" => (tree!(cpq_new, ML_KEM_768), tree!(cpq_base, ML_KEM_768), tree!(cpq_aa, ML_KEM_768)),
            _ => (tree!(cpq_new, ML_KEM_1024), tree!(cpq_base, ML_KEM_1024), tree!(cpq_aa, ML_KEM_1024)),
        };

        let (ek, ct, ss, pub_ct, pub_ss) = a.1.clone();

        assert!(a.1.0 == b.1.0 && a.1.0 == c.1.0 && a.1.1 == b.1.1 && a.1.2 == c.1.2, "ML-KEM-{size}: crypto-pq trees differ");

        let r = rival(size);

        let kem = oqs::kem::Kem::new(r.alg).unwrap();

        let seed: [u8; 64] = core::array::from_fn(|i| i as u8 ^ 0x5a);

        let m = [9u8; 32];

        let (opk, osk) = kem.keypair_derand(kem.keypair_seed_from_bytes(&seed).unwrap()).unwrap();

        assert!(opk.as_ref() == ek.as_slice(), "ML-KEM-{size}: oqs public key differs");

        let oss = kem.decapsulate(&osk, kem.ciphertext_from_bytes(&pub_ct).unwrap()).unwrap();

        assert!(oss.as_ref() == pub_ss.as_slice(), "ML-KEM-{size}: oqs decapsulates new's random ciphertext to another secret");

        let (oct, oss2) = kem.encapsulate(kem.public_key_from_bytes(&ek).unwrap()).unwrap();

        let _ = (&oct, &oss2);

        let mut pk = vec![0u8; kem.length_public_key()];

        let mut sk = vec![0u8; kem.length_secret_key()];

        assert!(unsafe { (r.raw_keypair)(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) } == ffi::OQS_STATUS::OQS_SUCCESS);

        assert!(pk == ek && sk.as_slice() == osk.as_ref(), "ML-KEM-{size}: raw keypair differs");

        let mut oct2 = vec![0u8; kem.length_ciphertext()];

        let mut oss3 = [0u8; 32];

        if let Some(f) = r.int_enc {
            assert_eq!(unsafe { f(oct2.as_mut_ptr(), oss3.as_mut_ptr(), ek.as_ptr(), m.as_ptr()) }, 0);

            assert!(oct2 == ct && oss3.as_slice() == ss.as_slice(), "ML-KEM-{size}: liboqs 0.13 enc_derand differs");
        }

        if let Some((kp, enc)) = r.v16 {
            let mut pk16 = pk.clone();

            let mut sk16 = sk.clone();

            assert_eq!(unsafe { kp(pk16.as_mut_ptr(), sk16.as_mut_ptr(), seed.as_ptr()) }, 0);

            assert!(pk16 == ek && sk16 == sk, "ML-KEM-{size}: liboqs 0.16 keypair differs");

            assert_eq!(unsafe { enc(oct2.as_mut_ptr(), oss3.as_mut_ptr(), ek.as_ptr(), m.as_ptr()) }, 0);

            assert!(oct2 == ct && oss3.as_slice() == ss.as_slice(), "ML-KEM-{size}: liboqs 0.16 encaps differs");
        }

        println!("SAME ML-KEM-{size}: new, base, aa, oqs crate, raw{}{}", if r.int_enc.is_some() { ", oqs13-int" } else { "" }, if r.v16.is_some() { ", v16" } else { "" });

        // PB_CHECK=1: the output checks only.
        if std::env::var_os("PB_CHECK").is_some() {
            continue;
        }

        let [a0, a1, a2, a3] = a.0;

        let [b0, b1, ..] = b.0;

        let [c0, c1, ..] = c.0;

        let mut keygen: Vec<(&'static str, Op)> = vec![("new", a0), ("base", b0), ("aa", c0)];

        let k1 = oqs::kem::Kem::new(r.alg).unwrap();

        keygen.push(("oqs", Box::new(move || {
            black_box(k1.keypair_derand(k1.keypair_seed_from_bytes(black_box(&seed)).unwrap()).unwrap());
        })));

        let raw = r.raw_keypair;

        let (mut p1, mut s1) = (pk.clone(), sk.clone());

        keygen.push(("oqs-raw", Box::new(move || unsafe {
            black_box(raw(p1.as_mut_ptr(), s1.as_mut_ptr(), black_box(seed.as_ptr())));
        })));

        let mut fresh: Vec<(&'static str, Op)> = vec![("new", a1), ("base", b1), ("aa", c1)];

        if let Some(f) = r.int_enc {
            let (mut x, mut y, e) = (oct2.clone(), [0u8; 32], ek.clone());

            fresh.push(("oqs13-int", Box::new(move || unsafe {
                black_box(f(x.as_mut_ptr(), y.as_mut_ptr(), black_box(e.as_ptr()), black_box(m.as_ptr())));
            })));
        }

        if let Some((kp, enc)) = r.v16 {
            let (mut p2, mut s2) = (pk.clone(), sk.clone());

            keygen.push(("v16", Box::new(move || unsafe {
                black_box(kp(p2.as_mut_ptr(), s2.as_mut_ptr(), black_box(seed.as_ptr())));
            })));

            let (mut x, mut y, e) = (oct2.clone(), [0u8; 32], ek.clone());

            fresh.push(("v16", Box::new(move || unsafe {
                black_box(enc(x.as_mut_ptr(), y.as_mut_ptr(), black_box(e.as_ptr()), black_box(m.as_ptr())));
            })));
        }

        let k2 = oqs::kem::Kem::new(r.alg).unwrap();

        let e2 = ek.clone();

        let public: Vec<(&'static str, Op)> = vec![
            ("new", a2),
            ("oqs", Box::new(move || {
                black_box(k2.encapsulate(k2.public_key_from_bytes(black_box(&e2)).unwrap()).unwrap());
            })),
        ];

        let k3 = oqs::kem::Kem::new(r.alg).unwrap();

        let keygen_public: Vec<(&'static str, Op)> = vec![
            ("new", a3),
            ("oqs", Box::new(move || {
                black_box(k3.keypair().unwrap());
            })),
        ];

        run(&format!("ML-KEM-{size}/keygen"), keygen, rounds);

        run(&format!("ML-KEM-{size}/fresh"), fresh, rounds);

        run(&format!("ML-KEM-{size}/fresh-public"), public, rounds);

        run(&format!("ML-KEM-{size}/keygen-public"), keygen_public, rounds);
    }
}

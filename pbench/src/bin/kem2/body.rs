// kem-rab2 (kem-eng, never shipped): crypto-pq new and an A/A copy against aws-lc-rs and
// pqcrypto-mlkem in one process, rotating order, 1 ms batches; ratio = column time / new time.
//   keygen  new: seeded key pair; new-rand: OS-random key pair without the self-test; aws:
//           DecapsulationKey::generate (DRBG); pqc: keypair (OS random)
//   fresh   import of the encoded encapsulation key plus a random encapsulation
//   decaps  decapsulation with a key object made before the timing
use std::hint::black_box;
use std::time::Instant;

use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};

type Op = Box<dyn FnMut()>;

macro_rules! tree {
    ($c:ident, $alg:ident) => {{
        use $c::{KeyFormat, KeyGenOptions, hazmat};

        let algorithm = $c::$alg;

        let seed: [u8; 64] = core::array::from_fn(|i| i as u8 ^ 0x5a);

        let pair = hazmat::generate_kem_key_pair(algorithm, &seed).unwrap();

        let ek = pair.public_key.export_key(KeyFormat::Raw).unwrap();

        let e = pair.public_key.encapsulate().unwrap();

        let ct = e.ciphertext.clone();

        let private = pair.private_key;

        let decaps = move |c: &[u8]| private.decapsulate(c).unwrap().to_vec();

        let ek2 = ek.clone();

        let ops: [Op; 3] = [
            Box::new(move || {
                black_box(hazmat::generate_kem_key_pair(algorithm, black_box(&seed)).unwrap());
            }),
            Box::new(move || {
                let key = algorithm.import_public_key(black_box(&ek2), KeyFormat::Raw).unwrap();

                black_box(key.encapsulate().unwrap());
            }),
            Box::new(move || {
                black_box(algorithm.generate_key_pair(&KeyGenOptions::default().with_self_test(false)).unwrap());
            }),
        ];

        (ops, ek, ct, e.shared_secret.to_vec(), decaps)
    }};
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

macro_rules! size {
    ($size:literal, $alg:ident, $aws:expr, $pqc:ident, $rounds:expr) => {{
        let (a, ek, ct, ss, a_dec) = tree!(cpq_new, $alg);

        let (c, c_ek, _, _, c_dec) = tree!(cpq_aa, $alg);

        assert!(c_ek == ek, "the A/A copy has another key");

        let a_dec = a_dec;

        let dk = DecapsulationKey::generate(&$aws).unwrap();

        let aws_ek = dk.encapsulation_key().unwrap().key_bytes().unwrap().as_ref().to_vec();

        let theirs = cpq_new::$alg.import_public_key(&aws_ek, cpq_new::KeyFormat::Raw).unwrap().encapsulate().unwrap();

        assert!(dk.decapsulate(Ciphertext::from(theirs.ciphertext.as_slice())).unwrap().as_ref() == &theirs.shared_secret[..], "aws-lc-rs decapsulates new's ciphertext to another secret");

        let aws_ct = theirs.ciphertext.clone();

        let (act, ass) = EncapsulationKey::new(&$aws, &ek).unwrap().encapsulate().unwrap();

        assert!(a_dec(act.as_ref()) == ass.as_ref(), "new decapsulates aws-lc-rs's ciphertext to another secret");

        let (ppk, psk) = pqcrypto_mlkem::$pqc::keypair();

        let theirs = cpq_new::$alg.import_public_key(ppk.as_bytes(), cpq_new::KeyFormat::Raw).unwrap().encapsulate().unwrap();

        let pct = pqcrypto_mlkem::$pqc::Ciphertext::from_bytes(&theirs.ciphertext).unwrap();

        assert!(pqcrypto_mlkem::$pqc::decapsulate(&pct, &psk).as_bytes() == &theirs.shared_secret[..], "pqcrypto decapsulates new's ciphertext to another secret");

        let (pss, pct2) = pqcrypto_mlkem::$pqc::encapsulate(&pqcrypto_mlkem::$pqc::PublicKey::from_bytes(&ek).unwrap());

        assert!(a_dec(pct2.as_bytes()) == pss.as_bytes(), "new decapsulates pqcrypto's ciphertext to another secret");

        assert!(a_dec(&ct) == ss);

        println!("SAME ML-KEM-{}: new, aa, aws-lc-rs, pqcrypto-mlkem (cross decapsulation both ways)", $size);

        let [a0, a1, a2] = a;

        let [c0, c1, _] = c;

        let keygen: Vec<(&'static str, Op)> = vec![
            ("new", a0),
            ("aa", c0),
            ("new-rand", a2),
            ("aws", Box::new(|| { black_box(DecapsulationKey::generate(&$aws).unwrap()); })),
            ("pqc", Box::new(|| { black_box(pqcrypto_mlkem::$pqc::keypair()); })),
        ];

        let (e1, e2) = (ek.clone(), ek.clone());

        let fresh: Vec<(&'static str, Op)> = vec![
            ("new", a1),
            ("aa", c1),
            ("aws", Box::new(move || {
                black_box(EncapsulationKey::new(&$aws, black_box(&e1)).unwrap().encapsulate().unwrap());
            })),
            ("pqc", Box::new(move || {
                black_box(pqcrypto_mlkem::$pqc::encapsulate(&pqcrypto_mlkem::$pqc::PublicKey::from_bytes(black_box(&e2)).unwrap()));
            })),
        ];

        let ct2 = ct.clone();

        let decaps: Vec<(&'static str, Op)> = vec![
            ("new", Box::new(move || { black_box(a_dec(black_box(&ct))); })),
            ("aa", Box::new(move || { black_box(c_dec(black_box(&ct2))); })),
            ("aws", Box::new(move || {
                black_box(dk.decapsulate(Ciphertext::from(black_box(aws_ct.as_slice()))).unwrap());
            })),
            ("pqc", Box::new(move || {
                black_box(pqcrypto_mlkem::$pqc::decapsulate(black_box(&pct), &psk));
            })),
        ];

        // PB_CHECK=1: the output checks only.
        if std::env::var_os("PB_CHECK").is_none() {
            run(&format!("ML-KEM-{}/keygen", $size), keygen, $rounds);

            run(&format!("ML-KEM-{}/fresh", $size), fresh, $rounds);

            run(&format!("ML-KEM-{}/decaps", $size), decaps, $rounds);
        }
    }};
}

pub fn main() {
    let rounds: usize = std::env::args().nth(1).map_or(101, |r| r.parse().unwrap());

    size!(512, ML_KEM_512, aws_lc_rs::kem::ML_KEM_512, mlkem512, rounds);

    size!(768, ML_KEM_768, aws_lc_rs::kem::ML_KEM_768, mlkem768, rounds);

    size!(1024, ML_KEM_1024, aws_lc_rs::kem::ML_KEM_1024, mlkem1024, rounds);
}

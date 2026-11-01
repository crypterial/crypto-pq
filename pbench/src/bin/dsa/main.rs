// dsa-rab (dsa-eng, never shipped): crypto-pq new, base and an A/A copy of new beside the ML-DSA
// rival crates as a user adds them (default features), all in one process. Before any timing,
// every output is checked: the three crypto-pq trees give the same keys and deterministic
// signatures; oqs (with a fixed randombytes source for the check only), aws-lc-rs, libcrux and
// RustCrypto give the same public key from the same seed and the same deterministic signatures
// where they sign deterministically; hedged signatures are verified by crypto-pq; every
// implementation verifies crypto-pq's signatures and rejects a flipped one.
// Rows, for ML-DSA-44, -65 and -87:
//   keygen  crypto-pq: hazmat key generation from the seed (no self-test); oqs: Sig::keypair
//           (random, as the crate offers it); others: from the seed
//   sign    deterministic, reused key: crypto-pq, libcrux, RustCrypto (same signatures, so the same
//           numbers of attempts)
//   signh   hedged, reused key: crypto-pq (OS randomness), oqs (secret key bytes), aws-lc-rs; the
//           attempts are random for all, so these columns compare means over many signatures
//   verify  reused key objects where the API has them (oqs and libcrux take bytes)
//   fresh   the public key imported or decoded inside every call
// Each round takes one sample of every column, in an order that turns by round; a sample runs
// enough calls for about SAMPLE_NS (8 times that for signh). Output: per row the median ns of each column and the medians
// of rival/new, base/new, aa/new and wb/new over rounds.
// Usage: dsa-rab [rounds] [row filter]
use std::hint::black_box;
use std::time::Instant;

const SAMPLE_NS: f64 = 2e6;

const LABELS: [&str; 3] = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];

type Call = Box<dyn FnMut(usize)>;

trait Cpq {
    fn keygen(&self, set: usize, seed: &[u8]) -> (Vec<u8>, Vec<u8>);

    fn generate(&self, set: usize, seed: &[u8]);

    fn signer(&self, set: usize, sk: &[u8]) -> Box<dyn Fn(&[u8]) -> Vec<u8>>;

    fn hedged(&self, set: usize, sk: &[u8]) -> Box<dyn Fn(&[u8]) -> Vec<u8>>;

    fn verifier(&self, set: usize, pk: &[u8]) -> Box<dyn Fn(&[u8], &[u8]) -> bool>;

    fn fresh(&self, set: usize, pk: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

macro_rules! cpq {
    ($module:ident, $krate:ident) => {
        mod $module {
            use $krate::{KeyFormat, SignOptions, SignatureAlgorithm, VerifyOptions, hazmat};

            const SETS: [SignatureAlgorithm; 3] = [$krate::ML_DSA_44, $krate::ML_DSA_65, $krate::ML_DSA_87];

            pub struct Imp;

            impl super::Cpq for Imp {
                fn keygen(&self, set: usize, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
                    let pair = hazmat::generate_signature_key_pair(SETS[set], seed).unwrap();

                    (
                        pair.public_key.export_key(KeyFormat::Raw).unwrap(),
                        pair.private_key.export_key(KeyFormat::Raw).unwrap().to_vec(),
                    )
                }

                fn generate(&self, set: usize, seed: &[u8]) {
                    std::hint::black_box(hazmat::generate_signature_key_pair(SETS[set], seed).unwrap());
                }

                fn signer(&self, set: usize, sk: &[u8]) -> Box<dyn Fn(&[u8]) -> Vec<u8>> {
                    let key = SETS[set].import_private_key(sk, KeyFormat::Raw).unwrap();

                    let options = SignOptions::default().with_deterministic(true);

                    Box::new(move |message| key.sign(message, &options).unwrap())
                }

                fn hedged(&self, set: usize, sk: &[u8]) -> Box<dyn Fn(&[u8]) -> Vec<u8>> {
                    let key = SETS[set].import_private_key(sk, KeyFormat::Raw).unwrap();

                    Box::new(move |message| key.sign(message, &SignOptions::default()).unwrap())
                }

                fn verifier(&self, set: usize, pk: &[u8]) -> Box<dyn Fn(&[u8], &[u8]) -> bool> {
                    let key = SETS[set].import_public_key(pk, KeyFormat::Raw).unwrap();

                    Box::new(move |message, signature| key.verify(signature, message, &VerifyOptions::default()))
                }

                fn fresh(&self, set: usize, pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
                    let key = SETS[set].import_public_key(pk, KeyFormat::Raw).unwrap();

                    key.verify(signature, message, &VerifyOptions::default())
                }
            }
        }
    };
}

cpq!(v_new, cpq_new);

cpq!(v_base, cpq_base);

cpq!(v_aa, cpq_aa);

cpq!(v_wb, cpq_wb);

// randombytes for the oqs output check only: the seed, then zeros (rnd = 0, deterministic signing).
#[cfg(pb_oqs)]
static mut FIXED: [u8; 64] = [0; 64];

#[cfg(pb_oqs)]
static mut FIXED_AT: usize = 0;

#[cfg(pb_oqs)]
#[allow(static_mut_refs)]
unsafe extern "C" fn fixed_bytes(out: *mut u8, length: usize) {
    for i in 0..length {
        unsafe {
            *out.add(i) = if FIXED_AT < 64 { FIXED[FIXED_AT] } else { 0 };

            FIXED_AT += 1;
        }
    }
}

#[cfg(pb_oqs)]
#[allow(static_mut_refs)]
fn fixed_rng(seed: &[u8]) {
    unsafe {
        FIXED = [0; 64];

        FIXED[..seed.len()].copy_from_slice(seed);

        FIXED_AT = 0;

        oqs::ffi::rand::OQS_randombytes_custom_algorithm(Some(fixed_bytes));
    }
}

#[cfg(pb_oqs)]
fn zero_rng() {
    fixed_rng(&[0; 64]);
}

#[cfg(pb_oqs)]
fn default_rng() {
    let status = unsafe { oqs::ffi::rand::OQS_randombytes_switch_algorithm(c"OpenSSL".as_ptr()) };

    assert!(status == oqs::ffi::common::OQS_STATUS::OQS_SUCCESS, "OpenSSL randombytes");
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);

    let n = values.len();

    if n % 2 == 1 { values[n / 2] } else { (values[n / 2 - 1] + values[n / 2]) / 2.0 }
}

// Column 0 is new, 1 base, 2 aa, 3 wb, the rest rivals.
fn rounds(count: usize, label: &str, sample_ns: f64, mut columns: Vec<(&'static str, Call)>) {
    let start = Instant::now();

    (columns[0].1)(0);

    (columns[0].1)(1);

    let per = ((sample_ns / (start.elapsed().as_nanos() as f64 / 2.0)) as usize).clamp(1, 1_000_000);

    let n = columns.len();

    let mut index = vec![0usize; n];

    let mut sample = |c: usize, columns: &mut Vec<(&'static str, Call)>| {
        let start = Instant::now();

        for _ in 0..per {
            (columns[c].1)(index[c]);

            index[c] += 1;
        }

        start.elapsed().as_nanos() as f64 / per as f64
    };

    for c in 0..n {
        black_box(sample(c, &mut columns));
    }

    let mut times = vec![vec![0.0; n]; count];

    for (round, row) in times.iter_mut().enumerate() {
        for k in 0..n {
            let c = (if round % 2 == 0 { k } else { n - 1 - k } + round) % n;

            row[c] = sample(c, &mut columns);
        }
    }

    let mut line = format!("ROW {label:18}");

    for c in 0..n {
        let mut column: Vec<f64> = times.iter().map(|t| t[c]).collect();

        line += &format!(" {}={:.1}", columns[c].0, median(&mut column));
    }

    println!("{line}");

    let mut ratios = format!("RATIO {label:18}");

    for c in 1..n {
        let mut ratio: Vec<f64> = times.iter().map(|t| t[c] / t[0]).collect();

        ratios += &format!(" {}={:.4}", columns[c].0, median(&mut ratio));
    }

    println!("{ratios}");
}

macro_rules! libcrux_backend {
    ($module:ident, $body:ident, $($args:expr),*) => {{
        #[cfg(target_arch = "x86_64")]
        {
            if std::arch::is_x86_feature_detected!("avx2") {
                $body!(libcrux_ml_dsa::$module::avx2, "libcrux-avx2", $($args),*)
            } else {
                $body!(libcrux_ml_dsa::$module::portable, "libcrux-portable", $($args),*)
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            $body!(libcrux_ml_dsa::$module::neon, "libcrux-neon", $($args),*)
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            $body!(libcrux_ml_dsa::$module::portable, "libcrux-portable", $($args),*)
        }
    }};
}

macro_rules! libcrux_rows {
    ($imp:path, $name:expr, $label:expr, $inp2:expr, $keygen:expr, $sign:expr, $verify:expr, $fresh:expr) => {{
        let label: &str = $label;

        use $imp as imp;

        let inp: &Inputs = $inp2;

        let pair = imp::generate_key_pair(inp.seed);

        assert!(pair.verification_key.as_slice() == inp.pk.as_slice(), "{label}: libcrux public key differs");

        let signatures: Vec<_> = inp
            .signatures
            .iter()
            .map(|s| libcrux_ml_dsa::MLDSASignature::new(s.as_slice().try_into().unwrap()))
            .collect();

        for ((m, s), raw) in inp.messages.iter().zip(&signatures).zip(&inp.signatures) {
            let own = imp::sign(&pair.signing_key, m, b"", [0u8; 32]).unwrap();

            assert!(own.as_slice() == raw.as_slice(), "{label}: libcrux signature differs");

            assert!(imp::verify(&pair.verification_key, m, b"", s).is_ok(), "{label}: libcrux rejects crypto-pq's signature");

            let bad = libcrux_ml_dsa::MLDSASignature::new(flip(raw).as_slice().try_into().unwrap());

            assert!(imp::verify(&pair.verification_key, m, b"", &bad).is_err(), "{label}: libcrux accepts a flipped signature");
        }

        let seed = inp.seed;

        $keygen.push(($name, Box::new(move |_| {
            black_box(imp::generate_key_pair(black_box(seed)));
        })));

        let messages = inp.messages.clone();

        let signing_key = pair.signing_key;

        $sign.push(($name, Box::new(move |i| {
            black_box(imp::sign(&signing_key, black_box(&messages[i % 16]), b"", [0u8; 32]).unwrap());
        })));

        for row in [&mut *$verify, &mut *$fresh] {
            let (key, messages, signatures) = (pair.verification_key.clone(), inp.messages.clone(), signatures.clone());

            row.push(($name, Box::new(move |i| {
                assert!(imp::verify(black_box(&key), &messages[i % 16], b"", black_box(&signatures[i % 16])).is_ok());
            })));
        }
    }};
}

fn flip(s: &[u8]) -> Vec<u8> {
    let mut f = s.to_vec();

    let middle = f.len() / 2;

    f[middle] ^= 1;

    f
}

struct Inputs {
    seed: [u8; 32],
    pk: Vec<u8>,
    messages: Vec<Vec<u8>>,
    signatures: Vec<Vec<u8>>,
}

// Checks and columns of one rival; pushes onto the four rows.
macro_rules! rows_of {
    ($p:ty, $libcrux:ident, $aws_signing:expr, $aws_verify:expr, $oqs:expr, $label:expr, $inp:expr, $cpq:expr, $rows:expr) => {{
        let inp: &Inputs = $inp;

        let label: &str = $label;

        let [keygen, sign, signh, verify, fresh]: &mut [Vec<(&'static str, Call)>; 5] = $rows;

        // oqs: liboqs 0.13.0 as oqs-sys builds it.
        #[cfg(pb_oqs)]
        {
            let sig = oqs::sig::Sig::new($oqs).unwrap();

            fixed_rng(&inp.seed);

            let (pk, sk) = sig.keypair().unwrap();

            assert!(pk.as_ref() == inp.pk.as_slice(), "{label}: oqs public key differs");

            for (m, s) in inp.messages.iter().zip(&inp.signatures) {
                zero_rng();

                let own = sig.sign(m, &sk).unwrap();

                assert!(own.as_ref() == s.as_slice(), "{label}: oqs deterministic signature differs");

                let parsed = sig.signature_from_bytes(s).unwrap();

                let key = sig.public_key_from_bytes(&inp.pk).unwrap();

                assert!(sig.verify(m, parsed, key).is_ok(), "{label}: oqs rejects crypto-pq's signature");

                let bad = flip(s);

                assert!(sig.verify(m, sig.signature_from_bytes(&bad).unwrap(), key).is_err(), "{label}: oqs accepts a flipped signature");
            }

            default_rng();

            for m in &inp.messages[..4] {
                let hedged = sig.sign(m, &sk).unwrap();

                assert!($cpq.fresh(&inp.pk, m, hedged.as_ref()), "{label}: crypto-pq rejects oqs's hedged signature");
            }

            let s1 = oqs::sig::Sig::new($oqs).unwrap();

            keygen.push(("oqs", Box::new(move |_| {
                black_box(s1.keypair().unwrap());
            })));

            let s2 = oqs::sig::Sig::new($oqs).unwrap();

            let messages = inp.messages.clone();

            signh.push(("oqs", Box::new(move |i| {
                black_box(s2.sign(black_box(&messages[i % 16]), &sk).unwrap());
            })));

            for row in [&mut *verify, &mut *fresh] {
                let s3 = oqs::sig::Sig::new($oqs).unwrap();

                let (pk, messages, signatures) = (inp.pk.clone(), inp.messages.clone(), inp.signatures.clone());

                row.push(("oqs", Box::new(move |i| {
                    let key = s3.public_key_from_bytes(black_box(&pk)).unwrap();

                    let s = s3.signature_from_bytes(black_box(&signatures[i % 16])).unwrap();

                    assert!(s3.verify(&messages[i % 16], s, key).is_ok());
                })));
            }
        }

        // aws-lc-rs: signs hedged only.
        #[cfg(pb_c)]
        {
            use aws_lc_rs::signature::{KeyPair, ParsedPublicKey, PqdsaKeyPair};

            let pair = PqdsaKeyPair::from_seed(&$aws_signing, &inp.seed).unwrap();

            assert!(pair.public_key().as_ref() == inp.pk.as_slice(), "{label}: aws-lc-rs public key differs");

            let parsed = ParsedPublicKey::new(&$aws_verify, &inp.pk).unwrap();

            for (m, s) in inp.messages.iter().zip(&inp.signatures) {
                assert!(parsed.verify_sig(m, s).is_ok(), "{label}: aws-lc-rs rejects crypto-pq's signature");

                assert!(parsed.verify_sig(m, &flip(s)).is_err(), "{label}: aws-lc-rs accepts a flipped signature");
            }

            let mut out = vec![0u8; $aws_signing.signature_len()];

            for m in &inp.messages[..4] {
                pair.sign(m, &mut out).unwrap();

                assert!($cpq.fresh(&inp.pk, m, &out), "{label}: crypto-pq rejects aws-lc-rs's hedged signature");
            }

            let seed = inp.seed;

            keygen.push(("aws-lc-rs", Box::new(move |_| {
                black_box(PqdsaKeyPair::from_seed(&$aws_signing, black_box(&seed)).unwrap());
            })));

            let messages = inp.messages.clone();

            signh.push(("aws-lc-rs", Box::new(move |i| {
                black_box(pair.sign(black_box(&messages[i % 16]), &mut out).unwrap());
            })));

            let (messages, signatures) = (inp.messages.clone(), inp.signatures.clone());

            verify.push(("aws-lc-rs", Box::new(move |i| {
                assert!(parsed.verify_sig(&messages[i % 16], black_box(&signatures[i % 16])).is_ok());
            })));

            let (pk, messages, signatures) = (inp.pk.clone(), inp.messages.clone(), inp.signatures.clone());

            fresh.push(("aws-lc-rs", Box::new(move |i| {
                let key = ParsedPublicKey::new(&$aws_verify, black_box(&pk)).unwrap();

                assert!(key.verify_sig(&messages[i % 16], black_box(&signatures[i % 16])).is_ok());
            })));
        }

        // libcrux: its backend for the CPU; verify takes the encoded key.
        libcrux_backend!($libcrux, libcrux_rows, label, inp, keygen, sign, verify, fresh);

        // RustCrypto ml-dsa: deterministic signing; its VerifyingKey caches A, so fresh decodes.
        {
            use ml_dsa::signature::Signer;

            let seed: ml_dsa::Seed = inp.seed.as_slice().try_into().unwrap();

            let sk = ml_dsa::SigningKey::<$p>::from_seed(&seed);

            let vk: ml_dsa::VerifyingKey<$p> = sk.as_ref().clone();

            assert!(vk.encode().as_slice() == inp.pk.as_slice(), "{label}: RustCrypto public key differs");

            let signatures: Vec<ml_dsa::Signature<$p>> = inp
                .signatures
                .iter()
                .map(|s| ml_dsa::Signature::<$p>::try_from(s.as_slice()).unwrap())
                .collect();

            for ((m, s), raw) in inp.messages.iter().zip(&signatures).zip(&inp.signatures) {
                assert!(sk.sign(m).encode().as_slice() == raw.as_slice(), "{label}: RustCrypto signature differs");

                assert!(vk.verify_with_context(m, &[], s), "{label}: RustCrypto rejects crypto-pq's signature");
            }

            keygen.push(("RustCrypto", Box::new(move |_| {
                black_box(ml_dsa::SigningKey::<$p>::from_seed(black_box(&seed)));
            })));

            let messages = inp.messages.clone();

            sign.push(("RustCrypto", Box::new(move |i| {
                black_box(sk.sign(black_box(&messages[i % 16])));
            })));

            let encoded = vk.encode();

            let (messages, sigs) = (inp.messages.clone(), signatures.clone());

            verify.push(("RustCrypto", Box::new(move |i| {
                assert!(vk.verify_with_context(&messages[i % 16], &[], black_box(&sigs[i % 16])));
            })));

            let (messages, sigs) = (inp.messages.clone(), signatures.clone());

            fresh.push(("RustCrypto", Box::new(move |i| {
                let key = ml_dsa::VerifyingKey::<$p>::decode(black_box(&encoded));

                assert!(key.verify_with_context(&messages[i % 16], &[], black_box(&sigs[i % 16])));
            })));
        }
    }};
}

struct Fresh<'a>(&'a dyn Cpq, usize);

impl Fresh<'_> {
    fn fresh(&self, pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
        self.0.fresh(self.1, pk, message, signature)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let count: usize = args.get(1).map_or(31, |r| r.parse().unwrap());

    let filter = args.get(2).cloned();

    #[cfg(pb_oqs)]
    oqs::init();

    let variants: [&'static dyn Cpq; 4] = [&v_new::Imp, &v_base::Imp, &v_aa::Imp, &v_wb::Imp];

    let messages: Vec<Vec<u8>> = (0..16).map(|i| format!("crypto-pq benchmark message {i}").into_bytes()).collect();

    // The seed and messages of the earlier dsa-bench rows, so that the signing loops take the same
    // numbers of attempts.
    let seed: [u8; 32] = core::array::from_fn(|i| i as u8);

    for (set, label) in LABELS.iter().enumerate() {
        if filter.as_deref().is_some_and(|f| !label.contains(f)) {
            continue;
        }

        let keys: Vec<(Vec<u8>, Vec<u8>)> = variants.iter().map(|v| v.keygen(set, &seed)).collect();

        assert!(keys.iter().all(|k| *k == keys[0]), "{label}: crypto-pq keys differ");

        let (pk, sk) = keys[0].clone();

        let signers: Vec<_> = variants.iter().map(|v| v.signer(set, &sk)).collect();

        let verifiers: Vec<_> = variants.iter().map(|v| v.verifier(set, &pk)).collect();

        let signatures: Vec<Vec<u8>> = messages
            .iter()
            .map(|m| {
                let all: Vec<Vec<u8>> = signers.iter().map(|s| s(m)).collect();

                assert!(all.iter().all(|s| *s == all[0]), "{label}: crypto-pq signatures differ");

                for (verify, v) in verifiers.iter().zip(&variants) {
                    assert!(verify(m, &all[0]) && v.fresh(set, &pk, m, &all[0]), "{label}: crypto-pq rejects its signature");
                }

                all[0].clone()
            })
            .collect();

        let inp = Inputs { seed, pk: pk.clone(), messages: messages.clone(), signatures: signatures.clone() };

        let mut rows: [Vec<(&'static str, Call)>; 5] = Default::default();

        let names = ["new", "base", "aa", "wb"];

        for (c, v) in variants.iter().enumerate() {
            let v: &'static dyn Cpq = *v;

            rows[0].push((names[c], Box::new(move |_| v.generate(set, black_box(&seed)))));

            let signer = v.signer(set, &sk);

            let ms = messages.clone();

            rows[1].push((names[c], Box::new(move |i| {
                black_box(signer(black_box(&ms[i % 16])));
            })));

            let hedged = v.hedged(set, &sk);

            for m in &messages[..4] {
                assert!(v.fresh(set, &pk, m, &hedged(m)), "{label}: crypto-pq rejects its hedged signature");
            }

            let ms = messages.clone();

            rows[2].push((names[c], Box::new(move |i| {
                black_box(hedged(black_box(&ms[i % 16])));
            })));

            let verifier = v.verifier(set, &pk);

            let (ms, ss) = (messages.clone(), signatures.clone());

            rows[3].push((names[c], Box::new(move |i| {
                assert!(verifier(black_box(&ms[i % 16]), black_box(&ss[i % 16])));
            })));

            let (key, ms, ss) = (pk.clone(), messages.clone(), signatures.clone());

            rows[4].push((names[c], Box::new(move |i| {
                assert!(v.fresh(set, black_box(&key), &ms[i % 16], black_box(&ss[i % 16])));
            })));
        }

        let cpq = Fresh(variants[0], set);

        match set {
            0 => rows_of!(ml_dsa::MlDsa44, ml_dsa_44, aws_lc_rs::signature::ML_DSA_44_SIGNING, aws_lc_rs::signature::ML_DSA_44, oqs::sig::Algorithm::MlDsa44, label, &inp, cpq, &mut rows),
            1 => rows_of!(ml_dsa::MlDsa65, ml_dsa_65, aws_lc_rs::signature::ML_DSA_65_SIGNING, aws_lc_rs::signature::ML_DSA_65, oqs::sig::Algorithm::MlDsa65, label, &inp, cpq, &mut rows),
            _ => rows_of!(ml_dsa::MlDsa87, ml_dsa_87, aws_lc_rs::signature::ML_DSA_87_SIGNING, aws_lc_rs::signature::ML_DSA_87, oqs::sig::Algorithm::MlDsa87, label, &inp, cpq, &mut rows),
        }

        let names: Vec<&str> = rows[4].iter().map(|c| c.0).collect();

        println!("SAME {label}: {} (pk {} B, signature {} B)", names.join(", "), pk.len(), signatures[0].len());

        // PB_CHECK=1: the output checks only.
        if std::env::var_os("PB_CHECK").is_some() {
            continue;
        }

        let [keygen, sign, signh, verify, fresh] = rows;

        for (op, row) in [("keygen", keygen), ("sign", sign), ("signh", signh), ("verify", verify), ("fresh", fresh)] {
            // Hedged signing takes a random number of attempts: longer samples average them.
            let sample_ns = if op == "signh" { 8.0 * SAMPLE_NS } else { SAMPLE_NS };

            rounds(count, &format!("{label}/{op}"), sample_ns, row);
        }
    }
}

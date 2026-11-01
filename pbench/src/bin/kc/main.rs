// Keccak category benchmark (crypto-pq 1.0.1 against its rivals), derived from the review-perf
// harness (fm-rust10) of the 2026-10-19 run. Every rival's deterministic outputs are compared with
// crypto-pq's before anything is measured; a mismatch drops that rival's rows for the case and is
// reported. Modes and timing method: fm.rs.

#[cfg(not(any(feature = "flavor-base", feature = "flavor-aa", feature = "flavor-wb")))]
extern crate cpq_new as crypto_pq;

#[cfg(feature = "flavor-base")]
extern crate cpq_base as crypto_pq;

#[cfg(feature = "flavor-aa")]
extern crate cpq_aa as crypto_pq;

#[cfg(feature = "flavor-wb")]
extern crate cpq_wb as crypto_pq;

extern crate rustcrypto_slh as slh_dsa;

mod fm;

use std::hint::black_box;

use crypto_pq::{
    KemAlgorithm, KeyFormat, KeyGenOptions, SignOptions, SignatureAlgorithm, VerifyOptions, hazmat,
};

use fm::{Check, List, bytes, hex, same, timed};

const CPQ: &str = "crypto-pq";

const MESSAGES: usize = 16;

const CUSTOM: &[u8] = b"crypto-pq benchmark";

const SIZES: [(usize, &str); 2] = [(64, "64B"), (1024, "1KiB")];

// Every Keccak case, and every ML-KEM row of RustCrypto, libcrux and aws-lc-rs (category 3).
// ML-DSA, SLH-DSA and FrodoKEM run in the dsa, slh and meas binaries.
fn wanted(case: &str) -> bool {
    match case.split_once('/') {
        Some((family, _)) => !["ML-DSA", "SLH-DSA", "Frodo"].iter().any(|f| family.starts_with(f)),
        None => true,
    }
}

// ---------------------------------------------------------------------------------------------
// Symmetric cases. Each row computes the same output from (key, data); the first row is crypto-pq
// and the reference.

type OneShot = Box<dyn Fn(&[u8], &[u8], &mut [u8])>;

fn row(imp: &str, function: impl Fn(&[u8], &[u8], &mut [u8]) + 'static) -> (&str, OneShot) {
    (imp, Box::new(function))
}

fn case(list: &mut List, name: &str, key: &[u8], data: &[u8], size: usize, rows: Vec<(&str, OneShot)>) {
    if !list.wants_case(name) {
        return;
    }

    let mut reference = vec![0u8; size];

    (rows[0].1)(key, data, &mut reference);

    println!("FP {name} {}", hex(&reference));

    for (imp, function) in rows {
        let mut out = vec![0u8; size];

        function(key, data, &mut out);

        if !list.same(name, imp, &out, &reference) {
            continue;
        }

        let (key, data) = (key.to_vec(), data.to_vec());

        list.add(name, imp, move |n| {
            let mut out = vec![0u8; size];

            timed(n, || {
                function(black_box(&key), black_box(&data), &mut out);

                black_box(&out);
            })
        });
    }
}

fn messages() -> Vec<Vec<u8>> {
    (0..MESSAGES)
        .map(|i| format!("crypto-pq benchmark message {i}").into_bytes())
        .collect()
}

// SHA3-224/256/384/512. aws-lc-rs has no SHA3-224.
macro_rules! sha3_case {
    ($list:expr, $name:expr, $d:expr, $suffix:expr, $size:expr, $cpq:expr, $rc:ty, $libcrux:path, $tiny:ident, $aws:expr) => {{
        use sha3::Digest;

        let mut rows = vec![
            row(CPQ, |_, d, o| $cpq.digest_into(d, o).unwrap()),
            row("RustCrypto", |_, d, o| o.copy_from_slice(&<$rc>::digest(d))),
            row("libcrux", |_, d, o| o.copy_from_slice(&$libcrux(d))),
            row("tiny-keccak", |_, d, o| {
                use tiny_keccak::Hasher;

                let mut h = tiny_keccak::Sha3::$tiny();

                h.update(d);

                h.finalize(o);
            }),
        ];

        #[cfg(pb_c)]
        if let Some(algorithm) = $aws {
            rows.push(row("aws-lc-rs", move |_, d, o| o.copy_from_slice(aws_lc_rs::digest::digest(algorithm, d).as_ref())));
        }

        case($list, &format!("{}/{}", $name, $suffix), &[], $d, $size, rows);
    }};
}

fn sha3s(list: &mut List) {
    let data = bytes(16384);

    for (length, suffix) in [(64, "64B"), (1024, "1KiB"), (16384, "16KiB")] {
        let d = &data[..length];

        sha3_case!(list, "sha3-224", d, suffix, 28, crypto_pq::SHA3_224, sha3::Sha3_224, libcrux_sha3::sha224, v224, None::<&'static aws_lc_rs::digest::Algorithm>);

        sha3_case!(list, "sha3-256", d, suffix, 32, crypto_pq::SHA3_256, sha3::Sha3_256, libcrux_sha3::sha256, v256, Some(&aws_lc_rs::digest::SHA3_256));

        sha3_case!(list, "sha3-384", d, suffix, 48, crypto_pq::SHA3_384, sha3::Sha3_384, libcrux_sha3::sha384, v384, Some(&aws_lc_rs::digest::SHA3_384));

        sha3_case!(list, "sha3-512", d, suffix, 64, crypto_pq::SHA3_512, sha3::Sha3_512, libcrux_sha3::sha512, v512, Some(&aws_lc_rs::digest::SHA3_512));
    }
}

// SHAKE128/256: input 64 B or 1 KiB, output 32 B or 1 KiB.
fn shakes(list: &mut List) {
    use shake::{ExtendableOutput, Update, XofReader};

    let data = bytes(1024);

    for (length, suffix) in SIZES {
        let d = &data[..length];

        for (out_size, out_suffix) in [(32, "32B"), (1024, "1KiB")] {
            let name = |base: &str| format!("{base}/in{suffix}/out{out_suffix}");

            case(list, &name("shake128"), &[], d, out_size, vec![
                row(CPQ, |_, d, o| crypto_pq::SHAKE128.digest_into(d, o).unwrap()),
                row("RustCrypto", |_, d, o| {
                    let mut h = shake::Shake128::default();

                    h.update(d);

                    h.finalize_xof().read(o);
                }),
                row("libcrux", |_, d, o| {
                    if o.len() == 32 {
                        o.copy_from_slice(&libcrux_sha3::shake128::<32>(d));
                    } else {
                        o.copy_from_slice(&libcrux_sha3::shake128::<1024>(d));
                    }
                }),
                row("tiny-keccak", |_, d, o| {
                    use tiny_keccak::{Hasher, Xof};

                    let mut h = tiny_keccak::Shake::v128();

                    h.update(d);

                    h.squeeze(o);
                }),
            ]);

            case(list, &name("shake256"), &[], d, out_size, vec![
                row(CPQ, |_, d, o| crypto_pq::SHAKE256.digest_into(d, o).unwrap()),
                row("RustCrypto", |_, d, o| {
                    let mut h = shake::Shake256::default();

                    h.update(d);

                    h.finalize_xof().read(o);
                }),
                row("libcrux", |_, d, o| {
                    if o.len() == 32 {
                        o.copy_from_slice(&libcrux_sha3::shake256::<32>(d));
                    } else {
                        o.copy_from_slice(&libcrux_sha3::shake256::<1024>(d));
                    }
                }),
                row("tiny-keccak", |_, d, o| {
                    use tiny_keccak::{Hasher, Xof};

                    let mut h = tiny_keccak::Shake::v256();

                    h.update(d);

                    h.squeeze(o);
                }),
            ]);
        }
    }
}

// cSHAKE128/256 with a customization string and 32-byte output. crypto-pq's configured algorithm
// precomputes the customization state, so the rivals also run with a cloned prepared state.
fn cshakes(list: &mut List) {
    let data = bytes(1024);

    let options = crypto_pq::XofOptions::default().with_customization(CUSTOM);

    let c128 = crypto_pq::CSHAKE128.configure(&options).unwrap();

    let c256 = crypto_pq::CSHAKE256.configure(&options).unwrap();

    for (length, suffix) in SIZES {
        let d = &data[..length];

        let rc = {
            use cshake::digest::CustomizedInit;

            cshake::CShake128::new_customized(CUSTOM)
        };

        let tk = tiny_keccak::CShake::v128(b"", CUSTOM);

        case(list, &format!("cshake128/{suffix}"), &[], d, 32, vec![
            row(CPQ, move |_, d, o| c128.digest_into(d, o).unwrap()),
            row("RustCrypto", |_, d, o| {
                use cshake::digest::{CustomizedInit, ExtendableOutput, Update, XofReader};

                let mut x = cshake::CShake128::new_customized(CUSTOM);

                x.update(d);

                x.finalize_xof().read(o);
            }),
            row("RustCrypto (state reused)", move |_, d, o| {
                use cshake::digest::{ExtendableOutput, Update, XofReader};

                let mut x = rc.clone();

                x.update(d);

                x.finalize_xof().read(o);
            }),
            row("tiny-keccak", |_, d, o| {
                use tiny_keccak::Hasher;

                let mut x = tiny_keccak::CShake::v128(b"", CUSTOM);

                x.update(d);

                x.finalize(o);
            }),
            row("tiny-keccak (state reused)", move |_, d, o| {
                use tiny_keccak::Hasher;

                let mut x = tk.clone();

                x.update(d);

                x.finalize(o);
            }),
        ]);

        let rc = {
            use cshake::digest::CustomizedInit;

            cshake::CShake256::new_customized(CUSTOM)
        };

        let tk = tiny_keccak::CShake::v256(b"", CUSTOM);

        case(list, &format!("cshake256/{suffix}"), &[], d, 32, vec![
            row(CPQ, move |_, d, o| c256.digest_into(d, o).unwrap()),
            row("RustCrypto", |_, d, o| {
                use cshake::digest::{CustomizedInit, ExtendableOutput, Update, XofReader};

                let mut x = cshake::CShake256::new_customized(CUSTOM);

                x.update(d);

                x.finalize_xof().read(o);
            }),
            row("RustCrypto (state reused)", move |_, d, o| {
                use cshake::digest::{ExtendableOutput, Update, XofReader};

                let mut x = rc.clone();

                x.update(d);

                x.finalize_xof().read(o);
            }),
            row("tiny-keccak", |_, d, o| {
                use tiny_keccak::Hasher;

                let mut x = tiny_keccak::CShake::v256(b"", CUSTOM);

                x.update(d);

                x.finalize(o);
            }),
            row("tiny-keccak (state reused)", move |_, d, o| {
                use tiny_keccak::Hasher;

                let mut x = tk.clone();

                x.update(d);

                x.finalize(o);
            }),
        ]);
    }
}

// KMAC128/256: 32-byte key, customization string, 32-byte output.
fn kmacs(list: &mut List) {
    let data = bytes(1024);

    let key = bytes(32);

    let options = crypto_pq::MacOptions::default().with_customization(CUSTOM);

    let k128 = crypto_pq::KMAC128.configure(&options).unwrap();

    let k256 = crypto_pq::KMAC256.configure(&options.with_length(32)).unwrap();

    for (length, suffix) in SIZES {
        let d = &data[..length];

        case(list, &format!("kmac128/{suffix}"), &key, d, 32, vec![
            row(CPQ, move |k, d, o| k128.digest_into(k, d, o).unwrap()),
            row("tiny-keccak", |k, d, o| {
                use tiny_keccak::Hasher;

                let mut x = tiny_keccak::Kmac::v128(k, CUSTOM);

                x.update(d);

                x.finalize(o);
            }),
            row("sha3-kmac", |k, d, o| {
                let mut x = sha3_kmac::Kmac128::new(k, CUSTOM).unwrap();

                x.update(d);

                x.finalize_into(o);
            }),
        ]);

        case(list, &format!("kmac256/{suffix}"), &key, d, 32, vec![
            row(CPQ, move |k, d, o| k256.digest_into(k, d, o).unwrap()),
            row("tiny-keccak", |k, d, o| {
                use tiny_keccak::Hasher;

                let mut x = tiny_keccak::Kmac::v256(k, CUSTOM);

                x.update(d);

                x.finalize(o);
            }),
            row("sha3-kmac", |k, d, o| {
                let mut x = sha3_kmac::Kmac256::new(k, CUSTOM).unwrap();

                x.update(d);

                x.finalize_into(o);
            }),
        ]);
    }
}

// ---------------------------------------------------------------------------------------------
// ML-KEM and FrodoKEM.

struct KemRef {
    ek: Vec<u8>,
    ct: Vec<u8>,
    ss: Vec<u8>,
}

fn cpq_kem(list: &mut List, algorithm: KemAlgorithm, label: &str, seed_size: usize, randomness_size: usize) -> KemRef {
    let seed = bytes(seed_size);

    let m = bytes(randomness_size);

    let pair = hazmat::generate_kem_key_pair(algorithm, &seed).unwrap();

    let ek = pair.public_key.export_key(KeyFormat::Raw).unwrap();

    let encapsulation = hazmat::encapsulate(&pair.public_key, &m).unwrap();

    let ss = pair.private_key.decapsulate(&encapsulation.ciphertext).unwrap();

    assert_eq!(&*ss, &*encapsulation.shared_secret);

    println!("FP {label}/ek {}", hex(&crypto_pq::SHA3_256.digest(&ek)));

    println!("FP {label}/ct {}", hex(&crypto_pq::SHA3_256.digest(&encapsulation.ciphertext)));

    let reference = KemRef {
        ek,
        ct: encapsulation.ciphertext.clone(),
        ss: ss.to_vec(),
    };

    list.add(&format!("{label}/keygen"), "crypto-pq (seeded)", move |n| {
        timed(n, || {
            black_box(hazmat::generate_kem_key_pair(algorithm, black_box(&seed)).unwrap());
        })
    });

    let public_key = pair.public_key.clone();

    list.add(&format!("{label}/encaps"), CPQ, move |n| {
        timed(n, || {
            black_box(hazmat::encapsulate(&public_key, black_box(&m)).unwrap());
        })
    });

    let private_key = pair.private_key;

    let ciphertext = encapsulation.ciphertext;

    list.add(&format!("{label}/decaps"), CPQ, move |n| {
        timed(n, || {
            black_box(private_key.decapsulate(black_box(&ciphertext)).unwrap());
        })
    });

    reference
}

macro_rules! rustcrypto_kem {
    ($list:expr, $p:ty, $label:expr, $reference:expr) => {{
        let label: &str = $label;

        let reference: &KemRef = $reference;

        let result = (|| -> Check {
            use ml_kem::KeyExport;
            use ml_kem::kem::Decapsulate;

            let seed: ml_kem::Seed = bytes(64).as_slice().try_into().unwrap();

            let m: ml_kem::B32 = bytes(32).as_slice().try_into().unwrap();

            let dk = ml_kem::DecapsulationKey::<$p>::from_seed(seed.clone());

            let ek = dk.encapsulation_key().clone();

            same("ek", ek.to_bytes().as_slice(), &reference.ek)?;

            let (ct, k) = ek.encapsulate_deterministic(&m);

            same("ct", ct.as_slice(), &reference.ct)?;

            same("ss", k.as_slice(), &reference.ss)?;

            same("decaps", dk.decapsulate(&ct).as_slice(), &reference.ss)?;

            $list.add(&format!("{label}/keygen"), "RustCrypto", move |n| {
                timed(n, || {
                    black_box(ml_kem::DecapsulationKey::<$p>::from_seed(black_box(seed.clone())));
                })
            });

            $list.add(&format!("{label}/encaps"), "RustCrypto", move |n| {
                timed(n, || {
                    black_box(ek.encapsulate_deterministic(black_box(&m)));
                })
            });

            $list.add(&format!("{label}/decaps"), "RustCrypto", move |n| {
                timed(n, || {
                    black_box(dk.decapsulate(black_box(&ct)));
                })
            });

            Ok(())
        })();

        $list.report("RustCrypto", label, result);
    }};
}

// Returns the FIPS 203 expanded decapsulation key from libcrux (after its outputs matched), so
// that aws-lc-rs can decapsulate crypto-pq's ciphertext with crypto-pq's key.
macro_rules! libcrux_kem {
    ($list:expr, $module:ident, $label:expr, $reference:expr) => {{
        let a = libcrux_kem!(@one $list, $module, portable, "libcrux-portable", "libcrux-portable unpacked", $label, $reference);

        #[cfg(target_arch = "x86_64")]
        let b = if std::arch::is_x86_feature_detected!("avx2") {
            libcrux_kem!(@one $list, $module, avx2, "libcrux-avx2", "libcrux-avx2 unpacked", $label, $reference)
        } else {
            None
        };

        #[cfg(target_arch = "aarch64")]
        let b = libcrux_kem!(@one $list, $module, neon, "libcrux-neon", "libcrux-neon unpacked", $label, $reference);

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let b: Option<Vec<u8>> = None;

        a.or(b)
    }};

    (@one $list:expr, $module:ident, $backend:ident, $name:expr, $unpacked:expr, $label:expr, $reference:expr) => {{
        use libcrux_ml_kem::$module::$backend as imp;

        let label: &str = $label;

        let reference: &KemRef = $reference;

        let mut expanded: Option<Vec<u8>> = None;

        let result = (|| -> Check {
            let seed: [u8; 64] = bytes(64).try_into().unwrap();

            let m: [u8; 32] = bytes(32).try_into().unwrap();

            let pair = imp::generate_key_pair(seed);

            same("ek", pair.pk(), &reference.ek)?;

            let (ct, ss) = imp::encapsulate(pair.public_key(), m);

            same("ct", ct.as_slice(), &reference.ct)?;

            same("ss", &ss, &reference.ss)?;

            same("decaps", &imp::decapsulate(pair.private_key(), &ct), &reference.ss)?;

            // The unpacked keys keep the sampled matrix A and the NTT-domain vectors between calls.
            let unpacked = imp::unpacked::generate_key_pair(seed);

            let mut unpacked_public = imp::unpacked::init_public_key();

            imp::unpacked::unpacked_public_key(pair.public_key(), &mut unpacked_public);

            let (uct, uss) = imp::unpacked::encapsulate(&unpacked_public, m);

            same("unpacked ct", uct.as_slice(), &reference.ct)?;

            same("unpacked ss", &uss, &reference.ss)?;

            same("unpacked decaps", &imp::unpacked::decapsulate(&unpacked, &ct), &reference.ss)?;

            expanded = Some(pair.sk().to_vec());

            $list.add(&format!("{label}/keygen"), $name, move |n| {
                timed(n, || {
                    black_box(imp::generate_key_pair(black_box(seed)));
                })
            });

            let public_key = pair.public_key().clone();

            $list.add(&format!("{label}/encaps"), $name, move |n| {
                timed(n, || {
                    black_box(imp::encapsulate(&public_key, black_box(m)));
                })
            });

            let private_key = pair.private_key().clone();

            let ciphertext = ct.clone();

            $list.add(&format!("{label}/decaps"), $name, move |n| {
                timed(n, || {
                    black_box(imp::decapsulate(&private_key, black_box(&ciphertext)));
                })
            });

            $list.add(&format!("{label}/encaps"), $unpacked, move |n| {
                timed(n, || {
                    black_box(imp::unpacked::encapsulate(&unpacked_public, black_box(m)));
                })
            });

            $list.add(&format!("{label}/decaps"), $unpacked, move |n| {
                timed(n, || {
                    black_box(imp::unpacked::decapsulate(&unpacked, black_box(&ct)));
                })
            });

            Ok(())
        })();

        $list.report($name, label, result);

        expanded
    }};
}

// aws-lc-rs has no seeded key generation or derandomized encapsulation: keygen and encaps draw
// from its DRBG. Encapsulation uses crypto-pq's public key; decapsulation uses crypto-pq's
// private key (the expanded FIPS 203 form) and ciphertext, and must give crypto-pq's secret.
macro_rules! aws_kem {
    ($list:expr, $algorithm:expr, $label:expr, $reference:expr, $expanded:expr) => {{
        use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey};

        let label: &str = $label;

        let reference: &KemRef = $reference;

        let expanded: Option<Vec<u8>> = $expanded;

        let result = (|| -> Check {
            let expanded = expanded.ok_or("no expanded key to import (libcrux check failed)")?;

            let dk = DecapsulationKey::new(&$algorithm, &expanded).map_err(|e| format!("import dk: {e:?}"))?;

            let ss = dk.decapsulate(Ciphertext::from(reference.ct.as_slice())).map_err(|e| format!("decaps: {e:?}"))?;

            same("decaps of crypto-pq's ciphertext", ss.as_ref(), &reference.ss)?;

            let ek = EncapsulationKey::new(&$algorithm, &reference.ek).map_err(|e| format!("import ek: {e:?}"))?;

            let (ct, ss) = ek.encapsulate().map_err(|e| format!("encaps: {e:?}"))?;

            let ss2 = dk.decapsulate(Ciphertext::from(ct.as_ref())).map_err(|e| format!("decaps: {e:?}"))?;

            same("round trip", ss2.as_ref(), ss.as_ref())?;

            $list.add(&format!("{label}/keygen"), "aws-lc-rs (DRBG)", move |n| {
                timed(n, || {
                    black_box(DecapsulationKey::generate(&$algorithm).unwrap());
                })
            });

            $list.add(&format!("{label}/encaps"), "aws-lc-rs (DRBG)", move |n| {
                timed(n, || {
                    black_box(ek.encapsulate().unwrap());
                })
            });

            let ct = reference.ct.clone();

            $list.add(&format!("{label}/decaps"), "aws-lc-rs", move |n| {
                timed(n, || {
                    black_box(dk.decapsulate(Ciphertext::from(black_box(ct.as_slice()))).unwrap());
                })
            });

            Ok(())
        })();

        $list.report("aws-lc-rs", label, result);
    }};
}

// ---------------------------------------------------------------------------------------------
// ML-DSA and SLH-DSA.

struct SigRef {
    pk: Vec<u8>,
    msgs: Vec<Vec<u8>>,
    sigs: Vec<Vec<u8>>,
    public_key: crypto_pq::SignaturePublicKey,
}

fn cpq_signature(list: &mut List, algorithm: SignatureAlgorithm, label: &str, seed_size: usize, rotate: bool) -> SigRef {
    let seed = bytes(seed_size);

    let pair = hazmat::generate_signature_key_pair(algorithm, &seed).unwrap();

    let pk = pair.public_key.export_key(KeyFormat::Raw).unwrap();

    let mut msgs = messages();

    if !rotate {
        msgs.truncate(1);
    }

    let options = SignOptions::default().with_deterministic(true);

    let sigs: Vec<Vec<u8>> = msgs.iter().map(|m| pair.private_key.sign(m, &options).unwrap()).collect();

    for (m, s) in msgs.iter().zip(&sigs) {
        assert!(pair.public_key.verify(s, m, &VerifyOptions::default()));
    }

    println!("FP {label}/pk {}", hex(&crypto_pq::SHA3_256.digest(&pk)));

    println!("FP {label}/sig0 {}", hex(&crypto_pq::SHA3_256.digest(&sigs[0])));

    let reference = SigRef {
        pk,
        msgs: msgs.clone(),
        sigs: sigs.clone(),
        public_key: pair.public_key.clone(),
    };

    list.add(&format!("{label}/keygen"), "crypto-pq (seeded)", move |n| {
        timed(n, || {
            black_box(hazmat::generate_signature_key_pair(algorithm, black_box(&seed)).unwrap());
        })
    });

    let private_key = pair.private_key;

    let sign_msgs = msgs.clone();

    let mut next = 0;

    list.add(&format!("{label}/sign"), CPQ, move |n| {
        timed(n, || {
            let m = &sign_msgs[next % sign_msgs.len()];

            next += 1;

            black_box(private_key.sign(black_box(m), &options).unwrap());
        })
    });

    let public_key = pair.public_key;

    let mut next = 0;

    list.add(&format!("{label}/verify"), CPQ, move |n| {
        timed(n, || {
            let i = next % sigs.len();

            next += 1;

            assert!(public_key.verify(black_box(&sigs[i]), &msgs[i], &VerifyOptions::default()));
        })
    });

    reference
}

macro_rules! rustcrypto_mldsa {
    ($list:expr, $p:ty, $label:expr, $reference:expr) => {{
        let label: &str = $label;

        let reference: &SigRef = $reference;

        let result = (|| -> Check {
            use ml_dsa::signature::Signer;

            let seed: ml_dsa::Seed = bytes(32).as_slice().try_into().unwrap();

            let sk = ml_dsa::SigningKey::<$p>::from_seed(&seed);

            let vk: ml_dsa::VerifyingKey<$p> = sk.as_ref().clone();

            same("pk", vk.encode().as_slice(), &reference.pk)?;

            for (m, s) in reference.msgs.iter().zip(&reference.sigs) {
                same("sig", sk.sign(m).encode().as_slice(), s)?;
            }

            let sigs: Vec<ml_dsa::Signature<$p>> = reference
                .sigs
                .iter()
                .map(|s| ml_dsa::Signature::<$p>::try_from(s.as_slice()).unwrap())
                .collect();

            let msgs = reference.msgs.clone();

            $list.add(&format!("{label}/keygen"), "RustCrypto", move |n| {
                timed(n, || {
                    black_box(ml_dsa::SigningKey::<$p>::from_seed(black_box(&seed)));
                })
            });

            let sign_msgs = msgs.clone();

            let mut next = 0;

            $list.add(&format!("{label}/sign"), "RustCrypto", move |n| {
                timed(n, || {
                    let m = &sign_msgs[next % sign_msgs.len()];

                    next += 1;

                    black_box(sk.sign(black_box(m)));
                })
            });

            let mut next = 0;

            $list.add(&format!("{label}/verify"), "RustCrypto", move |n| {
                timed(n, || {
                    let i = next % sigs.len();

                    next += 1;

                    assert!(vk.verify_with_context(&msgs[i], &[], black_box(&sigs[i])));
                })
            });

            Ok(())
        })();

        $list.report("RustCrypto", label, result);
    }};
}

macro_rules! libcrux_mldsa {
    ($list:expr, $module:ident, $label:expr, $reference:expr) => {{
        libcrux_mldsa!(@one $list, $module, portable, "libcrux-portable", $label, $reference);

        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("avx2") {
            libcrux_mldsa!(@one $list, $module, avx2, "libcrux-avx2", $label, $reference);
        }

        #[cfg(target_arch = "aarch64")]
        libcrux_mldsa!(@one $list, $module, neon, "libcrux-neon", $label, $reference);
    }};

    (@one $list:expr, $module:ident, $backend:ident, $name:expr, $label:expr, $reference:expr) => {{
        use libcrux_ml_dsa::$module::$backend as imp;

        let label: &str = $label;

        let reference: &SigRef = $reference;

        let result = (|| -> Check {
            let seed: [u8; 32] = bytes(32).try_into().unwrap();

            let pair = imp::generate_key_pair(seed);

            same("pk", pair.verification_key.as_slice(), &reference.pk)?;

            for (m, s) in reference.msgs.iter().zip(&reference.sigs) {
                let sig = imp::sign(&pair.signing_key, m, b"", [0u8; 32]).map_err(|e| format!("sign: {e:?}"))?;

                same("sig", sig.as_slice(), s)?;
            }

            let sigs: Vec<_> = reference
                .sigs
                .iter()
                .map(|s| libcrux_ml_dsa::MLDSASignature::new(s.as_slice().try_into().unwrap()))
                .collect();

            let msgs = reference.msgs.clone();

            $list.add(&format!("{label}/keygen"), $name, move |n| {
                timed(n, || {
                    black_box(imp::generate_key_pair(black_box(seed)));
                })
            });

            let signing_key = pair.signing_key;

            let sign_msgs = msgs.clone();

            let mut next = 0;

            $list.add(&format!("{label}/sign"), $name, move |n| {
                timed(n, || {
                    let m = &sign_msgs[next % sign_msgs.len()];

                    next += 1;

                    black_box(imp::sign(&signing_key, black_box(m), b"", [0u8; 32]).unwrap());
                })
            });

            let verification_key = pair.verification_key;

            let mut next = 0;

            $list.add(&format!("{label}/verify"), $name, move |n| {
                timed(n, || {
                    let i = next % sigs.len();

                    next += 1;

                    assert!(imp::verify(&verification_key, &msgs[i], b"", black_box(&sigs[i])).is_ok());
                })
            });

            Ok(())
        })();

        $list.report($name, label, result);
    }};
}

// aws-lc-rs signs ML-DSA hedged only (fresh rnd from its DRBG): its signatures cannot equal the
// deterministic ones, so they are checked by crypto-pq's verify instead.
macro_rules! aws_mldsa {
    ($list:expr, $signing:expr, $verification:expr, $label:expr, $reference:expr) => {{
        use aws_lc_rs::signature::{KeyPair, ParsedPublicKey, PqdsaKeyPair};

        let label: &str = $label;

        let reference: &SigRef = $reference;

        let result = (|| -> Check {
            let seed = bytes(32);

            let pair = PqdsaKeyPair::from_seed(&$signing, &seed).map_err(|e| format!("keygen: {e:?}"))?;

            same("pk", pair.public_key().as_ref(), &reference.pk)?;

            let parsed = ParsedPublicKey::new(&$verification, pair.public_key().as_ref()).map_err(|e| format!("parse: {e:?}"))?;

            for (m, s) in reference.msgs.iter().zip(&reference.sigs) {
                parsed.verify_sig(m, s).map_err(|e| format!("verify of crypto-pq signature: {e:?}"))?;
            }

            let mut out = vec![0u8; $signing.signature_len()];

            for m in &reference.msgs {
                pair.sign(m, &mut out).map_err(|e| format!("sign: {e:?}"))?;

                if !reference.public_key.verify(&out, m, &VerifyOptions::default()) {
                    return Err("crypto-pq rejects its hedged signature".to_string());
                }
            }

            $list.add(&format!("{label}/keygen"), "aws-lc-rs", move |n| {
                timed(n, || {
                    black_box(PqdsaKeyPair::from_seed(&$signing, black_box(&seed)).unwrap());
                })
            });

            let sign_msgs = reference.msgs.clone();

            let mut next = 0;

            $list.add(&format!("{label}/sign"), "aws-lc-rs (hedged)", move |n| {
                timed(n, || {
                    let m = &sign_msgs[next % sign_msgs.len()];

                    next += 1;

                    black_box(pair.sign(black_box(m), &mut out).unwrap());
                })
            });

            let msgs = reference.msgs.clone();

            let sigs = reference.sigs.clone();

            let mut next = 0;

            $list.add(&format!("{label}/verify"), "aws-lc-rs", move |n| {
                timed(n, || {
                    let i = next % sigs.len();

                    next += 1;

                    assert!(parsed.verify_sig(&msgs[i], black_box(&sigs[i])).is_ok());
                })
            });

            Ok(())
        })();

        $list.report("aws-lc-rs", label, result);
    }};
}

macro_rules! rustcrypto_slh {
    ($list:expr, $p:ty, $n:expr, $label:expr, $reference:expr) => {{
        let label: &str = $label;

        let reference: &SigRef = $reference;

        let result = (|| -> Check {
            let n: usize = $n;

            let seed = bytes(3 * n);

            let sk = slh_dsa::SigningKey::<$p>::slh_keygen_internal(&seed[..n], &seed[n..2 * n], &seed[2 * n..]);

            let vk: slh_dsa::VerifyingKey<$p> = sk.as_ref().clone();

            same("pk", vk.to_bytes().as_slice(), &reference.pk)?;

            let m = reference.msgs[0].clone();

            let sig = sk.try_sign_with_context(&m, &[], None).map_err(|e| format!("sign: {e:?}"))?;

            same("sig", sig.to_bytes().as_slice(), &reference.sigs[0])?;

            $list.add(&format!("{label}/keygen"), "RustCrypto", move |count| {
                timed(count, || {
                    let seed = black_box(&seed);

                    black_box(slh_dsa::SigningKey::<$p>::slh_keygen_internal(&seed[..n], &seed[n..2 * n], &seed[2 * n..]));
                })
            });

            let sign_m = m.clone();

            $list.add(&format!("{label}/sign"), "RustCrypto", move |count| {
                timed(count, || {
                    black_box(sk.try_sign_with_context(black_box(&sign_m), &[], None).unwrap());
                })
            });

            $list.add(&format!("{label}/verify"), "RustCrypto", move |count| {
                timed(count, || {
                    assert!(vk.try_verify_with_context(&m, &[], black_box(&sig)).is_ok());
                })
            });

            Ok(())
        })();

        $list.report("RustCrypto", label, result);
    }};
}
// FrodoKEM's seed (s || seedSE || z) and encapsulation randomness (u || salt) sizes, found by the
// lengths hazmat accepts.
fn frodo_sizes(algorithm: KemAlgorithm) -> (usize, usize) {
    let seed = (1..=256).find(|&n| hazmat::generate_kem_key_pair(algorithm, &bytes(n)).is_ok()).unwrap();

    let pair = hazmat::generate_kem_key_pair(algorithm, &bytes(seed)).unwrap();

    let randomness = (1..=256).find(|&n| hazmat::encapsulate(&pair.public_key, &bytes(n)).is_ok()).unwrap();

    println!("NOTE\t{}\tseed {seed} randomness {randomness}", algorithm.name());

    (seed, randomness)
}

// The public API as an application calls it: key generation from the OS entropy with the pairwise
// self-test (the default, row "crypto-pq") and without it (row "crypto-pq (no self-test)"). The
// seeded hazmat rows are informational.
fn api_keygen(list: &mut List, label: &str, generate: fn(&KeyGenOptions)) {
    for (name, self_test) in [(CPQ, true), ("crypto-pq (no self-test)", false)] {
        let options = KeyGenOptions::default().with_self_test(self_test);

        list.add(&format!("{label}/keygen"), name, move |n| {
            timed(n, || generate(black_box(&options)))
        });
    }
}

fn build(list: &mut List) {
    use crypto_pq::{ML_DSA_44, ML_DSA_65, ML_DSA_87, ML_KEM_512, ML_KEM_768, ML_KEM_1024};

    sha3s(list);

    shakes(list);

    cshakes(list);

    kmacs(list);

    macro_rules! kem {
        ($algorithm:expr, $label:expr, $p:ty, $module:ident, $aws:expr) => {
            if list.family($label) {
                let r = cpq_kem(list, $algorithm, $label, 64, 32);

                api_keygen(list, $label, |o| {
                    black_box($algorithm.generate_key_pair(o).unwrap());
                });

                rustcrypto_kem!(list, $p, $label, &r);

                let expanded = libcrux_kem!(list, $module, $label, &r);

                #[cfg(pb_c)]
                aws_kem!(list, $aws, $label, &r, expanded);

                #[cfg(not(pb_c))]
                drop(expanded);
            }
        };
    }

    kem!(ML_KEM_512, "ML-KEM-512", ml_kem::MlKem512, mlkem512, aws_lc_rs::kem::ML_KEM_512);

    kem!(ML_KEM_768, "ML-KEM-768", ml_kem::MlKem768, mlkem768, aws_lc_rs::kem::ML_KEM_768);

    kem!(ML_KEM_1024, "ML-KEM-1024", ml_kem::MlKem1024, mlkem1024, aws_lc_rs::kem::ML_KEM_1024);

    macro_rules! frodo {
        ($algorithm:expr, $label:expr) => {
            if list.family($label) {
                let (seed, randomness) = frodo_sizes($algorithm);

                cpq_kem(list, $algorithm, $label, seed, randomness);

                api_keygen(list, $label, |o| {
                    black_box($algorithm.generate_key_pair(o).unwrap());
                });
            }
        };
    }

    frodo!(crypto_pq::FRODOKEM_976_SHAKE, "FrodoKEM-976-SHAKE");

    frodo!(crypto_pq::FRODOKEM_1344_SHAKE, "FrodoKEM-1344-SHAKE");

    macro_rules! mldsa {
        ($algorithm:expr, $label:expr, $p:ty, $module:ident, $signing:expr, $verification:expr) => {
            if list.family($label) {
                let r = cpq_signature(list, $algorithm, $label, 32, true);

                api_keygen(list, $label, |o| {
                    black_box($algorithm.generate_key_pair(o).unwrap());
                });

                rustcrypto_mldsa!(list, $p, $label, &r);

                libcrux_mldsa!(list, $module, $label, &r);

                #[cfg(pb_c)]
                aws_mldsa!(list, $signing, $verification, $label, &r);
            }
        };
    }

    mldsa!(ML_DSA_44, "ML-DSA-44", ml_dsa::MlDsa44, ml_dsa_44, aws_lc_rs::signature::ML_DSA_44_SIGNING, aws_lc_rs::signature::ML_DSA_44);

    mldsa!(ML_DSA_65, "ML-DSA-65", ml_dsa::MlDsa65, ml_dsa_65, aws_lc_rs::signature::ML_DSA_65_SIGNING, aws_lc_rs::signature::ML_DSA_65);

    mldsa!(ML_DSA_87, "ML-DSA-87", ml_dsa::MlDsa87, ml_dsa_87, aws_lc_rs::signature::ML_DSA_87_SIGNING, aws_lc_rs::signature::ML_DSA_87);

    if list.family("SLH-DSA-SHAKE-128f") {
        let r = cpq_signature(list, crypto_pq::SLH_DSA_SHAKE_128F, "SLH-DSA-SHAKE-128f", 48, false);

        rustcrypto_slh!(list, slh_dsa::Shake128f, 16, "SLH-DSA-SHAKE-128f", &r);
    }
}

fn main() {
    fm::main(wanted, build);
}

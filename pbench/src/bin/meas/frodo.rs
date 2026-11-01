// Category 8: FrodoKEM and eFrodoKEM, 976 and 1344, AES and SHAKE. Before timing: crypto-pq's
// keys and encapsulations from fixed randomness are compared byte for byte with the rivals that take
// caller randomness (frodo-kem, frodo-kem-rs), and every rival is cross-decapsulated both ways with
// crypto-pq. A rival that fails a check is left out of that parameter set.
use std::hint::black_box;

#[cfg(not(target_family = "wasm"))]
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};

use crate::{Imp, time_row};

// Replays fixed bytes as the random source of the frodo-kem crates.
struct Replay {
    bytes: Vec<u8>,
    at: usize,
}

impl rand_core::TryRng for Replay {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];

        self.try_fill_bytes(&mut b)?;

        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];

        self.try_fill_bytes(&mut b)?;

        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for d in dst {
            *d = self.bytes[self.at % self.bytes.len()];

            self.at += 1;
        }

        Ok(())
    }
}

impl rand_core::TryCryptoRng for Replay {}

// The byte-level operations of one rival on one parameter set.
struct Rival {
    name: &'static str,
    keygen: Box<dyn Fn() -> (Vec<u8>, Vec<u8>)>,
    encaps: Box<dyn Fn(&[u8]) -> (Vec<u8>, Vec<u8>)>,
    decaps: Box<dyn Fn(&[u8], &[u8]) -> Vec<u8>>,
}

macro_rules! fk_rival {
    ($krate:ident, $name:literal, $alg:ident, $seed:expr, $salted:expr) => {{
        let seed: Vec<u8> = $seed;

        let alg = $krate::Algorithm::$alg;

        Rival {
            name: $name,
            keygen: Box::new(move || {
                let (ek, dk) = alg.generate_keypair(&mut Replay { bytes: seed.clone(), at: 0 });

                (ek.value().to_vec(), dk.value().to_vec())
            }),
            encaps: Box::new(move |pk| {
                let ek = $krate::EncryptionKey::from_bytes(alg, pk).unwrap();

                let (ct, ss) = if $salted {
                    let (u, salt) = MU_SALT.split_at(MU_SALT.len() / 2);

                    let (u, salt) = (&u[..alg_len(pk.len())], &salt[..2 * alg_len(pk.len())]);

                    alg.encapsulate(&ek, u, salt).unwrap()
                } else {
                    alg.encapsulate(&ek, &MU_SALT[..alg_len(pk.len())], []).unwrap()
                };

                (ct.value().to_vec(), ss.value().to_vec())
            }),
            decaps: Box::new(move |sk, ct| {
                let dk = $krate::DecryptionKey::from_bytes(alg, sk).unwrap();

                let ct = $krate::Ciphertext::from_bytes(alg, ct).unwrap();

                alg.decapsulate(&dk, &ct).unwrap().0.value().to_vec()
            }),
        }
    }};
}

// The entry of a rival crate that does not build for the target; run skips unnamed rivals.
macro_rules! absent_rival {
    () => {
        Rival {
            name: "",
            keygen: Box::new(|| unreachable!()),
            encaps: Box::new(|_| unreachable!()),
            decaps: Box::new(|_, _| unreachable!()),
        }
    };
}

#[cfg(any(target_family = "wasm", target_arch = "arm"))]
macro_rules! oqs_rival {
    ($alg:ident) => {
        absent_rival!()
    };
}

#[cfg(target_family = "wasm")]
macro_rules! pqc_rival {
    ($m:ident) => {
        absent_rival!()
    };
}

#[cfg(not(any(target_family = "wasm", target_arch = "arm")))]
macro_rules! oqs_rival {
    ($alg:ident) => {{
        Rival {
            name: "oqs",
            keygen: Box::new(|| {
                let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::$alg).unwrap();

                let (pk, sk) = kem.keypair().unwrap();

                (pk.as_ref().to_vec(), sk.as_ref().to_vec())
            }),
            encaps: Box::new(|pk| {
                let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::$alg).unwrap();

                let (ct, ss) = kem.encapsulate(kem.public_key_from_bytes(pk).unwrap()).unwrap();

                (ct.as_ref().to_vec(), ss.as_ref().to_vec())
            }),
            decaps: Box::new(|sk, ct| {
                let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::$alg).unwrap();

                let ss = kem
                    .decapsulate(kem.secret_key_from_bytes(sk).unwrap(), kem.ciphertext_from_bytes(ct).unwrap())
                    .unwrap();

                ss.as_ref().to_vec()
            }),
        }
    }};
}

#[cfg(not(target_family = "wasm"))]
macro_rules! pqc_rival {
    ($m:ident) => {{
        use pqcrypto_frodo::$m;

        Rival {
            name: "pqcrypto-frodo",
            keygen: Box::new(|| {
                let (pk, sk) = $m::keypair();

                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }),
            encaps: Box::new(|pk| {
                let (ss, ct) = $m::encapsulate(&$m::PublicKey::from_bytes(pk).unwrap());

                (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            }),
            decaps: Box::new(|sk, ct| {
                $m::decapsulate(&$m::Ciphertext::from_bytes(ct).unwrap(), &$m::SecretKey::from_bytes(sk).unwrap())
                    .as_bytes()
                    .to_vec()
            }),
        }
    }};
}

// 64 bytes of encapsulation randomness: u in the first half, the salt in the second.
const MU_SALT: [u8; 128] = {
    let mut b = [0u8; 128];

    let mut i = 0;

    while i < 128 {
        b[i] = (i as u8).wrapping_mul(53).wrapping_add(17);

        i += 1;
    }

    b
};

// len_sec / 8 from the public key size: 24 bytes for 976, 32 for 1344.
fn alg_len(pk_len: usize) -> usize {
    if pk_len == 15632 { 24 } else { 32 }
}

struct Set {
    label: &'static str,
    cpq: cpq::KemAlgorithm,
    aa: cpq_aa::KemAlgorithm,
    salted: bool,
    rivals: Vec<Rival>,
}

fn seed_for(cpq_alg: cpq::KemAlgorithm) -> Vec<u8> {
    let probe = cpq::hazmat::generate_kem_key_pair(cpq_alg, &[]);

    assert!(probe.is_err());

    // The seed size is not public; find it from the accepted lengths.
    let size = (1..=256).find(|&n| cpq::hazmat::generate_kem_key_pair(cpq_alg, &vec![0u8; n]).is_ok()).unwrap();

    (0..size).map(|i| (i as u8).wrapping_mul(29).wrapping_add(3)).collect()
}

fn randomness_for(cpq_alg: cpq::KemAlgorithm, pk: &cpq::KemPublicKey) -> Vec<u8> {
    let size = (1..=256).find(|&n| cpq::hazmat::encapsulate(pk, &vec![0u8; n]).is_ok()).unwrap();

    let _ = cpq_alg;

    let half = alg_len(pk.export_key(cpq::KeyFormat::Raw).unwrap().len());

    if size == half {
        MU_SALT[..half].to_vec()
    } else {
        assert_eq!(size, 3 * half);

        let mut r = MU_SALT[..half].to_vec();

        r.extend_from_slice(&MU_SALT[64..64 + 2 * half]);

        r
    }
}

fn sets() -> Vec<Set> {
    let s = |a| seed_for(a);

    vec![
        Set {
            label: "FrodoKEM-976-AES",
            cpq: cpq::FRODOKEM_976_AES,
            aa: cpq_aa::FRODOKEM_976_AES,
            salted: true,
            rivals: vec![
                fk_rival!(frodo_kem, "frodo-kem", FrodoKem976Aes, s(cpq::FRODOKEM_976_AES), true),
                fk_rival!(frodo_kem_rs, "frodo-kem-rs", FrodoKem976Aes, s(cpq::FRODOKEM_976_AES), true),
                oqs_rival!(FrodoKem976Aes),
                pqc_rival!(frodokem976aes),
            ],
        },
        Set {
            label: "FrodoKEM-976-SHAKE",
            cpq: cpq::FRODOKEM_976_SHAKE,
            aa: cpq_aa::FRODOKEM_976_SHAKE,
            salted: true,
            rivals: vec![
                fk_rival!(frodo_kem, "frodo-kem", FrodoKem976Shake, s(cpq::FRODOKEM_976_SHAKE), true),
                fk_rival!(frodo_kem_rs, "frodo-kem-rs", FrodoKem976Shake, s(cpq::FRODOKEM_976_SHAKE), true),
                oqs_rival!(FrodoKem976Shake),
                pqc_rival!(frodokem976shake),
            ],
        },
        Set {
            label: "FrodoKEM-1344-AES",
            cpq: cpq::FRODOKEM_1344_AES,
            aa: cpq_aa::FRODOKEM_1344_AES,
            salted: true,
            rivals: vec![
                fk_rival!(frodo_kem, "frodo-kem", FrodoKem1344Aes, s(cpq::FRODOKEM_1344_AES), true),
                fk_rival!(frodo_kem_rs, "frodo-kem-rs", FrodoKem1344Aes, s(cpq::FRODOKEM_1344_AES), true),
                oqs_rival!(FrodoKem1344Aes),
                pqc_rival!(frodokem1344aes),
            ],
        },
        Set {
            label: "FrodoKEM-1344-SHAKE",
            cpq: cpq::FRODOKEM_1344_SHAKE,
            aa: cpq_aa::FRODOKEM_1344_SHAKE,
            salted: true,
            rivals: vec![
                fk_rival!(frodo_kem, "frodo-kem", FrodoKem1344Shake, s(cpq::FRODOKEM_1344_SHAKE), true),
                fk_rival!(frodo_kem_rs, "frodo-kem-rs", FrodoKem1344Shake, s(cpq::FRODOKEM_1344_SHAKE), true),
                oqs_rival!(FrodoKem1344Shake),
                pqc_rival!(frodokem1344shake),
            ],
        },
        Set {
            label: "eFrodoKEM-976-AES",
            cpq: cpq::EFRODOKEM_976_AES,
            aa: cpq_aa::EFRODOKEM_976_AES,
            salted: false,
            rivals: vec![
                fk_rival!(frodo_kem, "frodo-kem", EphemeralFrodoKem976Aes, s(cpq::EFRODOKEM_976_AES), false),
                fk_rival!(frodo_kem_rs, "frodo-kem-rs", EphemeralFrodoKem976Aes, s(cpq::EFRODOKEM_976_AES), false),
                oqs_rival!(FrodoKem976Aes),
                pqc_rival!(frodokem976aes),
            ],
        },
        Set {
            label: "eFrodoKEM-976-SHAKE",
            cpq: cpq::EFRODOKEM_976_SHAKE,
            aa: cpq_aa::EFRODOKEM_976_SHAKE,
            salted: false,
            rivals: vec![
                fk_rival!(frodo_kem, "frodo-kem", EphemeralFrodoKem976Shake, s(cpq::EFRODOKEM_976_SHAKE), false),
                fk_rival!(frodo_kem_rs, "frodo-kem-rs", EphemeralFrodoKem976Shake, s(cpq::EFRODOKEM_976_SHAKE), false),
                oqs_rival!(FrodoKem976Shake),
                pqc_rival!(frodokem976shake),
            ],
        },
        Set {
            label: "eFrodoKEM-1344-AES",
            cpq: cpq::EFRODOKEM_1344_AES,
            aa: cpq_aa::EFRODOKEM_1344_AES,
            salted: false,
            rivals: vec![
                fk_rival!(frodo_kem, "frodo-kem", EphemeralFrodoKem1344Aes, s(cpq::EFRODOKEM_1344_AES), false),
                fk_rival!(frodo_kem_rs, "frodo-kem-rs", EphemeralFrodoKem1344Aes, s(cpq::EFRODOKEM_1344_AES), false),
                oqs_rival!(FrodoKem1344Aes),
                pqc_rival!(frodokem1344aes),
            ],
        },
        Set {
            label: "eFrodoKEM-1344-SHAKE",
            cpq: cpq::EFRODOKEM_1344_SHAKE,
            aa: cpq_aa::EFRODOKEM_1344_SHAKE,
            salted: false,
            rivals: vec![
                fk_rival!(frodo_kem, "frodo-kem", EphemeralFrodoKem1344Shake, s(cpq::EFRODOKEM_1344_SHAKE), false),
                fk_rival!(frodo_kem_rs, "frodo-kem-rs", EphemeralFrodoKem1344Shake, s(cpq::EFRODOKEM_1344_SHAKE), false),
                oqs_rival!(FrodoKem1344Shake),
                pqc_rival!(frodokem1344shake),
            ],
        },
    ]
}

fn cpq_decaps(alg: cpq::KemAlgorithm, sk: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    Some(alg.import_private_key(sk, cpq::KeyFormat::Raw).ok()?.decapsulate(ct).ok()?.to_vec())
}

// Byte-for-byte keys and encapsulation (frodo-kem crates), then cross-decapsulation both ways.
fn check(set: &Set, rival: &Rival, seed: &[u8], randomness: &[u8]) -> Result<(), String> {
    let pair = cpq::hazmat::generate_kem_key_pair(set.cpq, seed).unwrap();

    let pk = pair.public_key.export_key(cpq::KeyFormat::Raw).unwrap();

    let sk = pair.private_key.export_key(cpq::KeyFormat::Raw).unwrap().to_vec();

    let (rpk, rsk) = (rival.keygen)();

    if rpk.len() != pk.len() || rsk.len() != sk.len() {
        return Err(format!("sizes pk {} sk {} (crypto-pq {} {})", rpk.len(), rsk.len(), pk.len(), sk.len()));
    }

    let deterministic = rival.name.starts_with("frodo-kem");

    if deterministic && (rpk != pk || rsk != sk) {
        return Err("keys from the same seed differ".into());
    }

    let mine = cpq::hazmat::encapsulate(&pair.public_key, randomness).unwrap();

    let (ct, ss) = (rival.encaps)(&pk);

    if deterministic && (ct != mine.ciphertext || ss != mine.shared_secret.to_vec()) {
        return Err("encapsulation from the same randomness differs".into());
    }

    if ct.len() != mine.ciphertext.len() {
        return Err(format!("ciphertext size {} (crypto-pq {})", ct.len(), mine.ciphertext.len()));
    }

    if cpq_decaps(set.cpq, &sk, &ct) != Some(ss) {
        return Err("crypto-pq does not decapsulate the rival's ciphertext".into());
    }

    let other = set.cpq.import_public_key(&rpk, cpq::KeyFormat::Raw).unwrap().encapsulate().unwrap();

    if (rival.decaps)(&rsk, &other.ciphertext) != other.shared_secret.to_vec() {
        return Err("the rival does not decapsulate crypto-pq's ciphertext".into());
    }

    let mut bad = other.ciphertext.clone();

    bad[100] ^= 1;

    if (rival.decaps)(&rsk, &bad) == other.shared_secret.to_vec() {
        return Err("a changed ciphertext gives the same secret".into());
    }

    Ok(())
}

pub fn run(rounds: usize, filter: Option<&str>) {
    #[cfg(not(any(target_family = "wasm", target_arch = "arm")))]
    oqs::init();

    for set in sets() {
        if filter.is_some_and(|f| !set.label.contains(f)) {
            continue;
        }

        let seed = seed_for(set.cpq);

        let pair = cpq::hazmat::generate_kem_key_pair(set.cpq, &seed).unwrap();

        let pair_aa = cpq_aa::hazmat::generate_kem_key_pair(set.aa, &seed).unwrap();

        let pk = pair.public_key.export_key(cpq::KeyFormat::Raw).unwrap();

        let sk = pair.private_key.export_key(cpq::KeyFormat::Raw).unwrap().to_vec();

        assert_eq!(pair_aa.public_key.export_key(cpq_aa::KeyFormat::Raw).unwrap(), pk);

        let randomness = randomness_for(set.cpq, &pair.public_key);

        let ct = cpq::hazmat::encapsulate(&pair.public_key, &randomness).unwrap().ciphertext;

        let mut rivals = Vec::new();

        for rival in set.rivals.iter().filter(|r| !r.name.is_empty()) {
            match check(&set, rival, &seed, &randomness) {
                Ok(()) => {
                    println!("CHECK\t{}\t{}\tok", set.label, rival.name);

                    rivals.push(rival);
                }
                Err(e) => println!("MISMATCH\t{}\t{}\t{e}", set.label, rival.name),
            }
        }

        // Each rival's own key pair and a ciphertext to it, for its encaps and decaps rows.
        let own: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = rivals
            .iter()
            .map(|r| {
                let (rpk, rsk) = (r.keygen)();

                let (rct, _) = (r.encaps)(&rpk);

                (rpk, rsk, rct)
            })
            .collect();

        let (alg, aa) = (set.cpq, set.aa);

        let ops = ["keygen", "keygen-selftest", "encaps", "encaps-fresh", "decaps", "decaps-fresh"];

        for op in ops {
            let label = format!("{}/{op}", set.label);

            if filter.is_some_and(|f| !label.contains(f) && !set.label.contains(f)) {
                continue;
            }

            let mut imps: Vec<Imp> = Vec::new();

            let (seed, randomness, pk, sk, ct) = (&seed, &randomness, &pk, &sk, &ct);

            let (cpq_pk, cpq_sk) = (&pair.public_key, &pair.private_key);

            let (aa_pk, aa_sk) = (&pair_aa.public_key, &pair_aa.private_key);

            match op {
                "keygen" => {
                    imps.push(Imp { name: "crypto-pq", run: Box::new(move || {
                        black_box(cpq::hazmat::generate_kem_key_pair(alg, black_box(seed)).unwrap());
                    }) });

                    imps.push(Imp { name: "crypto-pq-aa", run: Box::new(move || {
                        black_box(cpq_aa::hazmat::generate_kem_key_pair(aa, black_box(seed)).unwrap());
                    }) });
                }
                "keygen-selftest" => {
                    imps.push(Imp { name: "crypto-pq", run: Box::new(move || {
                        black_box(alg.generate_key_pair(&cpq::KeyGenOptions::default()).unwrap());
                    }) });

                    imps.push(Imp { name: "crypto-pq-aa", run: Box::new(move || {
                        black_box(aa.generate_key_pair(&cpq_aa::KeyGenOptions::default()).unwrap());
                    }) });
                }
                "encaps" => {
                    imps.push(Imp { name: "crypto-pq", run: Box::new(move || {
                        black_box(cpq::hazmat::encapsulate(cpq_pk, black_box(randomness)).unwrap());
                    }) });

                    imps.push(Imp { name: "crypto-pq-aa", run: Box::new(move || {
                        black_box(cpq_aa::hazmat::encapsulate(aa_pk, black_box(randomness)).unwrap());
                    }) });
                }
                "encaps-fresh" => {
                    imps.push(Imp { name: "crypto-pq", run: Box::new(move || {
                        let key = alg.import_public_key(black_box(pk), cpq::KeyFormat::Raw).unwrap();

                        black_box(cpq::hazmat::encapsulate(&key, black_box(randomness)).unwrap());
                    }) });

                    imps.push(Imp { name: "crypto-pq-aa", run: Box::new(move || {
                        let key = aa.import_public_key(black_box(pk), cpq_aa::KeyFormat::Raw).unwrap();

                        black_box(cpq_aa::hazmat::encapsulate(&key, black_box(randomness)).unwrap());
                    }) });
                }
                "decaps" => {
                    imps.push(Imp { name: "crypto-pq", run: Box::new(move || {
                        black_box(cpq_sk.decapsulate(black_box(ct)).unwrap());
                    }) });

                    imps.push(Imp { name: "crypto-pq-aa", run: Box::new(move || {
                        black_box(aa_sk.decapsulate(black_box(ct)).unwrap());
                    }) });
                }
                _ => {
                    imps.push(Imp { name: "crypto-pq", run: Box::new(move || {
                        let key = alg.import_private_key(black_box(sk), cpq::KeyFormat::Raw).unwrap();

                        black_box(key.decapsulate(black_box(ct)).unwrap());
                    }) });

                    imps.push(Imp { name: "crypto-pq-aa", run: Box::new(move || {
                        let key = aa.import_private_key(black_box(sk), cpq_aa::KeyFormat::Raw).unwrap();

                        black_box(key.decapsulate(black_box(ct)).unwrap());
                    }) });
                }
            }

            // The rivals work from bytes: their rows include the decode, which is all a fresh key
            // costs them, so they run the same code in the cached and the fresh rows.
            for (r, (rpk, rsk, rct)) in rivals.iter().zip(&own) {
                let run: Box<dyn FnMut()> = match op {
                    "keygen" | "keygen-selftest" => Box::new(move || {
                        black_box((r.keygen)());
                    }),
                    "encaps" | "encaps-fresh" => Box::new(move || {
                        black_box((r.encaps)(black_box(rpk)));
                    }),
                    _ => Box::new(move || {
                        black_box((r.decaps)(black_box(rsk), black_box(rct)));
                    }),
                };

                imps.push(Imp { name: r.name, run });
            }

            time_row(&label, &mut imps, rounds, 2e6);
        }
    }
}

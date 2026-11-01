// HSS/LMS and XMSS/XMSS^MT. Every implementation is wrapped in an Imp: key generation from
// crypto-pq's seed, signing with the key object, verification with a parsed public key and from
// bytes. Public keys and signatures are in the RFC encodings that crypto-pq uses (HSS with its
// level count, XMSS with its OID); a rival with another encoding converts outside the timed region
// only where the conversion is a prefix.
//
// Checks before timing, per set and rival: equal public keys where the rival takes the seed as
// crypto-pq does; the rival's signature verifies under crypto-pq, crypto-pq's under the rival, and
// a signature with one flipped byte fails under both. liboqs (c/stfl.c) exchanges XC/XV lines.

use std::hint::black_box;
use std::time::{Duration, Instant};

use crypto_pq::{
    Error, HSS_LMS, KeyFormat, StateStore, StatefulKeyGenOptions, StatefulParameters,
    StatefulPrivateKey, StatefulSignatureAlgorithm, XMSS, XMSS_MT, hazmat,
};

use crate::CPQ;
use crate::fm::{List, hex, timed};

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

pub fn messages() -> Vec<Vec<u8>> {
    (0..16).map(|i| format!("crypto-pq stateful benchmark message {i}").into_bytes()).collect()
}

trait Signer {
    fn sign(&mut self, message: &[u8]) -> Vec<u8>;

    fn remaining(&self) -> u64;
}

type Verify = Box<dyn Fn(&[u8], &[u8]) -> bool>;

struct Imp {
    name: &'static str,
    keygen: Box<dyn Fn(&[u8]) -> (Box<dyn Signer>, Vec<u8>)>,
    verifier: Box<dyn Fn(&[u8]) -> Verify>,
    verify_bytes: Box<dyn Fn(&[u8], &[u8], &[u8]) -> bool>,
    same_public_key: bool,
}

// ---------------------------------------------------------------------------------------------
// crypto-pq

struct CpqKey(StatefulPrivateKey<MemoryStore>);

impl Signer for CpqKey {
    fn sign(&mut self, message: &[u8]) -> Vec<u8> {
        self.0.sign(message).unwrap()
    }

    fn remaining(&self) -> u64 {
        self.0.remaining_signatures()
    }
}

fn cpq(algorithm: StatefulSignatureAlgorithm, parameters: StatefulParameters<'static>) -> Imp {
    Imp {
        name: CPQ,
        keygen: Box::new(move |seed| {
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

            (Box::new(CpqKey(pair.private_key)) as Box<dyn Signer>, public)
        }),
        verifier: Box::new(move |public| {
            let key = algorithm.import_public_key(public, KeyFormat::Raw).unwrap();

            Box::new(move |message, signature| key.verify(signature, message))
        }),
        verify_bytes: Box::new(move |public, message, signature| {
            algorithm
                .import_public_key(public, KeyFormat::Raw)
                .is_ok_and(|key| key.verify(signature, message))
        }),
        same_public_key: true,
    }
}

// ---------------------------------------------------------------------------------------------
// hbs-lms (Fraunhofer AISEC): HSS in the reference implementation's private-key format, which
// derives I and SEED from its own seed; signing with its auxiliary tree cache.

const HBS_AUX: usize = 1 << 17;

struct HbsKey<H: hbs_lms::HashChain> {
    key: hbs_lms::SigningKey<H>,
    aux: Vec<u8>,
    left: u64,
}

impl<H: hbs_lms::HashChain> Signer for HbsKey<H> {
    fn sign(&mut self, message: &[u8]) -> Vec<u8> {
        self.left -= 1;

        let mut aux = &mut self.aux[..];

        self.key.try_sign_with_aux(message, Some(&mut aux)).unwrap().as_ref().to_vec()
    }

    fn remaining(&self) -> u64 {
        self.left
    }
}

fn hbs<H: hbs_lms::HashChain + 'static>(levels: &'static [(u32, u32)]) -> Imp {
    use hbs_lms::{HssParameter, LmotsAlgorithm, LmsAlgorithm};

    let parameters = move || -> Vec<HssParameter<H>> {
        levels
            .iter()
            .map(|&(h, w)| {
                let lms = match h {
                    5 => LmsAlgorithm::LmsH5,
                    10 => LmsAlgorithm::LmsH10,
                    15 => LmsAlgorithm::LmsH15,
                    _ => unreachable!(),
                };

                let ots = match w {
                    1 => LmotsAlgorithm::LmotsW1,
                    2 => LmotsAlgorithm::LmotsW2,
                    4 => LmotsAlgorithm::LmotsW4,
                    _ => LmotsAlgorithm::LmotsW8,
                };

                HssParameter::new(ots, lms)
            })
            .collect()
    };

    let capacity: u64 = levels.iter().map(|&(h, _)| 1u64 << h).product();

    let verify = |public: &[u8], message: &[u8], signature: &[u8]| hbs_lms::verify::<H>(message, signature, public).is_ok();

    Imp {
        name: "hbs-lms",
        keygen: Box::new(move |seed| {
            let mut s = hbs_lms::Seed::<H>::default();

            let n = s.as_slice().len();

            s.as_mut_slice().copy_from_slice(&seed[seed.len() - n..]);

            let mut aux = vec![0u8; HBS_AUX];

            let (key, public) = {
                let mut slice = &mut aux[..];

                hbs_lms::keygen::<H>(&parameters(), &s, Some(&mut slice)).unwrap()
            };

            let public = public.as_slice().to_vec();

            (Box::new(HbsKey { key, aux, left: capacity }) as Box<dyn Signer>, public)
        }),
        verifier: Box::new(move |public| {
            let public = public.to_vec();

            Box::new(move |message, signature| verify(&public, message, signature))
        }),
        verify_bytes: Box::new(verify),
        same_public_key: false,
    }
}

// ---------------------------------------------------------------------------------------------
// lms-signature (RustCrypto): single-level LMS from I and SEED as RFC 8554 Appendix A derives
// them; its key keeps the whole tree. The HSS encodings add the level count (1) to the public key
// and Nspk (0) to the signature.

// A macro, so that the encodings' bounds resolve on the concrete types.
macro_rules! rc_lms {
    ($mode:ty, $lms:expr, $ots:expr) => {{
        type M = $mode;

        struct Key {
            key: lms_signature::lms::SigningKey<M>,
            rng: getrandom::rand_core::UnwrapErr<getrandom::SysRng>,
        }

        impl Signer for Key {
            fn sign(&mut self, message: &[u8]) -> Vec<u8> {
                use ::signature::RandomizedSignerMut;

                let signature = self.key.try_sign_with_rng(&mut self.rng, message).unwrap();

                let mut out = 0u32.to_be_bytes().to_vec();

                out.extend_from_slice(&Vec::<u8>::from(signature));

                out
            }

            fn remaining(&self) -> u64 {
                u64::from(<M as lms_signature::lms::LmsMode>::LEAVES - self.key.q())
            }
        }

        fn verify(key: &lms_signature::lms::VerifyingKey<M>, message: &[u8], signature: &[u8]) -> bool {
            use ::signature::Verifier;

            signature.len() > 4
                && signature[..4] == [0; 4]
                && lms_signature::lms::Signature::<M>::try_from(&signature[4..]).is_ok_and(|s| key.verify(message, &s).is_ok())
        }

        fn parse(public: &[u8]) -> Option<lms_signature::lms::VerifyingKey<M>> {
            if public.len() < 4 || public[..4] != 1u32.to_be_bytes() {
                return None;
            }

            lms_signature::lms::VerifyingKey::<M>::try_from(&public[4..]).ok()
        }

        Imp {
            name: "RustCrypto",
            keygen: Box::new(|seed| {
                let mut id = [0u8; 16];

                id.copy_from_slice(&seed[..16]);

                let key = lms_signature::lms::SigningKey::<M>::new_from_seed(id.into(), &seed[16..]).unwrap();

                let public_key = key.public();

                let mut public = 1u32.to_be_bytes().to_vec();

                public.extend_from_slice(&($lms as u32).to_be_bytes());

                public.extend_from_slice(&($ots as u32).to_be_bytes());

                public.extend_from_slice(public_key.id().as_ref());

                public.extend_from_slice(public_key.k());

                let rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);

                (Box::new(Key { key, rng }) as Box<dyn Signer>, public)
            }),
            verifier: Box::new(|public| {
                let key = parse(public).unwrap();

                Box::new(move |message, signature| verify(&key, message, signature))
            }),
            verify_bytes: Box::new(|public, message, signature| parse(public).is_some_and(|key| verify(&key, message, signature))),
            same_public_key: true,
        }
    }};
}

// ---------------------------------------------------------------------------------------------
// xmss (RustCrypto): from the 3n-byte seed S_XMSS || SK_PRF || SEED, as crypto-pq's hazmat key.

struct RcXmssKey<P: xmss::XmssParameter> {
    pair: xmss::KeyPair<P>,
    left: u64,
}

impl<P: xmss::XmssParameter> Signer for RcXmssKey<P> {
    fn sign(&mut self, message: &[u8]) -> Vec<u8> {
        self.left -= 1;

        Vec::from(self.pair.signing_key().sign_detached(message).unwrap())
    }

    fn remaining(&self) -> u64 {
        self.left
    }
}

fn rc_xmss_verify<P: xmss::XmssParameter>(key: &xmss::VerifyingKey<P>, message: &[u8], signature: &[u8]) -> bool {
    xmss::DetachedSignature::<P>::try_from(signature).is_ok_and(|s| key.verify_detached(&s, message).is_ok())
}

fn rc_xmss<P: xmss::XmssParameter + 'static>(capacity: u64) -> Imp {
    Imp {
        name: "RustCrypto",
        keygen: Box::new(move |seed| {
            let pair = xmss::KeyPair::<P>::from_seed(seed).unwrap();

            let public = pair.verifying_key().as_ref().to_vec();

            (Box::new(RcXmssKey { pair, left: capacity }) as Box<dyn Signer>, public)
        }),
        verifier: Box::new(|public| {
            let key = xmss::VerifyingKey::<P>::try_from(public).unwrap();

            Box::new(move |message, signature| rc_xmss_verify(&key, message, signature))
        }),
        verify_bytes: Box::new(|public, message, signature| {
            xmss::VerifyingKey::<P>::try_from(public).is_ok_and(|key| rc_xmss_verify(&key, message, signature))
        }),
        same_public_key: true,
    }
}

// ---------------------------------------------------------------------------------------------

fn flipped(signature: &[u8]) -> Vec<u8> {
    let mut bad = signature.to_vec();

    let at = bad.len() / 2;

    bad[at] ^= 1;

    bad
}

fn liboqs_lines() -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let Some(path) = std::env::var_os("OQS_XV") else {
        return Vec::new();
    };

    let unhex = |s: &str| (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect::<Vec<u8>>();

    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter_map(|line| {
            let mut parts = line.split(' ');

            (parts.next()? == "XV").then(|| {
                let label = parts.next().unwrap().to_string();

                (label, unhex(parts.next().unwrap()), unhex(parts.next().unwrap()))
            })
        })
        .collect()
}

// The checks, then the rows: keygen (or keygen-info), sign, verify, verify-fresh.
fn set(list: &mut List, label: &str, seed: Vec<u8>, imps: Vec<Imp>, signing: bool, info: bool) {
    let keygen_case = format!("{label}/{}", if info { "keygen-info" } else { "keygen" });

    let ops = ["sign", "verify", "verify-fresh"].map(|op| format!("{label}/{op}"));

    let first_case = format!("{label}/keygen+sign1");

    let multi_level = signing && (label.starts_with("HSS2") || label.starts_with("XMSSMT"));

    if !list.wants_case(&keygen_case)
        && !(signing && ops.iter().any(|c| list.wants_case(c)))
        && !(multi_level && list.wants_case(&first_case))
    {
        return;
    }

    let messages = messages();

    let message = &messages[0];

    let (mut key, public) = (imps[0].keygen)(&seed);

    let signature = key.sign(message);

    let reference_verify = &imps[0].verify_bytes;

    println!("FP {label}/pk {}", hex(&public));

    println!("XC {label} {} {}", hex(&public), hex(&signature));

    // Key generation and signing count when the rival's key and signature are right (crypto-pq
    // accepts the signature and rejects it flipped; equal keys where the seeds map); verification
    // counts when the rival accepts crypto-pq's signature, with both its key forms, and rejects it
    // flipped.
    let mut good = vec![(true, true); imps.len()];

    for (i, imp) in imps.iter().enumerate() {
        let (mut rival, rival_public) = (imp.keygen)(&seed);

        let rival_signature = rival.sign(message);

        let signing_result = if imp.same_public_key && rival_public != public {
            Err("public key differs from crypto-pq's".to_string())
        } else if !reference_verify(&rival_public, message, &rival_signature) {
            Err("crypto-pq rejects its signature".to_string())
        } else if reference_verify(&rival_public, message, &flipped(&rival_signature)) {
            Err("crypto-pq accepts its signature with a flipped byte".to_string())
        } else {
            Ok(())
        };

        let verify_result = if !(imp.verify_bytes)(&public, message, &signature) {
            Err("it rejects crypto-pq's signature (verify rows dropped)".to_string())
        } else if (imp.verify_bytes)(&public, message, &flipped(&signature)) {
            Err("it accepts crypto-pq's signature with a flipped byte (verify rows dropped)".to_string())
        } else if !(imp.verifier)(&public)(message, &signature) {
            Err("its parsed key rejects crypto-pq's signature (verify rows dropped)".to_string())
        } else {
            Ok(())
        };

        if imp.same_public_key && i > 0 && rival_public == public {
            println!("NOTE\t{}\t{label}: public key equal to crypto-pq's (signature {})", imp.name, if rival_signature == signature { "equal" } else { "differs" });
        }

        good[i] = (list.check(imp.name, label, signing_result), list.check(imp.name, label, verify_result));
    }

    for (oqs_label, oqs_public, oqs_signature) in liboqs_lines() {
        if oqs_label != label {
            continue;
        }

        let result = if !reference_verify(&oqs_public, message, &oqs_signature) {
            Err("crypto-pq rejects its signature".to_string())
        } else if reference_verify(&oqs_public, message, &flipped(&oqs_signature)) {
            Err("crypto-pq accepts its signature with a flipped byte".to_string())
        } else {
            Ok(())
        };

        if oqs_public == public {
            println!("NOTE\tliboqs\t{label}: public key equal to crypto-pq's (signature {})", if oqs_signature == signature { "equal" } else { "differs" });
        }

        list.check("liboqs", label, result);
    }

    // Sixteen signatures by one crypto-pq key, which every implementation verifies.
    let (signed_public, signed) = if signing {
        let (mut k, public) = (imps[0].keygen)(&seed);

        let signed: Vec<(Vec<u8>, Vec<u8>)> = messages.iter().map(|m| (m.clone(), k.sign(m))).collect();

        (std::rc::Rc::new(public), std::rc::Rc::new(signed))
    } else {
        Default::default()
    };

    let imps: Vec<(Imp, (bool, bool))> = imps.into_iter().zip(good).collect();

    let seed = std::rc::Rc::new(seed);

    for (imp, (signs, verifies)) in imps {
        let imp = std::rc::Rc::new(imp);

        if signs {
            let (imp, seed) = (imp.clone(), seed.clone());

            list.add(&keygen_case, imp.name, move |n| {
                timed(n, || {
                    black_box((imp.keygen)(black_box(&seed)));
                })
            });
        }

        // Multi-level keys: key generation and the first signature together. crypto-pq
        // builds and signs every level's tree at key generation (D-64), RustCrypto xmss and hbs-lms
        // build the top tree only and the rest at the first signature, so only the sum is the same
        // work.
        if signs && multi_level {
            let (imp, seed) = (imp.clone(), seed.clone());

            let message = messages[0].clone();

            list.add(&first_case, imp.name, move |n| {
                timed(n, || {
                    let (mut key, _) = (imp.keygen)(black_box(&seed));

                    black_box(key.sign(black_box(&message)));
                })
            });
        }

        if !signing {
            continue;
        }

        if signs {
            let (imp, seed) = (imp.clone(), seed.clone());

            let messages = messages.clone();

            let mut key: Option<Box<dyn Signer>> = None;

            let mut next = 0;

            // An exhausted key is replaced outside the measured time.
            list.add(&ops[0], imp.name, move |n| {
                let mut elapsed = Duration::ZERO;

                for _ in 0..n {
                    if key.as_ref().is_none_or(|k| k.remaining() == 0) {
                        key = Some((imp.keygen)(&seed).0);
                    }

                    let k = key.as_mut().unwrap();

                    let message = &messages[next % messages.len()];

                    next += 1;

                    let start = Instant::now();

                    black_box(k.sign(black_box(message)));

                    elapsed += start.elapsed();
                }

                elapsed
            });
        }

        if !verifies {
            continue;
        }

        let (verify_case, fresh_case) = (&ops[1], &ops[2]);

        let parsed = (imp.verifier)(&signed_public);

        {
            let signed = signed.clone();

            let mut next = 0;

            list.add(verify_case, imp.name, move |n| {
                timed(n, || {
                    let (message, signature) = &signed[next % signed.len()];

                    next += 1;

                    assert!(parsed(black_box(message), black_box(signature)));
                })
            });
        }

        {
            let (imp, signed, public) = (imp.clone(), signed.clone(), signed_public.clone());

            let mut next = 0;

            list.add(fresh_case, imp.name, move |n| {
                timed(n, || {
                    let (message, signature) = &signed[next % signed.len()];

                    next += 1;

                    assert!((imp.verify_bytes)(black_box(&public), black_box(message), black_box(signature)));
                })
            });
        }
    }
}

fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

fn lms_seed(m: usize) -> Vec<u8> {
    (0..16 + m).map(|i| (i as u8).wrapping_mul(29).wrapping_add(11)).collect()
}

fn hbs_for(hash: &str, m: usize, levels: &'static [(u32, u32)]) -> Imp {
    match (hash, m) {
        ("SHA256", 32) => hbs::<hbs_lms::Sha256_256>(levels),
        ("SHA256", _) => hbs::<hbs_lms::Sha256_192>(levels),
        (_, 32) => hbs::<hbs_lms::Shake256_256>(levels),
        _ => hbs::<hbs_lms::Shake256_192>(levels),
    }
}

// RFC 8554 type codes: LMS_SHA256_M32_H5 = 5, H10 = 6; LMOTS_SHA256_N32_W1..W8 = 1..4. The
// crate's H15 tree (2^16 - 1 nodes) is not an array size that its hybrid-array supports.
fn rc_lms_for(h: u32, w: u32) -> Option<Imp> {
    use lms_signature::lms::*;
    use lms_signature::ots::*;

    Some(match (h, w) {
        (5, 1) => rc_lms!(LmsSha256M32H5<LmsOtsSha256N32W1>, 5, 1),
        (5, 2) => rc_lms!(LmsSha256M32H5<LmsOtsSha256N32W2>, 5, 2),
        (5, 4) => rc_lms!(LmsSha256M32H5<LmsOtsSha256N32W4>, 5, 3),
        (5, 8) => rc_lms!(LmsSha256M32H5<LmsOtsSha256N32W8>, 5, 4),
        (10, 1) => rc_lms!(LmsSha256M32H10<LmsOtsSha256N32W1>, 6, 1),
        (10, 2) => rc_lms!(LmsSha256M32H10<LmsOtsSha256N32W2>, 6, 2),
        (10, 4) => rc_lms!(LmsSha256M32H10<LmsOtsSha256N32W4>, 6, 3),
        (10, 8) => rc_lms!(LmsSha256M32H10<LmsOtsSha256N32W8>, 6, 4),
        _ => return None,
    })
}

// Labels: LMS-<hash>-M<m>-H<h>-W<w> (one level) and HSS2-SHA256-M32-H<h>W<w>-H<h>W<w>.
pub fn lms(list: &mut List) {
    for hash in ["SHA256", "SHAKE"] {
        for m in [32, 24] {
            for (h, info) in [(5, false), (10, false), (15, true)] {
                for w in [1, 2, 4, 8] {
                    if info && (hash != "SHA256" || m != 32 || w != 4) {
                        continue;
                    }

                    let label = format!("LMS-{hash}-M{m}-H{h}-W{w}");

                    let names: &'static [(&'static str, &'static str)] = leak([(
                        &*leak(format!("LMS_{hash}_M{m}_H{h}")).as_str(),
                        &*leak(format!("LMOTS_{hash}_N{m}_W{w}")).as_str(),
                    )]);

                    let levels: &'static [(u32, u32)] = leak([(h, w)]);

                    let mut imps = vec![cpq(HSS_LMS, StatefulParameters::Levels(names))];

                    if hash == "SHA256" && m == 32 {
                        imps.push(hbs_for(hash, m, levels));

                        imps.extend(rc_lms_for(h, w));
                    } else if std::env::var_os("SHA_HBS_ALL").is_some() {
                        // hbs-lms writes the SHA-256 M32 type codes for every hash and size, so
                        // these fail the checks (SHA_HBS_ALL=1 shows it).
                        imps.push(hbs_for(hash, m, levels));
                    }

                    set(list, &label, lms_seed(m), imps, !info, info);
                }
            }
        }
    }

    for levels in [[(5u32, 8u32), (5, 8)], [(10, 4), (5, 8)]] {
        let label = format!("HSS2-SHA256-M32-H{}W{}-H{}W{}", levels[0].0, levels[0].1, levels[1].0, levels[1].1);

        let names: Vec<(&'static str, &'static str)> = levels
            .iter()
            .map(|&(h, w)| (leak(format!("LMS_SHA256_M32_H{h}")).as_str(), leak(format!("LMOTS_SHA256_N32_W{w}")).as_str()))
            .collect();

        let names: &'static [(&'static str, &'static str)] = Box::leak(names.into_boxed_slice());

        let levels: &'static [(u32, u32)] = leak(levels);

        let imps = vec![cpq(HSS_LMS, StatefulParameters::Levels(names)), hbs_for("SHA256", 32, levels)];

        set(list, &label, lms_seed(32), imps, true, false);
    }
}

fn xmss_seed(n: usize) -> Vec<u8> {
    (0..3 * n).map(|i| (i as u8).wrapping_mul(37).wrapping_add(5)).collect()
}

// Labels: the parameter-set names.
pub fn xmss(list: &mut List) {
    use xmss::*;

    let sets: Vec<(&'static str, usize, u64, bool, Imp)> = vec![
        ("XMSS-SHA2_10_256", 32, 1 << 10, false, rc_xmss::<XmssSha2_10_256>(1 << 10)),
        ("XMSS-SHA2_10_192", 24, 1 << 10, false, rc_xmss::<XmssSha2_10_192>(1 << 10)),
        ("XMSS-SHAKE256_10_256", 32, 1 << 10, false, rc_xmss::<XmssShake256_10_256>(1 << 10)),
        ("XMSS-SHAKE256_10_192", 24, 1 << 10, false, rc_xmss::<XmssShake256_10_192>(1 << 10)),
        ("XMSS-SHA2_16_256", 32, 1 << 16, true, rc_xmss::<XmssSha2_16_256>(1 << 16)),
        ("XMSSMT-SHA2_20/2_256", 32, 1 << 20, false, rc_xmss::<XmssMtSha2_20_2_256>(1 << 20)),
        ("XMSSMT-SHA2_20/4_256", 32, 1 << 20, false, rc_xmss::<XmssMtSha2_20_4_256>(1 << 20)),
        ("XMSSMT-SHA2_20/2_192", 24, 1 << 20, false, rc_xmss::<XmssMtSha2_20_2_192>(1 << 20)),
        ("XMSSMT-SHA2_20/4_192", 24, 1 << 20, false, rc_xmss::<XmssMtSha2_20_4_192>(1 << 20)),
        ("XMSSMT-SHAKE256_20/2_256", 32, 1 << 20, false, rc_xmss::<XmssMtShake256_20_2_256>(1 << 20)),
        ("XMSSMT-SHAKE256_20/4_256", 32, 1 << 20, false, rc_xmss::<XmssMtShake256_20_4_256>(1 << 20)),
        ("XMSSMT-SHAKE256_20/2_192", 24, 1 << 20, false, rc_xmss::<XmssMtShake256_20_2_192>(1 << 20)),
        ("XMSSMT-SHAKE256_20/4_192", 24, 1 << 20, false, rc_xmss::<XmssMtShake256_20_4_192>(1 << 20)),
    ];

    for (name, n, _, info, rival) in sets {
        let algorithm = if name.starts_with("XMSSMT") { XMSS_MT } else { XMSS };

        let imps = vec![cpq(algorithm, StatefulParameters::Name(name)), rival];

        set(list, name, xmss_seed(n), imps, !info, info);
    }
}

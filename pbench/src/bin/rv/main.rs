// SHA-2 category benchmark (sha-eng): SHA-2, HMAC, HKDF, HSS/LMS and XMSS/XMSS^MT of crypto-pq
// against its Rust rivals; liboqs runs from c/stfl.c with the same timing loop. Every rival's
// deterministic outputs are compared with crypto-pq's before anything is measured (a mismatch
// drops that rival's rows for the case and is reported). Stateful signatures, whose rivals derive
// keys or randomizers differently, are cross-verified both ways; equal public keys are reported
// where the derivations agree. Modes and timing method: fm.rs.

#[cfg(not(any(feature = "flavor-base", feature = "flavor-aa")))]
extern crate cpq_new as crypto_pq;

#[cfg(feature = "flavor-base")]
extern crate cpq_base as crypto_pq;

#[cfg(feature = "flavor-aa")]
extern crate cpq_aa as crypto_pq;

mod fm;
mod stfl;

use std::hint::black_box;

use crypto_pq::{HashAlgorithm, KdfOptions};

use fm::{List, bytes, hex, timed};

pub const CPQ: &str = "crypto-pq";

// Info rows (H15 and h16 key generation) run only with SHA_INFO=1.
fn wanted(case: &str) -> bool {
    !case.contains("info") || std::env::var_os("SHA_INFO").is_some()
}

type OneShot = Box<dyn Fn(&[u8], &[u8], &mut [u8])>;

fn row(imp: &str, function: impl Fn(&[u8], &[u8], &mut [u8]) + 'static) -> (&str, OneShot) {
    (imp, Box::new(function))
}

// Each row computes the same output from (key, data); the first row is crypto-pq and the
// reference.
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

// ---------------------------------------------------------------------------------------------
// SHA-2

#[derive(Clone, Copy)]
enum Sha {
    S224,
    S256,
    S384,
    S512,
    S512_224,
    S512_256,
}

impl Sha {
    fn name(self) -> &'static str {
        match self {
            Sha::S224 => "sha224",
            Sha::S256 => "sha256",
            Sha::S384 => "sha384",
            Sha::S512 => "sha512",
            Sha::S512_224 => "sha512_224",
            Sha::S512_256 => "sha512_256",
        }
    }

    fn cpq(self) -> HashAlgorithm {
        match self {
            Sha::S224 => crypto_pq::SHA_224,
            Sha::S256 => crypto_pq::SHA_256,
            Sha::S384 => crypto_pq::SHA_384,
            Sha::S512 => crypto_pq::SHA_512,
            Sha::S512_224 => crypto_pq::SHA_512_224,
            Sha::S512_256 => crypto_pq::SHA_512_256,
        }
    }

    fn size(self) -> usize {
        match self {
            Sha::S224 | Sha::S512_224 => 28,
            Sha::S256 | Sha::S512_256 => 32,
            Sha::S384 => 48,
            Sha::S512 => 64,
        }
    }

    #[cfg(pb_c)]
    fn aws(self) -> Option<&'static aws_lc_rs::digest::Algorithm> {
        use aws_lc_rs::digest as d;

        match self {
            Sha::S224 => Some(&d::SHA224),
            Sha::S256 => Some(&d::SHA256),
            Sha::S384 => Some(&d::SHA384),
            Sha::S512 => Some(&d::SHA512),
            Sha::S512_224 => None,
            Sha::S512_256 => Some(&d::SHA512_256),
        }
    }

    #[cfg(pb_c)]
    fn ring(self) -> Option<&'static ring::digest::Algorithm> {
        use ring::digest as d;

        match self {
            Sha::S256 => Some(&d::SHA256),
            Sha::S384 => Some(&d::SHA384),
            Sha::S512 => Some(&d::SHA512),
            Sha::S512_256 => Some(&d::SHA512_256),
            _ => None,
        }
    }

    fn rc_oneshot(self, d: &[u8], o: &mut [u8]) {
        use sha2::Digest;

        match self {
            Sha::S224 => o.copy_from_slice(&sha2::Sha224::digest(d)),
            Sha::S256 => o.copy_from_slice(&sha2::Sha256::digest(d)),
            Sha::S384 => o.copy_from_slice(&sha2::Sha384::digest(d)),
            Sha::S512 => o.copy_from_slice(&sha2::Sha512::digest(d)),
            Sha::S512_224 => o.copy_from_slice(&sha2::Sha512_224::digest(d)),
            Sha::S512_256 => o.copy_from_slice(&sha2::Sha512_256::digest(d)),
        }
    }

    fn libcrux_oneshot(self, d: &[u8], o: &mut [u8]) -> Option<()> {
        match self {
            Sha::S224 => o.copy_from_slice(&libcrux_sha2::sha224(d)),
            Sha::S256 => o.copy_from_slice(&libcrux_sha2::sha256(d)),
            Sha::S384 => o.copy_from_slice(&libcrux_sha2::sha384(d)),
            Sha::S512 => o.copy_from_slice(&libcrux_sha2::sha512(d)),
            _ => return None,
        }

        Some(())
    }
}

fn rc_stream<D: sha2::Digest>(d: &[u8], o: &mut [u8]) {
    let mut h = D::new();

    for chunk in d.chunks(64) {
        h.update(chunk);
    }

    o.copy_from_slice(&h.finalize());
}

fn libcrux_stream<H: libcrux_sha2::Digest<N> + Default, const N: usize>(d: &[u8], o: &mut [u8]) {
    let mut h = H::default();

    for chunk in d.chunks(64) {
        h.update(chunk);
    }

    let mut out = [0u8; N];

    h.finish(&mut out);

    o.copy_from_slice(&out);
}

fn hashes(list: &mut List) {
    let data = bytes(16384);

    for sha in [Sha::S224, Sha::S256, Sha::S384, Sha::S512, Sha::S512_224, Sha::S512_256] {
        let size = sha.size();

        for (length, suffix) in [(0, "0B"), (64, "64B"), (1024, "1KiB"), (16384, "16KiB")] {
            let d = &data[..length];

            let algorithm = sha.cpq();

            let mut rows = vec![
                row(CPQ, move |_, d, o| algorithm.digest_into(d, o).unwrap()),
                row("RustCrypto", move |_, d, o| sha.rc_oneshot(d, o)),
            ];

            #[cfg(pb_c)]
            if let Some(a) = sha.aws() {
                rows.push(row("aws-lc-rs", move |_, d, o| o.copy_from_slice(aws_lc_rs::digest::digest(a, d).as_ref())));
            }

            #[cfg(pb_c)]
            if let Some(a) = sha.ring() {
                rows.push(row("ring", move |_, d, o| o.copy_from_slice(ring::digest::digest(a, d).as_ref())));
            }

            if sha.libcrux_oneshot(&[], &mut vec![0; size]).is_some() {
                rows.push(row("libcrux", move |_, d, o| sha.libcrux_oneshot(d, o).unwrap()));
            }

            case(list, &format!("{}/{suffix}", sha.name()), &[], d, size, rows);
        }

        // Streaming: the input in 64-byte updates.
        for (length, suffix) in [(1024, "1KiB"), (16384, "16KiB")] {
            let d = &data[..length];

            let algorithm = sha.cpq();

            let mut rows = vec![
                row(CPQ, move |_, d, o| {
                    let mut h = algorithm.create();

                    for chunk in d.chunks(64) {
                        h.update(chunk);
                    }

                    h.digest_into(o).unwrap();
                }),
                row("RustCrypto", move |_, d, o| match sha {
                    Sha::S224 => rc_stream::<sha2::Sha224>(d, o),
                    Sha::S256 => rc_stream::<sha2::Sha256>(d, o),
                    Sha::S384 => rc_stream::<sha2::Sha384>(d, o),
                    Sha::S512 => rc_stream::<sha2::Sha512>(d, o),
                    Sha::S512_224 => rc_stream::<sha2::Sha512_224>(d, o),
                    Sha::S512_256 => rc_stream::<sha2::Sha512_256>(d, o),
                }),
            ];

            #[cfg(pb_c)]
            if let Some(a) = sha.aws() {
                rows.push(row("aws-lc-rs", move |_, d, o| {
                    let mut c = aws_lc_rs::digest::Context::new(a);

                    for chunk in d.chunks(64) {
                        c.update(chunk);
                    }

                    o.copy_from_slice(c.finish().as_ref());
                }));
            }

            #[cfg(pb_c)]
            if let Some(a) = sha.ring() {
                rows.push(row("ring", move |_, d, o| {
                    let mut c = ring::digest::Context::new(a);

                    for chunk in d.chunks(64) {
                        c.update(chunk);
                    }

                    o.copy_from_slice(c.finish().as_ref());
                }));
            }

            match sha {
                Sha::S224 => rows.push(row("libcrux", |_, d, o| libcrux_stream::<libcrux_sha2::Sha224, 28>(d, o))),
                Sha::S256 => rows.push(row("libcrux", |_, d, o| libcrux_stream::<libcrux_sha2::Sha256, 32>(d, o))),
                Sha::S384 => rows.push(row("libcrux", |_, d, o| libcrux_stream::<libcrux_sha2::Sha384, 48>(d, o))),
                Sha::S512 => rows.push(row("libcrux", |_, d, o| libcrux_stream::<libcrux_sha2::Sha512, 64>(d, o))),
                _ => {}
            }

            case(list, &format!("{}/stream64/{suffix}", sha.name()), &[], d, size, rows);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// HMAC: key setup plus a 64-byte message; 1 KiB and 16 KiB under a key set up once (crypto-pq:
// Mac::reset).

#[derive(Clone, Copy)]
enum HmacHash {
    S224,
    S256,
    S384,
    S512,
}

fn rc_hmac<D>(key: &[u8], d: &[u8], o: &mut [u8])
where
    hmac::Hmac<D>: hmac::KeyInit + hmac::Mac,
    D: hmac::digest::block_api::EagerHash,
{
    use hmac::{KeyInit, Mac};

    let mut m = <hmac::Hmac<D> as KeyInit>::new_from_slice(key).unwrap();

    m.update(d);

    o.copy_from_slice(&m.finalize().into_bytes());
}

fn rc_hmac_reused<D>(base: &hmac::Hmac<D>, d: &[u8], o: &mut [u8])
where
    hmac::Hmac<D>: hmac::Mac + Clone,
    D: hmac::digest::block_api::EagerHash,
{
    use hmac::Mac;

    let mut m = base.clone();

    m.update(d);

    o.copy_from_slice(&m.finalize().into_bytes());
}

fn macs(list: &mut List) {
    let data = bytes(16384);

    let key: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(3)).collect();

    for hash in [HmacHash::S224, HmacHash::S256, HmacHash::S384, HmacHash::S512] {
        let (name, cpq, size) = match hash {
            HmacHash::S224 => ("hmac-sha224", crypto_pq::HMAC_SHA_224, 28),
            HmacHash::S256 => ("hmac-sha256", crypto_pq::HMAC_SHA_256, 32),
            HmacHash::S384 => ("hmac-sha384", crypto_pq::HMAC_SHA_384, 48),
            HmacHash::S512 => ("hmac-sha512", crypto_pq::HMAC_SHA_512, 64),
        };

        #[cfg(pb_c)]
        let aws = match hash {
            HmacHash::S224 => aws_lc_rs::hmac::HMAC_SHA224,
            HmacHash::S256 => aws_lc_rs::hmac::HMAC_SHA256,
            HmacHash::S384 => aws_lc_rs::hmac::HMAC_SHA384,
            HmacHash::S512 => aws_lc_rs::hmac::HMAC_SHA512,
        };

        #[cfg(pb_c)]
        let ring_alg = match hash {
            HmacHash::S224 => None,
            HmacHash::S256 => Some(ring::hmac::HMAC_SHA256),
            HmacHash::S384 => Some(ring::hmac::HMAC_SHA384),
            HmacHash::S512 => Some(ring::hmac::HMAC_SHA512),
        };

        let libcrux = match hash {
            HmacHash::S224 => None,
            HmacHash::S256 => Some(libcrux_hmac::Algorithm::Sha256),
            HmacHash::S384 => Some(libcrux_hmac::Algorithm::Sha384),
            HmacHash::S512 => Some(libcrux_hmac::Algorithm::Sha512),
        };

        let rc_oneshot = move |k: &[u8], d: &[u8], o: &mut [u8]| match hash {
            HmacHash::S224 => rc_hmac::<sha2::Sha224>(k, d, o),
            HmacHash::S256 => rc_hmac::<sha2::Sha256>(k, d, o),
            HmacHash::S384 => rc_hmac::<sha2::Sha384>(k, d, o),
            HmacHash::S512 => rc_hmac::<sha2::Sha512>(k, d, o),
        };

        // Key setup plus 64 bytes.
        {
            let mut rows = vec![
                row(CPQ, move |k, d, o| cpq.digest_into(k, d, o).unwrap()),
                row("RustCrypto", rc_oneshot),
            ];

            #[cfg(pb_c)]
            rows.push(row("aws-lc-rs", move |k, d, o| {
                let key = aws_lc_rs::hmac::Key::new(aws, k);

                o.copy_from_slice(aws_lc_rs::hmac::sign(&key, d).as_ref());
            }));

            #[cfg(pb_c)]
            if let Some(a) = ring_alg {
                rows.push(row("ring", move |k, d, o| {
                    let key = ring::hmac::Key::new(a, k);

                    o.copy_from_slice(ring::hmac::sign(&key, d).as_ref());
                }));
            }

            if let Some(a) = libcrux {
                rows.push(row("libcrux", move |k, d, o| libcrux_hmac::hmac(a, k, d, o)));
            }

            case(list, &format!("{name}/key+64B"), &key, &data[..64], size, rows);
        }

        // Reused key: the rivals key once outside the timed region; libcrux has only the one-shot
        // call, which keys every time.
        for (length, suffix) in [(1024, "1KiB"), (16384, "16KiB")] {
            // crypto-pq keys once too: one MacKey, then per message a Mac from it.
            let keyed = cpq.key(&key).unwrap();

            let mut rows = vec![
                row(CPQ, move |_, d, o| {
                    let mut mac = keyed.create();

                    mac.update(d);

                    mac.digest_into(o).unwrap();
                }),
            ];

            #[cfg(pb_c)]
            {
                let aws_key = aws_lc_rs::hmac::Key::new(aws, &key);

                rows.push(row("aws-lc-rs", move |_, d, o| o.copy_from_slice(aws_lc_rs::hmac::sign(&aws_key, d).as_ref())));
            }

            {
                use hmac::KeyInit;

                match hash {
                    HmacHash::S224 => {
                        let base = hmac::Hmac::<sha2::Sha224>::new_from_slice(&key).unwrap();

                        rows.push(row("RustCrypto", move |_, d, o| rc_hmac_reused(&base, d, o)));
                    }
                    HmacHash::S256 => {
                        let base = hmac::Hmac::<sha2::Sha256>::new_from_slice(&key).unwrap();

                        rows.push(row("RustCrypto", move |_, d, o| rc_hmac_reused(&base, d, o)));
                    }
                    HmacHash::S384 => {
                        let base = hmac::Hmac::<sha2::Sha384>::new_from_slice(&key).unwrap();

                        rows.push(row("RustCrypto", move |_, d, o| rc_hmac_reused(&base, d, o)));
                    }
                    HmacHash::S512 => {
                        let base = hmac::Hmac::<sha2::Sha512>::new_from_slice(&key).unwrap();

                        rows.push(row("RustCrypto", move |_, d, o| rc_hmac_reused(&base, d, o)));
                    }
                }
            }

            #[cfg(pb_c)]
            if let Some(a) = ring_alg {
                let ring_key = ring::hmac::Key::new(a, &key);

                rows.push(row("ring", move |_, d, o| o.copy_from_slice(ring::hmac::sign(&ring_key, d).as_ref())));
            }

            if let Some(a) = libcrux {
                rows.push(row("libcrux", move |k, d, o| libcrux_hmac::hmac(a, k, d, o)));
            }

            case(list, &format!("{name}/reused/{suffix}"), &key, &data[..length], size, rows);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// HKDF: extract then expand. RFC 5869 cases 1 to 3 (their sizes, for every hash) and TLS 1.3
// sizes: 32-byte IKM, a salt of the hash length, an HkdfLabel-sized info (22 bytes plus a hash),
// 32 and 64 bytes of output.

#[cfg(pb_c)]
struct OkmLen(usize);

#[cfg(pb_c)]
impl aws_lc_rs::hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(pb_c)]
impl ring::hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn kdfs(list: &mut List) {
    let material = bytes(512);

    for bits in [256, 384, 512] {
        let hash_len = bits / 8;

        let (cpq, libcrux) = match bits {
            256 => (crypto_pq::HKDF_SHA_256, libcrux_hkdf::Algorithm::Sha256),
            384 => (crypto_pq::HKDF_SHA_384, libcrux_hkdf::Algorithm::Sha384),
            _ => (crypto_pq::HKDF_SHA_512, libcrux_hkdf::Algorithm::Sha512),
        };

        #[cfg(pb_c)]
        let (aws, ring_alg) = match bits {
            256 => (aws_lc_rs::hkdf::HKDF_SHA256, ring::hkdf::HKDF_SHA256),
            384 => (aws_lc_rs::hkdf::HKDF_SHA384, ring::hkdf::HKDF_SHA384),
            _ => (aws_lc_rs::hkdf::HKDF_SHA512, ring::hkdf::HKDF_SHA512),
        };

        let cases = [
            ("rfc1", 22, 13, 10, 42),
            ("rfc2", 80, 80, 80, 82),
            ("rfc3", 22, 0, 0, 42),
            ("tls-okm32", 32, hash_len, 22 + hash_len, 32),
            ("tls-okm64", 32, hash_len, 22 + hash_len, 64),
        ];

        for (suffix, ikm_len, salt_len, info_len, okm_len) in cases {
            // key = salt || info; data = ikm.
            let key: Vec<u8> = material[100..100 + salt_len + info_len].to_vec();

            let ikm = &material[..ikm_len];

            let mut rows = vec![
                row(CPQ, move |k, d, o| {
                    let (s, i) = (&k[..salt_len], &k[salt_len..]);

                    cpq.derive_into(d, o, &KdfOptions::default().with_salt(s).with_info(i)).unwrap();
                }),
                row("RustCrypto", move |k, d, o| {
                    let (s, i) = (&k[..salt_len], &k[salt_len..]);

                    match bits {
                        256 => hkdf::Hkdf::<sha2::Sha256>::new(Some(s), d).expand(i, o).unwrap(),
                        384 => hkdf::Hkdf::<sha2::Sha384>::new(Some(s), d).expand(i, o).unwrap(),
                        _ => hkdf::Hkdf::<sha2::Sha512>::new(Some(s), d).expand(i, o).unwrap(),
                    }
                }),
                row("libcrux", move |k, d, o| {
                    let (s, i) = (&k[..salt_len], &k[salt_len..]);

                    libcrux_hkdf::hkdf(libcrux, o, s, d, i).unwrap();
                }),
            ];

            #[cfg(pb_c)]
            rows.push(row("aws-lc-rs", move |k, d, o| {
                let (s, i) = (&k[..salt_len], &k[salt_len..]);

                let prk = aws_lc_rs::hkdf::Salt::new(aws, s).extract(d);

                let info = [i];

                prk.expand(&info, OkmLen(o.len())).unwrap().fill(o).unwrap();
            }));

            #[cfg(pb_c)]
            rows.push(row("ring", move |k, d, o| {
                let (s, i) = (&k[..salt_len], &k[salt_len..]);

                let prk = ring::hkdf::Salt::new(ring_alg, s).extract(d);

                let info = [i];

                prk.expand(&info, OkmLen(o.len())).unwrap().fill(o).unwrap();
            }));

            case(list, &format!("hkdf-sha{bits}/{suffix}"), &key, ikm, okm_len, rows);
        }
    }
}

fn build(list: &mut List) {
    hashes(list);

    macs(list);

    kdfs(list);

    stfl::lms(list);

    stfl::xmss(list);
}

fn main() {
    fm::main(wanted, build);
}

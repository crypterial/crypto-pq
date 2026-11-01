// Category 6 rows (from meas-eng overlay-1): crypto-pq (new), its A/A copy, main, the forced
// variant x (x86: scalar on every CPU; arm64: LAZY and BLAKE3_NARROW on every core), and the rivals.
use crate::{HashFn, HashRow, data};

const SIZES: [usize; 4] = [0, 64, 1024, 16384];

const CONTEXT: &str = "crypto-pq meas 2026-10-31 BLAKE3 derive_key context";

const CONTEXT2: &str = "crypto-pq meas 2026-10-31 BLAKE3 derive_key context two";

fn row<'a>(label: String, input: Vec<u8>, out: usize, imps: Vec<(&'static str, HashFn<'a>)>) -> HashRow<'a> {
    HashRow { label, input, out, imps }
}

fn b2b512<'a>() -> Vec<(&'static str, HashFn<'a>)> {
    let mut v: Vec<(&'static str, HashFn<'a>)> = vec![
        ("crypto-pq", Box::new(|d: &[u8], o: &mut [u8]| cpq::BLAKE2B_512.digest_into(d, o).unwrap())),
        ("crypto-pq-aa", Box::new(|d: &[u8], o: &mut [u8]| cpq_aa::BLAKE2B_512.digest_into(d, o).unwrap())),
        ("crypto-pq-main", Box::new(|d: &[u8], o: &mut [u8]| cpq_main::BLAKE2B_512.digest_into(d, o).unwrap())),
        ("blake2", Box::new(|d: &[u8], o: &mut [u8]| {
            use blake2::Digest;

            o.copy_from_slice(&blake2::Blake2b512::digest(d))
        })),
        ("blake2b_simd", Box::new(|d: &[u8], o: &mut [u8]| o.copy_from_slice(blake2b_simd::blake2b(d).as_bytes()))),
        ("blake2-rfc", Box::new(|d: &[u8], o: &mut [u8]| o.copy_from_slice(blake2_rfc::blake2b::blake2b(64, &[], d).as_bytes()))),
        ("blake2b-ref", Box::new(|d: &[u8], o: &mut [u8]| blake2b_ref::blake2b(&[], d, o))),
        ("libcrux-blake2", Box::new(|d: &[u8], o: &mut [u8]| {
            let mut h = libcrux_blake2::Blake2bBuilder::new_unkeyed().build_const_digest_len::<64>();

            h.update(d).unwrap();

            h.finalize(o.try_into().unwrap());
        })),
        ("tc_blake", Box::new(|d: &[u8], o: &mut [u8]| {
            use tc_digest::TryDigest;

            let mut h = tc_blake::Blake2bDigest::new();

            h.try_update(d).unwrap();

            h.try_do_final(o).unwrap();
        })),
        ("cryptoxide", Box::new(|d: &[u8], o: &mut [u8]| cryptoxide::hashing::blake2b::ContextDyn::new(o.len()).update(d).finalize_at(o))),
        ("orion", Box::new(|d: &[u8], o: &mut [u8]| {
            o.copy_from_slice(orion::hazardous::hash::blake2::blake2b::Hasher::Blake2b512.digest(d).unwrap().as_ref())
        })),
        ("dryoc", Box::new(|d: &[u8], o: &mut [u8]| dryoc::classic::crypto_generichash::crypto_generichash(o, d, None).unwrap())),
        ("krypteia-tessera", Box::new(|d: &[u8], o: &mut [u8]| {
            use tessera::Digest;

            let mut h = tessera::blake2::Blake2b::with_output_len(64);

            h.update(d);

            h.finalize(o);
        })),
        ("purecrypto", Box::new(|d: &[u8], o: &mut [u8]| o.copy_from_slice(&purecrypto::hash::blake2b512(d)))),
        ("rscrypto", Box::new(|d: &[u8], o: &mut [u8]| o.copy_from_slice(&rscrypto::Blake2b512::digest(d)))),
        ("openssl", Box::new(|d: &[u8], o: &mut [u8]| {
            o.copy_from_slice(&openssl::hash::hash(openssl::hash::MessageDigest::from_name("BLAKE2b512").unwrap(), d).unwrap())
        })),
    ];

    #[cfg(feature = "main")]
    v.push(("libsodium", Box::new(|d: &[u8], o: &mut [u8]| unsafe {
            assert_eq!(
                libsodium_sys::crypto_generichash(o.as_mut_ptr(), o.len(), d.as_ptr(), d.len() as u64, std::ptr::null(), 0),
                0
            );
        })));

    #[cfg(feature = "alt")]
    v.push(("blake2b-rs", Box::new(|d: &[u8], o: &mut [u8]| blake2b_rs::blake2b(&[], d, o))));

    v
}

fn b2b256<'a>() -> Vec<(&'static str, HashFn<'a>)> {
    let mut v: Vec<(&'static str, HashFn<'a>)> = vec![
        ("crypto-pq", Box::new(|d: &[u8], o: &mut [u8]| cpq::BLAKE2B_256.digest_into(d, o).unwrap())),
        ("crypto-pq-aa", Box::new(|d: &[u8], o: &mut [u8]| cpq_aa::BLAKE2B_256.digest_into(d, o).unwrap())),
        ("crypto-pq-main", Box::new(|d: &[u8], o: &mut [u8]| cpq_main::BLAKE2B_256.digest_into(d, o).unwrap())),
        ("blake2", Box::new(|d: &[u8], o: &mut [u8]| {
            use blake2::Digest;

            o.copy_from_slice(&blake2::Blake2b256::digest(d))
        })),
        ("blake2b_simd", Box::new(|d: &[u8], o: &mut [u8]| {
            o.copy_from_slice(blake2b_simd::Params::new().hash_length(32).hash(d).as_bytes())
        })),
        ("blake2-rfc", Box::new(|d: &[u8], o: &mut [u8]| o.copy_from_slice(blake2_rfc::blake2b::blake2b(32, &[], d).as_bytes()))),
        ("blake2b-ref", Box::new(|d: &[u8], o: &mut [u8]| blake2b_ref::blake2b(&[], d, o))),
        ("libcrux-blake2", Box::new(|d: &[u8], o: &mut [u8]| {
            let mut h = libcrux_blake2::Blake2bBuilder::new_unkeyed().build_const_digest_len::<32>();

            h.update(d).unwrap();

            h.finalize(o.try_into().unwrap());
        })),
        ("tc_blake", Box::new(|d: &[u8], o: &mut [u8]| {
            use tc_digest::TryDigest;

            let mut h = tc_blake::Blake2bDigest::with_digest_size(256);

            h.try_update(d).unwrap();

            h.try_do_final(o).unwrap();
        })),
        ("cryptoxide", Box::new(|d: &[u8], o: &mut [u8]| cryptoxide::hashing::blake2b::ContextDyn::new(o.len()).update(d).finalize_at(o))),
        ("orion", Box::new(|d: &[u8], o: &mut [u8]| {
            o.copy_from_slice(orion::hazardous::hash::blake2::blake2b::Hasher::Blake2b256.digest(d).unwrap().as_ref())
        })),
        ("dryoc", Box::new(|d: &[u8], o: &mut [u8]| dryoc::classic::crypto_generichash::crypto_generichash(o, d, None).unwrap())),
        ("krypteia-tessera", Box::new(|d: &[u8], o: &mut [u8]| {
            use tessera::Digest;

            let mut h = tessera::blake2::Blake2b::with_output_len(32);

            h.update(d);

            h.finalize(o);
        })),
        ("purecrypto", Box::new(|d: &[u8], o: &mut [u8]| o.copy_from_slice(&purecrypto::hash::blake2b256(d)))),
        ("rscrypto", Box::new(|d: &[u8], o: &mut [u8]| o.copy_from_slice(&rscrypto::Blake2b256::digest(d)))),
    ];

    #[cfg(feature = "main")]
    v.push(("libsodium", Box::new(|d: &[u8], o: &mut [u8]| unsafe {
            assert_eq!(
                libsodium_sys::crypto_generichash(o.as_mut_ptr(), o.len(), d.as_ptr(), d.len() as u64, std::ptr::null(), 0),
                0
            );
        })));

    #[cfg(feature = "alt")]
    v.push(("blake2b-rs", Box::new(|d: &[u8], o: &mut [u8]| blake2b_rs::blake2b(&[], d, o))));

    v
}

fn b2b_mac<'a>(key: &'a [u8; 64]) -> Vec<(&'static str, HashFn<'a>)> {
    let mut v: Vec<(&'static str, HashFn<'a>)> = vec![
        ("crypto-pq", Box::new(move |d: &[u8], o: &mut [u8]| cpq::BLAKE2B_MAC.digest_into(key, d, o).unwrap())),
        ("crypto-pq-aa", Box::new(move |d: &[u8], o: &mut [u8]| cpq_aa::BLAKE2B_MAC.digest_into(key, d, o).unwrap())),
        ("crypto-pq-main", Box::new(move |d: &[u8], o: &mut [u8]| cpq_main::BLAKE2B_MAC.digest_into(key, d, o).unwrap())),
        ("blake2", Box::new(move |d: &[u8], o: &mut [u8]| {
            use blake2::digest::{KeyInit, Mac};

            let mut m = <blake2::Blake2bMac512 as KeyInit>::new_from_slice(key).unwrap();

            m.update(d);

            o.copy_from_slice(&m.finalize().into_bytes())
        })),
        ("blake2b_simd", Box::new(move |d: &[u8], o: &mut [u8]| {
            o.copy_from_slice(blake2b_simd::Params::new().key(key).hash(d).as_bytes())
        })),
        ("blake2-rfc", Box::new(move |d: &[u8], o: &mut [u8]| o.copy_from_slice(blake2_rfc::blake2b::blake2b(64, key, d).as_bytes()))),
        ("blake2b-ref", Box::new(move |d: &[u8], o: &mut [u8]| blake2b_ref::blake2b(key, d, o))),
        ("libcrux-blake2", Box::new(move |d: &[u8], o: &mut [u8]| {
            let mut h = libcrux_blake2::Blake2bBuilder::new_keyed_const(key).build_const_digest_len::<64>();

            h.update(d).unwrap();

            h.finalize(o.try_into().unwrap());
        })),
        ("tc_blake", Box::new(move |d: &[u8], o: &mut [u8]| {
            use tc_digest::TryDigest;

            let mut h = tc_blake::Blake2bDigest::with_key(key);

            h.try_update(d).unwrap();

            h.try_do_final(o).unwrap();
        })),
        ("cryptoxide", Box::new(move |d: &[u8], o: &mut [u8]| cryptoxide::hashing::blake2b::ContextDyn::new_keyed(64, key).update(d).finalize_at(o))),
        ("orion", Box::new(move |d: &[u8], o: &mut [u8]| {
            let k = orion::hazardous::mac::blake2b::SecretKey::try_from(key.as_slice()).unwrap();

            let mut m = orion::hazardous::mac::blake2b::Blake2b::new(&k, 64).unwrap();

            m.update(d).unwrap();

            let t = m.finalize().unwrap();

            let t: &[u8] = t.unprotected_as_ref();

            o.copy_from_slice(t)
        })),
        ("dryoc", Box::new(move |d: &[u8], o: &mut [u8]| {
            dryoc::classic::crypto_generichash::crypto_generichash(o, d, Some(key)).unwrap()
        })),
        ("purecrypto", Box::new(move |d: &[u8], o: &mut [u8]| {
            let mut m = purecrypto::hash::Blake2bMac::new(key, 64);

            m.update(d);

            m.finalize_into(o)
        })),
        ("rscrypto", Box::new(move |d: &[u8], o: &mut [u8]| {
            o.copy_from_slice(&rscrypto::Blake2b512::keyed_digest(rscrypto::Blake2bKey::new(key).unwrap(), d))
        })),
    ];

    #[cfg(feature = "main")]
    v.push(("libsodium", Box::new(move |d: &[u8], o: &mut [u8]| unsafe {
            assert_eq!(
                libsodium_sys::crypto_generichash(o.as_mut_ptr(), o.len(), d.as_ptr(), d.len() as u64, key.as_ptr(), key.len()),
                0
            );
        })));

    #[cfg(feature = "alt")]
    v.push(("blake2b-rs", Box::new(move |d: &[u8], o: &mut [u8]| blake2b_rs::blake2b(key, d, o))));

    v
}

fn b2s256<'a>() -> Vec<(&'static str, HashFn<'a>)> {
    let v: Vec<(&'static str, HashFn<'a>)> = vec![
        ("crypto-pq", Box::new(|d: &[u8], o: &mut [u8]| cpq::BLAKE2S_256.digest_into(d, o).unwrap())),
        ("crypto-pq-aa", Box::new(|d: &[u8], o: &mut [u8]| cpq_aa::BLAKE2S_256.digest_into(d, o).unwrap())),
        ("crypto-pq-main", Box::new(|d: &[u8], o: &mut [u8]| cpq_main::BLAKE2S_256.digest_into(d, o).unwrap())),
        ("blake2", Box::new(|d: &[u8], o: &mut [u8]| {
            use blake2::Digest;

            o.copy_from_slice(&blake2::Blake2s256::digest(d))
        })),
        ("blake2s_simd", Box::new(|d: &[u8], o: &mut [u8]| o.copy_from_slice(blake2s_simd::blake2s(d).as_bytes()))),
        ("blake2-rfc", Box::new(|d: &[u8], o: &mut [u8]| o.copy_from_slice(blake2_rfc::blake2s::blake2s(32, &[], d).as_bytes()))),
        ("libcrux-blake2", Box::new(|d: &[u8], o: &mut [u8]| {
            let mut h = libcrux_blake2::Blake2sBuilder::new_unkeyed().build_const_digest_len::<32>();

            h.update(d).unwrap();

            h.finalize(o.try_into().unwrap());
        })),
        ("tc_blake", Box::new(|d: &[u8], o: &mut [u8]| {
            use tc_digest::TryDigest;

            let mut h = tc_blake::Blake2sDigest::new();

            h.try_update(d).unwrap();

            h.try_do_final(o).unwrap();
        })),
        ("cryptoxide", Box::new(|d: &[u8], o: &mut [u8]| cryptoxide::hashing::blake2s::ContextDyn::new(32).update(d).finalize_at(o))),
        ("krypteia-tessera", Box::new(|d: &[u8], o: &mut [u8]| {
            use tessera::Digest;

            let mut h = tessera::blake2::Blake2s::with_output_len(32);

            h.update(d);

            h.finalize(o);
        })),
        ("kevy-crypto", Box::new(|d: &[u8], o: &mut [u8]| o.copy_from_slice(&kevy_crypto::blake2s::hash(d)))),
        ("p3-blake2s", Box::new(|d: &[u8], o: &mut [u8]| o.copy_from_slice(&p3_blake2s::Blake2s256::hash(d)))),
        ("purecrypto", Box::new(|d: &[u8], o: &mut [u8]| o.copy_from_slice(&purecrypto::hash::blake2s256(d)))),
        ("rscrypto", Box::new(|d: &[u8], o: &mut [u8]| o.copy_from_slice(&rscrypto::Blake2s256::digest(d)))),
        ("openssl", Box::new(|d: &[u8], o: &mut [u8]| {
            o.copy_from_slice(&openssl::hash::hash(openssl::hash::MessageDigest::from_name("BLAKE2s256").unwrap(), d).unwrap())
        })),
    ];


    v
}

fn b2s_mac<'a>(key: &'a [u8; 32]) -> Vec<(&'static str, HashFn<'a>)> {
    let v: Vec<(&'static str, HashFn<'a>)> = vec![
        ("crypto-pq", Box::new(move |d: &[u8], o: &mut [u8]| cpq::BLAKE2S_MAC.digest_into(key, d, o).unwrap())),
        ("crypto-pq-aa", Box::new(move |d: &[u8], o: &mut [u8]| cpq_aa::BLAKE2S_MAC.digest_into(key, d, o).unwrap())),
        ("crypto-pq-main", Box::new(move |d: &[u8], o: &mut [u8]| cpq_main::BLAKE2S_MAC.digest_into(key, d, o).unwrap())),
        ("blake2", Box::new(move |d: &[u8], o: &mut [u8]| {
            use blake2::digest::{KeyInit, Mac};

            let mut m = <blake2::Blake2sMac256 as KeyInit>::new_from_slice(key).unwrap();

            m.update(d);

            o.copy_from_slice(&m.finalize().into_bytes())
        })),
        ("blake2s_simd", Box::new(move |d: &[u8], o: &mut [u8]| {
            o.copy_from_slice(blake2s_simd::Params::new().key(key).hash(d).as_bytes())
        })),
        ("blake2-rfc", Box::new(move |d: &[u8], o: &mut [u8]| o.copy_from_slice(blake2_rfc::blake2s::blake2s(32, key, d).as_bytes()))),
        ("libcrux-blake2", Box::new(move |d: &[u8], o: &mut [u8]| {
            let mut h = libcrux_blake2::Blake2sBuilder::new_keyed_const(key).build_const_digest_len::<32>();

            h.update(d).unwrap();

            h.finalize(o.try_into().unwrap());
        })),
        ("tc_blake", Box::new(move |d: &[u8], o: &mut [u8]| {
            use tc_digest::TryDigest;

            let mut h = tc_blake::Blake2sDigest::with_key(key);

            h.try_update(d).unwrap();

            h.try_do_final(o).unwrap();
        })),
        ("cryptoxide", Box::new(move |d: &[u8], o: &mut [u8]| cryptoxide::hashing::blake2s::ContextDyn::new_keyed(32, key).update(d).finalize_at(o))),
        ("kevy-crypto", Box::new(move |d: &[u8], o: &mut [u8]| {
            let mut s = kevy_crypto::blake2s::Blake2s::new_keyed(32, key);

            s.update(d);

            s.finalize(o)
        })),
        ("purecrypto", Box::new(move |d: &[u8], o: &mut [u8]| {
            let mut m = purecrypto::hash::Blake2sMac::new(key, 32);

            m.update(d);

            m.finalize_into(o)
        })),
        ("rscrypto", Box::new(move |d: &[u8], o: &mut [u8]| {
            o.copy_from_slice(&rscrypto::Blake2s256::keyed_digest(rscrypto::Blake2sKey::new(key).unwrap(), d))
        })),
    ];


    v
}

fn b3_hash<'a>(input_len: usize) -> Vec<(&'static str, HashFn<'a>)> {
    let mut v: Vec<(&'static str, HashFn<'a>)> = vec![
        ("crypto-pq", Box::new(|d: &[u8], o: &mut [u8]| cpq::BLAKE3_256.digest_into(d, o).unwrap())),
        ("crypto-pq-aa", Box::new(|d: &[u8], o: &mut [u8]| cpq_aa::BLAKE3_256.digest_into(d, o).unwrap())),
        ("crypto-pq-main", Box::new(|d: &[u8], o: &mut [u8]| cpq_main::BLAKE3_256.digest_into(d, o).unwrap())),
        ("blake3", Box::new(|d: &[u8], o: &mut [u8]| o.copy_from_slice(blake3::hash(d).as_bytes()))),
        ("tc_blake", Box::new(|d: &[u8], o: &mut [u8]| {
            use tc_digest::TryDigest;

            let mut h = tc_blake::Blake3Digest::new();

            h.try_update(d).unwrap();

            h.try_do_final(o).unwrap();
        })),
        ("cryptoxide", Box::new(|d: &[u8], o: &mut [u8]| {
            cryptoxide::hashing::blake3::Blake3::new().update(d).finalize_at(o)
        })),
        ("krypteia-tessera", Box::new(|d: &[u8], o: &mut [u8]| tessera::blake3::hash(d, o))),
        ("purecrypto", Box::new(|d: &[u8], o: &mut [u8]| o.copy_from_slice(&purecrypto::hash::blake3(d)))),
        ("rscrypto", Box::new(|d: &[u8], o: &mut [u8]| o.copy_from_slice(&rscrypto::Blake3::digest(d)))),
    ];

    if input_len <= 64 {
        v.push(("ab-blake3-block", Box::new(|d: &[u8], o: &mut [u8]| {
            o.copy_from_slice(&ab_blake3::single_block_hash(d).unwrap())
        })));
    }

    if input_len <= 1024 {
        v.push(("ab-blake3-chunk", Box::new(|d: &[u8], o: &mut [u8]| {
            o.copy_from_slice(&ab_blake3::single_chunk_hash(d).unwrap())
        })));
    }

    v
}

fn b3_keyed<'a>(key: &'a [u8; 32], input_len: usize) -> Vec<(&'static str, HashFn<'a>)> {
    let mut v: Vec<(&'static str, HashFn<'a>)> = vec![
        ("crypto-pq", Box::new(move |d: &[u8], o: &mut [u8]| cpq::BLAKE3_MAC.digest_into(key, d, o).unwrap())),
        ("crypto-pq-aa", Box::new(move |d: &[u8], o: &mut [u8]| cpq_aa::BLAKE3_MAC.digest_into(key, d, o).unwrap())),
        ("crypto-pq-main", Box::new(move |d: &[u8], o: &mut [u8]| cpq_main::BLAKE3_MAC.digest_into(key, d, o).unwrap())),
        ("blake3", Box::new(move |d: &[u8], o: &mut [u8]| o.copy_from_slice(blake3::keyed_hash(key, d).as_bytes()))),
        ("tc_blake", Box::new(move |d: &[u8], o: &mut [u8]| {
            use tc_digest::TryDigest;

            let mut h = tc_blake::Blake3Digest::with_key(256, key);

            h.try_update(d).unwrap();

            h.try_do_final(o).unwrap();
        })),
        ("cryptoxide", Box::new(move |d: &[u8], o: &mut [u8]| {
            cryptoxide::hashing::blake3::Blake3::new_keyed(key).update(d).finalize_at(o)
        })),
        ("krypteia-tessera", Box::new(move |d: &[u8], o: &mut [u8]| tessera::blake3::keyed_hash(key, d, o))),
        ("purecrypto", Box::new(move |d: &[u8], o: &mut [u8]| {
            let mut h = purecrypto::hash::Blake3::new_keyed(key);

            h.update(d);

            o.copy_from_slice(&h.finalize())
        })),
        ("rscrypto", Box::new(move |d: &[u8], o: &mut [u8]| {
            o.copy_from_slice(rscrypto::Blake3::keyed_digest(key, d).as_bytes())
        })),
    ];

    if input_len <= 64 {
        v.push(("ab-blake3-block", Box::new(move |d: &[u8], o: &mut [u8]| {
            o.copy_from_slice(&ab_blake3::single_block_keyed_hash(key, d).unwrap())
        })));
    }

    if input_len <= 1024 {
        v.push(("ab-blake3-chunk", Box::new(move |d: &[u8], o: &mut [u8]| {
            o.copy_from_slice(&ab_blake3::single_chunk_keyed_hash(key, d).unwrap())
        })));
    }

    v
}

fn b3_derive<'a>(input_len: usize, ctx: &'static str) -> Vec<(&'static str, HashFn<'a>)> {
    let mut v: Vec<(&'static str, HashFn<'a>)> = vec![
        ("crypto-pq", Box::new(move |d: &[u8], o: &mut [u8]| {
            cpq::BLAKE3_KDF.derive_into(d, o, &cpq::KdfOptions::default().with_info(ctx.as_bytes())).unwrap()
        })),
        ("crypto-pq-aa", Box::new(move |d: &[u8], o: &mut [u8]| {
            cpq_aa::BLAKE3_KDF.derive_into(d, o, &cpq_aa::KdfOptions::default().with_info(ctx.as_bytes())).unwrap()
        })),
        ("crypto-pq-main", Box::new(move |d: &[u8], o: &mut [u8]| {
            cpq_main::BLAKE3_KDF.derive_into(d, o, &cpq_main::KdfOptions::default().with_info(ctx.as_bytes())).unwrap()
        })),
        ("blake3", Box::new(move |d: &[u8], o: &mut [u8]| o.copy_from_slice(&blake3::derive_key(ctx, d)))),
        ("tc_blake", Box::new(move |d: &[u8], o: &mut [u8]| {
            use tc_digest::TryDigest;

            let mut h = tc_blake::Blake3Digest::with_derive_key(256, ctx.as_bytes());

            h.try_update(d).unwrap();

            h.try_do_final(o).unwrap();
        })),
        ("cryptoxide", Box::new(move |d: &[u8], o: &mut [u8]| {
            cryptoxide::hashing::blake3::Blake3::new_derive_key(ctx.as_bytes()).update(d).finalize_at(o)
        })),
        ("krypteia-tessera", Box::new(move |d: &[u8], o: &mut [u8]| tessera::blake3::derive_key(ctx, d, o))),
        ("purecrypto", Box::new(move |d: &[u8], o: &mut [u8]| {
            let mut h = purecrypto::hash::Blake3::new_derive_key(ctx);

            h.update(d);

            o.copy_from_slice(&h.finalize())
        })),
        ("rscrypto", Box::new(move |d: &[u8], o: &mut [u8]| o.copy_from_slice(&rscrypto::Blake3::derive_key(ctx, d)))),
    ];

    if input_len <= 64 {
        v.push(("ab-blake3-block", Box::new(move |d: &[u8], o: &mut [u8]| {
            o.copy_from_slice(&ab_blake3::single_block_derive_key(ctx, d).unwrap())
        })));
    }

    if input_len <= 1024 {
        v.push(("ab-blake3-chunk", Box::new(move |d: &[u8], o: &mut [u8]| {
            o.copy_from_slice(&ab_blake3::single_chunk_derive_key(ctx, d).unwrap())
        })));
    }

    v
}

// Two derive_key calls per operation under two alternating contexts, so that no implementation can
// reuse the hash of the previous call's context (rscrypto keeps the last one per thread).
fn b3_derive2<'a>(input_len: usize) -> Vec<(&'static str, HashFn<'a>)> {
    b3_derive(input_len, CONTEXT)
        .into_iter()
        .zip(b3_derive(input_len, CONTEXT2))
        .map(|((name, a), (_, b))| {
            let f: HashFn<'a> = Box::new(move |d: &[u8], o: &mut [u8]| {
                let (x, y) = o.split_at_mut(32);

                a(d, x);

                b(d, y);
            });

            (name, f)
        })
        .collect()
}

fn b3_xof<'a>() -> Vec<(&'static str, HashFn<'a>)> {
    vec![
        ("crypto-pq", Box::new(|d: &[u8], o: &mut [u8]| cpq::BLAKE3.digest_into(d, o).unwrap())),
        ("crypto-pq-aa", Box::new(|d: &[u8], o: &mut [u8]| cpq_aa::BLAKE3.digest_into(d, o).unwrap())),
        ("crypto-pq-main", Box::new(|d: &[u8], o: &mut [u8]| cpq_main::BLAKE3.digest_into(d, o).unwrap())),
        ("blake3", Box::new(|d: &[u8], o: &mut [u8]| {
            let mut h = blake3::Hasher::new();

            h.update(d);

            h.finalize_xof().fill(o)
        })),
        ("cryptoxide", Box::new(|d: &[u8], o: &mut [u8]| {
            cryptoxide::hashing::blake3::Blake3::new().update(d).finalize_xof().fill(o)
        })),
        ("krypteia-tessera", Box::new(|d: &[u8], o: &mut [u8]| {
            let mut h = tessera::blake3::Blake3::new();

            h.update(d);

            h.finalize_xof(0, o)
        })),
        ("purecrypto", Box::new(|d: &[u8], o: &mut [u8]| {
            use purecrypto::hash::XofReader;

            let mut h = purecrypto::hash::Blake3::new();

            h.update(d);

            h.finalize_xof().read(o)
        })),
        ("rscrypto", Box::new(|d: &[u8], o: &mut [u8]| {
            use rscrypto::Xof;

            rscrypto::Blake3::xof(d).squeeze(o)
        })),
    ]
}

// The four builds through HashAlgorithm, XofAlgorithm and MacAlgorithm, no rivals: the rows that
// show whether a change in BLAKE moved the dispatch of the other algorithms.
macro_rules! disp {
    ($name:ident, $c:ident) => {
        fn $name<'a>() -> Vec<(&'static str, HashFn<'a>)> {
            vec![
                ("crypto-pq", Box::new(|d: &[u8], o: &mut [u8]| cpq::$c.digest_into(d, o).unwrap())),
                ("crypto-pq-aa", Box::new(|d: &[u8], o: &mut [u8]| cpq_aa::$c.digest_into(d, o).unwrap())),
                ("crypto-pq-main", Box::new(|d: &[u8], o: &mut [u8]| cpq_main::$c.digest_into(d, o).unwrap())),
            ]
        }
    };
}

macro_rules! disp_mac {
    ($name:ident, $c:ident) => {
        fn $name<'a>(key: &'a [u8; 32]) -> Vec<(&'static str, HashFn<'a>)> {
            vec![
                ("crypto-pq", Box::new(move |d: &[u8], o: &mut [u8]| cpq::$c.digest_into(key, d, o).unwrap())),
                ("crypto-pq-aa", Box::new(move |d: &[u8], o: &mut [u8]| cpq_aa::$c.digest_into(key, d, o).unwrap())),
                ("crypto-pq-main", Box::new(move |d: &[u8], o: &mut [u8]| cpq_main::$c.digest_into(key, d, o).unwrap())),
            ]
        }
    };
}

disp!(d_sha256, SHA_256);
disp!(d_sha512, SHA_512);
disp!(d_sha3_256, SHA3_256);
disp!(d_shake128, SHAKE128);
disp!(d_blake2b, BLAKE2B_512);
disp!(d_blake2s, BLAKE2S_256);
disp!(d_blake3, BLAKE3_256);
disp_mac!(d_hmac256, HMAC_SHA_256);
disp_mac!(d_kmac128, KMAC128);

pub fn rows() -> Vec<HashRow<'static>> {
    #[cfg(feature = "main")]
    unsafe {
        assert!(libsodium_sys::sodium_init() >= 0);
    }

    let key64: &'static [u8; 64] = Box::leak(Box::new(std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1))));

    let key32: &'static [u8; 32] = Box::leak(Box::new(std::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(5))));

    let mut rows = Vec::new();

    for n in SIZES {
        rows.push(row(format!("blake2b-512/{n}"), data(n, 1), 64, b2b512()));
    }

    rows.push(row("blake2b-256/64".into(), data(64, 2), 32, b2b256()));

    for n in SIZES {
        rows.push(row(format!("blake2b-mac/{n}"), data(n, 3), 64, b2b_mac(key64)));
    }

    for n in SIZES {
        rows.push(row(format!("blake2s-256/{n}"), data(n, 4), 32, b2s256()));
    }

    for n in SIZES {
        rows.push(row(format!("blake2s-mac/{n}"), data(n, 5), 32, b2s_mac(key32)));
    }

    for n in SIZES {
        rows.push(row(format!("blake3/{n}"), data(n, 6), 32, b3_hash(n)));
    }

    for n in SIZES {
        rows.push(row(format!("blake3-keyed/{n}"), data(n, 7), 32, b3_keyed(key32, n)));
    }

    for n in [32, 1024] {
        rows.push(row(format!("blake3-derive/{n}"), data(n, 8), 32, b3_derive(n, CONTEXT)));
    }

    for n in [32, 1024] {
        rows.push(row(format!("blake3-derive2ctx/{n}"), data(n, 10), 64, b3_derive2(n)));
    }

    for out in [64, 1024, 16384] {
        rows.push(row(format!("blake3-xof/64>{out}"), data(64, 9), out, b3_xof()));
    }

    let disp: [(&str, usize, fn() -> Vec<(&'static str, HashFn<'static>)>); 7] = [
        ("sha256", 32, d_sha256),
        ("sha512", 64, d_sha512),
        ("sha3-256", 32, d_sha3_256),
        ("shake128", 32, d_shake128),
        ("blake2b", 64, d_blake2b),
        ("blake2s", 32, d_blake2s),
        ("blake3", 32, d_blake3),
    ];

    for (name, out, imps) in disp {
        for n in [0, 64, 1024] {
            rows.push(row(format!("disp-{name}/{n}"), data(n, 11), out, imps()));
        }
    }

    for n in [0, 64, 1024] {
        rows.push(row(format!("disp-hmac-sha256/{n}"), data(n, 12), 32, d_hmac256(key32)));

        rows.push(row(format!("disp-kmac128/{n}"), data(n, 13), 32, d_kmac128(key32)));
    }

    rows
}

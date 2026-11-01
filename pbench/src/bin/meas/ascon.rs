// Category 7: Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 (SP 800-232). crypto-pq has no
// Ascon-AEAD128 (spec 04-scope.md), so there is no AEAD row.
use crate::{HashFn, HashRow, data};

const SIZES: [usize; 4] = [0, 64, 1024, 16384];

const Z: &[u8] = b"crypto-pq meas z";

fn hash256<'a>() -> Vec<(&'static str, HashFn<'a>)> {
    vec![
        ("crypto-pq", Box::new(|d: &[u8], o: &mut [u8]| cpq::ASCON_HASH256.digest_into(d, o).unwrap())),
        ("crypto-pq-aa", Box::new(|d: &[u8], o: &mut [u8]| cpq_aa::ASCON_HASH256.digest_into(d, o).unwrap())),
        ("ascon-hash256", Box::new(|d: &[u8], o: &mut [u8]| {
            use ascon_hash256::Digest;

            o.copy_from_slice(&ascon_hash256::AsconHash256::digest(d))
        })),
        ("ascon-hash", Box::new(|d: &[u8], o: &mut [u8]| {
            use ascon_hash::Digest;

            o.copy_from_slice(&ascon_hash::AsconHash256::digest(d))
        })),
        ("tc_ascon_hash", Box::new(|d: &[u8], o: &mut [u8]| {
            use tc_digest::TryDigest;

            let mut h = tc_ascon_hash::AsconHash256::new();

            h.try_update(d).unwrap();

            h.try_do_final(o).unwrap();
        })),
        ("ascon-rs", Box::new(|d: &[u8], o: &mut [u8]| o.copy_from_slice(&ascon::hash256(d)))),
        if_purecrypto!("purecrypto", Box::new(|d: &[u8], o: &mut [u8]| {
            use purecrypto::hash::Digest;

            let mut h = purecrypto::ascon::AsconHash256::new();

            h.update(d);

            o.copy_from_slice(&h.finalize())
        })),
        if_rscrypto!("rscrypto", Box::new(|d: &[u8], o: &mut [u8]| {
            use rscrypto::Digest;

            o.copy_from_slice(&rscrypto::AsconHash256::digest(d))
        })),
    ]
}

fn xof128<'a>() -> Vec<(&'static str, HashFn<'a>)> {
    vec![
        ("crypto-pq", Box::new(|d: &[u8], o: &mut [u8]| cpq::ASCON_XOF128.digest_into(d, o).unwrap())),
        ("crypto-pq-aa", Box::new(|d: &[u8], o: &mut [u8]| cpq_aa::ASCON_XOF128.digest_into(d, o).unwrap())),
        ("ascon-xof128", Box::new(|d: &[u8], o: &mut [u8]| {
            use ascon_xof128::ExtendableOutput;

            ascon_xof128::AsconXof128::digest_xof(d, o)
        })),
        ("ascon-hash", Box::new(|d: &[u8], o: &mut [u8]| {
            use ascon_hash::ExtendableOutput;

            ascon_hash::AsconXof128::digest_xof(d, o)
        })),
        ("tc_ascon_hash", Box::new(|d: &[u8], o: &mut [u8]| {
            use tc_digest::{TryDigest, TryXof};

            let mut h = tc_ascon_hash::AsconXof128::new();

            h.try_update(d).unwrap();

            h.try_output_final(o).unwrap();
        })),
        ("ascon-rs", Box::new(|d: &[u8], o: &mut [u8]| ascon::xof128(d, o))),
        if_purecrypto!("purecrypto", Box::new(|d: &[u8], o: &mut [u8]| {
            use purecrypto::hash::{ExtendableOutput, XofReader};

            let mut h = purecrypto::ascon::AsconXof128::new();

            h.update(d);

            h.finalize_xof().read(o)
        })),
        if_rscrypto!("rscrypto", Box::new(|d: &[u8], o: &mut [u8]| {
            use rscrypto::Xof;

            rscrypto::AsconXof::xof(d).squeeze(o)
        })),
    ]
}

fn cxof128<'a>() -> Vec<(&'static str, HashFn<'a>)> {
    vec![
        ("crypto-pq", Box::new(|d: &[u8], o: &mut [u8]| {
            cpq::ASCON_CXOF128
                .configure(&cpq::XofOptions::default().with_customization(Z))
                .unwrap()
                .digest_into(d, o)
                .unwrap()
        })),
        ("crypto-pq-aa", Box::new(|d: &[u8], o: &mut [u8]| {
            cpq_aa::ASCON_CXOF128
                .configure(&cpq_aa::XofOptions::default().with_customization(Z))
                .unwrap()
                .digest_into(d, o)
                .unwrap()
        })),
        ("ascon-xof128", Box::new(|d: &[u8], o: &mut [u8]| {
            use ascon_xof128::{ExtendableOutput, TryCustomizedInit, Update};

            let mut h = ascon_xof128::AsconCxof128::try_new_customized(Z).unwrap();

            h.update(d);

            h.finalize_xof_into(o)
        })),
        ("tc_ascon_hash", Box::new(|d: &[u8], o: &mut [u8]| {
            use tc_digest::{TryDigest, TryXof};

            let mut h = tc_ascon_hash::AsconCXof128::with_customization(Z);

            h.try_update(d).unwrap();

            h.try_output_final(o).unwrap();
        })),
        ("ascon-rs", Box::new(|d: &[u8], o: &mut [u8]| ascon::cxof128(d, Z, o).unwrap())),
        if_purecrypto!("purecrypto", Box::new(|d: &[u8], o: &mut [u8]| purecrypto::ascon::AsconCxof128::xof(Z, d, o))),
        if_rscrypto!("rscrypto", Box::new(|d: &[u8], o: &mut [u8]| rscrypto::AsconCxof128::hash_into(Z, d, o).unwrap())),
    ]
}

pub fn rows() -> Vec<HashRow<'static>> {
    let mut rows = Vec::new();

    for n in SIZES {
        rows.push(HashRow { label: format!("ascon-hash256/{n}"), input: data(n, 11), out: 32, imps: hash256() });
    }

    for (n, out) in SIZES.iter().map(|&n| (n, 32)).chain([(64, 1024), (64, 16384)]) {
        rows.push(HashRow { label: format!("ascon-xof128/{n}>{out}"), input: data(n, 12), out, imps: xof128() });
    }

    for (n, out) in SIZES.iter().map(|&n| (n, 32)).chain([(64, 1024)]) {
        rows.push(HashRow { label: format!("ascon-cxof128/{n}>{out}"), input: data(n, 13), out, imps: cxof128() });
    }

    rows
}

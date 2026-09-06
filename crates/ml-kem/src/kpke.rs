//! K-PKE, the public-key encryption scheme inside ML-KEM (FIPS 203, section 5).
//!
//! `K` is the module rank; `eta1`, `eta2`, `du` and `dv` are the remaining
//! parameters of the set (FIPS 203, table 2). Byte buffers are passed as slices
//! because their lengths depend on `K`.

use crate::field::{intt, mul_ntt, ntt, Poly, N};
use crate::hash::{g, prf, xof};
use crate::poly::{
    add_assign, byte_decode, byte_encode, compress_encode, decode_decompress, sub_assign,
};
use crate::sample::{sample_ntt, sample_poly_cbd};
use zeroize::Zeroize;

type PolyVec<const K: usize> = [Poly; K];

/// Generates A_hat with A_hat[i][j] = SampleNTT(XOF(rho, j, i)).
fn gen_matrix<const K: usize>(rho: &[u8; 32]) -> [PolyVec<K>; K] {
    let mut a = [[[0u16; N]; K]; K];
    for (i, row) in a.iter_mut().enumerate() {
        for (j, entry) in row.iter_mut().enumerate() {
            let mut reader = xof(rho, j as u8, i as u8);
            sample_ntt(&mut reader, entry);
        }
    }
    a
}

/// Samples K polynomials from the centered binomial distribution, advancing the
/// PRF counter `n` once per polynomial.
fn sample_vec<const K: usize>(eta: usize, seed: &[u8; 32], n: &mut u8, out: &mut PolyVec<K>) {
    let mut buf = [0u8; 192];
    for poly in out.iter_mut() {
        let bytes = &mut buf[..64 * eta];
        prf(seed, *n, bytes);
        *n += 1;
        sample_poly_cbd(eta, bytes, poly);
    }
    buf.zeroize();
}

/// K-PKE.KeyGen (algorithm 13). Writes 384K + 32 bytes to `ek` and 384K bytes to `dk_pke`.
pub(crate) fn keygen<const K: usize>(d: &[u8; 32], eta1: usize, ek: &mut [u8], dk_pke: &mut [u8]) {
    let (rho, mut sigma) = g(&[d, &[K as u8]]);
    let a = gen_matrix::<K>(&rho);
    let mut n = 0u8;
    let mut s = [[0u16; N]; K];
    let mut e = [[0u16; N]; K];
    sample_vec::<K>(eta1, &sigma, &mut n, &mut s);
    sample_vec::<K>(eta1, &sigma, &mut n, &mut e);
    for p in s.iter_mut() {
        ntt(p);
    }
    for p in e.iter_mut() {
        ntt(p);
    }
    for i in 0..K {
        let mut t = e[i];
        for j in 0..K {
            add_assign(&mut t, &mul_ntt(&a[i][j], &s[j]));
        }
        byte_encode(12, &t, &mut ek[384 * i..384 * (i + 1)]);
        byte_encode(12, &s[i], &mut dk_pke[384 * i..384 * (i + 1)]);
    }
    ek[384 * K..].copy_from_slice(&rho);
    s.zeroize();
    e.zeroize();
    sigma.zeroize();
}

/// K-PKE.Encrypt (algorithm 14). Writes 32 (du K + dv) bytes to `c`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypt<const K: usize>(
    ek: &[u8],
    m: &[u8; 32],
    r: &[u8; 32],
    eta1: usize,
    eta2: usize,
    du: usize,
    dv: usize,
    c: &mut [u8],
) {
    let mut t = [[0u16; N]; K];
    for (i, p) in t.iter_mut().enumerate() {
        byte_decode(12, &ek[384 * i..384 * (i + 1)], p);
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[384 * K..384 * K + 32]);
    let a = gen_matrix::<K>(&rho);

    let mut n = 0u8;
    let mut y = [[0u16; N]; K];
    let mut e1 = [[0u16; N]; K];
    let mut e2 = [0u16; N];
    sample_vec::<K>(eta1, r, &mut n, &mut y);
    sample_vec::<K>(eta2, r, &mut n, &mut e1);
    {
        let mut buf = [0u8; 192];
        let bytes = &mut buf[..64 * eta2];
        prf(r, n, bytes);
        sample_poly_cbd(eta2, bytes, &mut e2);
        buf.zeroize();
    }
    for p in y.iter_mut() {
        ntt(p);
    }

    // u = NTT^-1(A_hat^T y_hat) + e1
    for i in 0..K {
        let mut u = [0u16; N];
        for j in 0..K {
            add_assign(&mut u, &mul_ntt(&a[j][i], &y[j]));
        }
        intt(&mut u);
        add_assign(&mut u, &e1[i]);
        compress_encode(du, &u, &mut c[32 * du * i..32 * du * (i + 1)]);
        u.zeroize();
    }

    // v = NTT^-1(t_hat^T y_hat) + e2 + Decompress_1(ByteDecode_1(m))
    let mut v = [0u16; N];
    for i in 0..K {
        add_assign(&mut v, &mul_ntt(&t[i], &y[i]));
    }
    intt(&mut v);
    add_assign(&mut v, &e2);
    let mut mu = [0u16; N];
    decode_decompress(1, m, &mut mu);
    add_assign(&mut v, &mu);
    compress_encode(dv, &v, &mut c[32 * du * K..]);

    y.zeroize();
    e1.zeroize();
    e2.zeroize();
    v.zeroize();
    mu.zeroize();
}

/// K-PKE.Decrypt (algorithm 15).
pub(crate) fn decrypt<const K: usize>(dk_pke: &[u8], c: &[u8], du: usize, dv: usize) -> [u8; 32] {
    let mut w = [0u16; N];
    decode_decompress(dv, &c[32 * du * K..], &mut w);
    let mut acc = [0u16; N];
    for i in 0..K {
        let mut u = [0u16; N];
        decode_decompress(du, &c[32 * du * i..32 * du * (i + 1)], &mut u);
        ntt(&mut u);
        let mut s = [0u16; N];
        byte_decode(12, &dk_pke[384 * i..384 * (i + 1)], &mut s);
        add_assign(&mut acc, &mul_ntt(&s, &u));
        s.zeroize();
    }
    intt(&mut acc);
    sub_assign(&mut w, &acc);
    let mut m = [0u8; 32];
    compress_encode(1, &w, &mut m);
    w.zeroize();
    acc.zeroize();
    m
}

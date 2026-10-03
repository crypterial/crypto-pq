use alloc::vec;
use alloc::vec::Vec;

use crate::ct;
use crate::primitives::{sha3_256, sha3_512, shake128, shake256_into};
use crate::wipe::{SecretBytes, wipe};

const Q: u32 = 3329;

type Poly = [u16; 256];

const fn power(base: u32, exponent: u32) -> u32 {
    let mut result = 1;

    let mut i = 0;

    while i < exponent {
        result = result * base % Q;

        i += 1;
    }

    result
}

const fn bit_reverse7(value: usize) -> u32 {
    (value as u32).reverse_bits() >> 25
}

const ZETAS: [u16; 128] = {
    let mut table = [0; 128];

    let mut i = 0;

    while i < 128 {
        table[i] = power(17, bit_reverse7(i)) as u16;

        i += 1;
    }

    table
};

const GAMMAS: [u16; 128] = {
    let mut table = [0; 128];

    let mut i = 0;

    while i < 128 {
        table[i] = power(17, 2 * bit_reverse7(i) + 1) as u16;

        i += 1;
    }

    table
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Parameters {
    k: usize,
    eta1: usize,
    eta2: usize,
    du: u32,
    dv: u32,
}

pub(crate) const ML_KEM_512: Parameters = Parameters {
    k: 2,
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
};

pub(crate) const ML_KEM_768: Parameters = Parameters {
    k: 3,
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
};

pub(crate) const ML_KEM_1024: Parameters = Parameters {
    k: 4,
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
};

impl Parameters {
    pub(crate) const fn encapsulation_key_size(&self) -> usize {
        384 * self.k + 32
    }

    pub(crate) const fn decapsulation_key_size(&self) -> usize {
        768 * self.k + 96
    }

    pub(crate) const fn ciphertext_size(&self) -> usize {
        32 * (self.du as usize * self.k + self.dv as usize)
    }
}

// floor(t / q) for t < 2^24 without a division: 20642679 = ceil(2^36 / q) is exact there.
const fn divide(t: u32) -> u32 {
    ((t as u64 * 20642679) >> 36) as u32
}

const fn reduce(t: u32) -> u16 {
    (t - divide(t) * Q) as u16
}

// x < 2q to x mod q, by a masked rather than a branching subtraction.
const fn subtract_q(x: u32) -> u16 {
    let y = x.wrapping_sub(Q);

    y.wrapping_add(Q & 0u32.wrapping_sub(y >> 31)) as u16
}

const fn add(a: u16, b: u16) -> u16 {
    subtract_q(a as u32 + b as u32)
}

const fn sub(a: u16, b: u16) -> u16 {
    subtract_q(a as u32 + Q - b as u32)
}

const fn mul(a: u16, b: u16) -> u16 {
    reduce(a as u32 * b as u32)
}

fn add_assign(f: &mut Poly, g: &Poly) {
    for (x, y) in f.iter_mut().zip(g) {
        *x = add(*x, *y);
    }
}

fn ntt(f: &mut Poly) {
    let mut i = 1;

    let mut length = 128;

    while length >= 2 {
        for start in (0..256).step_by(2 * length) {
            let zeta = ZETAS[i];

            i += 1;

            for j in start..start + length {
                let t = mul(zeta, f[j + length]);

                f[j + length] = sub(f[j], t);

                f[j] = add(f[j], t);
            }
        }

        length /= 2;
    }
}

fn inverse_ntt(f: &mut Poly) {
    let mut i = 127;

    let mut length = 2;

    while length <= 128 {
        for start in (0..256).step_by(2 * length) {
            let zeta = ZETAS[i];

            i -= 1;

            for j in start..start + length {
                let t = f[j];

                f[j] = add(t, f[j + length]);

                f[j + length] = mul(zeta, sub(f[j + length], t));
            }
        }

        length *= 2;
    }

    // 3303 = 128^-1 mod q.
    for x in f.iter_mut() {
        *x = mul(*x, 3303);
    }
}

// acc += f * g in the NTT domain (FIPS 203, Algorithms 11 and 12).
fn multiply_add(acc: &mut Poly, f: &Poly, g: &Poly) {
    for (i, gamma) in GAMMAS.iter().enumerate() {
        let (a0, a1, b0, b1) = (f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]);

        let c0 = add(mul(a0, b0), mul(mul(a1, b1), *gamma));

        let c1 = add(mul(a0, b1), mul(a1, b0));

        acc[2 * i] = add(acc[2 * i], c0);

        acc[2 * i + 1] = add(acc[2 * i + 1], c1);
    }
}

fn byte_encode(f: &Poly, d: u32, out: &mut [u8]) {
    let mut buffer = 0u64;

    let mut bits = 0;

    let mut position = 0;

    for &coefficient in f {
        buffer |= u64::from(coefficient) << bits;

        bits += d;

        while bits >= 8 {
            out[position] = buffer as u8;

            buffer >>= 8;

            bits -= 8;

            position += 1;
        }
    }
}

fn byte_decode(data: &[u8], d: u32) -> Poly {
    let mut f = [0; 256];

    let mut buffer = 0u64;

    let mut bits = 0;

    let mut index = 0;

    for &byte in data {
        buffer |= u64::from(byte) << bits;

        bits += 8;

        while bits >= d {
            f[index] = (buffer & ((1 << d) - 1)) as u16;

            buffer >>= d;

            bits -= d;

            index += 1;
        }
    }

    f
}

fn decode12(data: &[u8]) -> Poly {
    byte_decode(data, 12).map(|x| subtract_q(u32::from(x)))
}

// round(2^d * x / q): q is odd, so adding floor(q / 2) before the floor division never meets a tie.
const fn compress(x: u16, d: u32) -> u16 {
    (divide(((x as u32) << d) + 1664) & ((1 << d) - 1)) as u16
}

const fn decompress(y: u16, d: u32) -> u16 {
    ((y as u32 * Q + (1 << (d - 1))) >> d) as u16
}

fn sample_ntt(rho: &[u8], first: usize, second: usize) -> Poly {
    let mut stream = shake128(&[rho, &[first as u8, second as u8]]);

    let mut a = [0; 256];

    let mut count = 0;

    let mut block = [0u8; 168];

    while count < 256 {
        stream.read(&mut block);

        for chunk in block.chunks_exact(3) {
            let d1 = u16::from(chunk[0]) | (u16::from(chunk[1] & 0x0F) << 8);

            let d2 = u16::from(chunk[1] >> 4) | (u16::from(chunk[2]) << 4);

            for candidate in [d1, d2] {
                if u32::from(candidate) < Q && count < 256 {
                    a[count] = candidate;

                    count += 1;
                }
            }
        }
    }

    a
}

// FIPS 203, Algorithm 8, applied to PRF_eta(seed, nonce) = SHAKE256(seed || nonce).
fn sample_noise(eta: usize, seed: &[u8], nonce: usize) -> Poly {
    let mut buffer = [0u8; 192];

    let data = &mut buffer[..64 * eta];

    shake256_into(&[seed, &[nonce as u8]], data);

    let bit = |index: usize| u16::from((data[index / 8] >> (index % 8)) & 1);

    let f = core::array::from_fn(|i| {
        let start = 2 * i * eta;

        let x = (start..start + eta).map(bit).sum();

        let y = (start + eta..start + 2 * eta).map(bit).sum();

        sub(x, y)
    });

    wipe(&mut buffer);

    f
}

fn pke_keygen(d: &[u8], p: &Parameters, ek: &mut [u8], dk: &mut [u8]) {
    let k = p.k;

    let mut g = sha3_512(&[d, &[k as u8]]);

    let (rho, sigma) = g.split_at(32);

    let mut s = [[0; 256]; 4];

    let mut e = [[0; 256]; 4];

    for n in 0..k {
        s[n] = sample_noise(p.eta1, sigma, n);

        ntt(&mut s[n]);

        e[n] = sample_noise(p.eta1, sigma, k + n);

        ntt(&mut e[n]);
    }

    for i in 0..k {
        let mut t = e[i];

        for (j, s_j) in s[..k].iter().enumerate() {
            multiply_add(&mut t, &sample_ntt(rho, j, i), s_j);
        }

        byte_encode(&t, 12, &mut ek[384 * i..384 * (i + 1)]);

        byte_encode(&s[i], 12, &mut dk[384 * i..384 * (i + 1)]);
    }

    ek[384 * k..].copy_from_slice(rho);

    wipe(s.as_flattened_mut());

    wipe(e.as_flattened_mut());

    wipe(&mut g);
}

fn pke_encrypt(ek: &[u8], m: &[u8], r: &[u8], p: &Parameters, c: &mut [u8]) {
    let k = p.k;

    let rho = &ek[384 * k..];

    let mut y = [[0; 256]; 4];

    for (n, y_n) in y[..k].iter_mut().enumerate() {
        *y_n = sample_noise(p.eta1, r, n);

        ntt(y_n);
    }

    let (c1, c2) = c.split_at_mut(32 * p.du as usize * k);

    let mut u = [0; 256];

    for (i, chunk) in c1.chunks_exact_mut(32 * p.du as usize).enumerate() {
        u = [0; 256];

        for (j, y_j) in y[..k].iter().enumerate() {
            multiply_add(&mut u, &sample_ntt(rho, i, j), y_j);
        }

        inverse_ntt(&mut u);

        add_assign(&mut u, &sample_noise(p.eta2, r, k + i));

        byte_encode(&u.map(|x| compress(x, p.du)), p.du, chunk);
    }

    let mut v = [0; 256];

    for (i, y_i) in y[..k].iter().enumerate() {
        multiply_add(&mut v, &decode12(&ek[384 * i..384 * (i + 1)]), y_i);
    }

    inverse_ntt(&mut v);

    let mut noise = sample_noise(p.eta2, r, 2 * k);

    add_assign(&mut v, &noise);

    let mut mu = byte_decode(m, 1).map(|bit| decompress(bit, 1));

    add_assign(&mut v, &mu);

    byte_encode(&v.map(|x| compress(x, p.dv)), p.dv, c2);

    wipe(y.as_flattened_mut());

    wipe(&mut u);

    wipe(&mut v);

    wipe(&mut noise);

    wipe(&mut mu);
}

fn pke_decrypt(dk: &[u8], c: &[u8], p: &Parameters) -> [u8; 32] {
    let k = p.k;

    let (c1, c2) = c.split_at(32 * p.du as usize * k);

    let mut w = [0; 256];

    for (i, chunk) in c1.chunks_exact(32 * p.du as usize).enumerate() {
        let mut u = byte_decode(chunk, p.du).map(|x| decompress(x, p.du));

        ntt(&mut u);

        let mut s = decode12(&dk[384 * i..384 * (i + 1)]);

        multiply_add(&mut w, &s, &u);

        wipe(&mut s);
    }

    inverse_ntt(&mut w);

    let v = byte_decode(c2, p.dv).map(|x| decompress(x, p.dv));

    for (x, y) in w.iter_mut().zip(v) {
        *x = compress(sub(y, *x), 1);
    }

    let mut m = [0; 32];

    byte_encode(&w, 1, &mut m);

    wipe(&mut w);

    m
}

pub(crate) fn keygen_internal(d: &[u8], z: &[u8], p: &Parameters) -> (Vec<u8>, SecretBytes) {
    let k = p.k;

    let mut ek = vec![0; p.encapsulation_key_size()];

    let mut dk = SecretBytes::zeroed(p.decapsulation_key_size());

    pke_keygen(d, p, &mut ek, &mut dk[..384 * k]);

    dk[384 * k..768 * k + 32].copy_from_slice(&ek);

    dk[768 * k + 32..768 * k + 64].copy_from_slice(&sha3_256(&[&ek]));

    dk[768 * k + 64..].copy_from_slice(z);

    (ek, dk)
}

pub(crate) fn encaps_internal(ek: &[u8], m: &[u8], p: &Parameters) -> ([u8; 32], Vec<u8>) {
    let mut g = sha3_512(&[m, &sha3_256(&[ek])]);

    let mut c = vec![0; p.ciphertext_size()];

    pke_encrypt(ek, m, &g[32..], p, &mut c);

    let mut shared_secret = [0; 32];

    shared_secret.copy_from_slice(&g[..32]);

    wipe(&mut g);

    (shared_secret, c)
}

// Implicit rejection: a ciphertext that does not re-encrypt to itself yields J(z || c), chosen
// by a mask so that the comparison result never steers a branch.
pub(crate) fn decaps_internal(dk: &[u8], c: &[u8], p: &Parameters) -> [u8; 32] {
    let k = p.k;

    let (dk_pke, rest) = dk.split_at(384 * k);

    let (ek, rest) = rest.split_at(384 * k + 32);

    let (h, z) = rest.split_at(32);

    let mut m = pke_decrypt(dk_pke, c, p);

    let mut g = sha3_512(&[&m, h]);

    let mut rejected = [0; 32];

    shake256_into(&[z, c], &mut rejected);

    let mut reencrypted = SecretBytes::zeroed(c.len());

    pke_encrypt(ek, &m, &g[32..], p, &mut reencrypted);

    let mut shared_secret = [0; 32];

    ct::select(
        ct::equal_mask(c, &reencrypted),
        &g[..32],
        &rejected,
        &mut shared_secret,
    );

    wipe(&mut m);

    wipe(&mut g);

    wipe(&mut rejected);

    shared_secret
}

// FIPS 203, 7.2: every coefficient of the encoded vector must already be reduced modulo q.
pub(crate) fn check_encapsulation_key(ek: &[u8], p: &Parameters) -> bool {
    ek.len() == p.encapsulation_key_size()
        && ek[..384 * p.k].chunks_exact(3).all(|chunk| {
            let d1 = u32::from(chunk[0]) | (u32::from(chunk[1] & 0x0F) << 8);

            let d2 = u32::from(chunk[1] >> 4) | (u32::from(chunk[2]) << 4);

            d1 < Q && d2 < Q
        })
}

pub(crate) fn check_decapsulation_key(dk: &[u8], p: &Parameters) -> bool {
    let k = p.k;

    dk.len() == p.decapsulation_key_size()
        && check_encapsulation_key(public_key_of(dk, p), p)
        && ct::equal(
            &sha3_256(&[public_key_of(dk, p)]),
            &dk[768 * k + 32..768 * k + 64],
        )
}

pub(crate) fn public_key_of<'a>(dk: &'a [u8], p: &Parameters) -> &'a [u8] {
    &dk[384 * p.k..768 * p.k + 32]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn division_is_exact() {
        for t in 0..1 << 24 {
            assert_eq!(divide(t), t / Q, "{t}");
        }
    }

    #[test]
    fn compression_matches_the_definition() {
        for d in [1, 4, 5, 10, 11] {
            for x in 0..Q as u16 {
                let exact = (((u32::from(x) << d) + 1664) / Q) & ((1 << d) - 1);

                assert_eq!(u32::from(compress(x, d)), exact, "x = {x}, d = {d}");
            }
        }
    }

    #[test]
    fn modular_arithmetic() {
        for a in (0..Q as u16).step_by(7) {
            for b in (0..Q as u16).step_by(11) {
                let (x, y) = (u32::from(a), u32::from(b));

                assert_eq!(u32::from(add(a, b)), (x + y) % Q);

                assert_eq!(u32::from(sub(a, b)), (x + Q - y) % Q);

                assert_eq!(u32::from(mul(a, b)), x * y % Q);
            }
        }
    }
}

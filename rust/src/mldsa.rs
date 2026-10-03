use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use crate::ct;
use crate::primitives::{shake128, shake256, shake256_into};
use crate::wipe::{SecretBytes, wipe};

const Q: i32 = 8380417;

const D: u32 = 13;

// q^-1 mod 2^32, for Montgomery reduction.
const QINV: i32 = 58728449;

// 2^64 mod q: a second Montgomery reduction against it turns a*b*2^-32 back into a*b.
const R2: i32 = ((1u128 << 64) % Q as u128) as i32;

type Poly = [i32; 256];

const fn power(base: u64, exponent: u32) -> u64 {
    let mut result = 1;

    let mut i = 0;

    while i < exponent {
        result = result * base % Q as u64;

        i += 1;
    }

    result
}

// 1753^BitRev8(m) mod q, premultiplied by 2^32 so that one Montgomery reduction of a product with
// it gives the plain product modulo q.
const ZETAS: [i32; 256] = {
    let mut table = [0; 256];

    let mut m = 0;

    while m < 256 {
        let zeta = power(1753, (m as u32).reverse_bits() >> 24);

        table[m] = ((zeta << 32) % Q as u64) as i32;

        m += 1;
    }

    table
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Parameters {
    k: usize,
    l: usize,
    eta: i32,
    tau: usize,
    pub(crate) lambda: usize,
    gamma1: i32,
    gamma2: i32,
    omega: usize,
}

pub(crate) const ML_DSA_44: Parameters = Parameters {
    k: 4,
    l: 4,
    eta: 2,
    tau: 39,
    lambda: 128,
    gamma1: 1 << 17,
    gamma2: (Q - 1) / 88,
    omega: 80,
};

pub(crate) const ML_DSA_65: Parameters = Parameters {
    k: 6,
    l: 5,
    eta: 4,
    tau: 49,
    lambda: 192,
    gamma1: 1 << 19,
    gamma2: (Q - 1) / 32,
    omega: 55,
};

pub(crate) const ML_DSA_87: Parameters = Parameters {
    k: 8,
    l: 7,
    eta: 2,
    tau: 60,
    lambda: 256,
    gamma1: 1 << 19,
    gamma2: (Q - 1) / 32,
    omega: 75,
};

const fn bit_length(value: i32) -> u32 {
    u32::BITS - (value as u32).leading_zeros()
}

impl Parameters {
    const fn beta(&self) -> i32 {
        self.tau as i32 * self.eta
    }

    const fn eta_bits(&self) -> u32 {
        bit_length(2 * self.eta)
    }

    const fn gamma1_bits(&self) -> u32 {
        1 + bit_length(self.gamma1 - 1)
    }

    const fn w1_bits(&self) -> u32 {
        bit_length((Q - 1) / (2 * self.gamma2) - 1)
    }

    const fn challenge_size(&self) -> usize {
        self.lambda / 4
    }

    pub(crate) const fn public_key_size(&self) -> usize {
        32 + 320 * self.k
    }

    pub(crate) const fn private_key_size(&self) -> usize {
        128 + 32 * ((self.k + self.l) * self.eta_bits() as usize + D as usize * self.k)
    }

    pub(crate) const fn signature_size(&self) -> usize {
        self.challenge_size() + 32 * self.l * self.gamma1_bits() as usize + self.omega + self.k
    }
}

// A vector of polynomials, wiped when dropped because most of them hold secret values.
struct Polys(Vec<Poly>);

impl Polys {
    fn new(count: usize) -> Self {
        Self(vec![[0; 256]; count])
    }
}

impl Deref for Polys {
    type Target = [Poly];

    fn deref(&self) -> &[Poly] {
        &self.0
    }
}

impl DerefMut for Polys {
    fn deref_mut(&mut self) -> &mut [Poly] {
        &mut self.0
    }
}

impl Drop for Polys {
    fn drop(&mut self) {
        wipe(self.0.as_flattened_mut());
    }
}

const fn high(a: i32, b: i32) -> i32 {
    ((a as i64 * b as i64) >> 32) as i32
}

// a * b * 2^-32 mod q in (-q, q), for |a * b| < 2^31 q, given b_qinv = b * q^-1 mod 2^32. The
// low halves of a * b and of its multiple of q cancel, so only high halves are computed, which
// the compiler can vectorize.
const fn montgomery(a: i32, b: i32, b_qinv: i32) -> i32 {
    high(a, b) - high(a.wrapping_mul(b_qinv), Q)
}

const fn montgomery_mul(a: i32, b: i32) -> i32 {
    montgomery(a, b, b.wrapping_mul(QINV))
}

// (-q, q) to [0, q) with a mask instead of a branch.
const fn freeze(a: i32) -> i32 {
    a + (Q & (a >> 31))
}

// |a| < 2^31 - 2^22 to a representative of absolute value below q, without a division.
const fn reduce(a: i32) -> i32 {
    a - ((a + (1 << 22)) >> 23) * Q
}

const fn add(a: i32, b: i32) -> i32 {
    freeze(a + b - Q)
}

const fn sub(a: i32, b: i32) -> i32 {
    freeze(a - b)
}

const fn mul(a: i32, b: i32) -> i32 {
    freeze(montgomery_mul(montgomery_mul(a, b), R2))
}

// 2^64 / 256 mod q: one Montgomery reduction against it removes the 2^-32 that the pointwise
// products carry and divides by the 256 of the transform.
const INVERSE_SCALE: i32 = mul(R2, 8347681);

// A coefficient in (-q, q) to [0, q).
const fn canonical(a: i32) -> i32 {
    freeze(a)
}

// [0, q) to the representative in (-(q - 1) / 2, (q - 1) / 2].
const fn centered(a: i32) -> i32 {
    a - (Q & (((Q - 1) / 2 - a) >> 31))
}

// Inputs of absolute value below q; the butterflies reduce only their products, so the outputs
// stay below 9q in absolute value.
fn ntt(w: &mut Poly) {
    let mut m = 0;

    let mut length = 128;

    while length >= 1 {
        for start in (0..256).step_by(2 * length) {
            m += 1;

            let zeta = centered(ZETAS[m]);

            let zeta_qinv = zeta.wrapping_mul(QINV);

            let (low, high) = w[start..start + 2 * length].split_at_mut(length);

            for (a, b) in low.iter_mut().zip(high) {
                let t = montgomery(*b, zeta, zeta_qinv);

                *b = *a - t;

                *a += t;
            }
        }

        length /= 2;
    }
}

// Inverts ntt on sums of pointwise products (see INVERSE_SCALE) and returns coefficients in
// [0, q). The input is first brought below q in absolute value, so the sums of the butterflies
// stay below 256q.
fn inverse_ntt(w: &mut Poly) {
    for x in w.iter_mut() {
        *x = reduce(*x);
    }

    let mut m = 256;

    let mut length = 1;

    while length < 256 {
        for start in (0..256).step_by(2 * length) {
            m -= 1;

            let zeta = -centered(ZETAS[m]);

            let zeta_qinv = zeta.wrapping_mul(QINV);

            let (low, high) = w[start..start + 2 * length].split_at_mut(length);

            for (a, b) in low.iter_mut().zip(high) {
                let t = *a;

                *a = t + *b;

                *b = montgomery(t - *b, zeta, zeta_qinv);
            }
        }

        length *= 2;
    }

    let scale_qinv = INVERSE_SCALE.wrapping_mul(QINV);

    for x in w.iter_mut() {
        *x = freeze(montgomery(*x, INVERSE_SCALE, scale_qinv));
    }
}

// acc += f * g * 2^-32 coefficient-wise, for outputs of ntt; inverse_ntt reduces the sums.
fn multiply_add(acc: &mut Poly, f: &Poly, g: &Poly) {
    for ((x, a), b) in acc.iter_mut().zip(f).zip(g) {
        *x += montgomery_mul(*a, *b);
    }
}

fn pointwise(f: &Poly, g: &Poly) -> Poly {
    core::array::from_fn(|i| montgomery_mul(f[i], g[i]))
}

// Branch-free FIPS 204 Algorithm 36 for r in [0, q): (r1, r0) with r0 centered.
const fn decompose(r: i32, gamma2: i32) -> (i32, i32) {
    let mut r1 = (r + 127) >> 7;

    if gamma2 == (Q - 1) / 32 {
        r1 = ((r1 * 1025 + (1 << 21)) >> 22) & 15;
    } else {
        r1 = (r1 * 11275 + (1 << 23)) >> 24;

        r1 ^= ((43 - r1) >> 31) & r1;
    }

    let r0 = r - r1 * 2 * gamma2;

    (r1, r0 - ((((Q - 1) / 2 - r0) >> 31) & Q))
}

const fn high_bits(r: i32, gamma2: i32) -> i32 {
    decompose(r, gamma2).0
}

const fn low_bits(r: i32, gamma2: i32) -> i32 {
    decompose(r, gamma2).1
}

// FIPS 204 Algorithm 35 for r in [0, q): (r + 2^12 - 1) >> 13 rounds r / 2^13 the same way.
const fn power2round(r: i32) -> (i32, i32) {
    let r1 = (r + (1 << (D - 1)) - 1) >> D;

    (r1, r - (r1 << D))
}

fn use_hint(hint: bool, r: i32, gamma2: i32) -> i32 {
    let m = (Q - 1) / (2 * gamma2);

    let (r1, r0) = decompose(r, gamma2);

    match (hint, r0 > 0) {
        (false, _) => r1,
        (true, true) => (r1 + 1) % m,
        (true, false) => (r1 - 1 + m) % m,
    }
}

// -1 when some centered value reaches the bound in absolute value, 0 otherwise, computed over
// every value without branching on any of them.
fn reaches(values: impl IntoIterator<Item = i32>, bound: i32) -> i32 {
    values.into_iter().fold(0, |flag, value| {
        let sign = value >> 31;

        flag | ((bound - 1 - ((value ^ sign) - sign)) >> 31)
    })
}

fn pack(out: &mut [u8], bits: u32, values: impl IntoIterator<Item = i32>) {
    let mut poly = [0; 256];

    for (x, value) in poly.iter_mut().zip(values) {
        *x = value;
    }

    match bits {
        3 => pack_bits::<3>(out, &poly),
        4 => pack_bits::<4>(out, &poly),
        6 => pack_bits::<6>(out, &poly),
        10 => pack_bits::<10>(out, &poly),
        13 => pack_bits::<13>(out, &poly),
        18 => pack_bits::<18>(out, &poly),
        20 => pack_bits::<20>(out, &poly),
        _ => unreachable!("no ML-DSA encoding uses {bits} bits"),
    }

    wipe(&mut poly);
}

fn unpack(data: &[u8], bits: u32) -> Poly {
    match bits {
        3 => unpack_bits::<3>(data),
        4 => unpack_bits::<4>(data),
        6 => unpack_bits::<6>(data),
        10 => unpack_bits::<10>(data),
        13 => unpack_bits::<13>(data),
        18 => unpack_bits::<18>(data),
        20 => unpack_bits::<20>(data),
        _ => unreachable!("no ML-DSA encoding uses {bits} bits"),
    }
}

// Values move in groups that fill whole bytes and fit 128 bits, eight of them or four above 16
// bits, so that every shift is a constant.
const fn group_size(bits: usize) -> usize {
    if bits <= 16 { 8 } else { 4 }
}

fn pack_bits<const BITS: usize>(out: &mut [u8], values: &Poly) {
    let size = group_size(BITS);

    for (bytes, group) in out
        .chunks_exact_mut(BITS * size / 8)
        .zip(values.chunks_exact(size))
    {
        let word = group.iter().enumerate().fold(0u128, |word, (i, &value)| {
            word | (u128::from(value as u32) << (BITS * i))
        });

        for (j, byte) in bytes.iter_mut().enumerate() {
            *byte = (word >> (8 * j)) as u8;
        }
    }
}

fn unpack_bits<const BITS: usize>(data: &[u8]) -> Poly {
    let size = group_size(BITS);

    let mut values = [0; 256];

    for (group, bytes) in values
        .chunks_exact_mut(size)
        .zip(data.chunks_exact(BITS * size / 8))
    {
        let word = bytes
            .iter()
            .rev()
            .fold(0u128, |word, &byte| (word << 8) | u128::from(byte));

        for (i, value) in group.iter_mut().enumerate() {
            *value = (word >> (BITS * i)) as i32 & ((1 << BITS) - 1);
        }
    }

    values
}

fn rej_ntt_poly(rho: &[u8], s: usize, r: usize) -> Poly {
    let mut stream = shake128(&[rho, &[s as u8, r as u8]]);

    let mut a = [0; 256];

    let mut count = 0;

    let mut block = [0u8; 168];

    while count < 256 {
        stream.read(&mut block);

        for chunk in block.as_chunks::<3>().0 {
            let z = i32::from(chunk[0])
                | (i32::from(chunk[1]) << 8)
                | (i32::from(chunk[2] & 0x7F) << 16);

            if z < Q && count < 256 {
                a[count] = z;

                count += 1;
            }
        }
    }

    a
}

// The rejection decisions are variable time, as FIPS 204 allows, but no branch depends on a
// candidate: each one is written and only an accepted one advances the count. The accepted values
// are computed without a division (205 * x >> 10 = x / 5 for x < 15).
fn rej_bounded_poly(seed: &[u8], r: usize, eta: i32) -> Poly {
    let mut stream = shake256(&[seed, &(r as u16).to_le_bytes()]);

    let mut a = [0; 256];

    let mut count = 0;

    let mut block = [0u8; 136];

    'blocks: while count < 256 {
        stream.read(&mut block);

        for half in block.iter().flat_map(|&byte| [byte & 0x0F, byte >> 4]) {
            let half = i32::from(half);

            let (value, accepted) = if eta == 2 {
                (2 - (half - 5 * ((205 * half) >> 10)), half < 15)
            } else {
                (4 - half, half < 9)
            };

            a[count] = value;

            count += usize::from(accepted);

            if count == 256 {
                break 'blocks;
            }
        }
    }

    wipe(&mut block);

    a
}

fn expand_a(rho: &[u8], p: &Parameters) -> Polys {
    let mut a = Polys::new(p.k * p.l);

    for (index, poly) in a.iter_mut().enumerate() {
        *poly = rej_ntt_poly(rho, index % p.l, index / p.l);
    }

    a
}

// Signed coefficients of s1 and s2 (FIPS 204 Algorithm 33).
fn expand_s(rho_prime: &[u8], p: &Parameters) -> Polys {
    let mut s = Polys::new(p.l + p.k);

    for (r, poly) in s.iter_mut().enumerate() {
        *poly = rej_bounded_poly(rho_prime, r, p.eta);
    }

    s
}

fn expand_mask(rho: &[u8], kappa: u16, p: &Parameters, y: &mut Polys) {
    let bits = p.gamma1_bits();

    let mut buffer = [0u8; 640];

    for (r, poly) in y.iter_mut().enumerate() {
        let data = &mut buffer[..32 * bits as usize];

        let nonce = kappa.wrapping_add(r as u16).to_le_bytes();

        shake256_into(&[rho, &nonce], data);

        *poly = unpack(data, bits).map(|x| canonical(p.gamma1 - x));
    }

    wipe(&mut buffer);
}

fn sample_in_ball(seed: &[u8], tau: usize) -> Poly {
    let mut stream = shake256(&[seed]);

    let mut signs = [0u8; 8];

    stream.read(&mut signs);

    let mut signs = u64::from_le_bytes(signs);

    let mut c = [0; 256];

    for i in 256 - tau..256 {
        let mut j = [0u8];

        loop {
            stream.read(&mut j);

            if usize::from(j[0]) <= i {
                break;
            }
        }

        let j = usize::from(j[0]);

        c[i] = c[j];

        c[j] = 1 - 2 * (signs & 1) as i32;

        signs >>= 1;
    }

    c.map(canonical)
}

fn ntt_of(signed: &Poly) -> Poly {
    let mut f = signed.map(canonical);

    ntt(&mut f);

    f
}

// t = A * s1 + s2 from the signed s1 and s2.
fn public_t(a: &Polys, s1: &[Poly], s2: &[Poly], p: &Parameters) -> Polys {
    let mut s1_hat = Polys::new(p.l);

    for (hat, s) in s1_hat.iter_mut().zip(s1) {
        *hat = ntt_of(s);
    }

    let mut t = Polys::new(p.k);

    for (i, t_i) in t.iter_mut().enumerate() {
        for (j, s_j) in s1_hat.iter().enumerate() {
            multiply_add(t_i, &a[i * p.l + j], s_j);
        }

        inverse_ntt(t_i);

        for (x, e) in t_i.iter_mut().zip(&s2[i]) {
            *x = add(*x, canonical(*e));
        }
    }

    t
}

fn encode_public_key(rho: &[u8], t: &Polys, p: &Parameters) -> Vec<u8> {
    let mut pk = vec![0; p.public_key_size()];

    pk[..32].copy_from_slice(rho);

    for (chunk, poly) in pk[32..].as_chunks_mut::<320>().0.iter_mut().zip(t.iter()) {
        pack(chunk, 10, poly.iter().map(|&x| power2round(x).0));
    }

    pk
}

fn encode_private_key(parts: [&[u8]; 3], s: &Polys, t: &Polys, p: &Parameters) -> SecretBytes {
    let mut sk = SecretBytes::zeroed(p.private_key_size());

    sk[..32].copy_from_slice(parts[0]);

    sk[32..64].copy_from_slice(parts[1]);

    sk[64..128].copy_from_slice(parts[2]);

    let size = 32 * p.eta_bits() as usize;

    let (s_bytes, t0_bytes) = sk[128..].split_at_mut((p.l + p.k) * size);

    for (chunk, poly) in s_bytes.chunks_exact_mut(size).zip(s.iter()) {
        pack(chunk, p.eta_bits(), poly.iter().map(|&x| p.eta - x));
    }

    for (chunk, poly) in t0_bytes
        .as_chunks_mut::<{ 32 * D as usize }>()
        .0
        .iter_mut()
        .zip(t.iter())
    {
        pack(
            chunk,
            D,
            poly.iter().map(|&x| (1 << (D - 1)) - power2round(x).1),
        );
    }

    sk
}

struct PrivateKey<'a> {
    rho: &'a [u8],
    key: &'a [u8],
    tr: &'a [u8],
    s: Polys,
    t0: Polys,
}

fn decode_private_key<'a>(sk: &'a [u8], p: &Parameters) -> PrivateKey<'a> {
    let size = 32 * p.eta_bits() as usize;

    let (s_bytes, t0_bytes) = sk[128..].split_at((p.l + p.k) * size);

    let mut s = Polys::new(p.l + p.k);

    for (poly, chunk) in s.iter_mut().zip(s_bytes.chunks_exact(size)) {
        *poly = unpack(chunk, p.eta_bits()).map(|x| p.eta - x);
    }

    let mut t0 = Polys::new(p.k);

    for (poly, chunk) in t0
        .iter_mut()
        .zip(t0_bytes.as_chunks::<{ 32 * D as usize }>().0.iter())
    {
        *poly = unpack(chunk, D).map(|x| (1 << (D - 1)) - x);
    }

    PrivateKey {
        rho: &sk[..32],
        key: &sk[32..64],
        tr: &sk[64..128],
        s,
        t0,
    }
}

fn hash_public_key(pk: &[u8]) -> [u8; 64] {
    let mut tr = [0; 64];

    shake256_into(&[pk], &mut tr);

    tr
}

pub(crate) fn keygen_internal(xi: &[u8], p: &Parameters) -> (Vec<u8>, SecretBytes) {
    let mut seeds = [0u8; 128];

    shake256_into(&[xi, &[p.k as u8, p.l as u8]], &mut seeds);

    let (rho, rest) = seeds.split_at(32);

    let (rho_prime, key) = rest.split_at(64);

    let s = expand_s(rho_prime, p);

    let (s1, s2) = s.split_at(p.l);

    let t = public_t(&expand_a(rho, p), s1, s2, p);

    let pk = encode_public_key(rho, &t, p);

    let sk = encode_private_key([rho, key, &hash_public_key(&pk)], &s, &t, p);

    wipe(&mut seeds);

    (pk, sk)
}

// An expanded private key carries everything needed to rebuild the public key, so a key whose
// parts disagree is rejected instead of producing signatures that never verify. Re-encoding the
// key from its own s1, s2, rho and K compares t0 and tr in one constant-time pass.
pub(crate) fn check_private_key(sk: &[u8], p: &Parameters) -> Option<Vec<u8>> {
    let key = decode_private_key(sk, p);

    if reaches(key.s.iter().flatten().copied(), p.eta + 1) != 0 {
        return None;
    }

    let (s1, s2) = key.s.split_at(p.l);

    let t = public_t(&expand_a(key.rho, p), s1, s2, p);

    let pk = encode_public_key(key.rho, &t, p);

    let rebuilt = encode_private_key([key.rho, key.key, &hash_public_key(&pk)], &key.s, &t, p);

    ct::equal(&rebuilt, sk).then_some(pk)
}

fn hint_bit_pack(h: &Polys, p: &Parameters, out: &mut [u8]) {
    let mut index = 0;

    for (i, poly) in h.iter().enumerate() {
        for (j, &bit) in poly.iter().enumerate() {
            if bit != 0 {
                out[index] = j as u8;

                index += 1;
            }
        }

        out[p.omega + i] = index as u8;
    }
}

// FIPS 204, Algorithm 21: the encoding must be canonical (strictly increasing indices, zero
// padding), otherwise the signature is rejected.
fn hint_bit_unpack(data: &[u8], p: &Parameters) -> Option<Vec<[bool; 256]>> {
    let mut h = vec![[false; 256]; p.k];

    let mut index = 0;

    for (i, poly) in h.iter_mut().enumerate() {
        let end = usize::from(data[p.omega + i]);

        if end < index || end > p.omega {
            return None;
        }

        let first = index;

        while index < end {
            if index > first && data[index - 1] >= data[index] {
                return None;
            }

            poly[usize::from(data[index])] = true;

            index += 1;
        }
    }

    data[index..p.omega]
        .iter()
        .all(|&byte| byte == 0)
        .then_some(h)
}

fn encode_w1(w: &Polys, p: &Parameters, out: &mut [u8]) {
    let bits = p.w1_bits();

    for (chunk, poly) in out.chunks_exact_mut(32 * bits as usize).zip(w.iter()) {
        pack(chunk, bits, poly.iter().map(|&x| high_bits(x, p.gamma2)));
    }
}

fn challenge(mu: &[u8], w1: &[u8], p: &Parameters) -> [u8; 64] {
    let mut c_tilde = [0; 64];

    shake256_into(&[mu, w1], &mut c_tilde[..p.challenge_size()]);

    c_tilde
}

fn message_hash(tr: &[u8], message: &[&[u8]]) -> [u8; 64] {
    let mut stream = shake256(&[tr]);

    for part in message {
        stream.update(part);
    }

    let mut mu = [0; 64];

    stream.read(&mut mu);

    mu
}

// FIPS 204 Algorithm 7. The norm checks run over every coefficient without branching; only their
// combined outcome, the rejection decision, steers the loop.
pub(crate) fn sign_internal(sk: &[u8], message: &[&[u8]], rnd: &[u8], p: &Parameters) -> Vec<u8> {
    let key = decode_private_key(sk, p);

    let mut s_hat = Polys::new(p.l + p.k);

    for (hat, s) in s_hat.iter_mut().zip(key.s.iter()) {
        *hat = ntt_of(s);
    }

    let (s1_hat, s2_hat) = s_hat.split_at(p.l);

    let mut t0_hat = Polys::new(p.k);

    for (hat, t) in t0_hat.iter_mut().zip(key.t0.iter()) {
        *hat = ntt_of(t);
    }

    let a = expand_a(key.rho, p);

    let mu = message_hash(key.tr, message);

    let mut rho_prime = [0u8; 64];

    shake256_into(&[key.key, rnd, &mu], &mut rho_prime);

    let mut y = Polys::new(p.l);

    let mut y_hat = Polys::new(p.l);

    let mut z = Polys::new(p.l);

    let mut w = Polys::new(p.k);

    let mut r = Polys::new(p.k);

    let mut ct0 = Polys::new(p.k);

    let mut h = Polys::new(p.k);

    let mut w1 = vec![0; 32 * p.k * p.w1_bits() as usize];

    let mut kappa = 0u16;

    let c_tilde = loop {
        expand_mask(&rho_prime, kappa, p, &mut y);

        kappa = kappa.wrapping_add(p.l as u16);

        for (hat, poly) in y_hat.iter_mut().zip(y.iter()) {
            *hat = *poly;

            ntt(hat);
        }

        for (i, w_i) in w.iter_mut().enumerate() {
            *w_i = [0; 256];

            for (j, y_j) in y_hat.iter().enumerate() {
                multiply_add(w_i, &a[i * p.l + j], y_j);
            }

            inverse_ntt(w_i);
        }

        encode_w1(&w, p, &mut w1);

        let c_tilde = challenge(&mu, &w1, p);

        let mut c_hat = sample_in_ball(&c_tilde[..p.challenge_size()], p.tau);

        ntt(&mut c_hat);

        for ((z_i, y_i), s) in z.iter_mut().zip(y.iter()).zip(s1_hat) {
            let mut cs1 = pointwise(&c_hat, s);

            inverse_ntt(&mut cs1);

            for ((x, a), b) in z_i.iter_mut().zip(y_i).zip(&cs1) {
                *x = add(*a, *b);
            }

            wipe(&mut cs1);
        }

        // r holds w - c*s2, the argument of both the low-bits check and the hints.
        for ((r_i, w_i), s) in r.iter_mut().zip(w.iter()).zip(s2_hat) {
            let mut cs2 = pointwise(&c_hat, s);

            inverse_ntt(&mut cs2);

            for ((x, a), b) in r_i.iter_mut().zip(w_i).zip(&cs2) {
                *x = sub(*a, *b);
            }

            wipe(&mut cs2);
        }

        let z_check = reaches(
            z.iter().flatten().map(|&x| centered(x)),
            p.gamma1 - p.beta(),
        );

        let r0_check = reaches(
            r.iter().flatten().map(|&x| low_bits(x, p.gamma2)),
            p.gamma2 - p.beta(),
        );

        if z_check | r0_check != 0 {
            continue;
        }

        for (ct0_i, t) in ct0.iter_mut().zip(t0_hat.iter()) {
            *ct0_i = pointwise(&c_hat, t);

            inverse_ntt(ct0_i);
        }

        let mut count = 0;

        for ((h_i, r_i), ct0_i) in h.iter_mut().zip(r.iter()).zip(ct0.iter()) {
            for ((bit, &x), &c) in h_i.iter_mut().zip(r_i).zip(ct0_i) {
                let difference = high_bits(add(x, c), p.gamma2) ^ high_bits(x, p.gamma2);

                *bit = ((difference | -difference) >> 31) & 1;

                count += *bit;
            }
        }

        let ct0_check = reaches(ct0.iter().flatten().map(|&x| centered(x)), p.gamma2);

        if ct0_check != 0 || count > p.omega as i32 {
            continue;
        }

        break c_tilde;
    };

    let mut signature = vec![0; p.signature_size()];

    let (head, hints) = signature.split_at_mut(p.signature_size() - p.omega - p.k);

    let (c_part, z_part) = head.split_at_mut(p.challenge_size());

    c_part.copy_from_slice(&c_tilde[..p.challenge_size()]);

    let bits = p.gamma1_bits();

    for (chunk, poly) in z_part.chunks_exact_mut(32 * bits as usize).zip(z.iter()) {
        pack(chunk, bits, poly.iter().map(|&x| p.gamma1 - centered(x)));
    }

    hint_bit_pack(&h, p, hints);

    wipe(&mut rho_prime);

    signature
}

pub(crate) fn verify_internal(pk: &[u8], message: &[&[u8]], sig: &[u8], p: &Parameters) -> bool {
    if pk.len() != p.public_key_size() || sig.len() != p.signature_size() {
        return false;
    }

    let (c_tilde, rest) = sig.split_at(p.challenge_size());

    let bits = p.gamma1_bits();

    let (z_bytes, hint_bytes) = rest.split_at(32 * p.l * bits as usize);

    let Some(h) = hint_bit_unpack(hint_bytes, p) else {
        return false;
    };

    let mut z = Polys::new(p.l);

    for (poly, chunk) in z.iter_mut().zip(z_bytes.chunks_exact(32 * bits as usize)) {
        *poly = unpack(chunk, bits).map(|x| p.gamma1 - x);
    }

    if reaches(z.iter().flatten().copied(), p.gamma1 - p.beta()) != 0 {
        return false;
    }

    let a = expand_a(&pk[..32], p);

    let mu = message_hash(&hash_public_key(pk), message);

    let mut c_hat = sample_in_ball(c_tilde, p.tau);

    ntt(&mut c_hat);

    for poly in z.iter_mut() {
        *poly = ntt_of(poly);
    }

    let mut w = Polys::new(p.k);

    for ((i, w_i), chunk) in w
        .iter_mut()
        .enumerate()
        .zip(pk[32..].as_chunks::<320>().0.iter())
    {
        let mut t1 = unpack(chunk, 10).map(|x| x << D);

        ntt(&mut t1);

        *w_i = pointwise(&c_hat, &t1).map(|x| -x);

        for (j, z_j) in z.iter().enumerate() {
            multiply_add(w_i, &a[i * p.l + j], z_j);
        }

        inverse_ntt(w_i);
    }

    let mut w1 = vec![0; 32 * p.k * p.w1_bits() as usize];

    for ((chunk, w_i), h_i) in w1
        .chunks_exact_mut(32 * p.w1_bits() as usize)
        .zip(w.iter())
        .zip(&h)
    {
        let hinted = w_i
            .iter()
            .zip(h_i)
            .map(|(&x, &hint)| use_hint(hint, x, p.gamma2));

        pack(chunk, p.w1_bits(), hinted);
    }

    challenge(&mu, &w1, p)[..p.challenge_size()] == *c_tilde
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_decompose(r: i32, gamma2: i32) -> (i32, i32) {
        let mut r0 = r % (2 * gamma2);

        if r0 > gamma2 {
            r0 -= 2 * gamma2;
        }

        if r - r0 == Q - 1 {
            (0, r0 - 1)
        } else {
            ((r - r0) / (2 * gamma2), r0)
        }
    }

    #[test]
    fn decompose_matches_the_definition() {
        for gamma2 in [(Q - 1) / 88, (Q - 1) / 32] {
            for r in 0..Q {
                assert_eq!(decompose(r, gamma2), reference_decompose(r, gamma2), "{r}");
            }
        }
    }

    #[test]
    fn power2round_matches_the_definition() {
        for r in 0..Q {
            let mut r0 = r & ((1 << D) - 1);

            if r0 > 1 << (D - 1) {
                r0 -= 1 << D;
            }

            assert_eq!(power2round(r), ((r - r0) >> D, r0), "{r}");
        }
    }

    #[test]
    fn modular_arithmetic() {
        for a in (0..Q).step_by(99_991) {
            for b in (0..Q).step_by(77_773) {
                let (x, y) = (i64::from(a), i64::from(b));

                let q = i64::from(Q);

                assert_eq!(i64::from(add(a, b)), (x + y) % q);

                assert_eq!(i64::from(sub(a, b)), (x - y).rem_euclid(q));

                assert_eq!(i64::from(mul(a, b)), x * y % q);
            }
        }

        assert_eq!(R2, 2365951);

        assert_eq!(ZETAS[1], mul(4808194, 4193792));
    }
}

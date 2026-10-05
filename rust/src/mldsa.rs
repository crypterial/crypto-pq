use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use crate::cpu::{self, Field, Prepare};
use crate::ct::{self, declassify, declassify_value};
use crate::keccak::{self, MAX_SPONGES, Sponges};
use crate::primitives::{shake256, shake256_into};
use crate::wipe::{SecretBytes, wipe};

const Q: i32 = 8380417;

const SHAKE: u8 = 0x1F;

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

// The twiddle factors as the CPU kernels take them.
static FIELD: Field = Field::new(
    Q,
    QINV,
    8,
    {
        let mut zetas = [0; 256];

        let mut m = 0;

        while m < 256 {
            zetas[m] = centered(ZETAS[m]);

            m += 1;
        }

        zetas
    },
    Prepare::Reduce,
    None,
    INVERSE_SCALE,
);

// Inputs of absolute value below q; the butterflies reduce only their products, so the outputs
// stay below 9q in absolute value.
fn ntt(w: &mut Poly) {
    if !cpu::ntt(w, &FIELD) {
        ntt_portable(w);
    }
}

fn ntt_portable(w: &mut Poly) {
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
    if !cpu::inverse_ntt(w, &FIELD) {
        inverse_ntt_portable(w);
    }
}

fn inverse_ntt_portable(w: &mut Poly) {
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

// acc += f[j] * g[j] * 2^-32 coefficient-wise, summed over j, for outputs of ntt; inverse_ntt
// reduces the sums.
fn multiply_add(acc: &mut Poly, f: &[Poly], g: &[Poly]) {
    if !cpu::multiply_add(acc, f, g, &FIELD) {
        for (f, g) in f.iter().zip(g) {
            multiply_add_portable(acc, f, g);
        }
    }
}

fn multiply_add_portable(acc: &mut Poly, f: &Poly, g: &Poly) {
    for ((x, a), b) in acc.iter_mut().zip(f).zip(g) {
        *x += montgomery_mul(*a, *b);
    }
}

fn pointwise(f: &Poly, g: &Poly) -> Poly {
    let mut product = [0; 256];

    if !cpu::multiply(&mut product, f, g, &FIELD) {
        product = pointwise_portable(f, g);
    }

    product
}

fn pointwise_portable(f: &Poly, g: &Poly) -> Poly {
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

// out = a + b or a - b modulo q, coefficient by coefficient, for canonical a and b.
fn add_polys(out: &mut Poly, a: &Poly, b: &Poly) {
    if !cpu::mldsa_add(out, a, b, Q) {
        add_polys_portable(out, a, b);
    }
}

fn add_polys_portable(out: &mut Poly, a: &Poly, b: &Poly) {
    for ((x, a), b) in out.iter_mut().zip(a).zip(b) {
        *x = add(*a, *b);
    }
}

fn sub_polys(out: &mut Poly, a: &Poly, b: &Poly) {
    if !cpu::mldsa_sub(out, a, b, Q) {
        sub_polys_portable(out, a, b);
    }
}

fn sub_polys_portable(out: &mut Poly, a: &Poly, b: &Poly) {
    for ((x, a), b) in out.iter_mut().zip(a).zip(b) {
        *x = sub(*a, *b);
    }
}

// reaches over the centered coefficients of a polynomial in [0, q), or with gamma2 over the low
// bits that Decompose gives them.
fn poly_reaches(values: &Poly, bound: i32, gamma2: Option<i32>) -> i32 {
    match cpu::mldsa_norm(values, bound, gamma2, Q) {
        Some(flag) => flag,
        None => poly_reaches_portable(values, bound, gamma2),
    }
}

fn poly_reaches_portable(values: &Poly, bound: i32, gamma2: Option<i32>) -> i32 {
    match gamma2 {
        Some(gamma2) => reaches(values.iter().map(|&x| low_bits(x, gamma2)), bound),
        None => reaches(values.iter().map(|&x| centered(x)), bound),
    }
}

// The hint bits of r and ct0, h = [HighBits(r + ct0) != HighBits(r)], and how many are set.
fn make_hints(h: &mut Poly, r: &Poly, ct0: &Poly, gamma2: i32) -> i32 {
    match cpu::mldsa_hints(h, r, ct0, gamma2, Q) {
        Some(count) => count,
        None => make_hints_portable(h, r, ct0, gamma2),
    }
}

fn make_hints_portable(h: &mut Poly, r: &Poly, ct0: &Poly, gamma2: i32) -> i32 {
    let mut count = 0;

    for ((bit, &x), &c) in h.iter_mut().zip(r).zip(ct0) {
        let difference = high_bits(add(x, c), gamma2) ^ high_bits(x, gamma2);

        *bit = ((difference | -difference) >> 31) & 1;

        count += *bit;
    }

    count
}

fn pack(out: &mut [u8], bits: u32, values: impl IntoIterator<Item = i32>) {
    let mut poly = [0; 256];

    for (x, value) in poly.iter_mut().zip(values) {
        *x = value;
    }

    pack_with(out, bits, &poly, |x| x);

    wipe(&mut poly);
}

// pack of f applied to every coefficient, which maps them as they are packed instead of into a
// buffer that would then need wiping.
fn pack_with(out: &mut [u8], bits: u32, poly: &Poly, f: impl Fn(i32) -> i32) {
    match bits {
        3 => pack_bits::<3>(out, poly, f),
        4 => pack_bits::<4>(out, poly, f),
        6 => pack_bits::<6>(out, poly, f),
        10 => pack_bits::<10>(out, poly, f),
        13 => pack_bits::<13>(out, poly, f),
        18 => pack_bits::<18>(out, poly, f),
        20 => pack_bits::<20>(out, poly, f),
        _ => unreachable!("no ML-DSA encoding uses {bits} bits"),
    }
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

fn pack_bits<const BITS: usize>(out: &mut [u8], values: &Poly, f: impl Fn(i32) -> i32) {
    let size = group_size(BITS);

    for (bytes, group) in out
        .chunks_exact_mut(BITS * size / 8)
        .zip(values.chunks_exact(size))
    {
        let word = group.iter().enumerate().fold(0u128, |word, (i, &value)| {
            word | (u128::from(f(value) as u32) << (BITS * i))
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

// One block of an XOF stream, as the lanes of the sponge, into the coefficients accepted so far
// (FIPS 204 Algorithm 30).
fn sample_uniform(block: &[u64; 21], a: &mut Poly, count: &mut usize) {
    if !cpu::uniform23(block, Q, a, count) {
        sample_uniform_portable(block, a, count);
    }
}

// The matrix is public, so its rejections may branch.
fn sample_uniform_portable(block: &[u64; 21], a: &mut Poly, count: &mut usize) {
    let mut bytes = [0; 168];

    for (out, lane) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(block) {
        *out = lane.to_le_bytes();
    }

    for chunk in bytes.as_chunks::<3>().0 {
        let z =
            i32::from(chunk[0]) | (i32::from(chunk[1]) << 8) | (i32::from(chunk[2] & 0x7F) << 16);

        if z < Q && *count < 256 {
            a[*count] = z;

            *count += 1;
        }
    }
}

// Entries first, first + 1, ... of Â, whose XOF streams are squeezed in lockstep.
fn rej_ntt_poly(sponges: &mut Sponges, rho: &[u8], l: usize, first: usize, out: &mut [Poly]) {
    let indices: [[u8; 2]; MAX_SPONGES] =
        core::array::from_fn(|e| [((first + e) % l) as u8, ((first + e) / l) as u8]);

    let parts = indices.each_ref().map(|index| [rho, &index[..]]);

    let messages = parts.each_ref().map(|parts| &parts[..]);

    sponges.start(168, SHAKE, &messages[..out.len()]);

    let mut counts = [0; MAX_SPONGES];

    while counts[..out.len()].iter().any(|&count| count < 256) {
        sponges.squeeze(counts.map(|count| count < 256));

        for (i, (a, count)) in out.iter_mut().zip(&mut counts).enumerate() {
            if *count < 256 {
                sample_uniform(sponges.lanes(i), a, count);
            }
        }
    }
}

fn sample_bounded(block: &[u64; 17], eta: i32, a: &mut Poly, count: &mut usize) {
    if !cpu::bounded(block, eta, a, count) {
        sample_bounded_portable(block, eta, a, count);
    }
}

// The accepted values never steer a branch: each candidate is written and only an accepted one
// advances the count. Which candidates are rejected is public, as BoringSSL also has it: the bytes
// of the SHAKE256 stream are independent of each other, so the rejected ones say nothing about the
// accepted coefficients. Those are computed without a division (205 * x >> 10 = x / 5 for x < 15).
fn sample_bounded_portable(block: &[u64; 17], eta: i32, a: &mut Poly, count: &mut usize) {
    let halves = block
        .iter()
        .flat_map(|lane| lane.to_le_bytes())
        .flat_map(|byte| [byte & 0x0F, byte >> 4]);

    for half in halves {
        if *count == 256 {
            return;
        }

        let half = i32::from(half);

        let (value, accepted) = if eta == 2 {
            (2 - (half - 5 * ((205 * half) >> 10)), half < 15)
        } else {
            (4 - half, half < 9)
        };

        a[*count] = value;

        *count += usize::from(declassify_value(accepted));
    }
}

// FIPS 204 Algorithm 34 for the nonces first, first + 1, ..., squeezed in lockstep.
fn rej_bounded_poly(sponges: &mut Sponges, seed: &[u8], first: usize, eta: i32, out: &mut [Poly]) {
    let nonces: [[u8; 2]; MAX_SPONGES] =
        core::array::from_fn(|i| ((first + i) as u16).to_le_bytes());

    let parts = nonces.each_ref().map(|nonce| [seed, &nonce[..]]);

    let messages = parts.each_ref().map(|parts| &parts[..]);

    sponges.start(136, SHAKE, &messages[..out.len()]);

    let mut counts = [0; MAX_SPONGES];

    while counts[..out.len()].iter().any(|&count| count < 256) {
        sponges.squeeze(counts.map(|count| count < 256));

        for (i, (a, count)) in out.iter_mut().zip(&mut counts).enumerate() {
            if *count < 256 {
                sample_bounded(sponges.lanes(i), eta, a, count);
            }
        }
    }
}

// Row i and column j at i * l + j, a group of entries at a time. The matrix is public, so it is
// not wiped.
fn expand_a(rho: &[u8], p: &Parameters) -> Vec<Poly> {
    let mut a = vec![[0; 256]; p.k * p.l];

    let mut sponges = Sponges::empty();

    let size = keccak::group();

    for (first, group) in (0..).step_by(size).zip(a.chunks_mut(size)) {
        rej_ntt_poly(&mut sponges, rho, p.l, first, group);
    }

    a
}

// Signed coefficients of s1 and s2 (FIPS 204 Algorithm 33).
fn expand_s(rho_prime: &[u8], p: &Parameters) -> Polys {
    let mut s = Polys::new(p.l + p.k);

    let mut sponges = Sponges::empty();

    let size = keccak::group();

    for (first, group) in (0..).step_by(size).zip(s.chunks_mut(size)) {
        rej_bounded_poly(&mut sponges, rho_prime, first, p.eta, group);
    }

    s
}

// FIPS 204 Algorithm 34 with the l nonces from kappa on, all sponges side by side. Inlined into
// the signing loop, its one caller: measured 4% faster signing than a call.
#[inline(always)]
fn expand_mask(rho: &[u8], kappa: u16, p: &Parameters, y: &mut Polys) {
    let bits = p.gamma1_bits();

    let size = 32 * bits as usize;

    let mut buffers = [[0u8; 640]; MAX_SPONGES];

    let mut sponges = Sponges::empty();

    for (first, group) in (0..).step_by(MAX_SPONGES).zip(y.chunks_mut(MAX_SPONGES)) {
        let nonces: [[u8; 2]; MAX_SPONGES] =
            core::array::from_fn(|i| kappa.wrapping_add((first + i) as u16).to_le_bytes());

        let parts = nonces.each_ref().map(|nonce| [rho, &nonce[..]]);

        let messages = parts.each_ref().map(|parts| &parts[..]);

        sponges.start(136, SHAKE, &messages[..group.len()]);

        for offset in (0..size).step_by(136) {
            sponges.squeeze([true; MAX_SPONGES]);

            let end = (offset + 136).min(size);

            for (i, buffer) in buffers[..group.len()].iter_mut().enumerate() {
                sponges.read(i, &mut buffer[offset..end]);
            }
        }

        for (poly, buffer) in group.iter_mut().zip(&buffers) {
            unpack_mask(poly, &buffer[..size], bits, p.gamma1);
        }
    }

    wipe(buffers.as_flattened_mut());
}

// The mask's coefficients gamma1 - x modulo q for its packed values x.
fn unpack_mask(poly: &mut Poly, bytes: &[u8], bits: u32, gamma1: i32) {
    if !cpu::mldsa_mask(poly, bytes, bits, gamma1, Q) {
        *poly = unpack_mask_portable(bytes, bits, gamma1);
    }
}

fn unpack_mask_portable(bytes: &[u8], bits: u32, gamma1: i32) -> Poly {
    unpack(bytes, bits).map(|x| canonical(gamma1 - x))
}

fn sample_in_ball(seed: &[u8], tau: usize) -> Poly {
    let mut stream = shake256(&[seed]);

    let mut signs = [0u8; 8];

    stream.read(&mut signs);

    let mut signs = u64::from_le_bytes(signs);

    let mut c = [0; 256];

    // The positions of the nonzero coefficients are public, as in BoringSSL, while their signs
    // stay secret. For an accepted signature c_tilde is public; for a rejected attempt the
    // positions say nothing about the key, because whether an attempt is rejected does not depend
    // on c * s1 or c * s2.
    for i in 256 - tau..256 {
        let mut j = [0u8];

        loop {
            stream.read(&mut j);

            declassify(&j);

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

fn ntt_all(signed: &[Poly]) -> Polys {
    let mut hat = Polys::new(signed.len());

    for (f, s) in hat.iter_mut().zip(signed) {
        *f = ntt_of(s);
    }

    hat
}

// t = A * s1 + s2 from the matrix and the signed s1 and s2.
fn public_t(a: &[Poly], s1: &[Poly], s2: &[Poly], p: &Parameters) -> Polys {
    let s1_hat = ntt_all(s1);

    let mut t = Polys::new(p.k);

    for ((t_i, row), s2_i) in t.iter_mut().zip(a.chunks_exact(p.l)).zip(s2) {
        multiply_add(t_i, row, &s1_hat);

        inverse_ntt(t_i);

        for (x, e) in t_i.iter_mut().zip(s2_i) {
            *x = add(*x, canonical(*e));
        }
    }

    t
}

fn encode_public_key(rho: &[u8], t: &Polys, p: &Parameters) -> Vec<u8> {
    let mut pk = vec![0; p.public_key_size()];

    pk[..32].copy_from_slice(rho);

    for (chunk, poly) in pk[32..].as_chunks_mut::<320>().0.iter_mut().zip(t.iter()) {
        pack_with(chunk, 10, poly, |x| power2round(x).0);
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
        pack_with(chunk, p.eta_bits(), poly, |x| p.eta - x);
    }

    for (chunk, poly) in t0_bytes
        .as_chunks_mut::<{ 32 * D as usize }>()
        .0
        .iter_mut()
        .zip(t.iter())
    {
        pack_with(chunk, D, poly, |x| (1 << (D - 1)) - power2round(x).1);
    }

    sk
}

// The signed coefficients of s1 and s2 of an expanded private key.
fn decode_s(sk: &[u8], p: &Parameters) -> Polys {
    let size = 32 * p.eta_bits() as usize;

    let mut s = Polys::new(p.l + p.k);

    for (poly, chunk) in s.iter_mut().zip(sk[128..].chunks_exact(size)) {
        *poly = unpack(chunk, p.eta_bits()).map(|x| p.eta - x);
    }

    s
}

fn hash_public_key(pk: &[u8]) -> [u8; 64] {
    let mut tr = [0; 64];

    shake256_into(&[pk], &mut tr);

    tr
}

// Â of a public key, which signing and verification both use. It is public, so it is not wiped.
#[derive(Clone)]
pub(crate) struct Matrix(Vec<Poly>);

impl Matrix {
    pub(crate) fn new(pk: &[u8], p: &Parameters) -> Self {
        Self(expand_a(&pk[..32], p))
    }
}

// What verification alone derives from a public key: t̂1 = NTT(t1 * 2^d) and tr = H(pk, 64).
#[derive(Clone)]
pub(crate) struct VerifyingKey {
    t1: Vec<Poly>,
    tr: [u8; 64],
}

impl VerifyingKey {
    pub(crate) fn new(pk: &[u8]) -> Self {
        let t1 = pk[32..]
            .as_chunks::<320>()
            .0
            .iter()
            .map(|chunk| {
                let mut t1 = unpack(chunk, 10).map(|x| x << D);

                ntt(&mut t1);

                t1
            })
            .collect();

        Self {
            t1,
            tr: hash_public_key(pk),
        }
    }
}

// The NTT forms of s1, s2 and t0 that signing uses, wiped when dropped. K and tr are read from the
// expanded private key itself.
pub(crate) struct SigningKey {
    s1: Polys,
    s2: Polys,
    t0: Polys,
}

impl SigningKey {
    // For an expanded private key from key generation or one that passed check_private_key.
    pub(crate) fn new(sk: &[u8], p: &Parameters) -> Self {
        let size = 32 * p.eta_bits() as usize;

        let s = decode_s(sk, p);

        let (s1, s2) = s.split_at(p.l);

        let mut t0 = Polys::new(p.k);

        let t0_bytes = &sk[128 + (p.l + p.k) * size..];

        for (hat, chunk) in t0
            .iter_mut()
            .zip(t0_bytes.as_chunks::<{ 32 * D as usize }>().0)
        {
            let mut t0_i = unpack(chunk, D).map(|x| (1 << (D - 1)) - x);

            *hat = ntt_of(&t0_i);

            wipe(&mut t0_i);
        }

        Self {
            s1: ntt_all(s1),
            s2: ntt_all(s2),
            t0,
        }
    }
}

pub(crate) fn keygen_internal(xi: &[u8], p: &Parameters) -> (Vec<u8>, SecretBytes) {
    let mut seeds = [0u8; 128];

    shake256_into(&[xi, &[p.k as u8, p.l as u8]], &mut seeds);

    let (rho, rest) = seeds.split_at(32);

    let (rho_prime, key) = rest.split_at(64);

    // rho is part of the public key.
    declassify(rho);

    let s = expand_s(rho_prime, p);

    let (s1, s2) = s.split_at(p.l);

    let t = public_t(&expand_a(rho, p), s1, s2, p);

    let pk = encode_public_key(rho, &t, p);

    declassify(&pk);

    let sk = encode_private_key([rho, key, &hash_public_key(&pk)], &s, &t, p);

    wipe(&mut seeds);

    (pk, sk)
}

// An expanded private key carries everything needed to rebuild the public key, so a key whose
// parts disagree is rejected instead of producing signatures that never verify. Re-encoding the
// key from its own s1, s2, rho and K compares t0 and tr in one constant-time pass. Returns pk.
pub(crate) fn check_private_key(sk: &[u8], p: &Parameters) -> Option<Vec<u8>> {
    // rho is part of the public key.
    declassify(&sk[..32]);

    let (rho, key) = (&sk[..32], &sk[32..64]);

    let s = decode_s(sk, p);

    // Whether the key is valid is public: importing it fails otherwise.
    if declassify_value(reaches(s.iter().flatten().copied(), p.eta + 1) != 0) {
        return None;
    }

    let (s1, s2) = s.split_at(p.l);

    let t = public_t(&expand_a(rho, p), s1, s2, p);

    let pk = encode_public_key(rho, &t, p);

    declassify(&pk);

    let rebuilt = encode_private_key([rho, key, &hash_public_key(&pk)], &s, &t, p);

    declassify_value(ct::equal(&rebuilt, sk)).then_some(pk)
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
        if !cpu::mldsa_w1(chunk, poly, p.gamma2, Q) {
            encode_w1_portable(chunk, poly, p.gamma2);
        }
    }
}

fn encode_w1_portable(out: &mut [u8], w: &Poly, gamma2: i32) {
    let bits = bit_length((Q - 1) / (2 * gamma2) - 1);

    pack_with(out, bits, w, |x| high_bits(x, gamma2));
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
// combined outcome, the rejection decision, steers the loop. sk supplies K and tr.
pub(crate) fn sign_internal(
    matrix: &Matrix,
    key: &SigningKey,
    sk: &[u8],
    message: &[&[u8]],
    rnd: &[u8],
    p: &Parameters,
) -> Vec<u8> {
    let (a, s1_hat, s2_hat, t0_hat) = (&matrix.0, &key.s1, &key.s2, &key.t0);

    let mu = message_hash(&sk[64..128], message);

    let mut rho_prime = [0u8; 64];

    shake256_into(&[&sk[32..64], rnd, &mu], &mut rho_prime);

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

        for (w_i, row) in w.iter_mut().zip(a.chunks_exact(p.l)) {
            *w_i = [0; 256];

            multiply_add(w_i, row, &y_hat);

            inverse_ntt(w_i);
        }

        encode_w1(&w, p, &mut w1);

        let c_tilde = challenge(&mu, &w1, p);

        let mut c_hat = sample_in_ball(&c_tilde[..p.challenge_size()], p.tau);

        ntt(&mut c_hat);

        for ((z_i, y_i), s) in z.iter_mut().zip(y.iter()).zip(s1_hat.iter()) {
            let mut cs1 = pointwise(&c_hat, s);

            inverse_ntt(&mut cs1);

            add_polys(z_i, y_i, &cs1);

            wipe(&mut cs1);
        }

        // r holds w - c*s2, the argument of both the low-bits check and the hints.
        for ((r_i, w_i), s) in r.iter_mut().zip(w.iter()).zip(s2_hat.iter()) {
            let mut cs2 = pointwise(&c_hat, s);

            inverse_ntt(&mut cs2);

            sub_polys(r_i, w_i, &cs2);

            wipe(&mut cs2);
        }

        let z_check = z.iter().fold(0, |flag, z_i| {
            flag | poly_reaches(z_i, p.gamma1 - p.beta(), None)
        });

        let r0_check = r.iter().fold(0, |flag, r_i| {
            flag | poly_reaches(r_i, p.gamma2 - p.beta(), Some(p.gamma2))
        });

        // Only the decision to restart is public, not which check failed or where: a restart
        // reveals nothing, because the next attempt is independent of this one.
        if declassify_value(z_check | r0_check != 0) {
            continue;
        }

        for (ct0_i, t) in ct0.iter_mut().zip(t0_hat.iter()) {
            *ct0_i = pointwise(&c_hat, t);

            inverse_ntt(ct0_i);
        }

        let mut count = 0;

        for ((h_i, r_i), ct0_i) in h.iter_mut().zip(r.iter()).zip(ct0.iter()) {
            count += make_hints(h_i, r_i, ct0_i, p.gamma2);
        }

        let ct0_check = ct0
            .iter()
            .fold(0, |flag, ct0_i| flag | poly_reaches(ct0_i, p.gamma2, None));

        if declassify_value((ct0_check != 0) | (count > p.omega as i32)) {
            continue;
        }

        break c_tilde;
    };

    // The accepted c_tilde, z and h form the signature.
    declassify(&h);

    let mut signature = vec![0; p.signature_size()];

    let (head, hints) = signature.split_at_mut(p.signature_size() - p.omega - p.k);

    let (c_part, z_part) = head.split_at_mut(p.challenge_size());

    c_part.copy_from_slice(&c_tilde[..p.challenge_size()]);

    let bits = p.gamma1_bits();

    for (chunk, poly) in z_part.chunks_exact_mut(32 * bits as usize).zip(z.iter()) {
        pack_with(chunk, bits, poly, |x| p.gamma1 - centered(x));
    }

    hint_bit_pack(&h, p, hints);

    wipe(&mut rho_prime);

    declassify(&signature);

    signature
}

pub(crate) fn verify_internal(
    matrix: &Matrix,
    key: &VerifyingKey,
    message: &[&[u8]],
    sig: &[u8],
    p: &Parameters,
) -> bool {
    if sig.len() != p.signature_size() {
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

    let mu = message_hash(&key.tr, message);

    let mut c_hat = sample_in_ball(c_tilde, p.tau);

    ntt(&mut c_hat);

    for poly in z.iter_mut() {
        *poly = ntt_of(poly);
    }

    let mut w = Polys::new(p.k);

    for ((w_i, t1), row) in w.iter_mut().zip(&key.t1).zip(matrix.0.chunks_exact(p.l)) {
        *w_i = pointwise(&c_hat, t1).map(|x| -x);

        multiply_add(w_i, row, &z);

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
    use crate::cpu::testing::Inputs;

    // A polynomial with coefficients in [low, high): the bounds themselves, alternated, for the
    // first cases, random ones after that.
    fn coefficients(inputs: &mut Inputs, case: usize, low: i32, high: i32) -> Poly {
        let edge = [low, high - 1];

        core::array::from_fn(|i| match case {
            0 | 1 => edge[case],
            2 => edge[i % 2],
            _ => {
                let width = (i64::from(high) - i64::from(low)) as u64;

                (i64::from(low) + (inputs.next() % width) as i64) as i32
            }
        })
    }

    // The transform and product kernels against the portable code, each on the range its callers
    // give it: canonical coefficients into the forward transform, sums of products below 2^31 -
    // 2^22 into the inverse, and the lazy outputs of the forward transform, below 9q, into the
    // products.
    #[test]
    fn transform_kernels_match_portable() {
        let mut inputs = Inputs::new(8380417);

        let mut accelerated = 0;

        for n in 0..20_000 {
            let f = coefficients(&mut inputs, n, 0, Q);

            let (mut expected, mut actual) = (f, f);

            ntt_portable(&mut expected);

            if cpu::ntt(&mut actual, &FIELD) {
                assert_eq!(actual, expected, "ntt, case {n}");

                accelerated += 1;
            }

            let bound = i32::MAX - (1 << 22) + 1;

            let f = coefficients(&mut inputs, n, -bound + 1, bound);

            let (mut expected, mut actual) = (f, f);

            inverse_ntt_portable(&mut expected);

            if cpu::inverse_ntt(&mut actual, &FIELD) {
                assert_eq!(actual, expected, "inverse, case {n}");
            }

            let (f, g) = (
                coefficients(&mut inputs, n, -9 * Q + 1, 9 * Q),
                coefficients(&mut inputs, n + 1, -9 * Q + 1, 9 * Q),
            );

            let acc = coefficients(&mut inputs, n, -(1 << 28), 1 << 28);

            let mut product = [0; 256];

            if cpu::multiply(&mut product, &f, &g, &FIELD) {
                assert_eq!(product, pointwise_portable(&f, &g), "multiply, case {n}");
            }

            // Rows of one to seven products, as signing and key generation sum them.
            let terms = 1 + n % 7;

            let row: [Poly; 7] =
                core::array::from_fn(|i| coefficients(&mut inputs, n + i, -9 * Q + 1, 9 * Q));

            let vector: [Poly; 7] =
                core::array::from_fn(|i| coefficients(&mut inputs, n + i + 1, -9 * Q + 1, 9 * Q));

            let (mut expected, mut actual) = (acc, acc);

            for (f, g) in row[..terms].iter().zip(&vector[..terms]) {
                multiply_add_portable(&mut expected, f, g);
            }

            if cpu::multiply_add(&mut actual, &row[..terms], &vector[..terms], &FIELD) {
                assert_eq!(actual, expected, "multiply_add, case {n}");
            }
        }

        std::eprintln!("ML-DSA: {accelerated} of 20000 cases through the CPU kernels");
    }

    // The rejection kernels against the portable code from every count near the end and from
    // random ones: the same count and the same accepted values; slots past the count may differ.
    // The uniform blocks include candidates at the bound and with the ignored top bit set.
    #[test]
    fn sampling_kernels_match_portable() {
        let mut inputs = Inputs::new(23);

        let mut accelerated = 0;

        for n in 0..20_000 {
            let start = match n % 3 {
                0 => 256 - n / 3 % 64,
                _ => (inputs.next() % 257) as usize,
            };

            let prefix: Poly = core::array::from_fn(|_| (inputs.next() % Q as u64) as i32);

            let bytes: [u8; 168] = match n % 5 {
                0 => {
                    let mut block = [0; 168];

                    for bytes in block.as_chunks_mut::<3>().0 {
                        let next = inputs.next();

                        let z = (Q as u64 - 2 + next % 4) | ((next >> 2) & 1) << 23;

                        *bytes = [z as u8, (z >> 8) as u8, (z >> 16) as u8];
                    }

                    block
                }
                1 => [[0x00, 0xFF, 0x7F][n / 5 % 3]; 168],
                _ => inputs.bytes(),
            };

            let block: [u64; 21] =
                core::array::from_fn(|i| u64::from_le_bytes(bytes.as_chunks::<8>().0[i]));

            let (mut expected, mut expected_count) = (prefix, start);

            sample_uniform_portable(&block, &mut expected, &mut expected_count);

            let (mut actual, mut actual_count) = (prefix, start);

            if cpu::uniform23(&block, Q, &mut actual, &mut actual_count) {
                assert_eq!(actual_count, expected_count, "uniform, case {n}");

                assert_eq!(
                    actual[..actual_count],
                    expected[..actual_count],
                    "uniform, case {n}"
                );

                accelerated += 1;
            }

            let block: [u64; 17] = match n % 5 {
                1 => [u64::from_ne_bytes([[0x00, 0xFF, 0x99, 0xEE, 0xF8, 0x8F][n / 5 % 6]; 8]); 17],
                _ => inputs.words(),
            };

            for eta in [2, 4] {
                let (mut expected, mut expected_count) = (prefix, start);

                sample_bounded_portable(&block, eta, &mut expected, &mut expected_count);

                let (mut actual, mut actual_count) = (prefix, start);

                if cpu::bounded(&block, eta, &mut actual, &mut actual_count) {
                    assert_eq!(actual_count, expected_count, "eta {eta}, case {n}");

                    assert_eq!(
                        actual[..actual_count],
                        expected[..actual_count],
                        "eta {eta}, case {n}"
                    );

                    accelerated += 1;
                }
            }
        }

        std::eprintln!("ML-DSA sampling: {accelerated} of 60000 cases through the CPU kernels");
    }

    // The signing kernels against the portable code on random canonical polynomials and on the
    // bounds of each step: sums and differences, both norm checks at bounds that the values
    // reach and miss, the hints with their count, the encoding of w1 and the mask expansion.
    #[test]
    fn signing_kernels_match_portable() {
        let mut inputs = Inputs::new(8380416);

        let mut accelerated = 0;

        for n in 0..20_000 {
            let (a, b) = (
                coefficients(&mut inputs, n, 0, Q),
                coefficients(&mut inputs, n + 1, 0, Q),
            );

            let (mut expected, mut actual) = ([0; 256], [0; 256]);

            add_polys_portable(&mut expected, &a, &b);

            if cpu::mldsa_add(&mut actual, &a, &b, Q) {
                assert_eq!(actual, expected, "add, case {n}");

                accelerated += 1;
            }

            sub_polys_portable(&mut expected, &a, &b);

            if cpu::mldsa_sub(&mut actual, &a, &b, Q) {
                assert_eq!(actual, expected, "sub, case {n}");
            }

            for gamma2 in [(Q - 1) / 88, (Q - 1) / 32] {
                // Values near the bound: a random centered value of absolute value up to 2^20,
                // and bounds around it.
                let bound = (inputs.next() % (1 << 20)) as i32 + 2;

                // Centered values strictly inside the bound, with the extremes, and then one
                // coefficient that reaches it, in a random position.
                let mut small: Poly = core::array::from_fn(|i| {
                    let value = match i % 4 {
                        0 => bound - 1,
                        1 => 1 - bound,
                        _ => (inputs.next() % (2 * bound as u64 - 1)) as i32 - (bound - 1),
                    };

                    freeze(value)
                });

                for values in [&a, &small] {
                    for low in [None, Some(gamma2)] {
                        let expected = poly_reaches_portable(values, bound, low);

                        if let Some(actual) = cpu::mldsa_norm(values, bound, low, Q) {
                            assert_eq!(actual, expected, "norm {low:?}, case {n}");
                        }
                    }
                }

                small[(inputs.next() % 256) as usize] =
                    freeze(if n % 2 == 0 { bound } else { -bound });

                let expected = poly_reaches_portable(&small, bound, None);

                assert_eq!(expected, -1, "the bound is reached, case {n}");

                if let Some(actual) = cpu::mldsa_norm(&small, bound, None, Q) {
                    assert_eq!(actual, expected, "norm at the bound, case {n}");
                }

                let mut expected_hints = [0; 256];

                let expected = make_hints_portable(&mut expected_hints, &a, &b, gamma2);

                let mut actual_hints = [0; 256];

                if let Some(count) = cpu::mldsa_hints(&mut actual_hints, &a, &b, gamma2, Q) {
                    assert_eq!(
                        (count, actual_hints),
                        (expected, expected_hints),
                        "hints, case {n}"
                    );
                }

                let size = 32 * bit_length((Q - 1) / (2 * gamma2) - 1) as usize;

                let (mut expected, mut actual) = ([0; 192], [0; 192]);

                encode_w1_portable(&mut expected[..size], &a, gamma2);

                if cpu::mldsa_w1(&mut actual[..size], &a, gamma2, Q) {
                    assert_eq!(actual[..size], expected[..size], "w1, case {n}");
                }
            }

            for (bits, gamma1) in [(18, 1 << 17), (20, 1 << 19)] {
                let bytes: [u8; 640] = match n {
                    0 => [0; 640],
                    1 => [0xFF; 640],
                    _ => inputs.bytes(),
                };

                let size = 32 * bits as usize;

                let expected = unpack_mask_portable(&bytes[..size], bits, gamma1);

                let mut actual = [0; 256];

                if cpu::mldsa_mask(&mut actual, &bytes[..size], bits, gamma1, Q) {
                    assert_eq!(actual, expected, "mask {bits}, case {n}");
                }
            }
        }

        std::eprintln!("ML-DSA signing: {accelerated} of 20000 cases through the CPU kernels");
    }

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

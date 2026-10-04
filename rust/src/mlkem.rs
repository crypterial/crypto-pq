use alloc::vec;
use alloc::vec::Vec;

use crate::cpu::{self, Field, Field16, Prepare};
use crate::ct::{self, declassify};
use crate::keccak::Sponges;
use crate::primitives::{sha3_256, sha3_512, shake256_into};
use crate::wipe::{SecretBytes, wipe};

const Q: u32 = 3329;

const SHAKE: u8 = 0x1F;

type Poly = [u16; 256];

// The NTT runs on 32-bit lanes; its sums are reduced lazily.
type Wide = [i32; 256];

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

// q^-1 mod 2^32, by Newton's iteration from 1, for Montgomery reduction.
const QINV: i32 = {
    let mut inverse = 1u32;

    let mut i = 0;

    while i < 5 {
        inverse = inverse.wrapping_mul(2u32.wrapping_sub(Q.wrapping_mul(inverse)));

        i += 1;
    }

    inverse as i32
};

const R_MOD_Q: u16 = ((1u64 << 32) % Q as u64) as u16;

// x * 2^32 mod q in (-q / 2, q / 2], so that one Montgomery reduction of a product with it gives
// the plain product modulo q.
const fn montgomery_form(x: u32) -> i32 {
    let value = mul(x as u16, R_MOD_Q) as i32;

    value - (Q as i32 & (((Q as i32 - 1) / 2 - value) >> 31))
}

const ZETAS: [i32; 128] = {
    let mut table = [0; 128];

    let mut i = 0;

    while i < 128 {
        table[i] = montgomery_form(power(17, bit_reverse7(i)));

        i += 1;
    }

    table
};

const GAMMAS: [i32; 128] = {
    let mut table = [0; 128];

    let mut i = 0;

    while i < 128 {
        table[i] = montgomery_form(power(17, 2 * bit_reverse7(i) + 1));

        i += 1;
    }

    table
};

// 3303 = 128^-1 mod q.
const INVERSE_SCALE: i32 = montgomery_form(3303);

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

const fn high(a: i32, b: i32) -> i32 {
    ((a as i64 * b as i64) >> 32) as i32
}

// a * b * 2^-32 mod q in (-q, q), for |a * b| < 2^31 q, given b_qinv = b * q^-1 mod 2^32. The
// low halves of a * b and of its multiple of q cancel, so only high halves are computed, which
// the compiler can vectorize.
const fn montgomery(a: i32, b: i32, b_qinv: i32) -> i32 {
    high(a, b) - high(a.wrapping_mul(b_qinv), Q as i32)
}

// (-q, q) to [0, q) with a mask instead of a branch.
const fn freeze(y: i32) -> u16 {
    (y + (Q as i32 & (y >> 31))) as u16
}

// |w| < 2^31 to the canonical coefficients w mod q.
fn canonical(w: &Wide) -> Poly {
    let (r, r_qinv) = (i32::from(R_MOD_Q), i32::from(R_MOD_Q).wrapping_mul(QINV));

    w.map(|x| freeze(montgomery(x, r, r_qinv)))
}

fn add_assign(f: &mut Poly, g: &Poly) {
    for (x, y) in f.iter_mut().zip(g) {
        *x = add(*x, *y);
    }
}

// The twiddle factors as the CPU kernels take them; the forward transform ends with the
// canonical form, as ntt does.
static FIELD: Field = Field::new(
    Q as i32,
    QINV,
    7,
    {
        let mut zetas = [0; 256];

        let mut i = 0;

        while i < 128 {
            zetas[i] = ZETAS[i];

            i += 1;
        }

        zetas
    },
    Prepare::Montgomery(R_MOD_Q as i32),
    Some(R_MOD_Q as i32),
    INVERSE_SCALE,
);

// The same factors for the 16-bit kernels, in Montgomery form for 2^16 instead of 2^32.
static FIELD16: Field16 = Field16::new(
    Q as i16,
    {
        let mut zetas = [0; 128];

        let mut i = 0;

        while i < 128 {
            let zeta = (power(17, bit_reverse7(i)) as u64 * 65536 % Q as u64) as i16;

            zetas[i] = if zeta > (Q as i16 - 1) / 2 {
                zeta - Q as i16
            } else {
                zeta
            };

            i += 1;
        }

        zetas
    },
    (65536 % Q) as i16,
    (3303 * 65536 % Q) as i16,
    R_MOD_Q as i32,
    QINV,
);

fn ntt(f: &mut Poly) {
    if cpu::ntt16(f, &FIELD16) {
        return;
    }

    let mut w = f.map(i32::from);

    if cpu::ntt(&mut w, &FIELD) {
        *f = w.map(|x| x as u16);
    } else {
        ntt_layers(&mut w);

        *f = canonical(&w);
    }

    wipe(&mut w);
}

// The butterflies reduce only their products, so the sums stay below 8q.
fn ntt_layers(w: &mut Wide) {
    let mut i = 1;

    let mut length = 128;

    while length >= 2 {
        for start in (0..256).step_by(2 * length) {
            let (zeta, zeta_qinv) = (ZETAS[i], ZETAS[i].wrapping_mul(QINV));

            i += 1;

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

// The inverse NTT of the accumulated products, as canonical coefficients.
fn inverse_ntt(acc: &Wide) -> Poly {
    let mut f = [0; 256];

    if cpu::inverse_ntt16(acc, &mut f, &FIELD16) {
        return f;
    }

    let mut w = *acc;

    let f = if cpu::inverse_ntt(&mut w, &FIELD) {
        w.map(|x| x as u16)
    } else {
        inverse_ntt_portable(&mut w)
    };

    wipe(&mut w);

    f
}

fn inverse_ntt_portable(w: &mut Wide) -> Poly {
    let (r, r_qinv) = (i32::from(R_MOD_Q), i32::from(R_MOD_Q).wrapping_mul(QINV));

    // Below q in absolute value first, so that the sums stay below 128q.
    for x in w.iter_mut() {
        *x = montgomery(*x, r, r_qinv);
    }

    let mut i = 127;

    let mut length = 2;

    while length <= 128 {
        for start in (0..256).step_by(2 * length) {
            let (zeta, zeta_qinv) = (ZETAS[i], ZETAS[i].wrapping_mul(QINV));

            i -= 1;

            let (low, high) = w[start..start + 2 * length].split_at_mut(length);

            for (a, b) in low.iter_mut().zip(high) {
                let t = *a;

                *a = t + *b;

                *b = montgomery(*b - t, zeta, zeta_qinv);
            }
        }

        length *= 2;
    }

    let scale_qinv = INVERSE_SCALE.wrapping_mul(QINV);

    w.map(|x| freeze(montgomery(x, INVERSE_SCALE, scale_qinv)))
}

// acc += f * g in the NTT domain (FIPS 203, Algorithms 11 and 12) for canonical f and g. The
// products are not reduced: k of them stay far below 2^31.
fn multiply_accumulate(acc: &mut Wide, f: &Poly, g: &Poly) {
    if !cpu::base_multiply_add(acc, f, g, &GAMMAS, &FIELD) {
        multiply_accumulate_portable(acc, f, g);
    }
}

fn multiply_accumulate_portable(acc: &mut Wide, f: &Poly, g: &Poly) {
    let pairs = acc.as_chunks_mut::<2>().0.iter_mut();

    let factors = f.as_chunks::<2>().0.iter().zip(g.as_chunks::<2>().0);

    for ((acc, (a, b)), &gamma) in pairs.zip(factors).zip(&GAMMAS) {
        let ([a0, a1], [b0, b1]) = (a.map(i32::from), b.map(i32::from));

        acc[0] += a0 * b0 + montgomery(a1, b1, b1.wrapping_mul(QINV)) * gamma;

        acc[1] += a0 * b1 + a1 * b0;
    }
}

fn byte_encode(f: &Poly, d: u32, out: &mut [u8]) {
    match d {
        1 => encode_bits::<1>(f, out),
        4 => encode_bits::<4>(f, out),
        5 => encode_bits::<5>(f, out),
        10 => encode_bits::<10>(f, out),
        11 => encode_bits::<11>(f, out),
        12 => encode_bits::<12>(f, out),
        _ => unreachable!("no ML-KEM encoding uses {d} bits"),
    }
}

fn byte_decode(data: &[u8], d: u32) -> Poly {
    match d {
        1 => decode_bits::<1>(data),
        4 => decode_bits::<4>(data),
        5 => decode_bits::<5>(data),
        10 => decode_bits::<10>(data),
        11 => decode_bits::<11>(data),
        12 => decode_bits::<12>(data),
        _ => unreachable!("no ML-KEM encoding uses {d} bits"),
    }
}

// Eight coefficients of D bits fill D bytes, so with D constant every shift is a constant.
fn encode_bits<const D: usize>(f: &Poly, out: &mut [u8]) {
    for (bytes, group) in out
        .as_chunks_mut::<D>()
        .0
        .iter_mut()
        .zip(f.as_chunks::<8>().0)
    {
        let word = group
            .iter()
            .enumerate()
            .fold(0u128, |word, (i, &x)| word | (u128::from(x) << (D * i)));

        for (j, byte) in bytes.iter_mut().enumerate() {
            *byte = (word >> (8 * j)) as u8;
        }
    }
}

fn decode_bits<const D: usize>(data: &[u8]) -> Poly {
    let mut f = [0; 256];

    for (group, bytes) in f
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(data.as_chunks::<D>().0)
    {
        let word = bytes
            .iter()
            .rev()
            .fold(0u128, |word, &byte| (word << 8) | u128::from(byte));

        for (i, x) in group.iter_mut().enumerate() {
            *x = (word >> (D * i)) as u16 & ((1 << D) - 1);
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

// One block of an XOF stream into the coefficients accepted so far. Every candidate is written
// and only an accepted one advances the count, so that no branch depends on a candidate, which a
// random matrix makes unpredictable.
fn sample_uniform(block: &[u8; 168], a: &mut Poly, count: &mut usize) {
    for chunk in block.as_chunks::<3>().0 {
        let d1 = u16::from(chunk[0]) | (u16::from(chunk[1] & 0x0F) << 8);

        let d2 = u16::from(chunk[1] >> 4) | (u16::from(chunk[2]) << 4);

        for candidate in [d1, d2] {
            if *count == 256 {
                return;
            }

            a[*count] = candidate;

            *count += usize::from(u32::from(candidate) < Q);
        }
    }
}

// Entries first, first + 1, ... of Â (FIPS 203, Algorithm 7, from XOF(rho, j, i) for row i and
// column j), whose XOF streams are squeezed in lockstep.
fn sample_ntt(rho: &[u8], k: usize, first: usize, out: &mut [Poly]) {
    let indices: [[u8; 2]; 4] =
        core::array::from_fn(|e| [((first + e) % k) as u8, ((first + e) / k) as u8]);

    let parts = indices.each_ref().map(|index| [rho, &index[..]]);

    let messages = parts.each_ref().map(|parts| &parts[..]);

    let mut sponges = Sponges::new(168, SHAKE, &messages[..out.len()]);

    let mut counts = [0; 4];

    let mut block = [0u8; 168];

    while counts[..out.len()].iter().any(|&count| count < 256) {
        sponges.squeeze(counts.map(|count| count < 256));

        for (i, (a, count)) in out.iter_mut().zip(&mut counts).enumerate() {
            if *count < 256 {
                sponges.read(i, &mut block);

                sample_uniform(&block, a, count);
            }
        }
    }
}

// FIPS 203, Algorithm 8, applied to PRF_eta(seed, nonce) = SHAKE256(seed || nonce) for the
// nonces first, first + 1, ..., whose sponges run side by side four at a time.
fn sample_noise(eta: usize, seed: &[u8], first: usize, out: &mut [Poly]) {
    for (start, group) in (first..).step_by(4).zip(out.chunks_mut(4)) {
        let nonces: [[u8; 1]; 4] = core::array::from_fn(|i| [(start + i) as u8]);

        let parts = nonces.each_ref().map(|nonce| [seed, &nonce[..]]);

        let messages = parts.each_ref().map(|parts| &parts[..]);

        let mut sponges = Sponges::new(136, SHAKE, &messages[..group.len()]);

        let mut buffers = [[0u8; 192]; 4];

        for offset in (0..64 * eta).step_by(136) {
            sponges.squeeze([true; 4]);

            let end = (offset + 136).min(64 * eta);

            for (i, buffer) in buffers[..group.len()].iter_mut().enumerate() {
                sponges.read(i, &mut buffer[offset..end]);
            }
        }

        for (f, buffer) in group.iter_mut().zip(&buffers) {
            *f = binomial(eta, &buffer[..64 * eta]);
        }

        wipe(buffers.as_flattened_mut());
    }
}

fn binomial(eta: usize, data: &[u8]) -> Poly {
    let mut f = [0; 256];

    if !cpu::binomial(eta, data, Q as u16, &mut f) {
        f = binomial_portable(eta, data);
    }

    f
}

// The bits of each half are summed with masks over a whole word, never one secret bit at a time.
fn binomial_portable(eta: usize, data: &[u8]) -> Poly {
    let mut f = [0; 256];

    if eta == 2 {
        for (bytes, group) in data.as_chunks::<4>().0.iter().zip(f.as_chunks_mut::<8>().0) {
            let t = u32::from_le_bytes(*bytes);

            let sums = (t & 0x5555_5555) + ((t >> 1) & 0x5555_5555);

            for (i, x) in group.iter_mut().enumerate() {
                *x = sub(
                    ((sums >> (4 * i)) & 3) as u16,
                    ((sums >> (4 * i + 2)) & 3) as u16,
                );
            }
        }
    } else {
        for (bytes, group) in data.as_chunks::<3>().0.iter().zip(f.as_chunks_mut::<4>().0) {
            let t = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]);

            let sums = (t & 0x24_9249) + ((t >> 1) & 0x24_9249) + ((t >> 2) & 0x24_9249);

            for (i, x) in group.iter_mut().enumerate() {
                *x = sub(
                    ((sums >> (6 * i)) & 7) as u16,
                    ((sums >> (6 * i + 3)) & 7) as u16,
                );
            }
        }
    }

    f
}

// Â, with row i and column j at i * k + j, four entries at a time.
fn sample_matrix(rho: &[u8], k: usize) -> Vec<Poly> {
    let mut matrix = vec![[0; 256]; k * k];

    for (first, group) in (0..).step_by(4).zip(matrix.chunks_mut(4)) {
        sample_ntt(rho, k, first, group);
    }

    matrix
}

fn decode_vector(bytes: &[u8]) -> Vec<Poly> {
    bytes
        .as_chunks::<384>()
        .0
        .iter()
        .map(|chunk| decode12(chunk))
        .collect()
}

// What an encapsulation key yields before any message: Â, t̂ and H(ek). Encapsulation and the
// re-encryption in decapsulation read them here instead of sampling Â and decoding and hashing
// the key on every call.
#[derive(Clone)]
pub(crate) struct EncapsulationKey {
    matrix: Vec<Poly>,
    t: Vec<Poly>,
    h: [u8; 32],
}

impl EncapsulationKey {
    // For a valid ek (check_encapsulation_key).
    pub(crate) fn new(ek: &[u8], p: &Parameters) -> Self {
        let (t, rho) = ek.split_at(384 * p.k);

        Self {
            matrix: sample_matrix(rho, p.k),
            t: decode_vector(t),
            h: sha3_256(&[ek]),
        }
    }
}

// The decoded NTT-form secret ŝ of a decapsulation key, wiped when dropped.
pub(crate) struct DecapsulationKey(Vec<Poly>);

impl DecapsulationKey {
    // For a dk from key generation or one that passed check_decapsulation_key.
    pub(crate) fn new(dk: &[u8], p: &Parameters) -> Self {
        Self(decode_vector(&dk[..384 * p.k]))
    }
}

impl Drop for DecapsulationKey {
    fn drop(&mut self) {
        wipe(self.0.as_flattened_mut());
    }
}

fn pke_keygen(d: &[u8], p: &Parameters, ek: &mut [u8], dk: &mut [u8]) {
    let k = p.k;

    let mut g = sha3_512(&[d, &[k as u8]]);

    let (rho, sigma) = g.split_at(32);

    // rho is part of the public key.
    declassify(rho);

    // s from the nonces 0 to k - 1 and e from k to 2k - 1.
    let mut noise = [[0; 256]; 8];

    sample_noise(p.eta1, sigma, 0, &mut noise[..2 * k]);

    for f in &mut noise[..2 * k] {
        ntt(f);
    }

    let (s, e) = noise.split_at(k);

    let matrix = sample_matrix(rho, k);

    for i in 0..k {
        let mut acc = [0; 256];

        for (a_ij, s_j) in matrix[i * k..(i + 1) * k].iter().zip(s) {
            multiply_accumulate(&mut acc, a_ij, s_j);
        }

        let mut t = canonical(&acc);

        wipe(&mut acc);

        add_assign(&mut t, &e[i]);

        byte_encode(&t, 12, &mut ek[384 * i..384 * (i + 1)]);

        byte_encode(&s[i], 12, &mut dk[384 * i..384 * (i + 1)]);
    }

    declassify(&ek[..384 * k]);

    ek[384 * k..].copy_from_slice(rho);

    wipe(noise[..2 * k].as_flattened_mut());

    wipe(&mut g);
}

fn pke_encrypt(key: &EncapsulationKey, m: &[u8], r: &[u8], p: &Parameters, c: &mut [u8]) {
    let k = p.k;

    let mut y = [[0; 256]; 4];

    sample_noise(p.eta1, r, 0, &mut y[..k]);

    for y_n in &mut y[..k] {
        ntt(y_n);
    }

    // e1 from the nonces k to 2k - 1 and e2 from 2k.
    let mut noise = [[0; 256]; 5];

    sample_noise(p.eta2, r, k, &mut noise[..k + 1]);

    let (c1, c2) = c.split_at_mut(32 * p.du as usize * k);

    let mut u = [0; 256];

    for (i, chunk) in c1.chunks_exact_mut(32 * p.du as usize).enumerate() {
        let mut acc = [0; 256];

        for (j, y_j) in y[..k].iter().enumerate() {
            multiply_accumulate(&mut acc, &key.matrix[j * k + i], y_j);
        }

        u = inverse_ntt(&acc);

        wipe(&mut acc);

        add_assign(&mut u, &noise[i]);

        byte_encode(&u.map(|x| compress(x, p.du)), p.du, chunk);
    }

    let mut acc = [0; 256];

    for (t_i, y_i) in key.t.iter().zip(&y[..k]) {
        multiply_accumulate(&mut acc, t_i, y_i);
    }

    let mut v = inverse_ntt(&acc);

    add_assign(&mut v, &noise[k]);

    let mut mu = byte_decode(m, 1).map(|bit| decompress(bit, 1));

    add_assign(&mut v, &mu);

    byte_encode(&v.map(|x| compress(x, p.dv)), p.dv, c2);

    wipe(y.as_flattened_mut());

    wipe(&mut acc);

    wipe(&mut u);

    wipe(&mut v);

    wipe(noise[..k + 1].as_flattened_mut());

    wipe(&mut mu);
}

fn pke_decrypt(s: &[Poly], c: &[u8], p: &Parameters) -> [u8; 32] {
    let k = p.k;

    let (c1, c2) = c.split_at(32 * p.du as usize * k);

    let mut acc = [0; 256];

    for (chunk, s_i) in c1.chunks_exact(32 * p.du as usize).zip(s) {
        let mut u = byte_decode(chunk, p.du).map(|x| decompress(x, p.du));

        ntt(&mut u);

        multiply_accumulate(&mut acc, s_i, &u);
    }

    let mut w = inverse_ntt(&acc);

    let v = byte_decode(c2, p.dv).map(|x| decompress(x, p.dv));

    for (x, y) in w.iter_mut().zip(v) {
        *x = compress(sub(y, *x), 1);
    }

    let mut m = [0; 32];

    byte_encode(&w, 1, &mut m);

    wipe(&mut acc);

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

pub(crate) fn encaps_internal(
    key: &EncapsulationKey,
    m: &[u8],
    p: &Parameters,
) -> ([u8; 32], Vec<u8>) {
    let mut g = sha3_512(&[m, &key.h]);

    let mut c = vec![0; p.ciphertext_size()];

    pke_encrypt(key, m, &g[32..], p, &mut c);

    declassify(&c);

    let mut shared_secret = [0; 32];

    shared_secret.copy_from_slice(&g[..32]);

    wipe(&mut g);

    (shared_secret, c)
}

// Implicit rejection: a ciphertext that does not re-encrypt to itself yields J(z || c), chosen
// by a mask so that the comparison result never steers a branch. dk supplies z; everything else
// comes from the decoded forms of the key and of its encapsulation key.
pub(crate) fn decaps_internal(
    public: &EncapsulationKey,
    secret: &DecapsulationKey,
    dk: &[u8],
    c: &[u8],
    p: &Parameters,
) -> [u8; 32] {
    let z = &dk[768 * p.k + 64..];

    let mut m = pke_decrypt(&secret.0, c, p);

    let mut g = sha3_512(&[&m, &public.h]);

    let mut rejected = [0; 32];

    shake256_into(&[z, c], &mut rejected);

    let mut reencrypted = SecretBytes::zeroed(c.len());

    pke_encrypt(public, &m, &g[32..], p, &mut reencrypted);

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
        && ek[..384 * p.k].as_chunks::<3>().0.iter().all(|chunk| {
            let d1 = u32::from(chunk[0]) | (u32::from(chunk[1] & 0x0F) << 8);

            let d2 = u32::from(chunk[1] >> 4) | (u32::from(chunk[2]) << 4);

            d1 < Q && d2 < Q
        })
}

pub(crate) fn check_decapsulation_key(dk: &[u8], p: &Parameters) -> bool {
    let k = p.k;

    if dk.len() != p.decapsulation_key_size() {
        return false;
    }

    // dk carries the encapsulation key and its hash, which are public.
    declassify(&dk[384 * k..768 * k + 64]);

    check_encapsulation_key(public_key_of(dk, p), p)
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
    use crate::cpu::testing::Inputs;

    // Values in [low, high): the bounds themselves, alternated, for the first cases, random ones
    // after that.
    fn values<T: Copy>(
        inputs: &mut Inputs,
        case: usize,
        low: i64,
        high: i64,
        cast: impl Fn(i64) -> T,
    ) -> [T; 256] {
        let edge = [low, high - 1];

        core::array::from_fn(|i| {
            cast(match case {
                0 | 1 => edge[case],
                2 => edge[i % 2],
                _ => low + (inputs.next() % (high - low) as u64) as i64,
            })
        })
    }

    // The transform and product kernels against the portable code: canonical coefficients into
    // the forward transform and the products, any 32-bit sums into the inverse, and sums below
    // 2^28 under the products.
    #[test]
    fn transform_kernels_match_portable() {
        let mut inputs = Inputs::new(3329);

        let mut accelerated = 0;

        let q = i64::from(Q);

        for n in 0..20_000 {
            let f = values(&mut inputs, n, 0, q, |x| x as u16);

            let mut expected = f.map(i32::from);

            ntt_layers(&mut expected);

            let mut actual = f.map(i32::from);

            if cpu::ntt(&mut actual, &FIELD) {
                assert_eq!(
                    actual.map(|x| x as u16),
                    canonical(&expected),
                    "ntt, case {n}"
                );

                accelerated += 1;
            }

            let mut actual = f;

            if cpu::ntt16(&mut actual, &FIELD16) {
                assert_eq!(actual, canonical(&expected), "16-bit ntt, case {n}");
            }

            let acc = values(&mut inputs, n, i64::from(i32::MIN), 1 << 31, |x| x as i32);

            let expected = inverse_ntt_portable(&mut acc.clone());

            let mut actual = acc;

            if cpu::inverse_ntt(&mut actual, &FIELD) {
                assert_eq!(actual.map(|x| x as u16), expected, "inverse, case {n}");
            }

            let mut actual = [0; 256];

            if cpu::inverse_ntt16(&acc, &mut actual, &FIELD16) {
                assert_eq!(actual, expected, "16-bit inverse, case {n}");
            }

            let g = values(&mut inputs, n + 1, 0, q, |x| x as u16);

            let acc = values(&mut inputs, n, -(1 << 28), 1 << 28, |x| x as i32);

            let (mut expected, mut actual) = (acc, acc);

            multiply_accumulate_portable(&mut expected, &f, &g);

            if cpu::base_multiply_add(&mut actual, &f, &g, &GAMMAS, &FIELD) {
                assert_eq!(actual, expected, "base multiplication, case {n}");
            }
        }

        std::eprintln!("ML-KEM: {accelerated} of 20000 cases through the CPU kernels");
    }

    // The noise kernel against the portable code, both values of eta, on random bytes and on
    // bytes of all zeros, all ones and alternating bits.
    #[test]
    fn binomial_kernel_matches_portable() {
        let mut inputs = Inputs::new(2);

        let mut accelerated = 0;

        for n in 0..20_000 {
            let data: [u8; 192] = match [0x00, 0xFF, 0x55, 0xAA].get(n) {
                Some(&byte) => [byte; 192],
                None => inputs.bytes(),
            };

            for eta in [2, 3] {
                let mut actual = [0; 256];

                if cpu::binomial(eta, &data[..64 * eta], Q as u16, &mut actual) {
                    let expected = binomial_portable(eta, &data[..64 * eta]);

                    assert_eq!(actual, expected, "eta {eta}, case {n}");

                    accelerated += 1;
                }
            }
        }

        std::eprintln!("ML-KEM noise: {accelerated} of 40000 cases through a CPU kernel");
    }

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

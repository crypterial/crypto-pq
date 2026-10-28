// FrodoKEM as ISO/IEC 18033-2:2006/Amd 2:2026 standardizes it, with draft-longa-cfrg-frodokem-03
// as the public text: the standard sets, which salt every encapsulation, and the ephemeral
// eFrodoKEM sets, which do not. Every set has q = 2^16 and n̄ = 8, so matrix entries are u16 values
// and arithmetic modulo q is plain wrapping arithmetic. The n x n matrix A is public and never
// stored: it is generated a few rows at a time and multiplied at once. Secret values never choose
// a branch or a memory index.

use alloc::vec;
use alloc::vec::Vec;
use core::array;
use core::hint::black_box;
use core::ops::{Deref, DerefMut};

use crate::aes::Aes;
use crate::cpu;
use crate::ct::{self, declassify};
use crate::keccak::{Keccak, MAX_SPONGES, Sponges};
use crate::primitives::shake256_into;
use crate::wipe::{SecretBytes, wipe, wipe_unless_optimized};

const BAR: usize = 8;

// The rows of A generated at once: one batch of the Keccak kernels, and the rows that the matrix
// kernels take.
const ROWS: usize = 8;

const MAX_N: usize = 1344;

const SHAKE128_RATE: usize = 168;

const SHAKE256_RATE: usize = 136;

const SHAKE_SUFFIX: u8 = 0x1f;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Parameters {
    n: usize,
    extracted: usize,
    secret_size: usize,
    seed_se_size: usize,
    salt_size: usize,
    shake: bool,
    // T_chi without its last entry, which sampling never reads.
    cdf: &'static [u16],
}

const CDF_976: &[u16] = &[
    5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766,
];

const CDF_1344: &[u16] = &[9142, 23462, 30338, 32361, 32725, 32765];

const fn set(n: usize, ephemeral: bool, shake: bool) -> Parameters {
    let (extracted, secret_size, cdf) = if n == 976 {
        (3, 24, CDF_976)
    } else {
        (4, 32, CDF_1344)
    };

    Parameters {
        n,
        extracted,
        secret_size,
        seed_se_size: if ephemeral {
            secret_size
        } else {
            2 * secret_size
        },
        salt_size: if ephemeral { 0 } else { 2 * secret_size },
        shake,
        cdf,
    }
}

pub(crate) const FRODOKEM_976_AES: Parameters = set(976, false, false);

pub(crate) const FRODOKEM_976_SHAKE: Parameters = set(976, false, true);

pub(crate) const FRODOKEM_1344_AES: Parameters = set(1344, false, false);

pub(crate) const FRODOKEM_1344_SHAKE: Parameters = set(1344, false, true);

pub(crate) const EFRODOKEM_976_AES: Parameters = set(976, true, false);

pub(crate) const EFRODOKEM_976_SHAKE: Parameters = set(976, true, true);

pub(crate) const EFRODOKEM_1344_AES: Parameters = set(1344, true, false);

pub(crate) const EFRODOKEM_1344_SHAKE: Parameters = set(1344, true, true);

impl Parameters {
    // pk = seedA || b, b the n x n̄ matrix B packed in 16-bit entries.
    pub(crate) const fn public_key_size(&self) -> usize {
        16 + 2 * BAR * self.n
    }

    // sk = s || pk || S^T || pkh.
    pub(crate) const fn private_key_size(&self) -> usize {
        2 * self.secret_size + self.public_key_size() + 2 * BAR * self.n
    }

    // ct = c1 || c2 || salt.
    pub(crate) const fn ciphertext_size(&self) -> usize {
        2 * BAR * self.n + 2 * BAR * BAR + self.salt_size
    }

    pub(crate) const fn shared_secret_size(&self) -> usize {
        self.secret_size
    }

    // The draw of key generation, s || seedSE || z.
    pub(crate) const fn seed_size(&self) -> usize {
        self.secret_size + self.seed_se_size + 16
    }

    // The draw of encapsulation, u || salt.
    pub(crate) const fn randomness_size(&self) -> usize {
        self.secret_size + self.salt_size
    }

    const fn work_size(&self) -> usize {
        3 * BAR * self.n + BAR * BAR
    }
}

// Matrix entries on the heap, wiped when dropped, so that a panic leaves no secret behind either.
struct Entries(Vec<u16>);

impl Entries {
    fn zeroed(length: usize) -> Self {
        Self(vec![0; length])
    }
}

impl Deref for Entries {
    type Target = [u16];

    fn deref(&self) -> &[u16] {
        &self.0
    }
}

impl DerefMut for Entries {
    fn deref_mut(&mut self) -> &mut [u16] {
        &mut self.0
    }
}

impl Drop for Entries {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

// Sample (draft 6.5): the magnitude counts the entries of T_chi below r >> 1, all of them compared
// arithmetically, and bit 0 of r gives the sign.
#[inline(always)]
fn sample(r: u16, cdf: &[u16]) -> u16 {
    let t = r >> 1;

    let mut e = 0u16;

    for &c in cdf {
        e += c.wrapping_sub(t) >> 15;
    }

    let sign = (r & 1).wrapping_neg();

    (e ^ sign).wrapping_sub(sign)
}

// Sample of each little-endian 16-bit value in bytes, into out. Each table is passed on as an
// array, so that its length is known at compile time: the comparisons unroll and the loop runs on
// vectors.
fn sample_all(out: &mut [u16], bytes: &[u8], cdf: &[u16]) {
    #[inline(always)]
    fn each(out: &mut [u16], bytes: &[u8], cdf: &[u16]) {
        for (value, pair) in out.iter_mut().zip(bytes.as_chunks::<2>().0) {
            *value = sample(u16::from_le_bytes(*pair), cdf);
        }
    }

    if let Ok(cdf) = <&[u16; 10]>::try_from(cdf) {
        each(out, bytes, cdf);
    } else if let Ok(cdf) = <&[u16; 6]>::try_from(cdf) {
        each(out, bytes, cdf);
    } else {
        each(out, bytes, cdf);
    }
}

// The 16-bit values of SHAKE256(domain || seedSE) (draft 7.1.1, 7.2 and 7.3), squeezed two blocks
// at a time and sampled as they are taken.
struct Stream {
    sponge: Keccak,
    blocks: [u8; 2 * SHAKE256_RATE],
    position: usize,
    cdf: &'static [u16],
}

impl Stream {
    fn new(domain: u8, seed_se: &[u8], cdf: &'static [u16]) -> Self {
        let mut sponge = Keccak::new(SHAKE256_RATE, SHAKE_SUFFIX);

        sponge.update(&[domain]);

        sponge.update(seed_se);

        Self {
            sponge,
            blocks: [0; 2 * SHAKE256_RATE],
            position: 2 * SHAKE256_RATE,
            cdf,
        }
    }

    fn fill(&mut self, mut out: &mut [u16]) {
        while !out.is_empty() {
            if self.position == self.blocks.len() {
                self.sponge.read(&mut self.blocks);

                self.position = 0;
            }

            let count = out.len().min((self.blocks.len() - self.position) / 2);

            let (now, rest) = out.split_at_mut(count);

            sample_all(now, &self.blocks[self.position..], self.cdf);

            self.position += 2 * count;

            out = rest;
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        wipe(&mut self.blocks);
    }
}

// pkh = SHAKE256(pk), the hash that encapsulation and the private key use.
pub(crate) fn public_key_hash(p: &Parameters, pk: &[u8]) -> [u8; 32] {
    let mut pkh = [0; 32];

    shake256_into(&[pk], &mut pkh[..p.secret_size]);

    pkh
}

// The rows of A from seedA (draft 6.7): SHAKE128(i || seedA) for row i, or the AES-128 blocks of
// 6.7.1 under the key seedA. A is public.
struct Matrix<'a> {
    p: &'a Parameters,
    seed_a: &'a [u8],
    sponges: Sponges,
    aes: Option<Aes>,
}

impl<'a> Matrix<'a> {
    fn new(p: &'a Parameters, seed_a: &'a [u8]) -> Self {
        Self {
            p,
            seed_a,
            sponges: Sponges::empty(),
            aes: (!p.shake).then(|| Aes::new(seed_a)),
        }
    }

    // Rows i0 to i0 + rows.len() / n - 1.
    fn rows(&mut self, rows: &mut [u16], i0: usize) {
        match &self.aes {
            Some(aes) => aes_rows(aes, rows, self.p.n, i0),
            None => shake_rows(&mut self.sponges, self.seed_a, rows, self.p.n, i0),
        }
    }
}

// One SHAKE128 sponge per row, all of them in lockstep. The AVX2 kernel keeps its sponges in
// vectors from one block to the next.
fn shake_rows(sponges: &mut Sponges, seed_a: &[u8], rows: &mut [u16], n: usize, i0: usize) {
    if cpu::frodo_shake_rows(seed_a, rows, n, i0) {
        return;
    }

    shake_rows_portable(sponges, seed_a, rows, n, i0);
}

fn shake_rows_portable(
    sponges: &mut Sponges,
    seed_a: &[u8],
    rows: &mut [u16],
    n: usize,
    i0: usize,
) {
    let count = rows.len() / n;

    let indices: [[u8; 2]; ROWS] = array::from_fn(|l| ((i0 + l) as u16).to_le_bytes());

    let parts: [[&[u8]; 2]; ROWS] = array::from_fn(|l| [&indices[l][..], seed_a]);

    let messages: [&[&[u8]]; ROWS] = array::from_fn(|l| &parts[l][..]);

    sponges.start(SHAKE128_RATE, SHAKE_SUFFIX, &messages[..count]);

    let mut active = [false; MAX_SPONGES];

    active[..count].fill(true);

    // n is a multiple of 4, so each lane gives four whole entries.
    for offset in (0..n).step_by(4 * 21) {
        sponges.squeeze(active);

        for (l, row) in rows.chunks_exact_mut(n).enumerate() {
            let lanes = sponges.lanes::<21>(l);

            for (entries, &lane) in row[offset..].as_chunks_mut::<4>().0.iter_mut().zip(lanes) {
                *entries = array::from_fn(|k| (lane >> (16 * k)) as u16);
            }
        }
    }
}

// Entries j to j + 7 of row i are AES128(seedA, i || j || 0...0) as little-endian 16-bit values,
// i and j little-endian 16-bit values too: a row is n / 8 blocks, encrypted in one call. With the
// AES instructions, the kernel builds the blocks in registers and runs them through the same core.
fn aes_rows(aes: &Aes, rows: &mut [u16], n: usize, i0: usize) {
    if let Some(keys) = aes.hardware_keys()
        && cpu::frodo_aes_rows(keys, rows, n, i0)
    {
        return;
    }

    aes_rows_portable(aes, rows, n, i0);
}

fn aes_rows_portable(aes: &Aes, rows: &mut [u16], n: usize, i0: usize) {
    let mut blocks = [[0u8; 16]; MAX_N / BAR];

    for (r, row) in rows.chunks_exact_mut(n).enumerate() {
        let blocks = &mut blocks[..n / BAR];

        for (j, block) in blocks.iter_mut().enumerate() {
            *block = [0; 16];

            block[..2].copy_from_slice(&((i0 + r) as u16).to_le_bytes());

            block[2..4].copy_from_slice(&((BAR * j) as u16).to_le_bytes());
        }

        aes.encrypt_blocks(blocks);

        for (entries, block) in row.as_chunks_mut::<BAR>().0.iter_mut().zip(blocks.iter()) {
            for (entry, pair) in entries.iter_mut().zip(block.as_chunks::<2>().0) {
                *entry = u16::from_le_bytes(*pair);
            }
        }
    }
}

// acc += rows S for ROWS consecutive rows of A, acc holding n̄ entries per row: s holds S, n̄
// entries per row, and st the same entries as S^T, n little-endian 16-bit values per row, as the
// private key stores it; each kernel reads the form that suits it.
fn mul_add_rows(acc: &mut [[u16; BAR]; ROWS], rows: &[u16], s: &[u16], st: &[u8], n: usize) {
    if cpu::frodo_mul_add_as(acc, rows, s, st, n) {
        return;
    }

    mul_add_rows_portable(acc, rows, s, n);
}

// Column by column, for all the rows at once: the rows' sums do not wait on each other.
fn mul_add_rows_portable(acc: &mut [[u16; BAR]; ROWS], rows: &[u16], s: &[u16], n: usize) {
    let rows: [&[u16]; ROWS] = array::from_fn(|r| &rows[r * n..(r + 1) * n]);

    for (j, s) in s.as_chunks::<BAR>().0.iter().enumerate().take(n) {
        for (acc, row) in acc.iter_mut().zip(&rows) {
            let a = row[j];

            for (acc, &s) in acc.iter_mut().zip(s) {
                *acc = acc.wrapping_add(a.wrapping_mul(s));
            }
        }
    }
}

// acc += S'[:, i0 : i0 + ROWS] rows for ROWS consecutive rows of A: acc holds n̄ rows of n
// entries, and column the n̄ entries of S'^T for each of the rows.
fn mul_add_columns(acc: &mut [u16], rows: &[u16], column: &[[u16; BAR]; ROWS], n: usize) {
    if cpu::frodo_mul_add_sa(acc, rows, column, n) {
        return;
    }

    mul_add_columns_portable(acc, rows, column, n);
}

fn mul_add_columns_portable(acc: &mut [u16], rows: &[u16], column: &[[u16; BAR]; ROWS], n: usize) {
    for (row, column) in rows.chunks_exact(n).zip(column) {
        for (dst, &c) in acc.chunks_exact_mut(n).zip(column) {
            for (d, &a) in dst.iter_mut().zip(row) {
                *d = d.wrapping_add(c.wrapping_mul(a));
            }
        }
    }
}

// v += S' B for S'^T in spt and B packed in b: the n̄ x n̄ part of encapsulation.
fn mul_add_sb(v: &mut [u16; BAR * BAR], spt: &[u16], b: &[u8]) {
    let (spt, _) = spt.as_chunks::<BAR>();

    let (b, _) = b.as_chunks::<{ 2 * BAR }>();

    for (column, packed) in spt.iter().zip(b) {
        let row: [u16; BAR] =
            array::from_fn(|l| u16::from_be_bytes([packed[2 * l], packed[2 * l + 1]]));

        for (k, &c) in column.iter().enumerate() {
            for (v, &x) in v[BAR * k..][..BAR].iter_mut().zip(&row) {
                *v = v.wrapping_add(c.wrapping_mul(x));
            }
        }
    }
}

// w -= B' S for B' packed in c1 and S in s: the n̄ x n̄ product of decapsulation.
fn mul_sub_bs(w: &mut [u16; BAR * BAR], s: &[u16], c1: &[u8], n: usize) {
    let (s, _) = s.as_chunks::<BAR>();

    for (k, row) in c1.chunks_exact(2 * n).enumerate() {
        let mut acc = [0u16; BAR];

        for (x, s) in row.as_chunks::<2>().0.iter().zip(s) {
            let x = u16::from_be_bytes(*x);

            for (acc, &y) in acc.iter_mut().zip(s) {
                *acc = acc.wrapping_add(x.wrapping_mul(y));
            }
        }

        for (w, y) in w[BAR * k..][..BAR].iter_mut().zip(acc) {
            *w = w.wrapping_sub(y);
        }

        wipe_unless_optimized!(&mut acc);
    }
}

// Pack (draft 6.4) for D = 16: each entry as two bytes, most significant first.
fn pack(out: &mut [u8], values: &[u16]) {
    for (out, v) in out.as_chunks_mut::<2>().0.iter_mut().zip(values) {
        *out = v.to_be_bytes();
    }
}

// out = in^T for in with n̄ rows of n little-endian 16-bit values.
fn transpose_bytes(out: &mut [u16], input: &[u8], n: usize) {
    for (k, row) in input.chunks_exact(2 * n).enumerate() {
        for (j, x) in row.as_chunks::<2>().0.iter().enumerate() {
            out[BAR * j + k] = u16::from_le_bytes(*x);
        }
    }
}

// Encode (draft 6.3) of the B-bit pieces of u, least significant bits first, each scaled to the top
// of its entry: C = Encode(u) is added to V in place.
fn add_encoded(p: &Parameters, v: &mut [u16; BAR * BAR], u: &[u8]) {
    let b = p.extracted;

    let mask = (1u64 << b) - 1;

    for (w, chunk) in u.chunks_exact(b).enumerate() {
        let t = chunk
            .iter()
            .enumerate()
            .fold(0u64, |t, (j, &x)| t | u64::from(x) << (8 * j));

        for (j, v) in v[BAR * w..][..BAR].iter_mut().enumerate() {
            *v = v.wrapping_add(((t >> (b * j) & mask) as u16) << (16 - b));
        }
    }
}

// Decode (draft 6.3): each entry rounded to its top B bits, which are packed back into u.
fn decode(p: &Parameters, u: &mut [u8], m: &[u16; BAR * BAR]) {
    let b = p.extracted;

    for (chunk, entries) in u.chunks_exact_mut(b).zip(m.as_chunks::<BAR>().0) {
        let t = entries.iter().enumerate().fold(0u64, |t, (j, &c)| {
            t | u64::from(c.wrapping_add(1 << (15 - b)) >> (16 - b)) << (b * j)
        });

        for (j, x) in chunk.iter_mut().enumerate() {
            *x = (t >> (8 * j)) as u8;
        }
    }
}

// b = A S + E packed, for S and E with n̄ entries per row and st as in mul_add_rows; rows holds
// ROWS rows of A at a time.
fn mul_add_as(a: &mut Matrix, b: &mut [u8], s: &[u16], st: &[u8], e: &[u16], rows: &mut [u16]) {
    let n = a.p.n;

    let mut acc = [[0u16; BAR]; ROWS];

    for i in (0..n).step_by(ROWS) {
        a.rows(rows, i);

        for (acc, e) in acc.iter_mut().zip(e[BAR * i..].as_chunks::<BAR>().0) {
            *acc = *e;
        }

        mul_add_rows(&mut acc, rows, s, st, n);

        pack(&mut b[2 * BAR * i..], acc.as_flattened());
    }

    wipe(acc.as_flattened_mut());
}

// acc += S' A, for S'^T in spt and acc with n̄ rows of n entries.
fn mul_add_sa(a: &mut Matrix, acc: &mut [u16], spt: &[u16], rows: &mut [u16]) {
    let n = a.p.n;

    let (spt, _) = spt.as_chunks::<BAR>();

    for i in (0..n).step_by(ROWS) {
        a.rows(rows, i);

        let column = spt[i..i + ROWS].try_into().expect("ROWS rows");

        mul_add_columns(acc, rows, column, n);
    }
}

// KeyGen (draft 7.1.1) from the draw s || seedSE || z: sk = s || pk || S^T || pkh, S^T sampled
// straight into sk.
pub(crate) fn keygen(p: &Parameters, seed: &[u8]) -> SecretBytes {
    let (n, secret) = (p.n, p.secret_size);

    let mut sk = SecretBytes::zeroed(p.private_key_size());

    let (s_bytes, rest) = sk.split_at_mut(secret);

    let (pk, rest) = rest.split_at_mut(p.public_key_size());

    let (st_bytes, pkh) = rest.split_at_mut(2 * BAR * n);

    s_bytes.copy_from_slice(&seed[..secret]);

    let (seed_a, b) = pk.split_at_mut(16);

    shake256_into(&[&seed[secret + p.seed_se_size..]], seed_a);

    // seedA and B make up the public key.
    declassify(seed_a);

    let mut work = Entries::zeroed(3 * BAR * n);

    let (s, rest) = work.split_at_mut(BAR * n);

    let (e, rows) = rest.split_at_mut(BAR * n);

    {
        let mut stream = Stream::new(0x5f, &seed[secret..secret + p.seed_se_size], p.cdf);

        // S^T first, through e.
        stream.fill(e);

        for (x, &v) in st_bytes.as_chunks_mut::<2>().0.iter_mut().zip(e.iter()) {
            *x = v.to_le_bytes();
        }

        stream.fill(e);
    }

    transpose_bytes(s, st_bytes, n);

    mul_add_as(
        &mut Matrix::new(p, seed_a),
        b,
        s,
        st_bytes,
        e,
        &mut rows[..ROWS * n],
    );

    declassify(b);

    pkh.copy_from_slice(&public_key_hash(p, pk)[..secret]);

    sk
}

// B' = S' A + E' into bp and C = S' B + E" + Encode(u) packed into c2, with the noise from stream;
// work holds S'^T, E' (where B' is accumulated) and the rows of A.
fn encrypt(
    p: &Parameters,
    work: &mut [u16],
    pk: &[u8],
    u: &[u8],
    stream: &mut Stream,
    c2: &mut [u8],
) {
    let n = p.n;

    let (spt, rest) = work.split_at_mut(BAR * n);

    let (bp, rest) = rest.split_at_mut(BAR * n);

    let (v, rows) = rest.split_at_mut(BAR * BAR);

    let v: &mut [u16; BAR * BAR] = v.try_into().expect("n̄ x n̄ entries");

    // S' first, through bp.
    stream.fill(bp);

    for (k, row) in bp.chunks_exact(n).enumerate() {
        for (column, &x) in spt.as_chunks_mut::<BAR>().0.iter_mut().zip(row) {
            column[k] = x;
        }
    }

    stream.fill(bp);

    stream.fill(v);

    let (seed_a, b) = pk.split_at(16);

    mul_add_sa(&mut Matrix::new(p, seed_a), bp, spt, &mut rows[..ROWS * n]);

    mul_add_sb(v, spt, b);

    add_encoded(p, v, u);

    pack(c2, v);
}

// Encaps (draft 7.2) with the draw u || salt and pkh = SHAKE(pk): the ciphertext, and the shared
// secret written to shared_secret, of secret_size bytes.
pub(crate) fn encapsulate(
    p: &Parameters,
    pk: &[u8],
    pkh: &[u8],
    randomness: &[u8],
    shared_secret: &mut [u8],
) -> Vec<u8> {
    let (n, secret) = (p.n, p.secret_size);

    let (u, salt) = randomness.split_at(secret);

    let mut g = [0u8; 96];

    shake256_into(&[pkh, u, salt], &mut g[..p.seed_se_size + secret]);

    let (seed_se, k) = g.split_at(p.seed_se_size);

    let mut ciphertext = vec![0; p.ciphertext_size()];

    let (c1, rest) = ciphertext.split_at_mut(2 * BAR * n);

    let (c2, salt_out) = rest.split_at_mut(2 * BAR * BAR);

    salt_out.copy_from_slice(salt);

    let mut work = Entries::zeroed(p.work_size());

    encrypt(
        p,
        &mut work,
        pk,
        u,
        &mut Stream::new(0x96, seed_se, p.cdf),
        c2,
    );

    pack(c1, &work[BAR * n..2 * BAR * n]);

    declassify(&ciphertext);

    shake256_into(&[&ciphertext, &k[..secret]], shared_secret);

    wipe(&mut g);

    ciphertext
}

// Decaps (draft 7.3) with sk = s || pk || S^T || pkh: the re-encryption of the decoded u' must give
// B' || C again, compared in full without an early exit; otherwise the shared secret comes from s
// instead of k', chosen with a mask. The shared secret, of secret_size bytes, goes to shared_secret.
pub(crate) fn decapsulate(p: &Parameters, sk: &[u8], ciphertext: &[u8], shared_secret: &mut [u8]) {
    let (n, secret) = (p.n, p.secret_size);

    let (s, rest) = sk.split_at(secret);

    let (pk, rest) = rest.split_at(p.public_key_size());

    let (st_bytes, pkh) = rest.split_at(2 * BAR * n);

    let (c1, rest) = ciphertext.split_at(2 * BAR * n);

    let (c2, salt) = rest.split_at(2 * BAR * BAR);

    let mut work = Entries::zeroed(p.work_size());

    transpose_bytes(&mut work[..BAR * n], st_bytes, n);

    let mut m: [u16; BAR * BAR] =
        array::from_fn(|i| u16::from_be_bytes([c2[2 * i], c2[2 * i + 1]]));

    mul_sub_bs(&mut m, &work[..BAR * n], c1, n);

    // pkh || u' || salt, the input of the second hash.
    let mut input = [0u8; 128];

    let length = 2 * secret + salt.len();

    input[..secret].copy_from_slice(pkh);

    decode(p, &mut input[secret..2 * secret], &m);

    input[2 * secret..length].copy_from_slice(salt);

    let mut g = [0u8; 96];

    shake256_into(&[&input[..length]], &mut g[..p.seed_se_size + secret]);

    let mut c2_prime = [0u8; 2 * BAR * BAR];

    encrypt(
        p,
        &mut work,
        pk,
        &input[secret..2 * secret],
        &mut Stream::new(0x96, &g[..p.seed_se_size], p.cdf),
        &mut c2_prime,
    );

    let mut difference = 0u16;

    for (&v, x) in work[BAR * n..2 * BAR * n].iter().zip(c1.as_chunks::<2>().0) {
        difference |= v ^ u16::from_be_bytes(*x);
    }

    let same = (u32::from(black_box(difference)).wrapping_sub(1) >> 31) as u8;

    let mask = same.wrapping_neg() & ct::equal_mask(&c2_prime, c2);

    let mut k_hat = [0u8; 32];

    ct::select(
        mask,
        &g[p.seed_se_size..p.seed_se_size + secret],
        s,
        &mut k_hat[..secret],
    );

    shake256_into(&[ciphertext, &k_hat[..secret]], shared_secret);

    wipe(&mut m);

    wipe(&mut input);

    wipe(&mut g);

    wipe(&mut c2_prime);

    wipe(&mut k_hat);
}

// The import checks of a raw private key before its pairwise test (SPEC 8.2.4 item 3): pkh must be
// SHAKE(pk) of the public key inside it, both public, and S^T must lie in the support of chi.
pub(crate) fn check_private_key(p: &Parameters, sk: &[u8]) -> bool {
    let secret = p.secret_size;

    let (pk, rest) = sk[secret..].split_at(p.public_key_size());

    let (st, pkh) = rest.split_at(2 * BAR * p.n);

    declassify(pk);

    declassify(pkh);

    ct::equal(&public_key_hash(p, pk)[..secret], pkh) && short_secret(p, st)
}

// Whether every entry of S^T lies in [-d, d] modulo q = 2^16, for the d entries of T_chi that
// Sample reads: the values that KeyGen samples (draft 6.5, 7.1.1) [D-74]. Every entry is compared
// without a branch; only the outcome is declassified, as the import fails on it.
fn short_secret(p: &Parameters, st: &[u8]) -> bool {
    let bound = p.cdf.len() as u32;

    let mut outside = 0;

    // x + d mod 2^16 is at most 2d exactly when x is in [-d, d] modulo 2^16.
    for x in st.as_chunks::<2>().0 {
        outside |= (2 * bound).wrapping_sub((u32::from(u16::from_le_bytes(*x)) + bound) & 0xFFFF);
    }

    ct::declassify_value(black_box(outside) >> 31) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // S^T of a private key: every entry at -d or d passes, one beyond either bound or with its top
    // bit flipped fails, at any position.
    #[test]
    fn secret_range() {
        for p in [FRODOKEM_976_AES, FRODOKEM_1344_SHAKE] {
            let d = p.cdf.len() as i32;

            let entries = BAR * p.n;

            let encoded = |values: &[i32]| -> Vec<u8> {
                values
                    .iter()
                    .flat_map(|&x| (x as u16).to_le_bytes())
                    .collect()
            };

            let mut st: Vec<i32> = (0..entries)
                .map(|i| if i % 2 == 0 { d } else { -d })
                .collect();

            assert!(short_secret(&p, &encoded(&st)));

            for position in [0, 1, entries / 2, entries - 1] {
                let original = st[position];

                for beyond in [d + 1, -d - 1, original ^ 0x8000, 0x7FFF] {
                    st[position] = beyond;

                    assert!(!short_secret(&p, &encoded(&st)), "{beyond}");
                }

                st[position] = original;
            }
        }
    }

    // Random 16-bit entries, with runs of the extreme values 0 and 0xFFFF, which drive the
    // wrapping products to their limits.
    fn entries(inputs: &mut crate::cpu::testing::Inputs, count: usize) -> Vec<u16> {
        let edge = inputs.next() % 4;

        (0..count)
            .map(|i| match (edge, i % 3) {
                (0, 0) => 0,
                (1, _) => 0xFFFF,
                _ => inputs.next() as u16,
            })
            .collect()
    }

    // The kernels for A against the portable code: the AES rows on random keys, from any row and
    // for any number of rows (whole groups of eight blocks and a rest), the SHAKE rows from any
    // row, and both products on random and extreme entries, for both matrix sizes and sizes that
    // the kernels refuse.
    #[test]
    fn matrix_kernels_match_portable() {
        let mut inputs = crate::cpu::testing::Inputs::new(0xF20D0);

        for case in 0..40 {
            let n = [976, 1344][case % 2];

            let key: [u8; 16] = inputs.bytes();

            let count = [ROWS, 1, 3, 5][case % 4];

            let i0 = (inputs.next() as usize) % (n - count + 1);

            let mut kernel = vec![0u16; count * n];

            let mut expected = kernel.clone();

            aes_rows(&Aes::new(&key), &mut kernel, n, i0);

            aes_rows_portable(&Aes::portable(&key), &mut expected, n, i0);

            assert_eq!(kernel, expected, "AES rows, case {case}");

            // The SHAKE kernel takes four rows at a time.
            let count = [ROWS, 4][case % 2];

            let mut kernel = vec![0u16; count * n];

            let mut expected = kernel.clone();

            let i0 = (inputs.next() as usize) % (n - count + 1);

            shake_rows(&mut Sponges::empty(), &key, &mut kernel, n, i0);

            shake_rows_portable(&mut Sponges::empty(), &key, &mut expected, n, i0);

            assert_eq!(kernel, expected, "SHAKE rows, case {case}");
        }

        for case in 0..60 {
            let n = [976, 1344, 16, 32, 8, 24][case % 6];

            let rows = entries(&mut inputs, ROWS * n);

            let s = entries(&mut inputs, BAR * n);

            let mut st = vec![0u8; 2 * BAR * n];

            for (j, row) in s.as_chunks::<BAR>().0.iter().enumerate() {
                for (k, &x) in row.iter().enumerate() {
                    st[2 * (n * k + j)..][..2].copy_from_slice(&x.to_le_bytes());
                }
            }

            let start: [[u16; BAR]; ROWS] =
                array::from_fn(|_| array::from_fn(|_| inputs.next() as u16));

            let (mut kernel, mut expected) = (start, start);

            mul_add_rows(&mut kernel, &rows, &s, &st, n);

            mul_add_rows_portable(&mut expected, &rows, &s, n);

            assert_eq!(kernel, expected, "A S, case {case}");

            let column: [[u16; BAR]; ROWS] =
                array::from_fn(|_| array::from_fn(|_| inputs.next() as u16));

            let mut kernel = entries(&mut inputs, BAR * n);

            let mut expected = kernel.clone();

            mul_add_columns(&mut kernel, &rows, &column, n);

            mul_add_columns_portable(&mut expected, &rows, &column, n);

            assert_eq!(kernel, expected, "S' A, case {case}");
        }
    }

    // Sampling in bulk against Sample on its own, for every 16-bit value and both tables, and the
    // generic path of a table of another length.
    #[test]
    fn bulk_sampling_matches_sample() {
        let bytes: Vec<u8> = (0..=u16::MAX).flat_map(u16::to_le_bytes).collect();

        for cdf in [CDF_976, CDF_1344, &CDF_976[..7]] {
            let mut out = vec![0u16; 1 << 16];

            sample_all(&mut out, &bytes, cdf);

            for (r, &value) in out.iter().enumerate() {
                assert_eq!(value, sample(r as u16, cdf), "{r}");
            }
        }
    }
}

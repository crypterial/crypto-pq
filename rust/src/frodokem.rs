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
use crate::ct::{self, declassify};
use crate::keccak::{Keccak, MAX_SPONGES, Sponges};
use crate::wipe::{SecretBytes, wipe};

const BAR: usize = 8;

// The rows of A generated at once: one batch of the Keccak kernels.
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
fn sample(r: u16, cdf: &[u16]) -> u16 {
    let t = r >> 1;

    let mut e = 0u16;

    for &c in cdf {
        e += c.wrapping_sub(t) >> 15;
    }

    let sign = (r & 1).wrapping_neg();

    (e ^ sign).wrapping_sub(sign)
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

    fn next(&mut self) -> u16 {
        if self.position == self.blocks.len() {
            self.sponge.read(&mut self.blocks);

            self.position = 0;
        }

        let value =
            u16::from_le_bytes([self.blocks[self.position], self.blocks[self.position + 1]]);

        self.position += 2;

        sample(value, self.cdf)
    }

    fn fill(&mut self, out: &mut [u16]) {
        for value in out {
            *value = self.next();
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        wipe(&mut self.blocks);
    }
}

fn shake256(out: &mut [u8], parts: &[&[u8]]) {
    let mut sponge = Keccak::new(SHAKE256_RATE, SHAKE_SUFFIX);

    for part in parts {
        sponge.update(part);
    }

    sponge.read(out);
}

// pkh = SHAKE256(pk), the hash that encapsulation and the private key use.
pub(crate) fn public_key_hash(p: &Parameters, pk: &[u8]) -> [u8; 32] {
    let mut pkh = [0; 32];

    shake256(&mut pkh[..p.secret_size], &[pk]);

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

// One SHAKE128 sponge per row, all of them in lockstep.
fn shake_rows(sponges: &mut Sponges, seed_a: &[u8], rows: &mut [u16], n: usize, i0: usize) {
    let count = rows.len() / n;

    let indices: [[u8; 2]; ROWS] = array::from_fn(|l| ((i0 + l) as u16).to_le_bytes());

    let parts: [[&[u8]; 2]; ROWS] = array::from_fn(|l| [&indices[l][..], seed_a]);

    let messages: [&[&[u8]]; ROWS] = array::from_fn(|l| &parts[l][..]);

    sponges.start(SHAKE128_RATE, SHAKE_SUFFIX, &messages[..count]);

    let mut active = [false; MAX_SPONGES];

    active[..count].fill(true);

    for offset in (0..n).step_by(4 * 21) {
        sponges.squeeze(active);

        for (l, row) in rows.chunks_exact_mut(n).enumerate() {
            let lanes = sponges.lanes::<21>(l);

            for (i, entry) in row[offset..].iter_mut().take(4 * 21).enumerate() {
                *entry = (lanes[i / 4] >> (16 * (i % 4))) as u16;
            }
        }
    }
}

// Entries j to j + 7 of row i are AES128(seedA, i || j || 0...0) as little-endian 16-bit values,
// i and j little-endian 16-bit values too: a row is n / 8 blocks, encrypted in one call.
fn aes_rows(aes: &Aes, rows: &mut [u16], n: usize, i0: usize) {
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

// out = rows S + E for consecutive rows of A, packed into out: s holds S and e the matching rows of
// E, n̄ entries per row of either.
fn mul_add_rows(out: &mut [u8], rows: &[u16], s: &[u16], e: &[u16], n: usize) {
    let (s, _) = s.as_chunks::<BAR>();

    let (e, _) = e.as_chunks::<BAR>();

    let (out, _) = out.as_chunks_mut::<{ 2 * BAR }>();

    for ((row, e), out) in rows.chunks_exact(n).zip(e).zip(out) {
        let mut acc = *e;

        for (&a, s) in row.iter().zip(s) {
            for (acc, &s) in acc.iter_mut().zip(s) {
                *acc = acc.wrapping_add(a.wrapping_mul(s));
            }
        }

        pack(out, &acc);
    }
}

// acc += S'[:, i0 : i0 + rows] rows for consecutive rows of A starting at row i0: acc holds n̄ rows
// of n entries, and spt holds S'^T, n̄ entries per row.
fn mul_add_columns(acc: &mut [u16], rows: &[u16], spt: &[u16], n: usize, i0: usize) {
    for (r, row) in rows.chunks_exact(n).enumerate() {
        let column = &spt[BAR * (i0 + r)..][..BAR];

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

// b = A S + E packed, for S and E with n̄ entries per row; rows holds ROWS rows of A at a time.
fn mul_add_as(a: &mut Matrix, b: &mut [u8], s: &[u16], e: &[u16], rows: &mut [u16]) {
    let n = a.p.n;

    for i in (0..n).step_by(ROWS) {
        a.rows(rows, i);

        mul_add_rows(&mut b[2 * BAR * i..], rows, s, &e[BAR * i..], n);
    }
}

// acc += S' A, for S'^T in spt and acc with n̄ rows of n entries.
fn mul_add_sa(a: &mut Matrix, acc: &mut [u16], spt: &[u16], rows: &mut [u16]) {
    let n = a.p.n;

    for i in (0..n).step_by(ROWS) {
        a.rows(rows, i);

        mul_add_columns(acc, rows, spt, n, i);
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

    shake256(seed_a, &[&seed[secret + p.seed_se_size..]]);

    // seedA and B make up the public key.
    declassify(seed_a);

    let mut work = Entries::zeroed(3 * BAR * n);

    let (s, rest) = work.split_at_mut(BAR * n);

    let (e, rows) = rest.split_at_mut(BAR * n);

    {
        let mut stream = Stream::new(0x5f, &seed[secret..secret + p.seed_se_size], p.cdf);

        for x in st_bytes.as_chunks_mut::<2>().0 {
            *x = stream.next().to_le_bytes();
        }

        stream.fill(e);
    }

    transpose_bytes(s, st_bytes, n);

    mul_add_as(&mut Matrix::new(p, seed_a), b, s, e, &mut rows[..ROWS * n]);

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

    for k in 0..BAR {
        for i in 0..n {
            spt[BAR * i + k] = stream.next();
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

// Encaps (draft 7.2) with the draw u || salt and pkh = SHAKE(pk): the shared secret, in the first
// secret_size bytes, and the ciphertext.
pub(crate) fn encapsulate(
    p: &Parameters,
    pk: &[u8],
    pkh: &[u8],
    randomness: &[u8],
) -> ([u8; 32], Vec<u8>) {
    let (n, secret) = (p.n, p.secret_size);

    let (u, salt) = randomness.split_at(secret);

    let mut g = [0u8; 96];

    shake256(&mut g[..p.seed_se_size + secret], &[pkh, u, salt]);

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

    let mut shared_secret = [0; 32];

    shake256(&mut shared_secret[..secret], &[&ciphertext, &k[..secret]]);

    wipe(&mut g);

    (shared_secret, ciphertext)
}

// Decaps (draft 7.3) with sk = s || pk || S^T || pkh: the re-encryption of the decoded u' must give
// B' || C again, compared in full without an early exit; otherwise the shared secret comes from s
// instead of k', chosen with a mask.
pub(crate) fn decapsulate(p: &Parameters, sk: &[u8], ciphertext: &[u8]) -> [u8; 32] {
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

    shake256(&mut g[..p.seed_se_size + secret], &[&input[..length]]);

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

    let mut shared_secret = [0; 32];

    shake256(
        &mut shared_secret[..secret],
        &[ciphertext, &k_hat[..secret]],
    );

    wipe(&mut m);

    wipe(&mut input);

    wipe(&mut g);

    wipe(&mut c2_prime);

    wipe(&mut k_hat);

    shared_secret
}

// The import check of a raw private key: pkh must be SHAKE(pk) of the public key inside it. Both
// are public.
pub(crate) fn check_private_key(p: &Parameters, sk: &[u8]) -> bool {
    let secret = p.secret_size;

    let pk = &sk[secret..secret + p.public_key_size()];

    let pkh = &sk[sk.len() - secret..];

    declassify(pk);

    declassify(pkh);

    ct::equal(&public_key_hash(p, pk)[..secret], pkh)
}

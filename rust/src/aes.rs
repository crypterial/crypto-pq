// AES-128 and AES-256 encryption (FIPS 197). With the AES instructions (AES-NI on x86-64, the
// ARMv8 AES instructions on arm64) the round keys are expanded and the blocks encrypted by them.
// Everywhere else the portable code is constant time all the same: a group of blocks in bitsliced
// form, as BearSSL's aes_ct64 and aes_ct pack them, eight planes of which plane b holds bit b of
// every byte. A u64 plane holds four blocks; a u32 plane holds two, on the 32-bit targets other
// than WebAssembly, where a 64-bit operation takes two instructions. The S-box is the circuit of
// Boyar and Peralta (eprint 2009/191). The rounds are fixsliced (Adomnicai and Peyrin, eprint
// 2020/1123): they leave out ShiftRows, so that after round r the state is ShiftRows applied r
// times fewer than FIPS 197 has it, and MixColumns and the round key of round r are moved to
// match. No table is indexed by data and no branch depends on it.

use alloc::boxed::Box;
use core::ops::{BitAnd, BitOr, BitXor, BitXorAssign, Not, Shl, Shr};

use crate::cpu;
use crate::wipe::wipe;

#[cfg(any(target_pointer_width = "64", target_family = "wasm"))]
type Native = u64;

#[cfg(not(any(target_pointer_width = "64", target_family = "wasm")))]
type Native = u32;

// A bit plane of a group of BLOCKS blocks: bit ROW r + BLOCKS c + i of plane b is bit b of the
// byte in row r, column c of block i. A row of the state is a run of ROW bits, a column of it a
// run of BLOCKS bits.
trait Plane:
    Copy
    + Default
    + BitAnd<Output = Self>
    + BitOr<Output = Self>
    + BitXor<Output = Self>
    + BitXorAssign
    + Not<Output = Self>
    + Shl<u32, Output = Self>
    + Shr<u32, Output = Self>
{
    const BLOCKS: usize;

    const ROW: u32 = 4 * Self::BLOCKS as u32;

    // A rotation right by n bits.
    fn rotate(self, n: u32) -> Self;

    // The low ROW bits of pattern in each of the four rows.
    fn rows(pattern: u32) -> Self;

    // pattern in each byte.
    fn bytes(pattern: u8) -> Self;

    // The first BLOCKS blocks into the planes, in the order that ortho turns into bit planes.
    fn spread(blocks: &[[u8; 16]], q: &mut [Self; 8]);

    // The inverse of spread, into the first BLOCKS blocks.
    fn gather(q: &[Self; 8], blocks: &mut [[u8; 16]]);
}

// As BearSSL's aes_ct64: words 0 and 1 of block i through q[i], words 2 and 3 through q[i + 4].
impl Plane for u64 {
    const BLOCKS: usize = 4;

    fn rotate(self, n: u32) -> Self {
        self.rotate_right(n)
    }

    fn rows(pattern: u32) -> Self {
        u64::from(pattern as u16) * 0x0001_0001_0001_0001
    }

    fn bytes(pattern: u8) -> Self {
        u64::from(pattern) * 0x0101_0101_0101_0101
    }

    #[inline(always)]
    fn spread(blocks: &[[u8; 16]], q: &mut [u64; 8]) {
        for (i, block) in blocks[..4].iter().enumerate() {
            (q[i], q[i + 4]) = interleave_in(&words_of(block));
        }
    }

    #[inline(always)]
    fn gather(q: &[u64; 8], blocks: &mut [[u8; 16]]) {
        for (i, block) in blocks[..4].iter_mut().enumerate() {
            let words = interleave_out(q[i], q[i + 4]);

            for (bytes, word) in block.as_chunks_mut::<4>().0.iter_mut().zip(words) {
                *bytes = word.to_le_bytes();
            }
        }
    }
}

// As BearSSL's aes_ct: word w of block i in q[2w + i].
impl Plane for u32 {
    const BLOCKS: usize = 2;

    fn rotate(self, n: u32) -> Self {
        self.rotate_right(n)
    }

    fn rows(pattern: u32) -> Self {
        (pattern & 0xFF) * 0x0101_0101
    }

    fn bytes(pattern: u8) -> Self {
        u32::from(pattern) * 0x0101_0101
    }

    #[inline(always)]
    fn spread(blocks: &[[u8; 16]], q: &mut [u32; 8]) {
        for (i, block) in blocks[..2].iter().enumerate() {
            for (w, word) in words_of(block).into_iter().enumerate() {
                q[2 * w + i] = word;
            }
        }
    }

    #[inline(always)]
    fn gather(q: &[u32; 8], blocks: &mut [[u8; 16]]) {
        for (i, block) in blocks[..2].iter_mut().enumerate() {
            for (w, bytes) in block.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                *bytes = q[2 * w + i].to_le_bytes();
            }
        }
    }
}

// The round keys of one key: in FIPS 197 byte order for the AES instructions, or bitsliced, each
// in every block of a group, for the portable code; only the form in use is filled. They are on
// the heap, so that moving an Aes moves a pointer and leaves no copy of them behind, and are wiped
// when it is dropped.
pub(crate) struct Aes {
    rounds: usize,
    keys: Box<RoundKeys>,
    hardware: bool,
}

struct RoundKeys {
    fips: [[u8; 16]; 15],
    bitsliced: [[Native; 8]; 15],
}

impl Drop for RoundKeys {
    fn drop(&mut self) {
        wipe(&mut self.fips);

        wipe(self.bitsliced.as_flattened_mut());
    }
}

impl Aes {
    // A key of 16 or 32 bytes; callers check the length before.
    pub(crate) fn new(key: &[u8]) -> Self {
        Self::with(key, true)
    }

    // The portable code alone, for the tests that compare it with the AES instructions.
    #[cfg(any(test, crypto_pq_ct))]
    pub(crate) fn portable(key: &[u8]) -> Self {
        Self::with(key, false)
    }

    fn with(key: &[u8], hardware: bool) -> Self {
        assert!(
            key.len() == 16 || key.len() == 32,
            "AES takes a 16- or 32-byte key"
        );

        let rounds = if key.len() == 16 { 10 } else { 14 };

        let mut aes = Self {
            rounds,
            keys: Box::new(RoundKeys {
                fips: [[0; 16]; 15],
                bitsliced: [[0; 8]; 15],
            }),
            hardware: false,
        };

        if hardware && cpu::aes_expand(key, &mut aes.keys.fips) {
            aes.hardware = true;

            return aes;
        }

        let mut words = [0u32; 60];

        expand(key, &mut words[..4 * (rounds + 1)]);

        bitslice_keys(
            &words[..4 * (rounds + 1)],
            &mut aes.keys.bitsliced[..rounds + 1],
        );

        wipe(&mut words);

        aes
    }

    // The round keys in FIPS 197 order, when the AES instructions run this key.
    pub(crate) fn hardware_keys(&self) -> Option<&[[u8; 16]]> {
        self.hardware.then(|| &self.keys.fips[..self.rounds + 1])
    }

    #[cfg(test)]
    pub(crate) fn encrypt_block(&self, block: &mut [u8; 16]) {
        self.encrypt_blocks(core::slice::from_mut(block));
    }

    // Encrypts the blocks in place.
    pub(crate) fn encrypt_blocks(&self, blocks: &mut [[u8; 16]]) {
        if let Some(keys) = self.hardware_keys()
            && cpu::aes_encrypt(keys, blocks)
        {
            return;
        }

        let keys = &self.keys.bitsliced[..self.rounds + 1];

        let (groups, rest) = blocks.as_chunks_mut::<{ Native::BLOCKS }>();

        for group in groups {
            encrypt_group(keys, group);
        }

        if !rest.is_empty() {
            let mut group = [[0; 16]; 4];

            group[..rest.len()].copy_from_slice(rest);

            encrypt_group(keys, &mut group);

            rest.copy_from_slice(&group[..rest.len()]);

            wipe(&mut group);
        }
    }
}

// Encrypts the first P::BLOCKS blocks in place under the bitsliced round keys. Rounds 1 to 4 run
// in the representations 1, 2, 3 and 0, and so on. The round before the last, 9 or 13, is in
// representation 1, so ShiftRows twice, the one left out and that of the last round, brings the
// state to the order of FIPS 197. The S-box and the other pieces are inlined here: a call would
// pass the planes through memory.
fn encrypt_group<P: Plane>(keys: &[[P; 8]], blocks: &mut [[u8; 16]]) {
    let rounds = keys.len() - 1;

    let mut q = [P::default(); 8];

    P::spread(blocks, &mut q);

    ortho(&mut q);

    add_round_key(&mut q, &keys[0]);

    for r in (1..rounds - 1).step_by(4) {
        round::<P, 1>(&mut q, &keys[r]);

        round::<P, 2>(&mut q, &keys[r + 1]);

        round::<P, 3>(&mut q, &keys[r + 2]);

        round::<P, 0>(&mut q, &keys[r + 3]);
    }

    round::<P, 1>(&mut q, &keys[rounds - 1]);

    sbox(&mut q);

    shift_rows_2(&mut q);

    add_round_key(&mut q, &keys[rounds]);

    ortho(&mut q);

    P::gather(&q, blocks);

    wipe(&mut q);
}

// The expanded key as bitsliced round keys, each in every block of a group. Round key r but the
// last is in the representation of round r, ShiftRows undone r times, and those after the first
// carry the S-box constant 0x63, which the circuit leaves out and MixColumns passes unchanged.
fn bitslice_keys<P: Plane>(words: &[u32], keys: &mut [[P; 8]]) {
    let last = keys.len() - 1;

    for (r, (key, words)) in keys.iter_mut().zip(words.as_chunks::<4>().0).enumerate() {
        let mut block = [0; 16];

        for (bytes, word) in block.as_chunks_mut::<4>().0.iter_mut().zip(words) {
            *bytes = word.to_le_bytes();
        }

        let turns = if r < last { (4 - r % 4) % 4 } else { 0 };

        let mut blocks = [shift_rows_bytes(&block, turns); 4];

        let mut q = [P::default(); 8];

        P::spread(&blocks, &mut q);

        ortho(&mut q);

        if r > 0 {
            for b in [0, 1, 5, 6] {
                q[b] = !q[b];
            }
        }

        *key = q;

        wipe(&mut q);

        wipe(&mut blocks);

        wipe(&mut block);
    }
}

// ShiftRows applied n times to a block in FIPS 197 order, byte 4c + r in row r, column c.
fn shift_rows_bytes(block: &[u8; 16], n: usize) -> [u8; 16] {
    core::array::from_fn(|i| block[4 * ((i / 4 + n * (i % 4)) % 4) + i % 4])
}

fn words_of(block: &[u8; 16]) -> [u32; 4] {
    core::array::from_fn(|i| u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap()))
}

// The key expansion of FIPS 197, 5.2, on little-endian words, in which RotWord is a rotation right
// by eight bits and Rcon sits in the low byte.
fn expand(key: &[u8], w: &mut [u32]) {
    let nk = key.len() / 4;

    for (i, word) in key.as_chunks::<4>().0.iter().enumerate() {
        w[i] = u32::from_le_bytes(*word);
    }

    let mut rcon = 1u32;

    for i in nk..w.len() {
        let mut t = w[i - 1];

        if i % nk == 0 {
            t = sub_word(t.rotate_right(8)) ^ rcon;

            rcon = (rcon << 1) ^ (0x11B & (rcon >> 7).wrapping_neg());
        } else if nk > 6 && i % nk == 4 {
            t = sub_word(t);
        }

        w[i] = w[i - nk] ^ t;
    }
}

// SubWord: the S-box on each byte of the word.
fn sub_word(x: u32) -> u32 {
    let mut blocks = [[0; 16]; 4];

    blocks[0][..4].copy_from_slice(&x.to_le_bytes());

    let mut q: [Native; 8] = [0; 8];

    Native::spread(&blocks, &mut q);

    ortho(&mut q);

    sbox(&mut q);

    ortho(&mut q);

    Native::gather(&q, &mut blocks);

    let out = u32::from_le_bytes(blocks[0][..4].try_into().unwrap()) ^ 0x6363_6363;

    wipe(&mut q);

    wipe(&mut blocks);

    out
}

// Spreads the four little-endian words of a block over two words, the order ortho expects: byte k
// of word i lands in byte 2k of x[i].
fn interleave_in(w: &[u32; 4]) -> (u64, u64) {
    let x: [u64; 4] = core::array::from_fn(|i| {
        let v = u64::from(w[i]);

        let v = (v | (v << 16)) & 0x0000_FFFF_0000_FFFF;

        (v | (v << 8)) & 0x00FF_00FF_00FF_00FF
    });

    (x[0] | (x[2] << 8), x[1] | (x[3] << 8))
}

fn interleave_out(q0: u64, q1: u64) -> [u32; 4] {
    let x = [
        q0 & 0x00FF_00FF_00FF_00FF,
        q1 & 0x00FF_00FF_00FF_00FF,
        (q0 >> 8) & 0x00FF_00FF_00FF_00FF,
        (q1 >> 8) & 0x00FF_00FF_00FF_00FF,
    ];

    x.map(|v| {
        let v = (v | (v >> 8)) & 0x0000_FFFF_0000_FFFF;

        v as u32 | (v >> 16) as u32
    })
}

// Swaps the bits of q[x] selected by low << shift with those of q[y] selected by low.
#[inline(always)]
fn swap<P: Plane>(q: &mut [P; 8], x: usize, y: usize, low: P, shift: u32) {
    let t = ((q[x] >> shift) ^ q[y]) & low;

    q[y] ^= t;

    q[x] ^= t << shift;
}

// Converts between the spread blocks and the bit planes; the transform is its own inverse.
#[inline(always)]
fn ortho<P: Plane>(q: &mut [P; 8]) {
    for i in [0, 2, 4, 6] {
        swap(q, i, i + 1, P::bytes(0x55), 1);
    }

    for i in [0, 1, 4, 5] {
        swap(q, i, i + 2, P::bytes(0x33), 2);
    }

    for i in 0..4 {
        swap(q, i, i + 4, P::bytes(0x0F), 4);
    }
}

fn add_round_key<P: Plane>(q: &mut [P; 8], key: &[P; 8]) {
    for (x, k) in q.iter_mut().zip(key) {
        *x ^= *k;
    }
}

// A round but the last, its ShiftRows left out: K of them so far, mod 4.
#[inline(always)]
fn round<P: Plane, const K: u32>(q: &mut [P; 8], key: &[P; 8]) {
    sbox(q);

    mix_columns::<P, K>(q);

    add_round_key(q, key);
}

// Row r of a plane.
fn row<P: Plane>(r: u32) -> P {
    (!P::default() >> (3 * P::ROW)) << (P::ROW * r)
}

// ShiftRows twice: rows 1 and 3 turn by two columns, half a row, and rows 0 and 2 stay.
fn shift_rows_2<P: Plane>(q: &mut [P; 8]) {
    let half = P::ROW / 2;

    let (stay, turn) = (row::<P>(0) | row(2), row::<P>(1) | row(3));

    let low = P::rows((1 << half) - 1);

    for x in q.iter_mut() {
        let v = *x;

        *x = (v & stay) | ((v >> half) & turn & low) | ((v << half) & turn & !low);
    }
}

// MixColumns in representation K, where byte (r, c) of the state of FIPS 197 sits in column
// c + K r (mod 4) of row r: output row r, column c takes row r + i from column c + K i.
#[inline(always)]
fn mix_columns<P: Plane, const K: u32>(q: &mut [P; 8]) {
    let r: [P; 8] = core::array::from_fn(|i| turn::<P, K, 1>(q[i]));

    let [q0, q1, q2, q3, q4, q5, q6, q7] = *q;

    let rot = turn::<P, K, 2>;

    q[0] = q7 ^ r[7] ^ r[0] ^ rot(q0 ^ r[0]);

    q[1] = q0 ^ r[0] ^ q7 ^ r[7] ^ r[1] ^ rot(q1 ^ r[1]);

    q[2] = q1 ^ r[1] ^ r[2] ^ rot(q2 ^ r[2]);

    q[3] = q2 ^ r[2] ^ q7 ^ r[7] ^ r[3] ^ rot(q3 ^ r[3]);

    q[4] = q3 ^ r[3] ^ q7 ^ r[7] ^ r[4] ^ rot(q4 ^ r[4]);

    q[5] = q4 ^ r[4] ^ r[5] ^ rot(q5 ^ r[5]);

    q[6] = q5 ^ r[5] ^ r[6] ^ rot(q6 ^ r[6]);

    q[7] = q6 ^ r[6] ^ r[7] ^ rot(q7 ^ r[7]);
}

// Row r of the result takes row r + I of x from column c + K I (mod 4): the rows turn and, unless
// K I is a multiple of 4, the columns within each row.
#[inline(always)]
fn turn<P: Plane, const K: u32, const I: u32>(x: P) -> P {
    let m = P::BLOCKS as u32 * (K * I % 4);

    if m == 0 {
        return x.rotate(P::ROW * I);
    }

    let low = P::rows((1 << (P::ROW - m)) - 1);

    (x.rotate(P::ROW * I + m) & low) | (x.rotate(P::ROW * I + m - P::ROW) & !low)
}

// The S-box on the eight bit planes, q[0] the least significant bit, but for its constant 0x63:
// the circuit of Boyar and Peralta, 32 AND and 83 XOR gates, which numbers the bits from the most
// significant one, x0 = q[7], with XORs in place of its four XNORs. The round keys after the
// first carry the constant instead, and SubWord adds it itself.
#[inline(always)]
fn sbox<P: Plane>(q: &mut [P; 8]) {
    let (x0, x1, x2, x3, x4, x5, x6, x7) = (q[7], q[6], q[5], q[4], q[3], q[2], q[1], q[0]);

    let y14 = x3 ^ x5;

    let y13 = x0 ^ x6;

    let y9 = x0 ^ x3;

    let y8 = x0 ^ x5;

    let t0 = x1 ^ x2;

    let y1 = t0 ^ x7;

    let y4 = y1 ^ x3;

    let y12 = y13 ^ y14;

    let y2 = y1 ^ x0;

    let y5 = y1 ^ x6;

    let y3 = y5 ^ y8;

    let t1 = x4 ^ y12;

    let y15 = t1 ^ x5;

    let y20 = t1 ^ x1;

    let y6 = y15 ^ x7;

    let y10 = y15 ^ t0;

    let y11 = y20 ^ y9;

    let y7 = x7 ^ y11;

    let y17 = y10 ^ y11;

    let y19 = y10 ^ y8;

    let y16 = t0 ^ y11;

    let y21 = y13 ^ y16;

    let y18 = x0 ^ y16;

    let t2 = y12 & y15;

    let t3 = y3 & y6;

    let t4 = t3 ^ t2;

    let t5 = y4 & x7;

    let t6 = t5 ^ t2;

    let t7 = y13 & y16;

    let t8 = y5 & y1;

    let t9 = t8 ^ t7;

    let t10 = y2 & y7;

    let t11 = t10 ^ t7;

    let t12 = y9 & y11;

    let t13 = y14 & y17;

    let t14 = t13 ^ t12;

    let t15 = y8 & y10;

    let t16 = t15 ^ t12;

    let t17 = t4 ^ t14;

    let t18 = t6 ^ t16;

    let t19 = t9 ^ t14;

    let t20 = t11 ^ t16;

    let t21 = t17 ^ y20;

    let t22 = t18 ^ y19;

    let t23 = t19 ^ y21;

    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;

    let t26 = t21 & t23;

    let t27 = t24 ^ t26;

    let t28 = t25 & t27;

    let t29 = t28 ^ t22;

    let t30 = t23 ^ t24;

    let t31 = t22 ^ t26;

    let t32 = t31 & t30;

    let t33 = t32 ^ t24;

    let t34 = t23 ^ t33;

    let t35 = t27 ^ t33;

    let t36 = t24 & t35;

    let t37 = t36 ^ t34;

    let t38 = t27 ^ t36;

    let t39 = t29 & t38;

    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;

    let t42 = t29 ^ t33;

    let t43 = t29 ^ t40;

    let t44 = t33 ^ t37;

    let t45 = t42 ^ t41;

    let z0 = t44 & y15;

    let z1 = t37 & y6;

    let z2 = t33 & x7;

    let z3 = t43 & y16;

    let z4 = t40 & y1;

    let z5 = t29 & y7;

    let z6 = t42 & y11;

    let z7 = t45 & y17;

    let z8 = t41 & y10;

    let z9 = t44 & y12;

    let z10 = t37 & y3;

    let z11 = t33 & y4;

    let z12 = t43 & y13;

    let z13 = t40 & y5;

    let z14 = t29 & y2;

    let z15 = t42 & y9;

    let z16 = t45 & y14;

    let z17 = t41 & y8;

    let t46 = z15 ^ z16;

    let t47 = z10 ^ z11;

    let t48 = z5 ^ z13;

    let t49 = z9 ^ z10;

    let t50 = z2 ^ z12;

    let t51 = z2 ^ z5;

    let t52 = z7 ^ z8;

    let t53 = z0 ^ z3;

    let t54 = z6 ^ z7;

    let t55 = z16 ^ z17;

    let t56 = z12 ^ t48;

    let t57 = t50 ^ t53;

    let t58 = z4 ^ t46;

    let t59 = z3 ^ t54;

    let t60 = t46 ^ t57;

    let t61 = z14 ^ t57;

    let t62 = t52 ^ t58;

    let t63 = t49 ^ t58;

    let t64 = z4 ^ t59;

    let t65 = t61 ^ t62;

    let t66 = z1 ^ t63;

    let t67 = t64 ^ t65;

    let s3 = t53 ^ t66;

    q[7] = t59 ^ t63;

    q[6] = t64 ^ s3;

    q[5] = t55 ^ t67;

    q[4] = s3;

    q[3] = t51 ^ t66;

    q[2] = t47 ^ t65;

    q[1] = t56 ^ t62;

    q[0] = t48 ^ t60;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(text: &str) -> alloc::vec::Vec<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn unhex<const N: usize>(text: &str) -> [u8; N] {
        bytes(text).try_into().unwrap()
    }

    // FIPS 197, Appendix C.1 and C.3.
    #[test]
    fn fips197() {
        let plaintext: [u8; 16] = unhex("00112233445566778899aabbccddeeff");

        for (key, expected) in [
            (
                "000102030405060708090a0b0c0d0e0f",
                "69c4e0d86a7b0430d8cdb78070b4c55a",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "8ea2b7ca516745bfeafc49904b496089",
            ),
        ] {
            let key = bytes(key);

            let expected: [u8; 16] = unhex(expected);

            let mut block = plaintext;

            Aes::new(&key).encrypt_block(&mut block);

            assert_eq!(block, expected);

            for aes in [Aes::new(&key), Aes::portable(&key)] {
                let mut blocks = [plaintext; 7];

                aes.encrypt_blocks(&mut blocks);

                assert!(blocks.iter().all(|b| *b == expected));
            }
        }
    }

    // The AESAVS known answers for ECB (KAT_AES.zip): GFSbox, KeySbox, VarKey and VarTxt for both
    // key sizes. Every record of the ENCRYPT and the DECRYPT sections is a key, a plaintext and
    // its ciphertext, checked through the AES instructions and through the portable code, with
    // planes of both types.
    #[test]
    fn aesavs() {
        let mut checked = 0;

        for kind in ["GFSbox", "KeySbox", "VarKey", "VarTxt"] {
            for bits in [128, 256] {
                let path = std::format!(
                    "{}/../vectors/cavp/ECB{kind}{bits}.rsp",
                    env!("CARGO_MANIFEST_DIR")
                );

                let text = std::fs::read_to_string(&path).unwrap();

                let (mut key, mut plaintext) = (alloc::vec::Vec::new(), alloc::vec::Vec::new());

                let mut ciphertext = alloc::vec::Vec::new();

                for line in text.lines().map(str::trim) {
                    let Some((name, value)) = line.split_once(" = ") else {
                        continue;
                    };

                    match name {
                        "KEY" => key = bytes(value),
                        "PLAINTEXT" => plaintext = bytes(value),
                        "CIPHERTEXT" => ciphertext = bytes(value),
                        _ => continue,
                    }

                    if key.len() * 8 == bits && plaintext.len() == 16 && ciphertext.len() == 16 {
                        for aes in [Aes::new(&key), Aes::portable(&key)] {
                            let mut block: [u8; 16] = plaintext[..].try_into().unwrap();

                            aes.encrypt_block(&mut block);

                            assert_eq!(block[..], ciphertext[..], "{path}");
                        }

                        for encrypt in [
                            encrypt_with::<u32> as fn(&[u8], &mut [u8; 16]),
                            encrypt_with::<u64>,
                        ] {
                            let mut block: [u8; 16] = plaintext[..].try_into().unwrap();

                            encrypt(&key, &mut block);

                            assert_eq!(block[..], ciphertext[..], "{path}");
                        }

                        checked += 1;

                        (plaintext, ciphertext) = (alloc::vec::Vec::new(), alloc::vec::Vec::new());
                    }
                }
            }
        }

        // 568 records for AES-128 and 810 for AES-256.
        assert_eq!(checked, 1378);
    }

    // The AES instructions against the portable code, on random keys and blocks, and the round
    // keys of both expansions.
    #[test]
    fn aes_kernel_matches_portable() {
        let mut inputs = crate::cpu::testing::Inputs::new(0xAE5);

        std::eprintln!(
            "AES instructions: {}",
            Aes::new(&[0; 16]).hardware_keys().is_some()
        );

        for n in 0..2_000 {
            let key: [u8; 32] = inputs.bytes();

            let key = &key[..if n % 2 == 0 { 16 } else { 32 }];

            let (fast, portable) = (Aes::new(key), Aes::portable(key));

            let mut blocks: [[u8; 16]; 9] = core::array::from_fn(|_| inputs.bytes());

            let mut expected = blocks;

            fast.encrypt_blocks(&mut blocks[..n % 10]);

            portable.encrypt_blocks(&mut expected[..n % 10]);

            assert_eq!(blocks, expected, "case {n}");

            if let Some(keys) = fast.hardware_keys() {
                let mut words = [0u32; 60];

                expand(key, &mut words[..keys.len() * 4]);

                for (r, round) in keys.iter().enumerate() {
                    assert_eq!(*round, words_of_bytes(&words[4 * r..4 * r + 4]), "case {n}");
                }
            }
        }
    }

    // The two plane types on random keys and four different blocks.
    #[test]
    fn planes_agree() {
        let mut inputs = crate::cpu::testing::Inputs::new(0xAE6);

        for n in 0..500 {
            let key: [u8; 32] = inputs.bytes();

            let key = &key[..if n % 2 == 0 { 16 } else { 32 }];

            let blocks: [[u8; 16]; 4] = core::array::from_fn(|_| inputs.bytes());

            let (mut wide, mut narrow) = (blocks, blocks);

            encrypt_group(&keys_for::<u64>(key), &mut wide);

            let keys = keys_for::<u32>(key);

            for pair in narrow.as_chunks_mut::<2>().0 {
                encrypt_group(&keys, pair);
            }

            assert_eq!(wide, narrow, "case {n}");
        }
    }

    // The bitsliced round keys of key in planes of type P, whichever type the target uses.
    fn keys_for<P: Plane>(key: &[u8]) -> alloc::vec::Vec<[P; 8]> {
        let rounds = if key.len() == 16 { 10 } else { 14 };

        let mut words = [0u32; 60];

        expand(key, &mut words[..4 * (rounds + 1)]);

        let mut keys = alloc::vec![[P::default(); 8]; rounds + 1];

        bitslice_keys(&words[..4 * (rounds + 1)], &mut keys);

        keys
    }

    // The block through the portable rounds in planes of type P, in every block of a group.
    fn encrypt_with<P: Plane>(key: &[u8], block: &mut [u8; 16]) {
        let mut group = [*block; 4];

        encrypt_group(&keys_for::<P>(key), &mut group);

        assert!(group[..P::BLOCKS].iter().all(|b| b == &group[0]));

        *block = group[0];
    }

    fn words_of_bytes(words: &[u32]) -> [u8; 16] {
        core::array::from_fn(|i| words[i / 4].to_le_bytes()[i % 4])
    }
}

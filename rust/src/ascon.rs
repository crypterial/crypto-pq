// Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 (NIST SP 800-232): the Ascon-p[12] permutation on
// a state of five 64-bit words, absorbing and squeezing eight bytes at a time, little-endian
// (Appendix A). The start states are the states after the first permutation of each IV (A.3).

use crate::cpu;
#[cfg(not(target_arch = "x86"))]
use crate::sha2::last_bytes;
use crate::wipe::wipe;

pub(crate) const HASH256: [u64; 5] = held([
    0x9B1E5494E934D681,
    0x4BC3A01E333751D2,
    0xAE65396C6B34B81A,
    0x3C7FD4A4D56A4DB3,
    0x1A5C464906C5976D,
]);

pub(crate) const XOF128: [u64; 5] = held([
    0xDA82CE768D9447EB,
    0xCC7CE6C75F1EF969,
    0xE7508FD780085631,
    0x0EE0EA53416B58CC,
    0xE0547524DB6F0BDE,
]);

const CXOF128: [u64; 5] = held([
    0x675527C2A0E8DE03,
    0x43D12D7DC0377BBC,
    0xE9901DEC426E81B5,
    0x2AB14907720780B6,
    0x8F3F1D02D432BC46,
]);

// SP 800-232, 5.3: the customization string is at most 2048 bits.
pub(crate) const MAX_CUSTOMIZATION: usize = 256;

// The constants of rounds 0 to 11 of Ascon-p[12] (Table 5).
const CONSTANTS: [u64; 12] = [
    0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B,
];

// On 32-bit Arm the state holds each word bit-interleaved: its even bits in the low half and its
// odd bits in the high half, bit j of a half being bit 2j or 2j + 1 of the word. A rotation of the
// word is then one 32-bit rotation of each half, the halves swapped for an odd amount, which Arm
// takes as the rotated operand of an EOR, where the 64-bit rotation took two shifts and an ORR a
// half. Elsewhere the state holds the words whole: on 32-bit x86 the interleaved words took more
// instructions, and the other 32-bit targets, on which they were not counted, keep the form of the
// 64-bit ones. Words enter the state through to_lane and leave it through from_lane, so that a
// permutation converts none; both are the identity where the state holds the words whole.
#[cfg(not(target_arch = "arm"))]
#[inline(always)]
const fn to_lane(word: u64) -> u64 {
    word
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
const fn from_lane(word: u64) -> u64 {
    word
}

#[cfg(target_arch = "arm")]
#[inline(always)]
const fn to_lane(word: u64) -> u64 {
    let low = unzip(word as u32);

    let high = unzip((word >> 32) as u32);

    ((low & 0xffff) | (high << 16)) as u64 | (((low >> 16) | (high & 0xffff_0000)) as u64) << 32
}

#[cfg(target_arch = "arm")]
#[inline(always)]
const fn from_lane(word: u64) -> u64 {
    let (even, odd) = (word as u32, (word >> 32) as u32);

    let low = zip((even & 0xffff) | (odd << 16));

    let high = zip((even >> 16) | (odd & 0xffff_0000));

    low as u64 | (high as u64) << 32
}

// The even bits of x in its low half, in order, and its odd bits in its high half: four exchanges
// of bit groups, each of the bits of x at the masked positions with the bits a distance above, as
// in Keccak's interleaved lanes.
#[cfg(target_arch = "arm")]
#[inline(always)]
const fn unzip(mut x: u32) -> u32 {
    let mut t = (x ^ (x >> 1)) & 0x2222_2222;

    x ^= t ^ (t << 1);

    t = (x ^ (x >> 2)) & 0x0c0c_0c0c;

    x ^= t ^ (t << 2);

    t = (x ^ (x >> 4)) & 0x00f0_00f0;

    x ^= t ^ (t << 4);

    t = (x ^ (x >> 8)) & 0x0000_ff00;

    x ^ t ^ (t << 8)
}

// The inverse of unzip: the same exchanges in the opposite order, as each is its own inverse.
#[cfg(target_arch = "arm")]
#[inline(always)]
const fn zip(mut x: u32) -> u32 {
    let mut t = (x ^ (x >> 8)) & 0x0000_ff00;

    x ^= t ^ (t << 8);

    t = (x ^ (x >> 4)) & 0x00f0_00f0;

    x ^= t ^ (t << 4);

    t = (x ^ (x >> 2)) & 0x0c0c_0c0c;

    x ^= t ^ (t << 2);

    t = (x ^ (x >> 1)) & 0x2222_2222;

    x ^ t ^ (t << 1)
}

// A state given word by word, as the state holds it.
const fn held(words: [u64; 5]) -> [u64; 5] {
    let mut s = [0; 5];

    let mut i = 0;

    while i < 5 {
        s[i] = to_lane(words[i]);

        i += 1;
    }

    s
}

// The S-box layer: the circuit of Zhang and Huang, ePrint 2023/1721, checked against the S-box
// table on all 32 inputs in every bit position by sbox_matches_table.
#[inline(always)]
const fn sbox(s: &mut [u64; 5]) {
    let [x0, x1, x2, x3, x4] = *s;

    let t0 = x0 ^ x4;

    let t3 = x1 ^ x2;

    let t5 = x3 ^ x4;

    let t8 = (x3 ^ x2) | t3;

    let t12 = (t0 | x1) ^ t5;

    *s = [
        t12 ^ (x2 & t3),
        t0 ^ t8,
        t3 ^ (!x4 | x3),
        t3 ^ (x0 | t5),
        t0 ^ t12,
    ];
}

// The linear layer, each x ^ ror(x, a) ^ ror(x, b) as x ^ ror(x ^ ror(x, b - a), a): AArch64 then
// folds both rotations into the EORs as rotated operands, and so does V8 on ARM64 for WebAssembly.
// Written with both rotations of x, the compiler XORs the two rotations together first, and V8
// computes one of them apart: one instruction more per word.
#[cfg(not(any(target_arch = "arm", target_arch = "x86")))]
#[inline(always)]
const fn linear(s: &mut [u64; 5]) {
    let [x0, x1, x2, x3, x4] = *s;

    *s = [
        x0 ^ (x0 ^ x0.rotate_right(9)).rotate_right(19),
        x1 ^ (x1 ^ x1.rotate_right(22)).rotate_right(39),
        x2 ^ (x2 ^ x2.rotate_right(5)).rotate_right(1),
        x3 ^ (x3 ^ x3.rotate_right(7)).rotate_right(10),
        x4 ^ (x4 ^ x4.rotate_right(34)).rotate_right(7),
    ];
}

// The linear layer on 32-bit x86 as the specification writes it: both rotations of x side by side,
// one step less in each round's chain of dependent instructions.
#[cfg(target_arch = "x86")]
#[inline(always)]
const fn linear(s: &mut [u64; 5]) {
    let [x0, x1, x2, x3, x4] = *s;

    *s = [
        x0 ^ x0.rotate_right(19) ^ x0.rotate_right(28),
        x1 ^ x1.rotate_right(61) ^ x1.rotate_right(39),
        x2 ^ x2.rotate_right(1) ^ x2.rotate_right(6),
        x3 ^ x3.rotate_right(10) ^ x3.rotate_right(17),
        x4 ^ x4.rotate_right(7) ^ x4.rotate_right(41),
    ];
}

// The linear layer on interleaved words: each x ^ ror(x, a) ^ ror(x, b) a half at a time, every
// rotation of a half the rotated operand of an EOR on 32-bit Arm.
#[cfg(target_arch = "arm")]
#[inline(always)]
const fn linear(s: &mut [u64; 5]) {
    *s = [
        diffuse(s[0], 19, 28),
        diffuse(s[1], 61, 39),
        diffuse(s[2], 1, 6),
        diffuse(s[3], 10, 17),
        diffuse(s[4], 7, 41),
    ];
}

#[cfg(target_arch = "arm")]
#[inline(always)]
const fn diffuse(x: u64, a: u32, b: u32) -> u64 {
    let (even, odd) = (x as u32, (x >> 32) as u32);

    let (even_a, odd_a) = rotate(even, odd, a);

    let (even_b, odd_b) = rotate(even, odd, b);

    (even ^ even_a ^ even_b) as u64 | ((odd ^ odd_a ^ odd_b) as u64) << 32
}

// The halves of an interleaved word rotated right by r.
#[cfg(target_arch = "arm")]
#[inline(always)]
const fn rotate(even: u32, odd: u32, r: u32) -> (u32, u32) {
    if r.is_multiple_of(2) {
        (even.rotate_right(r / 2), odd.rotate_right(r / 2))
    } else {
        (odd.rotate_right(r / 2), even.rotate_right(r / 2 + 1))
    }
}

#[inline(always)]
const fn round(s: &mut [u64; 5], constant: u64) {
    s[2] ^= to_lane(constant);

    sbox(s);

    linear(s);
}

// Ascon-p[12] for the start states that constants need at compile time.
const fn permute_const(s: &mut [u64; 5]) {
    let mut i = 0;

    while i < 12 {
        round(s, CONSTANTS[i]);

        i += 1;
    }
}

// The rounds written out, so that each constant is an immediate: as a loop over the table, the
// compiler kept it a loop.
#[inline(always)]
fn rounds(s: &mut [u64; 5]) {
    round(s, CONSTANTS[0]);

    round(s, CONSTANTS[1]);

    round(s, CONSTANTS[2]);

    round(s, CONSTANTS[3]);

    round(s, CONSTANTS[4]);

    round(s, CONSTANTS[5]);

    round(s, CONSTANTS[6]);

    round(s, CONSTANTS[7]);

    round(s, CONSTANTS[8]);

    round(s, CONSTANTS[9]);

    round(s, CONSTANTS[10]);

    round(s, CONSTANTS[11]);
}

pub(crate) fn permute(s: &mut [u64; 5]) {
    if cpu::ascon(s) {
        return;
    }

    rounds(s);
}

// The output for data from a start state, read once. cpu::ascon_digest declines exactly where
// cpu::ascon does, so the portable rounds run here with the state in registers: the blocks and
// the padded last block through one permutation, then the output words through another.
#[cfg(not(target_arch = "x86"))]
pub(crate) fn digest(start: &[u64; 5], data: &[u8], out: &mut [u8]) {
    if cpu::ascon_digest(start, data, out) {
        return;
    }

    let mut s = *start;

    let (blocks, tail) = data.as_chunks::<8>();

    let last = last_bytes(data, tail.len()) as u64 ^ 1 << (8 * tail.len());

    let words = blocks.iter().map(|block| u64::from_le_bytes(*block));

    for word in words.chain([last]) {
        s[0] ^= to_lane(word);

        rounds(&mut s);
    }

    for (i, chunk) in out.chunks_mut(8).enumerate() {
        if i > 0 {
            rounds(&mut s);
        }

        let bytes = from_lane(s[0]).to_le_bytes();

        match <&mut [u8; 8]>::try_from(&mut *chunk) {
            Ok(word) => *word = bytes,
            Err(_) => chunk.copy_from_slice(&bytes[..chunk.len()]),
        }
    }

    wipe(&mut s);
}

// The same digest on 32-bit x86, where this form took fewer instructions: whole output words are
// stored as they are and the bytes after the last whole word apart, in place of a test of the
// length of each chunk. On WebAssembly it took fewer instructions too, but Cranelift then compiled
// the loop over the blocks into code that took more time on AMD Zen cores.
#[cfg(target_arch = "x86")]
pub(crate) fn digest(start: &[u64; 5], data: &[u8], out: &mut [u8]) {
    if cpu::ascon_digest(start, data, out) {
        return;
    }

    let mut s = *start;

    let (blocks, tail) = data.as_chunks::<8>();

    let last = last_word(data, tail.len()) ^ 1 << (8 * tail.len());

    let words = blocks.iter().map(|block| u64::from_le_bytes(*block));

    for word in words.chain([last]) {
        s[0] ^= to_lane(word);

        rounds(&mut s);
    }

    let (words, tail) = out.as_chunks_mut::<8>();

    for (i, word) in words.iter_mut().enumerate() {
        if i > 0 {
            rounds(&mut s);
        }

        *word = from_lane(s[0]).to_le_bytes();
    }

    if !tail.is_empty() {
        if !words.is_empty() {
            rounds(&mut s);
        }

        tail.copy_from_slice(&from_lane(s[0]).to_le_bytes()[..tail.len()]);
    }

    wipe(&mut s);
}

// The last count bytes of data, count below 8, as a little-endian word, from the eight bytes at
// the end where there are as many: sha2::last_bytes shifts a 128-bit value, four words here, and
// reads a window only from 16 bytes of data.
#[cfg(target_arch = "x86")]
fn last_word(data: &[u8], count: usize) -> u64 {
    if count == 0 {
        return 0;
    }

    if let Some(window) = data.last_chunk::<8>() {
        return u64::from_le_bytes(*window) >> (8 * (8 - count));
    }

    data[data.len() - count..]
        .iter()
        .rev()
        .fold(0, |word, &byte| word << 8 | u64::from(byte))
}

// Ascon-CXOF128's state after the customization string z, at most MAX_CUSTOMIZATION bytes: its
// length in bits as the first block, then z padded. One body for the run-time state, through
// permute or the rounds inline, and for the constant, through permute_const.
macro_rules! customize {
    ($z:expr, $permute:ident) => {{
        let z: &[u8] = $z;

        let mut s = CXOF128;

        s[0] ^= to_lane(8 * z.len() as u64);

        $permute(&mut s);

        let (blocks, tail) = z.as_chunks::<8>();

        let mut i = 0;

        while i < blocks.len() {
            s[0] ^= to_lane(u64::from_le_bytes(blocks[i]));

            $permute(&mut s);

            i += 1;
        }

        let mut last = 1 << (8 * tail.len());

        let mut i = 0;

        while i < tail.len() {
            last ^= (tail[i] as u64) << (8 * i);

            i += 1;
        }

        s[0] ^= to_lane(last);

        $permute(&mut s);

        s
    }};
}

// On WebAssembly and 32-bit x86, where no CPU kernel takes the permutation, with the rounds
// inline: a call of permute per block loaded and stored the state each time.
pub(crate) fn customize(z: &[u8]) -> [u64; 5] {
    #[cfg(any(target_family = "wasm", target_arch = "x86"))]
    return customize!(z, rounds);

    #[cfg(not(any(target_family = "wasm", target_arch = "x86")))]
    customize!(z, permute)
}

const fn customize_const(z: &[u8]) -> [u64; 5] {
    customize!(z, permute_const)
}

// Ascon-CXOF128's state for the empty customization string.
pub(crate) const CXOF128_EMPTY: [u64; 5] = customize_const(&[]);

// An incremental sponge: `pending` holds the input bytes of a partial block until it fills, and
// once squeezing, `available` counts the bytes of the current output word not yet read.
#[derive(Clone)]
pub(crate) struct Sponge {
    s: [u64; 5],
    pending: [u8; 8],
    filled: usize,
    squeezing: bool,
    available: usize,
}

impl Sponge {
    pub(crate) const fn new(start: &[u64; 5]) -> Self {
        Self {
            s: *start,
            pending: [0; 8],
            filled: 0,
            squeezing: false,
            available: 0,
        }
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        assert!(!self.squeezing, "UNSUPPORTED: cannot update after read");

        if self.filled > 0 {
            let take = (8 - self.filled).min(data.len());

            self.pending[self.filled..self.filled + take].copy_from_slice(&data[..take]);

            self.filled += take;

            data = &data[take..];

            if self.filled < 8 {
                return;
            }

            self.s[0] ^= to_lane(u64::from_le_bytes(self.pending));

            permute(&mut self.s);

            self.filled = 0;
        }

        let (blocks, tail) = data.as_chunks::<8>();

        for block in blocks {
            self.s[0] ^= to_lane(u64::from_le_bytes(*block));

            permute(&mut self.s);
        }

        self.pending[..tail.len()].copy_from_slice(tail);

        self.filled = tail.len();
    }

    fn finish(&mut self) {
        let mut last = self.pending;

        last[self.filled..].fill(0);

        last[self.filled] = 0x01;

        self.s[0] ^= to_lane(u64::from_le_bytes(last));

        permute(&mut self.s);

        wipe(&mut last);

        self.squeezing = true;

        self.available = 8;
    }

    pub(crate) fn read(&mut self, mut out: &mut [u8]) {
        if !self.squeezing {
            self.finish();
        }

        while !out.is_empty() {
            if self.available == 0 {
                permute(&mut self.s);

                self.available = 8;
            }

            let take = self.available.min(out.len());

            let start = 8 - self.available;

            let (chunk, rest) = core::mem::take(&mut out).split_at_mut(take);

            chunk.copy_from_slice(&from_lane(self.s[0]).to_le_bytes()[start..start + take]);

            self.available -= take;

            out = rest;
        }
    }
}

impl Drop for Sponge {
    fn drop(&mut self) {
        wipe(&mut self.s);

        wipe(&mut self.pending);
    }
}

// The Ascon S-box as a table (SP 800-232), x0 the most significant bit of an input. Each of the
// 32 runs puts input (j + shift) % 32 into bit position j, so that every input meets every one of
// the 64 positions.
#[cfg(test)]
pub(crate) fn check_sbox(sbox: impl Fn(&mut [u64; 5])) {
    const TABLE: [u8; 32] = [
        0x04, 0x0B, 0x1F, 0x14, 0x1A, 0x15, 0x09, 0x02, 0x1B, 0x05, 0x08, 0x12, 0x1D, 0x03, 0x06,
        0x1C, 0x1E, 0x13, 0x07, 0x0E, 0x00, 0x0D, 0x11, 0x18, 0x10, 0x0C, 0x01, 0x19, 0x16, 0x0A,
        0x0F, 0x17,
    ];

    for shift in 0..32 {
        let input = |j: usize| (j + shift) % 32;

        let mut s = [0u64; 5];

        for j in 0..64 {
            for (i, word) in s.iter_mut().enumerate() {
                *word |= ((input(j) as u64 >> (4 - i)) & 1) << j;
            }
        }

        sbox(&mut s);

        for j in 0..64 {
            let output = (0..5).fold(0, |value, i| value << 1 | (s[i] >> j) & 1);

            assert_eq!(output, u64::from(TABLE[input(j)]), "shift {shift}, bit {j}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::testing::Inputs;

    // The round of crate version 1.0.1: the S-box of SP 800-232's Figure 3 and the linear layer as
    // written in the spec.
    fn classic_round(s: &mut [u64; 5], constant: u64) {
        let [mut x0, mut x1, mut x2, mut x3, mut x4] = *s;

        x2 ^= constant;

        x0 ^= x4;

        x4 ^= x3;

        x2 ^= x1;

        let t0 = !x0 & x1;

        let t1 = !x1 & x2;

        let t2 = !x2 & x3;

        let t3 = !x3 & x4;

        let t4 = !x4 & x0;

        x0 ^= t1;

        x1 ^= t2;

        x2 ^= t3;

        x3 ^= t4;

        x4 ^= t0;

        x1 ^= x0;

        x0 ^= x4;

        x3 ^= x2;

        x2 = !x2;

        *s = [
            x0 ^ x0.rotate_right(19) ^ x0.rotate_right(28),
            x1 ^ x1.rotate_right(61) ^ x1.rotate_right(39),
            x2 ^ x2.rotate_right(1) ^ x2.rotate_right(6),
            x3 ^ x3.rotate_right(10) ^ x3.rotate_right(17),
            x4 ^ x4.rotate_right(7) ^ x4.rotate_right(41),
        ];
    }

    fn classic_permute(s: &mut [u64; 5]) {
        for constant in CONSTANTS {
            classic_round(s, constant);
        }
    }

    // The customization of crate version 1.0.1, one byte of Z at a time.
    fn classic_customize(z: &[u8]) -> [u64; 5] {
        let mut s = CXOF128.map(from_lane);

        s[0] ^= 8 * z.len() as u64;

        classic_permute(&mut s);

        for (i, &byte) in z.iter().enumerate() {
            s[0] ^= u64::from(byte) << (8 * (i % 8));

            if (i + 1) % 8 == 0 {
                classic_permute(&mut s);
            }
        }

        s[0] ^= 1 << (8 * (z.len() % 8));

        classic_permute(&mut s);

        held(s)
    }

    #[test]
    fn sbox_matches_table() {
        check_sbox(sbox);
    }

    // The permutation alone, through whatever kernel the CPU selects and through the portable
    // rounds, against the round of 1.0.1, on edge and random states: no form of the state that a
    // kernel keeps inside the permutation reaches its caller.
    #[test]
    fn permutation_alone_matches_classic() {
        use crate::cpu::testing::EDGES;

        let mut inputs = Inputs::new(232);

        for n in 0..10_000 {
            let state: [u64; 5] = match EDGES.get(n / 4) {
                Some(&edge) => [edge; 5],
                None => inputs.words(),
            };

            let mut expected = state;

            classic_permute(&mut expected);

            let (state, expected) = (held(state), held(expected));

            let mut actual = state;

            permute(&mut actual);

            assert_eq!(actual, expected, "dispatched, case {n}");

            let mut actual = state;

            rounds(&mut actual);

            assert_eq!(actual, expected, "portable, case {n}");

            let mut actual = state;

            permute_const(&mut actual);

            assert_eq!(actual, expected, "const, case {n}");
        }
    }

    // The run-time customization against the constant's code and against 1.0.1's, for every
    // length of Z.
    #[test]
    fn customization_matches_const() {
        assert_eq!(customize(&[]), CXOF128_EMPTY);

        let z: [u8; MAX_CUSTOMIZATION] = Inputs::new(17).bytes();

        for length in 0..=MAX_CUSTOMIZATION {
            let z = &z[..length];

            let expected = classic_customize(z);

            assert_eq!(customize(z), expected, "length {length}");

            assert_eq!(customize_const(z), expected, "const, length {length}");
        }
    }

    // The start states are the first permutation of each IV (SP 800-232, Appendix A.3).
    #[test]
    fn start_states_follow_from_the_ivs() {
        for (iv, start) in [
            (0x0000_0801_00CC_0002, HASH256),
            (0x0000_0800_00CC_0003, XOF128),
            (0x0000_0800_00CC_0004, CXOF128),
        ] {
            let mut s = held([iv, 0, 0, 0, 0]);

            permute(&mut s);

            assert_eq!(s, start);

            let mut s = held([iv, 0, 0, 0, 0]);

            permute_const(&mut s);

            assert_eq!(s, start);
        }
    }

    // The kernels against the portable rounds, on edge and random states and data.
    #[test]
    fn ascon_kernel_matches_portable() {
        use crate::cpu::testing::EDGES;

        let mut inputs = Inputs::new(320);

        let mut accelerated = 0;

        for n in 0..10_000 {
            let state: [u64; 5] = match EDGES.get(n / 4) {
                Some(&edge) => [edge; 5],
                None => inputs.words(),
            };

            let mut expected = state;

            for constant in CONSTANTS {
                round(&mut expected, constant);
            }

            let mut actual = state;

            if cpu::ascon(&mut actual) {
                assert_eq!(actual, expected, "case {n}");

                accelerated += 1;
            }

            let data: [u8; 40] = inputs.bytes();

            let data = &data[..n % 41];

            let mut expected = [0; 41];

            let mut s = state;

            let (blocks, tail) = data.as_chunks::<8>();

            for block in blocks {
                s[0] ^= to_lane(u64::from_le_bytes(*block));

                permute_const(&mut s);
            }

            let mut last = [0; 8];

            last[..tail.len()].copy_from_slice(tail);

            last[tail.len()] = 1;

            s[0] ^= to_lane(u64::from_le_bytes(last));

            permute_const(&mut s);

            for (i, chunk) in expected[..n % 42].chunks_mut(8).enumerate() {
                if i > 0 {
                    permute_const(&mut s);
                }

                chunk.copy_from_slice(&from_lane(s[0]).to_le_bytes()[..chunk.len()]);
            }

            let mut actual = [0; 41];

            if cpu::ascon_digest(&state, data, &mut actual[..n % 42]) {
                assert_eq!(actual, expected, "digest, case {n}");
            }
        }

        std::eprintln!("Ascon: {accelerated} of 10000 cases through a CPU kernel");
    }

    // The one-shot output against the sponge fed and read in pieces, for lengths around the
    // block boundaries, and outputs of part of a word, of whole words and of both.
    #[test]
    fn digest_matches_sponge() {
        let data: [u8; 40] = Inputs::new(6).bytes();

        for length in 0..data.len() {
            for size in [1, 7, 8, 16, 45] {
                let mut expected = [0; 45];

                digest(&XOF128, &data[..length], &mut expected[..size]);

                for piece in [1, 3, 8, 9] {
                    let mut sponge = Sponge::new(&XOF128);

                    for chunk in data[..length].chunks(piece) {
                        sponge.update(chunk);
                    }

                    let mut actual = [0; 45];

                    for chunk in actual[..size].chunks_mut(piece + 2) {
                        sponge.read(chunk);
                    }

                    assert_eq!(
                        actual, expected,
                        "length {length}, size {size}, piece {piece}"
                    );
                }
            }
        }
    }
}

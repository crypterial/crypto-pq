// Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 (NIST SP 800-232): the Ascon-p[12] permutation on
// a state of five 64-bit words, absorbing and squeezing eight bytes at a time, little-endian
// (Appendix A). The start states are the states after the first permutation of each IV (A.3).

use crate::cpu;
use crate::sha2::last_bytes;
use crate::wipe::wipe;

pub(crate) const HASH256: [u64; 5] = [
    0x9B1E5494E934D681,
    0x4BC3A01E333751D2,
    0xAE65396C6B34B81A,
    0x3C7FD4A4D56A4DB3,
    0x1A5C464906C5976D,
];

pub(crate) const XOF128: [u64; 5] = [
    0xDA82CE768D9447EB,
    0xCC7CE6C75F1EF969,
    0xE7508FD780085631,
    0x0EE0EA53416B58CC,
    0xE0547524DB6F0BDE,
];

const CXOF128: [u64; 5] = [
    0x675527C2A0E8DE03,
    0x43D12D7DC0377BBC,
    0xE9901DEC426E81B5,
    0x2AB14907720780B6,
    0x8F3F1D02D432BC46,
];

// SP 800-232, 5.3: the customization string is at most 2048 bits.
pub(crate) const MAX_CUSTOMIZATION: usize = 256;

// The constants of rounds 0 to 11 of Ascon-p[12] (Table 5).
const CONSTANTS: [u64; 12] = [
    0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B,
];

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
// folds both rotations into the EORs as rotated operands.
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

#[inline(always)]
const fn round(s: &mut [u64; 5], constant: u64) {
    s[2] ^= constant;

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
pub(crate) fn digest(start: &[u64; 5], data: &[u8], out: &mut [u8]) {
    if cpu::ascon_digest(start, data, out) {
        return;
    }

    let mut s = *start;

    let (blocks, tail) = data.as_chunks::<8>();

    let last = last_bytes(data, tail.len()) as u64 ^ 1 << (8 * tail.len());

    let words = blocks.iter().map(|block| u64::from_le_bytes(*block));

    for word in words.chain([last]) {
        s[0] ^= word;

        rounds(&mut s);
    }

    for (i, chunk) in out.chunks_mut(8).enumerate() {
        if i > 0 {
            rounds(&mut s);
        }

        let bytes = s[0].to_le_bytes();

        match <&mut [u8; 8]>::try_from(&mut *chunk) {
            Ok(word) => *word = bytes,
            Err(_) => chunk.copy_from_slice(&bytes[..chunk.len()]),
        }
    }

    wipe(&mut s);
}

// Ascon-CXOF128's state after the customization string z, at most MAX_CUSTOMIZATION bytes: its
// length in bits as the first block, then z padded. One body for the run-time state, through the
// CPU kernels, and for the constant, through permute_const.
macro_rules! customize {
    ($z:expr, $permute:ident) => {{
        let z: &[u8] = $z;

        let mut s = CXOF128;

        s[0] ^= 8 * z.len() as u64;

        $permute(&mut s);

        let (blocks, tail) = z.as_chunks::<8>();

        let mut i = 0;

        while i < blocks.len() {
            s[0] ^= u64::from_le_bytes(blocks[i]);

            $permute(&mut s);

            i += 1;
        }

        let mut last = 1 << (8 * tail.len());

        let mut i = 0;

        while i < tail.len() {
            last ^= (tail[i] as u64) << (8 * i);

            i += 1;
        }

        s[0] ^= last;

        $permute(&mut s);

        s
    }};
}

pub(crate) fn customize(z: &[u8]) -> [u64; 5] {
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

            self.s[0] ^= u64::from_le_bytes(self.pending);

            permute(&mut self.s);

            self.filled = 0;
        }

        let (blocks, tail) = data.as_chunks::<8>();

        for block in blocks {
            self.s[0] ^= u64::from_le_bytes(*block);

            permute(&mut self.s);
        }

        self.pending[..tail.len()].copy_from_slice(tail);

        self.filled = tail.len();
    }

    fn finish(&mut self) {
        let mut last = self.pending;

        last[self.filled..].fill(0);

        last[self.filled] = 0x01;

        self.s[0] ^= u64::from_le_bytes(last);

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

            chunk.copy_from_slice(&self.s[0].to_le_bytes()[start..start + take]);

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
        let mut s = CXOF128;

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

        s
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
            let mut s = [iv, 0, 0, 0, 0];

            permute(&mut s);

            assert_eq!(s, start);

            let mut s = [iv, 0, 0, 0, 0];

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
                s[0] ^= u64::from_le_bytes(*block);

                permute_const(&mut s);
            }

            let mut last = [0; 8];

            last[..tail.len()].copy_from_slice(tail);

            last[tail.len()] = 1;

            s[0] ^= u64::from_le_bytes(last);

            permute_const(&mut s);

            for (i, chunk) in expected[..n % 42].chunks_mut(8).enumerate() {
                if i > 0 {
                    permute_const(&mut s);
                }

                chunk.copy_from_slice(&s[0].to_le_bytes()[..chunk.len()]);
            }

            let mut actual = [0; 41];

            if cpu::ascon_digest(&state, data, &mut actual[..n % 42]) {
                assert_eq!(actual, expected, "digest, case {n}");
            }
        }

        std::eprintln!("Ascon: {accelerated} of 10000 cases through a CPU kernel");
    }

    // The one-shot output against the sponge fed and read in pieces, for lengths around the
    // block boundaries.
    #[test]
    fn digest_matches_sponge() {
        let data: [u8; 40] = Inputs::new(6).bytes();

        for length in 0..data.len() {
            let mut expected = [0; 45];

            digest(&XOF128, &data[..length], &mut expected);

            for piece in [1, 3, 8, 9] {
                let mut sponge = Sponge::new(&XOF128);

                for chunk in data[..length].chunks(piece) {
                    sponge.update(chunk);
                }

                let mut actual = [0; 45];

                for chunk in actual.chunks_mut(piece + 2) {
                    sponge.read(chunk);
                }

                assert_eq!(actual, expected, "length {length}, piece {piece}");
            }
        }
    }
}

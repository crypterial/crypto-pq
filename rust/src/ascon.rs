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

// One round: the constant, the S-box layer as five bitsliced operations (Figure 3) and the linear
// layer.
#[inline(always)]
const fn round(s: &mut [u64; 5], constant: u64) {
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
pub(crate) fn permute(s: &mut [u64; 5]) {
    if cpu::ascon(s) {
        return;
    }

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

// The whole eight-byte blocks of data, then its last bytes with the padding byte 0x01 after them
// (an empty last block when data fills whole blocks), each followed by the permutation.
fn absorb(s: &mut [u64; 5], data: &[u8]) {
    let (blocks, tail) = data.as_chunks::<8>();

    for block in blocks {
        s[0] ^= u64::from_le_bytes(*block);

        permute(s);
    }

    s[0] ^= last_bytes(data, tail.len()) as u64 ^ 1 << (8 * tail.len());

    permute(s);
}

// out.len() bytes, eight from the first word of the state at a time, with a permutation between.
fn squeeze(s: &mut [u64; 5], out: &mut [u8]) {
    let mut chunks = out.chunks_mut(8).peekable();

    while let Some(chunk) = chunks.next() {
        chunk.copy_from_slice(&s[0].to_le_bytes()[..chunk.len()]);

        if chunks.peek().is_some() {
            permute(s);
        }
    }
}

// The output for data from a start state, read once.
pub(crate) fn digest(start: &[u64; 5], data: &[u8], out: &mut [u8]) {
    if cpu::ascon_digest(start, data, out) {
        return;
    }

    let mut s = *start;

    absorb(&mut s, data);

    squeeze(&mut s, out);

    wipe(&mut s);
}

// Ascon-CXOF128's state after the customization string z, at most MAX_CUSTOMIZATION bytes: its
// length in bits as the first block, then z padded.
pub(crate) const fn customize(z: &[u8]) -> [u64; 5] {
    let mut s = CXOF128;

    s[0] ^= 8 * z.len() as u64;

    permute_const(&mut s);

    let mut i = 0;

    while i < z.len() {
        s[0] ^= (z[i] as u64) << (8 * (i % 8));

        i += 1;

        if i % 8 == 0 {
            permute_const(&mut s);
        }
    }

    s[0] ^= 1 << (8 * (z.len() % 8));

    permute_const(&mut s);

    s
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::testing::Inputs;

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

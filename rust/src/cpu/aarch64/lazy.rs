// Keccak-f[1600] on one state in general registers, for Arm cores whose EOR and BIC take a rotated
// second operand at no cost (lazy rotation). Each lane is kept as a value whose left rotation by a
// known amount is the lane; the amounts depend only on the round, and every rotation of rho and of
// theta's parities folds into the operand of an EOR or a BIC, which leaves about 101 instructions
// a round instead of the portable code's 135. Every BLOCK rounds the lanes are rotated into place,
// so that the code of one block of rounds serves the whole permutation. The amounts are constants
// of the code, so the instructions, their order and their operands never depend on the data.

use crate::keccak::{ROTATIONS, ROUND_CONSTANTS};
use crate::sha2::last_bytes;
use crate::wipe::wipe;

pub(super) const BLOCK: usize = 8;

// Lane i before round r of a block is OFFSETS[r][i] bits to the right of its value. Theta keeps
// the amount of the lane that it reads, and chi that of its third input, the lane that BIC does
// not complement.
const OFFSETS: [[u32; 25]; BLOCK + 1] = offsets();

const fn offsets() -> [[u32; 25]; BLOCK + 1] {
    let mut table = [[0; 25]; BLOCK + 1];

    let mut r = 0;

    while r < BLOCK {
        let mut i = 0;

        while i < 25 {
            let (x, y) = ((i % 5 + 2) % 5, i / 5);

            let source = (x + 3 * y) % 5 + 5 * x;

            table[r + 1][i] = (table[r][source] + ROTATIONS[source]) % 64;

            i += 1;
        }

        r += 1;
    }

    table
}

// The rotation that brings a value kept at amount `from` to the base of one kept at amount `to`.
#[inline(always)]
const fn shift(from: u32, to: u32) -> u32 {
    (from + 64 - to) % 64
}

// Round R of a block. Lane x of plane y of the rho-pi output comes from lane (x + 3y) % 5 + 5x.
// Every index and amount is a constant block, so that each line is one instruction with an
// immediate rotation.
#[inline(always)]
pub(super) fn round<const R: usize>(v: &mut [u64; 25], constant: u64) {
    // A lane, kept at amount `from`, in the base of amount `to`.
    macro_rules! at {
        ($value:expr, $from:expr, $to:expr) => {
            $value.rotate_left(const { shift($from, $to) })
        };
    }

    macro_rules! o {
        ($i:expr) => {
            OFFSETS[R][$i]
        };
    }

    macro_rules! parity {
        ($x:literal) => {
            v[$x]
                ^ at!(v[$x + 5], o!($x + 5), o!($x))
                ^ at!(v[$x + 10], o!($x + 10), o!($x))
                ^ at!(v[$x + 15], o!($x + 15), o!($x))
                ^ at!(v[$x + 20], o!($x + 20), o!($x))
        };
    }

    let c = [parity!(0), parity!(1), parity!(2), parity!(3), parity!(4)];

    macro_rules! theta {
        ($x:literal) => {
            c[($x + 4) % 5] ^ at!(c[($x + 1) % 5], o!(($x + 1) % 5) + 1, o!(($x + 4) % 5))
        };
    }

    let d = [theta!(0), theta!(1), theta!(2), theta!(3), theta!(4)];

    macro_rules! lanes {
        ($($i:literal)*) => {
            [$(v[$i] ^ at!(d[$i % 5], o!(($i % 5 + 4) % 5), o!($i))),*]
        };
    }

    let t = lanes!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24);

    // The rho-pi source of output lane x of plane y, and its amount after rho.
    macro_rules! source {
        ($x:expr, $y:expr) => {
            ($x % 5 + 3 * $y) % 5 + 5 * ($x % 5)
        };
    }

    macro_rules! rho {
        ($s:expr) => {
            (o!($s) + ROTATIONS[$s]) % 64
        };
    }

    macro_rules! chi {
        ($($x:literal $y:literal)*) => {
            $(
                v[$x + 5 * $y] = (t[source!($x + 2, $y)]
                    & !at!(t[source!($x + 1, $y)], rho!(source!($x + 1, $y)), rho!(source!($x + 2, $y))))
                    ^ at!(t[source!($x, $y)], rho!(source!($x, $y)), rho!(source!($x + 2, $y)));
            )*
        };
    }

    chi!(0 0 1 0 2 0 3 0 4 0 0 1 1 1 2 1 3 1 4 1 0 2 1 2 2 2 3 2 4 2 0 3 1 3 2 3 3 3 4 3 0 4 1 4 2 4 3 4 4 4);

    v[0] ^= constant.rotate_right(const { OFFSETS[R + 1][0] });
}

// The lanes rotated into place after a block of rounds.
#[inline(always)]
pub(super) fn settle(v: &mut [u64; 25]) {
    macro_rules! lanes {
        ($($i:literal)*) => {
            $(v[$i] = v[$i].rotate_left(const { OFFSETS[BLOCK][$i] });)*
        };
    }

    lanes!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24);
}

// A block of rounds, written out so that R is a constant in each.
#[inline(always)]
pub(super) fn block(v: &mut [u64; 25], constants: &[u64; BLOCK]) {
    round::<0>(v, constants[0]);

    round::<1>(v, constants[1]);

    round::<2>(v, constants[2]);

    round::<3>(v, constants[3]);

    round::<4>(v, constants[4]);

    round::<5>(v, constants[5]);

    round::<6>(v, constants[6]);

    round::<7>(v, constants[7]);

    settle(v);
}

pub(super) fn permute(state: &mut [u64; 25]) {
    let mut v = *state;

    for constants in ROUND_CONSTANTS.as_chunks::<BLOCK>().0 {
        block(&mut v, constants);
    }

    *state = v;
}

fn xor_block<const RATE: usize>(state: &mut [u64; 25], block: &[u8; RATE]) {
    for (lane, bytes) in state.iter_mut().zip(block.as_chunks::<8>().0) {
        *lane ^= u64::from_le_bytes(*bytes);
    }
}

pub(super) fn absorb<const RATE: usize>(state: &mut [u64; 25], blocks: &[[u8; RATE]]) {
    for block in blocks {
        xor_block(state, block);

        permute(state);
    }
}

// The whole blocks of data, its padded last block, and then out.len() bytes squeezed, from the
// initial state if there is one and from zero otherwise, as the x86-64 digest kernels do. The
// last block is built in the state lane by lane, and the state is wiped at the end.
pub(super) fn digest<const RATE: usize>(
    initial: Option<&[u64; 25]>,
    data: &[u8],
    suffix: u8,
    out: &mut [u8],
) {
    let (blocks, tail) = data.as_chunks::<RATE>();

    let (lanes, rest) = tail.as_chunks::<8>();

    let mut state = match initial {
        Some(initial) => *initial,
        None => [0; 25],
    };

    absorb(&mut state, blocks);

    for (lane, bytes) in state.iter_mut().zip(lanes) {
        *lane ^= u64::from_le_bytes(*bytes);
    }

    let marker = last_bytes(data, rest.len()) as u64 | u64::from(suffix) << (8 * rest.len());

    state[lanes.len()] ^= marker;

    state[RATE / 8 - 1] ^= 0x80 << 56;

    permute(&mut state);

    let (whole, partial) = out.as_chunks_mut::<8>();

    let mut chunks = whole.chunks_mut(RATE / 8).peekable();

    let mut squeezed = 0;

    while let Some(chunk) = chunks.next() {
        for (bytes, lane) in chunk.iter_mut().zip(&state) {
            *bytes = lane.to_le_bytes();
        }

        squeezed += chunk.len();

        if chunk.len() == RATE / 8 && (chunks.peek().is_some() || !partial.is_empty()) {
            permute(&mut state);

            squeezed = 0;
        }
    }

    if !partial.is_empty() {
        let lane = state[squeezed].to_le_bytes();

        partial.copy_from_slice(&lane[..partial.len()]);
    }

    wipe(&mut state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::testing::Inputs;

    #[test]
    fn lazy_rotation_matches_portable() {
        let mut inputs = Inputs::new(25);

        for n in 0..2_000 {
            let mut state: [u64; 25] = inputs.words();

            let mut expected = state;

            crate::keccak::permute(&mut expected);

            permute(&mut state);

            assert_eq!(state, expected, "case {n}");
        }
    }

    // The one-call digest against the sponge of crate::keccak, for every rate, three suffixes,
    // lengths over several blocks and outputs around the block size.
    #[test]
    fn lazy_digest_matches_sponge() {
        let mut inputs = Inputs::new(64);

        let data: [u8; 3 * 168 + 9] = inputs.bytes();

        for n in 0..3_000 {
            let rate = [72, 104, 136, 144, 168][n % 5];

            let suffix = [0x06, 0x1F, 0x04][n / 5 % 3];

            let length = (n / 15 * 37 + n) % data.len();

            let size = [
                0,
                1,
                7,
                8,
                9,
                32,
                64,
                rate - 1,
                rate,
                rate + 1,
                2 * rate + 5,
            ][n % 11];

            let mut padded = data[..length].to_vec();

            padded.push(suffix);

            padded.resize(padded.len().next_multiple_of(rate), 0);

            *padded.last_mut().expect("a block") ^= 0x80;

            let mut state = [0u64; 25];

            for block in padded.chunks(rate) {
                for (lane, bytes) in state.iter_mut().zip(block.as_chunks::<8>().0) {
                    *lane ^= u64::from_le_bytes(*bytes);
                }

                crate::keccak::permute(&mut state);
            }

            let mut expected = [0; 2 * 168 + 5];

            for (i, byte) in expected[..size].iter_mut().enumerate() {
                if i > 0 && i % rate == 0 {
                    crate::keccak::permute(&mut state);
                }

                *byte = (state[i % rate / 8] >> (8 * (i % 8))) as u8;
            }

            let mut actual = [0; 2 * 168 + 5];

            match rate {
                72 => digest::<72>(None, &data[..length], suffix, &mut actual[..size]),
                104 => digest::<104>(None, &data[..length], suffix, &mut actual[..size]),
                136 => digest::<136>(None, &data[..length], suffix, &mut actual[..size]),
                144 => digest::<144>(None, &data[..length], suffix, &mut actual[..size]),
                _ => digest::<168>(None, &data[..length], suffix, &mut actual[..size]),
            }

            assert_eq!(
                actual[..size],
                expected[..size],
                "rate {rate}, length {length}, size {size}"
            );
        }
    }
}

use crate::cpu;
use crate::wipe::wipe;

pub(crate) const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const ROTATIONS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

// One round from a into e, one output plane at a time: lane x of plane y of the rho-pi output
// comes from lane (x + 3y) % 5 + 5x of a. The column parities that theta needs in the next round
// are summed as the lanes of e are written, so few values stay live and little spills to memory.
#[inline(always)]
fn round(a: &[u64; 25], e: &mut [u64; 25], parities: &mut [u64; 5], constant: u64) {
    let d: [u64; 5] =
        core::array::from_fn(|x| parities[(x + 4) % 5] ^ parities[(x + 1) % 5].rotate_left(1));

    let mut next = [0; 5];

    for y in 0..5 {
        let b: [u64; 5] = core::array::from_fn(|x| {
            let source = (x + 3 * y) % 5 + 5 * x;

            (a[source] ^ d[source % 5]).rotate_left(ROTATIONS[source])
        });

        for x in 0..5 {
            let lane = b[x] ^ (!b[(x + 1) % 5] & b[(x + 2) % 5]);

            // Iota folds into lane 0 as it is written: patching e[0] afterwards costs a reload.
            let lane = if x == 0 && y == 0 {
                lane ^ constant
            } else {
                lane
            };

            e[x + 5 * y] = lane;

            next[x] ^= lane;
        }
    }

    *parities = next;
}

pub(crate) fn permute(state: &mut [u64; 25]) {
    let mut parities: [u64; 5] = core::array::from_fn(|x| {
        state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
    });

    let mut e = [0; 25];

    for constants in ROUND_CONSTANTS.as_chunks::<2>().0 {
        round(state, &mut e, &mut parities, constants[0]);

        round(&e, state, &mut parities, constants[1]);
    }
}

// XORs bytes into the rate from position on, whole lanes at a time where they line up. The rate
// is a multiple of 8, so no lane crosses it.
fn xor_bytes(state: &mut [u64; 25], position: &mut usize, mut bytes: &[u8]) {
    while !position.is_multiple_of(8) {
        let Some((&byte, rest)) = bytes.split_first() else {
            return;
        };

        state[*position / 8] ^= u64::from(byte) << (8 * (*position % 8));

        *position += 1;

        bytes = rest;
    }

    let (lanes, tail) = bytes.as_chunks::<8>();

    for (lane, chunk) in state[*position / 8..].iter_mut().zip(lanes) {
        *lane ^= u64::from_le_bytes(*chunk);
    }

    *position += 8 * lanes.len();

    for &byte in tail {
        state[*position / 8] ^= u64::from(byte) << (8 * (*position % 8));

        *position += 1;
    }
}

// Every state, side by side where the CPU has a kernel for several at once.
pub(crate) fn permute_all(states: &mut [&mut [u64; 25]]) {
    let done = cpu::permute_many(states);

    for state in &mut states[done..] {
        permute(state);
    }
}

// Up to four sponges of one rate and suffix, each fed a message shorter than a block and then
// squeezed one block at a time in lockstep, so that their permutations run side by side: the
// independent XOF and PRF calls of matrix and noise sampling and of SLH-DSA's F.
pub(crate) struct Sponges {
    states: [[u64; 25]; 4],
    count: usize,
}

impl Sponges {
    // Each message is given as its parts, which are absorbed one after the other, so that no
    // copy of a secret input is made to concatenate them.
    pub(crate) fn new(rate: usize, suffix: u8, messages: &[&[&[u8]]]) -> Self {
        assert!(messages.len() <= 4, "at most four sponges run together");

        let mut states = [[0; 25]; 4];

        for (state, parts) in states.iter_mut().zip(messages) {
            let mut position = 0;

            for part in *parts {
                xor_bytes(state, &mut position, part);
            }

            assert!(position < rate, "the message must fit in one block");

            xor_bytes(state, &mut position, &[suffix]);

            // The rate is a multiple of 8, so its last byte is the top byte of a lane.
            state[rate / 8 - 1] ^= 0x80 << 56;
        }

        Self {
            states,
            count: messages.len(),
        }
    }

    // Squeezes the sponges marked active, which skips the permutations of those that already
    // have all the output they need.
    pub(crate) fn squeeze(&mut self, active: [bool; 4]) {
        let mut states = self.states.each_mut();

        let mut chosen = 0;

        for (i, &active) in active[..self.count].iter().enumerate() {
            if active {
                states.swap(chosen, i);

                chosen += 1;
            }
        }

        permute_all(&mut states[..chosen]);
    }

    // The first out.len() bytes of the block that sponge i squeezed last.
    pub(crate) fn read(&self, i: usize, out: &mut [u8]) {
        let (chunks, tail) = out.as_chunks_mut::<8>();

        for (chunk, lane) in chunks.iter_mut().zip(&self.states[i]) {
            *chunk = lane.to_le_bytes();
        }

        if !tail.is_empty() {
            let lane = self.states[i][chunks.len()].to_le_bytes();

            tail.copy_from_slice(&lane[..tail.len()]);
        }
    }
}

impl Drop for Sponges {
    fn drop(&mut self) {
        wipe(self.states.as_flattened_mut());
    }
}

#[derive(Clone)]
pub(crate) struct Keccak {
    state: [u64; 25],
    rate: usize,
    suffix: u8,
    position: usize,
    squeezing: bool,
}

impl Keccak {
    pub(crate) const fn new(rate: usize, suffix: u8) -> Self {
        Self {
            state: [0; 25],
            rate,
            suffix,
            position: 0,
            squeezing: false,
        }
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        assert!(!self.squeezing, "UNSUPPORTED: cannot update after read");

        while !data.is_empty() {
            let (chunk, rest) = data.split_at((self.rate - self.position).min(data.len()));

            self.xor(chunk);

            data = rest;

            if self.position == self.rate {
                permute(&mut self.state);

                self.position = 0;
            }
        }
    }

    fn xor(&mut self, bytes: &[u8]) {
        xor_bytes(&mut self.state, &mut self.position, bytes);
    }

    pub(crate) fn read(&mut self, mut out: &mut [u8]) {
        if !self.squeezing {
            let last = self.rate - 1;

            self.state[self.position / 8] ^= u64::from(self.suffix) << (8 * (self.position % 8));

            self.state[last / 8] ^= 0x80 << (8 * (last % 8));

            permute(&mut self.state);

            self.position = 0;

            self.squeezing = true;
        }

        while !out.is_empty() {
            if self.position == self.rate {
                permute(&mut self.state);

                self.position = 0;
            }

            let take = (self.rate - self.position).min(out.len());

            let (chunk, rest) = core::mem::take(&mut out).split_at_mut(take);

            self.extract(chunk);

            out = rest;
        }
    }

    fn extract(&mut self, mut out: &mut [u8]) {
        while !self.position.is_multiple_of(8) {
            let Some((byte, rest)) = core::mem::take(&mut out).split_first_mut() else {
                return;
            };

            *byte = (self.state[self.position / 8] >> (8 * (self.position % 8))) as u8;

            self.position += 1;

            out = rest;
        }

        let (lanes, tail) = out.as_chunks_mut::<8>();

        for (chunk, lane) in lanes.iter_mut().zip(&self.state[self.position / 8..]) {
            *chunk = lane.to_le_bytes();
        }

        self.position += 8 * lanes.len();

        for byte in tail {
            *byte = (self.state[self.position / 8] >> (8 * (self.position % 8))) as u8;

            self.position += 1;
        }
    }
}

impl Drop for Keccak {
    fn drop(&mut self) {
        wipe(&mut self.state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::testing::{EDGES, Inputs};

    // Batches of one to five states, edge patterns first: the kernels permute some leading
    // states, which must equal the portable permutation, and leave the rest untouched.
    #[test]
    fn keccak_kernels_match_portable() {
        let mut inputs = Inputs::new(1600);

        let (mut states_checked, mut accelerated) = (0, 0);

        for n in 0..7_000 {
            let count = 1 + n % 5;

            let mut states = [[0u64; 25]; 5];

            for (i, state) in states[..count].iter_mut().enumerate() {
                *state = match EDGES.get(n / 5) {
                    Some(&edge) => [edge ^ i as u64; 25],
                    None => inputs.words(),
                };
            }

            let mut expected = states;

            for state in &mut expected[..count] {
                permute(state);
            }

            let mut actual = states;

            let done = cpu::permute_many(&mut actual.each_mut()[..count]);

            assert_eq!(actual[..done], expected[..done], "case {n}");

            assert_eq!(actual[done..], states[done..], "case {n}");

            states_checked += count;

            accelerated += done;
        }

        assert!(states_checked >= 20_000);

        std::eprintln!("Keccak: {accelerated} of {states_checked} states through a CPU kernel");
    }

    // Sponges against the one-sponge Keccak, for every rate, both suffixes, every message length
    // that fits in a block and one to four sponges, over three squeezed blocks.
    #[test]
    fn sponges_match_keccak() {
        let mut inputs = Inputs::new(4);

        for rate in [72, 104, 136, 144, 168] {
            for suffix in [0x06, 0x1F] {
                for length in 0..rate {
                    let count = 1 + length % 4;

                    let messages: [[u8; 168]; 4] = core::array::from_fn(|_| inputs.bytes());

                    let parts = messages.each_ref().map(|message| &message[..length]);

                    // Each message in two parts, split at a point that moves with the length.
                    let split = parts.map(|part| part.split_at(length / 3));

                    let lists = split.each_ref().map(|(a, b)| [*a, *b]);

                    let lists = lists.each_ref().map(|list| &list[..]);

                    let mut sponges = Sponges::new(rate, suffix, &lists[..count]);

                    for (i, part) in parts[..count].iter().enumerate() {
                        let mut engine = Keccak::new(rate, suffix);

                        engine.update(part);

                        let mut expected = [0; 3 * 168];

                        engine.read(&mut expected[..3 * rate]);

                        let mut copy = Sponges {
                            states: sponges.states,
                            count: sponges.count,
                        };

                        for block in expected[..3 * rate].chunks(rate) {
                            copy.squeeze([true; 4]);

                            let mut actual = [0; 168];

                            copy.read(i, &mut actual[..rate]);

                            assert_eq!(&actual[..rate], block, "rate {rate}, length {length}");
                        }
                    }

                    sponges.squeeze([true; 4]);
                }
            }
        }
    }

    // A sponge left out of a squeeze keeps its block, and the others advance as they would alone.
    #[test]
    fn inactive_sponges_keep_their_state() {
        let messages: [[u8; 34]; 4] = core::array::from_fn(|i| [i as u8; 34]);

        let parts = messages.each_ref().map(|message| [&message[..]]);

        let lists = parts.each_ref().map(|list| &list[..]);

        let mut sponges = Sponges::new(168, 0x1F, &lists);

        sponges.squeeze([true; 4]);

        let before = sponges.states;

        sponges.squeeze([false, true, false, true]);

        for (i, [part]) in parts.iter().enumerate() {
            let mut engine = Keccak::new(168, 0x1F);

            engine.update(part);

            let mut expected = [0; 2 * 168];

            engine.read(&mut expected);

            let mut actual = [0; 168];

            sponges.read(i, &mut actual);

            let block = i % 2;

            assert_eq!(
                actual,
                expected[168 * block..168 * (block + 1)],
                "sponge {i}"
            );

            if i % 2 == 0 {
                assert_eq!(sponges.states[i], before[i]);
            }
        }
    }
}

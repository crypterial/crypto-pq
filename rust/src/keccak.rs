use alloc::vec;
use alloc::vec::Vec;

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
// A CPU kernel runs these rounds beside its vector rounds.
#[inline(always)]
pub(crate) fn round(a: &[u64; 25], e: &mut [u64; 25], parities: &mut [u64; 5], constant: u64) {
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

// The column parities that the first round's theta needs.
pub(crate) fn parities(state: &[u64; 25]) -> [u64; 5] {
    core::array::from_fn(|x| {
        state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
    })
}

pub(crate) fn permute(state: &mut [u64; 25]) {
    let mut parities = parities(state);

    let mut e = [0; 25];

    for constants in ROUND_CONSTANTS.as_chunks::<2>().0 {
        round(state, &mut e, &mut parities, constants[0]);

        round(&e, state, &mut parities, constants[1]);
    }
}

// One state through a CPU kernel where there is one.
fn permute_one(state: &mut [u64; 25]) {
    if cpu::permute_many(&mut [&mut *state]) == 0 {
        permute(state);
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

// The most sponges that run side by side; callers with more split them into groups of group().
pub(crate) const MAX_SPONGES: usize = 8;

// The group size, at most MAX_SPONGES, whose permutations the CPU's kernels run best together.
pub(crate) fn group() -> usize {
    cpu::keccak_group()
}

// Up to MAX_SPONGES sponges of one rate and suffix, each fed a message shorter than a block and
// then squeezed one block at a time in lockstep, so that their permutations run side by side:
// the independent XOF and PRF calls of matrix and noise sampling and of SLH-DSA's F.
pub(crate) struct Sponges {
    states: [[u64; 25]; MAX_SPONGES],
    count: usize,
}

impl Sponges {
    // No sponges: every state is zero, as start needs them.
    pub(crate) const fn empty() -> Self {
        Self {
            states: [[0; 25]; MAX_SPONGES],
            count: 0,
        }
    }

    // Starts a sponge on each message, after wiping the sponges started before. A caller keeps
    // one object for all its groups of sponges, whose states are written in place: a new object
    // for each group cost a copy and the zeroing of every state. Each message is given as its
    // parts, which are absorbed one after the other, so that no copy of a secret input is made to
    // concatenate them.
    pub(crate) fn start(&mut self, rate: usize, suffix: u8, messages: &[&[&[u8]]]) {
        assert!(
            messages.len() <= MAX_SPONGES,
            "at most MAX_SPONGES sponges run together"
        );

        wipe(self.states[..self.count].as_flattened_mut());

        self.count = messages.len();

        for (state, parts) in self.states.iter_mut().zip(messages) {
            let mut position = 0;

            for part in *parts {
                xor_bytes(state, &mut position, part);
            }

            assert!(position < rate, "the message must fit in one block");

            state[position / 8] ^= u64::from(suffix) << (8 * (position % 8));

            // The rate is a multiple of 8, so its last byte is the top byte of a lane.
            state[rate / 8 - 1] ^= 0x80 << 56;
        }
    }

    // Squeezes the sponges marked active, which skips the permutations of those that already
    // have all the output they need.
    pub(crate) fn squeeze(&mut self, active: [bool; MAX_SPONGES]) {
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

    // squeeze, and one more Keccak permutation of other beside those of the sponges, in the slot
    // after them: a state that a kernel permutes in the same call costs less than alone.
    pub(crate) fn squeeze_beside(&mut self, active: [bool; MAX_SPONGES], other: &mut [u64; 25]) {
        let spare = self.count;

        assert!(
            spare < MAX_SPONGES,
            "a free slot is needed beside the sponges"
        );

        self.states[spare] = *other;

        {
            let mut states = self.states.each_mut();

            let mut chosen = 0;

            for (i, &active) in active[..self.count].iter().enumerate() {
                if active {
                    states.swap(chosen, i);

                    chosen += 1;
                }
            }

            states.swap(chosen, spare);

            permute_all(&mut states[..chosen + 1]);
        }

        *other = self.states[spare];

        // The slot lies outside the sponges, which are all that drop wipes.
        wipe(&mut self.states[spare]);
    }

    // The lanes of the block that sponge i squeezed last, in output order on every target.
    pub(crate) fn lanes<const LANES: usize>(&self, i: usize) -> &[u64; LANES] {
        self.states[i]
            .first_chunk()
            .expect("the rate is at most 21 lanes")
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
        wipe(self.states[..self.count].as_flattened_mut());
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
            // Whole blocks from a block boundary go to a CPU kernel in one call, which keeps the
            // state in its registers from one block to the next.
            if self.position == 0 {
                let absorbed = cpu::absorb(&mut self.state, self.rate, data);

                data = &data[absorbed..];

                if data.is_empty() {
                    break;
                }
            }

            let (chunk, rest) = data.split_at((self.rate - self.position).min(data.len()));

            self.xor(chunk);

            data = rest;

            if self.position == self.rate {
                permute_one(&mut self.state);

                self.position = 0;
            }
        }
    }

    fn xor(&mut self, bytes: &[u8]) {
        xor_bytes(&mut self.state, &mut self.position, bytes);
    }

    // update with one whole block at a block boundary, whose permutation permute applies, so that
    // the caller can run it beside other permutations. permute must apply exactly Keccak-f[1600].
    pub(crate) fn update_block_with(&mut self, block: &[u8], permute: impl FnOnce(&mut [u64; 25])) {
        assert!(
            !self.squeezing && self.position == 0 && block.len() == self.rate,
            "a whole block at a block boundary"
        );

        self.xor(block);

        permute(&mut self.state);

        self.position = 0;
    }

    pub(crate) fn read(&mut self, mut out: &mut [u8]) {
        if !self.squeezing {
            let last = self.rate - 1;

            self.state[self.position / 8] ^= u64::from(self.suffix) << (8 * (self.position % 8));

            self.state[last / 8] ^= 0x80 << (8 * (last % 8));

            permute_one(&mut self.state);

            self.position = 0;

            self.squeezing = true;
        }

        while !out.is_empty() {
            if self.position == self.rate {
                permute_one(&mut self.state);

                self.position = 0;
            }

            let take = (self.rate - self.position).min(out.len());

            let (chunk, rest) = core::mem::take(&mut out).split_at_mut(take);

            self.extract(chunk);

            out = rest;
        }
    }

    pub(crate) fn digest(rate: usize, suffix: u8, data: &[u8], size: usize) -> Vec<u8> {
        let mut out = vec![0; size];

        Self::digest_into(rate, suffix, data, &mut out);

        out
    }

    // The first out.len() bytes of output for data, read once. Where there is a kernel, the
    // padded last block is absorbed in the same call as the whole blocks before it, and no state
    // is kept between calls.
    pub(crate) fn digest_into(rate: usize, suffix: u8, data: &[u8], out: &mut [u8]) {
        let (blocks, tail) = data.split_at(data.len() - data.len() % rate);

        let mut last = [0; 168];

        last[..tail.len()].copy_from_slice(tail);

        last[tail.len()] ^= suffix;

        last[rate - 1] ^= 0x80;

        let mut engine = Self::new(rate, suffix);

        if cpu::absorb_last(&mut engine.state, rate, blocks, &last[..rate]) {
            engine.squeezing = true;
        } else {
            engine.update(data);
        }

        wipe(&mut last);

        engine.read(out);
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

    // Batches of one to MAX_SPONGES states, edge patterns first: the kernels permute some
    // leading states, which must equal the portable permutation, and leave the rest untouched.
    #[test]
    fn keccak_kernels_match_portable() {
        let mut inputs = Inputs::new(1600);

        let (mut states_checked, mut accelerated) = (0, 0);

        for n in 0..7_000 {
            let count = 1 + n % MAX_SPONGES;

            let mut states = [[0u64; 25]; MAX_SPONGES];

            for (i, state) in states[..count].iter_mut().enumerate() {
                *state = match EDGES.get(n / MAX_SPONGES) {
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

    // The absorbing kernel against XOR and the portable permutation block by block, for every
    // rate, one to three blocks and a few bytes after them, which it must leave alone.
    #[test]
    fn absorb_kernel_matches_portable() {
        let mut inputs = Inputs::new(1088);

        let mut accelerated = 0;

        for n in 0..20_000 {
            let rate = [72, 104, 136, 144, 168][n % 5];

            let blocks = 1 + n / 5 % 3;

            let (state, data): ([u64; 25], [u8; 3 * 168 + 8]) = match EDGES.get(n / 15) {
                Some(&edge) => ([edge; 25], [!edge as u8; 3 * 168 + 8]),
                None => (inputs.words(), inputs.bytes()),
            };

            let data = &data[..blocks * rate + n % 8];

            let mut expected = state;

            for block in data.chunks_exact(rate) {
                for (lane, bytes) in expected.iter_mut().zip(block.as_chunks::<8>().0) {
                    *lane ^= u64::from_le_bytes(*bytes);
                }

                permute(&mut expected);
            }

            let mut actual = state;

            let absorbed = cpu::absorb(&mut actual, rate, data);

            if absorbed == 0 {
                assert_eq!(actual, state, "case {n}");
            } else {
                assert_eq!(absorbed, blocks * rate, "case {n}");

                assert_eq!(actual, expected, "case {n}");

                accelerated += 1;
            }
        }

        std::eprintln!("Keccak absorb: {accelerated} of 20000 cases through a CPU kernel");
    }

    fn started(rate: usize, suffix: u8, messages: &[&[&[u8]]]) -> Sponges {
        let mut sponges = Sponges::empty();

        sponges.start(rate, suffix, messages);

        sponges
    }

    // Sponges against the one-sponge Keccak, for every rate, both suffixes, every message length
    // that fits in a block and one to MAX_SPONGES sponges, over three squeezed blocks. One object
    // is started again for every case, after squeezes, with more or fewer sponges than before.
    #[test]
    fn sponges_match_keccak() {
        let mut inputs = Inputs::new(4);

        let mut sponges = Sponges::empty();

        for rate in [72, 104, 136, 144, 168] {
            for suffix in [0x06, 0x1F] {
                for length in 0..rate {
                    let count = 1 + length % MAX_SPONGES;

                    let messages: [[u8; 168]; MAX_SPONGES] =
                        core::array::from_fn(|_| inputs.bytes());

                    let parts = messages.each_ref().map(|message| &message[..length]);

                    // Each message in two parts, split at a point that moves with the length.
                    let split = parts.map(|part| part.split_at(length / 3));

                    let lists = split.each_ref().map(|(a, b)| [*a, *b]);

                    let lists = lists.each_ref().map(|list| &list[..]);

                    sponges.start(rate, suffix, &lists[..count]);

                    assert!(
                        sponges.states[count..]
                            .iter()
                            .all(|state| *state == [0; 25])
                    );

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
                            copy.squeeze([true; MAX_SPONGES]);

                            let mut actual = [0; 168];

                            copy.read(i, &mut actual[..rate]);

                            assert_eq!(&actual[..rate], block, "rate {rate}, length {length}");
                        }
                    }

                    sponges.squeeze([true; MAX_SPONGES]);
                }
            }
        }
    }

    // The one-shot digest against update and read, for every rate, both suffixes, message
    // lengths over several blocks and outputs longer than a block.
    #[test]
    fn digest_matches_update_and_read() {
        let mut inputs = Inputs::new(8);

        for rate in [72, 104, 136, 144, 168] {
            for suffix in [0x06, 0x1F] {
                for length in (0..3 * rate + 2).step_by(5) {
                    let data: [u8; 3 * 168 + 2] = inputs.bytes();

                    let size = [32, 64, rate, 2 * rate + 7][length % 4];

                    let mut engine = Keccak::new(rate, suffix);

                    engine.update(&data[..length]);

                    let mut expected = vec![0; size];

                    engine.read(&mut expected);

                    let actual = Keccak::digest(rate, suffix, &data[..length], size);

                    assert_eq!(actual, expected, "rate {rate}, length {length}");
                }
            }
        }
    }

    // A hash fed whole blocks whose permutations run beside a squeeze of sponges gives the same
    // digest as alone, and the sponges the same blocks, for every count of sponges that leaves a
    // slot free and every pattern of active sponges.
    #[test]
    fn permutations_beside_sponges_match() {
        let mut inputs = Inputs::new(136);

        for count in 1..MAX_SPONGES {
            for pattern in 0..1usize << count {
                let messages: [[u8; 34]; MAX_SPONGES] = core::array::from_fn(|_| inputs.bytes());

                let parts = messages.each_ref().map(|message| [&message[..]]);

                let lists = parts.each_ref().map(|list| &list[..]);

                let mut sponges = started(168, 0x1F, &lists[..count]);

                let mut expected = started(168, 0x1F, &lists[..count]);

                let data: [u8; 3 * 136] = inputs.bytes();

                let mut hash = Keccak::new(136, 0x06);

                let active = core::array::from_fn(|i| pattern & (1 << i) != 0);

                for block in data.chunks(136) {
                    hash.update_block_with(block, |state| sponges.squeeze_beside(active, state));

                    expected.squeeze(active);
                }

                assert_eq!(sponges.states[..count], expected.states[..count]);

                let mut alone = Keccak::new(136, 0x06);

                alone.update(&data);

                let (mut digest, mut reference) = ([0; 32], [0; 32]);

                hash.read(&mut digest);

                alone.read(&mut reference);

                assert_eq!(digest, reference, "{count} sponges, pattern {pattern:b}");
            }
        }
    }

    // A sponge left out of a squeeze keeps its block, and the others advance as they would alone.
    #[test]
    fn inactive_sponges_keep_their_state() {
        let messages: [[u8; 34]; 4] = core::array::from_fn(|i| [i as u8; 34]);

        let parts = messages.each_ref().map(|message| [&message[..]]);

        let lists = parts.each_ref().map(|list| &list[..]);

        let mut sponges = started(168, 0x1F, &lists);

        sponges.squeeze([true; MAX_SPONGES]);

        let before = sponges.states;

        sponges.squeeze(core::array::from_fn(|i| i % 2 == 1));

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

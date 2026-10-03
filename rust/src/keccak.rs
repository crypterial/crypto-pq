use crate::wipe::wipe;

const ROUND_CONSTANTS: [u64; 24] = [
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

    // XORs bytes into the rate from position on, whole lanes at a time where they line up. The
    // rate is a multiple of 8, so no lane crosses it.
    fn xor(&mut self, mut bytes: &[u8]) {
        while !self.position.is_multiple_of(8) {
            let Some((&byte, rest)) = bytes.split_first() else {
                return;
            };

            self.state[self.position / 8] ^= u64::from(byte) << (8 * (self.position % 8));

            self.position += 1;

            bytes = rest;
        }

        let (lanes, tail) = bytes.as_chunks::<8>();

        for (lane, chunk) in self.state[self.position / 8..].iter_mut().zip(lanes) {
            *lane ^= u64::from_le_bytes(*chunk);
        }

        self.position += 8 * lanes.len();

        for &byte in tail {
            self.state[self.position / 8] ^= u64::from(byte) << (8 * (self.position % 8));

            self.position += 1;
        }
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

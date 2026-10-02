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

pub(crate) fn permute(a: &mut [u64; 25]) {
    for constant in ROUND_CONSTANTS {
        let c: [u64; 5] =
            core::array::from_fn(|x| a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]);

        let d: [u64; 5] = core::array::from_fn(|x| c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1));

        let mut b = [0u64; 25];

        // Theta, then rho and pi: lane x + 5y moves to y + 5((2x + 3y) mod 5).
        for y in 0..5 {
            for x in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] =
                    (a[x + 5 * y] ^ d[x]).rotate_left(ROTATIONS[x + 5 * y]);
            }
        }

        for y in (0..25).step_by(5) {
            for x in 0..5 {
                a[y + x] = b[y + x] ^ (!b[y + (x + 1) % 5] & b[y + (x + 2) % 5]);
            }
        }

        a[0] ^= constant;
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
            if self.position == 0 && data.len() >= self.rate {
                let (block, rest) = data.split_at(self.rate);

                for (lane, bytes) in self.state.iter_mut().zip(block.as_chunks::<8>().0) {
                    *lane ^= u64::from_le_bytes(*bytes);
                }

                permute(&mut self.state);

                data = rest;

                continue;
            }

            let take = (self.rate - self.position).min(data.len());

            for (offset, &byte) in data[..take].iter().enumerate() {
                let index = self.position + offset;

                self.state[index / 8] ^= u64::from(byte) << (8 * (index % 8));
            }

            self.position += take;

            data = &data[take..];

            if self.position == self.rate {
                permute(&mut self.state);

                self.position = 0;
            }
        }
    }

    pub(crate) fn read(&mut self, out: &mut [u8]) {
        if !self.squeezing {
            let last = self.rate - 1;

            self.state[self.position / 8] ^= u64::from(self.suffix) << (8 * (self.position % 8));

            self.state[last / 8] ^= 0x80 << (8 * (last % 8));

            permute(&mut self.state);

            self.position = 0;

            self.squeezing = true;
        }

        for byte in out {
            if self.position == self.rate {
                permute(&mut self.state);

                self.position = 0;
            }

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

// BLAKE2b and BLAKE2s (RFC 7693) in sequential mode, with the salt and personalization fields of
// the BLAKE2 specification (2.8). A chaining value starts as the IV XORed with the parameter block,
// which configure computes once; a key is zero-padded to a block and processed as the first block.
// The final block, the only one with the final flag, is given as words: built with word stores, it
// is loaded with word loads, which store-to-load forwarding serves.

use core::ops::{BitXor, Not};

use crate::cpu;
use crate::sha2::{IV_256, IV_512, last_bytes};
use crate::wipe::wipe;

pub(crate) const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

// The final block and its counter, the number of bytes hashed in all, the key block included.
pub(crate) type Last<'a, W> = Option<(&'a [W; 16], u128)>;

// The word of BLAKE2b (u64) or BLAKE2s (u32) and what differs between the two functions.
pub(crate) trait Word:
    Copy + Default + Eq + BitXor<Output = Self> + Not<Output = Self> + 'static
{
    const BYTES: usize;

    const ROUNDS: usize;

    const ROTATIONS: [u32; 4];

    const IV: [Self; 8];

    fn add(self, other: Self) -> Self;

    fn rotate(self, n: u32) -> Self;

    fn from_le(bytes: &[u8]) -> Self;

    // The low bytes of a value of at most a word.
    fn from_value(value: u128) -> Self;

    // The leading out.len() bytes of the chaining value, little-endian.
    fn store(h: &[Self; 8], out: &mut [u8]);

    // The two counter words t0 and t1.
    fn counter(bytes: u128) -> [Self; 2];

    // The parameter block's first word with a key length: digest length, key length, fanout 1 and
    // depth 1 in its four low bytes, so the key length is its second byte.
    fn key_length(length: usize) -> Self;

    // The CPU kernel, which returns whether it did the work of process.
    fn kernel(
        h: &mut [Self; 8],
        first: Option<&[Self; 16]>,
        blocks: &[u8],
        counter: u128,
        last: Last<'_, Self>,
    ) -> bool;
}

impl Word for u64 {
    const BYTES: usize = 8;

    const ROUNDS: usize = 12;

    const ROTATIONS: [u32; 4] = [32, 24, 16, 63];

    // RFC 7693, 2.6: the IV of SHA-512.
    const IV: [u64; 8] = IV_512;

    #[inline(always)]
    fn add(self, other: Self) -> Self {
        self.wrapping_add(other)
    }

    #[inline(always)]
    fn rotate(self, n: u32) -> Self {
        self.rotate_right(n)
    }

    #[inline(always)]
    fn from_le(bytes: &[u8]) -> Self {
        Self::from_le_bytes(*bytes.first_chunk().expect("a whole word"))
    }

    #[inline(always)]
    fn from_value(value: u128) -> Self {
        value as Self
    }

    #[inline(always)]
    fn store(h: &[Self; 8], out: &mut [u8]) {
        let (words, rest) = out.as_chunks_mut::<8>();

        for (bytes, word) in words.iter_mut().zip(h) {
            *bytes = word.to_le_bytes();
        }

        if let Some(word) = h.get(words.len()) {
            rest.copy_from_slice(&word.to_le_bytes()[..rest.len()]);
        }
    }

    #[inline(always)]
    fn counter(bytes: u128) -> [Self; 2] {
        [bytes as Self, (bytes >> 64) as Self]
    }

    #[inline(always)]
    fn key_length(length: usize) -> Self {
        (length as Self) << 8
    }

    #[inline(always)]
    fn kernel(
        h: &mut [Self; 8],
        first: Option<&[Self; 16]>,
        blocks: &[u8],
        counter: u128,
        last: Last<'_, Self>,
    ) -> bool {
        cpu::blake2b(h, first, blocks.as_chunks().0, counter, last)
    }
}

impl Word for u32 {
    const BYTES: usize = 4;

    const ROUNDS: usize = 10;

    const ROTATIONS: [u32; 4] = [16, 12, 8, 7];

    // RFC 7693, 2.6: the IV of SHA-256.
    const IV: [u32; 8] = IV_256;

    #[inline(always)]
    fn add(self, other: Self) -> Self {
        self.wrapping_add(other)
    }

    #[inline(always)]
    fn rotate(self, n: u32) -> Self {
        self.rotate_right(n)
    }

    #[inline(always)]
    fn from_le(bytes: &[u8]) -> Self {
        Self::from_le_bytes(*bytes.first_chunk().expect("a whole word"))
    }

    #[inline(always)]
    fn from_value(value: u128) -> Self {
        value as Self
    }

    #[inline(always)]
    fn store(h: &[Self; 8], out: &mut [u8]) {
        let (words, rest) = out.as_chunks_mut::<4>();

        for (bytes, word) in words.iter_mut().zip(h) {
            *bytes = word.to_le_bytes();
        }

        if let Some(word) = h.get(words.len()) {
            rest.copy_from_slice(&word.to_le_bytes()[..rest.len()]);
        }
    }

    // BLAKE2s counts at most 2^64 - 1 bytes.
    #[inline(always)]
    fn counter(bytes: u128) -> [Self; 2] {
        [bytes as Self, (bytes >> 32) as Self]
    }

    #[inline(always)]
    fn key_length(length: usize) -> Self {
        (length as Self) << 8
    }

    #[inline(always)]
    fn kernel(
        h: &mut [Self; 8],
        first: Option<&[Self; 16]>,
        blocks: &[u8],
        counter: u128,
        last: Last<'_, Self>,
    ) -> bool {
        cpu::blake2s(h, first, blocks.as_chunks().0, counter as u64, last)
    }
}

// The BLAKE2b chaining value for a digest of `digest` bytes, without a key: the IV XORed with the
// parameter block, whose salt and personalization fields take the given bytes zero-padded to 16.
pub(crate) const fn start64(digest: usize, salt: &[u8], personalization: &[u8]) -> [u64; 8] {
    let mut h = IV_512;

    h[0] ^= digest as u64 | 1 << 16 | 1 << 24;

    let mut i = 0;

    while i < salt.len() {
        h[4 + i / 8] ^= (salt[i] as u64) << (8 * (i % 8));

        i += 1;
    }

    i = 0;

    while i < personalization.len() {
        h[6 + i / 8] ^= (personalization[i] as u64) << (8 * (i % 8));

        i += 1;
    }

    h
}

// start64 for BLAKE2s, whose fields take 8 bytes each.
pub(crate) const fn start32(digest: usize, salt: &[u8], personalization: &[u8]) -> [u32; 8] {
    let mut h = IV_256;

    h[0] ^= digest as u32 | 1 << 16 | 1 << 24;

    let mut i = 0;

    while i < salt.len() {
        h[4 + i / 4] ^= (salt[i] as u32) << (8 * (i % 4));

        i += 1;
    }

    i = 0;

    while i < personalization.len() {
        h[6 + i / 4] ^= (personalization[i] as u32) << (8 * (i % 4));

        i += 1;
    }

    h
}

// a takes the message word before b, so that only one addition waits for b.
#[inline(always)]
fn g<W: Word>(v: &mut [W; 16], [a, b, c, d]: [usize; 4], x: W, y: W) {
    let [r1, r2, r3, r4] = W::ROTATIONS;

    v[a] = v[a].add(x).add(v[b]);

    v[d] = (v[d] ^ v[a]).rotate(r1);

    v[c] = v[c].add(v[d]);

    v[b] = (v[b] ^ v[c]).rotate(r2);

    v[a] = v[a].add(y).add(v[b]);

    v[d] = (v[d] ^ v[a]).rotate(r3);

    v[c] = v[c].add(v[d]);

    v[b] = (v[b] ^ v[c]).rotate(r4);
}

#[inline(always)]
fn round<W: Word>(v: &mut [W; 16], m: &[W; 16], s: &[usize; 16]) {
    g(v, [0, 4, 8, 12], m[s[0]], m[s[1]]);

    g(v, [1, 5, 9, 13], m[s[2]], m[s[3]]);

    g(v, [2, 6, 10, 14], m[s[4]], m[s[5]]);

    g(v, [3, 7, 11, 15], m[s[6]], m[s[7]]);

    g(v, [0, 5, 10, 15], m[s[8]], m[s[9]]);

    g(v, [1, 6, 11, 12], m[s[10]], m[s[11]]);

    g(v, [2, 7, 8, 13], m[s[12]], m[s[13]]);

    g(v, [3, 4, 9, 14], m[s[14]], m[s[15]]);
}

// The compression function F of RFC 7693, 3.2, for one block of message words.
pub(crate) fn compress<W: Word>(h: &mut [W; 8], m: &[W; 16], counter: u128, last: bool) {
    let iv = W::IV;

    let [t0, t1] = W::counter(counter);

    let mut v = [
        h[0],
        h[1],
        h[2],
        h[3],
        h[4],
        h[5],
        h[6],
        h[7],
        iv[0],
        iv[1],
        iv[2],
        iv[3],
        iv[4] ^ t0,
        iv[5] ^ t1,
        if last { !iv[6] } else { iv[6] },
        iv[7],
    ];

    // Written out, so that every index into the message is a constant.
    round(&mut v, m, &SIGMA[0]);

    round(&mut v, m, &SIGMA[1]);

    round(&mut v, m, &SIGMA[2]);

    round(&mut v, m, &SIGMA[3]);

    round(&mut v, m, &SIGMA[4]);

    round(&mut v, m, &SIGMA[5]);

    round(&mut v, m, &SIGMA[6]);

    round(&mut v, m, &SIGMA[7]);

    round(&mut v, m, &SIGMA[8]);

    round(&mut v, m, &SIGMA[9]);

    if W::ROUNDS == 12 {
        round(&mut v, m, &SIGMA[0]);

        round(&mut v, m, &SIGMA[1]);
    }

    for (i, word) in h.iter_mut().enumerate() {
        *word = *word ^ v[i] ^ v[i + 8];
    }
}

// The first block (the key block of a MAC), then the whole blocks of bytes, then the final block,
// into h: counter is the number of bytes before the first of them.
fn process<W: Word>(
    h: &mut [W; 8],
    first: Option<&[W; 16]>,
    blocks: &[u8],
    counter: u128,
    last: Last<'_, W>,
) {
    if W::kernel(h, first, blocks, counter, last) {
        return;
    }

    let size = 16 * W::BYTES as u128;

    let mut counter = counter;

    if let Some(first) = first {
        counter = counter.wrapping_add(size);

        compress(h, first, counter, false);
    }

    for block in blocks.chunks_exact(16 * W::BYTES) {
        let m: [W; 16] =
            core::array::from_fn(|i| W::from_le(&block[i * W::BYTES..(i + 1) * W::BYTES]));

        counter = counter.wrapping_add(size);

        compress(h, &m, counter, false);
    }

    if let Some((m, total)) = last {
        compress(h, m, total, true);
    }
}

// The words of at most a block of bytes, zero-padded: the bytes of data from `start` on. A partial
// last word is read without a store, from the bytes that end data.
fn words<W: Word>(data: &[u8], start: usize, out: &mut [W; 16]) {
    let tail = &data[start..];

    let whole = tail.len() / W::BYTES;

    for (word, bytes) in out.iter_mut().zip(tail.chunks_exact(W::BYTES)) {
        *word = W::from_le(bytes);
    }

    let rest = tail.len() % W::BYTES;

    if rest > 0 {
        out[whole] = W::from_value(last_bytes(data, rest));
    }
}

// The bytes of data that precede its final block: whole blocks, leaving at least one byte for the
// final block when there is data.
fn leading<W: Word>(length: usize) -> usize {
    let block = 16 * W::BYTES;

    length.saturating_sub(1) / block * block
}

// The digest of data, out.len() bytes, from the chaining value h, in one pass over data.
pub(crate) fn digest<W: Word>(h: &[W; 8], data: &[u8], out: &mut [u8]) {
    let mut h = *h;

    let whole = leading::<W>(data.len());

    let mut last = [W::default(); 16];

    words(data, whole, &mut last);

    process(
        &mut h,
        None,
        &data[..whole],
        0,
        Some((&last, data.len() as u128)),
    );

    W::store(&h, out);

    wipe(&mut h);

    wipe(&mut last);
}

// The keyed hash of data under a key of 1 to 16 * W::BYTES bytes, from the unkeyed chaining value
// h of the configured digest length.
pub(crate) fn mac<W: Word>(h: &[W; 8], key: &[u8], data: &[u8], out: &mut [u8]) {
    let mut h = *h;

    h[0] = h[0] ^ W::key_length(key.len());

    let mut key_block = [W::default(); 16];

    words(key, 0, &mut key_block);

    let block = 16 * W::BYTES as u128;

    let mut last = [W::default(); 16];

    if data.is_empty() {
        process(&mut h, None, &[], 0, Some((&key_block, block)));
    } else {
        let whole = leading::<W>(data.len());

        words(data, whole, &mut last);

        process(
            &mut h,
            Some(&key_block),
            &data[..whole],
            0,
            Some((&last, block + data.len() as u128)),
        );
    }

    W::store(&h, out);

    wipe(&mut h);

    wipe(&mut key_block);

    wipe(&mut last);
}

// An incremental hash. The buffer keeps the last block seen until more data arrives, since only
// the final block is compressed with the final flag.
#[derive(Clone)]
pub(crate) struct Engine<W: Word> {
    h: [W; 8],
    buffer: [u8; 128],
    filled: usize,
    counter: u128,
}

impl<W: Word> Engine<W> {
    const BLOCK: usize = 16 * W::BYTES;

    pub(crate) const fn new(h: &[W; 8]) -> Self {
        Self {
            h: *h,
            buffer: [0; 128],
            filled: 0,
            counter: 0,
        }
    }

    // A MAC under a key of 1 to BLOCK bytes, whose padded block is the first block.
    pub(crate) fn keyed(h: &[W; 8], key: &[u8]) -> Self {
        let mut engine = Self::new(h);

        engine.h[0] = engine.h[0] ^ W::key_length(key.len());

        engine.buffer[..key.len()].copy_from_slice(key);

        engine.filled = Self::BLOCK;

        engine
    }

    // The buffered block, once more data shows that it is not the final one.
    fn flush(&mut self) {
        process(
            &mut self.h,
            None,
            &self.buffer[..Self::BLOCK],
            self.counter,
            None,
        );

        self.counter = self.counter.wrapping_add(Self::BLOCK as u128);

        self.filled = 0;
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }

        if self.filled == Self::BLOCK {
            self.flush();
        }

        if self.filled > 0 {
            let take = (Self::BLOCK - self.filled).min(data.len());

            self.buffer[self.filled..self.filled + take].copy_from_slice(&data[..take]);

            self.filled += take;

            data = &data[take..];

            if data.is_empty() {
                return;
            }

            self.flush();
        }

        let whole = leading::<W>(data.len());

        process(&mut self.h, None, &data[..whole], self.counter, None);

        self.counter = self.counter.wrapping_add(whole as u128);

        let rest = &data[whole..];

        self.buffer[..rest.len()].copy_from_slice(rest);

        self.filled = rest.len();
    }

    pub(crate) fn finish(&self, out: &mut [u8]) {
        let mut h = self.h;

        let mut last = [W::default(); 16];

        words(&self.buffer[..self.filled], 0, &mut last);

        let total = self.counter.wrapping_add(self.filled as u128);

        process(&mut h, None, &[], self.counter, Some((&last, total)));

        W::store(&h, out);

        wipe(&mut h);

        wipe(&mut last);
    }
}

impl<W: Word> Drop for Engine<W> {
    fn drop(&mut self) {
        wipe(&mut self.h);

        wipe(&mut self.buffer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::testing::{EDGES, Inputs};

    // The kernels against the portable compression: a key block or none, zero to three whole
    // blocks and a final block or none, from edge and random states, for both functions.
    fn kernel_matches<W: Word>(inputs: &mut Inputs, word: impl Fn(u64) -> W) -> usize {
        let mut accelerated = 0;

        for n in 0..10_000 {
            let edge = EDGES.get(n / 16).copied();

            let pick = |inputs: &mut Inputs| match edge {
                Some(value) => value,
                None => inputs.next(),
            };

            let h: [W; 8] = core::array::from_fn(|_| word(pick(inputs)));

            let first: [W; 16] = core::array::from_fn(|_| word(pick(inputs)));

            let last: [W; 16] = core::array::from_fn(|_| word(pick(inputs)));

            let bytes: [u8; 3 * 128] = inputs.bytes();

            let count = n % 4;

            let blocks = &bytes[..count * 16 * W::BYTES];

            let counter = match n % 3 {
                0 => 0,
                1 => u128::from(inputs.next()),
                _ => u128::MAX - 300,
            };

            let first = (n % 2 == 1).then_some(&first);

            let total = counter.wrapping_add(u128::from(inputs.next() % 1000));

            let last = (n % 5 != 0).then_some((&last, total));

            let mut expected = h;

            let size = 16 * W::BYTES as u128;

            let mut t = counter;

            if let Some(first) = first {
                t = t.wrapping_add(size);

                compress(&mut expected, first, t, false);
            }

            for block in blocks.chunks_exact(16 * W::BYTES) {
                let m: [W; 16] =
                    core::array::from_fn(|i| W::from_le(&block[i * W::BYTES..(i + 1) * W::BYTES]));

                t = t.wrapping_add(size);

                compress(&mut expected, &m, t, false);
            }

            if let Some((m, total)) = last {
                compress(&mut expected, m, total, true);
            }

            let mut actual = h;

            if W::kernel(&mut actual, first, blocks, counter, last) {
                assert!(actual == expected, "case {n}");

                accelerated += 1;
            }
        }

        accelerated
    }

    #[test]
    fn blake2_kernels_match_portable() {
        let mut inputs = Inputs::new(2);

        let b = kernel_matches::<u64>(&mut inputs, |x| x);

        let s = kernel_matches::<u32>(&mut inputs, |x| x as u32);

        std::eprintln!("BLAKE2b: {b} of 10000, BLAKE2s: {s} of 10000 cases through a CPU kernel");
    }

    // The one-shot digest and MAC against the engine fed in pieces, for lengths around the block
    // boundaries.
    fn one_shot_matches_engine<W: Word>() {
        let data: [u8; 3 * 128 + 5] = Inputs::new(9).bytes();

        let key: [u8; 64] = Inputs::new(10).bytes();

        let h = W::IV;

        for length in 0..data.len() {
            let message = &data[..length];

            for piece in [1, 7, 16 * W::BYTES, 16 * W::BYTES + 1] {
                let mut engine = Engine::new(&h);

                for chunk in message.chunks(piece) {
                    engine.update(chunk);
                }

                let (mut expected, mut actual) = ([0; 64], [0; 64]);

                engine.finish(&mut expected[..8 * W::BYTES]);

                digest(&h, message, &mut actual[..8 * W::BYTES]);

                assert!(expected == actual, "length {length}, piece {piece}");

                let key = &key[..1 + length % (8 * W::BYTES)];

                let mut engine = Engine::keyed(&h, key);

                for chunk in message.chunks(piece) {
                    engine.update(chunk);
                }

                engine.finish(&mut expected[..8 * W::BYTES]);

                mac(&h, key, message, &mut actual[..8 * W::BYTES]);

                assert!(expected == actual, "keyed, length {length}, piece {piece}");
            }
        }
    }

    #[test]
    fn one_shot_matches_engine_for_both() {
        one_shot_matches_engine::<u64>();

        one_shot_matches_engine::<u32>();
    }
}

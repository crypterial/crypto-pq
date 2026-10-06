use crate::cpu;
use crate::wipe::wipe;

pub(crate) const K256: [u32; 64] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
];

pub(crate) const K512: [u64; 80] = [
    0x428A2F98D728AE22,
    0x7137449123EF65CD,
    0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC,
    0x3956C25BF348B538,
    0x59F111F1B605D019,
    0x923F82A4AF194F9B,
    0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242,
    0x12835B0145706FBE,
    0x243185BE4EE4B28C,
    0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F,
    0x80DEB1FE3B1696B1,
    0x9BDC06A725C71235,
    0xC19BF174CF692694,
    0xE49B69C19EF14AD2,
    0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5,
    0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275,
    0x4A7484AA6EA6E483,
    0x5CB0A9DCBD41FBD4,
    0x76F988DA831153B5,
    0x983E5152EE66DFAB,
    0xA831C66D2DB43210,
    0xB00327C898FB213F,
    0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2,
    0xD5A79147930AA725,
    0x06CA6351E003826F,
    0x142929670A0E6E70,
    0x27B70A8546D22FFC,
    0x2E1B21385C26C926,
    0x4D2C6DFC5AC42AED,
    0x53380D139D95B3DF,
    0x650A73548BAF63DE,
    0x766A0ABB3C77B2A8,
    0x81C2C92E47EDAEE6,
    0x92722C851482353B,
    0xA2BFE8A14CF10364,
    0xA81A664BBC423001,
    0xC24B8B70D0F89791,
    0xC76C51A30654BE30,
    0xD192E819D6EF5218,
    0xD69906245565A910,
    0xF40E35855771202A,
    0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8,
    0x1E376C085141AB53,
    0x2748774CDF8EEB99,
    0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63,
    0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373,
    0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC,
    0x78A5636F43172F60,
    0x84C87814A1F0AB72,
    0x8CC702081A6439EC,
    0x90BEFFFA23631E28,
    0xA4506CEBDE82BDE9,
    0xBEF9A3F7B2C67915,
    0xC67178F2E372532B,
    0xCA273ECEEA26619C,
    0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E,
    0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA,
    0x0A637DC5A2C898A6,
    0x113F9804BEF90DAE,
    0x1B710B35131C471B,
    0x28DB77F523047D84,
    0x32CAAB7B40C72493,
    0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6,
    0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC,
    0x6C44198C4A475817,
];

pub(crate) const IV_224: [u32; 8] = [
    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939, 0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4,
];

pub(crate) const IV_256: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

pub(crate) const IV_384: [u64; 8] = [
    0xCBBB9D5DC1059ED8,
    0x629A292A367CD507,
    0x9159015A3070DD17,
    0x152FECD8F70E5939,
    0x67332667FFC00B31,
    0x8EB44A8768581511,
    0xDB0C2E0D64F98FA7,
    0x47B5481DBEFA4FA4,
];

pub(crate) const IV_512: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

pub(crate) const IV_512_224: [u64; 8] = [
    0x8C3D37C819544DA2,
    0x73E1996689DCD4D6,
    0x1DFAB7AE32FF9C82,
    0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8,
    0x77E36F7304C48942,
    0x3F9D85A86A1D36C8,
    0x1112E6AD91D692A1,
];

pub(crate) const IV_512_256: [u64; 8] = [
    0x22312194FC2BF72C,
    0x9F555FA3C84C64C2,
    0x2393B86B6F53B151,
    0x963877195940EABD,
    0x96283EE2A88EFFE3,
    0xBE5E1E2553863992,
    0x2B0199FC2C85B8AA,
    0x0EB72DDC81C52CA2,
];

#[derive(Clone)]
struct Blocks<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Blocks<N> {
    const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    // The whole blocks go to process in one call, so that a CPU kernel keeps the state in its
    // registers from one block to the next.
    fn update(&mut self, mut data: &[u8], mut process: impl FnMut(&[[u8; N]])) {
        if self.len > 0 {
            let take = (N - self.len).min(data.len());

            self.bytes[self.len..self.len + take].copy_from_slice(&data[..take]);

            self.len += take;

            data = &data[take..];

            if self.len < N {
                return;
            }

            process(core::slice::from_ref(&self.bytes));

            self.len = 0;
        }

        let (blocks, rest) = data.as_chunks::<N>();

        if !blocks.is_empty() {
            process(blocks);
        }

        self.bytes[..rest.len()].copy_from_slice(rest);

        self.len = rest.len();
    }

    // FIPS 180-4, 5.1: the 0x80 marker, zeros, then the message length in bits, big-endian.
    fn finish(&self, bits: &[u8], process: impl FnOnce(&[[u8; N]])) {
        let mut tail = [[0; N]; 2];

        tail[0][..self.len].copy_from_slice(&self.bytes[..self.len]);

        tail[0][self.len] = 0x80;

        let used = if self.len + 1 + bits.len() > N { 2 } else { 1 };

        tail[used - 1][N - bits.len()..].copy_from_slice(bits);

        process(&tail[..used]);

        wipe(tail.as_flattened_mut());
    }
}

impl<const N: usize> Drop for Blocks<N> {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

// One round, with the working variables passed in their rotated roles so that unrolled rounds
// never move values between them: only d and h receive new values.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn round256(a: u32, b: u32, c: u32, d: &mut u32, e: u32, f: u32, g: u32, h: &mut u32, kw: u32) {
    let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);

    let t1 = h
        .wrapping_add(kw)
        .wrapping_add((e & f) | (!e & g))
        .wrapping_add(s1);

    let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);

    *d = d.wrapping_add(t1);

    *h = s0.wrapping_add((a & b) | (c & (a | b))).wrapping_add(t1);
}

fn compress256(state: &mut [u32; 8], blocks: &[[u8; 64]], more: &[[u8; 64]]) {
    if cpu::compress256(state, blocks, more) {
        return;
    }

    for block in blocks.iter().chain(more) {
        compress256_block(state, block);
    }
}

// One block into each of two states, side by side: a lone stream waits on the latency of its
// rounds, which the other stream fills. HMAC's inner and outer key blocks are such a pair.
pub(crate) fn compress256_pair(states: &mut [[u32; 8]; 2], blocks: &[[u8; 64]; 2]) {
    if cpu::compress256_pair(states, blocks) {
        return;
    }

    let mut lanes: [[u32; 2]; 8] = core::array::from_fn(|i| [states[0][i], states[1][i]]);

    let words = blocks.each_ref().map(|block| block.as_chunks::<4>().0);

    let mut w: [[u32; 2]; 16] = core::array::from_fn(|t| {
        [
            u32::from_be_bytes(words[0][t]),
            u32::from_be_bytes(words[1][t]),
        ]
    });

    compress256_lanes(&mut lanes, &mut w);

    for (i, lane) in lanes.iter().enumerate() {
        states[0][i] = lane[0];

        states[1][i] = lane[1];
    }

    wipe(lanes.as_flattened_mut());

    wipe(w.as_flattened_mut());
}

// The words of a state as big-endian bytes, as many as out holds: a digest, or its truncation.
fn store256(state: &[u32; 8], out: &mut [u8]) {
    let (words, rest) = out.as_chunks_mut::<4>();

    for (bytes, word) in words.iter_mut().zip(state) {
        *bytes = word.to_be_bytes();
    }

    if let Some(word) = state.get(words.len()) {
        rest.copy_from_slice(&word.to_be_bytes()[..rest.len()]);
    }
}

fn store512(state: &[u64; 8], out: &mut [u8]) {
    let (words, rest) = out.as_chunks_mut::<8>();

    for (bytes, word) in words.iter_mut().zip(state) {
        *bytes = word.to_be_bytes();
    }

    if let Some(word) = state.get(words.len()) {
        rest.copy_from_slice(&word.to_be_bytes()[..rest.len()]);
    }
}

// The last `count` bytes of data, fewer than sixteen, as the low bytes of a little-endian value,
// read without a store: from the sixteen bytes that end data where it has them.
pub(crate) fn last_bytes(data: &[u8], count: usize) -> u128 {
    if count == 0 {
        return 0;
    }

    if let Some(window) = data.last_chunk::<16>() {
        return u128::from_le_bytes(*window) >> (8 * (16 - count));
    }

    data[data.len() - count..]
        .iter()
        .rev()
        .fold(0, |value, &byte| value << 8 | u128::from(byte))
}

// The padded last block or two (FIPS 180-4, 5.1) of a message that ends with data: the bytes of
// data after its whole blocks, the 0x80 marker, zeros, and the length field of `field` bytes, the
// message length in bits, at the end. Returns how many of the two blocks are used. Each 16-byte
// chunk gets a single store, which the compression's 16-byte load of it can forward: a chunk
// made of byte stores and read right away cost an Apple M3 tens of cycles.
fn pad<const BLOCK: usize>(
    data: &[u8],
    bits: u128,
    field: usize,
    last: &mut [[u8; BLOCK]; 2],
) -> usize {
    let tail = &data[data.len() - data.len() % BLOCK..];

    let used = if tail.len() + 1 + field > BLOCK { 2 } else { 1 };

    let chunks = last.as_flattened_mut().as_chunks_mut::<16>().0;

    let (whole, rest) = tail.as_chunks::<16>();

    for (chunk, bytes) in chunks.iter_mut().zip(whole) {
        *chunk = *bytes;
    }

    let mut marker = last_bytes(data, rest.len()) | 0x80 << (8 * rest.len());

    // The field's bytes are the last ones of the chunk, big-endian.
    let length = bits.swap_bytes() & (u128::MAX << (8 * (16 - field)));

    let end = used * BLOCK / 16 - 1;

    if whole.len() == end {
        marker |= length;
    } else {
        chunks[end] = length.to_le_bytes();
    }

    chunks[whole.len()] = marker.to_le_bytes();

    used
}

// The digest of `absorbed` bytes, whole blocks already compressed into state, followed by data,
// computed in one call: the whole blocks of data and the padding blocks go to the compression in
// one pass, without copying data into a block buffer. out receives the leading bytes of the
// digest.
pub(crate) fn finish256(state: &[u32; 8], absorbed: u64, data: &[u8], out: &mut [u8]) {
    let bits = absorbed.wrapping_add(data.len() as u64).wrapping_mul(8);

    let mut state = *state;

    if !cpu::finish256(&mut state, data, bits) {
        let mut last = [[0; 64]; 2];

        let used = pad(data, u128::from(bits), 8, &mut last);

        compress256(&mut state, data.as_chunks::<64>().0, &last[..used]);

        wipe(last.as_flattened_mut());
    }

    store256(&state, out);

    wipe(&mut state);
}

// finish256 for SHA-512, whose length field takes 16 bytes.
pub(crate) fn finish512(state: &[u64; 8], absorbed: u128, data: &[u8], out: &mut [u8]) {
    let bits = absorbed.wrapping_add(data.len() as u128).wrapping_mul(8);

    let mut state = *state;

    if !cpu::finish512(&mut state, data, bits) {
        let mut last = [[0; 128]; 2];

        let used = pad(data, bits, 16, &mut last);

        compress512(&mut state, data.as_chunks::<128>().0, &last[..used]);

        wipe(last.as_flattened_mut());
    }

    store512(&state, out);

    wipe(&mut state);
}

// HMAC (RFC 2104) keys: the key, at most a block, padded with zeros to a block and XORed with
// 0x36 for the inner hash and with 0x5C for the outer one.
fn pads<const BLOCK: usize>(key: &[u8]) -> [[u8; BLOCK]; 2] {
    let mut pads = [[0x36; BLOCK], [0x5C; BLOCK]];

    for pad in &mut pads {
        for (byte, key) in pad.iter_mut().zip(key) {
            *byte ^= key;
        }
    }

    pads
}

// The states after HMAC's inner and outer key blocks, compressed side by side.
pub(crate) fn keyed256(iv: &[u32; 8], key: &[u8]) -> [[u32; 8]; 2] {
    let mut pads = pads::<64>(key);

    let mut states = [*iv; 2];

    compress256_pair(&mut states, &pads);

    wipe(pads.as_flattened_mut());

    states
}

pub(crate) fn keyed512(iv: &[u64; 8], key: &[u8]) -> [[u64; 8]; 2] {
    let mut pads = pads::<128>(key);

    let mut states = [*iv; 2];

    compress512_pair(&mut states, &pads);

    wipe(pads.as_flattened_mut());

    states
}

// HMAC-SHA-256, or HMAC-SHA-224 for a 28-byte tag, under a key of at most a block.
pub(crate) fn hmac256(iv: &[u32; 8], key: &[u8], data: &[u8], tag: &mut [u8]) {
    if cpu::hmac256(iv, key, data, tag) {
        return;
    }

    let mut keyed = keyed256(iv, key);

    let mut inner = [0; 32];

    finish256(&keyed[0], 64, data, &mut inner[..tag.len()]);

    finish256(&keyed[1], 64, &inner[..tag.len()], tag);

    wipe(&mut inner);

    wipe(keyed.as_flattened_mut());
}

// HMAC-SHA-256 or HMAC-SHA-224 from the states after the inner and the outer key block, for
// many messages under one key.
pub(crate) fn hmac256_keyed(keyed: &[[u32; 8]; 2], data: &[u8], tag: &mut [u8]) {
    if cpu::hmac256_keyed(keyed, data, tag) {
        return;
    }

    let mut inner = [0; 32];

    finish256(&keyed[0], 64, data, &mut inner[..tag.len()]);

    finish256(&keyed[1], 64, &inner[..tag.len()], tag);

    wipe(&mut inner);
}

pub(crate) fn hmac512_keyed(keyed: &[[u64; 8]; 2], data: &[u8], tag: &mut [u8]) {
    if cpu::hmac512_keyed(keyed, data, tag) {
        return;
    }

    let mut inner = [0; 64];

    finish512(&keyed[0], 128, data, &mut inner[..tag.len()]);

    finish512(&keyed[1], 128, &inner[..tag.len()], tag);

    wipe(&mut inner);
}

// HMAC-SHA-512, or HMAC-SHA-384 for a 48-byte tag, under a key of at most a block.
pub(crate) fn hmac512(iv: &[u64; 8], key: &[u8], data: &[u8], tag: &mut [u8]) {
    if cpu::hmac512(iv, key, data, tag) {
        return;
    }

    let mut keyed = keyed512(iv, key);

    let mut inner = [0; 64];

    finish512(&keyed[0], 128, data, &mut inner[..tag.len()]);

    finish512(&keyed[1], 128, &inner[..tag.len()], tag);

    wipe(&mut inner);

    wipe(keyed.as_flattened_mut());
}

fn compress256_block(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 16];

    for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*bytes);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    // The schedule keeps its last 16 words: word t lives at t % 16, so t - 15, t - 7 and t - 2
    // are at (t + 1) % 16, (t + 9) % 16 and (t + 14) % 16, and t - 16 is the slot it replaces.
    for start in (0..64).step_by(8) {
        let mut kw = [0; 8];

        for (j, kw) in kw.iter_mut().enumerate() {
            let t = start + j;

            if t >= 16 {
                let (x, y) = (w[(t + 1) % 16], w[(t + 14) % 16]);

                let s0 = x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);

                let s1 = y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10);

                w[t % 16] = w[t % 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[(t + 9) % 16])
                    .wrapping_add(s1);
            }

            *kw = w[t % 16].wrapping_add(K256[t]);
        }

        round256(a, b, c, &mut d, e, f, g, &mut h, kw[0]);

        round256(h, a, b, &mut c, d, e, f, &mut g, kw[1]);

        round256(g, h, a, &mut b, c, d, e, &mut f, kw[2]);

        round256(f, g, h, &mut a, b, c, d, &mut e, kw[3]);

        round256(e, f, g, &mut h, a, b, c, &mut d, kw[4]);

        round256(d, e, f, &mut g, h, a, b, &mut c, kw[5]);

        round256(c, d, e, &mut f, g, h, a, &mut b, kw[6]);

        round256(b, c, d, &mut e, f, g, h, &mut a, kw[7]);
    }

    for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *word = word.wrapping_add(value);
    }
}

// LANES independent compressions side by side, each variable holding one word of every lane, so
// that the compiler interleaves or vectorizes them: a single SHA-256 is bound by the latency of
// its rounds, not by the arithmetic units.
type Lanes<const LANES: usize> = [u32; LANES];

#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn round256_lanes<const LANES: usize>(
    a: &Lanes<LANES>,
    b: &Lanes<LANES>,
    c: &Lanes<LANES>,
    d: &mut Lanes<LANES>,
    e: &Lanes<LANES>,
    f: &Lanes<LANES>,
    g: &Lanes<LANES>,
    h: &mut Lanes<LANES>,
    k: u32,
    w: &Lanes<LANES>,
) {
    let s1: Lanes<LANES> = core::array::from_fn(|i| {
        e[i].rotate_right(6) ^ e[i].rotate_right(11) ^ e[i].rotate_right(25)
    });

    let s0: Lanes<LANES> = core::array::from_fn(|i| {
        a[i].rotate_right(2) ^ a[i].rotate_right(13) ^ a[i].rotate_right(22)
    });

    for i in 0..LANES {
        let t1 = h[i]
            .wrapping_add(k)
            .wrapping_add(w[i])
            .wrapping_add((e[i] & f[i]) | (!e[i] & g[i]))
            .wrapping_add(s1[i]);

        d[i] = d[i].wrapping_add(t1);

        h[i] = s0[i]
            .wrapping_add((a[i] & b[i]) | (c[i] & (a[i] | b[i])))
            .wrapping_add(t1);
    }
}

// The states and the blocks are word-major: states[i][lane] is word i of the state of that lane.
// The schedule may overwrite the blocks.
fn compress256_lanes<const LANES: usize>(
    states: &mut [Lanes<LANES>; 8],
    w: &mut [Lanes<LANES>; 16],
) {
    if !cpu::compress256_lanes(states, w) {
        compress256_lanes_portable(states, w);
    }
}

// Always inlined, so that a caller built for wider vectors (x86-64 AVX2) vectorizes it for them.
#[inline(always)]
pub(crate) fn compress256_lanes_portable<const LANES: usize>(
    states: &mut [Lanes<LANES>; 8],
    w: &mut [Lanes<LANES>; 16],
) {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *states;

    for (round, k) in K256.as_chunks::<16>().0.iter().enumerate() {
        if round > 0 {
            for t in 0..16 {
                let (x, y, z) = (w[(t + 1) % 16], w[(t + 14) % 16], w[(t + 9) % 16]);

                for (lane, word) in w[t].iter_mut().enumerate() {
                    let s0 = x[lane].rotate_right(7) ^ x[lane].rotate_right(18) ^ (x[lane] >> 3);

                    let s1 = y[lane].rotate_right(17) ^ y[lane].rotate_right(19) ^ (y[lane] >> 10);

                    *word = word.wrapping_add(s0).wrapping_add(z[lane]).wrapping_add(s1);
                }
            }
        }

        round256_lanes(&a, &b, &c, &mut d, &e, &f, &g, &mut h, k[0], &w[0]);

        round256_lanes(&h, &a, &b, &mut c, &d, &e, &f, &mut g, k[1], &w[1]);

        round256_lanes(&g, &h, &a, &mut b, &c, &d, &e, &mut f, k[2], &w[2]);

        round256_lanes(&f, &g, &h, &mut a, &b, &c, &d, &mut e, k[3], &w[3]);

        round256_lanes(&e, &f, &g, &mut h, &a, &b, &c, &mut d, k[4], &w[4]);

        round256_lanes(&d, &e, &f, &mut g, &h, &a, &b, &mut c, k[5], &w[5]);

        round256_lanes(&c, &d, &e, &mut f, &g, &h, &a, &mut b, k[6], &w[6]);

        round256_lanes(&b, &c, &d, &mut e, &f, &g, &h, &mut a, k[7], &w[7]);

        round256_lanes(&a, &b, &c, &mut d, &e, &f, &g, &mut h, k[8], &w[8]);

        round256_lanes(&h, &a, &b, &mut c, &d, &e, &f, &mut g, k[9], &w[9]);

        round256_lanes(&g, &h, &a, &mut b, &c, &d, &e, &mut f, k[10], &w[10]);

        round256_lanes(&f, &g, &h, &mut a, &b, &c, &d, &mut e, k[11], &w[11]);

        round256_lanes(&e, &f, &g, &mut h, &a, &b, &c, &mut d, k[12], &w[12]);

        round256_lanes(&d, &e, &f, &mut g, &h, &a, &b, &mut c, k[13], &w[13]);

        round256_lanes(&c, &d, &e, &mut f, &g, &h, &a, &mut b, k[14], &w[14]);

        round256_lanes(&b, &c, &d, &mut e, &f, &g, &h, &mut a, k[15], &w[15]);
    }

    let words = [a, b, c, d, e, f, g, h];

    for (state, value) in states.iter_mut().zip(&words) {
        for (word, value) in state.iter_mut().zip(value) {
            *word = word.wrapping_add(*value);
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn round512(a: u64, b: u64, c: u64, d: &mut u64, e: u64, f: u64, g: u64, h: &mut u64, kw: u64) {
    let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);

    let t1 = h
        .wrapping_add(kw)
        .wrapping_add((e & f) | (!e & g))
        .wrapping_add(s1);

    let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);

    *d = d.wrapping_add(t1);

    *h = s0.wrapping_add((a & b) | (c & (a | b))).wrapping_add(t1);
}

fn compress512(state: &mut [u64; 8], blocks: &[[u8; 128]], more: &[[u8; 128]]) {
    if cpu::compress512(state, blocks, more) {
        return;
    }

    for block in blocks.iter().chain(more) {
        compress512_block(state, block);
    }
}

// compress256_pair for SHA-512.
pub(crate) fn compress512_pair(states: &mut [[u64; 8]; 2], blocks: &[[u8; 128]; 2]) {
    if cpu::compress512_pair(states, blocks) {
        return;
    }

    for (state, block) in states.iter_mut().zip(blocks) {
        compress512(state, core::slice::from_ref(block), &[]);
    }
}

// Never inlined: inlined into compress512, its frame and register saves came with every call, the
// kernel's included, and cost a one-block SHA-512 about 30 ns on an Apple M3.
#[inline(never)]
fn compress512_block(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 16];

    for (word, bytes) in w.iter_mut().zip(block.as_chunks::<8>().0) {
        *word = u64::from_be_bytes(*bytes);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    // The same rolling schedule as SHA-256.
    for start in (0..80).step_by(8) {
        let mut kw = [0; 8];

        for (j, kw) in kw.iter_mut().enumerate() {
            let t = start + j;

            if t >= 16 {
                let (x, y) = (w[(t + 1) % 16], w[(t + 14) % 16]);

                let s0 = x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7);

                let s1 = y.rotate_right(19) ^ y.rotate_right(61) ^ (y >> 6);

                w[t % 16] = w[t % 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[(t + 9) % 16])
                    .wrapping_add(s1);
            }

            *kw = w[t % 16].wrapping_add(K512[t]);
        }

        round512(a, b, c, &mut d, e, f, g, &mut h, kw[0]);

        round512(h, a, b, &mut c, d, e, f, &mut g, kw[1]);

        round512(g, h, a, &mut b, c, d, e, &mut f, kw[2]);

        round512(f, g, h, &mut a, b, c, d, &mut e, kw[3]);

        round512(e, f, g, &mut h, a, b, c, &mut d, kw[4]);

        round512(d, e, f, &mut g, h, a, b, &mut c, kw[5]);

        round512(c, d, e, &mut f, g, h, a, &mut b, kw[6]);

        round512(b, c, d, &mut e, f, g, h, &mut a, kw[7]);
    }

    for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *word = word.wrapping_add(value);
    }
}

#[derive(Clone)]
pub(crate) struct Sha256 {
    state: [u32; 8],
    blocks: Blocks<64>,
    length: u64,
}

impl Sha256 {
    pub(crate) const fn new(iv: &[u32; 8]) -> Self {
        Self::resume(*iv, 0)
    }

    // An engine whose first `absorbed` bytes, whole blocks, are already compressed into state.
    pub(crate) const fn resume(state: [u32; 8], absorbed: u64) -> Self {
        Self {
            state,
            blocks: Blocks::new(),
            length: absorbed,
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);

        let state = &mut self.state;

        self.blocks
            .update(data, |blocks| compress256(state, blocks, &[]));
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut out = [0; 32];

        self.digest_into(&mut out);

        out
    }

    // The leading out.len() bytes of the digest.
    pub(crate) fn digest_into(&self, out: &mut [u8]) {
        let mut state = self.state;

        let bits = self.length.wrapping_mul(8).to_be_bytes();

        self.blocks
            .finish(&bits, |blocks| compress256(&mut state, blocks, &[]));

        store256(&state, out);

        wipe(&mut state);
    }

    // finish_lanes for messages whose padded last block the caller has already built as words,
    // word-major (blocks[t][lane]); returns the final states, word-major too. The blocks are
    // overwritten.
    pub(crate) fn finish_words<const LANES: usize>(
        &self,
        blocks: &mut [[u32; LANES]; 16],
    ) -> [[u32; LANES]; 8] {
        assert_eq!(
            self.blocks.len, 0,
            "the shared input must fill whole blocks"
        );

        let mut states = self.state.map(|word| [word; LANES]);

        compress256_lanes(&mut states, blocks);

        states
    }

    // The digests of LANES messages of `length` bytes, each appended to the input so far, which
    // must fill whole blocks. Hashes that share a prefix, such as a public seed, pay for it once
    // and run side by side. The message buffers receive the padding and are wiped.
    pub(crate) fn finish_lanes<const LANES: usize, const SIZE: usize>(
        &self,
        messages: &mut [[u8; SIZE]; LANES],
        length: usize,
    ) -> [[u8; 32]; LANES] {
        assert_eq!(
            self.blocks.len, 0,
            "the shared input must fill whole blocks"
        );

        let end = (length + 9).next_multiple_of(64);

        let bits = self.length.wrapping_add(length as u64).wrapping_mul(8);

        for message in messages.iter_mut() {
            message[length..end].fill(0);

            message[length] = 0x80;

            message[end - 8..end].copy_from_slice(&bits.to_be_bytes());
        }

        let mut states = self.state.map(|word| [word; LANES]);

        let mut words = [[0; LANES]; 16];

        for offset in (0..end).step_by(64) {
            for (lane, message) in messages.iter().enumerate() {
                let block = message[offset..offset + 64].as_chunks::<4>().0;

                for (words, bytes) in words.iter_mut().zip(block) {
                    words[lane] = u32::from_be_bytes(*bytes);
                }
            }

            compress256_lanes(&mut states, &mut words);
        }

        let mut digests = [[0; 32]; LANES];

        for (lane, digest) in digests.iter_mut().enumerate() {
            for (bytes, state) in digest.as_chunks_mut::<4>().0.iter_mut().zip(&states) {
                *bytes = state[lane].to_be_bytes();
            }
        }

        wipe(messages.as_flattened_mut());

        wipe(states.as_flattened_mut());

        wipe(words.as_flattened_mut());

        digests
    }
}

#[derive(Clone)]
pub(crate) struct Sha512 {
    state: [u64; 8],
    blocks: Blocks<128>,
    length: u128,
}

impl Sha512 {
    pub(crate) const fn new(iv: &[u64; 8]) -> Self {
        Self::resume(*iv, 0)
    }

    // Sha256::resume.
    pub(crate) const fn resume(state: [u64; 8], absorbed: u128) -> Self {
        Self {
            state,
            blocks: Blocks::new(),
            length: absorbed,
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u128);

        let state = &mut self.state;

        self.blocks
            .update(data, |blocks| compress512(state, blocks, &[]));
    }

    pub(crate) fn digest(&self) -> [u8; 64] {
        let mut out = [0; 64];

        self.digest_into(&mut out);

        out
    }

    pub(crate) fn digest_into(&self, out: &mut [u8]) {
        let mut state = self.state;

        let bits = self.length.wrapping_mul(8).to_be_bytes();

        self.blocks
            .finish(&bits, |blocks| compress512(&mut state, blocks, &[]));

        store512(&state, out);

        wipe(&mut state);
    }

    // Sha256::finish_lanes for one message.
    pub(crate) fn finish_message<const SIZE: usize>(
        &self,
        message: &mut [u8; SIZE],
        length: usize,
    ) -> [u8; 64] {
        assert_eq!(
            self.blocks.len, 0,
            "the shared input must fill whole blocks"
        );

        let end = (length + 17).next_multiple_of(128);

        let bits = self.length.wrapping_add(length as u128).wrapping_mul(8);

        message[length..end].fill(0);

        message[length] = 0x80;

        message[end - 16..end].copy_from_slice(&bits.to_be_bytes());

        let mut state = self.state;

        compress512(&mut state, message[..end].as_chunks::<128>().0, &[]);

        let mut out = [0; 64];

        store512(&state, &mut out);

        wipe(message);

        wipe(&mut state);

        out
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        wipe(&mut self.state);
    }
}

impl Drop for Sha512 {
    fn drop(&mut self) {
        wipe(&mut self.state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::testing::{EDGES, Inputs};

    const CASES: usize = 20_000;

    // Each case is a state and up to three blocks: every combination of edge patterns first,
    // then random ones. Where neither the build nor the CPU has a kernel, the cpu functions
    // return false and only the portable code runs.
    fn case<const W: usize, T: Copy, const B: usize>(
        inputs: &mut Inputs,
        case: usize,
        word: impl Fn(u64) -> T,
    ) -> ([T; W], [[u8; B]; 3]) {
        match case.checked_sub(EDGES.len() * EDGES.len()) {
            None => {
                let (state, block) = (EDGES[case / EDGES.len()], EDGES[case % EDGES.len()]);

                ([word(state); W], [[block as u8; B]; 3])
            }
            Some(_) => (
                inputs.words::<W>().map(word),
                [inputs.bytes(), inputs.bytes(), inputs.bytes()],
            ),
        }
    }

    #[test]
    fn sha256_kernel_matches_portable() {
        let mut inputs = Inputs::new(256);

        let mut accelerated = 0;

        for n in 0..CASES {
            let (state, blocks) = case::<8, u32, 64>(&mut inputs, n, |x| x as u32);

            let blocks = &blocks[..1 + n % 3];

            let mut expected = state;

            for block in blocks {
                compress256_block(&mut expected, block);
            }

            let mut actual = state;

            // The blocks as one stream from two slices, split at every point in turn.
            let (first, more) = blocks.split_at(n / 3 % (blocks.len() + 1));

            if cpu::compress256(&mut actual, first, more) {
                assert_eq!(actual, expected, "case {n}");

                accelerated += 1;
            }
        }

        std::eprintln!("SHA-256: {accelerated} of {CASES} cases through a CPU kernel");
    }

    fn lanes_match<const LANES: usize>(inputs: &mut Inputs, cases: usize) -> usize {
        let mut accelerated = 0;

        for n in 0..cases {
            let edge = n < EDGES.len() * EDGES.len();

            let mut states = [[0u32; LANES]; 8];

            let mut w = [[0u32; LANES]; 16];

            for word in states.as_flattened_mut() {
                *word = if edge {
                    EDGES[n / EDGES.len()] as u32
                } else {
                    inputs.next() as u32
                };
            }

            for word in w.as_flattened_mut() {
                *word = if edge {
                    EDGES[n % EDGES.len()] as u32
                } else {
                    inputs.next() as u32
                };
            }

            let mut expected = states;

            compress256_lanes_portable(&mut expected, &mut w.clone());

            let mut actual = states;

            if cpu::compress256_lanes(&mut actual, &mut w) {
                assert_eq!(actual, expected, "{LANES} lanes, case {n}");

                accelerated += 1;
            }
        }

        accelerated
    }

    #[test]
    fn sha256_lane_kernel_matches_portable() {
        let mut inputs = Inputs::new(16);

        let accelerated = lanes_match::<1>(&mut inputs, 4_000)
            + lanes_match::<2>(&mut inputs, 4_000)
            + lanes_match::<3>(&mut inputs, 4_000)
            + lanes_match::<4>(&mut inputs, 4_000)
            + lanes_match::<16>(&mut inputs, 4_000);

        std::eprintln!("SHA-256 lanes: {accelerated} of 20000 cases through a CPU kernel");
    }

    #[test]
    fn sha512_kernel_matches_portable() {
        let mut inputs = Inputs::new(512);

        let mut accelerated = 0;

        for n in 0..CASES {
            let (state, blocks) = case::<8, u64, 128>(&mut inputs, n, |x| x);

            let blocks = &blocks[..1 + n % 3];

            let mut expected = state;

            for block in blocks {
                compress512_block(&mut expected, block);
            }

            let mut actual = state;

            let (first, more) = blocks.split_at(n / 3 % (blocks.len() + 1));

            if cpu::compress512(&mut actual, first, more) {
                assert_eq!(actual, expected, "case {n}");

                accelerated += 1;
            }
        }

        std::eprintln!("SHA-512: {accelerated} of {CASES} cases through a CPU kernel");
    }

    // The pairs against two lone compressions, through a kernel or through the fallback.
    #[test]
    fn pairs_match_lone_compressions() {
        let mut inputs = Inputs::new(2);

        for n in 0..4_000 {
            let (first, blocks) = case::<8, u32, 64>(&mut inputs, n, |x| x as u32);

            let mut states = [first, inputs.words::<8>().map(|x| x as u32)];

            let pair = [blocks[0], blocks[1]];

            let mut expected = states;

            for (state, block) in expected.iter_mut().zip(&pair) {
                compress256_block(state, block);
            }

            compress256_pair(&mut states, &pair);

            assert_eq!(states, expected, "SHA-256 case {n}");

            let (first, blocks) = case::<8, u64, 128>(&mut inputs, n, |x| x);

            let mut states = [first, inputs.words::<8>()];

            let pair = [blocks[0], blocks[2]];

            let mut expected = states;

            for (state, block) in expected.iter_mut().zip(&pair) {
                compress512_block(state, block);
            }

            compress512_pair(&mut states, &pair);

            assert_eq!(states, expected, "SHA-512 case {n}");
        }
    }

    // The one-shot finish against the incremental engine, for every tail length around the
    // padding boundaries, from a state that has absorbed a block or none.
    #[test]
    fn finish_matches_engine() {
        let data: [u8; 3 * 128 + 1] = Inputs::new(3).bytes();

        for length in 0..data.len() {
            let message = &data[..length];

            let mut engine = Sha256::new(&IV_256);

            engine.update(&data[..64]);

            let state = engine.state;

            engine.update(message);

            let mut out = [0; 32];

            finish256(&state, 64, message, &mut out);

            assert_eq!(
                out,
                engine.digest(),
                "SHA-256 after a block, length {length}"
            );

            let mut truncated = [0; 28];

            finish256(&IV_224, 0, message, &mut truncated);

            let mut whole = Sha256::new(&IV_224);

            whole.update(message);

            assert_eq!(truncated, whole.digest()[..28], "SHA-224, length {length}");

            let mut engine = Sha512::new(&IV_512);

            engine.update(&data[..128]);

            let state = engine.state;

            engine.update(message);

            let mut out = [0; 64];

            finish512(&state, 128, message, &mut out);

            assert_eq!(
                out,
                engine.digest(),
                "SHA-512 after a block, length {length}"
            );

            let mut truncated = [0; 28];

            finish512(&IV_512_224, 0, message, &mut truncated);

            let mut whole = Sha512::new(&IV_512_224);

            whole.update(message);

            assert_eq!(
                truncated,
                whole.digest()[..28],
                "SHA-512/224, length {length}"
            );
        }
    }

    // The one-call HMAC kernels against the key states and the finish of the generic path, for
    // every key length up to a block, data lengths around the padding boundaries and every tag
    // size. Where there is no kernel, the cpu functions return false.
    #[test]
    fn hmac_kernels_match_generic() {
        let bytes: [u8; 400] = Inputs::new(5).bytes();

        let mut accelerated = 0;

        for (n, key_length) in (0..=128).enumerate() {
            let data = &bytes[128..128 + [0, 1, 55, 56, 64, 111, 112, 128, 200, 260][n % 10]];

            for (iv, size) in [(&IV_256, 32), (&IV_224, 28)] {
                let key = &bytes[..key_length.min(64)];

                let keyed = keyed256(iv, key);

                let (mut inner, mut expected) = ([0; 32], [0; 32]);

                finish256(&keyed[0], 64, data, &mut inner[..size]);

                finish256(&keyed[1], 64, &inner[..size], &mut expected[..size]);

                let mut tag = [0; 32];

                if cpu::hmac256(iv, key, data, &mut tag[..size]) {
                    assert_eq!(tag, expected, "key {key_length}, size {size}");

                    accelerated += 1;
                }

                let mut tag = [0; 32];

                if cpu::hmac256_keyed(&keyed, data, &mut tag[..size]) {
                    assert_eq!(tag, expected, "keyed, key {key_length}, size {size}");

                    accelerated += 1;
                }
            }

            for (iv, size) in [(&IV_512, 64), (&IV_384, 48)] {
                let key = &bytes[..key_length];

                let keyed = keyed512(iv, key);

                let (mut inner, mut expected) = ([0; 64], [0; 64]);

                finish512(&keyed[0], 128, data, &mut inner[..size]);

                finish512(&keyed[1], 128, &inner[..size], &mut expected[..size]);

                let mut tag = [0; 64];

                if cpu::hmac512(iv, key, data, &mut tag[..size]) {
                    assert_eq!(tag, expected, "key {key_length}, size {size}");

                    accelerated += 1;
                }

                let mut tag = [0; 64];

                if cpu::hmac512_keyed(&keyed, data, &mut tag[..size]) {
                    assert_eq!(tag, expected, "keyed, key {key_length}, size {size}");

                    accelerated += 1;
                }
            }
        }

        std::eprintln!("HMAC: {accelerated} of 1032 cases through a CPU kernel");
    }
}

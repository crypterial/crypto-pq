// BLAKE2b and BLAKE2s (RFC 7693) in sequential mode, with the salt and personalization fields of
// the BLAKE2 specification (2.8). A chaining value starts as the IV XORed with the parameter block,
// which configure computes once; a key is zero-padded to a block and processed as the first block.
// The final block, the only one with the final flag, is given as words: built with word stores, it
// is loaded with word loads, which store-to-load forwarding serves.

use core::ops::{BitXor, Not};

use crate::cpu;
#[cfg(any(test, target_family = "wasm"))]
use crate::sha2::copy_in_line;
use crate::sha2::{IV_256, IV_512, last_bytes};
#[cfg(any(test, target_family = "wasm", target_arch = "arm"))]
use crate::wipe::registers;
use crate::wipe::{wipe, wipe_unless_optimized};

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

// What the CPU kernel of a digest or a MAC did: all the work (Done), or none, leaving it to process
// (Blocks), whose CPU kernel may take the blocks, or to the portable code that its dispatcher chose
// (Portable), so that one read of the CPU's features serves the message. Done and Portable come
// from the x86-64 kernels only.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) enum Kernel {
    Done,
    Blocks,
    Portable,
}

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

    // The word into out, BYTES bytes, little-endian.
    fn write_le(self, out: &mut [u8]);

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

    // The CPU kernel of digest.
    fn digest_kernel(h: &[Self; 8], data: &[u8], out: &mut [u8]) -> Kernel;

    // The CPU kernel of mac, from the unkeyed chaining value: the kernel puts the key's length in,
    // in registers.
    fn mac_kernel(h: &[Self; 8], key: &[u8], data: &[u8], out: &mut [u8]) -> Kernel;

    // The rounds of compress on pairs of words, where BLAKE2b runs them so, which returns whether
    // it did them.
    #[inline(always)]
    fn pair_rounds(_: &mut [Self; 8], _: &[Self; 16], _: u128, _: bool) -> bool {
        false
    }
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
    fn write_le(self, out: &mut [u8]) {
        out.copy_from_slice(&self.to_le_bytes());
    }

    #[inline(always)]
    fn from_value(value: u128) -> Self {
        value as Self
    }

    #[inline(always)]
    fn store(h: &[Self; 8], out: &mut [u8]) {
        // The whole chaining value and half of it (BLAKE2b-256) at a size the compiler knows, as
        // stores, where the size of out took a call of memcpy.
        if let Ok(whole) = <&mut [u8; 64]>::try_from(&mut *out) {
            store_fixed(h, whole);
        } else if let Ok(half) = <&mut [u8; 32]>::try_from(&mut *out) {
            store_fixed(h, half);
        } else {
            store_any(h, out);
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

    #[inline(always)]
    fn digest_kernel(h: &[Self; 8], data: &[u8], out: &mut [u8]) -> Kernel {
        cpu::blake2b_digest(h, data, out)
    }

    #[inline(always)]
    fn mac_kernel(h: &[Self; 8], key: &[u8], data: &[u8], out: &mut [u8]) -> Kernel {
        cpu::blake2b_mac(h, key, data, out)
    }

    #[cfg(crypto_pq_pairs)]
    #[inline(always)]
    fn pair_rounds(h: &mut [Self; 8], m: &[Self; 16], counter: u128, last: bool) -> bool {
        rounds_pair(h, m, counter, last);

        true
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
    fn write_le(self, out: &mut [u8]) {
        out.copy_from_slice(&self.to_le_bytes());
    }

    #[inline(always)]
    fn from_value(value: u128) -> Self {
        value as Self
    }

    #[inline(always)]
    fn store(h: &[Self; 8], out: &mut [u8]) {
        // The whole chaining value at a size the compiler knows, as stores, where the size of out
        // took a call of memcpy.
        if let Ok(whole) = <&mut [u8; 32]>::try_from(&mut *out) {
            store_fixed(h, whole);
        } else {
            store_any(h, out);
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

    #[inline(always)]
    fn digest_kernel(h: &[Self; 8], data: &[u8], out: &mut [u8]) -> Kernel {
        cpu::blake2s_digest(h, data, out)
    }

    #[inline(always)]
    fn mac_kernel(h: &[Self; 8], key: &[u8], data: &[u8], out: &mut [u8]) -> Kernel {
        cpu::blake2s_mac(h, key, data, out)
    }
}

// The leading N bytes of the chaining value, N a multiple of the word size.
#[inline(always)]
fn store_fixed<W: Word, const N: usize>(h: &[W; 8], out: &mut [u8; N]) {
    for (bytes, word) in out.chunks_exact_mut(W::BYTES).zip(h) {
        word.write_le(bytes);
    }
}

// The leading out.len() bytes of the chaining value, of any length up to the whole: the last
// partial word only where there is one, as its copy is a call of memcpy.
#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn store_any<W: Word>(h: &[W; 8], out: &mut [u8]) {
    let partial = h.get(out.len() / W::BYTES);

    let mut chunks = out.chunks_exact_mut(W::BYTES);

    for (bytes, word) in chunks.by_ref().zip(h) {
        word.write_le(bytes);
    }

    let rest = chunks.into_remainder();

    if let Some(word) = partial
        && !rest.is_empty()
    {
        let mut bytes = [0; 8];

        word.write_le(&mut bytes[..W::BYTES]);

        rest.copy_from_slice(&bytes[..rest.len()]);

        wipe(&mut bytes);
    }
}

#[cfg(target_arch = "arm")]
use store_in_locals as store_any;

// store_any with no run-time index into h, which stays in locals, and a frame only for a partial word.
#[cfg(any(test, target_arch = "arm"))]
#[inline(always)]
fn store_in_locals<W: Word>(h: &[W; 8], out: &mut [u8]) {
    let mut chunks = out.chunks_exact_mut(W::BYTES);

    for &word in h {
        let Some(bytes) = chunks.next() else {
            let rest = chunks.into_remainder();

            if !rest.is_empty() {
                store_partial(word, rest);
            }

            return;
        };

        word.write_le(bytes);
    }
}

#[cfg(any(test, target_arch = "arm"))]
#[inline(never)]
fn store_partial<W: Word>(word: W, rest: &mut [u8]) {
    let mut bytes = [0; 8];

    word.write_le(&mut bytes[..W::BYTES]);

    rest.copy_from_slice(&bytes[..rest.len()]);

    wipe(&mut bytes);
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

// The four G functions of a step side by side, each of g's operations for all four in turn, so
// that the four independent chains are interleaved in the code.
#[inline(always)]
fn step<W: Word>(v: &mut [W; 16], lanes: [[usize; 4]; 4], x: [W; 4], y: [W; 4]) {
    let [r1, r2, r3, r4] = W::ROTATIONS;

    for k in 0..4 {
        let [a, b, _, _] = lanes[k];

        v[a] = v[a].add(x[k]).add(v[b]);
    }

    for [a, _, _, d] in lanes {
        v[d] = (v[d] ^ v[a]).rotate(r1);
    }

    for [_, _, c, d] in lanes {
        v[c] = v[c].add(v[d]);
    }

    for [_, b, c, _] in lanes {
        v[b] = (v[b] ^ v[c]).rotate(r2);
    }

    for k in 0..4 {
        let [a, b, _, _] = lanes[k];

        v[a] = v[a].add(y[k]).add(v[b]);
    }

    for [a, _, _, d] in lanes {
        v[d] = (v[d] ^ v[a]).rotate(r3);
    }

    for [_, _, c, d] in lanes {
        v[c] = v[c].add(v[d]);
    }

    for [_, b, c, _] in lanes {
        v[b] = (v[b] ^ v[c]).rotate(r4);
    }
}

// On x86-64 the G functions of a step side by side: one after another, each chain came as a run
// of dependent instructions, which filled the scheduler of an AMD Zen core (llvm-mca, Zen 4, one
// compression: BLAKE2b 436 against 398 cycles, BLAKE2s 408 against 321). On ARM64 they go one
// after another, which llvm-mca puts level or up to 4% ahead on Neoverse N1, V1 and V2.
#[inline(always)]
fn round<W: Word>(v: &mut [W; 16], m: &[W; 16], s: &[usize; 16]) {
    if cfg!(target_arch = "x86_64") {
        step(
            v,
            [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]],
            [m[s[0]], m[s[2]], m[s[4]], m[s[6]]],
            [m[s[1]], m[s[3]], m[s[5]], m[s[7]]],
        );

        step(
            v,
            [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]],
            [m[s[8]], m[s[10]], m[s[12]], m[s[14]]],
            [m[s[9]], m[s[11]], m[s[13]], m[s[15]]],
        );

        return;
    }

    g(v, [0, 4, 8, 12], m[s[0]], m[s[1]]);

    g(v, [1, 5, 9, 13], m[s[2]], m[s[3]]);

    g(v, [2, 6, 10, 14], m[s[4]], m[s[5]]);

    g(v, [3, 7, 11, 15], m[s[6]], m[s[7]]);

    g(v, [0, 5, 10, 15], m[s[8]], m[s[9]]);

    g(v, [1, 6, 11, 12], m[s[10]], m[s[11]]);

    g(v, [2, 7, 8, 13], m[s[12]], m[s[13]]);

    g(v, [3, 4, 9, 14], m[s[14]], m[s[15]]);
}

// The compression function F of RFC 7693, 3.2, for one block of message words. Out of line, as
// before the loop of whole blocks took its own copy of the rounds.
#[inline(never)]
pub(crate) fn compress<W: Word>(h: &mut [W; 8], m: &[W; 16], counter: u128, last: bool) {
    rounds(h, m, counter, last);
}

// Whether each block on WebAssembly takes a call of the rounds, with the chaining value in memory.
// Under Cranelift, which compiles WebAssembly in wasmtime, a value live through the rounds holds a
// spill slot that the values of the rounds cannot share, and regalloc2 looks at only ten slots
// before it opens a new one: in a loop with h in locals, each spill took a slot of its own, 157 for
// BLAKE2b against 37 here. In a loop with h in memory, the values of the loop took the slots that a
// byte of displacement reaches: 8 KB of code against 7.6 KB here for BLAKE2s, and 3 percent more
// time on Ice Lake (D-89).
const BLOCK_CALLS: bool = cfg!(target_family = "wasm");

// compress, inlined into the loop over whole blocks too.
#[inline(always)]
fn rounds<W: Word>(h: &mut [W; 8], m: &[W; 16], counter: u128, last: bool) {
    if W::pair_rounds(h, m, counter, last) {
        return;
    }

    let mut v = [W::default(); 16];

    mix(h, m, counter, last, &mut v);

    for (i, word) in h.iter_mut().enumerate() {
        *word = *word ^ v[i] ^ v[i + 8];
    }

    wipe_unless_optimized!(&mut v);
}

// The rounds of compress, on v.
#[inline(always)]
fn mix<W: Word>(h: &[W; 8], m: &[W; 16], counter: u128, last: bool, v: &mut [W; 16]) {
    // The words come out of memory ahead of the state, here and not where the rounds read them. LLVM's
    // Reassociate adds the values of an expression by rank, and a load ranks by its place in the
    // block: read in the rounds, a word had the higher rank through the first rounds, and went into
    // a = a + b + x after b, one step more on the longest chain of dependencies for each.
    #[cfg(any(target_family = "wasm", target_arch = "arm"))]
    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut words: [W; 16] = registers!(
        |i| m[i];
        0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
    );

    #[cfg(any(target_family = "wasm", target_arch = "arm"))]
    let m = &words;

    let iv = W::IV;

    let [t0, t1] = W::counter(counter);

    *v = [
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
    round(v, m, &SIGMA[0]);

    round(v, m, &SIGMA[1]);

    round(v, m, &SIGMA[2]);

    round(v, m, &SIGMA[3]);

    round(v, m, &SIGMA[4]);

    round(v, m, &SIGMA[5]);

    round(v, m, &SIGMA[6]);

    round(v, m, &SIGMA[7]);

    round(v, m, &SIGMA[8]);

    round(v, m, &SIGMA[9]);

    if W::ROUNDS == 12 {
        round(v, m, &SIGMA[0]);

        round(v, m, &SIGMA[1]);
    }

    #[cfg(any(target_family = "wasm", target_arch = "arm"))]
    wipe_unless_optimized!(&mut words);
}

// On 32-bit x86 with SSE2 (crypto_pq_pairs, which build.rs sets), BLAKE2b's state goes in pairs
// of the words of a row, columns 0 and 2 and columns 1 and 3: each operation of a step is then
// one operation on both words of a pair, which LLVM's SLP vectorizer turns into one SSE2
// instruction, and the diagonal step takes the same pairs, some with their words swapped (D-82).
#[cfg(crypto_pq_pairs)]
type Pair = [u64; 2];

// The pairs of rows a to d: a02, a13, b02, b13, c02, c13, d02, d13. Aligned for the SSE2
// instructions that take an operand from memory.
#[cfg(crypto_pq_pairs)]
#[repr(C, align(16))]
struct Rows([Pair; 8]);

#[cfg(crypto_pq_pairs)]
#[inline(always)]
fn add_pair(a: Pair, b: Pair) -> Pair {
    [a[0].wrapping_add(b[0]), a[1].wrapping_add(b[1])]
}

#[cfg(crypto_pq_pairs)]
#[inline(always)]
fn xor_pair(a: Pair, b: Pair) -> Pair {
    [a[0] ^ b[0], a[1] ^ b[1]]
}

// A rotation as shifts of a and a ^ zero, as keccak::rotate_pair.
#[cfg(crypto_pq_pairs)]
#[inline(always)]
fn rotate_pair(a: Pair, zero: Pair, amount: u32) -> Pair {
    let b = xor_pair(a, zero);

    [
        a[0] >> amount | b[0] << (64 - amount),
        a[1] >> amount | b[1] << (64 - amount),
    ]
}

#[cfg(crypto_pq_pairs)]
#[inline(always)]
fn swap(a: Pair) -> Pair {
    [a[1], a[0]]
}

// A point that LLVM moves no load or store across, so that each half of a round loads and stores
// its own pairs: over a whole round it kept more values than the eight SSE2 registers hold, and
// spilled them.
#[cfg(crypto_pq_pairs)]
#[inline(always)]
fn order() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// g on both words of each pair.
#[cfg(crypto_pq_pairs)]
#[inline(always)]
fn g_pair(a: &mut Pair, b: &mut Pair, c: &mut Pair, d: &mut Pair, x: Pair, y: Pair, zero: Pair) {
    let [r1, r2, r3, r4] = u64::ROTATIONS;

    *a = add_pair(add_pair(*a, x), *b);

    *d = rotate_pair(xor_pair(*d, *a), zero, r1);

    *c = add_pair(*c, *d);

    *b = rotate_pair(xor_pair(*b, *c), zero, r2);

    *a = add_pair(add_pair(*a, y), *b);

    *d = rotate_pair(xor_pair(*d, *a), zero, r3);

    *c = add_pair(*c, *d);

    *b = rotate_pair(xor_pair(*b, *c), zero, r4);
}

// A round on the pairs: the columns, then the diagonals (0, 5, 10, 15) with (2, 7, 8, 13) and
// (1, 6, 11, 12) with (3, 4, 9, 14).
#[cfg(crypto_pq_pairs)]
#[inline(always)]
fn round_pair(rows: &mut Rows, m: &[u64; 16], s: &[usize; 16], zero: Pair) {
    order();

    let [a02, a13, b02, b13, c02, c13, d02, d13] = &mut rows.0;

    // The message words that g takes on the two words of a pair, at positions i and j of s.
    let message = |i: usize, j: usize| [m[s[i]], m[s[j]]];

    g_pair(a02, b02, c02, d02, message(0, 4), message(1, 5), zero);

    g_pair(a13, b13, c13, d13, message(2, 6), message(3, 7), zero);

    order();

    let c20 = &mut swap(*c02);

    let d31 = &mut swap(*d13);

    g_pair(a02, b13, c20, d31, message(8, 12), message(9, 13), zero);

    let b20 = &mut swap(*b02);

    let c31 = &mut swap(*c13);

    g_pair(a13, b20, c31, d02, message(10, 14), message(11, 15), zero);

    *b02 = swap(*b20);

    *c02 = swap(*c20);

    *c13 = swap(*c31);

    *d13 = swap(*d31);
}

// rounds on the pairs. The rows stay in memory, behind black_box, where the wipe reaches them: as
// values, they left the vectorizer no stores to start from.
#[cfg(crypto_pq_pairs)]
#[inline(always)]
fn rounds_pair(h: &mut [u64; 8], m: &[u64; 16], counter: u128, last: bool) {
    let iv = IV_512;

    let [t0, t1] = u64::counter(counter);

    let mut rows = Rows([
        [h[0], h[2]],
        [h[1], h[3]],
        [h[4], h[6]],
        [h[5], h[7]],
        [iv[0], iv[2]],
        [iv[1], iv[3]],
        [iv[4] ^ t0, if last { !iv[6] } else { iv[6] }],
        [iv[5] ^ t1, iv[7]],
    ]);

    core::hint::black_box(&mut rows);

    let zero = core::hint::black_box([0; 2]);

    // Written out, so that every index into the message is a constant.
    round_pair(&mut rows, m, &SIGMA[0], zero);

    round_pair(&mut rows, m, &SIGMA[1], zero);

    round_pair(&mut rows, m, &SIGMA[2], zero);

    round_pair(&mut rows, m, &SIGMA[3], zero);

    round_pair(&mut rows, m, &SIGMA[4], zero);

    round_pair(&mut rows, m, &SIGMA[5], zero);

    round_pair(&mut rows, m, &SIGMA[6], zero);

    round_pair(&mut rows, m, &SIGMA[7], zero);

    round_pair(&mut rows, m, &SIGMA[8], zero);

    round_pair(&mut rows, m, &SIGMA[9], zero);

    round_pair(&mut rows, m, &SIGMA[0], zero);

    round_pair(&mut rows, m, &SIGMA[1], zero);

    // h[j] ^= v[j] ^ v[j + 8], where pair i holds words j and j + 2 of row i / 2.
    for (i, (top, bottom)) in rows.0[..4].iter().zip(&rows.0[4..]).enumerate() {
        let j = 4 * (i / 2) + i % 2;

        h[j] ^= top[0] ^ bottom[0];

        h[j + 2] ^= top[1] ^ bottom[1];
    }

    wipe(&mut rows.0);
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
    run(true, h, first, blocks, counter, last);
}

// process with the portable code only.
#[inline(always)]
fn portable<W: Word>(
    h: &mut [W; 8],
    first: Option<&[W; 16]>,
    blocks: &[u8],
    counter: u128,
    last: Last<'_, W>,
) {
    if W::BYTES == 8 && !blocks.is_empty() {
        all_blocks(h, first, blocks, counter, last);

        return;
    }

    let size = 16 * W::BYTES as u128;

    let mut counter = counter;

    if let Some(first) = first {
        counter = counter.wrapping_add(size);

        compress(h, first, counter, false);
    }

    if !blocks.is_empty() {
        whole_blocks(h, blocks, counter);
    }

    if let Some((m, total)) = last {
        compress(h, m, total, true);
    }
}

// The counter of whole_blocks, BLAKE2s only, which counts at most 2^64 - 1 bytes. A u128 on 32-bit
// Arm keeps its upper half live through the loop, 10 instructions per block.
#[cfg(target_arch = "arm")]
type BlockCounter = u64;

#[cfg(not(target_arch = "arm"))]
type BlockCounter = u128;

// The whole blocks of bytes into h, counter the number of bytes before them. One loop with the
// compression inlined, so that the chaining value stays in registers from block to block and the
// message words come from the input, where a call per block took h and m through memory; on
// WebAssembly a call per block is the better form (BLOCK_CALLS). A MAC's key block comes here as the
// first buffered block. Out of line, so that a call of process without whole blocks keeps a small
// frame.
#[inline(never)]
fn whole_blocks<W: Word>(h: &mut [W; 8], blocks: &[u8], counter: u128) {
    let size = 16 * W::BYTES as BlockCounter;

    let mut counter: BlockCounter = counter as BlockCounter;

    let mut m = [W::default(); 16];

    if BLOCK_CALLS {
        for block in blocks.chunks_exact(16 * W::BYTES) {
            for (word, bytes) in m.iter_mut().zip(block.chunks_exact(W::BYTES)) {
                *word = W::from_le(bytes);
            }

            counter = counter.wrapping_add(size);

            compress(h, &m, counter as u128, false);
        }

        wipe(&mut m);

        return;
    }

    let mut state = *h;

    for block in blocks.chunks_exact(16 * W::BYTES) {
        for (word, bytes) in m.iter_mut().zip(block.chunks_exact(W::BYTES)) {
            *word = W::from_le(bytes);
        }

        counter = counter.wrapping_add(size);

        rounds(&mut state, &m, counter as u128, false);
    }

    *h = state;

    wipe_unless_optimized!(&mut state);

    wipe_unless_optimized!(&mut m);
}

// The first block, the whole blocks of bytes and the last block into h, counter the number of
// bytes before them. One loop with the compression inlined once, so that the chaining value stays
// in registers from block to block and the message words come from the input, where a call per
// block took h and m through memory; on WebAssembly a call per block is the better form
// (BLOCK_CALLS). The first and last blocks take the same code: a second copy
// of the compression for them doubled the code that a message of a few blocks runs (on an AMD Zen
// 5 core, BLAKE2b of 1 KiB took 70 ns more than the time of its blocks). BLAKE2b only: BLAKE2s,
// whose compression is smaller, took 3 to 4% more time this way for a MAC of 1 KiB on Zen 5 (EPYC
// 9V45, 24 of 24 seeds), and keeps whole_blocks. Out of line, so that a call of process without
// whole blocks keeps a small frame.
#[inline(never)]
fn all_blocks<W: Word>(
    h: &mut [W; 8],
    first: Option<&[W; 16]>,
    blocks: &[u8],
    counter: u128,
    last: Last<'_, W>,
) {
    let size = 16 * W::BYTES as u128;

    let mut counter = counter;

    let mut state = *h;

    let mut m = [W::default(); 16];

    let mut first = first;

    let mut last = last;

    let mut chunks = blocks.chunks_exact(16 * W::BYTES);

    loop {
        let (total, end) = if let Some(words) = first.take() {
            m = *words;

            counter = counter.wrapping_add(size);

            (counter, false)
        } else if let Some(block) = chunks.next() {
            for (word, bytes) in m.iter_mut().zip(block.chunks_exact(W::BYTES)) {
                *word = W::from_le(bytes);
            }

            counter = counter.wrapping_add(size);

            (counter, false)
        } else if let Some((words, total)) = last.take() {
            m = *words;

            (total, true)
        } else {
            break;
        };

        if BLOCK_CALLS {
            compress(&mut state, &m, total, end);
        } else {
            rounds(&mut state, &m, total, end);
        }
    }

    *h = state;

    if BLOCK_CALLS {
        wipe(&mut state);

        wipe(&mut m);
    }

    wipe_unless_optimized!(&mut state);

    wipe_unless_optimized!(&mut m);
}

// The words of at most a block of bytes, zero-padded: the bytes of data from `start` on. A partial
// last word is read without a store, from the bytes that end data. Always inlined, as before its
// copies of a constant size, which made the compiler move it and process out of mac.
#[inline(always)]
fn words<W: Word>(data: &[u8], start: usize, out: &mut [W; 16]) {
    let tail = &data[start..];

    // A whole block, and a key of half a block (the digest length of BLAKE2s-256 and BLAKE2b-512),
    // at a size the compiler knows, as loads and stores: at the size of the input, each took a
    // call of memcpy.
    if tail.len() == 16 * W::BYTES {
        fixed::<W, 16>(tail, out);

        return;
    }

    if tail.len() == 8 * W::BYTES {
        fixed::<W, 8>(tail, out);

        return;
    }

    let whole = tail.len() / W::BYTES;

    for (word, bytes) in out.iter_mut().zip(tail.chunks_exact(W::BYTES)) {
        *word = W::from_le(bytes);
    }

    let rest = tail.len() % W::BYTES;

    if rest > 0 {
        out[whole] = W::from_value(last_bytes(data, rest));
    }
}

// The first N words of out from tail, which holds N words.
#[inline(always)]
fn fixed<W: Word, const N: usize>(tail: &[u8], out: &mut [W; 16]) {
    for (i, word) in out.iter_mut().enumerate().take(N) {
        *word = W::from_le(&tail[i * W::BYTES..]);
    }
}

// The bytes of data that precede its final block: whole blocks, leaving at least one byte for the
// final block when there is data.
fn leading<W: Word>(length: usize) -> usize {
    let block = 16 * W::BYTES;

    length.saturating_sub(1) / block * block
}

// process, or the portable code alone where the CPU kernel of a digest or MAC chose it (kernel
// false).
#[inline(always)]
fn run<W: Word>(
    kernel: bool,
    h: &mut [W; 8],
    first: Option<&[W; 16]>,
    blocks: &[u8],
    counter: u128,
    last: Last<'_, W>,
) {
    if kernel && W::kernel(h, first, blocks, counter, last) {
        return;
    }

    portable(h, first, blocks, counter, last);
}

// A digest, or a MAC with its key, of at most a block of data on 32-bit Arm: state and message in
// registers and in the spills of the compiler, with no block in memory to fill, read and wipe.
#[cfg(any(test, target_arch = "arm"))]
#[inline(never)]
fn in_locals<W: Word>(h: &[W; 8], key: Option<&[u8]>, data: &[u8], out: &mut [u8]) {
    let mut state = *h;

    if let Some(key) = key {
        state[0] = state[0] ^ W::key_length(key.len());
    }

    let block = 16 * W::BYTES;

    let mut m = [W::default(); 16];

    let mut source = key.unwrap_or(data);

    let mut counter = if key.is_some() { block } else { data.len() };

    let mut last = key.is_none() || data.is_empty();

    loop {
        short_words(source, &mut m);

        rounds(&mut state, &m, counter as u128, last);

        if last {
            break;
        }

        source = data;

        counter = block + data.len();

        last = true;
    }

    W::store(&state, out);

    wipe_unless_optimized!(&mut state);

    wipe_unless_optimized!(&mut m);
}

// The words of at most a block of bytes, zeros after them. Leaves at the word that takes the last
// bytes, with no test on the zero words after it.
#[cfg(any(test, target_arch = "arm"))]
#[inline(always)]
fn short_words<W: Word>(data: &[u8], m: &mut [W; 16]) {
    *m = [W::default(); 16];

    let mut chunks = data.chunks_exact(W::BYTES);

    let mut partial = 0;

    for (i, &byte) in chunks.remainder().iter().enumerate() {
        partial |= u64::from(byte) << (8 * i);
    }

    macro_rules! word {
        ($($i:literal)*) => {
            $(
                let Some(bytes) = chunks.next() else {
                    m[$i] = W::from_value(u128::from(partial));

                    return;
                };

                m[$i] = W::from_le(bytes);
            )*
        };
    }

    word!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15);
}

// Whether short takes this data and out.
#[cfg(any(test, target_family = "wasm"))]
#[inline(always)]
pub(crate) fn fits<W: Word>(data: &[u8], out: &[u8]) -> bool {
    data.len() <= 16 * W::BYTES && (out.len() == 8 * W::BYTES || out.len() == 4 * W::BYTES)
}

// A digest, or a MAC with its key, of at most a block of data on WebAssembly, with no state to copy,
// fill and wipe for the last block. A message of a whole block, half a block or nothing goes straight
// from its slice into the rounds, with the zero words folded away. Any other length goes through
// words in memory, where the rounds read them: inside the rounds, a word that came through a branch
// took Cranelift most of its 166 spill slots, which cost Zen cores up to 43 percent.
#[cfg(any(test, target_family = "wasm"))]
#[inline(always)]
pub(crate) fn short<W: Word>(h: &[W; 8], key: Option<&[u8]>, data: &[u8], out: &mut [u8]) {
    let block = 16 * W::BYTES;

    let Some(key) = key else {
        return short_last(h, W::default(), data, data.len(), out);
    };

    let first = W::key_length(key.len());

    if data.is_empty() {
        return short_last(h, first, key, block, out);
    }

    let mut state = *h;

    state[0] = state[0] ^ first;

    if key.len() == block / 2 {
        key_block_half(&mut state, key);
    } else {
        let mut m = zero_words();

        words(key, 0, &mut m);

        compress(&mut state, &m, block as u128, false);

        wipe(&mut m);
    }

    short_last(&state, W::default(), data, block + data.len(), out);

    wipe(&mut state);
}

// A digest of at most a block for each word size. These are the functions that a digest in another
// crate calls: HashAlgorithm::digest_into is inlined there, and a generic function would be compiled
// there too, at the opt-level of that crate, with the wipes chosen for the opt-level of this one
// (D-76).
#[cfg(any(test, target_family = "wasm"))]
#[inline(never)]
pub(crate) fn short_digest_b(h: &[u64; 8], data: &[u8], out: &mut [u8]) {
    short(h, None, data, out);
}

#[cfg(any(test, target_family = "wasm"))]
#[inline(never)]
pub(crate) fn short_digest_s(h: &[u32; 8], data: &[u8], out: &mut [u8]) {
    short(h, None, data, out);
}

#[cfg(any(test, target_family = "wasm"))]
#[inline(always)]
fn short_last<W: Word>(h: &[W; 8], first: W, message: &[u8], counter: usize, out: &mut [u8]) {
    let block = 16 * W::BYTES;

    if message.len() == block {
        last_known::<W, 16>(h, first, message, counter, out);
    } else if message.len() == block / 2 {
        last_known::<W, 8>(h, first, message, counter, out);
    } else if message.is_empty() {
        last_known::<W, 0>(h, first, message, counter, out);
    } else {
        let mut m = zero_words();

        words(message, 0, &mut m);

        last_block(h, first, &m, counter, out);

        wipe(&mut m);
    }
}

// 16 zero words. 128 bytes of a constant would be memory.fill, a call into the runtime.
#[cfg(any(test, target_family = "wasm"))]
#[inline(always)]
fn zero_words<W: Word>() -> [W; 16] {
    if W::BYTES == 8 {
        [core::hint::black_box(W::default()); 16]
    } else {
        [W::default(); 16]
    }
}

// Word i of a message of K whole words and zeros after them.
#[cfg(any(test, target_family = "wasm"))]
#[inline(always)]
fn known_word<W: Word, const K: usize>(message: &[u8], i: usize) -> W {
    if i < K {
        W::from_le(&message[i * W::BYTES..(i + 1) * W::BYTES])
    } else {
        W::default()
    }
}

#[cfg(any(test, target_family = "wasm"))]
#[inline(never)]
fn key_block_half<W: Word>(state: &mut [W; 8], key: &[u8]) {
    let key = &key[..8 * W::BYTES];

    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut m: [W; 16] = registers!(
        |i| known_word::<W, 8>(key, i);
        0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
    );

    rounds(state, &m, 16 * W::BYTES as u128, false);

    wipe_unless_optimized!(&mut m);
}

#[cfg(any(test, target_family = "wasm"))]
#[inline(never)]
fn last_known<W: Word, const K: usize>(
    h: &[W; 8],
    first: W,
    message: &[u8],
    counter: usize,
    out: &mut [u8],
) {
    let message = &message[..K * W::BYTES];

    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut m: [W; 16] = registers!(
        |i| known_word::<W, K>(message, i);
        0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
    );

    last_rounds(h, first, &m, counter, out);

    wipe_unless_optimized!(&mut m);
}

#[cfg(any(test, target_family = "wasm"))]
#[inline(never)]
fn last_block<W: Word>(h: &[W; 8], first: W, m: &[W; 16], counter: usize, out: &mut [u8]) {
    last_rounds(h, first, m, counter, out);
}

// A digest or MAC on WebAssembly past what short takes. One copy of the rounds runs every block: a
// second copy for the last block took Zen 3 about the time of a block more per call, above the
// instructions it runs. With no runtime call: memory.fill and memory.copy leave the module.
#[cfg(any(test, target_family = "wasm"))]
#[inline(never)]
pub(crate) fn long<W: Word>(h: &[W; 8], key: Option<&[u8]>, data: &[u8], out: &mut [u8]) {
    let size = 16 * W::BYTES;

    let mut state = *h;

    let mut total = 0;

    if let Some(key) = key {
        state[0] = state[0] ^ W::key_length(key.len());

        total += size as u64;

        padded_block(&mut state, key, total, data.is_empty());
    }

    let rest = data.len() % size;

    let (blocks, tail) = data.split_at(data.len() - rest);

    if !blocks.is_empty() {
        total += blocks.len() as u64;

        in_blocks::<W>(&mut state, blocks, total, rest == 0);
    }

    if rest != 0 || (data.is_empty() && key.is_none()) {
        total += rest as u64;

        padded_block(&mut state, tail, total, true);
    }

    W::store(&state, out);

    wipe(&mut state);
}

// in_blocks of at most a block of bytes, with zeros after them.
#[cfg(any(test, target_family = "wasm"))]
fn padded_block<W: Word>(h: &mut [W; 8], bytes: &[u8], total: u64, last: bool) {
    // As a constant, the 128 bytes would be memory.fill.
    let mut block = [core::hint::black_box(0u64).to_ne_bytes(); 16];

    let padded = &mut block.as_flattened_mut()[..16 * W::BYTES];

    copy_in_line(&mut padded[..bytes.len()], bytes);

    in_blocks::<W>(h, padded, total, last);

    wipe(&mut block);
}

// The blocks into h, total the counter at the end of them, the last one the last of the message if
// last says so.
#[cfg(any(test, target_family = "wasm"))]
#[inline(never)]
fn in_blocks<W: Word>(h: &mut [W; 8], blocks: &[u8], total: u64, last: bool) {
    let mut rest = blocks;

    while let Some((block, after)) = rest.split_at_checked(16 * W::BYTES) {
        rest = after;

        let counter = total.wrapping_sub(rest.len() as u64);

        block_call(h, block, counter, last && rest.is_empty());
    }
}

// compress of a block of bytes, the message words read ahead of the state. A parameter, the block
// gets the offsets of its loads folded on WebAssembly, where the pointer of a loop takes an addition
// for each.
#[cfg(any(test, target_family = "wasm"))]
#[inline(never)]
fn block_call<W: Word>(h: &mut [W; 8], block: &[u8], counter: u64, last: bool) {
    let block = &block[..16 * W::BYTES];

    #[cfg_attr(crypto_pq_optimized, allow(unused_mut))]
    let mut m: [W; 16] = registers!(
        |i| W::from_le(&block[i * W::BYTES..(i + 1) * W::BYTES]);
        0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
    );

    rounds(h, &m, counter as u128, last);

    wipe_unless_optimized!(&mut m);
}

// compress of the last block into out, of 4 or 8 words, with no state to write back, from h with first
// XORed into its first word. The word indexes are constants, which keeps v out of memory, and the
// first store is not under a branch: Cranelift places each pure value right before its first use, so
// it would repeat the rounds in each arm.
#[cfg(any(test, target_family = "wasm"))]
#[inline(always)]
fn last_rounds<W: Word>(h: &[W; 8], first: W, m: &[W; 16], counter: usize, out: &mut [u8]) {
    let (low, high) = out.split_at_mut(4 * W::BYTES);

    let mut s = *h;

    s[0] = s[0] ^ first;

    let mut v = [W::default(); 16];

    mix(&s, m, counter as u128, true, &mut v);

    macro_rules! store {
        ($to:ident, $at:literal: $($i:literal)*) => {
            $(
                (s[$at + $i] ^ v[$at + $i] ^ v[$at + $i + 8])
                    .write_le(&mut $to[$i * W::BYTES..($i + 1) * W::BYTES]);
            )*
        };
    }

    store!(low, 0: 0 1 2 3);

    if high.len() == 4 * W::BYTES {
        store!(high, 4: 0 1 2 3);
    }

    wipe_unless_optimized!(&mut s);

    wipe_unless_optimized!(&mut v);
}

// The digest of data, out.len() bytes, from the chaining value h, in one pass over data.
#[cfg(target_family = "wasm")]
pub(crate) fn digest<W: Word>(h: &[W; 8], data: &[u8], out: &mut [u8]) {
    if !matches!(W::digest_kernel(h, data, out), Kernel::Done) {
        long(h, None, data, out);
    }
}

// The keyed hash of data under a key of 1 to 16 * W::BYTES bytes, from the unkeyed chaining value
// h of the configured digest length.
#[cfg(target_family = "wasm")]
#[inline(always)]
pub(crate) fn mac<W: Word>(h: &[W; 8], key: &[u8], data: &[u8], out: &mut [u8]) {
    if matches!(W::mac_kernel(h, key, data, out), Kernel::Done) {
        return;
    }

    if fits::<W>(data, out) {
        short(h, Some(key), data, out);
    } else {
        long(h, Some(key), data, out);
    }
}

// The digest of data, out.len() bytes, from the chaining value h, in one pass over data.
#[cfg(not(target_family = "wasm"))]
pub(crate) fn digest<W: Word>(h: &[W; 8], data: &[u8], out: &mut [u8]) {
    let kernel = match W::digest_kernel(h, data, out) {
        Kernel::Done => return,
        Kernel::Blocks => true,
        Kernel::Portable => false,
    };

    #[cfg(target_arch = "arm")]
    if data.len() <= 16 * W::BYTES {
        return in_locals(h, None, data, out);
    }

    let mut h = *h;

    let whole = leading::<W>(data.len());

    let mut last = [W::default(); 16];

    words(data, whole, &mut last);

    run(
        kernel,
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
#[cfg(not(target_family = "wasm"))]
pub(crate) fn mac<W: Word>(h: &[W; 8], key: &[u8], data: &[u8], out: &mut [u8]) {
    let kernel = match W::mac_kernel(h, key, data, out) {
        Kernel::Done => return,
        Kernel::Blocks => true,
        Kernel::Portable => false,
    };

    #[cfg(target_arch = "arm")]
    if data.len() <= 16 * W::BYTES {
        return in_locals(h, Some(key), data, out);
    }

    let mut h = *h;

    h[0] = h[0] ^ W::key_length(key.len());

    let mut key_block = [W::default(); 16];

    words(key, 0, &mut key_block);

    let block = 16 * W::BYTES as u128;

    let mut last = [W::default(); 16];

    if data.is_empty() {
        run(kernel, &mut h, None, &[], 0, Some((&key_block, block)));
    } else {
        let whole = leading::<W>(data.len());

        words(data, whole, &mut last);

        run(
            kernel,
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

    // A copy of other, written field by field into self: a clone moved into place went through
    // the stack (mac.rs, MacKey).
    pub(crate) fn copy_from(&mut self, other: &Self) {
        self.h = other.h;

        self.buffer = other.buffer;

        self.filled = other.filled;

        self.counter = other.counter;
    }

    pub(crate) const fn new(h: &[W; 8]) -> Self {
        Self {
            h: *h,
            buffer: [0; 128],
            filled: 0,
            counter: 0,
        }
    }

    // Turns a new engine into a MAC under a key of 1 to BLOCK bytes, whose padded block is the
    // first block. The key goes into the engine where it lives, so that no keyed copy of it is
    // moved.
    pub(crate) fn key(&mut self, key: &[u8]) {
        self.h[0] = self.h[0] ^ W::key_length(key.len());

        self.buffer[..key.len()].copy_from_slice(key);

        self.filled = Self::BLOCK;
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

    // The one-call digest kernels against the portable compression, from random chaining values,
    // for every length up to three blocks and nine bytes and every digest size.
    fn digest_kernel_matches<W: Word>(inputs: &mut Inputs, word: impl Fn(u64) -> W) -> usize {
        let mut accelerated = 0;

        let block = 16 * W::BYTES;

        for n in 0..4_000 {
            let h: [W; 8] = core::array::from_fn(|_| word(inputs.next()));

            let bytes: [u8; 3 * 128 + 9] = inputs.bytes();

            let data = &bytes[..n % (3 * block + 10)];

            let size = 1 + n % (8 * W::BYTES);

            let mut state = h;

            let whole = leading::<W>(data.len());

            for (i, chunk) in data[..whole].chunks_exact(block).enumerate() {
                let m: [W; 16] =
                    core::array::from_fn(|j| W::from_le(&chunk[j * W::BYTES..(j + 1) * W::BYTES]));

                compress(&mut state, &m, (block * (i + 1)) as u128, false);
            }

            let mut last = [W::default(); 16];

            words(data, whole, &mut last);

            compress(&mut state, &last, data.len() as u128, true);

            let (mut expected, mut actual) = ([0; 64], [0; 64]);

            W::store(&state, &mut expected[..size]);

            if matches!(
                W::digest_kernel(&h, data, &mut actual[..size]),
                Kernel::Done
            ) {
                assert_eq!(actual, expected, "case {n}");

                accelerated += 1;
            }
        }

        accelerated
    }

    #[test]
    fn blake2_digest_kernels_match_portable() {
        let mut inputs = Inputs::new(11);

        let b = digest_kernel_matches::<u64>(&mut inputs, |x| x);

        let s = digest_kernel_matches::<u32>(&mut inputs, |x| x as u32);

        std::eprintln!("BLAKE2 digest: b {b} of 4000, s {s} of 4000 cases through a CPU kernel");
    }

    // The one-call MAC kernels against the portable compression, from random chaining values,
    // for every key length, every length up to three blocks and nine bytes and every digest
    // size.
    fn mac_kernel_matches<W: Word>(inputs: &mut Inputs, word: impl Fn(u64) -> W) -> usize {
        let mut accelerated = 0;

        let block = 16 * W::BYTES;

        for n in 0..4_000 {
            let h: [W; 8] = core::array::from_fn(|_| word(inputs.next()));

            let bytes: [u8; 3 * 128 + 9] = inputs.bytes();

            let data = &bytes[..n % (3 * block + 10)];

            let key: [u8; 64] = inputs.bytes();

            let key = &key[..1 + n / 7 % (8 * W::BYTES)];

            let size = 1 + n % (8 * W::BYTES);

            let mut key_block = [W::default(); 16];

            words(key, 0, &mut key_block);

            let mut state = h;

            state[0] = state[0] ^ W::key_length(key.len());

            if data.is_empty() {
                compress(&mut state, &key_block, block as u128, true);
            } else {
                compress(&mut state, &key_block, block as u128, false);

                let whole = leading::<W>(data.len());

                for (i, chunk) in data[..whole].chunks_exact(block).enumerate() {
                    let m: [W; 16] = core::array::from_fn(|j| {
                        W::from_le(&chunk[j * W::BYTES..(j + 1) * W::BYTES])
                    });

                    compress(&mut state, &m, (block * (i + 2)) as u128, false);
                }

                let mut last = [W::default(); 16];

                words(data, whole, &mut last);

                compress(&mut state, &last, (block + data.len()) as u128, true);
            }

            let (mut expected, mut actual) = ([0; 64], [0; 64]);

            W::store(&state, &mut expected[..size]);

            if matches!(
                W::mac_kernel(&h, key, data, &mut actual[..size]),
                Kernel::Done
            ) {
                assert_eq!(actual, expected, "case {n}");

                accelerated += 1;
            }
        }

        accelerated
    }

    #[test]
    fn blake2_mac_kernels_match_portable() {
        let mut inputs = Inputs::new(12);

        let b = mac_kernel_matches::<u64>(&mut inputs, |x| x);

        let s = mac_kernel_matches::<u32>(&mut inputs, |x| x as u32);

        std::eprintln!("BLAKE2 MAC: b {b} of 4000, s {s} of 4000 cases through a CPU kernel");
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

                let mut engine = Engine::new(&h);

                engine.key(key);

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

    #[test]
    fn short_digests_match_compress() {
        let message: [u8; 128] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(7));

        for length in 0..=128 {
            let data = &message[..length];

            let mut m = [0u64; 16];

            words(data, 0, &mut m);

            let mut expected = <u64 as Word>::IV;

            compress(&mut expected, &m, length as u128, true);

            let mut out = [0; 64];

            short_digest_b(&<u64 as Word>::IV, data, &mut out);

            for (bytes, word) in out.chunks(8).zip(&expected) {
                assert_eq!(bytes, word.to_le_bytes());
            }
        }

        for length in 0..=64 {
            let data = &message[..length];

            let mut m = [0u32; 16];

            words(data, 0, &mut m);

            let mut expected = <u32 as Word>::IV;

            compress(&mut expected, &m, length as u128, true);

            let mut out = [0; 32];

            short_digest_s(&<u32 as Word>::IV, data, &mut out);

            for (bytes, word) in out.chunks(4).zip(&expected) {
                assert_eq!(bytes, word.to_le_bytes());
            }
        }
    }

    // in_locals against compress, for a digest and for a MAC.
    fn in_locals_matches_compress<W: Word>() {
        let block = 16 * W::BYTES;

        let whole = 8 * W::BYTES;

        let message: [u8; 128] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(3));

        let key: [u8; 128] = core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(1));

        let padded = |bytes: &[u8]| {
            let mut m = [W::default(); 16];

            words(bytes, 0, &mut m);

            m
        };

        let check = |expected: &[W; 8], key: Option<&[u8]>, data: &[u8]| {
            let mut all = [0; 64];

            W::store(expected, &mut all[..whole]);

            for size in 0..=whole {
                let mut out = [0xA5; 65];

                in_locals(&W::IV, key, data, &mut out[..size]);

                assert_eq!(out[..size], all[..size]);

                assert!(out[size..].iter().all(|&byte| byte == 0xA5));

                if fits::<W>(data, &out[..size]) {
                    let mut out = [0xA5; 65];

                    short(&W::IV, key, data, &mut out[..size]);

                    assert_eq!(out[..size], all[..size]);

                    assert!(out[size..].iter().all(|&byte| byte == 0xA5));
                }

                let mut out = [0xA5; 65];

                long(&W::IV, key, data, &mut out[..size]);

                assert_eq!(out[..size], all[..size]);

                assert!(out[size..].iter().all(|&byte| byte == 0xA5));

                let mut out = [0xA5; 65];

                store_in_locals(expected, &mut out[..size]);

                assert_eq!(out[..size], all[..size]);

                assert!(out[size..].iter().all(|&byte| byte == 0xA5));
            }
        };

        for length in 0..=block {
            let data = &message[..length];

            let mut expected = W::IV;

            compress(&mut expected, &padded(data), length as u128, true);

            check(&expected, None, data);

            for size in [1, 7, whole, block - 1, block] {
                let key = &key[..size];

                let mut expected = W::IV;

                expected[0] = expected[0] ^ W::key_length(size);

                if length == 0 {
                    compress(&mut expected, &padded(key), block as u128, true);
                } else {
                    compress(&mut expected, &padded(key), block as u128, false);

                    compress(&mut expected, &padded(data), (block + length) as u128, true);
                }

                check(&expected, Some(key), data);
            }
        }
    }

    #[test]
    fn in_locals_matches_compress_for_both_words() {
        in_locals_matches_compress::<u32>();

        in_locals_matches_compress::<u64>();
    }

    // long against compress over more than a block, whole blocks and odd tails, for a digest and for
    // a MAC, and its loop alone over whole blocks.
    fn long_matches_compress<W: Word>() {
        let block = 16 * W::BYTES;

        let whole = 8 * W::BYTES;

        let message: [u8; 400] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(7));

        let key: [u8; 128] = core::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(5));

        let padded = |bytes: &[u8]| {
            let mut m = [W::default(); 16];

            words(bytes, 0, &mut m);

            m
        };

        let lengths = [
            block + 1,
            2 * block - 1,
            2 * block,
            2 * block + 1,
            3 * block - 5,
            3 * block,
        ];

        let keys: [Option<&[u8]>; 5] = [
            None,
            Some(&key[..1]),
            Some(&key[..7]),
            Some(&key[..whole]),
            Some(&key[..block]),
        ];

        for length in lengths {
            let data = &message[..length];

            for key in keys {
                let mut expected = W::IV;

                let mut counter = 0;

                if let Some(key) = key {
                    expected[0] = expected[0] ^ W::key_length(key.len());

                    counter += block;

                    compress(&mut expected, &padded(key), counter as u128, false);
                }

                let mut rest = data;

                while rest.len() > block {
                    let (first, after) = rest.split_at(block);

                    counter += block;

                    compress(&mut expected, &padded(first), counter as u128, false);

                    rest = after;
                }

                counter += rest.len();

                compress(&mut expected, &padded(rest), counter as u128, true);

                let mut all = [0; 64];

                W::store(&expected, &mut all[..whole]);

                for size in [1, 7, whole] {
                    let mut out = [0xA5; 65];

                    long(&W::IV, key, data, &mut out[..size]);

                    assert_eq!(out[..size], all[..size]);

                    assert!(out[size..].iter().all(|&byte| byte == 0xA5));
                }

                if key.is_none() && length % block == 0 {
                    let mut h = W::IV;

                    in_blocks::<W>(&mut h, data, length as u64, true);

                    let mut out = [0; 64];

                    W::store(&h, &mut out[..whole]);

                    assert_eq!(out, all);
                }
            }
        }
    }

    #[test]
    fn long_matches_compress_for_both_words() {
        long_matches_compress::<u32>();

        long_matches_compress::<u64>();
    }
}

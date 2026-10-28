// BLAKE3 (the BLAKE3 specification, BLAKE3-team/BLAKE3-specs) on one thread: the hash and its
// extended output, keyed_hash and derive_key. The input splits into chunks of sixteen 64-byte
// blocks, whose chaining values are the leaves of a binary tree of parent nodes; a node's left
// subtree holds the largest power of two of chunks that leaves at least one byte for the right.
//
// A one-shot call knows the whole input, so any chunk may go side by side with others: groups of
// up to WIDE chunks hash their chunks and then their parents level by level, through hash_many and
// its kernels, the groups' chaining values merge on a stack, and only the root, the last node,
// stays unfinished. The incremental
// hasher knows only the input so far: it hashes whole subtrees the same way once more input
// follows them, and otherwise a block at a time, compressing a chunk's last block only once more
// input shows that it is not the root's; the chaining value of each finished subtree goes on a
// stack, where complete subtrees merge into their parent at once. In keyed and derive_key modes
// every chaining value derives from the key, so the buffers that hold them are wiped; the working
// state of the compression stays in registers, as in BLAKE2.

use crate::cpu;
use crate::sha2::IV_256;
use crate::wipe::wipe;

pub(crate) const KEY: usize = 32;

const BLOCK: usize = 64;

const CHUNK: usize = 1024;

const BLOCKS: u8 = 16;

// A chunk counter below 2^54 covers 2^64 bytes, and the stack holds one chaining value for each
// bit set in it.
const MAX_DEPTH: usize = 54;

// The chunks of the largest subtree that hash_many hashes at once, a group: their chaining values
// take 2 KiB of stack, and the parents of each level go through the kernels too.
const WIDE: usize = 64;

pub(crate) const CHUNK_START: u32 = 1;

pub(crate) const CHUNK_END: u32 = 2;

const PARENT: u32 = 4;

pub(crate) const ROOT: u32 = 8;

const KEYED_HASH: u32 = 16;

const DERIVE_KEY_CONTEXT: u32 = 32;

const DERIVE_KEY_MATERIAL: u32 = 64;

// Message word i of a round is word PERMUTATION[i] of the round before.
pub(crate) const PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[inline(always)]
fn g(v: &mut [u32; 16], [a, b, c, d]: [usize; 4], x: u32, y: u32) {
    // The message word is added first: it is ready long before b, whose chain this shortens.
    v[a] = v[a].wrapping_add(x).wrapping_add(v[b]);

    v[d] = (v[d] ^ v[a]).rotate_right(16);

    v[c] = v[c].wrapping_add(v[d]);

    v[b] = (v[b] ^ v[c]).rotate_right(12);

    v[a] = v[a].wrapping_add(y).wrapping_add(v[b]);

    v[d] = (v[d] ^ v[a]).rotate_right(8);

    v[c] = v[c].wrapping_add(v[d]);

    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

#[inline(always)]
fn round(v: &mut [u32; 16], m: &[u32; 16]) {
    g(v, [0, 4, 8, 12], m[0], m[1]);

    g(v, [1, 5, 9, 13], m[2], m[3]);

    g(v, [2, 6, 10, 14], m[4], m[5]);

    g(v, [3, 7, 11, 15], m[6], m[7]);

    g(v, [0, 5, 10, 15], m[8], m[9]);

    g(v, [1, 6, 11, 12], m[10], m[11]);

    g(v, [2, 7, 8, 13], m[12], m[13]);

    g(v, [3, 4, 9, 14], m[14], m[15]);
}

// Two independent rounds, G function by G function: a compression is longer than the CPU's window
// of instructions in flight, so two written one after the other ran one after the other.
#[inline(always)]
fn round_pair(v: &mut [u32; 16], w: &mut [u32; 16], m: &[u32; 16], n: &[u32; 16]) {
    g(v, [0, 4, 8, 12], m[0], m[1]);

    g(w, [0, 4, 8, 12], n[0], n[1]);

    g(v, [1, 5, 9, 13], m[2], m[3]);

    g(w, [1, 5, 9, 13], n[2], n[3]);

    g(v, [2, 6, 10, 14], m[4], m[5]);

    g(w, [2, 6, 10, 14], n[4], n[5]);

    g(v, [3, 7, 11, 15], m[6], m[7]);

    g(w, [3, 7, 11, 15], n[6], n[7]);

    g(v, [0, 5, 10, 15], m[8], m[9]);

    g(w, [0, 5, 10, 15], n[8], n[9]);

    g(v, [1, 6, 11, 12], m[10], m[11]);

    g(w, [1, 6, 11, 12], n[10], n[11]);

    g(v, [2, 7, 8, 13], m[12], m[13]);

    g(w, [2, 7, 8, 13], n[12], n[13]);

    g(v, [3, 4, 9, 14], m[14], m[15]);

    g(w, [3, 4, 9, 14], n[14], n[15]);
}

// The words in the next round's order; with every index a constant, the compiler only renames
// registers.
#[inline(always)]
fn permute(m: &[u32; 16]) -> [u32; 16] {
    core::array::from_fn(|i| m[PERMUTATION[i]])
}

// The state after the seven rounds over the chaining value cv and the message words m, with the
// 64-bit counter, the block's length and the domain flags.
#[inline(always)]
fn rounds(cv: &[u32; 8], m: &[u32; 16], counter: u64, length: u32, flags: u32) -> [u32; 16] {
    let mut v = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV_256[0],
        IV_256[1],
        IV_256[2],
        IV_256[3],
        counter as u32,
        (counter >> 32) as u32,
        length,
        flags,
    ];

    // Written out: as a loop, the permutation became moves between registers and the stack.
    round(&mut v, m);

    let m = permute(m);

    round(&mut v, &m);

    let m = permute(&m);

    round(&mut v, &m);

    let m = permute(&m);

    round(&mut v, &m);

    let m = permute(&m);

    round(&mut v, &m);

    let m = permute(&m);

    round(&mut v, &m);

    let m = permute(&m);

    round(&mut v, &m);

    v
}

// All sixteen output words of the compression of a block; the first eight are the next chaining
// value. This and the next two take a kernel where there is one; they are inlined, so that the
// kernel is called directly.
#[inline]
fn compress(
    cv: &[u32; 8],
    block: &[u8; BLOCK],
    counter: u64,
    length: u32,
    flags: u32,
) -> [u32; 16] {
    let mut out = [0; 16];

    if cpu::blake3_compress(cv, block, counter, [length, flags], &mut out) {
        return out;
    }

    compress_portable(cv, block, counter, length, flags)
}

fn compress_portable(
    cv: &[u32; 8],
    block: &[u8; BLOCK],
    counter: u64,
    length: u32,
    flags: u32,
) -> [u32; 16] {
    let v = rounds(cv, &words(block), counter, length, flags);

    core::array::from_fn(|i| {
        if i < 8 {
            v[i] ^ v[i + 8]
        } else {
            v[i] ^ cv[i - 8]
        }
    })
}

// The chaining value: the first eight output words alone.
#[inline]
fn chain(cv: &[u32; 8], block: &[u8; BLOCK], counter: u64, length: u32, flags: u32) -> [u32; 8] {
    let mut out = [0; 16];

    if cpu::blake3_compress(cv, block, counter, [length, flags], &mut out) {
        let first = *out.first_chunk().expect("sixteen words");

        wipe(&mut out);

        return first;
    }

    chain_portable(cv, block, counter, length, flags)
}

// The words of the block go from memory straight into the rounds.
fn chain_portable(
    cv: &[u32; 8],
    block: &[u8; BLOCK],
    counter: u64,
    length: u32,
    flags: u32,
) -> [u32; 8] {
    let v = rounds(cv, &words(block), counter, length, flags);

    core::array::from_fn(|i| v[i] ^ v[i + 8])
}

// The final block of a chain, with its length and flags.
pub(crate) type Last<'a> = Option<(&'a [u8; BLOCK], u32, u32)>;

// The chaining value after whole blocks of one chunk, from cv: the first block with `start`
// added to the flags and the last with `end`, and then `last` if there is one.
#[inline]
fn chain_blocks(
    cv: &[u32; 8],
    blocks: &[[u8; BLOCK]],
    counter: u64,
    flags: u32,
    edges: [u32; 2],
    last: Last,
) -> [u32; 8] {
    let mut h = *cv;

    if cpu::blake3_blocks(&mut h, blocks, counter, flags, edges, last) {
        return h;
    }

    chain_blocks_portable(cv, blocks, counter, flags, edges, last)
}

// The chain stays in registers from block to block; a call per block stored it and loaded it
// back, on the critical path.
fn chain_blocks_portable(
    cv: &[u32; 8],
    blocks: &[[u8; BLOCK]],
    counter: u64,
    flags: u32,
    [start, end]: [u32; 2],
    last: Last,
) -> [u32; 8] {
    let mut h = *cv;

    let whole = blocks.len();

    for (i, block) in blocks.iter().enumerate() {
        let mut f = flags;

        if i == 0 {
            f |= start;
        }

        if i + 1 == whole {
            f |= end;
        }

        let v = rounds(&h, &words(block), counter, BLOCK as u32, f);

        h = core::array::from_fn(|i| v[i] ^ v[i + 8]);
    }

    if let Some((block, length, f)) = last {
        let v = rounds(&h, &words(block), counter, length, f);

        h = core::array::from_fn(|i| v[i] ^ v[i + 8]);
    }

    h
}

// chain_blocks for two inputs of as many blocks.
fn chain_blocks_pair(
    key: &[u32; 8],
    inputs: [&[[u8; BLOCK]]; 2],
    counters: [u64; 2],
    flags: u32,
    [start, end]: [u32; 2],
) -> [[u32; 8]; 2] {
    let mut h = [*key; 2];

    for (i, (first, second)) in inputs[0].iter().zip(inputs[1]).enumerate() {
        let mut f = flags;

        if i == 0 {
            f |= start;
        }

        if i + 1 == inputs[0].len() {
            f |= end;
        }

        let start = |h: &[u32; 8], counter: u64| {
            [
                h[0],
                h[1],
                h[2],
                h[3],
                h[4],
                h[5],
                h[6],
                h[7],
                IV_256[0],
                IV_256[1],
                IV_256[2],
                IV_256[3],
                counter as u32,
                (counter >> 32) as u32,
                BLOCK as u32,
                f,
            ]
        };

        let (mut v, mut w) = (start(&h[0], counters[0]), start(&h[1], counters[1]));

        let (m, n) = (words(first), words(second));

        round_pair(&mut v, &mut w, &m, &n);

        let (m, n) = (permute(&m), permute(&n));

        round_pair(&mut v, &mut w, &m, &n);

        let (m, n) = (permute(&m), permute(&n));

        round_pair(&mut v, &mut w, &m, &n);

        let (m, n) = (permute(&m), permute(&n));

        round_pair(&mut v, &mut w, &m, &n);

        let (m, n) = (permute(&m), permute(&n));

        round_pair(&mut v, &mut w, &m, &n);

        let (m, n) = (permute(&m), permute(&n));

        round_pair(&mut v, &mut w, &m, &n);

        let (m, n) = (permute(&m), permute(&n));

        round_pair(&mut v, &mut w, &m, &n);

        h = [
            core::array::from_fn(|i| v[i] ^ v[i + 8]),
            core::array::from_fn(|i| w[i] ^ w[i + 8]),
        ];
    }

    h
}

#[inline(always)]
fn words(block: &[u8; BLOCK]) -> [u32; 16] {
    let mut m = [0; 16];

    for (word, bytes) in m.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }

    m
}

pub(crate) fn key_words(key: &[u8; KEY]) -> [u32; 8] {
    let mut k = [0; 8];

    for (word, bytes) in k.iter_mut().zip(key.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }

    k
}

fn cv_bytes(cv: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0; 32];

    for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(cv) {
        *chunk = word.to_le_bytes();
    }

    bytes
}

// What hash_many's inputs share (the reference implementation's hash_many): each has `blocks`
// whole blocks and is hashed from the key, input i with the counter plus i if `increment` (chunks)
// or the counter itself (parents), its first block with `start` added to the flags and its last
// with `end`.
pub(crate) struct Many<'a> {
    pub(crate) key: &'a [u32; 8],
    pub(crate) blocks: usize,
    pub(crate) counter: u64,
    pub(crate) increment: bool,
    pub(crate) flags: u32,
    pub(crate) start: u32,
    pub(crate) end: u32,
}

// The chaining values of the inputs into out, input i being input[i * blocks * 64..] for
// out.len() inputs: as many as the kernels take, side by side, and the rest one by one.
fn hash_many(input: &[u8], many: &Many, out: &mut [[u8; 32]]) {
    let size = many.blocks * BLOCK;

    debug_assert_eq!(input.len(), out.len() * size);

    let mut done = cpu::blake3_many(input, many, out);

    // Two inputs left: their chains side by side, which keeps more of the scalar pipes busy than
    // one chain after the other.
    if out.len() - done == 2 {
        let counter = |i: usize| {
            if many.increment {
                many.counter + i as u64
            } else {
                many.counter
            }
        };

        let (first, second) = input[done * size..].split_at(size);

        let mut pair = chain_blocks_pair(
            many.key,
            [first.as_chunks().0, second.as_chunks().0],
            [counter(done), counter(done + 1)],
            many.flags,
            [many.start, many.end],
        );

        out[done] = cv_bytes(&pair[0]);

        out[done + 1] = cv_bytes(&pair[1]);

        wipe(pair.as_flattened_mut());

        done += 2;
    }

    for (i, (cv, bytes)) in out
        .iter_mut()
        .zip(input.chunks_exact(size))
        .enumerate()
        .skip(done)
    {
        let counter = if many.increment {
            many.counter + i as u64
        } else {
            many.counter
        };

        let (blocks, _) = bytes.as_chunks::<BLOCK>();

        let mut state = chain_blocks(
            many.key,
            blocks,
            counter,
            many.flags,
            [many.start, many.end],
            None,
        );

        *cv = cv_bytes(&state);

        wipe(&mut state);
    }
}

// A node before its chaining value is taken. The root squeezes any number of 64-byte blocks from
// it, block i with counter i.
#[derive(Clone)]
struct Output {
    cv: [u32; 8],
    block: [u8; BLOCK],
    counter: u64,
    length: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        chain(&self.cv, &self.block, self.counter, self.length, self.flags)
    }

    // The root's output from byte `offset` on, into out.
    fn root(&self, offset: u64, out: &mut [u8]) {
        let flags = self.flags | ROOT;

        // A digest of at most 32 bytes needs only the chaining value's half of the output.
        if offset == 0 && out.len() <= 32 {
            let mut v = chain(&self.cv, &self.block, 0, self.length, flags);

            write_words(&v, out);

            wipe(&mut v);

            return;
        }

        let mut index = offset / BLOCK as u64;

        let mut skip = (offset % BLOCK as u64) as usize;

        let mut bytes = [0; BLOCK];

        let mut m = words(&self.block);

        let mut rest = out;

        while !rest.is_empty() {
            // Whole blocks from a block boundary on, as many as the kernels take side by side.
            if skip == 0 {
                let (blocks, _) = rest.as_chunks_mut::<BLOCK>();

                let done = cpu::blake3_xof(&self.cv, &m, index, [self.length, flags], blocks);

                rest = &mut core::mem::take(&mut rest)[done * BLOCK..];

                index = index.wrapping_add(done as u64);

                if rest.is_empty() {
                    break;
                }
            }

            let mut v = compress(&self.cv, &self.block, index, self.length, flags);

            for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(&v) {
                *chunk = word.to_le_bytes();
            }

            wipe(&mut v);

            let take = (BLOCK - skip).min(rest.len());

            let (head, tail) = core::mem::take(&mut rest).split_at_mut(take);

            head.copy_from_slice(&bytes[skip..skip + take]);

            rest = tail;

            skip = 0;

            index = index.wrapping_add(1);
        }

        wipe(&mut bytes);

        wipe(&mut m);
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        wipe(&mut self.cv);

        wipe(&mut self.block);
    }
}

// The nodes below are built with a zero block that is then filled in place, so that no copy of
// message bytes or chaining values is left behind on the stack by a move.
fn parent(key: &[u32; 8], flags: u32, left: &[u32; 8], right: &[u32; 8]) -> Output {
    let mut output = Output {
        cv: *key,
        block: [0; BLOCK],
        counter: 0,
        length: BLOCK as u32,
        flags: flags | PARENT,
    };

    for (bytes, word) in output
        .block
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(left.iter().chain(right))
    {
        *bytes = word.to_le_bytes();
    }

    output
}

// The blocks of at most a chunk but the last, which may be partial or empty, and the flags of
// that last block.
fn split_chunk(data: &[u8], flags: u32) -> (&[[u8; BLOCK]], &[u8], u32) {
    let (blocks, _) = data[..data.len().saturating_sub(1) / BLOCK * BLOCK].as_chunks::<BLOCK>();

    let last = &data[blocks.len() * BLOCK..];

    let start = if blocks.is_empty() { CHUNK_START } else { 0 };

    (blocks, last, flags | start | CHUNK_END)
}

// A chunk of at most CHUNK bytes as a node: every block but the last compressed.
fn chunk(key: &[u32; 8], flags: u32, counter: u64, data: &[u8]) -> Output {
    let (blocks, rest, last_flags) = split_chunk(data, flags);

    let mut output = Output {
        cv: [0; 8],
        block: [0; BLOCK],
        counter,
        length: rest.len() as u32,
        flags: last_flags,
    };

    output.cv = chain_blocks(key, blocks, counter, flags, [CHUNK_START, 0], None);

    output.block[..rest.len()].copy_from_slice(rest);

    output
}

// The first N output words of the root, N being 8 or 16, for at most a chunk of input: its
// blocks, then the last one as the root, with no node in memory between them. With whole blocks,
// the first eight words take a single pass, as the last block's chain is the output.
fn single<const N: usize>(key: &[u32; 8], flags: u32, data: &[u8]) -> [u32; N] {
    let (whole, partial) = data.as_chunks::<BLOCK>();

    if N == 8 && partial.is_empty() && !whole.is_empty() {
        let mut v = chain_blocks(key, whole, 0, flags, [CHUNK_START, CHUNK_END | ROOT], None);

        let words = core::array::from_fn(|i| v[i]);

        wipe(&mut v);

        return words;
    }

    let (blocks, rest, last_flags) = split_chunk(data, flags);

    let mut last = [0; BLOCK];

    last[..rest.len()].copy_from_slice(rest);

    let length = rest.len() as u32;

    // The last block in the same pass as the others, where only the chaining value's half of the
    // output is needed.
    if N == 8 {
        let tail = Some((&last, length, last_flags | ROOT));

        let mut v = chain_blocks(key, blocks, 0, flags, [CHUNK_START, 0], tail);

        let words = core::array::from_fn(|i| v[i]);

        wipe(&mut v);

        wipe(&mut last);

        return words;
    }

    let mut cv = *key;

    if !blocks.is_empty() {
        cv = chain_blocks(key, blocks, 0, flags, [CHUNK_START, 0], None);
    }

    let mut v = compress(&cv, &last, 0, length, last_flags | ROOT);

    let words = core::array::from_fn(|i| v[i]);

    wipe(&mut v);

    wipe(&mut cv);

    wipe(&mut last);

    words
}

// The first out.len() bytes of output words, at most all of them.
fn write_words<const N: usize>(v: &[u32; N], out: &mut [u8]) {
    if let Ok(out) = <&mut [u8; 32]>::try_from(&mut *out) {
        for (bytes, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(v) {
            *bytes = word.to_le_bytes();
        }

        return;
    }

    let mut bytes = [0; BLOCK];

    for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(v) {
        *chunk = word.to_le_bytes();
    }

    out.copy_from_slice(&bytes[..out.len()]);

    wipe(&mut bytes);
}

// The two children of the root of the subtree of the chunks of `data`, at least two and at most
// WIDE of them, the first one numbered `counter`: hash_many for the whole chunks, then for each
// level of parents, with the last value of an odd level carried up to the next, which builds the
// tree of the specification.
fn leaves(key: &[u32; 8], flags: u32, counter: u64, data: &[u8]) -> [[u32; 8]; 2] {
    let mut cvs = [[0; 32]; WIDE];

    let whole = data.len() / CHUNK;

    let (full, last) = data.split_at(whole * CHUNK);

    let chunks = Many {
        key,
        blocks: CHUNK / BLOCK,
        counter,
        increment: true,
        flags,
        start: CHUNK_START,
        end: CHUNK_END,
    };

    hash_many(full, &chunks, &mut cvs[..whole]);

    let mut count = whole;

    if !last.is_empty() {
        let mut cv = chunk(key, flags, counter + whole as u64, last).chaining_value();

        cvs[count] = cv_bytes(&cv);

        wipe(&mut cv);

        count += 1;
    }

    let parents = Many {
        key,
        blocks: 1,
        counter: 0,
        increment: false,
        flags: flags | PARENT,
        start: 0,
        end: 0,
    };

    let mut level = [[0; 32]; WIDE / 2];

    while count > 2 {
        let pairs = count / 2;

        hash_many(
            cvs[..2 * pairs].as_flattened(),
            &parents,
            &mut level[..pairs],
        );

        cvs[..pairs].copy_from_slice(&level[..pairs]);

        if count % 2 == 1 {
            cvs[pairs] = cvs[count - 1];
        }

        count = pairs + count % 2;
    }

    let children = [key_words(&cvs[0]), key_words(&cvs[1])];

    wipe(level.as_flattened_mut());

    wipe(cvs.as_flattened_mut());

    children
}

// The top node of at most WIDE chunks whose first one is numbered `counter`: the chunk, or the
// parent of leaves' two children.
fn top(key: &[u32; 8], flags: u32, counter: u64, data: &[u8]) -> Output {
    if data.len() <= CHUNK {
        return chunk(key, flags, counter, data);
    }

    let mut halves = leaves(key, flags, counter, data);

    let node = parent(key, flags, &halves[0], &halves[1]);

    wipe(halves.as_flattened_mut());

    node
}

// The top node of the subtree of `data`, whose first chunk is numbered `counter`, a multiple of
// the subtree's chunks rounded up to a power of two. The groups of WIDE chunks before the last
// are hashed one after the other, and their chaining values merge on a stack as each completes a
// subtree; the last group, whole or not, is the rightmost node, into which the stack then merges
// from the right, as the tree of the specification does. The stack has a fixed size however long
// the input: a recursion over the halves took 3.4 KiB of stack per doubling.
fn node(key: &[u32; 8], flags: u32, counter: u64, data: &[u8]) -> Output {
    const GROUP: usize = WIDE * CHUNK;

    if data.len() <= GROUP {
        return top(key, flags, counter, data);
    }

    let (head, last) = data.split_at(data.len() - ((data.len() - 1) % GROUP + 1));

    let mut stack = [[0; 8]; MAX_DEPTH];

    let (mut depth, mut peak) = (0, 0);

    for (i, group) in head.as_chunks::<GROUP>().0.iter().enumerate() {
        let mut cv = top(key, flags, counter + (i * WIDE) as u64, group).chaining_value();

        let mut total = i + 1;

        while total & 1 == 0 {
            depth -= 1;

            cv = parent(key, flags, &stack[depth], &cv).chaining_value();

            total >>= 1;
        }

        stack[depth] = cv;

        depth += 1;

        peak = peak.max(depth);

        wipe(&mut cv);
    }

    let mut output = top(key, flags, counter + (head.len() / CHUNK) as u64, last);

    for left in stack[..depth].iter().rev() {
        let mut right = output.chaining_value();

        output = parent(key, flags, left, &right);

        wipe(&mut right);
    }

    wipe(stack[..peak].as_flattened_mut());

    output
}

// The root node of the whole input.
fn tree(key: &[u32; 8], flags: u32, data: &[u8]) -> Output {
    node(key, flags, 0, data)
}

// An incremental hash in one of the three modes; once read, the root and the offset of the next
// output byte.
#[derive(Clone)]
pub(crate) struct Hasher {
    key: [u32; 8],
    flags: u32,
    cv: [u32; 8],
    chunk: u64,
    blocks: u8,
    buffer: [u8; BLOCK],
    filled: usize,
    stack: [[u32; 8]; MAX_DEPTH],
    depth: usize,
    // The deepest the stack has been: the entries that Drop wipes.
    peak: usize,
    root: Option<Output>,
    offset: u64,
}

impl Hasher {
    const fn new(key: [u32; 8], flags: u32) -> Self {
        Self {
            key,
            flags,
            cv: key,
            chunk: 0,
            blocks: 0,
            buffer: [0; BLOCK],
            filled: 0,
            stack: [[0; 8]; MAX_DEPTH],
            depth: 0,
            peak: 0,
            root: None,
            offset: 0,
        }
    }

    pub(crate) const fn hash() -> Self {
        Self::new(IV_256, 0)
    }

    // Turns a new hash() hasher into keyed_hash under a key of exactly KEY bytes, which the
    // callers check. The key words go into the hasher where it lives, so that no keyed copy of it
    // is moved.
    pub(crate) fn key(&mut self, key: &[u8]) {
        let key: &[u8; KEY] = key.try_into().expect("a 32-byte key");

        for ((word, cv), bytes) in self
            .key
            .iter_mut()
            .zip(&mut self.cv)
            .zip(key.as_chunks::<4>().0)
        {
            *word = u32::from_le_bytes(*bytes);

            *cv = *word;
        }

        self.flags = KEYED_HASH;
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        assert!(self.root.is_none(), "UNSUPPORTED: cannot update after read");

        while !data.is_empty() {
            if self.filled == BLOCK {
                let mut cv = self.next(core::slice::from_ref(&self.buffer));

                self.advance(&mut cv, 1);

                self.filled = 0;
            }

            if self.filled == 0 {
                if self.blocks == 0 {
                    data = self.subtrees(data);
                }

                while data.len() > BLOCK {
                    let room = (BLOCKS - self.blocks) as usize;

                    let count = ((data.len() - 1) / BLOCK).min(room);

                    let (blocks, rest) = data.split_at(count * BLOCK);

                    let (blocks, _) = blocks.as_chunks::<BLOCK>();

                    let mut cv = self.next(blocks);

                    self.advance(&mut cv, count as u8);

                    data = rest;
                }
            }

            let take = (BLOCK - self.filled).min(data.len());

            self.buffer[self.filled..self.filled + take].copy_from_slice(&data[..take]);

            self.filled += take;

            data = &data[take..];
        }
    }

    // At a chunk boundary, the largest whole subtrees that more input follows, each of a power of
    // two of chunks that divides the chunk counter; returns the rest.
    fn subtrees<'a>(&mut self, mut data: &'a [u8]) -> &'a [u8] {
        while data.len() > CHUNK {
            let fits = ((data.len() - 1) / CHUNK).ilog2();

            let level = fits.min(self.chunk.trailing_zeros());

            let (subtree, rest) = data.split_at(CHUNK << level);

            let mut cv = if level == 0 {
                self.chunk_value(subtree)
            } else {
                node(&self.key, self.flags, self.chunk, subtree).chaining_value()
            };

            self.push(&mut cv, level);

            data = rest;
        }

        data
    }

    // A whole chunk's chaining value, through hash_many for its kernels' single-chunk paths.
    fn chunk_value(&self, data: &[u8]) -> [u32; 8] {
        let mut cv = [[0; 32]; 1];

        let many = Many {
            key: &self.key,
            blocks: CHUNK / BLOCK,
            counter: self.chunk,
            increment: true,
            flags: self.flags,
            start: CHUNK_START,
            end: CHUNK_END,
        };

        hash_many(data, &many, &mut cv);

        let words = key_words(&cv[0]);

        wipe(cv.as_flattened_mut());

        words
    }

    // The chaining value of a complete subtree of 2^level chunks, which merges with every subtree
    // that it completes and then joins the stack; wipes cv.
    fn push(&mut self, cv: &mut [u32; 8], level: u32) {
        self.chunk += 1 << level;

        let mut total = self.chunk >> level;

        while total & 1 == 0 {
            self.depth -= 1;

            *cv = parent(&self.key, self.flags, &self.stack[self.depth], cv).chaining_value();

            total >>= 1;
        }

        self.stack[self.depth] = *cv;

        self.depth += 1;

        self.peak = self.peak.max(self.depth);

        wipe(cv);
    }

    // The chaining value after whole blocks of the current chunk that more input follows.
    fn next(&self, blocks: &[[u8; BLOCK]]) -> [u32; 8] {
        let start = if self.blocks == 0 { CHUNK_START } else { 0 };

        let end = if self.blocks as usize + blocks.len() == BLOCKS as usize {
            CHUNK_END
        } else {
            0
        };

        chain_blocks(&self.cv, blocks, self.chunk, self.flags, [start, end], None)
    }

    // The chain after `count` more blocks; the chunk's last one ends the chunk. Wipes cv.
    fn advance(&mut self, cv: &mut [u32; 8], count: u8) {
        self.blocks += count;

        if self.blocks < BLOCKS {
            self.cv = *cv;

            wipe(cv);

            return;
        }

        self.push(cv, 0);

        self.cv = self.key;

        self.blocks = 0;
    }

    // The root: the current chunk's last block, then the parents up the stack.
    fn output(&self) -> Output {
        let start = if self.blocks == 0 { CHUNK_START } else { 0 };

        let mut output = Output {
            cv: self.cv,
            block: [0; BLOCK],
            counter: self.chunk,
            length: self.filled as u32,
            flags: self.flags | start | CHUNK_END,
        };

        output.block[..self.filled].copy_from_slice(&self.buffer[..self.filled]);

        for left in self.stack[..self.depth].iter().rev() {
            let mut right = output.chaining_value();

            output = parent(&self.key, self.flags, left, &right);

            wipe(&mut right);
        }

        output
    }

    // The output from its start, which leaves the state as it was.
    pub(crate) fn finish(&self, out: &mut [u8]) {
        self.output().root(0, out);
    }

    // How many more bytes read can give: the output of one hasher ends after 2^64 - 1 bytes.
    pub(crate) const fn output_left(&self) -> u64 {
        u64::MAX - self.offset
    }

    // The next out.len() bytes of the output, at most output_left(); no update follows.
    pub(crate) fn read(&mut self, out: &mut [u8]) {
        if self.root.is_none() {
            self.root = Some(self.output());
        }

        if let Some(root) = &self.root {
            root.root(self.offset, out);
        }

        self.offset += out.len() as u64;
    }
}

impl Drop for Hasher {
    fn drop(&mut self) {
        wipe(&mut self.key);

        wipe(&mut self.cv);

        wipe(&mut self.buffer);

        wipe(self.stack[..self.peak].as_flattened_mut());
    }
}

// The key of derive_key's second stage: the context string hashed in its own mode.
fn context_key(context: &[u8]) -> [u32; 8] {
    if context.len() <= CHUNK {
        return single(&IV_256, DERIVE_KEY_CONTEXT, context);
    }

    let output = tree(&IV_256, DERIVE_KEY_CONTEXT, context);

    chain(
        &output.cv,
        &output.block,
        0,
        output.length,
        output.flags | ROOT,
    )
}

// At most 32 bytes of the root's output for at most a block of input, whose flags the caller
// gives: one compression, its output words straight into out.
fn digest1(key: &[u32; 8], flags: u32, data: &[u8], out: &mut [u8]) {
    let mut copy = [0; BLOCK];

    let block = match <&[u8; BLOCK]>::try_from(data) {
        Ok(block) => block,
        Err(_) => {
            copy[..data.len()].copy_from_slice(data);

            &copy
        }
    };

    let v = rounds(key, &words(block), 0, data.len() as u32, flags);

    let mut bytes = [0; 32];

    let target = match <&mut [u8; 32]>::try_from(&mut *out) {
        Ok(whole) => whole,
        Err(_) => &mut bytes,
    };

    for (i, chunk) in target.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        *chunk = (v[i] ^ v[i + 8]).to_le_bytes();
    }

    if out.len() < 32 {
        out.copy_from_slice(&bytes[..out.len()]);

        wipe(&mut bytes);
    }

    wipe(&mut copy);
}

// out.len() bytes of output for data in one call.
fn one_shot(key: &[u32; 8], flags: u32, data: &[u8], out: &mut [u8]) {
    let root = flags | CHUNK_START | CHUNK_END | ROOT;

    if data.len() <= BLOCK && out.len() <= 32 {
        if !cpu::blake3_digest1(key, root, data, out) {
            digest1(key, root, data, out);
        }

        return;
    }

    if data.len() <= CHUNK && out.len() <= 32 {
        let mut v = single::<8>(key, flags, data);

        write_words(&v, out);

        wipe(&mut v);
    } else if data.len() <= CHUNK && out.len() <= BLOCK {
        let mut v = single::<16>(key, flags, data);

        write_words(&v, out);

        wipe(&mut v);
    } else {
        tree(key, flags, data).root(0, out);
    }
}

// hash: out.len() bytes of output.
pub(crate) fn digest(data: &[u8], out: &mut [u8]) {
    one_shot(&IV_256, 0, data, out);
}

pub(crate) fn keyed_hash(key: &[u8], data: &[u8], out: &mut [u8]) {
    let mut k = key_words(key.try_into().expect("a 32-byte key"));

    one_shot(&k, KEYED_HASH, data, out);

    wipe(&mut k);
}

// derive_key(context, key material) into out.
pub(crate) fn derive_key(context: &[u8], material: &[u8], out: &mut [u8]) {
    let mut k = context_key(context);

    one_shot(&k, DERIVE_KEY_MATERIAL, material, out);

    wipe(&mut k);
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::cpu::testing::{EDGES, Inputs};

    // The portable compression, which every kernel must match.
    fn portable(
        cv: &[u32; 8],
        block: &[u8; BLOCK],
        counter: u64,
        length: u32,
        flags: u32,
    ) -> [u32; 16] {
        let v = rounds(cv, &words(block), counter, length, flags);

        core::array::from_fn(|i| {
            if i < 8 {
                v[i] ^ v[i + 8]
            } else {
                v[i] ^ cv[i - 8]
            }
        })
    }

    fn portable_chain(
        cv: &[u32; 8],
        blocks: &[[u8; BLOCK]],
        counter: u64,
        flags: u32,
        [start, end]: [u32; 2],
    ) -> [u32; 8] {
        let mut h = *cv;

        for (i, block) in blocks.iter().enumerate() {
            let mut f = flags;

            if i == 0 {
                f |= start;
            }

            if i + 1 == blocks.len() {
                f |= end;
            }

            h = *portable(&h, block, counter, BLOCK as u32, f)
                .first_chunk()
                .expect("sixteen words");
        }

        h
    }

    // A counter at a carry into its high word, near the end of its range, or random.
    fn counter(inputs: &mut Inputs, n: usize) -> u64 {
        match n % 4 {
            0 => 0,
            1 => u64::from(u32::MAX) - (inputs.next() % 9),
            2 => u64::MAX - (inputs.next() % 40),
            _ => inputs.next(),
        }
    }

    fn state(inputs: &mut Inputs, n: usize) -> [u32; 8] {
        match EDGES.get(n % 7) {
            Some(&edge) => [edge as u32; 8],
            None => core::array::from_fn(|_| inputs.next() as u32),
        }
    }

    fn random(inputs: &mut Inputs, length: usize) -> Vec<u8> {
        (0..length).map(|_| inputs.next() as u8).collect()
    }

    // Every kernel against the portable compression: hash_many on 1 to 20 inputs of one block
    // (parents) or a chunk, the extended output of 0 to 20 blocks, a chunk's chain of 0 to 16
    // blocks and single compressions of every length, from edge and random states and counters.
    #[test]
    fn blake3_kernels_match_portable() {
        let mut inputs = Inputs::new(3);

        let mut accelerated = [0; 5];

        for n in 0..400 {
            let key = state(&mut inputs, n);

            let count = 1 + n % 20;

            // Parents, chunks, the lengths between, and one past what the kernels take.
            let blocks = match n % 4 {
                0 => 1,
                1 => CHUNK / BLOCK,
                2 => 1 + n % 16,
                _ => CHUNK / BLOCK + 1,
            };

            let input = random(&mut inputs, count * blocks * BLOCK);

            let base = if n % 3 == 0 {
                counter(&mut inputs, n) % (1 << 40)
            } else {
                counter(&mut inputs, n)
            };

            let many = Many {
                key: &key,
                blocks,
                counter: base.min(u64::MAX - count as u64),
                increment: blocks > 1,
                flags: (inputs.next() as u32) & 0x71,
                start: if blocks > 1 { CHUNK_START } else { 0 },
                end: if blocks > 1 { CHUNK_END } else { 0 },
            };

            let mut out = vec![[0; 32]; count];

            let done = cpu::blake3_many(&input, &many, &mut out);

            assert!(done <= count);

            if blocks > CHUNK / BLOCK {
                assert_eq!(
                    done, 0,
                    "hash_many case {n}: more blocks than the kernels take"
                );
            }

            for (i, (cv, bytes)) in out
                .iter()
                .zip(input.chunks_exact(blocks * BLOCK))
                .enumerate()
                .take(done)
            {
                let c = if many.increment {
                    many.counter + i as u64
                } else {
                    many.counter
                };

                let expected = portable_chain(
                    &key,
                    bytes.as_chunks::<BLOCK>().0,
                    c,
                    many.flags,
                    [many.start, many.end],
                );

                assert_eq!(*cv, cv_bytes(&expected), "hash_many case {n} input {i}");
            }

            accelerated[0] += done;

            let root: [u8; BLOCK] = core::array::from_fn(|_| inputs.next() as u8);

            let mut out = vec![[0; BLOCK]; n % 21];

            let start = counter(&mut inputs, n);

            let info = [
                (inputs.next() % 65) as u32,
                (inputs.next() as u32) & 0x7F | ROOT,
            ];

            let done = cpu::blake3_xof(&key, &words(&root), start, info, &mut out);

            for (i, block) in out.iter().enumerate().take(done) {
                let v = portable(&key, &root, start.wrapping_add(i as u64), info[0], info[1]);

                let mut bytes = [0; BLOCK];

                for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(&v) {
                    *chunk = word.to_le_bytes();
                }

                assert_eq!(*block, bytes, "xof case {n} block {i}");
            }

            accelerated[1] += done;

            let blocks = random(&mut inputs, (n % 17) * BLOCK);

            let (blocks, _) = blocks.as_chunks::<BLOCK>();

            let c = counter(&mut inputs, n);

            let flags = (inputs.next() as u32) & 0x7F;

            let edges = [CHUNK_START, if n % 2 == 0 { CHUNK_END | ROOT } else { 0 }];

            let mut h = key;

            let tail: [u8; BLOCK] = core::array::from_fn(|_| inputs.next() as u8);

            let tail = (n % 3 == 0).then_some((&tail, (n % 65) as u32, flags | CHUNK_END));

            if cpu::blake3_blocks(&mut h, blocks, c, flags, edges, tail) {
                let mut expected = portable_chain(&key, blocks, c, flags, edges);

                if let Some((block, length, f)) = tail {
                    expected = *portable(&expected, block, c, length, f)
                        .first_chunk()
                        .expect("sixteen words");
                }

                assert_eq!(h, expected, "chain case {n}");

                accelerated[2] += 1;
            }

            let block: [u8; BLOCK] = core::array::from_fn(|_| inputs.next() as u8);

            let length = (n % 65) as u32;

            let mut out = [0; 16];

            if cpu::blake3_compress(&key, &block, c, [length, flags], &mut out) {
                assert_eq!(
                    out,
                    portable(&key, &block, c, length, flags),
                    "compress case {n}"
                );

                accelerated[3] += 1;
            }

            let mut padded = block;

            padded[length as usize..].fill(0);

            let size = 1 + n % 32;

            let mut digest = [0; 32];

            if cpu::blake3_digest1(&key, flags, &block[..length as usize], &mut digest[..size]) {
                let expected = cv_bytes(
                    portable(&key, &padded, 0, length, flags)
                        .first_chunk()
                        .expect("sixteen words"),
                );

                assert_eq!(digest[..size], expected[..size], "digest case {n}");

                accelerated[4] += 1;
            }
        }

        std::eprintln!(
            "BLAKE3 kernels: hash_many {} inputs, extended output {} blocks, chains {}, \
             compressions {} and digests {} of 400 cases",
            accelerated[0],
            accelerated[1],
            accelerated[2],
            accelerated[3],
            accelerated[4]
        );
    }

    // The specification's tree, recursively, on the portable compression alone: the node of the
    // data from chunk `counter` on, its chaining value not yet taken.
    fn reference_node(
        key: &[u32; 8],
        flags: u32,
        counter: u64,
        data: &[u8],
    ) -> ([u32; 8], [u8; BLOCK], u32, u64, u32) {
        if data.len() <= CHUNK {
            let mut cv = *key;

            let mut rest = data;

            let mut start = CHUNK_START;

            while rest.len() > BLOCK {
                let (block, tail) = rest.split_first_chunk::<BLOCK>().expect("a block");

                cv = *portable(&cv, block, counter, BLOCK as u32, flags | start)
                    .first_chunk()
                    .expect("words");

                start = 0;

                rest = tail;
            }

            let mut block = [0; BLOCK];

            block[..rest.len()].copy_from_slice(rest);

            return (
                cv,
                block,
                rest.len() as u32,
                counter,
                flags | start | CHUNK_END,
            );
        }

        // The largest power of two of chunks that leaves at least one byte.
        let left = 1usize << ((data.len() - 1) / CHUNK).ilog2();

        let (head, tail) = data.split_at(left * CHUNK);

        let l = reference_cv(key, flags, counter, head);

        let r = reference_cv(key, flags, counter + left as u64, tail);

        let mut block = [0; BLOCK];

        block[..32].copy_from_slice(&cv_bytes(&l));

        block[32..].copy_from_slice(&cv_bytes(&r));

        (*key, block, BLOCK as u32, 0, flags | PARENT)
    }

    fn reference_cv(key: &[u32; 8], flags: u32, counter: u64, data: &[u8]) -> [u32; 8] {
        let (cv, block, length, c, f) = reference_node(key, flags, counter, data);

        *portable(&cv, &block, c, length, f)
            .first_chunk()
            .expect("words")
    }

    fn reference(key: &[u32; 8], flags: u32, data: &[u8], offset: u64, out: &mut [u8]) {
        let (cv, block, length, _, f) = reference_node(key, flags, 0, data);

        for (i, byte) in out.iter_mut().enumerate() {
            let position = offset + i as u64;

            let v = portable(&cv, &block, position / BLOCK as u64, length, f | ROOT);

            let word = v[(position % BLOCK as u64 / 4) as usize];

            *byte = word.to_le_bytes()[(position % 4) as usize];
        }
    }

    fn context_reference(context: &[u8]) -> [u32; 8] {
        let mut k = [0; KEY];

        reference(&IV_256, DERIVE_KEY_CONTEXT, context, 0, &mut k);

        key_words(&k)
    }

    // The three modes, one-shot, incremental in uneven pieces and read in pieces, against the
    // reference, for the edge lengths of blocks, chunks and subtrees and for random lengths up to
    // 1 MiB: whatever kernels the CPU has, the outputs are the specification's.
    #[test]
    fn blake3_kernel_tree_matches_reference() {
        let mut inputs = Inputs::new(5);

        let mut lengths = vec![
            0,
            1,
            63,
            64,
            65,
            127,
            128,
            1023,
            1024,
            1025,
            2047,
            2048,
            2049,
            3072,
            3073,
            4096,
            4097,
            5 * 1024,
            7 * 1024 + 1,
            8 * 1024,
            8 * 1024 + 1,
            9 * 1024,
            16 * 1024,
            31 * 1024 + 5,
            32 * 1024,
            32 * 1024 + 1,
            33 * 1024,
            65 * 1024 + 1,
            100 * 1024 - 1,
        ];

        for _ in 0..6 {
            lengths.push((inputs.next() % (1 << 20)) as usize);
        }

        lengths.push(1 << 20);

        let data = random(&mut inputs, 1 << 20);

        let key_bytes: [u8; KEY] = inputs.bytes();

        let key = key_words(&key_bytes);

        let context = random(&mut inputs, 1100);

        for (n, &length) in lengths.iter().enumerate() {
            let data = &data[..length];

            let size = [32, 1, 64, 65, 300, 1031][n % 6];

            let context = &context[..[0, 47, 1024, 1025, 1100][n % 5]];

            let derived = context_reference(context);

            for (flags, k) in [
                (0, IV_256),
                (KEYED_HASH, key),
                (DERIVE_KEY_MATERIAL, derived),
            ] {
                let mut expected = vec![0; size];

                reference(&k, flags, data, 0, &mut expected);

                let mut actual = vec![0; size];

                match flags {
                    0 => digest(data, &mut actual),
                    KEYED_HASH => keyed_hash(&key_bytes, data, &mut actual),
                    _ => derive_key(context, data, &mut actual),
                }

                assert_eq!(actual, expected, "length {length} flags {flags} one-shot");

                let mut hasher = match flags {
                    0 => Hasher::hash(),
                    KEYED_HASH => {
                        let mut hasher = Hasher::hash();

                        hasher.key(&key_bytes);

                        hasher
                    }
                    _ => Hasher::new(derived, DERIVE_KEY_MATERIAL),
                };

                let mut rest = data;

                while !rest.is_empty() {
                    let piece = match inputs.next() % 4 {
                        0 => inputs.next() as usize % 70,
                        1 => inputs.next() as usize % 3000,
                        2 => CHUNK * (1 + inputs.next() as usize % 40),
                        _ => inputs.next() as usize % 70_000,
                    }
                    .min(rest.len());

                    hasher.update(&rest[..piece]);

                    rest = &rest[piece..];
                }

                hasher.finish(&mut actual);

                assert_eq!(
                    actual, expected,
                    "length {length} flags {flags} incremental"
                );

                let offset = inputs.next() % 200;

                let mut tail = vec![0; size];

                reference(&k, flags, data, offset, &mut tail);

                let mut skipped = vec![0; offset as usize];

                hasher.read(&mut skipped);

                let (first, second) = actual.split_at_mut(size / 3);

                hasher.read(first);

                hasher.read(second);

                assert_eq!(
                    actual, tail,
                    "length {length} flags {flags} read from {offset}"
                );
            }
        }
    }
}

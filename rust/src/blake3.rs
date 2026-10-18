// BLAKE3 (the BLAKE3 specification, BLAKE3-team/BLAKE3-specs) on one thread: the hash and its
// extended output, keyed_hash and derive_key. The input splits into chunks of sixteen 64-byte
// blocks. A chunk's last block is compressed only once more input shows that it is not the root's;
// the chaining value of each finished chunk goes on a stack, where the chaining values of complete
// subtrees are merged into their parent at once, so the root is known only at the end. In keyed
// and derive_key modes every chaining value derives from the key, so the states are wiped.

use crate::sha2::IV_256;
use crate::wipe::wipe;

pub(crate) const KEY: usize = 32;

const BLOCK: usize = 64;

const BLOCKS: u8 = 16;

// A chunk counter below 2^54 covers 2^64 bytes, and the stack holds one chaining value for each
// bit set in it.
const MAX_DEPTH: usize = 54;

const CHUNK_START: u32 = 1;

const CHUNK_END: u32 = 2;

const PARENT: u32 = 4;

const ROOT: u32 = 8;

const KEYED_HASH: u32 = 16;

const DERIVE_KEY_CONTEXT: u32 = 32;

const DERIVE_KEY_MATERIAL: u32 = 64;

const PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

// The message word order of each of the seven rounds: the permutation applied once more per round.
const SCHEDULE: [[usize; 16]; 7] = schedule();

const fn schedule() -> [[usize; 16]; 7] {
    let mut rounds = [[0; 16]; 7];

    let mut i = 0;

    while i < 16 {
        rounds[0][i] = i;

        i += 1;
    }

    let mut r = 1;

    while r < 7 {
        let mut i = 0;

        while i < 16 {
            rounds[r][i] = rounds[r - 1][PERMUTATION[i]];

            i += 1;
        }

        r += 1;
    }

    rounds
}

#[inline(always)]
fn g(v: &mut [u32; 16], [a, b, c, d]: [usize; 4], x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);

    v[d] = (v[d] ^ v[a]).rotate_right(16);

    v[c] = v[c].wrapping_add(v[d]);

    v[b] = (v[b] ^ v[c]).rotate_right(12);

    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);

    v[d] = (v[d] ^ v[a]).rotate_right(8);

    v[c] = v[c].wrapping_add(v[d]);

    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

// The sixteen output words of the chaining value cv over the message words m, with the 64-bit
// counter, the block's length and the domain flags; the first eight are the next chaining value.
fn compress(cv: &[u32; 8], m: &[u32; 16], counter: u64, length: u32, flags: u32) -> [u32; 16] {
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

    for s in &SCHEDULE {
        g(&mut v, [0, 4, 8, 12], m[s[0]], m[s[1]]);

        g(&mut v, [1, 5, 9, 13], m[s[2]], m[s[3]]);

        g(&mut v, [2, 6, 10, 14], m[s[4]], m[s[5]]);

        g(&mut v, [3, 7, 11, 15], m[s[6]], m[s[7]]);

        g(&mut v, [0, 5, 10, 15], m[s[8]], m[s[9]]);

        g(&mut v, [1, 6, 11, 12], m[s[10]], m[s[11]]);

        g(&mut v, [2, 7, 8, 13], m[s[12]], m[s[13]]);

        g(&mut v, [3, 4, 9, 14], m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        v[i] ^= v[i + 8];

        v[i + 8] ^= cv[i];
    }

    v
}

// The chaining value: compress's first eight words, the whole output wiped.
fn chain(cv: &[u32; 8], m: &[u32; 16], counter: u64, length: u32, flags: u32) -> [u32; 8] {
    let mut out = compress(cv, m, counter, length, flags);

    let next = *out.first_chunk().expect("sixteen words");

    wipe(&mut out);

    next
}

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

// A node before its chaining value is taken. The root squeezes any number of 64-byte blocks from
// it, block i with counter i.
#[derive(Clone)]
struct Output {
    cv: [u32; 8],
    block: [u32; 16],
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
        let mut index = offset / BLOCK as u64;

        let mut skip = (offset % BLOCK as u64) as usize;

        let mut bytes = [0; BLOCK];

        let mut rest = out;

        while !rest.is_empty() {
            let mut v = compress(&self.cv, &self.block, index, self.length, self.flags | ROOT);

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
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        wipe(&mut self.cv);

        wipe(&mut self.block);
    }
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
            root: None,
            offset: 0,
        }
    }

    pub(crate) const fn hash() -> Self {
        Self::new(IV_256, 0)
    }

    // keyed_hash under a key of exactly KEY bytes, which the callers check.
    pub(crate) fn keyed(key: &[u8]) -> Self {
        let mut k = key_words(key.try_into().expect("a 32-byte key"));

        let hasher = Self::new(k, KEYED_HASH);

        wipe(&mut k);

        hasher
    }

    // derive_key's second stage, keyed by the hash of the context string.
    pub(crate) fn derive(context: &[u8]) -> Self {
        let mut stage = Self::new(IV_256, DERIVE_KEY_CONTEXT);

        stage.update(context);

        let mut context_key = [0; KEY];

        stage.finish(&mut context_key);

        let mut k = key_words(&context_key);

        let hasher = Self::new(k, DERIVE_KEY_MATERIAL);

        wipe(&mut k);

        wipe(&mut context_key);

        hasher
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        assert!(self.root.is_none(), "UNSUPPORTED: cannot update after read");

        while !data.is_empty() {
            if self.filled == BLOCK {
                let mut m = words(&self.buffer);

                self.absorb(&m);

                wipe(&mut m);

                self.filled = 0;
            }

            if self.filled == 0 {
                while data.len() > BLOCK {
                    let (block, rest) = data.split_first_chunk().expect("more than a block");

                    let mut m = words(block);

                    self.absorb(&m);

                    wipe(&mut m);

                    data = rest;
                }
            }

            let take = (BLOCK - self.filled).min(data.len());

            self.buffer[self.filled..self.filled + take].copy_from_slice(&data[..take]);

            self.filled += take;

            data = &data[take..];
        }
    }

    // A whole block that more input follows. The chunk's last one ends the chunk, whose chaining
    // value joins the stack after merging every subtree that it completes.
    fn absorb(&mut self, m: &[u32; 16]) {
        let start = if self.blocks == 0 { CHUNK_START } else { 0 };

        if self.blocks < BLOCKS - 1 {
            self.cv = chain(&self.cv, m, self.chunk, BLOCK as u32, self.flags | start);

            self.blocks += 1;

            return;
        }

        let flags = self.flags | start | CHUNK_END;

        let mut cv = chain(&self.cv, m, self.chunk, BLOCK as u32, flags);

        self.chunk += 1;

        let mut total = self.chunk;

        while total & 1 == 0 {
            self.depth -= 1;

            cv = self.parent(&self.stack[self.depth], &cv).chaining_value();

            total >>= 1;
        }

        self.stack[self.depth] = cv;

        self.depth += 1;

        wipe(&mut cv);

        self.cv = self.key;

        self.blocks = 0;
    }

    fn parent(&self, left: &[u32; 8], right: &[u32; 8]) -> Output {
        let mut block = [0; 16];

        block[..8].copy_from_slice(left);

        block[8..].copy_from_slice(right);

        Output {
            cv: self.key,
            block,
            counter: 0,
            length: BLOCK as u32,
            flags: self.flags | PARENT,
        }
    }

    // The root: the current chunk's last block, then the parents up the stack.
    fn output(&self) -> Output {
        let mut last = [0; BLOCK];

        last[..self.filled].copy_from_slice(&self.buffer[..self.filled]);

        let start = if self.blocks == 0 { CHUNK_START } else { 0 };

        let mut output = Output {
            cv: self.cv,
            block: words(&last),
            counter: self.chunk,
            length: self.filled as u32,
            flags: self.flags | start | CHUNK_END,
        };

        wipe(&mut last);

        for left in self.stack[..self.depth].iter().rev() {
            let mut right = output.chaining_value();

            output = self.parent(left, &right);

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

        wipe(self.stack.as_flattened_mut());
    }
}

// hash: out.len() bytes of output.
pub(crate) fn digest(data: &[u8], out: &mut [u8]) {
    let mut hasher = Hasher::hash();

    hasher.update(data);

    hasher.finish(out);
}

pub(crate) fn keyed_hash(key: &[u8], data: &[u8], out: &mut [u8]) {
    let mut hasher = Hasher::keyed(key);

    hasher.update(data);

    hasher.finish(out);
}

// derive_key(context, key material) into out.
pub(crate) fn derive_key(context: &[u8], material: &[u8], out: &mut [u8]) {
    let mut hasher = Hasher::derive(context);

    hasher.update(material);

    hasher.finish(out);
}

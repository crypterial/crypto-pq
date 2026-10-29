use alloc::vec::Vec;

use crate::ct::declassify;
use crate::error::Error;
use crate::merkle::{MerkleTree, Node, TreeHasher};
use crate::primitives::TruncatedHash;
use crate::sha2::{IV_256, Sha256};
use crate::wipe::{SecretBytes, wipe};

const D_PBLC: [u8; 2] = [0x80, 0x80];

const D_MESG: [u8; 2] = [0x81, 0x81];

const D_LEAF: [u8; 2] = [0x82, 0x82];

const D_INTR: [u8; 2] = [0x83, 0x83];

// The values that the deterministic mode of SPEC 11.14 derives from a tree's I and SEED, as the
// hash-sigs reference of the RFC 8554 and RFC 9858 test cases does: the signature randomizer C,
// and the SEED and I of a child tree. Chain indices are below 0xFFFD.
const RANDOMIZER: u16 = 0xFFFD;

const CHILD_SEED: u16 = 0xFFFE;

const CHILD_I: u16 = 0xFFFF;

// The largest number of chains, p for n = 32 and w = 1.
const MAX_P: usize = 265;

// Hashes computed side by side (see Sha256::finish_lanes).
const LANES: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct OtsType {
    pub(crate) code: u32,
    name: &'static str,
    shake: bool,
    n: usize,
    w: u32,
}

const fn ots(code: u32, name: &'static str, shake: bool, n: usize, w: u32) -> OtsType {
    OtsType {
        code,
        name,
        shake,
        n,
        w,
    }
}

pub(crate) const OTS_TYPES: [OtsType; 16] = [
    ots(1, "LMOTS_SHA256_N32_W1", false, 32, 1),
    ots(2, "LMOTS_SHA256_N32_W2", false, 32, 2),
    ots(3, "LMOTS_SHA256_N32_W4", false, 32, 4),
    ots(4, "LMOTS_SHA256_N32_W8", false, 32, 8),
    ots(5, "LMOTS_SHA256_N24_W1", false, 24, 1),
    ots(6, "LMOTS_SHA256_N24_W2", false, 24, 2),
    ots(7, "LMOTS_SHA256_N24_W4", false, 24, 4),
    ots(8, "LMOTS_SHA256_N24_W8", false, 24, 8),
    ots(9, "LMOTS_SHAKE_N32_W1", true, 32, 1),
    ots(10, "LMOTS_SHAKE_N32_W2", true, 32, 2),
    ots(11, "LMOTS_SHAKE_N32_W4", true, 32, 4),
    ots(12, "LMOTS_SHAKE_N32_W8", true, 32, 8),
    ots(13, "LMOTS_SHAKE_N24_W1", true, 24, 1),
    ots(14, "LMOTS_SHAKE_N24_W2", true, 24, 2),
    ots(15, "LMOTS_SHAKE_N24_W4", true, 24, 4),
    ots(16, "LMOTS_SHAKE_N24_W8", true, 24, 8),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct LmsType {
    pub(crate) code: u32,
    name: &'static str,
    shake: bool,
    pub(crate) m: usize,
    pub(crate) h: u32,
}

const fn lms(code: u32, name: &'static str, shake: bool, m: usize, h: u32) -> LmsType {
    LmsType {
        code,
        name,
        shake,
        m,
        h,
    }
}

pub(crate) const LMS_TYPES: [LmsType; 20] = [
    lms(5, "LMS_SHA256_M32_H5", false, 32, 5),
    lms(6, "LMS_SHA256_M32_H10", false, 32, 10),
    lms(7, "LMS_SHA256_M32_H15", false, 32, 15),
    lms(8, "LMS_SHA256_M32_H20", false, 32, 20),
    lms(9, "LMS_SHA256_M32_H25", false, 32, 25),
    lms(10, "LMS_SHA256_M24_H5", false, 24, 5),
    lms(11, "LMS_SHA256_M24_H10", false, 24, 10),
    lms(12, "LMS_SHA256_M24_H15", false, 24, 15),
    lms(13, "LMS_SHA256_M24_H20", false, 24, 20),
    lms(14, "LMS_SHA256_M24_H25", false, 24, 25),
    lms(15, "LMS_SHAKE_M32_H5", true, 32, 5),
    lms(16, "LMS_SHAKE_M32_H10", true, 32, 10),
    lms(17, "LMS_SHAKE_M32_H15", true, 32, 15),
    lms(18, "LMS_SHAKE_M32_H20", true, 32, 20),
    lms(19, "LMS_SHAKE_M32_H25", true, 32, 25),
    lms(20, "LMS_SHAKE_M24_H5", true, 24, 5),
    lms(21, "LMS_SHAKE_M24_H10", true, 24, 10),
    lms(22, "LMS_SHAKE_M24_H15", true, 24, 15),
    lms(23, "LMS_SHAKE_M24_H20", true, 24, 20),
    lms(24, "LMS_SHAKE_M24_H25", true, 24, 25),
];

pub(crate) fn ots_by_name(name: &str) -> Option<OtsType> {
    OTS_TYPES.into_iter().find(|t| t.name == name)
}

pub(crate) fn lms_by_name(name: &str) -> Option<LmsType> {
    LMS_TYPES.into_iter().find(|t| t.name == name)
}

pub(crate) fn ots_by_code(code: u32) -> Option<OtsType> {
    OTS_TYPES.into_iter().find(|t| t.code == code)
}

pub(crate) fn lms_by_code(code: u32) -> Option<LmsType> {
    LMS_TYPES.into_iter().find(|t| t.code == code)
}

impl OtsType {
    // RFC 8554, Appendix B: u chains for the digest and v for the checksum, shifted left by ls.
    const fn u(&self) -> usize {
        8 * self.n / self.w as usize
    }

    const fn v(&self) -> usize {
        let bits = usize::BITS - (((1 << self.w) - 1) * self.u()).leading_zeros();

        bits.div_ceil(self.w) as usize
    }

    const fn p(&self) -> usize {
        self.u() + self.v()
    }

    const fn ls(&self) -> u32 {
        16 - self.v() as u32 * self.w
    }

    const fn signature_size(&self) -> usize {
        4 + self.n * (self.p() + 1)
    }

    pub(crate) const fn same_family(&self, lms: &LmsType) -> bool {
        self.shake == lms.shake && self.n == lms.m
    }
}

impl LmsType {
    pub(crate) const fn public_key_size(&self) -> usize {
        24 + self.m
    }

    pub(crate) const fn signature_size(&self, ots: &OtsType) -> usize {
        8 + ots.signature_size() + self.h as usize * self.m
    }
}

fn digest(shake: bool, n: usize, parts: &[&[u8]]) -> Node {
    let mut node = [0; 32];

    TruncatedHash::digest(shake, n, parts, &mut node);

    node
}

// The derived values are secret, so they go straight into out.
fn derive(lms: &LmsType, i: &[u8], q: u32, index: u16, seed: &[u8], out: &mut Node) {
    TruncatedHash::digest(
        lms.shake,
        lms.m,
        &[i, &q.to_be_bytes(), &index.to_be_bytes(), &[0xFF], seed],
        out,
    );
}

fn coefficient(t: &OtsType, data: &[u8], i: usize) -> u32 {
    let per_byte = 8 / t.w as usize;

    let shift = 8 - t.w as usize * (i % per_byte + 1);

    (u32::from(data[i / per_byte]) >> shift) & ((1 << t.w) - 1)
}

// The p base-2^w digits of the message hash followed by its checksum.
fn digits(t: &OtsType, q_hash: &[u8]) -> [u8; MAX_P] {
    let checksum: u32 = (0..t.u())
        .map(|i| (1 << t.w) - 1 - coefficient(t, q_hash, i))
        .sum::<u32>()
        << t.ls();

    let mut extended = [0u8; 34];

    extended[..t.n].copy_from_slice(&q_hash[..t.n]);

    extended[t.n..t.n + 2].copy_from_slice(&(checksum as u16).to_be_bytes());

    let mut out = [0; MAX_P];

    for (i, digit) in out.iter_mut().take(t.p()).enumerate() {
        *digit = coefficient(t, &extended, i) as u8;
    }

    out
}

// The truncated hashes of L messages of length bytes, which fit one SHA-256 block, side by side,
// into nodes; with SHAKE the inactive lanes are skipped and keep their nodes. The messages are
// wiped.
fn digest_lanes<const L: usize>(
    shake: bool,
    n: usize,
    messages: &mut [[u8; 64]; L],
    length: usize,
    active: [bool; L],
    nodes: &mut [Node; L],
) {
    if shake {
        for ((node, message), &active) in nodes.iter_mut().zip(&*messages).zip(&active) {
            if active {
                TruncatedHash::digest(true, n, &[&message[..length]], node);
            }
        }

        wipe(messages.as_flattened_mut());

        return;
    }

    let mut digests = [[0; 32]; L];

    Sha256::new(&IV_256).finish_lanes(messages, length, &mut digests);

    for (node, digest) in nodes.iter_mut().zip(&digests) {
        node[..n].copy_from_slice(&digest[..n]);

        node[n..].fill(0);
    }

    wipe(digests.as_flattened_mut());
}

// I || u32(q) || u16(j) || u8(k) || x: a chain step, or with k = 0xFF and x = SEED a derived value.
fn chain_message(out: &mut [u8; 64], i: &[u8], q: u32, j: usize, k: u8, x: &[u8]) -> usize {
    out[..16].copy_from_slice(i);

    out[16..20].copy_from_slice(&q.to_be_bytes());

    out[20..22].copy_from_slice(&(j as u16).to_be_bytes());

    out[22] = k;

    out[23..23 + x.len()].copy_from_slice(x);

    23 + x.len()
}

// H(I || u32(q) || u16(j) || u8(k) || x) for L lanes: a chain step, or with k = 0xFF and x = SEED
// a derived value. With SHA-256 the block is built as words; x starts three bytes into word 5,
// so each of its words straddles two block words.
#[allow(clippy::too_many_arguments)]
fn chain_lanes<const L: usize>(
    shake: bool,
    n: usize,
    i: &[u8],
    q: [u32; L],
    j: [usize; L],
    k: [u8; L],
    x: [&[u8]; L],
    active: [bool; L],
    nodes: &mut [Node; L],
) {
    if shake {
        let mut messages = [[0; 64]; L];

        for (lane, message) in messages.iter_mut().enumerate() {
            chain_message(message, i, q[lane], j[lane], k[lane], &x[lane][..n]);
        }

        return digest_lanes(true, n, &mut messages, 23 + n, active, nodes);
    }

    let mut blocks = [[0; L]; 16];

    for (t, bytes) in i.as_chunks::<4>().0.iter().enumerate() {
        blocks[t] = [u32::from_be_bytes(*bytes); L];
    }

    for lane in 0..L {
        blocks[4][lane] = q[lane];

        let mut carry = ((j[lane] as u32) << 16) | (u32::from(k[lane]) << 8);

        for (t, bytes) in x[lane][..n].as_chunks::<4>().0.iter().enumerate() {
            let word = u32::from_be_bytes(*bytes);

            blocks[5 + t][lane] = carry | (word >> 24);

            carry = word << 8;
        }

        blocks[5 + n / 4][lane] = carry | 0x80;

        blocks[15][lane] = ((23 + n) * 8) as u32;
    }

    let mut states = [[0; L]; 8];

    Sha256::new(&IV_256).finish_words(&mut blocks, &mut states);

    for (lane, node) in nodes.iter_mut().enumerate() {
        for (bytes, state) in node[..n].as_chunks_mut::<4>().0.iter_mut().zip(&states) {
            *bytes = state[lane].to_be_bytes();
        }

        node[n..].fill(0);
    }

    wipe(blocks.as_flattened_mut());

    wipe(states.as_flattened_mut());
}

// The secret first values x_j = derive(q, j) of L chains, into nodes.
fn chain_starts<const L: usize>(
    lms: &LmsType,
    i: &[u8],
    q: [u32; L],
    j: [usize; L],
    seed: &[u8],
    nodes: &mut [Node; L],
) {
    chain_lanes(
        lms.shake, lms.m, i, q, j, [0xFF; L], [seed; L], [true; L], nodes,
    );
}

// The LM-OTS public keys K of the L keys from q = first on, chain by chain for all of them.
fn ots_public_keys<const L: usize>(
    t: &OtsType,
    lms: &LmsType,
    i: &[u8],
    first: u32,
    seed: &[u8],
) -> [Node; L] {
    let n = t.n;

    let q: [u32; L] = core::array::from_fn(|lane| first + lane as u32);

    // The engines absorb in place from their empty state on, so that none is moved once it holds
    // input.
    let mut engines: [TruncatedHash; L] = core::array::from_fn(|_| TruncatedHash::new(t.shake));

    for (engine, q) in engines.iter_mut().zip(q) {
        for part in [i, &q.to_be_bytes(), &D_PBLC] {
            engine.update(part);
        }
    }

    // The chain values, secret below the ends: each step reads one buffer and writes the other,
    // and both are wiped at the end.
    let mut buffers = [[[0; 32]; L]; 2];

    let [mut x, mut y] = buffers.each_mut();

    for j in 0..t.p() {
        chain_starts(lms, i, q, [j; L], seed, x);

        for k in 0..(1u32 << t.w) - 1 {
            let inputs = core::array::from_fn(|lane| &x[lane][..n]);

            chain_lanes(t.shake, n, i, q, [j; L], [k as u8; L], inputs, [true; L], y);

            core::mem::swap(&mut x, &mut y);
        }

        for (engine, value) in engines.iter_mut().zip(x.iter()) {
            engine.update(&value[..n]);
        }
    }

    wipe(buffers.as_flattened_mut().as_flattened_mut());

    let mut nodes = [[0; 32]; L];

    for (engine, node) in engines.iter_mut().zip(&mut nodes) {
        engine.finish(n, node);
    }

    nodes
}

// Advances chain j of the LM-OTS key q from step starts[j] to ends[j], for every chain. The
// chains have different lengths, so each lane takes the next chain as its own ends, the longest
// first so that the last ones to finish are short. The lengths come from public digests.
fn chains(t: &OtsType, i: &[u8], q: u32, starts: &[u32], ends: &[u32], values: &mut [Node]) {
    let n = t.n;

    let mut order: [usize; MAX_P] = core::array::from_fn(|j| j);

    let order = &mut order[..values.len()];

    order.sort_unstable_by_key(|&j| core::cmp::Reverse(ends[j] - starts[j]));

    let mut pending = order.iter().copied().filter(|&j| starts[j] < ends[j]);

    let mut lanes: [Option<(usize, u32)>; LANES] = [None; LANES];

    // Chain values, secret in signing, wiped at the end.
    let mut outputs = [[0; 32]; LANES];

    loop {
        for lane in lanes.iter_mut().filter(|lane| lane.is_none()) {
            *lane = pending.next().map(|j| (j, starts[j]));
        }

        if lanes.iter().all(Option::is_none) {
            break;
        }

        let (j, k) = (
            lanes.map(|lane| lane.unwrap_or_default().0),
            lanes.map(|lane| lane.unwrap_or_default().1 as u8),
        );

        let inputs = core::array::from_fn(|lane| &values[j[lane]][..n]);

        let active = lanes.map(|lane| lane.is_some());

        chain_lanes(
            t.shake,
            n,
            i,
            [q; LANES],
            j,
            k,
            inputs,
            active,
            &mut outputs,
        );

        for (lane, output) in lanes.iter_mut().zip(&outputs) {
            if let Some((j, k)) = lane {
                values[*j] = *output;

                *k += 1;

                if *k == ends[*j] {
                    *lane = None;
                }
            }
        }
    }

    wipe(outputs.as_flattened_mut());
}

// The secret chain starts x_j of the key q, LANES at a time, into values.
fn secret_values(
    t: &OtsType,
    lms: &LmsType,
    i: &[u8],
    q: u32,
    seed: &[u8],
    values: &mut [Node; MAX_P],
) {
    let mut starts = [[0; 32]; LANES];

    for (first, group) in (0..t.p()).step_by(LANES).zip(values.chunks_mut(LANES)) {
        let j = core::array::from_fn(|lane| first + lane);

        chain_starts::<LANES>(lms, i, [q; LANES], j, seed, &mut starts);

        for (value, start) in group.iter_mut().zip(&starts) {
            *value = *start;
        }
    }

    wipe(starts.as_flattened_mut());
}

// The LM-OTS signature of key q with the randomizer C, which the caller draws or derives.
fn ots_sign(
    t: &OtsType,
    lms: &LmsType,
    i: &[u8],
    q: u32,
    seed: &[u8],
    c: &[u8],
    message: &[u8],
) -> Vec<u8> {
    let (n, p) = (t.n, t.p());

    #[cfg(test)]
    crate::merkle::one_time_signature(&[b"L", i, &q.to_be_bytes()]);

    // C is part of the signature, so the digits of Q are public as well.
    declassify(c);

    let q_hash = digest(t.shake, n, &[i, &q.to_be_bytes(), &D_MESG, c, message]);

    let mut out = Vec::with_capacity(t.signature_size());

    out.extend_from_slice(&t.code.to_be_bytes());

    out.extend_from_slice(c);

    let digits = digits(t, &q_hash).map(u32::from);

    let mut values = [[0; 32]; MAX_P];

    secret_values(t, lms, i, q, seed, &mut values);

    chains(t, i, q, &[0; MAX_P][..p], &digits[..p], &mut values[..p]);

    for value in &values[..p] {
        out.extend_from_slice(&value[..n]);
    }

    // The chain starts past p that the last group derived, and the copy of the signature, which
    // the caller verifies before it is released and wipes if it is faulty.
    wipe(values.as_flattened_mut());

    out
}

fn ots_candidate(t: &OtsType, i: &[u8], q: u32, signature: &[u8], message: &[u8]) -> Node {
    let (n, p) = (t.n, t.p());

    let c = &signature[4..4 + n];

    let q_hash = digest(t.shake, n, &[i, &q.to_be_bytes(), &D_MESG, c, message]);

    let mut values = [[0; 32]; MAX_P];

    for (value, y) in values.iter_mut().zip(signature[4 + n..].chunks_exact(n)) {
        value[..n].copy_from_slice(y);
    }

    let digits = digits(t, &q_hash).map(u32::from);

    chains(
        t,
        i,
        q,
        &digits[..p],
        &[(1 << t.w) - 1; MAX_P][..p],
        &mut values[..p],
    );

    let mut engine = TruncatedHash::new(t.shake);

    for part in [i, &q.to_be_bytes(), &D_PBLC] {
        engine.update(part);
    }

    for value in &values[..p] {
        engine.update(&value[..n]);
    }

    let mut node = [0; 32];

    engine.finish(n, &mut node);

    node
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;

    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

struct LmsPublicKey<'a> {
    lms: LmsType,
    ots: OtsType,
    i: &'a [u8],
    root: &'a [u8],
}

fn parse_public_key(data: &[u8]) -> Option<LmsPublicKey<'_>> {
    let lms = lms_by_code(read_u32(data, 0)?)?;

    let ots = ots_by_code(read_u32(data, 4)?)?;

    if !ots.same_family(&lms) || data.len() != lms.public_key_size() {
        return None;
    }

    Some(LmsPublicKey {
        lms,
        ots,
        i: &data[8..24],
        root: &data[24..],
    })
}

fn lms_verify(public_key: &LmsPublicKey, message: &[u8], signature: &[u8]) -> bool {
    let LmsPublicKey { lms, ots, i, root } = public_key;

    let (Some(q), Some(ots_code)) = (read_u32(signature, 0), read_u32(signature, 4)) else {
        return false;
    };

    if ots_code != ots.code || signature.len() != lms.signature_size(ots) {
        return false;
    }

    let offset = 4 + ots.signature_size();

    if read_u32(signature, offset) != Some(lms.code) || u64::from(q) >= 1 << lms.h {
        return false;
    }

    let mut node = (1 << lms.h) | q;

    let k = ots_candidate(ots, i, q, &signature[4..offset], message);

    let m = lms.m;

    let mut candidate = digest(
        lms.shake,
        m,
        &[i, &node.to_be_bytes(), &D_LEAF, &k[..ots.n]],
    );

    for sibling in signature[offset + 4..].chunks_exact(m) {
        let (left, right) = if node & 1 == 1 {
            (sibling, &candidate[..m])
        } else {
            (&candidate[..m], sibling)
        };

        node >>= 1;

        candidate = digest(
            lms.shake,
            m,
            &[i, &node.to_be_bytes(), &D_INTR, left, right],
        );
    }

    candidate[..m] == **root
}

// RFC 8554, Algorithm 6a, under an LMS public key u32(type) || u32(otstype) || I || T[1].
pub(crate) fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    parse_public_key(public_key).is_some_and(|key| lms_verify(&key, message, signature))
}

pub(crate) fn check_public_key(data: &[u8]) -> bool {
    matches!(read_u32(data, 0), Some(1..=8)) && parse_public_key(&data[4..]).is_some()
}

// RFC 8554, section 6.3: each level signs the public key of the next, which the signature
// carries; the bottom level signs the message.
pub(crate) fn hss_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Some(levels @ 1..=8) = read_u32(public_key, 0) else {
        return false;
    };

    let Some(mut key) = parse_public_key(&public_key[4..]) else {
        return false;
    };

    if read_u32(signature, 0) != Some(levels - 1) {
        return false;
    }

    let mut offset = 4;

    for _ in 1..levels {
        let end = offset + key.lms.signature_size(&key.ots);

        let Some(child_lms) = read_u32(signature, end).and_then(lms_by_code) else {
            return false;
        };

        let Some(child_bytes) = signature.get(end..end + child_lms.public_key_size()) else {
            return false;
        };

        let Some(child) = parse_public_key(child_bytes) else {
            return false;
        };

        if !lms_verify(&key, child_bytes, &signature[offset..end]) {
            return false;
        }

        key = child;

        offset = end + child_bytes.len();
    }

    lms_verify(&key, message, &signature[offset..])
}

struct TreeKey<'a> {
    lms: &'a LmsType,
    ots: &'a OtsType,
    i: &'a [u8],
    seed: &'a [u8],
}

impl TreeKey<'_> {
    fn leaf_lanes<const L: usize>(&self, first: u32, leaves: &mut [Node; L]) {
        let keys = ots_public_keys::<L>(self.ots, self.lms, self.i, first, self.seed);

        let mut messages = [[0; 64]; L];

        let n = self.ots.n;

        for (lane, (message, key)) in messages.iter_mut().zip(&keys).enumerate() {
            let node = (1u32 << self.lms.h) + first + lane as u32;

            message[..16].copy_from_slice(self.i);

            message[16..20].copy_from_slice(&node.to_be_bytes());

            message[20..22].copy_from_slice(&D_LEAF);

            message[22..22 + n].copy_from_slice(&key[..n]);
        }

        digest_lanes(
            self.lms.shake,
            self.lms.m,
            &mut messages,
            22 + n,
            [true; L],
            leaves,
        );
    }
}

impl TreeHasher for TreeKey<'_> {
    fn leaves(&self, first: u32, out: &mut [Node]) {
        for (start, group) in (first..).step_by(LANES).zip(out.chunks_mut(LANES)) {
            if let Ok(group) = <&mut [Node; LANES]>::try_from(&mut *group) {
                self.leaf_lanes(start, group);
            } else {
                for (q, node) in (start..).zip(group) {
                    self.leaf_lanes(q, core::array::from_mut(node));
                }
            }
        }
    }

    fn combine(&self, height: u32, index: u32, left: &Node, right: &Node) -> Node {
        let m = self.lms.m;

        let node = (1u32 << (self.lms.h - height - 1)) + index;

        digest(
            self.lms.shake,
            m,
            &[
                self.i,
                &node.to_be_bytes(),
                &D_INTR,
                &left[..m],
                &right[..m],
            ],
        )
    }
}

// One LMS tree of an HSS key: its types, I and SEED, the Merkle tree over its LM-OTS public keys,
// and its public key u32(type) || u32(otstype) || I || T[1].
pub(crate) struct Tree {
    lms: LmsType,
    ots: OtsType,
    i: [u8; 16],
    seed: SecretBytes,
    merkle: MerkleTree,
    public_key: Vec<u8>,
}

impl Tree {
    // The tree of the secrets I || SEED, built from its leaves, or from the nodes of a tree cache
    // that every parent there agrees with.
    pub(crate) fn new(
        lms: LmsType,
        ots: OtsType,
        secrets: &[u8],
        nodes: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let mut i = [0; 16];

        i.copy_from_slice(&secrets[..16]);

        // I is part of the tree's public key.
        declassify(&i);

        let seed = SecretBytes::concat(&[&secrets[16..]]);

        let key = TreeKey {
            lms: &lms,
            ots: &ots,
            i: &i,
            seed: &seed,
        };

        let merkle = match nodes {
            Some(nodes) => MerkleTree::restore(lms.h, lms.m, nodes, &key)?,
            None => MerkleTree::new(lms.h, &key),
        };

        let public_key = [
            &lms.code.to_be_bytes()[..],
            &ots.code.to_be_bytes(),
            &i,
            &merkle.root()[..lms.m],
        ]
        .concat();

        declassify(&public_key);

        Ok(Self {
            lms,
            ots,
            i,
            seed,
            merkle,
            public_key,
        })
    }

    pub(crate) fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub(crate) fn root(&self) -> &[u8] {
        &self.public_key[24..]
    }

    pub(crate) const fn merkle(&self) -> &MerkleTree {
        &self.merkle
    }

    // The randomizer C of a signature by leaf q in the deterministic mode.
    pub(crate) fn derived_randomizer(&self, q: u32) -> Node {
        let mut c = [0; 32];

        derive(&self.lms, &self.i, q, RANDOMIZER, &self.seed, &mut c);

        c
    }

    // The I || SEED of the child tree under leaf q in the deterministic mode.
    pub(crate) fn derived_child(&self, q: u32) -> SecretBytes {
        let m = self.lms.m;

        let (mut child_seed, mut child_i) = ([0; 32], [0; 32]);

        derive(
            &self.lms,
            &self.i,
            q,
            CHILD_SEED,
            &self.seed,
            &mut child_seed,
        );

        derive(&self.lms, &self.i, q, CHILD_I, &self.seed, &mut child_i);

        let child = SecretBytes::concat(&[&child_i[..16], &child_seed[..m]]);

        wipe(&mut child_seed);

        child
    }

    // RFC 8554, Algorithm 3 and section 5.4.1: the LMS signature of message by leaf q with the
    // randomizer C.
    pub(crate) fn sign(&mut self, q: u32, c: &[u8], message: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.lms.signature_size(&self.ots));

        out.extend_from_slice(&q.to_be_bytes());

        let mut ots = ots_sign(&self.ots, &self.lms, &self.i, q, &self.seed, c, message);

        out.extend_from_slice(&ots);

        // The caller verifies the signature before it is released and wipes it if it is faulty.
        wipe(&mut ots);

        out.extend_from_slice(&self.lms.code.to_be_bytes());

        let key = TreeKey {
            lms: &self.lms,
            ots: &self.ots,
            i: &self.i,
            seed: &self.seed,
        };

        out.extend_from_slice(&self.merkle.auth_path(q, self.lms.m, &key));

        declassify(&out);

        out
    }
}

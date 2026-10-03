use alloc::vec::Vec;

use crate::merkle::{MerkleTree, Node, TreeHasher};
use crate::primitives::TruncatedHash;
use crate::wipe::{SecretBytes, wipe};

const D_PBLC: [u8; 2] = [0x80, 0x80];

const D_MESG: [u8; 2] = [0x81, 0x81];

const D_LEAF: [u8; 2] = [0x82, 0x82];

const D_INTR: [u8; 2] = [0x83, 0x83];

// Pseudorandom values derived from a tree's SEED (RFC 8554, Appendix A, and the convention of
// the hash-sigs reference used by the RFC 8554 and RFC 9858 test cases): the signature
// randomizer C, and the SEED and I of a child tree. Chain indices are below 0xFFFD.
const RANDOMIZER: u16 = 0xFFFD;

const CHILD_SEED: u16 = 0xFFFE;

const CHILD_I: u16 = 0xFFFF;

// The largest number of chains, p for n = 32 and w = 1.
const MAX_P: usize = 265;

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
    const fn public_key_size(&self) -> usize {
        24 + self.m
    }

    const fn signature_size(&self, ots: &OtsType) -> usize {
        8 + ots.signature_size() + self.h as usize * self.m
    }
}

fn digest(shake: bool, n: usize, parts: &[&[u8]]) -> Node {
    TruncatedHash::digest(shake, n, parts)
}

fn derive(lms: &LmsType, i: &[u8], q: u32, index: u16, seed: &[u8]) -> Node {
    digest(
        lms.shake,
        lms.m,
        &[i, &q.to_be_bytes(), &index.to_be_bytes(), &[0xFF], seed],
    )
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

fn chain(t: &OtsType, i: &[u8], q: u32, j: usize, range: (u32, u32), mut x: Node) -> Node {
    for k in range.0..range.1 {
        x = digest(
            t.shake,
            t.n,
            &[
                i,
                &q.to_be_bytes(),
                &(j as u16).to_be_bytes(),
                &[k as u8],
                &x[..t.n],
            ],
        );
    }

    x
}

fn ots_public_key(t: &OtsType, lms: &LmsType, i: &[u8], q: u32, seed: &[u8]) -> Node {
    let mut engine = TruncatedHash::new(t.shake);

    for part in [i, &q.to_be_bytes(), &D_PBLC] {
        engine.update(part);
    }

    let top = (1 << t.w) - 1;

    for j in 0..t.p() {
        let x = derive(lms, i, q, j as u16, seed);

        engine.update(&chain(t, i, q, j, (0, top), x)[..t.n]);
    }

    engine.finish(t.n)
}

fn ots_sign(t: &OtsType, lms: &LmsType, i: &[u8], q: u32, seed: &[u8], message: &[u8]) -> Vec<u8> {
    let c = derive(lms, i, q, RANDOMIZER, seed);

    let q_hash = digest(
        t.shake,
        t.n,
        &[i, &q.to_be_bytes(), &D_MESG, &c[..t.n], message],
    );

    let mut out = Vec::with_capacity(t.signature_size());

    out.extend_from_slice(&t.code.to_be_bytes());

    out.extend_from_slice(&c[..t.n]);

    for (j, &a) in digits(t, &q_hash).iter().take(t.p()).enumerate() {
        let x = derive(lms, i, q, j as u16, seed);

        out.extend_from_slice(&chain(t, i, q, j, (0, u32::from(a)), x)[..t.n]);
    }

    out
}

fn ots_candidate(t: &OtsType, i: &[u8], q: u32, signature: &[u8], message: &[u8]) -> Node {
    let n = t.n;

    let c = &signature[4..4 + n];

    let q_hash = digest(t.shake, n, &[i, &q.to_be_bytes(), &D_MESG, c, message]);

    let mut engine = TruncatedHash::new(t.shake);

    for part in [i, &q.to_be_bytes(), &D_PBLC] {
        engine.update(part);
    }

    let top = (1 << t.w) - 1;

    let chains = signature[4 + n..].chunks_exact(n);

    for (j, (&a, y)) in digits(t, &q_hash).iter().zip(chains).enumerate() {
        let mut x = [0; 32];

        x[..n].copy_from_slice(y);

        engine.update(&chain(t, i, q, j, (u32::from(a), top), x)[..n]);
    }

    engine.finish(n)
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

impl TreeHasher for TreeKey<'_> {
    fn leaf(&self, q: u32) -> Node {
        let k = ots_public_key(self.ots, self.lms, self.i, q, self.seed);

        let node = (1u32 << self.lms.h) + q;

        digest(
            self.lms.shake,
            self.lms.m,
            &[self.i, &node.to_be_bytes(), &D_LEAF, &k[..self.ots.n]],
        )
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

// One LMS tree of an HSS key: its I, SEED and the Merkle tree over its OTS public keys.
struct Tree {
    lms: LmsType,
    ots: OtsType,
    i: [u8; 16],
    seed: SecretBytes,
    merkle: MerkleTree,
    public_key: Vec<u8>,
}

impl Tree {
    fn new(lms: LmsType, ots: OtsType, i: &[u8], seed: SecretBytes) -> Self {
        let mut identifier = [0; 16];

        identifier.copy_from_slice(i);

        let merkle = MerkleTree::new(
            lms.h,
            &TreeKey {
                lms: &lms,
                ots: &ots,
                i,
                seed: &seed,
            },
        );

        let mut public_key = Vec::with_capacity(lms.public_key_size());

        public_key.extend_from_slice(&lms.code.to_be_bytes());

        public_key.extend_from_slice(&ots.code.to_be_bytes());

        public_key.extend_from_slice(i);

        public_key.extend_from_slice(&merkle.root()[..lms.m]);

        Self {
            lms,
            ots,
            i: identifier,
            seed,
            merkle,
            public_key,
        }
    }

    fn key(&self) -> TreeKey<'_> {
        TreeKey {
            lms: &self.lms,
            ots: &self.ots,
            i: &self.i,
            seed: &self.seed,
        }
    }

    fn sign(&self, q: u32, message: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.lms.signature_size(&self.ots));

        out.extend_from_slice(&q.to_be_bytes());

        out.extend_from_slice(&ots_sign(
            &self.ots, &self.lms, &self.i, q, &self.seed, message,
        ));

        out.extend_from_slice(&self.lms.code.to_be_bytes());

        out.extend_from_slice(&self.merkle.auth_path(q, self.lms.m, &self.key()));

        out
    }

    fn child(&self, lms: LmsType, ots: OtsType, q: u32) -> Self {
        let mut seed = derive(&self.lms, &self.i, q, CHILD_SEED, &self.seed);

        let i = derive(&self.lms, &self.i, q, CHILD_I, &self.seed);

        let child_seed = SecretBytes::concat(&[&seed[..self.lms.m]]);

        wipe(&mut seed);

        Self::new(lms, ots, &i[..16], child_seed)
    }
}

// The signing side of an HSS key: the trees on the path to the next leaf, rebuilt when the
// index leaves a tree, and each child public key signed by its parent.
pub(crate) struct Hss {
    levels: Vec<(LmsType, OtsType)>,
    trees: Vec<Tree>,
    signed: Vec<Vec<u8>>,
    prefixes: Vec<u64>,
}

impl Hss {
    pub(crate) fn new(levels: &[(LmsType, OtsType)], i: &[u8], seed: &[u8]) -> Self {
        let (lms, ots) = levels[0];

        Self {
            levels: levels.to_vec(),
            trees: alloc::vec![Tree::new(lms, ots, i, SecretBytes::concat(&[seed]))],
            signed: Vec::new(),
            prefixes: alloc::vec![0],
        }
    }

    pub(crate) fn public_key(&self) -> Vec<u8> {
        let levels = self.levels.len() as u32;

        [&levels.to_be_bytes()[..], &self.trees[0].public_key].concat()
    }

    fn height_below(&self, level: usize) -> u32 {
        self.levels[level..].iter().map(|(lms, _)| lms.h).sum()
    }

    fn leaf_index(&self, index: u64, level: usize) -> u32 {
        let below = self.height_below(level + 1);

        ((index >> below) & ((1 << self.levels[level].0.h) - 1)) as u32
    }

    pub(crate) fn sign(&mut self, index: u64, message: &[u8]) -> Vec<u8> {
        for level in 1..self.levels.len() {
            let prefix = index >> self.height_below(level);

            if level < self.trees.len() && self.prefixes[level] == prefix {
                continue;
            }

            self.trees.truncate(level);

            self.signed.truncate(level - 1);

            self.prefixes.truncate(level);

            let q = self.leaf_index(index, level - 1);

            let (lms, ots) = self.levels[level];

            let parent = &self.trees[level - 1];

            let tree = parent.child(lms, ots, q);

            self.signed
                .push([parent.sign(q, &tree.public_key), tree.public_key.clone()].concat());

            self.trees.push(tree);

            self.prefixes.push(prefix);
        }

        let bottom = self.trees[self.levels.len() - 1]
            .sign(self.leaf_index(index, self.levels.len() - 1), message);

        let count = (self.levels.len() as u32 - 1).to_be_bytes();

        [&count[..], &self.signed.concat(), &bottom].concat()
    }
}

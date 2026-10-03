use alloc::vec::Vec;

use crate::merkle::{MerkleTree, Node, TreeHasher};
use crate::primitives::TruncatedHash;
use crate::sha2::{IV_256, Sha256};
use crate::wipe::SecretBytes;

const W: u32 = 16;

const OTS: u32 = 0;

const LTREE: u32 = 1;

const HASH_TREE: u32 = 2;

const F: u32 = 0;

const H: u32 = 1;

const H_MSG: u32 = 2;

const PRF: u32 = 3;

const PRF_KEYGEN: u32 = 4;

const MAX_LEN: usize = 67;

type Adrs = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Parameters {
    pub(crate) name: &'static str,
    pub(crate) oid: u32,
    shake: bool,
    pub(crate) n: usize,
    h: u32,
    d: u32,
    multi: bool,
}

const fn xmss(name: &'static str, oid: u32, shake: bool, n: usize, h: u32) -> Parameters {
    Parameters {
        name,
        oid,
        shake,
        n,
        h,
        d: 1,
        multi: false,
    }
}

const fn xmss_mt(
    name: &'static str,
    oid: u32,
    shake: bool,
    n: usize,
    h: u32,
    d: u32,
) -> Parameters {
    Parameters {
        name,
        oid,
        shake,
        n,
        h,
        d,
        multi: true,
    }
}

// The SP 800-208 parameter sets with their RFC 8391 and NIST code points.
pub(crate) const XMSS_SETS: [Parameters; 12] = [
    xmss("XMSS-SHA2_10_256", 0x01, false, 32, 10),
    xmss("XMSS-SHA2_16_256", 0x02, false, 32, 16),
    xmss("XMSS-SHA2_20_256", 0x03, false, 32, 20),
    xmss("XMSS-SHA2_10_192", 0x0D, false, 24, 10),
    xmss("XMSS-SHA2_16_192", 0x0E, false, 24, 16),
    xmss("XMSS-SHA2_20_192", 0x0F, false, 24, 20),
    xmss("XMSS-SHAKE256_10_256", 0x10, true, 32, 10),
    xmss("XMSS-SHAKE256_16_256", 0x11, true, 32, 16),
    xmss("XMSS-SHAKE256_20_256", 0x12, true, 32, 20),
    xmss("XMSS-SHAKE256_10_192", 0x13, true, 24, 10),
    xmss("XMSS-SHAKE256_16_192", 0x14, true, 24, 16),
    xmss("XMSS-SHAKE256_20_192", 0x15, true, 24, 20),
];

pub(crate) const XMSS_MT_SETS: [Parameters; 32] = [
    xmss_mt("XMSSMT-SHA2_20/2_256", 0x01, false, 32, 20, 2),
    xmss_mt("XMSSMT-SHA2_20/4_256", 0x02, false, 32, 20, 4),
    xmss_mt("XMSSMT-SHA2_40/2_256", 0x03, false, 32, 40, 2),
    xmss_mt("XMSSMT-SHA2_40/4_256", 0x04, false, 32, 40, 4),
    xmss_mt("XMSSMT-SHA2_40/8_256", 0x05, false, 32, 40, 8),
    xmss_mt("XMSSMT-SHA2_60/3_256", 0x06, false, 32, 60, 3),
    xmss_mt("XMSSMT-SHA2_60/6_256", 0x07, false, 32, 60, 6),
    xmss_mt("XMSSMT-SHA2_60/12_256", 0x08, false, 32, 60, 12),
    xmss_mt("XMSSMT-SHA2_20/2_192", 0x21, false, 24, 20, 2),
    xmss_mt("XMSSMT-SHA2_20/4_192", 0x22, false, 24, 20, 4),
    xmss_mt("XMSSMT-SHA2_40/2_192", 0x23, false, 24, 40, 2),
    xmss_mt("XMSSMT-SHA2_40/4_192", 0x24, false, 24, 40, 4),
    xmss_mt("XMSSMT-SHA2_40/8_192", 0x25, false, 24, 40, 8),
    xmss_mt("XMSSMT-SHA2_60/3_192", 0x26, false, 24, 60, 3),
    xmss_mt("XMSSMT-SHA2_60/6_192", 0x27, false, 24, 60, 6),
    xmss_mt("XMSSMT-SHA2_60/12_192", 0x28, false, 24, 60, 12),
    xmss_mt("XMSSMT-SHAKE256_20/2_256", 0x29, true, 32, 20, 2),
    xmss_mt("XMSSMT-SHAKE256_20/4_256", 0x2A, true, 32, 20, 4),
    xmss_mt("XMSSMT-SHAKE256_40/2_256", 0x2B, true, 32, 40, 2),
    xmss_mt("XMSSMT-SHAKE256_40/4_256", 0x2C, true, 32, 40, 4),
    xmss_mt("XMSSMT-SHAKE256_40/8_256", 0x2D, true, 32, 40, 8),
    xmss_mt("XMSSMT-SHAKE256_60/3_256", 0x2E, true, 32, 60, 3),
    xmss_mt("XMSSMT-SHAKE256_60/6_256", 0x2F, true, 32, 60, 6),
    xmss_mt("XMSSMT-SHAKE256_60/12_256", 0x30, true, 32, 60, 12),
    xmss_mt("XMSSMT-SHAKE256_20/2_192", 0x31, true, 24, 20, 2),
    xmss_mt("XMSSMT-SHAKE256_20/4_192", 0x32, true, 24, 20, 4),
    xmss_mt("XMSSMT-SHAKE256_40/2_192", 0x33, true, 24, 40, 2),
    xmss_mt("XMSSMT-SHAKE256_40/4_192", 0x34, true, 24, 40, 4),
    xmss_mt("XMSSMT-SHAKE256_40/8_192", 0x35, true, 24, 40, 8),
    xmss_mt("XMSSMT-SHAKE256_60/3_192", 0x36, true, 24, 60, 3),
    xmss_mt("XMSSMT-SHAKE256_60/6_192", 0x37, true, 24, 60, 6),
    xmss_mt("XMSSMT-SHAKE256_60/12_192", 0x38, true, 24, 60, 12),
];

impl Parameters {
    const fn padding(&self) -> usize {
        if self.n == 32 { 32 } else { 4 }
    }

    const fn tree_height(&self) -> u32 {
        self.h / self.d
    }

    const fn len(&self) -> usize {
        2 * self.n + 3
    }

    const fn index_size(&self) -> usize {
        if self.multi {
            self.h.div_ceil(8) as usize
        } else {
            4
        }
    }

    pub(crate) const fn public_key_size(&self) -> usize {
        4 + 2 * self.n
    }

    const fn signature_size(&self) -> usize {
        self.index_size() + self.n + (self.d as usize * self.len() + self.h as usize) * self.n
    }

    pub(crate) const fn capacity(&self) -> u64 {
        1 << self.h
    }
}

pub(crate) fn by_oid(sets: &'static [Parameters], oid: u32) -> Option<&'static Parameters> {
    sets.iter().find(|p| p.oid == oid)
}

pub(crate) fn by_name(sets: &'static [Parameters], name: &str) -> Option<&'static Parameters> {
    sets.iter().find(|p| p.name == name)
}

// toByte(value, size) in the first size bytes: big-endian, zero-padded on the left.
fn to_byte(value: u64, size: usize) -> [u8; 32] {
    let mut out = [0; 32];

    let bytes = value.to_be_bytes();

    if size >= bytes.len() {
        out[size - bytes.len()..size].copy_from_slice(&bytes);
    } else {
        out[..size].copy_from_slice(&bytes[bytes.len() - size..]);
    }

    out
}

fn set_word(adrs: &mut Adrs, word: usize, value: u32) {
    adrs[4 * word..4 * word + 4].copy_from_slice(&value.to_be_bytes());
}

fn address(layer: u32, tree: u64, kind: u32) -> Adrs {
    let mut adrs = [0; 32];

    set_word(&mut adrs, 0, layer);

    adrs[4..12].copy_from_slice(&tree.to_be_bytes());

    set_word(&mut adrs, 3, kind);

    adrs
}

fn xor(a: &Node, b: &Node) -> Node {
    core::array::from_fn(|i| a[i] ^ b[i])
}

struct Hashes<'a> {
    p: &'a Parameters,
    pub_seed: &'a [u8],
    sk_seed: &'a [u8],
    prf_state: Option<Sha256>,
    keygen_state: Option<Sha256>,
}

impl<'a> Hashes<'a> {
    // With n = 32 and SHA-256, toByte(prefix, 32) || KEY fills exactly one block, so the state
    // after it is computed once per key for PRF (keyed by PUB_SEED) and PRF_keygen (by SK_SEED).
    fn new(p: &'a Parameters, pub_seed: &'a [u8], sk_seed: &'a [u8]) -> Self {
        let keyed = |prefix: u32, key: &[u8]| {
            (p.n == 32 && !p.shake && !key.is_empty()).then(|| {
                let mut state = Sha256::new(&IV_256);

                state.update(&to_byte(u64::from(prefix), 32));

                state.update(key);

                state
            })
        };

        Self {
            p,
            pub_seed,
            sk_seed,
            prf_state: keyed(PRF, pub_seed),
            keygen_state: keyed(PRF_KEYGEN, sk_seed),
        }
    }

    fn hash(&self, prefix: u32, key: &[u8], message: &[&[u8]]) -> Node {
        let mut engine = TruncatedHash::new(self.p.shake);

        engine.update(&to_byte(u64::from(prefix), self.p.padding())[..self.p.padding()]);

        engine.update(key);

        for part in message {
            engine.update(part);
        }

        engine.finish(self.p.n)
    }

    fn resume(&self, state: &Sha256, message: &[&[u8]]) -> Node {
        let mut engine = state.clone();

        for part in message {
            engine.update(part);
        }

        let mut out = [0; 32];

        out[..self.p.n].copy_from_slice(&engine.digest()[..self.p.n]);

        out
    }

    fn prf(&self, adrs: &Adrs) -> Node {
        match &self.prf_state {
            Some(state) => self.resume(state, &[adrs]),
            None => self.hash(PRF, self.pub_seed, &[adrs]),
        }
    }

    // SP 800-208: secret chain values come from PRF_keygen(SK_SEED, PUB_SEED || ADRS).
    fn prf_keygen(&self, adrs: &Adrs) -> Node {
        match &self.keygen_state {
            Some(state) => self.resume(state, &[self.pub_seed, adrs]),
            None => self.hash(PRF_KEYGEN, self.sk_seed, &[self.pub_seed, adrs]),
        }
    }

    fn chain(&self, mut x: Node, start: u32, steps: u32, adrs: &mut Adrs) -> Node {
        let n = self.p.n;

        for k in start..start + steps {
            set_word(adrs, 6, k);

            set_word(adrs, 7, 0);

            let key = self.prf(adrs);

            set_word(adrs, 7, 1);

            let mask = self.prf(adrs);

            x = self.hash(F, &key[..n], &[&xor(&x, &mask)[..n]]);
        }

        x
    }

    fn wots_digits(&self, message: &[u8]) -> [u32; MAX_LEN] {
        let n = self.p.n;

        let mut digits = [0; MAX_LEN];

        for (i, &byte) in message[..n].iter().enumerate() {
            digits[2 * i] = u32::from(byte >> 4);

            digits[2 * i + 1] = u32::from(byte & 0x0F);
        }

        let checksum = digits[..2 * n]
            .iter()
            .map(|digit| W - 1 - digit)
            .sum::<u32>()
            << 4;

        for (i, shift) in [12, 8, 4].into_iter().enumerate() {
            digits[2 * n + i] = (checksum >> shift) & 0x0F;
        }

        digits
    }

    // The hash and key-and-mask words are cleared for the secret, then set by every chain step.
    fn wots_secret(&self, adrs: &mut Adrs, i: usize) -> Node {
        set_word(adrs, 5, i as u32);

        set_word(adrs, 6, 0);

        set_word(adrs, 7, 0);

        self.prf_keygen(adrs)
    }

    fn wots_public(&self, adrs: &mut Adrs) -> [Node; MAX_LEN] {
        let mut values = [[0; 32]; MAX_LEN];

        for (i, value) in values.iter_mut().take(self.p.len()).enumerate() {
            let secret = self.wots_secret(adrs, i);

            *value = self.chain(secret, 0, W - 1, adrs);
        }

        values
    }

    fn wots_sign(&self, message: &[u8], adrs: &mut Adrs, out: &mut Vec<u8>) {
        let digits = self.wots_digits(message);

        for (i, &digit) in digits.iter().take(self.p.len()).enumerate() {
            let secret = self.wots_secret(adrs, i);

            out.extend_from_slice(&self.chain(secret, 0, digit, adrs)[..self.p.n]);
        }
    }

    fn wots_public_from_signature(
        &self,
        signature: &[u8],
        message: &[u8],
        adrs: &mut Adrs,
    ) -> [Node; MAX_LEN] {
        let n = self.p.n;

        let digits = self.wots_digits(message);

        let mut values = [[0; 32]; MAX_LEN];

        let pieces = values
            .iter_mut()
            .zip(signature.chunks_exact(n))
            .zip(&digits);

        for (i, ((value, piece), &digit)) in pieces.enumerate() {
            set_word(adrs, 5, i as u32);

            let mut x = [0; 32];

            x[..n].copy_from_slice(piece);

            *value = self.chain(x, digit, W - 1 - digit, adrs);
        }

        values
    }

    fn rand_hash(&self, left: &Node, right: &Node, adrs: &mut Adrs) -> Node {
        let n = self.p.n;

        set_word(adrs, 7, 0);

        let key = self.prf(adrs);

        set_word(adrs, 7, 1);

        let mask0 = self.prf(adrs);

        set_word(adrs, 7, 2);

        let mask1 = self.prf(adrs);

        self.hash(
            H,
            &key[..n],
            &[&xor(left, &mask0)[..n], &xor(right, &mask1)[..n]],
        )
    }

    fn ltree(&self, mut values: [Node; MAX_LEN], adrs: &mut Adrs) -> Node {
        let mut count = self.p.len();

        let mut height = 0;

        set_word(adrs, 5, height);

        while count > 1 {
            for i in 0..count / 2 {
                set_word(adrs, 6, i as u32);

                values[i] = self.rand_hash(&values[2 * i], &values[2 * i + 1], adrs);
            }

            if count % 2 == 1 {
                values[count / 2] = values[count - 1];
            }

            count = count.div_ceil(2);

            height += 1;

            set_word(adrs, 5, height);
        }

        values[0]
    }

    fn leaf(&self, layer: u32, tree: u64, index: u32) -> Node {
        let mut ots = address(layer, tree, OTS);

        set_word(&mut ots, 4, index);

        let values = self.wots_public(&mut ots);

        let mut lt = address(layer, tree, LTREE);

        set_word(&mut lt, 4, index);

        self.ltree(values, &mut lt)
    }

    fn compute_root(&self, mut node: Node, index: u32, auth: &[u8], layer: u32, tree: u64) -> Node {
        let n = self.p.n;

        let mut adrs = address(layer, tree, HASH_TREE);

        for (k, piece) in auth.chunks_exact(n).enumerate() {
            set_word(&mut adrs, 5, k as u32);

            set_word(&mut adrs, 6, index >> (k + 1));

            let mut sibling = [0; 32];

            sibling[..n].copy_from_slice(piece);

            node = if (index >> k) & 1 == 1 {
                self.rand_hash(&sibling, &node, &mut adrs)
            } else {
                self.rand_hash(&node, &sibling, &mut adrs)
            };
        }

        node
    }

    fn message_digest(&self, r: &[u8], root: &[u8], index: u64, message: &[u8]) -> Node {
        let n = self.p.n;

        let key = [r, root, &to_byte(index, n)[..n]].concat();

        self.hash(H_MSG, &key, &[message])
    }
}

struct Subtree<'a> {
    hashes: &'a Hashes<'a>,
    layer: u32,
    tree: u64,
}

impl TreeHasher for Subtree<'_> {
    fn leaf(&self, index: u32) -> Node {
        self.hashes.leaf(self.layer, self.tree, index)
    }

    fn combine(&self, height: u32, index: u32, left: &Node, right: &Node) -> Node {
        let mut adrs = address(self.layer, self.tree, HASH_TREE);

        set_word(&mut adrs, 5, height);

        set_word(&mut adrs, 6, index);

        self.hashes.rand_hash(left, right, &mut adrs)
    }
}

fn read_index(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0, |value, &byte| (value << 8) | u64::from(byte))
}

pub(crate) fn verify(p: &Parameters, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let n = p.n;

    if public_key.len() != p.public_key_size() || signature.len() != p.signature_size() {
        return false;
    }

    if read_index(&public_key[..4]) != u64::from(p.oid) {
        return false;
    }

    let (root, pub_seed) = public_key[4..].split_at(n);

    let hashes = Hashes::new(p, pub_seed, &[]);

    let mut index = read_index(&signature[..p.index_size()]);

    if index >> p.h != 0 {
        return false;
    }

    let (r, mut rest) = signature[p.index_size()..].split_at(n);

    let mut node = hashes.message_digest(r, root, index, message);

    let height = p.tree_height();

    for layer in 0..p.d {
        let leaf = (index & ((1 << height) - 1)) as u32;

        index >>= height;

        let (wots, after) = rest.split_at(p.len() * n);

        let (auth, after) = after.split_at(height as usize * n);

        rest = after;

        let mut ots = address(layer, index, OTS);

        set_word(&mut ots, 4, leaf);

        let values = hashes.wots_public_from_signature(wots, &node[..n], &mut ots);

        let mut lt = address(layer, index, LTREE);

        set_word(&mut lt, 4, leaf);

        let leaf_node = hashes.ltree(values, &mut lt);

        node = hashes.compute_root(leaf_node, leaf, auth, layer, index);
    }

    node[..n] == *root
}

// The signing side of an XMSS or XMSS^MT key, with one cached tree per layer.
pub(crate) struct Xmss {
    p: &'static Parameters,
    sk_seed: SecretBytes,
    sk_prf: SecretBytes,
    pub_seed: Vec<u8>,
    trees: Vec<Option<(u64, MerkleTree)>>,
    root: Node,
}

fn cached_tree<'t>(
    trees: &'t mut [Option<(u64, MerkleTree)>],
    hashes: &Hashes,
    layer: u32,
    tree: u64,
) -> &'t MerkleTree {
    let slot = &mut trees[layer as usize];

    if slot.as_ref().is_some_and(|(cached, _)| *cached != tree) {
        *slot = None;
    }

    let (_, merkle) = slot.get_or_insert_with(|| {
        let subtree = Subtree {
            hashes,
            layer,
            tree,
        };

        (tree, MerkleTree::new(hashes.p.tree_height(), &subtree))
    });

    merkle
}

impl Xmss {
    pub(crate) fn new(p: &'static Parameters, seed: &[u8]) -> Self {
        let n = p.n;

        let mut xmss = Self {
            p,
            sk_seed: SecretBytes::concat(&[&seed[..n]]),
            sk_prf: SecretBytes::concat(&[&seed[n..2 * n]]),
            pub_seed: seed[2 * n..].to_vec(),
            trees: (0..p.d).map(|_| None).collect(),
            root: [0; 32],
        };

        let hashes = Hashes::new(p, &xmss.pub_seed, &xmss.sk_seed);

        xmss.root = *cached_tree(&mut xmss.trees, &hashes, p.d - 1, 0).root();

        xmss
    }

    pub(crate) fn public_key(&self) -> Vec<u8> {
        [
            &self.p.oid.to_be_bytes()[..],
            &self.root[..self.p.n],
            &self.pub_seed,
        ]
        .concat()
    }

    pub(crate) fn sign(&mut self, index: u64, message: &[u8]) -> Vec<u8> {
        let p = self.p;

        let n = p.n;

        let hashes = Hashes::new(p, &self.pub_seed, &self.sk_seed);

        let r = hashes.hash(PRF, &self.sk_prf, &[&to_byte(index, 32)]);

        let mut node = hashes.message_digest(&r[..n], &self.root[..n], index, message);

        let mut out = Vec::with_capacity(p.signature_size());

        out.extend_from_slice(&index.to_be_bytes()[8 - p.index_size()..]);

        out.extend_from_slice(&r[..n]);

        let height = p.tree_height();

        let mut rest = index;

        for layer in 0..p.d {
            let leaf = (rest & ((1 << height) - 1)) as u32;

            rest >>= height;

            let mut ots = address(layer, rest, OTS);

            set_word(&mut ots, 4, leaf);

            hashes.wots_sign(&node[..n], &mut ots, &mut out);

            let merkle = cached_tree(&mut self.trees, &hashes, layer, rest);

            let subtree = Subtree {
                hashes: &hashes,
                layer,
                tree: rest,
            };

            out.extend_from_slice(&merkle.auth_path(leaf, n, &subtree));

            node = *merkle.root();
        }

        out
    }
}

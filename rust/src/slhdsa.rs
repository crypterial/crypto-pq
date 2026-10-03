use alloc::vec;
use alloc::vec::Vec;

use crate::hash::{HMAC_SHA_256, HMAC_SHA_512};
use crate::primitives::{sha256, sha512, shake256};
use crate::sha2::{IV_256, IV_512, Sha256, Sha512};
use crate::wipe::SecretBytes;

const WOTS_HASH: u32 = 0;

const WOTS_PK: u32 = 1;

const TREE: u32 = 2;

const FORS_TREE: u32 = 3;

const FORS_ROOTS: u32 = 4;

const WOTS_PRF: u32 = 5;

const FORS_PRF: u32 = 6;

const W: u32 = 16;

// The largest WOTS+ length (2n + 3 for n = 32) and FORS tree count.
const MAX_LEN: usize = 67;

const MAX_K: usize = 35;

type Adrs = [u8; 32];

type Node = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Parameters {
    shake: bool,
    pub(crate) n: usize,
    h: usize,
    d: usize,
    hp: usize,
    a: usize,
    k: usize,
    m: usize,
}

const fn parameters(shake: bool, sizes: [usize; 7]) -> Parameters {
    let [n, h, d, hp, a, k, m] = sizes;

    Parameters {
        shake,
        n,
        h,
        d,
        hp,
        a,
        k,
        m,
    }
}

const SMALL_128: [usize; 7] = [16, 63, 7, 9, 12, 14, 30];

const FAST_128: [usize; 7] = [16, 66, 22, 3, 6, 33, 34];

const SMALL_192: [usize; 7] = [24, 63, 7, 9, 14, 17, 39];

const FAST_192: [usize; 7] = [24, 66, 22, 3, 8, 33, 42];

const SMALL_256: [usize; 7] = [32, 64, 8, 8, 14, 22, 47];

const FAST_256: [usize; 7] = [32, 68, 17, 4, 9, 35, 49];

pub(crate) const SHA2_128S: Parameters = parameters(false, SMALL_128);

pub(crate) const SHA2_128F: Parameters = parameters(false, FAST_128);

pub(crate) const SHA2_192S: Parameters = parameters(false, SMALL_192);

pub(crate) const SHA2_192F: Parameters = parameters(false, FAST_192);

pub(crate) const SHA2_256S: Parameters = parameters(false, SMALL_256);

pub(crate) const SHA2_256F: Parameters = parameters(false, FAST_256);

pub(crate) const SHAKE_128S: Parameters = parameters(true, SMALL_128);

pub(crate) const SHAKE_128F: Parameters = parameters(true, FAST_128);

pub(crate) const SHAKE_192S: Parameters = parameters(true, SMALL_192);

pub(crate) const SHAKE_192F: Parameters = parameters(true, FAST_192);

pub(crate) const SHAKE_256S: Parameters = parameters(true, SMALL_256);

pub(crate) const SHAKE_256F: Parameters = parameters(true, FAST_256);

impl Parameters {
    const fn len(&self) -> usize {
        2 * self.n + 3
    }

    pub(crate) const fn public_key_size(&self) -> usize {
        2 * self.n
    }

    pub(crate) const fn private_key_size(&self) -> usize {
        4 * self.n
    }

    pub(crate) const fn signature_size(&self) -> usize {
        (1 + self.k * (1 + self.a) + self.h + self.d * self.len()) * self.n
    }

    const fn xmss_size(&self) -> usize {
        (self.len() + self.hp) * self.n
    }

    const fn fors_size(&self) -> usize {
        self.k * (1 + self.a) * self.n
    }
}

fn set_word(adrs: &mut Adrs, offset: usize, value: u32) {
    adrs[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn get_word(adrs: &Adrs, offset: usize) -> u32 {
    u32::from_be_bytes([
        adrs[offset],
        adrs[offset + 1],
        adrs[offset + 2],
        adrs[offset + 3],
    ])
}

fn set_layer(adrs: &mut Adrs, layer: usize) {
    set_word(adrs, 0, layer as u32);
}

fn set_tree(adrs: &mut Adrs, tree: u64) {
    adrs[4..8].fill(0);

    adrs[8..16].copy_from_slice(&tree.to_be_bytes());
}

fn set_type(adrs: &mut Adrs, kind: u32) {
    set_word(adrs, 16, kind);

    adrs[20..].fill(0);
}

fn set_key_pair(adrs: &mut Adrs, key_pair: u32) {
    set_word(adrs, 20, key_pair);
}

fn key_pair(adrs: &Adrs) -> u32 {
    get_word(adrs, 20)
}

// The chain address and the tree height share word 6; the hash address and the tree index
// share word 7.
fn set_chain(adrs: &mut Adrs, value: u32) {
    set_word(adrs, 24, value);
}

fn set_hash(adrs: &mut Adrs, value: u32) {
    set_word(adrs, 28, value);
}

fn tree_index(adrs: &Adrs) -> u32 {
    get_word(adrs, 28)
}

// The SHA-2 states after the first block, PK.seed and its zero padding; H and T use SHA-512
// above security category 1 and the SHA-256 state otherwise.
struct Sha2States {
    small: Sha256,
    large: Option<Sha512>,
}

// FIPS 205, section 11: F, H, T and PRF bound to one public seed. For SHA-2 the block holding
// PK.seed and its zero padding is hashed once and the state reused for every call.
struct Hashes<'a> {
    n: usize,
    pk_seed: &'a [u8],
    sk_seed: &'a [u8],
    sha2: Option<Sha2States>,
}

impl<'a> Hashes<'a> {
    fn new(p: &Parameters, pk_seed: &'a [u8], sk_seed: &'a [u8]) -> Self {
        let sha2 = (!p.shake).then(|| {
            let mut small = Sha256::new(&IV_256);

            small.update(pk_seed);

            small.update(&[0; 64][p.n..]);

            let large = (p.n > 16).then(|| {
                let mut large = Sha512::new(&IV_512);

                large.update(pk_seed);

                large.update(&[0; 128][p.n..]);

                large
            });

            Sha2States { small, large }
        });

        Self {
            n: p.n,
            pk_seed,
            sk_seed,
            sha2,
        }
    }

    fn shake(&self, adrs: &Adrs, parts: &[&[u8]]) -> Node {
        let mut engine = shake256(&[self.pk_seed, adrs]);

        for part in parts {
            engine.update(part);
        }

        let mut out = [0; 32];

        engine.read(&mut out[..self.n]);

        out
    }

    // ADRSc: the layer, the low 8 bytes of the tree address, the type and the last 12 bytes.
    fn compressed(adrs: &Adrs) -> [u8; 22] {
        let mut out = [0; 22];

        out[0] = adrs[3];

        out[1..9].copy_from_slice(&adrs[8..16]);

        out[9] = adrs[19];

        out[10..].copy_from_slice(&adrs[20..]);

        out
    }

    fn truncate(&self, digest: &[u8]) -> Node {
        let mut out = [0; 32];

        out[..self.n].copy_from_slice(&digest[..self.n]);

        out
    }

    fn with_sha256(&self, base: &Sha256, adrs: &Adrs, parts: &[&[u8]]) -> Node {
        let mut engine = base.clone();

        engine.update(&Self::compressed(adrs));

        for part in parts {
            engine.update(part);
        }

        self.truncate(&engine.digest())
    }

    fn with_sha512(&self, base: &Sha512, adrs: &Adrs, parts: &[&[u8]]) -> Node {
        let mut engine = base.clone();

        engine.update(&Self::compressed(adrs));

        for part in parts {
            engine.update(part);
        }

        self.truncate(&engine.digest())
    }

    fn f(&self, adrs: &Adrs, parts: &[&[u8]]) -> Node {
        match &self.sha2 {
            None => self.shake(adrs, parts),
            Some(states) => self.with_sha256(&states.small, adrs, parts),
        }
    }

    // H and T.
    fn h(&self, adrs: &Adrs, parts: &[&[u8]]) -> Node {
        match &self.sha2 {
            None => self.shake(adrs, parts),
            Some(Sha2States {
                large: Some(large), ..
            }) => self.with_sha512(large, adrs, parts),
            Some(Sha2States { small, large: None }) => self.with_sha256(small, adrs, parts),
        }
    }

    fn prf(&self, adrs: &Adrs) -> Node {
        self.f(adrs, &[self.sk_seed])
    }
}

struct Context<'a> {
    p: &'a Parameters,
    hashes: Hashes<'a>,
}

impl Context<'_> {
    fn chain(&self, mut x: Node, start: u32, steps: u32, adrs: &mut Adrs) -> Node {
        for j in start..start + steps {
            set_hash(adrs, j);

            x = self.hashes.f(adrs, &[&x[..self.p.n]]);
        }

        x
    }

    // base_2b(message, 4, 2n) followed by the three digits of the shifted checksum.
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

    fn wots_secret(&self, adrs: &Adrs, i: usize) -> Node {
        let mut sk_adrs = *adrs;

        set_type(&mut sk_adrs, WOTS_PRF);

        set_key_pair(&mut sk_adrs, key_pair(adrs));

        set_chain(&mut sk_adrs, i as u32);

        self.hashes.prf(&sk_adrs)
    }

    fn wots_public(&self, adrs: &Adrs, values: &[u8]) -> Node {
        let mut pk_adrs = *adrs;

        set_type(&mut pk_adrs, WOTS_PK);

        set_key_pair(&mut pk_adrs, key_pair(adrs));

        self.hashes.h(&pk_adrs, &[values])
    }

    fn wots_pk_gen(&self, adrs: &mut Adrs) -> Node {
        let n = self.p.n;

        let mut values = [0u8; MAX_LEN * 32];

        for (i, value) in values.chunks_exact_mut(n).take(self.p.len()).enumerate() {
            let secret = self.wots_secret(adrs, i);

            set_chain(adrs, i as u32);

            value.copy_from_slice(&self.chain(secret, 0, W - 1, adrs)[..n]);
        }

        self.wots_public(adrs, &values[..self.p.len() * n])
    }

    fn wots_sign(&self, message: &[u8], adrs: &mut Adrs, out: &mut [u8]) {
        let n = self.p.n;

        let digits = self.wots_digits(message);

        for (i, (value, &digit)) in out.chunks_exact_mut(n).zip(&digits).enumerate() {
            let secret = self.wots_secret(adrs, i);

            set_chain(adrs, i as u32);

            value.copy_from_slice(&self.chain(secret, 0, digit, adrs)[..n]);
        }
    }

    fn wots_pk_from_sig(&self, signature: &[u8], message: &[u8], adrs: &mut Adrs) -> Node {
        let n = self.p.n;

        let digits = self.wots_digits(message);

        let mut values = [0u8; MAX_LEN * 32];

        let pieces = values.chunks_exact_mut(n).zip(signature.chunks_exact(n));

        for (i, ((value, piece), &digit)) in pieces.zip(&digits).enumerate() {
            set_chain(adrs, i as u32);

            let mut x = [0; 32];

            x[..n].copy_from_slice(piece);

            value.copy_from_slice(&self.chain(x, digit, W - 1 - digit, adrs)[..n]);
        }

        self.wots_public(adrs, &values[..self.p.len() * n])
    }

    fn xmss_node(&self, i: u32, z: u32, adrs: &mut Adrs) -> Node {
        if z == 0 {
            set_type(adrs, WOTS_HASH);

            set_key_pair(adrs, i);

            return self.wots_pk_gen(adrs);
        }

        let left = self.xmss_node(2 * i, z - 1, adrs);

        let right = self.xmss_node(2 * i + 1, z - 1, adrs);

        set_type(adrs, TREE);

        set_chain(adrs, z);

        set_hash(adrs, i);

        let n = self.p.n;

        self.hashes.h(adrs, &[&left[..n], &right[..n]])
    }

    fn xmss_sign(&self, message: &[u8], index: u32, adrs: &mut Adrs, out: &mut [u8]) {
        let n = self.p.n;

        let (wots, auth) = out.split_at_mut(self.p.len() * n);

        for (j, node) in auth.chunks_exact_mut(n).enumerate() {
            node.copy_from_slice(&self.xmss_node((index >> j) ^ 1, j as u32, adrs)[..n]);
        }

        set_type(adrs, WOTS_HASH);

        set_key_pair(adrs, index);

        self.wots_sign(message, adrs, wots);
    }

    // Climbs from the leaf to the root along the authentication path (FIPS 205, Algorithm 11,
    // and the same loop in Algorithm 17).
    fn climb(&self, mut node: Node, index: u32, auth: &[u8], adrs: &mut Adrs) -> Node {
        let n = self.p.n;

        for (k, sibling) in auth.chunks_exact(n).enumerate() {
            set_chain(adrs, k as u32 + 1);

            if (index >> k) & 1 == 0 {
                set_hash(adrs, tree_index(adrs) / 2);

                node = self.hashes.h(adrs, &[&node[..n], sibling]);
            } else {
                set_hash(adrs, (tree_index(adrs) - 1) / 2);

                node = self.hashes.h(adrs, &[sibling, &node[..n]]);
            }
        }

        node
    }

    fn xmss_pk_from_sig(
        &self,
        index: u32,
        signature: &[u8],
        message: &[u8],
        adrs: &mut Adrs,
    ) -> Node {
        let (wots, auth) = signature.split_at(self.p.len() * self.p.n);

        set_type(adrs, WOTS_HASH);

        set_key_pair(adrs, index);

        let node = self.wots_pk_from_sig(wots, message, adrs);

        set_type(adrs, TREE);

        set_hash(adrs, index);

        self.climb(node, index, auth, adrs)
    }

    fn leaf_mask(&self) -> u64 {
        (1 << self.p.hp) - 1
    }

    fn ht_sign(&self, message: &[u8], mut tree: u64, leaf: u32, out: &mut [u8]) {
        let n = self.p.n;

        let mut adrs = [0; 32];

        set_tree(&mut adrs, tree);

        let mut parts = out.chunks_exact_mut(self.p.xmss_size());

        let first = parts.next().expect("one XMSS signature per layer");

        self.xmss_sign(message, leaf, &mut adrs, first);

        let mut root = self.xmss_pk_from_sig(leaf, first, message, &mut adrs);

        for (j, part) in parts.enumerate().map(|(j, part)| (j + 1, part)) {
            let leaf = (tree & self.leaf_mask()) as u32;

            tree >>= self.p.hp;

            set_layer(&mut adrs, j);

            set_tree(&mut adrs, tree);

            self.xmss_sign(&root[..n], leaf, &mut adrs, part);

            if j < self.p.d - 1 {
                root = self.xmss_pk_from_sig(leaf, part, &root[..n], &mut adrs);
            }
        }
    }

    fn ht_verify(&self, message: &[u8], signature: &[u8], mut tree: u64, leaf: u32) -> Node {
        let n = self.p.n;

        let mut adrs = [0; 32];

        set_tree(&mut adrs, tree);

        let mut parts = signature.chunks_exact(self.p.xmss_size());

        let first = parts.next().expect("one XMSS signature per layer");

        let mut node = self.xmss_pk_from_sig(leaf, first, message, &mut adrs);

        for (j, part) in parts.enumerate().map(|(j, part)| (j + 1, part)) {
            let leaf = (tree & self.leaf_mask()) as u32;

            tree >>= self.p.hp;

            set_layer(&mut adrs, j);

            set_tree(&mut adrs, tree);

            node = self.xmss_pk_from_sig(leaf, part, &node[..n], &mut adrs);
        }

        node
    }

    fn fors_secret(&self, adrs: &Adrs, index: u32) -> Node {
        let mut sk_adrs = *adrs;

        set_type(&mut sk_adrs, FORS_PRF);

        set_key_pair(&mut sk_adrs, key_pair(adrs));

        set_hash(&mut sk_adrs, index);

        self.hashes.prf(&sk_adrs)
    }

    fn fors_node(&self, i: u32, z: u32, adrs: &mut Adrs) -> Node {
        let n = self.p.n;

        if z == 0 {
            let secret = self.fors_secret(adrs, i);

            set_chain(adrs, 0);

            set_hash(adrs, i);

            return self.hashes.f(adrs, &[&secret[..n]]);
        }

        let left = self.fors_node(2 * i, z - 1, adrs);

        let right = self.fors_node(2 * i + 1, z - 1, adrs);

        set_chain(adrs, z);

        set_hash(adrs, i);

        self.hashes.h(adrs, &[&left[..n], &right[..n]])
    }

    // base_2b(digest, a, k): the indices of the revealed FORS leaves.
    fn fors_indices(&self, digest: &[u8]) -> [u32; MAX_K] {
        let a = self.p.a;

        let mut indices = [0; MAX_K];

        let mut total = 0u64;

        let mut bits = 0;

        let mut bytes = digest.iter();

        for index in indices.iter_mut().take(self.p.k) {
            while bits < a {
                total = (total << 8) | u64::from(*bytes.next().expect("digest long enough"));

                bits += 8;
            }

            bits -= a;

            *index = ((total >> bits) & ((1 << a) - 1)) as u32;

            total &= (1 << bits) - 1;
        }

        indices
    }

    fn fors_sign(&self, digest: &[u8], adrs: &mut Adrs, out: &mut [u8]) {
        let (n, a) = (self.p.n, self.p.a);

        let indices = self.fors_indices(digest);

        for (i, (chunk, &index)) in out.chunks_exact_mut((a + 1) * n).zip(&indices).enumerate() {
            let base = (i << a) as u32;

            chunk[..n].copy_from_slice(&self.fors_secret(adrs, base + index)[..n]);

            for (j, node) in chunk[n..].chunks_exact_mut(n).enumerate() {
                let sibling = ((i << (a - j)) as u32) + ((index >> j) ^ 1);

                node.copy_from_slice(&self.fors_node(sibling, j as u32, adrs)[..n]);
            }
        }
    }

    fn fors_pk_from_sig(&self, signature: &[u8], digest: &[u8], adrs: &mut Adrs) -> Node {
        let (n, a) = (self.p.n, self.p.a);

        let indices = self.fors_indices(digest);

        let mut roots = [0u8; MAX_K * 32];

        let trees = signature.chunks_exact((a + 1) * n).zip(&indices);

        for (i, ((chunk, &index), root)) in trees.zip(roots.chunks_exact_mut(n)).enumerate() {
            set_chain(adrs, 0);

            set_hash(adrs, ((i << a) as u32) + index);

            let leaf = self.hashes.f(adrs, &[&chunk[..n]]);

            root.copy_from_slice(&self.climb(leaf, index, &chunk[n..], adrs)[..n]);
        }

        let mut pk_adrs = *adrs;

        set_type(&mut pk_adrs, FORS_ROOTS);

        set_key_pair(&mut pk_adrs, key_pair(adrs));

        self.hashes.h(&pk_adrs, &[&roots[..self.p.k * n]])
    }
}

fn mgf1(seed: &[&[u8]], out: &mut [u8], large: bool) {
    for (counter, chunk) in out.chunks_mut(if large { 64 } else { 32 }).enumerate() {
        let suffix = (counter as u32).to_be_bytes();

        let mut parts = seed.to_vec();

        parts.push(&suffix);

        if large {
            chunk.copy_from_slice(&sha512(&parts)[..chunk.len()]);
        } else {
            chunk.copy_from_slice(&sha256(&parts)[..chunk.len()]);
        }
    }
}

fn h_msg(p: &Parameters, r: &[u8], pk_seed: &[u8], pk_root: &[u8], message: &[&[u8]]) -> Vec<u8> {
    let mut digest = vec![0; p.m];

    let mut parts = vec![r, pk_seed, pk_root];

    parts.extend_from_slice(message);

    if p.shake {
        shake256(&parts).read(&mut digest);
    } else if p.n == 16 {
        mgf1(&[r, pk_seed, &sha256(&parts)], &mut digest, false);
    } else {
        mgf1(&[r, pk_seed, &sha512(&parts)], &mut digest, true);
    }

    digest
}

fn prf_msg(p: &Parameters, sk_prf: &[u8], opt_rand: &[u8], message: &[&[u8]]) -> Node {
    let mut out = [0; 32];

    if p.shake {
        let mut engine = shake256(&[sk_prf, opt_rand]);

        for part in message {
            engine.update(part);
        }

        engine.read(&mut out[..p.n]);
    } else {
        let mut hmac = if p.n == 16 {
            HMAC_SHA_256.create(sk_prf)
        } else {
            HMAC_SHA_512.create(sk_prf)
        };

        hmac.update(opt_rand);

        for part in message {
            hmac.update(part);
        }

        out[..p.n].copy_from_slice(&hmac.digest()[..p.n]);
    }

    out
}

fn read_bits(bytes: &[u8], bits: usize) -> u64 {
    let value = bytes
        .iter()
        .fold(0u64, |value, &byte| (value << 8) | u64::from(byte));

    value & (u64::MAX >> (64 - bits))
}

// The FORS message digest, the tree index and the leaf index (FIPS 205, Algorithm 19).
fn split_digest<'a>(p: &Parameters, digest: &'a [u8]) -> (&'a [u8], u64, u32) {
    let md_size = (p.k * p.a).div_ceil(8);

    let tree_bits = p.h - p.h / p.d;

    let tree_size = tree_bits.div_ceil(8);

    let leaf_bits = p.h / p.d;

    let (md, rest) = digest.split_at(md_size);

    let (tree, rest) = rest.split_at(tree_size);

    let leaf = read_bits(&rest[..leaf_bits.div_ceil(8)], leaf_bits);

    (md, read_bits(tree, tree_bits), leaf as u32)
}

pub(crate) fn root(p: &Parameters, sk_seed: &[u8], pk_seed: &[u8]) -> Node {
    let context = Context {
        p,
        hashes: Hashes::new(p, pk_seed, sk_seed),
    };

    let mut adrs = [0; 32];

    set_layer(&mut adrs, p.d - 1);

    context.xmss_node(0, p.hp as u32, &mut adrs)
}

pub(crate) fn keygen_internal(
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    p: &Parameters,
) -> (SecretBytes, Vec<u8>) {
    let pk_root = root(p, sk_seed, pk_seed);

    let pk_root = &pk_root[..p.n];

    let sk = SecretBytes::concat(&[sk_seed, sk_prf, pk_seed, pk_root]);

    (sk, [pk_seed, pk_root].concat())
}

pub(crate) fn sign_internal(
    message: &[&[u8]],
    sk: &[u8],
    addrnd: &[u8],
    p: &Parameters,
) -> Vec<u8> {
    let n = p.n;

    let (sk_seed, rest) = sk.split_at(n);

    let (sk_prf, rest) = rest.split_at(n);

    let (pk_seed, pk_root) = rest.split_at(n);

    let context = Context {
        p,
        hashes: Hashes::new(p, pk_seed, sk_seed),
    };

    let r = prf_msg(p, sk_prf, addrnd, message);

    let digest = h_msg(p, &r[..n], pk_seed, pk_root, message);

    let (md, tree, leaf) = split_digest(p, &digest);

    let mut signature = vec![0; p.signature_size()];

    let (r_part, rest) = signature.split_at_mut(n);

    r_part.copy_from_slice(&r[..n]);

    let (fors, ht) = rest.split_at_mut(p.fors_size());

    let mut adrs = [0; 32];

    set_tree(&mut adrs, tree);

    set_type(&mut adrs, FORS_TREE);

    set_key_pair(&mut adrs, leaf);

    context.fors_sign(md, &mut adrs, fors);

    let pk_fors = context.fors_pk_from_sig(fors, md, &mut adrs);

    context.ht_sign(&pk_fors[..n], tree, leaf, ht);

    signature
}

pub(crate) fn verify_internal(
    message: &[&[u8]],
    signature: &[u8],
    pk: &[u8],
    p: &Parameters,
) -> bool {
    let n = p.n;

    if signature.len() != p.signature_size() || pk.len() != p.public_key_size() {
        return false;
    }

    let (pk_seed, pk_root) = pk.split_at(n);

    let context = Context {
        p,
        hashes: Hashes::new(p, pk_seed, &[]),
    };

    let (r, rest) = signature.split_at(n);

    let (fors, ht) = rest.split_at(p.fors_size());

    let digest = h_msg(p, r, pk_seed, pk_root, message);

    let (md, tree, leaf) = split_digest(p, &digest);

    let mut adrs = [0; 32];

    set_tree(&mut adrs, tree);

    set_type(&mut adrs, FORS_TREE);

    set_key_pair(&mut adrs, leaf);

    let pk_fors = context.fors_pk_from_sig(fors, md, &mut adrs);

    context.ht_verify(&pk_fors[..n], ht, tree, leaf)[..n] == *pk_root
}

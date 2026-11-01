use alloc::vec;
use alloc::vec::Vec;

use crate::ct::declassify;
use crate::error::Error;
use crate::merkle::{MerkleTree, Node, TreeHasher};
use crate::primitives::TruncatedHash;
use crate::sha2::{IV_256, Sha256};
use crate::wipe::{SecretBytes, wipe};

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

// Hashes computed side by side (see Sha256::finish_lanes).
const LANES: usize = 16;

type Adrs = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Parameters {
    pub(crate) name: &'static str,
    pub(crate) oid: u32,
    shake: bool,
    pub(crate) n: usize,
    h: u32,
    pub(crate) d: u32,
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

    pub(crate) const fn tree_height(&self) -> u32 {
        self.h / self.d
    }

    const fn len(&self) -> usize {
        2 * self.n + 3
    }

    pub(crate) const fn index_size(&self) -> usize {
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
        self.index_size() + self.n + self.d as usize * self.layer_signature_size()
    }

    // What one layer adds to a signature: a WOTS+ signature and an authentication path.
    pub(crate) const fn layer_signature_size(&self) -> usize {
        (self.len() + self.tree_height() as usize) * self.n
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

// out = a ^ b, written in place, as a chain value's is secret.
fn xor_into(out: &mut [u8], a: &[u8], b: &[u8]) {
    for ((out, &a), &b) in out.iter_mut().zip(a).zip(b) {
        *out = a ^ b;
    }
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
    // after it is computed once per key for PRF (keyed by PUB_SEED, here, as it is public) and
    // PRF_keygen (by SK_SEED, in keygen).
    fn new(p: &'a Parameters, pub_seed: &'a [u8], sk_seed: &'a [u8]) -> Self {
        let mut prf_state = None;

        Self::key(p, &mut prf_state, PRF, pub_seed);

        Self {
            p,
            pub_seed,
            sk_seed,
            prf_state,
            keygen_state: None,
        }
    }

    fn key(p: &Parameters, state: &mut Option<Sha256>, prefix: u32, key: &[u8]) {
        if p.n == 32 && !p.shake && !key.is_empty() {
            let state = state.insert(Sha256::new(&IV_256));

            state.update(&to_byte(u64::from(prefix), 32));

            state.update(key);
        }
    }

    // The PRF_keygen state, keyed in place, where the drop of self wipes it: keyed in new and
    // moved into Self, the engine that absorbed SK_SEED would leave copies of it behind.
    fn keygen(&mut self) {
        Self::key(self.p, &mut self.keygen_state, PRF_KEYGEN, self.sk_seed);
    }

    fn hash(&self, prefix: u32, key: &[u8], message: &[&[u8]]) -> Node {
        let mut engine = TruncatedHash::new(self.p.shake);

        engine.update(&to_byte(u64::from(prefix), self.p.padding())[..self.p.padding()]);

        engine.update(key);

        for part in message {
            engine.update(part);
        }

        let mut node = [0; 32];

        engine.finish(self.p.n, &mut node);

        node
    }

    // The hashes of L messages of length bytes, side by side, after the shared input of state
    // if given, into nodes; with SHAKE the inactive lanes are skipped and keep their nodes. The
    // messages are wiped.
    fn finish_lanes<const L: usize, const SIZE: usize>(
        &self,
        state: Option<&Sha256>,
        messages: &mut [[u8; SIZE]; L],
        length: usize,
        active: [bool; L],
        nodes: &mut [Node; L],
    ) {
        let n = self.p.n;

        if self.p.shake {
            for ((node, message), &active) in nodes.iter_mut().zip(&*messages).zip(&active) {
                if active {
                    TruncatedHash::digest(true, n, &[&message[..length]], node);
                }
            }

            wipe(messages.as_flattened_mut());

            return;
        }

        let mut digests = [[0; 32]; L];

        state
            .unwrap_or(&Sha256::new(&IV_256))
            .finish_lanes(messages, length, &mut digests);

        for (node, digest) in nodes.iter_mut().zip(&digests) {
            node[..n].copy_from_slice(&digest[..n]);

            node[n..].fill(0);
        }

        wipe(digests.as_flattened_mut());
    }

    // toByte(prefix, padding) || KEY || M for each lane, where write(lane, out) puts KEY || M in
    // out and returns its length, the same for every lane.
    fn hash_lanes<const L: usize, const SIZE: usize>(
        &self,
        prefix: u32,
        active: [bool; L],
        write: impl Fn(usize, &mut [u8]) -> usize,
        nodes: &mut [Node; L],
    ) {
        let padding = self.p.padding();

        let mut messages = [[0; SIZE]; L];

        let mut length = 0;

        for (lane, message) in messages.iter_mut().enumerate() {
            message[..padding].copy_from_slice(&to_byte(u64::from(prefix), padding)[..padding]);

            length = padding + write(lane, &mut message[padding..]);
        }

        self.finish_lanes(None, &mut messages, length, active, nodes);
    }

    // The keys and bitmasks, from PUB_SEED and public addresses: public.
    fn prf_lanes<const L: usize>(&self, adrs: &[Adrs; L], active: [bool; L]) -> [Node; L] {
        let n = self.p.n;

        let mut nodes = [[0; 32]; L];

        let Some(state) = &self.prf_state else {
            self.hash_lanes::<L, 128>(
                PRF,
                active,
                |lane, out| {
                    out[..n].copy_from_slice(self.pub_seed);

                    out[n..n + 32].copy_from_slice(&adrs[lane]);

                    n + 32
                },
                &mut nodes,
            );

            return nodes;
        };

        let mut messages = [[0; 64]; L];

        for (message, adrs) in messages.iter_mut().zip(adrs) {
            message[..32].copy_from_slice(adrs);
        }

        self.finish_lanes(Some(state), &mut messages, 32, active, &mut nodes);

        nodes
    }

    // SP 800-208: secret chain values come from PRF_keygen(SK_SEED, PUB_SEED || ADRS), into
    // nodes.
    fn prf_keygen_lanes<const L: usize>(&self, adrs: &[Adrs; L], nodes: &mut [Node; L]) {
        let n = self.p.n;

        let Some(state) = &self.keygen_state else {
            return self.hash_lanes::<L, 128>(
                PRF_KEYGEN,
                [true; L],
                |lane, out| {
                    out[..n].copy_from_slice(self.sk_seed);

                    out[n..2 * n].copy_from_slice(self.pub_seed);

                    out[2 * n..2 * n + 32].copy_from_slice(&adrs[lane]);

                    2 * n + 32
                },
                nodes,
            );
        };

        let mut messages = [[0; 128]; L];

        for (message, adrs) in messages.iter_mut().zip(adrs) {
            message[..n].copy_from_slice(self.pub_seed);

            message[n..n + 32].copy_from_slice(adrs);
        }

        self.finish_lanes(Some(state), &mut messages, n + 32, [true; L], nodes);
    }

    // One step of each lane's chain, whose hash address is set in its adrs, from x into out: the
    // key and the bitmask from PRF, then F (RFC 8391, Algorithm 2).
    fn chain_lanes<const L: usize>(
        &self,
        x: &[Node; L],
        adrs: &mut [Adrs; L],
        active: [bool; L],
        out: &mut [Node; L],
    ) {
        let n = self.p.n;

        for adrs in adrs.iter_mut() {
            set_word(adrs, 7, 0);
        }

        let keys = self.prf_lanes(adrs, active);

        for adrs in adrs.iter_mut() {
            set_word(adrs, 7, 1);
        }

        let masks = self.prf_lanes(adrs, active);

        self.hash_lanes::<L, 128>(
            F,
            active,
            |lane, message| {
                message[..n].copy_from_slice(&keys[lane][..n]);

                xor_into(&mut message[n..2 * n], &x[lane][..n], &masks[lane][..n]);

                2 * n
            },
            out,
        );
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

    // The secret starts of the chains first.. of the key at adrs, into secrets; the hash and
    // key-and-mask words are cleared for them, and every chain step sets them again.
    fn wots_secrets<const L: usize>(
        &self,
        adrs: &mut [Adrs; L],
        chains: [usize; L],
        secrets: &mut [Node; L],
    ) {
        for (adrs, i) in adrs.iter_mut().zip(chains) {
            set_word(adrs, 5, i as u32);

            set_word(adrs, 6, 0);

            set_word(adrs, 7, 0);
        }

        self.prf_keygen_lanes(adrs, secrets);
    }

    // The WOTS+ public keys of L keys, from their OTS addresses, chain by chain for all of them.
    fn wots_public_lanes<const L: usize>(
        &self,
        adrs: &mut [Adrs; L],
        values: &mut [[Node; MAX_LEN]],
    ) {
        // The chain values, secret below the ends: each step reads one buffer and writes the
        // other, and both are wiped at the end.
        let mut buffers = [[[0; 32]; L]; 2];

        let [mut x, mut y] = buffers.each_mut();

        for i in 0..self.p.len() {
            self.wots_secrets(adrs, [i; L], x);

            for k in 0..W - 1 {
                for adrs in adrs.iter_mut() {
                    set_word(adrs, 6, k);
                }

                self.chain_lanes(x, adrs, [true; L], y);

                core::mem::swap(&mut x, &mut y);
            }

            for (value, x) in values.iter_mut().zip(x.iter()) {
                value[i] = *x;
            }
        }

        wipe(buffers.as_flattened_mut().as_flattened_mut());
    }

    // Advances chain i of the WOTS+ key at adrs from step starts[i] to ends[i], for every chain.
    // The chains have different lengths, so each lane takes the next chain as its own ends, the
    // longest first so that the last ones to finish are short. The lengths come from public
    // digests.
    fn chains(&self, adrs: &Adrs, starts: &[u32], ends: &[u32], values: &mut [Node]) {
        let mut order: [usize; MAX_LEN] = core::array::from_fn(|i| i);

        let order = &mut order[..values.len()];

        order.sort_unstable_by_key(|&i| core::cmp::Reverse(ends[i] - starts[i]));

        let mut pending = order.iter().copied().filter(|&i| starts[i] < ends[i]);

        let mut lanes: [Option<(usize, u32)>; LANES] = [None; LANES];

        // The inputs and outputs of the last steps: in a signature, chain values below the signed
        // ones, which would let anyone sign a smaller digit, so they are wiped.
        let (mut x, mut outputs) = ([[0; 32]; LANES], [[0; 32]; LANES]);

        loop {
            for lane in lanes.iter_mut().filter(|lane| lane.is_none()) {
                *lane = pending.next().map(|i| (i, starts[i]));
            }

            if lanes.iter().all(Option::is_none) {
                break;
            }

            let mut lane_adrs = lanes.map(|lane| {
                let mut chain_adrs = *adrs;

                if let Some((i, k)) = lane {
                    set_word(&mut chain_adrs, 5, i as u32);

                    set_word(&mut chain_adrs, 6, k);
                }

                chain_adrs
            });

            for (x, lane) in x.iter_mut().zip(lanes) {
                *x = lane.map_or([0; 32], |(i, _)| values[i]);
            }

            let active = lanes.map(|lane| lane.is_some());

            self.chain_lanes(&x, &mut lane_adrs, active, &mut outputs);

            for (lane, output) in lanes.iter_mut().zip(&outputs) {
                if let Some((i, k)) = lane {
                    values[*i] = *output;

                    *k += 1;

                    if *k == ends[*i] {
                        *lane = None;
                    }
                }
            }
        }

        wipe(x.as_flattened_mut());

        wipe(outputs.as_flattened_mut());
    }

    fn wots_sign(&self, message: &[u8], adrs: &Adrs, out: &mut Vec<u8>) {
        let len = self.p.len();

        #[cfg(test)]
        crate::merkle::one_time_signature(&[b"X", self.sk_seed, self.pub_seed, &adrs[..20]]);

        let mut values = [[0; 32]; MAX_LEN];

        let mut secrets = [[0; 32]; LANES];

        for (first, group) in (0..len).step_by(LANES).zip(values.chunks_mut(LANES)) {
            let chains = core::array::from_fn(|lane| first + lane);

            self.wots_secrets(&mut [*adrs; LANES], chains, &mut secrets);

            for (value, secret) in group.iter_mut().zip(&secrets) {
                *value = *secret;
            }
        }

        wipe(secrets.as_flattened_mut());

        self.chains(
            adrs,
            &[0; MAX_LEN][..len],
            &self.wots_digits(message)[..len],
            &mut values[..len],
        );

        for value in &values[..len] {
            out.extend_from_slice(&value[..self.p.n]);
        }

        // The caller verifies the signature before it is released and wipes it if it is faulty.
        wipe(values.as_flattened_mut());
    }

    fn wots_public_from_signature(
        &self,
        signature: &[u8],
        message: &[u8],
        adrs: &Adrs,
    ) -> [Node; MAX_LEN] {
        let (n, len) = (self.p.n, self.p.len());

        let mut values = [[0; 32]; MAX_LEN];

        for (value, piece) in values.iter_mut().zip(signature.chunks_exact(n)) {
            value[..n].copy_from_slice(piece);
        }

        let digits = self.wots_digits(message);

        self.chains(
            adrs,
            &digits[..len],
            &[W - 1; MAX_LEN][..len],
            &mut values[..len],
        );

        values
    }

    fn rand_hash_lanes<const L: usize>(
        &self,
        left: &[Node; L],
        right: &[Node; L],
        adrs: &mut [Adrs; L],
    ) -> [Node; L] {
        let n = self.p.n;

        let mut prf = |word: u32| {
            for adrs in adrs.iter_mut() {
                set_word(adrs, 7, word);
            }

            self.prf_lanes(adrs, [true; L])
        };

        let (keys, masks0, masks1) = (prf(0), prf(1), prf(2));

        let mut nodes = [[0; 32]; L];

        self.hash_lanes::<L, 192>(
            H,
            [true; L],
            |lane, out| {
                out[..n].copy_from_slice(&keys[lane][..n]);

                xor_into(&mut out[n..2 * n], &left[lane][..n], &masks0[lane][..n]);

                xor_into(
                    &mut out[2 * n..3 * n],
                    &right[lane][..n],
                    &masks1[lane][..n],
                );

                3 * n
            },
            &mut nodes,
        );

        nodes
    }

    fn rand_hash(&self, left: &Node, right: &Node, adrs: &mut Adrs) -> Node {
        let [node] = self.rand_hash_lanes(&[*left], &[*right], core::array::from_mut(adrs));

        node
    }

    // RFC 8391, Algorithm 8, for L keys at once.
    fn ltree_lanes<const L: usize>(
        &self,
        values: &mut [[Node; MAX_LEN]],
        adrs: &mut [Adrs; L],
    ) -> [Node; L] {
        let mut count = self.p.len();

        let mut height = 0;

        for adrs in adrs.iter_mut() {
            set_word(adrs, 5, height);
        }

        while count > 1 {
            for i in 0..count / 2 {
                for adrs in adrs.iter_mut() {
                    set_word(adrs, 6, i as u32);
                }

                let left = core::array::from_fn(|lane| values[lane][2 * i]);

                let right = core::array::from_fn(|lane| values[lane][2 * i + 1]);

                let parents = self.rand_hash_lanes(&left, &right, adrs);

                for (value, parent) in values.iter_mut().zip(parents) {
                    value[i] = parent;
                }
            }

            if count % 2 == 1 {
                for value in values.iter_mut() {
                    value[count / 2] = value[count - 1];
                }
            }

            count = count.div_ceil(2);

            height += 1;

            for adrs in adrs.iter_mut() {
                set_word(adrs, 5, height);
            }
        }

        core::array::from_fn(|lane| values[lane][0])
    }

    // The leaves first.. of the tree at layer and tree: L WOTS+ public keys and their L-trees.
    fn leaf_lanes<const L: usize>(&self, layer: u32, tree: u64, first: u32) -> [Node; L] {
        let addresses = |kind: u32| {
            core::array::from_fn(|lane| {
                let mut adrs = address(layer, tree, kind);

                set_word(&mut adrs, 4, first + lane as u32);

                adrs
            })
        };

        let mut values = vec![[[0; 32]; MAX_LEN]; L];

        self.wots_public_lanes(&mut addresses(OTS), &mut values);

        self.ltree_lanes(&mut values, &mut addresses(LTREE))
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
    fn leaves(&self, first: u32, out: &mut [Node]) {
        let (layer, tree) = (self.layer, self.tree);

        for (start, group) in (first..).step_by(LANES).zip(out.chunks_mut(LANES)) {
            if let Ok(group) = <&mut [Node; LANES]>::try_from(&mut *group) {
                *group = self.hashes.leaf_lanes(layer, tree, start);
            } else {
                for (index, node) in (start..).zip(group) {
                    [*node] = self.hashes.leaf_lanes(layer, tree, index);
                }
            }
        }
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

// The root of the tree `tree` of a layer that one layer of a signature gives for an n-byte message
// signed at leaf: the WOTS+ public key from the signature, its L-tree, then the path upwards.
fn layer_root(
    hashes: &Hashes,
    layer: u32,
    tree: u64,
    leaf: u32,
    message: &[u8],
    signature: &[u8],
) -> Node {
    let p = hashes.p;

    let (wots, auth) = signature.split_at(p.len() * p.n);

    let mut ots = address(layer, tree, OTS);

    set_word(&mut ots, 4, leaf);

    let values = hashes.wots_public_from_signature(wots, message, &ots);

    let mut lt = address(layer, tree, LTREE);

    set_word(&mut lt, 4, leaf);

    let [leaf_node] = hashes.ltree_lanes(&mut [values], core::array::from_mut(&mut lt));

    hashes.compute_root(leaf_node, leaf, auth, layer, tree)
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

    let (r, layers) = signature[p.index_size()..].split_at(n);

    let mut node = hashes.message_digest(r, root, index, message);

    let height = p.tree_height();

    for (layer, part) in (0..p.d).zip(layers.chunks_exact(p.layer_signature_size())) {
        let leaf = (index & ((1 << height) - 1)) as u32;

        index >>= height;

        node = layer_root(&hashes, layer, index, leaf, &node[..n], part);
    }

    node[..n] == *root
}

// Whether the signature of one layer, by leaf `leaf` of tree `tree` at `layer`, signs the n-byte
// root of the tree below under the root of its own tree (RFC 8391, Algorithm 17, one layer).
pub(crate) fn verify_root(
    p: &Parameters,
    pub_seed: &[u8],
    (layer, tree, leaf): (u32, u64, u32),
    message: &[u8],
    signature: &[u8],
    root: &[u8],
) -> bool {
    signature.len() == p.layer_signature_size()
        && layer_root(
            &Hashes::new(p, pub_seed, &[]),
            layer,
            tree,
            leaf,
            message,
            signature,
        )[..p.n]
            == *root
}

// The randomizer r = PRF(SK_PRF, toByte(index, 32)) of the message signature at index, which is
// part of the signature.
pub(crate) fn randomizer(p: &Parameters, sk_prf: &[u8], index: u64) -> Node {
    let r = Hashes::new(p, &[], &[]).hash(PRF, sk_prf, &[&to_byte(index, 32)]);

    declassify(&r[..p.n]);

    r
}

// H_msg(r || root || toByte(index, n), message), which the bottom layer signs.
pub(crate) fn message_digest(
    p: &Parameters,
    r: &[u8],
    root: &[u8],
    index: u64,
    message: &[u8],
) -> Node {
    Hashes::new(p, &[], &[]).message_digest(r, root, index, message)
}

// One XMSS tree of a key: its layer, its number there, its S_XMSS, and its Merkle tree. Every tree
// of a key shares PUB_SEED, which the key passes in.
pub(crate) struct Tree {
    p: &'static Parameters,
    layer: u32,
    number: u64,
    s_xmss: SecretBytes,
    merkle: MerkleTree,
}

impl Tree {
    // The tree built from its leaves, or from the nodes of a tree cache that every parent there
    // agrees with.
    pub(crate) fn new(
        p: &'static Parameters,
        pub_seed: &[u8],
        s_xmss: &[u8],
        (layer, number): (u32, u64),
        nodes: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let s_xmss = SecretBytes::concat(&[s_xmss]);

        let mut hashes = Hashes::new(p, pub_seed, &s_xmss);

        hashes.keygen();

        let subtree = Subtree {
            hashes: &hashes,
            layer,
            tree: number,
        };

        let merkle = match nodes {
            Some(nodes) => MerkleTree::restore(p.tree_height(), p.n, nodes, &subtree)?,
            None => MerkleTree::new(p.tree_height(), &subtree),
        };

        // The root is the public key or what the layer above signs.
        declassify(merkle.root());

        Ok(Self {
            p,
            layer,
            number,
            s_xmss,
            merkle,
        })
    }

    pub(crate) fn root(&self) -> &[u8] {
        &self.merkle.root()[..self.p.n]
    }

    pub(crate) const fn merkle(&self) -> &MerkleTree {
        &self.merkle
    }

    // The WOTS+ signature of an n-byte message by leaf, followed by the leaf's authentication
    // path.
    pub(crate) fn sign(&mut self, pub_seed: &[u8], leaf: u32, message: &[u8]) -> Vec<u8> {
        let p = self.p;

        let mut hashes = Hashes::new(p, pub_seed, &self.s_xmss);

        hashes.keygen();

        let mut ots = address(self.layer, self.number, OTS);

        set_word(&mut ots, 4, leaf);

        let mut out = Vec::with_capacity(p.layer_signature_size());

        hashes.wots_sign(message, &ots, &mut out);

        let subtree = Subtree {
            hashes: &hashes,
            layer: self.layer,
            tree: self.number,
        };

        out.extend_from_slice(&self.merkle.auth_path(leaf, p.n, &subtree));

        declassify(&out);

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A batch that does not fill every lane falls back to one lane at a time. Only XMSS-*_16
    // signing needs that, so it is checked here against a full batch.
    #[test]
    fn single_lane_leaves_match_a_full_batch() {
        for name in ["XMSS-SHA2_10_256", "XMSS-SHAKE256_10_192"] {
            let p = by_name(&XMSS_SETS, name).unwrap();

            let seeds: Vec<u8> = (0..2 * p.n).map(|i| i as u8).collect();

            let mut hashes = Hashes::new(p, &seeds[..p.n], &seeds[p.n..]);

            hashes.keygen();

            let batch: [Node; LANES] = hashes.leaf_lanes(0, 0, 32);

            for (lane, leaf) in batch.iter().enumerate() {
                let [single] = hashes.leaf_lanes(0, 0, 32 + lane as u32);

                assert_eq!(&single, leaf, "{name} {lane}");
            }
        }
    }
}

use alloc::vec;
use alloc::vec::Vec;

use crate::ct::declassify;
use crate::keccak::{self, MAX_SPONGES, Sponges};
use crate::mac::{HMAC_SHA_256, HMAC_SHA_512};
use crate::primitives::{sha256, sha512, shake256, shake256_into};
use crate::sha2::{IV_256, IV_512, Sha256, Sha512};
use crate::wipe::{SecretBytes, wipe, wipe_unless_optimized};

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

// The largest tree height: h' of a hypertree layer or a of a FORS tree.
const MAX_HEIGHT: usize = 14;

// Hashes computed side by side (see Sha256::finish_lanes).
const LANES: usize = 16;

// The FORS tree leaves that fors_sign builds at a time, a power of two and a multiple of LANES.
const FORS_BLOCK: usize = 128;

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
        let mut engine = Line(shake256());

        engine.0.update(self.pk_seed);

        engine.0.update(adrs);

        for part in parts {
            engine.0.update(part);
        }

        let mut out = [0; 32];

        engine.0.read(&mut out[..self.n]);

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

    // ADRSc followed by the parts, as the message after the PK.seed block; returns its length.
    fn message(out: &mut [u8], adrs: &Adrs, parts: &[&[u8]]) -> usize {
        out[..22].copy_from_slice(&Self::compressed(adrs));

        let mut length = 22;

        for part in parts {
            out[length..length + part.len()].copy_from_slice(part);

            length += part.len();
        }

        length
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

    // F with SHAKE256 for the lanes that have an input, a group of sponges side by side: PK.seed,
    // ADRS and the input fill less than one block. Kept out of f_lanes: inlined there, its sponges
    // cost the SHA-2 path of f_lanes about 1% more time. The lanes without input keep their nodes.
    // Builds with a one-block kernel take one_block_lanes.
    #[inline(never)]
    fn shake_lanes(
        &self,
        adrs: &[Adrs; LANES],
        inputs: [Option<&[u8]>; LANES],
        nodes: &mut [Node; LANES],
    ) {
        let n = self.n;

        let mut active = [0; LANES];

        let mut count = 0;

        for (lane, input) in inputs.iter().enumerate() {
            if input.is_some() {
                active[count] = lane;

                count += 1;
            }
        }

        if keccak::ONE_BLOCK {
            return self.one_block_lanes(adrs, &inputs, &active[..count], nodes);
        }

        let mut sponges = Sponges::empty();

        for group in active[..count].chunks(keccak::group()) {
            let parts: [[&[u8]; 3]; MAX_SPONGES] = core::array::from_fn(|i| {
                let lane = group.get(i).copied().unwrap_or_default();

                [self.pk_seed, &adrs[lane], inputs[lane].unwrap_or_default()]
            });

            let messages = parts.each_ref().map(|parts| &parts[..]);

            sponges.start(136, 0x1F, &messages[..group.len()]);

            sponges.squeeze([true; MAX_SPONGES]);

            for (i, &lane) in group.iter().enumerate() {
                sponges.read(i, &mut nodes[lane][..n]);
            }
        }
    }

    // shake_lanes through keccak::one_block, for the lanes of active.
    #[inline(always)]
    fn one_block_lanes(
        &self,
        adrs: &[Adrs; LANES],
        inputs: &[Option<&[u8]>; LANES],
        active: &[usize],
        nodes: &mut [Node; LANES],
    ) {
        let n = self.n;

        // The nodes of the active lanes, in the order of active.
        let mut targets = nodes
            .iter_mut()
            .zip(inputs)
            .filter(|(_, input)| input.is_some())
            .map(|(node, _)| &mut node[..n]);

        let mut spare = None;

        for group in active.chunks(keccak::group()) {
            let parts: [[&[u8]; 3]; MAX_SPONGES] = core::array::from_fn(|i| {
                let lane = group.get(i).copied().unwrap_or_default();

                [self.pk_seed, &adrs[lane], inputs[lane].unwrap_or_default()]
            });

            let messages = parts.each_ref().map(|parts| &parts[..]);

            let mut outs: [&mut [u8]; MAX_SPONGES] = Default::default();

            for (out, target) in outs.iter_mut().zip(targets.by_ref().take(group.len())) {
                *out = target;
            }

            keccak::one_block(
                &mut spare,
                136,
                0x1F,
                &messages[..group.len()],
                &mut outs[..group.len()],
            );
        }
    }

    // H with SHAKE256 for the lanes that have a pair of nodes, a group of sponges side by side:
    // PK.seed, ADRS and 2n bytes fill less than one block. Not through keccak::one_block: a second
    // caller kept it out of line in shake_lanes, which cost about 2.5% of SLH-DSA-SHAKE key
    // generation on Haswell. The lanes without input keep their nodes.
    #[inline(never)]
    fn shake_pairs(
        &self,
        adrs: &[Adrs; LANES],
        inputs: [Option<[&[u8]; 2]>; LANES],
        nodes: &mut [Node; LANES],
    ) {
        let n = self.n;

        let mut sponges = Line(Sponges::empty());

        let mut active = [0; LANES];

        let mut count = 0;

        for (lane, input) in inputs.iter().enumerate() {
            if input.is_some() {
                active[count] = lane;

                count += 1;
            }
        }

        for group in active[..count].chunks(keccak::group()) {
            let parts: [[&[u8]; 4]; MAX_SPONGES] = core::array::from_fn(|i| {
                let lane = group.get(i).copied().unwrap_or_default();

                let [left, right] = inputs[lane].unwrap_or_default();

                [self.pk_seed, &adrs[lane], left, right]
            });

            let messages = parts.each_ref().map(|parts| &parts[..]);

            sponges.0.start(136, 0x1F, &messages[..group.len()]);

            sponges.0.squeeze([true; MAX_SPONGES]);

            for (i, &lane) in group.iter().enumerate() {
                sponges.0.read(i, &mut nodes[lane][..n]);
            }
        }
    }

    // One SHA-256 block after the PK.seed block, word-major for lane `lane`, into blocks whose
    // words after the input are zero: ADRSc, then the parts (n or 2n bytes in all, whole words and
    // at most 32 bytes, so that the padding fits), the padding and the length.
    fn pack<const L: usize>(
        blocks: &mut [[u32; L]; 16],
        lane: usize,
        adrs: &Adrs,
        parts: [&[u8]; 2],
    ) {
        let adrs_c = Self::compressed(adrs);

        for (t, bytes) in adrs_c.as_chunks::<4>().0.iter().enumerate() {
            blocks[t][lane] = u32::from_be_bytes(*bytes);
        }

        // ADRSc ends two bytes into word 5, so every input word straddles two block words.
        let mut carry = (u32::from(adrs_c[20]) << 24) | (u32::from(adrs_c[21]) << 16);

        let mut t = 5;

        for part in parts {
            for bytes in part.as_chunks::<4>().0 {
                let word = u32::from_be_bytes(*bytes);

                blocks[t][lane] = carry | (word >> 16);

                carry = word << 16;

                t += 1;
            }
        }

        blocks[t][lane] = carry | 0x8000;

        blocks[15][lane] = ((64 + 22 + parts[0].len() + parts[1].len()) * 8) as u32;
    }

    // F of up to LANES independent inputs, side by side, into nodes, which the caller owns and
    // wipes where they are secret. A lane without input gives nothing useful; with SHAKE it costs
    // nothing.
    fn f_lanes(
        &self,
        adrs: &[Adrs; LANES],
        inputs: [Option<&[u8]>; LANES],
        nodes: &mut [Node; LANES],
    ) {
        let Some(states) = &self.sha2 else {
            return self.shake_lanes(adrs, inputs, nodes);
        };

        let n = self.n;

        let mut blocks = [[0; LANES]; 16];

        for (lane, (adrs, input)) in adrs.iter().zip(inputs).enumerate() {
            Self::pack(
                &mut blocks,
                lane,
                adrs,
                [input.unwrap_or(&[0; 32][..n]), &[]],
            );
        }

        let mut digests = [[0; LANES]; 8];

        states.small.finish_words(&mut blocks, &mut digests);

        for (lane, node) in nodes.iter_mut().enumerate() {
            for (bytes, state) in node[..n].as_chunks_mut::<4>().0.iter_mut().zip(&digests) {
                *bytes = state[lane].to_be_bytes();
            }
        }

        wipe(blocks.as_flattened_mut());

        wipe(digests.as_flattened_mut());
    }

    // H of up to LANES pairs of nodes into nodes: side by side with SHAKE and with SHA-256 (n = 16,
    // one block), two at a time with SHA-512. The lanes without input keep their nodes.
    fn h_lanes(
        &self,
        adrs: &[Adrs; LANES],
        inputs: [Option<[&[u8]; 2]>; LANES],
        nodes: &mut [Node; LANES],
    ) {
        let Some(states) = &self.sha2 else {
            return self.shake_pairs(adrs, inputs, nodes);
        };

        if let Some(large) = &states.large {
            // Two at a time: one SHA-512 block each.
            let mut live = (0..LANES).filter(|&lane| inputs[lane].is_some());

            while let Some(first) = live.next() {
                let [left, right] = inputs[first].unwrap_or_default();

                let Some(second) = live.next() else {
                    nodes[first] = self.h(&adrs[first], left, right);

                    break;
                };

                let mut messages = [[0; 128]; 2];

                let length = Self::message(&mut messages[0], &adrs[first], &[left, right]);

                let [left, right] = inputs[second].unwrap_or_default();

                Self::message(&mut messages[1], &adrs[second], &[left, right]);

                let mut digests = [[0; 64]; 2];

                large.finish_pair(&mut messages, length, &mut digests);

                nodes[first] = self.truncate(&digests[0]);

                nodes[second] = self.truncate(&digests[1]);
            }

            return;
        }

        // ADRSc and 32 bytes of nodes: one block, as for F with an input of 2n bytes.
        let mut blocks = [[0; LANES]; 16];

        for (lane, (adrs, input)) in adrs.iter().zip(inputs).enumerate() {
            Self::pack(
                &mut blocks,
                lane,
                adrs,
                input.unwrap_or([&[0; 16], &[0; 16]]),
            );
        }

        let mut digests = [[0; LANES]; 8];

        states.small.finish_words(&mut blocks, &mut digests);

        for (lane, node) in nodes.iter_mut().enumerate() {
            if inputs[lane].is_some() {
                for (bytes, state) in node[..16].as_chunks_mut::<4>().0.iter_mut().zip(&digests) {
                    *bytes = state[lane].to_be_bytes();
                }
            }
        }
    }

    // H of two n-byte nodes: one block of SHA-256 or SHA-512 after the seed.
    fn h(&self, adrs: &Adrs, left: &[u8], right: &[u8]) -> Node {
        match &self.sha2 {
            None => self.shake(adrs, &[left, right]),
            Some(Sha2States {
                large: Some(large), ..
            }) => {
                let mut message = [0; 128];

                let length = Self::message(&mut message, adrs, &[left, right]);

                let mut digest = [0; 64];

                large.finish_message(&mut message, length, &mut digest);

                self.truncate(&digest)
            }
            Some(Sha2States { small, large: None }) => {
                // One block, packed in words for the kernel as in f_lanes.
                let mut blocks = [[0; 1]; 16];

                Self::pack(&mut blocks, 0, adrs, [left, right]);

                let mut digest = [[0; 1]; 8];

                small.finish_words(&mut blocks, &mut digest);

                let mut out = [0; 32];

                for (bytes, word) in out[..16].as_chunks_mut::<4>().0.iter_mut().zip(&digest) {
                    *bytes = word[0].to_be_bytes();
                }

                out
            }
        }
    }

    // T_l over the concatenated nodes.
    fn t(&self, adrs: &Adrs, data: &[u8]) -> Node {
        match &self.sha2 {
            None => self.shake(adrs, &[data]),
            Some(Sha2States {
                large: Some(large), ..
            }) => self.with_sha512(large, adrs, &[data]),
            Some(Sha2States { small, large: None }) => self.with_sha256(small, adrs, &[data]),
        }
    }
}

// A value on a 64-byte boundary, for the Keccak states of SLH-DSA-SHAKE on the stack: the sponges
// of shake_pairs and the one of Hashes::shake (FLanes is aligned the same way). Unaligned, their
// place on the stack, which the operating system shifts in every process, made verification take
// up to 1.4x longer in some processes on AVX-512VL CPUs.
#[repr(C, align(64))]
struct Line<T>(T);

// LANES F chains side by side, each lane with its own address and node, stepped together. The
// nodes stay in the word form of the hash from one step to the next and become bytes only where a
// value leaves a chain. With SHA-2 a step's input is the digest of the step before, shifted into
// place in the block, and only the hash address changes in the address words. With SHAKE only the
// lanes marked live are hashed: through keccak::one_block where the build has its kernel, else
// with each sponge written as whole lanes, PK.seed, ADRS and the node of the step before.
// The nodes are secret in key generation and signing: the owner keeps this in its own frame and
// the buffers that hold them are wiped when it is dropped. Aligned as Line is.
#[repr(align(64))]
struct FLanes<'c> {
    hashes: &'c Hashes<'c>,
    // SHA-2: ADRSc words 0 to 4 of each lane, the two ADRSc bytes in the high half of word 5, the
    // node words (the digests) and the block of the next step.
    words: [[u32; LANES]; 5],
    high: [u32; LANES],
    digests: [[u32; LANES]; 8],
    blocks: [[u32; LANES]; 16],
    // SHAKE: PK.seed as Keccak lanes, the address of each lane, the nodes in one of two buffers
    // (side: which one), and the sponges, made on first use and kept for every step: a new Sponges
    // for each call cost the zeroing and the wipe of all its states. With a one-block kernel a
    // step reads the nodes from one buffer and writes the next into the other, and there is no
    // room for sponges: unused, they made the frame of xmss_tree 16 KB instead of 9 KB and cost
    // about 1% of SLH-DSA-SHAKE key generation on Haswell when its chains ran in FLanes.
    seed: [u64; 4],
    adrs: [Adrs; LANES],
    nodes: [[Node; LANES]; 2],
    side: usize,
    sponges: [Option<Sponges>; !keccak::ONE_BLOCK as usize],
}

impl<'c> FLanes<'c> {
    fn new(hashes: &'c Hashes<'c>) -> Self {
        Self {
            hashes,
            words: [[0; LANES]; 5],
            high: [0; LANES],
            digests: [[0; LANES]; 8],
            blocks: [[0; LANES]; 16],
            seed: core::array::from_fn(|i| {
                hashes
                    .pk_seed
                    .as_chunks::<8>()
                    .0
                    .get(i)
                    .map_or(0, |b| u64::from_le_bytes(*b))
            }),
            adrs: [[0; 32]; LANES],
            nodes: [[[0; 32]; LANES]; 2],
            side: 0,
            sponges: [const { None }; !keccak::ONE_BLOCK as usize],
        }
    }

    fn set_adrs(&mut self, lane: usize, adrs: &Adrs) {
        if self.hashes.sha2.is_none() {
            self.adrs[lane] = *adrs;

            return;
        }

        let adrs_c = Hashes::compressed(adrs);

        for (words, bytes) in self.words.iter_mut().zip(adrs_c.as_chunks::<4>().0) {
            words[lane] = u32::from_be_bytes(*bytes);
        }

        self.high[lane] = (u32::from(adrs_c[20]) << 24) | (u32::from(adrs_c[21]) << 16);
    }

    // The hash address of every lane: its high half ends ADRSc word 4, its low half starts word 5.
    fn set_hash(&mut self, value: u32) {
        if self.hashes.sha2.is_none() {
            for lane in 0..LANES {
                self.set_lane_hash(lane, value);
            }

            return;
        }

        for word in &mut self.words[4] {
            *word = (*word & 0xFFFF_0000) | (value >> 16);
        }

        self.high = [value << 16; LANES];
    }

    fn set_lane_hash(&mut self, lane: usize, value: u32) {
        if self.hashes.sha2.is_none() {
            self.adrs[lane][28..].copy_from_slice(&value.to_be_bytes());

            return;
        }

        self.words[4][lane] = (self.words[4][lane] & 0xFFFF_0000) | (value >> 16);

        self.high[lane] = value << 16;
    }

    fn load(&mut self, lane: usize, input: &[u8]) {
        if self.hashes.sha2.is_none() {
            self.nodes[self.side][lane][..input.len()].copy_from_slice(input);

            return;
        }

        for (words, bytes) in self.digests.iter_mut().zip(input.as_chunks::<4>().0) {
            words[lane] = u32::from_be_bytes(*bytes);
        }
    }

    fn read(&self, lane: usize, out: &mut [u8]) {
        if self.hashes.sha2.is_none() {
            out.copy_from_slice(&self.nodes[self.side][lane][..out.len()]);

            return;
        }

        for (bytes, words) in out.as_chunks_mut::<4>().0.iter_mut().zip(&self.digests) {
            *bytes = words[lane].to_be_bytes();
        }
    }

    // F of every lane's node under its address, in place; with SHAKE, of the live lanes only. A
    // lane that is not live has no defined node after the step: the callers load it before use.
    fn step(&mut self, live: &[bool; LANES]) {
        let n = self.hashes.n;

        let Some(states) = &self.hashes.sha2 else {
            return self.step_shake(live);
        };

        let words = n / 4;

        self.blocks[..5].copy_from_slice(&self.words);

        // ADRSc ends two bytes into word 5, so every node word straddles two block words.
        let mut carry = self.high;

        for t in 0..words {
            for (lane, carry) in carry.iter_mut().enumerate() {
                let word = self.digests[t][lane];

                self.blocks[5 + t][lane] = *carry | (word >> 16);

                *carry = word << 16;
            }
        }

        for (block, carry) in self.blocks[5 + words].iter_mut().zip(&carry) {
            *block = carry | 0x8000;
        }

        // The low halves of the last node words: secret in key generation and signing.
        wipe_unless_optimized!(&mut carry);

        for block in &mut self.blocks[6 + words..15] {
            *block = [0; LANES];
        }

        self.blocks[15] = [((64 + 22 + n) * 8) as u32; LANES];

        states
            .small
            .finish_words(&mut self.blocks, &mut self.digests);
    }

    // PK.seed, ADRS and the node fill 2n + 32 bytes, whole lanes, which the suffix follows.
    #[inline(never)]
    fn step_shake(&mut self, live: &[bool; LANES]) {
        let Some(slot) = self.sponges.first_mut() else {
            return self.step_one_block(live);
        };

        let sponges = slot.get_or_insert_with(Sponges::empty);

        let n = self.hashes.n;

        let words = n / 8;

        let mut active = [0; LANES];

        let mut count = 0;

        for (lane, &live) in live.iter().enumerate() {
            if live {
                active[count] = lane;

                count += 1;
            }
        }

        for group in active[..count].chunks(keccak::group()) {
            sponges.start_lanes(136, group.len(), |i, state| {
                let lane = group[i];

                state[..words].copy_from_slice(&self.seed[..words]);

                let adrs = self.adrs[lane].as_chunks::<8>().0;

                for (word, bytes) in state[words..words + 4].iter_mut().zip(adrs) {
                    *word = u64::from_le_bytes(*bytes);
                }

                let node = self.nodes[self.side][lane][..n].as_chunks::<8>().0;

                for (word, bytes) in state[words + 4..].iter_mut().zip(node) {
                    *word = u64::from_le_bytes(*bytes);
                }

                state[2 * words + 4] = 0x1F;

                state[16] = 0x80 << 56;
            });

            sponges.squeeze([true; MAX_SPONGES]);

            for (i, &lane) in group.iter().enumerate() {
                let node = self.nodes[self.side][lane][..n].as_chunks_mut::<8>().0;

                for (bytes, word) in node.iter_mut().zip(sponges.lanes::<4>(i)) {
                    *bytes = word.to_le_bytes();
                }
            }
        }
    }

    // step_shake through Hashes::shake_lanes, which takes keccak::one_block: the nodes of the live
    // lanes go from one buffer into the other. Carrying the other lanes over and the call through
    // f_lanes cost about 1% of SLH-DSA-SHAKE key generation on Haswell when its chains ran here.
    #[inline(always)]
    fn step_one_block(&mut self, live: &[bool; LANES]) {
        let n = self.hashes.n;

        let [even, odd] = &mut self.nodes;

        let (from, to) = if self.side == 0 {
            (&*even, odd)
        } else {
            (&*odd, even)
        };

        let inputs = core::array::from_fn(|lane| live[lane].then(|| &from[lane][..n]));

        self.hashes.shake_lanes(&self.adrs, inputs, to);

        self.side ^= 1;
    }
}

impl Drop for FLanes<'_> {
    fn drop(&mut self) {
        wipe(self.digests.as_flattened_mut());

        wipe(self.blocks.as_flattened_mut());

        wipe(self.nodes.as_flattened_mut().as_flattened_mut());
    }
}

// Treehash: the leaves arrive from left to right and each completed pair is replaced at once by
// its parent, so at most one node per height waits on the stack. The siblings on the path of
// the target leaf are recorded as they appear, n bytes per height.
struct TreeHash<'s> {
    n: usize,
    stack: [(u32, Node); MAX_HEIGHT + 1],
    size: usize,
    target: Option<(u32, &'s mut [u8])>,
}

impl<'s> TreeHash<'s> {
    fn new(n: usize, target: Option<(u32, &'s mut [u8])>) -> Self {
        Self {
            n,
            stack: [(0, [0; 32]); MAX_HEIGHT + 1],
            size: 0,
            target,
        }
    }

    // combine(height, index, left, right) is the node at that height and index over its children.
    fn push(&mut self, index: u32, node: Node, combine: impl Fn(u32, u32, &Node, &Node) -> Node) {
        self.push_at(0, index, node, combine);
    }

    // push for a node at a height above the leaves, the root of a subtree built by the caller,
    // which has recorded the siblings below that height.
    fn push_at(
        &mut self,
        mut height: u32,
        mut index: u32,
        mut node: Node,
        combine: impl Fn(u32, u32, &Node, &Node) -> Node,
    ) {
        loop {
            if let Some((leaf, auth)) = &mut self.target
                && index == (*leaf >> height) ^ 1
            {
                auth[height as usize * self.n..][..self.n].copy_from_slice(&node[..self.n]);
            }

            match self.size.checked_sub(1) {
                Some(top) if self.stack[top].0 == height => {
                    self.size = top;

                    index >>= 1;

                    height += 1;

                    node = combine(height, index, &self.stack[top].1, &node);
                }
                _ => break,
            }
        }

        self.stack[self.size] = (height, node);

        self.size += 1;
    }

    // The sibling at a height below the subtrees given to push_at, on the target leaf's path.
    fn record(&mut self, height: u32, node: &Node) {
        if let Some((_, auth)) = &mut self.target {
            auth[height as usize * self.n..][..self.n].copy_from_slice(&node[..self.n]);
        }
    }

    fn root(&self) -> Node {
        self.stack[0].1
    }
}

struct Context<'a> {
    p: &'a Parameters,
    hashes: Hashes<'a>,
}

impl Context<'_> {
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

    // The WOTS+ public keys of the leaves first, first + 1, ... filling `leaves`, from the XMSS
    // tree at adrs. Every (leaf, chain) pair is a job, and LANES jobs run side by side; keys
    // receives the chain ends. A signer, (leaf offset, digits, signature), receives the chain
    // values at its digits.
    fn wots_leaves(
        &self,
        adrs: &Adrs,
        first: u32,
        leaves: &mut [Node],
        keys: &mut [u8],
        mut signer: Option<(usize, &[u32; MAX_LEN], &mut [u8])>,
    ) {
        if !(keccak::ONE_BLOCK && self.hashes.sha2.is_none()) {
            return self.wots_leaves_lanes(adrs, first, leaves, keys, signer);
        }

        let (n, len, count) = (self.p.n, self.p.len(), leaves.len());

        // The chain values, secret below the ends: each step reads one buffer and writes the
        // other, and both are wiped at the end.
        let mut buffers = [[[0; 32]; LANES]; 2];

        let [mut x, mut y] = buffers.each_mut();

        for start in (0..count * len).step_by(LANES) {
            let jobs: [Option<(usize, usize)>; LANES] = core::array::from_fn(|lane| {
                let job = start + lane;

                (job < count * len).then_some((job % count, job / count))
            });

            let address = |kind: u32| {
                jobs.map(|job| {
                    let mut lane_adrs = *adrs;

                    set_type(&mut lane_adrs, kind);

                    if let Some((leaf, chain)) = job {
                        set_key_pair(&mut lane_adrs, first + leaf as u32);

                        set_chain(&mut lane_adrs, chain as u32);
                    }

                    lane_adrs
                })
            };

            self.hashes.f_lanes(
                &address(WOTS_PRF),
                jobs.map(|job| job.map(|_| self.hashes.sk_seed)),
                x,
            );

            let mut chain_adrs = address(WOTS_HASH);

            for j in 0..W {
                if let Some((signer_leaf, digits, signature)) = &mut signer {
                    for (job, value) in jobs.iter().zip(x.iter()) {
                        if let Some((leaf, chain)) = *job
                            && leaf == *signer_leaf
                            && digits[chain] == j
                        {
                            signature[chain * n..(chain + 1) * n].copy_from_slice(&value[..n]);
                        }
                    }
                }

                if j == W - 1 {
                    break;
                }

                for lane_adrs in &mut chain_adrs {
                    set_hash(lane_adrs, j);
                }

                let inputs = core::array::from_fn(|lane| jobs[lane].map(|_| &x[lane][..n]));

                self.hashes.f_lanes(&chain_adrs, inputs, y);

                core::mem::swap(&mut x, &mut y);
            }

            for (job, value) in jobs.iter().zip(x.iter()) {
                if let Some((leaf, chain)) = *job {
                    keys[(leaf * len + chain) * n..][..n].copy_from_slice(&value[..n]);
                }
            }
        }

        wipe(buffers.as_flattened_mut().as_flattened_mut());

        for (leaf, node) in leaves.iter_mut().enumerate() {
            let mut pk_adrs = *adrs;

            set_type(&mut pk_adrs, WOTS_PK);

            set_key_pair(&mut pk_adrs, first + leaf as u32);

            *node = self
                .hashes
                .t(&pk_adrs, &keys[leaf * len * n..(leaf + 1) * len * n]);
        }
    }

    // wots_leaves with the chains in FLanes, for SHA-2 and for builds without a one-block kernel.
    // With SHAKE and the kernel, the loop above around f_lanes keeps the frame of xmss_tree small:
    // with FLanes in it, key generation took about 2% longer on every x86 class.
    #[inline(never)]
    fn wots_leaves_lanes(
        &self,
        adrs: &Adrs,
        first: u32,
        leaves: &mut [Node],
        keys: &mut [u8],
        mut signer: Option<(usize, &[u32; MAX_LEN], &mut [u8])>,
    ) {
        let (n, len, count) = (self.p.n, self.p.len(), leaves.len());

        // The chain values, secret below the ends, stay in the lanes from one step to the next.
        let mut lanes = FLanes::new(&self.hashes);

        for start in (0..count * len).step_by(LANES) {
            let jobs: [Option<(usize, usize)>; LANES] = core::array::from_fn(|lane| {
                let job = start + lane;

                (job < count * len).then_some((job % count, job / count))
            });

            let live = jobs.map(|job| job.is_some());

            let address = |lanes: &mut FLanes, kind: u32| {
                for (lane, job) in jobs.iter().enumerate() {
                    let mut lane_adrs = *adrs;

                    set_type(&mut lane_adrs, kind);

                    if let Some((leaf, chain)) = *job {
                        set_key_pair(&mut lane_adrs, first + leaf as u32);

                        set_chain(&mut lane_adrs, chain as u32);
                    }

                    lanes.set_adrs(lane, &lane_adrs);
                }
            };

            address(&mut lanes, WOTS_PRF);

            for lane in 0..LANES {
                lanes.load(lane, self.hashes.sk_seed);
            }

            lanes.step(&live);

            address(&mut lanes, WOTS_HASH);

            for j in 0..W {
                if let Some((signer_leaf, digits, signature)) = &mut signer {
                    for (lane, job) in jobs.iter().enumerate() {
                        if let Some((leaf, chain)) = *job
                            && leaf == *signer_leaf
                            && digits[chain] == j
                        {
                            lanes.read(lane, &mut signature[chain * n..(chain + 1) * n]);
                        }
                    }
                }

                if j == W - 1 {
                    break;
                }

                lanes.set_hash(j);

                lanes.step(&live);
            }

            for (lane, job) in jobs.iter().enumerate() {
                if let Some((leaf, chain)) = *job {
                    lanes.read(lane, &mut keys[(leaf * len + chain) * n..][..n]);
                }
            }
        }

        drop(lanes);

        for (leaf, node) in leaves.iter_mut().enumerate() {
            let mut pk_adrs = *adrs;

            set_type(&mut pk_adrs, WOTS_PK);

            set_key_pair(&mut pk_adrs, first + leaf as u32);

            *node = self
                .hashes
                .t(&pk_adrs, &keys[leaf * len * n..(leaf + 1) * len * n]);
        }
    }

    // The root of the XMSS tree at adrs (layer and tree set). A signer, (leaf, message,
    // signature), receives the WOTS+ signature of the message by that leaf and its
    // authentication path.
    fn xmss_tree(&self, adrs: &Adrs, signer: Option<(u32, &[u8], &mut [u8])>) -> Node {
        let (n, len) = (self.p.n, self.p.len());

        let group = (1 << self.p.hp).min(LANES);

        let mut leaves = [[0; 32]; LANES];

        let mut keys = vec![0; group * len * n];

        let (target, mut wots) = match signer {
            Some((leaf, message, signature)) => {
                let (wots, auth) = signature.split_at_mut(len * n);

                (
                    Some((leaf, auth)),
                    Some((leaf, self.wots_digits(message), wots)),
                )
            }
            None => (None, None),
        };

        let mut tree = TreeHash::new(n, target);

        for first in (0..1 << self.p.hp).step_by(group) {
            let signer = wots
                .as_mut()
                .filter(|(leaf, ..)| (first..first + group as u32).contains(leaf))
                .map(|(leaf, digits, wots)| ((*leaf - first) as usize, &*digits, &mut **wots));

            self.wots_leaves(adrs, first, &mut leaves[..group], &mut keys, signer);

            for (offset, leaf) in leaves[..group].iter().enumerate() {
                tree.push(
                    first + offset as u32,
                    *leaf,
                    |height, index, left, right| {
                        let mut node_adrs = *adrs;

                        set_type(&mut node_adrs, TREE);

                        set_chain(&mut node_adrs, height);

                        set_hash(&mut node_adrs, index);

                        self.hashes.h(&node_adrs, &left[..n], &right[..n])
                    },
                );
            }
        }

        tree.root()
    }

    // Advances chain i of the WOTS+ key at adrs from step starts[i] to the end, for every chain.
    // The chains have different lengths, so each lane takes the next chain as its own ends, the
    // longest first so that the last ones to finish are short. The lengths come from public
    // digests.
    fn chains(&self, adrs: &Adrs, starts: &[u32], values: &mut [Node]) {
        let n = self.p.n;

        let mut order: [usize; MAX_LEN] = core::array::from_fn(|i| i);

        let order = &mut order[..starts.len()];

        order.sort_unstable_by_key(|&i| starts[i]);

        let mut pending = order.iter().copied().filter(|&i| starts[i] < W - 1);

        let mut lanes: [Option<(usize, u32)>; LANES] = [None; LANES];

        // The values are public: they start from a signature.
        let mut chains = FLanes::new(&self.hashes);

        loop {
            for (lane, slot) in lanes.iter_mut().enumerate() {
                if slot.is_none()
                    && let Some(i) = pending.next()
                {
                    let mut chain_adrs = *adrs;

                    set_chain(&mut chain_adrs, i as u32);

                    set_hash(&mut chain_adrs, starts[i]);

                    chains.set_adrs(lane, &chain_adrs);

                    chains.load(lane, &values[i][..n]);

                    *slot = Some((i, starts[i]));
                }
            }

            if lanes.iter().all(Option::is_none) {
                return;
            }

            chains.step(&lanes.map(|lane| lane.is_some()));

            for (lane, slot) in lanes.iter_mut().enumerate() {
                if let Some((i, j)) = slot {
                    *j += 1;

                    if *j == W - 1 {
                        chains.read(lane, &mut values[*i][..n]);

                        *slot = None;
                    } else {
                        chains.set_lane_hash(lane, *j);
                    }
                }
            }
        }
    }

    fn wots_pk_from_sig(&self, signature: &[u8], message: &[u8], adrs: &Adrs) -> Node {
        let (n, len) = (self.p.n, self.p.len());

        let digits = self.wots_digits(message);

        let mut values = [[0; 32]; MAX_LEN];

        for (value, piece) in values.iter_mut().zip(signature.chunks_exact(n)) {
            value[..n].copy_from_slice(piece);
        }

        self.chains(adrs, &digits[..len], &mut values[..len]);

        let mut key = [0; MAX_LEN * 32];

        for (piece, value) in key.chunks_exact_mut(n).zip(&values[..len]) {
            piece.copy_from_slice(&value[..n]);
        }

        let mut pk_adrs = *adrs;

        set_type(&mut pk_adrs, WOTS_PK);

        set_key_pair(&mut pk_adrs, key_pair(adrs));

        self.hashes.t(&pk_adrs, &key[..len * n])
    }

    // Climbs from the leaf to the root along the authentication path (FIPS 205, Algorithm 11,
    // and the same loop in Algorithm 17).
    fn climb(&self, mut node: Node, index: u32, auth: &[u8], adrs: &mut Adrs) -> Node {
        let n = self.p.n;

        for (k, sibling) in auth.chunks_exact(n).enumerate() {
            set_chain(adrs, k as u32 + 1);

            if (index >> k) & 1 == 0 {
                set_hash(adrs, tree_index(adrs) / 2);

                node = self.hashes.h(adrs, &node[..n], sibling);
            } else {
                set_hash(adrs, (tree_index(adrs) - 1) / 2);

                node = self.hashes.h(adrs, sibling, &node[..n]);
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

    // Each layer signs the root of the layer below, the bottom one the FORS public key.
    fn ht_sign(&self, message: &[u8], mut tree: u64, mut leaf: u32, out: &mut [u8]) {
        let n = self.p.n;

        let mut root = [0; 32];

        root[..n].copy_from_slice(message);

        for (layer, part) in out.chunks_exact_mut(self.p.xmss_size()).enumerate() {
            let mut adrs = [0; 32];

            set_layer(&mut adrs, layer);

            set_tree(&mut adrs, tree);

            root = self.xmss_tree(&adrs, Some((leaf, &root[..n], part)));

            declassify(&root[..n]);

            leaf = (tree & self.leaf_mask()) as u32;

            tree >>= self.p.hp;
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

    fn fors_public_key(&self, adrs: &Adrs, roots: &[u8]) -> Node {
        let mut pk_adrs = *adrs;

        set_type(&mut pk_adrs, FORS_ROOTS);

        set_key_pair(&mut pk_adrs, key_pair(adrs));

        self.hashes.t(&pk_adrs, roots)
    }

    // Signs the digest with the FORS key at adrs (FORS_TREE type, key pair set) and returns the
    // FORS public key, revealing the secret value of each selected leaf and its authentication
    // path. Each tree is built in blocks of FORS_BLOCK leaves: the PRF and F of LANES leaves side
    // by side, then the levels of the block with H side by side (with SHA-256 while a level has
    // LANES nodes or more, as its lanes cost the same however many are live); the roots of the
    // blocks go on a treehash.
    fn fors_sign(&self, digest: &[u8], adrs: &Adrs, out: &mut [u8]) -> Node {
        let (n, a) = (self.p.n, self.p.a);

        let indices = self.fors_indices(digest);

        let mut roots = [0u8; MAX_K * 32];

        // The secret values stay in the lanes, which wipe them when dropped; the nodes above them
        // are public.
        let mut lanes = FLanes::new(&self.hashes);

        let mut level = [[0; 32]; FORS_BLOCK];

        let block = (1usize << a).min(FORS_BLOCK);

        let block_height = block.trailing_zeros();

        let trees = out
            .chunks_exact_mut((a + 1) * n)
            .zip(roots.chunks_exact_mut(n));

        for (i, (chunk, root)) in trees.enumerate() {
            let (secret, auth) = chunk.split_at_mut(n);

            let selected = indices[i] as usize;

            let base = (i << a) as u32;

            let node_adrs = |height: u32, index: usize| {
                let mut node_adrs = *adrs;

                set_chain(&mut node_adrs, height);

                set_hash(
                    &mut node_adrs,
                    ((i << (a - height as usize)) + index) as u32,
                );

                node_adrs
            };

            let mut tree = TreeHash::new(n, Some((selected as u32, auth)));

            for start in (0..1 << a).step_by(block) {
                for first in (start..start + block).step_by(LANES) {
                    for lane in 0..LANES {
                        let mut secret_adrs = *adrs;

                        set_type(&mut secret_adrs, FORS_PRF);

                        set_key_pair(&mut secret_adrs, key_pair(adrs));

                        set_hash(&mut secret_adrs, base + (first + lane) as u32);

                        lanes.set_adrs(lane, &secret_adrs);

                        lanes.load(lane, self.hashes.sk_seed);
                    }

                    lanes.step(&[true; LANES]);

                    if (first..first + LANES).contains(&selected) {
                        lanes.read(selected - first, secret);
                    }

                    for lane in 0..LANES {
                        lanes.set_adrs(lane, &node_adrs(0, first + lane));
                    }

                    lanes.step(&[true; LANES]);

                    for lane in 0..LANES {
                        lanes.read(lane, &mut level[first - start + lane][..n]);
                    }
                }

                let mut count = block;

                for height in 0..block_height {
                    if (start..start + block).contains(&selected) {
                        tree.record(height, &level[((selected - start) >> height) ^ 1]);
                    }

                    count /= 2;

                    let offset = start >> (height + 1);

                    // SHA-256 in lanes costs LANES hashes however many are live.
                    let small = matches!(self.hashes.sha2, Some(Sha2States { large: None, .. }));

                    if count < LANES && small {
                        for j in 0..count {
                            level[j] = self.hashes.h(
                                &node_adrs(height + 1, offset + j),
                                &level[2 * j][..n],
                                &level[2 * j + 1][..n],
                            );
                        }

                        continue;
                    }

                    for first in (0..count).step_by(LANES) {
                        let live = first..count.min(first + LANES);

                        let lane_adrs = core::array::from_fn(|lane| {
                            node_adrs(height + 1, offset + first + lane)
                        });

                        let inputs = core::array::from_fn(|lane| {
                            let j = first + lane;

                            live.contains(&j)
                                .then(|| [&level[2 * j][..n], &level[2 * j + 1][..n]])
                        });

                        let mut outputs = [[0; 32]; LANES];

                        self.hashes.h_lanes(&lane_adrs, inputs, &mut outputs);

                        level[live.clone()].copy_from_slice(&outputs[..live.len()]);
                    }
                }

                tree.push_at(
                    block_height,
                    (start >> block_height) as u32,
                    level[0],
                    |height, index, left, right| {
                        self.hashes
                            .h(&node_adrs(height, index as usize), &left[..n], &right[..n])
                    },
                );
            }

            root.copy_from_slice(&tree.root()[..n]);
        }

        drop(lanes);

        self.fors_public_key(adrs, &roots[..self.p.k * n])
    }

    fn fors_pk_from_sig(&self, signature: &[u8], digest: &[u8], adrs: &mut Adrs) -> Node {
        let (n, a, k) = (self.p.n, self.p.a, self.p.k);

        let indices = self.fors_indices(digest);

        let chunks: Vec<&[u8]> = signature.chunks_exact((a + 1) * n).collect();

        let mut leaves = [[0; 32]; MAX_K];

        for first in (0..k).step_by(LANES) {
            let lane_adrs = core::array::from_fn(|lane| {
                let mut leaf_adrs = *adrs;

                if let Some(&index) = indices[..k].get(first + lane) {
                    set_chain(&mut leaf_adrs, 0);

                    set_hash(&mut leaf_adrs, (((first + lane) << a) as u32) + index);
                }

                leaf_adrs
            });

            let inputs =
                core::array::from_fn(|lane| chunks.get(first + lane).map(|chunk| &chunk[..n]));

            let mut outputs = [[0; 32]; LANES];

            self.hashes.f_lanes(&lane_adrs, inputs, &mut outputs);

            for (leaf, output) in leaves[first..k].iter_mut().zip(&outputs) {
                *leaf = *output;
            }
        }

        // The k climbs run side by side, one H per tree at each height (FIPS 205, Algorithm 17):
        // the parent of the node at tree index t is at t / 2 one height up.
        for first in (0..k).step_by(LANES) {
            let trees = first..k.min(first + LANES);

            for height in 0..a {
                let lane_adrs = core::array::from_fn(|lane| {
                    let mut node_adrs = *adrs;

                    if trees.contains(&(first + lane)) {
                        let i = first + lane;

                        set_chain(&mut node_adrs, height as u32 + 1);

                        set_hash(
                            &mut node_adrs,
                            (((i << a) as u32) + indices[i]) >> (height + 1),
                        );
                    }

                    node_adrs
                });

                let inputs = core::array::from_fn(|lane| {
                    let i = first + lane;

                    trees.contains(&i).then(|| {
                        let sibling = &chunks[i][n * (height + 1)..][..n];

                        if (indices[i] >> height) & 1 == 0 {
                            [&leaves[i][..n], sibling]
                        } else {
                            [sibling, &leaves[i][..n]]
                        }
                    })
                });

                let mut outputs = [[0; 32]; LANES];

                self.hashes.h_lanes(&lane_adrs, inputs, &mut outputs);

                for (leaf, output) in leaves[trees.clone()].iter_mut().zip(&outputs) {
                    *leaf = *output;
                }
            }
        }

        let mut roots = [0u8; MAX_K * 32];

        for (root, leaf) in roots.chunks_exact_mut(n).zip(&leaves[..k]) {
            root.copy_from_slice(&leaf[..n]);
        }

        self.fors_public_key(adrs, &roots[..k * n])
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
        shake256_into(&parts, &mut digest);
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
        let mut engine = shake256();

        engine.update(sk_prf);

        engine.update(opt_rand);

        for part in message {
            engine.update(part);
        }

        engine.read(&mut out[..p.n]);
    } else {
        let mut hmac = if p.n == 16 {
            HMAC_SHA_256.create_unchecked(sk_prf)
        } else {
            HMAC_SHA_512.create_unchecked(sk_prf)
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

    context.xmss_tree(&adrs, None)
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

    let pk = [pk_seed, pk_root].concat();

    declassify(&sk[2 * p.n..]);

    declassify(&pk);

    (sk, pk)
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

    // R opens the signature; the digest, and the indices taken from it, follow from R, the public
    // key and the message.
    declassify(&r[..n]);

    let digest = h_msg(p, &r[..n], pk_seed, pk_root, message);

    declassify(&digest);

    let (md, tree, leaf) = split_digest(p, &digest);

    let mut signature = vec![0; p.signature_size()];

    let (r_part, rest) = signature.split_at_mut(n);

    r_part.copy_from_slice(&r[..n]);

    let (fors, ht) = rest.split_at_mut(p.fors_size());

    let mut adrs = [0; 32];

    set_tree(&mut adrs, tree);

    set_type(&mut adrs, FORS_TREE);

    set_key_pair(&mut adrs, leaf);

    let pk_fors = context.fors_sign(md, &adrs, fors);

    // The FORS public key and the root of every tree are what the next layer signs; the verifier
    // recomputes each of them from the signature.
    declassify(&pk_fors[..n]);

    context.ht_sign(&pk_fors[..n], tree, leaf, ht);

    declassify(&signature);

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

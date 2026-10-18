use alloc::vec::Vec;
use core::fmt;

use crate::cpu::Dit;
use crate::ct;
use crate::error::Error;
use crate::keys::{KeyFormat, export_public, import_public};
use crate::lms::{self, LmsType, OtsType};
use crate::mac::HMAC_SHA_256;
use crate::merkle::{CACHED_HEIGHT, MerkleTree};
use crate::primitives::sha256;
use crate::rng::random_bytes;
use crate::wipe::{SecretBytes, wipe};
use crate::xmss;

// SPEC 11.7: the state record, version 2.
const VERSION: u8 = 2;

const CHECKSUM_SIZE: usize = 16;

// Flags bit 0: the key derives its child trees and randomizers (SPEC 11.14) instead of drawing
// them from the entropy source.
const DETERMINISTIC: u8 = 1;

const CLAIMED: u8 = 0;

const SIGNED: u8 = 1;

const TREE_CACHE_VERSION: u8 = 1;

const TREE_CACHE_LABEL: &[u8] = b"crypto-pq tree cache v1";

const TAG_SIZE: usize = 32;

const MAX_LEVELS: usize = 8;

const MAX_HEIGHT: u32 = 60;

// Persistent storage for the signing state (SPEC 11.6). update(previous, next) is an atomic
// compare-and-swap: it replaces the stored record with next only when the stored one is byte for
// byte previous (None: the store is empty), and reports whether it did. It must make next durable,
// surviving a crash and a power loss, before it returns true. The record holds the private key,
// so the store must protect it like one, and must never restore it from a copy or a backup, clone
// it, or let two key objects or processes use it at once: an old record signs again with spent
// one-time keys. Compare-and-swap catches another writer on the same store, not a rollback of
// the storage itself.
pub trait StateStore {
    fn read(&mut self) -> Result<Option<Vec<u8>>, Error>;

    fn update(&mut self, previous: Option<&[u8]>, next: &[u8]) -> Result<bool, Error>;
}

impl<T: StateStore + ?Sized> StateStore for &mut T {
    fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
        (**self).read()
    }

    fn update(&mut self, previous: Option<&[u8]>, next: &[u8]) -> Result<bool, Error> {
        (**self).update(previous, next)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatefulParameters<'a> {
    Levels(&'a [(&'a str, &'a str)]),
    Name(&'a str),
}

// reserve: how many indices one write to the store claims, at least 1. A key that stops before
// using them loses the rest, because loading starts after them. It is not part of the stored
// state, so a generated key and a loaded one each take it as an option.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct StatefulKeyGenOptions {
    pub reserve: u64,
}

impl Default for StatefulKeyGenOptions {
    fn default() -> Self {
        Self { reserve: 1 }
    }
}

impl StatefulKeyGenOptions {
    #[must_use]
    pub const fn with_reserve(mut self, reserve: u64) -> Self {
        self.reserve = reserve;

        self
    }
}

// tree_cache: bytes from export_tree_cache, for load_private_key to take the trees they hold
// instead of building them; the key loads only if they pass every check. Empty means none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct StatefulLoadOptions<'a> {
    pub reserve: u64,
    pub tree_cache: &'a [u8],
}

impl Default for StatefulLoadOptions<'_> {
    fn default() -> Self {
        Self {
            reserve: 1,
            tree_cache: &[],
        }
    }
}

impl<'a> StatefulLoadOptions<'a> {
    #[must_use]
    pub const fn with_reserve(mut self, reserve: u64) -> Self {
        self.reserve = reserve;

        self
    }

    #[must_use]
    pub const fn with_tree_cache(mut self, tree_cache: &'a [u8]) -> Self {
        self.tree_cache = tree_cache;

        self
    }
}

pub(crate) fn check_reserve(reserve: u64) -> Result<u64, Error> {
    if reserve == 0 {
        return Err(Error::InvalidOption);
    }

    Ok(reserve)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Hss,
    Xmss,
    XmssMt,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatefulSignatureAlgorithm {
    name: &'static str,
    kind: Kind,
}

pub const HSS_LMS: StatefulSignatureAlgorithm = StatefulSignatureAlgorithm {
    name: "HSS/LMS",
    kind: Kind::Hss,
};

pub const XMSS: StatefulSignatureAlgorithm = StatefulSignatureAlgorithm {
    name: "XMSS",
    kind: Kind::Xmss,
};

pub const XMSS_MT: StatefulSignatureAlgorithm = StatefulSignatureAlgorithm {
    name: "XMSS^MT",
    kind: Kind::XmssMt,
};

// The levels of SPEC 11.3 are numbered from the top: HSS level l, or XMSS^MT layer d - 1 - l.
pub(crate) enum Parameters {
    Hss(Vec<(LmsType, OtsType)>),
    Xmss(&'static xmss::Parameters),
}

impl Parameters {
    fn levels(&self) -> usize {
        match self {
            Self::Hss(levels) => levels.len(),
            Self::Xmss(p) => p.d as usize,
        }
    }

    fn height(&self, level: usize) -> u32 {
        match self {
            Self::Hss(levels) => levels[level].0.h,
            Self::Xmss(p) => p.tree_height(),
        }
    }

    // H_l: the height of the levels from l down.
    fn below(&self, level: usize) -> u32 {
        (level..self.levels()).map(|l| self.height(l)).sum()
    }

    pub(crate) fn capacity(&self) -> u64 {
        1 << self.below(0)
    }

    // t_l(i), the tree that index signs with on a level; the top level has one tree.
    fn tree_number(&self, index: u64, level: usize) -> u64 {
        if level == 0 {
            0
        } else {
            index >> self.below(level)
        }
    }

    // q_l(i), the leaf of that tree.
    fn leaf(&self, index: u64, level: usize) -> u32 {
        ((index >> self.below(level + 1)) & ((1 << self.height(level)) - 1)) as u32
    }

    // The leaf of the level above that signs tree `tree` of a level.
    fn parent_leaf(&self, level: usize, tree: u64) -> u32 {
        (tree & ((1 << self.height(level - 1)) - 1)) as u32
    }

    // HSS: I || SEED of the top tree. XMSS: S_XMSS || SK_PRF || SEED.
    pub(crate) fn seed_size(&self) -> usize {
        match self {
            Self::Hss(levels) => 16 + levels[0].0.m,
            Self::Xmss(p) => 3 * p.n,
        }
    }

    fn public_key_size(&self) -> usize {
        match self {
            Self::Hss(levels) => 4 + levels[0].0.public_key_size(),
            Self::Xmss(p) => p.public_key_size(),
        }
    }

    fn node_size(&self) -> usize {
        match self {
            Self::Hss(levels) => levels[0].0.m,
            Self::Xmss(p) => p.n,
        }
    }

    // HSS: I || SEED of a child tree. XMSS^MT: its S_XMSS.
    fn child_secrets_size(&self) -> usize {
        match self {
            Self::Hss(levels) => 16 + levels[0].0.m,
            Self::Xmss(p) => p.n,
        }
    }

    // The signature of a child's public key by its parent at level - 1.
    fn parent_signature_size(&self, level: usize) -> usize {
        match self {
            Self::Hss(levels) => {
                let (lms, ots) = &levels[level - 1];

                lms.signature_size(ots)
            }
            Self::Xmss(p) => p.layer_signature_size(),
        }
    }

    fn record_size(&self, level: usize, signed: bool) -> usize {
        let parts =
            self.child_secrets_size() + self.node_size() + self.parent_signature_size(level);

        9 + if signed { parts } else { 0 }
    }

    // The parameters as the state record and a tree cache encode them: the HSS level count and the
    // type codes of every level, or the XMSS OID.
    fn section(&self) -> Vec<u8> {
        match self {
            Self::Hss(levels) => {
                let mut section = alloc::vec![levels.len() as u8];

                for (lms, ots) in levels {
                    section.extend_from_slice(&lms.code.to_be_bytes());

                    section.extend_from_slice(&ots.code.to_be_bytes());
                }

                section
            }
            Self::Xmss(p) => p.oid.to_be_bytes().to_vec(),
        }
    }

    // A level's position in a tree cache: the HSS level, or the XMSS layer.
    fn position(&self, level: usize) -> u8 {
        match self {
            Self::Hss(_) => level as u8,
            Self::Xmss(p) => (p.d as usize - 1 - level) as u8,
        }
    }

    fn level_at(&self, position: u8) -> Option<usize> {
        let position = usize::from(position);

        let levels = self.levels();

        (position < levels).then(|| match self {
            Self::Hss(_) => position,
            Self::Xmss(_) => levels - 1 - position,
        })
    }

    // PUB_SEED, which every XMSS tree of a key hashes with; HSS has none.
    fn pub_seed<'a>(&self, top: &'a [u8]) -> &'a [u8] {
        match self {
            Self::Hss(_) => &[],
            Self::Xmss(p) => &top[2 * p.n..],
        }
    }

    // PUB_SEED as the raw public key holds it.
    fn public_seed<'a>(&self, public_key: &'a [u8]) -> &'a [u8] {
        match self {
            Self::Hss(_) => &[],
            Self::Xmss(p) => &public_key[4 + p.n..],
        }
    }

    // The bytes of the raw public key that hold the top root.
    fn top_root<'a>(&self, public_key: &'a [u8]) -> &'a [u8] {
        match self {
            Self::Hss(levels) => &public_key[28..28 + levels[0].0.m],
            Self::Xmss(p) => &public_key[4..4 + p.n],
        }
    }

    // What verifies the signatures of a level's tree: its LMS public key, or its root.
    fn tree_key(&self, level: usize, public_key: &[u8], record: Option<&Record>) -> Vec<u8> {
        match (self, record) {
            (Self::Hss(_), None) => public_key[4..].to_vec(),
            (Self::Xmss(_), None) => self.top_root(public_key).to_vec(),
            (Self::Hss(levels), Some(record)) => {
                let (lms, ots) = &levels[level];

                let secrets = record.secrets.as_deref().unwrap_or_default();

                [
                    &lms.code.to_be_bytes()[..],
                    &ots.code.to_be_bytes(),
                    &secrets[..16],
                    &record.root,
                ]
                .concat()
            }
            (Self::Xmss(_), Some(record)) => record.root.clone(),
        }
    }

    // The tree `tree` of a level from its secrets, built from its leaves or from cached nodes.
    fn build(
        &self,
        pub_seed: &[u8],
        level: usize,
        tree: u64,
        secrets: &[u8],
        nodes: Option<&[u8]>,
    ) -> Result<Tree, Error> {
        Ok(match self {
            Self::Hss(levels) => {
                let (lms, ots) = levels[level];

                Tree::Lms(lms::Tree::new(lms, ots, secrets, nodes)?)
            }
            Self::Xmss(p) => {
                let layer = p.d - 1 - level as u32;

                Tree::Xmss(xmss::Tree::new(
                    p,
                    pub_seed,
                    &secrets[..p.n],
                    (layer, tree),
                    nodes,
                )?)
            }
        })
    }

    // Whether `signature` signs the key of tree `tree` of a level under its parent's key, by the
    // parent leaf of that tree: a stored signature by another leaf would make that leaf sign twice.
    fn verifies_child(
        &self,
        pub_seed: &[u8],
        (level, tree): (usize, u64),
        parent_key: &[u8],
        child_key: &[u8],
        signature: &[u8],
    ) -> bool {
        match self {
            Self::Hss(_) => {
                signature.get(..4) == Some(&self.parent_leaf(level, tree).to_be_bytes()[..])
                    && lms::verify(parent_key, child_key, signature)
            }
            Self::Xmss(p) => {
                let address = (
                    p.d - level as u32,
                    tree >> p.tree_height(),
                    self.parent_leaf(level, tree),
                );

                xmss::verify_root(p, pub_seed, address, child_key, signature, parent_key)
            }
        }
    }

    // Whether a public key has every byte that the top secrets give: all but the root. The secrets
    // are secret until the key loads, so the comparison is constant-time and only its result is
    // public.
    fn matches_secrets(&self, top: &[u8], public_key: &[u8]) -> bool {
        match self {
            Self::Hss(levels) => {
                let (lms, ots) = levels[0];

                let expected = [
                    &(levels.len() as u32).to_be_bytes()[..],
                    &lms.code.to_be_bytes(),
                    &ots.code.to_be_bytes(),
                    &top[..16],
                ]
                .concat();

                ct::declassify_value(ct::equal(&public_key[..expected.len()], &expected))
            }
            Self::Xmss(p) => {
                public_key[..4] == p.oid.to_be_bytes()
                    && ct::declassify_value(ct::equal(&public_key[4 + p.n..], &top[2 * p.n..]))
            }
        }
    }
}

// 1 to 8 levels with the same hash function and output size and at most 60 levels of height.
fn valid_levels(levels: &[(LmsType, OtsType)]) -> bool {
    let Some((top, _)) = levels.first() else {
        return false;
    };

    let same_family = levels
        .iter()
        .all(|(lms, ots)| ots.same_family(lms) && ots.same_family(top));

    let height: u32 = levels.iter().map(|(lms, _)| lms.h).sum();

    levels.len() <= MAX_LEVELS && same_family && height <= MAX_HEIGHT
}

// One tree that a key holds, with its secrets.
enum Tree {
    Lms(lms::Tree),
    Xmss(xmss::Tree),
}

impl Tree {
    const fn merkle(&self) -> &MerkleTree {
        match self {
            Self::Lms(tree) => tree.merkle(),
            Self::Xmss(tree) => tree.merkle(),
        }
    }

    fn root(&self) -> &[u8] {
        match self {
            Self::Lms(tree) => tree.root(),
            Self::Xmss(tree) => tree.root(),
        }
    }

    // What verifies the tree's signatures: its LMS public key, or its root.
    fn key(&self) -> &[u8] {
        match self {
            Self::Lms(tree) => tree.public_key(),
            Self::Xmss(tree) => tree.root(),
        }
    }

    // The one-time signature of message by a leaf with its path: LMS with the randomizer C, or
    // WOTS+ of an n-byte message.
    fn sign(&mut self, pub_seed: &[u8], leaf: u32, randomizer: &[u8], message: &[u8]) -> Vec<u8> {
        match self {
            Self::Lms(tree) => tree.sign(leaf, randomizer, message),
            Self::Xmss(tree) => tree.sign(pub_seed, leaf, message),
        }
    }
}

// The record of a level below the top (SPEC 11.7): the tree it uses and, once its parent has
// signed it, its secrets, its root and that signature. secrets is None while it is claimed.
struct Record {
    tree: u64,
    secrets: Option<SecretBytes>,
    root: Vec<u8>,
    signature: Vec<u8>,
}

// A signature goes with its record, wiped, so that the new child-root signatures of a call that
// fails leave no copy (SPEC 11.5.2 step 3.5).
impl Drop for Record {
    fn drop(&mut self) {
        wipe(&mut self.signature);
    }
}

impl Record {
    const fn claimed(tree: u64) -> Self {
        Self {
            tree,
            secrets: None,
            root: Vec::new(),
            signature: Vec::new(),
        }
    }
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_u64(bytes: &[u8]) -> u64 {
    let mut word = [0; 8];

    word.copy_from_slice(bytes);

    u64::from_be_bytes(word)
}

// Reads the big-endian fields of a state record or a tree cache from the front; a field past the
// end fails with `error`.
struct Reader<'a> {
    data: &'a [u8],
    error: Error,
}

impl<'a> Reader<'a> {
    fn take(&mut self, size: u64) -> Result<&'a [u8], Error> {
        let size = usize::try_from(size).map_err(|_| self.error)?;

        let (head, rest) = self.data.split_at_checked(size).ok_or(self.error)?;

        self.data = rest;

        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn number(&mut self, size: usize) -> Result<u64, Error> {
        let bytes = self.take(size as u64)?;

        Ok(bytes
            .iter()
            .fold(0, |value, &byte| (value << 8) | u64::from(byte)))
    }

    // How far into `data`, which the reader started from, it has read.
    const fn position(&self, data: &[u8]) -> usize {
        data.len() - self.data.len()
    }
}

// What a state record holds, checked as SPEC 11.9 items 2 and 3 require.
struct Decoded {
    parameters: Parameters,
    deterministic: bool,
    next: u64,
    top: SecretBytes,
    public_key: Vec<u8>,
    records: Vec<Record>,
}

impl StatefulSignatureAlgorithm {
    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub fn generate_key_pair<S: StateStore>(
        &self,
        parameters: StatefulParameters,
        store: S,
        options: &StatefulKeyGenOptions,
    ) -> Result<StatefulKeyPair<S>, Error> {
        let reserve = check_reserve(options.reserve)?;

        let parameters = self.parameters(parameters)?;

        let top = random_bytes(parameters.seed_size())?;

        self.create(parameters, top, false, 0, reserve, store)
    }

    // SPEC 11.9. The key resumes at the stored bound `next`, past every index that an earlier key
    // reserved, and past the subtree of every level that a crash left claimed but not signed.
    pub fn load_private_key<S: StateStore>(
        &self,
        mut store: S,
        options: &StatefulLoadOptions<'_>,
    ) -> Result<StatefulPrivateKey<S>, Error> {
        let _dit = Dit::new();

        let reserve = check_reserve(options.reserve)?;

        // A copy, so that the trees take the bytes that the tag covers even if the caller's buffer
        // changes meanwhile, as a mapped file may.
        let cache = (!options.tree_cache.is_empty()).then(|| options.tree_cache.to_vec());

        let state = store
            .read()
            .map_err(|_| Error::StatePersistFailed)?
            .ok_or(Error::InvalidPrivateKey)?;

        let state = SecretBytes::from_vec(state);

        let decoded = self.decode(&state)?;

        let levels = decoded.parameters.levels();

        let mut key = StatefulPrivateKey {
            algorithm: *self,
            parameters: decoded.parameters,
            deterministic: decoded.deterministic,
            top: decoded.top,
            public_key: decoded.public_key,
            records: decoded.records,
            trees: (0..levels).map(|_| None).collect(),
            store,
            state,
            index: decoded.next,
            next: decoded.next,
            reserve,
            erasure_pending: false,
        };

        key.index = key.resume()?;

        if key.index == key.parameters.capacity() {
            if key.next != key.index || key.holds_secrets() {
                key.erase();
            }

            key.wipe_secrets();

            return Ok(key);
        }

        let cached = cache
            .as_deref()
            .map(|data| key.open_tree_cache(data))
            .transpose()?
            .unwrap_or_default();

        key.restore_trees(&cached)?;

        Ok(key)
    }

    pub fn import_public_key(
        &self,
        data: &[u8],
        format: KeyFormat,
    ) -> Result<StatefulPublicKey, Error> {
        let key = import_public(format, data, Some(self.oid()))?;

        if !self.check_public_key(&key) {
            return Err(Error::InvalidPublicKey);
        }

        Ok(StatefulPublicKey {
            algorithm: *self,
            key,
        })
    }

    pub(crate) fn parameters(&self, parameters: StatefulParameters) -> Result<Parameters, Error> {
        match (self.kind, parameters) {
            (Kind::Hss, StatefulParameters::Levels(names)) => {
                let levels = names
                    .iter()
                    .map(|&(lms, ots)| Some((lms::lms_by_name(lms)?, lms::ots_by_name(ots)?)))
                    .collect::<Option<Vec<_>>>()
                    .filter(|levels| valid_levels(levels))
                    .ok_or(Error::InvalidOption)?;

                Ok(Parameters::Hss(levels))
            }
            (Kind::Xmss | Kind::XmssMt, StatefulParameters::Name(name)) => {
                let p = xmss::by_name(self.sets(), name).ok_or(Error::InvalidOption)?;

                Ok(Parameters::Xmss(p))
            }
            _ => Err(Error::InvalidOption),
        }
    }

    // SPEC 11.5.3: the top tree and, on every lower level, the tree that index uses, each signed by
    // its parent leaf and verified, then the first record, stored into an empty store. The key
    // starts at index, which is 0 except for the deterministic keys of hazmat [D-64]; an exhausted
    // one, at the capacity, has no tree in use and records trees 0.
    pub(crate) fn create<S: StateStore>(
        &self,
        parameters: Parameters,
        top: SecretBytes,
        deterministic: bool,
        index: u64,
        reserve: u64,
        store: S,
    ) -> Result<StatefulKeyPair<S>, Error> {
        let _dit = Dit::new();

        let levels = parameters.levels();

        let mut key = StatefulPrivateKey {
            algorithm: *self,
            parameters,
            deterministic,
            top,
            public_key: Vec::new(),
            records: Vec::new(),
            trees: (0..levels).map(|_| None).collect(),
            store,
            state: SecretBytes::from_vec(Vec::new()),
            index,
            next: index,
            reserve,
            erasure_pending: false,
        };

        let fresh = key.draw(1)?;

        let pub_seed = key.parameters.pub_seed(&key.top);

        // PUB_SEED is part of the public key.
        ct::declassify(pub_seed);

        let tree = key.parameters.build(pub_seed, 0, 0, &key.top, None)?;

        key.public_key = match &key.parameters {
            Parameters::Hss(_) => [&(levels as u32).to_be_bytes()[..], tree.key()].concat(),
            Parameters::Xmss(p) => [&p.oid.to_be_bytes()[..], tree.root(), pub_seed].concat(),
        };

        key.trees[0] = Some(tree);

        let exhausted = index == key.parameters.capacity();

        let grown = key.grow(if exhausted { 0 } else { index }, 1, fresh)?;

        key.install(1, grown);

        if exhausted {
            for tree in &mut key.trees[1..] {
                *tree = None;
            }
        }

        let record = key.encode(index, levels, &[], false);

        key.write(record)?;

        Ok(StatefulKeyPair {
            public_key: key.public_key(),
            private_key: key,
        })
    }

    const fn kind_byte(&self) -> u8 {
        match self.kind {
            Kind::Hss => 1,
            Kind::Xmss => 2,
            Kind::XmssMt => 3,
        }
    }

    const fn oid(&self) -> &'static [u8] {
        match self.kind {
            Kind::Hss => &[
                0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x11,
            ],
            Kind::Xmss => &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x22],
            Kind::XmssMt => &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x23],
        }
    }

    fn sets(&self) -> &'static [xmss::Parameters] {
        if self.kind == Kind::XmssMt {
            &xmss::XMSS_MT_SETS
        } else {
            &xmss::XMSS_SETS
        }
    }

    // SPEC 11.9 items 2 and 3, in order. Every failure is InvalidPrivateKey but a record of
    // another kind, which is AlgorithmMismatch.
    fn decode(&self, state: &[u8]) -> Result<Decoded, Error> {
        if state.len() < 2 + CHECKSUM_SIZE {
            return Err(Error::InvalidPrivateKey);
        }

        let (body, checksum) = state.split_at(state.len() - CHECKSUM_SIZE);

        // Whether a stored state is intact is public: loading fails on it.
        if !ct::declassify_value(ct::equal(&sha256(&[body])[..CHECKSUM_SIZE], checksum))
            || body[0] != VERSION
        {
            return Err(Error::InvalidPrivateKey);
        }

        if body[1] != self.kind_byte() {
            return Err(Error::AlgorithmMismatch);
        }

        let mut reader = Reader {
            data: &body[2..],
            error: Error::InvalidPrivateKey,
        };

        let parameters = match self.kind {
            Kind::Hss => {
                let count = reader.byte()?;

                let codes = reader.take(8 * u64::from(count))?;

                let levels = codes
                    .as_chunks::<8>()
                    .0
                    .iter()
                    .map(|chunk| {
                        let lms = lms::lms_by_code(read_u32(&chunk[..4]))?;

                        Some((lms, lms::ots_by_code(read_u32(&chunk[4..]))?))
                    })
                    .collect::<Option<Vec<_>>>()
                    .filter(|levels| valid_levels(levels))
                    .ok_or(Error::InvalidPrivateKey)?;

                Parameters::Hss(levels)
            }
            Kind::Xmss | Kind::XmssMt => {
                let oid = reader.number(4)? as u32;

                Parameters::Xmss(xmss::by_oid(self.sets(), oid).ok_or(Error::InvalidPrivateKey)?)
            }
        };

        let flags = reader.byte()?;

        let next = reader.number(8)?;

        let top = SecretBytes::concat(&[reader.take(parameters.seed_size() as u64)?]);

        ct::secret(&top);

        let public_key = reader.take(parameters.public_key_size() as u64)?.to_vec();

        let mut records = Vec::with_capacity(parameters.levels() - 1);

        for level in 1..parameters.levels() {
            let tree = reader.number(8)?;

            let record = match reader.byte()? {
                CLAIMED => Record::claimed(tree),
                SIGNED => {
                    let secrets =
                        SecretBytes::concat(
                            &[reader.take(parameters.child_secrets_size() as u64)?],
                        );

                    ct::secret(&secrets);

                    Record {
                        tree,
                        secrets: Some(secrets),
                        root: reader.take(parameters.node_size() as u64)?.to_vec(),
                        signature: reader
                            .take(parameters.parent_signature_size(level) as u64)?
                            .to_vec(),
                    }
                }
                _ => return Err(Error::InvalidPrivateKey),
            };

            records.push(record);
        }

        if !reader.data.is_empty() || flags & !DETERMINISTIC != 0 || next > parameters.capacity() {
            return Err(Error::InvalidPrivateKey);
        }

        if next != parameters.capacity() && !parameters.matches_secrets(&top, &public_key) {
            return Err(Error::InvalidPrivateKey);
        }

        // I of every HSS tree and PUB_SEED are parts of public keys.
        match &parameters {
            Parameters::Hss(_) => {
                ct::declassify(&top[..16]);

                for secrets in records.iter().filter_map(|record| record.secrets.as_ref()) {
                    ct::declassify(&secrets[..16]);
                }
            }
            Parameters::Xmss(_) => ct::declassify(parameters.pub_seed(&top)),
        }

        Ok(Decoded {
            parameters,
            deterministic: flags & DETERMINISTIC != 0,
            next,
            top,
            public_key,
            records,
        })
    }

    fn check_public_key(&self, key: &[u8]) -> bool {
        match self.kind {
            Kind::Hss => lms::check_public_key(key),
            Kind::Xmss | Kind::XmssMt => key
                .get(..4)
                .and_then(|oid| xmss::by_oid(self.sets(), read_u32(oid)))
                .is_some_and(|p| key.len() == p.public_key_size()),
        }
    }

    fn verifies(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        match self.kind {
            Kind::Hss => lms::hss_verify(public_key, message, signature),
            Kind::Xmss | Kind::XmssMt => public_key
                .get(..4)
                .and_then(|oid| xmss::by_oid(self.sets(), read_u32(oid)))
                .is_some_and(|p| xmss::verify(p, public_key, message, signature)),
        }
    }
}

impl fmt::Debug for StatefulSignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StatefulSignatureAlgorithm")
            .field(&self.name)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct StatefulPublicKey {
    algorithm: StatefulSignatureAlgorithm,
    key: Vec<u8>,
}

impl StatefulPublicKey {
    pub const fn algorithm(&self) -> StatefulSignatureAlgorithm {
        self.algorithm
    }

    pub fn verify(&self, signature: &[u8], message: &[u8]) -> bool {
        self.algorithm.verifies(&self.key, message, signature)
    }

    pub fn export_key(&self, format: KeyFormat) -> Result<Vec<u8>, Error> {
        export_public(format, Some(self.algorithm.oid()), &self.key)
    }
}

impl fmt::Debug for StatefulPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatefulPublicKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

// A key object bound to its store (SPEC 11). `index` is the next index to sign with, `next` the
// bound in the stored record: no index at or above it has been used, and the indices from index
// up to it are reserved. `records` holds the level records of levels 1 to L - 1 as last stored,
// and `trees[l]` the tree of level l while that level is current. Every secret is in a
// SecretBytes, which wipes itself when the key, a record or a tree is dropped.
//
// sign takes &mut self, so two calls on one key cannot overlap, and the key owns its store, so the
// store's update cannot reach the key that is signing: a store that holds the key through a
// RefCell finds it borrowed, and safe code has no other way back in (SPEC 11.13 item 2).
pub struct StatefulPrivateKey<S> {
    algorithm: StatefulSignatureAlgorithm,
    parameters: Parameters,
    deterministic: bool,
    top: SecretBytes,
    public_key: Vec<u8>,
    records: Vec<Record>,
    trees: Vec<Option<Tree>>,
    store: S,
    state: SecretBytes,
    index: u64,
    next: u64,
    reserve: u64,
    erasure_pending: bool,
}

impl<S> StatefulPrivateKey<S> {
    pub const fn algorithm(&self) -> StatefulSignatureAlgorithm {
        self.algorithm
    }

    pub fn public_key(&self) -> StatefulPublicKey {
        StatefulPublicKey {
            algorithm: self.algorithm,
            key: self.public_key.clone(),
        }
    }

    pub fn remaining_signatures(&self) -> u64 {
        self.parameters.capacity() - self.index
    }

    // SPEC 11.10: the public nodes of the tree of every level that is current for the next index,
    // top first, for StatefulLoadOptions::tree_cache to skip their build. sign takes &mut self, so
    // no export can overlap a signature: the StateConflict of the other languages cannot happen
    // here.
    //
    // A tree cache holds public nodes only, but the key trusts the root of a cached tree as the
    // root that its record holds, so the cache is authenticated with a key derived from the top
    // secrets and names every level's parameters. The body is the version, the kind, the
    // parameters as the state record encodes them, the public key and every tree, top first: its
    // level or layer, its number there, its lowest cached height, its height, the node size, its
    // node count and its nodes, height by height from the lowest, left to right. The tag,
    // HMAC-SHA-256 of the body, follows it.
    pub fn export_tree_cache(&self) -> Result<Vec<u8>, Error> {
        let _dit = Dit::new();

        if self.index == self.parameters.capacity() {
            return Err(Error::KeyExhausted);
        }

        let p = &self.parameters;

        let section = p.section();

        let trees: Vec<(usize, &MerkleTree)> = (0..p.levels())
            .take_while(|&level| self.current(level, self.index))
            .filter_map(|level| Some((level, self.trees[level].as_ref()?.merkle())))
            .collect();

        let n = p.node_size();

        let nodes: usize = trees
            .iter()
            .map(|(_, merkle)| 16 + n * merkle.node_count())
            .sum();

        let size = 2 + section.len() + 4 + self.public_key.len() + 1 + nodes + TAG_SIZE;

        let mut cache = Vec::with_capacity(size);

        cache.extend_from_slice(&[TREE_CACHE_VERSION, self.algorithm.kind_byte()]);

        cache.extend_from_slice(&section);

        cache.extend_from_slice(&(self.public_key.len() as u32).to_be_bytes());

        cache.extend_from_slice(&self.public_key);

        cache.push(trees.len() as u8);

        for (level, merkle) in trees {
            cache.push(p.position(level));

            cache.extend_from_slice(&p.tree_number(self.index, level).to_be_bytes());

            cache.extend_from_slice(&[merkle.low() as u8, merkle.height() as u8, n as u8]);

            cache.extend_from_slice(&(merkle.node_count() as u32).to_be_bytes());

            merkle.write_nodes(n, &mut cache);
        }

        cache.extend_from_slice(&self.tag(&cache)?);

        ct::declassify(&cache);

        Ok(cache)
    }

    // The tag of a tree cache body: HMAC-SHA-256 under HKDF-Extract (RFC 5869) of the top secrets
    // with the label as salt.
    fn tag(&self, body: &[u8]) -> Result<Vec<u8>, Error> {
        let key = SecretBytes::from_vec(HMAC_SHA_256.digest(TREE_CACHE_LABEL, &self.top)?);

        HMAC_SHA_256.digest(&key, body)
    }

    // SPEC 11.5.1: level l >= 1 is current for index when its record is signed for the tree that
    // index uses there and the level above is current.
    fn current(&self, level: usize, index: u64) -> bool {
        self.records[..level].iter().enumerate().all(|(i, record)| {
            record.secrets.is_some() && record.tree == self.parameters.tree_number(index, i + 1)
        })
    }

    // SPEC 11.9 item 4: the index that the stored record leaves, past the subtree of a level that
    // is claimed for the tree that the index would use.
    fn resume(&self) -> Result<u64, Error> {
        let p = &self.parameters;

        let capacity = p.capacity();

        let mut index = self.next;

        for level in 1..p.levels() {
            let record = &self.records[level - 1];

            let tree = p.tree_number(index, level);

            if record.tree > tree {
                return Err(Error::InvalidPrivateKey);
            }

            if record.tree < tree {
                continue;
            }

            if record.secrets.is_none() {
                index = ((tree + 1) << p.below(level)).min(capacity);
            } else if !self.current(level - 1, index) {
                return Err(Error::InvalidPrivateKey);
            }
        }

        Ok(index)
    }

    // Whether any secret field of the record is not zero.
    fn holds_secrets(&self) -> bool {
        let fields = core::iter::once(&self.top[..]).chain(
            self.records
                .iter()
                .filter_map(|record| record.secrets.as_deref()),
        );

        let mut zero = true;

        for field in fields {
            zero &= ct::declassify_value(ct::equal(field, &alloc::vec![0; field.len()]));
        }

        !zero
    }

    // SPEC 11.12: the secrets in memory are no longer needed once the key is exhausted.
    fn wipe_secrets(&mut self) {
        wipe(&mut self.top);

        for secrets in self
            .records
            .iter_mut()
            .filter_map(|record| record.secrets.as_mut())
        {
            wipe(secrets);
        }

        for tree in &mut self.trees {
            *tree = None;
        }
    }

    // The state record (SPEC 11.7) with the bound `next` and the records of the levels from
    // `first` replaced by `fresh`, or with every secret replaced by zeros when `erase` is set.
    fn encode(&self, next: u64, first: usize, fresh: &[&Record], erase: bool) -> SecretBytes {
        let p = &self.parameters;

        let records: Vec<(usize, &Record)> = (1..p.levels())
            .map(|level| {
                let record = if level >= first {
                    fresh[level - first]
                } else {
                    &self.records[level - 1]
                };

                (level, record)
            })
            .collect();

        let section = p.section();

        let size = 2
            + section.len()
            + 9
            + self.top.len()
            + self.public_key.len()
            + records
                .iter()
                .map(|(level, record)| p.record_size(*level, record.secrets.is_some()))
                .sum::<usize>()
            + CHECKSUM_SIZE;

        let mut state = SecretBytes::zeroed(size);

        let mut at = 0;

        let mut put = |bytes: &[u8], secret: bool| {
            if !(secret && erase) {
                state[at..at + bytes.len()].copy_from_slice(bytes);
            }

            at += bytes.len();
        };

        let flags = if self.deterministic { DETERMINISTIC } else { 0 };

        put(&[VERSION, self.algorithm.kind_byte()], false);

        put(&section, false);

        put(&[flags], false);

        put(&next.to_be_bytes(), false);

        put(&self.top, true);

        put(&self.public_key, false);

        for (_, record) in records {
            put(&record.tree.to_be_bytes(), false);

            match &record.secrets {
                None => put(&[CLAIMED], false),
                Some(secrets) => {
                    put(&[SIGNED], false);

                    put(secrets, true);

                    put(&record.root, false);

                    put(&record.signature, false);
                }
            }
        }

        let checksum = sha256(&[&state[..size - CHECKSUM_SIZE]]);

        state[size - CHECKSUM_SIZE..].copy_from_slice(&checksum[..CHECKSUM_SIZE]);

        state
    }

    // SPEC 11.10 items 3 and 4, in order: the structure, then the version, the kind, the parameters
    // and the public key, then the tag in constant time, then each tree's level and shape. Every
    // failure is InvalidEncoding except a cache of another algorithm, which is AlgorithmMismatch.
    // The trees with the number that the index uses at their level are returned with their level,
    // for restore_trees to check their roots; the others are stale and skipped.
    fn open_tree_cache<'a>(&self, data: &'a [u8]) -> Result<Vec<(usize, &'a [u8])>, Error> {
        let p = &self.parameters;

        let mut reader = Reader {
            data,
            error: Error::InvalidEncoding,
        };

        let version = reader.byte()?;

        let kind = reader.byte()?;

        // The parameters have the layout of the kind that the cache names: an HSS level count and a
        // pair of types per level, or an OID. A cache of no known kind cannot be read further.
        let start = reader.position(data);

        match kind {
            1 => {
                let count = reader.byte()?;

                reader.take(8 * u64::from(count))?;
            }
            2 | 3 => {
                reader.take(4)?;
            }
            _ => return Err(Error::InvalidEncoding),
        }

        let section = &data[start..reader.position(data)];

        let size = reader.number(4)?;

        let public_key = reader.take(size)?;

        let count = reader.byte()?;

        let first_tree = reader.position(data);

        for _ in 0..count {
            let header = reader.take(16)?;

            reader.take(u64::from(read_u32(&header[12..])) * u64::from(header[11]))?;
        }

        let body = &data[..reader.position(data)];

        let tag = reader.take(TAG_SIZE as u64)?;

        if !reader.data.is_empty() || version != TREE_CACHE_VERSION {
            return Err(Error::InvalidEncoding);
        }

        if kind != self.algorithm.kind_byte() {
            return Err(Error::AlgorithmMismatch);
        }

        // The stored public key passed the check of its fields against the top secrets, and the
        // cache's must equal it.
        if *section != p.section() || *public_key != self.public_key {
            return Err(Error::InvalidEncoding);
        }

        // Whether the cache is authentic is public: loading fails on it.
        if !ct::declassify_value(ct::equal(&self.tag(body)?, tag)) {
            return Err(Error::InvalidEncoding);
        }

        let mut trees = Reader {
            data: &body[first_tree..],
            error: Error::InvalidEncoding,
        };

        let mut previous = None;

        let mut needed = Vec::new();

        for _ in 0..count {
            let header = trees.take(16)?;

            let level = p.level_at(header[0]).ok_or(Error::InvalidEncoding)?;

            let tree = read_u64(&header[1..9]);

            if previous.is_some_and(|previous| level <= previous) {
                return Err(Error::InvalidEncoding);
            }

            previous = Some(level);

            let height = p.height(level);

            let low = height.saturating_sub(CACHED_HEIGHT);

            let shape = (u32::from(header[9]), u32::from(header[10]), header[11]);

            let nodes = read_u32(&header[12..]);

            if shape != (low, height, p.node_size() as u8) || nodes != (2 << (height - low)) - 1 {
                return Err(Error::InvalidEncoding);
            }

            let nodes = trees.take(u64::from(nodes) * p.node_size() as u64)?;

            // A tree that the index uses is checked against the root of its level's record, so a
            // level that is not current, whose record holds another tree or none, refuses it.
            if tree == p.tree_number(self.index, level) {
                if !self.current(level, self.index) {
                    return Err(Error::InvalidEncoding);
                }

                needed.push((level, nodes));
            }
        }

        Ok(needed)
    }

    // SPEC 11.9 item 6: the tree of every level that is current for the index, from cached nodes
    // where `cached` holds them, each with the root that the public key or its record gives, then
    // the verification of every current record's signature by its parent.
    fn restore_trees(&mut self, cached: &[(usize, &[u8])]) -> Result<(), Error> {
        let p = &self.parameters;

        let pub_seed = p.public_seed(&self.public_key);

        let current = (0..p.levels())
            .take_while(|&level| self.current(level, self.index))
            .count();

        for level in 0..current {
            let nodes = cached
                .iter()
                .find(|(cached, _)| *cached == level)
                .map(|(_, nodes)| *nodes);

            let (secrets, root) = match level {
                0 => (&self.top[..], p.top_root(&self.public_key)),
                _ => {
                    let record = &self.records[level - 1];

                    (
                        record.secrets.as_deref().unwrap_or_default(),
                        &record.root[..],
                    )
                }
            };

            let tree = p.build(
                pub_seed,
                level,
                p.tree_number(self.index, level),
                secrets,
                nodes,
            )?;

            if tree.root() != root {
                return Err(if nodes.is_some() {
                    Error::InvalidEncoding
                } else {
                    Error::InvalidPrivateKey
                });
            }

            self.trees[level] = Some(tree);
        }

        for level in 1..current {
            let parent = (level > 1).then(|| &self.records[level - 2]);

            let record = &self.records[level - 1];

            let parent_key = p.tree_key(level - 1, &self.public_key, parent);

            let child_key = p.tree_key(level, &self.public_key, Some(record));

            let address = (level, record.tree);

            if !p.verifies_child(
                pub_seed,
                address,
                &parent_key,
                &child_key,
                &record.signature,
            ) {
                return Err(Error::SelfTestFailed);
            }
        }

        Ok(())
    }

    // SPEC 11.4: the secrets of the child trees of the levels from `first` and the randomizers of
    // their signatures, from the entropy source; none in the deterministic mode, which derives them
    // as it builds.
    fn draw(&self, first: usize) -> Result<Vec<(SecretBytes, SecretBytes)>, Error> {
        let p = &self.parameters;

        if self.deterministic {
            return Ok(Vec::new());
        }

        (first..p.levels())
            .map(|_| {
                let secrets = random_bytes(p.child_secrets_size())?;

                let randomizer = match p {
                    Parameters::Hss(_) => random_bytes(p.node_size())?,
                    Parameters::Xmss(_) => SecretBytes::zeroed(0),
                };

                Ok((secrets, randomizer))
            })
            .collect()
    }

    // SPEC 11.5.2 step 3.3 and 11.5.3 step 3: for each level from `first` down, the tree that
    // index uses, built from its secrets, its key signed by the parent leaf, and that signature
    // verified under the parent's key. The trees of the levels above are held.
    fn grow(
        &mut self,
        index: u64,
        first: usize,
        fresh: Vec<(SecretBytes, SecretBytes)>,
    ) -> Result<Vec<(Tree, Record)>, Error> {
        let p = &self.parameters;

        let pub_seed = p.public_seed(&self.public_key);

        let mut fresh = fresh.into_iter();

        let mut grown: Vec<(Tree, Record)> = Vec::with_capacity(p.levels() - first);

        for level in first..p.levels() {
            let number = p.tree_number(index, level);

            let leaf = p.parent_leaf(level, number);

            let parent = match grown.last_mut() {
                Some((tree, _)) => tree,
                None => self.trees[level - 1]
                    .as_mut()
                    .expect("the parent level is current"),
            };

            let (secrets, randomizer) = match (fresh.next(), &*parent) {
                (Some(drawn), _) => drawn,
                (None, Tree::Lms(tree)) => {
                    let randomizer = tree.derived_randomizer(leaf);

                    (
                        tree.derived_child(leaf),
                        SecretBytes::concat(&[&randomizer[..p.node_size()]]),
                    )
                }
                (None, Tree::Xmss(_)) => (
                    SecretBytes::concat(&[&self.top[..p.node_size()]]),
                    SecretBytes::zeroed(0),
                ),
            };

            let tree = p.build(pub_seed, level, number, &secrets, None)?;

            let mut signature = parent.sign(pub_seed, leaf, &randomizer, tree.key());

            #[cfg(test)]
            tests::inject(tests::Fault::ChildRoot, &mut signature);

            let address = (level, number);

            // A faulty one-time signature can reveal one-time secrets (SPEC 11.5.2 step 3.5).
            if !p.verifies_child(pub_seed, address, parent.key(), tree.key(), &signature) {
                wipe(&mut signature);

                return Err(Error::SelfTestFailed);
            }

            let record = Record {
                tree: number,
                secrets: Some(secrets),
                root: tree.root().to_vec(),
                signature,
            };

            grown.push((tree, record));
        }

        Ok(grown)
    }

    // The trees and records of the levels from `first`, which the store now holds.
    fn install(&mut self, first: usize, grown: Vec<(Tree, Record)>) {
        for (level, (tree, record)) in (first..).zip(grown) {
            self.trees[level] = Some(tree);

            if level > self.records.len() {
                self.records.push(record);
            } else {
                self.records[level - 1] = record;
            }
        }
    }
}

impl<S: StateStore> StatefulPrivateKey<S> {
    // SPEC 11.5.2. Every index is made durable before its signature exists, and every child tree is
    // claimed before its parent leaf signs it, so a crash or a failed write can waste indices but
    // never use a one-time key twice.
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let _dit = Dit::new();

        let index = self.index;

        let capacity = self.parameters.capacity();

        if index == capacity {
            if self.erasure_pending {
                self.erase();
            }

            return Err(Error::KeyExhausted);
        }

        let levels = self.parameters.levels();

        let stale = (1..levels).find(|&level| !self.current(level, index));

        if let Some(first) = stale {
            self.transition(index, first)?;
        } else if index >= self.next {
            let next = index.saturating_add(self.reserve).min(capacity);

            let record = self.encode(next, levels, &[], false);

            self.write(record)?;

            self.next = next;
        }

        self.index = index + 1;

        let signature = self.sign_message(index, message).and_then(|mut signature| {
            // SPEC 11.5.2 step 7 [D-63]: a faulty one-time signature can reveal one-time secrets,
            // so the one that this call computed is never released unverified. The child-root
            // signatures that a transition computed were verified before the signed write, and
            // the stored ones are copied as they were verified.
            if self.verifies_message(index, message, &signature) {
                Ok(signature)
            } else {
                wipe(&mut signature);

                Err(Error::SelfTestFailed)
            }
        });

        // SPEC 11.12 item 2, also when the last index failed to sign: it is spent either way.
        if self.index == capacity {
            self.erase();

            self.wipe_secrets();
        }

        signature
    }

    // Stores `state` in place of the record that the key last read or stored, which the store is
    // empty of only while the key is being generated.
    fn write(&mut self, state: SecretBytes) -> Result<(), Error> {
        let previous = (!self.state.is_empty()).then_some(&self.state[..]);

        match self.store.update(previous, &state) {
            Err(_) => Err(Error::StatePersistFailed),
            Ok(false) => Err(Error::StateConflict),
            Ok(true) => {
                self.state = state;

                Ok(())
            }
        }
    }

    // SPEC 11.12 item 2: the final record, with next = N and every secret replaced by zeros. A
    // failure leaves it pending, for the next sign or load to retry.
    fn erase(&mut self) {
        let capacity = self.parameters.capacity();

        let record = self.encode(capacity, self.parameters.levels(), &[], true);

        self.erasure_pending = self.write(record).is_err();

        if !self.erasure_pending {
            self.next = capacity;
        }
    }

    // SPEC 11.5.2 step 3: the levels from `first` down move to the trees that index uses. The
    // claim write makes the use of each parent leaf durable before the leaf signs; then the trees
    // are built and signed, and the signed write stores them.
    fn transition(&mut self, index: u64, first: usize) -> Result<(), Error> {
        let p = &self.parameters;

        let (levels, capacity) = (p.levels(), p.capacity());

        let fresh = self.draw(first)?;

        let claims: Vec<Record> = (first..levels)
            .map(|level| Record::claimed(p.tree_number(index, level)))
            .collect();

        let next = self.next.max(index);

        let record = self.encode(next, first, &claims.iter().collect::<Vec<_>>(), false);

        self.write(record)?;

        self.next = next;

        for (record, claim) in self.records[first - 1..].iter_mut().zip(claims) {
            *record = claim;
        }

        for tree in &mut self.trees[first..] {
            *tree = None;
        }

        let grown = match self.grow(index, first, fresh) {
            Ok(grown) => grown,
            Err(error) => return Err(self.abandon(index, first, error)),
        };

        let next = if index >= self.next {
            index.saturating_add(self.reserve).min(capacity)
        } else {
            self.next
        };

        let signed: Vec<&Record> = grown.iter().map(|(_, record)| record).collect();

        let record = self.encode(next, first, &signed, false);

        if let Err(error) = self.write(record) {
            return Err(self.abandon(index, first, error));
        }

        self.next = next;

        self.install(first, grown);

        Ok(())
    }

    // SPEC 11.5.2 step 3.5: after a failure that follows a claim, the key moves past the subtree
    // of the topmost claimed level, as a load of the claim would, so that no parent leaf that the
    // claim covers signs another tree. The new trees and signatures were dropped, and wiped, by
    // the caller.
    fn abandon(&mut self, index: u64, first: usize, error: Error) -> Error {
        let p = &self.parameters;

        let capacity = p.capacity();

        self.index = ((p.tree_number(index, first) + 1) << p.below(first)).min(capacity);

        if self.index == capacity {
            self.erasure_pending = true;

            self.wipe_secrets();
        }

        error
    }

    // SPEC 11.5.2 step 6: the bottom level signs the message, after the signatures that the
    // records hold of every lower level's key.
    fn sign_message(&mut self, index: u64, message: &[u8]) -> Result<Vec<u8>, Error> {
        let p = &self.parameters;

        let levels = p.levels();

        let bottom = levels - 1;

        let leaf = p.leaf(index, bottom);

        let pub_seed = p.public_seed(&self.public_key);

        let mut signature = Vec::new();

        match p {
            Parameters::Hss(_) => {
                let tree = self.trees[bottom]
                    .as_mut()
                    .expect("the bottom level is current");

                let randomizer = match (&*tree, self.deterministic) {
                    (Tree::Lms(tree), true) => {
                        SecretBytes::concat(&[&tree.derived_randomizer(leaf)[..p.node_size()]])
                    }
                    _ => random_bytes(p.node_size())?,
                };

                signature.extend_from_slice(&(bottom as u32).to_be_bytes());

                for (level, record) in (1..).zip(&self.records) {
                    signature.extend_from_slice(&record.signature);

                    signature.extend_from_slice(&p.tree_key(level, &self.public_key, Some(record)));
                }

                let mut bottom = tree.sign(pub_seed, leaf, &randomizer, message);

                #[cfg(test)]
                tests::inject(tests::Fault::Message, &mut bottom);

                signature.extend_from_slice(&bottom);

                // Only the copy in the signature remains, which sign wipes if it does not verify.
                wipe(&mut bottom);
            }
            Parameters::Xmss(xp) => {
                let n = xp.n;

                let r = xmss::randomizer(xp, &self.top[n..2 * n], index);

                let digest =
                    xmss::message_digest(xp, &r[..n], p.top_root(&self.public_key), index, message);

                // The whole signature, so that no reallocation leaves a copy of the unverified
                // layer behind.
                signature
                    .reserve_exact(xp.index_size() + n + xp.d as usize * xp.layer_signature_size());

                signature.extend_from_slice(&index.to_be_bytes()[8 - xp.index_size()..]);

                signature.extend_from_slice(&r[..n]);

                let tree = self.trees[bottom]
                    .as_mut()
                    .expect("the bottom level is current");

                let mut bottom = tree.sign(pub_seed, leaf, &[], &digest[..n]);

                #[cfg(test)]
                tests::inject(tests::Fault::Message, &mut bottom);

                signature.extend_from_slice(&bottom);

                wipe(&mut bottom);

                for record in self.records.iter().rev() {
                    signature.extend_from_slice(&record.signature);
                }
            }
        }

        ct::declassify(&signature);

        Ok(signature)
    }

    // Whether the message signature at the end (HSS) or the start (XMSS) of `signature` is the
    // one-time signature of message by the leaf that index uses, under the bottom tree's key: the
    // LMS signature of RFC 8554 Algorithm 6a, or the bottom layer of RFC 8391 Algorithm 14 with
    // the digest computed again from the signature's r.
    fn verifies_message(&self, index: u64, message: &[u8], signature: &[u8]) -> bool {
        let p = &self.parameters;

        let bottom = p.levels() - 1;

        let leaf = p.leaf(index, bottom);

        let Some(tree) = self.trees[bottom].as_ref() else {
            return false;
        };

        match p {
            Parameters::Hss(levels) => {
                let (lms, ots) = &levels[bottom];

                let Some(part) = signature
                    .len()
                    .checked_sub(lms.signature_size(ots))
                    .map(|start| &signature[start..])
                else {
                    return false;
                };

                part[..4] == leaf.to_be_bytes() && lms::verify(tree.key(), message, part)
            }
            Parameters::Xmss(xp) => {
                let (n, size) = (xp.n, xp.index_size());

                let Some(layer) = signature.get(size + n..size + n + xp.layer_signature_size())
                else {
                    return false;
                };

                let r = &signature[size..size + n];

                let digest =
                    xmss::message_digest(xp, r, p.top_root(&self.public_key), index, message);

                let address = (0, p.tree_number(index, bottom), leaf);

                signature[..size] == index.to_be_bytes()[8 - size..]
                    && xmss::verify_root(
                        xp,
                        p.public_seed(&self.public_key),
                        address,
                        &digest[..n],
                        layer,
                        tree.root(),
                    )
            }
        }
    }
}

impl<S> fmt::Debug for StatefulPrivateKey<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatefulPrivateKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

pub struct StatefulKeyPair<S> {
    pub public_key: StatefulPublicKey,
    pub private_key: StatefulPrivateKey<S>,
}

impl<S> fmt::Debug for StatefulKeyPair<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatefulKeyPair")
            .field("public_key", &self.public_key)
            .field("private_key", &self.private_key)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use alloc::rc::Rc;
    use alloc::vec::Vec;
    use core::cell::{Cell, RefCell};
    use std::collections::HashSet;

    use super::{
        HSS_LMS, StateStore, StatefulKeyGenOptions, StatefulLoadOptions, StatefulParameters,
        StatefulPrivateKey, StatefulSignatureAlgorithm, XMSS, XMSS_MT,
    };
    use crate::error::Error;
    use crate::hazmat::generate_stateful_key_pair;
    use crate::merkle::{LEAVES_COMPUTED, ONE_TIME_SIGNATURES};

    // The faults that a test can inject into the next one-time signature of its kind: one byte of
    // it flipped after it is computed, before it is verified (SPEC 11.5.2 steps 3.3 and 7).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Fault {
        Message,
        ChildRoot,
    }

    std::thread_local! {
        static ARMED: Cell<Option<Fault>> = const { Cell::new(None) };
    }

    pub(super) fn inject(kind: Fault, signature: &mut [u8]) {
        if ARMED.with(|armed| armed.get()) == Some(kind) {
            ARMED.with(|armed| armed.set(None));

            signature[signature.len() / 2] ^= 1;
        }
    }

    // A store shared by every key object of a run, as a file is by processes. Its write number
    // `crash` fails as a crash on one side of the durable write would: lost, or stored and then
    // reported as failed. Every write before and after it succeeds. `fault` injects a fault into
    // the sign call of that number.
    #[derive(Clone, Default)]
    struct CrashingStore {
        state: Rc<RefCell<Option<Vec<u8>>>>,
        writes: Rc<Cell<usize>>,
        crash: usize,
        stored: bool,
        fault: Option<(usize, Fault)>,
    }

    impl StateStore for CrashingStore {
        fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
            Ok(self.state.borrow().clone())
        }

        fn update(&mut self, previous: Option<&[u8]>, next: &[u8]) -> Result<bool, Error> {
            let mut state = self.state.borrow_mut();

            if state.as_deref() != previous {
                return Ok(false);
            }

            self.writes.set(self.writes.get() + 1);

            if self.writes.get() == self.crash && !self.stored {
                return Err(Error::Unsupported);
            }

            *state = Some(next.to_vec());

            if self.writes.get() == self.crash {
                return Err(Error::Unsupported);
            }

            Ok(true)
        }
    }

    // How a run makes its key: the public generation with fresh randomness, or the deterministic
    // one of hazmat at a start index.
    #[derive(Clone, Copy)]
    enum Start {
        Random,
        Hazmat(u64),
    }

    // Generates a key, signs `count` messages and stops early when the key is exhausted. After a
    // failure the run either goes on with the same key object or drops it and loads the store, as
    // a restarted process would. Returns the released signatures and the writes the store saw.
    fn run(
        algorithm: StatefulSignatureAlgorithm,
        parameters: StatefulParameters,
        start: Start,
        count: usize,
        store: &CrashingStore,
        reload: bool,
    ) -> (Vec<Vec<u8>>, usize) {
        let generate = || match start {
            Start::Random => algorithm.generate_key_pair(
                parameters,
                store.clone(),
                &StatefulKeyGenOptions::default(),
            ),
            Start::Hazmat(index) => {
                let seed: Vec<u8> = (0..algorithm.parameters(parameters).unwrap().seed_size())
                    .map(|i| i as u8)
                    .collect();

                generate_stateful_key_pair(
                    algorithm,
                    &seed,
                    index,
                    parameters,
                    store.clone(),
                    &StatefulKeyGenOptions::default(),
                )
            }
        };

        let load = || algorithm.load_private_key(store.clone(), &StatefulLoadOptions::default());

        let mut key: StatefulPrivateKey<CrashingStore> = match generate() {
            Ok(pair) => pair.private_key,
            // The record was stored before the failure: the key exists, and a load resumes it.
            Err(_) if store.state.borrow().is_some() => load().unwrap(),
            // No key was stored and none was returned: what was signed is gone with its
            // secrets, and the deterministic seed makes the same key again.
            Err(_) => {
                ONE_TIME_SIGNATURES.with(|signatures| signatures.borrow_mut().clear());

                generate().unwrap().private_key
            }
        };

        let public_key = key.public_key();

        let mut released = Vec::new();

        let mut failures = 0;

        let mut calls = 0;

        while released.len() < count {
            let message = released.len().to_be_bytes();

            let fault = store
                .fault
                .filter(|&(call, _)| call == calls)
                .map(|(_, kind)| kind);

            ARMED.with(|armed| armed.set(fault));

            calls += 1;

            let result = key.sign(&message);

            // A fault that fired is refused as SELF_TEST_FAILED, and the index stays spent; a
            // child-root fault fires only in a call that moves to new trees.
            let fired = fault.is_some() && ARMED.with(|armed| armed.take()).is_none();

            assert_eq!(fired, result == Err(Error::SelfTestFailed), "{result:?}");

            if fired {
                if reload {
                    drop(key);

                    key = load().unwrap();
                }

                continue;
            }

            match result {
                Ok(signature) => {
                    assert!(public_key.verify(&signature, &message));

                    released.push(signature);
                }
                Err(Error::KeyExhausted) => break,
                Err(error) => {
                    assert!(
                        matches!(error, Error::StatePersistFailed | Error::StateConflict),
                        "{error:?}"
                    );

                    failures += 1;

                    assert!(failures < 4);

                    if reload || error == Error::StateConflict {
                        drop(key);

                        key = load().unwrap();
                    }
                }
            }
        }

        let exhausted = key.remaining_signatures() == 0;

        drop(key);

        // The store goes on where the key objects stopped. A key object that went on after a
        // write that was stored but reported as failed may have given up indices that the store
        // still holds, never the reverse.
        let mut last = load().unwrap();

        assert!(!(reload && exhausted) || last.remaining_signatures() == 0);

        for message in 0..4u64 {
            match last.sign(&message.to_be_bytes()) {
                Ok(signature) => {
                    assert!(public_key.verify(&signature, &message.to_be_bytes()));

                    released.push(signature);
                }
                Err(Error::KeyExhausted) => break,
                Err(_) => last = load().unwrap(),
            }
        }

        (released, store.writes.get())
    }

    // SPEC 11.5 and 11.9: across key generation, loads, signatures, a crash at every write point,
    // on either side of the durable write, and a fault in the new one-time signature of every
    // call, no one-time key signs twice. Every one-time signature that the library computes is
    // counted by its key, whether it was released, stored, refused or lost in the crash, and no
    // index is released twice.
    #[test]
    fn no_one_time_key_signs_twice() {
        let two = [
            ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"),
            ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W2"),
        ];

        let three = [("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W4"); 3];

        let mt = StatefulParameters::Name("XMSSMT-SHA2_20/4_192");

        let cases = [
            (HSS_LMS, StatefulParameters::Levels(&two), Start::Random, 34),
            (
                HSS_LMS,
                StatefulParameters::Levels(&two),
                Start::Hazmat(1000),
                40,
            ),
            (
                HSS_LMS,
                StatefulParameters::Levels(&three),
                Start::Hazmat(1022),
                6,
            ),
            (XMSS_MT, mt, Start::Random, 34),
            (XMSS_MT, mt, Start::Hazmat(32766), 6),
            (XMSS_MT, mt, Start::Hazmat((1 << 20) - 6), 10),
            (
                XMSS,
                StatefulParameters::Name("XMSS-SHA2_10_192"),
                Start::Hazmat(1015),
                10,
            ),
        ];

        // One thread per case, each with its own count of one-time signatures.
        std::thread::scope(|scope| {
            for (algorithm, parameters, start, count) in cases {
                scope.spawn(move || crash_everywhere(algorithm, parameters, start, count));
            }
        });
    }

    fn crash_everywhere(
        algorithm: StatefulSignatureAlgorithm,
        parameters: StatefulParameters,
        start: Start,
        count: usize,
    ) {
        let (_, writes) = run(
            algorithm,
            parameters,
            start,
            count,
            &CrashingStore::default(),
            true,
        );

        for crash in 1..=writes {
            for (stored, reload) in [(false, true), (true, true), (false, false), (true, false)] {
                ONE_TIME_SIGNATURES.with(|signatures| signatures.borrow_mut().clear());

                let store = CrashingStore {
                    crash,
                    stored,
                    ..CrashingStore::default()
                };

                let (released, _) = run(algorithm, parameters, start, count, &store, reload);

                let context = std::format!("{} {crash} {stored} {reload}", algorithm.name());

                let signed = ONE_TIME_SIGNATURES.with(|signatures| signatures.take());

                let keys: HashSet<&Vec<u8>> = signed.iter().collect();

                assert_eq!(keys.len(), signed.len(), "{context}");

                let distinct: HashSet<&Vec<u8>> = released.iter().collect();

                assert_eq!(distinct.len(), released.len(), "{context}");
            }
        }

        // A fault in the new one-time signature of every call, with and without a reload after
        // it: never released, and the one-time key that computed it signs nothing else.
        for call in 0..count {
            for kind in [Fault::Message, Fault::ChildRoot] {
                for reload in [true, false] {
                    ONE_TIME_SIGNATURES.with(|signatures| signatures.borrow_mut().clear());

                    let store = CrashingStore {
                        fault: Some((call, kind)),
                        ..CrashingStore::default()
                    };

                    let (released, _) = run(algorithm, parameters, start, count, &store, reload);

                    let context = std::format!("{} {call} {kind:?} {reload}", algorithm.name());

                    let signed = ONE_TIME_SIGNATURES.with(|signatures| signatures.take());

                    let keys: HashSet<&Vec<u8>> = signed.iter().collect();

                    assert_eq!(keys.len(), signed.len(), "{context}");

                    let distinct: HashSet<&Vec<u8>> = released.iter().collect();

                    assert_eq!(distinct.len(), released.len(), "{context}");
                }
            }
        }
    }

    // SPEC 11.5.2 steps 3.3, 3.5 and 7 [D-63]: a fault in the message signature fails the call
    // with SELF_TEST_FAILED and spends its index; a fault in the signature of a new child root
    // fails it too, after the claim, and the key moves past the claimed subtree as a load does.
    // The key signs on correctly after either.
    #[test]
    fn a_faulty_new_signature_is_never_released() {
        let two = [
            ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"),
            ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W2"),
        ];

        let mt = StatefulParameters::Name("XMSSMT-SHA2_20/4_192");

        let xmss = StatefulParameters::Name("XMSS-SHA2_10_192");

        for (algorithm, parameters, capacity, skip) in [
            (HSS_LMS, StatefulParameters::Levels(&two), 1 << 10, Some(64)),
            (XMSS_MT, mt, 1 << 20, Some(64)),
            (XMSS, xmss, 1 << 10, None),
        ] {
            ONE_TIME_SIGNATURES.with(|signatures| signatures.borrow_mut().clear());

            let seed: Vec<u8> = (0..algorithm.parameters(parameters).unwrap().seed_size())
                .map(|i| i as u8)
                .collect();

            let store = CrashingStore::default();

            let pair = generate_stateful_key_pair(
                algorithm,
                &seed,
                30,
                parameters,
                store.clone(),
                &StatefulKeyGenOptions::default(),
            )
            .unwrap();

            let (public_key, mut key) = (pair.public_key, pair.private_key);

            let sign = |key: &mut StatefulPrivateKey<CrashingStore>, fault| {
                ARMED.with(|armed| armed.set(fault));

                let result = key.sign(b"m");

                assert_eq!(ARMED.with(|armed| armed.take()), None);

                result.inspect(|signature| assert!(public_key.verify(signature, b"m")))
            };

            // Index 30.
            assert_eq!(
                sign(&mut key, Some(Fault::Message)).err(),
                Some(Error::SelfTestFailed)
            );

            assert_eq!(key.remaining_signatures(), capacity - 31);

            // Index 31, then 32 moves the lower levels to their next trees.
            sign(&mut key, None).unwrap();

            if let Some(skip) = skip {
                let result = sign(&mut key, Some(Fault::ChildRoot));

                assert_eq!(result.err(), Some(Error::SelfTestFailed));

                assert_eq!(key.remaining_signatures(), capacity - skip);

                let loaded = algorithm
                    .load_private_key(store.clone(), &StatefulLoadOptions::default())
                    .unwrap();

                assert_eq!(loaded.remaining_signatures(), capacity - skip);
            }

            sign(&mut key, None).unwrap();

            let signed = ONE_TIME_SIGNATURES.with(|signatures| signatures.take());

            let keys: HashSet<&Vec<u8>> = signed.iter().collect();

            assert_eq!(keys.len(), signed.len(), "{}", algorithm.name());
        }
    }

    // The leaves that this thread computed since the last call.
    fn computed() -> u64 {
        LEAVES_COMPUTED.with(|count| count.replace(0))
    }

    // A load with the cache computes no leaf; without it, the trees of every current level are
    // built. The signature after either computes none.
    #[test]
    fn a_tree_cache_skips_the_build() {
        let seed: Vec<u8> = (0..72).collect();

        let two = [
            ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"),
            ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W2"),
        ];

        let mt = StatefulParameters::Name("XMSSMT-SHA2_20/4_192");

        for (algorithm, parameters, size, index, trees) in [
            (HSS_LMS, StatefulParameters::Levels(&two), 40, 40, 2),
            (XMSS_MT, mt, 72, 0x12345, 4),
        ] {
            let store = CrashingStore::default();

            let mut pair = generate_stateful_key_pair(
                algorithm,
                &seed[..size],
                index,
                parameters,
                store.clone(),
                &StatefulKeyGenOptions::default(),
            )
            .unwrap();

            pair.private_key.sign(b"first").unwrap();

            let cache = pair.private_key.export_tree_cache().unwrap();

            drop(pair);

            let state = store.state.borrow().clone().unwrap();

            for (tree_cache, leaves) in [(&cache[..], 0), (&[][..], 32 * trees)] {
                let options = StatefulLoadOptions::default().with_tree_cache(tree_cache);

                computed();

                let store = CrashingStore::default();

                *store.state.borrow_mut() = Some(state.clone());

                let mut key = algorithm.load_private_key(store, &options).unwrap();

                assert_eq!(computed(), leaves);

                key.sign(b"m").unwrap();

                assert_eq!(computed(), 0);
            }
        }
    }
}

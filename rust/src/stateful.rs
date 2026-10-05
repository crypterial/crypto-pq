use alloc::vec::Vec;
use core::fmt;

use crate::cpu::Dit;
use crate::ct;
use crate::error::Error;
use crate::hash::HMAC_SHA_256;
use crate::keys::{KeyFormat, export_public, import_public};
use crate::lms::{self, Hss, LmsType, OtsType};
use crate::merkle::{CACHED_HEIGHT, CachedTree, HeldTree};
use crate::primitives::sha256;
use crate::rng::random_bytes;
use crate::wipe::SecretBytes;
use crate::xmss::{self, Xmss};

const VERSION: u8 = 1;

const CHECKSUM_SIZE: usize = 16;

const TREE_CACHE_VERSION: u8 = 1;

const TREE_CACHE_LABEL: &[u8] = b"crypto-pq tree cache v1";

const TAG_SIZE: usize = 32;

const MAX_LEVELS: usize = 8;

const MAX_HEIGHT: u32 = 60;

// Persistent storage for the signing state. update must replace the stored state only when it
// still equals previous (None: the store is empty) and report whether it did.
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
pub struct StatefulKeyGenOptions {
    pub reserve: u64,
}

impl Default for StatefulKeyGenOptions {
    fn default() -> Self {
        Self { reserve: 1 }
    }
}

// tree_cache: bytes from export_tree_cache, for load_private_key to take the trees they hold
// instead of building them; the key loads only if they pass every check. It borrows the caller's
// bytes, so that the options stay Copy and a cache is never moved or cloned to pass it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StatefulLoadOptions<'a> {
    pub reserve: u64,
    pub tree_cache: Option<&'a [u8]>,
}

impl Default for StatefulLoadOptions<'_> {
    fn default() -> Self {
        Self {
            reserve: 1,
            tree_cache: None,
        }
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

pub(crate) enum Parameters {
    Hss(Vec<(LmsType, OtsType)>),
    Xmss(&'static xmss::Parameters),
}

impl Parameters {
    // HSS seeds are I || SEED of the top tree; XMSS seeds are SK_SEED || SK_PRF || PUB_SEED.
    pub(crate) fn seed_size(&self) -> usize {
        match self {
            Self::Hss(levels) => 16 + levels[0].0.m,
            Self::Xmss(p) => 3 * p.n,
        }
    }

    pub(crate) fn capacity(&self) -> u64 {
        match self {
            Self::Hss(levels) => 1 << levels.iter().map(|(lms, _)| lms.h).sum::<u32>(),
            Self::Xmss(p) => p.capacity(),
        }
    }

    // The parameters as the state blob and a tree cache encode them: the HSS level count and the
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

    // Where the trees of a level or layer stand in a tree cache, top first, with their height and
    // node size.
    fn tree_shape(&self, level: u8) -> Option<(usize, u32, usize)> {
        let level = usize::from(level);

        match self {
            Self::Hss(levels) => levels.get(level).map(|(lms, _)| (level, lms.h, lms.m)),
            Self::Xmss(p) => {
                let layers = p.d as usize;

                (level < layers).then(|| (layers - 1 - level, p.tree_height(), p.n))
            }
        }
    }

    // The number of the tree that index signs with on a level or layer; the top one has one tree.
    fn tree_number(&self, index: u64, level: u8) -> u64 {
        match self {
            Self::Hss(_) if level == 0 => 0,
            Self::Hss(levels) => {
                index
                    >> levels[usize::from(level)..]
                        .iter()
                        .map(|(lms, _)| lms.h)
                        .sum::<u32>()
            }
            Self::Xmss(p) if u32::from(level) == p.d - 1 => 0,
            Self::Xmss(p) => index >> ((u32::from(level) + 1) * p.tree_height()),
        }
    }

    // Whether a public key has every byte that the seed gives: all but the root. The seed is
    // secret until the key loads, so the comparison is constant-time and only its result is public.
    fn matches_seed(&self, seed: &[u8], public_key: &[u8]) -> bool {
        match self {
            Self::Hss(levels) => {
                let (lms, ots) = levels[0];

                let expected = [
                    &(levels.len() as u32).to_be_bytes()[..],
                    &lms.code.to_be_bytes(),
                    &ots.code.to_be_bytes(),
                    &seed[..16],
                ]
                .concat();

                public_key.len() == expected.len() + lms.m
                    && ct::declassify_value(ct::equal(&public_key[..expected.len()], &expected))
            }
            Self::Xmss(p) => {
                public_key.len() == p.public_key_size()
                    && public_key[..4] == p.oid.to_be_bytes()
                    && ct::declassify_value(ct::equal(&public_key[4 + p.n..], &seed[2 * p.n..]))
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

enum Signer {
    Hss(Hss),
    Xmss(Xmss),
}

impl Signer {
    // `cached` holds the trees of an opened tree cache that the next index signs with.
    fn new(parameters: &Parameters, seed: &[u8], cached: &[CachedTree<'_>]) -> Result<Self, Error> {
        Ok(match parameters {
            Parameters::Hss(levels) => {
                Self::Hss(Hss::new(levels, &seed[..16], &seed[16..], cached)?)
            }
            Parameters::Xmss(p) => Self::Xmss(Xmss::new(p, seed, cached)?),
        })
    }

    fn cached_trees(&self) -> Vec<HeldTree<'_>> {
        match self {
            Self::Hss(hss) => hss.cached_trees(),
            Self::Xmss(xmss) => xmss.cached_trees(),
        }
    }

    fn public_key(&self) -> Vec<u8> {
        match self {
            Self::Hss(hss) => hss.public_key(),
            Self::Xmss(xmss) => xmss.public_key(),
        }
    }

    fn sign(&mut self, index: u64, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Hss(hss) => hss.sign(index, message),
            Self::Xmss(xmss) => xmss.sign(index, message),
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

// Reads the big-endian fields of a tree cache from the front.
struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, size: u64) -> Result<&'a [u8], Error> {
        let size = usize::try_from(size).map_err(|_| Error::InvalidEncoding)?;

        let (head, rest) = self
            .data
            .split_at_checked(size)
            .ok_or(Error::InvalidEncoding)?;

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

// What a tree cache gives the key that loads it: the public key that it names, and the trees that
// the next index signs with.
struct OpenedCache<'a> {
    public_key: &'a [u8],
    trees: Vec<CachedTree<'a>>,
}

// State blob: version, kind, the parameters, the secret seeds and the next index, closed by the
// first 16 bytes of its SHA-256 so that a damaged state is refused rather than reused.
fn seal(parts: &[&[u8]]) -> SecretBytes {
    let size: usize = parts.iter().map(|part| part.len()).sum();

    let mut state = Vec::with_capacity(size + CHECKSUM_SIZE);

    for part in parts {
        state.extend_from_slice(part);
    }

    let checksum = sha256(&[&state]);

    state.extend_from_slice(&checksum[..CHECKSUM_SIZE]);

    SecretBytes::from_vec(state)
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

        let seed = random_bytes(parameters.seed_size())?;

        self.create(parameters, seed, 0, reserve, store)
    }

    // The stored index is the first one not handed out, so signing resumes there even when the
    // last key reserved more than it used. A tree cache from export_tree_cache replaces the build
    // of the trees it holds; the state is checked first, and the key loads only if the cache
    // passes.
    pub fn load_private_key<S: StateStore>(
        &self,
        mut store: S,
        options: &StatefulLoadOptions<'_>,
    ) -> Result<StatefulPrivateKey<S>, Error> {
        let _dit = Dit::new();

        let reserve = check_reserve(options.reserve)?;

        // A copy, so that the trees take the bytes that the tag covers even if the caller's buffer
        // changes meanwhile, as a mapped file may.
        let cache = options.tree_cache.map(<[u8]>::to_vec);

        let state = store
            .read()
            .map_err(|_| Error::StatePersistFailed)?
            .ok_or(Error::InvalidPrivateKey)?;

        let state = SecretBytes::from_vec(state);

        let (parameters, seed, index) = self.decode(&state)?;

        if index > parameters.capacity() {
            return Err(Error::InvalidPrivateKey);
        }

        let opened = cache
            .as_deref()
            .map(|data| self.open_tree_cache(&parameters, &seed, index, data))
            .transpose()?;

        let restored = opened
            .as_ref()
            .map_or(&[][..], |opened| opened.trees.as_slice());

        let signer = Signer::new(&parameters, &seed, restored)?;

        if opened
            .as_ref()
            .is_some_and(|opened| signer.public_key() != opened.public_key)
        {
            return Err(Error::InvalidEncoding);
        }

        Ok(StatefulPrivateKey {
            algorithm: *self,
            parameters,
            seed,
            signer,
            store,
            state,
            index,
            reserved: index,
            reserve,
        })
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

    // The new key stores index itself; its first signature reserves the indices after it.
    pub(crate) fn create<S: StateStore>(
        &self,
        parameters: Parameters,
        seed: SecretBytes,
        index: u64,
        reserve: u64,
        mut store: S,
    ) -> Result<StatefulKeyPair<S>, Error> {
        let _dit = Dit::new();

        let signer = Signer::new(&parameters, &seed, &[])?;

        let state = self.encode(&parameters, &seed, index);

        match store.update(None, &state) {
            Err(_) => return Err(Error::StatePersistFailed),
            Ok(false) => return Err(Error::StateConflict),
            Ok(true) => {}
        }

        let private_key = StatefulPrivateKey {
            algorithm: *self,
            parameters,
            seed,
            signer,
            store,
            state,
            index,
            reserved: index,
            reserve,
        };

        Ok(StatefulKeyPair {
            public_key: private_key.public_key(),
            private_key,
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

    fn encode(&self, parameters: &Parameters, seed: &[u8], index: u64) -> SecretBytes {
        let header = [VERSION, self.kind_byte()];

        let section = parameters.section();

        let index = index.to_be_bytes();

        match parameters {
            Parameters::Hss(_) => seal(&[&header, &section, seed, &index]),
            Parameters::Xmss(_) => seal(&[&header, &section, &index, seed]),
        }
    }

    // Checks a tree cache in this order: the structure, then the version, the kind, the parameters
    // and the bytes of the public key that the seed gives, then the tag in constant time, then each
    // tree's level and shape. Every failure is InvalidEncoding except a cache of another algorithm,
    // which is AlgorithmMismatch. A tree that the index does not sign with is stale: it is skipped
    // and built again when needed. The others are returned for the signer to recompute their
    // parents; the caller then compares the signer's public key, and with it the top root, with
    // the cache's.
    fn open_tree_cache<'a>(
        &self,
        parameters: &Parameters,
        seed: &[u8],
        index: u64,
        data: &'a [u8],
    ) -> Result<OpenedCache<'a>, Error> {
        let mut reader = Reader { data };

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

        if kind != self.kind_byte() {
            return Err(Error::AlgorithmMismatch);
        }

        if *section != parameters.section() || !parameters.matches_seed(seed, public_key) {
            return Err(Error::InvalidEncoding);
        }

        let key = SecretBytes::from_vec(HMAC_SHA_256.digest(TREE_CACHE_LABEL, seed));

        // Whether the cache is authentic is public: loading fails on it.
        if !ct::declassify_value(ct::equal(&HMAC_SHA_256.digest(&key, body), tag)) {
            return Err(Error::InvalidEncoding);
        }

        let mut trees = Reader {
            data: &body[first_tree..],
        };

        let mut previous = None;

        let mut needed = Vec::new();

        for _ in 0..count {
            let header = trees.take(16)?;

            let (level, tree) = (header[0], read_u64(&header[1..9]));

            let (low, height, n) = (header[9], header[10], header[11]);

            let (position, expected_height, expected_n) =
                parameters.tree_shape(level).ok_or(Error::InvalidEncoding)?;

            if previous.is_some_and(|previous| position <= previous) {
                return Err(Error::InvalidEncoding);
            }

            previous = Some(position);

            let expected_low = expected_height.saturating_sub(CACHED_HEIGHT);

            let shape = (u32::from(low), u32::from(height), usize::from(n));

            let count = read_u32(&header[12..]);

            if shape != (expected_low, expected_height, expected_n)
                || count != (2 << (expected_height - expected_low)) - 1
            {
                return Err(Error::InvalidEncoding);
            }

            let nodes = trees.take(u64::from(count) * u64::from(n))?;

            if tree == parameters.tree_number(index, level) {
                needed.push(CachedTree { level, tree, nodes });
            }
        }

        Ok(OpenedCache {
            public_key,
            trees: needed,
        })
    }

    fn unseal<'a>(&self, state: &'a [u8]) -> Result<&'a [u8], Error> {
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

        Ok(&body[2..])
    }

    fn decode(&self, state: &[u8]) -> Result<(Parameters, SecretBytes, u64), Error> {
        let body = self.unseal(state)?;

        match self.kind {
            Kind::Hss => {
                let (&count, rest) = body.split_first().ok_or(Error::InvalidPrivateKey)?;

                let (codes, rest) = rest
                    .split_at_checked(8 * usize::from(count))
                    .ok_or(Error::InvalidPrivateKey)?;

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

                let parameters = Parameters::Hss(levels);

                let size = parameters.seed_size();

                if rest.len() != size + 8 {
                    return Err(Error::InvalidPrivateKey);
                }

                let seed = SecretBytes::concat(&[&rest[..size]]);

                Ok((parameters, seed, read_u64(&rest[size..])))
            }
            Kind::Xmss | Kind::XmssMt => {
                let p = body
                    .get(..4)
                    .and_then(|oid| xmss::by_oid(self.sets(), read_u32(oid)))
                    .ok_or(Error::InvalidPrivateKey)?;

                if body.len() != 12 + 3 * p.n {
                    return Err(Error::InvalidPrivateKey);
                }

                let seed = SecretBytes::concat(&[&body[12..]]);

                Ok((Parameters::Xmss(p), seed, read_u64(&body[4..12])))
            }
        }
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
        match self.algorithm.kind {
            Kind::Hss => lms::hss_verify(&self.key, message, signature),
            Kind::Xmss | Kind::XmssMt => xmss::by_oid(self.algorithm.sets(), read_u32(&self.key))
                .is_some_and(|p| xmss::verify(p, &self.key, message, signature)),
        }
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

// The seeds and the state are SecretBytes, which wipe themselves when the key is dropped, and so
// does each state the key replaces. `index` is the next index to sign with and `reserved` the one
// in the stored state, never below it: the indices in between are claimed and unused.
//
// sign takes &mut self, so two calls on one key cannot overlap, and the key owns its store, so the
// store's update cannot reach the key that is signing: a store that holds the key through a
// RefCell finds it borrowed, and safe code has no other way back in.
pub struct StatefulPrivateKey<S> {
    algorithm: StatefulSignatureAlgorithm,
    parameters: Parameters,
    seed: SecretBytes,
    signer: Signer,
    store: S,
    state: SecretBytes,
    index: u64,
    reserved: u64,
    reserve: u64,
}

impl<S> StatefulPrivateKey<S> {
    pub const fn algorithm(&self) -> StatefulSignatureAlgorithm {
        self.algorithm
    }

    pub fn public_key(&self) -> StatefulPublicKey {
        StatefulPublicKey {
            algorithm: self.algorithm,
            key: self.signer.public_key(),
        }
    }

    pub fn remaining_signatures(&self) -> u64 {
        self.parameters.capacity() - self.index
    }

    // The trees that the key holds, for StatefulLoadOptions::tree_cache to skip their build. sign
    // takes &mut self, so no export can overlap a signature: the StateConflict of the other
    // languages cannot happen here.
    //
    // A tree cache holds public nodes only, but the signer trusts the root of a cached lower tree
    // as the child key that its parent signs, and the public key covers only the top root and the
    // top level's types, so the cache is authenticated with a key derived from the seed and names
    // every level's parameters. The body is the version, the kind, the parameters as the state
    // blob encodes them, the public key and every cached tree, top first: its level or layer, its
    // number on that level, its lowest cached height, its height, n, its node count and its nodes,
    // level by level from the lowest, left to right. The tag, HMAC-SHA-256 of the body, follows it.
    pub fn export_tree_cache(&self) -> Result<Vec<u8>, Error> {
        let _dit = Dit::new();

        let section = self.parameters.section();

        let public_key = self.signer.public_key();

        let trees = self.signer.cached_trees();

        let nodes: usize = trees
            .iter()
            .map(|tree| 16 + tree.n * tree.merkle.node_count())
            .sum();

        let size = 2 + section.len() + 4 + public_key.len() + 1 + nodes + TAG_SIZE;

        let mut cache = Vec::with_capacity(size);

        cache.extend_from_slice(&[TREE_CACHE_VERSION, self.algorithm.kind_byte()]);

        cache.extend_from_slice(&section);

        cache.extend_from_slice(&(public_key.len() as u32).to_be_bytes());

        cache.extend_from_slice(&public_key);

        cache.push(trees.len() as u8);

        for tree in &trees {
            let merkle = tree.merkle;

            cache.push(tree.level);

            cache.extend_from_slice(&tree.tree.to_be_bytes());

            cache.extend_from_slice(&[merkle.low() as u8, merkle.height() as u8, tree.n as u8]);

            cache.extend_from_slice(&(merkle.node_count() as u32).to_be_bytes());

            merkle.write_nodes(tree.n, &mut cache);
        }

        // The key of the tag is HKDF-Extract (RFC 5869) of the seed with the label as salt.
        let key = SecretBytes::from_vec(HMAC_SHA_256.digest(TREE_CACHE_LABEL, &self.seed));

        let tag = HMAC_SHA_256.digest(&key, &cache);

        cache.extend_from_slice(&tag);

        ct::declassify(&cache);

        Ok(cache)
    }
}

impl<S: StateStore> StatefulPrivateKey<S> {
    // Indices are claimed in the store before any signature uses them, `reserve` at a time, so a
    // crash or a failed write can waste indices but never use one twice.
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let _dit = Dit::new();

        let index = self.index;

        let capacity = self.parameters.capacity();

        if index >= capacity {
            return Err(Error::KeyExhausted);
        }

        if index == self.reserved {
            let reserved = index.saturating_add(self.reserve).min(capacity);

            let next = self
                .algorithm
                .encode(&self.parameters, &self.seed, reserved);

            match self.store.update(Some(&self.state), &next) {
                Err(_) => return Err(Error::StatePersistFailed),
                Ok(false) => return Err(Error::StateConflict),
                Ok(true) => {}
            }

            self.state = next;

            self.reserved = reserved;
        }

        self.index = index + 1;

        Ok(self.signer.sign(index, message))
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
    use alloc::vec::Vec;

    use super::{
        HSS_LMS, StateStore, StatefulKeyGenOptions, StatefulLoadOptions, StatefulParameters,
        XMSS_MT,
    };
    use crate::error::Error;
    use crate::hazmat::generate_stateful_key_pair;
    use crate::merkle::LEAVES_COMPUTED;

    #[derive(Default)]
    struct MemoryStore(Option<Vec<u8>>);

    impl StateStore for MemoryStore {
        fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
            Ok(self.0.clone())
        }

        fn update(&mut self, previous: Option<&[u8]>, next: &[u8]) -> Result<bool, Error> {
            if self.0.as_deref() != previous {
                return Ok(false);
            }

            self.0 = Some(next.to_vec());

            Ok(true)
        }
    }

    // The leaves that this thread computed since the last call.
    fn computed() -> u64 {
        LEAVES_COMPUTED.with(|count| count.replace(0))
    }

    // A load with the cache computes no leaf; the trees that the next index has left are built.
    #[test]
    fn a_tree_cache_skips_the_build() {
        let seed: Vec<u8> = (0..72).collect();

        let two = [
            ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4"),
            ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W2"),
        ];

        let mt = StatefulParameters::Name("XMSSMT-SHA2_20/4_192");

        for (algorithm, parameters, size, index, later, trees) in [
            (HSS_LMS, StatefulParameters::Levels(&two), 40, 40, 64, 2),
            (XMSS_MT, mt, 72, 0x12345, 0x12360, 4),
        ] {
            let options = StatefulKeyGenOptions::default();

            let seed = &seed[..size];

            let mut pair = generate_stateful_key_pair(
                algorithm,
                parameters,
                seed,
                index,
                MemoryStore::default(),
                &options,
            )
            .unwrap();

            pair.private_key.sign(b"first").unwrap();

            let cache = pair.private_key.export_tree_cache().unwrap();

            let state = pair.private_key.store.0.clone().unwrap();

            let stale = algorithm.encode(&algorithm.parameters(parameters).unwrap(), seed, later);

            for (state, tree_cache, leaves) in [
                (&state[..], Some(&cache[..]), 0),
                (&state[..], None, 32 * trees),
                (&stale[..], Some(&cache[..]), 32),
            ] {
                let options = StatefulLoadOptions {
                    reserve: 1,
                    tree_cache,
                };

                computed();

                let mut key = algorithm
                    .load_private_key(MemoryStore(Some(state.to_vec())), &options)
                    .unwrap();

                key.sign(b"m").unwrap();

                assert_eq!(computed(), leaves);
            }
        }
    }
}

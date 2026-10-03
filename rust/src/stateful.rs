use alloc::vec::Vec;
use core::fmt;

use crate::ct;
use crate::error::Error;
use crate::keys::{KeyFormat, export_public, import_public};
use crate::lms::{self, Hss, LmsType, OtsType};
use crate::primitives::sha256;
use crate::rng::random_bytes;
use crate::wipe::SecretBytes;
use crate::xmss::{self, Xmss};

const VERSION: u8 = 1;

const CHECKSUM_SIZE: usize = 16;

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
    fn new(parameters: &Parameters, seed: &[u8]) -> Self {
        match parameters {
            Parameters::Hss(levels) => Self::Hss(Hss::new(levels, &seed[..16], &seed[16..])),
            Parameters::Xmss(p) => Self::Xmss(Xmss::new(p, seed)),
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
    ) -> Result<StatefulKeyPair<S>, Error> {
        let parameters = self.parameters(parameters)?;

        let seed = random_bytes(parameters.seed_size())?;

        self.create(parameters, seed, 0, store)
    }

    pub fn load_private_key<S: StateStore>(
        &self,
        mut store: S,
    ) -> Result<StatefulPrivateKey<S>, Error> {
        let state = store
            .read()
            .map_err(|_| Error::StatePersistFailed)?
            .ok_or(Error::InvalidPrivateKey)?;

        let state = SecretBytes::from_vec(state);

        let (parameters, seed, index) = self.decode(&state)?;

        if index > parameters.capacity() {
            return Err(Error::InvalidPrivateKey);
        }

        let signer = Signer::new(&parameters, &seed);

        Ok(StatefulPrivateKey {
            algorithm: *self,
            parameters,
            seed,
            signer,
            store,
            state,
            index,
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

    pub(crate) fn create<S: StateStore>(
        &self,
        parameters: Parameters,
        seed: SecretBytes,
        index: u64,
        mut store: S,
    ) -> Result<StatefulKeyPair<S>, Error> {
        let signer = Signer::new(&parameters, &seed);

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

        let index = index.to_be_bytes();

        match parameters {
            Parameters::Hss(levels) => {
                let codes: Vec<u8> = levels
                    .iter()
                    .flat_map(|(lms, ots)| [lms.code.to_be_bytes(), ots.code.to_be_bytes()])
                    .flatten()
                    .collect();

                seal(&[&header, &[levels.len() as u8], &codes, seed, &index])
            }
            Parameters::Xmss(p) => seal(&[&header, &p.oid.to_be_bytes(), &index, seed]),
        }
    }

    fn unseal<'a>(&self, state: &'a [u8]) -> Result<&'a [u8], Error> {
        if state.len() < 2 + CHECKSUM_SIZE {
            return Err(Error::InvalidPrivateKey);
        }

        let (body, checksum) = state.split_at(state.len() - CHECKSUM_SIZE);

        if !ct::equal(&sha256(&[body])[..CHECKSUM_SIZE], checksum) || body[0] != VERSION {
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
                    .chunks_exact(8)
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

// The seeds and the state are SecretBytes, which wipe themselves when the key is dropped.
pub struct StatefulPrivateKey<S> {
    algorithm: StatefulSignatureAlgorithm,
    parameters: Parameters,
    seed: SecretBytes,
    signer: Signer,
    store: S,
    state: SecretBytes,
    index: u64,
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
}

impl<S: StateStore> StatefulPrivateKey<S> {
    // The next index is written to the store before the signature exists, so a crash or a
    // failed write can waste an index but never use one twice.
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let index = self.index;

        if index >= self.parameters.capacity() {
            return Err(Error::KeyExhausted);
        }

        let next = self
            .algorithm
            .encode(&self.parameters, &self.seed, index + 1);

        match self.store.update(Some(&self.state), &next) {
            Err(_) => return Err(Error::StatePersistFailed),
            Ok(false) => return Err(Error::StateConflict),
            Ok(true) => {}
        }

        self.state = next;

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

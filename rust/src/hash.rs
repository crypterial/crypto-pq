#[cfg(feature = "blake3")]
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "ascon")]
use crate::ascon;
#[cfg(feature = "blake2")]
use crate::blake2;
#[cfg(feature = "blake3")]
use crate::blake3;
use crate::error::Error;
#[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
use crate::keccak::Keccak;
#[cfg(any(
    feature = "sha2",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
use crate::sha2::{
    IV_224, IV_256, IV_384, IV_512, IV_512_224, IV_512_256, Sha256, Sha512, finish256, finish512,
};
#[cfg(feature = "sha3")]
use crate::sp800_185;

#[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
const SHA3_SUFFIX: u8 = 0x06;

#[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
const SHAKE_SUFFIX: u8 = 0x1F;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    #[cfg(any(
        feature = "sha2",
        feature = "ml-dsa",
        feature = "slh-dsa",
        feature = "lms",
        feature = "xmss"
    ))]
    Sha256(&'static [u32; 8]),
    #[cfg(any(
        feature = "sha2",
        feature = "ml-dsa",
        feature = "slh-dsa",
        feature = "lms",
        feature = "xmss"
    ))]
    Sha512(&'static [u64; 8]),
    #[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
    Sha3,
    // The chaining value after the parameter block.
    #[cfg(feature = "blake2")]
    Blake2b([u64; 8]),
    #[cfg(feature = "blake2")]
    Blake2s([u32; 8]),
    #[cfg(feature = "ascon")]
    Ascon,
    #[cfg(feature = "blake3")]
    Blake3,
}

#[derive(Clone)]
pub(crate) enum Engine {
    #[cfg(any(
        feature = "sha2",
        feature = "ml-dsa",
        feature = "slh-dsa",
        feature = "lms",
        feature = "xmss"
    ))]
    Sha256(Sha256),
    #[cfg(any(
        feature = "sha2",
        feature = "ml-dsa",
        feature = "slh-dsa",
        feature = "lms",
        feature = "xmss"
    ))]
    Sha512(Sha512),
    #[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
    Keccak(Keccak),
    #[cfg(feature = "blake2")]
    Blake2b(blake2::Engine<u64>),
    #[cfg(feature = "blake2")]
    Blake2s(blake2::Engine<u32>),
    #[cfg(feature = "ascon")]
    Ascon(ascon::Sponge),
    // Boxed: with its stack of chaining values it is ten times the size of the others.
    #[cfg(feature = "blake3")]
    Blake3(Box<blake3::Hasher>),
}

impl Engine {
    pub(crate) fn update(&mut self, data: &[u8]) {
        match self {
            #[cfg(any(
                feature = "sha2",
                feature = "ml-dsa",
                feature = "slh-dsa",
                feature = "lms",
                feature = "xmss"
            ))]
            Self::Sha256(engine) => engine.update(data),
            #[cfg(any(
                feature = "sha2",
                feature = "ml-dsa",
                feature = "slh-dsa",
                feature = "lms",
                feature = "xmss"
            ))]
            Self::Sha512(engine) => engine.update(data),
            #[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
            Self::Keccak(engine) => engine.update(data),
            #[cfg(feature = "blake2")]
            Self::Blake2b(engine) => engine.update(data),
            #[cfg(feature = "blake2")]
            Self::Blake2s(engine) => engine.update(data),
            #[cfg(feature = "ascon")]
            Self::Ascon(sponge) => sponge.update(data),
            #[cfg(feature = "blake3")]
            Self::Blake3(hasher) => hasher.update(data),
        }
    }

    pub(crate) fn digest_into(&self, out: &mut [u8]) {
        match self {
            #[cfg(any(
                feature = "sha2",
                feature = "ml-dsa",
                feature = "slh-dsa",
                feature = "lms",
                feature = "xmss"
            ))]
            Self::Sha256(engine) => engine.digest_into(out),
            #[cfg(any(
                feature = "sha2",
                feature = "ml-dsa",
                feature = "slh-dsa",
                feature = "lms",
                feature = "xmss"
            ))]
            Self::Sha512(engine) => engine.digest_into(out),
            #[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
            Self::Keccak(engine) => engine.clone().read(out),
            #[cfg(feature = "blake2")]
            Self::Blake2b(engine) => engine.finish(out),
            #[cfg(feature = "blake2")]
            Self::Blake2s(engine) => engine.finish(out),
            #[cfg(feature = "ascon")]
            Self::Ascon(sponge) => sponge.clone().read(out),
            #[cfg(feature = "blake3")]
            Self::Blake3(hasher) => hasher.finish(out),
        }
    }
}

// A caller buffer of another length fails, and is left as it was.
pub(crate) const fn check_length(actual: usize, expected: usize) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::InvalidLength)
    }
}

// The largest output of one XOF call, and of a KMAC tag, on every platform (SPEC 12.8).
pub(crate) const fn fits_u32(length: usize) -> bool {
    length <= u32::MAX as usize
}

// A BLAKE2 salt or personalization of at most `size` bytes, which the parameter block zero-pads.
pub(crate) fn field(bytes: &[u8], size: usize) -> Result<&[u8], Error> {
    if bytes.len() <= size {
        Ok(bytes)
    } else {
        Err(Error::InvalidOption)
    }
}

/// A hash function with a fixed digest size: SHA-2, SHA-3, BLAKE2, Ascon-Hash256 or BLAKE3-256.
// oid_arc is the last arc of the NIST identifier 2.16.840.1.101.3.4.2.x, which pre-hashed
// signatures embed; 0 for a hash function that FIPS 204 and FIPS 205 do not allow there.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HashAlgorithm {
    name: &'static str,
    pub(crate) digest_size: usize,
    pub(crate) kind: Kind,
    oid_arc: u8,
}

impl fmt::Debug for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HashAlgorithm").field(&self.name).finish()
    }
}

/// BLAKE2's salt and personalization, at most 16 bytes each for BLAKE2b and 8 for BLAKE2s. Other
/// hash functions take only the empty options.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct HashOptions<'a> {
    /// The BLAKE2 salt.
    pub salt: &'a [u8],
    /// The BLAKE2 personalization.
    pub personalization: &'a [u8],
}

impl<'a> HashOptions<'a> {
    /// These options with `salt` set.
    #[must_use]
    pub const fn with_salt(mut self, salt: &'a [u8]) -> Self {
        self.salt = salt;

        self
    }

    /// These options with `personalization` set.
    #[must_use]
    pub const fn with_personalization(mut self, personalization: &'a [u8]) -> Self {
        self.personalization = personalization;

        self
    }
}

impl HashAlgorithm {
    /// The name of the algorithm, such as `"SHA-256"`.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The size of a digest in bytes.
    pub const fn digest_size(&self) -> usize {
        self.digest_size
    }

    pub(crate) const fn oid_arc(&self) -> u8 {
        self.oid_arc
    }

    /// The algorithm with these options in place of any set before. Hash functions without
    /// options accept only the empty ones; others fail with [`Error::InvalidOption`].
    pub fn configure(&self, options: &HashOptions) -> Result<Self, Error> {
        let (salt, personalization) = (options.salt, options.personalization);

        let kind = match self.kind {
            #[cfg(feature = "blake2")]
            Kind::Blake2b(_) => Kind::Blake2b(blake2::start64(
                self.digest_size,
                field(salt, 16)?,
                field(personalization, 16)?,
            )),
            #[cfg(feature = "blake2")]
            Kind::Blake2s(_) => Kind::Blake2s(blake2::start32(
                self.digest_size,
                field(salt, 8)?,
                field(personalization, 8)?,
            )),
            _ if salt.is_empty() && personalization.is_empty() => return Ok(*self),
            _ => return Err(Error::InvalidOption),
        };

        Ok(Self { kind, ..*self })
    }

    /// The digest of `data`.
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0; self.digest_size];

        self.digest_unchecked(data, &mut out);

        out
    }

    /// The digest of `data` written into `out`, which must be [`digest_size`](Self::digest_size)
    /// bytes, without allocating. Fails with [`Error::InvalidLength`] if `out` has another length.
    // Inline, so that a caller's buffer of the right size needs no check at run time.
    #[inline]
    pub fn digest_into(&self, data: &[u8], out: &mut [u8]) -> Result<(), Error> {
        check_length(out.len(), self.digest_size)?;

        self.digest_unchecked(data, out);

        Ok(())
    }

    // digest_into for an out of digest_size bytes.
    pub(crate) fn digest_unchecked(&self, data: &[u8], out: &mut [u8]) {
        match &self.kind {
            #[cfg(any(
                feature = "sha2",
                feature = "ml-dsa",
                feature = "slh-dsa",
                feature = "lms",
                feature = "xmss"
            ))]
            Kind::Sha256(iv) => finish256(iv, 0, data, out),
            #[cfg(any(
                feature = "sha2",
                feature = "ml-dsa",
                feature = "slh-dsa",
                feature = "lms",
                feature = "xmss"
            ))]
            Kind::Sha512(iv) => finish512(iv, 0, data, out),
            #[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
            Kind::Sha3 => Keccak::digest_into(self.block_size(), SHA3_SUFFIX, data, out),
            #[cfg(feature = "blake2")]
            Kind::Blake2b(h) => blake2::digest(h, data, out),
            #[cfg(feature = "blake2")]
            Kind::Blake2s(h) => blake2::digest(h, data, out),
            #[cfg(feature = "ascon")]
            Kind::Ascon => ascon::digest(&ascon::HASH256, data, out),
            #[cfg(feature = "blake3")]
            Kind::Blake3 => blake3::digest(data, out),
        }
    }

    /// An incremental hasher.
    pub fn create(&self) -> Hasher {
        let engine = match &self.kind {
            #[cfg(any(
                feature = "sha2",
                feature = "ml-dsa",
                feature = "slh-dsa",
                feature = "lms",
                feature = "xmss"
            ))]
            Kind::Sha256(iv) => Engine::Sha256(Sha256::new(iv)),
            #[cfg(any(
                feature = "sha2",
                feature = "ml-dsa",
                feature = "slh-dsa",
                feature = "lms",
                feature = "xmss"
            ))]
            Kind::Sha512(iv) => Engine::Sha512(Sha512::new(iv)),
            #[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
            Kind::Sha3 => Engine::Keccak(Keccak::new(self.block_size(), SHA3_SUFFIX)),
            #[cfg(feature = "blake2")]
            Kind::Blake2b(h) => Engine::Blake2b(blake2::Engine::new(h)),
            #[cfg(feature = "blake2")]
            Kind::Blake2s(h) => Engine::Blake2s(blake2::Engine::new(h)),
            #[cfg(feature = "ascon")]
            Kind::Ascon => Engine::Ascon(ascon::Sponge::new(&ascon::HASH256)),
            #[cfg(feature = "blake3")]
            Kind::Blake3 => Engine::Blake3(Box::new(blake3::Hasher::hash())),
        };

        Hasher {
            engine,
            size: self.digest_size,
        }
    }

    // The block size of HMAC's key blocks, and the rate of SHA-3.
    pub(crate) const fn block_size(&self) -> usize {
        match self.kind {
            #[cfg(any(
                feature = "sha2",
                feature = "ml-dsa",
                feature = "slh-dsa",
                feature = "lms",
                feature = "xmss"
            ))]
            Kind::Sha256(_) => 64,
            #[cfg(any(
                feature = "sha2",
                feature = "ml-dsa",
                feature = "slh-dsa",
                feature = "lms",
                feature = "xmss"
            ))]
            Kind::Sha512(_) => 128,
            #[cfg(feature = "blake2")]
            Kind::Blake2s(_) => 64,
            #[cfg(feature = "blake2")]
            Kind::Blake2b(_) => 128,
            #[cfg(feature = "blake3")]
            Kind::Blake3 => 64,
            #[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
            Kind::Sha3 => 200 - 2 * self.digest_size,
            #[cfg(feature = "ascon")]
            Kind::Ascon => 8,
        }
    }
}

/// An incremental hash computation, made by [`HashAlgorithm::create`].
pub struct Hasher {
    engine: Engine,
    size: usize,
}

impl Hasher {
    /// Absorbs `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.engine.update(data);
    }

    /// The digest of everything absorbed so far. The hasher stays usable.
    pub fn digest(&self) -> Vec<u8> {
        let mut out = vec![0; self.size];

        self.engine.digest_into(&mut out);

        out
    }

    /// The digest written into `out`, which must be the digest size of the algorithm. Fails with
    /// [`Error::InvalidLength`] if `out` has another length.
    pub fn digest_into(&self, out: &mut [u8]) -> Result<(), Error> {
        check_length(out.len(), self.size)?;

        self.engine.digest_into(out);

        Ok(())
    }
}

#[cfg(any(
    feature = "sha3",
    feature = "blake3",
    feature = "ascon",
    feature = "ml-dsa",
    feature = "slh-dsa"
))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum XofKind {
    #[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
    Shake,
    // The state after cSHAKE's prefix, or None when the function name and the customization are
    // both empty, which makes cSHAKE equal to SHAKE.
    #[cfg(feature = "sha3")]
    CShake(Option<[u64; 25]>),
    #[cfg(feature = "ascon")]
    AsconXof,
    // The state after the customization string.
    #[cfg(feature = "ascon")]
    AsconCxof([u64; 5]),
    #[cfg(feature = "blake3")]
    Blake3,
}

/// An extendable-output function: SHAKE, cSHAKE, Ascon-XOF128, Ascon-CXOF128 or BLAKE3.
#[cfg(any(
    feature = "sha3",
    feature = "blake3",
    feature = "ascon",
    feature = "ml-dsa",
    feature = "slh-dsa"
))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct XofAlgorithm {
    name: &'static str,
    rate: usize,
    kind: XofKind,
    oid_arc: u8,
}

#[cfg(any(
    feature = "sha3",
    feature = "blake3",
    feature = "ascon",
    feature = "ml-dsa",
    feature = "slh-dsa"
))]
impl fmt::Debug for XofAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("XofAlgorithm").field(&self.name).finish()
    }
}

/// The customization string S of cSHAKE (any length) and of Ascon-CXOF128 (at most 256 bytes).
/// Other XOFs take only the empty string.
#[cfg(any(
    feature = "sha3",
    feature = "blake3",
    feature = "ascon",
    feature = "ml-dsa",
    feature = "slh-dsa"
))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct XofOptions<'a> {
    /// The customization string.
    pub customization: &'a [u8],
}

#[cfg(any(
    feature = "sha3",
    feature = "blake3",
    feature = "ascon",
    feature = "ml-dsa",
    feature = "slh-dsa"
))]
impl<'a> XofOptions<'a> {
    /// These options with `customization` set.
    #[must_use]
    pub const fn with_customization(mut self, customization: &'a [u8]) -> Self {
        self.customization = customization;

        self
    }
}

#[cfg(any(
    feature = "sha3",
    feature = "blake3",
    feature = "ascon",
    feature = "ml-dsa",
    feature = "slh-dsa"
))]
impl XofAlgorithm {
    /// The name of the algorithm, such as `"SHAKE256"`.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub(crate) const fn oid_arc(&self) -> u8 {
        self.oid_arc
    }

    /// The algorithm with this customization in place of any set before.
    ///
    /// cSHAKE's function name N is reserved for NIST, so this sets the customization alone.
    pub fn configure(&self, options: &XofOptions) -> Result<Self, Error> {
        let customization = options.customization;

        let kind = match self.kind {
            #[cfg(feature = "sha3")]
            XofKind::CShake(_) => XofKind::CShake(sp800_185::prefix(self.rate, &[], customization)),
            #[cfg(feature = "ascon")]
            XofKind::AsconCxof(_) if customization.len() <= ascon::MAX_CUSTOMIZATION => {
                XofKind::AsconCxof(ascon::customize(customization))
            }
            _ if customization.is_empty() => return Ok(*self),
            _ => return Err(Error::InvalidOption),
        };

        Ok(Self { kind, ..*self })
    }

    #[cfg(all(any(feature = "hazmat", test), feature = "sha3"))]
    pub(crate) fn configure_cshake(
        &self,
        name: &[u8],
        customization: &[u8],
    ) -> Result<Self, Error> {
        match self.kind {
            #[cfg(feature = "sha3")]
            XofKind::CShake(_) => Ok(Self {
                kind: XofKind::CShake(sp800_185::prefix(self.rate, name, customization)),
                ..*self
            }),
            _ => Err(Error::InvalidOption),
        }
    }

    // SP 800-232, 5.2 and 5.3: the Ascon XOFs take an output length L > 0.
    const fn check_output(&self, length: usize) -> Result<(), Error> {
        #[cfg(feature = "ascon")]
        let ascon = matches!(self.kind, XofKind::AsconXof | XofKind::AsconCxof(_));

        #[cfg(not(feature = "ascon"))]
        let ascon = false;

        if !fits_u32(length) || (ascon && length == 0) {
            Err(Error::InvalidLength)
        } else {
            Ok(())
        }
    }

    /// `length` bytes of output for `data`. A call gives at most 2^32 - 1 bytes; the Ascon XOFs
    /// give at least one.
    pub fn digest(&self, data: &[u8], length: usize) -> Result<Vec<u8>, Error> {
        self.check_output(length)?;

        let mut out = vec![0; length];

        self.digest_unchecked(data, &mut out);

        Ok(out)
    }

    /// `out.len()` bytes of output for `data`, without allocating. Fails with
    /// [`Error::InvalidLength`] if `out` is longer than 2^32 - 1 bytes or, for the Ascon XOFs,
    /// empty.
    pub fn digest_into(&self, data: &[u8], out: &mut [u8]) -> Result<(), Error> {
        self.check_output(out.len())?;

        self.digest_unchecked(data, out);

        Ok(())
    }

    pub(crate) fn digest_unchecked(&self, data: &[u8], out: &mut [u8]) {
        match &self.kind {
            #[cfg(feature = "sha3")]
            XofKind::Shake | XofKind::CShake(None) => {
                Keccak::digest_into(self.rate, SHAKE_SUFFIX, data, out);
            }
            #[cfg(all(not(feature = "sha3"), any(feature = "ml-dsa", feature = "slh-dsa")))]
            XofKind::Shake => Keccak::digest_into(self.rate, SHAKE_SUFFIX, data, out),
            #[cfg(feature = "sha3")]
            XofKind::CShake(Some(start)) => {
                Keccak::digest_from(start, self.rate, sp800_185::SUFFIX, data, out);
            }
            #[cfg(feature = "ascon")]
            XofKind::AsconXof => ascon::digest(&ascon::XOF128, data, out),
            #[cfg(feature = "ascon")]
            XofKind::AsconCxof(start) => ascon::digest(start, data, out),
            #[cfg(feature = "blake3")]
            XofKind::Blake3 => blake3::digest(data, out),
        }
    }

    /// An incremental XOF.
    pub fn create(&self) -> Xof {
        let engine = match &self.kind {
            #[cfg(feature = "sha3")]
            XofKind::Shake | XofKind::CShake(None) => {
                XofEngine::Keccak(Keccak::new(self.rate, SHAKE_SUFFIX))
            }
            #[cfg(all(not(feature = "sha3"), any(feature = "ml-dsa", feature = "slh-dsa")))]
            XofKind::Shake => XofEngine::Keccak(Keccak::new(self.rate, SHAKE_SUFFIX)),
            #[cfg(feature = "sha3")]
            XofKind::CShake(Some(start)) => {
                XofEngine::Keccak(Keccak::resume(*start, self.rate, sp800_185::SUFFIX))
            }
            #[cfg(feature = "ascon")]
            XofKind::AsconXof => XofEngine::Ascon(ascon::Sponge::new(&ascon::XOF128)),
            #[cfg(feature = "ascon")]
            XofKind::AsconCxof(start) => XofEngine::Ascon(ascon::Sponge::new(start)),
            #[cfg(feature = "blake3")]
            XofKind::Blake3 => XofEngine::Blake3(Box::new(blake3::Hasher::hash())),
        };

        Xof {
            engine,
            squeezing: false,
        }
    }
}

#[cfg(any(
    feature = "sha3",
    feature = "blake3",
    feature = "ascon",
    feature = "ml-dsa",
    feature = "slh-dsa"
))]
enum XofEngine {
    #[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
    Keccak(Keccak),
    #[cfg(feature = "ascon")]
    Ascon(ascon::Sponge),
    #[cfg(feature = "blake3")]
    Blake3(Box<blake3::Hasher>),
}

/// An incremental XOF, made by [`XofAlgorithm::create`]: it absorbs until the first read and
/// squeezes from then on.
#[cfg(any(
    feature = "sha3",
    feature = "blake3",
    feature = "ascon",
    feature = "ml-dsa",
    feature = "slh-dsa"
))]
pub struct Xof {
    engine: XofEngine,
    squeezing: bool,
}

#[cfg(any(
    feature = "sha3",
    feature = "blake3",
    feature = "ascon",
    feature = "ml-dsa",
    feature = "slh-dsa"
))]
impl Xof {
    /// Absorbs `data`; [`Error::Unsupported`] after the first read.
    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.squeezing {
            return Err(Error::Unsupported);
        }

        match &mut self.engine {
            #[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
            XofEngine::Keccak(engine) => engine.update(data),
            #[cfg(feature = "ascon")]
            XofEngine::Ascon(sponge) => sponge.update(data),
            #[cfg(feature = "blake3")]
            XofEngine::Blake3(hasher) => hasher.update(data),
        }

        Ok(())
    }

    /// The next `length` bytes of output, at most 2^32 - 1 a call. BLAKE3 ends after 2^64 - 1
    /// bytes.
    pub fn read(&mut self, length: usize) -> Result<Vec<u8>, Error> {
        self.check_read(length)?;

        let mut out = vec![0; length];

        self.read_unchecked(&mut out);

        Ok(out)
    }

    /// The next `out.len()` bytes of output, as [`read`](Self::read) gives them.
    pub fn read_into(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.check_read(out.len())?;

        self.read_unchecked(out);

        Ok(())
    }

    // At most 2^32 - 1 bytes a call, and BLAKE3 ends after 2^64 - 1 bytes in all.
    fn check_read(&self, length: usize) -> Result<(), Error> {
        let fits = match &self.engine {
            #[cfg(feature = "blake3")]
            XofEngine::Blake3(hasher) => length as u64 <= hasher.output_left(),
            _ => true,
        };

        if fits_u32(length) && fits {
            Ok(())
        } else {
            Err(Error::InvalidLength)
        }
    }

    fn read_unchecked(&mut self, out: &mut [u8]) {
        self.squeezing = true;

        match &mut self.engine {
            #[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
            XofEngine::Keccak(engine) => engine.read(out),
            #[cfg(feature = "ascon")]
            XofEngine::Ascon(sponge) => sponge.read(out),
            #[cfg(feature = "blake3")]
            XofEngine::Blake3(hasher) => hasher.read(out),
        }
    }
}

/// SHA-224 (FIPS 180-4).
#[cfg(any(
    feature = "sha2",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
pub const SHA_224: HashAlgorithm = HashAlgorithm {
    name: "SHA-224",
    digest_size: 28,
    kind: Kind::Sha256(&IV_224),
    oid_arc: 4,
};

/// SHA-256 (FIPS 180-4).
#[cfg(any(
    feature = "sha2",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
pub const SHA_256: HashAlgorithm = HashAlgorithm {
    name: "SHA-256",
    digest_size: 32,
    kind: Kind::Sha256(&IV_256),
    oid_arc: 1,
};

/// SHA-384 (FIPS 180-4).
#[cfg(any(
    feature = "sha2",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
pub const SHA_384: HashAlgorithm = HashAlgorithm {
    name: "SHA-384",
    digest_size: 48,
    kind: Kind::Sha512(&IV_384),
    oid_arc: 2,
};

/// SHA-512 (FIPS 180-4).
#[cfg(any(
    feature = "sha2",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
pub const SHA_512: HashAlgorithm = HashAlgorithm {
    name: "SHA-512",
    digest_size: 64,
    kind: Kind::Sha512(&IV_512),
    oid_arc: 3,
};

/// SHA-512/224 (FIPS 180-4).
#[cfg(any(
    feature = "sha2",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
pub const SHA_512_224: HashAlgorithm = HashAlgorithm {
    name: "SHA-512/224",
    digest_size: 28,
    kind: Kind::Sha512(&IV_512_224),
    oid_arc: 5,
};

/// SHA-512/256 (FIPS 180-4).
#[cfg(any(
    feature = "sha2",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
pub const SHA_512_256: HashAlgorithm = HashAlgorithm {
    name: "SHA-512/256",
    digest_size: 32,
    kind: Kind::Sha512(&IV_512_256),
    oid_arc: 6,
};

/// SHA3-224 (FIPS 202).
#[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
pub const SHA3_224: HashAlgorithm = HashAlgorithm {
    name: "SHA3-224",
    digest_size: 28,
    kind: Kind::Sha3,
    oid_arc: 7,
};

/// SHA3-256 (FIPS 202).
#[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
pub const SHA3_256: HashAlgorithm = HashAlgorithm {
    name: "SHA3-256",
    digest_size: 32,
    kind: Kind::Sha3,
    oid_arc: 8,
};

/// SHA3-384 (FIPS 202).
#[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
pub const SHA3_384: HashAlgorithm = HashAlgorithm {
    name: "SHA3-384",
    digest_size: 48,
    kind: Kind::Sha3,
    oid_arc: 9,
};

/// SHA3-512 (FIPS 202).
#[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
pub const SHA3_512: HashAlgorithm = HashAlgorithm {
    name: "SHA3-512",
    digest_size: 64,
    kind: Kind::Sha3,
    oid_arc: 10,
};

// RFC 7693, 4: BLAKE2b and BLAKE2s at their recommended digest sizes, unkeyed.
#[cfg(feature = "blake2")]
const fn blake2b(name: &'static str, digest_size: usize) -> HashAlgorithm {
    HashAlgorithm {
        name,
        digest_size,
        kind: Kind::Blake2b(blake2::start64(digest_size, &[], &[])),
        oid_arc: 0,
    }
}

#[cfg(feature = "blake2")]
const fn blake2s(name: &'static str, digest_size: usize) -> HashAlgorithm {
    HashAlgorithm {
        name,
        digest_size,
        kind: Kind::Blake2s(blake2::start32(digest_size, &[], &[])),
        oid_arc: 0,
    }
}

/// BLAKE2b with a 20-byte digest (RFC 7693).
#[cfg(feature = "blake2")]
pub const BLAKE2B_160: HashAlgorithm = blake2b("BLAKE2b-160", 20);

/// BLAKE2b with a 32-byte digest (RFC 7693).
#[cfg(feature = "blake2")]
pub const BLAKE2B_256: HashAlgorithm = blake2b("BLAKE2b-256", 32);

/// BLAKE2b with a 48-byte digest (RFC 7693).
#[cfg(feature = "blake2")]
pub const BLAKE2B_384: HashAlgorithm = blake2b("BLAKE2b-384", 48);

/// BLAKE2b with a 64-byte digest (RFC 7693).
#[cfg(feature = "blake2")]
pub const BLAKE2B_512: HashAlgorithm = blake2b("BLAKE2b-512", 64);

/// BLAKE2s with a 16-byte digest (RFC 7693).
#[cfg(feature = "blake2")]
pub const BLAKE2S_128: HashAlgorithm = blake2s("BLAKE2s-128", 16);

/// BLAKE2s with a 20-byte digest (RFC 7693).
#[cfg(feature = "blake2")]
pub const BLAKE2S_160: HashAlgorithm = blake2s("BLAKE2s-160", 20);

/// BLAKE2s with a 28-byte digest (RFC 7693).
#[cfg(feature = "blake2")]
pub const BLAKE2S_224: HashAlgorithm = blake2s("BLAKE2s-224", 28);

/// BLAKE2s with a 32-byte digest (RFC 7693).
#[cfg(feature = "blake2")]
pub const BLAKE2S_256: HashAlgorithm = blake2s("BLAKE2s-256", 32);

/// Ascon-Hash256 (NIST SP 800-232).
#[cfg(feature = "ascon")]
pub const ASCON_HASH256: HashAlgorithm = HashAlgorithm {
    name: "Ascon-Hash256",
    digest_size: 32,
    kind: Kind::Ascon,
    oid_arc: 0,
};

/// BLAKE3 with a 32-byte digest.
#[cfg(feature = "blake3")]
pub const BLAKE3_256: HashAlgorithm = HashAlgorithm {
    name: "BLAKE3-256",
    digest_size: 32,
    kind: Kind::Blake3,
    oid_arc: 0,
};

/// SHAKE128 (FIPS 202).
#[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
pub const SHAKE128: XofAlgorithm = XofAlgorithm {
    name: "SHAKE128",
    rate: 168,
    kind: XofKind::Shake,
    oid_arc: 11,
};

/// SHAKE256 (FIPS 202).
#[cfg(any(feature = "sha3", feature = "ml-dsa", feature = "slh-dsa"))]
pub const SHAKE256: XofAlgorithm = XofAlgorithm {
    name: "SHAKE256",
    rate: 136,
    kind: XofKind::Shake,
    oid_arc: 12,
};

/// cSHAKE128 (NIST SP 800-185), with the customization of [`XofOptions`].
#[cfg(feature = "sha3")]
pub const CSHAKE128: XofAlgorithm = XofAlgorithm {
    name: "cSHAKE128",
    rate: 168,
    kind: XofKind::CShake(None),
    oid_arc: 0,
};

/// cSHAKE256 (NIST SP 800-185), with the customization of [`XofOptions`].
#[cfg(feature = "sha3")]
pub const CSHAKE256: XofAlgorithm = XofAlgorithm {
    name: "cSHAKE256",
    rate: 136,
    kind: XofKind::CShake(None),
    oid_arc: 0,
};

/// Ascon-XOF128 (NIST SP 800-232).
#[cfg(feature = "ascon")]
pub const ASCON_XOF128: XofAlgorithm = XofAlgorithm {
    name: "Ascon-XOF128",
    rate: 8,
    kind: XofKind::AsconXof,
    oid_arc: 0,
};

/// Ascon-CXOF128 (NIST SP 800-232), with the customization of [`XofOptions`].
#[cfg(feature = "ascon")]
pub const ASCON_CXOF128: XofAlgorithm = XofAlgorithm {
    name: "Ascon-CXOF128",
    rate: 8,
    kind: XofKind::AsconCxof(ascon::CXOF128_EMPTY),
    oid_arc: 0,
};

/// BLAKE3 as an XOF.
#[cfg(feature = "blake3")]
pub const BLAKE3: XofAlgorithm = XofAlgorithm {
    name: "BLAKE3",
    rate: 64,
    kind: XofKind::Blake3,
    oid_arc: 0,
};

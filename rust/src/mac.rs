#[cfg(feature = "blake3")]
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "blake2")]
use crate::blake2;
#[cfg(feature = "blake3")]
use crate::blake3;
use crate::cpu::Dit;
use crate::ct;
use crate::error::Error;
use crate::hash::check_length;
#[cfg(feature = "blake2")]
use crate::hash::field;
#[cfg(feature = "sha3")]
use crate::hash::fits_u32;
#[cfg(any(
    feature = "hmac",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
use crate::hash::{Engine, HashAlgorithm, Kind, SHA_224, SHA_256, SHA_384, SHA_512};
#[cfg(feature = "sha3")]
use crate::keccak::Keccak;
#[cfg(any(
    feature = "hmac",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
use crate::sha2::{self, Sha256, Sha512, finish256, finish512};
#[cfg(feature = "sha3")]
use crate::sp800_185;
use crate::wipe::wipe;

#[derive(Clone, Copy, PartialEq, Eq)]
enum MacKind {
    // The tag is the leftmost `size` bytes of the hash output (FIPS 198-1, 5).
    #[cfg(any(
        feature = "hmac",
        feature = "slh-dsa",
        feature = "lms",
        feature = "xmss"
    ))]
    Hmac(HashAlgorithm),
    // The state after cSHAKE's prefix for the function name "KMAC" and the customization.
    #[cfg(feature = "sha3")]
    Kmac {
        prefix: [u64; 25],
        rate: usize,
        xof: bool,
    },
    // The chaining value of the configured length, salt and personalization, before the key
    // length is added.
    #[cfg(feature = "blake2")]
    Blake2b([u64; 8]),
    #[cfg(feature = "blake2")]
    Blake2s([u32; 8]),
    // keyed_hash, under a key of exactly 32 bytes.
    #[cfg(feature = "blake3")]
    Blake3,
}

/// A message authentication code: HMAC with SHA-2, KMAC, keyed BLAKE2 or keyed BLAKE3.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MacAlgorithm {
    name: &'static str,
    size: usize,
    kind: MacKind,
}

impl fmt::Debug for MacAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MacAlgorithm").field(&self.name).finish()
    }
}

/// The options of a MAC. HMAC takes `length` alone, KMAC `length`, `customization` and `xof`,
/// BLAKE2 `length`, `salt` and `personalization`, and BLAKE3 none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MacOptions<'a> {
    /// The tag size in bytes; `None` for the default: the hash output for HMAC, 32 for KMAC128, 64
    /// for KMAC256 and BLAKE2b, 32 for BLAKE2s. HMAC and KMAC tags have at least 4 bytes; a tag
    /// shorter than 8 bytes needs a careful risk analysis, and the key needs at least the security
    /// strength that the MAC is to provide.
    pub length: Option<usize>,
    /// The KMAC customization string.
    pub customization: &'a [u8],
    /// KMACXOF instead of KMAC.
    pub xof: bool,
    /// The BLAKE2 salt, at most 16 bytes for BLAKE2b and 8 for BLAKE2s.
    pub salt: &'a [u8],
    /// The BLAKE2 personalization, at most 16 bytes for BLAKE2b and 8 for BLAKE2s.
    pub personalization: &'a [u8],
}

impl<'a> MacOptions<'a> {
    /// These options with `length` set.
    #[must_use]
    pub const fn with_length(mut self, length: usize) -> Self {
        self.length = Some(length);

        self
    }

    /// These options with `customization` set.
    #[must_use]
    pub const fn with_customization(mut self, customization: &'a [u8]) -> Self {
        self.customization = customization;

        self
    }

    /// These options with `xof` set.
    #[must_use]
    pub const fn with_xof(mut self, xof: bool) -> Self {
        self.xof = xof;

        self
    }

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

// RFC 2104: a key longer than a block is replaced by its hash, which `hashed` then holds.
#[cfg(any(
    feature = "hmac",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
pub(crate) fn block_key<'a>(
    hash: &HashAlgorithm,
    key: &'a [u8],
    hashed: &'a mut [u8; 64],
) -> &'a [u8] {
    if key.len() <= hash.block_size() {
        return key;
    }

    let hashed = &mut hashed[..hash.digest_size];

    hash.digest_unchecked(key, hashed);

    hashed
}

// HMAC over SHA-2 of data, out.len() bytes: the hash's digest size.
#[cfg(any(
    feature = "hmac",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
pub(crate) fn hmac(hash: &HashAlgorithm, key: &[u8], data: &[u8], out: &mut [u8]) {
    let mut hashed = [0; 64];

    let key = block_key(hash, key, &mut hashed);

    match hash.kind {
        Kind::Sha256(iv) => sha2::hmac256(iv, key, data, out),
        Kind::Sha512(iv) => sha2::hmac512(iv, key, data, out),
        _ => unreachable!("HMAC is defined here over SHA-2 only"),
    }

    wipe(&mut hashed);
}

// Whether the next tag.len() bytes of output equal tag, in chunks that need no allocation and in
// constant time over the whole tag.
#[cfg(feature = "sha3")]
fn squeeze_equal(engine: &mut Keccak, tag: &[u8]) -> bool {
    let mut chunk = [0; 64];

    let mut mask = 0xFF;

    for part in tag.chunks(chunk.len()) {
        let expected = &mut chunk[..part.len()];

        engine.read(expected);

        mask &= ct::equal_mask(expected, part);
    }

    wipe(&mut chunk);

    ct::declassify_value(mask) == 0xFF
}

// Each public method that uses the key takes the keyed DIT guard once, around everything it does
// with the key, and the functions it calls take none of their own.
impl MacAlgorithm {
    /// The name of the algorithm, such as `"HMAC-SHA-256"`.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The size of a tag in bytes.
    pub const fn digest_size(&self) -> usize {
        self.size
    }

    /// The algorithm with these options in place of any set before. An option that the algorithm
    /// does not take fails with [`Error::InvalidOption`].
    pub fn configure(&self, options: &MacOptions) -> Result<Self, Error> {
        let MacOptions {
            length,
            customization,
            xof,
            salt,
            personalization,
        } = *options;

        let (size, kind) = match self.kind {
            #[cfg(feature = "blake3")]
            MacKind::Blake3 if *options == MacOptions::default() => return Ok(*self),
            #[cfg(feature = "blake3")]
            MacKind::Blake3 => return Err(Error::InvalidOption),
            // The 32-bit minimum is KMAC's (SP 800-185, 8.4.2).
            #[cfg(any(
                feature = "hmac",
                feature = "slh-dsa",
                feature = "lms",
                feature = "xmss"
            ))]
            MacKind::Hmac(hash) => {
                let size = length.unwrap_or(hash.digest_size);

                let others = MacOptions {
                    length: None,
                    ..*options
                };

                if !(4..=hash.digest_size).contains(&size) || others != MacOptions::default() {
                    return Err(Error::InvalidOption);
                }

                (size, MacKind::Hmac(hash))
            }
            #[cfg(feature = "sha3")]
            MacKind::Kmac { rate, .. } => {
                // SP 800-185, 8.4.2: a tag shall not be shorter than 32 bits.
                let size = length.unwrap_or(if rate == 168 { 32 } else { 64 });

                if size < 4 || !fits_u32(size) || !salt.is_empty() || !personalization.is_empty() {
                    return Err(Error::InvalidOption);
                }

                let prefix = sp800_185::prefix(rate, b"KMAC", customization)
                    .expect("the function name is not empty");

                (size, MacKind::Kmac { prefix, rate, xof })
            }
            #[cfg(feature = "blake2")]
            MacKind::Blake2b(_) => {
                let size = length.unwrap_or(64);

                if !(1..=64).contains(&size) || !customization.is_empty() || xof {
                    return Err(Error::InvalidOption);
                }

                let h = blake2::start64(size, field(salt, 16)?, field(personalization, 16)?);

                (size, MacKind::Blake2b(h))
            }
            #[cfg(feature = "blake2")]
            MacKind::Blake2s(_) => {
                let size = length.unwrap_or(32);

                if !(1..=32).contains(&size) || !customization.is_empty() || xof {
                    return Err(Error::InvalidOption);
                }

                let h = blake2::start32(size, field(salt, 8)?, field(personalization, 8)?);

                (size, MacKind::Blake2s(h))
            }
        };

        Ok(Self {
            size,
            kind,
            ..*self
        })
    }

    // RFC 7693, 2.1: a BLAKE2 key has 1 to 64 (BLAKE2b) or 32 (BLAKE2s) bytes, and a BLAKE3 key
    // exactly 32. HMAC and KMAC take keys of any length.
    const fn key_sizes(&self) -> (usize, usize) {
        match self.kind {
            #[cfg(feature = "blake2")]
            MacKind::Blake2b(_) => (1, 64),
            #[cfg(feature = "blake2")]
            MacKind::Blake2s(_) => (1, 32),
            #[cfg(feature = "blake3")]
            MacKind::Blake3 => (blake3::KEY, blake3::KEY),
            _ => (0, usize::MAX),
        }
    }

    const fn key_fits(&self, key: &[u8]) -> bool {
        let (minimum, maximum) = self.key_sizes();

        key.len() >= minimum && key.len() <= maximum
    }

    const fn check_key(&self, key: &[u8]) -> Result<(), Error> {
        if self.key_fits(key) {
            Ok(())
        } else {
            Err(Error::InvalidLength)
        }
    }

    /// The tag of `data` under `key`. HMAC and KMAC take keys of any length, BLAKE2b 1 to 64 bytes,
    /// BLAKE2s 1 to 32 and BLAKE3 exactly 32.
    pub fn digest(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
        self.check_key(key)?;

        let mut out = vec![0; self.size];

        let _dit = Dit::keyed();

        self.mac(key, data, &mut out);

        Ok(out)
    }

    /// The tag of `data` under `key`, written into `out`, which must be
    /// [`digest_size`](Self::digest_size) bytes. Fails with [`Error::InvalidLength`] if the key
    /// length is not accepted or `out` has another length.
    pub fn digest_into(&self, key: &[u8], data: &[u8], out: &mut [u8]) -> Result<(), Error> {
        self.check_key(key)?;

        check_length(out.len(), self.size)?;

        let _dit = Dit::keyed();

        self.mac(key, data, out);

        Ok(())
    }

    /// An incremental MAC under `key`.
    pub fn create(&self, key: &[u8]) -> Result<Mac, Error> {
        self.check_key(key)?;

        let _dit = Dit::keyed();

        Ok(self.create_unchecked(key))
    }

    // create for a key of an accepted length, under the caller's DIT guard.
    pub(crate) fn create_unchecked(&self, key: &[u8]) -> Mac {
        let engine = match &self.kind {
            #[cfg(any(
                feature = "hmac",
                feature = "slh-dsa",
                feature = "lms",
                feature = "xmss"
            ))]
            MacKind::Hmac(hash) => keyed_hmac(hash, key),
            #[cfg(feature = "sha3")]
            MacKind::Kmac { prefix, rate, xof } => MacEngine::Kmac {
                engine: sp800_185::keyed(prefix, *rate, key),
                xof: *xof,
            },
            #[cfg(feature = "blake2")]
            MacKind::Blake2b(h) => MacEngine::Blake2b(blake2::Engine::keyed(h, key)),
            #[cfg(feature = "blake2")]
            MacKind::Blake2s(h) => MacEngine::Blake2s(blake2::Engine::keyed(h, key)),
            #[cfg(feature = "blake3")]
            MacKind::Blake3 => MacEngine::Blake3(Box::new(blake3::Hasher::keyed(key))),
        };

        Mac {
            engine,
            size: self.size,
        }
    }

    /// Whether `tag` is the tag of `data` under `key`, compared in constant time over the whole
    /// tag. A tag of another size, or a key of a length the algorithm does not take, verifies
    /// nothing.
    pub fn verify(&self, key: &[u8], data: &[u8], tag: &[u8]) -> bool {
        if !self.key_fits(key) || tag.len() != self.size {
            return false;
        }

        let _dit = Dit::keyed();

        #[cfg(feature = "sha3")]
        if let MacKind::Kmac { prefix, rate, xof } = &self.kind {
            let mut engine = sp800_185::keyed(prefix, *rate, key);

            engine.update(data);

            engine.update(sp800_185::output_length(*xof, self.size).as_slice());

            return squeeze_equal(&mut engine, tag);
        }

        let mut expected = [0; 64];

        self.mac(key, data, &mut expected[..self.size]);

        let equal = ct::equal(&expected[..self.size], tag);

        wipe(&mut expected);

        ct::declassify_value(equal)
    }

    // The tag into out, which has digest_size() bytes.
    fn mac(&self, key: &[u8], data: &[u8], out: &mut [u8]) {
        match &self.kind {
            #[cfg(any(
                feature = "hmac",
                feature = "slh-dsa",
                feature = "lms",
                feature = "xmss"
            ))]
            MacKind::Hmac(hash) if out.len() == hash.digest_size => hmac(hash, key, data, out),
            #[cfg(any(
                feature = "hmac",
                feature = "slh-dsa",
                feature = "lms",
                feature = "xmss"
            ))]
            MacKind::Hmac(hash) => {
                let mut full = [0; 64];

                hmac(hash, key, data, &mut full[..hash.digest_size]);

                out.copy_from_slice(&full[..out.len()]);

                wipe(&mut full);
            }
            #[cfg(feature = "sha3")]
            MacKind::Kmac { prefix, rate, xof } => {
                sp800_185::kmac(prefix, *rate, key, data, *xof, out);
            }
            #[cfg(feature = "blake2")]
            MacKind::Blake2b(h) => blake2::mac(h, key, data, out),
            #[cfg(feature = "blake2")]
            MacKind::Blake2s(h) => blake2::mac(h, key, data, out),
            #[cfg(feature = "blake3")]
            MacKind::Blake3 => blake3::keyed_hash(key, data, out),
        }
    }
}

// HMAC's inner engine after the inner key block, and the state after the outer one.
#[cfg(any(
    feature = "hmac",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
fn keyed_hmac(hash: &HashAlgorithm, key: &[u8]) -> MacEngine {
    let mut hashed = [0; 64];

    let key = block_key(hash, key, &mut hashed);

    let (inner, outer) = match hash.kind {
        Kind::Sha256(iv) => {
            let mut keyed = sha2::keyed256(iv, key);

            let engines = (
                Engine::Sha256(Sha256::resume(keyed[0], 64)),
                Outer::Sha256(keyed[1]),
            );

            wipe(keyed.as_flattened_mut());

            engines
        }
        Kind::Sha512(iv) => {
            let mut keyed = sha2::keyed512(iv, key);

            let engines = (
                Engine::Sha512(Sha512::resume(keyed[0], 128)),
                Outer::Sha512(keyed[1]),
            );

            wipe(keyed.as_flattened_mut());

            engines
        }
        _ => unreachable!("HMAC is defined here over SHA-2 only"),
    };

    wipe(&mut hashed);

    MacEngine::Hmac {
        inner,
        outer,
        digest_size: hash.digest_size,
    }
}

// HMAC's state after the outer key block, wiped when dropped.
#[cfg(any(
    feature = "hmac",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
enum Outer {
    Sha256([u32; 8]),
    Sha512([u64; 8]),
}

#[cfg(any(
    feature = "hmac",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
impl Drop for Outer {
    fn drop(&mut self) {
        match self {
            Self::Sha256(state) => wipe(state),
            Self::Sha512(state) => wipe(state),
        }
    }
}

enum MacEngine {
    // The inner engine has absorbed the inner key block and the data so far.
    #[cfg(any(
        feature = "hmac",
        feature = "slh-dsa",
        feature = "lms",
        feature = "xmss"
    ))]
    Hmac {
        inner: Engine,
        outer: Outer,
        digest_size: usize,
    },
    #[cfg(feature = "sha3")]
    Kmac { engine: Keccak, xof: bool },
    #[cfg(feature = "blake2")]
    Blake2b(blake2::Engine<u64>),
    #[cfg(feature = "blake2")]
    Blake2s(blake2::Engine<u32>),
    #[cfg(feature = "blake3")]
    Blake3(Box<blake3::Hasher>),
}

/// An incremental MAC computation, made by [`MacAlgorithm::create`]. Its keyed state is wiped
/// when it is dropped.
pub struct Mac {
    engine: MacEngine,
    size: usize,
}

impl Mac {
    /// Absorbs `data`.
    pub fn update(&mut self, data: &[u8]) {
        let _dit = Dit::keyed();

        match &mut self.engine {
            #[cfg(any(
                feature = "hmac",
                feature = "slh-dsa",
                feature = "lms",
                feature = "xmss"
            ))]
            MacEngine::Hmac { inner, .. } => inner.update(data),
            #[cfg(feature = "sha3")]
            MacEngine::Kmac { engine, .. } => engine.update(data),
            #[cfg(feature = "blake2")]
            MacEngine::Blake2b(engine) => engine.update(data),
            #[cfg(feature = "blake2")]
            MacEngine::Blake2s(engine) => engine.update(data),
            #[cfg(feature = "blake3")]
            MacEngine::Blake3(hasher) => hasher.update(data),
        }
    }

    /// The tag of everything absorbed so far. The MAC stays usable.
    pub fn digest(&self) -> Vec<u8> {
        let mut out = vec![0; self.size];

        let _dit = Dit::keyed();

        self.finish(&mut out);

        out
    }

    /// The tag written into `out`, which must be the tag size of the algorithm. Fails with
    /// [`Error::InvalidLength`] if `out` has another length.
    pub fn digest_into(&self, out: &mut [u8]) -> Result<(), Error> {
        check_length(out.len(), self.size)?;

        let _dit = Dit::keyed();

        self.finish(out);

        Ok(())
    }

    /// Whether `tag` is the tag of everything absorbed so far, compared in constant time.
    pub fn verify(&self, tag: &[u8]) -> bool {
        if tag.len() != self.size {
            return false;
        }

        let _dit = Dit::keyed();

        #[cfg(feature = "sha3")]
        if let MacEngine::Kmac { engine, xof } = &self.engine {
            let mut engine = engine.clone();

            engine.update(sp800_185::output_length(*xof, self.size).as_slice());

            return squeeze_equal(&mut engine, tag);
        }

        let mut expected = [0; 64];

        self.finish(&mut expected[..self.size]);

        let equal = ct::equal(&expected[..self.size], tag);

        wipe(&mut expected);

        ct::declassify_value(equal)
    }

    // HMAC's inner digest is wiped: with the outer key it gives the output, which may be a key
    // itself. The engines that finish here are copies, which their drops wipe.
    fn finish(&self, out: &mut [u8]) {
        match &self.engine {
            #[cfg(any(
                feature = "hmac",
                feature = "slh-dsa",
                feature = "lms",
                feature = "xmss"
            ))]
            MacEngine::Hmac {
                inner,
                outer,
                digest_size,
            } => {
                let mut digest = [0; 64];

                let mut full = [0; 64];

                let (inner_digest, tag) = (&mut digest[..*digest_size], &mut full[..*digest_size]);

                inner.digest_into(inner_digest);

                match outer {
                    Outer::Sha256(state) => finish256(state, 64, inner_digest, tag),
                    Outer::Sha512(state) => finish512(state, 128, inner_digest, tag),
                }

                out.copy_from_slice(&tag[..out.len()]);

                wipe(&mut digest);

                wipe(&mut full);
            }
            #[cfg(feature = "sha3")]
            MacEngine::Kmac { engine, xof } => {
                let mut engine = engine.clone();

                engine.update(sp800_185::output_length(*xof, self.size).as_slice());

                engine.read(out);
            }
            #[cfg(feature = "blake2")]
            MacEngine::Blake2b(engine) => engine.finish(out),
            #[cfg(feature = "blake2")]
            MacEngine::Blake2s(engine) => engine.finish(out),
            #[cfg(feature = "blake3")]
            MacEngine::Blake3(hasher) => hasher.finish(out),
        }
    }
}

#[cfg(any(
    feature = "hmac",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
const fn hmac_algorithm(name: &'static str, hash: HashAlgorithm) -> MacAlgorithm {
    MacAlgorithm {
        name,
        size: hash.digest_size,
        kind: MacKind::Hmac(hash),
    }
}

/// HMAC with SHA-224 (FIPS 198-1, RFC 2104).
#[cfg(any(
    feature = "hmac",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
pub const HMAC_SHA_224: MacAlgorithm = hmac_algorithm("HMAC-SHA-224", SHA_224);

/// HMAC with SHA-256 (FIPS 198-1, RFC 2104).
#[cfg(any(
    feature = "hmac",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
pub const HMAC_SHA_256: MacAlgorithm = hmac_algorithm("HMAC-SHA-256", SHA_256);

/// HMAC with SHA-384 (FIPS 198-1, RFC 2104).
#[cfg(any(
    feature = "hmac",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
pub const HMAC_SHA_384: MacAlgorithm = hmac_algorithm("HMAC-SHA-384", SHA_384);

/// HMAC with SHA-512 (FIPS 198-1, RFC 2104).
#[cfg(any(
    feature = "hmac",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
pub const HMAC_SHA_512: MacAlgorithm = hmac_algorithm("HMAC-SHA-512", SHA_512);

/// KMAC128 (NIST SP 800-185), with a 32-byte tag by default.
#[cfg(feature = "sha3")]
pub const KMAC128: MacAlgorithm = MacAlgorithm {
    name: "KMAC128",
    size: 32,
    kind: MacKind::Kmac {
        prefix: sp800_185::kmac_prefix(168),
        rate: 168,
        xof: false,
    },
};

/// KMAC256 (NIST SP 800-185), with a 64-byte tag by default.
#[cfg(feature = "sha3")]
pub const KMAC256: MacAlgorithm = MacAlgorithm {
    name: "KMAC256",
    size: 64,
    kind: MacKind::Kmac {
        prefix: sp800_185::kmac_prefix(136),
        rate: 136,
        xof: false,
    },
};

/// Keyed BLAKE2b (RFC 7693), with a 64-byte tag by default.
#[cfg(feature = "blake2")]
pub const BLAKE2B_MAC: MacAlgorithm = MacAlgorithm {
    name: "BLAKE2b-MAC",
    size: 64,
    kind: MacKind::Blake2b(blake2::start64(64, &[], &[])),
};

/// Keyed BLAKE2s (RFC 7693), with a 32-byte tag by default.
#[cfg(feature = "blake2")]
pub const BLAKE2S_MAC: MacAlgorithm = MacAlgorithm {
    name: "BLAKE2s-MAC",
    size: 32,
    kind: MacKind::Blake2s(blake2::start32(32, &[], &[])),
};

/// BLAKE3's keyed_hash mode, under a 32-byte key, with a 32-byte tag.
#[cfg(feature = "blake3")]
pub const BLAKE3_MAC: MacAlgorithm = MacAlgorithm {
    name: "BLAKE3-MAC",
    size: 32,
    kind: MacKind::Blake3,
};

use core::fmt;

#[cfg(feature = "blake3")]
use crate::blake3;
use crate::cpu::Dit;
use crate::error::Error;
#[cfg(feature = "blake3")]
use crate::hash::fits_u32;
#[cfg(feature = "hkdf")]
use crate::hash::{HashAlgorithm, Kind, SHA_256, SHA_384, SHA_512};
#[cfg(feature = "hkdf")]
use crate::mac::{block_key, hmac};
#[cfg(feature = "hkdf")]
use crate::sha2::{self, Sha256, Sha512, finish256, finish512};
use crate::wipe::{SecretBytes, wipe};

// A build without HKDF has no hash for it: hkdf() always fails, which the empty type lets the
// compiler see, so that BLAKE3-KDF keeps the whole interface.
#[cfg(not(feature = "hkdf"))]
#[derive(Clone, Copy)]
enum HashAlgorithm {}

#[cfg(not(feature = "hkdf"))]
fn hmac(hash: &HashAlgorithm, _: &[u8], _: &[u8], _: &mut [u8]) {
    match *hash {}
}

#[cfg(not(feature = "hkdf"))]
fn expand_unchecked(hash: &HashAlgorithm, _: &[u8], _: &[u8], _: &mut [u8]) {
    match *hash {}
}

/// A key derivation function: HKDF (RFC 5869) over HMAC with SHA-2, or BLAKE3-KDF, BLAKE3's
/// `derive_key` with `info` as its context string.
// The PRK, every T(i) and the keyed states are secret and wiped; one keyed DIT guard covers each
// public call.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KdfAlgorithm {
    name: &'static str,
    kind: KdfKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KdfKind {
    #[cfg(feature = "hkdf")]
    Hkdf(HashAlgorithm),
    // No extract or expand step of its own, and no salt.
    #[cfg(feature = "blake3")]
    Blake3,
}

impl fmt::Debug for KdfAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KdfAlgorithm").field(&self.name).finish()
    }
}

/// The options of a key derivation. An empty HKDF salt stands for HashLen zero bytes (RFC 5869,
/// 2.2). `extract` takes no `info` and `expand` no `salt`; BLAKE3-KDF takes no `salt`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct KdfOptions<'a> {
    /// The HKDF salt.
    pub salt: &'a [u8],
    /// The HKDF info, or the BLAKE3-KDF context string.
    pub info: &'a [u8],
}

impl<'a> KdfOptions<'a> {
    /// These options with `salt` set.
    #[must_use]
    pub const fn with_salt(mut self, salt: &'a [u8]) -> Self {
        self.salt = salt;

        self
    }

    /// These options with `info` set.
    #[must_use]
    pub const fn with_info(mut self, info: &'a [u8]) -> Self {
        self.info = info;

        self
    }
}

impl KdfAlgorithm {
    /// The name of the algorithm, such as `"HKDF-SHA-256"`.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The size of a pseudorandom key: HashLen for HKDF, BLAKE3's 32-byte key size for BLAKE3-KDF.
    pub const fn prk_size(&self) -> usize {
        match self.kind {
            #[cfg(feature = "hkdf")]
            KdfKind::Hkdf(hash) => hash.digest_size(),
            #[cfg(feature = "blake3")]
            KdfKind::Blake3 => blake3::KEY,
        }
    }

    // HKDF's hash; BLAKE3-KDF has no extract and expand steps.
    const fn hkdf(&self) -> Result<HashAlgorithm, Error> {
        match self.kind {
            #[cfg(feature = "hkdf")]
            KdfKind::Hkdf(hash) => Ok(hash),
            #[cfg(feature = "blake3")]
            KdfKind::Blake3 => Err(Error::Unsupported),
        }
    }

    // RFC 5869, 2.3: L is at most 255 HashLen, and BLAKE3-KDF's at most 2^32 - 1 (SPEC 12.8).
    // Every KDF refuses an empty output.
    const fn check_output(&self, length: usize) -> Result<(), Error> {
        let fits = match self.kind {
            #[cfg(feature = "hkdf")]
            KdfKind::Hkdf(hash) => length <= 255 * hash.digest_size(),
            #[cfg(feature = "blake3")]
            KdfKind::Blake3 => fits_u32(length),
        };

        if length == 0 || !fits {
            Err(Error::InvalidLength)
        } else {
            Ok(())
        }
    }

    /// Derives `length` bytes from the input keying material `ikm`: HKDF Extract and then Expand,
    /// or BLAKE3-KDF. `length` is at most 255 HashLen for HKDF and below 2^32 for BLAKE3-KDF, and
    /// never 0.
    pub fn derive(
        &self,
        ikm: &[u8],
        length: usize,
        options: &KdfOptions,
    ) -> Result<SecretBytes, Error> {
        self.check_derive(options)?;

        self.check_output(length)?;

        let mut out = SecretBytes::zeroed(length);

        self.derive_unchecked(ikm, &mut out, options);

        Ok(out)
    }

    /// Derives `out.len()` bytes into `out`, as [`derive`](Self::derive) does.
    pub fn derive_into(
        &self,
        ikm: &[u8],
        out: &mut [u8],
        options: &KdfOptions,
    ) -> Result<(), Error> {
        self.check_derive(options)?;

        self.check_output(out.len())?;

        self.derive_unchecked(ikm, out, options);

        Ok(())
    }

    // BLAKE3-KDF has no salt.
    const fn check_derive(&self, options: &KdfOptions) -> Result<(), Error> {
        match self.kind {
            #[cfg(feature = "blake3")]
            KdfKind::Blake3 if !options.salt.is_empty() => Err(Error::InvalidOption),
            _ => Ok(()),
        }
    }

    fn derive_unchecked(&self, ikm: &[u8], out: &mut [u8], options: &KdfOptions) {
        let hash = match self.kind {
            #[cfg(feature = "hkdf")]
            KdfKind::Hkdf(hash) => hash,
            #[cfg(feature = "blake3")]
            KdfKind::Blake3 => {
                let _dit = Dit::keyed();

                blake3::derive_key(options.info, ikm, out);

                return;
            }
        };

        let _dit = Dit::keyed();

        let mut prk = [0; 64];

        let size = self.prk_size();

        hmac(&hash, options.salt, ikm, &mut prk[..size]);

        expand_unchecked(&hash, &prk[..size], options.info, out);

        wipe(&mut prk);
    }

    /// HKDF Extract: the pseudorandom key HMAC(salt, ikm), of [`prk_size`](Self::prk_size) bytes.
    /// [`Error::Unsupported`] for BLAKE3-KDF.
    pub fn extract(&self, ikm: &[u8], options: &KdfOptions) -> Result<SecretBytes, Error> {
        let mut out = SecretBytes::zeroed(self.prk_size());

        self.extract_into(ikm, &mut out, options)?;

        Ok(out)
    }

    /// HKDF Extract into `out`, which must be [`prk_size`](Self::prk_size) bytes.
    /// [`Error::Unsupported`] for BLAKE3-KDF.
    pub fn extract_into(
        &self,
        ikm: &[u8],
        out: &mut [u8],
        options: &KdfOptions,
    ) -> Result<(), Error> {
        let hash = self.hkdf()?;

        if !options.info.is_empty() {
            return Err(Error::InvalidOption);
        }

        if out.len() != self.prk_size() {
            return Err(Error::InvalidLength);
        }

        let _dit = Dit::keyed();

        hmac(&hash, options.salt, ikm, out);

        Ok(())
    }

    /// HKDF Expand: `length` bytes from a pseudorandom key of at least
    /// [`prk_size`](Self::prk_size) bytes. [`Error::Unsupported`] for BLAKE3-KDF.
    pub fn expand(
        &self,
        prk: &[u8],
        length: usize,
        options: &KdfOptions,
    ) -> Result<SecretBytes, Error> {
        let hash = self.check_expand(prk, length, options)?;

        let mut out = SecretBytes::zeroed(length);

        let _dit = Dit::keyed();

        expand_unchecked(&hash, prk, options.info, &mut out);

        Ok(out)
    }

    /// HKDF Expand into `out`, as [`expand`](Self::expand) does.
    pub fn expand_into(
        &self,
        prk: &[u8],
        out: &mut [u8],
        options: &KdfOptions,
    ) -> Result<(), Error> {
        let hash = self.check_expand(prk, out.len(), options)?;

        let _dit = Dit::keyed();

        expand_unchecked(&hash, prk, options.info, out);

        Ok(())
    }

    // RFC 5869, 2.3: a PRK of at least HashLen bytes, after the options (SPEC 12.7.1).
    fn check_expand(
        &self,
        prk: &[u8],
        length: usize,
        options: &KdfOptions,
    ) -> Result<HashAlgorithm, Error> {
        let hash = self.hkdf()?;

        if !options.salt.is_empty() {
            return Err(Error::InvalidOption);
        }

        if prk.len() < self.prk_size() {
            return Err(Error::InvalidLength);
        }

        self.check_output(length)?;

        Ok(hash)
    }
}

// T(i) = HMAC(PRK, T(i - 1) || info || i), from T(0) empty, until out is full. T(1) alone is a
// single HMAC call; otherwise the key blocks are compressed once, and each message is built in a
// buffer that holds info from the start and takes T(i - 1) and i before each call.
#[cfg(feature = "hkdf")]
fn expand_unchecked(hash: &HashAlgorithm, prk: &[u8], info: &[u8], out: &mut [u8]) {
    let size = hash.digest_size();

    let mut message = [0; MESSAGE];

    let length = info.len();

    if out.len() <= size && length < MESSAGE {
        message[..length].copy_from_slice(info);

        message[length] = 1;

        let mut t = [0; 64];

        hmac(hash, prk, &message[..length + 1], &mut t[..size]);

        out.copy_from_slice(&t[..out.len()]);

        wipe(&mut t);

        return;
    }

    let mut hashed = [0; 64];

    let keyed = Keyed::new(hash, block_key(hash, prk, &mut hashed));

    wipe(&mut hashed);

    let fits = size + length < MESSAGE;

    if fits {
        message[size..size + length].copy_from_slice(info);
    }

    let mut t = [0; 64];

    for (i, chunk) in out.chunks_mut(size).enumerate() {
        let counter = i as u8 + 1;

        let previous = if i == 0 { 0 } else { size };

        if fits {
            message[size + length] = counter;

            keyed.mac(&message[size - previous..size + length + 1], &mut t[..size]);

            message[..size].copy_from_slice(&t[..size]);
        } else {
            let mut next = [0; 64];

            keyed.stream(&[&t[..previous], info, &[counter]], &mut next[..size]);

            t = next;

            wipe(&mut next);
        }

        chunk.copy_from_slice(&t[..chunk.len()]);
    }

    wipe(&mut t);

    wipe(&mut message);
}

// The messages of expand: T(i - 1), info and the counter byte together, when they fit.
#[cfg(feature = "hkdf")]
const MESSAGE: usize = 256;

// HMAC's states after the inner and the outer key block of a PRK, wiped when dropped.
#[cfg(feature = "hkdf")]
enum Keyed {
    Sha256([[u32; 8]; 2]),
    Sha512([[u64; 8]; 2]),
}

#[cfg(feature = "hkdf")]
impl Keyed {
    fn new(hash: &HashAlgorithm, key: &[u8]) -> Self {
        match hash.kind {
            Kind::Sha256(iv) => Self::Sha256(sha2::keyed256(iv, key)),
            Kind::Sha512(iv) => Self::Sha512(sha2::keyed512(iv, key)),
            _ => unreachable!("HKDF is defined here over SHA-2 only"),
        }
    }

    // The tag of data, tag.len() bytes: the hash's digest size.
    fn mac(&self, data: &[u8], tag: &mut [u8]) {
        match self {
            Self::Sha256(keyed) => sha2::hmac256_keyed(keyed, data, tag),
            Self::Sha512(keyed) => sha2::hmac512_keyed(keyed, data, tag),
        }
    }

    // The tag of the concatenated parts, which an engine absorbs one after the other.
    fn stream(&self, parts: &[&[u8]], tag: &mut [u8]) {
        let mut inner = [0; 64];

        let inner = &mut inner[..tag.len()];

        match self {
            Self::Sha256(keyed) => {
                let mut engine = Sha256::resume(keyed[0], 64);

                for part in parts {
                    engine.update(part);
                }

                engine.digest_into(inner);

                finish256(&keyed[1], 64, inner, tag);
            }
            Self::Sha512(keyed) => {
                let mut engine = Sha512::resume(keyed[0], 128);

                for part in parts {
                    engine.update(part);
                }

                engine.digest_into(inner);

                finish512(&keyed[1], 128, inner, tag);
            }
        }

        wipe(inner);
    }
}

#[cfg(feature = "hkdf")]
impl Drop for Keyed {
    fn drop(&mut self) {
        match self {
            Self::Sha256(keyed) => wipe(keyed.as_flattened_mut()),
            Self::Sha512(keyed) => wipe(keyed.as_flattened_mut()),
        }
    }
}

/// HKDF with HMAC-SHA-256 (RFC 5869).
#[cfg(feature = "hkdf")]
pub const HKDF_SHA_256: KdfAlgorithm = KdfAlgorithm {
    name: "HKDF-SHA-256",
    kind: KdfKind::Hkdf(SHA_256),
};

/// HKDF with HMAC-SHA-384 (RFC 5869).
#[cfg(feature = "hkdf")]
pub const HKDF_SHA_384: KdfAlgorithm = KdfAlgorithm {
    name: "HKDF-SHA-384",
    kind: KdfKind::Hkdf(SHA_384),
};

/// HKDF with HMAC-SHA-512 (RFC 5869).
#[cfg(feature = "hkdf")]
pub const HKDF_SHA_512: KdfAlgorithm = KdfAlgorithm {
    name: "HKDF-SHA-512",
    kind: KdfKind::Hkdf(SHA_512),
};

/// BLAKE3-KDF: BLAKE3's `derive_key` mode, with the `info` option as its context string.
#[cfg(feature = "blake3")]
pub const BLAKE3_KDF: KdfAlgorithm = KdfAlgorithm {
    name: "BLAKE3-KDF",
    kind: KdfKind::Blake3,
};

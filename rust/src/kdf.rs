use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::cpu::Dit;
use crate::error::Error;
use crate::hash::{HashAlgorithm, Kind, SHA_256, SHA_384, SHA_512};
use crate::mac::{block_key, hmac};
use crate::sha2::{self, Sha256, Sha512, finish256, finish512};
use crate::wipe::wipe;

// HKDF (RFC 5869) over HMAC with SHA-2. The PRK, every T(i) and the keyed states are secret and
// wiped; one DIT guard covers each public call.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KdfAlgorithm {
    name: &'static str,
    hash: HashAlgorithm,
}

impl fmt::Debug for KdfAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KdfAlgorithm").field(&self.name).finish()
    }
}

// An empty salt is HashLen zero bytes (RFC 5869, 2.2). Extract takes no info and Expand no salt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KdfOptions<'a> {
    pub salt: &'a [u8],
    pub info: &'a [u8],
}

impl KdfAlgorithm {
    pub const fn name(&self) -> &'static str {
        self.name
    }

    // The size of a pseudorandom key, HashLen.
    pub const fn prk_size(&self) -> usize {
        self.hash.digest_size()
    }

    // RFC 5869, 2.3: L is at most 255 HashLen; an empty output is refused as well.
    fn check_output(&self, length: usize) -> Result<(), Error> {
        if length == 0 || length > 255 * self.prk_size() {
            Err(Error::InvalidLength)
        } else {
            Ok(())
        }
    }

    pub fn derive(
        &self,
        ikm: &[u8],
        length: usize,
        options: &KdfOptions,
    ) -> Result<Vec<u8>, Error> {
        self.check_output(length)?;

        let mut out = vec![0; length];

        self.derive_into(ikm, &mut out, options)?;

        Ok(out)
    }

    // Extract and then Expand into out, whose length is L.
    pub fn derive_into(
        &self,
        ikm: &[u8],
        out: &mut [u8],
        options: &KdfOptions,
    ) -> Result<(), Error> {
        self.check_output(out.len())?;

        let _dit = Dit::new();

        let mut prk = [0; 64];

        let size = self.prk_size();

        hmac(&self.hash, options.salt, ikm, &mut prk[..size]);

        self.expand_unchecked(&prk[..size], options.info, out);

        wipe(&mut prk);

        Ok(())
    }

    pub fn extract(&self, ikm: &[u8], options: &KdfOptions) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; self.prk_size()];

        self.extract_into(ikm, &mut out, options)?;

        Ok(out)
    }

    // PRK = HMAC(salt, IKM) into out, which must be prk_size() bytes.
    pub fn extract_into(
        &self,
        ikm: &[u8],
        out: &mut [u8],
        options: &KdfOptions,
    ) -> Result<(), Error> {
        if !options.info.is_empty() {
            return Err(Error::InvalidOption);
        }

        if out.len() != self.prk_size() {
            return Err(Error::InvalidLength);
        }

        let _dit = Dit::new();

        hmac(&self.hash, options.salt, ikm, out);

        Ok(())
    }

    pub fn expand(
        &self,
        prk: &[u8],
        length: usize,
        options: &KdfOptions,
    ) -> Result<Vec<u8>, Error> {
        self.check_output(length)?;

        let mut out = vec![0; length];

        self.expand_into(prk, &mut out, options)?;

        Ok(out)
    }

    // RFC 5869, 2.3: a PRK of at least HashLen bytes.
    pub fn expand_into(
        &self,
        prk: &[u8],
        out: &mut [u8],
        options: &KdfOptions,
    ) -> Result<(), Error> {
        if !options.salt.is_empty() {
            return Err(Error::InvalidOption);
        }

        if prk.len() < self.prk_size() {
            return Err(Error::InvalidLength);
        }

        self.check_output(out.len())?;

        let _dit = Dit::new();

        self.expand_unchecked(prk, options.info, out);

        Ok(())
    }

    // T(i) = HMAC(PRK, T(i - 1) || info || i), from T(0) empty, until out is full. T(1) alone is
    // a single HMAC call; otherwise the key blocks are compressed once, and each message is built
    // in a buffer that holds info from the start and takes T(i - 1) and i before each call.
    fn expand_unchecked(&self, prk: &[u8], info: &[u8], out: &mut [u8]) {
        let size = self.prk_size();

        let mut message = [0; MESSAGE];

        let length = info.len();

        if out.len() <= size && length < MESSAGE {
            message[..length].copy_from_slice(info);

            message[length] = 1;

            let mut t = [0; 64];

            hmac(&self.hash, prk, &message[..length + 1], &mut t[..size]);

            out.copy_from_slice(&t[..out.len()]);

            wipe(&mut t);

            return;
        }

        let mut hashed = [0; 64];

        let keyed = Keyed::new(&self.hash, block_key(&self.hash, prk, &mut hashed));

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
}

// The messages of expand: T(i - 1), info and the counter byte together, when they fit.
const MESSAGE: usize = 256;

// HMAC's states after the inner and the outer key block of a PRK, wiped when dropped.
enum Keyed {
    Sha256([[u32; 8]; 2]),
    Sha512([[u64; 8]; 2]),
}

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

impl Drop for Keyed {
    fn drop(&mut self) {
        match self {
            Self::Sha256(keyed) => wipe(keyed.as_flattened_mut()),
            Self::Sha512(keyed) => wipe(keyed.as_flattened_mut()),
        }
    }
}

pub const HKDF_SHA_256: KdfAlgorithm = KdfAlgorithm {
    name: "HKDF-SHA-256",
    hash: SHA_256,
};

pub const HKDF_SHA_384: KdfAlgorithm = KdfAlgorithm {
    name: "HKDF-SHA-384",
    hash: SHA_384,
};

pub const HKDF_SHA_512: KdfAlgorithm = KdfAlgorithm {
    name: "HKDF-SHA-512",
    hash: SHA_512,
};

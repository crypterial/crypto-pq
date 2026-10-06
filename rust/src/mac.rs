use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::blake2;
use crate::cpu::Dit;
use crate::ct;
use crate::error::Error;
use crate::hash::{
    Engine, HashAlgorithm, Kind, SHA_224, SHA_256, SHA_384, SHA_512, check_length, field,
};
use crate::keccak::Keccak;
use crate::sha2::{self, Sha256, Sha512, finish256, finish512};
use crate::sp800_185;
use crate::wipe::wipe;

#[derive(Clone, Copy, PartialEq, Eq)]
enum MacKind {
    Hmac(HashAlgorithm),
    // The state after cSHAKE's prefix for the function name "KMAC" and the customization.
    Kmac {
        prefix: [u64; 25],
        rate: usize,
        xof: bool,
    },
    // The chaining value of the configured length, salt and personalization, before the key
    // length is added.
    Blake2b([u64; 8]),
    Blake2s([u32; 8]),
}

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

// length: the tag size in bytes, None for the default (KMAC128 32, KMAC256 64, BLAKE2b 64,
// BLAKE2s 32). KMAC takes a customization and xof (KMACXOF); BLAKE2 a salt and personalization.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MacOptions<'a> {
    pub length: Option<usize>,
    pub customization: &'a [u8],
    pub xof: bool,
    pub salt: &'a [u8],
    pub personalization: &'a [u8],
}

// RFC 2104: a key longer than a block is replaced by its hash, which `hashed` then holds.
pub(crate) fn block_key<'a>(
    hash: &HashAlgorithm,
    key: &'a [u8],
    hashed: &'a mut [u8; 64],
) -> &'a [u8] {
    if key.len() <= hash.block_size() {
        return key;
    }

    let hashed = &mut hashed[..hash.digest_size];

    hash.digest_into(key, hashed);

    hashed
}

// HMAC over SHA-2 of data, out.len() bytes: the hash's digest size.
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

// Every keyed computation runs under DIT. Each public method takes the guard once, around
// everything it does with the key, and the functions it calls take none of their own.
impl MacAlgorithm {
    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn digest_size(&self) -> usize {
        self.size
    }

    // The algorithm with these options in place of any set before. HMAC takes no options.
    pub fn configure(&self, options: &MacOptions) -> Result<Self, Error> {
        let MacOptions {
            length,
            customization,
            xof,
            salt,
            personalization,
        } = *options;

        let (size, kind) = match self.kind {
            MacKind::Hmac(_) if *options == MacOptions::default() => return Ok(*self),
            MacKind::Hmac(_) => return Err(Error::InvalidOption),
            MacKind::Kmac { rate, .. } => {
                // SP 800-185, 8.4.2: a tag shall not be shorter than 32 bits.
                let size = length.unwrap_or(if rate == 168 { 32 } else { 64 });

                if size < 4 || !salt.is_empty() || !personalization.is_empty() {
                    return Err(Error::InvalidOption);
                }

                let prefix = sp800_185::prefix(rate, b"KMAC", customization)
                    .expect("the function name is not empty");

                (size, MacKind::Kmac { prefix, rate, xof })
            }
            MacKind::Blake2b(_) => {
                let size = length.unwrap_or(64);

                if !(1..=64).contains(&size) || !customization.is_empty() || xof {
                    return Err(Error::InvalidOption);
                }

                let h = blake2::start64(size, field(salt, 16)?, field(personalization, 16)?);

                (size, MacKind::Blake2b(h))
            }
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

    // RFC 7693, 2.1: a BLAKE2 key has 1 to 64 (BLAKE2b) or 32 (BLAKE2s) bytes. HMAC and KMAC take
    // keys of any length.
    const fn maximum_key(&self) -> usize {
        match self.kind {
            MacKind::Blake2b(_) => 64,
            MacKind::Blake2s(_) => 32,
            _ => usize::MAX,
        }
    }

    const fn key_fits(&self, key: &[u8]) -> bool {
        match self.kind {
            MacKind::Blake2b(_) | MacKind::Blake2s(_) => {
                !key.is_empty() && key.len() <= self.maximum_key()
            }
            _ => true,
        }
    }

    // The methods without an error result refuse a key of another length as a programming error.
    fn check_key(&self, key: &[u8]) {
        assert!(
            self.key_fits(key),
            "INVALID_LENGTH: the key of {} must be 1 to {} bytes",
            self.name,
            self.maximum_key()
        );
    }

    pub fn digest(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = vec![0; self.size];

        self.digest_into(key, data, &mut out);

        out
    }

    pub fn digest_into(&self, key: &[u8], data: &[u8], out: &mut [u8]) {
        check_length(out.len(), self.size);

        self.check_key(key);

        let _dit = Dit::new();

        self.mac(key, data, out);
    }

    pub fn create(&self, key: &[u8]) -> Mac {
        self.check_key(key);

        let _dit = Dit::new();

        let engine = match &self.kind {
            MacKind::Hmac(hash) => keyed_hmac(hash, key),
            MacKind::Kmac { prefix, rate, xof } => MacEngine::Kmac {
                engine: sp800_185::keyed(prefix, *rate, key),
                xof: *xof,
            },
            MacKind::Blake2b(h) => MacEngine::Blake2b(blake2::Engine::keyed(h, key)),
            MacKind::Blake2s(h) => MacEngine::Blake2s(blake2::Engine::keyed(h, key)),
        };

        Mac {
            engine,
            size: self.size,
        }
    }

    // Constant time over the whole tag, which must have the full length. A key of a length the
    // algorithm does not take verifies nothing.
    pub fn verify(&self, key: &[u8], data: &[u8], tag: &[u8]) -> bool {
        if !self.key_fits(key) || tag.len() != self.size {
            return false;
        }

        let _dit = Dit::new();

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

    fn mac(&self, key: &[u8], data: &[u8], out: &mut [u8]) {
        match &self.kind {
            MacKind::Hmac(hash) => hmac(hash, key, data, out),
            MacKind::Kmac { prefix, rate, xof } => {
                sp800_185::kmac(prefix, *rate, key, data, *xof, out);
            }
            MacKind::Blake2b(h) => blake2::mac(h, key, data, out),
            MacKind::Blake2s(h) => blake2::mac(h, key, data, out),
        }
    }
}

// HMAC's inner engine after the inner key block, and the state after the outer one.
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

    MacEngine::Hmac { inner, outer }
}

// HMAC's state after the outer key block, wiped when dropped.
enum Outer {
    Sha256([u32; 8]),
    Sha512([u64; 8]),
}

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
    Hmac { inner: Engine, outer: Outer },
    Kmac { engine: Keccak, xof: bool },
    Blake2b(blake2::Engine<u64>),
    Blake2s(blake2::Engine<u32>),
}

pub struct Mac {
    engine: MacEngine,
    size: usize,
}

impl Mac {
    pub fn update(&mut self, data: &[u8]) {
        let _dit = Dit::new();

        match &mut self.engine {
            MacEngine::Hmac { inner, .. } => inner.update(data),
            MacEngine::Kmac { engine, .. } => engine.update(data),
            MacEngine::Blake2b(engine) => engine.update(data),
            MacEngine::Blake2s(engine) => engine.update(data),
        }
    }

    pub fn digest(&self) -> Vec<u8> {
        let mut out = vec![0; self.size];

        self.digest_into(&mut out);

        out
    }

    pub fn digest_into(&self, out: &mut [u8]) {
        check_length(out.len(), self.size);

        let _dit = Dit::new();

        self.finish(out);
    }

    pub fn verify(&self, tag: &[u8]) -> bool {
        if tag.len() != self.size {
            return false;
        }

        let _dit = Dit::new();

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
            MacEngine::Hmac { inner, outer } => {
                let mut digest = [0; 64];

                let inner_digest = &mut digest[..self.size];

                inner.digest_into(inner_digest);

                match outer {
                    Outer::Sha256(state) => finish256(state, 64, inner_digest, out),
                    Outer::Sha512(state) => finish512(state, 128, inner_digest, out),
                }

                wipe(&mut digest);
            }
            MacEngine::Kmac { engine, xof } => {
                let mut engine = engine.clone();

                engine.update(sp800_185::output_length(*xof, self.size).as_slice());

                engine.read(out);
            }
            MacEngine::Blake2b(engine) => engine.finish(out),
            MacEngine::Blake2s(engine) => engine.finish(out),
        }
    }
}

const fn hmac_algorithm(name: &'static str, hash: HashAlgorithm) -> MacAlgorithm {
    MacAlgorithm {
        name,
        size: hash.digest_size,
        kind: MacKind::Hmac(hash),
    }
}

pub const HMAC_SHA_224: MacAlgorithm = hmac_algorithm("HMAC-SHA-224", SHA_224);

pub const HMAC_SHA_256: MacAlgorithm = hmac_algorithm("HMAC-SHA-256", SHA_256);

pub const HMAC_SHA_384: MacAlgorithm = hmac_algorithm("HMAC-SHA-384", SHA_384);

pub const HMAC_SHA_512: MacAlgorithm = hmac_algorithm("HMAC-SHA-512", SHA_512);

pub const KMAC128: MacAlgorithm = MacAlgorithm {
    name: "KMAC128",
    size: 32,
    kind: MacKind::Kmac {
        prefix: sp800_185::kmac_prefix(168),
        rate: 168,
        xof: false,
    },
};

pub const KMAC256: MacAlgorithm = MacAlgorithm {
    name: "KMAC256",
    size: 64,
    kind: MacKind::Kmac {
        prefix: sp800_185::kmac_prefix(136),
        rate: 136,
        xof: false,
    },
};

pub const BLAKE2B_MAC: MacAlgorithm = MacAlgorithm {
    name: "BLAKE2b-MAC",
    size: 64,
    kind: MacKind::Blake2b(blake2::start64(64, &[], &[])),
};

pub const BLAKE2S_MAC: MacAlgorithm = MacAlgorithm {
    name: "BLAKE2s-MAC",
    size: 32,
    kind: MacKind::Blake2s(blake2::start32(32, &[], &[])),
};

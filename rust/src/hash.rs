use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::ascon;
use crate::blake2;
use crate::error::Error;
use crate::keccak::Keccak;
use crate::sha2::{
    IV_224, IV_256, IV_384, IV_512, IV_512_224, IV_512_256, Sha256, Sha512, finish256, finish512,
};
use crate::sp800_185;

const SHA3_SUFFIX: u8 = 0x06;

const SHAKE_SUFFIX: u8 = 0x1F;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Sha256(&'static [u32; 8]),
    Sha512(&'static [u64; 8]),
    Sha3,
    // The chaining value after the parameter block.
    Blake2b([u64; 8]),
    Blake2s([u32; 8]),
    Ascon,
}

#[derive(Clone)]
pub(crate) enum Engine {
    Sha256(Sha256),
    Sha512(Sha512),
    Keccak(Keccak),
    Blake2b(blake2::Engine<u64>),
    Blake2s(blake2::Engine<u32>),
    Ascon(ascon::Sponge),
}

impl Engine {
    pub(crate) fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(engine) => engine.update(data),
            Self::Sha512(engine) => engine.update(data),
            Self::Keccak(engine) => engine.update(data),
            Self::Blake2b(engine) => engine.update(data),
            Self::Blake2s(engine) => engine.update(data),
            Self::Ascon(sponge) => sponge.update(data),
        }
    }

    pub(crate) fn digest_into(&self, out: &mut [u8]) {
        match self {
            Self::Sha256(engine) => engine.digest_into(out),
            Self::Sha512(engine) => engine.digest_into(out),
            Self::Keccak(engine) => engine.clone().read(out),
            Self::Blake2b(engine) => engine.finish(out),
            Self::Blake2s(engine) => engine.finish(out),
            Self::Ascon(sponge) => sponge.clone().read(out),
        }
    }
}

// An output buffer of another size is a programming error, as in copy_from_slice.
pub(crate) fn check_length(actual: usize, expected: usize) {
    assert!(
        actual == expected,
        "INVALID_LENGTH: the output must be exactly the digest size"
    );
}

// A BLAKE2 salt or personalization of at most `size` bytes, which the parameter block zero-pads.
pub(crate) fn field(bytes: &[u8], size: usize) -> Result<&[u8], Error> {
    if bytes.len() <= size {
        Ok(bytes)
    } else {
        Err(Error::InvalidOption)
    }
}

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

// BLAKE2's salt and personalization, at most 16 bytes each for BLAKE2b and 8 for BLAKE2s.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HashOptions<'a> {
    pub salt: &'a [u8],
    pub personalization: &'a [u8],
}

impl HashAlgorithm {
    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn digest_size(&self) -> usize {
        self.digest_size
    }

    pub(crate) const fn oid_arc(&self) -> u8 {
        self.oid_arc
    }

    // The algorithm with these options in place of any set before. Hash functions without
    // options take only the empty ones.
    pub fn configure(&self, options: &HashOptions) -> Result<Self, Error> {
        let (salt, personalization) = (options.salt, options.personalization);

        let kind = match self.kind {
            Kind::Blake2b(_) => Kind::Blake2b(blake2::start64(
                self.digest_size,
                field(salt, 16)?,
                field(personalization, 16)?,
            )),
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

    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0; self.digest_size];

        self.digest_into(data, &mut out);

        out
    }

    // The same digest written into out, which must be digest_size() bytes, without allocating.
    pub fn digest_into(&self, data: &[u8], out: &mut [u8]) {
        check_length(out.len(), self.digest_size);

        match &self.kind {
            Kind::Sha256(iv) => finish256(iv, 0, data, out),
            Kind::Sha512(iv) => finish512(iv, 0, data, out),
            Kind::Sha3 => Keccak::digest_into(self.block_size(), SHA3_SUFFIX, data, out),
            Kind::Blake2b(h) => blake2::digest(h, data, out),
            Kind::Blake2s(h) => blake2::digest(h, data, out),
            Kind::Ascon => ascon::digest(&ascon::HASH256, data, out),
        }
    }

    pub fn create(&self) -> Hasher {
        let engine = match &self.kind {
            Kind::Sha256(iv) => Engine::Sha256(Sha256::new(iv)),
            Kind::Sha512(iv) => Engine::Sha512(Sha512::new(iv)),
            Kind::Sha3 => Engine::Keccak(Keccak::new(self.block_size(), SHA3_SUFFIX)),
            Kind::Blake2b(h) => Engine::Blake2b(blake2::Engine::new(h)),
            Kind::Blake2s(h) => Engine::Blake2s(blake2::Engine::new(h)),
            Kind::Ascon => Engine::Ascon(ascon::Sponge::new(&ascon::HASH256)),
        };

        Hasher {
            engine,
            size: self.digest_size,
        }
    }

    // The block size of HMAC's key blocks, and the rate of SHA-3.
    pub(crate) const fn block_size(&self) -> usize {
        match self.kind {
            Kind::Sha256(_) | Kind::Blake2s(_) => 64,
            Kind::Sha512(_) | Kind::Blake2b(_) => 128,
            Kind::Sha3 => 200 - 2 * self.digest_size,
            Kind::Ascon => 8,
        }
    }
}

pub struct Hasher {
    engine: Engine,
    size: usize,
}

impl Hasher {
    pub fn update(&mut self, data: &[u8]) {
        self.engine.update(data);
    }

    pub fn digest(&self) -> Vec<u8> {
        let mut out = vec![0; self.size];

        self.engine.digest_into(&mut out);

        out
    }

    pub fn digest_into(&self, out: &mut [u8]) {
        check_length(out.len(), self.size);

        self.engine.digest_into(out);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum XofKind {
    Shake,
    // The state after cSHAKE's prefix, or None when the function name and the customization are
    // both empty, which makes cSHAKE equal to SHAKE.
    CShake(Option<[u64; 25]>),
    AsconXof,
    // The state after the customization string.
    AsconCxof([u64; 5]),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct XofAlgorithm {
    name: &'static str,
    rate: usize,
    kind: XofKind,
    oid_arc: u8,
}

impl fmt::Debug for XofAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("XofAlgorithm").field(&self.name).finish()
    }
}

// The customization string S of cSHAKE (any length) and of Ascon-CXOF128 (at most 256 bytes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XofOptions<'a> {
    pub customization: &'a [u8],
}

impl XofAlgorithm {
    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub(crate) const fn oid_arc(&self) -> u8 {
        self.oid_arc
    }

    // The algorithm with this customization in place of any set before; XOFs without one take
    // only the empty string. cSHAKE's function name N is reserved for NIST: only hazmat sets it.
    pub fn configure(&self, options: &XofOptions) -> Result<Self, Error> {
        let customization = options.customization;

        let kind = match self.kind {
            XofKind::CShake(_) => XofKind::CShake(sp800_185::prefix(self.rate, &[], customization)),
            XofKind::AsconCxof(_) if customization.len() <= ascon::MAX_CUSTOMIZATION => {
                XofKind::AsconCxof(ascon::customize(customization))
            }
            _ if customization.is_empty() => return Ok(*self),
            _ => return Err(Error::InvalidOption),
        };

        Ok(Self { kind, ..*self })
    }

    pub(crate) fn configure_cshake(
        &self,
        name: &[u8],
        customization: &[u8],
    ) -> Result<Self, Error> {
        match self.kind {
            XofKind::CShake(_) => Ok(Self {
                kind: XofKind::CShake(sp800_185::prefix(self.rate, name, customization)),
                ..*self
            }),
            _ => Err(Error::InvalidOption),
        }
    }

    pub fn digest(&self, data: &[u8], length: usize) -> Vec<u8> {
        let mut out = vec![0; length];

        self.digest_into(data, &mut out);

        out
    }

    // out.len() bytes of output, without allocating.
    pub fn digest_into(&self, data: &[u8], out: &mut [u8]) {
        match &self.kind {
            XofKind::Shake | XofKind::CShake(None) => {
                Keccak::digest_into(self.rate, SHAKE_SUFFIX, data, out);
            }
            XofKind::CShake(Some(start)) => {
                Keccak::digest_from(start, self.rate, sp800_185::SUFFIX, data, out);
            }
            XofKind::AsconXof => ascon::digest(&ascon::XOF128, data, out),
            XofKind::AsconCxof(start) => ascon::digest(start, data, out),
        }
    }

    pub fn create(&self) -> Xof {
        let engine = match &self.kind {
            XofKind::Shake | XofKind::CShake(None) => {
                Engine::Keccak(Keccak::new(self.rate, SHAKE_SUFFIX))
            }
            XofKind::CShake(Some(start)) => {
                Engine::Keccak(Keccak::resume(*start, self.rate, sp800_185::SUFFIX))
            }
            XofKind::AsconXof => Engine::Ascon(ascon::Sponge::new(&ascon::XOF128)),
            XofKind::AsconCxof(start) => Engine::Ascon(ascon::Sponge::new(start)),
        };

        Xof { engine }
    }
}

pub struct Xof {
    engine: Engine,
}

impl Xof {
    pub fn update(&mut self, data: &[u8]) {
        self.engine.update(data);
    }

    pub fn read(&mut self, length: usize) -> Vec<u8> {
        let mut out = vec![0; length];

        self.read_into(&mut out);

        out
    }

    pub fn read_into(&mut self, out: &mut [u8]) {
        match &mut self.engine {
            Engine::Keccak(engine) => engine.read(out),
            Engine::Ascon(sponge) => sponge.read(out),
            _ => unreachable!("an XOF is a Keccak or Ascon sponge"),
        }
    }
}

pub const SHA_224: HashAlgorithm = HashAlgorithm {
    name: "SHA-224",
    digest_size: 28,
    kind: Kind::Sha256(&IV_224),
    oid_arc: 4,
};

pub const SHA_256: HashAlgorithm = HashAlgorithm {
    name: "SHA-256",
    digest_size: 32,
    kind: Kind::Sha256(&IV_256),
    oid_arc: 1,
};

pub const SHA_384: HashAlgorithm = HashAlgorithm {
    name: "SHA-384",
    digest_size: 48,
    kind: Kind::Sha512(&IV_384),
    oid_arc: 2,
};

pub const SHA_512: HashAlgorithm = HashAlgorithm {
    name: "SHA-512",
    digest_size: 64,
    kind: Kind::Sha512(&IV_512),
    oid_arc: 3,
};

pub const SHA_512_224: HashAlgorithm = HashAlgorithm {
    name: "SHA-512/224",
    digest_size: 28,
    kind: Kind::Sha512(&IV_512_224),
    oid_arc: 5,
};

pub const SHA_512_256: HashAlgorithm = HashAlgorithm {
    name: "SHA-512/256",
    digest_size: 32,
    kind: Kind::Sha512(&IV_512_256),
    oid_arc: 6,
};

pub const SHA3_224: HashAlgorithm = HashAlgorithm {
    name: "SHA3-224",
    digest_size: 28,
    kind: Kind::Sha3,
    oid_arc: 7,
};

pub const SHA3_256: HashAlgorithm = HashAlgorithm {
    name: "SHA3-256",
    digest_size: 32,
    kind: Kind::Sha3,
    oid_arc: 8,
};

pub const SHA3_384: HashAlgorithm = HashAlgorithm {
    name: "SHA3-384",
    digest_size: 48,
    kind: Kind::Sha3,
    oid_arc: 9,
};

pub const SHA3_512: HashAlgorithm = HashAlgorithm {
    name: "SHA3-512",
    digest_size: 64,
    kind: Kind::Sha3,
    oid_arc: 10,
};

// RFC 7693, 4: BLAKE2b and BLAKE2s at their recommended digest sizes, unkeyed.
const fn blake2b(name: &'static str, digest_size: usize) -> HashAlgorithm {
    HashAlgorithm {
        name,
        digest_size,
        kind: Kind::Blake2b(blake2::start64(digest_size, &[], &[])),
        oid_arc: 0,
    }
}

const fn blake2s(name: &'static str, digest_size: usize) -> HashAlgorithm {
    HashAlgorithm {
        name,
        digest_size,
        kind: Kind::Blake2s(blake2::start32(digest_size, &[], &[])),
        oid_arc: 0,
    }
}

pub const BLAKE2B_160: HashAlgorithm = blake2b("BLAKE2b-160", 20);

pub const BLAKE2B_256: HashAlgorithm = blake2b("BLAKE2b-256", 32);

pub const BLAKE2B_384: HashAlgorithm = blake2b("BLAKE2b-384", 48);

pub const BLAKE2B_512: HashAlgorithm = blake2b("BLAKE2b-512", 64);

pub const BLAKE2S_128: HashAlgorithm = blake2s("BLAKE2s-128", 16);

pub const BLAKE2S_160: HashAlgorithm = blake2s("BLAKE2s-160", 20);

pub const BLAKE2S_224: HashAlgorithm = blake2s("BLAKE2s-224", 28);

pub const BLAKE2S_256: HashAlgorithm = blake2s("BLAKE2s-256", 32);

pub const ASCON_HASH256: HashAlgorithm = HashAlgorithm {
    name: "Ascon-Hash256",
    digest_size: 32,
    kind: Kind::Ascon,
    oid_arc: 0,
};

pub const SHAKE128: XofAlgorithm = XofAlgorithm {
    name: "SHAKE128",
    rate: 168,
    kind: XofKind::Shake,
    oid_arc: 11,
};

pub const SHAKE256: XofAlgorithm = XofAlgorithm {
    name: "SHAKE256",
    rate: 136,
    kind: XofKind::Shake,
    oid_arc: 12,
};

pub const CSHAKE128: XofAlgorithm = XofAlgorithm {
    name: "cSHAKE128",
    rate: 168,
    kind: XofKind::CShake(None),
    oid_arc: 0,
};

pub const CSHAKE256: XofAlgorithm = XofAlgorithm {
    name: "cSHAKE256",
    rate: 136,
    kind: XofKind::CShake(None),
    oid_arc: 0,
};

pub const ASCON_XOF128: XofAlgorithm = XofAlgorithm {
    name: "Ascon-XOF128",
    rate: 8,
    kind: XofKind::AsconXof,
    oid_arc: 0,
};

pub const ASCON_CXOF128: XofAlgorithm = XofAlgorithm {
    name: "Ascon-CXOF128",
    rate: 8,
    kind: XofKind::AsconCxof(ascon::customize(&[])),
    oid_arc: 0,
};

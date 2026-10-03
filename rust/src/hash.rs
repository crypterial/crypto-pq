use alloc::vec;
use alloc::vec::Vec;

use crate::ct;
use crate::keccak::Keccak;
use crate::sha2::{IV_224, IV_256, IV_384, IV_512, IV_512_224, IV_512_256, Sha256, Sha512};
use crate::wipe::wipe;

const SHA3_SUFFIX: u8 = 0x06;

const SHAKE_SUFFIX: u8 = 0x1F;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Sha256(&'static [u32; 8]),
    Sha512(&'static [u64; 8]),
    Sha3,
}

#[derive(Clone)]
enum Engine {
    Sha256(Sha256),
    Sha512(Sha512),
    Keccak(Keccak),
}

impl Engine {
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(engine) => engine.update(data),
            Self::Sha512(engine) => engine.update(data),
            Self::Keccak(engine) => engine.update(data),
        }
    }

    fn digest(&self, size: usize) -> Vec<u8> {
        match self {
            Self::Sha256(engine) => engine.digest()[..size].to_vec(),
            Self::Sha512(engine) => engine.digest()[..size].to_vec(),
            Self::Keccak(engine) => {
                let mut out = vec![0; size];

                engine.clone().read(&mut out);

                out
            }
        }
    }
}

// oid_arc is the last arc of the NIST identifier 2.16.840.1.101.3.4.2.x, which pre-hashed
// signatures embed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashAlgorithm {
    name: &'static str,
    digest_size: usize,
    kind: Kind,
    oid_arc: u8,
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

    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = self.create();

        hasher.update(data);

        hasher.digest()
    }

    pub fn create(&self) -> Hasher {
        let engine = match self.kind {
            Kind::Sha256(iv) => Engine::Sha256(Sha256::new(iv)),
            Kind::Sha512(iv) => Engine::Sha512(Sha512::new(iv)),
            Kind::Sha3 => Engine::Keccak(Keccak::new(self.block_size(), SHA3_SUFFIX)),
        };

        Hasher {
            engine,
            size: self.digest_size,
        }
    }

    const fn block_size(&self) -> usize {
        match self.kind {
            Kind::Sha256(_) => 64,
            Kind::Sha512(_) => 128,
            Kind::Sha3 => 200 - 2 * self.digest_size,
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
        self.engine.digest(self.size)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XofAlgorithm {
    name: &'static str,
    rate: usize,
    oid_arc: u8,
}

impl XofAlgorithm {
    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub(crate) const fn oid_arc(&self) -> u8 {
        self.oid_arc
    }

    pub fn digest(&self, data: &[u8], length: usize) -> Vec<u8> {
        let mut xof = self.create();

        xof.update(data);

        xof.read(length)
    }

    pub fn create(&self) -> Xof {
        Xof {
            engine: Keccak::new(self.rate, SHAKE_SUFFIX),
        }
    }
}

pub struct Xof {
    engine: Keccak,
}

impl Xof {
    pub fn update(&mut self, data: &[u8]) {
        self.engine.update(data);
    }

    pub fn read(&mut self, length: usize) -> Vec<u8> {
        let mut out = vec![0; length];

        self.engine.read(&mut out);

        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HmacAlgorithm {
    name: &'static str,
    hash: HashAlgorithm,
}

impl HmacAlgorithm {
    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn digest_size(&self) -> usize {
        self.hash.digest_size
    }

    pub fn digest(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut hmac = self.create(key);

        hmac.update(data);

        hmac.digest()
    }

    pub fn create(&self, key: &[u8]) -> Hmac {
        let block = self.hash.block_size();

        let mut pad = [0u8; 128];

        if key.len() > block {
            let mut digest = self.hash.digest(key);

            pad[..digest.len()].copy_from_slice(&digest);

            wipe(&mut digest);
        } else {
            pad[..key.len()].copy_from_slice(key);
        }

        pad.iter_mut().for_each(|b| *b ^= 0x36);

        let mut inner = self.hash.create();

        inner.update(&pad[..block]);

        pad.iter_mut().for_each(|b| *b ^= 0x36 ^ 0x5C);

        let mut outer = self.hash.create();

        outer.update(&pad[..block]);

        wipe(&mut pad);

        Hmac { inner, outer }
    }

    pub fn verify(&self, key: &[u8], data: &[u8], tag: &[u8]) -> bool {
        let mut hmac = self.create(key);

        hmac.update(data);

        hmac.verify(tag)
    }
}

pub struct Hmac {
    inner: Hasher,
    outer: Hasher,
}

impl Hmac {
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn digest(&self) -> Vec<u8> {
        let mut outer = self.outer.engine.clone();

        outer.update(&self.inner.digest());

        outer.digest(self.outer.size)
    }

    pub fn verify(&self, tag: &[u8]) -> bool {
        ct::equal(&self.digest(), tag)
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

pub const SHAKE128: XofAlgorithm = XofAlgorithm {
    name: "SHAKE128",
    rate: 168,
    oid_arc: 11,
};

pub const SHAKE256: XofAlgorithm = XofAlgorithm {
    name: "SHAKE256",
    rate: 136,
    oid_arc: 12,
};

pub const HMAC_SHA_224: HmacAlgorithm = HmacAlgorithm {
    name: "HMAC-SHA-224",
    hash: SHA_224,
};

pub const HMAC_SHA_256: HmacAlgorithm = HmacAlgorithm {
    name: "HMAC-SHA-256",
    hash: SHA_256,
};

pub const HMAC_SHA_384: HmacAlgorithm = HmacAlgorithm {
    name: "HMAC-SHA-384",
    hash: SHA_384,
};

pub const HMAC_SHA_512: HmacAlgorithm = HmacAlgorithm {
    name: "HMAC-SHA-512",
    hash: SHA_512,
};

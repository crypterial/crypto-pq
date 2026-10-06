use alloc::vec;
use alloc::vec::Vec;

use crate::cpu::Dit;
use crate::ct;
use crate::keccak::Keccak;
use crate::sha2::{
    self, IV_224, IV_256, IV_384, IV_512, IV_512_224, IV_512_256, Sha256, Sha512, finish256,
    finish512,
};
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

    fn digest_into(&self, out: &mut [u8]) {
        match self {
            Self::Sha256(engine) => engine.digest_into(out),
            Self::Sha512(engine) => engine.digest_into(out),
            Self::Keccak(engine) => engine.clone().read(out),
        }
    }
}

// An output buffer of another size is a programming error, as in copy_from_slice.
fn check_length(actual: usize, expected: usize) {
    assert!(
        actual == expected,
        "INVALID_LENGTH: the output must be exactly the digest size"
    );
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
        let mut out = vec![0; self.digest_size];

        self.digest_into(data, &mut out);

        out
    }

    // The same digest written into out, which must be digest_size() bytes, without allocating.
    pub fn digest_into(&self, data: &[u8], out: &mut [u8]) {
        check_length(out.len(), self.digest_size);

        match self.kind {
            Kind::Sha256(iv) => finish256(iv, 0, data, out),
            Kind::Sha512(iv) => finish512(iv, 0, data, out),
            Kind::Sha3 => Keccak::digest_into(self.block_size(), SHA3_SUFFIX, data, out),
        }
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
        let mut out = vec![0; self.size];

        self.engine.digest_into(&mut out);

        out
    }

    pub fn digest_into(&self, out: &mut [u8]) {
        check_length(out.len(), self.size);

        self.engine.digest_into(out);
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
        Keccak::digest(self.rate, SHAKE_SUFFIX, data, length)
    }

    // out.len() bytes of output, without allocating.
    pub fn digest_into(&self, data: &[u8], out: &mut [u8]) {
        Keccak::digest_into(self.rate, SHAKE_SUFFIX, data, out);
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

    pub fn read_into(&mut self, out: &mut [u8]) {
        self.engine.read(out);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HmacAlgorithm {
    name: &'static str,
    hash: HashAlgorithm,
}

// HMAC runs under DIT because its key is secret; plain hashes do not know whether their input is.
// Each public method takes the guard once, around everything it does with the key, and the
// functions it calls take none of their own.
impl HmacAlgorithm {
    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn digest_size(&self) -> usize {
        self.hash.digest_size
    }

    pub fn digest(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = vec![0; self.hash.digest_size];

        self.digest_into(key, data, &mut out);

        out
    }

    pub fn digest_into(&self, key: &[u8], data: &[u8], out: &mut [u8]) {
        check_length(out.len(), self.hash.digest_size);

        let _dit = Dit::new();

        self.mac(key, data, out);
    }

    pub fn create(&self, key: &[u8]) -> Hmac {
        let _dit = Dit::new();

        let mut hashed = [0; 64];

        let key = self.block_key(key, &mut hashed);

        let (inner, outer) = match self.hash.kind {
            Kind::Sha256(iv) => {
                let mut keyed = sha2::keyed256(iv, key);

                let engines = (
                    Engine::Sha256(Sha256::resume(keyed[0], 64)),
                    Engine::Sha256(Sha256::resume(keyed[1], 64)),
                );

                wipe(keyed.as_flattened_mut());

                engines
            }
            Kind::Sha512(iv) => {
                let mut keyed = sha2::keyed512(iv, key);

                let engines = (
                    Engine::Sha512(Sha512::resume(keyed[0], 128)),
                    Engine::Sha512(Sha512::resume(keyed[1], 128)),
                );

                wipe(keyed.as_flattened_mut());

                engines
            }
            Kind::Sha3 => unreachable!("HMAC is defined here over SHA-2 only"),
        };

        wipe(&mut hashed);

        Hmac {
            inner,
            outer,
            size: self.hash.digest_size,
        }
    }

    pub fn verify(&self, key: &[u8], data: &[u8], tag: &[u8]) -> bool {
        let _dit = Dit::new();

        let mut expected = [0; 64];

        let size = self.hash.digest_size;

        self.mac(key, data, &mut expected[..size]);

        let equal = ct::equal(&expected[..size], tag);

        wipe(&mut expected);

        equal
    }

    fn mac(&self, key: &[u8], data: &[u8], out: &mut [u8]) {
        let mut hashed = [0; 64];

        let key = self.block_key(key, &mut hashed);

        match self.hash.kind {
            Kind::Sha256(iv) => sha2::hmac256(iv, key, data, out),
            Kind::Sha512(iv) => sha2::hmac512(iv, key, data, out),
            Kind::Sha3 => unreachable!("HMAC is defined here over SHA-2 only"),
        }

        wipe(&mut hashed);
    }

    // RFC 2104: a key longer than a block is replaced by its hash, which `hashed` then holds.
    fn block_key<'a>(&self, key: &'a [u8], hashed: &'a mut [u8; 64]) -> &'a [u8] {
        if key.len() <= self.hash.block_size() {
            return key;
        }

        let hashed = &mut hashed[..self.hash.digest_size];

        self.hash.digest_into(key, hashed);

        hashed
    }
}

// The inner engine has absorbed the inner key block and the data so far; the outer one only the
// outer key block.
pub struct Hmac {
    inner: Engine,
    outer: Engine,
    size: usize,
}

impl Hmac {
    pub fn update(&mut self, data: &[u8]) {
        let _dit = Dit::new();

        self.inner.update(data);
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
        let _dit = Dit::new();

        let mut expected = [0; 64];

        self.finish(&mut expected[..self.size]);

        let equal = ct::equal(&expected[..self.size], tag);

        wipe(&mut expected);

        equal
    }

    // The inner digest is wiped: with the outer key it gives the output, which may be a key itself.
    fn finish(&self, out: &mut [u8]) {
        let mut inner = [0; 64];

        let inner_digest = &mut inner[..self.size];

        self.inner.digest_into(inner_digest);

        match &self.outer {
            Engine::Sha256(outer) => outer.digest_after(inner_digest, out),
            Engine::Sha512(outer) => outer.digest_after(inner_digest, out),
            Engine::Keccak(_) => unreachable!("HMAC is defined here over SHA-2 only"),
        }

        wipe(&mut inner);
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

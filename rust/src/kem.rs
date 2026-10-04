use alloc::vec::Vec;
use core::fmt;

use crate::ct;
use crate::error::Error;
use crate::keys::{
    KeyFormat, KeyGenOptions, PrivateInput, SeedChoice, check_size, decode_seed_choice,
    encode_expanded, encode_seed, export_private, export_public, import_private, import_public,
};
use crate::mlkem::{self, Parameters};
use crate::rng::random_bytes;
use crate::wipe::{SecretBytes, wipe};
use crate::xwing;

const ML_KEM_SEED_SIZE: usize = 64;

const ML_KEM_RANDOMNESS_SIZE: usize = 32;

const SHARED_SECRET_SIZE: usize = 32;

const fn oid(arc: u8) -> [u8; 9] {
    [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, arc]
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Scheme {
    MlKem(Parameters, [u8; 9]),
    XWing,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KemAlgorithm {
    name: &'static str,
    scheme: Scheme,
}

pub const ML_KEM_512: KemAlgorithm = KemAlgorithm {
    name: "ML-KEM-512",
    scheme: Scheme::MlKem(mlkem::ML_KEM_512, oid(1)),
};

pub const ML_KEM_768: KemAlgorithm = KemAlgorithm {
    name: "ML-KEM-768",
    scheme: Scheme::MlKem(mlkem::ML_KEM_768, oid(2)),
};

pub const ML_KEM_1024: KemAlgorithm = KemAlgorithm {
    name: "ML-KEM-1024",
    scheme: Scheme::MlKem(mlkem::ML_KEM_1024, oid(3)),
};

pub const X_WING: KemAlgorithm = KemAlgorithm {
    name: "X-Wing",
    scheme: Scheme::XWing,
};

impl KemAlgorithm {
    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn public_key_size(&self) -> usize {
        match self.scheme {
            Scheme::MlKem(p, _) => p.encapsulation_key_size(),
            Scheme::XWing => xwing::PUBLIC_KEY_SIZE,
        }
    }

    pub const fn ciphertext_size(&self) -> usize {
        match self.scheme {
            Scheme::MlKem(p, _) => p.ciphertext_size(),
            Scheme::XWing => xwing::CIPHERTEXT_SIZE,
        }
    }

    pub const fn shared_secret_size(&self) -> usize {
        SHARED_SECRET_SIZE
    }

    pub fn generate_key_pair(&self, options: &KeyGenOptions) -> Result<KemKeyPair, Error> {
        let private_key = self.key_from_seed(&random_bytes(self.seed_size())?);

        let public_key = private_key.public_key();

        if options.self_test {
            let mut encapsulation = public_key.encapsulate()?;

            let mut shared_secret = private_key.decapsulate(&encapsulation.ciphertext)?;

            // The outcome of the pairwise test is public: key generation fails on it.
            let consistent =
                ct::declassify_value(ct::equal(&shared_secret, &encapsulation.shared_secret));

            wipe(&mut shared_secret);

            wipe(&mut encapsulation.shared_secret);

            if !consistent {
                return Err(Error::SelfTestFailed);
            }
        }

        Ok(KemKeyPair {
            public_key,
            private_key,
        })
    }

    pub fn import_public_key(&self, data: &[u8], format: KeyFormat) -> Result<KemPublicKey, Error> {
        let key = import_public(format, data, self.oid())?;

        check_size(format, key.len(), self.public_key_size())?;

        let valid = match self.scheme {
            Scheme::MlKem(p, _) => mlkem::check_encapsulation_key(&key, &p),
            Scheme::XWing => xwing::check_public_key(&key),
        };

        if !valid {
            return Err(Error::InvalidPublicKey);
        }

        Ok(KemPublicKey {
            algorithm: *self,
            key,
        })
    }

    pub fn import_private_key(
        &self,
        data: &[u8],
        format: KeyFormat,
    ) -> Result<KemPrivateKey, Error> {
        let (key, public_key) = match import_private(format, data, self.oid())? {
            PrivateInput::Raw(raw) => return self.import_raw(&raw),
            PrivateInput::Pkcs8 { key, public_key } => (self.import_choice(&key)?, public_key),
        };

        if public_key.is_some_and(|public_key| public_key != key.public) {
            return Err(Error::InvalidPrivateKey);
        }

        Ok(key)
    }

    fn import_raw(&self, raw: &[u8]) -> Result<KemPrivateKey, Error> {
        if raw.len() == self.seed_size() {
            return Ok(self.key_from_seed(raw));
        }

        match self.scheme {
            Scheme::MlKem(p, _) if raw.len() == p.decapsulation_key_size() => {
                self.key_from_expanded(p, raw)
            }
            _ => Err(Error::InvalidLength),
        }
    }

    fn import_choice(&self, octets: &[u8]) -> Result<KemPrivateKey, Error> {
        let Scheme::MlKem(p, _) = self.scheme else {
            return Err(Error::Unsupported);
        };

        match decode_seed_choice(octets, ML_KEM_SEED_SIZE, p.decapsulation_key_size())? {
            SeedChoice::Seed(seed) => Ok(self.key_from_seed(seed)),
            SeedChoice::Expanded(expanded) => self.key_from_expanded(p, expanded),
            SeedChoice::Both { seed, expanded } => {
                let key = self.key_from_seed(seed);

                match &key.secret {
                    Secret::MlKem { dk, .. } if ct::equal(dk, expanded) => Ok(key),
                    _ => Err(Error::InvalidPrivateKey),
                }
            }
        }
    }

    fn key_from_expanded(&self, p: Parameters, dk: &[u8]) -> Result<KemPrivateKey, Error> {
        if !mlkem::check_decapsulation_key(dk, &p) {
            return Err(Error::InvalidPrivateKey);
        }

        Ok(KemPrivateKey {
            algorithm: *self,
            public: mlkem::public_key_of(dk, &p).to_vec(),
            secret: Secret::MlKem {
                params: p,
                seed: None,
                dk: SecretBytes::concat(&[dk]),
            },
        })
    }

    pub(crate) fn key_from_seed(&self, seed: &[u8]) -> KemPrivateKey {
        match self.scheme {
            Scheme::MlKem(p, _) => {
                let (public, dk) = mlkem::keygen_internal(&seed[..32], &seed[32..], &p);

                KemPrivateKey {
                    algorithm: *self,
                    public,
                    secret: Secret::MlKem {
                        params: p,
                        seed: Some(SecretBytes::concat(&[seed])),
                        dk,
                    },
                }
            }
            Scheme::XWing => {
                let expanded = xwing::expand(seed);

                KemPrivateKey {
                    algorithm: *self,
                    public: expanded.public,
                    secret: Secret::XWing {
                        seed: SecretBytes::concat(&[seed]),
                        dk: expanded.dk,
                        scalar: expanded.scalar,
                    },
                }
            }
        }
    }

    pub(crate) const fn seed_size(&self) -> usize {
        match self.scheme {
            Scheme::MlKem(..) => ML_KEM_SEED_SIZE,
            Scheme::XWing => xwing::SEED_SIZE,
        }
    }

    pub(crate) const fn randomness_size(&self) -> usize {
        match self.scheme {
            Scheme::MlKem(..) => ML_KEM_RANDOMNESS_SIZE,
            Scheme::XWing => xwing::RANDOMNESS_SIZE,
        }
    }

    fn oid(&self) -> Option<&[u8]> {
        match &self.scheme {
            Scheme::MlKem(_, oid) => Some(oid),
            Scheme::XWing => None,
        }
    }
}

impl fmt::Debug for KemAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KemAlgorithm").field(&self.name).finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct KemPublicKey {
    algorithm: KemAlgorithm,
    key: Vec<u8>,
}

impl KemPublicKey {
    pub const fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }

    pub fn encapsulate(&self) -> Result<Encapsulation, Error> {
        let randomness = random_bytes(self.algorithm.randomness_size())?;

        Ok(self.encapsulate_with(&randomness))
    }

    pub(crate) fn encapsulate_with(&self, randomness: &[u8]) -> Encapsulation {
        let (mut shared_secret, ciphertext) = match self.algorithm.scheme {
            Scheme::MlKem(p, _) => mlkem::encaps_internal(&self.key, randomness, &p),
            Scheme::XWing => xwing::encapsulate(&self.key, randomness),
        };

        let encapsulation = Encapsulation {
            shared_secret: shared_secret.to_vec(),
            ciphertext,
        };

        wipe(&mut shared_secret);

        encapsulation
    }

    pub fn export_key(&self, format: KeyFormat) -> Result<Vec<u8>, Error> {
        export_public(format, self.algorithm.oid(), &self.key)
    }
}

impl fmt::Debug for KemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KemPublicKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct Encapsulation {
    pub shared_secret: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for Encapsulation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encapsulation")
            .field("ciphertext", &self.ciphertext)
            .finish_non_exhaustive()
    }
}

enum Secret {
    MlKem {
        params: Parameters,
        seed: Option<SecretBytes>,
        dk: SecretBytes,
    },
    XWing {
        seed: SecretBytes,
        dk: SecretBytes,
        scalar: SecretBytes,
    },
}

// The secret fields are SecretBytes, which wipe themselves when the key is dropped.
pub struct KemPrivateKey {
    algorithm: KemAlgorithm,
    public: Vec<u8>,
    secret: Secret,
}

impl KemPrivateKey {
    pub const fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }

    pub fn public_key(&self) -> KemPublicKey {
        KemPublicKey {
            algorithm: self.algorithm,
            key: self.public.clone(),
        }
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if ciphertext.len() != self.algorithm.ciphertext_size() {
            return Err(Error::InvalidLength);
        }

        let mut shared_secret = match &self.secret {
            Secret::MlKem { params, dk, .. } => mlkem::decaps_internal(dk, ciphertext, params),
            Secret::XWing { dk, scalar, .. } => {
                xwing::decapsulate(dk, scalar, xwing::public_point(&self.public), ciphertext)
            }
        };

        let out = shared_secret.to_vec();

        wipe(&mut shared_secret);

        Ok(out)
    }

    pub fn export_key(&self, format: KeyFormat) -> Result<Vec<u8>, Error> {
        let oid = self.algorithm.oid();

        match &self.secret {
            Secret::MlKem {
                seed: Some(seed), ..
            }
            | Secret::XWing { seed, .. } => export_private(format, oid, &encode_seed(seed), seed),
            Secret::MlKem { seed: None, dk, .. } => {
                export_private(format, oid, &encode_expanded(dk), dk)
            }
        }
    }
}

impl fmt::Debug for KemPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KemPrivateKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct KemKeyPair {
    pub public_key: KemPublicKey,
    pub private_key: KemPrivateKey,
}

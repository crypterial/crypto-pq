use alloc::vec::Vec;
use core::fmt;
use core::hash::{Hash, Hasher};

use crate::ct;
use crate::error::Error;
use crate::keys::{
    KeyFormat, KeyGenOptions, PrivateInput, SeedChoice, check_size, decode_seed_choice,
    encode_expanded, encode_seed, export_private, export_public, import_private, import_public,
};
use crate::mlkem::{self, Parameters};
use crate::once::{OnceBox, Shared};
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

    // The self-test is the first use of the new keys, so it computes their cached forms from the
    // encoded keys and checks those too.
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
            public: Shared::new(PublicPart::new(self.scheme, key)),
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

        if public_key.is_some_and(|public_key| public_key != key.public.key) {
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

        let secret = Secret::MlKem {
            params: p,
            seed: None,
            dk: SecretBytes::concat(&[dk]),
        };

        Ok(self.private_key(mlkem::public_key_of(dk, &p).to_vec(), secret))
    }

    pub(crate) fn key_from_seed(&self, seed: &[u8]) -> KemPrivateKey {
        match self.scheme {
            Scheme::MlKem(p, _) => {
                let (public, dk) = mlkem::keygen_internal(&seed[..32], &seed[32..], &p);

                let secret = Secret::MlKem {
                    params: p,
                    seed: Some(SecretBytes::concat(&[seed])),
                    dk,
                };

                self.private_key(public, secret)
            }
            Scheme::XWing => {
                let expanded = xwing::expand(seed);

                let secret = Secret::XWing {
                    seed: SecretBytes::concat(&[seed]),
                    dk: expanded.dk,
                    scalar: expanded.scalar,
                };

                self.private_key(expanded.public, secret)
            }
        }
    }

    fn private_key(&self, public: Vec<u8>, secret: Secret) -> KemPrivateKey {
        let decoded = OnceBox::new(|| secret.decode());

        KemPrivateKey {
            algorithm: *self,
            public: Shared::new(PublicPart::new(self.scheme, public)),
            secret,
            decoded,
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

// A public key and the form of it that encapsulation uses, computed on first use so that no
// encapsulation samples the matrix or hashes the key again. A private key and every public key
// that comes from it, clones included, share one.
#[derive(Clone)]
struct PublicPart {
    key: Vec<u8>,
    expanded: OnceBox<mlkem::EncapsulationKey>,
}

impl PublicPart {
    fn new(scheme: Scheme, key: Vec<u8>) -> Self {
        let expanded = OnceBox::new(|| expand(scheme, &key));

        Self { key, expanded }
    }

    fn expanded(&self, scheme: Scheme) -> &mlkem::EncapsulationKey {
        self.expanded.get_or_init(|| expand(scheme, &self.key))
    }
}

// For a valid public key: the ML-KEM form of it, or for X-Wing of its ML-KEM part.
fn expand(scheme: Scheme, key: &[u8]) -> mlkem::EncapsulationKey {
    match scheme {
        Scheme::MlKem(p, _) => mlkem::EncapsulationKey::new(key, &p),
        Scheme::XWing => xwing::encapsulation_key(key),
    }
}

// Equality and hashing look at the key alone.
#[derive(Clone)]
pub struct KemPublicKey {
    algorithm: KemAlgorithm,
    public: Shared<PublicPart>,
}

impl PartialEq for KemPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.public.key == other.public.key
    }
}

impl Eq for KemPublicKey {}

impl Hash for KemPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.algorithm.hash(state);

        self.public.key.hash(state);
    }
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
        let scheme = self.algorithm.scheme;

        let key = self.public.expanded(scheme);

        let (mut shared_secret, ciphertext) = match scheme {
            Scheme::MlKem(p, _) => mlkem::encaps_internal(key, randomness, &p),
            Scheme::XWing => xwing::encapsulate(key, &self.public.key, randomness),
        };

        let encapsulation = Encapsulation {
            shared_secret: shared_secret.to_vec(),
            ciphertext,
        };

        wipe(&mut shared_secret);

        encapsulation
    }

    pub fn export_key(&self, format: KeyFormat) -> Result<Vec<u8>, Error> {
        export_public(format, self.algorithm.oid(), &self.public.key)
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

impl Secret {
    // The form of the ML-KEM decapsulation key, X-Wing's included, that decapsulation uses.
    fn decode(&self) -> mlkem::DecapsulationKey {
        match self {
            Self::MlKem { params, dk, .. } => mlkem::DecapsulationKey::new(dk, params),
            Self::XWing { dk, .. } => xwing::decapsulation_key(dk),
        }
    }
}

// The secret fields are SecretBytes, which wipe themselves when the key is dropped, as does
// `decoded`, the decoded secret that decapsulation computes on first use.
pub struct KemPrivateKey {
    algorithm: KemAlgorithm,
    public: Shared<PublicPart>,
    secret: Secret,
    decoded: OnceBox<mlkem::DecapsulationKey>,
}

impl KemPrivateKey {
    pub const fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }

    pub fn public_key(&self) -> KemPublicKey {
        KemPublicKey {
            algorithm: self.algorithm,
            public: self.public.clone(),
        }
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if ciphertext.len() != self.algorithm.ciphertext_size() {
            return Err(Error::InvalidLength);
        }

        let public = self.public.expanded(self.algorithm.scheme);

        let secret = self.decoded.get_or_init(|| self.secret.decode());

        let mut shared_secret = match &self.secret {
            Secret::MlKem { params, dk, .. } => {
                mlkem::decaps_internal(public, secret, dk, ciphertext, params)
            }
            Secret::XWing { dk, scalar, .. } => {
                let pk_x = xwing::public_point(&self.public.key);

                xwing::decapsulate(public, secret, dk, scalar, pk_x, ciphertext)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hazmat;

    fn filled(key: &KemPrivateKey) -> (bool, bool) {
        (
            key.public.expanded.get().is_some(),
            key.decoded.get().is_some(),
        )
    }

    // The caches fill on first use, which for a generated key is its self-test, and a key pair
    // shares one public part.
    #[test]
    fn caches_fill_on_first_use_and_are_shared() {
        for algorithm in [ML_KEM_512, ML_KEM_768, ML_KEM_1024, X_WING] {
            let seed = [7; 64];

            let pair = hazmat::generate_kem_key_pair(algorithm, &seed[..algorithm.seed_size()])
                .expect("key pair");

            let (public_key, private_key) = (&pair.public_key, &pair.private_key);

            assert!(core::ptr::eq(&*public_key.public, &*private_key.public));

            assert_eq!(filled(private_key), (false, false));

            let randomness = [9; 64];

            let encapsulation =
                hazmat::encapsulate(public_key, &randomness[..algorithm.randomness_size()])
                    .expect("encapsulation");

            assert_eq!(filled(private_key), (true, false));

            let shared_secret = private_key
                .decapsulate(&encapsulation.ciphertext)
                .expect("decapsulation");

            assert_eq!(shared_secret, encapsulation.shared_secret);

            assert_eq!(filled(private_key), (true, true));

            let raw = public_key.export_key(KeyFormat::Raw).expect("export");

            let imported = algorithm
                .import_public_key(&raw, KeyFormat::Raw)
                .expect("import");

            assert!(imported.public.expanded.get().is_none());

            let clone = imported.clone();

            assert!(core::ptr::eq(&*clone.public, &*imported.public));

            hazmat::encapsulate(&clone, &randomness[..algorithm.randomness_size()])
                .expect("encapsulation");

            assert!(imported.public.expanded.get().is_some());

            let seed = private_key.export_key(KeyFormat::Raw).expect("export");

            let reimported = algorithm
                .import_private_key(&seed, KeyFormat::Raw)
                .expect("import");

            assert_eq!(filled(&reimported), (false, false));

            let generated = algorithm
                .generate_key_pair(&KeyGenOptions::default())
                .expect("key pair");

            assert_eq!(filled(&generated.private_key), (true, true));

            let untested = algorithm
                .generate_key_pair(&KeyGenOptions { self_test: false })
                .expect("key pair");

            assert_eq!(filled(&untested.private_key), (false, false));
        }
    }

    #[test]
    fn expanded_keys_start_empty() {
        let pair = hazmat::generate_kem_key_pair(ML_KEM_768, &[3; 64]).expect("key pair");

        let Secret::MlKem { dk, .. } = &pair.private_key.secret else {
            unreachable!("an ML-KEM key");
        };

        let imported = ML_KEM_768
            .import_private_key(dk, KeyFormat::Raw)
            .expect("import");

        assert_eq!(filled(&imported), (false, false));

        let encapsulation = imported.public_key().encapsulate().expect("encapsulation");

        assert_eq!(
            imported.decapsulate(&encapsulation.ciphertext),
            Ok(encapsulation.shared_secret)
        );

        assert_eq!(filled(&imported), (true, true));
    }
}

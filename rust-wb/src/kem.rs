use alloc::vec::Vec;
use core::fmt;
use core::hash::{Hash, Hasher};

use crate::cpu::Dit;
use crate::ct;
use crate::error::Error;
#[cfg(feature = "frodokem")]
use crate::frodokem;
use crate::keys::{
    KeyFormat, KeyGenOptions, PrivateInput, check_size, export_private, export_public,
    import_private, import_public,
};
#[cfg(feature = "ml-kem")]
use crate::keys::{SeedChoice, decode_seed_choice, encode_expanded, encode_seed};
#[cfg(feature = "ml-kem")]
use crate::mlkem::{self, Parameters};
use crate::once::{OnceBox, Shared};
use crate::rng::random_bytes;
use crate::wipe::SecretBytes;

const ML_KEM_SEED_SIZE: usize = 64;

const ML_KEM_RANDOMNESS_SIZE: usize = 32;

const SHARED_SECRET_SIZE: usize = 32;

#[cfg(feature = "ml-kem")]
const fn oid(arc: u8) -> [u8; 9] {
    [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, arc]
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Scheme {
    #[cfg(feature = "ml-kem")]
    MlKem(Parameters, [u8; 9]),
    #[cfg(feature = "frodokem")]
    Frodo(frodokem::Parameters),
}

/// A key encapsulation mechanism: ML-KEM (FIPS 203) or FrodoKEM (ISO/IEC 18033-2 Amd 2).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KemAlgorithm {
    name: &'static str,
    scheme: Scheme,
}

/// ML-KEM-512 (FIPS 203), security category 1.
#[cfg(feature = "ml-kem")]
pub const ML_KEM_512: KemAlgorithm = KemAlgorithm {
    name: "ML-KEM-512",
    scheme: Scheme::MlKem(mlkem::ML_KEM_512, oid(1)),
};

/// ML-KEM-768 (FIPS 203), security category 3.
#[cfg(feature = "ml-kem")]
pub const ML_KEM_768: KemAlgorithm = KemAlgorithm {
    name: "ML-KEM-768",
    scheme: Scheme::MlKem(mlkem::ML_KEM_768, oid(2)),
};

/// ML-KEM-1024 (FIPS 203), security category 5.
#[cfg(feature = "ml-kem")]
pub const ML_KEM_1024: KemAlgorithm = KemAlgorithm {
    name: "ML-KEM-1024",
    scheme: Scheme::MlKem(mlkem::ML_KEM_1024, oid(3)),
};

/// FrodoKEM-976-AES, security category 3, with AES-128 generating the matrix.
#[cfg(feature = "frodokem")]
pub const FRODOKEM_976_AES: KemAlgorithm = KemAlgorithm {
    name: "FrodoKEM-976-AES",
    scheme: Scheme::Frodo(frodokem::FRODOKEM_976_AES),
};

/// FrodoKEM-976-SHAKE, security category 3, with SHAKE128 generating the matrix.
#[cfg(feature = "frodokem")]
pub const FRODOKEM_976_SHAKE: KemAlgorithm = KemAlgorithm {
    name: "FrodoKEM-976-SHAKE",
    scheme: Scheme::Frodo(frodokem::FRODOKEM_976_SHAKE),
};

/// FrodoKEM-1344-AES, security category 5, with AES-128 generating the matrix.
#[cfg(feature = "frodokem")]
pub const FRODOKEM_1344_AES: KemAlgorithm = KemAlgorithm {
    name: "FrodoKEM-1344-AES",
    scheme: Scheme::Frodo(frodokem::FRODOKEM_1344_AES),
};

/// FrodoKEM-1344-SHAKE, security category 5, with SHAKE128 generating the matrix.
#[cfg(feature = "frodokem")]
pub const FRODOKEM_1344_SHAKE: KemAlgorithm = KemAlgorithm {
    name: "FrodoKEM-1344-SHAKE",
    scheme: Scheme::Frodo(frodokem::FRODOKEM_1344_SHAKE),
};

/// eFrodoKEM-976-AES, the ephemeral form of FrodoKEM-976-AES: a public key must encapsulate
/// fewer than 2^8 ciphertexts.
#[cfg(feature = "frodokem")]
pub const EFRODOKEM_976_AES: KemAlgorithm = KemAlgorithm {
    name: "eFrodoKEM-976-AES",
    scheme: Scheme::Frodo(frodokem::EFRODOKEM_976_AES),
};

/// eFrodoKEM-976-SHAKE, the ephemeral form of FrodoKEM-976-SHAKE: a public key must
/// encapsulate fewer than 2^8 ciphertexts.
#[cfg(feature = "frodokem")]
pub const EFRODOKEM_976_SHAKE: KemAlgorithm = KemAlgorithm {
    name: "eFrodoKEM-976-SHAKE",
    scheme: Scheme::Frodo(frodokem::EFRODOKEM_976_SHAKE),
};

/// eFrodoKEM-1344-AES, the ephemeral form of FrodoKEM-1344-AES: a public key must
/// encapsulate fewer than 2^8 ciphertexts.
#[cfg(feature = "frodokem")]
pub const EFRODOKEM_1344_AES: KemAlgorithm = KemAlgorithm {
    name: "eFrodoKEM-1344-AES",
    scheme: Scheme::Frodo(frodokem::EFRODOKEM_1344_AES),
};

/// eFrodoKEM-1344-SHAKE, the ephemeral form of FrodoKEM-1344-SHAKE: a public key must
/// encapsulate fewer than 2^8 ciphertexts.
#[cfg(feature = "frodokem")]
pub const EFRODOKEM_1344_SHAKE: KemAlgorithm = KemAlgorithm {
    name: "eFrodoKEM-1344-SHAKE",
    scheme: Scheme::Frodo(frodokem::EFRODOKEM_1344_SHAKE),
};

impl KemAlgorithm {
    /// The name of the algorithm, such as `"ML-KEM-768"`.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The size of a raw public key in bytes.
    pub const fn public_key_size(&self) -> usize {
        match self.scheme {
            #[cfg(feature = "ml-kem")]
            Scheme::MlKem(p, _) => p.encapsulation_key_size(),
            #[cfg(feature = "frodokem")]
            Scheme::Frodo(p) => p.public_key_size(),
        }
    }

    /// The size of a ciphertext in bytes.
    pub const fn ciphertext_size(&self) -> usize {
        match self.scheme {
            #[cfg(feature = "ml-kem")]
            Scheme::MlKem(p, _) => p.ciphertext_size(),
            #[cfg(feature = "frodokem")]
            Scheme::Frodo(p) => p.ciphertext_size(),
        }
    }

    /// The size of a shared secret in bytes.
    pub const fn shared_secret_size(&self) -> usize {
        match self.scheme {
            #[cfg(feature = "frodokem")]
            Scheme::Frodo(p) => p.shared_secret_size(),
            _ => SHARED_SECRET_SIZE,
        }
    }

    /// Generates a key pair from the operating-system entropy source.
    ///
    /// With `options.self_test` (the default) a fresh encapsulation must decapsulate to its shared
    /// secret, or the call fails with [`Error::SelfTestFailed`].
    // The self-test is the first use of the new keys, so it computes their cached forms from the
    // encoded keys and checks those too.
    pub fn generate_key_pair(&self, options: &KeyGenOptions) -> Result<KemKeyPair, Error> {
        let _dit = Dit::new();

        let private_key = self.key_from_seed(&random_bytes(self.seed_size())?);

        if options.self_test && !private_key.consistent()? {
            return Err(Error::SelfTestFailed);
        }

        Ok(KemKeyPair {
            public_key: private_key.public_key(),
            private_key,
        })
    }

    /// Imports a public key in `format`. An ML-KEM key must pass the modulus check of FIPS 203.
    /// FrodoKEM keys have only the raw form.
    pub fn import_public_key(&self, data: &[u8], format: KeyFormat) -> Result<KemPublicKey, Error> {
        let key = import_public(format, data, self.oid())?;

        check_size(format, key.len(), self.public_key_size())?;

        let public = match self.scheme {
            #[cfg(feature = "ml-kem")]
            Scheme::MlKem(p, _) if mlkem::check_encapsulation_key(&key, &p) => {
                PublicPart::MlKem(Shared::new(MlKemPublic::new(key, p)))
            }
            #[cfg(feature = "ml-kem")]
            Scheme::MlKem(..) => return Err(Error::InvalidPublicKey),
            // Every bit pattern of the right length is a FrodoKEM public key.
            #[cfg(feature = "frodokem")]
            Scheme::Frodo(p) => PublicPart::Frodo(Shared::new(FrodoPublic::new(key, p))),
        };

        Ok(KemPublicKey {
            algorithm: *self,
            public,
        })
    }

    /// Imports a private key in `format` and checks it.
    ///
    /// A raw ML-KEM key is the 64-byte seed or the expanded decapsulation key; a raw FrodoKEM key
    /// is the standard secret key. An imported key without its seed, and every FrodoKEM key, must
    /// have its secret in the range that key generation samples and pass a pairwise test.
    pub fn import_private_key(
        &self,
        data: &[u8],
        format: KeyFormat,
    ) -> Result<KemPrivateKey, Error> {
        let _dit = Dit::new();

        let (key, public_key) = match import_private(format, data, self.oid())? {
            PrivateInput::Raw(raw) => return self.import_raw(&raw),
            PrivateInput::Pkcs8 { key, public_key } => (self.import_choice(&key)?, public_key),
        };

        if public_key.is_some_and(|public_key| public_key != key.public_key().key()) {
            return Err(Error::InvalidPrivateKey);
        }

        Ok(key)
    }

    // A raw FrodoKEM private key is the standard sk, with no seed form: its length must be exact,
    // its pkh must match the public key inside it, S^T must lie in the support of chi, and it must
    // pass the pairwise test.
    fn import_raw(&self, raw: &[u8]) -> Result<KemPrivateKey, Error> {
        match self.scheme {
            #[cfg(feature = "frodokem")]
            Scheme::Frodo(p) if raw.len() != p.private_key_size() => Err(Error::InvalidLength),
            #[cfg(feature = "frodokem")]
            Scheme::Frodo(p) if !frodokem::check_private_key(&p, raw) => {
                Err(Error::InvalidPrivateKey)
            }
            #[cfg(feature = "frodokem")]
            Scheme::Frodo(p) => self.frodo_key(p, SecretBytes::concat(&[raw])).checked(),
            #[cfg(feature = "ml-kem")]
            Scheme::MlKem(..) if raw.len() == ML_KEM_SEED_SIZE => Ok(self.key_from_seed(raw)),
            #[cfg(feature = "ml-kem")]
            Scheme::MlKem(p, _) if raw.len() == p.decapsulation_key_size() => {
                self.key_from_expanded(p, raw)
            }
            #[cfg(feature = "ml-kem")]
            Scheme::MlKem(..) => Err(Error::InvalidLength),
        }
    }

    #[cfg(feature = "ml-kem")]
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
                    #[cfg(feature = "ml-kem")]
                    Secret::MlKem { dk, .. } if ct::declassify_value(ct::equal(dk, expanded)) => {
                        Ok(key)
                    }
                    _ => Err(Error::InvalidPrivateKey),
                }
            }
        }
    }

    // FrodoKEM has no PKCS #8 form, so import_private never gives one.
    #[cfg(not(feature = "ml-kem"))]
    fn import_choice(&self, _: &[u8]) -> Result<KemPrivateKey, Error> {
        Err(Error::Unsupported)
    }

    // SPEC 8.1.4: the checks of the encoding and of the range of the secret, then a pairwise test
    // with fresh randomness.
    #[cfg(feature = "ml-kem")]
    fn key_from_expanded(&self, p: Parameters, dk: &[u8]) -> Result<KemPrivateKey, Error> {
        if !mlkem::check_decapsulation_key(dk, &p) {
            return Err(Error::InvalidPrivateKey);
        }

        let public = Shared::new(MlKemPublic::new(mlkem::public_key_of(dk, &p).to_vec(), p));

        self.ml_kem_key(public, None, SecretBytes::concat(&[dk]))
            .checked()
    }

    pub(crate) fn key_from_seed(&self, seed: &[u8]) -> KemPrivateKey {
        let _dit = Dit::new();

        match self.scheme {
            #[cfg(feature = "ml-kem")]
            Scheme::MlKem(p, _) => {
                let (public, dk) = mlkem::keygen_internal(&seed[..32], &seed[32..], &p);

                let public = Shared::new(MlKemPublic::new(public, p));

                self.ml_kem_key(public, Some(SecretBytes::concat(&[seed])), dk)
            }
            #[cfg(feature = "frodokem")]
            Scheme::Frodo(p) => self.frodo_key(p, frodokem::keygen(&p, seed)),
        }
    }

    #[cfg(feature = "ml-kem")]
    fn ml_kem_key(
        &self,
        public: Shared<MlKemPublic>,
        seed: Option<SecretBytes>,
        dk: SecretBytes,
    ) -> KemPrivateKey {
        let p = public.params;

        let decoded = OnceBox::new(|| mlkem::DecapsulationKey::new(&dk, &p));

        KemPrivateKey {
            algorithm: *self,
            secret: Secret::MlKem {
                public,
                seed,
                dk,
                decoded,
            },
        }
    }

    #[cfg(feature = "frodokem")]
    fn frodo_key(&self, p: frodokem::Parameters, sk: SecretBytes) -> KemPrivateKey {
        let start = p.shared_secret_size();

        let public = sk[start..start + p.public_key_size()].to_vec();

        KemPrivateKey {
            algorithm: *self,
            secret: Secret::Frodo {
                public: Shared::new(FrodoPublic::new(public, p)),
                sk,
            },
        }
    }

    pub(crate) const fn seed_size(&self) -> usize {
        match self.scheme {
            #[cfg(feature = "ml-kem")]
            Scheme::MlKem(..) => ML_KEM_SEED_SIZE,
            #[cfg(feature = "frodokem")]
            Scheme::Frodo(p) => p.seed_size(),
        }
    }

    pub(crate) const fn randomness_size(&self) -> usize {
        match self.scheme {
            #[cfg(feature = "ml-kem")]
            Scheme::MlKem(..) => ML_KEM_RANDOMNESS_SIZE,
            #[cfg(feature = "frodokem")]
            Scheme::Frodo(p) => p.randomness_size(),
        }
    }

    fn oid(&self) -> Option<&[u8]> {
        match &self.scheme {
            #[cfg(feature = "ml-kem")]
            Scheme::MlKem(_, oid) => Some(oid),
            #[cfg(feature = "frodokem")]
            Scheme::Frodo(_) => None,
        }
    }
}

impl fmt::Debug for KemAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KemAlgorithm").field(&self.name).finish()
    }
}

// An ML-KEM public key and the form of it that encapsulation uses, computed on first use so that
// no encapsulation samples the matrix or hashes the key again.
#[cfg(feature = "ml-kem")]
struct MlKemPublic {
    key: Vec<u8>,
    params: Parameters,
    form: OnceBox<mlkem::EncapsulationKey>,
}

#[cfg(feature = "ml-kem")]
impl MlKemPublic {
    fn new(key: Vec<u8>, params: Parameters) -> Self {
        let form = OnceBox::new(|| mlkem::EncapsulationKey::new(&key, &params));

        Self { key, params, form }
    }

    fn form(&self) -> &mlkem::EncapsulationKey {
        self.form
            .get_or_init(|| mlkem::EncapsulationKey::new(&self.key, &self.params))
    }
}

// A FrodoKEM public key and its pkh, computed on first use; the matrix is never kept.
#[cfg(feature = "frodokem")]
struct FrodoPublic {
    key: Vec<u8>,
    params: frodokem::Parameters,
    pkh: OnceBox<[u8; 32]>,
}

#[cfg(feature = "frodokem")]
impl FrodoPublic {
    fn new(key: Vec<u8>, params: frodokem::Parameters) -> Self {
        let pkh = OnceBox::new(|| frodokem::public_key_hash(&params, &key));

        Self { key, params, pkh }
    }

    fn pkh(&self) -> &[u8] {
        let pkh = self
            .pkh
            .get_or_init(|| frodokem::public_key_hash(&self.params, &self.key));

        &pkh[..self.params.shared_secret_size()]
    }
}

// A private key and every public key that comes from it, clones included, share one part.
#[derive(Clone)]
enum PublicPart {
    #[cfg(feature = "ml-kem")]
    MlKem(Shared<MlKemPublic>),
    #[cfg(feature = "frodokem")]
    Frodo(Shared<FrodoPublic>),
}

/// A KEM public key. Equality and hashing compare the algorithm and the encoded key.
#[derive(Clone)]
pub struct KemPublicKey {
    algorithm: KemAlgorithm,
    public: PublicPart,
}

impl PartialEq for KemPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.key() == other.key()
    }
}

impl Eq for KemPublicKey {}

impl Hash for KemPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.algorithm.hash(state);

        self.key().hash(state);
    }
}

impl KemPublicKey {
    /// The algorithm of the key.
    pub const fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }

    fn key(&self) -> &[u8] {
        match &self.public {
            #[cfg(feature = "ml-kem")]
            PublicPart::MlKem(part) => &part.key,
            #[cfg(feature = "frodokem")]
            PublicPart::Frodo(part) => &part.key,
        }
    }

    /// Encapsulates a fresh shared secret to this key, with randomness from the operating-system
    /// entropy source.
    pub fn encapsulate(&self) -> Result<Encapsulation, Error> {
        let randomness = random_bytes(self.algorithm.randomness_size())?;

        Ok(self.encapsulate_with(&randomness))
    }

    pub(crate) fn encapsulate_with(&self, randomness: &[u8]) -> Encapsulation {
        let _dit = Dit::new();

        // The schemes write the shared secret here, so that no copy of it is moved.
        let mut shared_secret = SecretBytes::zeroed(self.algorithm.shared_secret_size());

        let ciphertext = match &self.public {
            #[cfg(feature = "ml-kem")]
            PublicPart::MlKem(part) => {
                mlkem::encaps_internal(part.form(), randomness, &part.params, &mut shared_secret)
            }
            #[cfg(feature = "frodokem")]
            PublicPart::Frodo(part) => frodokem::encapsulate(
                &part.params,
                &part.key,
                part.pkh(),
                randomness,
                &mut shared_secret,
            ),
        };

        Encapsulation {
            shared_secret,
            ciphertext,
        }
    }

    /// Exports the key in `format`; FrodoKEM keys have only the raw form.
    pub fn export_key(&self, format: KeyFormat) -> Result<Vec<u8>, Error> {
        export_public(format, self.algorithm.oid(), self.key())
    }
}

impl fmt::Debug for KemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KemPublicKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// The result of an encapsulation.
pub struct Encapsulation {
    /// The shared secret, which the holder of the private key recovers from the ciphertext.
    pub shared_secret: SecretBytes,
    /// The ciphertext to send to the holder of the private key.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for Encapsulation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encapsulation")
            .field("ciphertext", &self.ciphertext)
            .finish_non_exhaustive()
    }
}

// The secret fields are SecretBytes, which wipe themselves when the key is dropped, as does
// `decoded`, the decoded secret that decapsulation computes on first use; FrodoKEM keys have none.
enum Secret {
    #[cfg(feature = "ml-kem")]
    MlKem {
        public: Shared<MlKemPublic>,
        seed: Option<SecretBytes>,
        dk: SecretBytes,
        decoded: OnceBox<mlkem::DecapsulationKey>,
    },
    #[cfg(feature = "frodokem")]
    Frodo {
        public: Shared<FrodoPublic>,
        sk: SecretBytes,
    },
}

/// A KEM private key. Its secrets are wiped when it is dropped; it has neither `Clone` nor
/// `PartialEq`.
pub struct KemPrivateKey {
    algorithm: KemAlgorithm,
    secret: Secret,
}

impl KemPrivateKey {
    /// The algorithm of the key.
    pub const fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }

    /// The public key of this private key.
    pub fn public_key(&self) -> KemPublicKey {
        let public = match &self.secret {
            #[cfg(feature = "ml-kem")]
            Secret::MlKem { public, .. } => PublicPart::MlKem(public.clone()),
            #[cfg(feature = "frodokem")]
            Secret::Frodo { public, .. } => PublicPart::Frodo(public.clone()),
        };

        KemPublicKey {
            algorithm: self.algorithm,
            public,
        }
    }

    /// Recovers the shared secret of `ciphertext`.
    ///
    /// A ciphertext of the right size never fails: a modified one gives an unrelated secret
    /// (implicit rejection), so that decapsulation reveals nothing about it.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SecretBytes, Error> {
        let _dit = Dit::new();

        if ciphertext.len() != self.algorithm.ciphertext_size() {
            return Err(Error::InvalidLength);
        }

        let mut shared_secret = SecretBytes::zeroed(self.algorithm.shared_secret_size());

        match &self.secret {
            #[cfg(feature = "ml-kem")]
            Secret::MlKem {
                public,
                dk,
                decoded,
                ..
            } => {
                let p = &public.params;

                let decoded = decoded.get_or_init(|| mlkem::DecapsulationKey::new(dk, p));

                mlkem::decaps_internal(
                    public.form(),
                    decoded,
                    dk,
                    ciphertext,
                    p,
                    &mut shared_secret,
                );
            }
            #[cfg(feature = "frodokem")]
            Secret::Frodo { public, sk } => {
                frodokem::decapsulate(&public.params, sk, ciphertext, &mut shared_secret);
            }
        }

        Ok(shared_secret)
    }

    // The pairwise consistency test (SPEC 14.4): a fresh encapsulation decapsulates to its shared
    // secret. The outcome is public: key generation or import fails on it.
    fn consistent(&self) -> Result<bool, Error> {
        let encapsulation = self.public_key().encapsulate()?;

        let shared_secret = self.decapsulate(&encapsulation.ciphertext)?;

        Ok(ct::declassify_value(ct::equal(
            &shared_secret,
            &encapsulation.shared_secret,
        )))
    }

    // An imported key that fails the pairwise test is not a valid key.
    fn checked(self) -> Result<Self, Error> {
        if self.consistent()? {
            Ok(self)
        } else {
            Err(Error::InvalidPrivateKey)
        }
    }

    /// Exports the key in `format`. A raw ML-KEM key is its seed when the key holds one, otherwise
    /// the expanded decapsulation key; FrodoKEM keys have only the raw form.
    pub fn export_key(&self, format: KeyFormat) -> Result<SecretBytes, Error> {
        let _dit = Dit::new();

        let oid = self.algorithm.oid();

        match &self.secret {
            #[cfg(feature = "ml-kem")]
            Secret::MlKem {
                seed: Some(seed), ..
            } => export_private(format, oid, &encode_seed(seed), seed),
            #[cfg(feature = "ml-kem")]
            Secret::MlKem { seed: None, dk, .. } => {
                export_private(format, oid, &encode_expanded(dk), dk)
            }
            #[cfg(feature = "frodokem")]
            Secret::Frodo { sk, .. } => export_private(format, oid, &[], sk),
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

/// A KEM key pair.
#[derive(Debug)]
pub struct KemKeyPair {
    /// The public key.
    pub public_key: KemPublicKey,
    /// The private key.
    pub private_key: KemPrivateKey,
}

#[cfg(all(test, feature = "ml-kem"))]
mod tests {
    use super::*;
    use crate::hazmat;

    fn part(key: &KemPrivateKey) -> &MlKemPublic {
        match &key.secret {
            Secret::MlKem { public, .. } => public,
            #[cfg(feature = "frodokem")]
            Secret::Frodo { .. } => panic!("an ML-KEM key"),
        }
    }

    fn filled(key: &KemPrivateKey) -> (bool, bool) {
        match &key.secret {
            Secret::MlKem {
                public, decoded, ..
            } => (public.form.get().is_some(), decoded.get().is_some()),
            #[cfg(feature = "frodokem")]
            Secret::Frodo { .. } => panic!("an ML-KEM key"),
        }
    }

    fn public_part(key: &KemPublicKey) -> &MlKemPublic {
        match &key.public {
            PublicPart::MlKem(part) => part,
            #[cfg(feature = "frodokem")]
            PublicPart::Frodo(_) => panic!("an ML-KEM key"),
        }
    }

    // The caches fill on first use, which for a generated key is its self-test, and a key pair
    // shares one public part.
    #[test]
    fn caches_fill_on_first_use_and_are_shared() {
        for algorithm in [ML_KEM_512, ML_KEM_768, ML_KEM_1024] {
            let seed = [7; 64];

            let pair = hazmat::generate_kem_key_pair(algorithm, &seed[..algorithm.seed_size()])
                .expect("key pair");

            let (public_key, private_key) = (&pair.public_key, &pair.private_key);

            assert!(core::ptr::eq(public_part(public_key), part(private_key)));

            assert_eq!(filled(private_key), (false, false));

            let randomness = [9; 64];

            let encapsulation =
                hazmat::encapsulate(public_key, &randomness[..algorithm.randomness_size()])
                    .expect("encapsulation");

            assert_eq!(filled(private_key), (true, false));

            let shared_secret = private_key
                .decapsulate(&encapsulation.ciphertext)
                .expect("decapsulation");

            assert_eq!(*shared_secret, *encapsulation.shared_secret);

            assert_eq!(filled(private_key), (true, true));

            let raw = public_key.export_key(KeyFormat::Raw).expect("export");

            let imported = algorithm
                .import_public_key(&raw, KeyFormat::Raw)
                .expect("import");

            assert!(public_part(&imported).form.get().is_none());

            let clone = imported.clone();

            assert!(core::ptr::eq(public_part(&clone), public_part(&imported)));

            hazmat::encapsulate(&clone, &randomness[..algorithm.randomness_size()])
                .expect("encapsulation");

            assert!(public_part(&imported).form.get().is_some());

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
                .generate_key_pair(&KeyGenOptions::default().with_self_test(false))
                .expect("key pair");

            assert_eq!(filled(&untested.private_key), (false, false));
        }
    }

    // An expanded key without its seed passes the pairwise test on import, which fills both
    // caches.
    #[test]
    fn expanded_keys_are_tested_on_import() {
        let pair = hazmat::generate_kem_key_pair(ML_KEM_768, &[3; 64]).expect("key pair");

        let Secret::MlKem { dk, .. } = &pair.private_key.secret else {
            panic!("an ML-KEM key");
        };

        let imported = ML_KEM_768
            .import_private_key(dk, KeyFormat::Raw)
            .expect("import");

        assert_eq!(filled(&imported), (true, true));

        let encapsulation = imported.public_key().encapsulate().expect("encapsulation");

        let shared_secret = imported
            .decapsulate(&encapsulation.ciphertext)
            .expect("decapsulation");

        assert_eq!(*shared_secret, *encapsulation.shared_secret);
    }
}

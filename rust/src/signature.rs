use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::ct;
use crate::error::Error;
use crate::hash::{HashAlgorithm, SHAKE128, XofAlgorithm};
use crate::keys::{
    KeyFormat, KeyGenOptions, PrivateInput, SeedChoice, check_size, decode_seed_choice,
    encode_expanded, encode_seed, export_private, export_public, import_private, import_public,
};
use crate::mldsa;
use crate::rng::random_bytes;
use crate::slhdsa;
use crate::wipe::SecretBytes;

const SELF_TEST_MESSAGE: &[u8] = b"crypto-pq pairwise consistency test";

const ML_DSA_SEED_SIZE: usize = 32;

const ML_DSA_RANDOMNESS_SIZE: usize = 32;

const MAX_CONTEXT_SIZE: usize = 255;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PreHashKind {
    Hash(HashAlgorithm),
    Xof(XofAlgorithm),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PreHash(PreHashKind);

impl fmt::Debug for PreHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.0 {
            PreHashKind::Hash(algorithm) => algorithm.name(),
            PreHashKind::Xof(algorithm) => algorithm.name(),
        };

        f.debug_tuple("PreHash").field(&name).finish()
    }
}

impl From<HashAlgorithm> for PreHash {
    fn from(algorithm: HashAlgorithm) -> Self {
        Self(PreHashKind::Hash(algorithm))
    }
}

impl From<XofAlgorithm> for PreHash {
    fn from(algorithm: XofAlgorithm) -> Self {
        Self(PreHashKind::Xof(algorithm))
    }
}

impl PreHash {
    // DER of the OID 2.16.840.1.101.3.4.2.x.
    const fn oid(&self) -> [u8; 11] {
        let arc = match self.0 {
            PreHashKind::Hash(algorithm) => algorithm.oid_arc(),
            PreHashKind::Xof(algorithm) => algorithm.oid_arc(),
        };

        [
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, arc,
        ]
    }

    // FIPS 204 and FIPS 205 take 256 bits of SHAKE128 and 512 of SHAKE256.
    fn output_size(&self) -> usize {
        match self.0 {
            PreHashKind::Hash(algorithm) => algorithm.digest_size(),
            PreHashKind::Xof(algorithm) if algorithm == SHAKE128 => 32,
            PreHashKind::Xof(_) => 64,
        }
    }

    // Collision strength in bits: half the output.
    fn strength(&self) -> usize {
        4 * self.output_size()
    }

    fn digest(&self, message: &[u8]) -> Vec<u8> {
        match self.0 {
            PreHashKind::Hash(algorithm) => algorithm.digest(message),
            PreHashKind::Xof(algorithm) => algorithm.digest(message, self.output_size()),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignOptions<'a> {
    pub context: &'a [u8],
    pub deterministic: bool,
    pub pre_hash: Option<PreHash>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VerifyOptions<'a> {
    pub context: &'a [u8],
    pub pre_hash: Option<PreHash>,
}

// FIPS 204 and FIPS 205: M' = 0 || |ctx| || ctx || M, or 1 || |ctx| || ctx || OID || PH(M). The
// prefix is built apart from M so that a long message is never copied.
struct Representative<'a> {
    prefix: Vec<u8>,
    message: &'a [u8],
}

impl<'a> Representative<'a> {
    fn new(message: &'a [u8], context: &[u8], pre_hash: Option<PreHash>) -> Self {
        let mut prefix = vec![u8::from(pre_hash.is_some()), context.len() as u8];

        prefix.extend_from_slice(context);

        match pre_hash {
            None => Self { prefix, message },
            Some(pre_hash) => {
                prefix.extend_from_slice(&pre_hash.oid());

                prefix.extend_from_slice(&pre_hash.digest(message));

                Self {
                    prefix,
                    message: &[],
                }
            }
        }
    }

    fn parts(&self) -> [&[u8]; 2] {
        [&self.prefix, self.message]
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Scheme {
    MlDsa(mldsa::Parameters),
    SlhDsa(slhdsa::Parameters),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignatureAlgorithm {
    name: &'static str,
    scheme: Scheme,
    oid: [u8; 9],
}

const fn oid(arc: u8) -> [u8; 9] {
    [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, arc]
}

const fn ml_dsa(name: &'static str, parameters: mldsa::Parameters, arc: u8) -> SignatureAlgorithm {
    SignatureAlgorithm {
        name,
        scheme: Scheme::MlDsa(parameters),
        oid: oid(arc),
    }
}

const fn slh_dsa(
    name: &'static str,
    parameters: slhdsa::Parameters,
    arc: u8,
) -> SignatureAlgorithm {
    SignatureAlgorithm {
        name,
        scheme: Scheme::SlhDsa(parameters),
        oid: oid(arc),
    }
}

pub const ML_DSA_44: SignatureAlgorithm = ml_dsa("ML-DSA-44", mldsa::ML_DSA_44, 17);

pub const ML_DSA_65: SignatureAlgorithm = ml_dsa("ML-DSA-65", mldsa::ML_DSA_65, 18);

pub const ML_DSA_87: SignatureAlgorithm = ml_dsa("ML-DSA-87", mldsa::ML_DSA_87, 19);

pub const SLH_DSA_SHA2_128S: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHA2-128s", slhdsa::SHA2_128S, 20);

pub const SLH_DSA_SHA2_128F: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHA2-128f", slhdsa::SHA2_128F, 21);

pub const SLH_DSA_SHA2_192S: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHA2-192s", slhdsa::SHA2_192S, 22);

pub const SLH_DSA_SHA2_192F: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHA2-192f", slhdsa::SHA2_192F, 23);

pub const SLH_DSA_SHA2_256S: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHA2-256s", slhdsa::SHA2_256S, 24);

pub const SLH_DSA_SHA2_256F: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHA2-256f", slhdsa::SHA2_256F, 25);

pub const SLH_DSA_SHAKE_128S: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHAKE-128s", slhdsa::SHAKE_128S, 26);

pub const SLH_DSA_SHAKE_128F: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHAKE-128f", slhdsa::SHAKE_128F, 27);

pub const SLH_DSA_SHAKE_192S: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHAKE-192s", slhdsa::SHAKE_192S, 28);

pub const SLH_DSA_SHAKE_192F: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHAKE-192f", slhdsa::SHAKE_192F, 29);

pub const SLH_DSA_SHAKE_256S: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHAKE-256s", slhdsa::SHAKE_256S, 30);

pub const SLH_DSA_SHAKE_256F: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHAKE-256f", slhdsa::SHAKE_256F, 31);

impl SignatureAlgorithm {
    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn public_key_size(&self) -> usize {
        match self.scheme {
            Scheme::MlDsa(p) => p.public_key_size(),
            Scheme::SlhDsa(p) => p.public_key_size(),
        }
    }

    pub const fn signature_size(&self) -> usize {
        match self.scheme {
            Scheme::MlDsa(p) => p.signature_size(),
            Scheme::SlhDsa(p) => p.signature_size(),
        }
    }

    pub fn generate_key_pair(&self, options: &KeyGenOptions) -> Result<SignatureKeyPair, Error> {
        let private_key = self.key_from_seed(&random_bytes(self.seed_size())?);

        let public_key = private_key.public_key();

        if options.self_test {
            let options = SignOptions {
                deterministic: true,
                ..SignOptions::default()
            };

            let signature = private_key.sign(SELF_TEST_MESSAGE, &options)?;

            if !public_key.verify(&signature, SELF_TEST_MESSAGE, &VerifyOptions::default()) {
                return Err(Error::SelfTestFailed);
            }
        }

        Ok(SignatureKeyPair {
            public_key,
            private_key,
        })
    }

    pub fn import_public_key(
        &self,
        data: &[u8],
        format: KeyFormat,
    ) -> Result<SignaturePublicKey, Error> {
        let key = import_public(format, data, Some(&self.oid))?;

        check_size(format, key.len(), self.public_key_size())?;

        Ok(SignaturePublicKey {
            algorithm: *self,
            key,
        })
    }

    pub fn import_private_key(
        &self,
        data: &[u8],
        format: KeyFormat,
    ) -> Result<SignaturePrivateKey, Error> {
        let input = import_private(format, data, Some(&self.oid))?;

        let (key, public_key) = match (input, self.scheme) {
            (PrivateInput::Raw(raw), Scheme::SlhDsa(p)) => {
                (self.import_slh_dsa(p, KeyFormat::Raw, &raw)?, None)
            }
            (PrivateInput::Pkcs8 { key, public_key }, Scheme::SlhDsa(p)) => {
                (self.import_slh_dsa(p, format, &key)?, public_key)
            }
            (PrivateInput::Raw(raw), Scheme::MlDsa(p)) => (self.import_ml_dsa_raw(p, &raw)?, None),
            (PrivateInput::Pkcs8 { key, public_key }, Scheme::MlDsa(p)) => {
                (self.import_ml_dsa_choice(p, &key)?, public_key)
            }
        };

        if public_key.is_some_and(|public_key| public_key != key.public) {
            return Err(Error::InvalidPrivateKey);
        }

        Ok(key)
    }

    fn import_slh_dsa(
        &self,
        p: slhdsa::Parameters,
        format: KeyFormat,
        sk: &[u8],
    ) -> Result<SignaturePrivateKey, Error> {
        check_size(format, sk.len(), p.private_key_size())?;

        let n = p.n;

        let root = slhdsa::root(&p, &sk[..n], &sk[2 * n..3 * n]);

        if !ct::equal(&root[..n], &sk[3 * n..]) {
            return Err(Error::InvalidPrivateKey);
        }

        Ok(SignaturePrivateKey {
            algorithm: *self,
            seed: None,
            private: SecretBytes::concat(&[sk]),
            public: sk[2 * n..].to_vec(),
        })
    }

    fn import_ml_dsa_raw(
        &self,
        p: mldsa::Parameters,
        raw: &[u8],
    ) -> Result<SignaturePrivateKey, Error> {
        if raw.len() == ML_DSA_SEED_SIZE {
            return Ok(self.key_from_seed(raw));
        }

        check_size(KeyFormat::Raw, raw.len(), p.private_key_size())?;

        self.key_from_expanded(p, raw)
    }

    fn import_ml_dsa_choice(
        &self,
        p: mldsa::Parameters,
        octets: &[u8],
    ) -> Result<SignaturePrivateKey, Error> {
        match decode_seed_choice(octets, ML_DSA_SEED_SIZE, p.private_key_size())? {
            SeedChoice::Seed(seed) => Ok(self.key_from_seed(seed)),
            SeedChoice::Expanded(expanded) => self.key_from_expanded(p, expanded),
            SeedChoice::Both { seed, expanded } => {
                let key = self.key_from_seed(seed);

                if !ct::equal(&key.private, expanded) {
                    return Err(Error::InvalidPrivateKey);
                }

                Ok(key)
            }
        }
    }

    fn key_from_expanded(
        &self,
        p: mldsa::Parameters,
        sk: &[u8],
    ) -> Result<SignaturePrivateKey, Error> {
        let public = mldsa::check_private_key(sk, &p).ok_or(Error::InvalidPrivateKey)?;

        Ok(SignaturePrivateKey {
            algorithm: *self,
            seed: None,
            private: SecretBytes::concat(&[sk]),
            public,
        })
    }

    // ML-DSA keeps the seed as its private key; SLH-DSA keeps the 4n-byte key.
    pub(crate) fn key_from_seed(&self, seed: &[u8]) -> SignaturePrivateKey {
        match self.scheme {
            Scheme::MlDsa(p) => {
                let (public, private) = mldsa::keygen_internal(seed, &p);

                SignaturePrivateKey {
                    algorithm: *self,
                    seed: Some(SecretBytes::concat(&[seed])),
                    private,
                    public,
                }
            }
            Scheme::SlhDsa(p) => {
                let n = p.n;

                let (private, public) =
                    slhdsa::keygen_internal(&seed[..n], &seed[n..2 * n], &seed[2 * n..], &p);

                SignaturePrivateKey {
                    algorithm: *self,
                    seed: None,
                    private,
                    public,
                }
            }
        }
    }

    pub(crate) const fn seed_size(&self) -> usize {
        match self.scheme {
            Scheme::MlDsa(_) => ML_DSA_SEED_SIZE,
            Scheme::SlhDsa(p) => 3 * p.n,
        }
    }

    pub(crate) const fn randomness_size(&self) -> usize {
        match self.scheme {
            Scheme::MlDsa(_) => ML_DSA_RANDOMNESS_SIZE,
            Scheme::SlhDsa(p) => p.n,
        }
    }

    // A pre-hash must give at least the collision strength of the signature (FIPS 204, 5.4, and
    // FIPS 205, 10.2).
    fn too_weak(&self, pre_hash: Option<PreHash>, policy: bool) -> bool {
        let strength = match self.scheme {
            Scheme::MlDsa(p) => p.lambda,
            Scheme::SlhDsa(p) => 8 * p.n,
        };

        policy && pre_hash.is_some_and(|pre_hash| pre_hash.strength() < strength)
    }
}

impl fmt::Debug for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SignatureAlgorithm")
            .field(&self.name)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SignaturePublicKey {
    algorithm: SignatureAlgorithm,
    key: Vec<u8>,
}

impl SignaturePublicKey {
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    // Fails closed: a long context, a wrong signature length or a weak pre-hash is just false.
    pub fn verify(&self, signature: &[u8], message: &[u8], options: &VerifyOptions) -> bool {
        self.verify_with(signature, message, options, true)
    }

    pub(crate) fn verify_with(
        &self,
        signature: &[u8],
        message: &[u8],
        options: &VerifyOptions,
        policy: bool,
    ) -> bool {
        let algorithm = self.algorithm;

        if algorithm.too_weak(options.pre_hash, policy)
            || options.context.len() > MAX_CONTEXT_SIZE
            || signature.len() != algorithm.signature_size()
        {
            return false;
        }

        let representative = Representative::new(message, options.context, options.pre_hash);

        let parts = representative.parts();

        match algorithm.scheme {
            Scheme::MlDsa(p) => mldsa::verify_internal(&self.key, &parts, signature, &p),
            Scheme::SlhDsa(p) => slhdsa::verify_internal(&parts, signature, &self.key, &p),
        }
    }

    pub fn export_key(&self, format: KeyFormat) -> Result<Vec<u8>, Error> {
        export_public(format, Some(&self.algorithm.oid), &self.key)
    }
}

impl fmt::Debug for SignaturePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignaturePublicKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

// The secret fields are SecretBytes, which wipe themselves when the key is dropped.
pub struct SignaturePrivateKey {
    algorithm: SignatureAlgorithm,
    seed: Option<SecretBytes>,
    private: SecretBytes,
    public: Vec<u8>,
}

impl SignaturePrivateKey {
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    pub fn public_key(&self) -> SignaturePublicKey {
        SignaturePublicKey {
            algorithm: self.algorithm,
            key: self.public.clone(),
        }
    }

    pub fn sign(&self, message: &[u8], options: &SignOptions) -> Result<Vec<u8>, Error> {
        self.check_options(options, true)?;

        let randomness = match (options.deterministic, self.algorithm.scheme) {
            (true, Scheme::MlDsa(_)) => SecretBytes::zeroed(ML_DSA_RANDOMNESS_SIZE),
            (true, Scheme::SlhDsa(p)) => SecretBytes::concat(&[&self.private[2 * p.n..3 * p.n]]),
            (false, _) => random_bytes(self.algorithm.randomness_size())?,
        };

        Ok(self.sign_with(message, &randomness, options))
    }

    pub(crate) fn check_options(&self, options: &SignOptions, policy: bool) -> Result<(), Error> {
        if self.algorithm.too_weak(options.pre_hash, policy) {
            return Err(Error::InvalidOption);
        }

        if options.context.len() > MAX_CONTEXT_SIZE {
            return Err(Error::InvalidContext);
        }

        Ok(())
    }

    pub(crate) fn sign_with(
        &self,
        message: &[u8],
        randomness: &[u8],
        options: &SignOptions,
    ) -> Vec<u8> {
        let representative = Representative::new(message, options.context, options.pre_hash);

        let parts = representative.parts();

        match self.algorithm.scheme {
            Scheme::MlDsa(p) => mldsa::sign_internal(&self.private, &parts, randomness, &p),
            Scheme::SlhDsa(p) => slhdsa::sign_internal(&parts, &self.private, randomness, &p),
        }
    }

    pub fn export_key(&self, format: KeyFormat) -> Result<Vec<u8>, Error> {
        let oid = Some(&self.algorithm.oid[..]);

        match (&self.seed, self.algorithm.scheme) {
            (_, Scheme::SlhDsa(_)) => export_private(format, oid, &self.private, &self.private),
            (Some(seed), Scheme::MlDsa(_)) => export_private(format, oid, &encode_seed(seed), seed),
            (None, Scheme::MlDsa(_)) => {
                export_private(format, oid, &encode_expanded(&self.private), &self.private)
            }
        }
    }
}

impl fmt::Debug for SignaturePrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignaturePrivateKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct SignatureKeyPair {
    pub public_key: SignaturePublicKey,
    pub private_key: SignaturePrivateKey,
}

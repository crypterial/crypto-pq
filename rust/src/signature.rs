use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::hash::{Hash, Hasher};

use crate::cpu::Dit;
use crate::ct;
#[cfg(feature = "slh-dsa")]
use crate::ct::declassify;
use crate::error::Error;
use crate::hash::{HashAlgorithm, SHA_256, SHA_512, SHAKE128, SHAKE256, XofAlgorithm};
use crate::keys::{
    KeyFormat, KeyGenOptions, PrivateInput, check_size, export_private, export_public,
    import_private, import_public,
};
#[cfg(feature = "ml-dsa")]
use crate::keys::{SeedChoice, decode_seed_choice, encode_expanded, encode_seed};
#[cfg(feature = "ml-dsa")]
use crate::mldsa::{self, SigningKey};
use crate::once::{OnceBox, Shared};
use crate::rng::random_bytes;
#[cfg(feature = "slh-dsa")]
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

/// The hash function of HashML-DSA or HashSLH-DSA, made from a [`HashAlgorithm`] or an
/// [`XofAlgorithm`] with `From`. FIPS 204 and FIPS 205 allow SHA-2, SHA-3, SHAKE128 and SHAKE256;
/// the others are refused.
///
/// The function must also give at least the collision strength of the signature: 128 bits for
/// ML-DSA-44 and the SLH-DSA 128 sets (SHA-256, SHA-384, SHA-512, SHA-512/256, SHA3-256, SHA3-384,
/// SHA3-512, SHAKE128, SHAKE256), 192 bits for ML-DSA-65 and the 192 sets (SHA-384, SHA-512,
/// SHA3-384, SHA3-512, SHAKE256) and 256 bits for ML-DSA-87 and the 256 sets (SHA-512, SHA3-512,
/// SHAKE256). SHA-224, SHA-512/224 and SHA3-224 are never accepted. A refused pre-hash fails
/// signing with [`Error::InvalidOption`] and makes verification return `false`; the policy has no
/// switch.
///
/// The crate computes the pre-hash from the message. Outside the `hazmat` test functions, no
/// operation takes μ, the message representative or a precomputed digest in place of the message.
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

    // FIPS 204 and FIPS 205 allow only hash functions with a NIST identifier; the others, such as
    // BLAKE2, Ascon-Hash256 and cSHAKE, are refused.
    const fn approved(&self) -> bool {
        let arc = match self.0 {
            PreHashKind::Hash(algorithm) => algorithm.oid_arc(),
            PreHashKind::Xof(algorithm) => algorithm.oid_arc(),
        };

        arc != 0
    }

    // Collision strength in bits: half the output.
    fn strength(&self) -> usize {
        4 * self.output_size()
    }

    fn digest(&self, message: &[u8]) -> Vec<u8> {
        match self.0 {
            PreHashKind::Hash(algorithm) => algorithm.digest(message),
            PreHashKind::Xof(algorithm) => {
                let mut out = vec![0; self.output_size()];

                algorithm.digest_unchecked(message, &mut out);

                out
            }
        }
    }
}

// The pre-hash that RFC 9909 fixes for each HashSLH-DSA value.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Fixed {
    Sha256,
    Sha512,
    Shake128,
    Shake256,
}

impl Fixed {
    const fn pre_hash(self) -> PreHash {
        PreHash(match self {
            Self::Sha256 => PreHashKind::Hash(SHA_256),
            Self::Sha512 => PreHashKind::Hash(SHA_512),
            Self::Shake128 => PreHashKind::Xof(SHAKE128),
            Self::Shake256 => PreHashKind::Xof(SHAKE256),
        })
    }
}

/// The options of signing.
///
/// Use one key with only one of the hedged and deterministic variants, and with only one of the
/// pure and pre-hash modes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SignOptions<'a> {
    /// The context string, 0 to 255 bytes.
    pub context: &'a [u8],
    /// The deterministic variant instead of hedged signing, which adds fresh randomness.
    pub deterministic: bool,
    /// HashML-DSA or HashSLH-DSA with this function instead of the pure mode. It must give at least
    /// the collision strength of the signature.
    pub pre_hash: Option<PreHash>,
}

impl<'a> SignOptions<'a> {
    /// These options with `context` set.
    #[must_use]
    pub const fn with_context(mut self, context: &'a [u8]) -> Self {
        self.context = context;

        self
    }

    /// These options with `deterministic` set.
    #[must_use]
    pub const fn with_deterministic(mut self, deterministic: bool) -> Self {
        self.deterministic = deterministic;

        self
    }

    /// These options with `pre_hash` set.
    #[must_use]
    pub fn with_pre_hash(mut self, pre_hash: impl Into<PreHash>) -> Self {
        self.pre_hash = Some(pre_hash.into());

        self
    }
}

/// The options of verification, which must match those of signing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifyOptions<'a> {
    /// The context string that the signature was made with.
    pub context: &'a [u8],
    /// The pre-hash that the signature was made with, if any.
    pub pre_hash: Option<PreHash>,
}

impl<'a> VerifyOptions<'a> {
    /// These options with `context` set.
    #[must_use]
    pub const fn with_context(mut self, context: &'a [u8]) -> Self {
        self.context = context;

        self
    }

    /// These options with `pre_hash` set.
    #[must_use]
    pub fn with_pre_hash(mut self, pre_hash: impl Into<PreHash>) -> Self {
        self.pre_hash = Some(pre_hash.into());

        self
    }
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
    #[cfg(feature = "ml-dsa")]
    MlDsa(mldsa::Parameters),
    #[cfg(feature = "slh-dsa")]
    SlhDsa(slhdsa::Parameters),
}

/// A stateless signature algorithm: ML-DSA (FIPS 204), SLH-DSA (FIPS 205), or HashSLH-DSA with
/// the pre-hash that RFC 9909 fixes for it.
// fixed: the pre-hash of a HashSLH-DSA value, which every signature under it uses.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignatureAlgorithm {
    name: &'static str,
    scheme: Scheme,
    oid: [u8; 9],
    fixed: Option<Fixed>,
}

const fn oid(arc: u8) -> [u8; 9] {
    [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, arc]
}

#[cfg(feature = "ml-dsa")]
const fn ml_dsa(name: &'static str, parameters: mldsa::Parameters, arc: u8) -> SignatureAlgorithm {
    SignatureAlgorithm {
        name,
        scheme: Scheme::MlDsa(parameters),
        oid: oid(arc),
        fixed: None,
    }
}

#[cfg(feature = "slh-dsa")]
const fn slh_dsa(
    name: &'static str,
    parameters: slhdsa::Parameters,
    arc: u8,
) -> SignatureAlgorithm {
    SignatureAlgorithm {
        name,
        scheme: Scheme::SlhDsa(parameters),
        oid: oid(arc),
        fixed: None,
    }
}

// RFC 9909, 3 and 4: HashSLH-DSA with the pre-hash of its identifier, which keys, sizes and raw
// formats share with the pure value of the same set.
#[cfg(feature = "slh-dsa")]
const fn hash_slh_dsa(
    name: &'static str,
    parameters: slhdsa::Parameters,
    arc: u8,
    fixed: Fixed,
) -> SignatureAlgorithm {
    SignatureAlgorithm {
        name,
        scheme: Scheme::SlhDsa(parameters),
        oid: oid(arc),
        fixed: Some(fixed),
    }
}

/// ML-DSA-44 (FIPS 204), security category 2.
#[cfg(feature = "ml-dsa")]
pub const ML_DSA_44: SignatureAlgorithm = ml_dsa("ML-DSA-44", mldsa::ML_DSA_44, 17);

/// ML-DSA-65 (FIPS 204), security category 3.
#[cfg(feature = "ml-dsa")]
pub const ML_DSA_65: SignatureAlgorithm = ml_dsa("ML-DSA-65", mldsa::ML_DSA_65, 18);

/// ML-DSA-87 (FIPS 204), security category 5.
#[cfg(feature = "ml-dsa")]
pub const ML_DSA_87: SignatureAlgorithm = ml_dsa("ML-DSA-87", mldsa::ML_DSA_87, 19);

/// SLH-DSA-SHA2-128s (FIPS 205), security category 1, the set for small signatures.
#[cfg(feature = "slh-dsa")]
pub const SLH_DSA_SHA2_128S: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHA2-128s", slhdsa::SHA2_128S, 20);

/// SLH-DSA-SHA2-128f (FIPS 205), security category 1, the set for less signing work.
#[cfg(feature = "slh-dsa")]
pub const SLH_DSA_SHA2_128F: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHA2-128f", slhdsa::SHA2_128F, 21);

/// SLH-DSA-SHA2-192s (FIPS 205), security category 3, the set for small signatures.
#[cfg(feature = "slh-dsa")]
pub const SLH_DSA_SHA2_192S: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHA2-192s", slhdsa::SHA2_192S, 22);

/// SLH-DSA-SHA2-192f (FIPS 205), security category 3, the set for less signing work.
#[cfg(feature = "slh-dsa")]
pub const SLH_DSA_SHA2_192F: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHA2-192f", slhdsa::SHA2_192F, 23);

/// SLH-DSA-SHA2-256s (FIPS 205), security category 5, the set for small signatures.
#[cfg(feature = "slh-dsa")]
pub const SLH_DSA_SHA2_256S: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHA2-256s", slhdsa::SHA2_256S, 24);

/// SLH-DSA-SHA2-256f (FIPS 205), security category 5, the set for less signing work.
#[cfg(feature = "slh-dsa")]
pub const SLH_DSA_SHA2_256F: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHA2-256f", slhdsa::SHA2_256F, 25);

/// SLH-DSA-SHAKE-128s (FIPS 205), security category 1, the set for small signatures.
#[cfg(feature = "slh-dsa")]
pub const SLH_DSA_SHAKE_128S: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHAKE-128s", slhdsa::SHAKE_128S, 26);

/// SLH-DSA-SHAKE-128f (FIPS 205), security category 1, the set for less signing work.
#[cfg(feature = "slh-dsa")]
pub const SLH_DSA_SHAKE_128F: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHAKE-128f", slhdsa::SHAKE_128F, 27);

/// SLH-DSA-SHAKE-192s (FIPS 205), security category 3, the set for small signatures.
#[cfg(feature = "slh-dsa")]
pub const SLH_DSA_SHAKE_192S: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHAKE-192s", slhdsa::SHAKE_192S, 28);

/// SLH-DSA-SHAKE-192f (FIPS 205), security category 3, the set for less signing work.
#[cfg(feature = "slh-dsa")]
pub const SLH_DSA_SHAKE_192F: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHAKE-192f", slhdsa::SHAKE_192F, 29);

/// SLH-DSA-SHAKE-256s (FIPS 205), security category 5, the set for small signatures.
#[cfg(feature = "slh-dsa")]
pub const SLH_DSA_SHAKE_256S: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHAKE-256s", slhdsa::SHAKE_256S, 30);

/// SLH-DSA-SHAKE-256f (FIPS 205), security category 5, the set for less signing work.
#[cfg(feature = "slh-dsa")]
pub const SLH_DSA_SHAKE_256F: SignatureAlgorithm =
    slh_dsa("SLH-DSA-SHAKE-256f", slhdsa::SHAKE_256F, 31);

/// HashSLH-DSA-SHA2-128s-with-SHA256 (FIPS 205, RFC 9909), security category 1: every signature
/// pre-hashes the message with SHA-256.
#[cfg(feature = "slh-dsa")]
pub const HASH_SLH_DSA_SHA2_128S_WITH_SHA256: SignatureAlgorithm = hash_slh_dsa(
    "HashSLH-DSA-SHA2-128s-with-SHA256",
    slhdsa::SHA2_128S,
    35,
    Fixed::Sha256,
);

/// HashSLH-DSA-SHA2-128f-with-SHA256 (FIPS 205, RFC 9909), security category 1: every signature
/// pre-hashes the message with SHA-256.
#[cfg(feature = "slh-dsa")]
pub const HASH_SLH_DSA_SHA2_128F_WITH_SHA256: SignatureAlgorithm = hash_slh_dsa(
    "HashSLH-DSA-SHA2-128f-with-SHA256",
    slhdsa::SHA2_128F,
    36,
    Fixed::Sha256,
);

/// HashSLH-DSA-SHA2-192s-with-SHA512 (FIPS 205, RFC 9909), security category 3: every signature
/// pre-hashes the message with SHA-512.
#[cfg(feature = "slh-dsa")]
pub const HASH_SLH_DSA_SHA2_192S_WITH_SHA512: SignatureAlgorithm = hash_slh_dsa(
    "HashSLH-DSA-SHA2-192s-with-SHA512",
    slhdsa::SHA2_192S,
    37,
    Fixed::Sha512,
);

/// HashSLH-DSA-SHA2-192f-with-SHA512 (FIPS 205, RFC 9909), security category 3: every signature
/// pre-hashes the message with SHA-512.
#[cfg(feature = "slh-dsa")]
pub const HASH_SLH_DSA_SHA2_192F_WITH_SHA512: SignatureAlgorithm = hash_slh_dsa(
    "HashSLH-DSA-SHA2-192f-with-SHA512",
    slhdsa::SHA2_192F,
    38,
    Fixed::Sha512,
);

/// HashSLH-DSA-SHA2-256s-with-SHA512 (FIPS 205, RFC 9909), security category 5: every signature
/// pre-hashes the message with SHA-512.
#[cfg(feature = "slh-dsa")]
pub const HASH_SLH_DSA_SHA2_256S_WITH_SHA512: SignatureAlgorithm = hash_slh_dsa(
    "HashSLH-DSA-SHA2-256s-with-SHA512",
    slhdsa::SHA2_256S,
    39,
    Fixed::Sha512,
);

/// HashSLH-DSA-SHA2-256f-with-SHA512 (FIPS 205, RFC 9909), security category 5: every signature
/// pre-hashes the message with SHA-512.
#[cfg(feature = "slh-dsa")]
pub const HASH_SLH_DSA_SHA2_256F_WITH_SHA512: SignatureAlgorithm = hash_slh_dsa(
    "HashSLH-DSA-SHA2-256f-with-SHA512",
    slhdsa::SHA2_256F,
    40,
    Fixed::Sha512,
);

/// HashSLH-DSA-SHAKE-128s-with-SHAKE128 (FIPS 205, RFC 9909), security category 1: every signature
/// pre-hashes the message with SHAKE128.
#[cfg(feature = "slh-dsa")]
pub const HASH_SLH_DSA_SHAKE_128S_WITH_SHAKE128: SignatureAlgorithm = hash_slh_dsa(
    "HashSLH-DSA-SHAKE-128s-with-SHAKE128",
    slhdsa::SHAKE_128S,
    41,
    Fixed::Shake128,
);

/// HashSLH-DSA-SHAKE-128f-with-SHAKE128 (FIPS 205, RFC 9909), security category 1: every signature
/// pre-hashes the message with SHAKE128.
#[cfg(feature = "slh-dsa")]
pub const HASH_SLH_DSA_SHAKE_128F_WITH_SHAKE128: SignatureAlgorithm = hash_slh_dsa(
    "HashSLH-DSA-SHAKE-128f-with-SHAKE128",
    slhdsa::SHAKE_128F,
    42,
    Fixed::Shake128,
);

/// HashSLH-DSA-SHAKE-192s-with-SHAKE256 (FIPS 205, RFC 9909), security category 3: every signature
/// pre-hashes the message with SHAKE256.
#[cfg(feature = "slh-dsa")]
pub const HASH_SLH_DSA_SHAKE_192S_WITH_SHAKE256: SignatureAlgorithm = hash_slh_dsa(
    "HashSLH-DSA-SHAKE-192s-with-SHAKE256",
    slhdsa::SHAKE_192S,
    43,
    Fixed::Shake256,
);

/// HashSLH-DSA-SHAKE-192f-with-SHAKE256 (FIPS 205, RFC 9909), security category 3: every signature
/// pre-hashes the message with SHAKE256.
#[cfg(feature = "slh-dsa")]
pub const HASH_SLH_DSA_SHAKE_192F_WITH_SHAKE256: SignatureAlgorithm = hash_slh_dsa(
    "HashSLH-DSA-SHAKE-192f-with-SHAKE256",
    slhdsa::SHAKE_192F,
    44,
    Fixed::Shake256,
);

/// HashSLH-DSA-SHAKE-256s-with-SHAKE256 (FIPS 205, RFC 9909), security category 5: every signature
/// pre-hashes the message with SHAKE256.
#[cfg(feature = "slh-dsa")]
pub const HASH_SLH_DSA_SHAKE_256S_WITH_SHAKE256: SignatureAlgorithm = hash_slh_dsa(
    "HashSLH-DSA-SHAKE-256s-with-SHAKE256",
    slhdsa::SHAKE_256S,
    45,
    Fixed::Shake256,
);

/// HashSLH-DSA-SHAKE-256f-with-SHAKE256 (FIPS 205, RFC 9909), security category 5: every signature
/// pre-hashes the message with SHAKE256.
#[cfg(feature = "slh-dsa")]
pub const HASH_SLH_DSA_SHAKE_256F_WITH_SHAKE256: SignatureAlgorithm = hash_slh_dsa(
    "HashSLH-DSA-SHAKE-256f-with-SHAKE256",
    slhdsa::SHAKE_256F,
    46,
    Fixed::Shake256,
);

impl SignatureAlgorithm {
    /// The name of the algorithm, such as `"ML-DSA-65"`.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The size of a raw public key in bytes.
    pub const fn public_key_size(&self) -> usize {
        match self.scheme {
            #[cfg(feature = "ml-dsa")]
            Scheme::MlDsa(p) => p.public_key_size(),
            #[cfg(feature = "slh-dsa")]
            Scheme::SlhDsa(p) => p.public_key_size(),
        }
    }

    /// The size of a signature in bytes.
    pub const fn signature_size(&self) -> usize {
        match self.scheme {
            #[cfg(feature = "ml-dsa")]
            Scheme::MlDsa(p) => p.signature_size(),
            #[cfg(feature = "slh-dsa")]
            Scheme::SlhDsa(p) => p.signature_size(),
        }
    }

    /// Generates a key pair from the operating-system entropy source.
    ///
    /// With `options.self_test` (the default) a signature of a fixed message must verify, or the
    /// call fails with [`Error::SelfTestFailed`].
    // The self-test is the first use of the new keys, so it computes their cached forms from the
    // encoded keys and checks those too.
    pub fn generate_key_pair(&self, options: &KeyGenOptions) -> Result<SignatureKeyPair, Error> {
        let _dit = Dit::new();

        let private_key = self.key_from_seed(&random_bytes(self.seed_size())?);

        let public_key = private_key.public_key();

        if options.self_test {
            self_test(&private_key, &public_key)?;
        }

        Ok(SignatureKeyPair {
            public_key,
            private_key,
        })
    }

    /// Imports a public key in `format`.
    pub fn import_public_key(
        &self,
        data: &[u8],
        format: KeyFormat,
    ) -> Result<SignaturePublicKey, Error> {
        let key = import_public(format, data, Some(&self.oid))?;

        check_size(format, key.len(), self.public_key_size())?;

        Ok(SignaturePublicKey {
            algorithm: *self,
            public: Shared::new(PublicPart::new(self.scheme, key)),
        })
    }

    /// Imports a private key in `format` and checks it. A raw ML-DSA key is the 32-byte seed or the
    /// expanded key; a raw SLH-DSA key is the 4n-byte key, whose public root must match its seeds.
    pub fn import_private_key(
        &self,
        data: &[u8],
        format: KeyFormat,
    ) -> Result<SignaturePrivateKey, Error> {
        let _dit = Dit::new();

        let input = import_private(format, data, Some(&self.oid))?;

        let (key, public_key) = match (input, self.scheme) {
            #[cfg(feature = "slh-dsa")]
            (PrivateInput::Raw(raw), Scheme::SlhDsa(p)) => {
                (self.import_slh_dsa(p, KeyFormat::Raw, &raw)?, None)
            }
            #[cfg(feature = "slh-dsa")]
            (PrivateInput::Pkcs8 { key, public_key }, Scheme::SlhDsa(p)) => {
                (self.import_slh_dsa(p, format, &key)?, public_key)
            }
            #[cfg(feature = "ml-dsa")]
            (PrivateInput::Raw(raw), Scheme::MlDsa(p)) => (self.import_ml_dsa_raw(p, &raw)?, None),
            #[cfg(feature = "ml-dsa")]
            (PrivateInput::Pkcs8 { key, public_key }, Scheme::MlDsa(p)) => {
                (self.import_ml_dsa_choice(p, &key)?, public_key)
            }
        };

        if public_key.is_some_and(|public_key| public_key != key.public.key) {
            return Err(Error::InvalidPrivateKey);
        }

        Ok(key)
    }

    #[cfg(feature = "slh-dsa")]
    fn import_slh_dsa(
        &self,
        p: slhdsa::Parameters,
        format: KeyFormat,
        sk: &[u8],
    ) -> Result<SignaturePrivateKey, Error> {
        check_size(format, sk.len(), p.private_key_size())?;

        let n = p.n;

        // PK.seed and PK.root are public, and so is whether the key is valid: importing it fails
        // otherwise.
        declassify(&sk[2 * n..]);

        let root = slhdsa::root(&p, &sk[..n], &sk[2 * n..3 * n]);

        if !ct::declassify_value(ct::equal(&root[..n], &sk[3 * n..])) {
            return Err(Error::InvalidPrivateKey);
        }

        Ok(SignaturePrivateKey {
            algorithm: *self,
            seed: None,
            private: SecretBytes::concat(&[sk]),
            public: Shared::new(PublicPart::new(self.scheme, sk[2 * n..].to_vec())),
            signing: None,
        })
    }

    #[cfg(feature = "ml-dsa")]
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

    #[cfg(feature = "ml-dsa")]
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

                if !ct::declassify_value(ct::equal(&key.private, expanded)) {
                    return Err(Error::InvalidPrivateKey);
                }

                Ok(key)
            }
        }
    }

    #[cfg(feature = "ml-dsa")]
    fn key_from_expanded(
        &self,
        p: mldsa::Parameters,
        sk: &[u8],
    ) -> Result<SignaturePrivateKey, Error> {
        let public = mldsa::check_private_key(sk, &p).ok_or(Error::InvalidPrivateKey)?;

        Ok(self.ml_dsa_key(p, None, SecretBytes::concat(&[sk]), public))
    }

    // ML-DSA keeps the seed as its private key; SLH-DSA keeps the 4n-byte key.
    pub(crate) fn key_from_seed(&self, seed: &[u8]) -> SignaturePrivateKey {
        let _dit = Dit::new();

        match self.scheme {
            #[cfg(feature = "ml-dsa")]
            Scheme::MlDsa(p) => {
                let (public, private) = mldsa::keygen_internal(seed, &p);

                self.ml_dsa_key(p, Some(SecretBytes::concat(&[seed])), private, public)
            }
            #[cfg(feature = "slh-dsa")]
            Scheme::SlhDsa(p) => {
                let n = p.n;

                let (private, public) =
                    slhdsa::keygen_internal(&seed[..n], &seed[n..2 * n], &seed[2 * n..], &p);

                SignaturePrivateKey {
                    algorithm: *self,
                    seed: None,
                    private,
                    public: Shared::new(PublicPart::new(self.scheme, public)),
                    signing: None,
                }
            }
        }
    }

    #[cfg(feature = "ml-dsa")]
    fn ml_dsa_key(
        &self,
        p: mldsa::Parameters,
        seed: Option<SecretBytes>,
        private: SecretBytes,
        public: Vec<u8>,
    ) -> SignaturePrivateKey {
        let signing = OnceBox::new(|| SigningKey::new(&private, &p));

        SignaturePrivateKey {
            algorithm: *self,
            seed,
            private,
            public: Shared::new(PublicPart::new(self.scheme, public)),
            signing: Some(signing),
        }
    }

    pub(crate) const fn seed_size(&self) -> usize {
        match self.scheme {
            #[cfg(feature = "ml-dsa")]
            Scheme::MlDsa(_) => ML_DSA_SEED_SIZE,
            #[cfg(feature = "slh-dsa")]
            Scheme::SlhDsa(p) => 3 * p.n,
        }
    }

    pub(crate) const fn randomness_size(&self) -> usize {
        match self.scheme {
            #[cfg(feature = "ml-dsa")]
            Scheme::MlDsa(_) => ML_DSA_RANDOMNESS_SIZE,
            #[cfg(feature = "slh-dsa")]
            Scheme::SlhDsa(p) => p.n,
        }
    }

    // A HashSLH-DSA value, whose keys sign only pre-hashed messages.
    #[cfg(any(feature = "hazmat", test))]
    pub(crate) const fn has_fixed_pre_hash(&self) -> bool {
        self.fixed.is_some()
    }

    // A pre-hash must give at least the collision strength of the signature (FIPS 204, 5.4, and
    // FIPS 205, 10.2).
    fn too_weak(&self, pre_hash: Option<PreHash>, policy: bool) -> bool {
        let strength = match self.scheme {
            #[cfg(feature = "ml-dsa")]
            Scheme::MlDsa(p) => p.lambda,
            #[cfg(feature = "slh-dsa")]
            Scheme::SlhDsa(p) => 8 * p.n,
        };

        policy && pre_hash.is_some_and(|pre_hash| pre_hash.strength() < strength)
    }

    // The pre-hash that a signature uses: the option, or the fixed function of a HashSLH-DSA
    // value, which the option may only name again (SPEC 9.4). INVALID_OPTION for a pre-hash that
    // is not approved, or too weak where the policy applies (hazmat skips it).
    fn pre_hash(&self, option: Option<PreHash>, policy: bool) -> Result<Option<PreHash>, Error> {
        let pre_hash = match (self.fixed, option) {
            (Some(fixed), None) => Some(fixed.pre_hash()),
            (Some(fixed), Some(option)) if option != fixed.pre_hash() => {
                return Err(Error::InvalidOption);
            }
            (_, option) => option,
        };

        if pre_hash.is_some_and(|pre_hash| !pre_hash.approved()) || self.too_weak(pre_hash, policy)
        {
            return Err(Error::InvalidOption);
        }

        Ok(pre_hash)
    }
}

// SPEC 9.1.7 and D-69: a fixed message, signed hedged in the algorithm's own mode and verified:
// pure for ML-DSA and SLH-DSA, and pre-hashed with the fixed function for HashSLH-DSA, which the
// default options select. Returns the signature, for the tests.
fn self_test(
    private_key: &SignaturePrivateKey,
    public_key: &SignaturePublicKey,
) -> Result<Vec<u8>, Error> {
    let signature = private_key.sign(SELF_TEST_MESSAGE, &SignOptions::default())?;

    if public_key.verify(&signature, SELF_TEST_MESSAGE, &VerifyOptions::default()) {
        Ok(signature)
    } else {
        Err(Error::SelfTestFailed)
    }
}

impl fmt::Debug for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SignatureAlgorithm")
            .field(&self.name)
            .finish()
    }
}

// SLH-DSA derives nothing from its keys: without ML-DSA in the build, the types of the cached
// forms are empty.
#[cfg(not(feature = "ml-dsa"))]
#[derive(Clone)]
struct Derived;

#[cfg(not(feature = "ml-dsa"))]
struct SigningKey;

// What ML-DSA derives from a public key, computed on first use so that no signature or
// verification samples the matrix or hashes the key again: Â for both, t̂1 and tr for
// verification alone.
#[cfg(feature = "ml-dsa")]
#[derive(Clone)]
struct Derived {
    matrix: OnceBox<mldsa::Matrix>,
    verifying: OnceBox<mldsa::VerifyingKey>,
}

#[cfg(feature = "ml-dsa")]
impl Derived {
    fn new(key: &[u8], p: mldsa::Parameters) -> Self {
        Self {
            matrix: OnceBox::new(|| mldsa::Matrix::new(key, &p)),
            verifying: OnceBox::new(|| mldsa::VerifyingKey::new(key)),
        }
    }

    fn matrix(&self, key: &[u8], p: &mldsa::Parameters) -> &mldsa::Matrix {
        self.matrix.get_or_init(|| mldsa::Matrix::new(key, p))
    }

    fn verifying(&self, key: &[u8]) -> &mldsa::VerifyingKey {
        self.verifying.get_or_init(|| mldsa::VerifyingKey::new(key))
    }

    // Both, for a verification. A key whose first use this is fills them together, which hashes
    // the key beside the sampling of the matrix.
    fn for_verify(
        &self,
        key: &[u8],
        p: &mldsa::Parameters,
    ) -> (&mldsa::Matrix, &mldsa::VerifyingKey) {
        if self.matrix.get().is_none() && self.verifying.get().is_none() {
            let (matrix, verifying) = mldsa::public_derived(key, p);

            return (
                self.matrix.get_or_init(|| matrix),
                self.verifying.get_or_init(|| verifying),
            );
        }

        (self.matrix(key, p), self.verifying(key))
    }
}

// A public key and what ML-DSA derives from it; SLH-DSA derives nothing. A private key and every
// public key that comes from it, clones included, share one.
#[derive(Clone)]
struct PublicPart {
    key: Vec<u8>,
    derived: Option<Derived>,
}

impl PublicPart {
    fn new(scheme: Scheme, key: Vec<u8>) -> Self {
        let derived = match scheme {
            #[cfg(feature = "ml-dsa")]
            Scheme::MlDsa(p) => Some(Derived::new(&key, p)),
            #[cfg(feature = "slh-dsa")]
            Scheme::SlhDsa(_) => None,
        };

        Self { key, derived }
    }
}

/// A signature public key. Equality and hashing compare the algorithm and the encoded key.
#[derive(Clone)]
pub struct SignaturePublicKey {
    algorithm: SignatureAlgorithm,
    public: Shared<PublicPart>,
}

impl PartialEq for SignaturePublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.public.key == other.public.key
    }
}

impl Eq for SignaturePublicKey {}

impl Hash for SignaturePublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.algorithm.hash(state);

        self.public.key.hash(state);
    }
}

impl SignaturePublicKey {
    /// The algorithm of the key.
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// Whether `signature` is a valid signature of `message` with these options. A context longer
    /// than 255 bytes, a signature of the wrong size, or a pre-hash that is not approved or too
    /// weak gives `false`.
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

        let Ok(pre_hash) = algorithm.pre_hash(options.pre_hash, policy) else {
            return false;
        };

        if options.context.len() > MAX_CONTEXT_SIZE || signature.len() != algorithm.signature_size()
        {
            return false;
        }

        let representative = Representative::new(message, options.context, pre_hash);

        self.verify_representative(&representative.parts(), signature)
    }

    // FIPS 204 Algorithm 8 or FIPS 205 Algorithm 20 on M', given in parts.
    pub(crate) fn verify_representative(&self, parts: &[&[u8]], signature: &[u8]) -> bool {
        let key = &self.public.key;

        match (self.algorithm.scheme, &self.public.derived) {
            #[cfg(feature = "ml-dsa")]
            (Scheme::MlDsa(p), Some(derived)) => {
                let (matrix, verifying) = derived.for_verify(key, &p);

                mldsa::verify_internal(matrix, verifying, parts, signature, &p)
            }
            #[cfg(feature = "slh-dsa")]
            (Scheme::SlhDsa(p), _) => slhdsa::verify_internal(parts, signature, key, &p),
            // Every ML-DSA key is made with its caches.
            #[cfg(feature = "ml-dsa")]
            (Scheme::MlDsa(_), None) => false,
        }
    }

    /// Exports the key in `format`.
    pub fn export_key(&self, format: KeyFormat) -> Result<Vec<u8>, Error> {
        export_public(format, Some(&self.algorithm.oid), &self.public.key)
    }
}

impl fmt::Debug for SignaturePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignaturePublicKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// A signature private key. Its secrets are wiped when it is dropped; it has neither `Clone` nor
/// `PartialEq`.
// The secret fields are SecretBytes, which wipe themselves when the key is dropped, as does
// `signing`, the form of an ML-DSA key that signing computes on first use.
pub struct SignaturePrivateKey {
    algorithm: SignatureAlgorithm,
    seed: Option<SecretBytes>,
    private: SecretBytes,
    public: Shared<PublicPart>,
    signing: Option<OnceBox<SigningKey>>,
}

impl SignaturePrivateKey {
    /// The algorithm of the key.
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// The public key of this private key.
    pub fn public_key(&self) -> SignaturePublicKey {
        SignaturePublicKey {
            algorithm: self.algorithm,
            public: self.public.clone(),
        }
    }

    /// Signs `message` with these options, hedged with randomness from the operating-system entropy
    /// source unless `options.deterministic` is set. A HashSLH-DSA key always pre-hashes with its
    /// fixed function, which `options.pre_hash` may only name again.
    pub fn sign(&self, message: &[u8], options: &SignOptions) -> Result<Vec<u8>, Error> {
        let _dit = Dit::new();

        let pre_hash = self.check_options(options, true)?;

        let randomness = match (options.deterministic, self.algorithm.scheme) {
            #[cfg(feature = "ml-dsa")]
            (true, Scheme::MlDsa(_)) => SecretBytes::zeroed(ML_DSA_RANDOMNESS_SIZE),
            #[cfg(feature = "slh-dsa")]
            (true, Scheme::SlhDsa(p)) => SecretBytes::concat(&[&self.private[2 * p.n..3 * p.n]]),
            (false, _) => random_bytes(self.algorithm.randomness_size())?,
        };

        Ok(self.sign_with(message, &randomness, options.context, pre_hash))
    }

    // The pre-hash that the signature uses, after the checks of the options (SPEC 7.3).
    pub(crate) fn check_options(
        &self,
        options: &SignOptions,
        policy: bool,
    ) -> Result<Option<PreHash>, Error> {
        let pre_hash = self.algorithm.pre_hash(options.pre_hash, policy)?;

        if options.context.len() > MAX_CONTEXT_SIZE {
            return Err(Error::InvalidContext);
        }

        Ok(pre_hash)
    }

    pub(crate) fn sign_with(
        &self,
        message: &[u8],
        randomness: &[u8],
        context: &[u8],
        pre_hash: Option<PreHash>,
    ) -> Vec<u8> {
        let representative = Representative::new(message, context, pre_hash);

        self.sign_representative(&representative.parts(), randomness)
    }

    // FIPS 204 Algorithm 7 or FIPS 205 Algorithm 19 on M', given in parts.
    pub(crate) fn sign_representative(&self, parts: &[&[u8]], randomness: &[u8]) -> Vec<u8> {
        let _dit = Dit::new();

        let sk = &self.private;

        match (self.algorithm.scheme, &self.public.derived, &self.signing) {
            #[cfg(feature = "ml-dsa")]
            (Scheme::MlDsa(p), Some(derived), Some(signing)) => {
                let matrix = derived.matrix(&self.public.key, &p);

                let key = signing.get_or_init(|| SigningKey::new(sk, &p));

                mldsa::sign_internal(matrix, key, sk, parts, randomness, &p)
            }
            #[cfg(feature = "slh-dsa")]
            (Scheme::SlhDsa(p), ..) => slhdsa::sign_internal(parts, sk, randomness, &p),
            #[cfg(feature = "ml-dsa")]
            (Scheme::MlDsa(_), ..) => unreachable!("every ML-DSA key is made with its caches"),
        }
    }

    /// Exports the key in `format`. A raw ML-DSA key is its seed when the key holds one, otherwise
    /// the expanded key.
    pub fn export_key(&self, format: KeyFormat) -> Result<SecretBytes, Error> {
        let _dit = Dit::new();

        let oid = Some(&self.algorithm.oid[..]);

        match (&self.seed, self.algorithm.scheme) {
            #[cfg(feature = "slh-dsa")]
            (_, Scheme::SlhDsa(_)) => export_private(format, oid, &self.private, &self.private),
            #[cfg(feature = "ml-dsa")]
            (Some(seed), Scheme::MlDsa(_)) => export_private(format, oid, &encode_seed(seed), seed),
            #[cfg(feature = "ml-dsa")]
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

/// A signature key pair.
#[derive(Debug)]
pub struct SignatureKeyPair {
    /// The public key.
    pub public_key: SignaturePublicKey,
    /// The private key.
    pub private_key: SignaturePrivateKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hazmat;

    // Whether Â, t̂1 and tr, and the signing form of a private key, are filled.
    #[cfg(feature = "ml-dsa")]
    fn filled(key: &SignaturePrivateKey) -> (bool, bool, bool) {
        let derived = key.public.derived.as_ref().expect("an ML-DSA key");

        (
            derived.matrix.get().is_some(),
            derived.verifying.get().is_some(),
            key.signing.as_ref().and_then(OnceBox::get).is_some(),
        )
    }

    #[cfg(feature = "ml-dsa")]
    const MESSAGE: &[u8] = b"lazy caches";

    // The caches fill on first use, which for a generated key is its self-test, and a key pair
    // shares one public part. Signing needs Â but not t̂1.
    #[cfg(feature = "ml-dsa")]
    #[test]
    fn caches_fill_on_first_use_and_are_shared() {
        let options = SignOptions::default().with_deterministic(true);

        for algorithm in [ML_DSA_44, ML_DSA_65, ML_DSA_87] {
            let pair = hazmat::generate_signature_key_pair(algorithm, &[5; 32]).expect("key pair");

            let (public_key, private_key) = (&pair.public_key, &pair.private_key);

            assert!(core::ptr::eq(&*public_key.public, &*private_key.public));

            assert_eq!(filled(private_key), (false, false, false));

            let signed = private_key.sign(MESSAGE, &options).expect("signature");

            assert_eq!(filled(private_key), (true, false, true));

            assert!(public_key.verify(&signed, MESSAGE, &VerifyOptions::default()));

            assert_eq!(filled(private_key), (true, true, true));

            let raw = public_key.export_key(KeyFormat::Raw).expect("export");

            let imported = algorithm
                .import_public_key(&raw, KeyFormat::Raw)
                .expect("import");

            let derived = imported.public.derived.as_ref().expect("an ML-DSA key");

            assert!(derived.matrix.get().is_none() && derived.verifying.get().is_none());

            assert!(imported.verify(&signed, MESSAGE, &VerifyOptions::default()));

            assert!(derived.matrix.get().is_some() && derived.verifying.get().is_some());

            for format in [KeyFormat::Raw, KeyFormat::Der] {
                let exported = private_key.export_key(format).expect("export");

                let reimported = algorithm
                    .import_private_key(&exported, format)
                    .expect("import");

                assert_eq!(filled(&reimported), (false, false, false));

                assert_eq!(reimported.sign(MESSAGE, &options), Ok(signed.clone()));
            }

            let generated = algorithm
                .generate_key_pair(&KeyGenOptions::default())
                .expect("key pair");

            assert_eq!(filled(&generated.private_key), (true, true, true));

            let untested = algorithm
                .generate_key_pair(&KeyGenOptions::default().with_self_test(false))
                .expect("key pair");

            assert_eq!(filled(&untested.private_key), (false, false, false));
        }
    }

    // D-69: the self-test signature of a HashSLH-DSA key is a pre-hash signature with its fixed
    // function, hedged, and that of an SLH-DSA key a pure one.
    #[cfg(feature = "slh-dsa")]
    #[test]
    fn self_test_in_the_algorithm_mode() {
        let seed = [6; 48];

        let hashed =
            hazmat::generate_signature_key_pair(HASH_SLH_DSA_SHAKE_128F_WITH_SHAKE128, &seed)
                .expect("key");

        let pure = hazmat::generate_signature_key_pair(SLH_DSA_SHAKE_128F, &seed).expect("key");

        let pre_hashed = VerifyOptions::default().with_pre_hash(SHAKE128);

        let signature = self_test(&hashed.private_key, &hashed.public_key).expect("self-test");

        assert!(
            pure.public_key
                .verify(&signature, SELF_TEST_MESSAGE, &pre_hashed)
        );

        assert!(
            !pure
                .public_key
                .verify(&signature, SELF_TEST_MESSAGE, &VerifyOptions::default())
        );

        let signature = self_test(&pure.private_key, &pure.public_key).expect("self-test");

        assert!(
            pure.public_key
                .verify(&signature, SELF_TEST_MESSAGE, &VerifyOptions::default())
        );

        let deterministic = SignOptions::default().with_deterministic(true);

        let fixed = pure
            .private_key
            .sign(SELF_TEST_MESSAGE, &deterministic)
            .expect("signature");

        assert_ne!(signature, fixed);
    }

    #[cfg(feature = "slh-dsa")]
    #[test]
    fn slh_dsa_keys_have_no_caches() {
        let pair = hazmat::generate_signature_key_pair(SLH_DSA_SHAKE_128F, &[4; 48]).expect("key");

        assert!(pair.private_key.public.derived.is_none() && pair.private_key.signing.is_none());

        assert!(core::ptr::eq(
            &*pair.public_key.public,
            &*pair.private_key.public
        ));
    }
}

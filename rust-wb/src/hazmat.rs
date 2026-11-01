//! Deterministic operations for test vectors, enabled by the `hazmat` feature.
//!
//! Production code must not call them. Each one takes a seed or randomness from the caller
//! instead of the operating-system entropy source, and reusing one with a different key, message
//! or ciphertext breaks the scheme. The signing functions skip the pre-hash strength policy of the
//! public API, but not the fixed pre-hash of the HashSLH-DSA values.

#[cfg(any(feature = "ml-dsa", feature = "slh-dsa"))]
use alloc::vec::Vec;

#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss",
    feature = "sha3"
))]
use crate::error::Error;
#[cfg(feature = "sha3")]
use crate::hash::XofAlgorithm;
#[cfg(any(feature = "ml-kem", feature = "frodokem"))]
use crate::kem::{Encapsulation, KemAlgorithm, KemKeyPair, KemPublicKey};
#[cfg(any(feature = "ml-dsa", feature = "slh-dsa"))]
use crate::signature::{
    SignOptions, SignatureAlgorithm, SignatureKeyPair, SignaturePrivateKey, SignaturePublicKey,
    VerifyOptions,
};
#[cfg(any(feature = "lms", feature = "xmss"))]
use crate::stateful::{
    StateStore, StatefulKeyGenOptions, StatefulKeyPair, StatefulParameters,
    StatefulSignatureAlgorithm, check_reserve,
};
#[cfg(any(feature = "lms", feature = "xmss"))]
use crate::wipe::SecretBytes;

#[cfg(any(
    feature = "ml-kem",
    feature = "frodokem",
    feature = "ml-dsa",
    feature = "slh-dsa",
    feature = "lms",
    feature = "xmss"
))]
fn require_length(data: &[u8], length: usize) -> Result<(), Error> {
    if data.len() == length {
        Ok(())
    } else {
        Err(Error::InvalidLength)
    }
}

/// The KEM key pair of `seed`, of the algorithm's seed size: d || z for ML-KEM (FIPS 203
/// Algorithm 16). The pairwise test is not run.
#[cfg(any(feature = "ml-kem", feature = "frodokem"))]
pub fn generate_kem_key_pair(algorithm: KemAlgorithm, seed: &[u8]) -> Result<KemKeyPair, Error> {
    require_length(seed, algorithm.seed_size())?;

    let private_key = algorithm.key_from_seed(seed);

    Ok(KemKeyPair {
        public_key: private_key.public_key(),
        private_key,
    })
}

/// The signature key pair of `seed`: the 32-byte ξ for ML-DSA, SK.seed || SK.prf || PK.seed for
/// SLH-DSA.
#[cfg(any(feature = "ml-dsa", feature = "slh-dsa"))]
pub fn generate_signature_key_pair(
    algorithm: SignatureAlgorithm,
    seed: &[u8],
) -> Result<SignatureKeyPair, Error> {
    require_length(seed, algorithm.seed_size())?;

    let private_key = algorithm.key_from_seed(seed);

    Ok(SignatureKeyPair {
        public_key: private_key.public_key(),
        private_key,
    })
}

/// Encapsulation with the caller's `randomness`, of the algorithm's randomness size.
#[cfg(any(feature = "ml-kem", feature = "frodokem"))]
pub fn encapsulate(public_key: &KemPublicKey, randomness: &[u8]) -> Result<Encapsulation, Error> {
    require_length(randomness, public_key.algorithm().randomness_size())?;

    Ok(public_key.encapsulate_with(randomness))
}

/// Signing with the caller's `randomness`: rnd for ML-DSA, opt_rand for SLH-DSA.
/// `options.deterministic` is ignored, since the randomness decides, and the pre-hash strength
/// policy of [`SignaturePrivateKey::sign`] does not apply; the fixed pre-hash of a HashSLH-DSA key
/// does.
// The options are checked before the length of the randomness (SPEC 7.3).
#[cfg(any(feature = "ml-dsa", feature = "slh-dsa"))]
pub fn sign(
    private_key: &SignaturePrivateKey,
    message: &[u8],
    randomness: &[u8],
    options: &SignOptions,
) -> Result<Vec<u8>, Error> {
    let pre_hash = private_key.check_options(options, false)?;

    require_length(randomness, private_key.algorithm().randomness_size())?;

    Ok(private_key.sign_with(message, randomness, options.context, pre_hash))
}

/// Verification without the pre-hash strength policy of [`SignaturePublicKey::verify`].
#[cfg(any(feature = "ml-dsa", feature = "slh-dsa"))]
pub fn verify(
    public_key: &SignaturePublicKey,
    signature: &[u8],
    message: &[u8],
    options: &VerifyOptions,
) -> bool {
    public_key.verify_with(signature, message, options, false)
}

/// ML-DSA.Sign_internal (FIPS 204 Algorithm 7) or slh_sign_internal (FIPS 205 Algorithm 19) on a
/// message representative M' given by the caller, as the internal test groups of ACVP use them.
///
/// M' skips the domain separation of the pure and pre-hash interfaces, so a HashSLH-DSA key, which
/// signs pre-hashed messages alone, refuses it with [`Error::InvalidOption`]. The randomness is
/// rnd for ML-DSA (32 zero bytes for the deterministic variant) and opt_rand for SLH-DSA (PK.seed
/// for the deterministic variant).
// SPEC D-65.
#[cfg(any(feature = "ml-dsa", feature = "slh-dsa"))]
pub fn sign_internal(
    private_key: &SignaturePrivateKey,
    message_representative: &[u8],
    randomness: &[u8],
) -> Result<Vec<u8>, Error> {
    let algorithm = private_key.algorithm();

    if algorithm.has_fixed_pre_hash() {
        return Err(Error::InvalidOption);
    }

    require_length(randomness, algorithm.randomness_size())?;

    Ok(private_key.sign_representative(&[message_representative], randomness))
}

/// ML-DSA.Verify_internal (FIPS 204 Algorithm 8) or slh_verify_internal (FIPS 205 Algorithm 20)
/// on a message representative M'; `false` for a HashSLH-DSA key, as [`sign_internal`] refuses
/// it.
#[cfg(any(feature = "ml-dsa", feature = "slh-dsa"))]
pub fn verify_internal(
    public_key: &SignaturePublicKey,
    signature: &[u8],
    message_representative: &[u8],
) -> bool {
    let algorithm = public_key.algorithm();

    !algorithm.has_fixed_pre_hash()
        && signature.len() == algorithm.signature_size()
        && public_key.verify_representative(&[message_representative], signature)
}

/// A stateful key pair whose top secrets are `seed`, I || SEED of the top LMS tree or
/// S_XMSS || SK_PRF || SEED, and which derives its child trees and randomizers as the reference
/// implementations do, so that it reproduces their test vectors. It starts at `index`, which must
/// be below the capacity: a key that starts exhausted could never sign.
// SPEC 11.14 and D-68.
#[cfg(any(feature = "lms", feature = "xmss"))]
pub fn generate_stateful_key_pair<S: StateStore>(
    algorithm: StatefulSignatureAlgorithm,
    seed: &[u8],
    index: u64,
    parameters: StatefulParameters,
    store: S,
    options: &StatefulKeyGenOptions,
) -> Result<StatefulKeyPair<S>, Error> {
    let reserve = check_reserve(options.reserve)?;

    let parameters = algorithm.parameters(parameters)?;

    require_length(seed, parameters.seed_size())?;

    if index >= parameters.capacity() {
        return Err(Error::InvalidOption);
    }

    let seed = SecretBytes::concat(&[seed]);

    algorithm.create(parameters, seed, true, index, reserve, store)
}

/// cSHAKE128 or cSHAKE256 with a function name N as well as a customization S, as the ACVP
/// vectors set them. NIST SP 800-185, 3.4, reserves N for values that NIST defines, so
/// [`XofAlgorithm::configure`] takes S alone.
#[cfg(feature = "sha3")]
pub fn configure_cshake(
    algorithm: XofAlgorithm,
    function_name: &[u8],
    customization: &[u8],
) -> Result<XofAlgorithm, Error> {
    algorithm.configure_cshake(function_name, customization)
}

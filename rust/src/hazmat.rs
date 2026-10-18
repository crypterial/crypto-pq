// Deterministic operations for test vectors. Production code must not call them: reusing a seed
// or randomness value with a different key, message or ciphertext breaks the scheme, and the
// signing functions skip the pre-hash strength policy of the public API.

use alloc::vec::Vec;

use crate::error::Error;
use crate::hash::XofAlgorithm;
use crate::kem::{Encapsulation, KemAlgorithm, KemKeyPair, KemPublicKey};
use crate::signature::{
    SignOptions, SignatureAlgorithm, SignatureKeyPair, SignaturePrivateKey, SignaturePublicKey,
    VerifyOptions,
};
use crate::stateful::{
    StateStore, StatefulKeyGenOptions, StatefulKeyPair, StatefulParameters,
    StatefulSignatureAlgorithm, check_reserve,
};
use crate::wipe::SecretBytes;

fn require_length(data: &[u8], length: usize) -> Result<(), Error> {
    if data.len() == length {
        Ok(())
    } else {
        Err(Error::InvalidLength)
    }
}

pub fn generate_kem_key_pair(algorithm: KemAlgorithm, seed: &[u8]) -> Result<KemKeyPair, Error> {
    require_length(seed, algorithm.seed_size())?;

    let private_key = algorithm.key_from_seed(seed);

    Ok(KemKeyPair {
        public_key: private_key.public_key(),
        private_key,
    })
}

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

pub fn encapsulate(public_key: &KemPublicKey, randomness: &[u8]) -> Result<Encapsulation, Error> {
    require_length(randomness, public_key.algorithm().randomness_size())?;

    Ok(public_key.encapsulate_with(randomness))
}

// options.deterministic is ignored: the randomness argument decides.
pub fn sign(
    private_key: &SignaturePrivateKey,
    message: &[u8],
    randomness: &[u8],
    options: &SignOptions,
) -> Result<Vec<u8>, Error> {
    require_length(randomness, private_key.algorithm().randomness_size())?;

    private_key.check_options(options, false)?;

    Ok(private_key.sign_with(message, randomness, options))
}

pub fn verify(
    public_key: &SignaturePublicKey,
    signature: &[u8],
    message: &[u8],
    options: &VerifyOptions,
) -> bool {
    public_key.verify_with(signature, message, options, false)
}

// SPEC 11.14: a key whose top secrets are the seed, I || SEED of the top LMS tree or
// S_XMSS || SK_PRF || SEED, which derives its child trees and randomizers as the reference
// implementations do, so that it reproduces their test vectors; it starts at index, which may be
// the capacity itself for an exhausted key.
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

    if index > parameters.capacity() {
        return Err(Error::InvalidOption);
    }

    let seed = SecretBytes::concat(&[seed]);

    algorithm.create(parameters, seed, true, index, reserve, store)
}

// cSHAKE128 or cSHAKE256 with a function name N as well as a customization S, as the ACVP vectors
// set it. SP 800-185, 3.4: N should only take values that NIST defines, so the public configure
// takes S alone.
pub fn configure_cshake(
    algorithm: XofAlgorithm,
    function_name: &[u8],
    customization: &[u8],
) -> Result<XofAlgorithm, Error> {
    algorithm.configure_cshake(function_name, customization)
}

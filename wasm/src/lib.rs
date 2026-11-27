use crypto_pq::{
    Error, HMAC_SHA_256, KeyGenOptions, ML_DSA_65, ML_KEM_768, SignOptions, VerifyOptions,
};

const MISMATCH: i32 = 100;

fn code(result: Result<bool, Error>) -> i32 {
    match result {
        Ok(true) => 0,
        Ok(false) => MISMATCH,
        Err(error) => 1 + error as i32,
    }
}

fn kem_round_trip() -> Result<bool, Error> {
    let pair = ML_KEM_768.generate_key_pair(&KeyGenOptions::default())?;

    let encapsulation = pair.public_key.encapsulate()?;

    let shared_secret = pair.private_key.decapsulate(&encapsulation.ciphertext)?;

    let tag = HMAC_SHA_256.digest(&encapsulation.shared_secret, b"key confirmation")?;

    Ok(HMAC_SHA_256.verify(&shared_secret, b"key confirmation", &tag))
}

fn dsa_round_trip() -> Result<bool, Error> {
    let pair = ML_DSA_65.generate_key_pair(&KeyGenOptions::default())?;

    let signature = pair
        .private_key
        .sign(b"message", &SignOptions::default().with_context(b"example"))?;

    let options = VerifyOptions::default().with_context(b"example");

    Ok(pair.public_key.verify(&signature, b"message", &options))
}

#[unsafe(no_mangle)]
pub extern "C" fn ml_kem_768_round_trip() -> i32 {
    code(kem_round_trip())
}

#[unsafe(no_mangle)]
pub extern "C" fn ml_dsa_65_round_trip() -> i32 {
    code(dsa_round_trip())
}

#[unsafe(no_mangle)]
pub extern "C" fn rng_failure_code() -> i32 {
    code(Err(Error::RngFailure))
}

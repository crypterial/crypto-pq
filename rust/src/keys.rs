use alloc::vec::Vec;

use crate::encoding::{
    CONTEXT_0, OCTET_STRING, Reader, SEQUENCE, decode_private_key, decode_public_key, element,
    encode_private_key, encode_public_key, only, pem_decode, pem_encode,
};
use crate::error::Error;
use crate::wipe::SecretBytes;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyFormat {
    Raw,
    Der,
    Pem,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyGenOptions {
    pub self_test: bool,
}

impl Default for KeyGenOptions {
    fn default() -> Self {
        Self { self_test: true }
    }
}

const PUBLIC: &[u8] = b"PUBLIC KEY";

const PRIVATE: &[u8] = b"PRIVATE KEY";

// A raw key of the wrong size is a length error; inside DER or PEM it is an encoding error.
pub(crate) fn check_size(format: KeyFormat, actual: usize, expected: usize) -> Result<(), Error> {
    match (actual == expected, format) {
        (true, _) => Ok(()),
        (false, KeyFormat::Raw) => Err(Error::InvalidLength),
        (false, _) => Err(Error::InvalidEncoding),
    }
}

pub(crate) fn export_public(
    format: KeyFormat,
    oid: Option<&[u8]>,
    raw: &[u8],
) -> Result<Vec<u8>, Error> {
    match (format, oid) {
        (KeyFormat::Raw, _) => Ok(raw.to_vec()),
        (_, None) => Err(Error::Unsupported),
        (KeyFormat::Der, Some(oid)) => Ok(encode_public_key(oid, raw)),
        (KeyFormat::Pem, Some(oid)) => Ok(pem_encode(PUBLIC, &encode_public_key(oid, raw))),
    }
}

pub(crate) fn import_public(
    format: KeyFormat,
    data: &[u8],
    oid: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let expected = match (format, oid) {
        (KeyFormat::Raw, _) => return Ok(data.to_vec()),
        (_, None) => return Err(Error::Unsupported),
        (_, Some(oid)) => oid,
    };

    let der;

    let data = if format == KeyFormat::Pem {
        der = pem_decode(PUBLIC, data)?;

        &der[..]
    } else {
        data
    };

    let (found, key) = decode_public_key(data)?;

    if found != expected {
        return Err(Error::AlgorithmMismatch);
    }

    Ok(key.to_vec())
}

pub(crate) fn export_private(
    format: KeyFormat,
    oid: Option<&[u8]>,
    octets: &[u8],
    raw: &[u8],
) -> Result<Vec<u8>, Error> {
    match (format, oid) {
        (KeyFormat::Raw, _) => Ok(raw.to_vec()),
        (_, None) => Err(Error::Unsupported),
        (KeyFormat::Der, Some(oid)) => Ok(encode_private_key(oid, octets).to_vec()),
        (KeyFormat::Pem, Some(oid)) => Ok(pem_encode(PRIVATE, &encode_private_key(oid, octets))),
    }
}

pub(crate) enum PrivateInput {
    Raw(SecretBytes),
    Pkcs8 {
        key: SecretBytes,
        public_key: Option<Vec<u8>>,
    },
}

pub(crate) fn import_private(
    format: KeyFormat,
    data: &[u8],
    oid: Option<&[u8]>,
) -> Result<PrivateInput, Error> {
    let expected = match (format, oid) {
        (KeyFormat::Raw, _) => return Ok(PrivateInput::Raw(SecretBytes::concat(&[data]))),
        (_, None) => return Err(Error::Unsupported),
        (_, Some(oid)) => oid,
    };

    let der;

    let data = if format == KeyFormat::Pem {
        der = pem_decode(PRIVATE, data)?;

        &der[..]
    } else {
        data
    };

    let info = decode_private_key(data)?;

    if info.oid != expected {
        return Err(Error::AlgorithmMismatch);
    }

    Ok(PrivateInput::Pkcs8 {
        key: SecretBytes::concat(&[info.key]),
        public_key: info.public_key.map(<[u8]>::to_vec),
    })
}

// ML-KEM and ML-DSA private keys: CHOICE { seed [0] IMPLICIT OCTET STRING, expandedKey OCTET
// STRING, both SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING } }.
pub(crate) enum SeedChoice<'a> {
    Seed(&'a [u8]),
    Expanded(&'a [u8]),
    Both { seed: &'a [u8], expanded: &'a [u8] },
}

pub(crate) fn encode_seed(seed: &[u8]) -> SecretBytes {
    SecretBytes::from_vec(element(CONTEXT_0, seed))
}

pub(crate) fn encode_expanded(expanded: &[u8]) -> SecretBytes {
    SecretBytes::from_vec(element(OCTET_STRING, expanded))
}

pub(crate) fn decode_seed_choice(
    octets: &[u8],
    seed_size: usize,
    expanded_size: usize,
) -> Result<SeedChoice<'_>, Error> {
    let choice = match octets.first() {
        Some(&CONTEXT_0) => SeedChoice::Seed(only(octets, CONTEXT_0)?),
        Some(&OCTET_STRING) => SeedChoice::Expanded(only(octets, OCTET_STRING)?),
        Some(&SEQUENCE) => {
            let mut reader = Reader::new(only(octets, SEQUENCE)?);

            let seed = reader.read(OCTET_STRING)?;

            let expanded = reader.read(OCTET_STRING)?;

            reader.finish()?;

            SeedChoice::Both { seed, expanded }
        }
        _ => return Err(Error::InvalidEncoding),
    };

    let sizes_match = match choice {
        SeedChoice::Seed(seed) => seed.len() == seed_size,
        SeedChoice::Expanded(expanded) => expanded.len() == expanded_size,
        SeedChoice::Both { seed, expanded } => {
            seed.len() == seed_size && expanded.len() == expanded_size
        }
    };

    if !sizes_match {
        return Err(Error::InvalidEncoding);
    }

    Ok(choice)
}

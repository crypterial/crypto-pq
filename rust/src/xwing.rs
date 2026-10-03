use alloc::vec::Vec;

use crate::mlkem::{self, ML_KEM_768};
use crate::primitives::{sha3_256, shake256_into};
use crate::wipe::{SecretBytes, wipe};
use crate::x25519::{BASE, x25519};

const LABEL: &[u8] = b"\\.//^\\";

const ML_KEM_PUBLIC_KEY_SIZE: usize = 1184;

const ML_KEM_CIPHERTEXT_SIZE: usize = 1088;

pub(crate) const PUBLIC_KEY_SIZE: usize = 1216;

pub(crate) const CIPHERTEXT_SIZE: usize = 1120;

pub(crate) const SEED_SIZE: usize = 32;

pub(crate) const RANDOMNESS_SIZE: usize = 64;

pub(crate) struct Expanded {
    pub(crate) public: Vec<u8>,
    pub(crate) dk: SecretBytes,
    pub(crate) scalar: SecretBytes,
}

pub(crate) fn expand(seed: &[u8]) -> Expanded {
    let mut expanded = [0u8; 96];

    shake256_into(&[seed], &mut expanded);

    let (mut public, dk) = mlkem::keygen_internal(&expanded[..32], &expanded[32..64], &ML_KEM_768);

    let scalar = SecretBytes::concat(&[&expanded[64..]]);

    public.extend_from_slice(&x25519(&scalar, &BASE));

    wipe(&mut expanded);

    Expanded { public, dk, scalar }
}

fn combine(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> [u8; 32] {
    sha3_256(&[ss_m, ss_x, ct_x, pk_x, LABEL])
}

pub(crate) fn check_public_key(pk: &[u8]) -> bool {
    pk.len() == PUBLIC_KEY_SIZE
        && mlkem::check_encapsulation_key(&pk[..ML_KEM_PUBLIC_KEY_SIZE], &ML_KEM_768)
}

pub(crate) fn encapsulate(pk: &[u8], eseed: &[u8]) -> ([u8; 32], Vec<u8>) {
    let (pk_m, pk_x) = pk.split_at(ML_KEM_PUBLIC_KEY_SIZE);

    let (mut ss_m, mut ct) = mlkem::encaps_internal(pk_m, &eseed[..32], &ML_KEM_768);

    let ct_x = x25519(&eseed[32..], &BASE);

    let mut ss_x = x25519(&eseed[32..], pk_x);

    let shared_secret = combine(&ss_m, &ss_x, &ct_x, pk_x);

    ct.extend_from_slice(&ct_x);

    wipe(&mut ss_m);

    wipe(&mut ss_x);

    (shared_secret, ct)
}

pub(crate) fn decapsulate(dk: &[u8], scalar: &[u8], pk_x: &[u8], ct: &[u8]) -> [u8; 32] {
    let (ct_m, ct_x) = ct.split_at(ML_KEM_CIPHERTEXT_SIZE);

    let mut ss_m = mlkem::decaps_internal(dk, ct_m, &ML_KEM_768);

    let mut ss_x = x25519(scalar, ct_x);

    let shared_secret = combine(&ss_m, &ss_x, ct_x, pk_x);

    wipe(&mut ss_m);

    wipe(&mut ss_x);

    shared_secret
}

pub(crate) fn public_point(pk: &[u8]) -> &[u8] {
    &pk[ML_KEM_PUBLIC_KEY_SIZE..]
}

"""Deterministic operations for test vectors. Production code must not call them: reusing a seed
or randomness value with a different key, message or ciphertext breaks the scheme, and these
functions skip the pre-hash strength policy of the public API."""

from ._kem import KemAlgorithm, KemKeyPair, KemPublicKey
from ._keys import require_bytes, require_length
from ._signature import SignatureAlgorithm, SignaturePrivateKey, SignaturePublicKey


def generate_key_pair(algorithm, seed):
    seed = require_bytes(seed, "seed")

    if isinstance(algorithm, KemAlgorithm):
        require_length(seed, algorithm._backend.seed_size, "seed")

        private_key = algorithm._from_seed(seed)

        return KemKeyPair(private_key.public_key, private_key)

    if isinstance(algorithm, SignatureAlgorithm):
        require_length(seed, algorithm._backend.seed_size, "seed")

        return algorithm._from_seed(seed)

    raise TypeError("algorithm must be a crypto_pq algorithm")


def encapsulate(public_key, randomness):
    if not isinstance(public_key, KemPublicKey):
        raise TypeError("public_key must be a KemPublicKey")

    randomness = require_bytes(randomness, "randomness")

    require_length(randomness, public_key.algorithm._backend.randomness_size, "randomness")

    return public_key._encapsulate(randomness)


def sign(private_key, message, randomness, *, context=b"", pre_hash=None):
    if not isinstance(private_key, SignaturePrivateKey):
        raise TypeError("private_key must be a SignaturePrivateKey")

    randomness = require_bytes(randomness, "randomness")

    require_length(randomness, private_key.algorithm._backend.randomness_size, "randomness")

    return private_key._sign(message, randomness, context, pre_hash, False)


def verify(public_key, signature, message, *, context=b"", pre_hash=None):
    if not isinstance(public_key, SignaturePublicKey):
        raise TypeError("public_key must be a SignaturePublicKey")

    return public_key._verify(signature, message, context, pre_hash, False)

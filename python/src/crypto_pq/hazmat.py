"""Deterministic operations for test vectors. Production code must not call them: reusing a seed
or randomness value with a different key, message or ciphertext breaks the scheme, and these
functions skip the pre-hash strength policy of the public API."""

from __future__ import annotations

from collections.abc import Sequence
from typing import overload

from ._kem import Encapsulation, KemAlgorithm, KemKeyPair, KemPublicKey
from ._keys import require_bytes, require_length
from ._signature import SignatureAlgorithm, SignatureKeyPair, SignaturePrivateKey, SignaturePublicKey, _Bytes, _PreHash
from ._stateful import StatefulKeyPair, StatefulSignatureAlgorithm, StateStore, require_reserve


@overload
def generate_key_pair(algorithm: KemAlgorithm, seed: _Bytes) -> KemKeyPair: ...


@overload
def generate_key_pair(algorithm: SignatureAlgorithm, seed: _Bytes) -> SignatureKeyPair: ...


@overload
def generate_key_pair(algorithm: StatefulSignatureAlgorithm, seed: _Bytes, *, parameters: str | Sequence[tuple[str, str]], state_store: StateStore, index: int = 0, reserve: int = 1) -> StatefulKeyPair: ...


# Stateful seeds are I || SEED of the top LMS tree, or SK_SEED || SK_PRF || PUB_SEED for XMSS.
def generate_key_pair(algorithm: KemAlgorithm | SignatureAlgorithm | StatefulSignatureAlgorithm, seed: _Bytes, *, parameters: str | Sequence[tuple[str, str]] | None = None, state_store: StateStore | None = None, index: int = 0, reserve: int = 1) -> KemKeyPair | SignatureKeyPair | StatefulKeyPair:
    seed = require_bytes(seed, "seed")

    if isinstance(algorithm, StatefulSignatureAlgorithm):
        parameters = algorithm._backend.parameters(parameters)

        require_reserve(reserve)

        require_length(seed, algorithm._backend.seed_size(parameters), "seed")

        return algorithm._create(parameters, seed, index, state_store, reserve)

    if isinstance(algorithm, KemAlgorithm):
        require_length(seed, algorithm._backend.seed_size, "seed")

        private_key = algorithm._from_seed(seed)

        return KemKeyPair(private_key.public_key, private_key)

    if isinstance(algorithm, SignatureAlgorithm):
        require_length(seed, algorithm._backend.seed_size, "seed")

        return algorithm._from_seed(seed)

    raise TypeError("algorithm must be a crypto_pq algorithm")


def encapsulate(public_key: KemPublicKey, randomness: _Bytes) -> Encapsulation:
    if not isinstance(public_key, KemPublicKey):
        raise TypeError("public_key must be a KemPublicKey")

    randomness = require_bytes(randomness, "randomness")

    require_length(randomness, public_key.algorithm._backend.randomness_size, "randomness")

    return public_key._encapsulate(randomness)


def sign(private_key: SignaturePrivateKey, message: _Bytes, randomness: _Bytes, *, context: _Bytes = b"", pre_hash: _PreHash = None) -> bytes:
    if not isinstance(private_key, SignaturePrivateKey):
        raise TypeError("private_key must be a SignaturePrivateKey")

    randomness = require_bytes(randomness, "randomness")

    require_length(randomness, private_key.algorithm._backend.randomness_size, "randomness")

    return private_key._sign(message, randomness, context, pre_hash, False)


def verify(public_key: SignaturePublicKey, signature: _Bytes, message: _Bytes, *, context: _Bytes = b"", pre_hash: _PreHash = None) -> bool:
    if not isinstance(public_key, SignaturePublicKey):
        raise TypeError("public_key must be a SignaturePublicKey")

    return public_key._verify(signature, message, context, pre_hash, False)

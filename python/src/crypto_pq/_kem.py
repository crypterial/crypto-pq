from __future__ import annotations

from typing import NamedTuple

from . import _mlkem, _native, _xwing
from ._bytes import equal
from ._encoding import KeyFormat, object_identifier
from ._errors import CryptoPQError, ErrorCode
from ._keys import (
    decode_seed_choice,
    encode_seed_choice,
    export_private,
    export_public,
    import_private,
    import_public,
    mismatch,
    require_bool,
    require_bytes,
    require_key_length,
    require_length,
)
from ._rng import random_bytes

_Bytes = bytes | bytearray | memoryview


# The pairwise test of key generation: an encapsulation to the new public key must decapsulate to
# the same shared secret.
def pairwise(backend, state):
    shared_secret, ciphertext = backend.encapsulate(backend.public_state_of(state), random_bytes(backend.randomness_size))

    return equal(backend.decapsulate(state, ciphertext), shared_secret)


class _MlKem:
    def __init__(self, params, arc):
        self.params = params

        self.oid = object_identifier(f"2.16.840.1.101.3.4.4.{arc}")

        self.seed_size = 64

        self.randomness_size = 32

        self.expanded_size = params.decapsulation_key_size

        self.public_key_size = params.encapsulation_key_size

        self.ciphertext_size = params.ciphertext_size

    # The public key, the private key and the seed that the key keeps.
    def from_seed(self, seed):
        ek, dk = _mlkem.keygen_internal(seed[:32], seed[32:], self.params)

        return ek, dk, seed

    def from_expanded(self, dk):
        if not _mlkem.check_decapsulation_key(dk, self.params):
            return None

        return _mlkem.public_key_of(dk, self.params), dk

    def seed(self, private):
        return None

    def expanded(self, private):
        return private

    def import_public(self, ek):
        return _mlkem.public_state(ek, self.params) if _mlkem.check_encapsulation_key(ek, self.params) else None

    def private_state(self, dk):
        return _mlkem.private_state(dk, self.params)

    def public_state_of(self, state):
        return state.public

    def encapsulate(self, state, randomness):
        return _mlkem.encaps_internal(state, randomness, self.params)

    def decapsulate(self, state, ciphertext):
        return _mlkem.decaps_internal(state, ciphertext, self.params)

    def self_test(self, state):
        return pairwise(self, state)


class _XWing:
    oid = None

    seed_size = _xwing.SEED_SIZE

    randomness_size = 64

    expanded_size = None

    public_key_size = _xwing.PUBLIC_KEY_SIZE

    ciphertext_size = _xwing.CIPHERTEXT_SIZE

    def from_seed(self, seed):
        public, private = _xwing.expand(seed)

        return public, private, seed

    def seed(self, private):
        return None

    def import_public(self, pk):
        return _xwing.public_state(pk) if _xwing.check_public_key(pk) else None

    def private_state(self, private):
        return _xwing.private_state(private)

    def public_state_of(self, state):
        return _xwing.public_state_of(state)

    def encapsulate(self, state, randomness):
        return _xwing.encapsulate(state, randomness)

    def decapsulate(self, state, ciphertext):
        return _xwing.decapsulate(state, ciphertext)

    def self_test(self, state):
        return pairwise(self, state)


# A KEM of the native library, with the sizes of its pure twin. A private key is a private slot,
# which holds its seed or expanded key and its public part; the public key of a private key gets
# a public slot of its own on first use, so that the private slot lives no longer than the
# private key.
class _NativeKem:
    def __init__(self, pure, number):
        self.oid = pure.oid

        self.seed_size = pure.seed_size

        self.randomness_size = pure.randomness_size

        self.expanded_size = pure.expanded_size

        self.public_key_size = pure.public_key_size

        self.ciphertext_size = pure.ciphertext_size

        self.number = number

    def from_seed(self, seed):
        private = _native.kem_generate(self.number, seed)

        return _native.kem_export_public(private, self.public_key_size), private, None

    def from_expanded(self, dk):
        private = _native.kem_import_private(self.number, dk)

        if private is None:
            return None

        return _native.kem_export_public(private, self.public_key_size), private

    def seed(self, private):
        return _native.kem_export_private(private, _native.EXPORT_SEED, self.seed_size)

    def expanded(self, private):
        return _native.kem_export_private(private, _native.EXPORT_PRIVATE, self.expanded_size)

    def import_public(self, key):
        return _native.kem_import_public(self.number, key)

    def private_state(self, private):
        return _native.PrivateState(private)

    def public_state_of(self, state):
        public = state.public

        if public is None:
            public = state.public = _native.kem_public(self.number, state.private)

        return public

    def encapsulate(self, state, randomness):
        return _native.kem_encapsulate(state, randomness, self.ciphertext_size)

    def decapsulate(self, state, ciphertext):
        return _native.kem_decapsulate(state.private, ciphertext)

    def self_test(self, state):
        return _native.kem_self_test(state.private, random_bytes(self.randomness_size))


def _backend(pure, number):
    return _NativeKem(pure, number) if _native.BACKEND == "native" else pure


class Encapsulation(NamedTuple):
    shared_secret: bytes

    ciphertext: bytes


# A key keeps what its operations derive from it, such as H(ek) and the matrix of ML-KEM, in its
# state; a private key shares the state of its public part with its public key.
class KemPublicKey:
    __slots__ = ("_algorithm", "_key", "_state")

    def __init__(self, algorithm: KemAlgorithm, key: bytes, state: object) -> None:
        self._algorithm = algorithm

        self._key = key

        self._state = state

    @property
    def algorithm(self) -> KemAlgorithm:
        return self._algorithm

    def encapsulate(self) -> Encapsulation:
        backend = self._algorithm._backend

        return self._encapsulate(random_bytes(backend.randomness_size))

    def _encapsulate(self, randomness: bytes) -> Encapsulation:
        shared_secret, ciphertext = self._algorithm._backend.encapsulate(self._state, randomness)

        return Encapsulation(shared_secret, ciphertext)

    def export_key(self, format: KeyFormat | str) -> bytes:
        return export_public(format, self._algorithm._backend.oid, self._key)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, KemPublicKey) and self._algorithm is other._algorithm and self._key == other._key

    def __hash__(self) -> int:
        return hash(self._key)

    def __repr__(self) -> str:
        return f"<KemPublicKey {self._algorithm.name}>"


class KemPrivateKey:
    __slots__ = ("_algorithm", "_seed", "_private", "_public", "_state")

    def __init__(self, algorithm: KemAlgorithm, seed: bytes | None, private: object, public: bytes) -> None:
        self._algorithm = algorithm

        self._seed = seed

        self._private = private

        self._public = public

        self._state = algorithm._backend.private_state(private)

    @property
    def algorithm(self) -> KemAlgorithm:
        return self._algorithm

    @property
    def public_key(self) -> KemPublicKey:
        return KemPublicKey(self._algorithm, self._public, self._algorithm._backend.public_state_of(self._state))

    def decapsulate(self, ciphertext: _Bytes) -> bytes:
        ciphertext = require_bytes(ciphertext, "ciphertext")

        backend = self._algorithm._backend

        require_length(ciphertext, backend.ciphertext_size, "ciphertext")

        return backend.decapsulate(self._state, ciphertext)

    # The seed if the key has one, kept here or in its private part; the expanded key otherwise.
    def export_key(self, format: KeyFormat | str) -> bytes:
        backend = self._algorithm._backend

        seed = self._seed if self._seed is not None else backend.seed(self._private)

        if seed is not None:
            return export_private(format, backend.oid, encode_seed_choice(seed, None), seed)

        expanded = backend.expanded(self._private)

        return export_private(format, backend.oid, encode_seed_choice(None, expanded), expanded)

    def __repr__(self) -> str:
        return f"<KemPrivateKey {self._algorithm.name}>"


class KemKeyPair(NamedTuple):
    public_key: KemPublicKey

    private_key: KemPrivateKey


class KemAlgorithm:
    __slots__ = ("_name", "_backend")

    def __init__(self, name: str, backend) -> None:
        self._name = name

        self._backend = backend

    @property
    def name(self) -> str:
        return self._name

    @property
    def public_key_size(self) -> int:
        return self._backend.public_key_size

    @property
    def ciphertext_size(self) -> int:
        return self._backend.ciphertext_size

    @property
    def shared_secret_size(self) -> int:
        return 32

    def generate_key_pair(self, *, self_test: bool = True) -> KemKeyPair:
        require_bool(self_test, "self_test")

        private_key = self._from_seed(random_bytes(self._backend.seed_size))

        public_key = private_key.public_key

        if self_test and not self._backend.self_test(private_key._state):
            raise CryptoPQError(ErrorCode.SELF_TEST_FAILED, "the new key pair failed its consistency test")

        return KemKeyPair(public_key, private_key)

    def _from_seed(self, seed: bytes) -> KemPrivateKey:
        public, private, kept = self._backend.from_seed(seed)

        return KemPrivateKey(self, kept, private, public)

    def _from_expanded(self, expanded: bytes) -> KemPrivateKey:
        key = self._backend.from_expanded(expanded)

        if key is None:
            raise mismatch("the decapsulation key fails the FIPS 203 checks")

        public, private = key

        return KemPrivateKey(self, None, private, public)

    def import_public_key(self, data: _Bytes | str, format: KeyFormat | str) -> KemPublicKey:
        key = import_public(format, data, self._backend.oid)

        require_key_length(key, self._backend.public_key_size, format, "public key")

        state = self._backend.import_public(key)

        if state is None:
            raise CryptoPQError(ErrorCode.INVALID_PUBLIC_KEY, "the public key fails the encoding checks")

        return KemPublicKey(self, key, state)

    def import_private_key(self, data: _Bytes | str, format: KeyFormat | str) -> KemPrivateKey:
        backend = self._backend

        octets, raw, public_key = import_private(format, data, backend.oid)

        if raw is not None:
            if len(raw) == backend.seed_size:
                return self._from_seed(raw)

            if backend.expanded_size is not None and len(raw) == backend.expanded_size:
                return self._from_expanded(raw)

            raise CryptoPQError(ErrorCode.INVALID_LENGTH, "the private key has the wrong length")

        seed, expanded = decode_seed_choice(octets, backend.seed_size, backend.expanded_size)

        if seed is not None:
            key = self._from_seed(seed)

            if expanded is not None and expanded != backend.expanded(key._private):
                raise mismatch("the seed and the expanded key do not match")
        else:
            key = self._from_expanded(expanded)

        if public_key is not None and public_key != key._public:
            raise mismatch("the embedded public key does not match the private key")

        return key

    def __repr__(self) -> str:
        return f"<KemAlgorithm {self._name}>"


ML_KEM_512 = KemAlgorithm("ML-KEM-512", _backend(_MlKem(_mlkem.ML_KEM_512, 1), 0))

ML_KEM_768 = KemAlgorithm("ML-KEM-768", _backend(_MlKem(_mlkem.ML_KEM_768, 2), 1))

ML_KEM_1024 = KemAlgorithm("ML-KEM-1024", _backend(_MlKem(_mlkem.ML_KEM_1024, 3), 2))

X_WING = KemAlgorithm("X-Wing", _backend(_XWing(), 3))

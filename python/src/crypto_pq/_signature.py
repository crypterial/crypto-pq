from __future__ import annotations

from typing import NamedTuple

from . import _mldsa, _native, _slhdsa
from ._encoding import OBJECT_IDENTIFIER, KeyFormat, element, object_identifier
from ._errors import CryptoPQError, ErrorCode
from ._hash import (
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHA_224,
    SHA_256,
    SHA_384,
    SHA_512,
    SHA_512_224,
    SHA_512_256,
    SHAKE128,
    SHAKE256,
    HashAlgorithm,
    XofAlgorithm,
)
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

_PreHash = HashAlgorithm | XofAlgorithm | None

SELF_TEST_MESSAGE = b"crypto-pq pairwise consistency test"


class PreHash(NamedTuple):
    oid: bytes

    strength: int

    digest: object

    number: int


def _pre_hash(arc, strength, digest, number):
    return PreHash(element(OBJECT_IDENTIFIER, object_identifier(f"2.16.840.1.101.3.4.2.{arc}")), strength, digest, number)


# Collision strength in bits of each approved pre-hash; SHAKE128 and SHAKE256 produce 256 and
# 512 bits as FIPS 204 and FIPS 205 require. The last number is the native library's id.
PRE_HASHES = {
    SHA_224: _pre_hash(4, 112, SHA_224.digest, 1),
    SHA_256: _pre_hash(1, 128, SHA_256.digest, 2),
    SHA_384: _pre_hash(2, 192, SHA_384.digest, 3),
    SHA_512: _pre_hash(3, 256, SHA_512.digest, 4),
    SHA_512_224: _pre_hash(5, 112, SHA_512_224.digest, 5),
    SHA_512_256: _pre_hash(6, 128, SHA_512_256.digest, 6),
    SHA3_224: _pre_hash(7, 112, SHA3_224.digest, 7),
    SHA3_256: _pre_hash(8, 128, SHA3_256.digest, 8),
    SHA3_384: _pre_hash(9, 192, SHA3_384.digest, 9),
    SHA3_512: _pre_hash(10, 256, SHA3_512.digest, 10),
    SHAKE128: _pre_hash(11, 128, lambda message: SHAKE128.digest(message, 32), 11),
    SHAKE256: _pre_hash(12, 256, lambda message: SHAKE256.digest(message, 64), 12),
}


class _MlDsa:
    def __init__(self, params, arc):
        self.params = params

        self.oid = object_identifier(f"2.16.840.1.101.3.4.3.{arc}")

        self.seed_size = 32

        self.expanded_size = params.private_key_size

        self.public_key_size = params.public_key_size

        self.signature_size = params.signature_size

        self.randomness_size = 32

        self.strength = params.lam

    # The public key, the private key and the seed that the key keeps.
    def from_seed(self, seed):
        pk, sk = _mldsa.keygen_internal(seed, self.params)

        return pk, sk, seed

    def from_expanded(self, sk):
        pk = _mldsa.check_private_key(sk, self.params)

        return None if pk is None else (pk, sk)

    def seed(self, private):
        return None

    def expanded(self, private):
        return private

    def import_public(self, pk):
        return _mldsa.public_state(pk, self.params)

    def private_state(self, sk, pk):
        return _mldsa.private_state(sk, pk, self.params)

    def public_state_of(self, state):
        return state.public

    def deterministic_randomness(self, state):
        return bytes(32)

    # `randomness` is None for a deterministic signature.
    def sign(self, state, message, context, entry, randomness, policy):
        if randomness is None:
            randomness = self.deterministic_randomness(state)

        return _mldsa.sign_internal(state, message_representative(message, context, entry), randomness, self.params)

    def verify(self, state, message, context, entry, signature, policy):
        return _mldsa.verify_internal(state, message_representative(message, context, entry), signature, self.params)


class _SlhDsa:
    def __init__(self, params, arc):
        self.params = params

        self.oid = object_identifier(f"2.16.840.1.101.3.4.3.{arc}")

        self.seed_size = 3 * params.n

        self.expanded_size = None

        self.public_key_size = params.public_key_size

        self.signature_size = params.signature_size

        self.randomness_size = params.n

        self.strength = 8 * params.n

    def from_seed(self, seed):
        n = self.params.n

        sk, pk = _slhdsa.keygen_internal(seed[:n], seed[n : 2 * n], seed[2 * n :], self.params)

        return pk, sk, None

    def from_private(self, sk):
        n = self.params.n

        if _slhdsa.root(self.params, sk[:n], sk[2 * n : 3 * n]) != sk[3 * n :]:
            return None

        return sk[2 * n :], sk

    def seed(self, private):
        return None

    def expanded(self, private):
        return private

    def import_public(self, pk):
        return pk

    def private_state(self, sk, pk):
        return sk

    def public_state_of(self, state):
        return state[2 * self.params.n :]

    def deterministic_randomness(self, state):
        n = self.params.n

        return state[2 * n : 3 * n]

    def sign(self, state, message, context, entry, randomness, policy):
        if randomness is None:
            randomness = self.deterministic_randomness(state)

        return _slhdsa.sign_internal(message_representative(message, context, entry), state, randomness, self.params)

    def verify(self, state, message, context, entry, signature, policy):
        return _slhdsa.verify_internal(message_representative(message, context, entry), signature, state, self.params)


# A signature algorithm of the native library, with the sizes of its pure twin. The library builds
# the message representative, pre-hash included; a private key is a private slot, and the public
# key of a private key gets a public slot of its own on first use.
class _NativeSignature:
    def __init__(self, pure, number):
        self.params = pure.params

        self.oid = pure.oid

        self.seed_size = pure.seed_size

        self.expanded_size = pure.expanded_size

        self.public_key_size = pure.public_key_size

        self.signature_size = pure.signature_size

        self.randomness_size = pure.randomness_size

        self.strength = pure.strength

        self.number = number

    def from_seed(self, seed):
        private = _native.signature_generate(self.number, seed, _native.FILL_CACHE)

        return _native.signature_export_public(private, self.public_key_size), private, None

    def from_expanded(self, sk):
        private = _native.signature_import_private(self.number, sk)

        if private is None:
            return None

        return _native.signature_export_public(private, self.public_key_size), private

    from_private = from_expanded

    def seed(self, private):
        if self.expanded_size is None:
            return None

        return _native.signature_export_private(private, _native.EXPORT_SEED, self.seed_size)

    def expanded(self, private):
        return _native.signature_export_private(private, _native.EXPORT_PRIVATE, self.params.private_key_size)

    def import_public(self, pk):
        return _native.signature_import_public(self.number, pk)

    def private_state(self, private, public):
        return _native.PrivateState(private)

    def public_state_of(self, state):
        public = state.public

        if public is None:
            public = state.public = _native.signature_public(self.number, state.private)

        return public

    def sign(self, state, message, context, entry, randomness, policy):
        flags = 0 if policy else _native.HAZMAT

        if randomness is None:
            randomness, flags = b"", flags | _native.DETERMINISTIC

        return _native.sign(state.private, message, context, entry.number if entry else 0, randomness, flags, self.signature_size)

    def verify(self, state, message, context, entry, signature, policy):
        return _native.verify(state, signature, message, context, entry.number if entry else 0, 0 if policy else _native.HAZMAT)


def _backend(pure, number):
    return _NativeSignature(pure, number) if _native.BACKEND == "native" else pure


def pre_hash_entry(pre_hash):
    if pre_hash is None:
        return None

    try:
        return PRE_HASHES[pre_hash]
    except (KeyError, TypeError):
        raise CryptoPQError(ErrorCode.INVALID_OPTION, "pre_hash must be one of the crypto_pq hash functions") from None


# A pre-hash must give at least the collision strength of the signature (FIPS 204, 5.4, and
# FIPS 205, 10.2): signing with a weaker one is refused and verification fails closed.
def too_weak(backend, entry, policy):
    return policy and entry is not None and entry.strength < backend.strength


# FIPS 204 and FIPS 205: M' = 0 || |ctx| || ctx || M, or 1 || |ctx| || ctx || OID || PH(M).
def message_representative(message, context, entry):
    if entry is None:
        return bytes([0, len(context)]) + context + message

    return bytes([1, len(context)]) + context + entry.oid + entry.digest(message)


# A key keeps what its operations derive from it, such as tr and the matrix of ML-DSA, in its
# state; a private key shares the state of its public part with its public key.
class SignaturePublicKey:
    __slots__ = ("_algorithm", "_key", "_state")

    def __init__(self, algorithm: SignatureAlgorithm, key: bytes, state: object) -> None:
        self._algorithm = algorithm

        self._key = key

        self._state = state

    @property
    def algorithm(self) -> SignatureAlgorithm:
        return self._algorithm

    def verify(self, signature: _Bytes, message: _Bytes, *, context: _Bytes = b"", pre_hash: _PreHash = None) -> bool:
        return self._verify(signature, message, context, pre_hash, True)

    def _verify(self, signature, message, context, pre_hash, policy):
        signature = require_bytes(signature, "signature")

        message = require_bytes(message, "message")

        context = require_bytes(context, "context")

        backend = self._algorithm._backend

        entry = pre_hash_entry(pre_hash)

        if too_weak(backend, entry, policy) or len(context) > 255 or len(signature) != backend.signature_size:
            return False

        return backend.verify(self._state, message, context, entry, signature, policy)

    def export_key(self, format: KeyFormat | str) -> bytes:
        return export_public(format, self._algorithm._backend.oid, self._key)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SignaturePublicKey) and self._algorithm is other._algorithm and self._key == other._key

    def __hash__(self) -> int:
        return hash(self._key)

    def __repr__(self) -> str:
        return f"<SignaturePublicKey {self._algorithm.name}>"


class SignaturePrivateKey:
    __slots__ = ("_algorithm", "_seed", "_private", "_public", "_state")

    def __init__(self, algorithm: SignatureAlgorithm, seed: bytes | None, private: object, public: bytes) -> None:
        self._algorithm = algorithm

        self._seed = seed

        self._private = private

        self._public = public

        self._state = algorithm._backend.private_state(private, public)

    @property
    def algorithm(self) -> SignatureAlgorithm:
        return self._algorithm

    @property
    def public_key(self) -> SignaturePublicKey:
        return SignaturePublicKey(self._algorithm, self._public, self._algorithm._backend.public_state_of(self._state))

    def sign(self, message: _Bytes, *, context: _Bytes = b"", deterministic: bool = False, pre_hash: _PreHash = None) -> bytes:
        require_bool(deterministic, "deterministic")

        randomness = None if deterministic else random_bytes(self._algorithm._backend.randomness_size)

        return self._sign(message, randomness, context, pre_hash, True)

    def _sign(self, message, randomness, context, pre_hash, policy):
        message = require_bytes(message, "message")

        context = require_bytes(context, "context")

        backend = self._algorithm._backend

        entry = pre_hash_entry(pre_hash)

        if too_weak(backend, entry, policy):
            raise CryptoPQError(ErrorCode.INVALID_OPTION, f"{pre_hash.name} is weaker than the signature algorithm")

        if len(context) > 255:
            raise CryptoPQError(ErrorCode.INVALID_CONTEXT, "the context must be at most 255 bytes")

        return backend.sign(self._state, message, context, entry, randomness, policy)

    # SLH-DSA exports its 4n-byte key; ML-DSA its seed, kept here or in its private part, or the
    # expanded key of a key imported without a seed.
    def export_key(self, format: KeyFormat | str) -> bytes:
        backend = self._algorithm._backend

        if backend.expanded_size is None:
            private = backend.expanded(self._private)

            return export_private(format, backend.oid, private, private)

        seed = self._seed if self._seed is not None else backend.seed(self._private)

        if seed is not None:
            return export_private(format, backend.oid, encode_seed_choice(seed, None), seed)

        expanded = backend.expanded(self._private)

        return export_private(format, backend.oid, encode_seed_choice(None, expanded), expanded)

    def __repr__(self) -> str:
        return f"<SignaturePrivateKey {self._algorithm.name}>"


class SignatureKeyPair(NamedTuple):
    public_key: SignaturePublicKey

    private_key: SignaturePrivateKey


class SignatureAlgorithm:
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
    def signature_size(self) -> int:
        return self._backend.signature_size

    def generate_key_pair(self, *, self_test: bool = True) -> SignatureKeyPair:
        require_bool(self_test, "self_test")

        pair = self._from_seed(random_bytes(self._backend.seed_size))

        if self_test:
            signature = pair.private_key.sign(SELF_TEST_MESSAGE, deterministic=True)

            if not pair.public_key.verify(signature, SELF_TEST_MESSAGE):
                raise CryptoPQError(ErrorCode.SELF_TEST_FAILED, "the new key pair failed its consistency test")

        return pair

    # ML-DSA keeps the seed as its private key; SLH-DSA keeps the expanded 4n-byte key.
    def _from_seed(self, seed: bytes) -> SignatureKeyPair:
        public, private, kept = self._backend.from_seed(seed)

        private_key = SignaturePrivateKey(self, kept, private, public)

        return SignatureKeyPair(private_key.public_key, private_key)

    def import_public_key(self, data: _Bytes | str, format: KeyFormat | str) -> SignaturePublicKey:
        key = import_public(format, data, self._backend.oid)

        require_key_length(key, self._backend.public_key_size, format, "public key")

        return SignaturePublicKey(self, key, self._backend.import_public(key))

    def import_private_key(self, data: _Bytes | str, format: KeyFormat | str) -> SignaturePrivateKey:
        backend = self._backend

        octets, raw, public_key = import_private(format, data, backend.oid)

        if backend.expanded_size is None:
            key = self._import_slh_dsa(raw if raw is not None else octets, format)
        elif raw is not None:
            key = self._import_ml_dsa_raw(raw)
        else:
            key = self._import_ml_dsa_choice(octets)

        if public_key is not None and public_key != key._public:
            raise mismatch("the embedded public key does not match the private key")

        return key

    def _import_slh_dsa(self, sk, format):
        require_key_length(sk, self._backend.params.private_key_size, format, "private key")

        key = self._backend.from_private(sk)

        if key is None:
            raise mismatch("the private key does not match its public root")

        public, private = key

        return SignaturePrivateKey(self, None, private, public)

    def _import_ml_dsa_raw(self, raw):
        backend = self._backend

        if len(raw) == backend.seed_size:
            return self._from_seed(raw).private_key

        require_length(raw, backend.expanded_size, "private key")

        return self._from_expanded(raw)

    def _import_ml_dsa_choice(self, octets):
        backend = self._backend

        seed, expanded = decode_seed_choice(octets, backend.seed_size, backend.expanded_size)

        if seed is None:
            return self._from_expanded(expanded)

        key = self._from_seed(seed).private_key

        if expanded is not None and expanded != backend.expanded(key._private):
            raise mismatch("the seed and the expanded key do not match")

        return key

    def _from_expanded(self, sk):
        key = self._backend.from_expanded(sk)

        if key is None:
            raise mismatch("the private key fails the consistency checks")

        public, private = key

        return SignaturePrivateKey(self, None, private, public)

    def __repr__(self) -> str:
        return f"<SignatureAlgorithm {self._name}>"


ML_DSA_44 = SignatureAlgorithm("ML-DSA-44", _backend(_MlDsa(_mldsa.ML_DSA_44, 17), 0))

ML_DSA_65 = SignatureAlgorithm("ML-DSA-65", _backend(_MlDsa(_mldsa.ML_DSA_65, 18), 1))

ML_DSA_87 = SignatureAlgorithm("ML-DSA-87", _backend(_MlDsa(_mldsa.ML_DSA_87, 19), 2))

_SLH_DSA = [SignatureAlgorithm(p.name, _backend(_SlhDsa(p, arc), number)) for p, arc, number in zip(_slhdsa.SHA2 + _slhdsa.SHAKE, range(20, 32), range(3, 15))]

(
    SLH_DSA_SHA2_128S,
    SLH_DSA_SHA2_128F,
    SLH_DSA_SHA2_192S,
    SLH_DSA_SHA2_192F,
    SLH_DSA_SHA2_256S,
    SLH_DSA_SHA2_256F,
    SLH_DSA_SHAKE_128S,
    SLH_DSA_SHAKE_128F,
    SLH_DSA_SHAKE_192S,
    SLH_DSA_SHAKE_192F,
    SLH_DSA_SHAKE_256S,
    SLH_DSA_SHAKE_256F,
) = _SLH_DSA

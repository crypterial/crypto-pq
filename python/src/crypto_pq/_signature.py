from typing import NamedTuple

from . import _mldsa, _slhdsa
from ._encoding import OBJECT_IDENTIFIER, element, object_identifier
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

SELF_TEST_MESSAGE = b"crypto-pq pairwise consistency test"


class PreHash(NamedTuple):
    oid: bytes

    strength: int

    digest: object


def _pre_hash(arc, strength, digest):
    return PreHash(element(OBJECT_IDENTIFIER, object_identifier(f"2.16.840.1.101.3.4.2.{arc}")), strength, digest)


# Collision strength in bits of each approved pre-hash; SHAKE128 and SHAKE256 produce 256 and
# 512 bits as FIPS 204 and FIPS 205 require.
PRE_HASHES = {
    SHA_224: _pre_hash(4, 112, SHA_224.digest),
    SHA_256: _pre_hash(1, 128, SHA_256.digest),
    SHA_384: _pre_hash(2, 192, SHA_384.digest),
    SHA_512: _pre_hash(3, 256, SHA_512.digest),
    SHA_512_224: _pre_hash(5, 112, SHA_512_224.digest),
    SHA_512_256: _pre_hash(6, 128, SHA_512_256.digest),
    SHA3_224: _pre_hash(7, 112, SHA3_224.digest),
    SHA3_256: _pre_hash(8, 128, SHA3_256.digest),
    SHA3_384: _pre_hash(9, 192, SHA3_384.digest),
    SHA3_512: _pre_hash(10, 256, SHA3_512.digest),
    SHAKE128: _pre_hash(11, 128, lambda message: SHAKE128.digest(message, 32)),
    SHAKE256: _pre_hash(12, 256, lambda message: SHAKE256.digest(message, 64)),
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

    def from_seed(self, seed):
        return _mldsa.keygen_internal(seed, self.params)

    def from_expanded(self, sk):
        pk = _mldsa.check_private_key(sk, self.params)

        if pk is None:
            raise mismatch("the private key fails the consistency checks")

        return pk, sk

    def deterministic_randomness(self, private):
        return bytes(32)

    def sign(self, private, message, randomness):
        return _mldsa.sign_internal(private, message, randomness, self.params)

    def verify(self, public, message, signature):
        return _mldsa.verify_internal(public, message, signature, self.params)


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

        return pk, sk

    def from_private(self, sk):
        n = self.params.n

        if _slhdsa.root(self.params, sk[:n], sk[2 * n : 3 * n]) != sk[3 * n :]:
            raise mismatch("the private key does not match its public root")

        return sk[2 * n :], sk

    def deterministic_randomness(self, private):
        n = self.params.n

        return private[2 * n : 3 * n]

    def sign(self, private, message, randomness):
        return _slhdsa.sign_internal(message, private, randomness, self.params)

    def verify(self, public, message, signature):
        return _slhdsa.verify_internal(message, signature, public, self.params)


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


class SignaturePublicKey:
    __slots__ = ("_algorithm", "_key")

    def __init__(self, algorithm, key):
        self._algorithm = algorithm

        self._key = key

    @property
    def algorithm(self):
        return self._algorithm

    def verify(self, signature, message, *, context=b"", pre_hash=None):
        return self._verify(signature, message, context, pre_hash, True)

    def _verify(self, signature, message, context, pre_hash, policy):
        signature = require_bytes(signature, "signature")

        message = require_bytes(message, "message")

        context = require_bytes(context, "context")

        backend = self._algorithm._backend

        entry = pre_hash_entry(pre_hash)

        if too_weak(backend, entry, policy) or len(context) > 255 or len(signature) != backend.signature_size:
            return False

        return backend.verify(self._key, message_representative(message, context, entry), signature)

    def export_key(self, format):
        return export_public(format, self._algorithm._backend.oid, self._key)

    def __eq__(self, other):
        return isinstance(other, SignaturePublicKey) and self._algorithm is other._algorithm and self._key == other._key

    def __hash__(self):
        return hash(self._key)

    def __repr__(self):
        return f"<SignaturePublicKey {self._algorithm.name}>"


class SignaturePrivateKey:
    __slots__ = ("_algorithm", "_seed", "_private", "_public")

    def __init__(self, algorithm, seed, private, public):
        self._algorithm = algorithm

        self._seed = seed

        self._private = private

        self._public = public

    @property
    def algorithm(self):
        return self._algorithm

    @property
    def public_key(self):
        return SignaturePublicKey(self._algorithm, self._public)

    def sign(self, message, *, context=b"", deterministic=False, pre_hash=None):
        require_bool(deterministic, "deterministic")

        backend = self._algorithm._backend

        if deterministic:
            randomness = backend.deterministic_randomness(self._private)
        else:
            randomness = random_bytes(backend.randomness_size)

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

        return backend.sign(self._private, message_representative(message, context, entry), randomness)

    def export_key(self, format):
        backend = self._algorithm._backend

        if backend.expanded_size is None:
            return export_private(format, backend.oid, self._private, self._private)

        if self._seed is not None:
            return export_private(format, backend.oid, encode_seed_choice(self._seed, None), self._seed)

        return export_private(format, backend.oid, encode_seed_choice(None, self._private), self._private)

    def __repr__(self):
        return f"<SignaturePrivateKey {self._algorithm.name}>"


class SignatureKeyPair(NamedTuple):
    public_key: SignaturePublicKey

    private_key: SignaturePrivateKey


class SignatureAlgorithm:
    __slots__ = ("_name", "_backend")

    def __init__(self, name, backend):
        self._name = name

        self._backend = backend

    @property
    def name(self):
        return self._name

    @property
    def public_key_size(self):
        return self._backend.public_key_size

    @property
    def signature_size(self):
        return self._backend.signature_size

    def generate_key_pair(self, *, self_test=True):
        require_bool(self_test, "self_test")

        pair = self._from_seed(random_bytes(self._backend.seed_size))

        if self_test:
            signature = pair.private_key.sign(SELF_TEST_MESSAGE, deterministic=True)

            if not pair.public_key.verify(signature, SELF_TEST_MESSAGE):
                raise CryptoPQError(ErrorCode.SELF_TEST_FAILED, "the new key pair failed its consistency test")

        return pair

    # ML-DSA keeps the seed as its private key; SLH-DSA keeps the expanded 4n-byte key.
    def _from_seed(self, seed):
        public, private = self._backend.from_seed(seed)

        kept = seed if self._backend.expanded_size is not None else None

        private_key = SignaturePrivateKey(self, kept, private, public)

        return SignatureKeyPair(private_key.public_key, private_key)

    def import_public_key(self, data, format):
        key = import_public(format, data, self._backend.oid)

        require_key_length(key, self._backend.public_key_size, format, "public key")

        return SignaturePublicKey(self, key)

    def import_private_key(self, data, format):
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

        public, private = self._backend.from_private(sk)

        return SignaturePrivateKey(self, None, private, public)

    def _import_ml_dsa_raw(self, raw):
        backend = self._backend

        if len(raw) == backend.seed_size:
            return self._from_seed(raw).private_key

        require_length(raw, backend.expanded_size, "private key")

        public, private = backend.from_expanded(raw)

        return SignaturePrivateKey(self, None, private, public)

    def _import_ml_dsa_choice(self, octets):
        backend = self._backend

        seed, expanded = decode_seed_choice(octets, backend.seed_size, backend.expanded_size)

        if seed is None:
            public, private = backend.from_expanded(expanded)

            return SignaturePrivateKey(self, None, private, public)

        key = self._from_seed(seed).private_key

        if expanded is not None and expanded != key._private:
            raise mismatch("the seed and the expanded key do not match")

        return key

    def __repr__(self):
        return f"<SignatureAlgorithm {self._name}>"


ML_DSA_44 = SignatureAlgorithm("ML-DSA-44", _MlDsa(_mldsa.ML_DSA_44, 17))

ML_DSA_65 = SignatureAlgorithm("ML-DSA-65", _MlDsa(_mldsa.ML_DSA_65, 18))

ML_DSA_87 = SignatureAlgorithm("ML-DSA-87", _MlDsa(_mldsa.ML_DSA_87, 19))

_SLH_DSA = [SignatureAlgorithm(p.name, _SlhDsa(p, arc)) for p, arc in zip(_slhdsa.SHA2 + _slhdsa.SHAKE, range(20, 32))]

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

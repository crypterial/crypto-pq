import threading
from typing import NamedTuple, Protocol

from . import _lms, _xmss
from ._encoding import object_identifier
from ._errors import CryptoPQError, ErrorCode
from ._keys import export_public, import_public, mismatch, require_bytes
from ._primitives import sha256
from ._rng import random_bytes

VERSION = 1

HSS_KIND, XMSS_KIND, XMSS_MT_KIND = 1, 2, 3


class StateStore(Protocol):
    def read(self) -> bytes | None: ...

    def update(self, previous: bytes | None, next: bytes) -> bool: ...


def option(message):
    return CryptoPQError(ErrorCode.INVALID_OPTION, message)


# State blob: version, kind, the parameters, the secret seeds and the next index, closed by the
# first 16 bytes of its SHA-256 so that a damaged state is refused rather than reused.
def seal(body):
    return body + sha256(body)[:16]


def unseal(state, kind):
    if not isinstance(state, (bytes, bytearray)) or len(state) < 18:
        raise mismatch("the state store holds no valid key")

    state = bytes(state)

    body, checksum = state[:-16], state[-16:]

    if sha256(body)[:16] != checksum or body[0] != VERSION:
        raise mismatch("the stored key state is damaged or unsupported")

    if body[1] != kind:
        raise CryptoPQError(ErrorCode.ALGORITHM_MISMATCH, "the stored key belongs to another algorithm")

    return body[2:]


class _Hss:
    kind = HSS_KIND

    oid = object_identifier("1.2.840.113549.1.9.16.3.17")

    def parameters(self, parameters):
        if isinstance(parameters, (str, bytes)) or not hasattr(parameters, "__len__"):
            raise option("parameters must be a list of (LMS, LM-OTS) type names, one per level")

        levels = []

        for level in parameters:
            if not isinstance(level, (tuple, list)) or len(level) != 2:
                raise option("each level must be a pair of LMS and LM-OTS type names")

            lms, ots = _lms.LMS_BY_NAME.get(level[0]), _lms.OTS_BY_NAME.get(level[1])

            if lms is None or ots is None:
                raise option(f"unknown LMS or LM-OTS type {level!r}")

            levels.append((lms, ots))

        if not 1 <= len(levels) <= 8:
            raise option("HSS needs between 1 and 8 levels")

        family = {(lms.shake, lms.m) for lms, _ in levels} | {(ots.shake, ots.n) for _, ots in levels}

        if len(family) != 1:
            raise option("every level must use the same hash function and output size")

        if sum(lms.h for lms, _ in levels) > 60:
            raise option("the total tree height must not exceed 60")

        return levels

    def seed_size(self, levels):
        return 16 + levels[0][0].m

    def encode(self, levels, seed, index):
        body = bytes([VERSION, self.kind, len(levels)])

        body += b"".join(_lms.u32(lms.code) + _lms.u32(ots.code) for lms, ots in levels)

        return seal(body + seed + index.to_bytes(8, "big"))

    def decode(self, state):
        body = unseal(state, self.kind)

        count = body[0]

        names = [(int.from_bytes(body[1 + 8 * i : 5 + 8 * i], "big"), int.from_bytes(body[5 + 8 * i : 9 + 8 * i], "big")) for i in range(count)]

        try:
            levels = self.parameters([(_lms.LMS_TYPES[a].name, _lms.OTS_TYPES[b].name) for a, b in names])
        except (KeyError, CryptoPQError):
            raise mismatch("the stored key has invalid parameters") from None

        rest = body[1 + 8 * count :]

        size = self.seed_size(levels)

        if len(rest) != size + 8:
            raise mismatch("the stored key has the wrong length")

        return levels, rest[:size], int.from_bytes(rest[size:], "big")

    def signer(self, levels, seed):
        return _lms.Hss(levels, seed[:16], seed[16:])

    def check_public_key(self, key):
        return _lms.check_public_key(key)

    def verify(self, key, message, signature):
        return _lms.hss_verify(key, message, signature)


class _Xmss:
    def __init__(self, multi):
        self.multi = multi

        self.kind = XMSS_MT_KIND if multi else XMSS_KIND

        self.sets = _xmss.XMSS_MT_SETS if multi else _xmss.XMSS_SETS

        self.oid = object_identifier(f"1.3.6.1.5.5.7.6.{35 if multi else 34}")

    def parameters(self, parameters):
        p = self.sets.get(parameters) if isinstance(parameters, str) else None

        if p is None:
            raise option(f"parameters must be one of {', '.join(self.sets)}")

        return p

    def seed_size(self, p):
        return 3 * p.n

    def encode(self, p, seed, index):
        body = bytes([VERSION, self.kind]) + p.oid.to_bytes(4, "big") + index.to_bytes(8, "big") + seed

        return seal(body)

    def decode(self, state):
        body = unseal(state, self.kind)

        p = _xmss.by_oid(self.sets, int.from_bytes(body[:4], "big"))

        if p is None or len(body) != 12 + 3 * p.n:
            raise mismatch("the stored key has invalid parameters")

        return p, body[12:], int.from_bytes(body[4:12], "big")

    def signer(self, p, seed):
        n = p.n

        return _xmss.Xmss(p, seed[:n], seed[n : 2 * n], seed[2 * n :])

    def check_public_key(self, key):
        p = _xmss.by_oid(self.sets, int.from_bytes(key[:4], "big")) if len(key) >= 4 else None

        return p is not None and len(key) == p.public_key_size

    def verify(self, key, message, signature):
        p = _xmss.by_oid(self.sets, int.from_bytes(key[:4], "big"))

        return _xmss.verify(p, key, message, signature)


class StatefulPublicKey:
    __slots__ = ("_algorithm", "_key")

    def __init__(self, algorithm, key):
        self._algorithm = algorithm

        self._key = key

    @property
    def algorithm(self):
        return self._algorithm

    def verify(self, signature, message):
        signature = require_bytes(signature, "signature")

        message = require_bytes(message, "message")

        return self._algorithm._backend.verify(self._key, message, signature)

    def export_key(self, format):
        return export_public(format, self._algorithm._backend.oid, self._key)

    def __eq__(self, other):
        return isinstance(other, StatefulPublicKey) and self._algorithm is other._algorithm and self._key == other._key

    def __hash__(self):
        return hash(self._key)

    def __repr__(self):
        return f"<StatefulPublicKey {self._algorithm.name}>"


class StatefulPrivateKey:
    __slots__ = ("_algorithm", "_parameters", "_seed", "_signer", "_store", "_state", "_index", "_lock")

    def __init__(self, algorithm, parameters, seed, signer, store, state, index):
        self._algorithm = algorithm

        self._parameters = parameters

        self._seed = seed

        self._signer = signer

        self._store = store

        self._state = state

        self._index = index

        self._lock = threading.Lock()

    @property
    def algorithm(self):
        return self._algorithm

    @property
    def public_key(self):
        return StatefulPublicKey(self._algorithm, self._signer.public_key)

    def remaining_signatures(self):
        with self._lock:
            return self._signer.capacity - self._index

    # The next index is written to the store before the signature exists, so a crash or a failed
    # write can waste an index but never use one twice.
    def sign(self, message):
        message = require_bytes(message, "message")

        with self._lock:
            index = self._index

            if index >= self._signer.capacity:
                raise CryptoPQError(ErrorCode.KEY_EXHAUSTED, "every one-time key has been used")

            state = self._algorithm._backend.encode(self._parameters, self._seed, index + 1)

            try:
                updated = self._store.update(self._state, state)
            except Exception as error:
                raise CryptoPQError(ErrorCode.STATE_PERSIST_FAILED, "the state store failed to save the key state") from error

            if updated is not True:
                raise CryptoPQError(ErrorCode.STATE_CONFLICT, "the stored key state changed; load the key again")

            self._state = state

            self._index = index + 1

            return self._signer.sign(index, message)

    def __repr__(self):
        return f"<StatefulPrivateKey {self._algorithm.name}>"


class StatefulKeyPair(NamedTuple):
    public_key: StatefulPublicKey

    private_key: StatefulPrivateKey


class StatefulSignatureAlgorithm:
    __slots__ = ("_name", "_backend")

    def __init__(self, name, backend):
        self._name = name

        self._backend = backend

    @property
    def name(self):
        return self._name

    def generate_key_pair(self, *, parameters, state_store):
        parameters = self._backend.parameters(parameters)

        return self._create(parameters, random_bytes(self._backend.seed_size(parameters)), 0, state_store)

    def _create(self, parameters, seed, index, store):
        signer = self._backend.signer(parameters, seed)

        state = self._backend.encode(parameters, seed, index)

        try:
            created = store.update(None, state)
        except Exception as error:
            raise CryptoPQError(ErrorCode.STATE_PERSIST_FAILED, "the state store failed to save the new key") from error

        if created is not True:
            raise CryptoPQError(ErrorCode.STATE_CONFLICT, "the state store already holds a key")

        private_key = StatefulPrivateKey(self, parameters, seed, signer, store, state, index)

        return StatefulKeyPair(private_key.public_key, private_key)

    def load_private_key(self, state_store):
        try:
            state = state_store.read()
        except Exception as error:
            raise CryptoPQError(ErrorCode.STATE_PERSIST_FAILED, "the state store failed to read the key state") from error

        parameters, seed, index = self._backend.decode(state)

        signer = self._backend.signer(parameters, seed)

        if index > signer.capacity:
            raise mismatch("the stored index is beyond the key's capacity")

        return StatefulPrivateKey(self, parameters, seed, signer, state_store, bytes(state), index)

    def import_public_key(self, data, format):
        key = import_public(format, data, self._backend.oid)

        if not self._backend.check_public_key(key):
            raise CryptoPQError(ErrorCode.INVALID_PUBLIC_KEY, "the public key is malformed")

        return StatefulPublicKey(self, key)

    def __repr__(self):
        return f"<StatefulSignatureAlgorithm {self._name}>"


HSS_LMS = StatefulSignatureAlgorithm("HSS/LMS", _Hss())

XMSS = StatefulSignatureAlgorithm("XMSS", _Xmss(False))

XMSS_MT = StatefulSignatureAlgorithm("XMSS^MT", _Xmss(True))

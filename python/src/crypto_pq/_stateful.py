from __future__ import annotations

import operator
import threading
from collections.abc import Sequence
from typing import NamedTuple, Protocol

from . import _lms, _native, _xmss
from ._encoding import KeyFormat, invalid, object_identifier
from ._errors import CryptoPQError, ErrorCode
from ._hash import HMAC_SHA_256, SHA_256
from ._keys import export_public, import_public, mismatch, require_bytes
from ._merkle import CACHED_HEIGHT
from ._rng import random_bytes

_Bytes = bytes | bytearray | memoryview

VERSION = 1

HSS_KIND, XMSS_KIND, XMSS_MT_KIND = 1, 2, 3

TREE_CACHE_VERSION = 1

TREE_CACHE_LABEL = b"crypto-pq tree cache v1"

TAG_SIZE = 32


class StateStore(Protocol):
    def read(self) -> bytes | None: ...

    def update(self, previous: bytes | None, next: bytes) -> bool: ...


def option(message):
    return CryptoPQError(ErrorCode.INVALID_OPTION, message)


def require_store(store):
    if store is None:
        raise option("a state store is required")

    if not callable(getattr(store, "read", None)) or not callable(getattr(store, "update", None)):
        raise TypeError("state_store must provide read() and update(previous, next)")

    return store


def require_reserve(reserve):
    if isinstance(reserve, bool) or not isinstance(reserve, int) or reserve < 1:
        raise option("reserve must be a positive integer")

    return reserve


# State blob: version, kind, the parameters, the secret seeds and the next index, closed by the
# first 16 bytes of its SHA-256 so that a damaged state is refused rather than reused.
def seal(body):
    return body + SHA_256.digest(body)[:16]


def require_state(state):
    if not isinstance(state, (bytes, bytearray)):
        raise mismatch("the state store holds no valid key")

    return bytes(state)


def unseal(state, kind):
    state = require_state(state)

    if len(state) < 18:
        raise mismatch("the state store holds no valid key")

    body, checksum = state[:-16], state[-16:]

    if SHA_256.digest(body)[:16] != checksum or body[0] != VERSION:
        raise mismatch("the stored key state is damaged or unsupported")

    if body[1] != kind:
        raise CryptoPQError(ErrorCode.ALGORITHM_MISMATCH, "the stored key belongs to another algorithm")

    return body[2:]


# The key of the tree cache tag: HKDF-Extract (RFC 5869) of the seed with the label as salt.
def tree_cache_key(seed):
    return bytearray(HMAC_SHA_256.digest(TREE_CACHE_LABEL, seed))


# A tree cache holds public nodes only, but the signer trusts the root of a cached lower tree as
# the child key that its parent signs, and the public key covers only the top root and the top
# level's types, so the cache is authenticated with a key derived from the seed and names every
# level's parameters. The body is the version, the kind, the parameters as the state blob encodes
# them, the public key and every cached tree, top first: its level or layer, its number on that
# level, its lowest cached height, its height, n, its node count and its nodes, level by level
# from the lowest, left to right. The tag, HMAC-SHA-256 of the body, follows it.
def tree_cache_body(kind, section, signer):
    public_key = signer.public_key

    trees = signer.cached()

    body = bytearray([TREE_CACHE_VERSION, kind]) + section + len(public_key).to_bytes(4, "big") + public_key + bytes([len(trees)])

    for level, tree, merkle in trees:
        nodes = b"".join(merkle.levels)

        body += bytes([level]) + tree.to_bytes(8, "big") + bytes([merkle.low, merkle.height, merkle.size])

        body += (len(nodes) // merkle.size).to_bytes(4, "big") + nodes

    return bytes(body)


# Python cannot wipe every copy of the tag key; the one it holds is zeroed.
def seal_tree_cache(body, seed):
    key = tree_cache_key(seed)

    try:
        return body + HMAC_SHA_256.digest(key, body)
    finally:
        key[:] = bytes(len(key))


def parse_tree_cache(data):
    position = 0

    def take(size):
        nonlocal position

        if size > len(data) - position:
            raise invalid("the tree cache is truncated")

        position += size

        return data[position - size : position]

    def number(size):
        return int.from_bytes(take(size), "big")

    version, kind = number(1), number(1)

    # The parameters have the layout of the kind that the cache names: an HSS level count and a
    # pair of types per level, or an OID. A cache of no known kind cannot be read further.
    start = position

    if kind == HSS_KIND:
        take(8 * number(1))
    elif kind in (XMSS_KIND, XMSS_MT_KIND):
        take(4)
    else:
        raise invalid("the tree cache has an unknown kind")

    section = data[start:position]

    public_key = take(number(4))

    trees = []

    for _ in range(number(1)):
        level, tree, low, height, n, count = number(1), number(8), number(1), number(1), number(1), number(4)

        trees.append((level, tree, low, height, n, count, take(count * n)))

    body = data[:position]

    tag = take(TAG_SIZE)

    if position != len(data):
        raise invalid("the tree cache has trailing bytes")

    return version, kind, section, public_key, trees, body, tag


# The checks run in this order: the structure, then the version, the kind, the parameters and the
# parts of the public key that the state gives, then the tag in constant time, then each tree's
# level and shape. Every failure is INVALID_ENCODING except a cache of another algorithm, which is
# ALGORITHM_MISMATCH. A tree that the next index does not sign with is stale: it is skipped and
# built again when needed. The others are returned as {level: (tree number, levels)}, for the
# signer to check against their own nodes; the caller then compares the signer's public key, and
# with it the top root, with the cache's.
def open_tree_cache(backend, parameters, seed, index, data):
    version, kind, section, public_key, trees, body, tag = parse_tree_cache(data)

    if version != TREE_CACHE_VERSION:
        raise invalid("the tree cache has an unsupported version")

    if kind != backend.kind:
        raise CryptoPQError(ErrorCode.ALGORITHM_MISMATCH, "the tree cache belongs to another algorithm")

    if section != backend.parameter_section(parameters):
        raise invalid("the tree cache belongs to other parameters")

    before, root_size, after = backend.public_parts(parameters, seed)

    if len(public_key) != len(before) + root_size + len(after) or public_key[: len(before)] != before or public_key[len(before) + root_size :] != after:
        raise invalid("the tree cache belongs to another key")

    key = tree_cache_key(seed)

    try:
        authentic = HMAC_SHA_256.verify(key, body, tag)
    finally:
        key[:] = bytes(len(key))

    if not authentic:
        raise invalid("the tree cache is not authentic")

    layout = backend.layout(parameters)

    positions = {level: i for i, (level, _, _) in enumerate(layout)}

    previous = -1

    cached = {}

    for level, tree, low, height, n, count, nodes in trees:
        position = positions.get(level, -1)

        if position <= previous:
            raise invalid("the tree cache lists an unknown level or its levels out of order")

        previous = position

        _, expected_height, expected_n = layout[position]

        expected_low = max(0, expected_height - CACHED_HEIGHT)

        if (low, height, n, count) != (expected_low, expected_height, expected_n, (2 << (expected_height - expected_low)) - 1):
            raise invalid("the tree cache does not match the key's parameters")

        if tree == backend.tree_id(parameters, index, level):
            cached[level] = (tree, split_levels(nodes, low, height, n))

    return public_key, cached


def split_levels(nodes, low, height, n):
    levels, offset = [], 0

    for z in range(low, height + 1):
        size = n << (height - z)

        levels.append(nodes[offset : offset + size])

        offset += size

    return levels


class _Signer:
    """The pure-Python signer of a stateful key: its trees, with the parameters and the seed that
    the next state blobs and its tree cache take."""

    __slots__ = ("_backend", "_parameters", "_seed", "_trees", "public_key", "capacity")

    def __init__(self, backend, parameters, seed, trees):
        self._backend = backend

        self._parameters = parameters

        self._seed = seed

        self._trees = trees

        self.public_key = trees.public_key

        self.capacity = trees.capacity

    def sign(self, index, message):
        return self._trees.sign(index, message)

    # The sealed state blob that claims the indices below `index`.
    def next_state(self, state, index):
        return self._backend.encode(self._parameters, self._seed, index)

    # The body of the tree cache, under the key's lock; the tag follows outside it.
    def tree_cache(self):
        backend = self._backend

        return tree_cache_body(backend.kind, backend.parameter_section(self._parameters), self._trees)

    def seal_tree_cache(self, body):
        return seal_tree_cache(body, self._seed)

    def free(self):
        pass


class _Stateful:
    """A stateful algorithm: its parameter sets, its state blob and its signers, which _Hss and
    _Xmss give for their kinds."""

    kind: int

    def parameter_section(self, parameters):
        raise NotImplementedError

    def capacity(self, parameters):
        raise NotImplementedError

    def encode(self, parameters, seed, index):
        raise NotImplementedError

    def decode(self, state):
        raise NotImplementedError

    def signer(self, parameters, seed, cached=None):
        raise NotImplementedError

    # The signer of a new key at `index`, and the state blob of that index.
    def create(self, parameters, seed, index):
        return _Signer(self, parameters, seed, self.signer(parameters, seed)), self.encode(parameters, seed, index)

    # The signer of a stored state and its index. A tree cache replaces the build of the trees it
    # holds: the state is checked first, and the key loads only if the cache passes.
    def load(self, state, tree_cache):
        parameters, seed, index = self.decode(state)

        if index > self.capacity(parameters):
            raise mismatch("the stored index is beyond the key's capacity")

        if tree_cache is None:
            return _Signer(self, parameters, seed, self.signer(parameters, seed)), index

        public_key, cached = open_tree_cache(self, parameters, seed, index, tree_cache)

        trees = self.signer(parameters, seed, cached)

        if trees.public_key != public_key:
            raise invalid("the tree cache belongs to another key")

        return _Signer(self, parameters, seed, trees), index


class _Hss(_Stateful):
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

    def capacity(self, levels):
        return 1 << sum(lms.h for lms, _ in levels)

    # The trees of a tree cache, top first, as (level, height, n).
    def layout(self, levels):
        return [(level, lms.h, lms.m) for level, (lms, _) in enumerate(levels)]

    # The number of the tree that `index` signs with on `level`: the top level has one tree.
    def tree_id(self, levels, index, level):
        return index >> sum(lms.h for lms, _ in levels[level:]) if level else 0

    # The public key around the root, which only the top tree gives: the bytes before it, its
    # size and the bytes after it.
    def public_parts(self, levels, seed):
        lms, ots = levels[0]

        return _lms.u32(len(levels)) + _lms.u32(lms.code) + _lms.u32(ots.code) + seed[:16], lms.m, b""

    # The level count and the type codes of every level, as the state blob and the tree cache hold
    # them.
    def parameter_section(self, levels):
        return bytes([len(levels)]) + b"".join(_lms.u32(lms.code) + _lms.u32(ots.code) for lms, ots in levels)

    def encode(self, levels, seed, index):
        body = bytes([VERSION, self.kind]) + self.parameter_section(levels)

        return seal(body + seed + index.to_bytes(8, "big"))

    def decode(self, state):
        body = unseal(state, self.kind)

        count = body[0] if body else 0

        if len(body) < 1 + 8 * count:
            raise mismatch("the stored key has the wrong length")

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

    def signer(self, levels, seed, cached=None):
        return _lms.Hss(levels, seed[:16], seed[16:], cached)

    def check_public_key(self, key):
        return _lms.check_public_key(key)

    def verify(self, key, message, signature):
        return _lms.hss_verify(key, message, signature)


class _Xmss(_Stateful):
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

    def capacity(self, p):
        return 1 << p.h

    def layout(self, p):
        return [(layer, p.tree_height, p.n) for layer in reversed(range(p.d))]

    def tree_id(self, p, index, layer):
        return index >> ((layer + 1) * p.tree_height) if layer < p.d - 1 else 0

    def public_parts(self, p, seed):
        return p.oid.to_bytes(4, "big"), p.n, seed[2 * p.n :]

    def parameter_section(self, p):
        return p.oid.to_bytes(4, "big")

    def encode(self, p, seed, index):
        body = bytes([VERSION, self.kind]) + self.parameter_section(p) + index.to_bytes(8, "big") + seed

        return seal(body)

    def decode(self, state):
        body = unseal(state, self.kind)

        p = _xmss.by_oid(self.sets, int.from_bytes(body[:4], "big"))

        if p is None or len(body) != 12 + 3 * p.n:
            raise mismatch("the stored key has invalid parameters")

        return p, body[12:], int.from_bytes(body[4:12], "big")

    def signer(self, p, seed, cached=None):
        n = p.n

        return _xmss.Xmss(p, seed[:n], seed[n : 2 * n], seed[2 * n :], cached)

    def check_public_key(self, key):
        p = _xmss.by_oid(self.sets, int.from_bytes(key[:4], "big")) if len(key) >= 4 else None

        return p is not None and len(key) == p.public_key_size

    def verify(self, key, message, signature):
        p = _xmss.by_oid(self.sets, int.from_bytes(key[:4], "big"))

        return _xmss.verify(p, key, message, signature)


# The native library's signer, state blobs and verification, with the parameter handling of the
# pure backend: the library builds and checks the state blob and the tree cache itself.
class _Native(_Stateful):
    def create(self, parameters, seed, index):
        return _native.signer_create(self.kind, self.parameter_section(parameters), seed, index)

    def load(self, state, tree_cache):
        return _native.signer_load(self.kind, require_state(state), tree_cache)

    def check_public_key(self, key):
        return _native.stateful_check_public_key(self.kind, key)

    def verify(self, key, message, signature):
        return _native.stateful_verify(self.kind, key, message, signature)


class _NativeHss(_Native, _Hss):
    pass


class _NativeXmss(_Native, _Xmss):
    pass


class StatefulPublicKey:
    __slots__ = ("_algorithm", "_key")

    def __init__(self, algorithm: StatefulSignatureAlgorithm, key: bytes) -> None:
        self._algorithm = algorithm

        self._key = key

    @property
    def algorithm(self) -> StatefulSignatureAlgorithm:
        return self._algorithm

    def verify(self, signature: _Bytes, message: _Bytes) -> bool:
        signature = require_bytes(signature, "signature")

        message = require_bytes(message, "message")

        return self._algorithm._backend.verify(self._key, message, signature)

    def export_key(self, format: KeyFormat | str) -> bytes:
        return export_public(format, self._algorithm._backend.oid, self._key)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, StatefulPublicKey) and self._algorithm is other._algorithm and self._key == other._key

    def __hash__(self) -> int:
        return hash(self._key)

    def __repr__(self) -> str:
        return f"<StatefulPublicKey {self._algorithm.name}>"


class StatefulPrivateKey:
    __slots__ = ("_algorithm", "_signer", "_store", "_state", "_index", "_reserved", "_reserve", "_capacity", "_busy")

    def __init__(self, algorithm, signer, store, state, index, reserve):
        self._algorithm = algorithm

        self._signer = signer

        self._store = store

        self._state = state

        # `index` is the next index to sign with; `reserved` is the index that the store holds,
        # never below it. The indices in between were claimed by one store write.
        self._index = index

        self._reserved = index

        self._reserve = reserve

        self._capacity = signer.capacity

        self._busy = threading.Lock()

    @property
    def algorithm(self) -> StatefulSignatureAlgorithm:
        return self._algorithm

    @property
    def public_key(self) -> StatefulPublicKey:
        return StatefulPublicKey(self._algorithm, self._signer.public_key)

    # A plain read without the lock, so that a store may call it from inside update().
    def remaining_signatures(self) -> int:
        return self._capacity - self._index

    # A call that finds the key busy, from another thread or from inside the store's update(),
    # fails at once instead of waiting: waiting would deadlock the re-entrant call and stall the
    # others for as long as a tree rebuild takes.
    def sign(self, message: _Bytes) -> bytes:
        message = require_bytes(message, "message")

        if not self._busy.acquire(blocking=False):
            raise CryptoPQError(ErrorCode.STATE_CONFLICT, "the key is signing in another call")

        try:
            return self._sign(message)
        finally:
            self._busy.release()

    # The store receives the end of the next reserved range before any index of that range
    # signs, so a crash or a failed write can waste indices but never use one twice.
    def _sign(self, message):
        index = self._index

        if index >= self._capacity:
            raise CryptoPQError(ErrorCode.KEY_EXHAUSTED, "every one-time key has been used")

        if index == self._reserved:
            reserved = min(index + self._reserve, self._capacity)

            state = self._signer.next_state(self._state, reserved)

            try:
                updated = self._store.update(self._state, state)
            except Exception as error:
                raise CryptoPQError(ErrorCode.STATE_PERSIST_FAILED, "the state store failed to save the key state") from error

            if updated is not True:
                raise CryptoPQError(ErrorCode.STATE_CONFLICT, "the stored key state changed; load the key again")

            # Python cannot wipe bytes, so the superseded blob, which holds the seed, stays in
            # memory until its space is reused.
            self._state, self._reserved = state, reserved

        self._index = index + 1

        return self._signer.sign(index, message)

    # The trees that the key holds, for load_private_key(tree_cache=...) to skip their build. A
    # call made while the key signs, from another thread or from inside the store, fails at once,
    # as the trees are changing. The pure signer copies the body under the lock and tags it after,
    # so that hashing megabytes in Python does not hold off signatures; the native one exports the
    # whole cache under the lock.
    def export_tree_cache(self) -> bytes:
        if not self._busy.acquire(blocking=False):
            raise CryptoPQError(ErrorCode.STATE_CONFLICT, "the key is signing in another call")

        try:
            cache = self._signer.tree_cache()
        finally:
            self._busy.release()

        return self._signer.seal_tree_cache(cache)

    def __repr__(self) -> str:
        return f"<StatefulPrivateKey {self._algorithm.name}>"


class StatefulKeyPair(NamedTuple):
    public_key: StatefulPublicKey

    private_key: StatefulPrivateKey


class StatefulSignatureAlgorithm:
    __slots__ = ("_name", "_backend")

    def __init__(self, name: str, backend) -> None:
        self._name = name

        self._backend = backend

    @property
    def name(self) -> str:
        return self._name

    # `reserve` is how many indices one store write claims. It is not part of the stored state: a
    # stored index is always the first one not handed out, whatever claimed it.
    def generate_key_pair(self, *, parameters: str | Sequence[tuple[str, str]], state_store: StateStore, reserve: int = 1) -> StatefulKeyPair:
        parameters = self._backend.parameters(parameters)

        require_reserve(reserve)

        return self._create(parameters, random_bytes(self._backend.seed_size(parameters)), 0, state_store, reserve)

    # A signer that the store refuses is freed at once rather than left to the exception's frames.
    def _create(self, parameters, seed, index, store, reserve):
        require_store(store)

        index = operator.index(index)

        if not 0 <= index <= self._backend.capacity(parameters):
            raise option("the index must lie between 0 and the key's capacity")

        signer, state = self._backend.create(parameters, seed, index)

        try:
            created = store.update(None, state)
        except Exception as error:
            signer.free()

            raise CryptoPQError(ErrorCode.STATE_PERSIST_FAILED, "the state store failed to save the new key") from error

        if created is not True:
            signer.free()

            raise CryptoPQError(ErrorCode.STATE_CONFLICT, "the state store already holds a key")

        private_key = StatefulPrivateKey(self, signer, store, state, index, reserve)

        return StatefulKeyPair(private_key.public_key, private_key)

    # The key resumes at the stored index, so the indices that a previous key reserved and never
    # used are skipped, never reused. A tree cache from export_tree_cache() replaces the build of
    # the trees it holds; the state is checked first, and the key loads only if the cache passes.
    def load_private_key(self, state_store: StateStore, *, reserve: int = 1, tree_cache: _Bytes | None = None) -> StatefulPrivateKey:
        require_reserve(reserve)

        require_store(state_store)

        if tree_cache is not None:
            tree_cache = require_bytes(tree_cache, "tree_cache")

        try:
            state = state_store.read()
        except Exception as error:
            raise CryptoPQError(ErrorCode.STATE_PERSIST_FAILED, "the state store failed to read the key state") from error

        if state is None:
            raise mismatch("the state store holds no key")

        signer, index = self._backend.load(state, tree_cache)

        return StatefulPrivateKey(self, signer, state_store, bytes(state), index, reserve)

    def import_public_key(self, data: _Bytes | str, format: KeyFormat | str) -> StatefulPublicKey:
        key = import_public(format, data, self._backend.oid)

        if not self._backend.check_public_key(key):
            raise CryptoPQError(ErrorCode.INVALID_PUBLIC_KEY, "the public key is malformed")

        return StatefulPublicKey(self, key)

    def __repr__(self) -> str:
        return f"<StatefulSignatureAlgorithm {self._name}>"


_NATIVE = _native.BACKEND == "native"

HSS_LMS = StatefulSignatureAlgorithm("HSS/LMS", _NativeHss() if _NATIVE else _Hss())

XMSS = StatefulSignatureAlgorithm("XMSS", _NativeXmss(False) if _NATIVE else _Xmss(False))

XMSS_MT = StatefulSignatureAlgorithm("XMSS^MT", _NativeXmss(True) if _NATIVE else _Xmss(True))

import threading
from functools import partial

from . import _native, _primitives
from ._bytes import equal, immutable, require_output_length, view
from ._keccak import Keccak

_Bytes = bytes | bytearray | memoryview


# A hash, XOF or HMAC object takes one call at a time, as hashlib's do: calls from several threads
# wait for each other instead of tearing the state, which the native library would refuse.
class Hasher:
    __slots__ = ("_engine", "_lock")

    def __init__(self, engine) -> None:
        self._engine = engine

        self._lock = threading.Lock()

    def update(self, data: _Bytes) -> None:
        data = view(data)

        with self._lock:
            self._engine.update(data)

    def digest(self) -> bytes:
        with self._lock:
            return self._engine.digest()


# `digest` is the shortest path the backend has: with the extension module, one of its functions.
class HashAlgorithm:
    __slots__ = ("_name", "_digest_size", "_engine", "_digest")

    def __init__(self, name: str, digest_size: int, engine, digest) -> None:
        self._name = name

        self._digest_size = digest_size

        self._engine = engine

        self._digest = digest

    @property
    def name(self) -> str:
        return self._name

    @property
    def digest_size(self) -> int:
        return self._digest_size

    def digest(self, data: _Bytes) -> bytes:
        return self._digest(data)

    def create(self) -> Hasher:
        return Hasher(self._engine())

    def __repr__(self) -> str:
        return f"<HashAlgorithm {self._name}>"


class Xof:
    __slots__ = ("_engine", "_lock")

    def __init__(self, engine) -> None:
        self._engine = engine

        self._lock = threading.Lock()

    def update(self, data: _Bytes) -> None:
        data = view(data)

        with self._lock:
            self._engine.update(data)

    def read(self, length: int) -> bytes:
        length = require_output_length(length)

        with self._lock:
            return self._engine.read(length)


class XofAlgorithm:
    __slots__ = ("_name", "_engine", "_digest")

    def __init__(self, name: str, engine, digest) -> None:
        self._name = name

        self._engine = engine

        self._digest = digest

    @property
    def name(self) -> str:
        return self._name

    def digest(self, data: _Bytes, length: int) -> bytes:
        return self._digest(data, length)

    def create(self) -> Xof:
        return Xof(self._engine())

    def __repr__(self) -> str:
        return f"<XofAlgorithm {self._name}>"


class Hmac:
    __slots__ = ("_engine", "_lock")

    def __init__(self, engine) -> None:
        self._engine = engine

        self._lock = threading.Lock()

    def update(self, data: _Bytes) -> None:
        data = view(data)

        with self._lock:
            self._engine.update(data)

    def digest(self) -> bytes:
        with self._lock:
            return self._engine.digest()

    def verify(self, tag: _Bytes) -> bool:
        tag = view(tag)

        with self._lock:
            return self._engine.verify(tag)


class HmacAlgorithm:
    __slots__ = ("_name", "_digest_size", "_engine", "_digest", "_verify")

    def __init__(self, name: str, digest_size: int, engine, digest, verify) -> None:
        self._name = name

        self._digest_size = digest_size

        self._engine = engine

        self._digest = digest

        self._verify = verify

    @property
    def name(self) -> str:
        return self._name

    @property
    def digest_size(self) -> int:
        return self._digest_size

    def digest(self, key: _Bytes, data: _Bytes) -> bytes:
        return self._digest(key, data)

    def create(self, key: _Bytes) -> Hmac:
        return Hmac(self._engine(view(key)))

    def verify(self, key: _Bytes, data: _Bytes, tag: _Bytes) -> bool:
        return self._verify(key, data, tag)

    def __repr__(self) -> str:
        return f"<HmacAlgorithm {self._name}>"


# HMAC on crypto-pq's own hash engines.
class _PureHmac:
    __slots__ = ("_inner", "_outer")

    # The padded key is zeroed afterwards; Python cannot promise that no other copy remains.
    def __init__(self, engine, key):
        inner = engine()

        pad = bytearray(inner._block)

        if len(key) > len(pad):
            inner.update(key)

            pad[: inner._size] = inner.digest()

            inner = engine()
        else:
            pad[: len(key)] = key

        for i in range(len(pad)):
            pad[i] ^= 0x36

        inner.update(pad)

        for i in range(len(pad)):
            pad[i] ^= 0x36 ^ 0x5C

        outer = engine()

        outer.update(pad)

        pad[:] = bytes(len(pad))

        self._inner = inner

        self._outer = outer

    def update(self, data):
        self._inner.update(data)

    def digest(self):
        outer = self._outer.copy()

        outer.update(self._inner.digest())

        return outer.digest()

    def verify(self, tag):
        return equal(self.digest(), tag)


# HMAC from the standard library's hmac module, for a hash that hashlib provides.
class _HashlibHmac:
    __slots__ = ("_hmac", "_compare")

    def __init__(self, module, name, key):
        self._hmac = module.new(immutable(key), digestmod=name)

        self._compare = module.compare_digest

    def update(self, data):
        self._hmac.update(data)

    def digest(self):
        return self._hmac.digest()

    def verify(self, tag):
        return self._compare(self._hmac.digest(), tag)


def _pure_digest(engine, data):
    hasher = engine()

    hasher.update(view(data))

    return hasher.digest()


def _pure_xof(engine, data, length):
    xof = engine()

    xof.update(view(data))

    return xof.read(require_output_length(length))


def _shake_digest(constructor, data, length):
    return constructor(view(data)).digest(require_output_length(length))


def _pure_hmac(engine, key, data):
    hmac = _PureHmac(engine, view(key))

    hmac.update(view(data))

    return hmac.digest()


def _pure_hmac_verify(engine, key, data, tag):
    hmac = _PureHmac(engine, view(key))

    hmac.update(view(data))

    return hmac.verify(view(tag))


def _hashlib_hmac(module, name, key, data):
    return module.digest(immutable(key), view(data), name)


def _hashlib_hmac_verify(module, name, key, data, tag):
    return module.compare_digest(module.digest(immutable(key), view(data), name), view(tag))


# Each algorithm is the native library's when the native backend is in use, by the library's id
# `number`; otherwise the pure backend's: hashlib's where it has the algorithm (see _primitives),
# crypto-pq's own code where it does not, and crypto-pq's own sponge for the streaming XOF reads
# that hashlib cannot make.
def _hash(name, digest_size, number, hash_name):
    if _native.BACKEND == "native":
        return HashAlgorithm(name, digest_size, partial(_native.HashState, number, digest_size), _native.hash_function(number, digest_size))

    constructor = getattr(_primitives, hash_name)

    return HashAlgorithm(name, digest_size, constructor, partial(_pure_digest, constructor))


def _xof(name, number, rate, hash_name):
    if _native.BACKEND == "native":
        return XofAlgorithm(name, partial(_native.XofState, number), _native.xof_function(number))

    return XofAlgorithm(name, partial(Keccak, rate, 0x1F, 0), partial(_shake_digest, getattr(_primitives, hash_name)))


def _hmac(name, digest_size, number, hash_name):
    if _native.BACKEND == "native":
        return HmacAlgorithm(name, digest_size, partial(_native.HmacState, number, digest_size), _native.hmac_function(number, digest_size), _native.hmac_verify_function(number))

    engine = getattr(_primitives, hash_name)

    if _primitives.hashlib is not None and engine is getattr(_primitives.hashlib, hash_name, None):
        import hmac

        return HmacAlgorithm(name, digest_size, partial(_HashlibHmac, hmac, hash_name), partial(_hashlib_hmac, hmac, hash_name), partial(_hashlib_hmac_verify, hmac, hash_name))

    return HmacAlgorithm(name, digest_size, partial(_PureHmac, engine), partial(_pure_hmac, engine), partial(_pure_hmac_verify, engine))


SHA_224 = _hash("SHA-224", 28, 0, "sha224")

SHA_256 = _hash("SHA-256", 32, 1, "sha256")

SHA_384 = _hash("SHA-384", 48, 2, "sha384")

SHA_512 = _hash("SHA-512", 64, 3, "sha512")

SHA_512_224 = _hash("SHA-512/224", 28, 4, "sha512_224")

SHA_512_256 = _hash("SHA-512/256", 32, 5, "sha512_256")

SHA3_224 = _hash("SHA3-224", 28, 6, "sha3_224")

SHA3_256 = _hash("SHA3-256", 32, 7, "sha3_256")

SHA3_384 = _hash("SHA3-384", 48, 8, "sha3_384")

SHA3_512 = _hash("SHA3-512", 64, 9, "sha3_512")

SHAKE128 = _xof("SHAKE128", 0, 168, "shake_128")

SHAKE256 = _xof("SHAKE256", 1, 136, "shake_256")

HMAC_SHA_224 = _hmac("HMAC-SHA-224", 28, 0, "sha224")

HMAC_SHA_256 = _hmac("HMAC-SHA-256", 32, 1, "sha256")

HMAC_SHA_384 = _hmac("HMAC-SHA-384", 48, 2, "sha384")

HMAC_SHA_512 = _hmac("HMAC-SHA-512", 64, 3, "sha512")

import operator
import threading
from functools import partial

from . import _native
from ._bytes import equal, view
from ._errors import CryptoPQError, ErrorCode
from ._keccak import Keccak
from ._sha2 import IV_224, IV_256, IV_384, IV_512, IV_512_224, IV_512_256, Sha256, Sha512

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


def require_output_length(length):
    length = operator.index(length)

    if length < 0:
        raise CryptoPQError(ErrorCode.INVALID_LENGTH, "length must not be negative")

    return length


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
        data = view(data)

        return self._digest(data, require_output_length(length))

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


def _pure_digest(engine, data):
    hasher = engine()

    hasher.update(view(data))

    return hasher.digest()


def _pure_xof(engine, data, length):
    xof = engine()

    xof.update(data)

    return xof.read(length)


def _pure_hmac(engine, key, data):
    hmac = _PureHmac(engine, view(key))

    hmac.update(view(data))

    return hmac.digest()


def _pure_hmac_verify(engine, key, data, tag):
    hmac = _PureHmac(engine, view(key))

    hmac.update(view(data))

    return hmac.verify(view(tag))


# Each function is the native library's when the native backend is in use, with the pure engine
# as its fallback; `number` is the library's id of the function.
def _hash(name, digest_size, number, engine):
    if _native.BACKEND == "native":
        return HashAlgorithm(name, digest_size, partial(_native.HashState, number, digest_size), partial(_native.hash_digest, number, digest_size))

    return HashAlgorithm(name, digest_size, engine, partial(_pure_digest, engine))


def _xof(name, number, engine):
    if _native.BACKEND == "native":
        return XofAlgorithm(name, partial(_native.XofState, number), partial(_native.xof_digest, number))

    return XofAlgorithm(name, engine, partial(_pure_xof, engine))


def _hmac(name, digest_size, number, engine):
    if _native.BACKEND == "native":
        return HmacAlgorithm(name, digest_size, partial(_native.HmacState, number, digest_size), partial(_native.hmac_digest, number, digest_size), partial(_native.hmac_verify, number))

    return HmacAlgorithm(name, digest_size, partial(_PureHmac, engine), partial(_pure_hmac, engine), partial(_pure_hmac_verify, engine))


_SHA_224 = partial(Sha256, IV_224, 28)

_SHA_256 = partial(Sha256, IV_256, 32)

_SHA_384 = partial(Sha512, IV_384, 48)

_SHA_512 = partial(Sha512, IV_512, 64)

SHA_224 = _hash("SHA-224", 28, 0, _SHA_224)

SHA_256 = _hash("SHA-256", 32, 1, _SHA_256)

SHA_384 = _hash("SHA-384", 48, 2, _SHA_384)

SHA_512 = _hash("SHA-512", 64, 3, _SHA_512)

SHA_512_224 = _hash("SHA-512/224", 28, 4, partial(Sha512, IV_512_224, 28))

SHA_512_256 = _hash("SHA-512/256", 32, 5, partial(Sha512, IV_512_256, 32))

SHA3_224 = _hash("SHA3-224", 28, 6, partial(Keccak, 144, 0x06, 28))

SHA3_256 = _hash("SHA3-256", 32, 7, partial(Keccak, 136, 0x06, 32))

SHA3_384 = _hash("SHA3-384", 48, 8, partial(Keccak, 104, 0x06, 48))

SHA3_512 = _hash("SHA3-512", 64, 9, partial(Keccak, 72, 0x06, 64))

SHAKE128 = _xof("SHAKE128", 0, partial(Keccak, 168, 0x1F, 0))

SHAKE256 = _xof("SHAKE256", 1, partial(Keccak, 136, 0x1F, 0))

HMAC_SHA_224 = _hmac("HMAC-SHA-224", 28, 0, _SHA_224)

HMAC_SHA_256 = _hmac("HMAC-SHA-256", 32, 1, _SHA_256)

HMAC_SHA_384 = _hmac("HMAC-SHA-384", 48, 2, _SHA_384)

HMAC_SHA_512 = _hmac("HMAC-SHA-512", 64, 3, _SHA_512)

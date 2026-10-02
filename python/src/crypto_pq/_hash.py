import operator
from functools import partial

from ._bytes import equal, view
from ._errors import CryptoPQError, ErrorCode
from ._keccak import Keccak
from ._sha2 import IV_224, IV_256, IV_384, IV_512, IV_512_224, IV_512_256, Sha256, Sha512

_Bytes = bytes | bytearray | memoryview


class Hasher:
    __slots__ = ("_engine",)

    def __init__(self, engine) -> None:
        self._engine = engine

    def update(self, data: _Bytes) -> None:
        self._engine.update(view(data))

    def digest(self) -> bytes:
        return self._engine.digest()


class HashAlgorithm:
    __slots__ = ("_name", "_digest_size", "_engine")

    def __init__(self, name: str, digest_size: int, engine) -> None:
        self._name = name

        self._digest_size = digest_size

        self._engine = engine

    @property
    def name(self) -> str:
        return self._name

    @property
    def digest_size(self) -> int:
        return self._digest_size

    def digest(self, data: _Bytes) -> bytes:
        hasher = self.create()

        hasher.update(data)

        return hasher.digest()

    def create(self) -> Hasher:
        return Hasher(self._engine())

    def __repr__(self) -> str:
        return f"<HashAlgorithm {self._name}>"


class Xof:
    __slots__ = ("_engine",)

    def __init__(self, engine) -> None:
        self._engine = engine

    def update(self, data: _Bytes) -> None:
        self._engine.update(view(data))

    def read(self, length: int) -> bytes:
        length = operator.index(length)

        if length < 0:
            raise CryptoPQError(ErrorCode.INVALID_LENGTH, "length must not be negative")

        return self._engine.read(length)


class XofAlgorithm:
    __slots__ = ("_name", "_engine")

    def __init__(self, name: str, engine) -> None:
        self._name = name

        self._engine = engine

    @property
    def name(self) -> str:
        return self._name

    def digest(self, data: _Bytes, length: int) -> bytes:
        xof = self.create()

        xof.update(data)

        return xof.read(length)

    def create(self) -> Xof:
        return Xof(self._engine())

    def __repr__(self) -> str:
        return f"<XofAlgorithm {self._name}>"


class Hmac:
    __slots__ = ("_inner", "_outer")

    # The padded key is zeroed afterwards; Python cannot promise that no other copy remains.
    def __init__(self, engine, key: _Bytes) -> None:
        key = view(key)

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

    def update(self, data: _Bytes) -> None:
        self._inner.update(view(data))

    def digest(self) -> bytes:
        outer = self._outer.copy()

        outer.update(self._inner.digest())

        return outer.digest()

    def verify(self, tag: _Bytes) -> bool:
        return equal(self.digest(), view(tag))


class HmacAlgorithm:
    __slots__ = ("_name", "_hash")

    def __init__(self, name: str, hash: HashAlgorithm) -> None:
        self._name = name

        self._hash = hash

    @property
    def name(self) -> str:
        return self._name

    @property
    def digest_size(self) -> int:
        return self._hash.digest_size

    def digest(self, key: _Bytes, data: _Bytes) -> bytes:
        hmac = self.create(key)

        hmac.update(data)

        return hmac.digest()

    def create(self, key: _Bytes) -> Hmac:
        return Hmac(self._hash._engine, key)

    def verify(self, key: _Bytes, data: _Bytes, tag: _Bytes) -> bool:
        hmac = self.create(key)

        hmac.update(data)

        return hmac.verify(tag)

    def __repr__(self) -> str:
        return f"<HmacAlgorithm {self._name}>"


SHA_224 = HashAlgorithm("SHA-224", 28, partial(Sha256, IV_224, 28))

SHA_256 = HashAlgorithm("SHA-256", 32, partial(Sha256, IV_256, 32))

SHA_384 = HashAlgorithm("SHA-384", 48, partial(Sha512, IV_384, 48))

SHA_512 = HashAlgorithm("SHA-512", 64, partial(Sha512, IV_512, 64))

SHA_512_224 = HashAlgorithm("SHA-512/224", 28, partial(Sha512, IV_512_224, 28))

SHA_512_256 = HashAlgorithm("SHA-512/256", 32, partial(Sha512, IV_512_256, 32))

SHA3_224 = HashAlgorithm("SHA3-224", 28, partial(Keccak, 144, 0x06, 28))

SHA3_256 = HashAlgorithm("SHA3-256", 32, partial(Keccak, 136, 0x06, 32))

SHA3_384 = HashAlgorithm("SHA3-384", 48, partial(Keccak, 104, 0x06, 48))

SHA3_512 = HashAlgorithm("SHA3-512", 64, partial(Keccak, 72, 0x06, 64))

SHAKE128 = XofAlgorithm("SHAKE128", partial(Keccak, 168, 0x1F, 0))

SHAKE256 = XofAlgorithm("SHAKE256", partial(Keccak, 136, 0x1F, 0))

HMAC_SHA_224 = HmacAlgorithm("HMAC-SHA-224", SHA_224)

HMAC_SHA_256 = HmacAlgorithm("HMAC-SHA-256", SHA_256)

HMAC_SHA_384 = HmacAlgorithm("HMAC-SHA-384", SHA_384)

HMAC_SHA_512 = HmacAlgorithm("HMAC-SHA-512", SHA_512)

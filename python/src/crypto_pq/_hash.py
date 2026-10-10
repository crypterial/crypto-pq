import operator
import threading
from functools import partial

from . import _ascon, _native, _primitives, _sp800_185
from ._bytes import equal, immutable, require_bytes, require_output_length, view
from ._errors import CryptoPQError, ErrorCode
from ._keccak import Keccak

_Bytes = bytes | bytearray | memoryview


def _invalid_option(message):
    return CryptoPQError(ErrorCode.INVALID_OPTION, message)


# A hash, XOF or MAC object takes one call at a time, as hashlib's do: calls from several threads
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
# `configure` sets a function's parameters once: the configured algorithm is the base algorithm
# with these options and the defaults for the rest (no options at all give the base algorithm
# itself); `_options(base, ...)` checks them and builds it, and is None where there are none.
class HashAlgorithm:
    __slots__ = ("_name", "_digest_size", "_engine", "_digest", "_options", "_base")

    def __init__(self, name: str, digest_size: int, engine, digest, options=None, base=None) -> None:
        self._name = name

        self._digest_size = digest_size

        self._engine = engine

        self._digest = digest

        self._options = options

        self._base = self if base is None else base

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

    # BLAKE2 alone takes a salt and a personalization, each of at most 16 (BLAKE2b) or 8 (BLAKE2s)
    # bytes and zero-padded to that size, as the parameter block holds them.
    def configure(self, *, salt: _Bytes = b"", personalization: _Bytes = b"") -> "HashAlgorithm":
        salt = require_bytes(salt, "salt")

        personalization = require_bytes(personalization, "personalization")

        if not salt and not personalization:
            return self._base

        if self._options is None:
            raise _invalid_option(f"{self._name} takes no salt or personalization")

        return self._options(self._base, salt, personalization)

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
    __slots__ = ("_name", "_engine", "_digest", "_options", "_base")

    def __init__(self, name: str, engine, digest, options=None, base=None) -> None:
        self._name = name

        self._engine = engine

        self._digest = digest

        self._options = options

        self._base = self if base is None else base

    @property
    def name(self) -> str:
        return self._name

    def digest(self, data: _Bytes, length: int) -> bytes:
        return self._digest(data, length)

    def create(self) -> Xof:
        return Xof(self._engine())

    # cSHAKE takes a customization string S of any length, Ascon-CXOF128 one of at most 256
    # bytes. cSHAKE's function name N is for NIST's own functions: hazmat.configure_cshake.
    def configure(self, *, customization: _Bytes = b"") -> "XofAlgorithm":
        customization = require_bytes(customization, "customization")

        if not customization:
            return self._base

        if self._options is None:
            raise _invalid_option(f"{self._name} takes no customization")

        return self._options(self._base, b"", customization)

    def __repr__(self) -> str:
        return f"<XofAlgorithm {self._name}>"


class Mac:
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


class MacAlgorithm:
    __slots__ = ("_name", "_digest_size", "_engine", "_digest", "_verify", "_options", "_base")

    def __init__(self, name: str, digest_size: int, engine, digest, verify, options=None, base=None) -> None:
        self._name = name

        self._digest_size = digest_size

        self._engine = engine

        self._digest = digest

        self._verify = verify

        self._options = options

        self._base = self if base is None else base

    @property
    def name(self) -> str:
        return self._name

    @property
    def digest_size(self) -> int:
        return self._digest_size

    def digest(self, key: _Bytes, data: _Bytes) -> bytes:
        return self._digest(key, data)

    def create(self, key: _Bytes) -> Mac:
        return Mac(self._engine(view(key)))

    # A tag of another length, or a key that the function cannot take, does not verify.
    def verify(self, key: _Bytes, data: _Bytes, tag: _Bytes) -> bool:
        return self._verify(key, data, tag)

    # KMAC takes the output length (at least 4 bytes), a customization string and xof (KMACXOF);
    # BLAKE2 the output length (1 to 64 or 32 bytes), a salt and a personalization; HMAC nothing.
    def configure(self, *, length: int | None = None, customization: _Bytes = b"", xof: bool = False, salt: _Bytes = b"", personalization: _Bytes = b"") -> "MacAlgorithm":
        customization = require_bytes(customization, "customization")

        salt = require_bytes(salt, "salt")

        personalization = require_bytes(personalization, "personalization")

        if not isinstance(xof, bool):
            raise _invalid_option("xof must be a bool")

        if length is not None:
            length = operator.index(length)
        elif not customization and not xof and not salt and not personalization:
            return self._base

        if self._options is None:
            raise _invalid_option(f"{self._name} takes no options")

        return self._options(self._base, length, customization, xof, salt, personalization)

    def __repr__(self) -> str:
        return f"<MacAlgorithm {self._name}>"


class KdfAlgorithm:
    __slots__ = ("_name", "_size", "_derive", "_extract", "_expand")

    def __init__(self, name: str, size: int, derive, extract, expand) -> None:
        self._name = name

        self._size = size

        self._derive = derive

        self._extract = extract

        self._expand = expand

    @property
    def name(self) -> str:
        return self._name

    def derive(self, ikm: _Bytes, length: int, *, salt: _Bytes = b"", info: _Bytes = b"") -> bytes:
        return self._derive(ikm, salt, info, self._output_length(length))

    # The pseudorandom key, of the hash's size. An empty salt is HashLen zero bytes (RFC 5869, 2.2).
    def extract(self, ikm: _Bytes, *, salt: _Bytes = b"") -> bytes:
        return self._extract(ikm, salt)

    def expand(self, prk: _Bytes, length: int, *, info: _Bytes = b"") -> bytes:
        prk = view(prk)

        if len(prk) < self._size:
            raise CryptoPQError(ErrorCode.INVALID_LENGTH, f"the pseudorandom key of {self._name} has at least {self._size} bytes")

        return self._expand(prk, info, self._output_length(length))

    # RFC 5869, 2.3: L is at most 255 HashLen; an empty output is refused as well.
    def _output_length(self, length):
        length = operator.index(length)

        if not 0 < length <= 255 * self._size:
            raise CryptoPQError(ErrorCode.INVALID_LENGTH, f"the output of {self._name} is 1 to {255 * self._size} bytes")

        return length

    def __repr__(self) -> str:
        return f"<KdfAlgorithm {self._name}>"


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


# Keyed BLAKE2 from hashlib (RFC 7693: the key is the first block); `constructor` holds the output
# length, the salt and the personalization.
class _HashlibBlake2Mac:
    __slots__ = ("_hash",)

    def __init__(self, constructor, maximum, key):
        if not 0 < len(key) <= maximum:
            raise CryptoPQError(ErrorCode.INVALID_LENGTH, f"a BLAKE2 key has 1 to {maximum} bytes")

        self._hash = constructor(key=immutable(key))

    def update(self, data):
        self._hash.update(data)

    def digest(self):
        return self._hash.digest()

    def verify(self, tag):
        return equal(self._hash.digest(), tag)


def _pure_digest(engine, data):
    hasher = engine()

    hasher.update(view(data))

    return hasher.digest()


def _hashlib_digest(constructor, data):
    return constructor(view(data)).digest()


def _pure_xof(engine, data, length):
    xof = engine()

    xof.update(view(data))

    return xof.read(require_output_length(length))


def _shake_digest(constructor, data, length):
    return constructor(view(data)).digest(require_output_length(length))


# `engine(key)` is a MAC state.
def _pure_mac(engine, key, data):
    mac = engine(view(key))

    mac.update(view(data))

    return mac.digest()


def _pure_mac_verify(engine, key, data, tag):
    mac = engine(view(key))

    mac.update(view(data))

    return mac.verify(view(tag))


def _blake2_mac_verify(engine, maximum, key, data, tag):
    key, data, tag = view(key), view(data), view(tag)

    if not 0 < len(key) <= maximum:
        return False

    return _pure_mac_verify(engine, key, data, tag)


def _hashlib_hmac(module, name, key, data):
    return module.digest(immutable(key), view(data), name)


def _hashlib_hmac_verify(module, name, key, data, tag):
    return module.compare_digest(module.digest(immutable(key), view(data), name), view(tag))


# HKDF (RFC 5869) on a backend's HMAC function hmac(key, data).
def _pure_extract(hmac, ikm, salt):
    return hmac(salt, ikm)


def _pure_expand(hmac, size, prk, info, length):
    info = immutable(info)

    okm = bytearray()

    block = b""

    for counter in range(1, -(-length // size) + 1):
        block = hmac(prk, block + info + bytes([counter]))

        okm += block

    out = bytes(okm[:length])

    okm[:] = bytes(len(okm))

    return out


def _pure_derive(hmac, size, ikm, salt, info, length):
    return _pure_expand(hmac, size, _pure_extract(hmac, ikm, salt), info, length)


def _unsupported(name):
    def refuse(*args, **kwargs):
        raise CryptoPQError(ErrorCode.UNSUPPORTED, f"this Python's hashlib has no {name}, which the pure backend computes BLAKE2 with")

    return refuse


def _blake2_hash_options(field, build):
    def configure(base, salt, personalization):
        if len(salt) > field or len(personalization) > field:
            raise _invalid_option(f"{base._name} takes a salt and a personalization of at most {field} bytes")

        return HashAlgorithm(base._name, base._digest_size, *build(salt, personalization), base._options, base)

    return configure


def _xof_options(limit, build):
    def configure(base, function_name, customization):
        if limit is not None and len(customization) > limit:
            raise _invalid_option(f"{base._name} takes a customization of at most {limit} bytes")

        return XofAlgorithm(base._name, *build(function_name, customization), base._options, base)

    return configure


# SP 800-185, 8.4.2: a KMAC tag has at least 32 bits. The upper bound keeps L, in bits, below 2^64.
def _kmac_options(build):
    def configure(base, length, customization, xof, salt, personalization):
        if salt or personalization:
            raise _invalid_option(f"{base._name} takes no salt or personalization")

        if length is None:
            length = base._digest_size

        if not 4 <= length < 1 << 61:
            raise _invalid_option(f"the output of {base._name} has at least 4 bytes")

        return MacAlgorithm(base._name, length, *build(length, customization, xof), base._options, base)

    return configure


def _blake2_mac_options(maximum, field, build):
    def configure(base, length, customization, xof, salt, personalization):
        if customization or xof:
            raise _invalid_option(f"{base._name} takes no customization or XOF mode")

        if len(salt) > field or len(personalization) > field:
            raise _invalid_option(f"{base._name} takes a salt and a personalization of at most {field} bytes")

        if length is None:
            length = maximum

        if not 0 < length <= maximum:
            raise _invalid_option(f"the output of {base._name} has 1 to {maximum} bytes")

        return MacAlgorithm(base._name, length, *build(length, salt, personalization), base._options, base)

    return configure


NATIVE = _native.BACKEND == "native"


# Each algorithm is the native library's when the native backend is in use, by the library's id
# `number`; otherwise the pure backend's: hashlib's where it has the algorithm (see _primitives),
# crypto-pq's own code where it does not, and crypto-pq's own sponge for the streaming XOF reads
# that hashlib cannot make.
def _hash(name, digest_size, number, hash_name):
    if NATIVE:
        return HashAlgorithm(name, digest_size, partial(_native.HashState, number, digest_size), _native.hash_function(number, digest_size))

    constructor = getattr(_primitives, hash_name)

    return HashAlgorithm(name, digest_size, constructor, partial(_pure_digest, constructor))


def _blake2(name, digest_size, number, field, hash_name):
    if not NATIVE:
        return _pure_blake2(name, digest_size, field, getattr(_primitives, hash_name) or _unsupported(hash_name))

    def build(salt, personalization):
        spec = _native.hash_configure(number, salt, personalization)

        return partial(_native.HashState, number, digest_size, spec), _native.hash_with_function(spec, digest_size)

    return HashAlgorithm(name, digest_size, partial(_native.HashState, number, digest_size), _native.hash_function(number, digest_size), _blake2_hash_options(field, build))


# BLAKE2 in the pure backend is hashlib's, the one place that takes its parameters.
def _pure_blake2(name, digest_size, field, constructor):
    def build(salt, personalization):
        engine = partial(constructor, digest_size=digest_size, salt=salt, person=personalization)

        return engine, partial(_hashlib_digest, engine)

    return HashAlgorithm(name, digest_size, *build(b"", b""), _blake2_hash_options(field, build))


def _ascon_hash():
    if NATIVE:
        return HashAlgorithm("Ascon-Hash256", 32, partial(_native.HashState, 18, 32), _native.hash_function(18, 32))

    return _pure_ascon_hash()


def _pure_ascon_hash():
    engine = partial(_ascon.Ascon, _ascon.HASH256, 32)

    return HashAlgorithm("Ascon-Hash256", 32, engine, partial(_pure_digest, engine))


def _xof(name, number, rate, hash_name):
    if NATIVE:
        return XofAlgorithm(name, partial(_native.XofState, number), _native.xof_function(number))

    return XofAlgorithm(name, partial(Keccak, rate, 0x1F, 0), partial(_shake_digest, getattr(_primitives, hash_name)))


def _native_xof_build(number):
    def build(function_name, customization):
        spec = _native.xof_configure(number, function_name, customization)

        return partial(_native.XofState, number, spec), _native.xof_with_function(spec)

    return build


def _pure_xof_build(start):
    def build(function_name, customization):
        prefix = start(function_name, customization)

        return prefix.copy, partial(_pure_xof, prefix.copy)

    return build


def _cshake(name, number, rate, shake):
    if NATIVE:
        return XofAlgorithm(name, partial(_native.XofState, number), _native.xof_function(number), _xof_options(None, _native_xof_build(number)))

    return _pure_cshake(name, rate, shake)


# cSHAKE without N and S is SHAKE, which the base algorithm computes as `shake` does.
def _pure_cshake(name, rate, shake):
    return XofAlgorithm(name, shake._engine, shake._digest, _xof_options(None, _pure_xof_build(partial(_sp800_185.cshake, rate))))


def _ascon_xof():
    if NATIVE:
        return XofAlgorithm("Ascon-XOF128", partial(_native.XofState, 4), _native.xof_function(4))

    return _pure_ascon_xof()


def _pure_ascon_xof():
    engine = partial(_ascon.Ascon, _ascon.XOF128)

    return XofAlgorithm("Ascon-XOF128", engine, partial(_pure_xof, engine))


def _ascon_cxof():
    if NATIVE:
        return XofAlgorithm("Ascon-CXOF128", partial(_native.XofState, 5), _native.xof_function(5), _xof_options(_ascon.MAX_CUSTOMIZATION, _native_xof_build(5)))

    return _pure_ascon_cxof()


def _pure_ascon_cxof():
    build = _pure_xof_build(lambda function_name, customization: _ascon.customized(customization))

    return XofAlgorithm("Ascon-CXOF128", *build(b"", b""), _xof_options(_ascon.MAX_CUSTOMIZATION, build))


def _hmac(name, digest_size, number, hash_name):
    if NATIVE:
        return MacAlgorithm(name, digest_size, *_native_mac(number, digest_size))

    engine = getattr(_primitives, hash_name)

    if _primitives.hashlib is not None and engine is getattr(_primitives.hashlib, hash_name, None):
        import hmac

        return MacAlgorithm(name, digest_size, partial(_HashlibHmac, hmac, hash_name), partial(_hashlib_hmac, hmac, hash_name), partial(_hashlib_hmac_verify, hmac, hash_name))

    return _pure_hmac(name, digest_size, engine)


def _pure_hmac(name, digest_size, engine):
    engine = partial(_PureHmac, engine)

    return MacAlgorithm(name, digest_size, engine, partial(_pure_mac, engine), partial(_pure_mac_verify, engine))


def _native_mac(number, size, spec=None):
    if spec is None:
        return partial(_native.MacState, number, size), _native.mac_function(number, size), _native.mac_verify_function(number)

    return partial(_native.MacState, number, size, spec=spec), _native.mac_with_function(spec, size), _native.mac_verify_with_function(spec)


# flags of the native library's MAC configuration: 1 KMACXOF, 2 the length is given.
def _kmac(name, default, number, rate):
    if not NATIVE:
        return _pure_kmac(name, default, rate)

    def build(length, customization, xof):
        return _native_mac(number, length, _native.mac_configure(number, length, 2 | xof, customization, b""))

    return MacAlgorithm(name, default, *_native_mac(number, default), _kmac_options(build))


def _pure_kmac(name, default, rate):
    def build(length, customization, xof):
        engine = partial(_sp800_185.Kmac, _sp800_185.cshake(rate, b"KMAC", customization), length, xof)

        return engine, partial(_pure_mac, engine), partial(_pure_mac_verify, engine)

    return MacAlgorithm(name, default, *build(default, b"", False), _kmac_options(build))


def _blake2_mac(name, maximum, number, field, hash_name):
    if not NATIVE:
        return _pure_blake2_mac(name, maximum, field, getattr(_primitives, hash_name) or _unsupported(hash_name))

    def build(length, salt, personalization):
        return _native_mac(number, length, _native.mac_configure(number, length, 2, salt, personalization))

    return MacAlgorithm(name, maximum, *_native_mac(number, maximum), _blake2_mac_options(maximum, field, build))


def _pure_blake2_mac(name, maximum, field, constructor):
    def build(length, salt, personalization):
        engine = partial(_HashlibBlake2Mac, partial(constructor, digest_size=length, salt=salt, person=personalization), maximum)

        return engine, partial(_pure_mac, engine), partial(_blake2_mac_verify, engine, maximum)

    return MacAlgorithm(name, maximum, *build(maximum, b"", b""), _blake2_mac_options(maximum, field, build))


def _hkdf(name, size, number, hmac):
    if NATIVE:
        return KdfAlgorithm(name, size, *_native.kdf_functions(number, size))

    return _pure_hkdf(name, size, hmac)


# HKDF on the HMAC algorithm `hmac` of the same backend.
def _pure_hkdf(name, size, hmac):
    function = hmac._digest

    return KdfAlgorithm(name, size, partial(_pure_derive, function, size), partial(_pure_extract, function), partial(_pure_expand, function, size))


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

BLAKE2B_160 = _blake2("BLAKE2b-160", 20, 10, 16, "blake2b")

BLAKE2B_256 = _blake2("BLAKE2b-256", 32, 11, 16, "blake2b")

BLAKE2B_384 = _blake2("BLAKE2b-384", 48, 12, 16, "blake2b")

BLAKE2B_512 = _blake2("BLAKE2b-512", 64, 13, 16, "blake2b")

BLAKE2S_128 = _blake2("BLAKE2s-128", 16, 14, 8, "blake2s")

BLAKE2S_160 = _blake2("BLAKE2s-160", 20, 15, 8, "blake2s")

BLAKE2S_224 = _blake2("BLAKE2s-224", 28, 16, 8, "blake2s")

BLAKE2S_256 = _blake2("BLAKE2s-256", 32, 17, 8, "blake2s")

ASCON_HASH256 = _ascon_hash()

SHAKE128 = _xof("SHAKE128", 0, 168, "shake_128")

SHAKE256 = _xof("SHAKE256", 1, 136, "shake_256")

CSHAKE128 = _cshake("cSHAKE128", 2, 168, SHAKE128)

CSHAKE256 = _cshake("cSHAKE256", 3, 136, SHAKE256)

ASCON_XOF128 = _ascon_xof()

ASCON_CXOF128 = _ascon_cxof()

HMAC_SHA_224 = _hmac("HMAC-SHA-224", 28, 0, "sha224")

HMAC_SHA_256 = _hmac("HMAC-SHA-256", 32, 1, "sha256")

HMAC_SHA_384 = _hmac("HMAC-SHA-384", 48, 2, "sha384")

HMAC_SHA_512 = _hmac("HMAC-SHA-512", 64, 3, "sha512")

KMAC128 = _kmac("KMAC128", 32, 4, 168)

KMAC256 = _kmac("KMAC256", 64, 5, 136)

BLAKE2B_MAC = _blake2_mac("BLAKE2b-MAC", 64, 6, 16, "blake2b")

BLAKE2S_MAC = _blake2_mac("BLAKE2s-MAC", 32, 7, 8, "blake2s")

HKDF_SHA_256 = _hkdf("HKDF-SHA-256", 32, 0, HMAC_SHA_256)

HKDF_SHA_384 = _hkdf("HKDF-SHA-384", 48, 1, HMAC_SHA_384)

HKDF_SHA_512 = _hkdf("HKDF-SHA-512", 64, 2, HMAC_SHA_512)

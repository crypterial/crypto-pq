"""The native backend: crypto-pq's Zig core, the shared library of a platform wheel, called
through ctypes.

The backend is chosen once, at import, from CRYPTO_PQ_BACKEND: "pure" never maps the library;
"auto" (the default) and "native" check the library against the build record shipped with it,
load it by its absolute path, check its ABI version, declare every function and run a
known-answer test. Any failure leaves the pure backend under "auto", with the reason in
LOAD_ERROR, and raises ImportError under "native".

Every input crosses as bytes, which no other thread can change during a call; every output comes
from a buffer of the exact size, and the buffers that held secrets are zeroed once copied out.
Keys, hash states and stateful signers live in slots: memory that Python owns, aligned as the
library asks, which the library tags and checks, and which is wiped when its object goes. The
library reads no randomness: the callers pass bytes from the package's OS source.
"""

import binascii
import os
import sys
from typing import Any

from ._bytes import immutable
from ._errors import CryptoPQError, ErrorCode

ABI_VERSION = 1

# The build record that the wheel builder writes next to the library: its file name, the platform
# it was built for, its size and its CRC-32.
RECORD = "native.record"

RECORD_FORMAT = "crypto-pq native library 1"

LIBRARIES = ("libcrypto_pq.so", "libcrypto_pq.dylib", "crypto_pq.dll")

KEM_PUBLIC, KEM_PRIVATE, SIGNATURE_PUBLIC, SIGNATURE_PRIVATE, HASHER, XOF, HMAC, SIGNER = range(1, 9)

CODES = {
    1: ErrorCode.INVALID_LENGTH,
    2: ErrorCode.INVALID_ENCODING,
    3: ErrorCode.ALGORITHM_MISMATCH,
    4: ErrorCode.INVALID_PUBLIC_KEY,
    5: ErrorCode.INVALID_PRIVATE_KEY,
    6: ErrorCode.INVALID_CONTEXT,
    7: ErrorCode.INVALID_OPTION,
    8: ErrorCode.RNG_FAILURE,
    9: ErrorCode.SELF_TEST_FAILED,
    10: ErrorCode.KEY_EXHAUSTED,
    11: ErrorCode.STATE_PERSIST_FAILED,
    12: ErrorCode.STATE_CONFLICT,
    13: ErrorCode.UNSUPPORTED,
}

INVALID_PUBLIC_KEY, INVALID_PRIVATE_KEY, SELF_TEST_FAILED, UNSUPPORTED = 4, 5, 9, 13

REJECTED, OUT_OF_MEMORY = 100, 103

FILL_CACHE = 1

EXPORT_SEED, EXPORT_PRIVATE = 0, 1

DETERMINISTIC, HAZMAT = 1, 2

WITH_TREE_CACHE = 1

# The known-answer test: an X-Wing key pair from a fixed seed encapsulates with a fixed eseed and
# decapsulates, an ML-DSA-44 key signs deterministically and verifies, HMAC-SHA-512 tags the
# signature with the shared secret, and SHA-256 of every output must be this digest, which the
# pure backend computes too (tests/test_native.py).
SELF_TEST_MESSAGE = b"crypto-pq native self-test"

SELF_TEST_DIGEST = "bbb955d5cf2b2f9b0d32ecdc3862346e1a795f0ce645a5428e466236aaeae1ad"

_lib: Any = None

_c: Any = None

# The size, the alignment and the memory type of each slot, by slot type and algorithm.
SIZES: dict[tuple[int, int], tuple[int, int, Any]] = {}


class Unusable(Exception):
    pass


def failure(status, message):
    code = CODES.get(status)

    if code is not None:
        return CryptoPQError(code, message)

    if status == OUT_OF_MEMORY:
        return MemoryError("the native library could not allocate memory")

    return RuntimeError(f"crypto-pq made an invalid call to its native library (status {status})")


def check(status, message="the native library refused the operation"):
    if status:
        raise failure(status, message)


def platform_target():
    if sys.maxsize < 1 << 32:
        return None

    if sys.platform == "win32":
        version = sys.version.lower()

        machine = "aarch64" if "(arm64)" in version else "x86_64" if "(amd64)" in version else None

        return f"{machine}-windows" if machine else None

    system = {"linux": "linux", "darwin": "macos"}.get(sys.platform)

    machine = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64", "riscv64": "riscv64"}.get(os.uname().machine.lower())

    return f"{machine}-{system}" if system and machine else None


def read_record(directory):
    try:
        with open(os.path.join(directory, RECORD), "rb") as handle:
            lines = handle.read(4096).decode("ascii").splitlines()
    except FileNotFoundError:
        raise Unusable("the package holds no native library") from None

    if not lines or lines[0] != RECORD_FORMAT:
        raise Unusable("the native library's build record has an unknown format")

    fields = dict(line.partition(" ")[::2] for line in lines[1:])

    try:
        return fields["file"], fields["target"], int(fields["size"]), int(fields["crc32"], 16)
    except (KeyError, ValueError):
        raise Unusable("the native library's build record is malformed") from None


def open_library():
    directory = os.path.dirname(os.path.abspath(__file__))

    name, target, size, crc = read_record(directory)

    if name not in LIBRARIES:
        raise Unusable("the build record names no crypto-pq library")

    running = platform_target()

    if target != running:
        raise Unusable(f"the native library is built for {target}, and this interpreter runs on {running or 'another platform'}")

    path = os.path.join(directory, name)

    # A truncated library can stop the process inside dlopen (SIGBUS), so the file must be the one
    # its record describes before it is mapped. The CRC-32 catches damage, not tampering: whoever
    # can rewrite the library can rewrite this module too.
    with open(path, "rb") as handle:
        data = handle.read(size + 1)

    if len(data) != size or binascii.crc32(data) != crc:
        raise Unusable("the native library is damaged: it differs from its build record")

    import ctypes

    library = ctypes.CDLL(path)

    version = library.cpq_abi_version

    version.argtypes = ()

    version.restype = ctypes.c_uint32

    found = version()

    if found != ABI_VERSION:
        raise Unusable(f"the native library has ABI version {found}, and this package needs {ABI_VERSION}")

    declare(library, ctypes)

    return library, ctypes


# Inputs are c_char_p, which takes bytes or None only; slots and outputs are c_void_p.
def declare(library, ctypes):
    status, size, u32, u64 = ctypes.c_int, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint64

    memory, data = ctypes.c_void_p, ctypes.c_char_p

    for name, restype, *argtypes in (
        ("cpq_slot_size", size, u32, u32),
        ("cpq_slot_align", size, u32, u32),
        ("cpq_slot_info", status, memory, size, memory),
        ("cpq_slot_wipe", status, memory, size),
        ("cpq_kem_keygen", status, u32, data, size, u32, memory, size),
        ("cpq_kem_import_public", status, u32, data, size, memory, size),
        ("cpq_kem_import_private", status, u32, data, size, memory, size),
        ("cpq_kem_public_from_private", status, memory, size, memory, size),
        ("cpq_kem_export_public", status, memory, size, memory, size),
        ("cpq_kem_export_private", status, memory, size, u32, memory, size),
        ("cpq_kem_encapsulate", status, memory, size, data, size, memory, size, memory, size),
        ("cpq_kem_decapsulate", status, memory, size, data, size, memory, size),
        ("cpq_kem_self_test", status, memory, size, data, size),
        ("cpq_sig_keygen", status, u32, data, size, u32, memory, size),
        ("cpq_sig_import_public", status, u32, data, size, memory, size),
        ("cpq_sig_import_private", status, u32, data, size, memory, size),
        ("cpq_sig_public_from_private", status, memory, size, memory, size),
        ("cpq_sig_export_public", status, memory, size, memory, size),
        ("cpq_sig_export_private", status, memory, size, u32, memory, size),
        ("cpq_sig_sign", status, memory, size, data, size, data, size, u32, data, size, u32, memory, size),
        ("cpq_sig_verify", status, memory, size, data, size, data, size, data, size, u32, u32),
        ("cpq_hash", status, u32, data, size, memory, size),
        ("cpq_hash_init", status, u32, memory, size),
        ("cpq_hash_update", status, memory, size, data, size),
        ("cpq_hash_final", status, memory, size, memory, size),
        ("cpq_xof", status, u32, data, size, memory, size),
        ("cpq_xof_init", status, u32, memory, size),
        ("cpq_xof_update", status, memory, size, data, size),
        ("cpq_xof_read", status, memory, size, memory, size),
        ("cpq_hmac", status, u32, data, size, data, size, memory, size),
        ("cpq_hmac_verify", status, u32, data, size, data, size, data, size),
        ("cpq_hmac_init", status, u32, data, size, memory, size),
        ("cpq_hmac_update", status, memory, size, data, size),
        ("cpq_hmac_final", status, memory, size, memory, size),
        ("cpq_hmac_final_verify", status, memory, size, data, size),
        ("cpq_stateful_info", status, u32, data, size, memory),
        ("cpq_stateful_signer_create", status, u32, data, size, data, size, u64, memory, size, memory, size),
        ("cpq_stateful_signer_load", status, u32, data, size, data, size, u32, memory, size, memory),
        ("cpq_stateful_signer_sign", status, memory, size, u64, data, size, memory, size),
        ("cpq_stateful_signer_public_key", status, memory, size, memory, size),
        ("cpq_stateful_signer_info", status, memory, size, memory),
        ("cpq_stateful_signer_tree_cache_size", status, memory, size, memory),
        ("cpq_stateful_signer_export_tree_cache", status, memory, size, memory, size),
        ("cpq_stateful_signer_free", status, memory, size),
        ("cpq_stateful_verify", status, u32, data, size, data, size, data, size),
        ("cpq_stateful_check_public_key", status, u32, data, size),
        ("cpq_stateful_state_reseal", status, u32, memory, size, u64),
    ):
        function = getattr(library, name)

        function.restype = restype

        function.argtypes = argtypes


def query_sizes():
    for kind, count, first in ((KEM_PUBLIC, 4, 0), (KEM_PRIVATE, 4, 0), (SIGNATURE_PUBLIC, 15, 0), (SIGNATURE_PRIVATE, 15, 0), (HASHER, 10, 0), (XOF, 2, 0), (HMAC, 4, 0), (SIGNER, 3, 1)):
        for algorithm in range(first, first + count):
            size, alignment = _lib.cpq_slot_size(kind, algorithm), _lib.cpq_slot_align(kind, algorithm)

            if size == 0 or alignment == 0 or alignment & (alignment - 1):
                raise Unusable("the native library lacks an algorithm")

            SIZES[kind, algorithm] = size, alignment, _c.c_char * (size + alignment - 1)


class Slot:
    """Memory for one object of the library: a key, a hash state or a stateful signer. The slot is
    wiped, and a signer freed, when the object goes; nothing else holds its memory."""

    __slots__ = ("_memory", "address", "size")

    wipe: Any = None

    # Memory whose wipe the library refused, as it does for a slot that a call still holds, stays
    # allocated rather than be freed under that call. A slot goes only when no call can hold it,
    # so this stays empty.
    kept: list = []

    def __init__(self, kind, algorithm):
        size, alignment, memory_type = SIZES[kind, algorithm]

        memory = memory_type()

        self._memory = memory

        self.address = (_c.addressof(memory) + alignment - 1) & -alignment

        self.size = size

    def __del__(self):
        if self.wipe(self.address, self.size):
            self.kept.append(self._memory)

    # A copy would keep the address of this memory and wipe it when it goes, perhaps after this
    # slot has been freed.
    def __reduce_ex__(self, protocol):
        raise TypeError("crypto-pq's native keys and states cannot be copied or pickled")


class PrivateState:
    """A private key of the library and the public slot made from it on first use, which the key's
    public keys share."""

    __slots__ = ("private", "public")

    def __init__(self, private):
        self.private = private

        self.public = None


def output(size):
    return (_c.c_char * size)()


# The slot's type, algorithm and flags: bit 0 the key kept its seed, bit 8 its public cache is
# filled, bit 9 its secret cache.
def slot_info(slot):
    out = (_c.c_uint32 * 3)()

    check(_lib.cpq_slot_info(slot.address, slot.size, out))

    return tuple(out)


def secret(buffer):
    value = buffer.raw

    buffer.raw = bytes(len(buffer))

    return value


def kem_generate(algorithm, seed):
    slot = Slot(KEM_PRIVATE, algorithm)

    check(_lib.cpq_kem_keygen(algorithm, seed, len(seed), FILL_CACHE, slot.address, slot.size))

    return slot


def kem_import_public(algorithm, key):
    slot = Slot(KEM_PUBLIC, algorithm)

    status = _lib.cpq_kem_import_public(algorithm, key, len(key), slot.address, slot.size)

    if status == INVALID_PUBLIC_KEY:
        return None

    check(status)

    return slot


def kem_import_private(algorithm, key):
    slot = Slot(KEM_PRIVATE, algorithm)

    status = _lib.cpq_kem_import_private(algorithm, key, len(key), slot.address, slot.size)

    if status == INVALID_PRIVATE_KEY:
        return None

    check(status)

    return slot


def kem_public(algorithm, private):
    slot = Slot(KEM_PUBLIC, algorithm)

    check(_lib.cpq_kem_public_from_private(private.address, private.size, slot.address, slot.size))

    return slot


def kem_export_public(slot, size):
    out = output(size)

    check(_lib.cpq_kem_export_public(slot.address, slot.size, out, size))

    return out.raw


def kem_export_private(slot, which, size):
    out = output(size)

    status = _lib.cpq_kem_export_private(slot.address, slot.size, which, out, size)

    if status == UNSUPPORTED:
        return None

    check(status)

    return secret(out)


def kem_encapsulate(slot, randomness, size):
    ciphertext, shared_secret = output(size), output(32)

    try:
        check(_lib.cpq_kem_encapsulate(slot.address, slot.size, randomness, len(randomness), ciphertext, size, shared_secret, 32))

        return shared_secret.raw, ciphertext.raw
    finally:
        shared_secret.raw = bytes(32)


def kem_decapsulate(slot, ciphertext):
    shared_secret = output(32)

    try:
        check(_lib.cpq_kem_decapsulate(slot.address, slot.size, ciphertext, len(ciphertext), shared_secret, 32))

        return shared_secret.raw
    finally:
        shared_secret.raw = bytes(32)


def kem_self_test(slot, randomness):
    status = _lib.cpq_kem_self_test(slot.address, slot.size, randomness, len(randomness))

    if status == SELF_TEST_FAILED:
        return False

    check(status)

    return True


def signature_generate(algorithm, seed, flags):
    slot = Slot(SIGNATURE_PRIVATE, algorithm)

    check(_lib.cpq_sig_keygen(algorithm, seed, len(seed), flags, slot.address, slot.size))

    return slot


def signature_import_public(algorithm, key):
    slot = Slot(SIGNATURE_PUBLIC, algorithm)

    check(_lib.cpq_sig_import_public(algorithm, key, len(key), slot.address, slot.size))

    return slot


def signature_import_private(algorithm, key):
    slot = Slot(SIGNATURE_PRIVATE, algorithm)

    status = _lib.cpq_sig_import_private(algorithm, key, len(key), slot.address, slot.size)

    if status == INVALID_PRIVATE_KEY:
        return None

    check(status)

    return slot


def signature_public(algorithm, private):
    slot = Slot(SIGNATURE_PUBLIC, algorithm)

    check(_lib.cpq_sig_public_from_private(private.address, private.size, slot.address, slot.size))

    return slot


def signature_export_public(slot, size):
    out = output(size)

    check(_lib.cpq_sig_export_public(slot.address, slot.size, out, size))

    return out.raw


def signature_export_private(slot, which, size):
    out = output(size)

    status = _lib.cpq_sig_export_private(slot.address, slot.size, which, out, size)

    if status == UNSUPPORTED:
        return None

    check(status)

    return secret(out)


def sign(slot, message, context, pre_hash, randomness, flags, size):
    out = output(size)

    check(_lib.cpq_sig_sign(slot.address, slot.size, message, len(message), context, len(context), pre_hash, randomness, len(randomness), flags, out, size))

    return out.raw


def verify(slot, signature, message, context, pre_hash, flags):
    status = _lib.cpq_sig_verify(slot.address, slot.size, signature, len(signature), message, len(message), context, len(context), pre_hash, flags)

    if status == REJECTED:
        return False

    check(status)

    return True


def hash_digest(algorithm, size, data):
    data = immutable(data)

    out = output(size)

    check(_lib.cpq_hash(algorithm, data, len(data), out, size))

    return out.raw


def xof_digest(algorithm, data, length):
    data = immutable(data)

    out = output(length)

    check(_lib.cpq_xof(algorithm, data, len(data), out, length))

    return out.raw


def hmac_digest(algorithm, size, key, data):
    key, data = immutable(key), immutable(data)

    out = output(size)

    check(_lib.cpq_hmac(algorithm, key, len(key), data, len(data), out, size))

    return out.raw


def hmac_verify(algorithm, key, data, tag):
    key, data, tag = immutable(key), immutable(data), immutable(tag)

    status = _lib.cpq_hmac_verify(algorithm, key, len(key), data, len(data), tag, len(tag))

    if status == REJECTED:
        return False

    check(status)

    return True


# The incremental states. Their callers, the public Hasher, Xof and Hmac objects, take one call at
# a time, which the library requires of a state.
class HashState:
    __slots__ = ("_slot", "_size")

    def __init__(self, algorithm, size):
        slot = Slot(HASHER, algorithm)

        check(_lib.cpq_hash_init(algorithm, slot.address, slot.size))

        self._slot = slot

        self._size = size

    def update(self, data):
        data, slot = immutable(data), self._slot

        check(_lib.cpq_hash_update(slot.address, slot.size, data, len(data)))

    def digest(self):
        slot, out = self._slot, output(self._size)

        check(_lib.cpq_hash_final(slot.address, slot.size, out, self._size))

        return out.raw


class XofState:
    __slots__ = ("_slot",)

    def __init__(self, algorithm):
        slot = Slot(XOF, algorithm)

        check(_lib.cpq_xof_init(algorithm, slot.address, slot.size))

        self._slot = slot

    def update(self, data):
        data, slot = immutable(data), self._slot

        check(_lib.cpq_xof_update(slot.address, slot.size, data, len(data)), "cannot update after read")

    def read(self, length):
        slot, out = self._slot, output(length)

        check(_lib.cpq_xof_read(slot.address, slot.size, out, length))

        return out.raw


class HmacState:
    __slots__ = ("_slot", "_size")

    def __init__(self, algorithm, size, key):
        key = immutable(key)

        slot = Slot(HMAC, algorithm)

        check(_lib.cpq_hmac_init(algorithm, key, len(key), slot.address, slot.size))

        self._slot = slot

        self._size = size

    def update(self, data):
        data, slot = immutable(data), self._slot

        check(_lib.cpq_hmac_update(slot.address, slot.size, data, len(data)))

    def digest(self):
        slot, out = self._slot, output(self._size)

        check(_lib.cpq_hmac_final(slot.address, slot.size, out, self._size))

        return out.raw

    def verify(self, tag):
        tag, slot = immutable(tag), self._slot

        status = _lib.cpq_hmac_final_verify(slot.address, slot.size, tag, len(tag))

        if status == REJECTED:
            return False

        check(status)

        return True


# Seed size, state size, public key size, signature size, capacity and the bytes that a signer of
# these parameters allocates.
def stateful_info(kind, section):
    out = (_c.c_uint64 * 6)()

    check(_lib.cpq_stateful_info(kind, section, len(section), out), "invalid parameters")

    return tuple(out)


def stateful_verify(kind, key, message, signature):
    status = _lib.cpq_stateful_verify(kind, key, len(key), message, len(message), signature, len(signature))

    if status == REJECTED:
        return False

    check(status)

    return True


def stateful_check_public_key(kind, key):
    status = _lib.cpq_stateful_check_public_key(kind, key, len(key))

    if status == INVALID_PUBLIC_KEY:
        return False

    check(status)

    return True


class Signer:
    """The library's signer of a stateful key: it holds the Merkle trees and signs at an index
    that the key's state machine has already claimed in its store. It is internal: signing twice
    at one index would reuse a one-time key, which the signer refuses only for indices below the
    next one it may use."""

    __slots__ = ("_slot", "_kind", "public_key", "capacity", "_signature_size")

    def __init__(self, slot, kind, public_key_size):
        info = (_c.c_uint64 * 4)()

        check(_lib.cpq_stateful_signer_info(slot.address, slot.size, info))

        key = output(public_key_size)

        check(_lib.cpq_stateful_signer_public_key(slot.address, slot.size, key, public_key_size))

        self._slot = slot

        self._kind = kind

        self.public_key = key.raw

        self.capacity = info[0]

        self._signature_size = info[2]

    def sign(self, index, message):
        slot, out = self._slot, output(self._signature_size)

        check(_lib.cpq_stateful_signer_sign(slot.address, slot.size, index, message, len(message), out, self._signature_size), "the signer refused the index")

        return out.raw

    # The sealed state blob that claims the indices below `index`, made from a valid blob of the
    # key.
    def next_state(self, state, index):
        blob = output(len(state))

        blob.raw = state

        try:
            check(_lib.cpq_stateful_state_reseal(self._kind, blob, len(state), index), "the key state cannot be advanced")

            return blob.raw
        finally:
            blob.raw = bytes(len(state))

    # The size changes when a signature starts a new lower tree, so the caller holds the key's lock
    # across both calls.
    def tree_cache(self):
        slot, size = self._slot, _c.c_uint64()

        check(_lib.cpq_stateful_signer_tree_cache_size(slot.address, slot.size, _c.byref(size)))

        out = output(size.value)

        check(_lib.cpq_stateful_signer_export_tree_cache(slot.address, slot.size, out, size.value))

        return out.raw

    # The library tags the cache as it exports it.
    def seal_tree_cache(self, cache):
        return cache

    # Frees the trees of a signer that no call can reach yet, as soon as its store refuses the new
    # key; a signer that the library finds in use is left to its slot's wipe.
    def free(self):
        slot = self._slot

        _lib.cpq_stateful_signer_free(slot.address, slot.size)


# The parameter section of a valid state blob: after the version and kind bytes, an HSS level
# count and two type codes per level, or an XMSS OID.
def state_section(kind, state):
    return state[2 : 3 + 8 * state[2]] if kind == 1 else state[2:6]


def signer_create(kind, section, seed, index):
    info = stateful_info(kind, section)

    slot, state = Slot(SIGNER, kind), output(info[1])

    try:
        check(_lib.cpq_stateful_signer_create(kind, section, len(section), seed, len(seed), index, state, info[1], slot.address, slot.size), "the key cannot be created")

        return Signer(slot, kind, info[2]), state.raw
    finally:
        state.raw = bytes(info[1])


def signer_load(kind, state, cache):
    slot, index = Slot(SIGNER, kind), _c.c_uint64()

    flags = 0 if cache is None else WITH_TREE_CACHE

    message = "the stored key state or its tree cache is invalid"

    check(_lib.cpq_stateful_signer_load(kind, state, len(state), cache or b"", len(cache or b""), flags, slot.address, slot.size, _c.byref(index)), message)

    return Signer(slot, kind, stateful_info(kind, state_section(kind, state))[2]), index.value


def self_test():
    xwing = kem_generate(3, bytes(range(32)))

    public = kem_export_public(xwing, 1216)

    shared_secret, ciphertext = kem_encapsulate(kem_import_public(3, public), bytes(range(32, 96)), 1120)

    if kem_decapsulate(xwing, ciphertext) != shared_secret:
        raise Unusable("the known-answer test failed: X-Wing decapsulation")

    mldsa = signature_generate(0, bytes(range(32)), FILL_CACHE)

    key = signature_export_public(mldsa, 1312)

    signature = sign(mldsa, SELF_TEST_MESSAGE, b"", 0, b"", DETERMINISTIC, 2420)

    if not verify(signature_import_public(0, key), signature, SELF_TEST_MESSAGE, b"", 0, 0):
        raise Unusable("the known-answer test failed: ML-DSA-44 verification")

    tag = hmac_digest(3, 64, shared_secret, signature)

    if hash_digest(1, 32, public + ciphertext + shared_secret + key + signature + tag).hex() != SELF_TEST_DIGEST:
        raise Unusable("the known-answer test failed: the outputs differ from the pure backend's")


def select():
    global _lib, _c

    choice = os.environ.get("CRYPTO_PQ_BACKEND", "auto")

    if choice not in ("auto", "native", "pure"):
        raise ImportError(f"CRYPTO_PQ_BACKEND must be auto, native or pure, not {choice!r}")

    if choice == "pure":
        return "pure", None

    try:
        _lib, _c = open_library()

        Slot.wipe = _lib.cpq_slot_wipe

        query_sizes()

        self_test()
    except Exception as error:
        _lib = _c = None

        reason = str(error) if isinstance(error, Unusable) else f"{type(error).__name__}: {error}"

        if choice == "native":
            raise ImportError(f"CRYPTO_PQ_BACKEND is native, but the native library cannot be used: {reason}") from error

        return "pure", reason

    return "native", None


BACKEND, LOAD_ERROR = select()

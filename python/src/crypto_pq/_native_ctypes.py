"""The native backend through ctypes: the plain shared library of the C ABI, loaded by its path,
for every interpreter that cannot load the extension module (PyPy, free-threaded CPython).

Every input crosses as bytes, which no other thread can change during a call (ctypes releases the
GIL around every call); every output comes from a ctypes buffer of the exact size, and the buffers
that held secrets are zeroed once copied out. Slots are ctypes buffers, aligned as the library asks
and wiped when their objects go.
"""

import sys
from functools import partial
from typing import Any

from ._bytes import immutable, require_output_length
from ._native import ABI_VERSION, CONFIGURED_HASH, CONFIGURED_MAC, CONFIGURED_XOF, FILL_CACHE, HASHER, INVALID_PRIVATE_KEY, INVALID_PUBLIC_KEY, KEM_PRIVATE, KEM_PUBLIC, MAC, REJECTED, SELF_TEST_FAILED, SIGNATURE_PRIVATE, SIGNATURE_PUBLIC, SIGNER, UNSUPPORTED, WITH_TREE_CACHE, XOF, Unusable, check, state_section

NAME = "ctypes"

_lib: Any = None

_c: Any = None

# The size, the alignment and the memory type of each slot, by slot type and algorithm.
SIZES: dict[tuple[int, int], tuple[int, int, Any]] = {}


# Loads the library at `path`, which the caller has checked against its build record, checks its ABI
# version and declares its functions: the binding is then this module.
def load(path):
    global _lib, _c

    import ctypes

    library = ctypes.CDLL(path)

    version = library.cpq_abi_version

    version.argtypes = ()

    version.restype = ctypes.c_uint32

    found = version()

    if found != ABI_VERSION:
        raise Unusable(f"the native library has ABI version {found}, and this package needs {ABI_VERSION}")

    declare(library, ctypes)

    _lib, _c = library, ctypes

    Slot.wipe = library.cpq_slot_wipe

    query_sizes()

    return sys.modules[__name__]


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
        ("cpq_hash_configure", status, u32, data, size, data, size, memory, size),
        ("cpq_hash_with", status, memory, size, data, size, memory, size),
        ("cpq_hash_init_with", status, memory, size, memory, size),
        ("cpq_xof_configure", status, u32, data, size, data, size, memory, size),
        ("cpq_xof_with", status, memory, size, data, size, memory, size),
        ("cpq_xof_init_with", status, memory, size, memory, size),
        ("cpq_mac", status, u32, data, size, data, size, memory, size),
        ("cpq_mac_verify", status, u32, data, size, data, size, data, size),
        ("cpq_mac_init", status, u32, data, size, memory, size),
        ("cpq_mac_update", status, memory, size, data, size),
        ("cpq_mac_final", status, memory, size, memory, size),
        ("cpq_mac_final_verify", status, memory, size, data, size),
        ("cpq_mac_configure", status, u32, size, u32, data, size, data, size, memory, size),
        ("cpq_mac_with", status, memory, size, data, size, data, size, memory, size),
        ("cpq_mac_verify_with", status, memory, size, data, size, data, size, data, size),
        ("cpq_mac_init_with", status, memory, size, data, size, memory, size),
        ("cpq_kdf_derive", status, u32, data, size, data, size, data, size, memory, size),
        ("cpq_kdf_extract", status, u32, data, size, data, size, memory, size),
        ("cpq_kdf_expand", status, u32, data, size, data, size, memory, size),
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
        function = getattr(library, name, None)

        if function is None:
            raise Unusable(f"the native library lacks {name}")

        function.restype = restype

        function.argtypes = argtypes


def query_sizes():
    for kind, count, first in ((KEM_PUBLIC, 4, 0), (KEM_PRIVATE, 4, 0), (SIGNATURE_PUBLIC, 15, 0), (SIGNATURE_PRIVATE, 15, 0), (HASHER, 19, 0), (XOF, 6, 0), (MAC, 8, 0), (SIGNER, 3, 1), (CONFIGURED_HASH, 19, 0), (CONFIGURED_XOF, 6, 0), (CONFIGURED_MAC, 8, 0)):
        for algorithm in range(first, first + count):
            size, alignment = _lib.cpq_slot_size(kind, algorithm), _lib.cpq_slot_align(kind, algorithm)

            if size == 0 or alignment == 0 or alignment & (alignment - 1):
                raise Unusable("the native library lacks an algorithm")

            SIZES[kind, algorithm] = size, alignment, _c.c_char * (size + alignment - 1)


class Slot:
    """Memory for one object of the library: a key, a hash state, a configured hash function or a
    stateful signer. The slot is wiped, and a signer freed, when the object goes; nothing else holds
    its memory."""

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

    @property
    def offset(self):
        return self.address - _c.addressof(self._memory)

    def __del__(self):
        if self.wipe(self.address, self.size):
            self.kept.append(self._memory)

    # A copy would keep the address of this memory and wipe it when it goes, perhaps after this
    # slot has been freed.
    def __reduce_ex__(self, protocol):
        raise TypeError("crypto-pq's native keys and states cannot be copied or pickled")


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
    data, length = immutable(data), require_output_length(length)

    out = output(length)

    check(_lib.cpq_xof(algorithm, data, len(data), out, length))

    return out.raw


def mac_digest(algorithm, size, key, data):
    key, data = immutable(key), immutable(data)

    out = output(size)

    check(_lib.cpq_mac(algorithm, key, len(key), data, len(data), out, size))

    return out.raw


def answer(status):
    if status == REJECTED:
        return False

    check(status)

    return True


def mac_verify(algorithm, key, data, tag):
    key, data, tag = immutable(key), immutable(data), immutable(tag)

    return answer(_lib.cpq_mac_verify(algorithm, key, len(key), data, len(data), tag, len(tag)))


# A configured algorithm: options checked and its state precomputed in a slot that the calls only
# read, any number of them at once.
def hash_configure(algorithm, salt, personalization):
    salt, personalization, spec = immutable(salt), immutable(personalization), Slot(CONFIGURED_HASH, algorithm)

    check(_lib.cpq_hash_configure(algorithm, salt, len(salt), personalization, len(personalization), spec.address, spec.size))

    return spec


def xof_configure(algorithm, function_name, customization):
    function_name, customization, spec = immutable(function_name), immutable(customization), Slot(CONFIGURED_XOF, algorithm)

    check(_lib.cpq_xof_configure(algorithm, function_name, len(function_name), customization, len(customization), spec.address, spec.size))

    return spec


def mac_configure(algorithm, size, flags, first, second):
    first, second, spec = immutable(first), immutable(second), Slot(CONFIGURED_MAC, algorithm)

    check(_lib.cpq_mac_configure(algorithm, size, flags, first, len(first), second, len(second), spec.address, spec.size))

    return spec


def hash_with(spec, size, data):
    data, out = immutable(data), output(size)

    check(_lib.cpq_hash_with(spec.address, spec.size, data, len(data), out, size))

    return out.raw


def xof_with(spec, data, length):
    data, length = immutable(data), require_output_length(length)

    out = output(length)

    check(_lib.cpq_xof_with(spec.address, spec.size, data, len(data), out, length))

    return out.raw


def mac_with(spec, size, key, data):
    key, data, out = immutable(key), immutable(data), output(size)

    check(_lib.cpq_mac_with(spec.address, spec.size, key, len(key), data, len(data), out, size))

    return out.raw


def mac_verify_with(spec, key, data, tag):
    key, data, tag = immutable(key), immutable(data), immutable(tag)

    return answer(_lib.cpq_mac_verify_with(spec.address, spec.size, key, len(key), data, len(data), tag, len(tag)))


# HKDF. The PRK and the OKM are secrets: their buffers are zeroed once copied out.
def kdf_derive(algorithm, ikm, salt, info, length):
    ikm, salt, info, out = immutable(ikm), immutable(salt), immutable(info), output(length)

    status = _lib.cpq_kdf_derive(algorithm, ikm, len(ikm), salt, len(salt), info, len(info), out, length)

    value = secret(out)

    check(status)

    return value


def kdf_extract(algorithm, size, ikm, salt):
    ikm, salt, out = immutable(ikm), immutable(salt), output(size)

    status = _lib.cpq_kdf_extract(algorithm, ikm, len(ikm), salt, len(salt), out, size)

    value = secret(out)

    check(status)

    return value


def kdf_expand(algorithm, prk, info, length):
    prk, info, out = immutable(prk), immutable(info), output(length)

    status = _lib.cpq_kdf_expand(algorithm, prk, len(prk), info, len(info), out, length)

    value = secret(out)

    check(status)

    return value


# The incremental states, of an algorithm's defaults or of a configured algorithm's slot `spec`.
# Their callers, the public Hasher, Xof and Mac objects, take one call at a time, which the library
# requires of a state.
class HashState:
    __slots__ = ("_slot", "_size")

    def __init__(self, algorithm, size, spec=None):
        slot = Slot(HASHER, algorithm)

        if spec is None:
            check(_lib.cpq_hash_init(algorithm, slot.address, slot.size))
        else:
            check(_lib.cpq_hash_init_with(spec.address, spec.size, slot.address, slot.size))

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

    def __init__(self, algorithm, spec=None):
        slot = Slot(XOF, algorithm)

        if spec is None:
            check(_lib.cpq_xof_init(algorithm, slot.address, slot.size))
        else:
            check(_lib.cpq_xof_init_with(spec.address, spec.size, slot.address, slot.size))

        self._slot = slot

    def update(self, data):
        data, slot = immutable(data), self._slot

        check(_lib.cpq_xof_update(slot.address, slot.size, data, len(data)), "cannot update after read")

    def read(self, length):
        slot, out = self._slot, output(length)

        check(_lib.cpq_xof_read(slot.address, slot.size, out, length))

        return out.raw


class MacState:
    __slots__ = ("_slot", "_size")

    def __init__(self, algorithm, size, key, spec=None):
        key = immutable(key)

        slot = Slot(MAC, algorithm)

        if spec is None:
            check(_lib.cpq_mac_init(algorithm, key, len(key), slot.address, slot.size))
        else:
            check(_lib.cpq_mac_init_with(spec.address, spec.size, key, len(key), slot.address, slot.size))

        self._slot = slot

        self._size = size

    def update(self, data):
        data, slot = immutable(data), self._slot

        check(_lib.cpq_mac_update(slot.address, slot.size, data, len(data)))

    def digest(self):
        slot, out = self._slot, output(self._size)

        check(_lib.cpq_mac_final(slot.address, slot.size, out, self._size))

        return out.raw

    def verify(self, tag):
        tag, slot = immutable(tag), self._slot

        return answer(_lib.cpq_mac_final_verify(slot.address, slot.size, tag, len(tag)))


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


def wipe(slot):
    return Slot.wipe(slot.address, slot.size)


# The one-shot functions of the hash API.
def hash_function(number, size):
    return partial(hash_digest, number, size)


def xof_function(number):
    return partial(xof_digest, number)


def mac_function(number, size):
    return partial(mac_digest, number, size)


def mac_verify_function(number):
    return partial(mac_verify, number)


def hash_with_function(spec, size):
    return partial(hash_with, spec, size)


def xof_with_function(spec):
    return partial(xof_with, spec)


def mac_with_function(spec, size):
    return partial(mac_with, spec, size)


def mac_verify_with_function(spec):
    return partial(mac_verify_with, spec)


def kdf_functions(number, size):
    return partial(kdf_derive, number), partial(kdf_extract, number, size), partial(kdf_expand, number)

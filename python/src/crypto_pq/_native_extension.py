"""The native backend through crypto_pq._cpq, the CPython extension module (zig/src/pyext.zig):
each operation is one call of the module, whose functions keep the C ABI's rules and raise the
package's exceptions through _native.failure. The incremental states and the stateful signers below
hold their slots."""

import sys
from functools import partial
from types import SimpleNamespace
from typing import Any

from ._native import ABI_VERSION, Unusable, failure, state_section

MODULE = f"{__package__}._cpq"

# The functions of the module that are the binding's own, under the same names.
DIRECT = (
    "Slot",
    "enable_data_independent_timing",
    "slot_info",
    "wipe",
    "kem_generate",
    "kem_import_public",
    "kem_import_private",
    "kem_public",
    "kem_export_public",
    "kem_export_private",
    "kem_encapsulate",
    "kem_decapsulate",
    "kem_self_test",
    "signature_generate",
    "signature_import_public",
    "signature_import_private",
    "signature_public",
    "signature_export_public",
    "signature_export_private",
    "sign",
    "verify",
    "stateful_verify",
    "stateful_check_public_key",
    "hash_configure",
    "xof_configure",
    "mac_configure",
)

_cpq: Any = None


# The module of the file at `path`, which the caller has checked against its build record, loaded
# by that path; an import of crypto_pq._cpq that a None in sys.modules blocks is refused, as the
# import statement refuses it.
def load(path):
    global _cpq

    if MODULE in sys.modules and sys.modules[MODULE] is None:
        raise Unusable(f"import of {MODULE} halted; None in sys.modules")

    from importlib.machinery import ExtensionFileLoader
    from importlib.util import module_from_spec, spec_from_file_location

    loader = ExtensionFileLoader(MODULE, path)

    module = module_from_spec(spec_from_file_location(MODULE, path, loader=loader))

    loader.exec_module(module)

    version = module.abi_version()

    if version != ABI_VERSION:
        raise Unusable(f"the extension module has ABI version {version}, and this package needs {ABI_VERSION}")

    module.setup(failure)

    _cpq = module

    binding = SimpleNamespace(**{name: getattr(module, name) for name in DIRECT})

    binding.NAME = "extension"

    binding.hash_function, binding.xof_function = hash_function, xof_function

    binding.mac_function, binding.mac_verify_function = mac_function, mac_verify_function

    binding.hash_with_function, binding.xof_with_function = hash_with_function, xof_with_function

    binding.mac_with_function, binding.mac_verify_with_function = mac_with_function, mac_verify_with_function

    binding.kdf_functions = kdf_functions

    binding.HashState, binding.XofState, binding.MacState = HashState, XofState, MacState

    binding.signer_create, binding.signer_load = signer_create, signer_load

    return binding


# The module passed its known-answer test: an import of crypto_pq._cpq gets this one, as the
# package's attribute too.
def register():
    sys.modules[MODULE] = _cpq

    setattr(sys.modules[__package__], "_cpq", _cpq)


# The one-shot functions, one per algorithm id of the C ABI.
def hash_function(number, size):
    return getattr(_cpq, f"hash{number}")


def xof_function(number):
    return getattr(_cpq, f"xof{number}")


def mac_function(number, size):
    return getattr(_cpq, f"mac{number}")


def mac_verify_function(number):
    return getattr(_cpq, f"mac_verify{number}")


# The one-shot functions of a configured algorithm, whose slot `spec` the calls only read.
def hash_with_function(spec, size):
    return partial(_cpq.hash_with, spec)


def xof_with_function(spec):
    return partial(_cpq.xof_with, spec)


def mac_with_function(spec, size):
    mac_with = _cpq.mac_with

    def digest(key, data):
        return mac_with(spec, key, data, size)

    return digest


def mac_verify_with_function(spec):
    return partial(_cpq.mac_verify_with, spec)


# HKDF's derive(ikm, salt, info, length), extract(ikm, salt) and expand(prk, info, length).
def kdf_functions(number, size):
    return partial(_cpq.kdf_derive, number), partial(_cpq.kdf_extract, number), partial(_cpq.kdf_expand, number)


# The incremental states, of an algorithm's defaults or of a configured algorithm's slot `spec`.
# Their callers, the public Hasher, Xof and Mac objects, take one call at a time, which the library
# requires of a state.
class HashState:
    __slots__ = ("_slot",)

    def __init__(self, number, size, spec=None):
        self._slot = _cpq.hash_init(number) if spec is None else _cpq.hash_init_with(spec)

    def update(self, data):
        _cpq.hash_update(self._slot, data)

    def digest(self):
        return _cpq.hash_final(self._slot)


class XofState:
    __slots__ = ("_slot",)

    def __init__(self, number, spec=None):
        self._slot = _cpq.xof_init(number) if spec is None else _cpq.xof_init_with(spec)

    def update(self, data):
        _cpq.xof_update(self._slot, data)

    def read(self, length):
        return _cpq.xof_read(self._slot, length)


class MacState:
    __slots__ = ("_slot", "_size")

    def __init__(self, number, size, key, spec=None):
        self._slot = _cpq.mac_init(number, key) if spec is None else _cpq.mac_init_with(spec, key)

        self._size = size

    def update(self, data):
        _cpq.mac_update(self._slot, data)

    def digest(self):
        return _cpq.mac_final(self._slot, self._size)

    def verify(self, tag):
        return _cpq.mac_final_verify(self._slot, tag)


class Signer:
    """The library's signer of a stateful key: it holds the Merkle trees and signs at an index
    that the key's state machine has already claimed in its store. It is internal: signing twice
    at one index would reuse a one-time key, which the signer refuses only for indices below the
    next one it may use."""

    __slots__ = ("_slot", "_kind", "public_key", "capacity", "_signature_size")

    def __init__(self, slot, kind, public_key_size):
        capacity, _, signature_size, _ = _cpq.signer_info(slot)

        self._slot = slot

        self._kind = kind

        self.public_key = _cpq.signer_public_key(slot, public_key_size)

        self.capacity = capacity

        self._signature_size = signature_size

    def sign(self, index, message):
        return _cpq.signer_sign(self._slot, index, message, self._signature_size)

    # The sealed state blob that claims the indices below `index`, made from a valid blob of the
    # key.
    def next_state(self, state, index):
        return _cpq.state_reseal(self._kind, state, index)

    # The size changes when a signature starts a new lower tree, so the caller holds the key's lock
    # across the call.
    def tree_cache(self):
        return _cpq.signer_tree_cache(self._slot)

    # The library tags the cache as it exports it.
    def seal_tree_cache(self, cache):
        return cache

    # Frees the trees of a signer that no call can reach yet, as soon as its store refuses the new
    # key; a signer that the library finds in use is left to its slot's wipe.
    def free(self):
        _cpq.signer_free(self._slot)


def signer_create(kind, section, seed, index):
    public_key_size = _cpq.stateful_info(kind, section)[2]

    slot, state = _cpq.signer_create(kind, section, seed, index)

    return Signer(slot, kind, public_key_size), state


def signer_load(kind, state, cache):
    slot, index = _cpq.signer_load(kind, state, cache)

    return Signer(slot, kind, _cpq.stateful_info(kind, state_section(kind, state))[2]), index

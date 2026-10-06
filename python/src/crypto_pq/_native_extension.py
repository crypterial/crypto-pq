"""The native backend through crypto_pq._cpq, the CPython extension module (zig/src/pyext.zig):
each operation is one call of the module, whose functions keep the C ABI's rules and raise the
package's exceptions through _native.failure. The incremental states and the stateful signers below
hold their slots."""

import sys
from types import SimpleNamespace
from typing import Any

from ._native import ABI_VERSION, Unusable, failure, state_section

MODULE = f"{__package__}._cpq"

# The functions of the module that are the binding's own, under the same names.
DIRECT = (
    "Slot",
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

    binding.hmac_function, binding.hmac_verify_function = hmac_function, hmac_verify_function

    binding.HashState, binding.XofState, binding.HmacState = HashState, XofState, HmacState

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


def hmac_function(number, size):
    return getattr(_cpq, f"hmac{number}")


def hmac_verify_function(number):
    return getattr(_cpq, f"hmac_verify{number}")


# The incremental states. Their callers, the public Hasher, Xof and Hmac objects, take one call at
# a time, which the library requires of a state.
class HashState:
    __slots__ = ("_slot",)

    def __init__(self, number, size):
        self._slot = _cpq.hash_init(number)

    def update(self, data):
        _cpq.hash_update(self._slot, data)

    def digest(self):
        return _cpq.hash_final(self._slot)


class XofState:
    __slots__ = ("_slot",)

    def __init__(self, number):
        self._slot = _cpq.xof_init(number)

    def update(self, data):
        _cpq.xof_update(self._slot, data)

    def read(self, length):
        return _cpq.xof_read(self._slot, length)


class HmacState:
    __slots__ = ("_slot",)

    def __init__(self, number, size, key):
        self._slot = _cpq.hmac_init(number, key)

    def update(self, data):
        _cpq.hmac_update(self._slot, data)

    def digest(self):
        return _cpq.hmac_final(self._slot)

    def verify(self, tag):
        return _cpq.hmac_final_verify(self._slot, tag)


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

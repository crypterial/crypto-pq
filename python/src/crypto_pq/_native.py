"""The native backend: crypto-pq's Zig core, which a platform wheel holds twice, as the CPython
extension module _cpq and as a plain shared library that ctypes calls.

The backend is chosen once, at import, from CRYPTO_PQ_BACKEND: "pure" loads nothing; "auto" (the
default) and "native" check each native file against the build record shipped with it, load it by
its absolute path, check its ABI version and run a known-answer test. The extension serves CPython
3.11 and later with a GIL, the interpreters of its stable ABI; ctypes serves every other
interpreter, and CPython when the extension cannot be used. When neither can, "auto" leaves the
pure backend, with the reason in LOAD_ERROR, and "native" raises ImportError. BINDING names the
binding in use ("extension" or "ctypes"), and EXTENSION_ERROR why the extension is not.

Both bindings keep the same rules. Inputs are read in place and held, so that nothing frees or
resizes them during the call; an operation on keys leaves the GIL only on bytes, which no other
thread can change, and a hash of a large input releases it as hashlib does. Every output comes from
a buffer of the exact size, and a buffer that held a secret is zeroed unless the secret is the result
itself. Keys, hash states, configured hash functions and stateful signers live in slots: memory
that Python owns, aligned as the library asks, which the library tags and checks, and which is
wiped when its object goes. The library reads no randomness: the callers pass bytes from the
package's OS source.

The binding's functions become this module's, under the names that the backends call.
"""

import binascii
import os
import sys

from ._errors import CryptoPQError, ErrorCode

ABI_VERSION = 1

# The build record that the wheel builder writes next to the native files: the platform they were
# built for, then each file's role, name, size and CRC-32.
RECORD = "native.record"

RECORD_FORMAT = "crypto-pq native files 1"

EXTENSIONS = ("_cpq.abi3.so", "_cpq.pyd")

LIBRARIES = ("libcrypto_pq.so", "libcrypto_pq.dylib", "crypto_pq.dll")

KEM_PUBLIC, KEM_PRIVATE, SIGNATURE_PUBLIC, SIGNATURE_PRIVATE, HASHER, XOF, MAC, SIGNER, CONFIGURED_HASH, CONFIGURED_XOF, CONFIGURED_MAC = range(1, 12)

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


class Unusable(Exception):
    pass


# A private key of the library and the public slot made from it on first use, which the key's
# public keys share.
class PrivateState:
    __slots__ = ("private", "public")

    def __init__(self, private):
        self.private = private

        self.public = None


# The parameter section of a valid state blob: after the version and kind bytes, an HSS level
# count and two type codes per level, or an XMSS OID.
def state_section(kind, state):
    return state[2 : 3 + 8 * state[2]] if kind == 1 else state[2:6]


def failure(status, message="the native library refused the operation"):
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


# The platform of the native files and, by role ("library", "extension"), each file's name, size
# and CRC-32.
def read_record(directory):
    try:
        with open(os.path.join(directory, RECORD), "rb") as handle:
            lines = handle.read(4096).decode("ascii").splitlines()
    except FileNotFoundError:
        raise Unusable("the package holds no native library") from None

    if not lines or lines[0] != RECORD_FORMAT:
        raise Unusable("the native library's build record has an unknown format")

    target, files = None, {}

    try:
        for line in lines[1:]:
            role, value = line.split(" ", 1)

            if role == "target" and target is None:
                target = value
            elif role in ("library", "extension") and role not in files:
                name, size, crc = value.split(" ")

                files[role] = name, int(size), int(crc, 16)
            else:
                raise ValueError(role)
    except ValueError:
        raise Unusable("the native library's build record is malformed") from None

    if target is None:
        raise Unusable("the native library's build record is malformed")

    return target, files


# The path of a native file that is the one its record describes. A truncated library can stop the
# process inside dlopen (SIGBUS), so the check comes before it is mapped. The CRC-32 catches damage,
# not tampering: whoever can rewrite the file can rewrite this module too.
def checked_path(directory, entry, names, what):
    name, size, crc = entry

    if name not in names:
        raise Unusable(f"the build record names no crypto-pq {what}")

    path = os.path.join(directory, name)

    with open(path, "rb") as handle:
        data = handle.read(size + 1)

    if len(data) != size or binascii.crc32(data) != crc:
        raise Unusable(f"the {what} is damaged: it differs from its build record")

    return path


# Why this interpreter cannot load the extension, built for the stable ABI of CPython 3.11 and
# later with a GIL, or None. A free-threaded interpreter has another object layout, and on Windows
# it could even pick up the regular interpreter's python3.dll; so has a debugging build with
# Py_TRACE_REFS, which the stable ABI leaves out. The extension is loaded by its path, so no import
# suffix keeps it from them.
def extension_refusal():
    if sys.implementation.name != "cpython":
        return f"the extension module needs CPython, and this interpreter is {sys.implementation.name}"

    if sys.version_info < (3, 11):
        return "the extension module needs Python 3.11 or later"

    import sysconfig

    if sysconfig.get_config_var("Py_GIL_DISABLED"):
        return "the extension module needs a CPython with the GIL, and this one is free-threaded"

    if sysconfig.get_config_var("Py_TRACE_REFS"):
        return "the extension module needs the stable ABI, which a CPython built with Py_TRACE_REFS lacks"

    return None


def reason_of(error):
    return str(error) if isinstance(error, Unusable) else f"{type(error).__name__}: {error}"


def self_test(binding):
    xwing = binding.kem_generate(3, bytes(range(32)))

    public = binding.kem_export_public(xwing, 1216)

    shared_secret, ciphertext = binding.kem_encapsulate(binding.kem_import_public(3, public), bytes(range(32, 96)), 1120)

    if binding.kem_decapsulate(xwing, ciphertext) != shared_secret:
        raise Unusable("the known-answer test failed: X-Wing decapsulation")

    mldsa = binding.signature_generate(0, bytes(range(32)), FILL_CACHE)

    key = binding.signature_export_public(mldsa, 1312)

    signature = binding.sign(mldsa, SELF_TEST_MESSAGE, b"", 0, b"", DETERMINISTIC, 2420)

    if not binding.verify(binding.signature_import_public(0, key), signature, SELF_TEST_MESSAGE, b"", 0, 0):
        raise Unusable("the known-answer test failed: ML-DSA-44 verification")

    tag = binding.mac_function(3, 64)(shared_secret, signature)

    if binding.hash_function(1, 32)(public + ciphertext + shared_secret + key + signature + tag).hex() != SELF_TEST_DIGEST:
        raise Unusable("the known-answer test failed: the outputs differ from the pure backend's")


def open_extension(directory, entry):
    from . import _native_extension

    binding = _native_extension.load(checked_path(directory, entry, EXTENSIONS, "extension module"))

    self_test(binding)

    _native_extension.register()

    return binding


def open_library(directory, entry):
    from . import _native_ctypes

    binding = _native_ctypes.load(checked_path(directory, entry, LIBRARIES, "native library"))

    self_test(binding)

    return binding


# (backend, LOAD_ERROR, binding, EXTENSION_ERROR).
def select():
    choice = os.environ.get("CRYPTO_PQ_BACKEND", "auto")

    if choice not in ("auto", "native", "pure"):
        raise ImportError(f"CRYPTO_PQ_BACKEND must be auto, native or pure, not {choice!r}")

    if choice == "pure":
        return "pure", None, None, None

    directory = os.path.dirname(os.path.abspath(__file__))

    try:
        target, files = read_record(directory)

        running = platform_target()

        if target != running:
            raise Unusable(f"the native library is built for {target}, and this interpreter runs on {running or 'another platform'}")
    except Exception as error:
        return refuse(choice, reason_of(error), None)

    extension_error = extension_refusal()

    if extension_error is None:
        try:
            if "extension" not in files:
                raise Unusable("the package holds no extension module")

            return "native", None, open_extension(directory, files["extension"]), None
        except Exception as error:
            extension_error = reason_of(error)

    try:
        if "library" not in files:
            raise Unusable("the package holds no native library")

        return "native", None, open_library(directory, files["library"]), extension_error
    except Exception as error:
        return refuse(choice, reason_of(error), extension_error)


def refuse(choice, reason, extension_error):
    if choice == "native":
        also = f" (and the extension module: {extension_error})" if extension_error else ""

        raise ImportError(f"CRYPTO_PQ_BACKEND is native, but the native library cannot be used: {reason}{also}")

    return "pure", reason, None, extension_error


BACKEND, LOAD_ERROR, binding, EXTENSION_ERROR = select()

BINDING = binding.NAME if binding is not None else None


if binding is not None:
    Slot = binding.Slot

    slot_info = binding.slot_info

    wipe = binding.wipe

    kem_generate = binding.kem_generate

    kem_import_public = binding.kem_import_public

    kem_import_private = binding.kem_import_private

    kem_public = binding.kem_public

    kem_export_public = binding.kem_export_public

    kem_export_private = binding.kem_export_private

    kem_encapsulate = binding.kem_encapsulate

    kem_decapsulate = binding.kem_decapsulate

    kem_self_test = binding.kem_self_test

    signature_generate = binding.signature_generate

    signature_import_public = binding.signature_import_public

    signature_import_private = binding.signature_import_private

    signature_public = binding.signature_public

    signature_export_public = binding.signature_export_public

    signature_export_private = binding.signature_export_private

    sign = binding.sign

    verify = binding.verify

    hash_function = binding.hash_function

    xof_function = binding.xof_function

    mac_function = binding.mac_function

    mac_verify_function = binding.mac_verify_function

    hash_configure = binding.hash_configure

    hash_with_function = binding.hash_with_function

    xof_configure = binding.xof_configure

    xof_with_function = binding.xof_with_function

    mac_configure = binding.mac_configure

    mac_with_function = binding.mac_with_function

    mac_verify_with_function = binding.mac_verify_with_function

    kdf_functions = binding.kdf_functions

    HashState = binding.HashState

    XofState = binding.XofState

    MacState = binding.MacState

    stateful_verify = binding.stateful_verify

    stateful_check_public_key = binding.stateful_check_public_key

    signer_create = binding.signer_create

    signer_load = binding.signer_load

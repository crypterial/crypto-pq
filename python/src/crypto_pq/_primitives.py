"""The hash functions of the pure algorithms, with hashlib's interface: a constructor takes the
first data and returns a state with update, copy and digest (digest(length) for SHAKE), which
leaves the state as it was.

While the pure backend is in use, they are the standard library's hashlib for every algorithm
that hashlib provides, and crypto-pq's own code for the rest (SHA-512/224 and SHA-512/256 without
OpenSSL, for instance). The native backend computes everything in its library, so it never
imports hashlib: the pure algorithms then run on crypto-pq's own code, as the tests' pure twins
do.
"""

import sys
from functools import partial

from . import _native
from ._keccak import Keccak
from ._sha2 import IV_224, IV_256, IV_384, IV_512, IV_512_224, IV_512_256, Sha256, Sha512


def _hashlib():
    if _native.BACKEND != "pure":
        return None

    import hashlib

    return hashlib


hashlib = _hashlib()


class _Shake:
    __slots__ = ("_engine",)

    def __init__(self, rate, data=b""):
        self._engine = Keccak(rate, 0x1F, 0)

        self._engine.update(data)

    def update(self, data):
        self._engine.update(data)

    def copy(self):
        other = _Shake.__new__(_Shake)

        other._engine = self._engine.copy()

        return other

    def digest(self, length):
        return self._engine.copy().read(length)


def _own(engine):
    def construct(data=b""):
        state = engine()

        state.update(data)

        return state

    return construct


# crypto-pq's own engines, by hashlib's names.
OWN = {
    "sha224": _own(partial(Sha256, IV_224, 28)),
    "sha256": _own(partial(Sha256, IV_256, 32)),
    "sha384": _own(partial(Sha512, IV_384, 48)),
    "sha512": _own(partial(Sha512, IV_512, 64)),
    "sha512_224": _own(partial(Sha512, IV_512_224, 28)),
    "sha512_256": _own(partial(Sha512, IV_512_256, 32)),
    "sha3_224": _own(partial(Keccak, 144, 0x06, 28)),
    "sha3_256": _own(partial(Keccak, 136, 0x06, 32)),
    "sha3_384": _own(partial(Keccak, 104, 0x06, 48)),
    "sha3_512": _own(partial(Keccak, 72, 0x06, 64)),
    "shake_128": partial(_Shake, 168),
    "shake_256": partial(_Shake, 136),
}

_FROM_HASHLIB: set = set()


# hashlib's constructor of `name`, or crypto-pq's engine where hashlib lacks the algorithm or
# refuses it.
def _pick(name):
    if hashlib is None:
        return OWN[name]

    constructor = getattr(hashlib, name, None) or partial(hashlib.new, name)

    try:
        constructor(b"")
    except ValueError:
        return OWN[name]

    _FROM_HASHLIB.add(constructor)

    return constructor


# Whether the states of `constructor` copy and update cheaply, so that hashes with a common prefix
# continue a copy of the state after it. On PyPy 3.11, hashlib's copy() takes about 8 us and
# update() 4 us, against 0.5 us for a new state of the whole input; on CPython copy() takes 0.1 us
# (measured).
def copies_cheaply(constructor):
    return constructor not in _FROM_HASHLIB or sys.implementation.name != "pypy"


sha224 = _pick("sha224")

sha256 = _pick("sha256")

sha384 = _pick("sha384")

sha512 = _pick("sha512")

sha512_224 = _pick("sha512_224")

sha512_256 = _pick("sha512_256")

sha3_224 = _pick("sha3_224")

sha3_256 = _pick("sha3_256")

sha3_384 = _pick("sha3_384")

sha3_512 = _pick("sha3_512")

shake_128 = _pick("shake_128")

shake_256 = _pick("shake_256")

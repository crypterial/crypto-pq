"""The hash functions of the pure algorithms, crypto-pq's own SHA-2 and Keccak code, with hashlib's
interface: a constructor takes the first data and returns a state with update, copy and digest
(digest(length) for SHAKE), which leaves the state as it was. The pure backend runs on this code
alone: it imports neither hashlib nor hmac.
"""

from functools import partial

from ._keccak import Keccak
from ._sha2 import IV_224, IV_256, IV_384, IV_512, IV_512_224, IV_512_256, Sha256, Sha512


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


# The constructors by hashlib's names.
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

sha224 = OWN["sha224"]

sha256 = OWN["sha256"]

sha384 = OWN["sha384"]

sha512 = OWN["sha512"]

sha512_224 = OWN["sha512_224"]

sha512_256 = OWN["sha512_256"]

sha3_224 = OWN["sha3_224"]

sha3_256 = OWN["sha3_256"]

sha3_384 = OWN["sha3_384"]

sha3_512 = OWN["sha3_512"]

shake_128 = OWN["shake_128"]

shake_256 = OWN["shake_256"]

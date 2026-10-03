from . import _mlkem
from ._primitives import sha3_256, shake256
from ._x25519 import BASE, x25519

LABEL = b"\\.//^\\"

PUBLIC_KEY_SIZE = 1216

CIPHERTEXT_SIZE = 1120

SEED_SIZE = 32


def expand(seed):
    expanded = shake256(seed, 96)

    ek, dk = _mlkem.keygen_internal(expanded[:32], expanded[32:64], _mlkem.ML_KEM_768)

    scalar = expanded[64:]

    point = x25519(scalar, BASE)

    return ek + point, (dk, scalar, point)


def combine(ss_m, ss_x, ct_x, pk_x):
    return sha3_256(ss_m + ss_x + ct_x + pk_x + LABEL)


def check_public_key(pk):
    return len(pk) == PUBLIC_KEY_SIZE and _mlkem.check_encapsulation_key(pk[:1184], _mlkem.ML_KEM_768)


def encapsulate(pk, eseed):
    pk_m, pk_x = pk[:1184], pk[1184:]

    ss_m, ct_m = _mlkem.encaps_internal(pk_m, eseed[:32], _mlkem.ML_KEM_768)

    ct_x = x25519(eseed[32:], BASE)

    ss_x = x25519(eseed[32:], pk_x)

    return combine(ss_m, ss_x, ct_x, pk_x), ct_m + ct_x


def decapsulate(private, ct):
    dk, scalar, point = private

    ct_m, ct_x = ct[:1088], ct[1088:]

    ss_m = _mlkem.decaps_internal(dk, ct_m, _mlkem.ML_KEM_768)

    ss_x = x25519(scalar, ct_x)

    return combine(ss_m, ss_x, ct_x, point)

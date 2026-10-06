from . import _mlkem, _primitives
from ._x25519 import x25519, x25519_base

LABEL = b"\\.//^\\"

PUBLIC_KEY_SIZE = 1216

CIPHERTEXT_SIZE = 1120

SEED_SIZE = 32


def expand(seed):
    expanded = _primitives.shake_256(seed).digest(96)

    ek, dk = _mlkem.keygen_internal(expanded[:32], expanded[32:64], _mlkem.ML_KEM_768)

    scalar = expanded[64:]

    point = x25519_base(scalar)

    return ek + point, (dk, scalar, point)


def combine(ss_m, ss_x, ct_x, pk_x):
    return _primitives.sha3_256(ss_m + ss_x + ct_x + pk_x + LABEL).digest()


def check_public_key(pk):
    return len(pk) == PUBLIC_KEY_SIZE and _mlkem.check_encapsulation_key(pk[:1184], _mlkem.ML_KEM_768)


def public_state(pk):
    return _mlkem.public_state(pk[:1184], _mlkem.ML_KEM_768), pk[1184:]


def private_state(private):
    dk, scalar, point = private

    return _mlkem.private_state(dk, _mlkem.ML_KEM_768), scalar, point


def public_state_of(state):
    key, _, point = state

    return key.public, point


def encapsulate(state, eseed):
    key, pk_x = state

    ss_m, ct_m = _mlkem.encaps_internal(key, eseed[:32], _mlkem.ML_KEM_768)

    ct_x = x25519_base(eseed[32:])

    ss_x = x25519(eseed[32:], pk_x)

    return combine(ss_m, ss_x, ct_x, pk_x), ct_m + ct_x


def decapsulate(state, ct):
    key, scalar, point = state

    ct_m, ct_x = ct[:1088], ct[1088:]

    ss_m = _mlkem.decaps_internal(key, ct_m, _mlkem.ML_KEM_768)

    ss_x = x25519(scalar, ct_x)

    return combine(ss_m, ss_x, ct_x, point)

from ._keccak import Keccak
from ._sha2 import IV_256, IV_512, Sha256, Sha512


def sha256(data):
    engine = Sha256(IV_256, 32)

    engine.update(data)

    return engine.digest()


def sha512(data):
    engine = Sha512(IV_512, 64)

    engine.update(data)

    return engine.digest()


def sha3_256(data):
    engine = Keccak(136, 0x06, 32)

    engine.update(data)

    return engine.digest()


def sha3_512(data):
    engine = Keccak(72, 0x06, 64)

    engine.update(data)

    return engine.digest()


def shake256(data, length):
    engine = Keccak(136, 0x1F, 0)

    engine.update(data)

    return engine.read(length)

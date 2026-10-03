import os

from ._errors import CryptoPQError, ErrorCode


def random_bytes(length):
    try:
        data = os.urandom(length)
    except (NotImplementedError, OSError) as error:
        raise CryptoPQError(ErrorCode.RNG_FAILURE, "the operating system did not provide random bytes") from error

    if len(data) != length:
        raise CryptoPQError(ErrorCode.RNG_FAILURE, "the operating system returned too few random bytes")

    return data

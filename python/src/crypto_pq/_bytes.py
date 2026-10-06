import operator

from ._errors import CryptoPQError, ErrorCode


def view(data):
    return memoryview(data).cast("B")


def require_output_length(length):
    length = operator.index(length)

    if length < 0:
        raise CryptoPQError(ErrorCode.INVALID_LENGTH, "length must not be negative")

    return length


# The bytes of `data` in an object that no other thread can change: a bytes object as it is, or
# as the view covers all of it, and a copy of anything else.
def immutable(data):
    if type(data) is bytes:
        return data

    data = view(data)

    source = data.obj

    if type(source) is bytes and data.nbytes == len(source):
        return source

    return data.tobytes()


def equal(a, b):
    if len(a) != len(b):
        return False

    difference = 0

    for x, y in zip(a, b):
        difference |= x ^ y

    return difference == 0

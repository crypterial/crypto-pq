import io
import operator

from ._errors import CryptoPQError, ErrorCode


def view(data):
    return memoryview(data).cast("B")


# The bytes of `data` to read in place: a bytes object as it is, any other buffer as a view of its
# bytes, whatever its item size, which also keeps a bytearray from being resized meanwhile.
def readable(data):
    return data if type(data) is bytes else view(data)


class Output:
    """An output of `size` bytes, zeroed, written in place through `view`. BytesIO holds them in one
    bytes object and, on CPython, hands that very object over once the view is released, so the
    output takes its size once rather than twice, as a bytearray copied into bytes would."""

    __slots__ = ("_stream", "view")

    def __init__(self, size):
        self._stream = io.BytesIO(bytes(size))

        self.view = self._stream.getbuffer()

    def finish(self):
        self.view.release()

        return self._stream.getvalue()


# Zeroes a bytearray that held secret-derived bytes, before it is dropped.
def wipe(buffer):
    buffer[:] = bytes(len(buffer))


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


def require_bytes(value, name) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return immutable(value)

    raise TypeError(f"{name} must be bytes-like")


def equal(a, b):
    if len(a) != len(b):
        return False

    difference = 0

    for x, y in zip(a, b):
        difference |= x ^ y

    return difference == 0

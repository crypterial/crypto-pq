"""BLAKE3 (the BLAKE3 specification, BLAKE3-team/BLAKE3-specs) on one thread: the hash and its
extendable output, keyed_hash and derive_key. A chaining value is a tuple of eight words, whose
little-endian bytes are the output. Python cannot promise that no copy of a key remains; the
buffers that this module holds are zeroed after use."""

import struct

from ._errors import CryptoPQError, ErrorCode
from ._sha2 import IV_256

IV = IV_256

CHUNK_START = 1

CHUNK_END = 2

PARENT = 4

ROOT = 8

KEYED_HASH = 16

DERIVE_KEY_CONTEXT = 32

DERIVE_KEY_MATERIAL = 64

BLOCK = 64

CHUNK = 1024

KEY = 32

_M32 = 0xFFFFFFFF

# Multiplying a word by 2^32 + 1 puts a copy of it above itself, so that a right rotation is one
# shift and a mask.
_COPY = (1 << 32) + 1

_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)


# The message word order of each of the seven rounds: the permutation applied once more per round.
def _schedule():
    order, rounds = tuple(range(16)), []

    for _ in range(7):
        rounds.append(order)

        order = tuple(order[i] for i in _PERMUTATION)

    return tuple(rounds)


_ROUNDS = _schedule()

_WORDS = struct.Struct("<16I")

_CV = struct.Struct("<8I")


def words(key):
    return _CV.unpack(key)


# The compression function: the sixteen output words of the chaining value cv over the message
# words m, with the 64-bit counter, the block's length and the domain flags.
def compress(cv, m, counter, length, flags):
    v0, v1, v2, v3, v4, v5, v6, v7 = cv

    v8, v9, v10, v11 = IV[0], IV[1], IV[2], IV[3]

    v12, v13, v14, v15 = counter & _M32, (counter >> 32) & _M32, length, flags

    for s in _ROUNDS:
        v0 = (v0 + v4 + m[s[0]]) & _M32

        v12 = (((v12 ^ v0) * _COPY) >> 16) & _M32

        v8 = (v8 + v12) & _M32

        v4 = (((v4 ^ v8) * _COPY) >> 12) & _M32

        v0 = (v0 + v4 + m[s[1]]) & _M32

        v12 = (((v12 ^ v0) * _COPY) >> 8) & _M32

        v8 = (v8 + v12) & _M32

        v4 = (((v4 ^ v8) * _COPY) >> 7) & _M32

        v1 = (v1 + v5 + m[s[2]]) & _M32

        v13 = (((v13 ^ v1) * _COPY) >> 16) & _M32

        v9 = (v9 + v13) & _M32

        v5 = (((v5 ^ v9) * _COPY) >> 12) & _M32

        v1 = (v1 + v5 + m[s[3]]) & _M32

        v13 = (((v13 ^ v1) * _COPY) >> 8) & _M32

        v9 = (v9 + v13) & _M32

        v5 = (((v5 ^ v9) * _COPY) >> 7) & _M32

        v2 = (v2 + v6 + m[s[4]]) & _M32

        v14 = (((v14 ^ v2) * _COPY) >> 16) & _M32

        v10 = (v10 + v14) & _M32

        v6 = (((v6 ^ v10) * _COPY) >> 12) & _M32

        v2 = (v2 + v6 + m[s[5]]) & _M32

        v14 = (((v14 ^ v2) * _COPY) >> 8) & _M32

        v10 = (v10 + v14) & _M32

        v6 = (((v6 ^ v10) * _COPY) >> 7) & _M32

        v3 = (v3 + v7 + m[s[6]]) & _M32

        v15 = (((v15 ^ v3) * _COPY) >> 16) & _M32

        v11 = (v11 + v15) & _M32

        v7 = (((v7 ^ v11) * _COPY) >> 12) & _M32

        v3 = (v3 + v7 + m[s[7]]) & _M32

        v15 = (((v15 ^ v3) * _COPY) >> 8) & _M32

        v11 = (v11 + v15) & _M32

        v7 = (((v7 ^ v11) * _COPY) >> 7) & _M32

        v0 = (v0 + v5 + m[s[8]]) & _M32

        v15 = (((v15 ^ v0) * _COPY) >> 16) & _M32

        v10 = (v10 + v15) & _M32

        v5 = (((v5 ^ v10) * _COPY) >> 12) & _M32

        v0 = (v0 + v5 + m[s[9]]) & _M32

        v15 = (((v15 ^ v0) * _COPY) >> 8) & _M32

        v10 = (v10 + v15) & _M32

        v5 = (((v5 ^ v10) * _COPY) >> 7) & _M32

        v1 = (v1 + v6 + m[s[10]]) & _M32

        v12 = (((v12 ^ v1) * _COPY) >> 16) & _M32

        v11 = (v11 + v12) & _M32

        v6 = (((v6 ^ v11) * _COPY) >> 12) & _M32

        v1 = (v1 + v6 + m[s[11]]) & _M32

        v12 = (((v12 ^ v1) * _COPY) >> 8) & _M32

        v11 = (v11 + v12) & _M32

        v6 = (((v6 ^ v11) * _COPY) >> 7) & _M32

        v2 = (v2 + v7 + m[s[12]]) & _M32

        v13 = (((v13 ^ v2) * _COPY) >> 16) & _M32

        v8 = (v8 + v13) & _M32

        v7 = (((v7 ^ v8) * _COPY) >> 12) & _M32

        v2 = (v2 + v7 + m[s[13]]) & _M32

        v13 = (((v13 ^ v2) * _COPY) >> 8) & _M32

        v8 = (v8 + v13) & _M32

        v7 = (((v7 ^ v8) * _COPY) >> 7) & _M32

        v3 = (v3 + v4 + m[s[14]]) & _M32

        v14 = (((v14 ^ v3) * _COPY) >> 16) & _M32

        v9 = (v9 + v14) & _M32

        v4 = (((v4 ^ v9) * _COPY) >> 12) & _M32

        v3 = (v3 + v4 + m[s[15]]) & _M32

        v14 = (((v14 ^ v3) * _COPY) >> 8) & _M32

        v9 = (v9 + v14) & _M32

        v4 = (((v4 ^ v9) * _COPY) >> 7) & _M32

    return (
        v0 ^ v8, v1 ^ v9, v2 ^ v10, v3 ^ v11, v4 ^ v12, v5 ^ v13, v6 ^ v14, v7 ^ v15,
        v8 ^ cv[0], v9 ^ cv[1], v10 ^ cv[2], v11 ^ cv[3], v12 ^ cv[4], v13 ^ cv[5], v14 ^ cv[6], v15 ^ cv[7],
    )  # fmt: skip


class Output:
    """A node before its chaining value is taken: the root of the tree squeezes any number of
    64-byte blocks from it, block i with counter i (the specification, 2.6)."""

    __slots__ = ("_cv", "_block", "_counter", "_length", "_flags")

    def __init__(self, cv, block, counter, length, flags):
        self._cv, self._block, self._counter, self._length, self._flags = cv, block, counter, length, flags

    def chaining_value(self):
        return compress(self._cv, self._block, self._counter, self._length, self._flags)[:8]

    # Bytes [offset, offset + length) of the root's output.
    def root(self, offset, length):
        out = bytearray()

        first = offset // BLOCK

        for i in range(first, -(-(offset + length) // BLOCK)):
            out += _WORDS.pack(*compress(self._cv, self._block, i, self._length, self._flags | ROOT))

        start = offset - BLOCK * first

        result = bytes(out[start : start + length])

        out[:] = bytes(len(out))

        return result


class Blake3:
    """A BLAKE3 hash over updates, under the key words and the mode's flags. A chunk's last block is
    compressed only once more input shows that it is not the root's; the chaining values of the
    complete subtrees wait on a stack, merged as soon as a subtree is complete. digest and read work
    from the state without changing it, so a digest can be taken again."""

    __slots__ = ("_key", "_flags", "_cv", "_chunks", "_blocks", "_buffer", "_stack", "_reader", "_position")

    def __init__(self, key, flags):
        self._key = key

        self._flags = flags

        self._cv = key

        self._chunks = 0

        self._blocks = 0

        self._buffer = bytearray()

        self._stack = []

        self._reader = None

        self._position = 0

    def copy(self):
        other = Blake3(self._key, self._flags)

        other._cv, other._chunks, other._blocks = self._cv, self._chunks, self._blocks

        other._buffer[:] = self._buffer

        other._stack = self._stack[:]

        other._reader, other._position = self._reader, self._position

        return other

    def update(self, data):
        if self._reader is not None:
            raise CryptoPQError(ErrorCode.UNSUPPORTED, "cannot update after read")

        buffer, length, offset = self._buffer, len(data), 0

        while offset < length:
            if len(buffer) == BLOCK:
                self._block(buffer, 0)

                buffer[:] = bytes(BLOCK)

                buffer.clear()

            if not buffer:
                while length - offset > BLOCK:
                    self._block(data, offset)

                    offset += BLOCK

            take = min(BLOCK - len(buffer), length - offset)

            buffer += data[offset : offset + take]

            offset += take

    # A whole block that more input follows: the chunk's last ends the chunk, whose chaining value
    # joins the stack.
    def _block(self, data, offset):
        flags = self._flags | (CHUNK_START if self._blocks == 0 else 0)

        m = _WORDS.unpack_from(data, offset)

        if self._blocks < CHUNK // BLOCK - 1:
            self._cv = compress(self._cv, m, self._chunks, BLOCK, flags)[:8]

            self._blocks += 1

            return

        cv = compress(self._cv, m, self._chunks, BLOCK, flags | CHUNK_END)[:8]

        self._chunks += 1

        total = self._chunks

        while total & 1 == 0:
            cv = self._parent(self._stack.pop(), cv).chaining_value()

            total >>= 1

        self._stack.append(cv)

        self._cv, self._blocks = self._key, 0

    def _parent(self, left, right):
        return Output(self._key, left + right, 0, BLOCK, self._flags | PARENT)

    # The root: the current chunk's last block, then the parents up the stack.
    def _root(self):
        last = bytearray(BLOCK)

        last[: len(self._buffer)] = self._buffer

        flags = self._flags | CHUNK_END | (CHUNK_START if self._blocks == 0 else 0)

        output = Output(self._cv, _WORDS.unpack(last), self._chunks, len(self._buffer), flags)

        last[:] = bytes(BLOCK)

        for cv in reversed(self._stack):
            output = self._parent(cv, output.chaining_value())

        return output

    def digest(self, length=KEY):
        return self._root().root(0, length)

    def read(self, length):
        if self._reader is None:
            self._reader = self._root()

        out = self._reader.root(self._position, length)

        self._position += length

        return out


def hasher():
    return Blake3(IV, 0)


def keyed(key):
    return Blake3(words(key), KEYED_HASH)


# derive_key's second stage, keyed by the hash of the context string.
def deriver(context):
    context_key = Blake3(IV, DERIVE_KEY_CONTEXT)

    context_key.update(context)

    return Blake3(words(context_key.digest()), DERIVE_KEY_MATERIAL)


def digest(data, length=KEY):
    h = hasher()

    h.update(data)

    return h.digest(length)


def keyed_hash(key, data, length=KEY):
    h = keyed(key)

    h.update(data)

    return h.digest(length)


def derive_key(context, material, length):
    h = deriver(context)

    h.update(material)

    out = h.digest(length)

    h._buffer[:] = bytes(len(h._buffer))

    return out

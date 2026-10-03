import enum

from ._errors import CryptoPQError, ErrorCode

SEQUENCE = 0x30

INTEGER = 0x02

BIT_STRING = 0x03

OCTET_STRING = 0x04

OBJECT_IDENTIFIER = 0x06

CONTEXT_0 = 0x80

CONTEXT_0_CONSTRUCTED = 0xA0

CONTEXT_1 = 0x81


class KeyFormat(enum.StrEnum):
    RAW = "raw"

    DER = "der"

    PEM = "pem"


def key_format(value):
    try:
        return KeyFormat(value)
    except ValueError:
        raise CryptoPQError(ErrorCode.INVALID_OPTION, "format must be raw, der or pem") from None


def invalid(message):
    return CryptoPQError(ErrorCode.INVALID_ENCODING, message)


def object_identifier(dotted):
    arcs = [int(arc) for arc in dotted.split(".")]

    content = bytearray([40 * arcs[0] + arcs[1]])

    for arc in arcs[2:]:
        chunk = [arc & 0x7F]

        arc >>= 7

        while arc:
            chunk.append(0x80 | (arc & 0x7F))

            arc >>= 7

        content += bytes(reversed(chunk))

    return bytes(content)


def element(tag, content):
    length = len(content)

    if length < 0x80:
        header = bytes([tag, length])
    else:
        size = (length.bit_length() + 7) // 8

        header = bytes([tag, 0x80 | size]) + length.to_bytes(size, "big")

    return header + content


class Reader:
    __slots__ = ("_data", "_offset")

    def __init__(self, data):
        self._data = data

        self._offset = 0

    # DER only: a single-byte tag and the shortest definite length.
    def read(self, tag):
        data = self._data

        if self._offset + 2 > len(data) or data[self._offset] != tag:
            raise invalid("unexpected DER element")

        first = data[self._offset + 1]

        offset = self._offset + 2

        if first < 0x80:
            length = first
        else:
            size = first & 0x7F

            if size == 0 or size > 4 or offset + size > len(data) or data[offset] == 0:
                raise invalid("invalid DER length")

            length = int.from_bytes(data[offset : offset + size], "big")

            offset += size

            if length < 0x80:
                raise invalid("invalid DER length")

        if offset + length > len(data):
            raise invalid("truncated DER element")

        self._offset = offset + length

        return data[offset : offset + length]

    def peek(self):
        return self._data[self._offset] if self._offset < len(self._data) else None

    def finish(self):
        if self._offset != len(self._data):
            raise invalid("trailing data after DER element")


def only(data, tag):
    reader = Reader(data)

    content = reader.read(tag)

    reader.finish()

    return content


def algorithm_identifier(oid):
    return element(SEQUENCE, element(OBJECT_IDENTIFIER, oid))


def read_algorithm(reader):
    return bytes(only(reader.read(SEQUENCE), OBJECT_IDENTIFIER))


def encode_public_key(oid, key):
    return element(SEQUENCE, algorithm_identifier(oid) + element(BIT_STRING, b"\x00" + key))


def decode_public_key(data):
    reader = Reader(only(data, SEQUENCE))

    oid = read_algorithm(reader)

    bits = reader.read(BIT_STRING)

    reader.finish()

    if len(bits) == 0 or bits[0] != 0:
        raise invalid("public key BIT STRING must have no unused bits")

    return oid, bytes(bits[1:])


def encode_private_key(oid, key):
    return element(SEQUENCE, element(INTEGER, b"\x00") + algorithm_identifier(oid) + element(OCTET_STRING, key))


# PKCS#8 OneAsymmetricKey (RFC 5958): version 0 or 1, attributes ignored, and the optional
# public key returned so that the caller can check that it matches.
def decode_private_key(data):
    reader = Reader(only(data, SEQUENCE))

    version = reader.read(INTEGER)

    if version not in (b"\x00", b"\x01"):
        raise invalid("unsupported PKCS#8 version")

    oid = read_algorithm(reader)

    key = bytes(reader.read(OCTET_STRING))

    public_key = None

    if reader.peek() == CONTEXT_0_CONSTRUCTED:
        reader.read(CONTEXT_0_CONSTRUCTED)

    if reader.peek() == CONTEXT_1:
        if version != b"\x01":
            raise invalid("a PKCS#8 public key requires version 1")

        bits = reader.read(CONTEXT_1)

        if len(bits) == 0 or bits[0] != 0:
            raise invalid("public key BIT STRING must have no unused bits")

        public_key = bytes(bits[1:])

    reader.finish()

    return oid, key, public_key


def _base64_character(value):
    character = value + 65

    character += ((25 - value) >> 8) & 6

    character -= ((51 - value) >> 8) & 75

    character -= ((61 - value) >> 8) & 15

    character += ((62 - value) >> 8) & 3

    return character


# Arithmetic instead of table lookups, so that decoding a private key does not index memory
# with secret values; -1 marks a character outside the alphabet.
def _base64_value(character):
    value = -1

    value += (((0x40 - character) & (character - 0x5B)) >> 8) & (character - 64)

    value += (((0x60 - character) & (character - 0x7B)) >> 8) & (character - 70)

    value += (((0x2F - character) & (character - 0x3A)) >> 8) & (character + 5)

    value += (((0x2A - character) & (character - 0x2C)) >> 8) & 63

    value += (((0x2E - character) & (character - 0x30)) >> 8) & 64

    return value


def base64_encode(data):
    out = bytearray()

    for offset in range(0, len(data), 3):
        chunk = data[offset : offset + 3]

        value = int.from_bytes(chunk.ljust(3, b"\x00"), "big")

        characters = [_base64_character((value >> shift) & 0x3F) for shift in (18, 12, 6, 0)]

        used = len(chunk) + 1

        out += bytes(characters[:used]) + b"=" * (4 - used)

    return bytes(out)


def base64_decode(text):
    if len(text) % 4:
        raise invalid("invalid base64 length")

    out = bytearray()

    for offset in range(0, len(text), 4):
        chunk = text[offset : offset + 4]

        padding = 0

        if offset + 4 == len(text):
            padding = 2 if chunk[2:] == b"==" else 1 if chunk[3:] == b"=" else 0

        values = [_base64_value(character) for character in chunk[: 4 - padding]]

        if min(values, default=0) < 0:
            raise invalid("invalid base64 character")

        value = 0

        for item in values:
            value = (value << 6) | item

        value <<= 6 * padding

        if value & ((1 << (8 * padding)) - 1 if padding else 0):
            raise invalid("non-canonical base64 padding")

        out += value.to_bytes(3, "big")[: 3 - padding]

    return bytes(out)


def pem_encode(label, der):
    body = base64_encode(der)

    lines = [body[offset : offset + 64] for offset in range(0, len(body), 64)]

    return b"-----BEGIN " + label + b"-----\n" + b"\n".join(lines) + b"\n-----END " + label + b"-----\n"


def pem_decode(label, data):
    if isinstance(data, str):
        try:
            data = data.encode("ascii")
        except UnicodeEncodeError:
            raise invalid("PEM must be ASCII") from None

    data = bytes(data).strip()

    begin = b"-----BEGIN " + label + b"-----"

    end = b"-----END " + label + b"-----"

    if not data.startswith(begin) or not data.endswith(end):
        raise invalid(f"expected a {label.decode()} PEM block")

    body = data[len(begin) : len(data) - len(end)]

    if any(character > 0x7F for character in body):
        raise invalid("PEM must be ASCII")

    return base64_decode(b"".join(body.split()))

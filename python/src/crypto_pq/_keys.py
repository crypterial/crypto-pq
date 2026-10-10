from ._bytes import require_bytes
from ._encoding import (
    CONTEXT_0,
    OCTET_STRING,
    SEQUENCE,
    KeyFormat,
    Reader,
    decode_private_key,
    decode_public_key,
    element,
    encode_private_key,
    encode_public_key,
    invalid,
    key_format,
    only,
    pem_decode,
    pem_encode,
)
from ._errors import CryptoPQError, ErrorCode

PUBLIC = b"PUBLIC KEY"

PRIVATE = b"PRIVATE KEY"


def require_bool(value, name):
    if not isinstance(value, bool):
        raise CryptoPQError(ErrorCode.INVALID_OPTION, f"{name} must be a bool")

    return value


def require_length(data, length, name):
    if len(data) != length:
        raise CryptoPQError(ErrorCode.INVALID_LENGTH, f"{name} must be {length} bytes")

    return data


# A raw key of the wrong size is a length error; inside DER or PEM it is an encoding error.
def require_key_length(data, length, format, name):
    if len(data) != length:
        if key_format(format) is KeyFormat.RAW:
            raise CryptoPQError(ErrorCode.INVALID_LENGTH, f"{name} must be {length} bytes")

        raise invalid(f"the encoded {name} has the wrong length")

    return data


def der_input(format, data, label):
    if format is KeyFormat.PEM:
        if isinstance(data, str):
            return pem_decode(label, data)

        return pem_decode(label, require_bytes(data, "data"))

    return require_bytes(data, "data")


def export_public(format, oid, raw):
    format = key_format(format)

    if format is KeyFormat.RAW:
        return raw

    if oid is None:
        raise CryptoPQError(ErrorCode.UNSUPPORTED, "this algorithm has no standard DER encoding")

    der = encode_public_key(oid, raw)

    return der if format is KeyFormat.DER else pem_encode(PUBLIC, der)


def import_public(format, data, oid):
    format = key_format(format)

    if format is KeyFormat.RAW:
        return require_bytes(data, "data")

    if oid is None:
        raise CryptoPQError(ErrorCode.UNSUPPORTED, "this algorithm has no standard DER encoding")

    found, key = decode_public_key(der_input(format, data, PUBLIC))

    if found != oid:
        raise CryptoPQError(ErrorCode.ALGORITHM_MISMATCH, "the key belongs to another algorithm")

    return key


def export_private(format, oid, octets, raw):
    format = key_format(format)

    if format is KeyFormat.RAW:
        return raw

    if oid is None:
        raise CryptoPQError(ErrorCode.UNSUPPORTED, "this algorithm has no standard DER encoding")

    der = encode_private_key(oid, octets)

    return der if format is KeyFormat.DER else pem_encode(PRIVATE, der)


# Returns (None, raw bytes, None) for raw input, or (privateKey octets, None, public key or None)
# for PKCS#8 input whose algorithm matches.
def import_private(format, data, oid):
    format = key_format(format)

    if format is KeyFormat.RAW:
        return None, require_bytes(data, "data"), None

    if oid is None:
        raise CryptoPQError(ErrorCode.UNSUPPORTED, "this algorithm has no standard DER encoding")

    found, octets, public_key = decode_private_key(der_input(format, data, PRIVATE))

    if found != oid:
        raise CryptoPQError(ErrorCode.ALGORITHM_MISMATCH, "the key belongs to another algorithm")

    return octets, None, public_key


# ML-KEM and ML-DSA private keys: CHOICE { seed [0] IMPLICIT OCTET STRING, expandedKey OCTET
# STRING, both SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING } }.
def encode_seed_choice(seed, expanded):
    if seed is not None:
        return element(CONTEXT_0, seed)

    return element(OCTET_STRING, expanded)


def decode_seed_choice(octets, seed_size, expanded_size):
    tag = octets[0] if octets else None

    if tag == CONTEXT_0:
        seed, expanded = bytes(only(octets, CONTEXT_0)), None
    elif tag == OCTET_STRING:
        seed, expanded = None, bytes(only(octets, OCTET_STRING))
    elif tag == SEQUENCE:
        reader = Reader(only(octets, SEQUENCE))

        seed = bytes(reader.read(OCTET_STRING))

        expanded = bytes(reader.read(OCTET_STRING))

        reader.finish()
    else:
        raise invalid("unknown private key form")

    if seed is not None and len(seed) != seed_size:
        raise invalid("the seed has the wrong length")

    if expanded is not None and len(expanded) != expanded_size:
        raise invalid("the expanded key has the wrong length")

    return seed, expanded


def mismatch(message):
    return CryptoPQError(ErrorCode.INVALID_PRIVATE_KEY, message)

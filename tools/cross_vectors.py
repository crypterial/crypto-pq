import pathlib
from concurrent.futures import ProcessPoolExecutor

from crypto_pq import (
    HSS_LMS,
    ML_DSA_44,
    ML_DSA_65,
    ML_DSA_87,
    ML_KEM_512,
    ML_KEM_768,
    ML_KEM_1024,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHA_224,
    SHA_256,
    SHA_384,
    SHA_512,
    SHA_512_224,
    SHA_512_256,
    SHAKE128,
    SHAKE256,
    SLH_DSA_SHA2_128F,
    SLH_DSA_SHA2_128S,
    SLH_DSA_SHA2_192F,
    SLH_DSA_SHA2_192S,
    SLH_DSA_SHA2_256F,
    SLH_DSA_SHA2_256S,
    SLH_DSA_SHAKE_128F,
    SLH_DSA_SHAKE_128S,
    SLH_DSA_SHAKE_192F,
    SLH_DSA_SHAKE_192S,
    SLH_DSA_SHAKE_256F,
    SLH_DSA_SHAKE_256S,
    X_WING,
    XMSS,
    XMSS_MT,
    CryptoPQError,
    KemAlgorithm,
    SignatureAlgorithm,
    hazmat,
)
from crypto_pq._encoding import pem_encode
from crypto_pq._signature import PRE_HASHES as STRENGTHS
from crypto_pq._stateful import seal

# The official vectors check the algorithms; these check what no standard fixes byte for byte:
# key encodings and the PKCS#8 forms, hazmat signing with every pre-hash, implicit rejection, the
# state blobs, and the error code of each malformed input. The Python reference computes every
# expected value, so a port that disagrees has a bug.
ROOT = pathlib.Path(__file__).resolve().parents[1]

VECTORS = ROOT / "vectors"

CROSS = VECTORS / "cross"

PRE_HASHES = {
    "SHA2-224": SHA_224,
    "SHA2-256": SHA_256,
    "SHA2-384": SHA_384,
    "SHA2-512": SHA_512,
    "SHA2-512/224": SHA_512_224,
    "SHA2-512/256": SHA_512_256,
    "SHA3-224": SHA3_224,
    "SHA3-256": SHA3_256,
    "SHA3-384": SHA3_384,
    "SHA3-512": SHA3_512,
    "SHAKE-128": SHAKE128,
    "SHAKE-256": SHAKE256,
}

SLH_DSA = (
    SLH_DSA_SHA2_128S,
    SLH_DSA_SHA2_128F,
    SLH_DSA_SHA2_192S,
    SLH_DSA_SHA2_192F,
    SLH_DSA_SHA2_256S,
    SLH_DSA_SHA2_256F,
    SLH_DSA_SHAKE_128S,
    SLH_DSA_SHAKE_128F,
    SLH_DSA_SHAKE_192S,
    SLH_DSA_SHAKE_192F,
    SLH_DSA_SHAKE_256S,
    SLH_DSA_SHAKE_256F,
)

PUBLIC = b"PUBLIC KEY"

PRIVATE = b"PRIVATE KEY"

ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

MASK = (1 << 64) - 1


class Stream:
    """splitmix64: a fixed non-cryptographic generator, so that every run writes the same bytes."""

    def __init__(self, seed):
        self.state = seed

    def next(self):
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK

        z = self.state

        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK

        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK

        return z ^ (z >> 31)

    def bytes(self, length):
        out = bytearray()

        while len(out) < length:
            out += self.next().to_bytes(8, "little")

        return bytes(out[:length])

    def below(self, bound):
        return self.next() % bound


class MemoryStore:
    def __init__(self, state=None):
        self.state = state

    def read(self):
        return self.state

    def update(self, previous, next):
        if self.state != previous:
            return False

        self.state = next

        return True


def length_octets(length):
    if length < 0x80:
        return bytes([length])

    size = (length.bit_length() + 7) // 8

    return bytes([0x80 | size]) + length.to_bytes(size, "big")


def der(tag, content):
    return bytes([tag]) + length_octets(len(content)) + content


def algorithm_identifier(oid):
    return der(0x30, der(0x06, oid))


def spki(oid, key, unused=0):
    return der(0x30, algorithm_identifier(oid) + der(0x03, bytes([unused]) + key))


def pkcs8(oid, octets, version=0, extra=b""):
    return der(0x30, der(0x02, bytes([version])) + algorithm_identifier(oid) + der(0x04, octets) + extra)


def public_bits(key, unused=0):
    return der(0x81, bytes([unused]) + key)


def flip(data, position, mask=1):
    out = bytearray(data)

    out[position] ^= mask

    return bytes(out)


def replace(data, position, value):
    return data[:position] + value + data[position + len(value) :]


def u32(value):
    return value.to_bytes(4, "big")


def text(value):
    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, (bytes, bytearray)):
        return value.hex()

    return str(value)


# Every group repeats every header key, as in fetch_vectors.py, so that no record ever sees a
# header value of an earlier group.
def render(groups):
    keys = list(dict.fromkeys(key for header, _ in groups for key in header))

    lines = []

    for header, records in groups:
        lines += [f"[{key} = {text(header.get(key, ''))}]" for key in keys]

        lines.append("")

        for record in records:
            lines += [f"{key} = {text(value)}" for key, value in record.items() if value is not None]

            lines.append("")

    return ("\n".join(lines) + "\n").encode()


def pre_hash(name):
    return None if name == "none" else PRE_HASHES[name]


def strength(name):
    return STRENGTHS[PRE_HASHES[name]].strength


def allowed(algorithm, name):
    return name == "none" or strength(name) >= algorithm._backend.strength


def kem_key_record(algorithm, seed, private_key):
    public_key = private_key.public_key

    record = {"seed": seed, "publicKey": public_key.export_key("raw")}

    oid = algorithm._backend.oid

    if oid is None:
        return record

    dk = private_key._private

    expanded = algorithm.import_private_key(dk, "raw")

    both = pkcs8(oid, der(0x30, der(0x04, seed) + der(0x04, dk)))

    assert algorithm.import_private_key(both, "der").export_key("der") == private_key.export_key("der")

    record.update(
        publicKeyDer=public_key.export_key("der"),
        publicKeyPem=public_key.export_key("pem"),
        privateKeyDer=private_key.export_key("der"),
        privateKeyPem=private_key.export_key("pem"),
        expandedKey=dk,
        expandedKeyDer=expanded.export_key("der"),
        expandedKeyPem=expanded.export_key("pem"),
        bothKeyDer=both,
    )

    return record


# Three keys per algorithm, from random bytes, zeros and ones, each ciphertext tampered at its
# first byte, its last byte or its middle (X-Wing: inside the X25519 share).
def kem():
    stream = Stream(1)

    groups = []

    for algorithm in (ML_KEM_512, ML_KEM_768, ML_KEM_1024, X_WING):
        backend = algorithm._backend

        records = []

        for case in range(3):
            if case == 0:
                seed, randomness = stream.bytes(backend.seed_size), stream.bytes(backend.randomness_size)
            else:
                seed, randomness = bytes([0xFF * (case - 1)]) * backend.seed_size, bytes([0xFF * (case - 1)]) * backend.randomness_size

            private_key = hazmat.generate_key_pair(algorithm, seed).private_key

            encapsulation = hazmat.encapsulate(private_key.public_key, randomness)

            ciphertext = encapsulation.ciphertext

            position = (0, len(ciphertext) - 1, 1095 if algorithm is X_WING else len(ciphertext) // 2)[case]

            tampered = flip(ciphertext, position, 0x40)

            rejected = private_key.decapsulate(tampered)

            assert private_key.decapsulate(ciphertext) == encapsulation.shared_secret != rejected

            record = {"tcId": case + 1, **kem_key_record(algorithm, seed, private_key)}

            record.update(randomness=randomness, ciphertext=ciphertext, sharedSecret=encapsulation.shared_secret, tamperedCiphertext=tampered, rejectedSecret=rejected)

            records.append(record)

        groups.append(({"algorithm": algorithm.name}, records))

    return groups


def signature_key_record(algorithm, seed, private_key):
    public_key = private_key.public_key

    record = {
        "publicKey": public_key.export_key("raw"),
        "publicKeyDer": public_key.export_key("der"),
        "publicKeyPem": public_key.export_key("pem"),
    }

    if algorithm._backend.expanded_size is None:
        record.update(privateKey=private_key.export_key("raw"), privateKeyDer=private_key.export_key("der"), privateKeyPem=private_key.export_key("pem"))

        return record

    sk = private_key._private

    expanded = algorithm.import_private_key(sk, "raw")

    both = pkcs8(algorithm._backend.oid, der(0x30, der(0x04, seed) + der(0x04, sk)))

    assert algorithm.import_private_key(both, "der").export_key("der") == private_key.export_key("der")

    record.update(
        privateKeyDer=private_key.export_key("der"),
        privateKeyPem=private_key.export_key("pem"),
        expandedKey=sk,
        expandedKeyDer=expanded.export_key("der"),
        expandedKeyPem=expanded.export_key("pem"),
        bothKeyDer=both,
    )

    return record


# mode "hazmat" signs with the given randomness and no pre-hash policy; "deterministic" signs
# through the public API. publicVerify is what the public verify must answer.
def signature_record(algorithm, private_key, mode, message, context, name, randomness=None):
    function = pre_hash(name)

    if mode == "hazmat":
        signature = hazmat.sign(private_key, message, randomness, context=context, pre_hash=function)
    else:
        signature = private_key.sign(message, context=context, deterministic=True, pre_hash=function)

    public_key = private_key.public_key

    assert hazmat.verify(public_key, signature, message, context=context, pre_hash=function)

    verified = public_key.verify(signature, message, context=context, pre_hash=function)

    assert verified == allowed(algorithm, name)

    return {"mode": mode, "message": message, "context": context, "preHash": name, "randomness": randomness, "signature": signature, "publicVerify": verified}


# Two keys per parameter set: the first signs through hazmat (no pre-hash with contexts of 0, 1
# and 255 bytes, then every pre-hash including the weak ones), the second deterministically
# through the public API with no pre-hash, the weakest allowed one and the strongest.
def mldsa():
    stream = Stream(2)

    groups = []

    for algorithm, weakest, strongest in ((ML_DSA_44, "SHAKE-128", "SHAKE-256"), (ML_DSA_65, "SHA3-384", "SHA3-512"), (ML_DSA_87, "SHA3-512", "SHA2-512")):
        for key in range(2):
            seed = stream.bytes(32)

            private_key = hazmat.generate_key_pair(algorithm, seed).private_key

            records = [signature_key_record(algorithm, seed, private_key)]

            if key == 0:
                for message, context in ((b"", b""), (stream.bytes(33), stream.bytes(1)), (stream.bytes(1000), stream.bytes(255))):
                    records.append(signature_record(algorithm, private_key, "hazmat", message, context, "none", stream.bytes(32)))

                for name in PRE_HASHES:
                    message, context = stream.bytes(stream.below(200)), stream.bytes(stream.below(256))

                    records.append(signature_record(algorithm, private_key, "hazmat", message, context, name, stream.bytes(32)))
            else:
                for name, context in (("none", b""), ("none", stream.bytes(17)), (weakest, stream.bytes(64)), (strongest, b"")):
                    records.append(signature_record(algorithm, private_key, "deterministic", stream.bytes(stream.below(300)), context, name))

            groups.append(({"algorithm": algorithm.name, "seed": seed}, records))

    return groups


# Pre-hashes of 256 bits of collision strength, the strongest every SLH-DSA set allows.
STRONGEST = ("SHA2-512", "SHA3-512", "SHAKE-256")


# One key per parameter set. Each set signs once through hazmat with its own pre-hash, so that
# the twelve sets use all twelve, weak ones included. The "f" sets, whose signing is fast, also
# sign deterministically through the public API: three of them with no pre-hash and three with
# the strongest.
def slhdsa_group(index):
    algorithm = SLH_DSA[index]

    n = algorithm._backend.params.n

    stream = Stream(100 + index)

    seed = stream.bytes(3 * n)

    private_key = hazmat.generate_key_pair(algorithm, seed).private_key

    records = [signature_key_record(algorithm, seed, private_key)]

    context = (b"", stream.bytes(1), stream.bytes(255), stream.bytes(index))[index % 4]

    name = list(PRE_HASHES)[5 * index % 12]

    records.append(signature_record(algorithm, private_key, "hazmat", stream.bytes(stream.below(100)), context, name, stream.bytes(n)))

    if algorithm.name.endswith("f"):
        name = "none" if index // 2 % 2 == 0 else STRONGEST[index % 3]

        records.append(signature_record(algorithm, private_key, "deterministic", stream.bytes(stream.below(100)), stream.bytes(stream.below(20)), name))

    return [({"algorithm": algorithm.name, "seed": seed}, records)]


def stateful_record(algorithm, parameters, seed, index, message):
    store = MemoryStore()

    pair = hazmat.generate_key_pair(algorithm, seed, parameters=parameters, state_store=store, index=index)

    state, remaining = store.state, pair.private_key.remaining_signatures()

    signature = pair.private_key.sign(message)

    assert pair.public_key.verify(signature, message)

    loaded = algorithm.load_private_key(MemoryStore(store.state))

    assert loaded.public_key == pair.public_key and loaded.remaining_signatures() == remaining - 1

    public_key = pair.public_key

    return {
        "seed": seed,
        "index": index,
        "publicKey": public_key.export_key("raw"),
        "publicKeyDer": public_key.export_key("der"),
        "publicKeyPem": public_key.export_key("pem"),
        "state": state,
        "remaining": remaining,
        "message": message,
        "signature": signature,
        "stateAfter": store.state,
    }


FAMILIES = (("SHA256_M32", "SHA256_N32"), ("SHA256_M24", "SHA256_N24"), ("SHAKE_M32", "SHAKE_N32"), ("SHAKE_M24", "SHAKE_N24"))


def hss_levels(family, widths):
    lms, ots = FAMILIES[family]

    return [(f"LMS_{lms}_H5", f"LMOTS_{ots}_W{w}") for w in widths]


# Every hash family with every Winternitz width at height 5, then trees of two, three and four
# levels, signing at the edges of their subtrees.
HSS_CASES = (
    *((hss_levels(f, (w,)), (0, 31, 17, 1, 9, 30, 2, 16)[(f + 2 * j) % 8]) for f in range(4) for j, w in enumerate((1, 2, 4, 8))),
    (hss_levels(0, (8, 2)), 31),
    (hss_levels(3, (4, 1)), 32),
    (hss_levels(1, (2, 4)), 1000),
    (hss_levels(2, (1, 8)), 1023),
    (hss_levels(0, (4, 4, 4)), 12345),
    (hss_levels(3, (8, 2, 1)), 32767),
    (hss_levels(1, (4, 2, 1, 8)), 0xABCDE),
)


def hss_record(case):
    levels, index = HSS_CASES[case]

    stream = Stream(300 + case)

    n = 32 if "_M32_" in levels[0][0] else 24

    record = stateful_record(HSS_LMS, levels, stream.bytes(16 + n), index, stream.bytes((0, 1, 50, 300)[case % 4]))

    return {"tcId": case + 1, "lms": ",".join(lms for lms, _ in levels), "ots": ",".join(ots for _, ots in levels), **record}


# Every XMSS^MT family with trees of height 5, the deeper sets of that height, and two XMSS sets
# of height 10, about ten seconds of key generation each in Python.
XMSS_CASES = (
    (XMSS_MT, "XMSSMT-SHA2_20/4_256", 0x5A5A5),
    (XMSS_MT, "XMSSMT-SHA2_20/4_192", 31),
    (XMSS_MT, "XMSSMT-SHAKE256_20/4_256", 32),
    (XMSS_MT, "XMSSMT-SHAKE256_20/4_192", (1 << 20) - 1),
    (XMSS_MT, "XMSSMT-SHA2_40/8_256", 0x123456789A),
    (XMSS_MT, "XMSSMT-SHAKE256_40/8_192", 1023),
    (XMSS_MT, "XMSSMT-SHA2_60/12_192", (1 << 60) - 2),
    (XMSS_MT, "XMSSMT-SHAKE256_60/12_256", 0x0FEDCBA987654321),
    (XMSS, "XMSS-SHA2_10_256", 0),
    (XMSS, "XMSS-SHA2_10_192", 1023),
)


def xmss_record(case):
    algorithm, name, index = XMSS_CASES[case]

    stream = Stream(400 + case)

    n = int(name.rsplit("_", 1)[1]) // 8

    record = stateful_record(algorithm, name, stream.bytes(3 * n), index, stream.bytes((0, 1, 33, 100)[case % 4]))

    return {"tcId": case + 1, "parameters": name, **record}


def execute(algorithm, record):
    """Runs one record of the error table as every port's test does, and returns its outcome."""

    operation = record["operation"]

    def get(name):
        return record.get(name, b"")

    context = get("context")

    function = pre_hash(record.get("preHash", "none"))

    output, remaining = None, None

    try:
        if operation == "importPublicKey":
            output = algorithm.import_public_key(get("input"), record["format"]).export_key("raw")
        elif operation == "importPrivateKey":
            output = algorithm.import_private_key(get("input"), record["format"]).public_key.export_key("raw")
        elif operation == "exportPublicKey":
            output = hazmat.generate_key_pair(algorithm, get("key")).public_key.export_key(record["format"])
        elif operation == "exportPrivateKey":
            output = hazmat.generate_key_pair(algorithm, get("key")).private_key.export_key(record["format"])
        elif operation == "generate" and isinstance(algorithm, (KemAlgorithm, SignatureAlgorithm)):
            output = hazmat.generate_key_pair(algorithm, get("input")).public_key.export_key("raw")
        elif operation == "generate":
            parameters = record["parameters"] if "parameters" in record else list(zip(record["lms"].split(","), record["ots"].split(",")))

            pair = hazmat.generate_key_pair(algorithm, get("input"), parameters=parameters, state_store=MemoryStore(), index=int(record["index"]))

            output, remaining = pair.public_key.export_key("raw"), pair.private_key.remaining_signatures()
        elif operation == "encapsulate":
            encapsulation = hazmat.encapsulate(algorithm.import_public_key(get("key"), "raw"), get("randomness"))

            output = encapsulation.shared_secret + encapsulation.ciphertext
        elif operation == "decapsulate":
            output = algorithm.import_private_key(get("key"), "raw").decapsulate(get("input"))
        elif operation == "sign" and isinstance(algorithm, SignatureAlgorithm):
            output = algorithm.import_private_key(get("key"), "raw").sign(get("message"), context=context, deterministic=True, pre_hash=function)
        elif operation == "sign":
            output = algorithm.load_private_key(MemoryStore(get("input"))).sign(get("message"))
        elif operation == "hazmatSign":
            output = hazmat.sign(algorithm.import_private_key(get("key"), "raw"), get("message"), get("randomness"), context=context, pre_hash=function)
        elif operation == "verify" and isinstance(algorithm, SignatureAlgorithm):
            return {"result": algorithm.import_public_key(get("key"), "raw").verify(get("input"), get("message"), context=context, pre_hash=function)}
        elif operation == "verify":
            return {"result": algorithm.import_public_key(get("key"), "raw").verify(get("input"), get("message"))}
        elif operation == "hazmatVerify":
            return {"result": hazmat.verify(algorithm.import_public_key(get("key"), "raw"), get("input"), get("message"), context=context, pre_hash=function)}
        elif operation == "loadPrivateKey":
            private_key = algorithm.load_private_key(MemoryStore(get("input")))

            output, remaining = private_key.public_key.export_key("raw"), private_key.remaining_signatures()
        else:
            raise ValueError(operation)
    except CryptoPQError as error:
        return {"result": str(error.code)}

    return {"result": "ok", "output": output, "remaining": remaining}


class Table:
    """The error records of one algorithm. `expect` guards the construction of a case: the
    reference decides the result, but a case built wrong would test nothing."""

    def __init__(self, algorithm):
        self.algorithm = algorithm

        self.records = []

        self.names = set()

    def add(self, name, operation, expect=None, output=True, **fields):
        assert name not in self.names, f"{self.algorithm.name}: duplicate case {name}"

        self.names.add(name)

        record = {"name": name, "operation": operation, **{key: value for key, value in fields.items() if value is not None}}

        outcome = execute(self.algorithm, record)

        result = text(outcome["result"])

        assert expect is None or result == expect, f"{self.algorithm.name}: {name}: {result}, expected {expect}"

        record["result"] = result

        if output and outcome.get("output") is not None:
            record["output"] = outcome["output"]

        if outcome.get("remaining") is not None:
            record["remaining"] = outcome["remaining"]

        self.records.append(record)

        return record

    def group(self):
        return ({"algorithm": self.algorithm.name}, self.records)


def pem_body(pem):
    return b"".join(pem.strip().split(b"\n")[1:-1])


def wrap(label, body, width=64):
    lines = [body[i : i + width] for i in range(0, len(body), width)]

    return b"-----BEGIN " + label + b"-----\n" + b"\n".join(lines) + b"\n-----END " + label + b"-----\n"


# PEM text around a valid encoding: what the reference accepts (any ASCII whitespace anywhere,
# any line length) and what it refuses. A body that ends in padding also gets the padding cases.
def pem_cases(table, prefix, operation, label, pem, other_label):
    body = pem_body(pem)

    begin, end = b"-----BEGIN " + label + b"-----", b"-----END " + label + b"-----"

    accepted = (
        ("surrounding whitespace", b" \t\r\n\x0b\x0c" + pem + b"\n \t\x0b\x0c\r"),
        ("crlf lines", pem.replace(b"\n", b"\r\n")),
        ("no line breaks", begin + body + end),
        ("76-character lines", wrap(label, body, 76)),
        ("4-character lines", wrap(label, body, 4)),
        ("whitespace inside the body", wrap(label, body[:7] + b" \t" + body[7:20] + b"\x0b" + body[20:40] + b"\x0c\r" + body[40:])),
        ("no final newline", pem.rstrip(b"\n")),
    )

    for name, data in accepted:
        table.add(f"{prefix} pem {name}", operation, "ok", format="pem", input=data)

    refused = [
        ("other label", wrap(other_label, body)),
        ("rsa label", wrap(b"RSA " + label, body)),
        ("lowercase label", wrap(label.lower(), body)),
        ("begin label changed", pem.replace(begin, b"-----BEGIN " + other_label + b"-----")),
        ("end line missing", pem[: pem.index(end)]),
        ("begin line missing", pem[len(begin) + 1 :]),
        ("text before begin", b"key:\n" + pem),
        ("text after end", pem + b"x"),
        ("character after end on its line", pem.rstrip(b"\n") + b"x\n"),
        ("four dashes", pem.replace(b"-----BEGIN", b"----BEGIN")),
        ("lowercase begin", pem.replace(b"BEGIN", b"begin")),
        ("asterisk in the body", wrap(label, replace(body, 10, b"*"))),
        ("dash in the body", wrap(label, replace(body, 10, b"-"))),
        ("underscore in the body", wrap(label, replace(body, 10, b"_"))),
        ("dot in the body", wrap(label, replace(body, 10, b"."))),
        ("nul in the body", wrap(label, replace(body, 10, b"\x00"))),
        ("utf-8 in the body", wrap(label, replace(body, 10, b"\xc3\xa9"))),
        ("high byte in the body", wrap(label, replace(body, 10, b"\x80"))),
        ("high byte before begin", b"\xa0" + pem),
        ("high byte after end", pem + b"\xa0"),
        ("no-break space before begin", b"\xc2\xa0" + pem),
        ("padding group appended", wrap(label, body + b"====")),
        ("body cut by one character", wrap(label, body[:-1])),
        ("body cut by one group", wrap(label, body[:-4])),
        ("padded group inside the body", wrap(label, body[:8] + b"QQ==" + body[8:])),
        ("padding in the second-to-last group", wrap(label, body[:-6] + b"==" + body[-4:])),
        ("base64 group appended", wrap(label, body + b"AAAA")),
        ("empty body", begin + b"\n" + end + b"\n"),
        ("begin and end overlapping", begin[:-5] + end),
        ("only whitespace", b" \n\t\r\n"),
        ("empty input", b""),
        ("encapsulated header", begin + b"\nProc-Type: 4,ENCRYPTED\n" + pem[len(begin) + 1 :]),
        ("two blocks", pem + pem),
    ]

    padding = len(body) - len(body.rstrip(b"="))

    if padding:
        last = body[-padding - 1]

        noncanonical = ALPHABET[ALPHABET.index(last) | 1 << (2 * padding - 2)]

        refused += [
            ("non-canonical padding bits", wrap(label, body[: -padding - 1] + bytes([noncanonical]) + body[-padding:])),
            ("padding removed", wrap(label, body[:-padding])),
            ("padding doubled", wrap(label, body + b"=" * padding)),
        ]

    for name, data in refused:
        table.add(f"{prefix} pem {name}", operation, "INVALID_ENCODING", format="pem", input=data)


# DER problems of a SubjectPublicKeyInfo or OneAsymmetricKey. build(algorithm, extra) rebuilds
# the valid encoding around another AlgorithmIdentifier element and extra content octets.
def der_cases(table, prefix, operation, build, oid, other_oid, wrong_structure):
    data = build(algorithm_identifier(oid), b"")

    content = data[2 if data[1] < 0x80 else 2 + (data[1] & 0x7F) :]

    length = len(content)

    size = (length.bit_length() + 7) // 8

    cases = [
        ("valid", data, "ok"),
        ("truncated by one byte", data[:-1], None),
        ("truncated to its header", data[:4], None),
        ("trailing zero byte", data + b"\x00", None),
        ("trailing element", data + b"\x05\x00", None),
        ("set tag", b"\x31" + data[1:], None),
        ("high tag number form", b"\x3f\x10" + data[1:], None),
        ("length with a leading zero", b"\x30" + bytes([0x81 + size, 0]) + length.to_bytes(size, "big") + content, None),
        ("indefinite length", b"\x30\x80" + content + b"\x00\x00", None),
        ("length of five octets", b"\x30\x85\x00" + length.to_bytes(4, "big") + content, None),
        ("length one too long", b"\x30" + length_octets(length + 1) + content, None),
        ("length one too short", b"\x30" + length_octets(length - 1) + content, None),
        ("length beyond the input", b"\x30\x84\xff\xff\xff\xff" + content, None),
        ("empty input", b"", None),
        ("empty sequence", b"\x30\x00", None),
        ("lone sequence tag", b"\x30", None),
        ("another structure", wrong_structure, None),
        ("algorithm identifier set tag", build(b"\x31" + algorithm_identifier(oid)[1:], b""), None),
        ("algorithm identifier length in long form", build(b"\x30\x81" + algorithm_identifier(oid)[1:], b""), None),
        ("oid tag", build(der(0x30, der(0x07, oid)), b""), None),
        ("algorithm null parameters", build(der(0x30, der(0x06, oid) + b"\x05\x00"), b""), None),
        ("algorithm with two oids", build(der(0x30, der(0x06, oid) * 2), b""), None),
        ("empty algorithm identifier", build(b"\x30\x00", b""), None),
        ("algorithm identifier missing", build(b"", b""), None),
        ("other algorithm", build(algorithm_identifier(other_oid), b""), "ALGORITHM_MISMATCH"),
        ("oid last arc changed", build(algorithm_identifier(oid[:-1] + bytes([oid[-1] ^ 0x40])), b""), "ALGORITHM_MISMATCH"),
        ("oid truncated", build(algorithm_identifier(oid[:-1]), b""), "ALGORITHM_MISMATCH"),
        ("empty oid", build(algorithm_identifier(b""), b""), "ALGORITHM_MISMATCH"),
        ("oid with a padded arc", build(algorithm_identifier(oid[:1] + b"\x80" + oid[1:]), b""), "ALGORITHM_MISMATCH"),
        ("other algorithm and trailing data inside", build(algorithm_identifier(other_oid), b"\x05\x00"), "INVALID_ENCODING"),
    ]

    if length < 0x80:
        cases.append(("short length in long form", b"\x30\x81" + bytes([length]) + content, None))

    for name, value, expect in cases:
        table.add(f"{prefix} der {name}", operation, expect, format="der", input=value)


def spki_cases(table, oid, other_oid, key, wrong_structure, length_code="INVALID_ENCODING"):
    def build(algorithm, extra):
        return der(0x30, algorithm + der(0x03, b"\x00" + key) + extra)

    der_cases(table, "public key", "importPublicKey", build, oid, other_oid, wrong_structure)

    algorithm = algorithm_identifier(oid)

    cases = (
        ("bit string tag", der(0x30, algorithm + der(0x04, b"\x00" + key)), None),
        ("unused bits", spki(oid, key, 1), None),
        ("eight unused bits", spki(oid, key, 8), None),
        ("empty bit string", der(0x30, algorithm + b"\x03\x00"), None),
        ("bit string missing", der(0x30, algorithm), None),
        ("two bit strings", der(0x30, algorithm + der(0x03, b"\x00" + key) + der(0x03, b"\x00")), None),
        ("key one byte short", spki(oid, key[:-1]), length_code),
        ("key one byte long", spki(oid, key + b"\x00"), length_code),
        ("other algorithm and short key", spki(other_oid, key[:-1]), "ALGORITHM_MISMATCH"),
        ("other algorithm and unused bits", spki(other_oid, key, 1), "INVALID_ENCODING"),
    )

    for name, value, expect in cases:
        table.add(f"public key der {name}", "importPublicKey", expect, format="der", input=value)


# A OneAsymmetricKey holding `octets`, with every problem of the version, the attributes and the
# embedded public key.
def pkcs8_cases(table, oid, other_oid, octets, public_key, wrong_structure):
    def build(algorithm, extra):
        return der(0x30, b"\x02\x01\x00" + algorithm + der(0x04, octets) + extra)

    der_cases(table, "private key", "importPrivateKey", build, oid, other_oid, wrong_structure)

    algorithm = algorithm_identifier(oid)

    private = der(0x04, octets)

    wrong = flip(public_key, len(public_key) // 2)

    cases = (
        ("version 1 without public key", pkcs8(oid, octets, 1), "ok"),
        ("version 2", pkcs8(oid, octets, 2), None),
        ("version of two octets", der(0x30, b"\x02\x02\x00\x00" + algorithm + private), None),
        ("empty version", der(0x30, b"\x02\x00" + algorithm + private), None),
        ("version minus one", der(0x30, b"\x02\x01\xff" + algorithm + private), None),
        ("version tag", der(0x30, b"\x03\x01\x00" + algorithm + private), None),
        ("version missing", der(0x30, algorithm + private), None),
        ("private key tag", der(0x30, b"\x02\x01\x00" + algorithm + der(0x03, octets)), None),
        ("private key missing", der(0x30, b"\x02\x01\x00" + algorithm), None),
        ("empty attributes", pkcs8(oid, octets, 0, b"\xa0\x00"), "ok"),
        ("attributes", pkcs8(oid, octets, 0, b"\xa0\x05\x30\x03\x02\x01\x00"), "ok"),
        ("primitive attributes tag", pkcs8(oid, octets, 0, b"\x80\x00"), None),
        ("public key", pkcs8(oid, octets, 1, public_bits(public_key)), "ok"),
        ("attributes and public key", pkcs8(oid, octets, 1, b"\xa0\x00" + public_bits(public_key)), "ok"),
        ("public key before attributes", pkcs8(oid, octets, 1, public_bits(public_key) + b"\xa0\x00"), None),
        ("two public keys", pkcs8(oid, octets, 1, public_bits(public_key) * 2), None),
        ("public key with version 0", pkcs8(oid, octets, 0, public_bits(public_key)), None),
        ("public key with unused bits", pkcs8(oid, octets, 1, public_bits(public_key, 1)), None),
        ("empty public key bit string", pkcs8(oid, octets, 1, b"\x81\x00"), None),
        ("constructed public key tag", pkcs8(oid, octets, 1, der(0xA1, b"\x00" + public_key)), None),
        ("public key mismatch", pkcs8(oid, octets, 1, public_bits(wrong)), "INVALID_PRIVATE_KEY"),
        ("public key one byte short", pkcs8(oid, octets, 1, public_bits(public_key[:-1])), "INVALID_PRIVATE_KEY"),
        ("empty public key", pkcs8(oid, octets, 1, public_bits(b"")), "INVALID_PRIVATE_KEY"),
        ("public key mismatch and other algorithm", pkcs8(other_oid, octets, 1, public_bits(wrong)), "ALGORITHM_MISMATCH"),
        ("public key with version 0 and other algorithm", pkcs8(other_oid, octets, 0, public_bits(public_key)), "INVALID_ENCODING"),
    )

    for name, value, expect in cases:
        table.add(f"private key der {name}", "importPrivateKey", expect, format="der", input=value)


# PEM text whose DER passes 16384 bytes, more than a port would decode into a fixed buffer. The
# result must be the one of the same DER at any size: large attributes are ignored, and a large
# OID, key or public key fails the check it would fail anyway.
LARGE = 16500


def large_private_cases(table, oid, other_oid, octets, public_key, full=True):
    attributes = der(0xA0, bytes(LARGE))

    cases = [("attributes", pkcs8(oid, octets, 0, attributes), "ok")]

    if full:
        cases += [
            ("attributes and public key", pkcs8(oid, octets, 1, attributes + public_bits(public_key)), "ok"),
            ("attributes and public key mismatch", pkcs8(oid, octets, 1, attributes + public_bits(flip(public_key, 0))), "INVALID_PRIVATE_KEY"),
            ("attributes and other algorithm", pkcs8(other_oid, octets, 0, attributes), "ALGORITHM_MISMATCH"),
            ("attributes and public key with version 0", pkcs8(oid, octets, 0, attributes + public_bits(public_key)), "INVALID_ENCODING"),
            ("attributes and trailing data inside", pkcs8(oid, octets, 0, attributes + b"\x05\x00"), "INVALID_ENCODING"),
            ("attributes beyond the key", pkcs8(oid, octets, 0, b"\xa0\x82" + (LARGE + 1).to_bytes(2, "big") + bytes(LARGE)), "INVALID_ENCODING"),
            ("private key", pkcs8(oid, der(0x80, bytes(LARGE))), "INVALID_ENCODING"),
            ("private key and other algorithm", pkcs8(other_oid, der(0x80, bytes(LARGE))), "ALGORITHM_MISMATCH"),
            ("public key", pkcs8(oid, octets, 1, public_bits(bytes(LARGE))), "INVALID_PRIVATE_KEY"),
            ("oid", der(0x30, b"\x02\x01\x00" + algorithm_identifier(b"\x2a" * LARGE) + der(0x04, octets)), "ALGORITHM_MISMATCH"),
        ]

    for name, data, expect in cases:
        table.add(f"private key pem large {name}", "importPrivateKey", expect, format="pem", input=pem_encode(PRIVATE, data))

    if not full:
        return

    # The last characters encode attribute bytes, so only the base64 checks can refuse them.
    body = pem_body(pem_encode(PRIVATE, pkcs8(oid, octets, 0, attributes)))

    table.add("private key pem large attributes and a bad last character", "importPrivateKey", "INVALID_ENCODING", format="pem", input=wrap(PRIVATE, body[:-5] + b"*" + body[-4:]))

    # An encoding of 3k + 2 bytes ends in one padding character, after one that has two spare bits.
    sized = next(data for data in (pkcs8(oid, octets, 0, der(0xA0, bytes(LARGE + extra))) for extra in range(3)) if len(data) % 3 == 2)

    padded = pem_body(pem_encode(PRIVATE, sized))

    noncanonical = ALPHABET[ALPHABET.index(padded[-2]) | 1]

    table.add("private key pem large attributes and non-canonical padding", "importPrivateKey", "INVALID_ENCODING", format="pem", input=wrap(PRIVATE, padded[:-2] + bytes([noncanonical]) + b"="))


def large_public_cases(table, oid, other_oid, key, length_code="INVALID_ENCODING"):
    for name, data, expect in (
        ("key", spki(oid, bytes(LARGE)), length_code),
        ("key and other algorithm", spki(other_oid, bytes(LARGE)), "ALGORITHM_MISMATCH"),
        ("key with unused bits", spki(oid, bytes(LARGE), 1), "INVALID_ENCODING"),
        ("oid", der(0x30, algorithm_identifier(b"\x2a" * LARGE) + der(0x03, b"\x00" + key)), "ALGORITHM_MISMATCH"),
    ):
        table.add(f"public key pem large {name}", "importPublicKey", expect, format="pem", input=pem_encode(PUBLIC, data))


# The seed / expandedKey / both CHOICE of the ML-KEM and ML-DSA private keys.
def choice_cases(table, oid, seed, expanded, other_expanded, invalid_expanded):
    cases = (
        ("seed", der(0x80, seed), "ok"),
        ("expanded key", der(0x04, expanded), "ok"),
        ("both", der(0x30, der(0x04, seed) + der(0x04, expanded)), "ok"),
        ("seed one byte short", der(0x80, seed[:-1]), None),
        ("seed one byte long", der(0x80, seed + b"\x00"), None),
        ("empty seed", der(0x80, b""), None),
        ("constructed seed tag", der(0xA0, seed), None),
        ("seed in an octet string", der(0x04, seed), None),
        ("expanded key one byte short", der(0x04, expanded[:-1]), None),
        ("expanded key one byte long", der(0x04, expanded + b"\x00"), None),
        ("both with a short seed", der(0x30, der(0x04, seed[:-1]) + der(0x04, expanded)), None),
        ("both with a short expanded key", der(0x30, der(0x04, seed) + der(0x04, expanded[:-1])), None),
        ("both with a third element", der(0x30, der(0x04, seed) + der(0x04, expanded) + der(0x04, b"")), None),
        ("both without expanded key", der(0x30, der(0x04, seed)), None),
        ("both with a tagged seed", der(0x30, der(0x80, seed) + der(0x04, expanded)), None),
        ("both in reverse order", der(0x30, der(0x04, expanded) + der(0x04, seed)), None),
        ("both mismatch", der(0x30, der(0x04, seed) + der(0x04, other_expanded)), "INVALID_PRIVATE_KEY"),
        ("both mismatch with a short seed", der(0x30, der(0x04, seed[:-1]) + der(0x04, other_expanded)), "INVALID_ENCODING"),
        ("seed with trailing data", der(0x80, seed) + b"\x00", None),
        ("unknown tag", der(0x81, seed), None),
        ("integer tag", der(0x02, seed), None),
        ("empty octets", b"", None),
        ("invalid expanded key", der(0x04, invalid_expanded), "INVALID_PRIVATE_KEY"),
        ("both with an invalid expanded key", der(0x30, der(0x04, seed) + der(0x04, invalid_expanded)), "INVALID_PRIVATE_KEY"),
    )

    for name, octets, expect in cases:
        table.add(f"private key choice {name}", "importPrivateKey", expect, format="der", input=pkcs8(oid, octets))


# ML-KEM packs two 12-bit coefficients into three bytes, little-endian.
def coefficient(data, index):
    word = int.from_bytes(data[3 * (index // 2) : 3 * (index // 2) + 3], "little")

    return (word >> (12 * (index % 2))) & 0xFFF


def set_coefficient(data, index, value):
    offset, shift = 3 * (index // 2), 12 * (index % 2)

    word = int.from_bytes(data[offset : offset + 3], "little")

    word = (word & ~(0xFFF << shift)) | (value << shift)

    return replace(data, offset, word.to_bytes(3, "little"))


def ml_kem_errors(number, algorithm, stream):
    table = Table(algorithm)

    oid, k = algorithm._backend.oid, algorithm._backend.params.k

    seed = stream.bytes(64)

    pair = hazmat.generate_key_pair(algorithm, seed)

    public, dk = pair.public_key.export_key("raw"), pair.private_key._private

    other_dk = hazmat.generate_key_pair(algorithm, stream.bytes(64)).private_key._private

    other_oid = (ML_KEM_768, ML_KEM_1024, ML_KEM_512)[number]._backend.oid

    for name, data in (("empty", b""), ("one byte short", public[:-1]), ("one byte long", public + b"\x00"), ("of the private key size", dk)):
        table.add(f"public key raw {name}", "importPublicKey", "INVALID_LENGTH", format="raw", input=data)

    for name, data, expect in (
        ("valid", public, "ok"),
        ("coefficient q", set_coefficient(public, 0, 3329), "INVALID_PUBLIC_KEY"),
        ("coefficient 4095", set_coefficient(public, 1, 4095), "INVALID_PUBLIC_KEY"),
        ("coefficient q - 1", set_coefficient(public, 2, 3328), "ok"),
        ("last coefficient q", set_coefficient(public, 256 * k - 1, 3329), "INVALID_PUBLIC_KEY"),
        ("rho all ones", public[:-32] + b"\xff" * 32, "ok"),
    ):
        table.add(f"public key raw {name}", "importPublicKey", expect, format="raw", input=data)

    invalid = spki(oid, set_coefficient(public, 0, 3329))

    table.add("public key der coefficient q", "importPublicKey", "INVALID_PUBLIC_KEY", format="der", input=invalid)

    table.add("public key pem coefficient q", "importPublicKey", "INVALID_PUBLIC_KEY", format="pem", input=pem_encode(PUBLIC, invalid))

    for name, data in (("empty", b""), ("63 bytes", seed[:-1]), ("65 bytes", seed + b"\x00"), ("expanded key one byte short", dk[:-1]), ("expanded key one byte long", dk + b"\x00"), ("of the public key size", public)):
        table.add(f"private key raw {name}", "importPrivateKey", "INVALID_LENGTH", format="raw", input=data)

    hashed = 768 * k + 32

    for name, data, expect in (
        ("seed", seed, "ok"),
        ("expanded key", dk, "ok"),
        ("hash of the public key changed", flip(dk, hashed), "INVALID_PRIVATE_KEY"),
        ("public key coefficient q", dk[: 384 * k] + set_coefficient(dk[384 * k :], 0, 3329), "INVALID_PRIVATE_KEY"),
        ("public key changed", flip(dk, 384 * k + 5), "INVALID_PRIVATE_KEY"),
        ("implicit rejection value changed", flip(dk, len(dk) - 1), "ok"),
        ("secret coefficient 4095", set_coefficient(dk, 0, 4095), "ok"),
    ):
        table.add(f"private key raw {name}", "importPrivateKey", expect, format="raw", input=data)

    choice_cases(table, oid, seed, dk, other_dk, flip(dk, hashed))

    if number == 1:
        spki_cases(table, oid, other_oid, public, pkcs8(oid, der(0x80, seed)))

        pem_cases(table, "public key", "importPublicKey", PUBLIC, pair.public_key.export_key("pem"), PRIVATE)

        pkcs8_cases(table, oid, other_oid, der(0x80, seed), public, spki(oid, public))

        pem_cases(table, "private key", "importPrivateKey", PRIVATE, pair.private_key.export_key("pem"), PUBLIC)

        pem_cases(table, "private key with attributes", "importPrivateKey", PRIVATE, pem_encode(PRIVATE, pkcs8(oid, der(0x80, seed), 0, b"\xa0\x00")), PUBLIC)

        table.add("private key pem expanded key", "importPrivateKey", "ok", format="pem", input=algorithm.import_private_key(dk, "raw").export_key("pem"))

        large_private_cases(table, oid, other_oid, der(0x80, seed), public)

        table.add("private key pem large attributes and expanded key", "importPrivateKey", "ok", format="pem", input=pem_encode(PRIVATE, pkcs8(oid, der(0x04, dk), 0, der(0xA0, bytes(LARGE)))))

        large_public_cases(table, oid, other_oid, public)
    else:
        for name, data, expect in (
            ("other algorithm", spki(other_oid, public), "ALGORITHM_MISMATCH"),
            ("ml-dsa algorithm", spki(ML_DSA_44._backend.oid, public), "ALGORITHM_MISMATCH"),
            ("key one byte short", spki(oid, public[:-1]), "INVALID_ENCODING"),
            ("trailing zero byte", spki(oid, public) + b"\x00", "INVALID_ENCODING"),
        ):
            table.add(f"public key der {name}", "importPublicKey", expect, format="der", input=data)

        for name, data, expect in (
            ("other algorithm", pkcs8(other_oid, der(0x80, seed)), "ALGORITHM_MISMATCH"),
            ("public key", pkcs8(oid, der(0x80, seed), 1, public_bits(public)), "ok"),
            ("public key mismatch", pkcs8(oid, der(0x80, seed), 1, public_bits(flip(public, 0))), "INVALID_PRIVATE_KEY"),
            ("expanded key with public key", pkcs8(oid, der(0x04, dk), 1, public_bits(public)), "ok"),
            ("expanded key with public key mismatch", pkcs8(oid, der(0x04, dk), 1, public_bits(flip(public, 3))), "INVALID_PRIVATE_KEY"),
        ):
            table.add(f"private key der {name}", "importPrivateKey", expect, format="der", input=data)

        table.add("public key pem private label", "importPublicKey", "INVALID_ENCODING", format="pem", input=pair.private_key.export_key("pem"))

        table.add("private key pem public label", "importPrivateKey", "INVALID_ENCODING", format="pem", input=pair.public_key.export_key("pem"))

        table.add("private key pem expanded key", "importPrivateKey", "ok", format="pem", input=algorithm.import_private_key(dk, "raw").export_key("pem"))

    encapsulation = hazmat.encapsulate(pair.public_key, stream.bytes(32))

    ciphertext = encapsulation.ciphertext

    for key_name, key in (("seed", seed), ("expanded", dk)):
        for name, data in (("empty", b""), ("one byte short", ciphertext[:-1]), ("one byte long", ciphertext + b"\x00")):
            table.add(f"decapsulate {name} with the {key_name} key", "decapsulate", "INVALID_LENGTH", key=key, input=data)

        assert table.add(f"decapsulate with the {key_name} key", "decapsulate", "ok", key=key, input=ciphertext)["output"] == encapsulation.shared_secret

        table.add(f"decapsulate tampered with the {key_name} key", "decapsulate", "ok", key=key, input=flip(ciphertext, 7))

    # FIPS 203 decodes the secret vector modulo q, so a coefficient c <= 766 stored as c + q is the
    # same key: decapsulation must succeed as with the canonical key.
    index = next(i for i in range(256 * k) if coefficient(dk, i) <= 766)

    congruent = set_coefficient(dk, index, coefficient(dk, index) + 3329)

    assert table.add("decapsulate with a secret coefficient stored as c + q", "decapsulate", "ok", key=congruent, input=ciphertext)["output"] == encapsulation.shared_secret

    table.add("decapsulate with secret coefficients 4095", "decapsulate", "ok", key=set_coefficient(set_coefficient(dk, 0, 4095), 1, 4095), input=ciphertext)

    table.add("decapsulate the zero ciphertext", "decapsulate", "ok", key=seed, input=bytes(len(ciphertext)))

    table.add("decapsulate the all-ones ciphertext", "decapsulate", "ok", key=seed, input=b"\xff" * len(ciphertext))

    for name, data in (("empty", b""), ("31 bytes", bytes(31)), ("33 bytes", bytes(33)), ("64 bytes", bytes(64))):
        table.add(f"encapsulate randomness {name}", "encapsulate", "INVALID_LENGTH", key=public, randomness=data)

    table.add("encapsulate", "encapsulate", "ok", key=public, randomness=bytes(32))

    for name, data in (("empty", b""), ("32 bytes", bytes(32)), ("63 bytes", bytes(63)), ("65 bytes", bytes(65))):
        table.add(f"generate seed {name}", "generate", "INVALID_LENGTH", input=data)

    table.add("generate", "generate", "ok", input=bytes(64))

    return table.group()


def x_wing_errors(stream):
    table = Table(X_WING)

    seed = stream.bytes(32)

    pair = hazmat.generate_key_pair(X_WING, seed)

    public = pair.public_key.export_key("raw")

    for name, data in (("empty", b""), ("one byte short", public[:-1]), ("one byte long", public + b"\x00"), ("of an ml-kem-768 key", public[:1184])):
        table.add(f"public key raw {name}", "importPublicKey", "INVALID_LENGTH", format="raw", input=data)

    for name, data, expect in (
        ("valid", public, "ok"),
        ("ml-kem coefficient q", set_coefficient(public, 0, 3329), "INVALID_PUBLIC_KEY"),
        ("x25519 share all ones", public[:1184] + b"\xff" * 32, "ok"),
    ):
        table.add(f"public key raw {name}", "importPublicKey", expect, format="raw", input=data)

    ml_kem = spki(ML_KEM_768._backend.oid, public[:1184])

    for format in ("der", "pem"):
        for name, data in (("empty", b""), ("ml-kem-768 key", ml_kem if format == "der" else pem_encode(PUBLIC, ml_kem)), ("garbage", b"\x00\x01")):
            table.add(f"public key {format} {name}", "importPublicKey", "UNSUPPORTED", format=format, input=data)

            table.add(f"private key {format} {name}", "importPrivateKey", "UNSUPPORTED", format=format, input=data)

        table.add(f"export public key {format}", "exportPublicKey", "UNSUPPORTED", key=seed, format=format)

        table.add(f"export private key {format}", "exportPrivateKey", "UNSUPPORTED", key=seed, format=format)

    table.add("export public key raw", "exportPublicKey", "ok", key=seed, format="raw")

    table.add("export private key raw", "exportPrivateKey", "ok", key=seed, format="raw")

    for name, data in (("empty", b""), ("31 bytes", seed[:-1]), ("33 bytes", seed + b"\x00"), ("64 bytes", bytes(64)), ("96 bytes", bytes(96)), ("of an ml-kem-768 expanded key", bytes(2400))):
        table.add(f"private key raw {name}", "importPrivateKey", "INVALID_LENGTH", format="raw", input=data)

    table.add("private key raw seed", "importPrivateKey", "ok", format="raw", input=seed)

    ciphertext = hazmat.encapsulate(pair.public_key, stream.bytes(64)).ciphertext

    for name, data in (("empty", b""), ("one byte short", ciphertext[:-1]), ("one byte long", ciphertext + b"\x00"), ("of ml-kem-768", ciphertext[:1088])):
        table.add(f"decapsulate {name}", "decapsulate", "INVALID_LENGTH", key=seed, input=data)

    table.add("decapsulate", "decapsulate", "ok", key=seed, input=ciphertext)

    # X25519 takes any 32 bytes: the top bit is ignored and values from p up are reduced.
    p = (1 << 255) - 19

    shares = (("zero", bytes(32)), ("one", (1).to_bytes(32, "little")), ("p", p.to_bytes(32, "little")), ("p + 1", (p + 1).to_bytes(32, "little")), ("all ones", b"\xff" * 32), ("high bit set", (9 + (1 << 255)).to_bytes(32, "little")))

    for name, share in shares:
        table.add(f"decapsulate x25519 share {name}", "decapsulate", "ok", key=seed, input=ciphertext[:1088] + share)

    for name, share in shares[::2]:
        table.add(f"encapsulate to x25519 share {name}", "encapsulate", "ok", key=public[:1184] + share, randomness=bytes(range(64)))

    for name, data in (("empty", b""), ("32 bytes", bytes(32)), ("63 bytes", bytes(63)), ("65 bytes", bytes(65))):
        table.add(f"encapsulate randomness {name}", "encapsulate", "INVALID_LENGTH", key=public, randomness=data)

    for name, data in (("empty", b""), ("31 bytes", bytes(31)), ("33 bytes", bytes(33)), ("64 bytes", bytes(64))):
        table.add(f"generate seed {name}", "generate", "INVALID_LENGTH", input=data)

    table.add("generate", "generate", "ok", input=bytes(32))

    return table.group()


def kem_errors():
    stream = Stream(500)

    return [ml_kem_errors(number, algorithm, stream) for number, algorithm in enumerate((ML_KEM_512, ML_KEM_768, ML_KEM_1024))] + [x_wing_errors(stream)]


LONG_CONTEXT = bytes(range(256))


# Context, pre-hash and randomness checks that fail before any signing or verifying work, so that
# they cost little even for the slow SLH-DSA sets. A port that skipped the context check would
# encode M' = 0 || 0 || ctx || M, which is M' of ctx || M with an empty context: `collision` signs
# that, so such a port would accept it. Without `private` the signing checks are left out, and
# without `verify` the verification checks, whose signatures are large for SLH-DSA.
def policy_errors(table, private_key, private, public, message, weak, lengths, verify=True):
    n = table.algorithm._backend.randomness_size

    if private is not None:
        table.add("sign context of 256 bytes", "sign", "INVALID_CONTEXT", key=private, message=message, context=LONG_CONTEXT)

        table.add("sign weak pre-hash", "sign", "INVALID_OPTION", key=private, message=message, preHash=weak[0])

        table.add("sign weak pre-hash and long context", "sign", "INVALID_OPTION", key=private, message=message, context=LONG_CONTEXT, preHash=weak[-1])

        table.add("hazmat sign context of 256 bytes", "hazmatSign", "INVALID_CONTEXT", key=private, message=message, context=LONG_CONTEXT, randomness=bytes(n))

        for name, data in (("empty", b""), ("one byte short", bytes(n - 1)), ("one byte long", bytes(n + 1))):
            table.add(f"hazmat sign randomness {name}", "hazmatSign", "INVALID_LENGTH", key=private, message=message, randomness=data)

        table.add("hazmat sign short randomness and long context", "hazmatSign", "INVALID_LENGTH", key=private, message=message, context=LONG_CONTEXT, randomness=bytes(n - 1))

    if not verify:
        return None

    collision = hazmat.sign(private_key, LONG_CONTEXT + message, bytes(n))

    hashed = hazmat.sign(private_key, message, bytes(n), pre_hash=PRE_HASHES[weak[0]])

    table.add("verify context of 256 bytes", "verify", "false", key=public, input=collision, message=message, context=LONG_CONTEXT)

    table.add("verify weak pre-hash", "verify", "false", key=public, input=hashed, message=message, preHash=weak[0])

    if lengths:
        table.add("hazmat verify context of 256 bytes", "hazmatVerify", "false", key=public, input=collision, message=message, context=LONG_CONTEXT)

        signature = hazmat.sign(private_key, message, bytes(n))

        for operation, prefix in (("verify", ""), ("hazmatVerify", "hazmat ")):
            table.add(f"{prefix}verify signature one byte short", operation, "false", key=public, input=signature[:-1], message=message)

            table.add(f"{prefix}verify signature one byte long", operation, "false", key=public, input=signature + b"\x00", message=message)

            table.add(f"{prefix}verify empty signature", operation, "false", key=public, input=b"", message=message)

    return hashed


# The policy checks and those that sign or verify: the boundary cases that succeed and the
# signatures that fail only on their content.
def signature_errors(table, private, public, stream):
    algorithm = table.algorithm

    n = algorithm._backend.randomness_size

    weak = [name for name in PRE_HASHES if not allowed(algorithm, name)]

    strong = [name for name in PRE_HASHES if allowed(algorithm, name)]

    weakest = min(strong, key=strength)

    message, max_context = stream.bytes(25), stream.bytes(255)

    private_key = algorithm.import_private_key(private, "raw")

    hashed = policy_errors(table, private_key, private, public, message, weak, True)

    output = algorithm._backend.expanded_size is not None

    table.add("sign context of 255 bytes", "sign", "ok", output, key=private, message=message, context=max_context)

    table.add("sign weakest allowed pre-hash", "sign", "ok", output, key=private, message=message, preHash=weakest)

    table.add("hazmat sign context of 255 bytes", "hazmatSign", "ok", output, key=private, message=message, context=max_context, randomness=bytes(n))

    table.add("hazmat sign weak pre-hash", "hazmatSign", "ok", output, key=private, message=message, preHash=weak[0], randomness=bytes(n))

    table.add("hazmat verify weak pre-hash", "hazmatVerify", "true", key=public, input=hashed, message=message, preHash=weak[0])

    table.add("verify weak pre-hash signature without pre-hash", "verify", "false", key=public, input=hashed, message=message)

    table.add("verify weakest allowed pre-hash", "verify", "true", key=public, input=hazmat.sign(private_key, message, bytes(n), pre_hash=PRE_HASHES[weakest]), message=message, preHash=weakest)

    signature = hazmat.sign(private_key, message, bytes(n), context=max_context)

    for name, operation, data, value, context, function in (
        ("verify context of 255 bytes", "verify", signature, message, max_context, None),
        ("hazmat verify context of 255 bytes", "hazmatVerify", signature, message, max_context, None),
        ("verify other context", "verify", signature, message, max_context[:-1], None),
        ("verify with a pre-hash", "verify", signature, message, max_context, strong[-1]),
        ("verify other message", "verify", signature, message + b"\x00", max_context, None),
        ("verify last byte changed", "verify", flip(signature, len(signature) - 1), message, max_context, None),
    ):
        table.add(name, operation, "true" if "255" in name else "false", key=public, input=data, message=value, context=context, preHash=function)


def mldsa_errors_group(number):
    algorithm = (ML_DSA_44, ML_DSA_65, ML_DSA_87)[number]

    params, oid = algorithm._backend.params, algorithm._backend.oid

    table = Table(algorithm)

    stream = Stream(600 + number)

    seed = stream.bytes(32)

    pair = hazmat.generate_key_pair(algorithm, seed)

    public, sk = pair.public_key.export_key("raw"), pair.private_key._private

    other_sk = hazmat.generate_key_pair(algorithm, stream.bytes(32)).private_key._private

    other_oid = (ML_DSA_65, ML_DSA_87, ML_DSA_44)[number]._backend.oid

    for name, data, expect in (("empty", b"", "INVALID_LENGTH"), ("one byte short", public[:-1], "INVALID_LENGTH"), ("one byte long", public + b"\x00", "INVALID_LENGTH"), ("zeros", bytes(len(public)), "ok")):
        table.add(f"public key raw {name}", "importPublicKey", expect, format="raw", input=data)

    for name, data in (("empty", b""), ("31 bytes", seed[:-1]), ("33 bytes", seed + b"\x00"), ("expanded key one byte short", sk[:-1]), ("expanded key one byte long", sk + b"\x00"), ("of the public key size", public)):
        table.add(f"private key raw {name}", "importPrivateKey", "INVALID_LENGTH", format="raw", input=data)

    eta_size = 32 * (2 * params.eta).bit_length()

    s1, t0 = 128, 128 + (params.k + params.l) * eta_size

    # The first coefficient of s1 is eta minus its low bits: 7 (eta 2) or 15 (eta 4) is beyond -eta.
    out_of_range = replace(sk, s1, bytes([sk[s1] & ~0x0F | (0x07 if params.eta == 2 else 0x0F)]))

    for name, data, expect in (
        ("seed", seed, "ok"),
        ("expanded key", sk, "ok"),
        ("rho changed", flip(sk, 0), "INVALID_PRIVATE_KEY"),
        ("signing seed changed", flip(sk, 40), "ok"),
        ("tr changed", flip(sk, 100), "INVALID_PRIVATE_KEY"),
        ("s1 coefficient out of range", out_of_range, "INVALID_PRIVATE_KEY"),
        ("s2 changed", flip(sk, s1 + params.l * eta_size + 3, 0x02), "INVALID_PRIVATE_KEY"),
        ("t0 changed", flip(sk, t0 + 11), "INVALID_PRIVATE_KEY"),
        ("t0 last byte changed", flip(sk, len(sk) - 1, 0x80), "INVALID_PRIVATE_KEY"),
    ):
        table.add(f"private key raw {name}", "importPrivateKey", expect, format="raw", input=data)

    choice_cases(table, oid, seed, sk, other_sk, flip(sk, 100))

    if number == 0:
        spki_cases(table, oid, other_oid, public, pkcs8(oid, der(0x80, seed)))

        pem_cases(table, "public key", "importPublicKey", PUBLIC, pair.public_key.export_key("pem"), PRIVATE)

        pkcs8_cases(table, oid, other_oid, der(0x80, seed), public, spki(oid, public))

        pem_cases(table, "private key", "importPrivateKey", PRIVATE, pair.private_key.export_key("pem"), PUBLIC)

        table.add("private key pem large attributes and public key", "importPrivateKey", "ok", format="pem", input=pem_encode(PRIVATE, pkcs8(oid, der(0x80, seed), 1, der(0xA0, bytes(LARGE)) + public_bits(public))))
    else:
        for name, data, expect in (
            ("other algorithm", spki(other_oid, public), "ALGORITHM_MISMATCH"),
            ("slh-dsa algorithm", spki(SLH_DSA_SHA2_128S._backend.oid, public), "ALGORITHM_MISMATCH"),
            ("ml-kem algorithm", spki(ML_KEM_768._backend.oid, public), "ALGORITHM_MISMATCH"),
            ("key one byte short", spki(oid, public[:-1]), "INVALID_ENCODING"),
        ):
            table.add(f"public key der {name}", "importPublicKey", expect, format="der", input=data)

        for name, data, expect in (
            ("other algorithm", pkcs8(other_oid, der(0x80, seed)), "ALGORITHM_MISMATCH"),
            ("public key", pkcs8(oid, der(0x80, seed), 1, public_bits(public)), "ok"),
            ("public key mismatch", pkcs8(oid, der(0x80, seed), 1, public_bits(flip(public, 0))), "INVALID_PRIVATE_KEY"),
        ):
            table.add(f"private key der {name}", "importPrivateKey", expect, format="der", input=data)

        table.add("private key pem expanded key", "importPrivateKey", "ok", format="pem", input=algorithm.import_private_key(sk, "raw").export_key("pem"))

        # With an attribute the encoding is 58 bytes, so its base64 ends in two padding characters.
        if number == 1:
            pem_cases(table, "private key with attributes", "importPrivateKey", PRIVATE, pem_encode(PRIVATE, pkcs8(oid, der(0x80, seed), 0, b"\xa0\x02\x30\x00")), PUBLIC)

    signature_errors(table, seed, public, stream)

    message = stream.bytes(40)

    signature = hazmat.sign(pair.private_key, message, stream.bytes(32))

    c_size, omega, k = params.lam // 4, params.omega, params.k

    hints = len(signature) - omega - k

    counts = list(signature[hints + omega :])

    total = counts[-1]

    assert 1 < total < omega

    # FIPS 204, Algorithm 21: the hint encoding must be canonical, or the signature is invalid.
    cases = [
        ("hint count above omega", replace(signature, len(signature) - 1, bytes([omega + 1]))),
        ("hint counts decreasing", replace(signature, hints + omega, bytes([total + 1]))),
        ("hint padding not zero", replace(signature, hints + omega - 1, b"\x01")),
        ("challenge changed", flip(signature, c_size - 1)),
        ("response top bit set", flip(signature, c_size + 2, 0x80)),
        ("response all ones", signature[:c_size] + b"\xff" * (hints - c_size) + signature[hints:]),
    ]

    poly = next((i for i in range(k) if counts[i] - (counts[i - 1] if i else 0) >= 2), None)

    if poly is not None:
        first = counts[poly - 1] if poly else 0

        cases.append(("hint indices not increasing", replace(signature, hints + first + 1, signature[hints + first : hints + first + 1])))

    for name, data in cases:
        table.add(f"verify {name}", "verify", "false", key=public, input=data, message=message)

    table.add("verify unmodified", "verify", "true", key=public, input=signature, message=message)

    return [table.group()]


# SLH-DSA-SHA2-128f runs every encoding and signing case; the other sets check what depends on
# their sizes and strength. The "s" sets skip whatever builds a key, which takes a second or more
# in Python, and carry the verification checks of their strength, as their signatures are the
# smallest.
def slhdsa_errors_group(index):
    algorithm = SLH_DSA[index]

    table = Table(algorithm)

    oid, n = algorithm._backend.oid, algorithm._backend.params.n

    stream = Stream(700 + index)

    seed = stream.bytes(3 * n)

    pair = hazmat.generate_key_pair(algorithm, seed)

    public, sk = pair.public_key.export_key("raw"), pair.private_key.export_key("raw")

    other_oid = next(a for a in SLH_DSA if a is not algorithm and a._backend.params.n == n)._backend.oid

    full = algorithm is SLH_DSA_SHA2_128F

    for name, data, expect in (("empty", b"", "INVALID_LENGTH"), ("one byte short", public[:-1], "INVALID_LENGTH"), ("one byte long", public + b"\x00", "INVALID_LENGTH"), ("valid", public, "ok")):
        table.add(f"public key raw {name}", "importPublicKey", expect, format="raw", input=data)

    for name, data in (("empty", b""), ("one byte short", sk[:-1]), ("one byte long", sk + b"\x00"), ("of the seed size", seed), ("of the public key size", public)):
        table.add(f"private key raw {name}", "importPrivateKey", "INVALID_LENGTH", format="raw", input=data)

    for name, octets in (("one byte short", sk[:-1]), ("one byte long", sk + b"\x00"), ("empty", b""), ("in a seed choice", der(0x80, sk)), ("in an octet string", der(0x04, sk))):
        table.add(f"private key der octets {name}", "importPrivateKey", "INVALID_ENCODING", format="der", input=pkcs8(oid, octets))

    if full:
        spki_cases(table, oid, other_oid, public, pkcs8(oid, sk))

        pem_cases(table, "public key", "importPublicKey", PUBLIC, pair.public_key.export_key("pem"), PRIVATE)

        pkcs8_cases(table, oid, other_oid, sk, public, spki(oid, public))

        pem_cases(table, "private key", "importPrivateKey", PRIVATE, pair.private_key.export_key("pem"), PUBLIC)

        large_private_cases(table, oid, other_oid, sk, public, False)
    else:
        table.add("public key der other set of the same size", "importPublicKey", "ALGORITHM_MISMATCH", format="der", input=spki(other_oid, public))

        table.add("public key der key one byte short", "importPublicKey", "INVALID_ENCODING", format="der", input=spki(oid, public[:-1]))

        table.add("private key der other set of the same size", "importPrivateKey", "ALGORITHM_MISMATCH", format="der", input=pkcs8(other_oid, sk))

    weak = [name for name in PRE_HASHES if not allowed(algorithm, name)]

    message = stream.bytes(10)

    if algorithm.name.endswith("s"):
        policy_errors(table, pair.private_key, None, public, message, weak, False)

        return [table.group()]

    for name, data, expect in (
        ("valid", sk, "ok"),
        ("secret seed changed", flip(sk, 0), "INVALID_PRIVATE_KEY"),
        ("prf key changed", flip(sk, n), "ok"),
        ("public seed changed", flip(sk, 2 * n), "INVALID_PRIVATE_KEY"),
        ("root changed", flip(sk, 4 * n - 1), "INVALID_PRIVATE_KEY"),
    ):
        table.add(f"private key raw {name}", "importPrivateKey", expect, format="raw", input=data)

    if full:
        signature_errors(table, sk, public, stream)

        return [table.group()]

    for name, data, expect in (
        ("with public key", pkcs8(oid, sk, 1, public_bits(public)), "ok"),
        ("with public key mismatch", pkcs8(oid, sk, 1, public_bits(flip(public, n))), "INVALID_PRIVATE_KEY"),
        ("with root changed", pkcs8(oid, flip(sk, 4 * n - 1)), "INVALID_PRIVATE_KEY"),
    ):
        table.add(f"private key der {name}", "importPrivateKey", expect, format="der", input=data)

    policy_errors(table, pair.private_key, sk, public, message, weak, False, False)

    return [table.group()]


LMS_CODES = {f"LMS_{lms}_H{h}": 5 + 5 * f + j for f, (lms, _) in enumerate(FAMILIES) for j, h in enumerate((5, 10, 15, 20, 25))}

OTS_CODES = {f"LMOTS_{ots}_W{w}": 1 + 4 * f + j for f, (_, ots) in enumerate(FAMILIES) for j, w in enumerate((1, 2, 4, 8))}


def hss_state(levels, seed, index, version=1, kind=1, count=None):
    body = bytes([version, kind, len(levels) if count is None else count])

    body += b"".join(u32(LMS_CODES[lms]) + u32(OTS_CODES[ots]) for lms, ots in levels)

    return seal(body + seed + index.to_bytes(8, "big"))


def named(levels):
    return {"lms": ",".join(lms for lms, _ in levels), "ots": ",".join(ots for _, ots in levels)}


def hss_errors():
    table = Table(HSS_LMS)

    stream = Stream(800)

    small = [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W4")]

    seed = stream.bytes(40)

    store = MemoryStore()

    pair = hazmat.generate_key_pair(HSS_LMS, seed, parameters=small, state_store=store, index=5)

    public, state = pair.public_key.export_key("raw"), store.state

    assert state == hss_state(small, seed, 5)

    message = stream.bytes(20)

    signature = pair.private_key.sign(message)

    for name, data, expect in (
        ("valid", public, "ok"),
        ("eight levels", u32(8) + public[4:], "ok"),
        ("zero levels", u32(0) + public[4:], "INVALID_PUBLIC_KEY"),
        ("nine levels", u32(9) + public[4:], "INVALID_PUBLIC_KEY"),
        ("unknown lms type", replace(public, 4, u32(4)), "INVALID_PUBLIC_KEY"),
        ("unknown lm-ots type", replace(public, 8, u32(17)), "INVALID_PUBLIC_KEY"),
        ("lm-ots of another hash function", replace(public, 8, u32(OTS_CODES["LMOTS_SHAKE_N24_W4"])), "INVALID_PUBLIC_KEY"),
        ("lm-ots of another output size", replace(public, 8, u32(OTS_CODES["LMOTS_SHA256_N32_W4"])), "INVALID_PUBLIC_KEY"),
        ("one byte short", public[:-1], "INVALID_PUBLIC_KEY"),
        ("one byte long", public + b"\x00", "INVALID_PUBLIC_KEY"),
        ("empty", b"", "INVALID_PUBLIC_KEY"),
        ("three bytes", public[:3], "INVALID_PUBLIC_KEY"),
        ("level count only", public[:4], "INVALID_PUBLIC_KEY"),
    ):
        table.add(f"public key raw {name}", "importPublicKey", expect, format="raw", input=data)

    oid = HSS_LMS._backend.oid

    spki_cases(table, oid, XMSS._backend.oid, public, b"\x30\x03\x02\x01\x00", "INVALID_PUBLIC_KEY")

    table.add("public key der nine levels", "importPublicKey", "INVALID_PUBLIC_KEY", format="der", input=spki(oid, u32(9) + public[4:]))

    pem_cases(table, "public key", "importPublicKey", PUBLIC, pair.public_key.export_key("pem"), PRIVATE)

    large_public_cases(table, oid, XMSS._backend.oid, public, "INVALID_PUBLIC_KEY")

    body = state[:-16]

    wide = [("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8")]

    tall = [("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W8"), ("LMS_SHA256_M24_H25", "LMOTS_SHA256_N24_W8"), ("LMS_SHA256_M24_H15", "LMOTS_SHA256_N24_W8")]

    for name, data, expect in (
        ("valid", state, "ok"),
        ("index zero", hss_state(small, seed, 0), "ok"),
        ("index at the capacity", hss_state(small, seed, 32), "ok"),
        ("index beyond the capacity", hss_state(small, seed, 33), "INVALID_PRIVATE_KEY"),
        ("index of all ones", hss_state(small, seed, MASK), "INVALID_PRIVATE_KEY"),
        ("checksum changed", flip(state, len(state) - 1), "INVALID_PRIVATE_KEY"),
        ("body changed", flip(state, 20), "INVALID_PRIVATE_KEY"),
        ("version 2", hss_state(small, seed, 5, version=2), "INVALID_PRIVATE_KEY"),
        ("version 0", hss_state(small, seed, 5, version=0), "INVALID_PRIVATE_KEY"),
        ("xmss kind", hss_state(small, seed, 5, kind=2), "ALGORITHM_MISMATCH"),
        ("xmss^mt kind", hss_state(small, seed, 5, kind=3), "ALGORITHM_MISMATCH"),
        ("kind 0", hss_state(small, seed, 5, kind=0), "ALGORITHM_MISMATCH"),
        ("kind 4", hss_state(small, seed, 5, kind=4), "ALGORITHM_MISMATCH"),
        ("version 2 and xmss kind", hss_state(small, seed, 5, version=2, kind=2), "INVALID_PRIVATE_KEY"),
        ("empty", b"", "INVALID_PRIVATE_KEY"),
        ("17 bytes", state[:17], "INVALID_PRIVATE_KEY"),
        ("checksum only", seal(b"\x01\x01"), "INVALID_PRIVATE_KEY"),
        ("level count only", seal(b"\x01\x01\x01"), "INVALID_PRIVATE_KEY"),
        ("one byte cut", state[:-1], "INVALID_PRIVATE_KEY"),
        ("one byte appended", state + b"\x00", "INVALID_PRIVATE_KEY"),
        ("body one byte short", seal(body[:-1]), "INVALID_PRIVATE_KEY"),
        ("body one byte long", seal(body + b"\x00"), "INVALID_PRIVATE_KEY"),
        ("seed of the other output size", hss_state(small, stream.bytes(48), 5), "INVALID_PRIVATE_KEY"),
        ("zero levels", seal(b"\x01\x01\x00" + seed + bytes(8)), "INVALID_PRIVATE_KEY"),
        ("level count beyond the body", hss_state(small, seed, 5, count=2), "INVALID_PRIVATE_KEY"),
        ("level count 255", hss_state(small, seed, 5, count=255), "INVALID_PRIVATE_KEY"),
        ("nine levels", hss_state(small * 9, seed, 5), "INVALID_PRIVATE_KEY"),
        ("eight levels", hss_state(small * 8, seed, 5), "ok"),
        ("unknown lms type", seal(replace(body, 3, u32(4))), "INVALID_PRIVATE_KEY"),
        ("unknown lm-ots type", seal(replace(body, 7, u32(0))), "INVALID_PRIVATE_KEY"),
        ("lm-ots of another hash function", seal(replace(body, 7, u32(OTS_CODES["LMOTS_SHAKE_N24_W4"]))), "INVALID_PRIVATE_KEY"),
        ("levels of two output sizes", hss_state(small + wide, seed, 5), "INVALID_PRIVATE_KEY"),
        ("total height 65", hss_state(tall, seed, 5), "INVALID_PRIVATE_KEY"),
    ):
        table.add(f"load {name}", "loadPrivateKey", expect, input=data)

    table.add("sign at the capacity", "sign", "KEY_EXHAUSTED", input=hss_state(small, seed, 32), message=message)

    assert table.add("sign", "sign", "ok", input=state, message=message)["output"] == signature

    for name, data, levels, index, expect in (
        ("valid", seed, small, 5, "ok"),
        ("index at the capacity", seed, small, 32, "ok"),
        ("index beyond the capacity", seed, small, 33, "INVALID_OPTION"),
        ("seed one byte short", seed[:-1], small, 0, "INVALID_LENGTH"),
        ("seed one byte long", seed + b"\x00", small, 0, "INVALID_LENGTH"),
        ("seed of the other output size", stream.bytes(48), small, 0, "INVALID_LENGTH"),
        ("short seed and index beyond the capacity", seed[:-1], small, 33, "INVALID_LENGTH"),
        ("unknown lms type", seed, [("LMS_SHA256_M24_H6", "LMOTS_SHA256_N24_W4")], 0, "INVALID_OPTION"),
        ("unknown lm-ots type", seed, [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W3")], 0, "INVALID_OPTION"),
        ("lm-ots of another hash function", seed, [("LMS_SHA256_M24_H5", "LMOTS_SHAKE_N24_W4")], 0, "INVALID_OPTION"),
        ("levels of two output sizes", seed, small + wide, 0, "INVALID_OPTION"),
        ("nine levels", seed, small * 9, 0, "INVALID_OPTION"),
        ("total height 65", seed, tall, 0, "INVALID_OPTION"),
        ("unknown type and short seed", seed[:-1], [("LMS_X", "LMOTS_SHA256_N24_W4")], 0, "INVALID_OPTION"),
    ):
        table.add(f"generate {name}", "generate", expect, input=data, index=index, **named(levels))

    # A signature of one level: L - 1, q, the LM-OTS signature (type, C and 51 chains of 24
    # bytes), the LMS type and the path.
    ots_size = 4 + 24 * (51 + 1)

    for name, data, expect in (
        ("unmodified", signature, "true"),
        ("one byte short", signature[:-1], "false"),
        ("one byte long", signature + b"\x00", "false"),
        ("last byte changed", flip(signature, len(signature) - 1), "false"),
        ("empty", b"", "false"),
        ("three bytes", signature[:3], "false"),
        ("level count only", signature[:4], "false"),
        ("one level more", replace(signature, 0, u32(1)), "false"),
        ("leaf beyond the tree", replace(signature, 4, u32(32)), "false"),
        ("leaf of all ones", replace(signature, 4, u32(0xFFFFFFFF)), "false"),
        ("other lm-ots type", replace(signature, 8, u32(OTS_CODES["LMOTS_SHA256_N24_W2"])), "false"),
        ("unknown lm-ots type", replace(signature, 8, u32(0)), "false"),
        ("other lms type", replace(signature, 8 + ots_size, u32(LMS_CODES["LMS_SHA256_M24_H10"])), "false"),
    ):
        table.add(f"verify {name}", "verify", expect, key=public, input=data, message=message)

    table.add("verify other message", "verify", "false", key=public, input=signature, message=message + b"\x00")

    two = [("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W2")] * 2

    pair = hazmat.generate_key_pair(HSS_LMS, stream.bytes(48), parameters=two, state_store=MemoryStore(), index=40)

    public, signature = pair.public_key.export_key("raw"), pair.private_key.sign(message)

    # The child public key follows the top signature: L - 1, q, LM-OTS (type, C, 133 chains of 32
    # bytes), the LMS type and a path of 5.
    child = 4 + 4 + 4 + 32 * (133 + 1) + 4 + 5 * 32

    for name, data, expect in (
        ("unmodified", signature, "true"),
        ("one level claimed", u32(0) + signature[4:], "false"),
        ("unknown child lms type", replace(signature, child, u32(3)), "false"),
        ("child lm-ots of another hash function", replace(signature, child + 4, u32(OTS_CODES["LMOTS_SHA256_N32_W2"])), "false"),
        ("child of another output size", replace(signature, child, u32(LMS_CODES["LMS_SHAKE_M24_H5"])), "false"),
        ("cut inside the child key", signature[: child + 10], "false"),
        ("cut after the child key", signature[: child + 56], "false"),
    ):
        table.add(f"verify two levels {name}", "verify", expect, key=public, input=data, message=message)

    return [table.group()]


def xmss_state(kind, oid, index, seed, version=1):
    return seal(bytes([version, kind]) + u32(oid) + index.to_bytes(8, "big") + seed)


def xmss_mt_errors():
    table = Table(XMSS_MT)

    stream = Stream(900)

    sets = XMSS_MT._backend.sets

    name = "XMSSMT-SHAKE256_20/4_192"

    oid = sets[name].oid

    xmss_oid = XMSS._backend.sets["XMSS-SHAKE256_10_192"].oid

    seed = stream.bytes(72)

    store = MemoryStore()

    pair = hazmat.generate_key_pair(XMSS_MT, seed, parameters=name, state_store=store, index=0x12345)

    public, state = pair.public_key.export_key("raw"), store.state

    assert state == xmss_state(3, oid, 0x12345, seed)

    message = stream.bytes(30)

    signature = pair.private_key.sign(message)

    for label, data, expect in (
        ("valid", public, "ok"),
        ("xmss oid", replace(public, 0, u32(xmss_oid)), "INVALID_PUBLIC_KEY"),
        ("unknown oid", replace(public, 0, u32(0)), "INVALID_PUBLIC_KEY"),
        ("oid of a 256-bit set", replace(public, 0, u32(sets["XMSSMT-SHAKE256_20/4_256"].oid)), "INVALID_PUBLIC_KEY"),
        ("one byte short", public[:-1], "INVALID_PUBLIC_KEY"),
        ("one byte long", public + b"\x00", "INVALID_PUBLIC_KEY"),
        ("three bytes", public[:3], "INVALID_PUBLIC_KEY"),
        ("empty", b"", "INVALID_PUBLIC_KEY"),
    ):
        table.add(f"public key raw {label}", "importPublicKey", expect, format="raw", input=data)

    spki_cases(table, XMSS_MT._backend.oid, XMSS._backend.oid, public, b"\x30\x03\x02\x01\x00", "INVALID_PUBLIC_KEY")

    table.add("public key der hss algorithm", "importPublicKey", "ALGORITHM_MISMATCH", format="der", input=spki(HSS_LMS._backend.oid, public))

    table.add("public key pem", "importPublicKey", "ok", format="pem", input=pair.public_key.export_key("pem"))

    capacity = 1 << 20

    for label, data, expect in (
        ("valid", state, "ok"),
        ("index at the capacity", xmss_state(3, oid, capacity, seed), "ok"),
        ("index beyond the capacity", xmss_state(3, oid, capacity + 1, seed), "INVALID_PRIVATE_KEY"),
        ("index of all ones", xmss_state(3, oid, MASK, seed), "INVALID_PRIVATE_KEY"),
        ("checksum changed", flip(state, len(state) - 1), "INVALID_PRIVATE_KEY"),
        ("seed changed", flip(state, 30), "INVALID_PRIVATE_KEY"),
        ("version 2", xmss_state(3, oid, 0, seed, 2), "INVALID_PRIVATE_KEY"),
        ("xmss kind", xmss_state(2, oid, 0, seed), "ALGORITHM_MISMATCH"),
        ("hss kind", xmss_state(1, oid, 0, seed), "ALGORITHM_MISMATCH"),
        ("xmss oid", xmss_state(3, xmss_oid, 0, seed), "INVALID_PRIVATE_KEY"),
        ("unknown oid", xmss_state(3, 0, 0, seed), "INVALID_PRIVATE_KEY"),
        ("seed one byte short", xmss_state(3, oid, 0, seed[:-1]), "INVALID_PRIVATE_KEY"),
        ("seed one byte long", xmss_state(3, oid, 0, seed + b"\x00"), "INVALID_PRIVATE_KEY"),
        ("seed of a 256-bit set", xmss_state(3, oid, 0, stream.bytes(96)), "INVALID_PRIVATE_KEY"),
        ("oid cut", seal(b"\x01\x03\x00\x00"), "INVALID_PRIVATE_KEY"),
        ("checksum only", seal(b"\x01\x03"), "INVALID_PRIVATE_KEY"),
        ("17 bytes", state[:17], "INVALID_PRIVATE_KEY"),
        ("empty", b"", "INVALID_PRIVATE_KEY"),
        ("one byte appended", state + b"\x00", "INVALID_PRIVATE_KEY"),
    ):
        table.add(f"load {label}", "loadPrivateKey", expect, input=data)

    table.add("sign at the capacity", "sign", "KEY_EXHAUSTED", input=xmss_state(3, oid, capacity, seed), message=message)

    for label, data, parameters, index, expect in (
        ("valid", seed, name, 7, "ok"),
        ("index at the capacity", seed, name, capacity, "ok"),
        ("index beyond the capacity", seed, name, capacity + 1, "INVALID_OPTION"),
        ("seed one byte short", seed[:-1], name, 0, "INVALID_LENGTH"),
        ("seed one byte long", seed + b"\x00", name, 0, "INVALID_LENGTH"),
        ("unknown name", seed, "XMSSMT-SHAKE256_20/5_192", 0, "INVALID_OPTION"),
        ("xmss name", seed, "XMSS-SHAKE256_10_192", 0, "INVALID_OPTION"),
        ("lowercase name", seed, name.lower(), 0, "INVALID_OPTION"),
        ("unknown name and short seed", seed[:-1], "XMSSMT", 0, "INVALID_OPTION"),
    ):
        table.add(f"generate {label}", "generate", expect, input=data, parameters=parameters, index=index)

    for label, data, expect in (
        ("unmodified", signature, "true"),
        ("index beyond the key", replace(signature, 0, capacity.to_bytes(3, "big")), "false"),
        ("index of all ones", replace(signature, 0, b"\xff\xff\xff"), "false"),
        ("other index", replace(signature, 0, (0x12346).to_bytes(3, "big")), "false"),
        ("one byte short", signature[:-1], "false"),
        ("one byte long", signature + b"\x00", "false"),
        ("last byte changed", flip(signature, len(signature) - 1), "false"),
        ("empty", b"", "false"),
    ):
        table.add(f"verify {label}", "verify", expect, key=public, input=data, message=message)

    table.add("verify other message", "verify", "false", key=public, input=signature, message=message + b"\x00")

    return [table.group()]


# XMSS keys of height 10 take seconds to build in Python, so only the cases that fail before the
# tree is built load or generate one; the signature comes from the key built here once.
def xmss_errors():
    table = Table(XMSS)

    stream = Stream(901)

    name = "XMSS-SHA2_10_256"

    oid = XMSS._backend.sets[name].oid

    # The XMSS and XMSS^MT code points overlap; 0x22 (XMSSMT-SHA2_20/4_192) is only XMSS^MT.
    mt_oid = XMSS_MT._backend.sets["XMSSMT-SHA2_20/4_192"].oid

    seed = stream.bytes(96)

    for label, data, expect in (
        ("version 2", xmss_state(2, oid, 0, seed, 2), "INVALID_PRIVATE_KEY"),
        ("xmss^mt kind", xmss_state(3, oid, 0, seed), "ALGORITHM_MISMATCH"),
        ("xmss^mt oid", xmss_state(2, mt_oid, 0, seed), "INVALID_PRIVATE_KEY"),
        ("seed one byte short", xmss_state(2, oid, 0, seed[:-1]), "INVALID_PRIVATE_KEY"),
        ("checksum changed", flip(xmss_state(2, oid, 0, seed), 5), "INVALID_PRIVATE_KEY"),
        ("hss state", hss_state([("LMS_SHA256_M32_H5", "LMOTS_SHA256_N32_W8")], seed[:48], 0), "ALGORITHM_MISMATCH"),
    ):
        table.add(f"load {label}", "loadPrivateKey", expect, input=data)

    for label, data, parameters, expect in (
        ("seed one byte short", seed[:-1], name, "INVALID_LENGTH"),
        ("xmss^mt name", seed, "XMSSMT-SHA2_20/4_256", "INVALID_OPTION"),
        ("unknown name", seed, "XMSS-SHA2_12_256", "INVALID_OPTION"),
    ):
        table.add(f"generate {label}", "generate", expect, input=data, parameters=parameters, index=0)

    pair = hazmat.generate_key_pair(XMSS, seed, parameters=name, state_store=MemoryStore(), index=1000)

    public = pair.public_key.export_key("raw")

    message = stream.bytes(30)

    signature = pair.private_key.sign(message)

    for label, data, expect in (
        ("valid", public, "ok"),
        ("xmss^mt oid", replace(public, 0, u32(mt_oid)), "INVALID_PUBLIC_KEY"),
        ("one byte short", public[:-1], "INVALID_PUBLIC_KEY"),
    ):
        table.add(f"public key raw {label}", "importPublicKey", expect, format="raw", input=data)

    table.add("public key der xmss^mt algorithm", "importPublicKey", "ALGORITHM_MISMATCH", format="der", input=spki(XMSS_MT._backend.oid, public))

    table.add("public key der", "importPublicKey", "ok", format="der", input=spki(XMSS._backend.oid, public))

    for label, data, expect in (
        ("unmodified", signature, "true"),
        ("index beyond the tree", replace(signature, 0, u32(1024)), "false"),
        ("index of all ones", replace(signature, 0, u32(0xFFFFFFFF)), "false"),
        ("one byte short", signature[:-1], "false"),
        ("authentication path changed", flip(signature, len(signature) - 5), "false"),
    ):
        table.add(f"verify {label}", "verify", expect, key=public, input=data, message=message)

    return [table.group()]


JOBS = {
    "kem": [(kem, ())],
    "mldsa": [(mldsa, ())],
    "slhdsa": [(slhdsa_group, (i,)) for i in range(len(SLH_DSA))],
    "hss": [(hss_record, (i,)) for i in range(len(HSS_CASES))],
    "xmss": [(xmss_record, (i,)) for i in range(len(XMSS_CASES))],
    "errors": [
        (kem_errors, ()),
        *[(mldsa_errors_group, (i,)) for i in range(3)],
        *[(slhdsa_errors_group, (i,)) for i in range(len(SLH_DSA))],
        (hss_errors, ()),
        (xmss_mt_errors, ()),
        (xmss_errors, ()),
    ],
}


def run(job):
    function, arguments = job

    return function(*arguments)


def checksum(path):
    return SHA_256.digest(path.read_bytes()).hex()


def main():
    jobs = [(family, job) for family, items in JOBS.items() for job in items]

    files = {}

    with ProcessPoolExecutor() as pool:
        for (family, _), result in zip(jobs, pool.map(run, [job for _, job in jobs])):
            if family == "hss":
                result = [({"algorithm": HSS_LMS.name}, [result])]
            elif family == "xmss":
                result = [({"algorithm": XMSS_CASES[result["tcId"] - 1][0].name}, [result])]

            files.setdefault(family, []).extend(result)

        CROSS.mkdir(parents=True, exist_ok=True)

        for family, groups in files.items():
            (CROSS / f"{family}.txt").write_bytes(render(groups))

        for path in CROSS.glob("*.txt"):
            if path.stem not in files:
                path.unlink()

        # The listing that fetch_vectors.py and xmss_vectors.py write too: every file under vectors.
        paths = sorted(p for p in VECTORS.rglob("*") if p.is_file() and p.name != "SHA256SUMS")

        lines = [f"{digest}  {p.relative_to(VECTORS).as_posix()}" for p, digest in zip(paths, pool.map(checksum, paths))]

    (VECTORS / "SHA256SUMS").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()

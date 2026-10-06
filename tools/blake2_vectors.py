import hashlib
import pathlib
import subprocess
import sys
import tempfile

from fetch_vectors import checksums, fetch, render, write

ROOT = pathlib.Path(__file__).resolve().parents[1]

# No standard publishes BLAKE2 vectors with a salt or a personalization, so these are derived and
# test-only: Python's hashlib computes every value, and the BLAKE2 reference implementation (CC0),
# fed the same parameters through its own parameter block, must agree on each one. Building needs
# a C compiler.
REFERENCE = "https://raw.githubusercontent.com/BLAKE2/BLAKE2/ed1974ea83433eba7b2d95c5dcd9ac33cb847913/ref"

FILES = {
    "blake2.h": "389bc87a83cdd9e25569a294d01a3347970d117237a66eee9df8edd6058736a4",
    "blake2-impl.h": "bc0ead7f3259a415325fa40ddebb1876f903d5062d888fc5994e8b2d9e616ec4",
    "blake2b-ref.c": "e2bf9872a8f0a51711b765936d420a7f8c34797db4d938948c24f2ddbc1dc588",
    "blake2s-ref.c": "645fb0212db0d6e15a1568da210ac3f7123da1ab4330d4fc0e33312d742d569a",
}

FUNCTIONS = (("BLAKE2b", hashlib.blake2b, (20, 32, 48, 64)), ("BLAKE2s", hashlib.blake2s, (16, 20, 28, 32)))


def pattern(length, start):
    return bytes((start + 7 * i) & 0xFF for i in range(length))


# derived/blake2.txt, 250 cases per function: the unkeyed hash at each RFC 7693 digest length and
# the MAC at 1 byte, half and full length with a 1-byte and a full-length key, each without salt or
# personalization, with either one at full length, both at full length and both at half length
# (which BLAKE2 zero-pads), over messages of 0, 3, one block, one block + 1 and 1000 bytes. Header
# hash (BLAKE2b or BLAKE2s); fields digestLength (bytes), key (empty: the unkeyed hash), salt,
# personalization, in, out.
def cases():
    for name, function, lengths in FUNCTIONS:
        full, field, block = function.MAX_DIGEST_SIZE, function.SALT_SIZE, function().block_size

        keys = [(length, 0) for length in lengths] + [(length, key) for length in (1, full // 2, full) for key in (1, function.MAX_KEY_SIZE)]

        for digest, key in keys:
            for salt, person in ((0, 0), (field, 0), (0, field), (field, field), (field // 2, field // 2)):
                for size in (0, 3, block, block + 1, 1000):
                    yield name, function, digest, pattern(key, 0x00), pattern(salt, 0x40), pattern(person, 0x80), pattern(size, 0xC0)


def main():
    entries = list(cases())

    expected = [function(message, digest_size=digest, key=key, salt=salt, person=person).hexdigest() for _, function, digest, key, salt, person, message in entries]

    lines = [" ".join([name[-1].lower(), str(digest), *(value.hex() or "-" for value in values)]) for name, _, digest, *values in entries]

    with tempfile.TemporaryDirectory() as work:
        work = pathlib.Path(work)

        for name, digest in FILES.items():
            (work / name).write_bytes(fetch(f"{REFERENCE}/{name}", digest))

        (work / "vectors.c").write_bytes((ROOT / "tools" / "blake2_vectors.c").read_bytes())

        subprocess.run(["cc", "-O2", "-std=c99", "-o", "vectors", "vectors.c", "blake2b-ref.c", "blake2s-ref.c"], cwd=work, check=True)

        output = subprocess.run([str(work / "vectors")], input="".join(f"{line}\n" for line in lines).encode(), check=True, capture_output=True).stdout

    if output.decode().split() != expected:
        sys.exit("the BLAKE2 reference implementation and hashlib disagree")

    groups = {}

    for (name, _, digest, key, salt, person, message), out in zip(entries, expected):
        record = {"digestLength": digest, "key": key.hex(), "salt": salt.hex(), "personalization": person.hex(), "in": message.hex(), "out": out}

        groups.setdefault(name, []).append(record)

    write("derived/blake2.txt", render([({"hash": name}, tests) for name, tests in groups.items()]))

    checksums()


if __name__ == "__main__":
    main()

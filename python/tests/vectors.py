import pathlib

VECTORS = pathlib.Path(__file__).resolve().parents[2] / "vectors"


def records(name, field):
    lines = (VECTORS / name).read_text().splitlines()

    header = {}

    record = {}

    found = []

    for line in [*lines, ""]:
        line = line.strip()

        if line.startswith("[") and line.endswith("]"):
            key, _, value = line[1:-1].partition("=")

            header[key.strip()] = value.strip()
        elif "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")

            record[key.strip()] = value.strip()
        elif record:
            found.append((dict(header), record))

            record = {}

    expected = sum(1 for line in lines if line.startswith(f"{field} ="))

    parsed = sum(1 for _, record in found if field in record)

    if expected == 0 or parsed != expected:
        raise AssertionError(f"{name}: parsed {parsed} records, expected {expected}")

    return found


def unhex(text):
    return bytes.fromhex(text)


# A minimal DER writer, so that tests can build encodings the library itself never produces.
def der(tag, content):
    length = len(content)

    if length < 0x80:
        return bytes([tag, length]) + content

    size = (length.bit_length() + 7) // 8

    return bytes([tag, 0x80 | size]) + length.to_bytes(size, "big") + content

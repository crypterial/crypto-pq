import hashlib
import sys

from fetch_vectors import checksums, render, write

# No standard publishes vectors for Keccak-256, KECCAK[512](M, 256) of FIPS 202, so these are derived
# and test-only: this file's own Keccak-f[1600], written from FIPS 202 §3, computes each value. Under
# the padding of SHA-3 it must agree with hashlib's SHA3-256, and under that of Keccak with the
# published digests below: of the empty message, of "abc", and of the Transfer event of ERC-20.
PUBLISHED = {
    b"": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    b"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    b"Transfer(address,address,uint256)": "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
}

RATE = 136

LANE = 2**64 - 1


def rotate(x, n):
    return ((x << n) | (x >> (64 - n))) & LANE if n else x


def round_constants():
    r = 1

    for _ in range(24):
        constant = 0

        for j in range(7):
            r = ((r << 1) ^ ((r >> 7) * 0x171)) & 0xFF

            if r & 2:
                constant |= 1 << ((1 << j) - 1)

        yield constant


def permute(a):
    a = list(a)

    for constant in round_constants():
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]

        d = [c[(x + 4) % 5] ^ rotate(c[(x + 1) % 5], 1) for x in range(5)]

        a = [a[i] ^ d[i % 5] for i in range(25)]

        # Rho and pi together, along the path of FIPS 202, Algorithm 2.
        x, y = 1, 0

        lane = a[x + 5 * y]

        for t in range(24):
            x, y = y, (2 * x + 3 * y) % 5

            lane, a[x + 5 * y] = a[x + 5 * y], rotate(lane, (t + 1) * (t + 2) // 2 % 64)

        a = [a[x + y] ^ (~a[(x + 1) % 5 + y] & a[(x + 2) % 5 + y] & LANE) for y in range(0, 25, 5) for x in range(5)]

        a[0] ^= constant

    return a


def sponge(message, suffix):
    padded = bytearray(message) + bytes([suffix])

    padded += bytes(-len(padded) % RATE)

    padded[-1] |= 0x80

    state = [0] * 25

    for start in range(0, len(padded), RATE):
        for i in range(RATE // 8):
            state[i] ^= int.from_bytes(padded[start + 8 * i : start + 8 * i + 8], "little")

        state = permute(state)

    return b"".join(lane.to_bytes(8, "little") for lane in state[:4])


def pattern(length):
    return bytes((0x5A + 7 * i) & 0xFF for i in range(length))


# derived/keccak256.txt: every length from 0 to two blocks and three bytes, and longer messages around
# multiples of the rate. Header hash; fields in, out.
def messages():
    for length in [*range(2 * RATE + 4), 3 * RATE - 1, 3 * RATE, 3 * RATE + 1, 1000, 4096]:
        yield pattern(length)

    yield from PUBLISHED


def main():
    for message in messages():
        if sponge(message, 0x06) != hashlib.sha3_256(message).digest():
            sys.exit("this Keccak-f[1600] and hashlib's SHA3-256 disagree")

    for message, digest in PUBLISHED.items():
        if sponge(message, 0x01).hex() != digest:
            sys.exit("this Keccak-256 and a published digest disagree")

    tests = [{"in": message.hex(), "out": sponge(message, 0x01).hex()} for message in messages()]

    write("derived/keccak256.txt", render([({"hash": "Keccak-256"}, tests)]))

    checksums()


if __name__ == "__main__":
    main()

P = 2**255 - 19

A24 = 121665

BASE = bytes([9]) + bytes(31)


# RFC 7748, section 5: Montgomery ladder over u-coordinates. Python integers are not constant
# time; the compiled implementations use fixed-size limbs and a masked swap instead.
def x25519(scalar, u):
    k = bytearray(scalar)

    k[0] &= 248

    k[31] &= 127

    k[31] |= 64

    k = int.from_bytes(k, "little")

    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)

    x2, z2, x3, z3 = 1, 0, x1, 1

    swap = 0

    for t in reversed(range(255)):
        bit = (k >> t) & 1

        if swap ^ bit:
            x2, x3, z2, z3 = x3, x2, z3, z2

        swap = bit

        a = (x2 + z2) % P

        aa = a * a % P

        b = (x2 - z2) % P

        bb = b * b % P

        e = (aa - bb) % P

        c = (x3 + z3) % P

        d = (x3 - z3) % P

        da = d * a % P

        cb = c * b % P

        x3 = (da + cb) ** 2 % P

        z3 = x1 * (da - cb) ** 2 % P

        x2 = aa * bb % P

        z2 = e * (aa + A24 * e) % P

    if swap:
        x2, z2 = x3, z3

    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")

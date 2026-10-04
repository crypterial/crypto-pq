import threading

P = 2**255 - 19

A24 = 121665

BASE = bytes([9]) + bytes(31)

# Edwards25519 (RFC 7748, section 4.1): -x^2 + y^2 = 1 + d x^2 y^2, birationally equivalent to
# Curve25519 through u = (1 + y) / (1 - y). Its base point has y = 4/5 and an even x, and maps to
# the base point u = 9 of X25519.
D = -121665 * pow(121666, P - 2, P) % P

D2 = 2 * D % P

_M256 = (1 << 256) - 1

# A table entry packs (y + x, y - x, 2dxy) of an affine point into one integer; this one is the
# neutral point (0, 1).
_IDENTITY = 1 | 1 << 256


def _clamp(scalar):
    k = bytearray(scalar)

    k[0] &= 248

    k[31] &= 127

    k[31] |= 64

    return k


# RFC 7748, section 5: Montgomery ladder over u-coordinates. Python integers are not constant
# time; the compiled implementations use fixed-size limbs and a masked swap instead.
def x25519(scalar, u):
    k = int.from_bytes(_clamp(scalar), "little")

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


def _base_point():
    y = 4 * pow(5, P - 2, P) % P

    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P

    x = pow(xx, (P + 3) // 8, P)

    if x * x % P != xx:
        x = x * pow(2, (P - 1) // 4, P) % P

    return (P - x if x & 1 else x), y


# Points in extended coordinates (X : Y : Z : T) with x = X / Z, y = Y / Z and T = XY / Z; the
# formulas are add-2008-hwcd-3 and dbl-2008-hwcd for a = -1 (Hisil, Wong, Carter and Dawson).
def _add(p1, p2):
    x1, y1, z1, t1 = p1

    x2, y2, z2, t2 = p2

    a = (y1 - x1) * (y2 - x2) % P

    b = (y1 + x1) * (y2 + x2) % P

    c = t1 * D2 * t2 % P

    d = 2 * z1 * z2 % P

    e, f, g, h = b - a, d - c, d + c, b + a

    return e * f % P, g * h % P, f * g % P, e * h % P


def _double(point):
    x, y, z, _ = point

    a = x * x % P

    b = y * y % P

    c = 2 * z * z % P

    e = ((x + y) * (x + y) - a - b) % P

    g = b - a

    f = g - c

    h = -a - b

    return e * f % P, g * h % P, f * g % P, e * h % P


# The sum of a point and a table entry (madd-2008-hwcd-3): the entry is affine, so Z2 = 1.
def _add_entry(point, entry):
    x, y, z, t = point

    yplusx, yminusx, xy2d = entry

    a = (y - x) * yminusx % P

    b = (y + x) * yplusx % P

    c = t * xy2d % P

    d = 2 * z

    e, f, g, h = b - a, d - c, d + c, b + a

    return e * f % P, g * h % P, f * g % P, e * h % P


# The table holds the public multiples j * 256^i * B for j = 1 .. 8 and i = 0 .. 31, so its
# inversions may take variable time.
def _entry(point):
    x, y, z, _ = point

    inverse = pow(z, -1, P)

    x = x * inverse % P

    y = y * inverse % P

    return (y + x) % P | ((y - x) % P) << 256 | (D2 * x * y % P) << 512


def _build_table():
    x, y = _base_point()

    point = (x, y, 1, x * y % P)

    table = []

    for _ in range(32):
        row = []

        multiple = point

        for _ in range(8):
            row.append(_entry(multiple))

            multiple = _add(multiple, point)

        table.append(tuple(row))

        for _ in range(8):
            point = _double(point)

    return tuple(table)


_table = None

_table_lock = threading.Lock()


def _base_table():
    global _table

    if _table is None:
        with _table_lock:
            if _table is None:
                _table = _build_table()

    return _table


# digit * 256^i * B for a signed digit in [-8, 8]: every entry of the row is read and masked, and
# the sign swaps y + x with y - x and negates 2dxy, so the digit picks neither a branch nor an index.
def _select(row, digit):
    negative = (digit >> 8) & 1

    absolute = digit - ((-negative) & (2 * digit))

    selected = _IDENTITY

    for j, entry in enumerate(row, 1):
        selected ^= (selected ^ entry) & (((absolute ^ j) - 1) >> 8)

    yplusx = selected & _M256

    yminusx = (selected >> 256) & _M256

    xy2d = selected >> 512

    mask = -negative

    swap = (yplusx ^ yminusx) & mask

    return yplusx ^ swap, yminusx ^ swap, xy2d ^ ((xy2d ^ (P - xy2d)) & mask)


# X25519(scalar, 9) as the fixed-base multiplication of ref10 on Edwards25519: the clamped scalar,
# below 2^255, becomes 64 signed radix-16 digits e_i in [-8, 8], and sum e_i 16^i B adds the odd
# digits, multiplies by 16 and adds the even digits, each digit from its table row. The result is
# never the neutral point, as no clamped scalar is a multiple of the order of B, and the
# u-coordinate equals the one of the Montgomery ladder.
def x25519_base(scalar):
    digits = []

    for byte in _clamp(scalar):
        digits.append(byte & 15)

        digits.append(byte >> 4)

    carry = 0

    for i in range(63):
        digits[i] += carry

        carry = (digits[i] + 8) >> 4

        digits[i] -= carry << 4

    digits[63] += carry

    table = _base_table()

    point = (0, 1, 1, 0)

    for i in range(1, 64, 2):
        point = _add_entry(point, _select(table[i >> 1], digits[i]))

    point = _double(_double(_double(_double(point))))

    for i in range(0, 64, 2):
        point = _add_entry(point, _select(table[i >> 1], digits[i]))

    _, y, z, _ = point

    return ((z + y) * pow(z - y, P - 2, P) % P).to_bytes(32, "little")

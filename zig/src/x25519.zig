const std = @import("std");

const ct = @import("ct.zig");

// Field elements modulo p = 2^255 - 19 in five 51-bit limbs; limbs may exceed 51 bits between
// operations, and only `freeze` produces the canonical value. The arithmetic also runs at
// compile time, where it builds the table of multiples of the base point.
const Fe = [5]u64;

const mask51: u64 = (1 << 51) - 1;

const zero: Fe = @splat(0);

const one: Fe = .{ 1, 0, 0, 0, 0 };

pub const base_point = [_]u8{9} ++ [_]u8{0} ** 31;

fn load(bytes: *const [32]u8) Fe {
    var words: [4]u64 = undefined;

    for (&words, 0..) |*word, i| {
        word.* = std.mem.readInt(u64, bytes[8 * i ..][0..8], .little);
    }

    return .{
        words[0] & mask51,
        ((words[0] >> 51) | (words[1] << 13)) & mask51,
        ((words[1] >> 38) | (words[2] << 26)) & mask51,
        ((words[2] >> 25) | (words[3] << 39)) & mask51,
        (words[3] >> 12) & mask51,
    };
}

fn carry(f: Fe) Fe {
    var h = f;

    for (0..4) |i| {
        h[i + 1] += h[i] >> 51;

        h[i] &= mask51;
    }

    h[0] += 19 * (h[4] >> 51);

    h[4] &= mask51;

    h[1] += h[0] >> 51;

    h[0] &= mask51;

    return h;
}

// The canonical representative, below p.
fn freeze(f: Fe) Fe {
    var h = carry(carry(f));

    // q is 1 exactly when h >= p: adding 19 then carries out of bit 255.
    var q = (h[0] + 19) >> 51;

    for (1..5) |i| {
        q = (h[i] + q) >> 51;
    }

    h[0] += 19 * q;

    for (0..4) |i| {
        h[i + 1] += h[i] >> 51;

        h[i] &= mask51;
    }

    h[4] &= mask51;

    return h;
}

fn store(f: Fe) [32]u8 {
    const h = freeze(f);

    const words = [4]u64{
        h[0] | (h[1] << 51),
        (h[1] >> 13) | (h[2] << 38),
        (h[2] >> 26) | (h[3] << 25),
        (h[3] >> 39) | (h[4] << 12),
    };

    var out: [32]u8 = undefined;

    for (words, 0..) |word, i| {
        std.mem.writeInt(u64, out[8 * i ..][0..8], word, .little);
    }

    return out;
}

fn add(a: Fe, b: Fe) Fe {
    var h: Fe = undefined;

    for (&h, a, b) |*x, y, z| {
        x.* = y + z;
    }

    return h;
}

// a + 2p - b, so that limbs never go negative; b must have limbs below 2^52.
fn sub(a: Fe, b: Fe) Fe {
    const two_p = Fe{ 2 * (mask51 - 18), 2 * mask51, 2 * mask51, 2 * mask51, 2 * mask51 };

    var h: Fe = undefined;

    for (&h, a, b, two_p) |*x, y, z, w| {
        x.* = y + w - z;
    }

    return carry(h);
}

fn wide(a: u64, b: u64) u128 {
    return @as(u128, a) * b;
}

// The multiples 19 * b_i and 2 * a_i fit in 64 bits for limbs below 2^54, so every product is a
// single 64 x 64 -> 128-bit multiplication.
fn mul(a: Fe, b: Fe) Fe {
    const b19 = [5]u64{ 0, 19 * b[1], 19 * b[2], 19 * b[3], 19 * b[4] };

    return reduceWide(.{
        wide(a[0], b[0]) + wide(a[1], b19[4]) + wide(a[2], b19[3]) + wide(a[3], b19[2]) + wide(a[4], b19[1]),
        wide(a[0], b[1]) + wide(a[1], b[0]) + wide(a[2], b19[4]) + wide(a[3], b19[3]) + wide(a[4], b19[2]),
        wide(a[0], b[2]) + wide(a[1], b[1]) + wide(a[2], b[0]) + wide(a[3], b19[4]) + wide(a[4], b19[3]),
        wide(a[0], b[3]) + wide(a[1], b[2]) + wide(a[2], b[1]) + wide(a[3], b[0]) + wide(a[4], b19[4]),
        wide(a[0], b[4]) + wide(a[1], b[3]) + wide(a[2], b[2]) + wide(a[3], b[1]) + wide(a[4], b[0]),
    });
}

// The products a_i * a_j and a_j * a_i of a square are equal, so each pair is computed once and
// doubled: 15 multiplications instead of 25.
fn square(a: Fe) Fe {
    const doubled = [4]u64{ 2 * a[0], 2 * a[1], 2 * a[2], 2 * a[3] };

    const a3_19 = 19 * a[3];

    const a4_19 = 19 * a[4];

    return reduceWide(.{
        wide(a[0], a[0]) + wide(doubled[1], a4_19) + wide(doubled[2], a3_19),
        wide(doubled[0], a[1]) + wide(doubled[2], a4_19) + wide(a[3], a3_19),
        wide(doubled[0], a[2]) + wide(a[1], a[1]) + wide(doubled[3], a4_19),
        wide(doubled[0], a[3]) + wide(doubled[1], a[2]) + wide(a[4], a4_19),
        wide(doubled[0], a[4]) + wide(doubled[1], a[3]) + wide(a[2], a[2]),
    });
}

// Carries the column sums of a product back into 51-bit limbs.
fn reduceWide(columns: [5]u128) Fe {
    var t = columns;

    for (0..4) |i| {
        t[i + 1] += t[i] >> 51;

        t[i] &= mask51;
    }

    var h: Fe = undefined;

    for (&h, t) |*x, y| {
        x.* = @truncate(y & mask51);
    }

    h[0] += 19 * @as(u64, @intCast(t[4] >> 51));

    h[1] += h[0] >> 51;

    h[0] &= mask51;

    return h;
}

fn squareTimes(a: Fe, count: usize) Fe {
    var h = a;

    for (0..count) |_| h = square(h);

    return h;
}

fn mulSmall(a: Fe, k: u64) Fe {
    var t: [5]u128 = undefined;

    for (&t, a) |*x, y| {
        x.* = @as(u128, y) * k;
    }

    for (0..4) |i| {
        t[i + 1] += t[i] >> 51;

        t[i] &= mask51;
    }

    var h: Fe = undefined;

    for (&h, t) |*x, y| {
        x.* = @truncate(y & mask51);
    }

    h[0] += 19 * @as(u64, @intCast(t[4] >> 51));

    return carry(h);
}

// z^(2^250 - 1) and z^11, through the usual chain shared by inversion and square roots.
fn power2501(z: Fe) [2]Fe {
    const z2 = square(z);

    const z9 = mul(squareTimes(z2, 2), z);

    const z11 = mul(z9, z2);

    const z_5_0 = mul(square(z11), z9);

    const z_10_0 = mul(squareTimes(z_5_0, 5), z_5_0);

    const z_20_0 = mul(squareTimes(z_10_0, 10), z_10_0);

    const z_40_0 = mul(squareTimes(z_20_0, 20), z_20_0);

    const z_50_0 = mul(squareTimes(z_40_0, 10), z_10_0);

    const z_100_0 = mul(squareTimes(z_50_0, 50), z_50_0);

    const z_200_0 = mul(squareTimes(z_100_0, 100), z_100_0);

    return .{ mul(squareTimes(z_200_0, 50), z_50_0), z11 };
}

// z^(p - 2) = z^(2^255 - 21): 254 squarings and 11 multiplications.
fn invert(z: Fe) Fe {
    const z_250_0, const z11 = power2501(z);

    return mul(squareTimes(z_250_0, 5), z11);
}

// z^((p - 5) / 8) = z^(2^252 - 3), the exponent of RFC 8032's square roots.
fn powerP58(z: Fe) Fe {
    const z_250_0, _ = power2501(z);

    return mul(squareTimes(z_250_0, 2), z);
}

fn conditionalSwap(swap: u64, a: *Fe, b: *Fe) void {
    const mask = 0 -% swap;

    for (a, b) |*x, *y| {
        const t = mask & (x.* ^ y.*);

        x.* ^= t;

        y.* ^= t;
    }
}

fn clamp(scalar: *const [32]u8) [32]u8 {
    var k = scalar.*;

    k[0] &= 248;

    k[31] &= 127;

    k[31] |= 64;

    return k;
}

// RFC 7748, section 5: the Montgomery ladder over u-coordinates with a masked swap per bit.
pub fn x25519(scalar: *const [32]u8, u: *const [32]u8) [32]u8 {
    var k = clamp(scalar);

    defer ct.wipe(&k);

    const x1 = load(u);

    var x2: Fe = .{ 1, 0, 0, 0, 0 };

    var z2: Fe = @splat(0);

    var x3 = x1;

    var z3: Fe = .{ 1, 0, 0, 0, 0 };

    var swap: u64 = 0;

    var t: usize = 255;

    while (t > 0) {
        t -= 1;

        const bit: u64 = (k[t / 8] >> @intCast(t % 8)) & 1;

        swap ^= bit;

        conditionalSwap(swap, &x2, &x3);

        conditionalSwap(swap, &z2, &z3);

        swap = bit;

        const a = add(x2, z2);

        const aa = square(a);

        const b = sub(x2, z2);

        const bb = square(b);

        const e = sub(aa, bb);

        const c = add(x3, z3);

        const d = sub(x3, z3);

        const da = mul(d, a);

        const cb = mul(c, b);

        x3 = square(add(da, cb));

        z3 = mul(x1, square(sub(da, cb)));

        x2 = mul(aa, bb);

        z2 = mul(e, add(aa, mulSmall(e, 121665)));
    }

    conditionalSwap(swap, &x2, &x3);

    conditionalSwap(swap, &z2, &z3);

    const out = store(mul(x2, invert(z2)));

    inline for (.{ &x2, &z2, &x3, &z3 }) |f| {
        ct.wipe(std.mem.asBytes(f));
    }

    return out;
}

// A point of edwards25519, -x^2 + y^2 = 1 + d x^2 y^2, in extended coordinates: x = X/Z,
// y = Y/Z and XY = ZT.
const Point = struct {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
};

const identity: Point = .{ .x = zero, .y = one, .z = one, .t = zero };

// An affine point as y + x, y - x and 2dxy, the form in which the table holds the multiples of
// the base point (ref10's ge_precomp).
const Precomputed = [3]Fe;

// The formulas of ref10's ge_p2_dbl and ge_p1p1_to_p3, reordered so that every subtrahend is
// carried: x = 2XY / (Y^2 - X^2) and y = (Y^2 + X^2) / (2Z^2 + X^2 - Y^2).
fn double(p: Point) Point {
    const xx = square(p.x);

    const yy = square(p.y);

    const zz = square(p.z);

    const e = sub(sub(square(add(p.x, p.y)), xx), yy);

    const g = sub(yy, xx);

    const h = add(yy, xx);

    const f = sub(add(add(zz, zz), xx), yy);

    return .{ .x = mul(e, f), .y = mul(h, g), .z = mul(g, f), .t = mul(e, h) };
}

// p + q for q in the table's form, as ref10's ge_madd and ge_p1p1_to_p3.
fn addPrecomputed(p: Point, q: Precomputed) Point {
    const a = mul(add(p.y, p.x), q[0]);

    const b = mul(sub(p.y, p.x), q[1]);

    const c = mul(q[2], p.t);

    const d = add(p.z, p.z);

    const e = sub(a, b);

    const f = sub(d, c);

    const g = add(d, c);

    const h = add(a, b);

    return .{ .x = mul(e, f), .y = mul(h, g), .z = mul(g, f), .t = mul(e, h) };
}

// What follows defines the table: the curve constant, the base point and the multiples
// j * 256^i * B for i < 32 and 1 <= j <= 8, all derived here from their definitions.

fn small(value: u64) Fe {
    return .{ value, 0, 0, 0, 0 };
}

fn same(a: Fe, b: Fe) bool {
    return std.mem.eql(u64, &freeze(a), &freeze(b));
}

// d = -121665 / 121666.
const curve_d: Fe = blk: {
    @setEvalBranchQuota(100_000);

    break :blk mul(sub(zero, small(121665)), invert(small(121666)));
};

const curve_d2 = add(curve_d, curve_d);

// 2^((p - 1) / 4), a square root of -1 because 2 is not a square modulo p.
const sqrt_m1: Fe = blk: {
    @setEvalBranchQuota(100_000);

    break :blk mul(square(powerP58(small(2))), small(2));
};

// p + q for two points in extended coordinates (Hisil, Wong, Carter and Dawson, 2008, for
// a = -1); only the table is built with it.
fn addPoints(p: Point, q: Point) Point {
    const a = mul(sub(p.y, p.x), sub(q.y, q.x));

    const b = mul(add(p.y, p.x), add(q.y, q.x));

    const c = mul(mul(p.t, q.t), curve_d2);

    const d = mul(p.z, add(q.z, q.z));

    const e = sub(b, a);

    const f = sub(d, c);

    const g = add(d, c);

    const h = add(b, a);

    return .{ .x = mul(e, f), .y = mul(g, h), .z = mul(f, g), .t = mul(e, h) };
}

// B = (x, 4/5) with x even (RFC 8032, section 5.1). x^2 = (y^2 - 1) / (d y^2 + 1), and the root
// is taken as in RFC 8032, section 5.1.3: x = u v^3 (u v^7)^((p - 5) / 8), times sqrt(-1) when
// v x^2 = -u.
const edwards_base: Point = blk: {
    @setEvalBranchQuota(1_000_000);

    const y = mul(small(4), invert(small(5)));

    const yy = square(y);

    const u = sub(yy, one);

    const v = add(mul(curve_d, yy), one);

    const v3 = mul(square(v), v);

    const v7 = mul(square(v3), v);

    var x = mul(mul(u, v3), powerP58(mul(u, v7)));

    if (!same(mul(v, square(x)), u)) x = mul(x, sqrt_m1);

    if (!same(mul(v, square(x)), u)) @compileError("x^2 has no square root");

    x = freeze(x);

    if (x[0] & 1 == 1) x = freeze(sub(zero, x));

    // On the curve, and mapped to u = 9 by u = (1 + y) / (1 - y): it is X25519's base point.
    const xx = square(x);

    if (!same(sub(yy, xx), add(one, mul(curve_d, mul(xx, yy))))) @compileError("B is not on the curve");

    if (!same(mul(add(one, y), invert(sub(one, y))), small(9))) @compileError("B does not map to u = 9");

    break :blk .{ .x = x, .y = freeze(y), .z = one, .t = mul(x, y) };
};

// The multiples in extended coordinates, then all brought to Z = 1 with one inversion
// (Montgomery's trick) and written as y + x, y - x and 2dxy.
const table: [32][8]Precomputed = blk: {
    @setEvalBranchQuota(100_000_000);

    var points: [32][8]Point = undefined;

    var base = edwards_base;

    for (&points) |*row| {
        row[0] = base;

        for (1..8) |j| row[j] = addPoints(row[j - 1], base);

        for (0..8) |_| base = double(base);
    }

    var prefixes: [256]Fe = undefined;

    var product = one;

    for (&prefixes, 0..) |*prefix, n| {
        prefix.* = product;

        product = mul(product, points[n / 8][n % 8].z);
    }

    var inverse = invert(product);

    var out: [32][8]Precomputed = undefined;

    var n: usize = 256;

    while (n > 0) {
        n -= 1;

        const point = points[n / 8][n % 8];

        const z_inverse = mul(inverse, prefixes[n]);

        inverse = mul(inverse, point.z);

        const x = mul(point.x, z_inverse);

        const y = mul(point.y, z_inverse);

        out[n / 8][n % 8] = .{ freeze(add(y, x)), freeze(sub(y, x)), freeze(mul(mul(x, y), curve_d2)) };
    }

    break :blk out;
};

// A value the compiler cannot see through, so that masked moves stay masked moves.
fn conceal(value: u64) u64 {
    var copy = value;

    const barrier: *volatile u64 = &copy;

    return barrier.*;
}

// 1 when a == b, 0 otherwise, for a and b below 2^31.
fn equal(a: u64, b: u64) u64 {
    return @as(u64, @as(u32, @truncate(a ^ b)) -% 1) >> 31;
}

// |digit| * 256^position * B, negated when the digit is negative, as ref10's select: every entry
// of the row is read and kept or dropped by a mask, so neither a branch nor an index depends on
// the digit.
fn select(position: usize, digit: i8) Precomputed {
    const sign = digit >> 7;

    const magnitude: u64 = @as(u8, @bitCast((digit ^ sign) -% sign));

    var t: Precomputed = .{ one, one, zero };

    for (&table[position], 1..) |*entry, j| {
        const mask = conceal(0 -% equal(magnitude, j));

        for (&t, entry) |*field, source| {
            for (field, source) |*x, y| x.* ^= mask & (x.* ^ y);
        }
    }

    // -(x, y) = (-x, y): y + x and y - x trade places and 2dxy changes sign.
    const negative = conceal(@bitCast(@as(i64, sign)));

    for (&t[0], &t[1]) |*x, *y| {
        const difference = negative & (x.* ^ y.*);

        x.* ^= difference;

        y.* ^= difference;
    }

    const negated = sub(zero, t[2]);

    for (&t[2], negated) |*x, y| x.* ^= negative & (x.* ^ y);

    return t;
}

// The clamped scalar as 64 signed radix-16 digits in [-8, 8], as ref10's ge_scalarmult_base: its
// top bit is clear, so the last digit takes the final carry without overflowing.
fn digits(k: *const [32]u8) [64]i8 {
    var e: [64]i8 = undefined;

    for (k, 0..) |byte, i| {
        e[2 * i] = @intCast(byte & 15);

        e[2 * i + 1] = @intCast(byte >> 4);
    }

    var carry_digit: i8 = 0;

    for (e[0..63]) |*digit| {
        digit.* += carry_digit;

        carry_digit = (digit.* + 8) >> 4;

        digit.* -= carry_digit << 4;
    }

    e[63] += carry_digit;

    return e;
}

// X25519(k, 9) for public keys: k * B on edwards25519 from the table, as ref10's
// ge_scalarmult_base, sums the multiples of the odd digits, multiplies by 16 and adds those of
// the even ones. u = (1 + y) / (1 - y) = (Z + Y) / (Z - Y) maps the result to the u-coordinate
// that the ladder computes: the map takes B to the point with u = 9 and preserves the group law.
pub fn x25519Base(scalar: *const [32]u8) [32]u8 {
    var k = clamp(scalar);

    var e = digits(&k);

    var h = identity;

    defer {
        ct.wipe(&k);

        ct.wipe(std.mem.asBytes(&e));

        ct.wipe(std.mem.asBytes(&h));
    }

    for (0..32) |position| h = addPrecomputed(h, select(position, e[2 * position + 1]));

    for (0..4) |_| h = double(h);

    for (0..32) |position| h = addPrecomputed(h, select(position, e[2 * position]));

    return store(mul(add(h.z, h.y), invert(sub(h.z, h.y))));
}

test "x25519 RFC 7748" {
    const vectors = @import("vectors");

    const v = try vectors.Vectors.load("rfc/x25519.txt", "output");

    defer v.deinit();

    for (v.records) |r| {
        const kind = r.header.get("kind");

        if (std.mem.eql(u8, kind, "multiply")) {
            const output = try vectors.decodeArray(32, r.values.get("output"));

            const scalar = try vectors.decodeArray(32, r.values.get("scalar"));

            const u = try vectors.decodeArray(32, r.values.get("u"));

            try std.testing.expectEqual(output, x25519(&scalar, &u));
        } else if (std.mem.eql(u8, kind, "iterate")) {
            const output = try vectors.decodeArray(32, r.values.get("output"));

            const count = try vectors.number(usize, r.values.get("iterations"));

            if (count > 1000 and !vectors.slow()) continue;

            var k = base_point;

            var u = base_point;

            for (0..count) |_| {
                const next = x25519(&k, &u);

                u = k;

                k = next;
            }

            try std.testing.expectEqual(output, k);
        } else {
            const alice = try vectors.decodeArray(32, r.values.get("alicePrivate"));

            const bob = try vectors.decodeArray(32, r.values.get("bobPrivate"));

            const alice_public = try vectors.decodeArray(32, r.values.get("alicePublic"));

            const bob_public = try vectors.decodeArray(32, r.values.get("bobPublic"));

            const shared = try vectors.decodeArray(32, r.values.get("shared"));

            try std.testing.expectEqual(alice_public, x25519(&alice, &base_point));

            try std.testing.expectEqual(bob_public, x25519(&bob, &base_point));

            try std.testing.expectEqual(alice_public, x25519Base(&alice));

            try std.testing.expectEqual(bob_public, x25519Base(&bob));

            try std.testing.expectEqual(shared, x25519(&alice, &bob_public));

            try std.testing.expectEqual(shared, x25519(&bob, &alice_public));
        }
    }
}

// Wycheproof marks low-order and twist points "acceptable"; X25519 itself is defined for them.
test "x25519 Wycheproof" {
    const vectors = @import("vectors");

    const v = try vectors.Vectors.load("wycheproof/x25519.txt", "tcId");

    defer v.deinit();

    for (v.records) |r| {
        const private = try vectors.decodeArray(32, r.values.get("private"));

        const public = try vectors.decodeArray(32, r.values.get("public"));

        const shared = try vectors.decodeArray(32, r.values.get("shared"));

        try std.testing.expectEqual(shared, x25519(&private, &public));
    }
}

// The table path must give the ladder's result for every scalar: many from a fixed SHAKE256
// stream, and edge scalars whose digits reach -8, 0 and 8 with every carry pattern.
test "x25519 base matches the ladder" {
    const keccak = @import("keccak.zig");

    var stream = keccak.Keccak.init(136, 0x1f);

    stream.update("crypto-pq x25519 base");

    for (0..10_000) |_| {
        var k: [32]u8 = undefined;

        stream.read(&k);

        try std.testing.expectEqual(x25519(&k, &base_point), x25519Base(&k));
    }

    const values = [_]u8{ 0x00, 0x01, 0x07, 0x08, 0x0f, 0x10, 0x70, 0x77, 0x78, 0x7f, 0x80, 0x87, 0x88, 0x8f, 0xf0, 0xf7, 0xf8, 0xff };

    for ([_]u8{ 0x00, 0x88, 0xff }) |background| {
        for (0..32) |position| {
            for (values) |value| {
                var k: [32]u8 = @splat(background);

                k[position] = value;

                try std.testing.expectEqual(x25519(&k, &base_point), x25519Base(&k));
            }
        }
    }
}

// zig build ct runs this test under valgrind with the private scalars marked secret. The table
// path selects entries by the secret digits; the filled scalars have digits 0, -8 and 8.
test "x25519 constant time" {
    var alice: [32]u8 = undefined;

    _ = try std.fmt.hexToBytes(&alice, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");

    var bob: [32]u8 = undefined;

    _ = try std.fmt.hexToBytes(&bob, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

    ct.secret(&alice);

    ct.secret(&bob);

    var alice_public = x25519(&alice, &base_point);

    ct.declassify(&alice_public);

    var shared = x25519(&bob, &alice_public);

    ct.declassify(&shared);

    var expected: [32]u8 = undefined;

    _ = try std.fmt.hexToBytes(&expected, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    try std.testing.expectEqual(expected, shared);

    var table_public = x25519Base(&alice);

    ct.declassify(&table_public);

    try std.testing.expectEqual(alice_public, table_public);

    for ([_]u8{ 0x00, 0x88, 0xff }) |fill| {
        var scalar: [32]u8 = @splat(fill);

        ct.secret(&scalar);

        var ladder = x25519(&scalar, &base_point);

        var fixed = x25519Base(&scalar);

        ct.declassify(&ladder);

        ct.declassify(&fixed);

        try std.testing.expectEqual(ladder, fixed);
    }
}

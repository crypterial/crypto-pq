const std = @import("std");

const ct = @import("ct.zig");

// Field elements modulo p = 2^255 - 19 in five 51-bit limbs; limbs may exceed 51 bits between
// operations, and only `store` produces the canonical value.
const Fe = [5]u64;

const mask51: u64 = (1 << 51) - 1;

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

fn store(f: Fe) [32]u8 {
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

// z^(p - 2) = z^(2^255 - 21) by the usual chain of 254 squarings and 11 multiplications.
fn invert(z: Fe) Fe {
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

    const z_250_0 = mul(squareTimes(z_200_0, 50), z_50_0);

    return mul(squareTimes(z_250_0, 5), z11);
}

fn conditionalSwap(swap: u64, a: *Fe, b: *Fe) void {
    const mask = 0 -% swap;

    for (a, b) |*x, *y| {
        const t = mask & (x.* ^ y.*);

        x.* ^= t;

        y.* ^= t;
    }
}

// RFC 7748, section 5: the Montgomery ladder over u-coordinates with a masked swap per bit.
pub fn x25519(scalar: *const [32]u8, u: *const [32]u8) [32]u8 {
    var k = scalar.*;

    defer ct.wipe(&k);

    k[0] &= 248;

    k[31] &= 127;

    k[31] |= 64;

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

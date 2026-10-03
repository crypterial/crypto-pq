const std = @import("std");

const ct = @import("ct.zig");
const hash = @import("hash.zig");
const primitives = @import("primitives.zig");

pub const Parameters = struct {
    k: u8,
    eta1: u8,
    eta2: u8,
    du: u5,
    dv: u5,

    pub inline fn encapsulationKeySize(comptime self: Parameters) usize {
        return 384 * @as(usize, self.k) + 32;
    }

    pub inline fn decapsulationKeySize(comptime self: Parameters) usize {
        return 768 * @as(usize, self.k) + 96;
    }

    pub inline fn ciphertextSize(comptime self: Parameters) usize {
        return 32 * (@as(usize, self.du) * self.k + self.dv);
    }
};

pub const ml_kem_512: Parameters = .{ .k = 2, .eta1 = 3, .eta2 = 2, .du = 10, .dv = 4 };

pub const ml_kem_768: Parameters = .{ .k = 3, .eta1 = 2, .eta2 = 2, .du = 10, .dv = 4 };

pub const ml_kem_1024: Parameters = .{ .k = 4, .eta1 = 2, .eta2 = 2, .du = 11, .dv = 5 };

const q = 3329;

const Poly = [256]i16;

// Powers of 17 in bit-reversed order, times the Montgomery factor 2^16, reduced to (-q/2, q/2].
const zetas: [128]i16 = blk: {
    @setEvalBranchQuota(100000);

    var table: [128]i16 = undefined;

    for (&table, 0..) |*zeta, i| {
        var power = (1 << 16) % q;

        for (0..@bitReverse(@as(u7, i))) |_| power = power * 17 % q;

        zeta.* = if (power > q / 2) power - q else power;
    }

    break :blk table;
};

// 2^32 mod q multiplies a Montgomery product back into the plain domain; 1441 is
// 2^32 / 128 mod q, the factor that completes the inverse NTT.
const montgomery_square = 1353;

const inverse_ntt_factor = 1441;

// Returns a value congruent to a * 2^-16 modulo q, in (-q, q) for |a| < 2^15 * q.
fn montgomeryReduce(a: i32) i16 {
    const t: i16 = @as(i16, @truncate(a)) *% -3327;

    return @intCast((a - @as(i32, t) * q) >> 16);
}

fn fqmul(a: i16, b: i16) i16 {
    return montgomeryReduce(@as(i32, a) * b);
}

// Returns the representative of a modulo q in [-(q - 1) / 2, (q - 1) / 2].
fn barrettReduce(a: i16) i16 {
    const v: i32 = ((1 << 26) + q / 2) / q;

    const t = (v * a + (1 << 25)) >> 26;

    return @intCast(a - t * q);
}

// Maps (-q, q) to [0, q) with a mask instead of a branch.
fn canonical(a: i16) u16 {
    return @intCast(a + ((a >> 15) & q));
}

fn reduce(f: *Poly) void {
    for (f) |*c| {
        c.* = barrettReduce(c.*);
    }
}

fn add(f: *Poly, g: *const Poly) void {
    for (f, g) |*a, b| {
        a.* += b;
    }
}

fn ntt(f: *Poly) void {
    var k: usize = 1;

    var length: usize = 128;

    while (length >= 2) : (length >>= 1) {
        var start: usize = 0;

        while (start < 256) : (start += 2 * length) {
            const zeta = zetas[k];

            k += 1;

            for (start..start + length) |j| {
                const t = fqmul(zeta, f[j + length]);

                f[j + length] = f[j] - t;

                f[j] = f[j] + t;
            }
        }
    }

    reduce(f);
}

// The output carries the factor 2^16 that cancels the 2^-16 of the preceding products.
fn inverseNtt(f: *Poly) void {
    var k: usize = 127;

    var length: usize = 2;

    while (length <= 128) : (length <<= 1) {
        var start: usize = 0;

        while (start < 256) : (start += 2 * length) {
            const zeta = zetas[k];

            k -= 1;

            for (start..start + length) |j| {
                const t = f[j];

                f[j] = barrettReduce(t + f[j + length]);

                f[j + length] = fqmul(zeta, f[j + length] - t);
            }
        }
    }

    for (f) |*c| {
        c.* = fqmul(c.*, inverse_ntt_factor);
    }
}

// The product of two degree-one residues modulo X^2 - zeta, times 2^-16.
fn basemul(r: *[2]i16, a: *const [2]i16, b: *const [2]i16, zeta: i16) void {
    r[0] = fqmul(fqmul(a[1], b[1]), zeta) + fqmul(a[0], b[0]);

    r[1] = fqmul(a[0], b[1]) + fqmul(a[1], b[0]);
}

fn multiplyAdd(r: *Poly, a: *const Poly, b: *const Poly) void {
    for (0..64) |i| {
        var product: [4]i16 = undefined;

        basemul(product[0..2], a[4 * i ..][0..2], b[4 * i ..][0..2], zetas[64 + i]);

        basemul(product[2..4], a[4 * i + 2 ..][0..2], b[4 * i + 2 ..][0..2], -zetas[64 + i]);

        for (r[4 * i ..][0..4], product) |*c, p| {
            c.* += p;
        }
    }
}

// The NTT-domain inner product of two vectors, reduced; it carries a factor 2^-16.
fn dot(comptime k: usize, a: *const [k]Poly, b: *const [k]Poly, r: *Poly) void {
    r.* = @splat(0);

    for (a, b) |*f, *g| {
        multiplyAdd(r, f, g);
    }

    reduce(r);
}

fn sampleNtt(rho: *const [32]u8, x: u8, y: u8, out: *Poly) void {
    var xof = hash.shake128.create();

    xof.update(rho);

    xof.update(&.{ x, y });

    var count: usize = 0;

    var block: [168]u8 = undefined;

    while (count < 256) {
        xof.read(&block);

        var offset: usize = 0;

        while (offset < block.len and count < 256) : (offset += 3) {
            const d1 = block[offset] | (@as(u16, block[offset + 1] & 0x0f) << 8);

            const d2 = (block[offset + 1] >> 4) | (@as(u16, block[offset + 2]) << 4);

            if (d1 < q) {
                out[count] = @intCast(d1);

                count += 1;
            }

            if (d2 < q and count < 256) {
                out[count] = @intCast(d2);

                count += 1;
            }
        }
    }
}

// The centered binomial distribution: each coefficient is the difference of the bit counts of
// two adjacent eta-bit groups.
fn sampleNoise(comptime eta: u8, seed: *const [32]u8, nonce: u8, out: *Poly) void {
    var bytes: [64 * eta]u8 = undefined;

    defer ct.wipe(&bytes);

    primitives.shake256(&.{ seed, &.{nonce} }, &bytes);

    if (eta == 2) {
        for (0..32) |i| {
            const t = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);

            const d = (t & 0x55555555) + ((t >> 1) & 0x55555555);

            for (0..8) |j| {
                const a: i16 = @intCast((d >> @intCast(4 * j)) & 3);

                const b: i16 = @intCast((d >> @intCast(4 * j + 2)) & 3);

                out[8 * i + j] = a - b;
            }
        }
    } else {
        for (0..64) |i| {
            const t = bytes[3 * i] | (@as(u32, bytes[3 * i + 1]) << 8) | (@as(u32, bytes[3 * i + 2]) << 16);

            const d = (t & 0x00249249) + ((t >> 1) & 0x00249249) + ((t >> 2) & 0x00249249);

            for (0..4) |j| {
                const a: i16 = @intCast((d >> @intCast(6 * j)) & 7);

                const b: i16 = @intCast((d >> @intCast(6 * j + 3)) & 7);

                out[4 * i + j] = a - b;
            }
        }
    }
}

fn encode12(f: *const Poly, out: *[384]u8) void {
    for (0..128) |i| {
        const a = canonical(f[2 * i]);

        const b = canonical(f[2 * i + 1]);

        out[3 * i] = @truncate(a);

        out[3 * i + 1] = @truncate((a >> 8) | (b << 4));

        out[3 * i + 2] = @truncate(b >> 4);
    }
}

// Coefficients come back unreduced, below 2^12; the arithmetic tolerates values up to 4095.
fn decode12(bytes: *const [384]u8, out: *Poly) void {
    for (0..128) |i| {
        const b0: i16 = bytes[3 * i];

        const b1: i16 = bytes[3 * i + 1];

        const b2: i16 = bytes[3 * i + 2];

        out[2 * i] = b0 | ((b1 & 0x0f) << 8);

        out[2 * i + 1] = (b1 >> 4) | (b2 << 4);
    }
}

// round(2^d * x / q) mod 2^d for x in [0, q): the floor division by q of t < 2^24 is exactly
// (t * 20642679) >> 36, so no division instruction touches the secret value.
fn compress(x: u16, comptime d: u5) u16 {
    const t = (@as(u64, x) << d) + q / 2;

    return @truncate(((t * 20642679) >> 36) & ((1 << d) - 1));
}

fn decompress(y: u16, comptime d: u5) i16 {
    return @intCast((@as(u32, y) * q + (1 << (d - 1))) >> d);
}

fn encodeCompressed(comptime d: u5, f: *const Poly, out: *[32 * @as(usize, d)]u8) void {
    var buffer: u32 = 0;

    var bits: u5 = 0;

    var index: usize = 0;

    for (f) |c| {
        buffer |= @as(u32, compress(canonical(c), d)) << bits;

        bits += d;

        while (bits >= 8) : (bits -= 8) {
            out[index] = @truncate(buffer);

            index += 1;

            buffer >>= 8;
        }
    }
}

fn decodeDecompressed(comptime d: u5, bytes: *const [32 * @as(usize, d)]u8, out: *Poly) void {
    var buffer: u32 = 0;

    var bits: u5 = 0;

    var index: usize = 0;

    for (out) |*c| {
        while (bits < d) : (bits += 8) {
            buffer |= @as(u32, bytes[index]) << bits;

            index += 1;
        }

        c.* = decompress(@truncate(buffer & ((1 << d) - 1)), d);

        buffer >>= d;

        bits -= d;
    }
}

fn fromMessage(m: *const [32]u8, out: *Poly) void {
    for (out, 0..) |*c, i| {
        const bit: i16 = (m[i / 8] >> @intCast(i % 8)) & 1;

        c.* = -bit & ((q + 1) / 2);
    }
}

fn encrypt(comptime p: Parameters, ek: *const [p.encapsulationKeySize()]u8, m: *const [32]u8, r: *const [32]u8, c: *[p.ciphertextSize()]u8) void {
    const k: usize = p.k;

    const rho = ek[384 * k ..][0..32];

    var t: [k]Poly = undefined;

    var y: [k]Poly = undefined;

    var e1: [k]Poly = undefined;

    var e2: Poly = undefined;

    var mu: Poly = undefined;

    defer {
        ct.wipe(std.mem.asBytes(&y));

        ct.wipe(std.mem.asBytes(&e1));

        ct.wipe(std.mem.asBytes(&e2));

        ct.wipe(std.mem.asBytes(&mu));
    }

    for (&t, 0..) |*f, i| {
        decode12(ek[384 * i ..][0..384], f);
    }

    for (&y, 0..) |*f, i| {
        sampleNoise(p.eta1, r, @intCast(i), f);

        ntt(f);
    }

    for (&e1, 0..) |*f, i| {
        sampleNoise(p.eta2, r, @intCast(k + i), f);
    }

    sampleNoise(p.eta2, r, 2 * k, &e2);

    for (0..k) |i| {
        var column: [k]Poly = undefined;

        for (&column, 0..) |*f, j| {
            sampleNtt(rho, @intCast(i), @intCast(j), f);
        }

        var u: Poly = undefined;

        dot(k, &column, &y, &u);

        inverseNtt(&u);

        add(&u, &e1[i]);

        reduce(&u);

        encodeCompressed(p.du, &u, c[32 * @as(usize, p.du) * i ..][0 .. 32 * @as(usize, p.du)]);
    }

    var v: Poly = undefined;

    defer ct.wipe(std.mem.asBytes(&v));

    dot(k, &t, &y, &v);

    inverseNtt(&v);

    add(&v, &e2);

    fromMessage(m, &mu);

    add(&v, &mu);

    reduce(&v);

    encodeCompressed(p.dv, &v, c[32 * @as(usize, p.du) * k ..][0 .. 32 * @as(usize, p.dv)]);
}

fn decrypt(comptime p: Parameters, dk_pke: *const [384 * @as(usize, p.k)]u8, c: *const [p.ciphertextSize()]u8, m: *[32]u8) void {
    const k: usize = p.k;

    var u: [k]Poly = undefined;

    var s: [k]Poly = undefined;

    var w: Poly = undefined;

    defer {
        ct.wipe(std.mem.asBytes(&s));

        ct.wipe(std.mem.asBytes(&w));
    }

    for (&u, 0..) |*f, i| {
        decodeDecompressed(p.du, c[32 * @as(usize, p.du) * i ..][0 .. 32 * @as(usize, p.du)], f);

        ntt(f);
    }

    for (&s, 0..) |*f, i| {
        decode12(dk_pke[384 * i ..][0..384], f);
    }

    var v: Poly = undefined;

    decodeDecompressed(p.dv, c[32 * @as(usize, p.du) * k ..][0 .. 32 * @as(usize, p.dv)], &v);

    dot(k, &s, &u, &w);

    inverseNtt(&w);

    for (&w, v) |*a, b| {
        a.* = b - a.*;
    }

    reduce(&w);

    @memset(m, 0);

    for (w, 0..) |a, i| {
        m[i / 8] |= @as(u8, @truncate(compress(canonical(a), 1))) << @intCast(i % 8);
    }
}

pub fn keyGen(comptime p: Parameters, d: *const [32]u8, z: *const [32]u8, ek: *[p.encapsulationKeySize()]u8, dk: *[p.decapsulationKeySize()]u8) void {
    const k: usize = p.k;

    var g: [64]u8 = undefined;

    var s: [k]Poly = undefined;

    var e: [k]Poly = undefined;

    defer {
        ct.wipe(&g);

        ct.wipe(std.mem.asBytes(&s));

        ct.wipe(std.mem.asBytes(&e));
    }

    primitives.digest(hash.sha3_512, &.{ d, &.{p.k} }, &g);

    const rho = g[0..32];

    const sigma = g[32..64];

    for (&s, 0..) |*f, i| {
        sampleNoise(p.eta1, sigma, @intCast(i), f);

        ntt(f);
    }

    for (&e, 0..) |*f, i| {
        sampleNoise(p.eta1, sigma, @intCast(k + i), f);

        ntt(f);
    }

    for (0..k) |i| {
        var row: [k]Poly = undefined;

        for (&row, 0..) |*f, j| {
            sampleNtt(rho, @intCast(j), @intCast(i), f);
        }

        var t: Poly = undefined;

        dot(k, &row, &s, &t);

        for (&t) |*c| {
            c.* = fqmul(c.*, montgomery_square);
        }

        add(&t, &e[i]);

        reduce(&t);

        encode12(&t, ek[384 * i ..][0..384]);
    }

    @memcpy(ek[384 * k ..], rho);

    for (&s, 0..) |*f, i| {
        encode12(f, dk[384 * i ..][0..384]);
    }

    @memcpy(dk[384 * k ..][0..ek.len], ek);

    primitives.digest(hash.sha3_256, &.{ek}, dk[768 * k + 32 ..][0..32]);

    @memcpy(dk[768 * k + 64 ..], z);
}

pub fn encaps(comptime p: Parameters, ek: *const [p.encapsulationKeySize()]u8, m: *const [32]u8, shared_secret: *[32]u8, c: *[p.ciphertextSize()]u8) void {
    var h: [32]u8 = undefined;

    primitives.digest(hash.sha3_256, &.{ek}, &h);

    var g: [64]u8 = undefined;

    defer ct.wipe(&g);

    primitives.digest(hash.sha3_512, &.{ m, &h }, &g);

    shared_secret.* = g[0..32].*;

    encrypt(p, ek, m, g[32..64], c);
}

// Implicit rejection: a ciphertext that does not re-encrypt to itself yields J(z || c), chosen
// with a mask so that the comparison result never reaches a branch.
pub fn decaps(comptime p: Parameters, dk: *const [p.decapsulationKeySize()]u8, c: *const [p.ciphertextSize()]u8) [32]u8 {
    const k: usize = p.k;

    const ek = dk[384 * k ..][0..p.encapsulationKeySize()];

    const h = dk[768 * k + 32 ..][0..32];

    const z = dk[768 * k + 64 ..][0..32];

    var m: [32]u8 = undefined;

    var g: [64]u8 = undefined;

    var rejected: [32]u8 = undefined;

    var again: [p.ciphertextSize()]u8 = undefined;

    defer {
        ct.wipe(&m);

        ct.wipe(&g);

        ct.wipe(&rejected);

        ct.wipe(&again);
    }

    decrypt(p, dk[0 .. 384 * k], c, &m);

    primitives.digest(hash.sha3_512, &.{ &m, h }, &g);

    primitives.shake256(&.{ z, c }, &rejected);

    encrypt(p, ek, &m, g[32..64], &again);

    var shared_secret: [32]u8 = undefined;

    ct.select(ct.equalMask(c, &again), g[0..32], &rejected, &shared_secret);

    return shared_secret;
}

// FIPS 203, 7.2: every coefficient of the encoded vector must already be reduced modulo q.
pub fn checkEncapsulationKey(comptime p: Parameters, ek: *const [p.encapsulationKeySize()]u8) bool {
    for (0..p.k) |i| {
        var f: Poly = undefined;

        decode12(ek[384 * i ..][0..384], &f);

        for (f) |c| {
            if (c >= q) return false;
        }
    }

    return true;
}

pub fn checkDecapsulationKey(comptime p: Parameters, dk: *const [p.decapsulationKeySize()]u8) bool {
    const k: usize = p.k;

    const ek = dk[384 * k ..][0..p.encapsulationKeySize()];

    var h: [32]u8 = undefined;

    primitives.digest(hash.sha3_256, &.{ek}, &h);

    return checkEncapsulationKey(p, ek) and ct.equal(&h, dk[768 * k + 32 ..][0..32]);
}

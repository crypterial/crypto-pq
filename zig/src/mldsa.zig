const std = @import("std");

const ct = @import("ct.zig");
const hash = @import("hash.zig");
const primitives = @import("primitives.zig");

pub const Parameters = struct {
    k: u8,
    l: u8,
    eta: u8,
    tau: u16,
    lambda: u16,
    gamma1: i32,
    gamma2: i32,
    omega: u16,

    pub inline fn beta(comptime self: Parameters) i32 {
        return @as(i32, self.tau) * self.eta;
    }

    pub inline fn etaBits(comptime self: Parameters) u5 {
        return if (self.eta == 2) 3 else 4;
    }

    pub inline fn gamma1Bits(comptime self: Parameters) u5 {
        return if (self.gamma1 == 1 << 17) 18 else 20;
    }

    pub inline fn w1Bits(comptime self: Parameters) u5 {
        return if (self.gamma2 == (q - 1) / 88) 6 else 4;
    }

    pub inline fn publicKeySize(comptime self: Parameters) usize {
        return 32 + 320 * @as(usize, self.k);
    }

    pub inline fn privateKeySize(comptime self: Parameters) usize {
        return 128 + 32 * ((@as(usize, self.k) + self.l) * self.etaBits() + d * @as(usize, self.k));
    }

    pub inline fn signatureSize(comptime self: Parameters) usize {
        return self.lambda / 4 + 32 * @as(usize, self.l) * self.gamma1Bits() + self.omega + self.k;
    }
};

const q: i32 = 8380417;

const d = 13;

pub const ml_dsa_44: Parameters = .{ .k = 4, .l = 4, .eta = 2, .tau = 39, .lambda = 128, .gamma1 = 1 << 17, .gamma2 = (q - 1) / 88, .omega = 80 };

pub const ml_dsa_65: Parameters = .{ .k = 6, .l = 5, .eta = 4, .tau = 49, .lambda = 192, .gamma1 = 1 << 19, .gamma2 = (q - 1) / 32, .omega = 55 };

pub const ml_dsa_87: Parameters = .{ .k = 8, .l = 7, .eta = 2, .tau = 60, .lambda = 256, .gamma1 = 1 << 19, .gamma2 = (q - 1) / 32, .omega = 75 };

const Poly = [256]i32;

// Powers of 1753 in bit-reversed order, times the Montgomery factor 2^32, reduced to (-q/2, q/2].
const zetas: [256]i32 = blk: {
    @setEvalBranchQuota(100000);

    var powers: [256]i64 = undefined;

    powers[0] = 1;

    for (1..256) |i| powers[i] = powers[i - 1] * 1753 % q;

    var table: [256]i32 = undefined;

    for (&table, 0..) |*zeta, i| {
        const value = (1 << 32) % @as(i64, q) * powers[@bitReverse(@as(u8, i))] % q;

        zeta.* = if (value > (q - 1) / 2) value - q else value;
    }

    break :blk table;
};

// 2^64 / 256 mod q completes the inverse NTT and leaves the factor 2^32.
const inverse_ntt_factor = 41978;

// Returns a value congruent to a * 2^-32 modulo q, in (-q, q) for |a| < 2^31 * q.
fn montgomeryReduce(a: i64) i32 {
    const t: i32 = @as(i32, @truncate(a)) *% 58728449;

    return @intCast((a - @as(i64, t) * q) >> 32);
}

// A representative of a modulo q with |r| <= 6283009, for |a| < 2^31 - 2^22.
fn reduce32(a: i32) i32 {
    const t = (a + (1 << 22)) >> 23;

    return a - t * q;
}

fn addQIfNegative(a: i32) i32 {
    return a + ((a >> 31) & q);
}

// The standard representative in [0, q).
fn freeze(a: i32) i32 {
    return addQIfNegative(reduce32(a));
}

// The representative in [-(q - 1) / 2, (q - 1) / 2] of a standard representative.
fn centered(a: i32) i32 {
    return a - (q & (((q - 1) / 2 - a) >> 31));
}

fn absolute(a: i32) i32 {
    const mask = a >> 31;

    return (a ^ mask) - mask;
}

fn ntt(f: *Poly) void {
    var k: usize = 0;

    var length: usize = 128;

    while (length > 0) : (length >>= 1) {
        var start: usize = 0;

        while (start < 256) : (start += 2 * length) {
            k += 1;

            const zeta: i64 = zetas[k];

            for (start..start + length) |j| {
                const t = montgomeryReduce(zeta * f[j + length]);

                f[j + length] = f[j] - t;

                f[j] = f[j] + t;
            }
        }
    }
}

// Inputs must be below q in absolute value; the output carries the factor 2^32 that cancels the
// 2^-32 of the preceding Montgomery products.
fn inverseNtt(f: *Poly) void {
    var k: usize = 256;

    var length: usize = 1;

    while (length < 256) : (length <<= 1) {
        var start: usize = 0;

        while (start < 256) : (start += 2 * length) {
            k -= 1;

            const zeta: i64 = -zetas[k];

            for (start..start + length) |j| {
                const t = f[j];

                f[j] = t + f[j + length];

                f[j + length] = montgomeryReduce(zeta * (t - f[j + length]));
            }
        }
    }

    for (f) |*c| {
        c.* = montgomeryReduce(@as(i64, inverse_ntt_factor) * c.*);
    }
}

fn pointwise(a: *const Poly, b: *const Poly, out: *Poly) void {
    for (out, a, b) |*c, x, y| {
        c.* = montgomeryReduce(@as(i64, x) * y);
    }
}

// The NTT-domain inner product of a matrix row with a vector, reduced below q.
fn dot(comptime n: usize, row: *const [n]Poly, vector: *const [n]Poly, out: *Poly) void {
    out.* = @splat(0);

    for (row, vector) |*f, *g| {
        for (out, f, g) |*c, x, y| {
            c.* += montgomeryReduce(@as(i64, x) * y);
        }
    }

    for (out) |*c| {
        c.* = reduce32(c.*);
    }
}

fn freezeAll(f: *Poly) void {
    for (f) |*c| {
        c.* = freeze(c.*);
    }
}

fn power2Round(r: i32) struct { i32, i32 } {
    const r1 = (r + (1 << (d - 1)) - 1) >> d;

    return .{ r1, r - (r1 << d) };
}

// FIPS 204, Algorithm 36, for a standard representative: r1 = (r - r0) / (2 * gamma2) with
// r0 = r mod± 2 * gamma2, except that r - r0 = q - 1 gives r1 = 0 and r0 - 1. Computed with
// multiplications and masks.
fn decompose(comptime gamma2: i32, r: i32) struct { i32, i32 } {
    var r1 = (r + 127) >> 7;

    if (gamma2 == (q - 1) / 32) {
        r1 = ((r1 * 1025 + (1 << 21)) >> 22) & 15;
    } else {
        r1 = (r1 * 11275 + (1 << 23)) >> 24;

        r1 ^= ((43 - r1) >> 31) & r1;
    }

    var r0 = r - r1 * 2 * gamma2;

    r0 -= (((q - 1) / 2 - r0) >> 31) & q;

    return .{ r1, r0 };
}

fn useHint(comptime gamma2: i32, hint: bool, r: i32) i32 {
    const m = (q - 1) / (2 * gamma2);

    const r1, const r0 = decompose(gamma2, r);

    if (!hint) return r1;

    return if (r0 > 0) @mod(r1 + 1, m) else @mod(r1 - 1, m);
}

fn pack(comptime bits: u5, values: *const [256]u32, out: *[32 * @as(usize, bits)]u8) void {
    var buffer: u64 = 0;

    var filled: u6 = 0;

    var index: usize = 0;

    for (values) |value| {
        buffer |= @as(u64, value) << filled;

        filled += bits;

        while (filled >= 8) : (filled -= 8) {
            out[index] = @truncate(buffer);

            index += 1;

            buffer >>= 8;
        }
    }
}

fn unpack(comptime bits: u5, bytes: *const [32 * @as(usize, bits)]u8, out: *[256]u32) void {
    var buffer: u64 = 0;

    var filled: u6 = 0;

    var index: usize = 0;

    for (out) |*value| {
        while (filled < bits) : (filled += 8) {
            buffer |= @as(u64, bytes[index]) << filled;

            index += 1;
        }

        value.* = @truncate(buffer & ((1 << bits) - 1));

        buffer >>= bits;

        filled -= bits;
    }
}

// Coefficients in [-a, b] are stored as b - x.
fn bitPack(comptime bits: u5, comptime b: i32, f: *const Poly, out: *[32 * @as(usize, bits)]u8) void {
    var values: [256]u32 = undefined;

    defer ct.wipe(std.mem.asBytes(&values));

    for (&values, f) |*value, c| {
        value.* = @intCast(b - c);
    }

    pack(bits, &values, out);
}

fn bitUnpack(comptime bits: u5, comptime b: i32, bytes: *const [32 * @as(usize, bits)]u8, f: *Poly) void {
    var values: [256]u32 = undefined;

    defer ct.wipe(std.mem.asBytes(&values));

    unpack(bits, bytes, &values);

    for (f, values) |*c, value| {
        c.* = b - @as(i32, @intCast(value));
    }
}

fn rejectionNttPoly(rho: *const [32]u8, s: u8, r: u8, out: *Poly) void {
    var xof = hash.shake128.create();

    xof.update(rho);

    xof.update(&.{ s, r });

    var count: usize = 0;

    var block: [168]u8 = undefined;

    while (count < 256) {
        xof.read(&block);

        var offset: usize = 0;

        while (offset < block.len and count < 256) : (offset += 3) {
            const z = block[offset] | (@as(i32, block[offset + 1]) << 8) | (@as(i32, block[offset + 2] & 0x7f) << 16);

            if (z < q) {
                out[count] = z;

                count += 1;
            }
        }
    }
}

// FIPS 204, Algorithm 31, on the secret seed: every candidate is written and the count advances
// by a mask, so the accepted values never steer a branch; only the loop end depends on them.
fn rejectionBoundedPoly(comptime eta: u8, rho: *const [64]u8, r: u16, out: *Poly) void {
    var xof = hash.shake256.create();

    defer ct.wipe(std.mem.asBytes(&xof));

    xof.update(rho);

    var nonce: [2]u8 = undefined;

    std.mem.writeInt(u16, &nonce, r, .little);

    xof.update(&nonce);

    var buffer: [257]i32 = undefined;

    defer ct.wipe(std.mem.asBytes(&buffer));

    var count: usize = 0;

    var block: [136]u8 = undefined;

    defer ct.wipe(&block);

    while (count < 256) {
        xof.read(&block);

        for (block) |byte| {
            for ([2]i32{ byte & 0x0f, byte >> 4 }) |half| {
                const accepted: usize = @intFromBool(if (eta == 2) half < 15 else half < 9);

                // half mod 5 is half - 5 * floor(205 * half / 1024) for half < 15.
                buffer[count] = if (eta == 2) 2 - (half - 5 * ((205 * half) >> 10)) else 4 - half;

                count += accepted & @intFromBool(count < 256);
            }
        }
    }

    out.* = buffer[0..256].*;
}

fn expandRow(comptime p: Parameters, rho: *const [32]u8, r: usize, row: *[p.l]Poly) void {
    for (row, 0..) |*f, s| {
        rejectionNttPoly(rho, @intCast(s), @intCast(r), f);
    }
}

fn expandMask(comptime p: Parameters, rho: *const [64]u8, kappa: u16, y: *[p.l]Poly) void {
    const bits = p.gamma1Bits();

    for (y, 0..) |*f, r| {
        var bytes: [32 * @as(usize, bits)]u8 = undefined;

        defer ct.wipe(&bytes);

        var nonce: [2]u8 = undefined;

        std.mem.writeInt(u16, &nonce, kappa + @as(u16, @intCast(r)), .little);

        primitives.shake256(&.{ rho, &nonce }, &bytes);

        bitUnpack(bits, p.gamma1, &bytes, f);
    }
}

fn sampleInBall(comptime p: Parameters, seed: []const u8, c: *Poly) void {
    var xof = hash.shake256.create();

    xof.update(seed);

    var sign_bytes: [8]u8 = undefined;

    xof.read(&sign_bytes);

    var signs = std.mem.readInt(u64, &sign_bytes, .little);

    c.* = @splat(0);

    for (256 - @as(usize, p.tau)..256) |i| {
        var j: [1]u8 = undefined;

        xof.read(&j);

        while (j[0] > i) xof.read(&j);

        c[i] = c[j[0]];

        c[j[0]] = 1 - 2 * @as(i32, @intCast(signs & 1));

        signs >>= 1;
    }
}

fn w1Encode(comptime p: Parameters, w1: *const [p.k]Poly, out: *[32 * @as(usize, p.k) * p.w1Bits()]u8) void {
    const size = 32 * @as(usize, p.w1Bits());

    for (w1, 0..) |*f, i| {
        var values: [256]u32 = undefined;

        for (&values, f) |*value, c| {
            value.* = @intCast(c);
        }

        pack(p.w1Bits(), &values, out[size * i ..][0..size]);
    }
}

fn challengeHash(comptime p: Parameters, mu: *const [64]u8, w1: *const [p.k]Poly, out: *[p.lambda / 4]u8) void {
    var encoded: [32 * @as(usize, p.k) * p.w1Bits()]u8 = undefined;

    w1Encode(p, w1, &encoded);

    primitives.shake256(&.{ mu, &encoded }, out);
}

fn encodePublicKey(comptime p: Parameters, rho: *const [32]u8, t1: *const [p.k]Poly, pk: *[p.publicKeySize()]u8) void {
    pk[0..32].* = rho.*;

    for (t1, 0..) |*f, i| {
        var values: [256]u32 = undefined;

        for (&values, f) |*value, c| {
            value.* = @intCast(c);
        }

        pack(10, &values, pk[32 + 320 * i ..][0..320]);
    }
}

// The public t = A * s1 + s2, in standard representatives.
fn publicT(comptime p: Parameters, rho: *const [32]u8, s1: *const [p.l]Poly, s2: *const [p.k]Poly, t: *[p.k]Poly) void {
    var s1_hat = s1.*;

    defer ct.wipe(std.mem.asBytes(&s1_hat));

    for (&s1_hat) |*f| ntt(f);

    for (t, 0..) |*f, i| {
        var row: [p.l]Poly = undefined;

        expandRow(p, rho, i, &row);

        dot(p.l, &row, &s1_hat, f);

        inverseNtt(f);

        for (f, s2[i]) |*c, e| {
            c.* = freeze(c.* + e);
        }
    }
}

fn SecretParts(comptime p: Parameters) type {
    return struct {
        rho: [32]u8,
        key: [32]u8,
        tr: [64]u8,
        s1: [p.l]Poly,
        s2: [p.k]Poly,
        t0: [p.k]Poly,

        fn wipe(self: *@This()) void {
            ct.wipe(std.mem.asBytes(self));
        }
    };
}

fn encodePrivateKey(comptime p: Parameters, parts: *const SecretParts(p), sk: *[p.privateKeySize()]u8) void {
    const eta_size = 32 * @as(usize, p.etaBits());

    sk[0..32].* = parts.rho;

    sk[32..64].* = parts.key;

    sk[64..128].* = parts.tr;

    var offset: usize = 128;

    for ([_][]const Poly{ &parts.s1, &parts.s2 }) |vector| {
        for (vector) |*f| {
            bitPack(p.etaBits(), p.eta, f, sk[offset..][0..eta_size]);

            offset += eta_size;
        }
    }

    for (&parts.t0) |*f| {
        bitPack(d, 1 << (d - 1), f, sk[offset..][0 .. 32 * d]);

        offset += 32 * d;
    }
}

fn decodePrivateKey(comptime p: Parameters, sk: *const [p.privateKeySize()]u8, parts: *SecretParts(p)) void {
    const eta_size = 32 * @as(usize, p.etaBits());

    parts.rho = sk[0..32].*;

    parts.key = sk[32..64].*;

    parts.tr = sk[64..128].*;

    var offset: usize = 128;

    for (&parts.s1) |*f| {
        bitUnpack(p.etaBits(), p.eta, sk[offset..][0..eta_size], f);

        offset += eta_size;
    }

    for (&parts.s2) |*f| {
        bitUnpack(p.etaBits(), p.eta, sk[offset..][0..eta_size], f);

        offset += eta_size;
    }

    for (&parts.t0) |*f| {
        bitUnpack(d, 1 << (d - 1), sk[offset..][0 .. 32 * d], f);

        offset += 32 * d;
    }
}

pub fn keyGen(comptime p: Parameters, seed: *const [32]u8, pk: *[p.publicKeySize()]u8, sk: *[p.privateKeySize()]u8) void {
    var expanded: [128]u8 = undefined;

    var parts: SecretParts(p) = undefined;

    var t: [p.k]Poly = undefined;

    defer {
        ct.wipe(&expanded);

        parts.wipe();

        ct.wipe(std.mem.asBytes(&t));
    }

    primitives.shake256(&.{ seed, &.{ p.k, p.l } }, &expanded);

    parts.rho = expanded[0..32].*;

    parts.key = expanded[96..128].*;

    for (&parts.s1, 0..) |*f, r| {
        rejectionBoundedPoly(p.eta, expanded[32..96], @intCast(r), f);
    }

    for (&parts.s2, 0..) |*f, r| {
        rejectionBoundedPoly(p.eta, expanded[32..96], @intCast(p.l + r), f);
    }

    publicT(p, &parts.rho, &parts.s1, &parts.s2, &t);

    var t1: [p.k]Poly = undefined;

    for (&t, &t1, &parts.t0) |*f, *high, *low| {
        for (f, high, low) |c, *r1, *r0| {
            r1.*, r0.* = power2Round(c);
        }
    }

    encodePublicKey(p, &parts.rho, &t1, pk);

    primitives.shake256(&.{pk}, &parts.tr);

    encodePrivateKey(p, &parts, sk);
}

// An expanded private key carries everything needed to rebuild the public key, so a key whose
// parts disagree is rejected instead of producing signatures that never verify. The checks
// accumulate differences so that the secret values do not decide any branch.
pub fn checkPrivateKey(comptime p: Parameters, sk: *const [p.privateKeySize()]u8, pk: *[p.publicKeySize()]u8) bool {
    var parts: SecretParts(p) = undefined;

    var t: [p.k]Poly = undefined;

    defer {
        parts.wipe();

        ct.wipe(std.mem.asBytes(&t));
    }

    decodePrivateKey(p, sk, &parts);

    var invalid: i32 = 0;

    for ([_][]const Poly{ &parts.s1, &parts.s2 }) |vector| {
        for (vector) |f| {
            for (f) |c| {
                invalid |= p.eta - absolute(c);
            }
        }
    }

    publicT(p, &parts.rho, &parts.s1, &parts.s2, &t);

    var t1: [p.k]Poly = undefined;

    for (&t, &t1, &parts.t0) |*f, *high, low| {
        for (f, high, low) |c, *r1, expected| {
            const r0 = power2Round(c)[1];

            r1.* = power2Round(c)[0];

            invalid |= -absolute(r0 - expected);
        }
    }

    encodePublicKey(p, &parts.rho, &t1, pk);

    var tr: [64]u8 = undefined;

    primitives.shake256(&.{pk}, &tr);

    const barrier: *volatile i32 = &invalid;

    return barrier.* >= 0 and ct.equal(&tr, &parts.tr);
}

pub fn sign(comptime p: Parameters, sk: *const [p.privateKeySize()]u8, message: []const []const u8, rnd: *const [32]u8, signature: *[p.signatureSize()]u8) void {
    const k = p.k;

    const l = p.l;

    var parts: SecretParts(p) = undefined;

    var mu: [64]u8 = undefined;

    var rho_prime: [64]u8 = undefined;

    var y: [l]Poly = undefined;

    var cs1: [l]Poly = undefined;

    var cs2: [k]Poly = undefined;

    var ct0: [k]Poly = undefined;

    var u: [k]Poly = undefined;

    defer {
        parts.wipe();

        ct.wipe(&rho_prime);

        inline for (.{ &y, &cs1, &cs2, &ct0, &u }) |vector| {
            ct.wipe(std.mem.asBytes(vector));
        }
    }

    decodePrivateKey(p, sk, &parts);

    for (&parts.s1) |*f| ntt(f);

    for (&parts.s2) |*f| ntt(f);

    for (&parts.t0) |*f| ntt(f);

    var a: [k][l]Poly = undefined;

    for (&a, 0..) |*row, r| {
        expandRow(p, &parts.rho, r, row);
    }

    var mu_hasher = hash.shake256.create();

    mu_hasher.update(&parts.tr);

    for (message) |part| {
        mu_hasher.update(part);
    }

    mu_hasher.read(&mu);

    primitives.shake256(&.{ &parts.key, rnd, &mu }, &rho_prime);

    var kappa: u16 = 0;

    while (true) : (kappa += l) {
        expandMask(p, &rho_prime, kappa, &y);

        var y_hat = y;

        defer ct.wipe(std.mem.asBytes(&y_hat));

        for (&y_hat) |*f| ntt(f);

        var w: [k]Poly = undefined;

        var w1: [k]Poly = undefined;

        defer {
            ct.wipe(std.mem.asBytes(&w));

            ct.wipe(std.mem.asBytes(&w1));
        }

        for (&w, &w1, &a) |*f, *high, *row| {
            dot(l, row, &y_hat, f);

            inverseNtt(f);

            freezeAll(f);

            for (f, high) |c, *r1| {
                r1.* = decompose(p.gamma2, c)[0];
            }
        }

        const c_tilde = signature[0 .. p.lambda / 4];

        challengeHash(p, &mu, &w1, c_tilde);

        var c_hat: Poly = undefined;

        sampleInBall(p, c_tilde, &c_hat);

        ntt(&c_hat);

        var invalid: i32 = 0;

        for (&cs1, &parts.s1, &y) |*f, *s, *mask| {
            pointwise(&c_hat, s, f);

            inverseNtt(f);

            for (f, mask) |*c, m| {
                c.* = centered(freeze(c.* + m));

                invalid |= (p.gamma1 - p.beta() - 1) - absolute(c.*);
            }
        }

        for (&cs2, &parts.s2, &w, &u) |*f, *s, *wf, *uf| {
            pointwise(&c_hat, s, f);

            inverseNtt(f);

            for (f, wf, uf) |c, wc, *uc| {
                uc.* = freeze(wc - c);

                invalid |= (p.gamma2 - p.beta() - 1) - absolute(decompose(p.gamma2, uc.*)[1]);
            }
        }

        var hints: u32 = 0;

        var h: [k][256]bool = undefined;

        for (&ct0, &parts.t0, &u, &h) |*f, *t, *uf, *hf| {
            pointwise(&c_hat, t, f);

            inverseNtt(f);

            for (f, uf, hf) |*c, uc, *hc| {
                c.* = centered(freeze(c.*));

                invalid |= (p.gamma2 - 1) - absolute(c.*);

                // MakeHint(-ct0, w - cs2 + ct0): whether adding ct0 moves the high bits.
                const moved = decompose(p.gamma2, freeze(uc + c.*))[0] ^ decompose(p.gamma2, uc)[0];

                const bit: u32 = @intCast(((moved | -moved) >> 31) & 1);

                hc.* = bit != 0;

                hints += bit;
            }
        }

        const barrier: *volatile i32 = &invalid;

        if (barrier.* < 0 or hints > p.omega) continue;

        encodeSignature(p, &cs1, &h, signature);

        return;
    }
}

fn encodeSignature(comptime p: Parameters, z: *const [p.l]Poly, h: *const [p.k][256]bool, signature: *[p.signatureSize()]u8) void {
    const bits = p.gamma1Bits();

    var offset: usize = p.lambda / 4;

    for (z) |*f| {
        bitPack(bits, p.gamma1, f, signature[offset..][0 .. 32 * @as(usize, bits)]);

        offset += 32 * @as(usize, bits);
    }

    const hint = signature[offset..][0 .. p.omega + p.k];

    @memset(hint, 0);

    var index: usize = 0;

    for (h, 0..) |row, i| {
        for (row, 0..) |bit, j| {
            if (bit) {
                hint[index] = @intCast(j);

                index += 1;
            }
        }

        hint[p.omega + i] = @intCast(index);
    }
}

// FIPS 204, Algorithm 21: the encoding must be canonical (strictly increasing indices, zero
// padding), otherwise the signature is rejected.
fn decodeHint(comptime p: Parameters, data: *const [p.omega + p.k]u8, h: *[p.k][256]bool) bool {
    for (h) |*row| row.* = @splat(false);

    var index: usize = 0;

    for (h, 0..) |*row, i| {
        const end = data[p.omega + i];

        if (end < index or end > p.omega) return false;

        const first = index;

        while (index < end) : (index += 1) {
            if (index > first and data[index - 1] >= data[index]) return false;

            row[data[index]] = true;
        }
    }

    for (data[index..p.omega]) |byte| {
        if (byte != 0) return false;
    }

    return true;
}

pub fn verify(comptime p: Parameters, pk: *const [p.publicKeySize()]u8, message: []const []const u8, signature: *const [p.signatureSize()]u8) bool {
    const k = p.k;

    const l = p.l;

    const bits = p.gamma1Bits();

    const rho = pk[0..32];

    const c_tilde = signature[0 .. p.lambda / 4];

    var z: [l]Poly = undefined;

    var offset: usize = p.lambda / 4;

    for (&z) |*f| {
        bitUnpack(bits, p.gamma1, signature[offset..][0 .. 32 * @as(usize, bits)], f);

        offset += 32 * @as(usize, bits);

        for (f) |c| {
            if (absolute(c) >= p.gamma1 - p.beta()) return false;
        }
    }

    var h: [k][256]bool = undefined;

    if (!decodeHint(p, signature[offset..][0 .. p.omega + p.k], &h)) return false;

    var tr: [64]u8 = undefined;

    primitives.shake256(&.{pk}, &tr);

    var mu: [64]u8 = undefined;

    var mu_hasher = hash.shake256.create();

    mu_hasher.update(&tr);

    for (message) |part| {
        mu_hasher.update(part);
    }

    mu_hasher.read(&mu);

    var c_hat: Poly = undefined;

    sampleInBall(p, c_tilde, &c_hat);

    ntt(&c_hat);

    for (&z) |*f| ntt(f);

    var w1: [k]Poly = undefined;

    for (&w1, 0..) |*f, i| {
        var row: [l]Poly = undefined;

        expandRow(p, rho, i, &row);

        dot(l, &row, &z, f);

        var t1: [256]u32 = undefined;

        unpack(10, pk[32 + 320 * i ..][0..320], &t1);

        var ct1: Poly = undefined;

        for (&ct1, t1) |*c, value| {
            c.* = @intCast(value << d);
        }

        ntt(&ct1);

        pointwise(&c_hat, &ct1, &ct1);

        for (f, ct1) |*c, x| {
            c.* = reduce32(c.* - x);
        }

        inverseNtt(f);

        for (f, h[i]) |*c, hint| {
            c.* = useHint(p.gamma2, hint, freeze(c.*));
        }
    }

    var expected: [p.lambda / 4]u8 = undefined;

    challengeHash(p, &mu, &w1, &expected);

    return std.mem.eql(u8, &expected, c_tilde);
}

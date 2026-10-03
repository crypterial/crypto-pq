const std = @import("std");

const ct = @import("ct.zig");
const hash = @import("hash.zig");
const keccak = @import("keccak.zig");
const primitives = @import("primitives.zig");
const vec = @import("vector.zig");

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

// Coefficients are processed eight at a time; every lane computes exactly what the scalar
// formulas compute, so the results do not depend on the vector width.
const V = @Vector(8, i32);

// q^-1 modulo 2^32.
const q_inverse = 58728449;

fn splat(value: i32) V {
    return @splat(value);
}

fn shiftRight(a: V, comptime r: u5) V {
    return a >> @splat(r);
}

// A representative of a modulo q with |r| <= 6283009, for |a| < 2^31 - 2^22.
fn reduce32(a: V) V {
    return a - shiftRight(a + splat(1 << 22), 23) * splat(q);
}

fn addQIfNegative(a: V) V {
    return a + (shiftRight(a, 31) & splat(q));
}

// The standard representative in [0, q).
fn freeze(a: V) V {
    return addQIfNegative(reduce32(a));
}

// The representative in [-(q - 1) / 2, (q - 1) / 2] of a standard representative.
fn centered(a: V) V {
    return a - (splat(q) & shiftRight(splat((q - 1) / 2) - a, 31));
}

fn absolute(a: V) V {
    const mask = shiftRight(a, 31);

    return (a ^ mask) - mask;
}

fn load(f: *const Poly, i: usize) V {
    return f[i..][0..8].*;
}

fn store(f: *Poly, i: usize, value: V) void {
    f[i..][0..8].* = value;
}

fn mulHigh(a: V, b: V) V {
    const Wide = @Vector(8, i64);

    return @truncate(@as(Wide, a) * @as(Wide, b) >> @splat(32));
}

// a * b * 2^-32 modulo q, given b_qinv = b * q^-1 mod 2^32: the low halves of a * b and t * q
// agree, so the difference of the high halves is the exact quotient.
fn montgomery(a: V, b: V, b_qinv: V) V {
    return mulHigh(a, b) - mulHigh(a *% b_qinv, splat(q));
}

fn montgomeryProduct(a: V, b: V) V {
    return montgomery(a, b, b *% splat(q_inverse));
}

fn timesQInverse(comptime table: anytype) @TypeOf(table) {
    var out = table;

    for (&out) |*value| value.* *%= if (@TypeOf(value.*) == V) splat(q_inverse) else q_inverse;

    return out;
}

const zetas_qinv = timesQInverse(zetas);

// The last three forward layers, and the first three inverse layers, run inside 16-coefficient
// chunks held in two vectors; their zetas are laid out per chunk in the lane order used there.
// Layer `step` pairs coefficients `step` apart, so a block holds 2 * step coefficients.
fn chunkZetas(comptime inverse: bool, comptime step: usize) [16]V {
    var out: [16]V = undefined;

    for (&out, 0..) |*chunk, c| {
        var lanes: [8]i32 = undefined;

        for (&lanes, 0..) |*lane, i| {
            const block = c * (8 / step) + i / step;

            lane.* = if (inverse) -zetas[256 / step - 1 - block] else zetas[128 / step + block];
        }

        chunk.* = lanes;
    }

    return out;
}

const Chunk = struct {
    zeta: [16]V,
    zeta_qinv: [16]V,

    fn init(comptime inverse: bool, comptime step: usize) Chunk {
        @setEvalBranchQuota(100000);

        const zeta = chunkZetas(inverse, step);

        return .{ .zeta = zeta, .zeta_qinv = timesQInverse(zeta) };
    }
};

const forward_chunks = [3]Chunk{ .init(false, 4), .init(false, 2), .init(false, 1) };

const inverse_chunks = [3]Chunk{ .init(true, 1), .init(true, 2), .init(true, 4) };

fn ntt(f: *Poly) void {
    var k: usize = 0;

    inline for ([_]usize{ 128, 64, 32, 16, 8 }) |length| {
        var start: usize = 0;

        while (start < 256) : (start += 2 * length) {
            k += 1;

            const zeta = splat(zetas[k]);

            const zeta_qinv = splat(zetas_qinv[k]);

            var j = start;

            while (j < start + length) : (j += 8) {
                const a = load(f, j);

                const t = montgomery(load(f, j + length), zeta, zeta_qinv);

                store(f, j + length, a - t);

                store(f, j, a + t);
            }
        }
    }

    for (0..16) |c| {
        var a = load(f, 16 * c);

        var b = load(f, 16 * c + 8);

        inline for (forward_chunks, [_]usize{ 4, 2, 1 }) |chunk, step| {
            const x, const y = vec.split(step, a, b);

            const t = montgomery(y, chunk.zeta[c], chunk.zeta_qinv[c]);

            a, b = vec.join(step, x + t, x - t);
        }

        store(f, 16 * c, a);

        store(f, 16 * c + 8, b);
    }
}

// Inputs must be below q in absolute value; the output carries the factor 2^32 that cancels the
// 2^-32 of the preceding Montgomery products.
fn inverseNtt(f: *Poly) void {
    for (0..16) |c| {
        var a = load(f, 16 * c);

        var b = load(f, 16 * c + 8);

        inline for (inverse_chunks, [_]usize{ 1, 2, 4 }) |chunk, step| {
            const x, const y = vec.split(step, a, b);

            a, b = vec.join(step, x + y, montgomery(x - y, chunk.zeta[c], chunk.zeta_qinv[c]));
        }

        store(f, 16 * c, a);

        store(f, 16 * c + 8, b);
    }

    var k: usize = 32;

    inline for ([_]usize{ 8, 16, 32, 64 }) |length| {
        var start: usize = 0;

        while (start < 256) : (start += 2 * length) {
            k -= 1;

            const zeta = splat(-zetas[k]);

            const zeta_qinv = splat(-zetas[k] *% q_inverse);

            var j = start;

            while (j < start + length) : (j += 8) {
                const a = load(f, j);

                const b = load(f, j + length);

                store(f, j, a + b);

                store(f, j + length, montgomery(a - b, zeta, zeta_qinv));
            }
        }
    }

    // The last layer and the final factor share one pass: the differences take the product of
    // -zeta_1 and the factor as one Montgomery constant. The results are congruent to those of two
    // separate products, and every caller reduces them to standard representatives.
    const factor = splat(inverse_ntt_factor);

    const factor_qinv = splat(@as(i32, inverse_ntt_factor) *% q_inverse);

    const last = splat(last_factor);

    const last_qinv = splat(last_factor *% q_inverse);

    for (0..16) |i| {
        const a = load(f, 8 * i);

        const b = load(f, 8 * i + 128);

        store(f, 8 * i, montgomery(a + b, factor, factor_qinv));

        store(f, 8 * i + 128, montgomery(a - b, last, last_qinv));
    }
}

// -zeta_1 * inverse_ntt_factor * 2^-32 modulo q.
const last_factor: i32 = blk: {
    const product: i64 = @as(i64, -zetas[1]) * inverse_ntt_factor;

    const t: i32 = @as(i32, @truncate(product)) *% q_inverse;

    break :blk @intCast((product - @as(i64, t) * q) >> 32);
};

fn pointwise(a: *const Poly, b: *const Poly, out: *Poly) void {
    for (0..32) |i| store(out, 8 * i, montgomeryProduct(load(a, 8 * i), load(b, 8 * i)));
}

// The NTT-domain inner product of a matrix row with a vector, reduced below q.
fn dot(comptime n: usize, row: *const [n]Poly, vector: *const [n]Poly, out: *Poly) void {
    for (0..32) |i| {
        var sum = splat(0);

        for (row, vector) |*f, *g| {
            sum += montgomeryProduct(load(f, 8 * i), load(g, 8 * i));
        }

        store(out, 8 * i, reduce32(sum));
    }
}

fn power2Round(r: V) struct { V, V } {
    const r1 = shiftRight(r + splat((1 << (d - 1)) - 1), d);

    return .{ r1, r - r1 * splat(1 << d) };
}

// FIPS 204, Algorithm 36, for a standard representative: r1 = (r - r0) / (2 * gamma2) with
// r0 = r mod± 2 * gamma2, except that r - r0 = q - 1 gives r1 = 0 and r0 - 1. Computed with
// multiplications and masks.
fn decompose(comptime gamma2: i32, r: V) struct { V, V } {
    var r1 = shiftRight(r + splat(127), 7);

    if (gamma2 == (q - 1) / 32) {
        r1 = shiftRight(r1 * splat(1025) + splat(1 << 21), 22) & splat(15);
    } else {
        r1 = shiftRight(r1 * splat(11275) + splat(1 << 23), 24);

        r1 ^= shiftRight(splat(43) - r1, 31) & r1;
    }

    var r0 = r - r1 * splat(2 * gamma2);

    r0 -= shiftRight(splat((q - 1) / 2) - r0, 31) & splat(q);

    return .{ r1, r0 };
}

// FIPS 204, Algorithm 40, on public values: r1 moves by one step modulo m where the hint is set.
fn useHint(comptime gamma2: i32, hint: @Vector(8, bool), r: V) V {
    const m = (q - 1) / (2 * gamma2);

    const r1, const r0 = decompose(gamma2, r);

    const up = @select(i32, r1 == splat(m - 1), splat(0), r1 + splat(1));

    const down = @select(i32, r1 == splat(0), splat(m - 1), r1 - splat(1));

    return @select(i32, hint, @select(i32, r0 > splat(0), up, down), r1);
}

fn pack(comptime bits: u5, values: *const [256]u32, out: *[32 * @as(usize, bits)]u8) void {
    const G = vec.Group(bits);

    for (0..256 / G.count) |g| {
        var word: G.Word = 0;

        inline for (0..G.count) |i| {
            word |= @as(G.Word, values[G.count * g + i]) << (G.width * i);
        }

        G.write(word, out[G.size * g ..][0..G.size]);
    }
}

fn unpack(comptime bits: u5, bytes: *const [32 * @as(usize, bits)]u8, out: *[256]u32) void {
    const G = vec.Group(bits);

    for (0..256 / G.count) |g| {
        const word = G.read(bytes[G.size * g ..][0..G.size]);

        inline for (0..G.count) |i| {
            out[G.count * g + i] = @truncate(word >> (G.width * i) & G.mask);
        }
    }
}

// Coefficients in [-a, b] are stored as b - x.
fn bitPack(comptime bits: u5, comptime b: i32, f: *const Poly, out: *[32 * @as(usize, bits)]u8) void {
    const G = vec.Group(bits);

    for (0..256 / G.count) |g| {
        var word: G.Word = 0;

        inline for (0..G.count) |i| {
            word |= @as(G.Word, @as(u32, @intCast(b - f[G.count * g + i]))) << (G.width * i);
        }

        G.write(word, out[G.size * g ..][0..G.size]);
    }
}

fn bitUnpack(comptime bits: u5, comptime b: i32, bytes: *const [32 * @as(usize, bits)]u8, f: *Poly) void {
    const G = vec.Group(bits);

    for (0..256 / G.count) |g| {
        const word = G.read(bytes[G.size * g ..][0..G.size]);

        inline for (0..G.count) |i| {
            f[G.count * g + i] = b - @as(i32, @intCast(word >> (G.width * i) & G.mask));
        }
    }
}

// Candidates from a block of the matrix XOF; the matrix is public and rejections are rare.
fn parseUniform(out: *Poly, start: usize, block: *const [168]u8) usize {
    var count = start;

    var offset: usize = 0;

    while (offset < block.len and count < 256) : (offset += 3) {
        const z = block[offset] | (@as(i32, block[offset + 1]) << 8) | (@as(i32, block[offset + 2] & 0x7f) << 16);

        if (z < q) {
            out[count] = z;

            count += 1;
        }
    }

    return count;
}

// FIPS 204, Algorithm 31, on the secret seed: every candidate is written and the count advances
// by a mask, so the accepted values never steer a branch; only the loop end depends on them.
fn parseBounded(comptime eta: u8, buffer: *[257]i32, start: usize, block: *const [136]u8) usize {
    var count = start;

    for (block) |byte| {
        for ([2]i32{ byte & 0x0f, byte >> 4 }) |half| {
            const accepted: usize = @intFromBool(if (eta == 2) half < 15 else half < 9);

            // half mod 5 is half - 5 * floor(205 * half / 1024) for half < 15.
            buffer[count] = if (eta == 2) 2 - (half - 5 * ((205 * half) >> 10)) else 4 - half;

            count += accepted & @intFromBool(count < 256);
        }
    }

    return count;
}

// The k * l matrix A, entry (r, s) from SHAKE128(rho || s || r), four entries at a time.
fn expandMatrix(comptime p: Parameters, rho: *const [32]u8, a: *[p.k][p.l]Poly) void {
    const count = @as(usize, p.k) * p.l;

    var first: usize = 0;

    while (first + 4 <= count) : (first += 4) {
        var inputs: [4][34]u8 = undefined;

        for (&inputs, first..) |*input, e| input.* = rho.* ++ [2]u8{ @intCast(e % p.l), @intCast(e / p.l) };

        var sponge: keccak.Sponge4 = .init(168, 0x1f, .{ &inputs[0], &inputs[1], &inputs[2], &inputs[3] });

        var counts: [4]usize = @splat(0);

        while (@reduce(.Min, @as(@Vector(4, usize), counts)) < 256) {
            var blocks: [4][168]u8 = undefined;

            sponge.squeeze(.{ &blocks[0], &blocks[1], &blocks[2], &blocks[3] });

            for (&counts, &blocks, first..) |*filled, *block, e| filled.* = parseUniform(&a[e / p.l][e % p.l], filled.*, block);
        }
    }

    for (first..count) |e| {
        var xof = hash.shake128.create();

        xof.update(rho);

        xof.update(&.{ @intCast(e % p.l), @intCast(e / p.l) });

        var filled: usize = 0;

        var block: [168]u8 = undefined;

        while (filled < 256) {
            xof.read(&block);

            filled = parseUniform(&a[e / p.l][e % p.l], filled, &block);
        }
    }
}

// The secret vectors: outs[i] from SHAKE256(rho || nonce + i), four at a time.
fn expandSecret(comptime eta: u8, rho: *const [64]u8, nonce: u16, outs: []const *Poly) void {
    var buffers: [4][257]i32 = undefined;

    var blocks: [4][136]u8 = undefined;

    defer {
        ct.wipe(std.mem.asBytes(&buffers));

        ct.wipe(std.mem.asBytes(&blocks));
    }

    var first: usize = 0;

    while (first + 4 <= outs.len) : (first += 4) {
        var inputs: [4][66]u8 = undefined;

        defer ct.wipe(std.mem.asBytes(&inputs));

        for (&inputs, first..) |*input, i| {
            input[0..64].* = rho.*;

            std.mem.writeInt(u16, input[64..66], nonce + @as(u16, @intCast(i)), .little);
        }

        var sponge: keccak.Sponge4 = .init(136, 0x1f, .{ &inputs[0], &inputs[1], &inputs[2], &inputs[3] });

        defer sponge.wipe();

        var counts: [4]usize = @splat(0);

        while (@reduce(.Min, @as(@Vector(4, usize), counts)) < 256) {
            sponge.squeeze(.{ &blocks[0], &blocks[1], &blocks[2], &blocks[3] });

            for (&buffers, &counts, &blocks) |*buffer, *filled, *block| filled.* = parseBounded(eta, buffer, filled.*, block);
        }

        for (&buffers, outs[first..][0..4]) |*buffer, out| out.* = buffer[0..256].*;
    }

    for (outs[first..], first..) |out, i| {
        var xof = hash.shake256.create();

        defer ct.wipe(std.mem.asBytes(&xof));

        xof.update(rho);

        var input: [2]u8 = undefined;

        std.mem.writeInt(u16, &input, nonce + @as(u16, @intCast(i)), .little);

        xof.update(&input);

        var filled: usize = 0;

        while (filled < 256) {
            xof.read(&blocks[0]);

            filled = parseBounded(eta, &buffers[0], filled, &blocks[0]);
        }

        out.* = buffers[0][0..256].*;
    }
}

// The mask y from SHAKE256(rho' || kappa + r), four polynomials at a time.
fn expandMask(comptime p: Parameters, rho: *const [64]u8, kappa: u16, y: *[p.l]Poly) void {
    const bits = p.gamma1Bits();

    const size = 32 * @as(usize, bits);

    var bytes: [4][size]u8 = undefined;

    defer ct.wipe(std.mem.asBytes(&bytes));

    var first: usize = 0;

    while (first + 4 <= p.l) : (first += 4) {
        var inputs: [4][66]u8 = undefined;

        defer ct.wipe(std.mem.asBytes(&inputs));

        for (&inputs, first..) |*input, r| {
            input[0..64].* = rho.*;

            std.mem.writeInt(u16, input[64..66], kappa + @as(u16, @intCast(r)), .little);
        }

        var sponge: keccak.Sponge4 = .init(136, 0x1f, .{ &inputs[0], &inputs[1], &inputs[2], &inputs[3] });

        defer sponge.wipe();

        var offset: usize = 0;

        while (offset < size) : (offset += 136) {
            const take = @min(136, size - offset);

            sponge.squeeze(.{ bytes[0][offset..][0..take], bytes[1][offset..][0..take], bytes[2][offset..][0..take], bytes[3][offset..][0..take] });
        }

        for (&bytes, y[first..][0..4]) |*lane, *f| bitUnpack(bits, p.gamma1, lane, f);
    }

    for (y[first..], first..) |*f, r| {
        var nonce: [2]u8 = undefined;

        std.mem.writeInt(u16, &nonce, kappa + @as(u16, @intCast(r)), .little);

        primitives.shake256(&.{ rho, &nonce }, &bytes[0]);

        bitUnpack(bits, p.gamma1, &bytes[0], f);
    }
}

fn sampleInBall(comptime p: Parameters, seed: []const u8, c: *Poly) void {
    var xof = hash.shake256.create();

    xof.update(seed);

    var sign_bytes: [8]u8 = undefined;

    xof.read(&sign_bytes);

    var signs = std.mem.readInt(u64, &sign_bytes, .little);

    ct.wipe(std.mem.asBytes(c));

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

    var a: [p.k][p.l]Poly = undefined;

    expandMatrix(p, rho, &a);

    for (t, &a, 0..) |*f, *row, i| {
        dot(p.l, row, &s1_hat, f);

        inverseNtt(f);

        for (0..32) |j| store(f, 8 * j, freeze(load(f, 8 * j) + load(&s2[i], 8 * j)));
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

    var outs: [@as(usize, p.l) + p.k]*Poly = undefined;

    for (outs[0..p.l], &parts.s1) |*out, *f| out.* = f;

    for (outs[p.l..], &parts.s2) |*out, *f| out.* = f;

    expandSecret(p.eta, expanded[32..96], 0, &outs);

    publicT(p, &parts.rho, &parts.s1, &parts.s2, &t);

    var t1: [p.k]Poly = undefined;

    for (&t, &t1, &parts.t0) |*f, *high, *low| {
        for (0..32) |i| {
            const r1, const r0 = power2Round(load(f, 8 * i));

            store(high, 8 * i, r1);

            store(low, 8 * i, r0);
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

    var invalid = splat(0);

    for ([_][]const Poly{ &parts.s1, &parts.s2 }) |vector| {
        for (vector) |*f| {
            for (0..32) |i| invalid |= splat(p.eta) - absolute(load(f, 8 * i));
        }
    }

    publicT(p, &parts.rho, &parts.s1, &parts.s2, &t);

    var t1: [p.k]Poly = undefined;

    for (&t, &t1, &parts.t0) |*f, *high, *low| {
        for (0..32) |i| {
            const r1, const r0 = power2Round(load(f, 8 * i));

            store(high, 8 * i, r1);

            invalid |= -absolute(r0 - load(low, 8 * i));
        }
    }

    encodePublicKey(p, &parts.rho, &t1, pk);

    var tr: [64]u8 = undefined;

    primitives.shake256(&.{pk}, &tr);

    var negative = @reduce(.Or, invalid);

    const barrier: *volatile i32 = &negative;

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

    expandMatrix(p, &parts.rho, &a);

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

            for (0..32) |i| {
                const c = freeze(load(f, 8 * i));

                store(f, 8 * i, c);

                store(high, 8 * i, decompose(p.gamma2, c)[0]);
            }
        }

        const c_tilde = signature[0 .. p.lambda / 4];

        challengeHash(p, &mu, &w1, c_tilde);

        var c_hat: Poly = undefined;

        sampleInBall(p, c_tilde, &c_hat);

        ntt(&c_hat);

        var invalid = splat(0);

        for (&cs1, &parts.s1, &y) |*f, *s, *mask| {
            pointwise(&c_hat, s, f);

            inverseNtt(f);

            for (0..32) |i| {
                const c = centered(freeze(load(f, 8 * i) + load(mask, 8 * i)));

                store(f, 8 * i, c);

                invalid |= splat(p.gamma1 - p.beta() - 1) - absolute(c);
            }
        }

        for (&cs2, &parts.s2, &w, &u) |*f, *s, *wf, *uf| {
            pointwise(&c_hat, s, f);

            inverseNtt(f);

            for (0..32) |i| {
                const uc = freeze(load(wf, 8 * i) - load(f, 8 * i));

                store(uf, 8 * i, uc);

                invalid |= splat(p.gamma2 - p.beta() - 1) - absolute(decompose(p.gamma2, uc)[1]);
            }
        }

        var counts = splat(0);

        var h: [k][256]bool = undefined;

        for (&ct0, &parts.t0, &u, &h) |*f, *t, *uf, *hf| {
            pointwise(&c_hat, t, f);

            inverseNtt(f);

            for (0..32) |i| {
                const c = centered(freeze(load(f, 8 * i)));

                store(f, 8 * i, c);

                invalid |= splat(p.gamma2 - 1) - absolute(c);

                // MakeHint(-ct0, w - cs2 + ct0): whether adding ct0 moves the high bits.
                const uc = load(uf, 8 * i);

                const moved = decompose(p.gamma2, freeze(uc + c))[0] ^ decompose(p.gamma2, uc)[0];

                const bit = shiftRight(moved | -moved, 31) & splat(1);

                hf[8 * i ..][0..8].* = bit != splat(0);

                counts += bit;
            }
        }

        var negative = @reduce(.Or, invalid);

        const barrier: *volatile i32 = &negative;

        if (barrier.* < 0 or @reduce(.Add, counts) > p.omega) continue;

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

        for (0..32) |i| {
            if (@reduce(.Or, absolute(load(f, 8 * i)) >= splat(p.gamma1 - p.beta()))) return false;
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

    var a: [k][l]Poly = undefined;

    expandMatrix(p, rho, &a);

    var w1: [k]Poly = undefined;

    for (&w1, &a, 0..) |*f, *row, i| {
        dot(l, row, &z, f);

        var t1: [256]u32 = undefined;

        unpack(10, pk[32 + 320 * i ..][0..320], &t1);

        var ct1: Poly = undefined;

        for (&ct1, t1) |*c, value| {
            c.* = @intCast(value << d);
        }

        ntt(&ct1);

        pointwise(&c_hat, &ct1, &ct1);

        for (0..32) |j| store(f, 8 * j, reduce32(load(f, 8 * j) - load(&ct1, 8 * j)));

        inverseNtt(f);

        for (0..32) |j| store(f, 8 * j, useHint(p.gamma2, h[i][8 * j ..][0..8].*, freeze(load(f, 8 * j))));
    }

    var expected: [p.lambda / 4]u8 = undefined;

    challengeHash(p, &mu, &w1, &expected);

    return std.mem.eql(u8, &expected, c_tilde);
}

const std = @import("std");

const aarch64 = @import("aarch64.zig");
const cpu = @import("cpu.zig");
const ct = @import("ct.zig");
const keccak = @import("keccak.zig");
const primitives = @import("primitives.zig");
const vec = @import("vector.zig");
const wasm = @import("wasm.zig");

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

pub const q: i32 = 8380417;

const d = 13;

pub const ml_dsa_44: Parameters = .{ .k = 4, .l = 4, .eta = 2, .tau = 39, .lambda = 128, .gamma1 = 1 << 17, .gamma2 = (q - 1) / 88, .omega = 80 };

pub const ml_dsa_65: Parameters = .{ .k = 6, .l = 5, .eta = 4, .tau = 49, .lambda = 192, .gamma1 = 1 << 19, .gamma2 = (q - 1) / 32, .omega = 55 };

pub const ml_dsa_87: Parameters = .{ .k = 8, .l = 7, .eta = 2, .tau = 60, .lambda = 256, .gamma1 = 1 << 19, .gamma2 = (q - 1) / 32, .omega = 75 };

const Poly = [256]i32;

// Powers of 1753 in bit-reversed order, times the Montgomery factor 2^32, reduced to (-q/2, q/2].
pub const zetas: [256]i32 = blk: {
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
pub const q_inverse = 58728449;

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
// agree, so the difference of the high halves is the exact quotient. With SQDMULH the halves are
// doubled, floor(a * b / 2^31), and differ by twice that quotient: SHSUB halves it exactly, four
// lanes at a time. The results are identical as long as a and b are not both -2^31, which no
// zeta and no reduced coefficient is.
pub fn montgomery(a: V, b: V, b_qinv: V) V {
    if (comptime cpu.neon) {
        var out: [2]@Vector(4, i32) = undefined;

        inline for (&out, halves(a), halves(b), halves(a *% b_qinv)) |*half, x, y, t| {
            half.* = aarch64.halvingSubtract32(aarch64.doublingHigh32(x, y), aarch64.doublingHigh32(t, @splat(q)));
        }

        return @shuffle(i32, out[0], out[1], [8]i32{ 0, 1, 2, 3, -1, -2, -3, -4 });
    }

    if (comptime cpu.wasm_simd) return wasm.montgomery32(q, a, b, b_qinv);

    return portable.montgomery(a, b, b_qinv);
}

fn halves(a: V) [2]@Vector(4, i32) {
    return .{ @shuffle(i32, a, undefined, [4]i32{ 0, 1, 2, 3 }), @shuffle(i32, a, undefined, [4]i32{ 4, 5, 6, 7 }) };
}

// The formulas for every target, which the AArch64 code must equal.
pub const portable = struct {
    pub fn montgomery(a: V, b: V, b_qinv: V) V {
        return mulHigh(a, b) - mulHigh(a *% b_qinv, splat(q));
    }

    // The matrix is public and rejections are rare.
    pub fn parseUniform(out: *Poly, start: usize, block: *const [168]u8) usize {
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

    // FIPS 204, Algorithm 31, on the secret seed: every candidate is written and the count
    // advances by the acceptance, so the accepted values never steer a branch. Which candidates
    // are rejected is public, as BoringSSL also has it: the bytes of the SHAKE256 stream are
    // independent of each other, so the rejected ones say nothing about the accepted
    // coefficients.
    pub fn parseBounded(comptime eta: u8, buffer: *[sample_buffer]i32, start: usize, block: *const [136]u8) usize {
        var count = start;

        for (block) |byte| {
            for ([2]i32{ byte & 0x0f, byte >> 4 }) |half| {
                const accepted: usize = @intFromBool(ct.declassifyValue(bool, if (eta == 2) half < 15 else half < 9));

                // half mod 5 is half - 5 * floor(205 * half / 1024) for half < 15.
                buffer[count] = if (eta == 2) 2 - (half - 5 * ((205 * half) >> 10)) else 4 - half;

                count += accepted & @intFromBool(count < 256);
            }
        }

        return count;
    }
};

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
    var entries: [n]*const Poly = undefined;

    for (&entries, row) |*entry, *f| entry.* = f;

    dotEntries(n, &entries, vector, out);
}

// The same for a row whose entries are apart. The sums of n products below q stay below 2^31.
fn dotEntries(comptime n: usize, row: *const [n]*const Poly, vector: *const [n]Poly, out: *Poly) void {
    for (0..32) |i| {
        var sum = splat(0);

        for (row, vector) |f, *g| {
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

// The room a sampling buffer has past the 256 coefficients: the vector code stores whole vectors
// at the count.
pub const sample_buffer = 256 + 8;

// Candidates from a block of the matrix XOF, written to out[start..256]; returns the new count.
fn parseUniform(out: *Poly, start: usize, block: *const [168]u8) usize {
    if (comptime cpu.neon) return aarch64.uniform23(out, start, block);

    return portable.parseUniform(out, start, block);
}

// Candidates from a block of the secret vectors' XOF, appended to buffer[start..]; returns the new
// count, which may pass 256, and only the first 256 count.
fn parseBounded(comptime eta: u8, buffer: *[sample_buffer]i32, start: usize, block: *const [136]u8) usize {
    if (comptime cpu.neon) return aarch64.bounded(eta, buffer, start, block);

    return portable.parseBounded(eta, buffer, start, block);
}

// Entries first .. first + outs.len - 1 (up to four) of the k * l matrix A in row-major order,
// entry (r, s) from SHAKE128(rho || s || r).
fn sampleMatrix(comptime p: Parameters, rho: *const [32]u8, first: usize, outs: []const *Poly) void {
    var inputs: [4][34]u8 = undefined;

    var messages: [4][]const u8 = undefined;

    for (inputs[0..outs.len], messages[0..outs.len], first..) |*input, *message, e| {
        input.* = rho.* ++ [2]u8{ @intCast(e % p.l), @intCast(e / p.l) };

        message.* = input;
    }

    var sponge: keccak.Sponge4 = undefined;

    sponge.startSome(168, 0x1f, messages[0..outs.len]);

    var counts: [4]usize = @splat(256);

    @memset(counts[0..outs.len], 0);

    while (@reduce(.Min, @as(@Vector(4, usize), counts)) < 256) {
        sponge.next();

        for (counts[0..outs.len], outs, 0..) |*filled, out, i| {
            var copy: [168]u8 = undefined;

            filled.* = parseUniform(out, filled.*, sponge.block(168, i, &copy));
        }
    }
}

fn expandMatrix(comptime p: Parameters, rho: *const [32]u8, matrix: *[p.k][p.l]Poly) void {
    const count = @as(usize, p.k) * p.l;

    var first: usize = 0;

    while (first < count) {
        const size = keccak.batch(count - first);

        var outs: [4]*Poly = undefined;

        for (outs[0..size], first..) |*out, e| out.* = &matrix[e / p.l][e % p.l];

        sampleMatrix(p, rho, first, outs[0..size]);

        first += size;
    }
}

// t_hat = A * s_hat in the NTT domain, reduced below q, with the entries of A sampled four at a
// time. They go into `matrix` when it is given. Otherwise they go into a ring of l + 3 entries,
// enough for the row in progress and the next four, and each row is multiplied once it is
// complete: summing a whole row in registers is twice as fast as adding each entry to memory.
fn multiplyMatrix(comptime p: Parameters, rho: *const [32]u8, s_hat: *const [p.l]Poly, t_hat: *[p.k]Poly, matrix: ?*[p.k][p.l]Poly) void {
    if (matrix) |m| {
        expandMatrix(p, rho, m);

        for (t_hat, m) |*f, *row| dot(p.l, row, s_hat, f);

        return;
    }

    const count = @as(usize, p.k) * p.l;

    const slots = @as(usize, p.l) + 3;

    var ring: [slots]Poly = undefined;

    var first: usize = 0;

    for (t_hat, 0..) |*f, i| {
        while (first < (i + 1) * p.l) {
            const size = keccak.batch(count - first);

            var outs: [4]*Poly = undefined;

            for (outs[0..size], first..) |*out, e| out.* = &ring[e % slots];

            sampleMatrix(p, rho, first, outs[0..size]);

            first += size;
        }

        var row: [p.l]*const Poly = undefined;

        for (&row, i * p.l..) |*entry, e| entry.* = &ring[e % slots];

        dotEntries(p.l, &row, s_hat, f);
    }
}

// The secret vectors: outs[i] from SHAKE256(rho || nonce + i), up to four at a time.
fn expandSecret(comptime eta: u8, rho: *const [64]u8, nonce: u16, outs: []const *Poly) void {
    var buffers: [4][sample_buffer]i32 = undefined;

    var inputs: [4][66]u8 = undefined;

    var copy: [136]u8 = undefined;

    defer {
        ct.wipe(std.mem.asBytes(&buffers));

        ct.wipe(std.mem.asBytes(&inputs));

        ct.wipe(&copy);
    }

    var first: usize = 0;

    while (first < outs.len) {
        const size = keccak.batch(outs.len - first);

        var messages: [4][]const u8 = undefined;

        for (inputs[0..size], messages[0..size], first..) |*input, *message, i| {
            input[0..64].* = rho.*;

            std.mem.writeInt(u16, input[64..66], nonce + @as(u16, @intCast(i)), .little);

            message.* = input;
        }

        var sponge: keccak.Sponge4 = undefined;

        sponge.startSome(136, 0x1f, messages[0..size]);

        defer sponge.wipe();

        var counts: [4]usize = @splat(256);

        @memset(counts[0..size], 0);

        while (@reduce(.Min, @as(@Vector(4, usize), counts)) < 256) {
            sponge.next();

            for (buffers[0..size], counts[0..size], 0..) |*buffer, *filled, i| filled.* = parseBounded(eta, buffer, filled.*, sponge.block(136, i, &copy));
        }

        for (buffers[0..size], outs[first..][0..size]) |*buffer, out| out.* = buffer[0..256].*;

        first += size;
    }
}

// The mask y from SHAKE256(rho' || kappa + r), up to four polynomials at a time.
fn expandMask(comptime p: Parameters, rho: *const [64]u8, kappa: u16, y: *[p.l]Poly) void {
    const bits = p.gamma1Bits();

    const size = 32 * @as(usize, bits);

    var bytes: [4][size]u8 = undefined;

    var inputs: [4][66]u8 = undefined;

    var copy: [136]u8 = undefined;

    defer {
        ct.wipe(std.mem.asBytes(&bytes));

        ct.wipe(std.mem.asBytes(&inputs));

        ct.wipe(&copy);
    }

    var first: usize = 0;

    while (first < p.l) {
        const count = keccak.batch(p.l - first);

        var messages: [4][]const u8 = undefined;

        for (inputs[0..count], messages[0..count], first..) |*input, *message, r| {
            input[0..64].* = rho.*;

            std.mem.writeInt(u16, input[64..66], kappa + @as(u16, @intCast(r)), .little);

            message.* = input;
        }

        var sponge: keccak.Sponge4 = undefined;

        sponge.startSome(136, 0x1f, messages[0..count]);

        defer sponge.wipe();

        var offset: usize = 0;

        while (offset < size) : (offset += 136) {
            const take = @min(136, size - offset);

            sponge.next();

            for (bytes[0..count], 0..) |*lane, i| @memcpy(lane[offset..][0..take], sponge.block(136, i, &copy)[0..take]);
        }

        for (bytes[0..count], y[first..][0..count]) |*lane, *f| bitUnpack(bits, p.gamma1, lane, f);

        first += count;
    }
}

fn sampleInBall(comptime p: Parameters, seed: []const u8, c: *Poly) void {
    var xof = primitives.shake256Sponge();

    xof.update(seed);

    var sign_bytes: [8]u8 = undefined;

    xof.read(&sign_bytes);

    var signs = std.mem.readInt(u64, &sign_bytes, .little);

    ct.wipe(std.mem.asBytes(c));

    // The positions of the nonzero coefficients are public, as in BoringSSL, while their signs
    // stay secret. For an accepted signature c_tilde is public; for a rejected attempt the
    // positions say nothing about the key, because whether an attempt is rejected does not depend
    // on c * s1 or c * s2.
    for (256 - @as(usize, p.tau)..256) |i| {
        var j: [1]u8 = undefined;

        while (true) {
            xof.read(&j);

            ct.declassify(&j);

            if (j[0] <= i) break;
        }

        c[i] = c[j[0]];

        c[j[0]] = 1 - 2 * @as(i32, @intCast(signs & 1));

        signs >>= 1;
    }
}

// w1Encode of one row of w1, absorbed into the challenge hash: the rows are hashed as they are
// produced instead of being kept.
fn absorbHigh(comptime p: Parameters, challenge: *keccak.Keccak, w1: *const Poly) void {
    var values: [256]u32 = undefined;

    var encoded: [32 * @as(usize, p.w1Bits())]u8 = undefined;

    defer {
        ct.wipe(std.mem.asBytes(&values));

        ct.wipe(&encoded);
    }

    for (&values, w1) |*value, c| value.* = @intCast(c);

    pack(p.w1Bits(), &values, &encoded);

    challenge.update(&encoded);
}

fn packHigh(t1: *const Poly, out: *[320]u8) void {
    var values: [256]u32 = undefined;

    for (&values, t1) |*value, c| value.* = @intCast(c);

    pack(10, &values, out);
}

fn unpackHigh(bytes: *const [320]u8, t1: *Poly) void {
    var values: [256]u32 = undefined;

    unpack(10, bytes, &values);

    for (t1, values) |*c, value| c.* = @intCast(value);
}

// NTT(t1 * 2^d), which verification multiplies by c.
fn shiftedNtt(t1: *const Poly, out: *Poly) void {
    for (out, t1) |*c, value| c.* = value << d;

    ntt(out);
}

// What signing and verification read from a public key: A and NTT(t1 * 2^d).
pub fn PublicCache(comptime p: Parameters) type {
    return struct {
        matrix: [p.k][p.l]Poly,
        t1: [p.k]Poly,

        pub fn fill(self: *@This(), pk: *const [p.publicKeySize()]u8) void {
            expandMatrix(p, pk[0..32], &self.matrix);

            for (&self.t1, 0..) |*f, i| {
                var t1: Poly = undefined;

                unpackHigh(pk[32 + 320 * i ..][0..320], &t1);

                shiftedNtt(&t1, f);
            }
        }
    };
}

// The NTT forms of s1, s2 and t0 that signing multiplies by c.
pub fn SecretCache(comptime p: Parameters) type {
    return struct {
        s1: [p.l]Poly,
        s2: [p.k]Poly,
        t0: [p.k]Poly,

        pub fn fill(self: *@This(), sk: *const [p.privateKeySize()]u8) void {
            const eta_size = 32 * @as(usize, p.etaBits());

            const t0_offset = 128 + eta_size * (@as(usize, p.l) + p.k);

            for (&self.s1, 0..) |*f, i| bitUnpack(p.etaBits(), p.eta, sk[128 + eta_size * i ..][0..eta_size], f);

            for (&self.s2, 0..) |*f, i| bitUnpack(p.etaBits(), p.eta, sk[128 + eta_size * (p.l + i) ..][0..eta_size], f);

            for (&self.t0, 0..) |*f, i| bitUnpack(d, 1 << (d - 1), sk[t0_offset + 32 * d * i ..][0 .. 32 * d], f);

            inline for (.{ &self.s1, &self.s2, &self.t0 }) |vector| {
                for (vector) |*f| ntt(f);
            }
        }
    };
}

// The secret vectors are encoded into sk as they are produced, and A is used as it is sampled; a
// generated key also fills `public` from the same computation. s1 and s2 come four at a time from
// one run of nonces, so s2 passes through `t` before the product overwrites it, and its rows are
// read back from sk. The entry points are not inlined, so that callers that dispatch over the
// parameter sets do not hold the frames of all of them at once.
pub noinline fn keyGen(comptime p: Parameters, seed: *const [32]u8, pk: *[p.publicKeySize()]u8, sk: *[p.privateKeySize()]u8, public: ?*PublicCache(p)) void {
    const eta_size = 32 * @as(usize, p.etaBits());

    const s2_offset = 128 + eta_size * @as(usize, p.l);

    const t0_offset = s2_offset + eta_size * @as(usize, p.k);

    var expanded: [128]u8 = undefined;

    var s1: [p.l]Poly = undefined;

    var t: [p.k]Poly = undefined;

    var row: Poly = undefined;

    defer {
        ct.wipe(&expanded);

        inline for (.{ &s1, &t, &row }) |value| ct.wipe(std.mem.asBytes(value));
    }

    primitives.shake256(&.{ seed, &.{ p.k, p.l } }, &expanded);

    const rho = expanded[0..32];

    // rho is part of the public key.
    ct.declassify(rho);

    var outs: [@as(usize, p.l) + p.k]*Poly = undefined;

    for (outs[0..p.l], &s1) |*out, *f| out.* = f;

    for (outs[p.l..], &t) |*out, *f| out.* = f;

    expandSecret(p.eta, expanded[32..96], 0, &outs);

    sk[0..32].* = rho.*;

    sk[32..64].* = expanded[96..128].*;

    for (outs, 0..) |f, i| bitPack(p.etaBits(), p.eta, f, sk[128 + eta_size * i ..][0..eta_size]);

    for (&s1) |*f| ntt(f);

    multiplyMatrix(p, rho, &s1, &t, if (public) |cache| &cache.matrix else null);

    for (&t, 0..) |*f, i| {
        inverseNtt(f);

        bitUnpack(p.etaBits(), p.eta, sk[s2_offset + eta_size * i ..][0..eta_size], &row);

        // row turns from s2 into t1, and f into t0.
        for (0..32) |j| {
            const r1, const r0 = power2Round(freeze(load(f, 8 * j) + load(&row, 8 * j)));

            store(&row, 8 * j, r1);

            store(f, 8 * j, r0);
        }

        // t1 is part of the public key.
        ct.declassify(std.mem.asBytes(&row));

        packHigh(&row, pk[32 + 320 * i ..][0..320]);

        bitPack(d, 1 << (d - 1), f, sk[t0_offset + 32 * d * i ..][0 .. 32 * d]);

        if (public) |cache| shiftedNtt(&row, &cache.t1[i]);
    }

    pk[0..32].* = rho.*;

    ct.declassify(pk);

    primitives.shake256(&.{pk}, sk[64..128]);
}

// An expanded private key carries everything needed to rebuild the public key, so a key whose
// parts disagree is rejected instead of producing signatures that never verify. The checks
// accumulate differences so that the secret values do not decide any branch. The rows of s2 and
// t0 are read from sk as they are needed.
pub noinline fn checkPrivateKey(comptime p: Parameters, sk: *const [p.privateKeySize()]u8, pk: *[p.publicKeySize()]u8) bool {
    const eta_size = 32 * @as(usize, p.etaBits());

    const s2_offset = 128 + eta_size * @as(usize, p.l);

    const t0_offset = s2_offset + eta_size * @as(usize, p.k);

    var s1: [p.l]Poly = undefined;

    var t: [p.k]Poly = undefined;

    var row: Poly = undefined;

    defer {
        inline for (.{ &s1, &t, &row }) |value| ct.wipe(std.mem.asBytes(value));
    }

    // rho is part of the public key.
    ct.declassify(sk[0..32]);

    const rho = sk[0..32];

    var invalid = splat(0);

    for (0..@as(usize, p.l) + p.k) |i| {
        const f = if (i < p.l) &s1[i] else &row;

        bitUnpack(p.etaBits(), p.eta, sk[128 + eta_size * i ..][0..eta_size], f);

        for (0..32) |j| invalid |= splat(p.eta) - absolute(load(f, 8 * j));
    }

    for (&s1) |*f| ntt(f);

    multiplyMatrix(p, rho, &s1, &t, null);

    for (&t, 0..) |*f, i| {
        inverseNtt(f);

        bitUnpack(p.etaBits(), p.eta, sk[s2_offset + eta_size * i ..][0..eta_size], &row);

        for (0..32) |j| store(f, 8 * j, freeze(load(f, 8 * j) + load(&row, 8 * j)));

        bitUnpack(d, 1 << (d - 1), sk[t0_offset + 32 * d * i ..][0 .. 32 * d], &row);

        for (0..32) |j| {
            const r1, const r0 = power2Round(load(f, 8 * j));

            store(f, 8 * j, r1);

            invalid |= -absolute(r0 - load(&row, 8 * j));
        }

        packHigh(f, pk[32 + 320 * i ..][0..320]);
    }

    pk[0..32].* = rho.*;

    ct.declassify(pk);

    var tr: [64]u8 = undefined;

    primitives.shake256(&.{pk}, &tr);

    var negative = @reduce(.Or, invalid);

    const barrier: *volatile i32 = &negative;

    // Whether the key is valid is public: importing it fails otherwise.
    const valid = @intFromBool(barrier.* >= 0) & @intFromBool(ct.equal(&tr, sk[64..128]));

    if (ct.declassifyValue(u1, valid) == 0) return false;

    // tr = H(pk) is public once it is known to match pk; the public key takes it from here.
    ct.declassify(sk[64..128]);

    return true;
}

// The memory of one signing call, which the caller allocates: an attempt keeps y, its NTT form,
// w and the hints, while w1 goes into the challenge hash row by row, z replaces y and w - c * s2
// replaces w.
pub fn Workspace(comptime p: Parameters) type {
    return struct {
        y: [p.l]Poly,
        y_hat: [p.l]Poly,
        w: [p.k]Poly,
        h: [p.k][256]bool,
        c_hat: Poly,
        product: Poly,
    };
}

// The caches hold A and the NTT forms of the secret vectors; `work` is wiped before it returns.
pub noinline fn sign(comptime p: Parameters, sk: *const [p.privateKeySize()]u8, secret: *const SecretCache(p), public: *const PublicCache(p), work: *Workspace(p), message: []const []const u8, rnd: *const [32]u8, signature: *[p.signatureSize()]u8) void {
    const l = p.l;

    const y = &work.y;

    const y_hat = &work.y_hat;

    const w = &work.w;

    const h = &work.h;

    const c_hat = &work.c_hat;

    const product = &work.product;

    var mu: [64]u8 = undefined;

    var rho_prime: [64]u8 = undefined;

    defer {
        ct.wipe(&rho_prime);

        ct.wipe(std.mem.asBytes(work));
    }

    var mu_hasher = primitives.shake256Sponge();

    mu_hasher.update(sk[64..128]);

    for (message) |part| {
        mu_hasher.update(part);
    }

    mu_hasher.read(&mu);

    primitives.shake256(&.{ sk[32..64], rnd, &mu }, &rho_prime);

    var kappa: u16 = 0;

    while (true) : (kappa += l) {
        expandMask(p, &rho_prime, kappa, y);

        y_hat.* = y.*;

        for (y_hat) |*f| ntt(f);

        var challenge = primitives.shake256Sponge();

        defer ct.wipe(std.mem.asBytes(&challenge));

        challenge.update(&mu);

        for (w, &public.matrix) |*f, *row| {
            dot(l, row, y_hat, f);

            inverseNtt(f);

            for (0..32) |i| {
                const c = freeze(load(f, 8 * i));

                store(f, 8 * i, c);

                store(product, 8 * i, decompose(p.gamma2, c)[0]);
            }

            absorbHigh(p, &challenge, product);
        }

        const c_tilde = signature[0 .. p.lambda / 4];

        challenge.read(c_tilde);

        sampleInBall(p, c_tilde, c_hat);

        ntt(c_hat);

        var invalid = splat(0);

        for (y, &secret.s1) |*f, *s| {
            pointwise(c_hat, s, product);

            inverseNtt(product);

            for (0..32) |i| {
                const c = centered(freeze(load(product, 8 * i) + load(f, 8 * i)));

                store(f, 8 * i, c);

                invalid |= splat(p.gamma1 - p.beta() - 1) - absolute(c);
            }
        }

        var counts = splat(0);

        for (w, &secret.s2, &secret.t0, h) |*f, *s, *t, *hf| {
            pointwise(c_hat, s, product);

            inverseNtt(product);

            for (0..32) |i| {
                const uc = freeze(load(f, 8 * i) - load(product, 8 * i));

                store(f, 8 * i, uc);

                invalid |= splat(p.gamma2 - p.beta() - 1) - absolute(decompose(p.gamma2, uc)[1]);
            }

            pointwise(c_hat, t, product);

            inverseNtt(product);

            for (0..32) |i| {
                const c = centered(freeze(load(product, 8 * i)));

                invalid |= splat(p.gamma2 - 1) - absolute(c);

                // MakeHint(-ct0, w - cs2 + ct0): whether adding ct0 moves the high bits.
                const uc = load(f, 8 * i);

                const moved = decompose(p.gamma2, freeze(uc + c))[0] ^ decompose(p.gamma2, uc)[0];

                const bit = shiftRight(moved | -moved, 31) & splat(1);

                hf[8 * i ..][0..8].* = bit != splat(0);

                counts += bit;
            }
        }

        var negative = @reduce(.Or, invalid);

        const barrier: *volatile i32 = &negative;

        // Only the decision to restart is public, not which check failed or where: a restart
        // reveals nothing, because the next attempt is independent of this one.
        const rejected = @intFromBool(barrier.* < 0) | @intFromBool(@reduce(.Add, counts) > p.omega);

        if (ct.declassifyValue(u1, rejected) == 1) continue;

        // The accepted c_tilde, z and h form the signature.
        ct.declassify(c_tilde);

        ct.declassify(std.mem.asBytes(y));

        ct.declassify(std.mem.asBytes(h));

        encodeSignature(p, y, h, signature);

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

// tr = H(pk, 64), which the key computed when it was created. Without a cache, which happens
// only when it cannot be allocated, A is sampled again as the product uses it.
pub noinline fn verify(comptime p: Parameters, pk: *const [p.publicKeySize()]u8, tr: *const [64]u8, public: ?*const PublicCache(p), message: []const []const u8, signature: *const [p.signatureSize()]u8) bool {
    const k = p.k;

    const l = p.l;

    const bits = p.gamma1Bits();

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

    var mu: [64]u8 = undefined;

    var mu_hasher = primitives.shake256Sponge();

    mu_hasher.update(tr);

    for (message) |part| {
        mu_hasher.update(part);
    }

    mu_hasher.read(&mu);

    var c_hat: Poly = undefined;

    sampleInBall(p, c_tilde, &c_hat);

    ntt(&c_hat);

    for (&z) |*f| ntt(f);

    var w: [k]Poly = undefined;

    if (public) |cache| {
        for (&w, &cache.matrix) |*f, *row| dot(l, row, &z, f);
    } else {
        multiplyMatrix(p, pk[0..32], &z, &w, null);
    }

    var challenge = primitives.shake256Sponge();

    challenge.update(&mu);

    for (&w, &h, 0..) |*f, *hints, i| {
        var ct1: Poly = undefined;

        if (public) |cache| {
            pointwise(&c_hat, &cache.t1[i], &ct1);
        } else {
            var t1: Poly = undefined;

            unpackHigh(pk[32 + 320 * i ..][0..320], &t1);

            shiftedNtt(&t1, &ct1);

            pointwise(&c_hat, &ct1, &ct1);
        }

        for (0..32) |j| store(f, 8 * j, reduce32(load(f, 8 * j) - load(&ct1, 8 * j)));

        inverseNtt(f);

        for (0..32) |j| store(f, 8 * j, useHint(p.gamma2, hints[8 * j ..][0..8].*, freeze(load(f, 8 * j))));

        absorbHigh(p, &challenge, f);
    }

    var expected: [p.lambda / 4]u8 = undefined;

    challenge.read(&expected);

    return std.mem.eql(u8, &expected, c_tilde);
}

const std = @import("std");
const builtin = @import("builtin");

const aarch64 = @import("aarch64.zig");
const cpu = @import("cpu.zig");
const ct = @import("ct.zig");
const hash = @import("hash.zig");
const keccak = @import("keccak.zig");
const primitives = @import("primitives.zig");
const vec = @import("vector.zig");
const wasm = @import("wasm.zig");

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

pub const q = 3329;

pub const Poly = [256]i16;

// Powers of 17 in bit-reversed order, times the Montgomery factor 2^16, reduced to (-q/2, q/2].
pub const zetas: [128]i16 = blk: {
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

// The arithmetic runs on eight coefficients per vector. Every lane computes exactly what the
// scalar formulas of FIPS 203 with Montgomery and Barrett reduction compute, so the results do not
// depend on the vector width.
const V = @Vector(8, i16);

const Wide = @Vector(8, i32);

const U = @Vector(8, u32);

// q^-1 modulo 2^16.
pub const q_inverse = -3327;

fn splat(value: i16) V {
    return @splat(value);
}

fn load(f: *const Poly, i: usize) V {
    return f[i..][0..8].*;
}

fn store(f: *Poly, i: usize, value: V) void {
    f[i..][0..8].* = value;
}

fn mulHigh(a: V, b: V) V {
    return @truncate(@as(Wide, a) * @as(Wide, b) >> @splat(16));
}

// a * b * 2^-16 modulo q, in (-q, q), given b_qinv = b * q^-1 mod 2^16: the low halves of a * b
// and t * q agree, so the difference of the high halves is the exact quotient. With SQDMULH the
// halves are doubled, floor(a * b / 2^15), and differ by twice that quotient: SHSUB halves it
// exactly. The results are identical as long as a and b are not both -2^15, which no zeta and no
// reduced coefficient is.
pub fn montgomery(a: V, b: V, b_qinv: V) V {
    if (comptime cpu.neon) return aarch64.halvingSubtract16(aarch64.doublingHigh16(a, b), aarch64.doublingHigh16(a *% b_qinv, splat(q)));

    return portable.montgomery(a, b, b_qinv);
}

fn montgomeryProduct(a: V, b: V) V {
    return montgomery(a, b, b *% splat(q_inverse));
}

fn constantProduct(a: V, comptime b: i16) V {
    return montgomery(a, splat(b), splat(b *% q_inverse));
}

const barrett_factor = ((1 << 26) + q / 2) / q;

// The representative modulo q in [-(q - 1) / 2, (q - 1) / 2]. SQDMULH gives floor(a * v / 2^15),
// and rounding that by 2^11 equals rounding a * v by 2^26, so the results are identical for every
// input.
pub fn barrett(a: V) V {
    if (comptime cpu.neon) {
        const t = (aarch64.doublingHigh16(a, splat(barrett_factor)) +% splat(1 << 10)) >> @splat(11);

        return a -% t *% splat(q);
    }

    return portable.barrett(a);
}

// The formulas for every target, which the AArch64 ones above must equal.
pub const portable = struct {
    pub fn montgomery(a: V, b: V, b_qinv: V) V {
        return mulHigh(a, b) - mulHigh(a *% b_qinv, splat(q));
    }

    pub fn barrett(a: V) V {
        const t = (@as(Wide, a) * @as(Wide, @splat(barrett_factor)) + @as(Wide, @splat(1 << 25))) >> @splat(26);

        return @truncate(@as(Wide, a) - t * @as(Wide, @splat(q)));
    }

    // The matrix is public, so the loop may end on its values, but a fifth of the candidates are
    // rejected at random: every candidate is written and the count advances by the comparison,
    // which avoids a mispredicted branch per rejection.
    pub fn parseUniform(buffer: *[sample_buffer]i16, start: usize, block: *const [168]u8) usize {
        var count = start;

        var offset: usize = 0;

        while (offset < block.len and count < 256) : (offset += 3) {
            const d1 = block[offset] | (@as(u16, block[offset + 1] & 0x0f) << 8);

            const d2 = (block[offset + 1] >> 4) | (@as(u16, block[offset + 2]) << 4);

            buffer[count] = @intCast(d1);

            count += @intFromBool(d1 < q);

            buffer[count] = @intCast(d2);

            count += @intFromBool(d2 < q) & @intFromBool(count < 256);
        }

        return count;
    }

    // Sixteen coefficients at a time: each pair (a, b) of canonical values becomes the 24 bits
    // a + 2^12 b, written as three bytes.
    pub fn encode12(f: *const Poly, out: *[384]u8) void {
        const Words = @Vector(8, u32);

        for (0..16) |i| {
            const low = canonical(load(f, 16 * i));

            const high = canonical(load(f, 16 * i + 8));

            const even = @shuffle(u32, low, high, [8]i32{ 0, 2, 4, 6, -1, -3, -5, -7 });

            const odd = @shuffle(u32, low, high, [8]i32{ 1, 3, 5, 7, -2, -4, -6, -8 });

            const words: Words = even | odd << @splat(12);

            const first: @Vector(8, u8) = @truncate(words);

            const second: @Vector(8, u8) = @truncate(words >> @splat(8));

            const third: @Vector(8, u8) = @truncate(words >> @splat(16));

            const two = @shuffle(u8, first, second, [16]i32{ 0, 1, 2, 3, 4, 5, 6, 7, -1, -2, -3, -4, -5, -6, -7, -8 });

            out[24 * i ..][0..16].* = @shuffle(u8, two, third, [16]i32{ 0, 8, -1, 1, 9, -2, 2, 10, -3, 3, 11, -4, 4, 12, -5, 5 });

            out[24 * i + 16 ..][0..8].* = @shuffle(u8, two, third, [8]i32{ 13, -6, 6, 14, -7, 7, 15, -8 });
        }
    }
};

// Maps (-q, q) to [0, q) with a mask instead of a branch.
fn canonical(a: V) U {
    return @intCast(a + (a >> @splat(15) & splat(q)));
}

fn reduce(f: *Poly) void {
    for (0..32) |i| store(f, 8 * i, barrett(load(f, 8 * i)));
}

fn add(f: *Poly, g: *const Poly) void {
    for (0..32) |i| store(f, 8 * i, load(f, 8 * i) + load(g, 8 * i));
}

// The last two forward layers and the first two inverse layers run inside 16-coefficient chunks
// held in two vectors; their zetas are laid out per chunk in the lane order used there. Layer
// `step` pairs coefficients `step` apart.
const Chunk = struct {
    zeta: [16]V,
    zeta_qinv: [16]V,

    fn init(comptime inverse: bool, comptime step: usize) Chunk {
        @setEvalBranchQuota(100000);

        var self: Chunk = undefined;

        for (&self.zeta, &self.zeta_qinv, 0..) |*zeta, *zeta_qinv, c| {
            var lanes: [8]i16 = undefined;

            for (&lanes, 0..) |*lane, i| {
                const block = c * (8 / step) + i / step;

                lane.* = zetas[if (inverse) 256 / step - 1 - block else 128 / step + block];
            }

            zeta.* = lanes;

            zeta_qinv.* = zeta.* *% splat(q_inverse);
        }

        return self;
    }
};

const forward_chunks = [2]Chunk{ .init(false, 4), .init(false, 2) };

const inverse_chunks = [2]Chunk{ .init(true, 2), .init(true, 4) };

// The zetas of the base multiplications of each chunk, alternating zeta and -zeta per pair.
const base_zetas: Chunk = blk: {
    var self: Chunk = undefined;

    for (&self.zeta, &self.zeta_qinv, 0..) |*zeta, *zeta_qinv, c| {
        var lanes: [8]i16 = undefined;

        for (&lanes, 0..) |*lane, i| lane.* = if (i % 2 == 0) zetas[64 + 4 * c + i / 2] else -zetas[64 + 4 * c + i / 2];

        zeta.* = lanes;

        zeta_qinv.* = zeta.* *% splat(q_inverse);
    }

    break :blk self;
};

fn ntt(f: *Poly) void {
    var k: usize = 1;

    inline for ([_]usize{ 128, 64, 32, 16, 8 }) |length| {
        var start: usize = 0;

        while (start < 256) : (start += 2 * length) {
            const zeta = splat(zetas[k]);

            const zeta_qinv = splat(zetas[k] *% q_inverse);

            k += 1;

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

        inline for (forward_chunks, [_]usize{ 4, 2 }) |chunk, step| {
            const x, const y = vec.split(step, a, b);

            const t = montgomery(y, chunk.zeta[c], chunk.zeta_qinv[c]);

            a, b = vec.join(step, x + t, x - t);
        }

        store(f, 16 * c, barrett(a));

        store(f, 16 * c + 8, barrett(b));
    }
}

// The output carries the factor 2^16 that cancels the 2^-16 of the preceding products.
fn inverseNtt(f: *Poly) void {
    for (0..16) |c| {
        var a = load(f, 16 * c);

        var b = load(f, 16 * c + 8);

        inline for (inverse_chunks, [_]usize{ 2, 4 }) |chunk, step| {
            const x, const y = vec.split(step, a, b);

            a, b = vec.join(step, barrett(x + y), montgomery(y - x, chunk.zeta[c], chunk.zeta_qinv[c]));
        }

        store(f, 16 * c, a);

        store(f, 16 * c + 8, b);
    }

    var k: usize = 31;

    inline for ([_]usize{ 8, 16, 32, 64, 128 }) |length| {
        var start: usize = 0;

        while (start < 256) : (start += 2 * length) {
            const zeta = splat(zetas[k]);

            const zeta_qinv = splat(zetas[k] *% q_inverse);

            k -= 1;

            var j = start;

            while (j < start + length) : (j += 8) {
                const a = load(f, j);

                const b = load(f, j + length);

                store(f, j, barrett(a + b));

                store(f, j + length, montgomery(b - a, zeta, zeta_qinv));
            }
        }
    }

    for (0..32) |i| store(f, 8 * i, constantProduct(load(f, 8 * i), inverse_ntt_factor));
}

// Every pair (b0, b1) of an NTT-domain polynomial with b1 replaced by b1 * zeta, the pair's zeta
// from the base multiplication: dot reads it in place of b for the first products.
fn zetaProducts(b: *const Poly) Poly {
    var out: Poly = undefined;

    for (0..16) |c| {
        const b0, const b1 = vec.split(1, load(b, 16 * c), load(b, 16 * c + 8));

        const low, const high = vec.join(1, b0, montgomery(b1, base_zetas.zeta[c], base_zetas.zeta_qinv[c]));

        store(&out, 16 * c, low);

        store(&out, 16 * c + 8, high);
    }

    return out;
}

// x * 2^-16 modulo q, in (-q, q) for |x| below 2^31 - 2^15 * q: x - t * q is a multiple of 2^16
// for t = x * q^-1 modulo 2^16.
fn montgomeryReduce(comptime n: usize, x: @Vector(n, i32)) @Vector(n, i16) {
    const t = @as(@Vector(n, i16), @truncate(x)) *% @as(@Vector(n, i16), @splat(q_inverse));

    return @intCast((x - @as(@Vector(n, i32), t) * @as(@Vector(n, i32), @splat(q))) >> @splat(16));
}

// The NTT-domain inner product of a with b, reduced; it carries a factor 2^-16. For pairs (a0, a1)
// and (b0, b1) the products of degree-one residues modulo X^2 - zeta are a0 * b0 + a1 * b1 * zeta
// and a0 * b1 + a1 * b0: the lane-wise products of a with b_zeta = zetaProducts(b) and with b's
// pairs swapped, each added up pairwise. They are summed over the k terms in 32 bits, below 2^27
// for entries below q, and reduced once.
fn dot(comptime k: usize, a: [k]*const Poly, b: *const [k]Poly, b_zeta: *const [k]Poly, r: *Poly) void {
    const Lanes = @Vector(8, i32);

    const swap = [8]i32{ 1, 0, 3, 2, 5, 4, 7, 6 };

    for (0..32) |i| {
        var with_zeta: Lanes = @splat(0);

        var crossed: Lanes = @splat(0);

        for (a, b, b_zeta) |f, *g, *g_zeta| {
            const x: Lanes = load(f, 8 * i);

            with_zeta += x * @as(Lanes, load(g_zeta, 8 * i));

            crossed += x * @as(Lanes, @shuffle(i16, load(g, 8 * i), undefined, swap));
        }

        const evens = [4]i32{ 0, 2, 4, 6 };

        const odds = [4]i32{ 1, 3, 5, 7 };

        const first = @shuffle(i32, with_zeta, undefined, evens) + @shuffle(i32, with_zeta, undefined, odds);

        const second = @shuffle(i32, crossed, undefined, evens) + @shuffle(i32, crossed, undefined, odds);

        const pairs = @shuffle(i16, montgomeryReduce(4, first), montgomeryReduce(4, second), [8]i32{ 0, -1, 1, -2, 2, -3, 3, -4 });

        store(r, 8 * i, barrett(pairs));
    }
}

// The entries of a vector of polynomials, as dot takes them.
fn entries(comptime k: usize, v: *const [k]Poly) [k]*const Poly {
    var out: [k]*const Poly = undefined;

    for (&out, v) |*entry, *f| entry.* = f;

    return out;
}

// The room a sampling buffer has past the 256 coefficients: the vector code stores whole vectors
// at the count.
pub const sample_buffer = 256 + 8;

// Candidates from a block of the matrix XOF, appended to buffer[start..]; returns the new count,
// which may pass 256, and only the first 256 count.
fn parseUniform(buffer: *[sample_buffer]i16, start: usize, block: *const [168]u8) usize {
    if (comptime cpu.neon) return aarch64.uniform12(buffer, start, block);

    return portable.parseUniform(buffer, start, block);
}

// The k * k matrix with entry (i, j) at i * k + j, from XOF(rho, j, i), or from XOF(rho, i, j)
// for its transpose, up to four entries at a time.
fn sampleMatrix(comptime k: usize, rho: *const [32]u8, transposed: bool, out: *[k * k]Poly) void {
    var first: usize = 0;

    while (first < k * k) {
        const size = keccak.batch(k * k - first);

        var inputs: [4][34]u8 = undefined;

        var messages: [4][]const u8 = undefined;

        for (inputs[0..size], messages[0..size], first..) |*input, *message, e| {
            const i: u8 = @intCast(e / k);

            const j: u8 = @intCast(e % k);

            input.* = rho.* ++ (if (transposed) [2]u8{ i, j } else [2]u8{ j, i });

            message.* = input;
        }

        var sponge: keccak.Sponge4 = undefined;

        sponge.startSome(168, 0x1f, messages[0..size]);

        var buffers: [4][sample_buffer]i16 = undefined;

        var counts: [4]usize = @splat(256);

        @memset(counts[0..size], 0);

        while (@reduce(.Min, @as(@Vector(4, usize), counts)) < 256) {
            sponge.next();

            for (buffers[0..size], counts[0..size], 0..) |*buffer, *count, i| {
                var copy: [168]u8 = undefined;

                count.* = parseUniform(buffer, count.*, sponge.block(168, i, &copy));
            }
        }

        for (buffers[0..size], first..) |*buffer, e| out[e] = buffer[0..256].*;

        first += size;
    }
}

// The centered binomial distribution: each coefficient is the difference of the bit counts of
// two adjacent eta-bit groups. For eta = 2 a byte holds two coefficients, and sixteen bytes go at
// once: their bit pairs are summed in place, and each nibble of the sums gives a - b.
fn binomial(comptime eta: u8, bytes: *const [64 * eta]u8, out: *Poly) void {
    if (eta == 2) {
        const Bytes = @Vector(16, u8);

        const Signed = @Vector(16, i8);

        const pairs: Bytes = @splat(0x55);

        const two: Bytes = @splat(3);

        // The coefficients of the first and the second half of the bytes, interleaved.
        const orders = comptime blk: {
            var table: [2][16]i32 = undefined;

            for (&table, 0..) |*order, h| {
                for (order, 0..) |*lane, j| lane.* = if (j % 2 == 0) 8 * h + j / 2 else ~@as(i32, 8 * h + j / 2);
            }

            break :blk table;
        };

        for (0..8) |i| {
            const x: Bytes = bytes[16 * i ..][0..16].*;

            const sums = (x & pairs) + ((x >> @splat(1)) & pairs);

            const first = @as(Signed, @bitCast(sums & two)) - @as(Signed, @bitCast((sums >> @splat(2)) & two));

            const second = @as(Signed, @bitCast((sums >> @splat(4)) & two)) - @as(Signed, @bitCast(sums >> @splat(6)));

            inline for (orders, 0..) |order, h| {
                out[32 * i + 16 * h ..][0..16].* = @as(@Vector(16, i16), @shuffle(i8, first, second, order));
            }
        }
    } else if (comptime builtin.cpu.arch.endian() == .little) {
        // For eta = 3, three bytes hold four coefficients. Four such groups go at once as the
        // 24-bit words of four lanes, whose bit triples are summed in place; the four 6-bit
        // fields of a word, a + 8b, then move to its four bytes, each giving a - b.
        const Words = @Vector(4, u32);

        const triples: Words = @splat(0x00249249);

        const groups = [2][16]i32{
            .{ 0, 1, 2, -1, 3, 4, 5, -1, 6, 7, 8, -1, 9, 10, 11, -1 },
            .{ 4, 5, 6, -1, 7, 8, 9, -1, 10, 11, 12, -1, 13, 14, 15, -1 },
        };

        for (0..8) |i| {
            inline for (groups, 0..) |group, h| {
                const x: @Vector(16, u8) = bytes[24 * i + 8 * h ..][0..16].*;

                const words: Words = @bitCast(@shuffle(u8, x, @as(@Vector(16, u8), @splat(0)), group));

                const sums = (words & triples) + ((words >> @splat(1)) & triples) + ((words >> @splat(2)) & triples);

                var fields = sums & @as(Words, @splat(0x3f));

                inline for (1..4) |j| fields |= (sums << @splat(2 * j)) & @as(Words, @splat(0x3f << (8 * j)));

                const parts: @Vector(16, u8) = @bitCast(fields);

                const coefficients = @as(@Vector(16, i8), @bitCast(parts & @as(@Vector(16, u8), @splat(7)))) - @as(@Vector(16, i8), @bitCast(parts >> @splat(3)));

                out[32 * i + 16 * h ..][0..16].* = @as(@Vector(16, i16), coefficients);
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

// Noise polynomials outs[i] = CBD(PRF(seed, nonce + i)), up to four at a time.
fn sampleNoise(comptime eta: u8, seed: *const [32]u8, nonce: u8, outs: []const *Poly) void {
    var bytes: [4][64 * eta]u8 = undefined;

    var inputs: [4][33]u8 = undefined;

    var copy: [136]u8 = undefined;

    defer {
        ct.wipe(std.mem.asBytes(&bytes));

        ct.wipe(std.mem.asBytes(&inputs));

        ct.wipe(&copy);
    }

    var first: usize = 0;

    while (first < outs.len) {
        const size = keccak.batch(outs.len - first);

        var messages: [4][]const u8 = undefined;

        for (inputs[0..size], messages[0..size], first..) |*input, *message, i| {
            input.* = seed.* ++ [1]u8{nonce + @as(u8, @intCast(i))};

            message.* = input;
        }

        var sponge: keccak.Sponge4 = undefined;

        sponge.startSome(136, 0x1f, messages[0..size]);

        defer sponge.wipe();

        var offset: usize = 0;

        while (offset < 64 * eta) : (offset += 136) {
            const take = @min(136, 64 * eta - offset);

            sponge.next();

            for (bytes[0..size], 0..) |*lane, i| @memcpy(lane[offset..][0..take], sponge.block(136, i, &copy)[0..take]);
        }

        for (bytes[0..size], outs[first..][0..size]) |*lane, out| binomial(eta, lane, out);

        first += size;
    }
}

fn encode12(f: *const Poly, out: *[384]u8) void {
    if (comptime cpu.neon) return aarch64.encode12(f, out);

    portable.encode12(f, out);
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
fn compress(x: U, comptime d: u5) U {
    const Long = @Vector(8, u64);

    const t = (x << @splat(d)) + @as(U, @splat(q / 2));

    const quotient = if (comptime cpu.wasm_simd) wasm.productsShifted(t, 20642679, 4) else @as(U, @truncate(@as(Long, t) * @as(Long, @splat(20642679)) >> @splat(36)));

    return quotient & @as(U, @splat((1 << d) - 1));
}

fn decompress(y: U, comptime d: u5) V {
    return @intCast((y * @as(U, @splat(q)) + @as(U, @splat(1 << (d - 1)))) >> @splat(d));
}

fn encodeCompressed(comptime d: u5, f: *const Poly, out: *[32 * @as(usize, d)]u8) void {
    const G = vec.Group(d);

    var values: [256]u32 = undefined;

    for (0..32) |i| values[8 * i ..][0..8].* = compress(canonical(load(f, 8 * i)), d);

    for (0..256 / G.count) |g| {
        var word: G.Word = 0;

        inline for (0..G.count) |i| {
            word |= @as(G.Word, values[G.count * g + i]) << (G.width * i);
        }

        G.write(word, out[G.size * g ..][0..G.size]);
    }
}

fn decodeDecompressed(comptime d: u5, bytes: *const [32 * @as(usize, d)]u8, out: *Poly) void {
    const G = vec.Group(d);

    var values: [256]u32 = undefined;

    for (0..256 / G.count) |g| {
        const word = G.read(bytes[G.size * g ..][0..G.size]);

        inline for (0..G.count) |i| {
            values[G.count * g + i] = @truncate(word >> (G.width * i) & G.mask);
        }
    }

    for (0..32) |i| store(out, 8 * i, decompress(values[8 * i ..][0..8].*, d));
}

fn fromMessage(m: *const [32]u8, out: *Poly) void {
    const positions: @Vector(8, u3) = std.simd.iota(u3, 8);

    for (m, 0..) |byte, i| {
        const bits: V = @intCast(@as(@Vector(8, u8), @splat(byte)) >> positions & @as(@Vector(8, u8), @splat(1)));

        store(out, 8 * i, -bits & splat((q + 1) / 2));
    }
}

// What an encapsulation key yields before any message: the transposed matrix (entry (i, j) of Â
// at j * k + i, so that row i gives u_i), t̂ and H(ek). Encapsulation and the re-encryption in
// decapsulation read them instead of sampling the matrix and decoding and hashing the key on
// every call. Its size is exact for k, so a smaller parameter set keeps less.
pub fn EncapsulationKey(comptime k: usize) type {
    return struct {
        matrix: [k * k]Poly,
        t: [k]Poly,
        h: [32]u8,

        // For a valid ek (checkEncapsulationKey).
        pub fn fill(self: *@This(), ek: *const [384 * k + 32]u8) void {
            primitives.digest(hash.sha3_256, &.{ek}, &self.h);

            sampleMatrix(k, ek[384 * k ..][0..32], true, &self.matrix);

            for (&self.t, 0..) |*f, i| decode12(ek[384 * i ..][0..384], f);
        }
    };
}

// The NTT-form secret s of a decapsulation key, as decryption reads it.
pub fn decodeSecret(comptime p: Parameters, dk: *const [p.decapsulationKeySize()]u8, s: *[p.k]Poly) void {
    for (s, 0..) |*f, i| decode12(dk[384 * i ..][0..384], f);
}

fn encrypt(comptime p: Parameters, key: *const EncapsulationKey(p.k), m: *const [32]u8, r: *const [32]u8, c: *[p.ciphertextSize()]u8) void {
    const k: usize = p.k;

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

    if (p.eta1 == p.eta2) {
        var outs: [2 * k + 1]*Poly = undefined;

        for (outs[0..k], &y) |*out, *f| out.* = f;

        for (outs[k..][0..k], &e1) |*out, *f| out.* = f;

        outs[2 * k] = &e2;

        sampleNoise(p.eta1, r, 0, &outs);
    } else {
        var outs: [k + 1]*Poly = undefined;

        for (outs[0..k], &y) |*out, *f| out.* = f;

        sampleNoise(p.eta1, r, 0, outs[0..k]);

        for (outs[0..k], &e1) |*out, *f| out.* = f;

        outs[k] = &e2;

        sampleNoise(p.eta2, r, k, &outs);
    }

    for (&y) |*f| ntt(f);

    var y_zeta: [k]Poly = undefined;

    defer ct.wipe(std.mem.asBytes(&y_zeta));

    for (&y_zeta, &y) |*products, *f| products.* = zetaProducts(f);

    for (0..k) |i| {
        var u: Poly = undefined;

        dot(k, entries(k, key.matrix[k * i ..][0..k]), &y, &y_zeta, &u);

        inverseNtt(&u);

        add(&u, &e1[i]);

        reduce(&u);

        encodeCompressed(p.du, &u, c[32 * @as(usize, p.du) * i ..][0 .. 32 * @as(usize, p.du)]);
    }

    var v: Poly = undefined;

    defer ct.wipe(std.mem.asBytes(&v));

    dot(k, entries(k, &key.t), &y, &y_zeta, &v);

    inverseNtt(&v);

    add(&v, &e2);

    fromMessage(m, &mu);

    add(&v, &mu);

    reduce(&v);

    encodeCompressed(p.dv, &v, c[32 * @as(usize, p.du) * k ..][0 .. 32 * @as(usize, p.dv)]);
}

fn decrypt(comptime p: Parameters, s: *const [p.k]Poly, c: *const [p.ciphertextSize()]u8, m: *[32]u8) void {
    const k: usize = p.k;

    var u: [k]Poly = undefined;

    var w: Poly = undefined;

    defer ct.wipe(std.mem.asBytes(&w));

    for (&u, 0..) |*f, i| {
        decodeDecompressed(p.du, c[32 * @as(usize, p.du) * i ..][0 .. 32 * @as(usize, p.du)], f);

        ntt(f);
    }

    var v: Poly = undefined;

    decodeDecompressed(p.dv, c[32 * @as(usize, p.du) * k ..][0 .. 32 * @as(usize, p.dv)], &v);

    var u_zeta: [k]Poly = undefined;

    for (&u_zeta, &u) |*products, *f| products.* = zetaProducts(f);

    dot(k, entries(k, s), &u, &u_zeta, &w);

    inverseNtt(&w);

    const positions: @Vector(8, u5) = std.simd.iota(u5, 8);

    for (m, 0..) |*byte, i| {
        const bits = compress(canonical(barrett(load(&v, 8 * i) - load(&w, 8 * i))), 1);

        byte.* = @truncate(@reduce(.Or, bits << positions));
    }
}

// Fills `public` when it is given, so that a generated key starts with its cache; otherwise the
// matrix lives on the stack for this call only. It is not inlined, so that a caller that
// dispatches over the parameter sets does not hold the frames of all of them at once.
pub noinline fn keyGen(comptime p: Parameters, d: *const [32]u8, z: *const [32]u8, ek: *[p.encapsulationKeySize()]u8, dk: *[p.decapsulationKeySize()]u8, s_hat: *[p.k]Poly, public: ?*EncapsulationKey(p.k)) void {
    const k: usize = p.k;

    var g: [64]u8 = undefined;

    var s: [k]Poly = undefined;

    var e: [k]Poly = undefined;

    var spare: [k * k]Poly = undefined;

    defer {
        ct.wipe(&g);

        ct.wipe(std.mem.asBytes(&s));

        ct.wipe(std.mem.asBytes(&e));
    }

    primitives.digest(hash.sha3_512, &.{ d, &.{p.k} }, &g);

    const rho = g[0..32];

    const sigma = g[32..64];

    // rho is part of the public key.
    ct.declassify(rho);

    var outs: [2 * k]*Poly = undefined;

    for (outs[0..k], &s) |*out, *f| out.* = f;

    for (outs[k..], &e) |*out, *f| out.* = f;

    sampleNoise(p.eta1, sigma, 0, &outs);

    for (outs) |f| ntt(f);

    const matrix = if (public) |key| &key.matrix else &spare;

    // The transposed matrix, as encryption reads it; row i of the matrix is its column i.
    sampleMatrix(k, rho, true, matrix);

    var s_zeta: [k]Poly = undefined;

    defer ct.wipe(std.mem.asBytes(&s_zeta));

    for (&s_zeta, &s) |*products, *f| products.* = zetaProducts(f);

    for (0..k) |i| {
        var row: [k]*const Poly = undefined;

        for (&row, 0..) |*f, j| f.* = &matrix[k * j + i];

        var t: Poly = undefined;

        dot(k, row, &s, &s_zeta, &t);

        for (0..32) |j| store(&t, 8 * j, barrett(constantProduct(load(&t, 8 * j), montgomery_square) + load(&e[i], 8 * j)));

        encode12(&t, ek[384 * i ..][0..384]);
    }

    ct.declassify(ek[0 .. 384 * k]);

    @memcpy(ek[384 * k ..], rho);

    for (&s, 0..) |*f, i| {
        encode12(f, dk[384 * i ..][0..384]);
    }

    @memcpy(dk[384 * k ..][0..ek.len], ek);

    primitives.digest(hash.sha3_256, &.{ek}, dk[768 * k + 32 ..][0..32]);

    @memcpy(dk[768 * k + 64 ..], z);

    // s exactly as decryption would decode it from the key: its canonical values.
    for (s_hat, &s) |*decoded, *f| {
        for (0..32) |j| store(decoded, 8 * j, @intCast(canonical(load(f, 8 * j))));
    }

    if (public) |key| {
        for (&key.t, 0..) |*f, i| decode12(ek[384 * i ..][0..384], f);

        key.h = dk[768 * k + 32 ..][0..32].*;
    }
}

pub fn encaps(comptime p: Parameters, key: *const EncapsulationKey(p.k), m: *const [32]u8, shared_secret: *[32]u8, c: *[p.ciphertextSize()]u8) void {
    var g: [64]u8 = undefined;

    defer ct.wipe(&g);

    primitives.digest(hash.sha3_512, &.{ m, &key.h }, &g);

    shared_secret.* = g[0..32].*;

    encrypt(p, key, m, g[32..64], c);

    ct.declassify(c);
}

// Implicit rejection: a ciphertext that does not re-encrypt to itself yields J(z || c), chosen
// with a mask so that the comparison result never reaches a branch. dk supplies z; everything
// else comes from its decoded form.
pub fn decaps(comptime p: Parameters, s_hat: *const [p.k]Poly, key: *const EncapsulationKey(p.k), dk: *const [p.decapsulationKeySize()]u8, c: *const [p.ciphertextSize()]u8) [32]u8 {
    const k: usize = p.k;

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

    decrypt(p, s_hat, c, &m);

    primitives.digest(hash.sha3_512, &.{ &m, &key.h }, &g);

    primitives.shake256(&.{ z, c }, &rejected);

    encrypt(p, key, &m, g[32..64], &again);

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

    // dk carries the encapsulation key and its hash, which are public.
    ct.declassify(dk[384 * k ..][0 .. 384 * k + 64]);

    const ek = dk[384 * k ..][0..p.encapsulationKeySize()];

    var h: [32]u8 = undefined;

    primitives.digest(hash.sha3_256, &.{ek}, &h);

    return checkEncapsulationKey(p, ek) and ct.equal(&h, dk[768 * k + 32 ..][0..32]);
}

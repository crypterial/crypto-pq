const std = @import("std");

const ct = @import("ct.zig");
const hash = @import("hash.zig");
const keccak = @import("keccak.zig");
const primitives = @import("primitives.zig");
const vec = @import("vector.zig");

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

// The arithmetic runs on eight coefficients per vector. Every lane computes exactly what the
// scalar formulas of FIPS 203 with Montgomery and Barrett reduction compute, so the results do not
// depend on the vector width.
const V = @Vector(8, i16);

const Wide = @Vector(8, i32);

const U = @Vector(8, u32);

// q^-1 modulo 2^16.
const q_inverse = -3327;

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
// and t * q agree, so the difference of the high halves is the exact quotient.
fn montgomery(a: V, b: V, b_qinv: V) V {
    return mulHigh(a, b) - mulHigh(a *% b_qinv, splat(q));
}

fn montgomeryProduct(a: V, b: V) V {
    return montgomery(a, b, b *% splat(q_inverse));
}

fn constantProduct(a: V, comptime b: i16) V {
    return montgomery(a, splat(b), splat(b *% q_inverse));
}

// The representative modulo q in [-(q - 1) / 2, (q - 1) / 2].
fn barrett(a: V) V {
    const v = ((1 << 26) + q / 2) / q;

    const t = (@as(Wide, a) * @as(Wide, @splat(v)) + @as(Wide, @splat(1 << 25))) >> @splat(26);

    return @truncate(@as(Wide, a) - t * @as(Wide, @splat(q)));
}

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

// The products of degree-one residues modulo X^2 - zeta, times 2^-16, added to r: for a pair
// (a0, a1) and (b0, b1), a1 * b1 * zeta + a0 * b0 and a0 * b1 + a1 * b0.
fn multiplyAdd(r: *Poly, a: *const Poly, b: *const Poly) void {
    for (0..16) |c| {
        const a0, const a1 = vec.split(1, load(a, 16 * c), load(a, 16 * c + 8));

        const b0, const b1 = vec.split(1, load(b, 16 * c), load(b, 16 * c + 8));

        const first = montgomery(montgomeryProduct(a1, b1), base_zetas.zeta[c], base_zetas.zeta_qinv[c]) + montgomeryProduct(a0, b0);

        const second = montgomeryProduct(a0, b1) + montgomeryProduct(a1, b0);

        const low, const high = vec.join(1, first, second);

        store(r, 16 * c, load(r, 16 * c) + low);

        store(r, 16 * c + 8, load(r, 16 * c + 8) + high);
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

// The matrix is public, so the loop may end on its values, but a fifth of the candidates are
// rejected at random: every candidate is written and the count advances by the comparison, which
// avoids a mispredicted branch per rejection. The buffer has room for the writes past the end.
fn parseUniform(buffer: *[258]i16, start: usize, block: *const [168]u8) usize {
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

fn sampleNtt(rho: *const [32]u8, x: u8, y: u8, out: *Poly) void {
    var xof = hash.shake128.create();

    xof.update(rho);

    xof.update(&.{ x, y });

    var buffer: [258]i16 = undefined;

    var count: usize = 0;

    var block: [168]u8 = undefined;

    while (count < 256) {
        xof.read(&block);

        count = parseUniform(&buffer, count, &block);
    }

    out.* = buffer[0..256].*;
}

// The k * k matrix with entry (i, j) at i * k + j, from XOF(rho, j, i), or from XOF(rho, i, j)
// for its transpose, four entries at a time.
fn sampleMatrix(comptime k: usize, rho: *const [32]u8, transposed: bool, out: *[k * k]Poly) void {
    var first: usize = 0;

    while (first + 4 <= k * k) : (first += 4) {
        var inputs: [4][34]u8 = undefined;

        var messages: [4][]const u8 = undefined;

        for (&inputs, &messages, first..) |*input, *message, e| {
            const i: u8 = @intCast(e / k);

            const j: u8 = @intCast(e % k);

            input.* = rho.* ++ (if (transposed) [2]u8{ i, j } else [2]u8{ j, i });

            message.* = input;
        }

        var sponge: keccak.Sponge4 = .init(168, 0x1f, messages);

        var buffers: [4][258]i16 = undefined;

        var counts: [4]usize = @splat(0);

        while (@reduce(.Min, @as(@Vector(4, usize), counts)) < 256) {
            var blocks: [4][168]u8 = undefined;

            sponge.squeeze(.{ &blocks[0], &blocks[1], &blocks[2], &blocks[3] });

            for (&buffers, &counts, &blocks) |*buffer, *count, *block| count.* = parseUniform(buffer, count.*, block);
        }

        for (&buffers, first..) |*buffer, e| out[e] = buffer[0..256].*;
    }

    for (first..k * k) |e| {
        const i: u8 = @intCast(e / k);

        const j: u8 = @intCast(e % k);

        if (transposed) sampleNtt(rho, i, j, &out[e]) else sampleNtt(rho, j, i, &out[e]);
    }
}

// The centered binomial distribution: each coefficient is the difference of the bit counts of
// two adjacent eta-bit groups.
fn binomial(comptime eta: u8, bytes: *const [64 * eta]u8, out: *Poly) void {
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

// Noise polynomials outs[i] = CBD(PRF(seed, nonce + i)), four at a time.
fn sampleNoise(comptime eta: u8, seed: *const [32]u8, nonce: u8, outs: []const *Poly) void {
    var bytes: [4][64 * eta]u8 = undefined;

    defer ct.wipe(std.mem.asBytes(&bytes));

    var first: usize = 0;

    while (first + 4 <= outs.len) : (first += 4) {
        var inputs: [4][33]u8 = undefined;

        for (&inputs, first..) |*input, i| input.* = seed.* ++ [1]u8{nonce + @as(u8, @intCast(i))};

        var sponge: keccak.Sponge4 = .init(136, 0x1f, .{ &inputs[0], &inputs[1], &inputs[2], &inputs[3] });

        defer sponge.wipe();

        defer ct.wipe(std.mem.asBytes(&inputs));

        var offset: usize = 0;

        while (offset < 64 * eta) : (offset += 136) {
            const size = @min(136, 64 * eta - offset);

            sponge.squeeze(.{ bytes[0][offset..][0..size], bytes[1][offset..][0..size], bytes[2][offset..][0..size], bytes[3][offset..][0..size] });
        }

        for (&bytes, outs[first..][0..4]) |*lane, out| binomial(eta, lane, out);
    }

    for (outs[first..], first..) |out, i| {
        primitives.shake256(&.{ seed, &.{nonce + @as(u8, @intCast(i))} }, &bytes[0]);

        binomial(eta, &bytes[0], out);
    }
}

fn encode12(f: *const Poly, out: *[384]u8) void {
    for (0..32) |i| {
        const values: [8]u32 = canonical(load(f, 8 * i));

        for (0..4) |j| {
            const a = values[2 * j];

            const b = values[2 * j + 1];

            out[12 * i + 3 * j] = @truncate(a);

            out[12 * i + 3 * j + 1] = @truncate((a >> 8) | (b << 4));

            out[12 * i + 3 * j + 2] = @truncate(b >> 4);
        }
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
fn compress(x: U, comptime d: u5) U {
    const Long = @Vector(8, u64);

    const t = (x << @splat(d)) + @as(U, @splat(q / 2));

    return @as(U, @truncate(@as(Long, t) * @as(Long, @splat(20642679)) >> @splat(36))) & @as(U, @splat((1 << d) - 1));
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

// What an encapsulation key yields before any message, sized for the largest parameter set: the
// transposed matrix (entry (i, j) of Â at j * k + i, so that row i gives u_i), t̂ and H(ek).
// Encapsulation and the re-encryption in decapsulation read them instead of sampling the matrix
// and decoding and hashing the key on every call.
pub const EncapsulationKey = struct {
    matrix: [16]Poly,
    t: [4]Poly,
    h: [32]u8,
};

// The decoded NTT-form secret s of a decapsulation key, which its owner wipes, next to what its
// encapsulation key yields.
pub const DecapsulationKey = struct {
    s: [4]Poly,
    public: EncapsulationKey,
};

// Zeroes the entries that k leaves unused, so that nothing of an earlier stack frame stays in a
// key, which its owner may copy around.
fn clearUnused(comptime k: usize, key: *EncapsulationKey) void {
    ct.wipe(std.mem.sliceAsBytes(key.matrix[k * k ..]));

    ct.wipe(std.mem.sliceAsBytes(key.t[k..]));
}

// For a valid ek (checkEncapsulationKey) and its hash.
pub fn expandPublic(comptime p: Parameters, ek: *const [p.encapsulationKeySize()]u8, h: *const [32]u8, key: *EncapsulationKey) void {
    const k: usize = p.k;

    clearUnused(k, key);

    sampleMatrix(k, ek[384 * k ..][0..32], true, key.matrix[0 .. k * k]);

    for (key.t[0..k], 0..) |*f, i| decode12(ek[384 * i ..][0..384], f);

    key.h = h.*;
}

// For a dk that passed checkDecapsulationKey, which compared its H(ek) with ek.
pub fn expandPrivate(comptime p: Parameters, dk: *const [p.decapsulationKeySize()]u8, key: *DecapsulationKey) void {
    const k: usize = p.k;

    expandPublic(p, dk[384 * k ..][0..p.encapsulationKeySize()], dk[768 * k + 32 ..][0..32], &key.public);

    ct.wipe(std.mem.sliceAsBytes(key.s[k..]));

    for (key.s[0..k], 0..) |*f, i| decode12(dk[384 * i ..][0..384], f);
}

fn encrypt(comptime p: Parameters, key: *const EncapsulationKey, m: *const [32]u8, r: *const [32]u8, c: *[p.ciphertextSize()]u8) void {
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

    for (0..k) |i| {
        var u: Poly = undefined;

        dot(k, key.matrix[k * i ..][0..k], &y, &u);

        inverseNtt(&u);

        add(&u, &e1[i]);

        reduce(&u);

        encodeCompressed(p.du, &u, c[32 * @as(usize, p.du) * i ..][0 .. 32 * @as(usize, p.du)]);
    }

    var v: Poly = undefined;

    defer ct.wipe(std.mem.asBytes(&v));

    dot(k, key.t[0..k], &y, &v);

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

    dot(k, s, &u, &w);

    inverseNtt(&w);

    const positions: @Vector(8, u5) = std.simd.iota(u5, 8);

    for (m, 0..) |*byte, i| {
        const bits = compress(canonical(barrett(load(&v, 8 * i) - load(&w, 8 * i))), 1);

        byte.* = @truncate(@reduce(.Or, bits << positions));
    }
}

pub fn keyGen(comptime p: Parameters, d: *const [32]u8, z: *const [32]u8, ek: *[p.encapsulationKeySize()]u8, dk: *[p.decapsulationKeySize()]u8, key: *DecapsulationKey) void {
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

    // rho is part of the public key.
    ct.declassify(rho);

    var outs: [2 * k]*Poly = undefined;

    for (outs[0..k], &s) |*out, *f| out.* = f;

    for (outs[k..], &e) |*out, *f| out.* = f;

    sampleNoise(p.eta1, sigma, 0, &outs);

    for (outs) |f| ntt(f);

    clearUnused(k, &key.public);

    ct.wipe(std.mem.sliceAsBytes(key.s[k..]));

    // The transposed matrix, as encryption reads it; row i of the matrix is its column i.
    sampleMatrix(k, rho, true, key.public.matrix[0 .. k * k]);

    for (0..k) |i| {
        var row: [k]Poly = undefined;

        for (&row, 0..) |*f, j| f.* = key.public.matrix[k * j + i];

        var t: Poly = undefined;

        dot(k, &row, &s, &t);

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

    // t and s exactly as encryption and decryption would decode them from the key.
    for (key.public.t[0..k], key.s[0..k], 0..) |*t_i, *s_i, i| {
        decode12(ek[384 * i ..][0..384], t_i);

        decode12(dk[384 * i ..][0..384], s_i);
    }

    key.public.h = dk[768 * k + 32 ..][0..32].*;
}

pub fn encaps(comptime p: Parameters, key: *const EncapsulationKey, m: *const [32]u8, shared_secret: *[32]u8, c: *[p.ciphertextSize()]u8) void {
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
pub fn decaps(comptime p: Parameters, key: *const DecapsulationKey, dk: *const [p.decapsulationKeySize()]u8, c: *const [p.ciphertextSize()]u8) [32]u8 {
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

    decrypt(p, key.s[0..k], c, &m);

    primitives.digest(hash.sha3_512, &.{ &m, &key.public.h }, &g);

    primitives.shake256(&.{ z, c }, &rejected);

    encrypt(p, &key.public, &m, g[32..64], &again);

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

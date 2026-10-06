const std = @import("std");
const builtin = @import("builtin");

const cpu = @import("cpu.zig");
const ct = @import("ct.zig");

const isa = switch (builtin.cpu.arch) {
    .aarch64 => @import("aarch64.zig"),
    .x86_64 => @import("x86_64.zig"),
    else => struct {},
};

// Debug builds give every temporary of every unrolled round its own stack slot, about 180 KiB for
// eight SHA-512 lanes, so they run the same rounds as a loop with run-time indices.
const unrolled = builtin.mode != .Debug;

pub const k256 = [64]u32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

pub const k512 = [80]u64{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

pub const iv_224 = [8]u32{ 0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4 };

pub const iv_256 = [8]u32{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

pub const iv_384 = [8]u64{
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
};

pub const iv_512 = [8]u64{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

pub const iv_512_224 = [8]u64{
    0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
    0x0f6d2b697bd44da8, 0x77e36f7304c48942, 0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1,
};

pub const iv_512_256 = [8]u64{
    0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd,
    0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2,
};

pub fn compress256(state: *[8]u32, block: *const [64]u8) void {
    blocks256(state, block);
}

pub fn compress512(state: *[8]u64, block: *const [128]u8) void {
    blocks512(state, block);
}

// Whole blocks, one after another: with the instructions the state stays in registers between
// them.
pub fn blocks256(state: *[8]u32, blocks: []const u8) void {
    if (comptime cpu.possible(.sha256)) {
        if (cpu.has(.sha256)) return isa.sha256Blocks(state, blocks);
    }

    var offset: usize = 0;

    while (offset < blocks.len) : (offset += 64) {
        portable.compress256(state, blocks[offset..][0..64]);
    }
}

pub fn blocks512(state: *[8]u64, blocks: []const u8) void {
    if (comptime cpu.possible(.sha512)) {
        if (cpu.has(.sha512)) return isa.sha512Blocks(state, blocks);
    }

    var offset: usize = 0;

    while (offset < blocks.len) : (offset += 128) {
        portable.compress512(state, blocks[offset..][0..128]);
    }
}

// The rounds on words of type u32, or u64 for SHA-512, or on vectors of them that carry
// independent computations in their lanes: AVX2 for eight SHA-256 lanes on x86-64, the SHA-2
// instructions otherwise where the CPU has them, and the portable code below. SHA-NI runs lanes
// two streams at a time in legacy SSE encodings, which measured no faster than the portable code
// on AMD and up to 289 times slower on Intel cores in builds that use AVX.
pub fn rounds256(comptime W: type, state: *[8]W, words: *const [16]W) void {
    if (comptime W == @Vector(8, u32) and cpu.possible(.avx2)) {
        if (cpu.has(.avx2)) return isa.sha256x8(state, words);
    }

    if (comptime cpu.possible(.sha256)) {
        if (cpu.has(.sha256)) return isa.sha256Rounds(W, state, words);
    }

    portable.rounds256(W, state, words);
}

pub fn rounds512(comptime W: type, state: *[8]W, words: *const [16]W) void {
    if (comptime cpu.possible(.sha512)) {
        if (cpu.has(.sha512)) return isa.sha512Rounds(W, state, words);
    }

    portable.rounds512(W, state, words);
}

fn broadcast(comptime W: type, value: anytype) W {
    return if (@typeInfo(W) == .vector) @splat(value) else value;
}

fn shr(comptime W: type, x: W, comptime r: comptime_int) W {
    if (@typeInfo(W) != .vector) return x >> r;

    const vector = @typeInfo(W).vector;

    return x >> @as(@Vector(vector.len, std.math.Log2Int(vector.child)), @splat(r));
}

// The code for every target. Fully unrolled, the eight working variables rotate by renaming
// instead of moving: at round t, variable i lives in slot (i - t) mod 8. The schedule keeps its
// last 16 words: word t lives at t % 16, so t - 15, t - 7 and t - 2 are at (t + 1) % 16,
// (t + 9) % 16 and (t + 14) % 16, and t - 16 is the slot it replaces.
pub const portable = struct {
    pub fn compress256(state: *[8]u32, block: *const [64]u8) void {
        var w: [16]u32 = undefined;

        for (&w, 0..) |*word, t| {
            word.* = std.mem.readInt(u32, block[4 * t ..][0..4], .big);
        }

        portableRounds256(u32, state, &w);
    }

    pub fn compress512(state: *[8]u64, block: *const [128]u8) void {
        var w: [16]u64 = undefined;

        for (&w, 0..) |*word, t| {
            word.* = std.mem.readInt(u64, block[8 * t ..][0..8], .big);
        }

        portableRounds512(u64, state, &w);
    }

    pub const rounds256 = portableRounds256;

    pub const rounds512 = portableRounds512;
};

fn portableRounds256(comptime W: type, state: *[8]W, words: *const [16]W) void {
    if (!unrolled) return looped(W, &k256, .{ 7, 18, 3, 17, 19, 10 }, .{ 6, 11, 25, 2, 13, 22 }, state, words);

    if (comptime by_eight and @typeInfo(W) == .vector) return roundsByEight(W, &k256, .{ 7, 18, 3, 17, 19, 10 }, .{ 6, 11, 25, 2, 13, 22 }, state, words);

    var w = words.*;

    var v = state.*;

    inline for (k256, 0..) |k, t| {
        if (t >= 16) {
            const x = w[(t + 1) % 16];

            const y = w[(t + 14) % 16];

            const s0 = std.math.rotr(W, x, 7) ^ std.math.rotr(W, x, 18) ^ shr(W, x, 3);

            const s1 = std.math.rotr(W, y, 17) ^ std.math.rotr(W, y, 19) ^ shr(W, y, 10);

            w[t % 16] = w[t % 16] +% s0 +% w[(t + 9) % 16] +% s1;
        }

        round(W, &v, t, broadcast(W, k) +% w[t % 16], .{ 6, 11, 25, 2, 13, 22 });
    }

    inline for (state, v) |*word, value| {
        word.* +%= value;
    }
}

fn portableRounds512(comptime W: type, state: *[8]W, words: *const [16]W) void {
    if (!unrolled) return looped(W, &k512, .{ 1, 8, 7, 19, 61, 6 }, .{ 14, 18, 41, 28, 34, 39 }, state, words);

    if (comptime by_eight and @typeInfo(W) == .vector) return roundsByEight(W, &k512, .{ 1, 8, 7, 19, 61, 6 }, .{ 14, 18, 41, 28, 34, 39 }, state, words);

    @setEvalBranchQuota(4000);

    var w = words.*;

    var v = state.*;

    inline for (k512, 0..) |k, t| {
        if (t >= 16) {
            const x = w[(t + 1) % 16];

            const y = w[(t + 14) % 16];

            const s0 = std.math.rotr(W, x, 1) ^ std.math.rotr(W, x, 8) ^ shr(W, x, 7);

            const s1 = std.math.rotr(W, y, 19) ^ std.math.rotr(W, y, 61) ^ shr(W, y, 6);

            w[t % 16] = w[t % 16] +% s0 +% w[(t + 9) % 16] +% s1;
        }

        round(W, &v, t, broadcast(W, k) +% w[t % 16], .{ 14, 18, 41, 28, 34, 39 });
    }

    inline for (state, v) |*word, value| {
        word.* +%= value;
    }
}

// WebAssembly engines compile the fully unrolled rounds of vectors into code whose speed varies
// widely between versions (V8 13.6 in Node 24 took 1.45 times as long as V8 12.4 in Node 22),
// while a loop over eight unrolled rounds runs about as fast in both.
const by_eight = builtin.cpu.arch.isWasm();

// Eight rounds at a time in a loop: within the eight the working variables rotate by renaming as
// in the unrolled code, and the schedule is a ring of sixteen words.
fn roundsByEight(comptime W: type, k: anytype, comptime sigma: [6]comptime_int, comptime r: [6]comptime_int, state: *[8]W, words: *const [16]W) void {
    var w = words.*;

    var v = state.*;

    var t: usize = 0;

    while (t < k.len) : (t += 8) {
        inline for (0..8) |j| {
            const u = t + j;

            if (u >= 16) {
                const x = w[(u + 1) % 16];

                const y = w[(u + 14) % 16];

                const s0 = std.math.rotr(W, x, sigma[0]) ^ std.math.rotr(W, x, sigma[1]) ^ shr(W, x, sigma[2]);

                const s1 = std.math.rotr(W, y, sigma[3]) ^ std.math.rotr(W, y, sigma[4]) ^ shr(W, y, sigma[5]);

                w[u % 16] = w[u % 16] +% s0 +% w[(u + 9) % 16] +% s1;
            }

            round(W, &v, j, broadcast(W, k[u]) +% w[u % 16], r);
        }
    }

    inline for (state, v) |*word, value| {
        word.* +%= value;
    }
}

// The rounds above with t known only at run time: `sigma` holds the rotations and the shift of
// the two schedule functions, `r` the rotations of the round functions.
fn looped(comptime W: type, k: anytype, comptime sigma: [6]comptime_int, comptime r: [6]comptime_int, state: *[8]W, words: *const [16]W) void {
    var w = words.*;

    var v = state.*;

    for (k, 0..) |constant, t| {
        if (t >= 16) {
            const x = w[(t + 1) % 16];

            const y = w[(t + 14) % 16];

            const s0 = std.math.rotr(W, x, sigma[0]) ^ std.math.rotr(W, x, sigma[1]) ^ shr(W, x, sigma[2]);

            const s1 = std.math.rotr(W, y, sigma[3]) ^ std.math.rotr(W, y, sigma[4]) ^ shr(W, y, sigma[5]);

            w[t % 16] = w[t % 16] +% s0 +% w[(t + 9) % 16] +% s1;
        }

        const kw = broadcast(W, constant) +% w[t % 16];

        const a = v[(8 - t % 8) % 8];

        const b = v[(9 - t % 8) % 8];

        const c = v[(10 - t % 8) % 8];

        const e = v[(12 - t % 8) % 8];

        const f = v[(13 - t % 8) % 8];

        const g = v[(14 - t % 8) % 8];

        const s1 = std.math.rotr(W, e, r[0]) ^ std.math.rotr(W, e, r[1]) ^ std.math.rotr(W, e, r[2]);

        const t1 = v[(15 - t % 8) % 8] +% s1 +% (((f ^ g) & e) ^ g) +% kw;

        const s0 = std.math.rotr(W, a, r[3]) ^ std.math.rotr(W, a, r[4]) ^ std.math.rotr(W, a, r[5]);

        v[(11 - t % 8) % 8] +%= t1;

        v[(15 - t % 8) % 8] = t1 +% s0 +% (((a ^ b) & c) ^ (a & b));
    }

    for (state, v) |*word, value| {
        word.* +%= value;
    }
}

inline fn round(comptime W: type, v: *[8]W, comptime t: usize, kw: W, comptime r: [6]comptime_int) void {
    const a = v[(8 - t % 8) % 8];

    const b = v[(9 - t % 8) % 8];

    const c = v[(10 - t % 8) % 8];

    const e = v[(12 - t % 8) % 8];

    const f = v[(13 - t % 8) % 8];

    const g = v[(14 - t % 8) % 8];

    const s1 = std.math.rotr(W, e, r[0]) ^ std.math.rotr(W, e, r[1]) ^ std.math.rotr(W, e, r[2]);

    const t1 = v[(15 - t % 8) % 8] +% s1 +% (((f ^ g) & e) ^ g) +% kw;

    const s0 = std.math.rotr(W, a, r[3]) ^ std.math.rotr(W, a, r[4]) ^ std.math.rotr(W, a, r[5]);

    v[(11 - t % 8) % 8] +%= t1;

    v[(15 - t % 8) % 8] = t1 +% s0 +% (((a ^ b) & c) ^ (a & b));
}

fn Sha2(comptime Word: type, comptime block_size: usize, comptime blocks: fn (*[8]Word, []const u8) void) type {
    return struct {
        const Self = @This();

        state: [8]Word,
        buffer: [block_size]u8 = undefined,
        used: usize = 0,
        length: u64 = 0,

        pub fn init(iv: *const [8]Word) Self {
            return .{ .state = iv.* };
        }

        pub fn update(self: *Self, data: []const u8) void {
            self.length +%= data.len;

            var rest = data;

            if (self.used > 0) {
                const take = @min(block_size - self.used, rest.len);

                @memcpy(self.buffer[self.used..][0..take], rest[0..take]);

                self.used += take;

                rest = rest[take..];

                if (self.used < block_size) return;

                blocks(&self.state, &self.buffer);

                self.used = 0;
            }

            const whole = rest.len / block_size * block_size;

            if (whole > 0) blocks(&self.state, rest[0..whole]);

            rest = rest[whole..];

            @memcpy(self.buffer[0..rest.len], rest);

            self.used = rest.len;
        }

        // FIPS 180-4, 5.1: the 0x80 marker, zeros, then the message length in bits, big-endian.
        // The length field is 8 bytes for SHA-256 and 16 for SHA-512; its high part is length >> 61.
        pub fn digest(self: *const Self) [8 * @sizeOf(Word)]u8 {
            const field = block_size / 8;

            var state = self.state;

            var tail: [2 * block_size]u8 = @splat(0);

            @memcpy(tail[0..self.used], self.buffer[0..self.used]);

            tail[self.used] = 0x80;

            const end: usize = if (self.used + 1 + field > block_size) 2 * block_size else block_size;

            if (field == 16) std.mem.writeInt(u64, tail[end - 16 ..][0..8], self.length >> 61, .big);

            std.mem.writeInt(u64, tail[end - 8 ..][0..8], self.length *% 8, .big);

            blocks(&state, tail[0..end]);

            var out: [8 * @sizeOf(Word)]u8 = undefined;

            for (state, 0..) |word, i| {
                std.mem.writeInt(Word, out[@sizeOf(Word) * i ..][0..@sizeOf(Word)], word, .big);
            }

            ct.wipe(std.mem.asBytes(&state));

            ct.wipe(&tail);

            return out;
        }
    };
}

pub const Sha256 = Sha2(u32, 64, blocks256);

pub const Sha512 = Sha2(u64, 128, blocks512);

// The last `count` bytes of data, fewer than sixteen, as the low bytes of a little-endian value,
// read without a store: from the sixteen bytes that end data where it has them.
pub fn lastBytes(data: []const u8, count: usize) u128 {
    if (count == 0) return 0;

    if (data.len >= 16) return std.mem.readInt(u128, data[data.len - 16 ..][0..16], .little) >> @intCast(8 * (16 - count));

    var value: u128 = 0;

    for (data[data.len - count ..], 0..) |byte, i| value |= @as(u128, byte) << @intCast(8 * i);

    return value;
}

// The padded last block or two (FIPS 180-4, 5.1) of a message that ends with data, into the zeroed
// `last`: the bytes of data after its whole blocks, the 0x80 marker, and the length field of
// `field` bytes, the message length in bits, at the end. Returns how many blocks are used. Each
// 16-byte chunk gets a single store, which the compression's load of it can forward.
fn pad(comptime block: usize, data: []const u8, bits: u128, comptime field: usize, last: *[2 * block]u8) usize {
    const tail = data[data.len - data.len % block ..];

    const used: usize = if (tail.len + 1 + field > block) 2 else 1;

    const whole = tail.len / 16;

    @memcpy(last[0 .. 16 * whole], tail[0 .. 16 * whole]);

    var marker = lastBytes(data, tail.len % 16) | @as(u128, 0x80) << @intCast(8 * (tail.len % 16));

    // The field's bytes are the last ones of the chunk, big-endian.
    const length = @byteSwap(bits) & (~@as(u128, 0) << (8 * (16 - field)));

    const end = used * block / 16 - 1;

    if (whole == end) {
        marker |= length;
    } else {
        std.mem.writeInt(u128, last[16 * end ..][0..16], length, .little);
    }

    std.mem.writeInt(u128, last[16 * whole ..][0..16], marker, .little);

    return used;
}

fn store(comptime Word: type, state: *const [8]Word, out: []u8) void {
    const size = @sizeOf(Word);

    for (0..out.len / size) |i| std.mem.writeInt(Word, out[size * i ..][0..size], state[i], .big);

    const rest = out.len % size;

    if (rest > 0) {
        const word = state[out.len / size];

        for (out[out.len - rest ..], 0..) |*byte, j| byte.* = @truncate(word >> @intCast(8 * (size - 1 - j)));
    }
}

// The digest of `absorbed` bytes, whole blocks already compressed into state, followed by data, in
// one call: the whole blocks of data go to the compression straight from data, and the padding
// after them. out receives the leading bytes of the digest.
pub fn finish256(state: [8]u32, absorbed: u64, data: []const u8, out: []u8) void {
    var s = state;

    defer ct.wipe(std.mem.asBytes(&s));

    const bits = (absorbed +% data.len) *% 8;

    if (comptime cpu.possible(.sha256) and @hasDecl(isa, "sha256Finish")) {
        if (cpu.has(.sha256)) {
            isa.sha256Finish(&s, data, bits);

            return store(u32, &s, out);
        }
    }

    var last: [128]u8 = @splat(0);

    defer ct.wipe(&last);

    const used = pad(64, data, bits, 8, &last);

    blocks256(&s, data[0 .. data.len / 64 * 64]);

    blocks256(&s, last[0 .. 64 * used]);

    store(u32, &s, out);
}

pub fn finish512(state: [8]u64, absorbed: u128, data: []const u8, out: []u8) void {
    var s = state;

    defer ct.wipe(std.mem.asBytes(&s));

    const bits = (absorbed +% data.len) *% 8;

    if (comptime cpu.possible(.sha512) and @hasDecl(isa, "sha512Finish")) {
        if (cpu.has(.sha512)) {
            isa.sha512Finish(&s, data, bits);

            return store(u64, &s, out);
        }
    }

    var last: [256]u8 = @splat(0);

    defer ct.wipe(&last);

    const used = pad(128, data, bits, 16, &last);

    blocks512(&s, data[0 .. data.len / 128 * 128]);

    blocks512(&s, last[0 .. 128 * used]);

    store(u64, &s, out);
}

// The states after HMAC's (RFC 2104) inner and outer key blocks, the key, at most a block, padded
// with zeros and XORed with 0x36 and 0x5c, compressed side by side as two lanes.
pub fn keyed256(iv: *const [8]u32, key: []const u8) [2][8]u32 {
    var block: [64]u8 = @splat(0);

    defer ct.wipe(&block);

    @memcpy(block[0..key.len], key);

    var states: [8]@Vector(2, u32) = undefined;

    defer ct.wipe(std.mem.asBytes(&states));

    for (&states, iv) |*lanes, word| lanes.* = @splat(word);

    var words: [16]@Vector(2, u32) = undefined;

    defer ct.wipe(std.mem.asBytes(&words));

    for (&words, 0..) |*lanes, t| {
        const word = std.mem.readInt(u32, block[4 * t ..][0..4], .big);

        lanes.* = .{ word ^ 0x36363636, word ^ 0x5c5c5c5c };
    }

    rounds256(@Vector(2, u32), &states, &words);

    var keyed: [2][8]u32 = undefined;

    for (states, 0..) |lanes, i| {
        keyed[0][i] = lanes[0];

        keyed[1][i] = lanes[1];
    }

    return keyed;
}

pub fn keyed512(iv: *const [8]u64, key: []const u8) [2][8]u64 {
    var block: [128]u8 = @splat(0);

    defer ct.wipe(&block);

    @memcpy(block[0..key.len], key);

    var states: [8]@Vector(2, u64) = undefined;

    defer ct.wipe(std.mem.asBytes(&states));

    for (&states, iv) |*lanes, word| lanes.* = @splat(word);

    var words: [16]@Vector(2, u64) = undefined;

    defer ct.wipe(std.mem.asBytes(&words));

    for (&words, 0..) |*lanes, t| {
        const word = std.mem.readInt(u64, block[8 * t ..][0..8], .big);

        lanes.* = .{ word ^ 0x3636363636363636, word ^ 0x5c5c5c5c5c5c5c5c };
    }

    rounds512(@Vector(2, u64), &states, &words);

    var keyed: [2][8]u64 = undefined;

    for (states, 0..) |lanes, i| {
        keyed[0][i] = lanes[0];

        keyed[1][i] = lanes[1];
    }

    return keyed;
}

// HMAC-SHA-256, or HMAC-SHA-224 for a 28-byte tag, under a key of at most a block.
pub fn hmac256(iv: *const [8]u32, key: []const u8, data: []const u8, tag: []u8) void {
    if (comptime cpu.possible(.sha256) and @hasDecl(isa, "hmac256")) {
        if (cpu.has(.sha256)) return isa.hmac256(iv, key, data, tag);
    }

    var keyed = keyed256(iv, key);

    defer ct.wipe(std.mem.asBytes(&keyed));

    var inner: [32]u8 = undefined;

    defer ct.wipe(&inner);

    finish256(keyed[0], 64, data, inner[0..tag.len]);

    finish256(keyed[1], 64, inner[0..tag.len], tag);
}

// HMAC-SHA-512, or HMAC-SHA-384 for a 48-byte tag, under a key of at most a block.
pub fn hmac512(iv: *const [8]u64, key: []const u8, data: []const u8, tag: []u8) void {
    if (comptime cpu.possible(.sha512) and @hasDecl(isa, "hmac512")) {
        if (cpu.has(.sha512)) return isa.hmac512(iv, key, data, tag);
    }

    var keyed = keyed512(iv, key);

    defer ct.wipe(std.mem.asBytes(&keyed));

    var inner: [64]u8 = undefined;

    defer ct.wipe(&inner);

    finish512(keyed[0], 128, data, inner[0..tag.len]);

    finish512(keyed[1], 128, inner[0..tag.len], tag);
}

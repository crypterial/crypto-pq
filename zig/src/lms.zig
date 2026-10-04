const std = @import("std");

const ct = @import("ct.zig");
const Error = @import("errors.zig").Error;
const hash = @import("hash.zig");
const merkle = @import("merkle.zig");
const primitives = @import("primitives.zig");
const sha2 = @import("sha2.zig");
const vec = @import("vector.zig");

const Allocator = std.mem.Allocator;

const d_pblc = [2]u8{ 0x80, 0x80 };

const d_mesg = [2]u8{ 0x81, 0x81 };

const d_leaf = [2]u8{ 0x82, 0x82 };

const d_intr = [2]u8{ 0x83, 0x83 };

// Pseudorandom values derived from a tree's SEED (RFC 8554, Appendix A, and the convention of
// the hash-sigs reference used by the RFC 8554 and RFC 9858 test cases): the signature
// randomizer C, and the SEED and I of a child tree. Chain indices are below 0xFFFD.
const randomizer = 0xfffd;

const child_seed = 0xfffe;

const child_i = 0xffff;

const max_n = 32;

const max_p = 265;

const OtsType = struct {
    code: u32,
    name: []const u8,
    shake: bool,
    n: usize,
    w: u4,

    fn u(self: OtsType) usize {
        return (8 * self.n + self.w - 1) / self.w;
    }

    fn v(self: OtsType) usize {
        const largest = ((@as(usize, 1) << self.w) - 1) * self.u();

        const bits = std.math.log2_int(usize, largest) + 1;

        return (bits + self.w - 1) / self.w;
    }

    pub fn p(self: OtsType) usize {
        return self.u() + self.v();
    }

    fn ls(self: OtsType) u4 {
        return @intCast(16 - self.v() * self.w);
    }

    pub fn signatureSize(self: OtsType) usize {
        return 4 + self.n * (self.p() + 1);
    }
};

const LmsType = struct {
    code: u32,
    name: []const u8,
    shake: bool,
    m: usize,
    h: u6,

    pub fn publicKeySize(self: LmsType) usize {
        return 24 + self.m;
    }
};

pub const Level = struct {
    lms: LmsType,
    ots: OtsType,
};

const families = [_]struct { shake: bool, n: usize, ots: []const u8, lms: []const u8 }{
    .{ .shake = false, .n = 32, .ots = "SHA256_N32", .lms = "SHA256_M32" },
    .{ .shake = false, .n = 24, .ots = "SHA256_N24", .lms = "SHA256_M24" },
    .{ .shake = true, .n = 32, .ots = "SHAKE_N32", .lms = "SHAKE_M32" },
    .{ .shake = true, .n = 24, .ots = "SHAKE_N24", .lms = "SHAKE_M24" },
};

const ots_types = blk: {
    var types: [16]OtsType = undefined;

    for (families, 0..) |family, index| {
        for ([_]u4{ 1, 2, 4, 8 }, 0..) |w, j| {
            types[4 * index + j] = .{ .code = 1 + 4 * index + j, .name = std.fmt.comptimePrint("LMOTS_{s}_W{d}", .{ family.ots, w }), .shake = family.shake, .n = family.n, .w = w };
        }
    }

    break :blk types;
};

const lms_types = blk: {
    var types: [20]LmsType = undefined;

    for (families, 0..) |family, index| {
        for ([_]u6{ 5, 10, 15, 20, 25 }, 0..) |h, j| {
            types[5 * index + j] = .{ .code = 5 + 5 * index + j, .name = std.fmt.comptimePrint("LMS_{s}_H{d}", .{ family.lms, h }), .shake = family.shake, .m = family.n, .h = h };
        }
    }

    break :blk types;
};

pub fn otsByCode(code: u32) ?OtsType {
    for (ots_types) |t| {
        if (t.code == code) return t;
    }

    return null;
}

pub fn lmsByCode(code: u32) ?LmsType {
    for (lms_types) |t| {
        if (t.code == code) return t;
    }

    return null;
}

pub fn otsByName(name: []const u8) ?OtsType {
    for (ots_types) |t| {
        if (std.mem.eql(u8, t.name, name)) return t;
    }

    return null;
}

pub fn lmsByName(name: []const u8) ?LmsType {
    for (lms_types) |t| {
        if (std.mem.eql(u8, t.name, name)) return t;
    }

    return null;
}

// HSS levels share one hash function and output size, and the total height is at most 60.
pub fn validLevels(levels: []const Level) bool {
    if (levels.len < 1 or levels.len > 8) return false;

    var height: usize = 0;

    for (levels) |level| {
        const first = levels[0].lms;

        if (level.lms.shake != first.shake or level.lms.m != first.m or level.ots.shake != first.shake or level.ots.n != first.m) return false;

        height += level.lms.h;
    }

    return height <= 60;
}

fn u32Bytes(value: u32) [4]u8 {
    var out: [4]u8 = undefined;

    std.mem.writeInt(u32, &out, value, .big);

    return out;
}

fn u16Bytes(value: u16) [2]u8 {
    var out: [2]u8 = undefined;

    std.mem.writeInt(u16, &out, value, .big);

    return out;
}

// SHA-256 truncated to n bytes, or SHAKE256 with n bytes of output.
const Hash = struct {
    shake: bool,
    n: usize,

    fn digest(self: Hash, parts: []const []const u8, out: []u8) void {
        var length: usize = 0;

        for (parts) |part| length += part.len;

        if (self.shake and length <= 135) return primitives.shake256Short(parts, out[0..self.n]);

        if (!self.shake and length <= 183) return primitives.sha256Finish(&sha2.iv_256, 0, parts, out[0..self.n]);

        var stream = self.start();

        for (parts) |part| stream.update(part);

        stream.finish(out[0..self.n]);
    }

    fn start(self: Hash) Stream {
        return if (self.shake) .{ .shake = hash.shake256.create() } else .{ .sha256 = hash.sha_256.create() };
    }
};

const Stream = union(enum) {
    shake: hash.Xof,
    sha256: hash.Hasher,

    fn update(self: *Stream, data: []const u8) void {
        switch (self.*) {
            inline else => |*engine| engine.update(data),
        }
    }

    // Fills `out` with the first out.len bytes of the output.
    fn finish(self: *Stream, out: []u8) void {
        switch (self.*) {
            .shake => |*xof| xof.read(out),
            .sha256 => |*hasher| {
                var full: [32]u8 = undefined;

                hasher.digest(&full);

                @memcpy(out, full[0..out.len]);
            },
        }
    }
};

fn derive(h: Hash, i_value: *const [16]u8, q: u32, index: u16, seed: []const u8, out: []u8) void {
    h.digest(&.{ i_value, &u32Bytes(q), &u16Bytes(index), &.{0xff}, seed }, out);
}

fn coefficient(t: OtsType, data: []const u8, i: usize) u32 {
    const per_byte = 8 / @as(usize, t.w);

    const shift: u3 = @intCast(8 - @as(usize, t.w) * (i % per_byte + 1));

    return (data[i / per_byte] >> shift) & ((@as(u32, 1) << t.w) - 1);
}

// The Winternitz digits of Q followed by those of its checksum.
fn digits(t: OtsType, q_hash: []const u8, out: *[max_p]u32) void {
    const count = 8 * t.n / t.w;

    var checksum: u32 = 0;

    for (0..count) |i| {
        out[i] = coefficient(t, q_hash, i);

        checksum += ((@as(u32, 1) << t.w) - 1) - out[i];
    }

    const tail = u16Bytes(@intCast(checksum << t.ls()));

    for (count..t.p()) |i| {
        out[i] = coefficient(t, &tail, i - count);
    }
}

fn chain(t: OtsType, i_value: *const [16]u8, q: u32, j: u16, start: usize, end: usize, x: []u8) void {
    const h: Hash = .{ .shake = t.shake, .n = t.n };

    for (start..end) |k| {
        h.digest(&.{ i_value, &u32Bytes(q), &u16Bytes(j), &.{@intCast(k)}, x[0..t.n] }, x);
    }
}

fn otsPublicKey(t: OtsType, i_value: *const [16]u8, q: u32, seed: []const u8, out: []u8) void {
    const h: Hash = .{ .shake = t.shake, .n = t.n };

    var stream = h.start();

    defer ct.wipe(std.mem.asBytes(&stream));

    for ([_][]const u8{ i_value, &u32Bytes(q), &d_pblc }) |part| stream.update(part);

    var y: [max_n]u8 = undefined;

    defer ct.wipe(&y);

    for (0..t.p()) |j| {
        derive(h, i_value, q, @intCast(j), seed, &y);

        chain(t, i_value, q, @intCast(j), 0, (@as(usize, 1) << t.w) - 1, &y);

        stream.update(y[0..t.n]);
    }

    stream.finish(out[0..t.n]);
}

fn otsSign(t: OtsType, i_value: *const [16]u8, q: u32, seed: []const u8, message: []const u8, out: []u8) void {
    const h: Hash = .{ .shake = t.shake, .n = t.n };

    const n = t.n;

    out[0..4].* = u32Bytes(t.code);

    const c = out[4..][0..n];

    derive(h, i_value, q, randomizer, seed, c);

    // C is part of the signature, so the digits of Q are public as well.
    ct.declassify(c);

    var q_hash: [max_n]u8 = undefined;

    h.digest(&.{ i_value, &u32Bytes(q), &d_mesg, c, message }, &q_hash);

    var a: [max_p]u32 = undefined;

    digits(t, q_hash[0..n], &a);

    if (!t.shake) {
        const values = out[4 + n ..][0 .. t.p() * n];

        const zeros: [max_p]u32 = @splat(0);

        switch (n) {
            inline 24, 32 => |size| {
                Lanes(max_lanes).derive(size / 4, i_value, q, seed, t.p(), values);

                Lanes(max_lanes).chains(size / 4, i_value, q, zeros[0..t.p()], a[0..t.p()], values);
            },
            else => unreachable,
        }

        return;
    }

    for (a[0..t.p()], 0..) |digit, j| {
        const y = out[4 + n * (j + 1) ..][0..n];

        derive(h, i_value, q, @intCast(j), seed, y);

        chain(t, i_value, q, @intCast(j), 0, digit, y);
    }
}

// The OTS public key that the signature implies (RFC 8554, Algorithm 4b).
fn otsCandidate(t: OtsType, i_value: *const [16]u8, q: u32, signature: []const u8, message: []const u8, out: []u8) void {
    const h: Hash = .{ .shake = t.shake, .n = t.n };

    const n = t.n;

    const c = signature[4..][0..n];

    var q_hash: [max_n]u8 = undefined;

    h.digest(&.{ i_value, &u32Bytes(q), &d_mesg, c, message }, &q_hash);

    var a: [max_p]u32 = undefined;

    digits(t, q_hash[0..n], &a);

    var stream = h.start();

    for ([_][]const u8{ i_value, &u32Bytes(q), &d_pblc }) |part| stream.update(part);

    if (!t.shake) {
        var values: [max_p * max_n]u8 = undefined;

        @memcpy(values[0 .. t.p() * n], signature[4 + n ..][0 .. t.p() * n]);

        const ends: [max_p]u32 = @splat((@as(u32, 1) << t.w) - 1);

        switch (n) {
            inline 24, 32 => |size| Lanes(max_lanes).chains(size / 4, i_value, q, a[0..t.p()], ends[0..t.p()], values[0 .. t.p() * n]),
            else => unreachable,
        }

        stream.update(values[0 .. t.p() * n]);

        stream.finish(out[0..n]);

        return;
    }

    for (a[0..t.p()], 0..) |digit, j| {
        var z: [max_n]u8 = undefined;

        @memcpy(z[0..n], signature[4 + n * (j + 1) ..][0..n]);

        chain(t, i_value, q, @intCast(j), digit, (@as(usize, 1) << t.w) - 1, &z);

        stream.update(z[0..n]);
    }

    stream.finish(out[0..n]);
}

fn lmsSignatureSize(level: Level) usize {
    return 8 + level.ots.signatureSize() + level.lms.h * level.lms.m;
}

const PublicKey = struct {
    level: Level,
    i_value: *const [16]u8,
    root: []const u8,
};

fn parsePublicKey(data: []const u8) ?PublicKey {
    if (data.len < 8) return null;

    const lms = lmsByCode(std.mem.readInt(u32, data[0..4], .big)) orelse return null;

    const ots = otsByCode(std.mem.readInt(u32, data[4..8], .big)) orelse return null;

    if (lms.shake != ots.shake or lms.m != ots.n or data.len != lms.publicKeySize()) return null;

    return .{ .level = .{ .lms = lms, .ots = ots }, .i_value = data[8..24], .root = data[24..] };
}

fn lmsVerify(public_key: []const u8, message: []const u8, signature: []const u8) bool {
    const key = parsePublicKey(public_key) orelse return false;

    const lms = key.level.lms;

    const ots = key.level.ots;

    if (signature.len < 8) return false;

    const q = std.mem.readInt(u32, signature[0..4], .big);

    if (std.mem.readInt(u32, signature[4..8], .big) != ots.code or signature.len != lmsSignatureSize(key.level)) return false;

    const offset = 4 + ots.signatureSize();

    if (std.mem.readInt(u32, signature[offset..][0..4], .big) != lms.code or q >= @as(u64, 1) << lms.h) return false;

    var node: u32 = (@as(u32, 1) << @intCast(lms.h)) | q;

    var k: [max_n]u8 = undefined;

    otsCandidate(ots, key.i_value, q, signature[4..offset], message, &k);

    const h: Hash = .{ .shake = lms.shake, .n = lms.m };

    var candidate: [max_n]u8 = undefined;

    h.digest(&.{ key.i_value, &u32Bytes(node), &d_leaf, k[0..ots.n] }, &candidate);

    for (0..lms.h) |i| {
        const sibling = signature[offset + 4 + i * lms.m ..][0..lms.m];

        const left: []const u8 = if (node & 1 == 1) sibling else candidate[0..lms.m];

        const right: []const u8 = if (node & 1 == 1) candidate[0..lms.m] else sibling;

        node >>= 1;

        h.digest(&.{ key.i_value, &u32Bytes(node), &d_intr, left, right }, &candidate);
    }

    return std.mem.eql(u8, candidate[0..lms.m], key.root);
}

pub fn checkPublicKey(data: []const u8) bool {
    if (data.len < 4) return false;

    const levels = std.mem.readInt(u32, data[0..4], .big);

    return levels >= 1 and levels <= 8 and parsePublicKey(data[4..]) != null;
}

pub fn hssVerify(public_key: []const u8, message: []const u8, signature: []const u8) bool {
    if (!checkPublicKey(public_key) or signature.len < 4) return false;

    const levels = std.mem.readInt(u32, public_key[0..4], .big);

    if (std.mem.readInt(u32, signature[0..4], .big) != levels - 1) return false;

    var key = public_key[4..];

    var offset: usize = 4;

    for (0..levels - 1) |_| {
        const end = offset + lmsSignatureSize(parsePublicKey(key).?.level);

        if (signature.len < end + 8) return false;

        const child_lms = lmsByCode(std.mem.readInt(u32, signature[end..][0..4], .big)) orelse return false;

        const child = signature[end..@min(end + child_lms.publicKeySize(), signature.len)];

        if (parsePublicKey(child) == null or !lmsVerify(key, child, signature[offset..end])) return false;

        key = child;

        offset = end + child.len;
    }

    return lmsVerify(key, message, signature[offset..]);
}

// Independent SHA-256 computations run side by side in the lanes of vectors. A target without
// vector registers computes one at a time: emulated lanes cost as much each and spill to the stack.
const max_lanes = if (std.simd.suggestVectorLength(u32) == null) 1 else 8;

// SHA-256 of L hashes at once: lane l of every vector belongs to the l-th. Values are kept as
// big-endian 32-bit words. Every hash starts with I || u32: a chain step or seed derivation then
// puts its value at byte offset 23, the public key and leaf hashes put theirs at offset 22, so
// the value words are split across two block words.
fn Lanes(comptime L: usize) type {
    return struct {
        const V = @Vector(L, u32);

        fn splat(value: u32) V {
            return @splat(value);
        }

        fn shl(x: V, comptime r: u5) V {
            return x << @as(@Vector(L, u5), @splat(r));
        }

        fn shr(x: V, comptime r: u5) V {
            return x >> @as(@Vector(L, u5), @splat(r));
        }

        fn words(bytes: []const u8, out: []V) void {
            for (out, 0..) |*word, i| word.* = splat(std.mem.readInt(u32, bytes[4 * i ..][0..4], .big));
        }

        fn initial() [8]V {
            var state: [8]V = undefined;

            for (&state, sha2.iv_256) |*word, value| word.* = @splat(value);

            return state;
        }

        // H(I || u32(q) || u16(j) || u8(k) || x) on m-word values: a chain step, or a seed
        // derivation with k = 0xff.
        fn step(comptime m: usize, i_words: *const [4]V, q: V, j: V, k: V, x: *const [m]V, out: *[m]V) void {
            var block: [16]V = undefined;

            defer ct.wipe(std.mem.asBytes(&block));

            block[0..4].* = i_words.*;

            block[4] = q;

            block[5] = shl(j, 16) | shl(k, 8) | shr(x[0], 24);

            inline for (1..m) |i| {
                block[5 + i] = shl(x[i - 1], 8) | shr(x[i], 24);
            }

            block[5 + m] = shl(x[m - 1], 8) | splat(0x80);

            inline for (6 + m..15) |i| {
                block[i] = splat(0);
            }

            block[15] = splat((23 + 4 * m) * 8);

            var state = initial();

            defer ct.wipe(std.mem.asBytes(&state));

            sha2.rounds256(V, &state, &block);

            out.* = state[0..m].*;
        }

        // H(I || u32(r) || D_LEAF || K).
        fn leafHash(comptime m: usize, i_words: *const [4]V, r: V, key: *const [m]V, out: *[m]V) void {
            var block: [16]V = undefined;

            block[0..4].* = i_words.*;

            block[4] = r;

            block[5] = splat(@as(u32, std.mem.readInt(u16, &d_leaf, .big)) << 16) | shr(key[0], 16);

            inline for (1..m) |i| {
                block[5 + i] = shl(key[i - 1], 16) | shr(key[i], 16);
            }

            block[5 + m] = shl(key[m - 1], 16) | splat(0x8000);

            inline for (6 + m..15) |i| {
                block[i] = splat(0);
            }

            block[15] = splat((22 + 4 * m) * 8);

            var state = initial();

            sha2.rounds256(V, &state, &block);

            out.* = state[0..m].*;
        }

        // K = H(I || u32(q) || D_PBLC || y_0 || ... || y_(p-1)), fed one chain end at a time.
        const KeyStream = struct {
            state: [8]V,
            block: [16]V,
            count: usize,
            carry: V,
            bytes: usize,

            fn init(i_words: *const [4]V, q: V) KeyStream {
                var self: KeyStream = .{ .state = initial(), .block = undefined, .count = 5, .carry = splat(@as(u32, std.mem.readInt(u16, &d_pblc, .big)) << 16), .bytes = 22 };

                self.block[0..4].* = i_words.*;

                self.block[4] = q;

                return self;
            }

            fn push(self: *KeyStream, word: V) void {
                self.block[self.count] = word;

                self.count += 1;

                if (self.count == 16) {
                    sha2.rounds256(V, &self.state, &self.block);

                    self.count = 0;
                }
            }

            fn absorb(self: *KeyStream, value: []const V) void {
                for (value) |word| {
                    self.push(self.carry | shr(word, 16));

                    self.carry = shl(word, 16);
                }

                self.bytes += 4 * value.len;
            }

            // The bit length fills the last two words of a block.
            fn finish(self: *KeyStream, out: []V) void {
                self.push(self.carry | splat(0x8000));

                if (self.count > 16 - 2) {
                    @memset(self.block[self.count..], splat(0));

                    sha2.rounds256(V, &self.state, &self.block);

                    self.count = 0;
                }

                @memset(self.block[self.count..15], splat(0));

                self.block[15] = splat(@intCast(self.bytes * 8));

                sha2.rounds256(V, &self.state, &self.block);

                @memcpy(out, self.state[0..out.len]);
            }
        };

        fn scatter(value: []const V, out: []u8) void {
            for (value, 0..) |word, w| {
                const values: [L]u32 = word;

                for (0..out.len / (4 * value.len)) |l| std.mem.writeInt(u32, out[4 * (l * value.len + w) ..][0..4], values[l], .big);
            }
        }

        // The leaves of key pairs first .. first + out.len / n - 1, one per lane.
        fn leaves(comptime m: usize, context: *const TreeContext, first: u32, out: []u8) void {
            const ots = context.level.ots;

            var i_words: [4]V = undefined;

            words(&context.i_value, &i_words);

            const q = std.simd.iota(u32, L) + splat(first);

            var seed: [m]V = undefined;

            var y: [m]V = undefined;

            defer {
                ct.wipe(std.mem.asBytes(&seed));

                ct.wipe(std.mem.asBytes(&y));
            }

            words(context.seed[0 .. 4 * m], &seed);

            var stream: KeyStream = .init(&i_words, q);

            for (0..ots.p()) |j| {
                step(m, &i_words, q, splat(@intCast(j)), splat(0xff), &seed, &y);

                for (0..(@as(usize, 1) << ots.w) - 1) |k| step(m, &i_words, q, splat(@intCast(j)), splat(@intCast(k)), &y, &y);

                stream.absorb(&y);
            }

            var key: [m]V = undefined;

            stream.finish(&key);

            var leaf: [m]V = undefined;

            leafHash(m, &i_words, q + splat(@as(u32, 1) << @intCast(context.level.lms.h)), &key, &leaf);

            scatter(&leaf, out);
        }

        // Runs chain j of key pair q from step starts[j] to ends[j] on the values in place.
        fn chains(comptime m: usize, i_value: *const [16]u8, q: u32, starts: []const u32, ends: []const u32, values: []u8) void {
            var i_words: [4]V = undefined;

            words(i_value, &i_words);

            var lanes: vec.ChainLanes(L, m) = .init(starts, ends, values);

            var value: [m]V = undefined;

            defer {
                lanes.wipe();

                ct.wipe(std.mem.asBytes(&value));
            }

            while (lanes.running > 0) {
                value = lanes.current();

                step(m, &i_words, splat(q), lanes.chain, lanes.step, &value, &value);

                lanes.advance(&value);
            }
        }

        // The starting values of all p chains: x_j = H(I || u32(q) || u16(j) || 0xff || SEED).
        fn derive(comptime m: usize, i_value: *const [16]u8, q: u32, seed: []const u8, p: usize, out: []u8) void {
            var i_words: [4]V = undefined;

            words(i_value, &i_words);

            var seed_words: [m]V = undefined;

            var x: [m]V = undefined;

            defer {
                ct.wipe(std.mem.asBytes(&seed_words));

                ct.wipe(std.mem.asBytes(&x));
            }

            words(seed[0 .. 4 * m], &seed_words);

            var j: usize = 0;

            while (j < p) : (j += L) {
                step(m, &i_words, splat(q), std.simd.iota(u32, L) + splat(@intCast(j)), splat(0xff), &seed_words, &x);

                scatter(&x, out[j * 4 * m ..][0 .. @as(usize, @min(L, p - j)) * 4 * m]);
            }
        }
    };
}

const TreeContext = struct {
    level: Level,
    i_value: [16]u8,
    seed: [max_n]u8,

    fn hasher(self: *const TreeContext) Hash {
        return .{ .shake = self.level.lms.shake, .n = self.level.lms.m };
    }

    pub fn leaf(self: *const TreeContext, index: u64, out: []u8) void {
        const lms = self.level.lms;

        var k: [max_n]u8 = undefined;

        otsPublicKey(self.level.ots, &self.i_value, @intCast(index), self.seed[0..lms.m], &k);

        self.hasher().digest(&.{ &self.i_value, &u32Bytes(@intCast((@as(u64, 1) << lms.h) + index)), &d_leaf, k[0..lms.m] }, out);
    }

    pub const lanes = max_lanes;

    pub fn leaves(self: *const TreeContext, first: u64, out: []u8) void {
        const n = self.level.lms.m;

        if (self.level.lms.shake) {
            for (0..out.len / n) |i| self.leaf(first + i, out[i * n ..][0..n]);

            return;
        }

        switch (n) {
            inline 24, 32 => |size| Lanes(max_lanes).leaves(size / 4, self, @intCast(first), out),
            else => unreachable,
        }
    }

    pub fn combine(self: *const TreeContext, z: u32, j: u64, left: []const u8, right: []const u8, out: []u8) void {
        const r: u32 = @intCast((@as(u64, 1) << @intCast(self.level.lms.h - z - 1)) + j);

        self.hasher().digest(&.{ &self.i_value, &u32Bytes(r), &d_intr, left, right }, out);
    }
};

// One LMS tree of an HSS key: its I, SEED and the Merkle tree over its OTS public keys.
const Tree = struct {
    merkle: merkle.MerkleTree(TreeContext),

    fn init(allocator: Allocator, level: Level) (Error || Allocator.Error)!Tree {
        return .{ .merkle = try .init(allocator, level.lms.h, level.lms.m) };
    }

    fn build(self: *Tree, level: Level, i_value: *const [16]u8, seed: []const u8) void {
        var context: TreeContext = .{ .level = level, .i_value = i_value.*, .seed = @splat(0) };

        defer ct.wipe(&context.seed);

        @memcpy(context.seed[0..seed.len], seed);

        self.merkle.build(context);

        // I and the root form the tree's public key.
        ct.declassify(&self.merkle.context.i_value);

        ct.declassify(&self.merkle.root);
    }

    fn deinit(self: *Tree, allocator: Allocator) void {
        ct.wipe(&self.merkle.context.seed);

        self.merkle.deinit(allocator);
    }

    fn publicKey(self: *const Tree, out: []u8) []u8 {
        const lms = self.merkle.context.level.lms;

        out[0..4].* = u32Bytes(lms.code);

        out[4..8].* = u32Bytes(self.merkle.context.level.ots.code);

        out[8..24].* = self.merkle.context.i_value;

        @memcpy(out[24..][0..lms.m], self.merkle.root[0..lms.m]);

        return out[0..lms.publicKeySize()];
    }

    fn sign(self: *Tree, q: u32, message: []const u8, out: []u8) void {
        const context = &self.merkle.context;

        const ots = context.level.ots;

        out[0..4].* = u32Bytes(q);

        otsSign(ots, &context.i_value, q, context.seed[0..ots.n], message, out[4..][0..ots.signatureSize()]);

        const offset = 4 + ots.signatureSize();

        out[offset..][0..4].* = u32Bytes(context.level.lms.code);

        self.merkle.authPath(q, out[offset + 4 ..][0 .. context.level.lms.h * context.level.lms.m]);
    }

    // The I and SEED of the child tree under leaf q.
    fn child(self: *const Tree, q: u32, i_value: *[16]u8, seed: *[max_n]u8) void {
        const context = &self.merkle.context;

        const h = context.hasher();

        derive(h, &context.i_value, q, child_seed, context.seed[0..h.n], seed);

        var full: [max_n]u8 = undefined;

        derive(h, &context.i_value, q, child_i, context.seed[0..h.n], &full);

        i_value.* = full[0..16].*;
    }
};

// The signing side of an HSS key: the trees on the path to the next leaf, rebuilt when the
// index leaves a tree, and each child public key signed by its parent. Every level has its tree
// memory from the start, so that signing never allocates.
pub const Hss = struct {
    levels: [8]Level,
    count: usize,
    trees: [8]Tree,
    built: usize,
    signed: [7][]u8,
    prefixes: [8]u64,

    pub fn init(allocator: Allocator, levels: []const Level, i_value: *const [16]u8, seed: []const u8) (Error || Allocator.Error)!Hss {
        var self: Hss = .{ .levels = undefined, .count = levels.len, .trees = undefined, .built = 1, .signed = undefined, .prefixes = @splat(0) };

        @memcpy(self.levels[0..levels.len], levels);

        var trees: usize = 0;

        errdefer for (self.trees[0..trees]) |*tree| tree.deinit(allocator);

        while (trees < levels.len) : (trees += 1) {
            self.trees[trees] = try .init(allocator, levels[trees]);
        }

        var signed: usize = 0;

        errdefer for (self.signed[0..signed]) |buffer| allocator.free(buffer);

        while (signed + 1 < levels.len) : (signed += 1) {
            self.signed[signed] = try allocator.alloc(u8, lmsSignatureSize(levels[signed]) + levels[signed + 1].lms.publicKeySize());
        }

        self.trees[0].build(levels[0], i_value, seed);

        return self;
    }

    pub fn deinit(self: *Hss, allocator: Allocator) void {
        for (self.trees[0..self.count]) |*tree| tree.deinit(allocator);

        for (self.signed[0 .. self.count - 1]) |buffer| allocator.free(buffer);
    }

    fn heightBelow(self: *const Hss, level: usize) u6 {
        var height: u6 = 0;

        for (self.levels[level..self.count]) |l| height += l.lms.h;

        return height;
    }

    pub fn capacity(self: *const Hss) u64 {
        return @as(u64, 1) << self.heightBelow(0);
    }

    fn leafIndex(self: *const Hss, index: u64, level: usize) u32 {
        return @intCast((index >> self.heightBelow(level + 1)) & ((@as(u64, 1) << self.levels[level].lms.h) - 1));
    }

    pub fn signatureSize(self: *const Hss) usize {
        var size: usize = 4 + lmsSignatureSize(self.levels[self.count - 1]);

        for (0..self.count - 1) |i| {
            size += lmsSignatureSize(self.levels[i]) + self.levels[i + 1].lms.publicKeySize();
        }

        return size;
    }

    pub fn publicKey(self: *const Hss, out: *[60]u8) []u8 {
        out[0..4].* = u32Bytes(@intCast(self.count));

        return out[0 .. 4 + self.trees[0].publicKey(out[4..]).len];
    }

    pub fn sign(self: *Hss, index: u64, message: []const u8, out: []u8) void {
        for (1..self.count) |level| {
            const prefix = index >> self.heightBelow(level);

            if (level < self.built and self.prefixes[level] == prefix) continue;

            const parent = &self.trees[level - 1];

            const q = self.leafIndex(index, level - 1);

            var i_value: [16]u8 = undefined;

            var seed: [max_n]u8 = undefined;

            defer ct.wipe(&seed);

            parent.child(q, &i_value, &seed);

            self.trees[level].build(self.levels[level], &i_value, seed[0..self.levels[level].lms.m]);

            const size = lmsSignatureSize(self.levels[level - 1]);

            const buffer = self.signed[level - 1];

            parent.sign(q, self.trees[level].publicKey(buffer[size..]), buffer[0..size]);

            self.prefixes[level] = prefix;

            self.built = level + 1;
        }

        out[0..4].* = u32Bytes(@intCast(self.count - 1));

        var offset: usize = 4;

        for (self.signed[0 .. self.count - 1]) |part| {
            @memcpy(out[offset..][0..part.len], part);

            offset += part.len;
        }

        self.trees[self.count - 1].sign(self.leafIndex(index, self.count - 1), message, out[offset..]);

        ct.declassify(out);
    }
};

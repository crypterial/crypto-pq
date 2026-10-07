const std = @import("std");
const builtin = @import("builtin");

const aarch64 = @import("aarch64.zig");
const cpu = @import("cpu.zig");
const ct = @import("ct.zig");
const sha2 = @import("sha2.zig");
const x86_64 = @import("x86_64.zig");

// BLAKE2b and BLAKE2s (RFC 7693) in sequential mode, with the salt and personalization fields of
// the BLAKE2 specification.

// Debug builds give every temporary of every unrolled round its own stack slot, so they run the
// rounds as a loop with run-time indices.
const unrolled = builtin.mode != .Debug;

const sigma = [10][16]u8{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    .{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    .{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

pub const Blake2b = Blake2(u64);

pub const Blake2s = Blake2(u32);

// The last `count` bytes of data, fewer than eight, as the low bytes of a little-endian word: from
// the eight bytes that end data where it has them.
fn lastBytes(data: []const u8, count: usize) u64 {
    if (data.len >= 8) return std.mem.readInt(u64, data[data.len - 8 ..][0..8], .little) >> @intCast(8 * (8 - count));

    var x: u64 = 0;

    for (data[data.len - count ..], 0..) |byte, i| x |= @as(u64, byte) << @intCast(8 * i);

    return x;
}

fn Blake2(comptime W: type) type {
    return struct {
        const word = @sizeOf(W);

        // The block, and the largest digest and key.
        pub const block = 16 * word;

        pub const max_size = 8 * word;

        // The salt and the personalization field each.
        pub const field = 2 * word;

        const rounds = if (W == u64) 12 else 10;

        const r: [4]comptime_int = if (W == u64) .{ 32, 24, 16, 63 } else .{ 16, 12, 8, 7 };

        // The byte counter: 128 bits for BLAKE2b, 64 for BLAKE2s.
        pub const Counter = std.meta.Int(.unsigned, 2 * @bitSizeOf(W));

        pub const iv: [8]W = if (W == u64) sha2.iv_512 else sha2.iv_256;

        // The chaining value of the parameter block (RFC 7693, 2.5; BLAKE2, 2.8): digest length,
        // key length, fanout 1, depth 1, and the salt and personalization, shorter values padded
        // with zeros. The caller checks the lengths.
        pub fn initial(size: usize, key_length: usize, salt: []const u8, personalization: []const u8) [8]W {
            var h = iv;

            h[0] ^= 0x0101_0000 | @as(W, @intCast(key_length)) << 8 | @as(W, @intCast(size));

            inline for (.{ salt, personalization }, .{ 4, 6 }) |value, at| {
                var padded: [field]u8 = @splat(0);

                @memcpy(padded[0..value.len], value);

                h[at] ^= std.mem.readInt(W, padded[0..word], .little);

                h[at + 1] ^= std.mem.readInt(W, padded[word..], .little);
            }

            return h;
        }

        // The words of a whole block of the message.
        fn load(bytes: *const [block]u8) [16]W {
            var m: [16]W = undefined;

            inline for (&m, 0..) |*x, i| x.* = std.mem.readInt(W, bytes[word * i ..][0..word], .little);

            return m;
        }

        // The words of the last block, the `count` bytes at the end of data padded with zeros, read
        // without a copy of them.
        fn loadLast(data: []const u8, count: usize) [16]W {
            if (count == block) return load(data[data.len - block ..][0..block]);

            var m: [16]W = @splat(0);

            const start = data.len - count;

            const whole = count / word;

            for (m[0..whole], 0..) |*x, i| x.* = std.mem.readInt(W, data[start + word * i ..][0..word], .little);

            if (count % word != 0) m[whole] = @truncate(lastBytes(data, count % word));

            return m;
        }

        inline fn g(v: *[16]W, comptime a: usize, comptime b: usize, comptime c: usize, comptime d: usize, x: W, y: W) void {
            v[a] = v[a] +% x +% v[b];

            v[d] = std.math.rotr(W, v[d] ^ v[a], r[0]);

            v[c] = v[c] +% v[d];

            v[b] = std.math.rotr(W, v[b] ^ v[c], r[1]);

            v[a] = v[a] +% y +% v[b];

            v[d] = std.math.rotr(W, v[d] ^ v[a], r[2]);

            v[c] = v[c] +% v[d];

            v[b] = std.math.rotr(W, v[b] ^ v[c], r[3]);
        }

        inline fn round(v: *[16]W, m: *const [16]W, s: *const [16]u8) void {
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);

            g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);

            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);

            g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);

            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);

            g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);

            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);

            g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        // The compression function F on a block of bytes. `t` counts the bytes so far, this block's
        // included; the last block sets the final flag. Which words a round reads is fixed by
        // sigma, never by data.
        pub fn compress(h: *[8]W, bytes: *const [block]u8, t: Counter, last: bool) void {
            if (comptime cpu.aarch64_base) return aarch64.blake2(W, h, bytes, &kernelRows(t, last));

            if (comptime cpu.possible(.avx2)) {
                if (cpu.has(.avx2)) return x86_64.blake2(W, h, bytes, &kernelRows(t, last));
            }

            var m = load(bytes);

            defer ct.wipe(std.mem.asBytes(&m));

            portable(h, &m, t, last);
        }

        // The compression on every CPU, which the kernel tests take as the reference.
        pub fn portable(h: *[8]W, m: *const [16]W, t: Counter, last: bool) void {
            var v: [16]W = h.* ++ iv;

            v[12] ^= @truncate(t);

            v[13] ^= @truncate(t >> @bitSizeOf(W));

            v[14] ^= @as(W, 0) -% @intFromBool(last);

            if (unrolled) {
                inline for (0..rounds) |i| round(&v, m, &sigma[i % 10]);
            } else {
                for (0..rounds) |i| round(&v, m, &sigma[i % 10]);
            }

            inline for (h, 0..) |*x, i| x.* ^= v[i] ^ v[i + 8];
        }

        // Whole blocks of data, none of them the last; `t` counts the bytes before them.
        pub fn blocks(h: *[8]W, data: []const u8, t: Counter) void {
            if (data.len == 0) return;

            if (comptime cpu.aarch64_base) return aarch64.blake2(W, h, data, &kernelRows(t +% block, false));

            if (comptime cpu.possible(.avx2)) {
                if (cpu.has(.avx2)) return x86_64.blake2(W, h, data, &kernelRows(t +% block, false));
            }

            var counter = t;

            var offset: usize = 0;

            while (offset < data.len) : (offset += block) {
                counter +%= block;

                portable(h, &load(data[offset..][0..block]), counter, false);
            }
        }

        // A block of the `count` bytes that end data, padded with zeros. The kernels take a whole
        // block straight from data and a shorter one from a padded copy; the portable code reads
        // the words straight from data. The copies are wiped.
        fn compressPadded(h: *[8]W, data: []const u8, count: usize, t: Counter, last: bool) void {
            if (comptime cpu.aarch64_base or cpu.possible(.avx2)) {
                if (count == block) return compress(h, data[data.len - block ..][0..block], t, last);

                var padded: [block]u8 = @splat(0);

                defer ct.wipe(&padded);

                @memcpy(padded[0..count], data[data.len - count ..]);

                return compress(h, &padded, t, last);
            }

            var m = loadLast(data, count);

            defer ct.wipe(std.mem.asBytes(&m));

            portable(h, &m, t, last);
        }

        // What the AArch64 and x86-64 kernels take besides the blocks: rows 2 and 3 of the working
        // vector without the counter, then the counter of the first block. The kernels read the
        // message words from memory as they lie, which on these little-endian CPUs is how `load`
        // reads them.
        fn kernelRows(t: Counter, last: bool) [10]W {
            var rows: [10]W = iv ++ [2]W{ @truncate(t), @truncate(t >> @bitSizeOf(W)) };

            rows[6] ^= @as(W, 0) -% @intFromBool(last);

            return rows;
        }

        fn store(h: *const [8]W, out: []u8) void {
            for (0..out.len / word) |i| std.mem.writeInt(W, out[word * i ..][0..word], h[i], .little);

            const rest = out.len % word;

            if (rest > 0) {
                const x = h[out.len / word];

                for (out[out.len - rest ..], 0..) |*byte, j| byte.* = @truncate(x >> @intCast(8 * j));
            }
        }

        // The digest of data under an optional key (1 to max_size bytes, empty for none), from the
        // chaining value h0 of a parameter block whose key length field is still zero: the whole
        // blocks go to the compression straight from data, and only the last one is padded.
        pub fn hash(h0: *const [8]W, key: []const u8, data: []const u8, out: []u8) void {
            var h = h0.*;

            defer ct.wipe(std.mem.asBytes(&h));

            var t: Counter = 0;

            if (key.len > 0) {
                h[0] ^= @as(W, @intCast(key.len)) << 8;

                t = block;

                compressPadded(&h, key, key.len, t, data.len == 0);

                if (data.len == 0) return store(&h, out);
            }

            var whole: usize = 0;

            if (data.len > block) {
                whole = (data.len - 1) / block * block;

                blocks(&h, data[0..whole], t);

                t +%= whole;
            }

            const count = data.len - whole;

            t +%= count;

            compressPadded(&h, data, count, t, true);

            store(&h, out);
        }

        // A streaming state. The last block takes the final flag, so a full block stays in the
        // buffer until more data follows it.
        pub const Engine = struct {
            h: [8]W,
            t: Counter = 0,
            buffer: [block]u8 = undefined,
            used: usize = 0,

            pub fn init(h0: *const [8]W) Engine {
                return .{ .h = h0.* };
            }

            // A keyed state, built in place: the key, zero padded, is the first block.
            pub fn initKeyed(self: *Engine, h0: *const [8]W, key: []const u8) void {
                self.h = h0.*;

                self.h[0] ^= @as(W, @intCast(key.len)) << 8;

                self.t = 0;

                @memset(&self.buffer, 0);

                @memcpy(self.buffer[0..key.len], key);

                self.used = block;
            }

            pub fn update(self: *Engine, data: []const u8) void {
                var rest = data;

                if (rest.len == 0) return;

                if (self.used > 0) {
                    const take = @min(block - self.used, rest.len);

                    @memcpy(self.buffer[self.used..][0..take], rest[0..take]);

                    self.used += take;

                    rest = rest[take..];

                    if (rest.len == 0) return;

                    self.t +%= block;

                    compress(&self.h, &self.buffer, self.t, false);

                    self.used = 0;
                }

                const whole = (rest.len - 1) / block * block;

                blocks(&self.h, rest[0..whole], self.t);

                self.t +%= whole;

                rest = rest[whole..];

                @memcpy(self.buffer[0..rest.len], rest);

                self.used = rest.len;
            }

            // The digest of everything so far, into out (at most max_size bytes); the state goes on.
            pub fn digest(self: *const Engine, out: []u8) void {
                var h = self.h;

                defer ct.wipe(std.mem.asBytes(&h));

                compressPadded(&h, self.buffer[0..self.used], self.used, self.t +% self.used, true);

                store(&h, out);
            }
        };
    };
}

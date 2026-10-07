const std = @import("std");

const ct = @import("ct.zig");
const hash = @import("hash.zig");
const keccak = @import("keccak.zig");
const sha2 = @import("sha2.zig");

const Keccak = keccak.Keccak;

// The library's own hashing uses the engines themselves rather than the public Hasher, Xof and
// Mac, whose unions would bring every other algorithm's code into each module.

// One-shot hashing of concatenated parts with SHA-2 or SHA-3. The engine state is wiped
// afterwards: a sponge state can be run backwards to its input, and the inputs here are often
// secret.
pub fn digest(comptime algorithm: hash.HashAlgorithm, parts: []const []const u8, out: []u8) void {
    switch (algorithm.kind) {
        .sha3 => {
            var sponge = Keccak.init(200 - 2 * algorithm.digest_size, 0x06);

            defer ct.wipe(std.mem.asBytes(&sponge));

            for (parts) |part| sponge.update(part);

            sponge.read(out);
        },
        inline .sha256, .sha512 => |iv| {
            var engine = (if (algorithm.kind == .sha256) sha2.Sha256 else sha2.Sha512).init(iv);

            defer ct.wipe(std.mem.asBytes(&engine));

            for (parts) |part| engine.update(part);

            var full = engine.digest();

            defer ct.wipe(&full);

            @memcpy(out, full[0..out.len]);
        },
        else => @compileError("not a SHA-2 or SHA-3 hash"),
    }
}

// SHAKE256's sponge.
pub fn shake256Sponge() Keccak {
    return .init(136, 0x1f);
}

pub fn shake256(parts: []const []const u8, out: []u8) void {
    var xof = shake256Sponge();

    for (parts) |part| {
        xof.update(part);
    }

    xof.read(out);

    ct.wipe(std.mem.asBytes(&xof));
}

// HMAC-SHA-256 (Word u32) or HMAC-SHA-512 (Word u64) of `first` and then `rest` under a key of
// at most a block, its output truncated to out.len bytes. The caller holds DIT.
pub fn hmac(comptime Word: type, key: []const u8, first: []const u8, rest: []const []const u8, out: []u8) void {
    const block = 16 * @sizeOf(Word);

    std.debug.assert(key.len <= block);

    var keyed = if (Word == u32) sha2.keyed256(&sha2.iv_256, key) else sha2.keyed512(&sha2.iv_512, key);

    defer ct.wipe(std.mem.asBytes(&keyed));

    var inner: (if (Word == u32) sha2.Sha256 else sha2.Sha512) = .{ .state = keyed[0], .length = block };

    defer ct.wipe(std.mem.asBytes(&inner));

    inner.update(first);

    for (rest) |part| inner.update(part);

    var inner_digest = inner.digest();

    defer ct.wipe(&inner_digest);

    if (Word == u32) return sha2.finish256(keyed[1], block, &inner_digest, out);

    sha2.finish512(keyed[1], block, &inner_digest, out);
}

fn gather(buffer: []u8, parts: []const []const u8) usize {
    var length: usize = 0;

    for (parts) |part| {
        @memcpy(buffer[length..][0..part.len], part);

        length += part.len;
    }

    return length;
}

// The hash-based signatures make millions of calls on inputs of a few dozen bytes. These finish a
// SHA-2 computation from a chaining state that already absorbed `absorbed` bytes (whole blocks)
// by padding the remaining parts in place, without the buffering of the streaming engines.
pub fn sha256Finish(state: *const [8]u32, absorbed: usize, parts: []const []const u8, out: []u8) void {
    var block: [192]u8 = undefined;

    const length = gather(&block, parts);

    const end = (length + 9 + 63) / 64 * 64;

    defer ct.wipe(block[0..end]);

    @memset(block[length..end], 0);

    block[length] = 0x80;

    std.mem.writeInt(u64, block[end - 8 ..][0..8], (absorbed + length) * 8, .big);

    var words = state.*;

    defer ct.wipe(std.mem.asBytes(&words));

    sha2.blocks256(&words, block[0..end]);

    for (0..out.len / 4) |i| {
        std.mem.writeInt(u32, out[4 * i ..][0..4], words[i], .big);
    }
}

pub fn sha512Finish(state: *const [8]u64, absorbed: usize, parts: []const []const u8, out: []u8) void {
    var block: [256]u8 = undefined;

    const length = gather(&block, parts);

    const end = (length + 17 + 127) / 128 * 128;

    defer ct.wipe(block[0..end]);

    @memset(block[length..end], 0);

    block[length] = 0x80;

    std.mem.writeInt(u64, block[end - 8 ..][0..8], (absorbed + length) * 8, .big);

    var words = state.*;

    defer ct.wipe(std.mem.asBytes(&words));

    sha2.blocks512(&words, block[0..end]);

    for (0..out.len / 8) |i| {
        std.mem.writeInt(u64, out[8 * i ..][0..8], words[i], .big);
    }
}

// SHAKE256 of at most 135 bytes: a single permutation of one padded block.
pub fn shake256Short(parts: []const []const u8, out: []u8) void {
    var state: [25]u64 = @splat(0);

    defer ct.wipe(std.mem.asBytes(&state));

    var length: usize = 0;

    for (parts) |part| {
        keccak.xorBytes(&state, length, part);

        length += part.len;
    }

    keccak.xorBytes(&state, length, &.{0x1f});

    keccak.xorBytes(&state, 135, &.{0x80});

    keccak.permute(&state);

    keccak.copyBytes(&state, 0, out);
}

const std = @import("std");

const ct = @import("ct.zig");
const hash = @import("hash.zig");
const keccak = @import("keccak.zig");
const sha2 = @import("sha2.zig");

// One-shot hashing of concatenated parts. The engine state is wiped afterwards: a sponge state
// can be run backwards to its input, and the inputs here are often secret.
pub fn digest(comptime algorithm: hash.HashAlgorithm, parts: []const []const u8, out: []u8) void {
    var hasher = algorithm.create();

    for (parts) |part| {
        hasher.update(part);
    }

    hasher.digest(out);

    ct.wipe(std.mem.asBytes(&hasher));
}

pub fn shake256(parts: []const []const u8, out: []u8) void {
    var xof = hash.shake256.create();

    for (parts) |part| {
        xof.update(part);
    }

    xof.read(out);

    ct.wipe(std.mem.asBytes(&xof));
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

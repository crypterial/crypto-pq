const std = @import("std");

const build_options = @import("build_options");

// With -Dct=true, `zig build ct` runs the library under valgrind's memcheck with every secret
// marked uninitialised, so that a branch or a memory index that depends on a secret is reported.
// A value derived from secrets is declassified where the specification makes it public. Without
// the option these hooks compile to nothing.
pub inline fn secret(bytes: []const u8) void {
    if (build_options.ct) std.valgrind.memcheck.makeMemUndefined(bytes);
}

pub inline fn declassify(bytes: []const u8) void {
    if (build_options.ct) std.valgrind.memcheck.makeMemDefined(bytes);
}

// declassify for a value that lives in registers: it passes through memory only under -Dct=true.
pub inline fn declassifyValue(comptime T: type, value: T) T {
    if (!build_options.ct) return value;

    var copy = value;

    declassify(std.mem.asBytes(&copy));

    return copy;
}

pub fn equal(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    var difference: u8 = 0;

    for (a, b) |x, y| {
        difference |= x ^ y;
    }

    const barrier: *volatile u8 = &difference;

    return barrier.* == 0;
}

// 0xff for equal slices of the same length and 0 otherwise, computed without branching on the
// contents so that the result can drive a masked selection.
pub fn equalMask(a: []const u8, b: []const u8) u8 {
    var difference: u8 = 0;

    for (a, b) |x, y| {
        difference |= x ^ y;
    }

    const barrier: *volatile u8 = &difference;

    return @truncate((@as(u16, barrier.*) -% 1) >> 8);
}

pub fn select(mask: u8, when_set: []const u8, otherwise: []const u8, out: []u8) void {
    for (out, when_set, otherwise) |*byte, a, b| {
        byte.* = b ^ (mask & (a ^ b));
    }
}

// Volatile writes survive dead-store elimination, so secrets are gone even when the memory is
// never read again. They are 16 bytes wide: a memset of more than a few hundred bytes becomes a
// call to the runtime's memset, which writes one byte at a time, so this also zeroes large
// buffers that hold nothing secret.
pub fn wipe(bytes: []u8) void {
    var rest = bytes;

    while (rest.len >= 16) : (rest = rest[16..]) {
        const chunk: *align(1) volatile @Vector(2, u64) = @ptrCast(rest.ptr);

        chunk.* = @splat(0);
    }

    if (rest.len >= 8) {
        const word: *align(1) volatile u64 = @ptrCast(rest.ptr);

        word.* = 0;

        rest = rest[8..];
    }

    for (rest) |*byte| {
        const target: *volatile u8 = byte;

        target.* = 0;
    }
}

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
// never read again.
pub fn wipe(bytes: []u8) void {
    @memset(@as([]volatile u8, bytes), 0);
}

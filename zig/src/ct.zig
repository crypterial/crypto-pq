pub fn equal(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    var difference: u8 = 0;

    for (a, b) |x, y| {
        difference |= x ^ y;
    }

    const barrier: *volatile u8 = &difference;

    return barrier.* == 0;
}

// Volatile writes survive dead-store elimination, so secrets are gone even when the memory is
// never read again.
pub fn wipe(bytes: []u8) void {
    @memset(@as([]volatile u8, bytes), 0);
}

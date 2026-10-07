const std = @import("std");
const pq = @import("crypto_pq");
const vectors = @import("vectors");

const testing = std.testing;

fn decode(hex: []const u8) ![]u8 {
    return vectors.decode(testing.allocator, hex);
}

const sizes = [_]usize{ 0, 1, 3, 8, 7, 16, 9, 0, 40 };

fn pieces(data: []const u8, index: *usize, offset: *usize) ?[]const u8 {
    if (offset.* >= data.len) return null;

    const start = offset.*;

    offset.* = @min(start + sizes[index.* % sizes.len], data.len);

    index.* += 1;

    return data[start..offset.*];
}

fn checkHash(data: []const u8, expected: []const u8) !void {
    var out: [32]u8 = undefined;

    pq.ascon_hash256.digest(data, &out);

    try testing.expectEqualSlices(u8, expected, &out);

    var hasher = pq.ascon_hash256.create();

    var index: usize = 0;

    var offset: usize = 0;

    while (pieces(data, &index, &offset)) |piece| hasher.update(piece);

    @memset(&out, 0);

    hasher.digest(&out);

    try testing.expectEqualSlices(u8, expected, &out);

    // The digest leaves the state going on.
    hasher.digest(&out);

    try testing.expectEqualSlices(u8, expected, &out);
}

fn checkXof(algorithm: pq.XofAlgorithm, data: []const u8, expected: []const u8) !void {
    const out = try testing.allocator.alloc(u8, expected.len);

    defer testing.allocator.free(out);

    algorithm.digest(data, out);

    try testing.expectEqualSlices(u8, expected, out);

    var xof = algorithm.create();

    var index: usize = 0;

    var offset: usize = 0;

    while (pieces(data, &index, &offset)) |piece| xof.update(piece);

    @memset(out, 0);

    // Reads that cross the blocks unevenly.
    var read: usize = 0;

    for ([_]usize{ 0, 1, 7, 9, 3, 13 }) |n| {
        const take = @min(n, expected.len - read);

        xof.read(out[read..][0..take]);

        read += take;
    }

    xof.read(out[read..]);

    try testing.expectEqualSlices(u8, expected, out);
}

test "Ascon-Hash256 KATs" {
    const v = try vectors.Vectors.load("ascon/LWC_HASH_KAT_128_256.txt", "MD");

    defer v.deinit();

    for (v.records) |r| {
        const data = try decode(r.values.get("Msg"));

        defer testing.allocator.free(data);

        const expected = try decode(r.values.get("MD"));

        defer testing.allocator.free(expected);

        try checkHash(data, expected);
    }

    try testing.expectEqual(1025, v.records.len);
}

test "Ascon-XOF128 KATs" {
    const v = try vectors.Vectors.load("ascon/LWC_XOF_KAT_128_512.txt", "MD");

    defer v.deinit();

    for (v.records) |r| {
        const data = try decode(r.values.get("Msg"));

        defer testing.allocator.free(data);

        const expected = try decode(r.values.get("MD"));

        defer testing.allocator.free(expected);

        try checkXof(pq.ascon_xof128, data, expected);
    }

    try testing.expectEqual(1025, v.records.len);
}

test "Ascon-CXOF128 KATs" {
    const v = try vectors.Vectors.load("ascon/LWC_CXOF_KAT_128_512.txt", "MD");

    defer v.deinit();

    for (v.records) |r| {
        const data = try decode(r.values.get("Msg"));

        defer testing.allocator.free(data);

        const customization = try decode(r.values.get("Z"));

        defer testing.allocator.free(customization);

        const expected = try decode(r.values.get("MD"));

        defer testing.allocator.free(expected);

        try checkXof(try pq.ascon_cxof128.configure(.{ .customization = customization }), data, expected);
    }

    try testing.expectEqual(1089, v.records.len);
}

// The ACVP cases whose lengths are whole bytes.
test "Ascon ACVP vectors" {
    const v = try vectors.Vectors.load("acvp/Ascon.txt", "md");

    defer v.deinit();

    var counts = [3]usize{ 0, 0, 0 };

    for (v.records) |r| {
        const set = r.header.get("parameterSet");

        const data = try decode(r.values.get("msg"));

        defer testing.allocator.free(data);

        const expected = try decode(r.values.get("md"));

        defer testing.allocator.free(expected);

        if (std.mem.eql(u8, set, "Ascon-Hash256")) {
            try checkHash(data, expected);

            counts[0] += 1;
        } else if (std.mem.eql(u8, set, "Ascon-XOF128")) {
            try checkXof(pq.ascon_xof128, data, expected);

            counts[1] += 1;
        } else if (std.mem.eql(u8, set, "Ascon-CXOF128")) {
            const customization = try decode(r.values.get("cs"));

            defer testing.allocator.free(customization);

            try checkXof(try pq.ascon_cxof128.configure(.{ .customization = customization }), data, expected);

            counts[2] += 1;
        } else return error.TestUnexpectedResult;
    }

    try testing.expectEqual([3]usize{ 12, 3, 1 }, counts);
}

test "Ascon-CXOF128 customization limit" {
    const long = [_]u8{0x5a} ** 257;

    try testing.expectError(error.InvalidOption, pq.ascon_cxof128.configure(.{ .customization = &long }));

    _ = try pq.ascon_cxof128.configure(.{ .customization = long[0..256] });

    try testing.expectError(error.InvalidOption, pq.ascon_xof128.configure(.{ .customization = "x" }));

    try testing.expectEqualDeep(pq.ascon_cxof128, try pq.ascon_cxof128.configure(.{}));

    // A customization changes the output, and no customization is the empty one.
    var plain: [32]u8 = undefined;

    var custom: [32]u8 = undefined;

    pq.ascon_cxof128.digest("data", &plain);

    (try pq.ascon_cxof128.configure(.{ .customization = "c" })).digest("data", &custom);

    try testing.expect(!std.mem.eql(u8, &plain, &custom));
}

test "Ascon properties" {
    try testing.expectEqualStrings("Ascon-Hash256", pq.ascon_hash256.name);

    try testing.expectEqual(32, pq.ascon_hash256.digest_size);

    try testing.expectEqualStrings("Ascon-XOF128", pq.ascon_xof128.name);

    try testing.expectEqualStrings("Ascon-CXOF128", pq.ascon_cxof128.name);
}

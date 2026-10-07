const std = @import("std");
const pq = @import("crypto_pq");
const vectors = @import("vectors");

const testing = std.testing;

fn decode(hex: []const u8) ![]u8 {
    return vectors.decode(testing.allocator, hex);
}

fn hkdf(name: []const u8) !pq.KdfAlgorithm {
    for ([_]pq.KdfAlgorithm{ pq.hkdf_sha_256, pq.hkdf_sha_384, pq.hkdf_sha_512 }) |algorithm| {
        if (std.mem.eql(u8, name, algorithm.name)) return algorithm;
    }

    return error.TestUnexpectedResult;
}

// derive, and extract followed by expand, give the same output.
fn checkDerive(algorithm: pq.KdfAlgorithm, ikm: []const u8, salt: []const u8, info: []const u8, expected: []const u8) !void {
    const out = try testing.allocator.alloc(u8, expected.len);

    defer testing.allocator.free(out);

    try algorithm.derive(ikm, out, .{ .salt = salt, .info = info });

    try testing.expectEqualSlices(u8, expected, out);

    var prk: [64]u8 = undefined;

    try algorithm.extract(ikm, prk[0..algorithm.hashSize()], .{ .salt = salt });

    @memset(out, 0);

    try algorithm.expand(prk[0..algorithm.hashSize()], out, .{ .info = info });

    try testing.expectEqualSlices(u8, expected, out);
}

test "HKDF RFC 5869 vectors" {
    const v = try vectors.Vectors.load("rfc/hkdf.txt", "okm");

    defer v.deinit();

    for (v.records) |r| {
        const algorithm = try hkdf(r.header.get("parameterSet"));

        const ikm = try decode(r.values.get("ikm"));

        defer testing.allocator.free(ikm);

        const salt = try decode(r.values.get("salt"));

        defer testing.allocator.free(salt);

        const info = try decode(r.values.get("info"));

        defer testing.allocator.free(info);

        const prk = try decode(r.values.get("prk"));

        defer testing.allocator.free(prk);

        const okm = try decode(r.values.get("okm"));

        defer testing.allocator.free(okm);

        try testing.expectEqual(try vectors.number(usize, r.values.get("length")), okm.len);

        var extracted: [32]u8 = undefined;

        try algorithm.extract(ikm, &extracted, .{ .salt = salt });

        try testing.expectEqualSlices(u8, prk, &extracted);

        try checkDerive(algorithm, ikm, salt, info, okm);
    }

    try testing.expectEqual(3, v.records.len);
}

// Invalid only where L exceeds 255 hash lengths, which must be refused.
test "HKDF Wycheproof vectors" {
    const v = try vectors.Vectors.load("wycheproof/hkdf.txt", "okm");

    defer v.deinit();

    var invalid: usize = 0;

    for (v.records) |r| {
        const algorithm = try hkdf(r.header.get("parameterSet"));

        const ikm = try decode(r.values.get("ikm"));

        defer testing.allocator.free(ikm);

        const salt = try decode(r.values.get("salt"));

        defer testing.allocator.free(salt);

        const info = try decode(r.values.get("info"));

        defer testing.allocator.free(info);

        const okm = try decode(r.values.get("okm"));

        defer testing.allocator.free(okm);

        const size = try vectors.number(usize, r.values.get("size"));

        if (r.values.is("result", "valid")) {
            try testing.expectEqual(size, okm.len);

            try checkDerive(algorithm, ikm, salt, info, okm);
        } else {
            invalid += 1;

            try testing.expect(size > 255 * algorithm.hashSize());

            const out = try testing.allocator.alloc(u8, size);

            defer testing.allocator.free(out);

            try testing.expectError(error.InvalidLength, algorithm.derive(ikm, out, .{ .salt = salt, .info = info }));

            var prk: [64]u8 = undefined;

            try algorithm.extract(ikm, prk[0..algorithm.hashSize()], .{ .salt = salt });

            try testing.expectError(error.InvalidLength, algorithm.expand(prk[0..algorithm.hashSize()], out, .{ .info = info }));
        }
    }

    try testing.expectEqual(252, v.records.len);

    try testing.expectEqual(9, invalid);
}

// One extract, then one expand per comma-separated info and okm.
test "HKDF ACVP KDA vectors" {
    const v = try vectors.Vectors.load("acvp/KDA-HKDF.txt", "okm");

    defer v.deinit();

    var expansions: usize = 0;

    for (v.records) |r| {
        const algorithm = try hkdf(r.header.get("parameterSet"));

        const ikm = try decode(r.values.get("ikm"));

        defer testing.allocator.free(ikm);

        const salt = try decode(r.values.get("salt"));

        defer testing.allocator.free(salt);

        const length = try vectors.number(usize, r.values.get("length"));

        var prk: [64]u8 = undefined;

        try algorithm.extract(ikm, prk[0..algorithm.hashSize()], .{ .salt = salt });

        var infos = std.mem.splitScalar(u8, r.values.get("info"), ',');

        var okms = std.mem.splitScalar(u8, r.values.get("okm"), ',');

        var count: usize = 0;

        while (infos.next()) |info_hex| {
            const info = try decode(info_hex);

            defer testing.allocator.free(info);

            const okm = try decode(okms.next() orelse return error.TestUnexpectedResult);

            defer testing.allocator.free(okm);

            try testing.expectEqual(length, okm.len);

            if (count == 0) try checkDerive(algorithm, ikm, salt, info, okm);

            const out = try testing.allocator.alloc(u8, length);

            defer testing.allocator.free(out);

            try algorithm.expand(prk[0..algorithm.hashSize()], out, .{ .info = info });

            try testing.expectEqualSlices(u8, okm, out);

            count += 1;
        }

        try testing.expect(okms.next() == null);

        expansions += count;
    }

    try testing.expectEqual(450, v.records.len);

    try testing.expect(expansions > v.records.len);
}

test "HKDF lengths and options" {
    for ([_]pq.KdfAlgorithm{ pq.hkdf_sha_256, pq.hkdf_sha_384, pq.hkdf_sha_512 }) |algorithm| {
        const n = algorithm.hashSize();

        var out: [255 * 64 + 1]u8 = undefined;

        try testing.expectError(error.InvalidLength, algorithm.derive("ikm", out[0..0], .{}));

        try testing.expectError(error.InvalidLength, algorithm.derive("ikm", out[0 .. 255 * n + 1], .{}));

        try algorithm.derive("ikm", out[0 .. 255 * n], .{ .salt = "salt", .info = "info" });

        // The longest output is the shorter ones extended.
        var short: [100]u8 = undefined;

        try algorithm.derive("ikm", &short, .{ .salt = "salt", .info = "info" });

        try testing.expectEqualSlices(u8, &short, out[0..100]);

        var prk: [64]u8 = undefined;

        try testing.expectError(error.InvalidLength, algorithm.extract("ikm", prk[0 .. n - 1], .{}));

        try testing.expectError(error.InvalidOption, algorithm.extract("ikm", prk[0..n], .{ .info = "info" }));

        try algorithm.extract("ikm", prk[0..n], .{ .salt = "salt" });

        try testing.expectError(error.InvalidLength, algorithm.expand(prk[0 .. n - 1], &short, .{}));

        try testing.expectError(error.InvalidOption, algorithm.expand(prk[0..n], &short, .{ .salt = "salt" }));

        try testing.expectError(error.InvalidLength, algorithm.expand(prk[0..n], out[0..0], .{}));

        // An absent salt is HashLen zeros; a PRK longer than a block is hashed, as HMAC does.
        var zeros: [64]u8 = @splat(0);

        var a: [32]u8 = undefined;

        var b: [32]u8 = undefined;

        try algorithm.derive("ikm", &a, .{});

        try algorithm.derive("ikm", &b, .{ .salt = zeros[0..n] });

        try testing.expectEqualSlices(u8, &a, &b);

        var long_prk: [300]u8 = @splat(7);

        try algorithm.expand(&long_prk, &a, .{ .info = "info" });

        // An info longer than the one-shot buffer takes the streaming path.
        var long_info: [1000]u8 = undefined;

        for (&long_info, 0..) |*x, i| x.* = @truncate(i);

        var streamed: [200]u8 = undefined;

        try algorithm.expand(prk[0..n], &streamed, .{ .info = &long_info });

        var reference: [200]u8 = undefined;

        try referenceExpand(algorithm, prk[0..n], &long_info, &reference);

        try testing.expectEqualSlices(u8, &reference, &streamed);

        try referenceExpand(algorithm, prk[0..n], "info", &reference);

        try algorithm.expand(prk[0..n], &streamed, .{ .info = "info" });

        try testing.expectEqualSlices(u8, &reference, &streamed);
    }
}

// RFC 5869, 2.3, written out with the MAC API.
fn referenceExpand(algorithm: pq.KdfAlgorithm, prk: []const u8, info: []const u8, out: []u8) !void {
    const mac = if (algorithm.hashSize() == 32) pq.hmac_sha_256 else if (algorithm.hashSize() == 48) pq.hmac_sha_384 else pq.hmac_sha_512;

    var t: [64]u8 = undefined;

    var previous: usize = 0;

    var offset: usize = 0;

    var counter: u8 = 1;

    while (offset < out.len) : (counter += 1) {
        var state = mac.create(prk);

        state.update(t[0..previous]);

        state.update(info);

        state.update(&.{counter});

        state.digest(t[0..mac.digest_size]);

        previous = mac.digest_size;

        const take = @min(previous, out.len - offset);

        @memcpy(out[offset..][0..take], t[0..take]);

        offset += take;
    }
}

test "HKDF properties" {
    try testing.expectEqualStrings("HKDF-SHA-256", pq.hkdf_sha_256.name);

    try testing.expectEqualStrings("HKDF-SHA-384", pq.hkdf_sha_384.name);

    try testing.expectEqualStrings("HKDF-SHA-512", pq.hkdf_sha_512.name);

    try testing.expectEqual(32, pq.hkdf_sha_256.hashSize());

    try testing.expectEqual(48, pq.hkdf_sha_384.hashSize());

    try testing.expectEqual(64, pq.hkdf_sha_512.hashSize());
}

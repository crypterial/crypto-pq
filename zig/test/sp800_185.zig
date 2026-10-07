const std = @import("std");
const pq = @import("crypto_pq");
const vectors = @import("vectors");

const testing = std.testing;

const hazmat = pq.hazmat;

fn decode(hex: []const u8) ![]u8 {
    return vectors.decode(testing.allocator, hex);
}

const sizes = [_]usize{ 0, 1, 3, 168, 7, 136, 135, 0, 300 };

fn pieces(data: []const u8, index: *usize, offset: *usize) ?[]const u8 {
    if (offset.* >= data.len) return null;

    const start = offset.*;

    offset.* = @min(start + sizes[index.* % sizes.len], data.len);

    index.* += 1;

    return data[start..offset.*];
}

fn cshake(name: []const u8) !pq.XofAlgorithm {
    if (std.mem.eql(u8, name, "cSHAKE128")) return pq.cshake128;

    if (std.mem.eql(u8, name, "cSHAKE256")) return pq.cshake256;

    return error.TestUnexpectedResult;
}

fn kmac(name: []const u8) !pq.MacAlgorithm {
    if (std.mem.eql(u8, name, "KMAC128")) return pq.kmac128;

    if (std.mem.eql(u8, name, "KMAC256")) return pq.kmac256;

    return error.TestUnexpectedResult;
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

    const first = @min(out.len, 1);

    xof.read(out[0..first]);

    xof.read(out[first..]);

    try testing.expectEqualSlices(u8, expected, out);
}

// Checks digest, verify and the streaming forms; with `valid` false the tag must not verify.
fn checkMac(algorithm: pq.MacAlgorithm, key: []const u8, data: []const u8, tag: []const u8, valid: bool) !void {
    const out = try testing.allocator.alloc(u8, algorithm.digest_size);

    defer testing.allocator.free(out);

    try testing.expectEqual(valid, algorithm.verify(key, data, tag));

    var mac = algorithm.create(key);

    var index: usize = 0;

    var offset: usize = 0;

    while (pieces(data, &index, &offset)) |piece| mac.update(piece);

    try testing.expectEqual(valid, mac.verify(tag));

    if (!valid) return;

    algorithm.digest(key, data, out);

    try testing.expectEqualSlices(u8, tag, out);

    @memset(out, 0);

    mac.digest(out);

    try testing.expectEqualSlices(u8, tag, out);
}

test "cSHAKE NIST examples" {
    const v = try vectors.Vectors.load("nist-examples/cSHAKE.txt", "md");

    defer v.deinit();

    for (v.records) |r| {
        const base = try cshake(r.header.get("parameterSet"));

        const function_name = try decode(r.values.get("functionName"));

        defer testing.allocator.free(function_name);

        const customization = try decode(r.values.get("customization"));

        defer testing.allocator.free(customization);

        const data = try decode(r.values.get("msg"));

        defer testing.allocator.free(data);

        const expected = try decode(r.values.get("md"));

        defer testing.allocator.free(expected);

        try testing.expectEqual(0, function_name.len);

        try checkXof(try base.configure(.{ .customization = customization }), data, expected);

        try checkXof(try hazmat.configureCshake(base, function_name, customization), data, expected);
    }

    try testing.expectEqual(4, v.records.len);
}

// All of them set a function name, which only hazmat takes.
test "cSHAKE ACVP vectors" {
    const v = try vectors.Vectors.load("acvp/cSHAKE.txt", "md");

    defer v.deinit();

    for (v.records) |r| {
        const base = try cshake(r.header.get("parameterSet"));

        const function_name = try decode(r.values.get("functionName"));

        defer testing.allocator.free(function_name);

        const customization = try decode(r.values.get("customization"));

        defer testing.allocator.free(customization);

        const data = try decode(r.values.get("msg"));

        defer testing.allocator.free(data);

        const expected = try decode(r.values.get("md"));

        defer testing.allocator.free(expected);

        try testing.expect(function_name.len > 0);

        try checkXof(try hazmat.configureCshake(base, function_name, customization), data, expected);
    }

    try testing.expectEqual(5, v.records.len);
}

test "cSHAKE without a name or customization is SHAKE" {
    const data = "crypto-pq";

    for ([_]pq.XofAlgorithm{ pq.cshake128, pq.cshake256 }, [_]pq.XofAlgorithm{ pq.shake128, pq.shake256 }) |c, s| {
        var a: [200]u8 = undefined;

        var b: [200]u8 = undefined;

        c.digest(data, &a);

        s.digest(data, &b);

        try testing.expectEqualSlices(u8, &b, &a);

        (try c.configure(.{})).digest(data, &a);

        try testing.expectEqualSlices(u8, &b, &a);

        (try hazmat.configureCshake(c, "", "")).digest(data, &a);

        try testing.expectEqualSlices(u8, &b, &a);

        // Any function name or customization makes it another function.
        (try hazmat.configureCshake(c, "N", "")).digest(data, &a);

        try testing.expect(!std.mem.eql(u8, &a, &b));
    }

    try testing.expectError(error.InvalidOption, pq.shake128.configure(.{ .customization = "x" }));

    try testing.expectError(error.InvalidOption, hazmat.configureCshake(pq.shake256, "N", ""));

    try testing.expectError(error.InvalidOption, hazmat.configureCshake(pq.ascon_cxof128, "", "S"));
}

// A customization of several blocks.
test "cSHAKE with a long customization streams like the one-shot" {
    var customization: [1000]u8 = undefined;

    for (&customization, 0..) |*b, i| b.* = @truncate(i *% 7);

    const data = "message";

    for ([_]pq.XofAlgorithm{ pq.cshake128, pq.cshake256 }) |base| {
        const configured = try base.configure(.{ .customization = &customization });

        var expected: [64]u8 = undefined;

        configured.digest(data, &expected);

        try checkXof(configured, data, &expected);
    }
}

test "KMAC NIST examples" {
    const v = try vectors.Vectors.load("nist-examples/KMAC.txt", "mac");

    defer v.deinit();

    for (v.records) |r| {
        const base = try kmac(r.header.get("parameterSet"));

        const xof = r.header.is("xof", "true");

        const key = try decode(r.values.get("key"));

        defer testing.allocator.free(key);

        const data = try decode(r.values.get("msg"));

        defer testing.allocator.free(data);

        const customization = try decode(r.values.get("customization"));

        defer testing.allocator.free(customization);

        const tag = try decode(r.values.get("mac"));

        defer testing.allocator.free(tag);

        const algorithm = try base.configure(.{ .length = tag.len, .customization = customization, .xof = xof });

        try checkMac(algorithm, key, data, tag, true);
    }

    try testing.expectEqual(12, v.records.len);
}

// The ACVP KMAC cases with whole-byte lengths (testPassed false: the tag was altered) and the
// KDF-KMAC cases of SP 800-108r1.
test "KMAC ACVP vectors" {
    const v = try vectors.Vectors.load("acvp/KMAC.txt", "mac");

    defer v.deinit();

    var rejected: usize = 0;

    for (v.records) |r| {
        const base = try kmac(r.header.get("parameterSet"));

        const xof = r.header.is("xof", "true");

        const key = try decode(r.values.get("key"));

        defer testing.allocator.free(key);

        const data = try decode(r.values.get("msg"));

        defer testing.allocator.free(data);

        const customization = try decode(r.values.get("customization"));

        defer testing.allocator.free(customization);

        const tag = try decode(r.values.get("mac"));

        defer testing.allocator.free(tag);

        const valid = r.values.is("testPassed", "true");

        if (!valid) rejected += 1;

        const algorithm = try base.configure(.{ .length = tag.len, .customization = customization, .xof = xof });

        try checkMac(algorithm, key, data, tag, valid);
    }

    try testing.expectEqual(103, v.records.len);

    try testing.expectEqual(2, rejected);
}

test "KMAC Wycheproof vectors" {
    const v = try vectors.Vectors.load("wycheproof/kmac.txt", "tag");

    defer v.deinit();

    var invalid: usize = 0;

    for (v.records) |r| {
        const base = try kmac(r.header.get("parameterSet"));

        const key = try decode(r.values.get("key"));

        defer testing.allocator.free(key);

        const data = try decode(r.values.get("msg"));

        defer testing.allocator.free(data);

        const tag = try decode(r.values.get("tag"));

        defer testing.allocator.free(tag);

        try testing.expectEqual(try vectors.number(usize, r.header.get("tagSize")), 8 * tag.len);

        const valid = r.values.is("result", "valid");

        if (!valid) invalid += 1;

        try checkMac(try base.configure(.{ .length = tag.len }), key, data, tag, valid);
    }

    try testing.expectEqual(435, v.records.len);

    try testing.expectEqual(270, invalid);
}

test "KMAC configure checks its options" {
    try testing.expectError(error.InvalidOption, pq.kmac128.configure(.{ .length = 3 }));

    try testing.expectError(error.InvalidOption, pq.kmac256.configure(.{ .length = 0 }));

    try testing.expectError(error.InvalidOption, pq.kmac128.configure(.{ .salt = "s" }));

    try testing.expectError(error.InvalidOption, pq.kmac256.configure(.{ .personalization = "p" }));

    try testing.expectError(error.InvalidOption, pq.hmac_sha_256.configure(.{ .length = 32 }));

    try testing.expectError(error.InvalidOption, pq.hmac_sha_256.configure(.{ .customization = "c" }));

    try testing.expectEqualDeep(pq.kmac128, try pq.kmac128.configure(.{}));

    try testing.expectEqualDeep(pq.hmac_sha_512, try pq.hmac_sha_512.configure(.{}));

    try testing.expectEqual(32, pq.kmac128.digest_size);

    try testing.expectEqual(64, pq.kmac256.digest_size);

    try testing.expectEqual(4, (try pq.kmac128.configure(.{ .length = 4 })).digest_size);

    // KMACXOF outputs are prefixes of each other; KMAC binds the length.
    var short: [16]u8 = undefined;

    var long: [100]u8 = undefined;

    (try pq.kmac128.configure(.{ .length = 16, .xof = true })).digest("key", "data", &short);

    (try pq.kmac128.configure(.{ .length = 100, .xof = true })).digest("key", "data", &long);

    try testing.expectEqualSlices(u8, &short, long[0..16]);

    (try pq.kmac128.configure(.{ .length = 100 })).digest("key", "data", &long);

    try testing.expect(!std.mem.eql(u8, &short, long[0..16]));

    // Tags longer than one comparison piece verify, and a change anywhere is refused.
    const algorithm = try pq.kmac256.configure(.{ .length = 200, .customization = "c" });

    var tag: [200]u8 = undefined;

    algorithm.digest("", "data", &tag);

    try testing.expect(algorithm.verify("", "data", &tag));

    tag[150] ^= 1;

    try testing.expect(!algorithm.verify("", "data", &tag));

    try testing.expect(!algorithm.verify("", "data", tag[0..199]));
}

test "SP 800-185 properties" {
    try testing.expectEqualStrings("cSHAKE128", pq.cshake128.name);

    try testing.expectEqualStrings("cSHAKE256", pq.cshake256.name);

    try testing.expectEqualStrings("KMAC128", pq.kmac128.name);

    try testing.expectEqualStrings("KMAC256", pq.kmac256.name);
}

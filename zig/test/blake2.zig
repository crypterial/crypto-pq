const std = @import("std");
const pq = @import("crypto_pq");
const vectors = @import("vectors");

const testing = std.testing;

const Fields = vectors.Fields;

fn decode(hex: []const u8) ![]u8 {
    return vectors.decode(testing.allocator, hex);
}

// The unkeyed algorithms of RFC 7693 by family and digest length.
const hashes = [_]pq.HashAlgorithm{
    pq.blake2b_160,
    pq.blake2b_256,
    pq.blake2b_384,
    pq.blake2b_512,
    pq.blake2s_128,
    pq.blake2s_160,
    pq.blake2s_224,
    pq.blake2s_256,
};

fn unkeyed(family: []const u8, size: usize) ?pq.HashAlgorithm {
    for (hashes) |h| {
        if (std.mem.startsWith(u8, h.name, family) and h.digest_size == size) return h;
    }

    return null;
}

fn keyed(family: []const u8) pq.MacAlgorithm {
    return if (std.mem.eql(u8, family, "BLAKE2b")) pq.blake2b_mac else pq.blake2s_mac;
}

// Uneven sizes reach every buffering path: empty updates, partial blocks and whole blocks.
const sizes = [_]usize{ 0, 1, 3, 64, 7, 128, 129, 0, 200 };

fn pieces(data: []const u8, index: *usize, offset: *usize) ?[]const u8 {
    if (offset.* >= data.len) return null;

    const start = offset.*;

    offset.* = @min(start + sizes[index.* % sizes.len], data.len);

    index.* += 1;

    return data[start..offset.*];
}

fn checkHash(algorithm: pq.HashAlgorithm, data: []const u8, expected: []const u8) !void {
    var out: [64]u8 = undefined;

    const digest = out[0..algorithm.digest_size];

    algorithm.digest(data, digest);

    try testing.expectEqualSlices(u8, expected, digest);

    var hasher = algorithm.create();

    var index: usize = 0;

    var offset: usize = 0;

    while (pieces(data, &index, &offset)) |piece| hasher.update(piece);

    @memset(digest, 0);

    hasher.digest(digest);

    try testing.expectEqualSlices(u8, expected, digest);
}

fn checkMac(algorithm: pq.MacAlgorithm, key: []const u8, data: []const u8, expected: []const u8) !void {
    var out: [64]u8 = undefined;

    const tag = out[0..algorithm.digest_size];

    algorithm.digest(key, data, tag);

    try testing.expectEqualSlices(u8, expected, tag);

    try testing.expect(algorithm.verify(key, data, expected));

    var mac = algorithm.create(key);

    var index: usize = 0;

    var offset: usize = 0;

    while (pieces(data, &index, &offset)) |piece| mac.update(piece);

    @memset(tag, 0);

    mac.digest(tag);

    try testing.expectEqualSlices(u8, expected, tag);

    try testing.expect(mac.verify(expected));

    var flipped: [64]u8 = undefined;

    @memcpy(flipped[0..expected.len], expected);

    flipped[expected.len - 1] ^= 1;

    try testing.expect(!algorithm.verify(key, data, flipped[0..expected.len]));

    try testing.expect(!mac.verify(flipped[0..expected.len]));
}

test "BLAKE2 RFC 7693 examples" {
    const v = try vectors.Vectors.load("rfc/blake2.txt", "out");

    defer v.deinit();

    var examples: usize = 0;

    for (v.records) |r| {
        if (!r.header.is("kind", "example")) continue;

        const name = r.values.get("hash");

        const algorithm = if (std.mem.eql(u8, name, "BLAKE2b-512")) pq.blake2b_512 else if (std.mem.eql(u8, name, "BLAKE2s-256")) pq.blake2s_256 else return error.TestUnexpectedResult;

        const data = try decode(r.values.get("in"));

        defer testing.allocator.free(data);

        const expected = try decode(r.values.get("out"));

        defer testing.allocator.free(expected);

        try checkHash(algorithm, data, expected);

        examples += 1;
    }

    try testing.expectEqual(2, examples);
}

// RFC 7693 Appendix E: selftest_seq(len, seed) is a Fibonacci sequence's top bytes.
fn sequence(out: []u8, seed: u32) void {
    var a: u32 = 0xdead4bad *% seed;

    var b: u32 = 1;

    for (out) |*byte| {
        const t = a +% b;

        a = b;

        b = t;

        byte.* = @truncate(t >> 24);
    }
}

test "BLAKE2 RFC 7693 Appendix E self-test" {
    const v = try vectors.Vectors.load("rfc/blake2.txt", "out");

    defer v.deinit();

    var tests: usize = 0;

    for (v.records) |r| {
        if (!r.header.is("kind", "selftest")) continue;

        const family = r.values.get("hash");

        var grand = (if (std.mem.eql(u8, family, "BLAKE2b")) pq.blake2b_256 else pq.blake2s_256).create();

        var lengths = std.mem.splitScalar(u8, r.values.get("digestLengths"), ',');

        while (lengths.next()) |text| {
            const outlen = try vectors.number(usize, text);

            var inputs = std.mem.splitScalar(u8, r.values.get("inputLengths"), ',');

            while (inputs.next()) |input_text| {
                const inlen = try vectors.number(usize, input_text);

                var data: [1024]u8 = undefined;

                sequence(data[0..inlen], @intCast(inlen));

                var md: [64]u8 = undefined;

                (unkeyed(family, outlen) orelse return error.TestUnexpectedResult).digest(data[0..inlen], md[0..outlen]);

                grand.update(md[0..outlen]);

                var key: [64]u8 = undefined;

                sequence(key[0..outlen], @intCast(outlen));

                const mac = try keyed(family).configure(.{ .length = outlen });

                mac.digest(key[0..outlen], data[0..inlen], md[0..outlen]);

                grand.update(md[0..outlen]);
            }
        }

        var out: [32]u8 = undefined;

        grand.digest(&out);

        const expected = try decode(r.values.get("out"));

        defer testing.allocator.free(expected);

        try testing.expectEqualSlices(u8, expected, &out);

        tests += 1;
    }

    try testing.expectEqual(2, tests);
}

// The reference KATs: the hashes of 0..255 bytes at the full output length, unkeyed and keyed
// with the longest key.
test "BLAKE2 reference KATs" {
    for ([_][]const u8{ "blake2/blake2b.txt", "blake2/blake2s.txt" }, [_][]const u8{ "BLAKE2b", "BLAKE2s" }) |file, family| {
        const v = try vectors.Vectors.load(file, "out");

        defer v.deinit();

        var plain: usize = 0;

        var with_key: usize = 0;

        for (v.records) |r| {
            const data = try decode(r.values.get("in"));

            defer testing.allocator.free(data);

            const key = try decode(r.values.get("key"));

            defer testing.allocator.free(key);

            const expected = try decode(r.values.get("out"));

            defer testing.allocator.free(expected);

            if (key.len == 0) {
                try checkHash(unkeyed(family, expected.len) orelse return error.TestUnexpectedResult, data, expected);

                plain += 1;
            } else {
                try checkMac(keyed(family), key, data, expected);

                with_key += 1;
            }
        }

        try testing.expectEqual(256, plain);

        try testing.expectEqual(256, with_key);
    }
}

// Salt, personalization and key, cross-checked between hashlib and the BLAKE2 reference code.
test "BLAKE2 salt, personalization and keys" {
    const v = try vectors.Vectors.load("derived/blake2.txt", "out");

    defer v.deinit();

    var plain: usize = 0;

    var with_key: usize = 0;

    for (v.records) |r| {
        const family = r.header.get("hash");

        const size = try vectors.number(usize, r.values.get("digestLength"));

        const key = try decode(r.values.get("key"));

        defer testing.allocator.free(key);

        const salt = try decode(r.values.get("salt"));

        defer testing.allocator.free(salt);

        const personalization = try decode(r.values.get("personalization"));

        defer testing.allocator.free(personalization);

        const data = try decode(r.values.get("in"));

        defer testing.allocator.free(data);

        const expected = try decode(r.values.get("out"));

        defer testing.allocator.free(expected);

        try testing.expectEqual(size, expected.len);

        if (key.len == 0) {
            const base = unkeyed(family, size) orelse return error.TestUnexpectedResult;

            try checkHash(try base.configure(.{ .salt = salt, .personalization = personalization }), data, expected);

            plain += 1;
        } else {
            const mac = try keyed(family).configure(.{ .length = size, .salt = salt, .personalization = personalization });

            try checkMac(mac, key, data, expected);

            with_key += 1;
        }
    }

    try testing.expectEqual(200, plain);

    try testing.expectEqual(300, with_key);
}

test "BLAKE2 configure checks its options" {
    const long = [_]u8{0} ** 17;

    try testing.expectError(error.InvalidOption, pq.blake2b_256.configure(.{ .salt = &long }));

    try testing.expectError(error.InvalidOption, pq.blake2b_256.configure(.{ .personalization = &long }));

    try testing.expectError(error.InvalidOption, pq.blake2s_256.configure(.{ .salt = long[0..9] }));

    try testing.expectError(error.InvalidOption, pq.blake2s_256.configure(.{ .personalization = long[0..9] }));

    try testing.expectError(error.InvalidOption, pq.sha_256.configure(.{ .salt = "x" }));

    try testing.expectError(error.InvalidOption, pq.ascon_hash256.configure(.{ .personalization = "x" }));

    try testing.expectError(error.InvalidOption, pq.blake2b_mac.configure(.{ .length = 0 }));

    try testing.expectError(error.InvalidOption, pq.blake2b_mac.configure(.{ .length = 65 }));

    try testing.expectError(error.InvalidOption, pq.blake2s_mac.configure(.{ .length = 33 }));

    try testing.expectError(error.InvalidOption, pq.blake2s_mac.configure(.{ .customization = "x" }));

    try testing.expectError(error.InvalidOption, pq.blake2b_mac.configure(.{ .xof = true }));

    try testing.expectError(error.InvalidOption, pq.blake2s_mac.configure(.{ .salt = long[0..9] }));

    // No options give the algorithm itself; the longest salt and personalization are taken.
    try testing.expectEqualDeep(pq.blake2b_256, try pq.blake2b_256.configure(.{}));

    try testing.expectEqualDeep(pq.sha_256, try pq.sha_256.configure(.{}));

    try testing.expectEqualDeep(pq.blake2s_mac, try pq.blake2s_mac.configure(.{}));

    _ = try pq.blake2b_512.configure(.{ .salt = long[0..16], .personalization = long[0..16] });

    _ = try pq.blake2s_256.configure(.{ .salt = long[0..8], .personalization = long[0..8] });

    // A shorter salt is the same salt zero padded.
    var short: [32]u8 = undefined;

    var padded: [32]u8 = undefined;

    (try pq.blake2s_256.configure(.{ .salt = "ab" })).digest("data", &short);

    (try pq.blake2s_256.configure(.{ .salt = "ab\x00\x00\x00\x00\x00\x00" })).digest("data", &padded);

    try testing.expectEqualSlices(u8, &padded, &short);
}

// A key the MAC cannot take (computing with one panics INVALID_LENGTH) makes a verification fail
// whatever the tag, and the longest keys work.
test "BLAKE2 MAC key lengths" {
    const key = [_]u8{7} ** 65;

    var tag: [64]u8 = undefined;

    for ([_]pq.MacAlgorithm{ pq.blake2b_mac, pq.blake2s_mac }, [_]usize{ 64, 32 }) |mac, max| {
        const size = mac.digest_size;

        try testing.expect(!mac.verify("", "data", tag[0..size]));

        try testing.expect(!mac.verify(key[0 .. max + 1], "data", tag[0..size]));

        mac.digest(key[0..max], "data", tag[0..size]);

        try testing.expect(mac.verify(key[0..max], "data", tag[0..size]));

        try testing.expect(!mac.verify(key[0 .. max - 1], "data", tag[0..size]));

        mac.digest(key[0..1], "data", tag[0..size]);

        try testing.expect(mac.verify(key[0..1], "data", tag[0..size]));
    }
}

test "BLAKE2 properties" {
    const names = [_][]const u8{ "BLAKE2b-160", "BLAKE2b-256", "BLAKE2b-384", "BLAKE2b-512", "BLAKE2s-128", "BLAKE2s-160", "BLAKE2s-224", "BLAKE2s-256" };

    const digest_sizes = [_]usize{ 20, 32, 48, 64, 16, 20, 28, 32 };

    for (hashes, names, digest_sizes) |h, name, size| {
        try testing.expectEqualStrings(name, h.name);

        try testing.expectEqual(size, h.digest_size);
    }

    try testing.expectEqualStrings("BLAKE2b-MAC", pq.blake2b_mac.name);

    try testing.expectEqualStrings("BLAKE2s-MAC", pq.blake2s_mac.name);

    try testing.expectEqual(64, pq.blake2b_mac.digest_size);

    try testing.expectEqual(32, pq.blake2s_mac.digest_size);
}

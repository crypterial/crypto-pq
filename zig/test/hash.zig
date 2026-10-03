const std = @import("std");
const pq = @import("crypto_pq");
const vectors = @import("vectors");

const testing = std.testing;

const Fields = vectors.Fields;

const hashes = [_]struct { file: []const u8, name: []const u8, algorithm: pq.HashAlgorithm }{
    .{ .file = "SHA224", .name = "SHA-224", .algorithm = pq.sha_224 },
    .{ .file = "SHA256", .name = "SHA-256", .algorithm = pq.sha_256 },
    .{ .file = "SHA384", .name = "SHA-384", .algorithm = pq.sha_384 },
    .{ .file = "SHA512", .name = "SHA-512", .algorithm = pq.sha_512 },
    .{ .file = "SHA512_224", .name = "SHA-512/224", .algorithm = pq.sha_512_224 },
    .{ .file = "SHA512_256", .name = "SHA-512/256", .algorithm = pq.sha_512_256 },
    .{ .file = "SHA3_224", .name = "SHA3-224", .algorithm = pq.sha3_224 },
    .{ .file = "SHA3_256", .name = "SHA3-256", .algorithm = pq.sha3_256 },
    .{ .file = "SHA3_384", .name = "SHA3-384", .algorithm = pq.sha3_384 },
    .{ .file = "SHA3_512", .name = "SHA3-512", .algorithm = pq.sha3_512 },
};

const xofs = [_]struct { file: []const u8, algorithm: pq.XofAlgorithm }{
    .{ .file = "SHAKE128", .algorithm = pq.shake128 },
    .{ .file = "SHAKE256", .algorithm = pq.shake256 },
};

// HMAC.rsp labels each group by digest length in bytes; L=20 is SHA-1, which is out of scope.
const hmacs = [_]struct { length: []const u8, name: []const u8, algorithm: pq.HmacAlgorithm }{
    .{ .length = "28", .name = "HMAC-SHA-224", .algorithm = pq.hmac_sha_224 },
    .{ .length = "32", .name = "HMAC-SHA-256", .algorithm = pq.hmac_sha_256 },
    .{ .length = "48", .name = "HMAC-SHA-384", .algorithm = pq.hmac_sha_384 },
    .{ .length = "64", .name = "HMAC-SHA-512", .algorithm = pq.hmac_sha_512 },
};

// Uneven sizes reach every buffering path: empty updates, partial blocks and whole blocks.
const sizes = [_]usize{ 0, 1, 3, 64, 7, 136, 128, 168, 0, 200 };

const Pieces = struct {
    data: []const u8,
    offset: usize = 0,
    index: usize = 0,

    fn next(self: *Pieces) ?[]const u8 {
        if (self.offset >= self.data.len) return null;

        const start = self.offset;

        self.offset = @min(start + sizes[self.index % sizes.len], self.data.len);

        self.index += 1;

        return self.data[start..self.offset];
    }
};

fn decode(hex: []const u8) ![]u8 {
    return vectors.decode(testing.allocator, hex);
}

fn number(text: []const u8) !usize {
    return vectors.number(usize, text);
}

fn message(values: Fields) ![]u8 {
    const bits = try number(values.get("Len"));

    if (bits % 8 != 0) return error.TestUnexpectedResult;

    return decode(values.get("Msg")[0 .. bits / 4]);
}

test "hash vectors" {
    for (hashes) |h| {
        for ([_][]const u8{ "ShortMsg", "LongMsg" }) |kind| {
            var name: [64]u8 = undefined;

            const v = try vectors.Vectors.load(try std.fmt.bufPrint(&name, "cavp/{s}{s}.rsp", .{ h.file, kind }), "MD");

            defer v.deinit();

            for (v.records) |r| {
                const data = try message(r.values);

                defer testing.allocator.free(data);

                const expected = try decode(r.values.get("MD"));

                defer testing.allocator.free(expected);

                var out: [64]u8 = undefined;

                const digest = out[0..h.algorithm.digest_size];

                h.algorithm.digest(data, digest);

                try testing.expectEqualSlices(u8, expected, digest);

                var hasher = h.algorithm.create();

                var pieces: Pieces = .{ .data = data };

                while (pieces.next()) |piece| {
                    hasher.update(piece);
                }

                hasher.digest(digest);

                try testing.expectEqualSlices(u8, expected, digest);
            }
        }
    }
}

// SHAVS 6.4 and SHA3VS 6.2.3: each checkpoint chains 1000 digests from the previous one.
test "hash monte carlo" {
    for (hashes) |h| {
        var name: [64]u8 = undefined;

        const v = try vectors.Vectors.load(try std.fmt.bufPrint(&name, "cavp/{s}Monte.rsp", .{h.file}), "MD");

        defer v.deinit();

        const size = h.algorithm.digest_size;

        var md: [3][64]u8 = undefined;

        _ = try std.fmt.hexToBytes(md[2][0..size], v.records[0].values.get("Seed"));

        for (v.records[1..]) |r| {
            if (std.mem.startsWith(u8, h.file, "SHA3_")) {
                for (0..1000) |_| {
                    var next: [64]u8 = undefined;

                    h.algorithm.digest(md[2][0..size], next[0..size]);

                    md[2] = next;
                }
            } else {
                md[0] = md[2];

                md[1] = md[2];

                for (0..1000) |_| {
                    var input: [192]u8 = undefined;

                    for (md, 0..) |part, i| {
                        @memcpy(input[i * size ..][0..size], part[0..size]);
                    }

                    md[0] = md[1];

                    md[1] = md[2];

                    h.algorithm.digest(input[0 .. 3 * size], md[2][0..size]);
                }
            }

            const expected = try decode(r.values.get("MD"));

            defer testing.allocator.free(expected);

            try testing.expectEqualSlices(u8, expected, md[2][0..size]);
        }
    }
}

test "hash digest is repeatable" {
    for (hashes) |h| {
        var first: [64]u8 = undefined;

        var again: [64]u8 = undefined;

        var expected: [64]u8 = undefined;

        const size = h.algorithm.digest_size;

        var hasher = h.algorithm.create();

        hasher.update("abc");

        hasher.digest(first[0..size]);

        hasher.digest(again[0..size]);

        h.algorithm.digest("abc", expected[0..size]);

        try testing.expectEqualSlices(u8, first[0..size], again[0..size]);

        try testing.expectEqualSlices(u8, expected[0..size], first[0..size]);

        hasher.update("def");

        hasher.digest(first[0..size]);

        h.algorithm.digest("abcdef", expected[0..size]);

        try testing.expectEqualSlices(u8, expected[0..size], first[0..size]);
    }
}

test "hash properties" {
    for (hashes) |h| {
        try testing.expectEqualStrings(h.name, h.algorithm.name);
    }
}

test "xof vectors" {
    for (xofs) |x| {
        for ([_][]const u8{ "ShortMsg", "LongMsg" }) |kind| {
            var name: [64]u8 = undefined;

            const v = try vectors.Vectors.load(try std.fmt.bufPrint(&name, "cavp/{s}{s}.rsp", .{ x.file, kind }), "Output");

            defer v.deinit();

            for (v.records) |r| {
                const data = try message(r.values);

                defer testing.allocator.free(data);

                const expected = try decode(r.values.get("Output"));

                defer testing.allocator.free(expected);

                try testing.expectEqual(8 * expected.len, try number(r.header.get("Outputlen")));

                var buffer: [256]u8 = undefined;

                const out = buffer[0..expected.len];

                x.algorithm.digest(data, out);

                try testing.expectEqualSlices(u8, expected, out);

                var xof = x.algorithm.create();

                var pieces: Pieces = .{ .data = data };

                while (pieces.next()) |piece| {
                    xof.update(piece);
                }

                xof.read(out[0..1]);

                xof.read(out[1..]);

                try testing.expectEqualSlices(u8, expected, out);
            }
        }

        var name: [64]u8 = undefined;

        const v = try vectors.Vectors.load(try std.fmt.bufPrint(&name, "cavp/{s}VariableOut.rsp", .{x.file}), "Output");

        defer v.deinit();

        for (v.records) |r| {
            const data = try decode(r.values.get("Msg"));

            defer testing.allocator.free(data);

            const expected = try decode(r.values.get("Output"));

            defer testing.allocator.free(expected);

            try testing.expectEqual(8 * expected.len, try number(r.values.get("Outputlen")));

            var buffer: [256]u8 = undefined;

            x.algorithm.digest(data, buffer[0..expected.len]);

            try testing.expectEqualSlices(u8, expected, buffer[0..expected.len]);
        }
    }
}

// SHA3VS 6.3.3: the next input is the first 16 output bytes, zero-padded, and the last two
// output bytes pick the next output length.
test "xof monte carlo" {
    for (xofs) |x| {
        var name: [64]u8 = undefined;

        const v = try vectors.Vectors.load(try std.fmt.bufPrint(&name, "cavp/{s}Monte.rsp", .{x.file}), "Output");

        defer v.deinit();

        const header = v.records[0].header;

        const minimum = try number(header.get("Minimum Output Length (bits)")) / 8;

        const maximum = try number(header.get("Maximum Output Length (bits)")) / 8;

        var output: [256]u8 = undefined;

        var length: usize = 16;

        _ = try std.fmt.hexToBytes(output[0..length], v.records[0].values.get("Msg"));

        var next = maximum;

        for (v.records[1..]) |r| {
            for (0..1000) |_| {
                var input: [16]u8 = @splat(0);

                const n = @min(length, 16);

                @memcpy(input[0..n], output[0..n]);

                length = next;

                x.algorithm.digest(&input, output[0..length]);

                next = minimum + (@as(usize, output[length - 2]) << 8 | output[length - 1]) % (maximum - minimum + 1);
            }

            const expected = try decode(r.values.get("Output"));

            defer testing.allocator.free(expected);

            try testing.expectEqualSlices(u8, expected, output[0..length]);

            try testing.expectEqual(8 * length, try number(r.values.get("Outputlen")));
        }
    }
}

test "xof streaming read" {
    for (xofs) |x| {
        var expected: [1000]u8 = undefined;

        x.algorithm.digest("abc", &expected);

        var out: [1000]u8 = undefined;

        var xof = x.algorithm.create();

        xof.update("abc");

        var offset: usize = 0;

        for ([_]usize{ 0, 1, 135, 1, 167, 200, 496 }) |n| {
            xof.read(out[offset..][0..n]);

            offset += n;
        }

        try testing.expectEqualSlices(u8, &expected, &out);
    }
}

test "xof properties" {
    try testing.expectEqualStrings("SHAKE128", pq.shake128.name);

    try testing.expectEqualStrings("SHAKE256", pq.shake256.name);
}

test "hmac vectors" {
    const v = try vectors.Vectors.load("cavp/HMAC.rsp", "Mac");

    defer v.deinit();

    var tested: usize = 0;

    for (v.records) |r| {
        const length = r.header.get("L");

        if (std.mem.eql(u8, length, "20")) continue;

        const algorithm = for (hmacs) |h| {
            if (std.mem.eql(u8, h.length, length)) break h.algorithm;
        } else return error.TestUnexpectedResult;

        const key = try decode(r.values.get("Key"));

        defer testing.allocator.free(key);

        const data = try decode(r.values.get("Msg"));

        defer testing.allocator.free(data);

        const mac = try decode(r.values.get("Mac"));

        defer testing.allocator.free(mac);

        try testing.expectEqual(key.len, try number(r.values.get("Klen")));

        try testing.expectEqual(mac.len, try number(r.values.get("Tlen")));

        var buffer: [64]u8 = undefined;

        const tag = buffer[0..algorithm.digest_size];

        algorithm.digest(key, data, tag);

        try testing.expectEqualSlices(u8, mac, tag[0..mac.len]);

        var streamed: [64]u8 = undefined;

        var hmac = algorithm.create(key);

        var pieces: Pieces = .{ .data = data };

        while (pieces.next()) |piece| {
            hmac.update(piece);
        }

        hmac.digest(streamed[0..algorithm.digest_size]);

        try testing.expectEqualSlices(u8, tag, streamed[0..algorithm.digest_size]);

        try testing.expect(hmac.verify(tag));

        try testing.expect(algorithm.verify(key, data, tag));

        tested += 1;
    }

    try testing.expectEqual(1275, tested);
}

test "hmac verify rejects" {
    var tag: [32]u8 = undefined;

    pq.hmac_sha_256.digest("key", "data", &tag);

    try testing.expect(!pq.hmac_sha_256.verify("key", "data", tag[0..31]));

    try testing.expect(!pq.hmac_sha_256.verify("key", "data", &(tag ++ [_]u8{0})));

    try testing.expect(!pq.hmac_sha_256.verify("kez", "data", &tag));

    for (0..tag.len) |index| {
        var flipped = tag;

        flipped[index] ^= 0x80;

        try testing.expect(!pq.hmac_sha_256.verify("key", "data", &flipped));
    }
}

test "hmac properties" {
    for (hmacs) |h| {
        try testing.expectEqualStrings(h.name, h.algorithm.name);

        try testing.expectEqual(h.algorithm.hash.digest_size, h.algorithm.digest_size);
    }
}

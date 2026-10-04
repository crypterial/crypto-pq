// Untrusted input gets only the defined errors: random and mutated encodings, signatures,
// ciphertexts and state blobs go through every parsing path, accepted inputs must round-trip, and
// nothing may trip a safety check. A deterministic generator keeps every run reproducible;
// CRYPTO_PQ_FUZZ=1 runs many more rounds.

const std = @import("std");
const builtin = @import("builtin");
const pq = @import("crypto_pq");
const vectors = @import("vectors");

const testing = std.testing;

const hazmat = pq.hazmat;

const Allocator = std.mem.Allocator;

fn scale() usize {
    return if (testing.environ.containsUnempty(testing.allocator, "CRYPTO_PQ_FUZZ") catch false) 50 else 1;
}

// SplitMix64, the generator of every implementation's robustness tests.
const Random = struct {
    state: u64,

    fn next(self: *Random) u64 {
        self.state +%= 0x9E3779B97F4A7C15;

        var z = self.state;

        z = (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;

        z = (z ^ (z >> 27)) *% 0x94D049BB133111EB;

        return z ^ (z >> 31);
    }

    fn below(self: *Random, bound: usize) usize {
        return @intCast(self.next() % bound);
    }

    fn bytes(self: *Random, allocator: Allocator, size: usize) ![]u8 {
        const out = try allocator.alloc(u8, size);

        for (out) |*byte| byte.* = @truncate(self.next());

        return out;
    }
};

fn pattern(allocator: Allocator, size: usize, first: u8) ![]u8 {
    const out = try allocator.alloc(u8, size);

    for (out, 0..) |*byte, i| byte.* = first +% @as(u8, @truncate(i));

    return out;
}

const tags = [_]u8{ 0x02, 0x03, 0x04, 0x06, 0x30, 0x80, 0x81, 0xa0 };

// Indefinite, gigabytes, non-minimal, five bytes long, and plain wrong lengths.
const lengths = [_][]const u8{
    &.{0x80},
    &.{ 0x84, 0xff, 0xff, 0xff, 0xff },
    &.{ 0x84, 0x7f, 0xff, 0xff, 0xff },
    &.{ 0x83, 0xff, 0xff, 0xff },
    &.{ 0x82, 0xff, 0xff },
    &.{ 0x81, 0x05 },
    &.{ 0x81, 0x7f },
    &.{ 0x82, 0x00, 0x80 },
    &.{ 0x85, 0x01, 0x00, 0x00, 0x00, 0x00 },
    &.{0x00},
    &.{0x01},
    &.{0x7f},
};

const spaces = [_][]const u8{ " ", "\t", "\n", "\r\n", "\x0b", "\x0c" };

// The OIDs of every algorithm and of SHA-256, those of the stateful schemes, and broken ones.
const oids = blk: {
    var out: [4 + 32 + 4 + 3][]const u8 = undefined;

    for (0..4) |i| out[i] = &[_]u8{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 1 + i };

    for (0..32) |i| out[4 + i] = &[_]u8{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 16 + i };

    out[36] = &.{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };

    out[37] = &.{ 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x11 };

    out[38] = &.{ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x22 };

    out[39] = &.{ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x23 };

    out[40] = &.{ 0x06, 0x00 };

    out[41] = &.{ 0x06, 0x01, 0x00 };

    out[42] = &.{ 0x06, 0x81, 0x01, 0x2a };

    break :blk out;
};

fn tagPosition(rng: *Random, data: []const u8) ?usize {
    for (0..16) |_| {
        const position = rng.below(data.len);

        if (std.mem.findScalar(u8, &tags, data[position]) != null and position + 1 < data.len) return position;
    }

    return null;
}

fn oidPosition(rng: *Random, data: []const u8) ?usize {
    var count: usize = 0;

    for (0..data.len -| 1) |i| {
        if (data[i] == 0x06 and data[i + 1] < 0x10 and i + 2 + data[i + 1] <= data.len) count += 1;
    }

    if (count == 0) return null;

    var target = rng.below(count);

    for (0..data.len - 1) |i| {
        if (data[i] == 0x06 and data[i + 1] < 0x10 and i + 2 + data[i + 1] <= data.len) {
            if (target == 0) return i;

            target -= 1;
        }
    }

    unreachable;
}

// One random edit: bits, bytes, insertions, deletions, truncation, DER length fields (huge,
// indefinite, non-minimal), tags, OIDs, or a slice of another valid encoding.
fn mutate(rng: *Random, allocator: Allocator, data: []const u8, others: []const []const u8) ![]u8 {
    if (data.len == 0) return rng.bytes(allocator, rng.below(16));

    var out: std.ArrayList(u8) = .empty;

    try out.appendSlice(allocator, data);

    const operation = rng.below(11);

    const position = rng.below(data.len);

    // An edit that does not apply (no tag, no OID, nothing to splice from) duplicates a slice.
    const header = if (operation == 6 or operation == 7) tagPosition(rng, out.items) else null;

    const oid = if (operation == 8) oidPosition(rng, out.items) else null;

    if (operation == 0) {
        out.items[position] ^= @as(u8, 1) << @intCast(rng.below(8));
    } else if (operation == 1) {
        const choices = [_]u8{ 0x00, 0x01, 0x7f, 0x80, 0xff, @truncate(rng.below(256)) };

        out.items[position] = choices[rng.below(choices.len)];
    } else if (operation == 2) {
        try out.insertSlice(allocator, position, try rng.bytes(allocator, 1 + rng.below(4)));
    } else if (operation == 3) {
        const end = @min(out.items.len, position + 1 + rng.below(4));

        try out.replaceRange(allocator, position, end - position, &.{});
    } else if (operation == 4) {
        out.shrinkRetainingCapacity(position);
    } else if (operation == 5) {
        try out.appendSlice(allocator, try rng.bytes(allocator, 1 + rng.below(32)));
    } else if (operation == 6 and header != null) {
        const first = out.items[header.? + 1];

        const size = 1 + if (first & 0x80 != 0) @as(usize, first & 0x7f) else 0;

        const end = @min(out.items.len, header.? + 1 + size);

        var single = [_]u8{0};

        const length: []const u8 = if (rng.below(2) == 1) lengths[rng.below(lengths.len)] else blk: {
            single[0] = @truncate(rng.below(256));

            break :blk &single;
        };

        try out.replaceRange(allocator, header.? + 1, end - header.? - 1, length);
    } else if (operation == 7 and header != null) {
        const random: u8 = @truncate(rng.below(256));

        out.items[header.?] = if (rng.below(2) == 1) tags[rng.below(tags.len)] else random;
    } else if (operation == 8 and oid != null) {
        const end = oid.? + 2 + out.items[oid.? + 1];

        try out.replaceRange(allocator, oid.?, end - oid.?, oids[rng.below(oids.len)]);
    } else if (operation == 9 and others.len > 0) {
        const other = others[rng.below(others.len)];

        const start = rng.below(other.len + 1);

        const piece = other[start..@min(other.len, start + rng.below(64))];

        const end = @min(out.items.len, position + rng.below(64));

        try out.replaceRange(allocator, position, end - position, piece);
    } else {
        const end = @min(out.items.len, position + 1 + rng.below(16));

        const copy = try allocator.dupe(u8, out.items[position..end]);

        try out.insertSlice(allocator, position, copy);
    }

    return out.toOwnedSlice(allocator);
}

fn isSpace(byte: u8) bool {
    return byte == ' ' or (byte >= 0x09 and byte <= 0x0d);
}

fn mutatePem(rng: *Random, allocator: Allocator, text: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;

    try out.appendSlice(allocator, text);

    const operation = rng.below(8);

    const position = rng.below(text.len + 1);

    switch (operation) {
        0 => {
            const space = spaces[rng.below(spaces.len)];

            for (0..1 + rng.below(3)) |_| try out.insertSlice(allocator, position, space);
        },
        1 => try out.insert(allocator, position, @as(u8, 0x80) + @as(u8, @truncate(rng.below(128)))),
        2 => try out.insert(allocator, position, '='),
        3 => if (std.mem.find(u8, out.items, "PUBLIC")) |at| {
            try out.replaceRange(allocator, at, 6, "PRIVATE");
        },
        4 => {
            var kept: usize = 0;

            for (out.items) |byte| {
                if (byte != '\n') {
                    out.items[kept] = byte;

                    kept += 1;
                }
            }

            out.shrinkRetainingCapacity(kept);
        },
        5 => {
            const width = 1 + rng.below(80);

            var lines: std.ArrayList(u8) = .empty;

            var column: usize = 0;

            for (text) |byte| {
                if (isSpace(byte)) continue;

                try lines.append(allocator, byte);

                column += 1;

                if (column == width) {
                    try lines.append(allocator, '\n');

                    column = 0;
                }
            }

            out.deinit(allocator);

            return lines.toOwnedSlice(allocator);
        },
        else => {
            out.deinit(allocator);

            return mutate(rng, allocator, text, &.{});
        },
    }

    return out.toOwnedSlice(allocator);
}

fn nextInput(rng: *Random, allocator: Allocator, seeds: []const []const u8) ![]u8 {
    if (rng.below(8) == 0) return rng.bytes(allocator, rng.below(96));

    var data: []const u8 = seeds[rng.below(seeds.len)];

    for (0..1 + rng.below(3)) |_| data = try mutate(rng, allocator, data, seeds);

    return @constCast(data);
}

// An error must be one of the codes; the input is printed so that a failure can be replayed.
fn expectCode(err: anyerror, codes: []const anyerror, what: []const u8, data: []const u8) !void {
    for (codes) |code| {
        if (err == code) return;
    }

    std.debug.print("{s}: {s} for {x}\n", .{ what, @errorName(err), data });

    return error.TestUnexpectedResult;
}

const formats = [_]pq.KeyFormat{ .raw, .der, .pem };

// The DER inside a PEM input, so that encodings that differ only in whitespace compare equal.
fn pemBody(allocator: Allocator, data: []const u8) ![]u8 {
    var text: std.ArrayList(u8) = .empty;

    for (data) |byte| {
        if (!isSpace(byte)) try text.append(allocator, byte);
    }

    const items = text.items;

    const start = std.mem.findScalarPos(u8, items, 5, '-').? + 5;

    const end = std.mem.findScalarLast(u8, items[0 .. items.len - 5], '-').? - 4;

    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    var out: std.ArrayList(u8) = .empty;

    var bits: u32 = 0;

    var count: u5 = 0;

    for (items[start..end]) |byte| {
        const value = std.mem.findScalar(u8, alphabet, byte) orelse continue;

        bits = (bits << 6) | @as(u32, @intCast(value));

        count += 6;

        if (count >= 8) {
            count -= 8;

            try out.append(allocator, @truncate(bits >> count));
        }
    }

    return out.toOwnedSlice(allocator);
}

fn sameEncoding(allocator: Allocator, exported: []const u8, data: []const u8, format: pq.KeyFormat) !void {
    if (format == .pem) {
        try testing.expectEqualSlices(u8, try pemBody(allocator, data), try pemBody(allocator, exported));
    } else {
        try testing.expectEqualSlices(u8, data, exported);
    }
}

const kems = [_]pq.KemAlgorithm{ pq.ml_kem_512, pq.ml_kem_768, pq.ml_kem_1024, pq.x_wing };

fn kemSizes(algorithm: pq.KemAlgorithm) [2]usize {
    return if (algorithm.kind == .x_wing) .{ 32, 64 } else .{ 64, 32 };
}

fn kemCodes(algorithm: pq.KemAlgorithm, format: pq.KeyFormat, check: anyerror) []const anyerror {
    return switch (format) {
        .raw => if (check == error.InvalidPublicKey) &.{ error.InvalidLength, error.InvalidPublicKey } else &.{ error.InvalidLength, error.InvalidPrivateKey },
        else => if (algorithm.kind == .x_wing) &.{error.Unsupported} else if (check == error.InvalidPublicKey) &.{ error.InvalidEncoding, error.AlgorithmMismatch, error.InvalidPublicKey } else &.{ error.InvalidEncoding, error.AlgorithmMismatch, error.InvalidPrivateKey },
    };
}

fn checkKemPublic(allocator: Allocator, algorithm: pq.KemAlgorithm, data: []const u8, format: pq.KeyFormat) !void {
    var key = algorithm.importPublicKey(allocator, data, format) catch |err| return expectCode(err, kemCodes(algorithm, format, error.InvalidPublicKey), algorithm.name, data);

    defer key.deinit();

    try sameEncoding(allocator, try key.exportKey(allocator, format), data, format);

    for (formats) |other| {
        const exported = key.exportKey(allocator, other) catch continue;

        var again = try algorithm.importPublicKey(allocator, exported, other);

        defer again.deinit();

        try testing.expect(again.eql(&key));
    }

    const randomness = try allocator.alloc(u8, kemSizes(algorithm)[1]);

    @memset(randomness, 0);

    const encapsulation = try hazmat.encapsulate(&key, randomness);

    try testing.expectEqual(algorithm.ciphertext_size, encapsulation.ciphertext().len);
}

fn checkKemPrivate(allocator: Allocator, algorithm: pq.KemAlgorithm, data: []const u8, format: pq.KeyFormat) !void {
    var key = algorithm.importPrivateKey(allocator, data, format) catch |err| return expectCode(err, kemCodes(algorithm, format, error.InvalidPrivateKey), algorithm.name, data);

    defer key.deinit();

    const raw = try key.exportKey(allocator, .raw);

    if (format == .raw) try testing.expectEqualSlices(u8, data, raw);

    for (formats) |other| {
        const exported = key.exportKey(allocator, other) catch continue;

        var again = try algorithm.importPrivateKey(allocator, exported, other);

        defer again.deinit();

        try testing.expectEqualSlices(u8, raw, try again.exportKey(allocator, .raw));
    }

    // A key from a seed decapsulates what its public key encapsulates. FIPS 203 checks only the
    // hash of the public part of an expanded key, so one with another secret vector is accepted
    // and gives the implicit rejection, SHAKE256(z || c).
    const randomness = try allocator.alloc(u8, kemSizes(algorithm)[1]);

    @memset(randomness, 0);

    var public_key = key.publicKey();

    defer public_key.deinit();

    const encapsulation = try hazmat.encapsulate(&public_key, randomness);

    const secret = try key.decapsulate(encapsulation.ciphertext());

    if (!std.mem.eql(u8, &secret, &encapsulation.shared_secret)) {
        try testing.expect(raw.len != kemSizes(algorithm)[0]);

        var rejection: [32]u8 = undefined;

        pq.shake256.digest(try std.mem.concat(allocator, u8, &.{ raw[raw.len - 32 ..], encapsulation.ciphertext() }), &rejection);

        try testing.expectEqualSlices(u8, &rejection, &secret);
    }
}

// The expanded private key of the first ACVP key generation record of an ML-KEM parameter set.
fn expandedKey(allocator: Allocator, records: []const vectors.Record, algorithm: pq.KemAlgorithm) ![]u8 {
    for (records) |record| {
        if (record.header.is("parameterSet", algorithm.name)) return vectors.decode(allocator, record.values.get("dk"));
    }

    return error.TestUnexpectedResult;
}

// FIPS 203 checks only the hash of the public part of an expanded key, so one whose secret vector
// was changed is accepted and decapsulates to the implicit rejection, SHAKE256(z || c).
test "robustness: an inconsistent expanded ML-KEM key decapsulates to the implicit rejection" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const acvp = try vectors.Vectors.load("acvp/ML-KEM-keyGen.txt", "dk");

    defer acvp.deinit();

    for (kems[0..3]) |algorithm| {
        const dk = try expandedKey(allocator, acvp.records, algorithm);

        dk[0] ^= 1;

        var key = try algorithm.importPrivateKey(allocator, dk, .raw);

        defer key.deinit();

        var public_key = key.publicKey();

        defer public_key.deinit();

        const encapsulation = try hazmat.encapsulate(&public_key, try pattern(allocator, 32, 0x80));

        var rejection: [32]u8 = undefined;

        pq.shake256.digest(try std.mem.concat(allocator, u8, &.{ dk[dk.len - 32 ..], encapsulation.ciphertext() }), &rejection);

        try testing.expectEqualSlices(u8, &rejection, &try key.decapsulate(encapsulation.ciphertext()));
    }
}

test "robustness: KEM key import takes any bytes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const acvp = try vectors.Vectors.load("acvp/ML-KEM-keyGen.txt", "dk");

    defer acvp.deinit();

    var rng: Random = .{ .state = 3 };

    for (kems) |algorithm| {
        var pair = try hazmat.generateKemKeyPair(algorithm, testing.allocator, try pattern(allocator, kemSizes(algorithm)[0], 0));

        defer pair.private_key.deinit();

        defer pair.public_key.deinit();

        var expanded: ?pq.KemPrivateKey = if (algorithm.kind == .x_wing) null else try algorithm.importPrivateKey(testing.allocator, try expandedKey(allocator, acvp.records, algorithm), .raw);

        defer if (expanded) |*key| key.deinit();

        for ([_]bool{ false, true }) |private| {
            for (formats) |format| {
                var seeds: [2][]const u8 = undefined;

                var count: usize = 1;

                seeds[0] = if (algorithm.kind == .x_wing and format != .raw)
                    try pair.public_key.exportKey(allocator, .raw)
                else if (private)
                    try pair.private_key.exportKey(allocator, format)
                else
                    try pair.public_key.exportKey(allocator, format);

                if (private and expanded != null) {
                    seeds[1] = try expanded.?.exportKey(allocator, format);

                    count = 2;
                }

                for (0..25 * scale()) |_| {
                    const data = try nextInput(&rng, allocator, seeds[0..count]);

                    if (private) {
                        try checkKemPrivate(allocator, algorithm, data, format);
                    } else {
                        try checkKemPublic(allocator, algorithm, data, format);
                    }
                }

                _ = arena.reset(.retain_capacity);
            }
        }
    }
}

const signatures = [_]pq.SignatureAlgorithm{
    pq.ml_dsa_44,
    pq.ml_dsa_65,
    pq.ml_dsa_87,
    pq.slh_dsa_sha2_128s,
    pq.slh_dsa_sha2_128f,
    pq.slh_dsa_sha2_192s,
    pq.slh_dsa_sha2_192f,
    pq.slh_dsa_sha2_256s,
    pq.slh_dsa_sha2_256f,
    pq.slh_dsa_shake_128s,
    pq.slh_dsa_shake_128f,
    pq.slh_dsa_shake_192s,
    pq.slh_dsa_shake_192f,
    pq.slh_dsa_shake_256s,
    pq.slh_dsa_shake_256f,
};

fn isMlDsa(algorithm: pq.SignatureAlgorithm) bool {
    return std.mem.startsWith(u8, algorithm.name, "ML-DSA");
}

// The fast sets by default; every set in a long run.
fn selected(algorithm: pq.SignatureAlgorithm) bool {
    return scale() > 1 or isMlDsa(algorithm) or std.mem.endsWith(u8, algorithm.name, "f");
}

fn signatureSeedSize(algorithm: pq.SignatureAlgorithm) usize {
    return if (isMlDsa(algorithm)) 32 else 3 * algorithm.public_key_size / 2;
}

fn signatureCodes(format: pq.KeyFormat, check: anyerror) []const anyerror {
    return switch (format) {
        .raw => if (check == error.InvalidLength) &.{error.InvalidLength} else &.{ error.InvalidLength, error.InvalidPrivateKey },
        else => if (check == error.InvalidLength) &.{ error.InvalidEncoding, error.AlgorithmMismatch } else &.{ error.InvalidEncoding, error.AlgorithmMismatch, error.InvalidPrivateKey },
    };
}

fn checkSignaturePublic(allocator: Allocator, algorithm: pq.SignatureAlgorithm, data: []const u8, format: pq.KeyFormat) !void {
    var key = algorithm.importPublicKey(allocator, data, format) catch |err| return expectCode(err, signatureCodes(format, error.InvalidLength), algorithm.name, data);

    defer key.deinit();

    try sameEncoding(allocator, try key.exportKey(allocator, format), data, format);

    for (formats) |other| {
        var again = try algorithm.importPublicKey(allocator, try key.exportKey(allocator, other), other);

        defer again.deinit();

        try testing.expect(again.eql(&key));
    }

    const zero = try allocator.alloc(u8, algorithm.signature_size);

    @memset(zero, 0);

    try testing.expect(!key.verify(zero, "", .{}));
}

fn checkSignaturePrivate(allocator: Allocator, algorithm: pq.SignatureAlgorithm, data: []const u8, format: pq.KeyFormat) !void {
    var key = algorithm.importPrivateKey(allocator, data, format) catch |err| return expectCode(err, signatureCodes(format, error.InvalidPrivateKey), algorithm.name, data);

    defer key.deinit();

    const raw = try key.exportKey(allocator, .raw);

    if (format == .raw) try testing.expectEqualSlices(u8, data, raw);

    for (formats) |other| {
        var again = try algorithm.importPrivateKey(allocator, try key.exportKey(allocator, other), other);

        defer again.deinit();

        try testing.expectEqualSlices(u8, raw, try again.exportKey(allocator, .raw));
    }

    var public_key = key.publicKey();

    defer public_key.deinit();

    if (!isMlDsa(algorithm)) {
        try testing.expectEqualSlices(u8, raw[raw.len / 2 ..], try public_key.exportKey(allocator, .raw));

        return;
    }

    const signature = try hazmat.sign(&key, allocator, "accepted", &([_]u8{0} ** 32), .{});

    try testing.expect(public_key.verify(signature, "accepted", .{}));
}

test "robustness: signature key import takes any bytes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    var rng: Random = .{ .state = 4 };

    for (signatures) |algorithm| {
        if (!selected(algorithm)) continue;

        var pair = try hazmat.generateSignatureKeyPair(algorithm, testing.allocator, try pattern(allocator, signatureSeedSize(algorithm), 0));

        defer pair.private_key.deinit();

        defer pair.public_key.deinit();

        const rounds = (if (isMlDsa(algorithm)) @as(usize, 25) else 4) * scale();

        for ([_]bool{ false, true }) |private| {
            for (formats) |format| {
                const seed = if (private) try pair.private_key.exportKey(allocator, format) else try pair.public_key.exportKey(allocator, format);

                for (0..rounds) |_| {
                    const data = try nextInput(&rng, allocator, &.{seed});

                    if (private) {
                        try checkSignaturePrivate(allocator, algorithm, data, format);
                    } else {
                        try checkSignaturePublic(allocator, algorithm, data, format);
                    }
                }

                _ = arena.reset(.retain_capacity);
            }
        }
    }
}

const stateful_seeds = [_]struct { algorithm: pq.StatefulSignatureAlgorithm, prefix: []const u8, size: usize }{
    .{ .algorithm = pq.hss_lms, .prefix = &.{ 0, 0, 0, 1, 0, 0, 0, 10, 0, 0, 0, 5 }, .size = 40 },
    .{ .algorithm = pq.hss_lms, .prefix = &.{ 0, 0, 0, 8, 0, 0, 0, 0x14, 0, 0, 0, 0x10 }, .size = 40 },
    .{ .algorithm = pq.xmss, .prefix = &.{ 0, 0, 0, 1 }, .size = 64 },
    .{ .algorithm = pq.xmss, .prefix = &.{ 0, 0, 0, 0x15 }, .size = 48 },
    .{ .algorithm = pq.xmss_mt, .prefix = &.{ 0, 0, 0, 0x31 }, .size = 48 },
    .{ .algorithm = pq.xmss_mt, .prefix = &.{ 0, 0, 0, 8 }, .size = 64 },
};

test "robustness: stateful public key import takes any bytes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    var rng: Random = .{ .state = 5 };

    for (stateful_seeds) |seed| {
        const algorithm = seed.algorithm;

        const key = try algorithm.importPublicKey(try std.mem.concat(allocator, u8, &.{ seed.prefix, try pattern(allocator, seed.size, 0) }), .raw);

        for (formats) |format| {
            const encoded = try key.exportKey(allocator, format);

            for (0..150 * scale()) |_| {
                const data = try nextInput(&rng, allocator, &.{encoded});

                const codes: []const anyerror = if (format == .raw) &.{error.InvalidPublicKey} else &.{ error.InvalidEncoding, error.AlgorithmMismatch, error.InvalidPublicKey };

                const imported = algorithm.importPublicKey(data, format) catch |err| {
                    try expectCode(err, codes, algorithm.name, data);

                    continue;
                };

                try sameEncoding(allocator, try imported.exportKey(allocator, format), data, format);

                for (formats) |other| {
                    const again = try algorithm.importPublicKey(try imported.exportKey(allocator, other), other);

                    try testing.expect(again.eql(&imported));
                }

                try testing.expect(!imported.verify(&([_]u8{0} ** 64), ""));
            }

            _ = arena.reset(.retain_capacity);
        }
    }
}

// PEM edits: whitespace anywhere, non-ASCII bytes, padding, the other label, other line widths.
test "robustness: PEM import takes any text" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    var rng: Random = .{ .state = 10 };

    var kem = try hazmat.generateKemKeyPair(pq.ml_kem_768, testing.allocator, try pattern(allocator, 64, 0));

    defer kem.private_key.deinit();

    defer kem.public_key.deinit();

    var dsa = try hazmat.generateSignatureKeyPair(pq.ml_dsa_44, testing.allocator, try pattern(allocator, 32, 0));

    defer dsa.private_key.deinit();

    defer dsa.public_key.deinit();

    const seeds = [_][]const u8{
        try kem.public_key.exportKey(allocator, .pem),
        try kem.private_key.exportKey(allocator, .pem),
        try dsa.public_key.exportKey(allocator, .pem),
        try dsa.private_key.exportKey(allocator, .pem),
    };

    var scratch = std.heap.ArenaAllocator.init(testing.allocator);

    defer scratch.deinit();

    for (0..300 * scale()) |_| {
        const choice = rng.below(seeds.len);

        var text: []const u8 = seeds[choice];

        for (0..1 + rng.below(3)) |_| text = try mutatePem(&rng, scratch.allocator(), text);

        switch (choice) {
            0 => try checkKemPublic(scratch.allocator(), pq.ml_kem_768, text, .pem),
            1 => try checkKemPrivate(scratch.allocator(), pq.ml_kem_768, text, .pem),
            2 => try checkSignaturePublic(scratch.allocator(), pq.ml_dsa_44, text, .pem),
            else => try checkSignaturePrivate(scratch.allocator(), pq.ml_dsa_44, text, .pem),
        }

        _ = scratch.reset(.retain_capacity);
    }
}

const pre_hashes = [_]struct { strength: usize, pre_hash: pq.PreHash }{
    .{ .strength = 112, .pre_hash = .{ .hash = pq.sha_224 } },
    .{ .strength = 128, .pre_hash = .{ .hash = pq.sha_256 } },
    .{ .strength = 192, .pre_hash = .{ .hash = pq.sha_384 } },
    .{ .strength = 256, .pre_hash = .{ .hash = pq.sha_512 } },
    .{ .strength = 112, .pre_hash = .{ .hash = pq.sha_512_224 } },
    .{ .strength = 128, .pre_hash = .{ .hash = pq.sha_512_256 } },
    .{ .strength = 112, .pre_hash = .{ .hash = pq.sha3_224 } },
    .{ .strength = 128, .pre_hash = .{ .hash = pq.sha3_256 } },
    .{ .strength = 192, .pre_hash = .{ .hash = pq.sha3_384 } },
    .{ .strength = 256, .pre_hash = .{ .hash = pq.sha3_512 } },
    .{ .strength = 128, .pre_hash = .{ .xof = pq.shake128 } },
    .{ .strength = 256, .pre_hash = .{ .xof = pq.shake256 } },
};

fn strength(algorithm: pq.SignatureAlgorithm) usize {
    if (std.mem.eql(u8, algorithm.name, "ML-DSA-44")) return 128;

    if (std.mem.eql(u8, algorithm.name, "ML-DSA-65")) return 192;

    if (std.mem.eql(u8, algorithm.name, "ML-DSA-87")) return 256;

    return 4 * algorithm.public_key_size;
}

test "robustness: verification takes any signature, message, context and pre-hash" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    var rng: Random = .{ .state = 6 };

    for (signatures) |algorithm| {
        if (!selected(algorithm)) continue;

        const size = algorithm.signature_size;

        const real = isMlDsa(algorithm);

        var public_key: pq.SignaturePublicKey = undefined;

        var message: []const u8 = "";

        var signature: []u8 = try allocator.alloc(u8, size);

        @memset(signature, 0);

        // SLH-DSA keys are expensive to make, so verification gets a public key of the right
        // size, which is all that it checks, and an all-zero signature.
        // The public key outlives the private key, which it was taken from.
        if (real) {
            var pair = try hazmat.generateSignatureKeyPair(algorithm, testing.allocator, try pattern(allocator, 32, 0));

            defer pair.private_key.deinit();

            public_key = pair.public_key;

            message = "crypto-pq robustness";

            signature = try hazmat.sign(&pair.private_key, allocator, message, try pattern(allocator, 32, 0x60), .{ .context = "context" });
        } else {
            public_key = try algorithm.importPublicKey(testing.allocator, try pattern(allocator, algorithm.public_key_size, 0x20), .raw);
        }

        defer public_key.deinit();

        var scratch = std.heap.ArenaAllocator.init(testing.allocator);

        defer scratch.deinit();

        const temporary = scratch.allocator();

        for (0..(if (real) @as(usize, 60) else 6) * scale()) |_| {
            var candidate: []u8 = undefined;

            if (rng.below(8) != 0) {
                candidate = signature;

                for (0..1 + rng.below(2)) |_| candidate = try mutate(&rng, temporary, candidate, &.{});
            } else {
                candidate = try rng.bytes(temporary, rng.below(size + 2));
            }

            if (rng.below(2) == 1) {
                const exact = try temporary.alloc(u8, size);

                @memset(exact, 0);

                @memcpy(exact[0..@min(size, candidate.len)], candidate[0..@min(size, candidate.len)]);

                candidate = exact;
            }

            const text = if (rng.below(2) == 1) try mutate(&rng, temporary, message, &.{}) else message;

            const random_context = try rng.bytes(temporary, rng.below(300));

            const contexts = [_][]const u8{ "context", "", random_context, &([_]u8{0} ** 255), &([_]u8{0} ** 256) };

            const context = contexts[rng.below(contexts.len)];

            const choice = rng.below(pre_hashes.len + 1);

            const pre_hash: ?pq.PreHash = if (choice < pre_hashes.len) pre_hashes[choice].pre_hash else null;

            const policy = rng.below(4) != 0;

            const options: pq.VerifyOptions = .{ .context = context, .pre_hash = pre_hash };

            const valid = if (policy) public_key.verify(candidate, text, options) else hazmat.verify(&public_key, candidate, text, options);

            const weak = policy and choice < pre_hashes.len and pre_hashes[choice].strength < strength(algorithm);

            if (valid) {
                try testing.expect(!weak and context.len <= 255 and candidate.len == size);

                try testing.expect(real and std.mem.eql(u8, candidate, signature) and std.mem.eql(u8, text, message) and std.mem.eql(u8, context, "context") and pre_hash == null);
            }

            _ = scratch.reset(.retain_capacity);
        }

        const fake: pq.PreHash = .{ .hash = .{ .name = "SHA-256", .digest_size = 99, .kind = pq.sha_512.kind } };

        try testing.expect(!public_key.verify(signature, message, .{ .pre_hash = fake }));
    }
}

const MemoryStore = struct {
    state: ?[]u8 = null,
    lock: std.atomic.Value(bool) = .init(false),

    const vtable: pq.StateStore.VTable = .{ .read = read, .update = update };

    fn holding(state: []const u8) !MemoryStore {
        return .{ .state = try testing.allocator.dupe(u8, state) };
    }

    fn deinit(self: *MemoryStore) void {
        if (self.state) |state| testing.allocator.free(state);
    }

    fn store(self: *MemoryStore) pq.StateStore {
        return .{ .ptr = self, .vtable = &vtable };
    }

    // A spin lock, so that threads can share the store; std's locks need an Io in Zig 0.16.
    fn acquire(self: *MemoryStore) void {
        while (self.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
    }

    fn release(self: *MemoryStore) void {
        self.lock.store(false, .release);
    }

    fn read(ptr: *anyopaque, allocator: Allocator) anyerror!?[]u8 {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));

        self.acquire();

        defer self.release();

        const state = self.state orelse return null;

        return try allocator.dupe(u8, state);
    }

    fn update(ptr: *anyopaque, previous: ?[]const u8, next: []const u8) anyerror!bool {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));

        self.acquire();

        defer self.release();

        const same = if (self.state) |state| previous != null and std.mem.eql(u8, state, previous.?) else previous == null;

        if (!same) return false;

        const copy = try testing.allocator.dupe(u8, next);

        if (self.state) |state| testing.allocator.free(state);

        self.state = copy;

        return true;
    }
};

test "robustness: stateful verification takes any signature and public key" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    var rng: Random = .{ .state = 7 };

    const levels = [_]pq.HssLevel{ .{ .lms = "LMS_SHAKE_M24_H5", .ots = "LMOTS_SHAKE_N24_W2" }, .{ .lms = "LMS_SHAKE_M24_H5", .ots = "LMOTS_SHAKE_N24_W1" } };

    var hss_store: MemoryStore = .{};

    defer hss_store.deinit();

    var hss = try hazmat.generateStatefulKeyPair(pq.hss_lms, testing.allocator, .{ .levels = &levels }, try pattern(allocator, 40, 0), 33, hss_store.store(), .{});

    defer hss.private_key.deinit(testing.allocator);

    var mt_store: MemoryStore = .{};

    defer mt_store.deinit();

    var mt = try hazmat.generateStatefulKeyPair(pq.xmss_mt, testing.allocator, .{ .name = "XMSSMT-SHA2_20/4_192" }, try pattern(allocator, 72, 0), 7, mt_store.store(), .{});

    defer mt.private_key.deinit(testing.allocator);

    const message = "crypto-pq robustness";

    const xmss_signature = try allocator.alloc(u8, 4 + 24 + (51 + 10) * 24);

    @memset(xmss_signature, 0);

    const cases = [_]struct { algorithm: pq.StatefulSignatureAlgorithm, raw: []const u8, signature: []const u8 }{
        .{ .algorithm = pq.hss_lms, .raw = try hss.public_key.exportKey(allocator, .raw), .signature = try hss.private_key.sign(allocator, message) },
        .{ .algorithm = pq.xmss_mt, .raw = try mt.public_key.exportKey(allocator, .raw), .signature = try mt.private_key.sign(allocator, message) },
        .{ .algorithm = pq.xmss, .raw = try std.mem.concat(allocator, u8, &.{ &.{ 0, 0, 0, 0x0d }, try pattern(allocator, 48, 0) }), .signature = xmss_signature },
    };

    var scratch = std.heap.ArenaAllocator.init(testing.allocator);

    defer scratch.deinit();

    const temporary = scratch.allocator();

    for (cases) |case| {
        const public_key = try case.algorithm.importPublicKey(case.raw, .raw);

        for (0..60 * scale()) |_| {
            const candidate = if (rng.below(8) != 0) try mutate(&rng, temporary, case.signature, &.{}) else try rng.bytes(temporary, rng.below(case.signature.len + 2));

            const text = if (rng.below(2) == 1) try mutate(&rng, temporary, message, &.{}) else message;

            if (public_key.verify(candidate, text)) {
                try testing.expect(std.mem.eql(u8, candidate, case.signature) and std.mem.eql(u8, text, message));
            }

            _ = scratch.reset(.retain_capacity);
        }
    }

    const algorithms = [_]pq.StatefulSignatureAlgorithm{ pq.hss_lms, pq.xmss, pq.xmss_mt };

    for (0..300 * scale()) |_| {
        const algorithm = algorithms[rng.below(algorithms.len)];

        const raw = try mutate(&rng, temporary, cases[rng.below(cases.len)].raw, &.{});

        const public_key = algorithm.importPublicKey(raw, .raw) catch |err| {
            try expectCode(err, &.{error.InvalidPublicKey}, algorithm.name, raw);

            continue;
        };

        _ = public_key.verify(try rng.bytes(temporary, rng.below(4096)), "");

        _ = scratch.reset(.retain_capacity);
    }
}

test "robustness: decapsulation takes any ciphertext" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    var rng: Random = .{ .state = 8 };

    for (kems) |algorithm| {
        const sizes = kemSizes(algorithm);

        var pair = try hazmat.generateKemKeyPair(algorithm, testing.allocator, try pattern(allocator, sizes[0], 0));

        defer pair.private_key.deinit();

        defer pair.public_key.deinit();

        const encapsulation = try hazmat.encapsulate(&pair.public_key, try pattern(allocator, sizes[1], 0x80));

        const size = algorithm.ciphertext_size;

        for (0..60 * scale()) |_| {
            var candidate = if (rng.below(8) != 0) try mutate(&rng, allocator, encapsulation.ciphertext(), &.{}) else try rng.bytes(allocator, rng.below(size + 2));

            if (rng.below(2) == 1) {
                const exact = try allocator.alloc(u8, size);

                @memset(exact, 0);

                @memcpy(exact[0..@min(size, candidate.len)], candidate[0..@min(size, candidate.len)]);

                candidate = exact;
            }

            const secret = pair.private_key.decapsulate(candidate) catch |err| {
                try testing.expect(err == error.InvalidLength and candidate.len != size);

                continue;
            };

            try testing.expectEqual(size, candidate.len);

            // Implicit rejection: any other ciphertext gives a different secret.
            try testing.expectEqual(std.mem.eql(u8, candidate, encapsulation.ciphertext()), std.mem.eql(u8, &secret, &encapsulation.shared_secret));
        }
    }
}

const xmss_heights = [_]u32{ 10, 16, 20 };

const lms_heights = [_]u32{ 5, 10, 15, 20, 25 };

const ots_widths = [_]u6{ 1, 2, 4, 8 };

const xmss_shapes = [_][2]u32{ .{ 20, 2 }, .{ 20, 4 }, .{ 40, 2 }, .{ 40, 4 }, .{ 40, 8 }, .{ 60, 3 }, .{ 60, 6 }, .{ 60, 12 } };

const Expected = struct { index: u64, capacity: u64, cost: u64 };

// What loading a state blob must give, from the format rules alone: the error, or the index, the
// capacity and the number of hash calls that building the key's trees takes.
fn expectedState(algorithm: pq.StatefulSignatureAlgorithm, state: []const u8) pq.Error!Expected {
    if (state.len < 18) return error.InvalidPrivateKey;

    const full = state[0 .. state.len - 16];

    var checksum: [32]u8 = undefined;

    pq.sha_256.digest(full, &checksum);

    if (!std.mem.eql(u8, checksum[0..16], state[state.len - 16 ..]) or full[0] != 1) return error.InvalidPrivateKey;

    const kind: u8 = if (std.mem.eql(u8, algorithm.name, "HSS/LMS")) 1 else if (std.mem.eql(u8, algorithm.name, "XMSS")) 2 else 3;

    if (full[1] != kind) return error.AlgorithmMismatch;

    const body = full[2..];

    if (kind != 1) {
        if (body.len < 4) return error.InvalidPrivateKey;

        const oid = std.mem.readInt(u32, body[0..4], .big);

        const bases: [4]u32 = if (kind == 3) .{ 0x01, 0x21, 0x29, 0x31 } else .{ 0x01, 0x0d, 0x10, 0x13 };

        for (bases, [_]u64{ 32, 24, 32, 24 }) |base, n| {
            if (oid < base or oid - base >= (if (kind == 3) @as(u32, 8) else 3)) continue;

            const shape: [2]u32 = if (kind == 3) xmss_shapes[oid - base] else .{ xmss_heights[oid - base], 1 };

            const h = shape[0];

            const d = shape[1];

            if (body.len != 12 + 3 * n) return error.InvalidPrivateKey;

            return .{ .index = std.mem.readInt(u64, body[4..12], .big), .capacity = @as(u64, 1) << @intCast(h), .cost = (@as(u64, d) << @intCast(h / d)) * (2 * n + 3) * 16 };
        }

        return error.InvalidPrivateKey;
    }

    const count: usize = if (body.len > 0) body[0] else 0;

    if (body.len < 1 + 8 * count or count < 1 or count > 8) return error.InvalidPrivateKey;

    var m: u64 = 0;

    var family: u32 = 0;

    var height: u32 = 0;

    var cost: u64 = 0;

    for (0..count) |i| {
        const lms = std.mem.readInt(u32, body[1 + 8 * i ..][0..4], .big);

        const ots = std.mem.readInt(u32, body[5 + 8 * i ..][0..4], .big);

        if (lms < 5 or lms > 24 or ots < 1 or ots > 16) return error.InvalidPrivateKey;

        const lms_family = (lms - 5) / 5;

        const ots_family = (ots - 1) / 4;

        const n: u64 = if (lms_family % 2 == 0) 32 else 24;

        if (i == 0) {
            m = n;

            family = lms_family;
        }

        if (lms_family != family or ots_family != family) return error.InvalidPrivateKey;

        const h = lms_heights[(lms - 5) % 5];

        const w = ots_widths[(ots - 1) % 4];

        const u = (8 * n + w - 1) / w;

        const v = (64 - @clz(((@as(u64, 1) << w) - 1) * u) + w - 1) / w;

        height += h;

        cost += (u + v) << @intCast(h + w);
    }

    if (height > 60) return error.InvalidPrivateKey;

    const rest = body[1 + 8 * count ..];

    const seed_size: usize = @intCast(16 + m);

    if (rest.len != seed_size + 8) return error.InvalidPrivateKey;

    return .{ .index = std.mem.readInt(u64, rest[seed_size..][0..8], .big), .capacity = @as(u64, 1) << @intCast(height), .cost = cost };
}

fn sealed(allocator: Allocator, body: []const u8) ![]u8 {
    var checksum: [32]u8 = undefined;

    pq.sha_256.digest(body, &checksum);

    return std.mem.concat(allocator, u8, &.{ body, checksum[0..16] });
}

// Random edits of a state blob, mostly resealed so that they reach the parser behind the
// checksum: level counts, type codes, indices at and beyond the capacity, and byte edits.
fn mutateState(rng: *Random, allocator: Allocator, state: []const u8) ![]u8 {
    var body = try allocator.dupe(u8, state[0 .. state.len - 16]);

    const index_offset = if (state[1] == 1 and state.len >= 24) state.len - 24 else 6;

    const operation = rng.below(6);

    if (operation == 0 and body.len > 2) {
        const counts = [_]u8{ 0, 1, 2, 3, 8, 9, 0x80, 0xff };

        body[2] = counts[rng.below(counts.len)];
    } else if (operation == 1 and body.len > 6) {
        const offset = if (body[1] == 1) 3 + 8 * rng.below(@max(1, body[2])) + 4 * rng.below(2) else 2;

        const values = [_]u32{ @intCast(rng.below(48)), @truncate(rng.next()), 0 };

        const value = values[rng.below(values.len)];

        if (offset + 4 <= body.len) std.mem.writeInt(u32, body[offset..][0..4], value, .big);
    } else if (operation == 2 and body.len >= index_offset + 8) {
        const heights = [_]u7{ 5, 10, 20, 40, 60, 64 };

        const height = heights[rng.below(heights.len)];

        const top: u64 = if (height == 64) 0 else @as(u64, 1) << @intCast(height);

        const values = [_]u64{ 0, 1, top -% 1, top, top +% 1, std.math.maxInt(u64) };

        std.mem.writeInt(u64, body[index_offset..][0..8], values[rng.below(values.len)], .big);
    } else {
        body = try mutate(rng, allocator, body, &.{});
    }

    if (rng.below(4) != 0) return sealed(allocator, body);

    return std.mem.concat(allocator, u8, &.{ body, state[state.len - 16 ..] });
}

fn storedState(allocator: Allocator, algorithm: pq.StatefulSignatureAlgorithm, parameters: pq.StatefulParameters, seed: []const u8, index: u64) ![]u8 {
    var store: MemoryStore = .{};

    defer store.deinit();

    var pair = try hazmat.generateStatefulKeyPair(algorithm, testing.allocator, parameters, seed, index, store.store(), .{});

    pair.private_key.deinit(testing.allocator);

    return allocator.dupe(u8, store.state.?);
}

fn checkState(allocator: Allocator, algorithm: pq.StatefulSignatureAlgorithm, state: []const u8, budget: u64) !void {
    const expected = expectedState(algorithm, state) catch |code| {
        var store = try MemoryStore.holding(state);

        defer store.deinit();

        if (algorithm.loadPrivateKey(testing.allocator, store.store(), .{})) |loaded| {
            var key = loaded;

            key.deinit(testing.allocator);

            std.debug.print("{s} loaded {x}\n", .{ algorithm.name, state });

            return error.TestUnexpectedResult;
        } else |err| {
            try expectCode(err, &.{code}, algorithm.name, state);
        }

        return;
    };

    var store = try MemoryStore.holding(state);

    defer store.deinit();

    if (expected.index > expected.capacity) {
        try testing.expectError(error.InvalidPrivateKey, algorithm.loadPrivateKey(testing.allocator, store.store(), .{}));

        return;
    }

    if (expected.cost > budget) return;

    var key = try algorithm.loadPrivateKey(testing.allocator, store.store(), .{});

    defer key.deinit(testing.allocator);

    try testing.expectEqual(expected.capacity - expected.index, key.remainingSignatures());

    if (expected.index == expected.capacity) {
        try testing.expectError(error.KeyExhausted, key.sign(allocator, "m"));

        return;
    }

    const signature = try key.sign(allocator, "m");

    const public_key = key.publicKey();

    try testing.expect(public_key.verify(signature, "m"));

    const next = try allocator.dupe(u8, state[0 .. state.len - 16]);

    std.mem.writeInt(u64, next[if (state[1] == 1) next.len - 8 else 6..][0..8], expected.index + 1, .big);

    try testing.expectEqualSlices(u8, try sealed(allocator, next), store.state.?);
}

// Debug builds hash about ten times slower, so they build smaller trees.
const state_budget: u64 = if (builtin.mode == .Debug) 1 << 15 else 1 << 18;

test "robustness: state loading takes any blob" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    var rng: Random = .{ .state = 9 };

    const seed = try pattern(allocator, 96, 0);

    const levels_1 = [_]pq.HssLevel{.{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W1" }};

    const levels_2 = [_]pq.HssLevel{ .{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W4" }, .{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W1" } };

    const seeds = [_][]const u8{
        try storedState(allocator, pq.hss_lms, .{ .levels = &levels_1 }, seed[0..40], 3),
        try storedState(allocator, pq.hss_lms, .{ .levels = &levels_2 }, seed[0..40], 3),
        try storedState(allocator, pq.xmss, .{ .name = "XMSS-SHA2_10_256" }, seed[0..96], 3),
        try storedState(allocator, pq.xmss_mt, .{ .name = "XMSSMT-SHAKE256_20/4_192" }, seed[0..72], 3),
    };

    const algorithms = [_]pq.StatefulSignatureAlgorithm{ pq.hss_lms, pq.xmss, pq.xmss_mt };

    var scratch = std.heap.ArenaAllocator.init(testing.allocator);

    defer scratch.deinit();

    for (0..300 * scale()) |_| {
        var state: []const u8 = seeds[rng.below(seeds.len)];

        for (0..1 + rng.below(2)) |_| {
            state = if (state.len >= 18) try mutateState(&rng, scratch.allocator(), state) else try rng.bytes(scratch.allocator(), rng.below(160));
        }

        // Mostly the algorithm the blob names, so that more blobs get past the kind check.
        const named = state.len > 1 and state[1] >= 1 and state[1] <= 3;

        const algorithm = if (named and rng.below(4) != 0) algorithms[state[1] - 1] else algorithms[rng.below(algorithms.len)];

        try checkState(scratch.allocator(), algorithm, state, state_budget);

        _ = scratch.reset(.retain_capacity);
    }
}

test "robustness: state blobs that claim many levels or indices are refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const levels = [_]pq.HssLevel{.{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W1" }};

    const state = try storedState(allocator, pq.hss_lms, .{ .levels = &levels }, &([_]u8{0} ** 40), 0);

    const body = state[0 .. state.len - 16];

    for ([_]u8{ 0, 2, 9, 0xff }) |count| {
        const claimed = try allocator.dupe(u8, body);

        claimed[2] = count;

        try expectRefused(allocator, pq.hss_lms, claimed);

        if (count != 2) {
            var padded: std.ArrayList(u8) = .empty;

            try padded.appendSlice(allocator, claimed[0..3]);

            for (0..count) |_| try padded.appendSlice(allocator, &.{ 0, 0, 0, 10, 0, 0, 0, 5 });

            try padded.appendSlice(allocator, claimed[11..]);

            try expectRefused(allocator, pq.hss_lms, padded.items);
        }
    }

    var tall: std.ArrayList(u8) = .empty;

    try tall.appendSlice(allocator, &.{ 1, 1, 3 });

    for (0..3) |_| try tall.appendSlice(allocator, &.{ 0, 0, 0, 14, 0, 0, 0, 5 });

    try tall.appendSlice(allocator, &([_]u8{0} ** 48));

    try expectRefused(allocator, pq.hss_lms, tall.items);

    for ([_]u64{ 33, std.math.maxInt(u64) }) |index| {
        const beyond = try allocator.dupe(u8, body);

        std.mem.writeInt(u64, beyond[beyond.len - 8 ..][0..8], index, .big);

        try expectRefused(allocator, pq.hss_lms, beyond);
    }

    const mt = try storedState(allocator, pq.xmss_mt, .{ .name = "XMSSMT-SHA2_60/12_256" }, &([_]u8{0} ** 96), 0);

    for ([_]u64{ (1 << 60) + 1, std.math.maxInt(u64) }) |index| {
        const beyond = try allocator.dupe(u8, mt[0 .. mt.len - 16]);

        std.mem.writeInt(u64, beyond[6..14], index, .big);

        try expectRefused(allocator, pq.xmss_mt, beyond);
    }
}

fn expectRefused(allocator: Allocator, algorithm: pq.StatefulSignatureAlgorithm, body: []const u8) !void {
    var store = try MemoryStore.holding(try sealed(allocator, body));

    defer store.deinit();

    try testing.expectError(error.InvalidPrivateKey, algorithm.loadPrivateKey(testing.allocator, store.store(), .{}));
}

// ReleaseSafe keeps the safety checks and runs these in seconds; a Debug build takes far longer,
// so there they wait for CRYPTO_PQ_SLOW=1.
fn largeInputs() bool {
    return builtin.mode != .Debug or vectors.slow();
}

fn largeMessage(allocator: Allocator) ![]u8 {
    const message = try allocator.alloc(u8, 16 << 20);

    for (message, 0..) |*byte, i| byte.* = @intCast(i % 251);

    return message;
}

// The digests of the message whose byte i is i mod 251, from an independent implementation.
const digests = [_]struct { algorithm: pq.HashAlgorithm, hex: []const u8 }{
    .{ .algorithm = pq.sha_224, .hex = "81e763ef9866bdefa03f5c58819e12ba2bc7dd6913eb36e8ec666036" },
    .{ .algorithm = pq.sha_256, .hex = "287507f403176f1f5b22b9a4d9cb49f7d7f88ac19e406b5ae87ce109564846bd" },
    .{ .algorithm = pq.sha_384, .hex = "4bc9798cec40d12e4f7198b89e0a5d4b7e7474ec255f3280b126bd3bc141103ca9a906d12fa05c0c5eb50f2bef840908" },
    .{ .algorithm = pq.sha_512, .hex = "ef9941360046598bd9a89eb56a4440e46255bfa79529f9d3a8813aa899d5c64d8cc75f0c023b8d82ec41cc60ae69d311a80fb9ad372bf3d149574a87bc195c08" },
    .{ .algorithm = pq.sha_512_224, .hex = "181650285d94081ca60b6dad6cb501607c0b47b793d95f4b3fe703ef" },
    .{ .algorithm = pq.sha_512_256, .hex = "61fb65258a2a6ca095a709e2d1026483ef0d5dab44e374f55599d867e0d5d2f9" },
    .{ .algorithm = pq.sha3_224, .hex = "3e121e54d1b7d67d8a6489426c33d7a5078089e9f7ff736786fc2cf3" },
    .{ .algorithm = pq.sha3_256, .hex = "acade24d564f1dae78e26ca4615bc8061dda3835de1bb7afde3ef0d32a931191" },
    .{ .algorithm = pq.sha3_384, .hex = "4934100bb50d9a97d1463c521a58ca562a59e07b6753076e45a824d8545df2358c346274ad7809ffeaac2e56a9cef7fb" },
    .{ .algorithm = pq.sha3_512, .hex = "314cd6d2e1cc05dfc4c8429541a2877becd82e9def2333f26a4eb7f72cffe758289f9185ddae4bb5017ad7019933404f241787ac650e505530f2973d3233a88d" },
};

test "robustness: 16 MiB messages hash as an independent implementation does" {
    if (!largeInputs()) return error.SkipZigTest;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const message = try largeMessage(allocator);

    for (digests) |entry| {
        var digest: [64]u8 = undefined;

        const out = digest[0..entry.algorithm.digest_size];

        entry.algorithm.digest(message, out);

        try testing.expectEqualSlices(u8, try vectors.decode(allocator, entry.hex), out);

        var hasher = entry.algorithm.create();

        var offset: usize = 0;

        while (offset < message.len) : (offset += 1_000_003) hasher.update(message[offset..@min(message.len, offset + 1_000_003)]);

        hasher.digest(out);

        try testing.expectEqualSlices(u8, try vectors.decode(allocator, entry.hex), out);
    }

    var shake128: [32]u8 = undefined;

    pq.shake128.digest(message, &shake128);

    try testing.expectEqualSlices(u8, try vectors.decode(allocator, "8a38dce3e6592d50867536f5f352abd74e486bdbfe48c43b8372d55e6547110a"), &shake128);

    var shake256: [64]u8 = undefined;

    pq.shake256.digest(message, &shake256);

    try testing.expectEqualSlices(u8, try vectors.decode(allocator, "525fa10737fa7538afe5df929cfadb606e52a2b2e2f0e4c5626510e720319b7366c387167707535aa23a5d027a155150fe5c73c329f2113d1220a8d9d7b9a5e3"), &shake256);

    var tag: [32]u8 = undefined;

    pq.hmac_sha_256.digest(try pattern(allocator, 32, 0), message, &tag);

    try testing.expectEqualSlices(u8, try vectors.decode(allocator, "e9fb7e5b1f5d2702eba341df5e51ec9e4ed48db395f66dff93e30808b88f0750"), &tag);
}

test "robustness: 16 MiB and empty messages sign and verify; contexts stop at 255 bytes" {
    if (!largeInputs()) return error.SkipZigTest;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const message = try largeMessage(allocator);

    const changed = try allocator.dupe(u8, message);

    changed[changed.len - 1] ^= 1;

    const longest = try pattern(allocator, 255, 0);

    for ([_]pq.SignatureAlgorithm{ pq.ml_dsa_44, pq.slh_dsa_sha2_128f }) |algorithm| {
        var pair = try hazmat.generateSignatureKeyPair(algorithm, testing.allocator, try pattern(allocator, signatureSeedSize(algorithm), 0));

        defer pair.private_key.deinit();

        defer pair.public_key.deinit();

        const cases = [_]struct { text: []const u8, context: []const u8, pre_hash: ?pq.PreHash }{
            .{ .text = message, .context = "", .pre_hash = null },
            .{ .text = "", .context = &([_]u8{0} ** 255), .pre_hash = null },
            .{ .text = message, .context = longest, .pre_hash = .{ .hash = pq.sha_512 } },
            .{ .text = "", .context = "", .pre_hash = .{ .xof = pq.shake256 } },
        };

        for (cases) |case| {
            const signature = try pair.private_key.sign(allocator, case.text, .{ .context = case.context, .deterministic = true, .pre_hash = case.pre_hash });

            const options: pq.VerifyOptions = .{ .context = case.context, .pre_hash = case.pre_hash };

            try testing.expect(pair.public_key.verify(signature, case.text, options));

            try testing.expect(!pair.public_key.verify(signature, if (case.text.len > 0) changed else "\x00", options));

            const longer = try std.mem.concat(allocator, u8, &.{ case.context, "\x00" });

            try testing.expect(!pair.public_key.verify(signature, case.text, .{ .context = longer, .pre_hash = case.pre_hash }));
        }

        try testing.expectError(error.InvalidContext, pair.private_key.sign(allocator, "", .{ .context = &([_]u8{0} ** 256) }));
    }

    const levels = [_]pq.HssLevel{.{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W1" }};

    var hss_store: MemoryStore = .{};

    defer hss_store.deinit();

    var hss = try pq.hss_lms.generateKeyPair(testing.allocator, .{ .levels = &levels }, hss_store.store(), .{});

    defer hss.private_key.deinit(testing.allocator);

    var mt_store: MemoryStore = .{};

    defer mt_store.deinit();

    var mt = try pq.xmss_mt.generateKeyPair(testing.allocator, .{ .name = "XMSSMT-SHA2_20/4_192" }, mt_store.store(), .{});

    defer mt.private_key.deinit(testing.allocator);

    for ([_][]const u8{ message, "" }) |text| {
        const other: []const u8 = if (text.len > 0) changed else "\x00";

        const hss_signature = try hss.private_key.sign(allocator, text);

        try testing.expect(hss.public_key.verify(hss_signature, text) and !hss.public_key.verify(hss_signature, other));

        const mt_signature = try mt.private_key.sign(allocator, text);

        try testing.expect(mt.public_key.verify(mt_signature, text) and !mt.public_key.verify(mt_signature, other));
    }
}

fn base64(allocator: Allocator, data: []const u8) ![]u8 {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    var out: std.ArrayList(u8) = .empty;

    var offset: usize = 0;

    while (offset < data.len) : (offset += 3) {
        const chunk = data[offset..@min(data.len, offset + 3)];

        var value: u32 = 0;

        for (chunk, 0..) |byte, i| value |= @as(u32, byte) << @intCast(16 - 8 * i);

        for (0..4) |i| try out.append(allocator, if (i <= chunk.len) alphabet[(value >> @intCast(18 - 6 * i)) & 0x3f] else '=');
    }

    return out.toOwnedSlice(allocator);
}

test "robustness: PEM with very long lines or huge bodies" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    // The header and the footer share their dashes, leaving no body between them.
    try testing.expectError(error.InvalidEncoding, pq.ml_kem_768.importPublicKey(testing.allocator, "-----BEGIN PUBLIC KEY-----END PUBLIC KEY-----", .pem));

    // The last base64 quantum of an ML-DSA-44 key carries two unused bits, which must be zero.
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    var dsa = try hazmat.generateSignatureKeyPair(pq.ml_dsa_44, testing.allocator, try pattern(allocator, 32, 0));

    defer dsa.private_key.deinit();

    defer dsa.public_key.deinit();

    const flipped = try dsa.public_key.exportKey(allocator, .pem);

    const last = std.mem.findScalarLast(u8, flipped, '=').? - 1;

    flipped[last] = alphabet[std.mem.findScalar(u8, alphabet, flipped[last]).? ^ 1];

    try testing.expectError(error.InvalidEncoding, pq.ml_dsa_44.importPublicKey(testing.allocator, flipped, .pem));

    try testing.expectError(error.InvalidEncoding, pq.ml_dsa_44.importPrivateKey(testing.allocator, "-----BEGIN PRIVATE KEY-----END PRIVATE KEY-----", .pem));

    var pair = try hazmat.generateKemKeyPair(pq.ml_kem_768, testing.allocator, try pattern(allocator, 64, 0));

    defer pair.private_key.deinit();

    defer pair.public_key.deinit();

    const body = try base64(allocator, try pair.public_key.exportKey(allocator, .der));

    var narrow: std.ArrayList(u8) = .empty;

    try narrow.appendSlice(allocator, "-----BEGIN PUBLIC KEY-----\n");

    for (body) |character| try narrow.appendSlice(allocator, &.{ character, '\n' });

    try narrow.appendSlice(allocator, "-----END PUBLIC KEY-----\n");

    var from_narrow = try pq.ml_kem_768.importPublicKey(testing.allocator, narrow.items, .pem);

    defer from_narrow.deinit();

    try testing.expect(from_narrow.eql(&pair.public_key));

    const wide = try std.mem.concat(allocator, u8, &.{ "-----BEGIN PUBLIC KEY-----", body, "-----END PUBLIC KEY-----" });

    var from_wide = try pq.ml_kem_768.importPublicKey(testing.allocator, wide, .pem);

    defer from_wide.deinit();

    try testing.expect(from_wide.eql(&pair.public_key));

    const zeros = try allocator.alloc(u8, 4 << 20);

    @memset(zeros, 0);

    const huge = try base64(allocator, try std.mem.concat(allocator, u8, &.{ &.{ 0x30, 0x84, 0x00, 0xff, 0xff, 0xff }, zeros }));

    for ([_][]const u8{ huge, huge[0 .. huge.len - 1] }) |text| {
        const pem = try std.mem.concat(allocator, u8, &.{ "-----BEGIN PUBLIC KEY-----\n", text, "\n-----END PUBLIC KEY-----\n" });

        try testing.expectError(error.InvalidEncoding, pq.ml_kem_768.importPublicKey(testing.allocator, pem, .pem));
    }
}

// A length field that claims gigabytes is refused, and so are one with a needless leading zero
// byte and a PKCS#8 version above 1; import never allocates, so nothing can be sized from a
// claimed length.
test "robustness: DER lengths that claim gigabytes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    var pair = try hazmat.generateSignatureKeyPair(pq.ml_dsa_65, testing.allocator, try pattern(allocator, 32, 0));

    defer pair.private_key.deinit();

    defer pair.public_key.deinit();

    const public = try pair.public_key.exportKey(allocator, .der);

    const private = try pair.private_key.exportKey(allocator, .der);

    const cases = [_][]const u8{
        try std.mem.concat(allocator, u8, &.{ &.{ 0x30, 0x84, 0xff, 0xff, 0xff, 0xff }, public[4..] }),
        try std.mem.concat(allocator, u8, &.{ &.{ 0x30, 0x84, 0x7f, 0xff, 0xff, 0xff }, public[4..] }),
        try std.mem.concat(allocator, u8, &.{ public[0..4], &.{ 0x30, 0x84, 0xff, 0xff, 0xff, 0xf0 }, public[6..] }),
        try std.mem.concat(allocator, u8, &.{ public[0..17], &.{ 0x03, 0x84, 0xff, 0xff, 0xff, 0xff }, public[21..] }),
        try std.mem.concat(allocator, u8, &.{ private[0..2], &.{ 0x02, 0x84, 0xff, 0xff, 0xff, 0xff, 0x00 } }),
        try std.mem.concat(allocator, u8, &.{ private[0..20], &.{ 0x04, 0x84, 0x40, 0x00, 0x00, 0x00 }, private[22..] }),
        try std.mem.concat(allocator, u8, &.{ &.{ 0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00 }, public[4..] }),
        try std.mem.concat(allocator, u8, &.{ &.{ 0x30, 0x80 }, public[4..], &.{ 0, 0 } }),
        try std.mem.concat(allocator, u8, &.{ &.{ 0x30, 0x83, 0x00, 0x07, 0xb2 }, public[4..] }),
        try std.mem.concat(allocator, u8, &.{ &.{ 0x30, 0x82, 0x07, 0xb3 }, public[4..17], &.{ 0x03, 0x83, 0x00, 0x07, 0xa1 }, public[21..] }),
        try std.mem.concat(allocator, u8, &.{ private[0..4], &.{2}, private[5..] }),
    };

    for (cases) |data| {
        try testing.expectError(error.InvalidEncoding, pq.ml_dsa_65.importPublicKey(testing.allocator, data, .der));

        try testing.expectError(error.InvalidEncoding, pq.ml_dsa_65.importPrivateKey(testing.allocator, data, .der));

        const pem = try std.mem.concat(allocator, u8, &.{ "-----BEGIN PUBLIC KEY-----\n", try base64(allocator, data), "\n-----END PUBLIC KEY-----\n" });

        try testing.expectError(error.InvalidEncoding, pq.ml_dsa_65.importPublicKey(testing.allocator, pem, .pem));
    }
}

const small_levels = [_]pq.HssLevel{.{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W1" }};

const SharedSigning = struct {
    key: *pq.StatefulPrivateKey,
    used: [32]std.atomic.Value(u32) = @splat(.init(0)),
    conflicts: std.atomic.Value(u32) = .init(0),
    failures: std.atomic.Value(u32) = .init(0),
    start: std.atomic.Value(bool) = .init(false),

    fn work(self: *SharedSigning) void {
        while (!self.start.load(.acquire)) std.atomic.spinLoopHint();

        for (0..8) |_| {
            const signature = self.key.sign(testing.allocator, "m") catch |err| {
                _ = (if (err == error.StateConflict or err == error.KeyExhausted) &self.conflicts else &self.failures).fetchAdd(1, .monotonic);

                continue;
            };

            defer testing.allocator.free(signature);

            _ = self.used[std.mem.readInt(u32, signature[4..8], .big)].fetchAdd(1, .monotonic);
        }
    }
};

// One key used by several threads at once: a call made while another is signing fails with
// StateConflict by design, and no index is ever used twice.
test "robustness: one key signing on several threads" {
    var store: MemoryStore = .{};

    defer store.deinit();

    var pair = try pq.hss_lms.generateKeyPair(testing.allocator, .{ .levels = &small_levels }, store.store(), .{});

    defer pair.private_key.deinit(testing.allocator);

    var shared: SharedSigning = .{ .key = &pair.private_key };

    var threads: [6]std.Thread = undefined;

    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, SharedSigning.work, .{&shared});

    shared.start.store(true, .release);

    for (threads) |thread| thread.join();

    var signed: u64 = 0;

    for (&shared.used) |*count| {
        try testing.expect(count.load(.monotonic) <= 1);

        signed += count.load(.monotonic);
    }

    try testing.expectEqual(0, shared.failures.load(.monotonic));

    try testing.expectEqual(32 - signed, pair.private_key.remainingSignatures());
}

const StoreSigning = struct {
    store: *MemoryStore,
    used: [32]std.atomic.Value(u32) = @splat(.init(0)),
    failures: std.atomic.Value(u32) = .init(0),
    start: std.atomic.Value(bool) = .init(false),

    fn work(self: *StoreSigning) void {
        self.run() catch {
            _ = self.failures.fetchAdd(1, .monotonic);
        };
    }

    // Loads its own key, signs until the key is exhausted and loads it again whenever another
    // thread has used the stored index.
    fn run(self: *StoreSigning) !void {
        var key = try pq.hss_lms.loadPrivateKey(testing.allocator, self.store.store(), .{});

        defer key.deinit(testing.allocator);

        while (!self.start.load(.acquire)) std.atomic.spinLoopHint();

        while (true) {
            const signature = key.sign(testing.allocator, "m") catch |err| switch (err) {
                error.KeyExhausted => return,
                error.StateConflict => {
                    key.deinit(testing.allocator);

                    key = try pq.hss_lms.loadPrivateKey(testing.allocator, self.store.store(), .{});

                    continue;
                },
                else => return err,
            };

            defer testing.allocator.free(signature);

            _ = self.used[std.mem.readInt(u32, signature[4..8], .big)].fetchAdd(1, .monotonic);
        }
    }
};

// Keys loaded from one store on several threads: the compare-and-swap lets one of them use each
// index; the others get StateConflict and load the key again.
test "robustness: keys sharing a store on several threads" {
    var store: MemoryStore = .{};

    defer store.deinit();

    var pair = try pq.hss_lms.generateKeyPair(testing.allocator, .{ .levels = &small_levels }, store.store(), .{});

    pair.private_key.deinit(testing.allocator);

    var shared: StoreSigning = .{ .store = &store };

    var threads: [6]std.Thread = undefined;

    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, StoreSigning.work, .{&shared});

    shared.start.store(true, .release);

    for (threads) |thread| thread.join();

    try testing.expectEqual(0, shared.failures.load(.monotonic));

    for (&shared.used) |*count| try testing.expectEqual(1, count.load(.monotonic));
}

// Every implementation runs these rounds on the same inputs, made by the same generator from
// byte-identical keys, and hashes each input with its outcome: an error code, true or false, or
// OK and the result. Equal digests mean that all five implementations accept, refuse and compute
// alike on untrusted input.
const transcript_rounds = 96;

const transcript_budget: u64 = 1 << 14;

const transcripts = [_][]const u8{
    "4d454f3aca564e383f51723ee3814f1fe105a61b1fd38c536e2ea675d78fabe7",
    "db3f28b7c8f7949f104d15d6de629e0dea7fca38f38c970d520278617dc99474",
    "aafe47ac9480c88402b7974385fac0547b2f4d611f36ec692ca2748e5dec949e",
    "ce9fd19a166b8a384fab4dafffed98c85dd9fb7f3e2ab789f33c832cda8b199d",
    "14d657260a5c207db5e73e9dbaac6d3458b0ba16e507f256bea8fac9fd0f2a0a",
    "19d93bae7a287d14492808654d0580f1043443ad3cf6710e043ea34c462b3307",
    "38a35f3547d4414788484ce0b4b836a27f72fba19931a9f3680cbcadd6d5d97a",
    "7b468ce2966d2edd458ed4a62183bf6d4c06e182509a7773c505a3cb2ae12e58",
    "b2ecff951172fdfdd464c3b4bed07055c3041b64d0c11dc6c9bc62eae7cc0b0e",
    "57986f97a5d291a67f8a875f558d59a535f2157155e13b83b364a6a1cca5dc7d",
    "b46878b67dab92d46731b18b1c63b71f24e7ec4cb53bca10ec36540ca1b4b054",
};

const Transcript = struct {
    hasher: pq.Hasher = pq.sha_256.create(),

    fn add(self: *Transcript, data: []const u8, selector: u8, code: []const u8, output: []const u8) void {
        for ([_][]const u8{ data, &.{selector}, code, output }) |part| {
            var length: [4]u8 = undefined;

            std.mem.writeInt(u32, &length, @intCast(part.len), .big);

            self.hasher.update(&length);

            self.hasher.update(part);
        }
    }

    fn hex(self: *const Transcript) [64]u8 {
        var digest: [32]u8 = undefined;

        self.hasher.digest(&digest);

        return std.fmt.bytesToHex(digest, .lower);
    }
};

fn codeOf(err: anyerror) []const u8 {
    return switch (err) {
        error.InvalidLength => "INVALID_LENGTH",
        error.InvalidEncoding => "INVALID_ENCODING",
        error.AlgorithmMismatch => "ALGORITHM_MISMATCH",
        error.InvalidPublicKey => "INVALID_PUBLIC_KEY",
        error.InvalidPrivateKey => "INVALID_PRIVATE_KEY",
        error.InvalidContext => "INVALID_CONTEXT",
        error.InvalidOption => "INVALID_OPTION",
        error.RngFailure => "RNG_FAILURE",
        error.SelfTestFailed => "SELF_TEST_FAILED",
        error.KeyExhausted => "KEY_EXHAUSTED",
        error.StatePersistFailed => "STATE_PERSIST_FAILED",
        error.StateConflict => "STATE_CONFLICT",
        error.Unsupported => "UNSUPPORTED",
        else => @errorName(err),
    };
}

// Random bytes, or the seed with up to three edits, so that some inputs stay valid.
fn edited(rng: *Random, allocator: Allocator, seed: []const u8, others: []const []const u8) ![]const u8 {
    if (rng.below(8) == 0) return rng.bytes(allocator, rng.below(96));

    var data = seed;

    for (0..rng.below(4)) |_| data = try mutate(rng, allocator, data, others);

    return data;
}

fn resized(rng: *Random, allocator: Allocator, data: []const u8, size: usize) ![]const u8 {
    if (rng.below(2) == 0) return data;

    const out = try allocator.alloc(u8, size);

    @memset(out, 0);

    @memcpy(out[0..@min(size, data.len)], data[0..@min(size, data.len)]);

    return out;
}

const Import = *const fn (Allocator, []const u8, pq.KeyFormat) anyerror![]u8;

fn importer(comptime algorithm: anytype, comptime private: bool) Import {
    return struct {
        fn run(allocator: Allocator, data: []const u8, format: pq.KeyFormat) anyerror![]u8 {
            if (private) {
                var key = try algorithm.importPrivateKey(allocator, data, format);

                defer key.deinit();

                return key.exportKey(allocator, .raw);
            }

            if (@TypeOf(algorithm) == pq.StatefulSignatureAlgorithm) {
                const key = try algorithm.importPublicKey(data, format);

                return key.exportKey(allocator, .raw);
            }

            var key = try algorithm.importPublicKey(allocator, data, format);

            defer key.deinit();

            return key.exportKey(allocator, .raw);
        }
    }.run;
}

const Seed = struct { encoding: []const u8, function: usize, format: usize };

fn importCase(rng: *Random, allocator: Allocator, transcript: *Transcript, seeds: []const Seed, imports: []const Import) !void {
    const others = try allocator.alloc([]const u8, seeds.len);

    for (seeds, others) |seed, *other| other.* = seed.encoding;

    for (0..transcript_rounds) |_| {
        const seed = seeds[rng.below(seeds.len)];

        const data = try edited(rng, allocator, seed.encoding, others);

        const format = if (rng.below(4) == 0) rng.below(3) else seed.format;

        const selector: u8 = @intCast(3 * seed.function + format);

        if (imports[seed.function](allocator, data, formats[format])) |raw| {
            transcript.add(data, selector, "OK", raw);
        } else |err| {
            transcript.add(data, selector, codeOf(err), "");
        }
    }
}

fn exportsOf(allocator: Allocator, key: anytype, function: usize) ![3]Seed {
    var out: [3]Seed = undefined;

    for (formats, 0..) |format, number| out[number] = .{ .encoding = try key.exportKey(allocator, format), .function = function, .format = number };

    return out;
}

const Verifier = struct {
    context: *const anyopaque,
    run: *const fn (*const anyopaque, []const u8, []const u8) bool,
};

fn signatureCase(rng: *Random, allocator: Allocator, transcript: *Transcript, signature: []const u8, verifier: Verifier) !void {
    for (0..transcript_rounds) |_| {
        const data = try resized(rng, allocator, try edited(rng, allocator, signature, &.{signature}), signature.len);

        const context: []const u8 = if (rng.below(2) == 0) "context" else "";

        transcript.add(data, @intCast(context.len), if (verifier.run(verifier.context, data, context)) "true" else "false", "");
    }
}

const message_text = "crypto-pq transcript";

fn verifyDsa(context: *const anyopaque, data: []const u8, ctx: []const u8) bool {
    const key: *const pq.SignaturePublicKey = @ptrCast(@alignCast(context));

    return key.verify(data, message_text, .{ .context = ctx });
}

fn verifyHss(context: *const anyopaque, data: []const u8, ctx: []const u8) bool {
    const key: *const pq.StatefulPublicKey = @ptrCast(@alignCast(context));

    var buffer: [64]u8 = undefined;

    @memcpy(buffer[0..message_text.len], message_text);

    @memcpy(buffer[message_text.len..][0..ctx.len], ctx);

    return key.verify(data, buffer[0 .. message_text.len + ctx.len]);
}

// Loading builds the key's trees, so a valid state of a key larger than the budget is only
// recorded as skipped.
fn stateCase(rng: *Random, allocator: Allocator, transcript: *Transcript, base: []const u8) !void {
    const algorithms = [_]pq.StatefulSignatureAlgorithm{ pq.hss_lms, pq.xmss, pq.xmss_mt };

    for (0..transcript_rounds) |_| {
        var state = base;

        for (0..1 + rng.below(2)) |_| {
            state = if (state.len >= 18) try mutateState(rng, allocator, state) else try rng.bytes(allocator, rng.below(160));
        }

        const named = state.len > 1 and state[1] >= 1 and state[1] <= 3;

        const choice: usize = if (named and rng.below(4) != 0) state[1] - 1 else rng.below(3);

        const algorithm = algorithms[choice];

        if (expectedState(algorithm, state)) |expected| {
            if (expected.cost > transcript_budget) {
                transcript.add(state, @intCast(choice), "SKIP", "");

                continue;
            }
        } else |_| {}

        var store = try MemoryStore.holding(state);

        defer store.deinit();

        var key = algorithm.loadPrivateKey(testing.allocator, store.store(), .{}) catch |err| {
            transcript.add(state, @intCast(choice), codeOf(err), "");

            continue;
        };

        defer key.deinit(testing.allocator);

        const public_key = key.publicKey();

        var remaining: [8]u8 = undefined;

        std.mem.writeInt(u64, &remaining, key.remainingSignatures(), .big);

        transcript.add(state, @intCast(choice), "OK", try std.mem.concat(allocator, u8, &.{ try public_key.exportKey(allocator, .raw), &remaining }));
    }
}

test "robustness: all implementations agree on untrusted input" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    var kem = try hazmat.generateKemKeyPair(pq.ml_kem_768, testing.allocator, try pattern(allocator, 64, 0));

    defer kem.private_key.deinit();

    defer kem.public_key.deinit();

    const encapsulation = try hazmat.encapsulate(&kem.public_key, try pattern(allocator, 32, 0x80));

    var xwing = try hazmat.generateKemKeyPair(pq.x_wing, testing.allocator, try pattern(allocator, 32, 0));

    defer xwing.private_key.deinit();

    defer xwing.public_key.deinit();

    var dsa = try hazmat.generateSignatureKeyPair(pq.ml_dsa_44, testing.allocator, try pattern(allocator, 32, 0));

    defer dsa.private_key.deinit();

    defer dsa.public_key.deinit();

    const signature = try hazmat.sign(&dsa.private_key, allocator, message_text, try pattern(allocator, 32, 0x60), .{ .context = "context" });

    var slh = try hazmat.generateSignatureKeyPair(pq.slh_dsa_sha2_128f, testing.allocator, try pattern(allocator, 48, 0));

    defer slh.private_key.deinit();

    defer slh.public_key.deinit();

    const levels = [_]pq.HssLevel{ .{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W1" }, .{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W1" } };

    var hss_store: MemoryStore = .{};

    defer hss_store.deinit();

    var hss = try hazmat.generateStatefulKeyPair(pq.hss_lms, testing.allocator, .{ .levels = &levels }, try pattern(allocator, 40, 0), 33, hss_store.store(), .{});

    defer hss.private_key.deinit(testing.allocator);

    const hss_signature = try hss.private_key.sign(allocator, message_text);

    const state = try storedState(allocator, pq.hss_lms, .{ .levels = levels[0..1] }, try pattern(allocator, 40, 0), 3);

    const xmss_public = try std.mem.concat(allocator, u8, &.{ &.{ 0, 0, 0, 1 }, try pattern(allocator, 64, 0) });

    const xmss_mt_public = try std.mem.concat(allocator, u8, &.{ &.{ 0, 0, 0, 0x31 }, try pattern(allocator, 48, 0) });

    const xmss_mt_key = try pq.xmss_mt.importPublicKey(xmss_mt_public, .raw);

    const hss_seeds = try exportsOf(allocator, &hss.public_key, 0);

    const public_seeds = hss_seeds ++ [_]Seed{
        .{ .encoding = xmss_public, .function = 1, .format = 0 },
        .{ .encoding = xmss_mt_public, .function = 2, .format = 0 },
        .{ .encoding = try xmss_mt_key.exportKey(allocator, .der), .function = 2, .format = 1 },
    };

    const xwing_seeds = [_]Seed{
        .{ .encoding = try xwing.public_key.exportKey(allocator, .raw), .function = 0, .format = 0 },
        .{ .encoding = try xwing.private_key.exportKey(allocator, .raw), .function = 1, .format = 0 },
    };

    const slh_seeds = try exportsOf(allocator, &slh.public_key, 0) ++ try exportsOf(allocator, &slh.private_key, 1);

    const ciphertext = encapsulation.ciphertext();

    var results: [11][64]u8 = undefined;

    for (&results, 0..) |*digest, case| {
        var rng: Random = .{ .state = 101 + case };

        var transcript: Transcript = .{};

        const t = &transcript;

        switch (case) {
            0 => try importCase(&rng, allocator, t, &try exportsOf(allocator, &kem.public_key, 0), &.{importer(pq.ml_kem_768, false)}),
            1 => try importCase(&rng, allocator, t, &try exportsOf(allocator, &kem.private_key, 0), &.{importer(pq.ml_kem_768, true)}),
            2 => try importCase(&rng, allocator, t, &xwing_seeds, &.{ importer(pq.x_wing, false), importer(pq.x_wing, true) }),
            3 => try importCase(&rng, allocator, t, &try exportsOf(allocator, &dsa.public_key, 0), &.{importer(pq.ml_dsa_44, false)}),
            4 => try importCase(&rng, allocator, t, &try exportsOf(allocator, &dsa.private_key, 0), &.{importer(pq.ml_dsa_44, true)}),
            5 => try importCase(&rng, allocator, t, &slh_seeds, &.{ importer(pq.slh_dsa_sha2_128f, false), importer(pq.slh_dsa_sha2_128f, true) }),
            6 => try importCase(&rng, allocator, t, &public_seeds, &.{ importer(pq.hss_lms, false), importer(pq.xmss, false), importer(pq.xmss_mt, false) }),
            7 => try signatureCase(&rng, allocator, t, signature, .{ .context = &dsa.public_key, .run = verifyDsa }),
            8 => for (0..transcript_rounds) |_| {
                const data = try resized(&rng, allocator, try edited(&rng, allocator, ciphertext, &.{ciphertext}), ciphertext.len);

                if (kem.private_key.decapsulate(data)) |secret| {
                    t.add(data, 0, "OK", &secret);
                } else |err| {
                    t.add(data, 0, codeOf(err), "");
                }
            },
            9 => try signatureCase(&rng, allocator, t, hss_signature, .{ .context = &hss.public_key, .run = verifyHss }),
            else => try stateCase(&rng, allocator, t, state),
        }

        digest.* = transcript.hex();
    }

    for (results, transcripts) |digest, expected| try testing.expectEqualStrings(expected, &digest);
}

// Structures that random edits rarely build: an HSS signature cut inside a field or inside a
// signed child key, counts and leaf indices beyond their range, and hint sections that claim more
// than omega hints, repeat an index or leave padding. Verification refuses every one.
test "robustness: verification refuses crafted structures" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const message = "crypto-pq edge";

    const levels = [_]pq.HssLevel{ .{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W1" }, .{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W1" } };

    var store: MemoryStore = .{};

    defer store.deinit();

    var pair = try hazmat.generateStatefulKeyPair(pq.hss_lms, testing.allocator, .{ .levels = &levels }, try pattern(allocator, 40, 0), 33, store.store(), .{});

    defer pair.private_key.deinit(testing.allocator);

    const signature = try pair.private_key.sign(allocator, message);

    // Nspk, then the first LMS signature (4956 bytes), the signed child key (48) and the second.
    const end = 4 + 4956;

    for ([_]usize{ 0, 1, 3, 4, 5, 8, 12, signature.len - 1 }) |length| try testing.expect(!pair.public_key.verify(signature[0..length], message));

    for (end - 1..end + 50) |length| try testing.expect(!pair.public_key.verify(signature[0..length], message));

    try testing.expect(pair.public_key.verify(signature, message));

    try testing.expect(!pair.public_key.verify(try std.mem.concat(allocator, u8, &.{ signature, &.{0} }), message));

    const fields = [_][2]u32{ .{ 0, 0 }, .{ 0, 2 }, .{ 0, 0x7fffffff }, .{ 0, 0xffffffff }, .{ 4, 32 }, .{ 4, 0xffffffff }, .{ end + 48, 32 }, .{ end + 48, 0xffffffff } };

    for (fields) |field| {
        const changed = try allocator.dupe(u8, signature);

        std.mem.writeInt(u32, changed[field[0]..][0..4], field[1], .big);

        try testing.expect(!pair.public_key.verify(changed, message));
    }

    // Level counts outside 1 to 8 make a malformed public key.
    const public = try pair.public_key.exportKey(allocator, .raw);

    for ([_]u32{ 0, 9, 0xffffffff }) |count| {
        std.mem.writeInt(u32, public[0..4], count, .big);

        try testing.expectError(error.InvalidPublicKey, pq.hss_lms.importPublicKey(public, .raw));
    }

    var dsa = try hazmat.generateSignatureKeyPair(pq.ml_dsa_44, testing.allocator, try pattern(allocator, 32, 0));

    defer dsa.private_key.deinit();

    defer dsa.public_key.deinit();

    const valid = try hazmat.sign(&dsa.private_key, allocator, message, &([_]u8{0} ** 32), .{});

    // ML-DSA-44: omega = 80 hint positions, then k = 4 cumulative counts.
    const counts = [_][4]u8{ .{ 81, 82, 83, 84 }, .{ 200, 201, 202, 203 }, .{ 80, 80, 80, 80 }, .{ 255, 255, 255, 255 }, .{ 5, 3, 3, 3 }, .{ 0, 0, 0, 0 } };

    for (counts) |count| {
        for ([_]bool{ false, true }) |repeat| {
            const changed = try allocator.dupe(u8, valid);

            const hints = changed[changed.len - 84 ..];

            for (hints[0..80], 0..) |*position, i| position.* = @intCast(i);

            if (repeat) hints[1] = 0;

            @memcpy(hints[80..], &count);

            try testing.expect(!dsa.public_key.verify(changed, message, .{}));
        }
    }

    // The valid signature with a nonzero byte after its last hint: the encoding must be canonical.
    const used = valid[valid.len - 1];

    if (used < 80) {
        const changed = try allocator.dupe(u8, valid);

        changed[changed.len - 84 + used] = 1;

        try testing.expect(dsa.public_key.verify(valid, message, .{}));

        try testing.expect(!dsa.public_key.verify(changed, message, .{}));
    }

    const xmss_cases = [_]struct { algorithm: pq.StatefulSignatureAlgorithm, oid: u8, size: usize, index: []const u8 }{
        .{ .algorithm = pq.xmss, .oid = 0x0d, .size = 4 + 24 + 61 * 24, .index = &.{ 0, 0, 4, 0 } },
        .{ .algorithm = pq.xmss, .oid = 0x0d, .size = 4 + 24 + 61 * 24, .index = &.{ 0xff, 0xff, 0xff, 0xff } },
        .{ .algorithm = pq.xmss_mt, .oid = 0x22, .size = 3 + 24 + (4 * 51 + 20) * 24, .index = &.{ 0x10, 0, 0 } },
        .{ .algorithm = pq.xmss_mt, .oid = 0x22, .size = 3 + 24 + (4 * 51 + 20) * 24, .index = &.{ 0xff, 0xff, 0xff } },
    };

    for (xmss_cases) |case| {
        const key = try case.algorithm.importPublicKey(try std.mem.concat(allocator, u8, &.{ &.{ 0, 0, 0, case.oid }, try pattern(allocator, 48, 0) }), .raw);

        const changed = try allocator.alloc(u8, case.size);

        @memset(changed, 0);

        @memcpy(changed[0..case.index.len], case.index);

        try testing.expect(!key.verify(changed, message));
    }
}

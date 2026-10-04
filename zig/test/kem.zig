const std = @import("std");
const pq = @import("crypto_pq");
const vectors = @import("vectors");

const testing = std.testing;

const hazmat = pq.hazmat;

const Allocator = std.mem.Allocator;

const algorithms = [_]pq.KemAlgorithm{ pq.ml_kem_512, pq.ml_kem_768, pq.ml_kem_1024 };

fn algorithmNamed(name: []const u8) !pq.KemAlgorithm {
    for (algorithms) |algorithm| {
        if (std.mem.eql(u8, algorithm.name, name)) return algorithm;
    }

    return error.TestUnexpectedResult;
}

fn objectIdentifier(allocator: Allocator, algorithm: pq.KemAlgorithm) ![]u8 {
    const arc: u8 = for (algorithms, 1..) |candidate, i| {
        if (candidate.kind == algorithm.kind) break @intCast(i);
    } else unreachable;

    return vectors.der(allocator, 0x06, &.{ &.{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04 }, &.{arc} });
}

fn pkcs8(allocator: Allocator, algorithm: pq.KemAlgorithm, private_key: []const u8) ![]u8 {
    const version = try vectors.der(allocator, 0x02, &.{&.{0}});

    const identifier = try vectors.der(allocator, 0x30, &.{try objectIdentifier(allocator, algorithm)});

    return vectors.der(allocator, 0x30, &.{ version, identifier, try vectors.der(allocator, 0x04, &.{private_key}) });
}

fn expectExport(allocator: Allocator, expected: []const u8, key: anytype, format: pq.KeyFormat) !void {
    try testing.expectEqualSlices(u8, expected, try key.exportKey(allocator, format));
}

fn keyGeneration(_: void, r: vectors.Record, allocator: Allocator) !void {
    const algorithm = try algorithmNamed(r.header.get("parameterSet"));

    const seed = try std.mem.concat(allocator, u8, &.{ try vectors.decode(allocator, r.values.get("d")), try vectors.decode(allocator, r.values.get("z")) });

    const ek = try vectors.decode(allocator, r.values.get("ek"));

    const dk = try vectors.decode(allocator, r.values.get("dk"));

    var pair = try hazmat.generateKemKeyPair(algorithm, allocator, seed);

    defer pair.private_key.deinit();

    defer pair.public_key.deinit();

    try expectExport(allocator, ek, &pair.public_key, .raw);

    try expectExport(allocator, seed, &pair.private_key, .raw);

    var expanded = try algorithm.importPrivateKey(allocator, dk, .raw);

    defer expanded.deinit();

    var expanded_public = expanded.publicKey();

    defer expanded_public.deinit();

    try expectExport(allocator, ek, &expanded_public, .raw);

    try expectExport(allocator, dk, &expanded, .raw);

    const both = try pkcs8(allocator, algorithm, try vectors.der(allocator, 0x30, &.{ try vectors.der(allocator, 0x04, &.{seed}), try vectors.der(allocator, 0x04, &.{dk}) }));

    var imported = try algorithm.importPrivateKey(allocator, both, .der);

    defer imported.deinit();

    try expectExport(allocator, seed, &imported, .raw);
}

test "ML-KEM ACVP key generation" {
    const v = try vectors.Vectors.load("acvp/ML-KEM-keyGen.txt", "dk");

    defer v.deinit();

    try vectors.parallel(v.records, {}, keyGeneration);
}

fn checkImport(function: anytype, algorithm: pq.KemAlgorithm, allocator: Allocator, data: []const u8, passed: []const u8) !void {
    if (std.mem.eql(u8, passed, "true")) {
        var key = try function(algorithm, allocator, data, .raw);

        key.deinit();
    } else if (function(algorithm, allocator, data, .raw)) |_| {
        return error.TestExpectedError;
    } else |_| {}
}

fn encapsulationAndDecapsulation(_: void, r: vectors.Record, allocator: Allocator) !void {
    const algorithm = try algorithmNamed(r.header.get("parameterSet"));

    const function = r.header.get("function");

    if (std.mem.eql(u8, function, "encapsulation")) {
        var public_key = try algorithm.importPublicKey(allocator, try vectors.decode(allocator, r.values.get("ek")), .raw);

        defer public_key.deinit();

        const result = try hazmat.encapsulate(&public_key, try vectors.decode(allocator, r.values.get("m")));

        try testing.expectEqualSlices(u8, try vectors.decode(allocator, r.values.get("c")), result.ciphertext());

        try testing.expectEqualSlices(u8, try vectors.decode(allocator, r.values.get("k")), &result.shared_secret);
    } else if (std.mem.eql(u8, function, "decapsulation")) {
        var private_key = if (r.header.is("keyFormat", "seed"))
            try algorithm.importPrivateKey(allocator, try std.mem.concat(allocator, u8, &.{ try vectors.decode(allocator, r.values.get("d")), try vectors.decode(allocator, r.values.get("z")) }), .raw)
        else
            try algorithm.importPrivateKey(allocator, try vectors.decode(allocator, r.values.get("dk")), .raw);

        defer private_key.deinit();

        const shared_secret = try private_key.decapsulate(try vectors.decode(allocator, r.values.get("c")));

        try testing.expectEqualSlices(u8, try vectors.decode(allocator, r.values.get("k")), &shared_secret);
    } else if (std.mem.eql(u8, function, "encapsulationKeyCheck")) {
        try checkImport(pq.KemAlgorithm.importPublicKey, algorithm, allocator, try vectors.decode(allocator, r.values.get("ek")), r.values.get("testPassed"));
    } else {
        try checkImport(pq.KemAlgorithm.importPrivateKey, algorithm, allocator, try vectors.decode(allocator, r.values.get("dk")), r.values.get("testPassed"));
    }
}

test "ML-KEM ACVP encapsulation and decapsulation" {
    const v = try vectors.Vectors.load("acvp/ML-KEM-encapDecap.txt", "tcId");

    defer v.deinit();

    try vectors.parallel(v.records, {}, encapsulationAndDecapsulation);
}

fn wycheproofDecapsulation(_: void, r: vectors.Record, allocator: Allocator) !void {
    const algorithm = try algorithmNamed(r.header.get("parameterSet"));

    const seed = try vectors.decode(allocator, r.values.get("seed"));

    const c = try vectors.decode(allocator, r.values.get("c"));

    if (r.values.is("result", "valid")) {
        var pair = try hazmat.generateKemKeyPair(algorithm, allocator, seed);

        defer pair.private_key.deinit();

        defer pair.public_key.deinit();

        try expectExport(allocator, try vectors.decode(allocator, r.values.get("ek")), &pair.public_key, .raw);

        const shared_secret = try pair.private_key.decapsulate(c);

        try testing.expectEqualSlices(u8, try vectors.decode(allocator, r.values.get("K")), &shared_secret);
    } else if (seed.len != 64) {
        try testing.expectError(error.InvalidLength, hazmat.generateKemKeyPair(algorithm, allocator, seed));
    } else {
        var pair = try hazmat.generateKemKeyPair(algorithm, allocator, seed);

        defer pair.private_key.deinit();

        defer pair.public_key.deinit();

        try testing.expectError(error.InvalidLength, pair.private_key.decapsulate(c));
    }
}

test "ML-KEM Wycheproof decapsulation" {
    const v = try vectors.Vectors.load("wycheproof/mlkem.txt", "tcId");

    defer v.deinit();

    try vectors.parallel(v.records, {}, wycheproofDecapsulation);
}

fn wycheproofEncapsulation(_: void, r: vectors.Record, allocator: Allocator) !void {
    const algorithm = try algorithmNamed(r.header.get("parameterSet"));

    const ek = try vectors.decode(allocator, r.values.get("ek"));

    if (r.values.is("result", "valid")) {
        var public_key = try algorithm.importPublicKey(allocator, ek, .raw);

        defer public_key.deinit();

        const result = try hazmat.encapsulate(&public_key, try vectors.decode(allocator, r.values.get("m")));

        try testing.expectEqualSlices(u8, try vectors.decode(allocator, r.values.get("c")), result.ciphertext());

        try testing.expectEqualSlices(u8, try vectors.decode(allocator, r.values.get("K")), &result.shared_secret);
    } else {
        const code = if (ek.len != algorithm.public_key_size) error.InvalidLength else error.InvalidPublicKey;

        try testing.expectError(code, algorithm.importPublicKey(allocator, ek, .raw));
    }
}

test "ML-KEM Wycheproof encapsulation" {
    const v = try vectors.Vectors.load("wycheproof/mlkem_encaps.txt", "tcId");

    defer v.deinit();

    try vectors.parallel(v.records, {}, wycheproofEncapsulation);
}

fn wycheproofExpandedDecapsulation(_: void, r: vectors.Record, allocator: Allocator) !void {
    const algorithm = try algorithmNamed(r.header.get("parameterSet"));

    const dk = try vectors.decode(allocator, r.values.get("dk"));

    const c = try vectors.decode(allocator, r.values.get("c"));

    const flags = r.values.find("flags") orelse "";

    if (r.values.is("result", "valid")) {
        var private_key = try algorithm.importPrivateKey(allocator, dk, .raw);

        defer private_key.deinit();

        var public_key = private_key.publicKey();

        defer public_key.deinit();

        try expectExport(allocator, try vectors.decode(allocator, r.values.get("ek")), &public_key, .raw);

        const shared_secret = try private_key.decapsulate(c);

        try testing.expectEqualSlices(u8, try vectors.decode(allocator, r.values.get("K")), &shared_secret);
    } else if (std.mem.find(u8, flags, "IncorrectCiphertextLength") != null) {
        var private_key = try algorithm.importPrivateKey(allocator, dk, .raw);

        defer private_key.deinit();

        try testing.expectError(error.InvalidLength, private_key.decapsulate(c));
    } else if (std.mem.find(u8, flags, "IncorrectDecapsulationKeyLength") != null) {
        try testing.expectError(error.InvalidLength, algorithm.importPrivateKey(allocator, dk, .raw));
    } else {
        try testing.expectError(error.InvalidPrivateKey, algorithm.importPrivateKey(allocator, dk, .raw));
    }
}

test "ML-KEM Wycheproof expanded decapsulation" {
    const v = try vectors.Vectors.load("wycheproof/mlkem_semi_expanded_decaps.txt", "tcId");

    defer v.deinit();

    try vectors.parallel(v.records, {}, wycheproofExpandedDecapsulation);
}

test "KEM round trip" {
    for (algorithms ++ [_]pq.KemAlgorithm{pq.x_wing}) |algorithm| {
        var pair = try algorithm.generateKeyPair(testing.allocator, .{});

        defer pair.private_key.deinit();

        defer pair.public_key.deinit();

        const encapsulation = try pair.public_key.encapsulate();

        try testing.expectEqual(algorithm.ciphertext_size, encapsulation.ciphertext().len);

        try testing.expectEqual(algorithm.shared_secret_size, encapsulation.shared_secret.len);

        const shared_secret = try pair.private_key.decapsulate(encapsulation.ciphertext());

        try testing.expectEqualSlices(u8, &encapsulation.shared_secret, &shared_secret);

        var tampered = encapsulation;

        tampered.ciphertext_buffer[0] ^= 1;

        const rejected = try pair.private_key.decapsulate(tampered.ciphertext());

        try testing.expect(!std.mem.eql(u8, &encapsulation.shared_secret, &rejected));

        const ciphertext = encapsulation.ciphertext();

        try testing.expectError(error.InvalidLength, pair.private_key.decapsulate(ciphertext[0 .. ciphertext.len - 1]));

        const raw = try pair.public_key.exportKey(testing.allocator, .raw);

        defer testing.allocator.free(raw);

        try testing.expectEqual(algorithm.public_key_size, raw.len);

        var unchecked = try algorithm.generateKeyPair(testing.allocator, .{ .self_test = false });

        defer unchecked.private_key.deinit();

        defer unchecked.public_key.deinit();

        try testing.expectEqual(algorithm.kind, unchecked.public_key.algorithm.kind);
    }
}

test "KEM formats" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    for (algorithms) |algorithm| {
        var pair = try algorithm.generateKeyPair(testing.allocator, .{});

        defer pair.private_key.deinit();

        defer pair.public_key.deinit();

        for ([_]pq.KeyFormat{ .raw, .der, .pem }) |format| {
            var public_key = try algorithm.importPublicKey(testing.allocator, try pair.public_key.exportKey(allocator, format), format);

            defer public_key.deinit();

            try testing.expect(public_key.eql(&pair.public_key));

            var private_key = try algorithm.importPrivateKey(testing.allocator, try pair.private_key.exportKey(allocator, format), format);

            defer private_key.deinit();

            var derived = private_key.publicKey();

            defer derived.deinit();

            try testing.expect(derived.eql(&pair.public_key));
        }

        const pem = try pair.public_key.exportKey(allocator, .pem);

        try testing.expectStringStartsWith(pem, "-----BEGIN PUBLIC KEY-----\n");

        try testing.expectStringStartsWith(try pair.private_key.exportKey(allocator, .pem), "-----BEGIN PRIVATE KEY-----\n");

        const der = try pair.private_key.exportKey(allocator, .der);

        try testing.expectEqualSlices(u8, &.{ 0x80, 0x40 }, der[der.len - 66 .. der.len - 64]);

        const public_der = try pair.public_key.exportKey(allocator, .der);

        try testing.expectError(error.InvalidEncoding, algorithm.importPublicKey(testing.allocator, try std.mem.concat(allocator, u8, &.{ public_der, &.{0} }), .der));

        try testing.expectError(error.InvalidEncoding, algorithm.importPublicKey(testing.allocator, try pair.private_key.exportKey(allocator, .pem), .pem));

        try testing.expectError(error.InvalidLength, algorithm.importPrivateKey(testing.allocator, &([_]u8{0} ** 63), .raw));
    }

    var pair = try pq.ml_kem_768.generateKeyPair(testing.allocator, .{});

    defer pair.private_key.deinit();

    defer pair.public_key.deinit();

    try testing.expectError(error.AlgorithmMismatch, pq.ml_kem_512.importPublicKey(testing.allocator, try pair.public_key.exportKey(allocator, .der), .der));

    try testing.expectError(error.AlgorithmMismatch, pq.ml_kem_1024.importPrivateKey(testing.allocator, try pair.private_key.exportKey(allocator, .pem), .pem));
}

test "X-Wing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const v = try vectors.Vectors.load("xwing/test-vectors.txt", "seed");

    defer v.deinit();

    for (v.records) |r| {
        var pair = try hazmat.generateKemKeyPair(pq.x_wing, testing.allocator, try vectors.decode(allocator, r.values.get("seed")));

        defer pair.private_key.deinit();

        defer pair.public_key.deinit();

        try expectExport(allocator, try vectors.decode(allocator, r.values.get("pk")), &pair.public_key, .raw);

        try expectExport(allocator, try vectors.decode(allocator, r.values.get("sk")), &pair.private_key, .raw);

        const result = try hazmat.encapsulate(&pair.public_key, try vectors.decode(allocator, r.values.get("eseed")));

        try testing.expectEqualSlices(u8, try vectors.decode(allocator, r.values.get("ct")), result.ciphertext());

        try testing.expectEqualSlices(u8, try vectors.decode(allocator, r.values.get("ss")), &result.shared_secret);

        const shared_secret = try pair.private_key.decapsulate(result.ciphertext());

        try testing.expectEqualSlices(u8, &result.shared_secret, &shared_secret);
    }

    var pair = try pq.x_wing.generateKeyPair(testing.allocator, .{});

    defer pair.private_key.deinit();

    defer pair.public_key.deinit();

    for ([_]pq.KeyFormat{ .der, .pem }) |format| {
        try testing.expectError(error.Unsupported, pair.public_key.exportKey(allocator, format));

        try testing.expectError(error.Unsupported, pair.private_key.exportKey(allocator, format));

        try testing.expectError(error.Unsupported, pq.x_wing.importPublicKey(testing.allocator, "", format));

        try testing.expectError(error.Unsupported, pq.x_wing.importPrivateKey(testing.allocator, "", format));
    }

    var imported = try pq.x_wing.importPrivateKey(testing.allocator, try pair.private_key.exportKey(allocator, .raw), .raw);

    defer imported.deinit();

    var derived = imported.publicKey();

    defer derived.deinit();

    try testing.expect(derived.eql(&pair.public_key));
}

// Every byte of the seed and of the decoded secret is wiped before its memory is freed.
test "KEM private keys are wiped by deinit" {
    var seed: [64]u8 = undefined;

    for (&seed, 0..) |*byte, i| byte.* = @intCast(i + 1);

    var check: vectors.WipeCheck = .{ .child = testing.allocator, .secrets = &.{} };

    var pair = try hazmat.generateKemKeyPair(pq.ml_kem_512, check.allocator(), &seed);

    const encoded_s = try testing.allocator.dupe(u8, pair.private_key.secret.dk[0..32]);

    defer testing.allocator.free(encoded_s);

    const secrets = [_][]const u8{ &seed, encoded_s };

    check.secrets = &secrets;

    pair.public_key.deinit();

    pair.private_key.deinit();

    try testing.expect(!check.leaked and check.frees >= 2);
}

const Case = struct {
    data: []const u8,
    expected: ?anyerror = null,
};

fn expectImports(algorithm: pq.KemAlgorithm, comptime private: bool, format: pq.KeyFormat, cases: []const Case) !void {
    for (cases, 0..) |case, i| {
        const result = if (private) algorithm.importPrivateKey(testing.allocator, case.data, format) else algorithm.importPublicKey(testing.allocator, case.data, format);

        if (case.expected) |code| {
            testing.expectError(code, result) catch |err| {
                std.debug.print("case {d}\n", .{i});

                return err;
            };
        } else {
            var key = result catch |err| {
                std.debug.print("case {d}: {s}\n", .{ i, @errorName(err) });

                return err;
            };

            key.deinit();
        }
    }
}

// The DER and PEM rules: single-byte tags, shortest definite lengths, no trailing data, an
// AlgorithmIdentifier without parameters, BIT STRINGs without unused bits, PKCS#8 versions 0 and
// 1, and PEM text that may only be surrounded or split by whitespace.
test "key encoding strictness" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const algorithm = pq.ml_kem_512;

    var seed: [64]u8 = undefined;

    for (&seed, 0..) |*byte, i| byte.* = @intCast(i);

    var pair = try hazmat.generateKemKeyPair(algorithm, testing.allocator, &seed);

    defer pair.private_key.deinit();

    defer pair.public_key.deinit();

    var other = try hazmat.generateKemKeyPair(algorithm, testing.allocator, &([_]u8{0} ** 64));

    defer other.private_key.deinit();

    defer other.public_key.deinit();

    const pk = try pair.public_key.exportKey(allocator, .raw);

    const oid = try objectIdentifier(allocator, algorithm);

    const identifier = try vectors.der(allocator, 0x30, &.{oid});

    const bits = try vectors.der(allocator, 0x03, &.{ &.{0}, pk });

    const spki = try vectors.der(allocator, 0x30, &.{ identifier, bits });

    try expectImports(algorithm, false, .der, &.{
        .{ .data = spki },
        .{ .data = try std.mem.concat(allocator, u8, &.{ &.{ 0x30, 0x83, 0x00, 0x03, 0x32 }, identifier, bits }), .expected = error.InvalidEncoding },
        .{ .data = try std.mem.concat(allocator, u8, &.{ &.{ 0x30, 0x82, 0x03, 0x33, 0x30, 0x81, 0x0b }, oid, bits }), .expected = error.InvalidEncoding },
        .{ .data = try std.mem.concat(allocator, u8, &.{ &.{ 0x30, 0x85, 0x00, 0x00, 0x00, 0x03, 0x32 }, identifier, bits }), .expected = error.InvalidEncoding },
        .{ .data = try vectors.der(allocator, 0x30, &.{ try vectors.der(allocator, 0x30, &.{ oid, &.{ 0x05, 0x00 } }), bits }), .expected = error.InvalidEncoding },
        .{ .data = try vectors.der(allocator, 0x30, &.{ identifier, try vectors.der(allocator, 0x03, &.{ &.{1}, pk }) }), .expected = error.InvalidEncoding },
        .{ .data = try vectors.der(allocator, 0x30, &.{ identifier, try vectors.der(allocator, 0x03, &.{}) }), .expected = error.InvalidEncoding },
        .{ .data = try vectors.der(allocator, 0x30, &.{ identifier, try vectors.der(allocator, 0x03, &.{ &.{0}, pk[0 .. pk.len - 1] }) }), .expected = error.InvalidEncoding },
        .{ .data = try std.mem.concat(allocator, u8, &.{ &.{0x1f}, spki }), .expected = error.InvalidEncoding },
        .{ .data = spki[0 .. spki.len - 1], .expected = error.InvalidEncoding },
    });

    const version_0 = try vectors.der(allocator, 0x02, &.{&.{0}});

    const version_1 = try vectors.der(allocator, 0x02, &.{&.{1}});

    const octets = try vectors.der(allocator, 0x04, &.{try vectors.der(allocator, 0x80, &.{&seed})});

    const public = try vectors.der(allocator, 0x81, &.{ &.{0}, pk });

    const attributes = try vectors.der(allocator, 0xa0, &.{try vectors.der(allocator, 0x30, &.{})});

    const other_public = try vectors.der(allocator, 0x81, &.{ &.{0}, try other.public_key.exportKey(allocator, .raw) });

    try expectImports(algorithm, true, .der, &.{
        .{ .data = try vectors.der(allocator, 0x30, &.{ version_0, identifier, octets }) },
        .{ .data = try vectors.der(allocator, 0x30, &.{ version_1, identifier, octets, public }) },
        .{ .data = try vectors.der(allocator, 0x30, &.{ version_0, identifier, octets, attributes }) },
        .{ .data = try vectors.der(allocator, 0x30, &.{ version_1, identifier, octets, attributes, public }) },
        .{ .data = try vectors.der(allocator, 0x30, &.{ version_0, identifier, octets, public }), .expected = error.InvalidEncoding },
        .{ .data = try vectors.der(allocator, 0x30, &.{ try vectors.der(allocator, 0x02, &.{&.{2}}), identifier, octets }), .expected = error.InvalidEncoding },
        .{ .data = try vectors.der(allocator, 0x30, &.{ try vectors.der(allocator, 0x02, &.{&.{ 0, 1 }}), identifier, octets }), .expected = error.InvalidEncoding },
        .{ .data = try vectors.der(allocator, 0x30, &.{ version_1, identifier, octets, other_public }), .expected = error.InvalidPrivateKey },
        .{ .data = try vectors.der(allocator, 0x30, &.{ version_1, identifier, octets, try vectors.der(allocator, 0x81, &.{ &.{1}, pk }) }), .expected = error.InvalidEncoding },
        .{ .data = try vectors.der(allocator, 0x30, &.{ version_0, identifier, try vectors.der(allocator, 0x04, &.{try vectors.der(allocator, 0x80, &.{seed[0..63]})}) }), .expected = error.InvalidEncoding },
        .{ .data = try vectors.der(allocator, 0x30, &.{ version_0, identifier, try vectors.der(allocator, 0x04, &.{try vectors.der(allocator, 0x81, &.{&seed})}) }), .expected = error.InvalidEncoding },
        .{ .data = try vectors.der(allocator, 0x30, &.{ version_0, identifier, try vectors.der(allocator, 0x04, &.{}) }), .expected = error.InvalidEncoding },
        .{ .data = try vectors.der(allocator, 0x30, &.{ version_0, identifier, try vectors.der(allocator, 0x04, &.{ try vectors.der(allocator, 0x80, &.{&seed}), &.{0} }) }), .expected = error.InvalidEncoding },
    });

    const pem = try pair.public_key.exportKey(allocator, .pem);

    const header = "-----BEGIN PUBLIC KEY-----\n";

    const footer = "\n-----END PUBLIC KEY-----\n";

    const body = try std.mem.replaceOwned(u8, allocator, pem[header.len .. pem.len - footer.len], "\n", "");

    var rewrapped: std.ArrayList(u8) = .empty;

    try rewrapped.appendSlice(allocator, header);

    var offset: usize = 0;

    while (offset < body.len) : (offset += 30) {
        try rewrapped.appendSlice(allocator, body[offset..@min(offset + 30, body.len)]);

        try rewrapped.append(allocator, '\n');
    }

    try rewrapped.appendSlice(allocator, footer[1..]);

    const bad_character = try allocator.dupe(u8, pem);

    bad_character[header.len] = '*';

    const inner_equals = try allocator.dupe(u8, pem);

    inner_equals[header.len + 4] = '=';

    try expectImports(algorithm, false, .pem, &.{
        .{ .data = try std.mem.concat(allocator, u8, &.{ " \t\n", pem, "\n\n " }) },
        .{ .data = rewrapped.items },
        .{ .data = try std.mem.replaceOwned(u8, allocator, pem, "\n", " \r\n") },
        .{ .data = pem[0 .. pem.len - footer.len + 1], .expected = error.InvalidEncoding },
        .{ .data = try std.mem.replaceOwned(u8, allocator, pem, "PUBLIC", "PRIVATE"), .expected = error.InvalidEncoding },
        .{ .data = try std.mem.concat(allocator, u8, &.{ header, "\xc3\xa9", pem[header.len..] }), .expected = error.InvalidEncoding },
        .{ .data = bad_character, .expected = error.InvalidEncoding },
        .{ .data = inner_equals, .expected = error.InvalidEncoding },
        .{ .data = try std.mem.concat(allocator, u8, &.{ "x", pem }), .expected = error.InvalidEncoding },
    });

    // The seed-form PKCS#8 encoding is 86 bytes, so its base64 ends in one '=': the character
    // before it carries two padding bits, which must be zero.
    const private_pem = try pair.private_key.exportKey(allocator, .pem);

    const padding = std.mem.findScalar(u8, private_pem, '=').?;

    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    const non_canonical = try allocator.dupe(u8, private_pem);

    non_canonical[padding - 1] = alphabet[std.mem.findScalar(u8, alphabet, private_pem[padding - 1]).? ^ 1];

    try expectImports(algorithm, true, .pem, &.{
        .{ .data = private_pem },
        .{ .data = non_canonical, .expected = error.InvalidEncoding },
    });
}

fn cached(public_key: *const pq.KemPublicKey) bool {
    return public_key.public.shared.cache.pointer.load(.acquire) != null;
}

// The keys of a pair share one cache. Generation fills it only for its self-test, which uses it at
// once; every other key fills it on first use. A public key keeps it after its private key is gone.
test "KEM keys share one cache, filled on first use" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    for (algorithms ++ [_]pq.KemAlgorithm{pq.x_wing}) |algorithm| {
        var untested = try algorithm.generateKeyPair(testing.allocator, .{ .self_test = false });

        defer untested.private_key.deinit();

        defer untested.public_key.deinit();

        try testing.expect(!cached(&untested.public_key));

        var pair = try algorithm.generateKeyPair(testing.allocator, .{});

        defer pair.public_key.deinit();

        try testing.expectEqual(pair.private_key.public, pair.public_key.public);

        try testing.expect(cached(&pair.public_key));

        const seed = try pair.private_key.exportKey(allocator, .raw);

        pair.private_key.deinit();

        var private_key = try algorithm.importPrivateKey(testing.allocator, seed, .raw);

        defer private_key.deinit();

        var derived = private_key.publicKey();

        defer derived.deinit();

        try testing.expectEqual(private_key.public, derived.public);

        try testing.expect(!cached(&derived));

        const encapsulation = try pair.public_key.encapsulate();

        try testing.expectEqualSlices(u8, &encapsulation.shared_secret, &try private_key.decapsulate(encapsulation.ciphertext()));

        try testing.expect(cached(&derived));

        const again = try derived.encapsulate();

        try testing.expectEqualSlices(u8, &again.shared_secret, &try private_key.decapsulate(again.ciphertext()));
    }
}

// When the cache cannot be allocated, each call computes what it needs for itself.
test "KEM keys without memory for their cache" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    for (algorithms ++ [_]pq.KemAlgorithm{pq.x_wing}) |algorithm| {
        var pair = try algorithm.generateKeyPair(testing.allocator, .{ .self_test = false });

        defer pair.private_key.deinit();

        defer pair.public_key.deinit();

        var public_memory = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 1 });

        var public_key = try algorithm.importPublicKey(public_memory.allocator(), try pair.public_key.exportKey(allocator, .raw), .raw);

        defer public_key.deinit();

        // A private key has a public and a secret part.
        var private_memory = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 2 });

        var private_key = try algorithm.importPrivateKey(private_memory.allocator(), try pair.private_key.exportKey(allocator, .raw), .raw);

        defer private_key.deinit();

        for (0..2) |_| {
            const encapsulation = try public_key.encapsulate();

            try testing.expectEqualSlices(u8, &encapsulation.shared_secret, &try pair.private_key.decapsulate(encapsulation.ciphertext()));

            const other = try pair.public_key.encapsulate();

            try testing.expectEqualSlices(u8, &other.shared_secret, &try private_key.decapsulate(other.ciphertext()));
        }

        try testing.expect(!cached(&public_key));

        try testing.expect(private_key.public.shared.cache.pointer.load(.acquire) == null);
    }
}

// Threads that use a fresh key at the same time each compute the cache; one copy is kept.
test "KEM cache under concurrent first use" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;

    var pair = try pq.ml_kem_768.generateKeyPair(testing.allocator, .{ .self_test = false });

    defer pair.private_key.deinit();

    defer pair.public_key.deinit();

    const raw = try pair.public_key.exportKey(testing.allocator, .raw);

    defer testing.allocator.free(raw);

    var public_key = try pq.ml_kem_768.importPublicKey(testing.allocator, raw, .raw);

    defer public_key.deinit();

    var results: [8]pq.Encapsulation = undefined;

    var threads: [8]std.Thread = undefined;

    const Worker = struct {
        fn run(key: *const pq.KemPublicKey, out: *pq.Encapsulation) void {
            out.* = key.encapsulate() catch unreachable;
        }
    };

    for (&threads, &results) |*thread, *result| thread.* = try std.Thread.spawn(.{}, Worker.run, .{ &public_key, result });

    for (threads) |thread| thread.join();

    for (results) |result| try testing.expectEqualSlices(u8, &result.shared_secret, &try pair.private_key.decapsulate(result.ciphertext()));

    try testing.expect(cached(&public_key));
}

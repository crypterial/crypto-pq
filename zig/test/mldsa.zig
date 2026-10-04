const std = @import("std");
const pq = @import("crypto_pq");
const vectors = @import("vectors");

const testing = std.testing;

const hazmat = pq.hazmat;

const Allocator = std.mem.Allocator;

const algorithms = [_]pq.SignatureAlgorithm{ pq.ml_dsa_44, pq.ml_dsa_65, pq.ml_dsa_87 };

pub const pre_hashes = [_]struct { name: []const u8, pre_hash: pq.PreHash }{
    .{ .name = "SHA2-224", .pre_hash = .{ .hash = pq.sha_224 } },
    .{ .name = "SHA2-256", .pre_hash = .{ .hash = pq.sha_256 } },
    .{ .name = "SHA2-384", .pre_hash = .{ .hash = pq.sha_384 } },
    .{ .name = "SHA2-512", .pre_hash = .{ .hash = pq.sha_512 } },
    .{ .name = "SHA2-512/224", .pre_hash = .{ .hash = pq.sha_512_224 } },
    .{ .name = "SHA2-512/256", .pre_hash = .{ .hash = pq.sha_512_256 } },
    .{ .name = "SHA3-224", .pre_hash = .{ .hash = pq.sha3_224 } },
    .{ .name = "SHA3-256", .pre_hash = .{ .hash = pq.sha3_256 } },
    .{ .name = "SHA3-384", .pre_hash = .{ .hash = pq.sha3_384 } },
    .{ .name = "SHA3-512", .pre_hash = .{ .hash = pq.sha3_512 } },
    .{ .name = "SHAKE-128", .pre_hash = .{ .xof = pq.shake128 } },
    .{ .name = "SHAKE-256", .pre_hash = .{ .xof = pq.shake256 } },
};

fn algorithmNamed(name: []const u8) !pq.SignatureAlgorithm {
    for (algorithms) |algorithm| {
        if (std.mem.eql(u8, algorithm.name, name)) return algorithm;
    }

    return error.TestUnexpectedResult;
}

pub fn preHash(r: vectors.Record) !?pq.PreHash {
    if (r.header.is("preHash", "pure")) return null;

    for (pre_hashes) |entry| {
        if (r.values.is("hashAlg", entry.name)) return entry.pre_hash;
    }

    return error.TestUnexpectedResult;
}

fn pkcs8(allocator: Allocator, algorithm: pq.SignatureAlgorithm, private_key: []const u8) ![]u8 {
    const arc: u8 = for (algorithms, 17..) |candidate, i| {
        if (candidate.kind == algorithm.kind) break @intCast(i);
    } else unreachable;

    const oid = try vectors.der(allocator, 0x06, &.{ &.{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03 }, &.{arc} });

    return vectors.der(allocator, 0x30, &.{ try vectors.der(allocator, 0x02, &.{&.{0}}), try vectors.der(allocator, 0x30, &.{oid}), try vectors.der(allocator, 0x04, &.{private_key}) });
}

fn expectExport(allocator: Allocator, expected: []const u8, key: anytype, format: pq.KeyFormat) !void {
    try testing.expectEqualSlices(u8, expected, try key.exportKey(allocator, format));
}

fn keyGeneration(_: void, r: vectors.Record, allocator: Allocator) !void {
    const algorithm = try algorithmNamed(r.header.get("parameterSet"));

    const seed = try vectors.decode(allocator, r.values.get("seed"));

    const pk = try vectors.decode(allocator, r.values.get("pk"));

    const sk = try vectors.decode(allocator, r.values.get("sk"));

    var pair = try hazmat.generateSignatureKeyPair(algorithm, allocator, seed);

    defer pair.private_key.deinit();

    defer pair.public_key.deinit();

    try expectExport(allocator, pk, &pair.public_key, .raw);

    try expectExport(allocator, seed, &pair.private_key, .raw);

    var expanded = try algorithm.importPrivateKey(allocator, sk, .raw);

    defer expanded.deinit();

    var expanded_public = expanded.publicKey();

    defer expanded_public.deinit();

    try expectExport(allocator, pk, &expanded_public, .raw);

    try expectExport(allocator, sk, &expanded, .raw);

    const both = try pkcs8(allocator, algorithm, try vectors.der(allocator, 0x30, &.{ try vectors.der(allocator, 0x04, &.{seed}), try vectors.der(allocator, 0x04, &.{sk}) }));

    var imported = try algorithm.importPrivateKey(allocator, both, .der);

    defer imported.deinit();

    try expectExport(allocator, seed, &imported, .raw);

    sk[sk.len - 1] ^= 1;

    try testing.expectError(error.InvalidPrivateKey, algorithm.importPrivateKey(allocator, sk, .raw));
}

test "ML-DSA ACVP key generation" {
    const v = try vectors.Vectors.load("acvp/ML-DSA-keyGen.txt", "sk");

    defer v.deinit();

    try vectors.parallel(v.records, {}, keyGeneration);
}

fn signatureGeneration(_: void, r: vectors.Record, allocator: Allocator) !void {
    const algorithm = try algorithmNamed(r.header.get("parameterSet"));

    var private_key = if (r.header.is("keyFormat", "seed"))
        try algorithm.importPrivateKey(allocator, try vectors.decode(allocator, r.values.get("seed")), .raw)
    else
        try algorithm.importPrivateKey(allocator, try vectors.decode(allocator, r.values.get("sk")), .raw);

    defer private_key.deinit();

    var public_key = private_key.publicKey();

    defer public_key.deinit();

    try expectExport(allocator, try vectors.decode(allocator, r.values.get("pk")), &public_key, .raw);

    const zeros: [32]u8 = @splat(0);

    const randomness = if (r.header.is("deterministic", "true")) &zeros else try vectors.decode(allocator, r.values.get("rnd"));

    const message = try vectors.decode(allocator, r.values.get("message"));

    const context = try vectors.decode(allocator, r.values.get("context"));

    const pre_hash = try preHash(r);

    const signature = try hazmat.sign(&private_key, allocator, message, randomness, .{ .context = context, .pre_hash = pre_hash });

    try testing.expectEqualSlices(u8, try vectors.decode(allocator, r.values.get("signature")), signature);

    try testing.expect(hazmat.verify(&public_key, signature, message, .{ .context = context, .pre_hash = pre_hash }));
}

test "ML-DSA ACVP signature generation" {
    const v = try vectors.Vectors.load("acvp/ML-DSA-sigGen.txt", "signature");

    defer v.deinit();

    try vectors.parallel(v.records, {}, signatureGeneration);
}

fn signatureVerification(_: void, r: vectors.Record, allocator: Allocator) !void {
    const algorithm = try algorithmNamed(r.header.get("parameterSet"));

    var public_key = try algorithm.importPublicKey(allocator, try vectors.decode(allocator, r.values.get("pk")), .raw);

    defer public_key.deinit();

    const result = hazmat.verify(&public_key, try vectors.decode(allocator, r.values.get("signature")), try vectors.decode(allocator, r.values.get("message")), .{
        .context = try vectors.decode(allocator, r.values.get("context")),
        .pre_hash = try preHash(r),
    });

    try testing.expectEqual(r.values.is("testPassed", "true"), result);
}

test "ML-DSA ACVP signature verification" {
    const v = try vectors.Vectors.load("acvp/ML-DSA-sigVer.txt", "signature");

    defer v.deinit();

    try vectors.parallel(v.records, {}, signatureVerification);
}

fn wycheproofVerification(_: void, r: vectors.Record, allocator: Allocator) !void {
    const algorithm = try algorithmNamed(r.header.get("parameterSet"));

    const key = try vectors.decode(allocator, r.header.get("publicKey"));

    if (key.len != algorithm.public_key_size) {
        try testing.expectError(error.InvalidLength, algorithm.importPublicKey(allocator, key, .raw));

        return;
    }

    var public_key = try algorithm.importPublicKey(allocator, key, .raw);

    defer public_key.deinit();

    const der = r.header.get("publicKeyDer");

    if (der.len > 0) {
        var imported = try algorithm.importPublicKey(allocator, try vectors.decode(allocator, der), .der);

        defer imported.deinit();

        try testing.expect(imported.eql(&public_key));
    }

    const context = try vectors.decode(allocator, r.values.find("ctx") orelse "");

    const result = public_key.verify(try vectors.decode(allocator, r.values.get("sig")), try vectors.decode(allocator, r.values.get("msg")), .{ .context = context });

    try testing.expectEqual(r.values.is("result", "valid"), result);
}

test "ML-DSA Wycheproof verification" {
    const v = try vectors.Vectors.load("wycheproof/mldsa_verify.txt", "tcId");

    defer v.deinit();

    try vectors.parallel(v.records, {}, wycheproofVerification);
}

fn wycheproofSigning(_: void, r: vectors.Record, allocator: Allocator) !void {
    if (r.values.find("msg") == null) return;

    const algorithm = try algorithmNamed(r.header.get("parameterSet"));

    const seed = try vectors.decode(allocator, r.header.get("privateSeed"));

    const context = try vectors.decode(allocator, r.values.find("ctx") orelse "");

    const message = try vectors.decode(allocator, r.values.get("msg"));

    const flags = r.values.find("flags") orelse "";

    if (std.mem.find(u8, flags, "IncorrectPrivateKeyLength") != null) {
        try testing.expectError(error.InvalidLength, hazmat.generateSignatureKeyPair(algorithm, allocator, seed));

        return;
    }

    const encoded = r.header.get("privateKeyPkcs8");

    var private_key = if (encoded.len > 0)
        try algorithm.importPrivateKey(allocator, try vectors.decode(allocator, encoded), .der)
    else
        try algorithm.importPrivateKey(allocator, seed, .raw);

    defer private_key.deinit();

    var public_key = private_key.publicKey();

    defer public_key.deinit();

    try expectExport(allocator, try vectors.decode(allocator, r.header.get("publicKey")), &public_key, .raw);

    if (std.mem.find(u8, flags, "InvalidContext") != null) {
        try testing.expectError(error.InvalidContext, private_key.sign(allocator, message, .{ .context = context }));
    } else if (std.mem.find(u8, flags, "Randomized") != null) {
        try testing.expect(public_key.verify(try vectors.decode(allocator, r.values.get("sig")), message, .{ .context = context }));
    } else {
        const signature = try private_key.sign(allocator, message, .{ .context = context, .deterministic = true });

        try testing.expectEqualSlices(u8, try vectors.decode(allocator, r.values.get("sig")), signature);
    }
}

test "ML-DSA Wycheproof deterministic signing" {
    const v = try vectors.Vectors.load("wycheproof/mldsa_sign_seed.txt", "tcId");

    defer v.deinit();

    try vectors.parallel(v.records, {}, wycheproofSigning);
}

test "signature round trip" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    for (algorithms) |algorithm| {
        var pair = try algorithm.generateKeyPair(testing.allocator, .{});

        defer pair.private_key.deinit();

        defer pair.public_key.deinit();

        const public_key = &pair.public_key;

        const signature = try pair.private_key.sign(allocator, "message", .{ .context = "context" });

        try testing.expectEqual(algorithm.signature_size, signature.len);

        try testing.expect(public_key.verify(signature, "message", .{ .context = "context" }));

        try testing.expect(!public_key.verify(signature, "message", .{}));

        try testing.expect(!public_key.verify(signature, "other", .{ .context = "context" }));

        try testing.expect(!public_key.verify(signature[0 .. signature.len - 1], "message", .{ .context = "context" }));

        const long_context: [256]u8 = @splat(0);

        try testing.expect(!public_key.verify(signature, "message", .{ .context = &long_context }));

        try testing.expectError(error.InvalidContext, pair.private_key.sign(allocator, "message", .{ .context = &long_context }));

        const deterministic = try pair.private_key.sign(allocator, "message", .{ .deterministic = true });

        try testing.expectEqualSlices(u8, deterministic, try pair.private_key.sign(allocator, "message", .{ .deterministic = true }));

        try testing.expect(!std.mem.eql(u8, try pair.private_key.sign(allocator, "message", .{}), try pair.private_key.sign(allocator, "message", .{})));

        const sha_512: pq.PreHash = .{ .hash = pq.sha_512 };

        const hashed = try pair.private_key.sign(allocator, "message", .{ .pre_hash = sha_512 });

        try testing.expect(public_key.verify(hashed, "message", .{ .pre_hash = sha_512 }));

        try testing.expect(!public_key.verify(hashed, "message", .{}));

        try testing.expectError(error.InvalidOption, pair.private_key.sign(allocator, "message", .{ .pre_hash = .{ .hash = pq.sha_224 } }));

        // Only the library's own hash constants count as pre-hashes; a hand-made one is refused.
        var forged = pq.sha_512;

        forged.name = "SHA-512 (forged)";

        try testing.expectError(error.InvalidOption, pair.private_key.sign(allocator, "message", .{ .pre_hash = .{ .hash = forged } }));

        try testing.expect(!public_key.verify(hashed, "message", .{ .pre_hash = .{ .hash = forged } }));
    }
}

test "pre-hash strength" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const allowed = [_][]const []const u8{
        &.{ "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-512/256", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE-128", "SHAKE-256" },
        &.{ "SHA2-384", "SHA2-512", "SHA3-384", "SHA3-512", "SHAKE-256" },
        &.{ "SHA2-512", "SHA3-512", "SHAKE-256" },
    };

    const zeros: [32]u8 = @splat(0);

    for (algorithms, allowed) |algorithm, names| {
        var pair = try hazmat.generateSignatureKeyPair(algorithm, testing.allocator, &zeros);

        defer pair.private_key.deinit();

        defer pair.public_key.deinit();

        for (pre_hashes) |entry| {
            const permitted = for (names) |name| {
                if (std.mem.eql(u8, name, entry.name)) break true;
            } else false;

            if (permitted) {
                const signature = try pair.private_key.sign(allocator, "m", .{ .pre_hash = entry.pre_hash });

                try testing.expect(pair.public_key.verify(signature, "m", .{ .pre_hash = entry.pre_hash }));
            } else {
                try testing.expectError(error.InvalidOption, pair.private_key.sign(allocator, "m", .{ .pre_hash = entry.pre_hash }));

                const signature = try hazmat.sign(&pair.private_key, allocator, "m", &zeros, .{ .pre_hash = entry.pre_hash });

                try testing.expect(hazmat.verify(&pair.public_key, signature, "m", .{ .pre_hash = entry.pre_hash }));

                try testing.expect(!pair.public_key.verify(signature, "m", .{ .pre_hash = entry.pre_hash }));
            }
        }
    }
}

test "signature formats" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    for (algorithms) |algorithm| {
        var pair = try algorithm.generateKeyPair(testing.allocator, .{ .self_test = false });

        defer pair.private_key.deinit();

        defer pair.public_key.deinit();

        const raw = try pair.private_key.exportKey(allocator, .raw);

        for ([_]pq.KeyFormat{ .raw, .der, .pem }) |format| {
            var public_key = try algorithm.importPublicKey(testing.allocator, try pair.public_key.exportKey(allocator, format), format);

            defer public_key.deinit();

            try testing.expect(public_key.eql(&pair.public_key));

            var private_key = try algorithm.importPrivateKey(testing.allocator, try pair.private_key.exportKey(allocator, format), format);

            defer private_key.deinit();

            try expectExport(allocator, raw, &private_key, .raw);
        }

        const der = try pair.private_key.exportKey(allocator, .der);

        try testing.expectEqualSlices(u8, &.{ 0x80, 0x20 }, der[der.len - 34 .. der.len - 32]);

        var expanded = try hazmat.generateSignatureKeyPair(algorithm, testing.allocator, raw);

        defer expanded.private_key.deinit();

        defer expanded.public_key.deinit();

        try testing.expect(expanded.public_key.eql(&pair.public_key));

        const other = if (algorithm.kind != pq.ml_dsa_44.kind) pq.ml_dsa_44 else pq.ml_dsa_65;

        try testing.expectError(error.AlgorithmMismatch, other.importPublicKey(testing.allocator, try pair.public_key.exportKey(allocator, .der), .der));

        try testing.expectError(error.InvalidLength, algorithm.importPrivateKey(testing.allocator, &([_]u8{0} ** 33), .raw));
    }
}

// Every byte of the seed and of the expanded key is wiped before its memory is freed.
test "signature private keys are wiped by deinit" {
    var seed: [32]u8 = undefined;

    for (&seed, 0..) |*byte, i| byte.* = @intCast(i + 1);

    var check: vectors.WipeCheck = .{ .child = testing.allocator, .secrets = &.{} };

    var pair = try hazmat.generateSignatureKeyPair(pq.ml_dsa_44, check.allocator(), &seed);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    _ = try pair.private_key.sign(arena.allocator(), "message", .{});

    const encoded_s1 = try testing.allocator.dupe(u8, pair.private_key.secret.bytes[128..160]);

    defer testing.allocator.free(encoded_s1);

    const secrets = [_][]const u8{ &seed, encoded_s1 };

    check.secrets = &secrets;

    pair.public_key.deinit();

    pair.private_key.deinit();

    try testing.expect(!check.leaked and check.frees >= 4);
}

fn cached(slot: anytype) bool {
    return slot.pointer.load(.acquire) != null;
}

// The keys of a pair share one cache of A and NTT(t1 * 2^d), and the private key has its own cache
// of the secret vectors. Generation fills them only for its self-test, which uses them at once;
// every other key fills them on first use.
test "ML-DSA keys share one cache, filled on first use" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    for (algorithms) |algorithm| {
        var untested = try algorithm.generateKeyPair(testing.allocator, .{ .self_test = false });

        defer untested.private_key.deinit();

        defer untested.public_key.deinit();

        try testing.expect(!cached(&untested.public_key.public.shared.cache) and !cached(&untested.private_key.secret.cache));

        _ = try untested.private_key.sign(allocator, "message", .{});

        try testing.expect(cached(&untested.public_key.public.shared.cache) and cached(&untested.private_key.secret.cache));

        var pair = try algorithm.generateKeyPair(testing.allocator, .{});

        defer pair.public_key.deinit();

        try testing.expectEqual(pair.private_key.public, pair.public_key.public);

        try testing.expect(cached(&pair.public_key.public.shared.cache) and cached(&pair.private_key.secret.cache));

        const signature = try pair.private_key.sign(allocator, "message", .{});

        const seed = try pair.private_key.exportKey(allocator, .raw);

        pair.private_key.deinit();

        try testing.expect(pair.public_key.verify(signature, "message", .{}));

        var public_key = try algorithm.importPublicKey(testing.allocator, try pair.public_key.exportKey(allocator, .raw), .raw);

        defer public_key.deinit();

        try testing.expect(!cached(&public_key.public.shared.cache));

        try testing.expect(public_key.verify(signature, "message", .{}));

        try testing.expect(cached(&public_key.public.shared.cache));

        var private_key = try algorithm.importPrivateKey(testing.allocator, seed, .raw);

        defer private_key.deinit();

        try testing.expect(!cached(&private_key.public.shared.cache));

        try testing.expect(pair.public_key.verify(try private_key.sign(allocator, "other", .{}), "other", .{}));

        try testing.expect(cached(&private_key.public.shared.cache) and cached(&private_key.secret.cache));
    }
}

// Without memory for the cache, verification samples A as it goes and signing reports
// OutOfMemory.
test "ML-DSA keys without memory for their cache" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    for (algorithms) |algorithm| {
        var pair = try algorithm.generateKeyPair(testing.allocator, .{ .self_test = false });

        defer pair.private_key.deinit();

        defer pair.public_key.deinit();

        const signature = try pair.private_key.sign(allocator, "message", .{ .context = "context" });

        var public_memory = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 1 });

        var public_key = try algorithm.importPublicKey(public_memory.allocator(), try pair.public_key.exportKey(allocator, .raw), .raw);

        defer public_key.deinit();

        try testing.expect(public_key.verify(signature, "message", .{ .context = "context" }));

        try testing.expect(!public_key.verify(signature, "message", .{}));

        try testing.expect(!cached(&public_key.public.shared.cache));

        // A private key has a public and a secret part.
        var private_memory = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 2 });

        var private_key = try algorithm.importPrivateKey(private_memory.allocator(), try pair.private_key.exportKey(allocator, .raw), .raw);

        defer private_key.deinit();

        try testing.expectError(error.OutOfMemory, private_key.sign(allocator, "message", .{}));

        var workspace_memory = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 1 });

        try testing.expectError(error.OutOfMemory, pair.private_key.sign(workspace_memory.allocator(), "message", .{}));
    }
}

// Threads that use a fresh key at the same time each compute the caches; one copy of each is kept.
test "ML-DSA caches under concurrent first use" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    var pair = try pq.ml_dsa_65.generateKeyPair(testing.allocator, .{ .self_test = false });

    defer pair.private_key.deinit();

    defer pair.public_key.deinit();

    const signature = try pair.private_key.sign(allocator, "message", .{});

    var public_key = try pq.ml_dsa_65.importPublicKey(testing.allocator, try pair.public_key.exportKey(allocator, .raw), .raw);

    defer public_key.deinit();

    var private_key = try pq.ml_dsa_65.importPrivateKey(testing.allocator, try pair.private_key.exportKey(allocator, .raw), .raw);

    defer private_key.deinit();

    var verified: [4]bool = undefined;

    var signatures: [4][]u8 = undefined;

    var threads: [8]std.Thread = undefined;

    const Worker = struct {
        fn verify(key: *const pq.SignaturePublicKey, data: []const u8, out: *bool) void {
            out.* = key.verify(data, "message", .{});
        }

        fn sign(key: *const pq.SignaturePrivateKey, out: *[]u8) void {
            out.* = key.sign(testing.allocator, "message", .{}) catch unreachable;
        }
    };

    for (threads[0..4], &verified) |*thread, *result| thread.* = try std.Thread.spawn(.{}, Worker.verify, .{ &public_key, signature, result });

    for (threads[4..], &signatures) |*thread, *result| thread.* = try std.Thread.spawn(.{}, Worker.sign, .{ &private_key, result });

    for (threads) |thread| thread.join();

    for (verified) |result| try testing.expect(result);

    for (signatures) |result| {
        defer testing.allocator.free(result);

        try testing.expect(public_key.verify(result, "message", .{}));
    }
}

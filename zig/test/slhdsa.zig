const std = @import("std");
const pq = @import("crypto_pq");
const vectors = @import("vectors");

const mldsa = @import("mldsa.zig");

const testing = std.testing;

const hazmat = pq.hazmat;

const Allocator = std.mem.Allocator;

const algorithms = [_]pq.SignatureAlgorithm{
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

fn algorithmNamed(name: []const u8) !pq.SignatureAlgorithm {
    for (algorithms) |algorithm| {
        if (std.mem.eql(u8, algorithm.name, name)) return algorithm;
    }

    return error.TestUnexpectedResult;
}

fn keyGeneration(_: void, r: vectors.Record, allocator: Allocator) !void {
    const algorithm = try algorithmNamed(r.header.get("parameterSet"));

    const seed = try std.mem.concat(allocator, u8, &.{
        try vectors.decode(allocator, r.values.get("skSeed")),
        try vectors.decode(allocator, r.values.get("skPrf")),
        try vectors.decode(allocator, r.values.get("pkSeed")),
    });

    const sk = try vectors.decode(allocator, r.values.get("sk"));

    var pair = try hazmat.generateSignatureKeyPair(algorithm, seed);

    defer pair.private_key.deinit();

    try testing.expectEqualSlices(u8, try vectors.decode(allocator, r.values.get("pk")), try pair.public_key.exportKey(allocator, .raw));

    try testing.expectEqualSlices(u8, sk, try pair.private_key.exportKey(allocator, .raw));

    var imported = try algorithm.importPrivateKey(sk, .raw);

    defer imported.deinit();

    const imported_public = imported.publicKey();

    try testing.expect(imported_public.eql(&pair.public_key));

    sk[sk.len - 1] ^= 1;

    try testing.expectError(error.InvalidPrivateKey, algorithm.importPrivateKey(sk, .raw));
}

test "SLH-DSA ACVP key generation" {
    const v = try vectors.Vectors.load("acvp/SLH-DSA-keyGen.txt", "sk");

    defer v.deinit();

    try vectors.parallel(v.records, {}, keyGeneration);
}

fn signatureGeneration(_: void, r: vectors.Record, allocator: Allocator) !void {
    const algorithm = try algorithmNamed(r.header.get("parameterSet"));

    const sk = try vectors.decode(allocator, r.values.get("sk"));

    var private_key = try algorithm.importPrivateKey(sk, .raw);

    defer private_key.deinit();

    const n = sk.len / 4;

    const randomness = if (r.header.is("deterministic", "true")) sk[2 * n .. 3 * n] else try vectors.decode(allocator, r.values.get("additionalRandomness"));

    const signature = try hazmat.sign(&private_key, allocator, try vectors.decode(allocator, r.values.get("message")), randomness, .{
        .context = try vectors.decode(allocator, r.values.get("context")),
        .pre_hash = try mldsa.preHash(r),
    });

    try testing.expectEqualSlices(u8, try vectors.decode(allocator, r.values.get("signature")), signature);
}

test "SLH-DSA ACVP signature generation" {
    const v = try vectors.Vectors.load("acvp/SLH-DSA-sigGen.txt", "signature");

    defer v.deinit();

    try vectors.parallel(v.records, {}, signatureGeneration);
}

fn signatureVerification(_: void, r: vectors.Record, allocator: Allocator) !void {
    const algorithm = try algorithmNamed(r.header.get("parameterSet"));

    const public_key = try algorithm.importPublicKey(try vectors.decode(allocator, r.values.get("pk")), .raw);

    const result = hazmat.verify(&public_key, try vectors.decode(allocator, r.values.get("signature")), try vectors.decode(allocator, r.values.get("message")), .{
        .context = try vectors.decode(allocator, r.values.get("context")),
        .pre_hash = try mldsa.preHash(r),
    });

    try testing.expectEqual(r.values.is("testPassed", "true"), result);
}

test "SLH-DSA ACVP signature verification" {
    const v = try vectors.Vectors.load("acvp/SLH-DSA-sigVer.txt", "signature");

    defer v.deinit();

    try vectors.parallel(v.records, {}, signatureVerification);
}

test "SLH-DSA round trip" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const algorithm = pq.slh_dsa_shake_128f;

    var pair = try algorithm.generateKeyPair(.{ .self_test = false });

    defer pair.private_key.deinit();

    const signature = try pair.private_key.sign(allocator, "message", .{ .context = "context", .deterministic = true });

    try testing.expect(pair.public_key.verify(signature, "message", .{ .context = "context" }));

    try testing.expect(!pair.public_key.verify(signature, "message", .{}));

    try testing.expect(!pair.public_key.verify(signature[0 .. signature.len - 1], "message", .{ .context = "context" }));

    const raw = try pair.private_key.exportKey(allocator, .raw);

    for ([_]pq.KeyFormat{ .raw, .der, .pem }) |format| {
        const public_key = try algorithm.importPublicKey(try pair.public_key.exportKey(allocator, format), format);

        try testing.expect(public_key.eql(&pair.public_key));

        var private_key = try algorithm.importPrivateKey(try pair.private_key.exportKey(allocator, format), format);

        defer private_key.deinit();

        try testing.expectEqualSlices(u8, raw, try private_key.exportKey(allocator, .raw));
    }

    try testing.expectEqual(64, raw.len);

    try testing.expectError(error.InvalidOption, pair.private_key.sign(allocator, "m", .{ .pre_hash = .{ .hash = pq.sha_224 } }));
}

// RFC 9909, Appendix C: an SLH-DSA-SHA2-128s private key in PKCS#8.
test "SLH-DSA RFC 9909 private key" {
    const pem =
        \\-----BEGIN PRIVATE KEY-----
        \\MFICAQAwCwYJYIZIAWUDBAMUBECiJjvKRYYINlIxYASVI9YhZ3+tkNUetgZ6Mn4N
        \\HmSlASuBCex3fKpOHwJMz8+Ul9mRgFCSgPQlavKwevgCibSU
        \\-----END PRIVATE KEY-----
        \\
    ;

    var private_key = try pq.slh_dsa_sha2_128s.importPrivateKey(pem, .pem);

    defer private_key.deinit();

    const exported = try private_key.exportKey(testing.allocator, .pem);

    defer testing.allocator.free(exported);

    try testing.expectEqualStrings(pem, exported);
}

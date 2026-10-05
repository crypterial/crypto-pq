const std = @import("std");
const pq = @import("crypto_pq");
const vectors = @import("vectors");

const pre_hashes = @import("mldsa.zig").pre_hashes;

const testing = std.testing;

const hazmat = pq.hazmat;

const Allocator = std.mem.Allocator;

// The vectors under vectors/cross were computed by the Python reference: keys and their
// encodings, hazmat signatures with every pre-hash, implicit rejection, state blobs, and the error
// code of every malformed input.
const kems = [_]pq.KemAlgorithm{ pq.ml_kem_512, pq.ml_kem_768, pq.ml_kem_1024, pq.x_wing };

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

const stateful = [_]pq.StatefulSignatureAlgorithm{ pq.hss_lms, pq.xmss, pq.xmss_mt };

const encodings = [_]struct { format: pq.KeyFormat, suffix: []const u8 }{
    .{ .format = .der, .suffix = "Der" },
    .{ .format = .pem, .suffix = "Pem" },
};

fn named(comptime T: type, algorithms: []const T, name: []const u8) ?T {
    for (algorithms) |algorithm| {
        if (std.mem.eql(u8, algorithm.name, name)) return algorithm;
    }

    return null;
}

// A field decoded from hexadecimal; a missing field is empty.
fn field(allocator: Allocator, values: vectors.Fields, name: []const u8) ![]u8 {
    return vectors.decode(allocator, values.find(name) orelse "");
}

fn encoded(allocator: Allocator, values: vectors.Fields, prefix: []const u8, suffix: []const u8) ![]u8 {
    return field(allocator, values, try std.mem.concat(allocator, u8, &.{ prefix, suffix }));
}

fn preHash(name: ?[]const u8) !?pq.PreHash {
    const label = name orelse return null;

    if (std.mem.eql(u8, label, "none")) return null;

    for (pre_hashes) |entry| {
        if (std.mem.eql(u8, entry.name, label)) return entry.pre_hash;
    }

    return error.TestUnexpectedResult;
}

fn expectExport(allocator: Allocator, expected: []const u8, key: anytype, format: pq.KeyFormat) !void {
    try testing.expectEqualSlices(u8, expected, try key.exportKey(allocator, format));
}

// HSS levels from the comma-separated "lms" and "ots" fields, or an XMSS parameter set name.
fn parameters(allocator: Allocator, values: vectors.Fields) !pq.StatefulParameters {
    if (values.find("parameters")) |name| return .{ .name = name };

    var levels: std.ArrayList(pq.HssLevel) = .empty;

    var lms = std.mem.splitScalar(u8, values.get("lms"), ',');

    var ots = std.mem.splitScalar(u8, values.get("ots"), ',');

    while (lms.next()) |tree| {
        try levels.append(allocator, .{ .lms = tree, .ots = ots.next() orelse return error.TestUnexpectedResult });
    }

    return .{ .levels = levels.items };
}

// The rough cost of checking a record: an SLH-DSA "s" set and an XMSS tree of height 10 cost the
// most, then LM-OTS with W = 8, and SHAKE about three times SHA-2.
fn cost(r: vectors.Record) u32 {
    const name = r.values.find("parameters") orelse r.header.get("algorithm");

    var weight: u32 = 1;

    if (std.mem.startsWith(u8, name, "SLH-DSA") and std.mem.endsWith(u8, name, "s")) weight *= 10;

    if (std.mem.find(u8, name, "_10_") != null) weight *= 30;

    if (std.mem.find(u8, r.values.find("ots") orelse "", "W8") != null) weight *= 5;

    if (std.mem.find(u8, name, "SHAKE") != null) weight *= 3;

    return weight;
}

fn costlier(_: void, a: vectors.Record, b: vectors.Record) bool {
    return cost(a) > cost(b);
}

// Runs the costliest records first, so that no thread is left with a long one at the end.
fn parallelCostliestFirst(records: []const vectors.Record, comptime run: fn (void, vectors.Record, Allocator) anyerror!void) !void {
    const sorted = try testing.allocator.dupe(vectors.Record, records);

    defer testing.allocator.free(sorted);

    std.mem.sort(vectors.Record, sorted, {}, costlier);

    try vectors.parallel(sorted, {}, run);
}

// A compare-and-swap store in memory, allocating from the arena of the record being checked.
const MemoryStore = struct {
    allocator: Allocator,
    state: ?[]u8 = null,

    const vtable: pq.StateStore.VTable = .{ .read = read, .update = update };

    fn store(self: *MemoryStore) pq.StateStore {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn read(ptr: *anyopaque, allocator: Allocator) anyerror!?[]u8 {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));

        const state = self.state orelse return null;

        return try allocator.dupe(u8, state);
    }

    fn update(ptr: *anyopaque, previous: ?[]const u8, next: []const u8) anyerror!bool {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));

        const same = if (self.state) |state| previous != null and std.mem.eql(u8, state, previous.?) else previous == null;

        if (!same) return false;

        self.state = try self.allocator.dupe(u8, next);

        return true;
    }
};

fn kem(_: void, r: vectors.Record, allocator: Allocator) !void {
    const algorithm = named(pq.KemAlgorithm, &kems, r.header.get("algorithm")) orelse return error.TestUnexpectedResult;

    const seed = try field(allocator, r.values, "seed");

    const public = try field(allocator, r.values, "publicKey");

    var pair = try hazmat.generateKemKeyPair(algorithm, allocator, seed);

    defer pair.private_key.deinit();

    defer pair.public_key.deinit();

    try expectExport(allocator, public, &pair.public_key, .raw);

    try expectExport(allocator, seed, &pair.private_key, .raw);

    var imported = try algorithm.importPublicKey(allocator, public, .raw);

    defer imported.deinit();

    try testing.expect(imported.eql(&pair.public_key));

    var from_seed = try algorithm.importPrivateKey(allocator, seed, .raw);

    defer from_seed.deinit();

    var expanded_key: ?pq.KemPrivateKey = null;

    defer if (expanded_key) |*key| key.deinit();

    if (r.values.find("expandedKey")) |text| {
        for (encodings) |encoding| {
            const public_encoded = try encoded(allocator, r.values, "publicKey", encoding.suffix);

            try expectExport(allocator, public_encoded, &pair.public_key, encoding.format);

            var imported_public = try algorithm.importPublicKey(allocator, public_encoded, encoding.format);

            defer imported_public.deinit();

            try testing.expect(imported_public.eql(&pair.public_key));

            const private_encoded = try encoded(allocator, r.values, "privateKey", encoding.suffix);

            try expectExport(allocator, private_encoded, &pair.private_key, encoding.format);

            var imported_private = try algorithm.importPrivateKey(allocator, private_encoded, encoding.format);

            defer imported_private.deinit();

            try expectExport(allocator, seed, &imported_private, .raw);
        }

        const expanded = try vectors.decode(allocator, text);

        expanded_key = try algorithm.importPrivateKey(allocator, expanded, .raw);

        const key = &expanded_key.?;

        try expectExport(allocator, expanded, key, .raw);

        var key_public = key.publicKey();

        defer key_public.deinit();

        try testing.expect(key_public.eql(&pair.public_key));

        for (encodings) |encoding| {
            const expanded_encoded = try encoded(allocator, r.values, "expandedKey", encoding.suffix);

            try expectExport(allocator, expanded_encoded, key, encoding.format);

            var imported_private = try algorithm.importPrivateKey(allocator, expanded_encoded, encoding.format);

            defer imported_private.deinit();

            try expectExport(allocator, expanded, &imported_private, .raw);
        }

        var both = try algorithm.importPrivateKey(allocator, try field(allocator, r.values, "bothKeyDer"), .der);

        defer both.deinit();

        try expectExport(allocator, try field(allocator, r.values, "privateKeyDer"), &both, .der);
    }

    const encapsulation = try hazmat.encapsulate(&pair.public_key, try field(allocator, r.values, "randomness"));

    try testing.expectEqualSlices(u8, try field(allocator, r.values, "ciphertext"), encapsulation.ciphertext());

    const shared_secret = try field(allocator, r.values, "sharedSecret");

    try testing.expectEqualSlices(u8, shared_secret, &encapsulation.shared_secret);

    const tampered = try field(allocator, r.values, "tamperedCiphertext");

    const rejected = try field(allocator, r.values, "rejectedSecret");

    var keys: [3]*const pq.KemPrivateKey = .{ &pair.private_key, &from_seed, undefined };

    var count: usize = 2;

    if (expanded_key) |*key| {
        keys[2] = key;

        count = 3;
    }

    for (keys[0..count]) |key| {
        const decapsulated = try key.decapsulate(encapsulation.ciphertext());

        try testing.expectEqualSlices(u8, shared_secret, &decapsulated);

        const implicit = try key.decapsulate(tampered);

        try testing.expectEqualSlices(u8, rejected, &implicit);
    }
}

test "cross KEM vectors" {
    const v = try vectors.Vectors.load("cross/kem.txt", "seed");

    defer v.deinit();

    try vectors.parallel(v.records, {}, kem);
}

fn signature(_: void, r: vectors.Record, allocator: Allocator) !void {
    const algorithm = named(pq.SignatureAlgorithm, &signatures, r.header.get("algorithm")) orelse return error.TestUnexpectedResult;

    const seed = try vectors.decode(allocator, r.header.get("seed"));

    var pair = try hazmat.generateSignatureKeyPair(algorithm, allocator, seed);

    defer pair.private_key.deinit();

    defer pair.public_key.deinit();

    if (r.values.find("signature") == null) return signatureKey(algorithm, &pair, seed, r.values, allocator);

    const message = try field(allocator, r.values, "message");

    const context = try field(allocator, r.values, "context");

    const pre_hash = try preHash(r.values.find("preHash"));

    const signed = if (r.values.is("mode", "hazmat"))
        try hazmat.sign(&pair.private_key, allocator, message, try field(allocator, r.values, "randomness"), .{ .context = context, .pre_hash = pre_hash })
    else
        try pair.private_key.sign(allocator, message, .{ .context = context, .deterministic = true, .pre_hash = pre_hash });

    try testing.expectEqualSlices(u8, try field(allocator, r.values, "signature"), signed);

    const options: pq.VerifyOptions = .{ .context = context, .pre_hash = pre_hash };

    try testing.expect(hazmat.verify(&pair.public_key, signed, message, options));

    try testing.expectEqual(r.values.is("publicVerify", "true"), pair.public_key.verify(signed, message, options));
}

fn signatureKey(algorithm: pq.SignatureAlgorithm, pair: *const pq.SignatureKeyPair, seed: []const u8, values: vectors.Fields, allocator: Allocator) !void {
    const public = try field(allocator, values, "publicKey");

    try expectExport(allocator, public, &pair.public_key, .raw);

    var imported = try algorithm.importPublicKey(allocator, public, .raw);

    defer imported.deinit();

    try testing.expect(imported.eql(&pair.public_key));

    // ML-DSA keeps its seed as the raw private key; SLH-DSA has the 4n-byte key.
    const private: []const u8 = if (values.find("privateKey")) |text| try vectors.decode(allocator, text) else seed;

    try expectExport(allocator, private, &pair.private_key, .raw);

    var from_raw = try algorithm.importPrivateKey(allocator, private, .raw);

    defer from_raw.deinit();

    var raw_public = from_raw.publicKey();

    defer raw_public.deinit();

    try testing.expect(raw_public.eql(&pair.public_key));

    for (encodings) |encoding| {
        const public_encoded = try encoded(allocator, values, "publicKey", encoding.suffix);

        try expectExport(allocator, public_encoded, &pair.public_key, encoding.format);

        var imported_public = try algorithm.importPublicKey(allocator, public_encoded, encoding.format);

        defer imported_public.deinit();

        try testing.expect(imported_public.eql(&pair.public_key));

        const private_encoded = try encoded(allocator, values, "privateKey", encoding.suffix);

        try expectExport(allocator, private_encoded, &pair.private_key, encoding.format);

        var imported_private = try algorithm.importPrivateKey(allocator, private_encoded, encoding.format);

        defer imported_private.deinit();

        try expectExport(allocator, private, &imported_private, .raw);
    }

    const text = values.find("expandedKey") orelse return;

    const expanded = try vectors.decode(allocator, text);

    var key = try algorithm.importPrivateKey(allocator, expanded, .raw);

    defer key.deinit();

    try expectExport(allocator, expanded, &key, .raw);

    var key_public = key.publicKey();

    defer key_public.deinit();

    try testing.expect(key_public.eql(&pair.public_key));

    for (encodings) |encoding| {
        const expanded_encoded = try encoded(allocator, values, "expandedKey", encoding.suffix);

        try expectExport(allocator, expanded_encoded, &key, encoding.format);

        var imported_private = try algorithm.importPrivateKey(allocator, expanded_encoded, encoding.format);

        defer imported_private.deinit();

        try expectExport(allocator, expanded, &imported_private, .raw);
    }

    var both = try algorithm.importPrivateKey(allocator, try field(allocator, values, "bothKeyDer"), .der);

    defer both.deinit();

    try expectExport(allocator, try field(allocator, values, "privateKeyDer"), &both, .der);
}

test "cross ML-DSA vectors" {
    const v = try vectors.Vectors.load("cross/mldsa.txt", "signature");

    defer v.deinit();

    try vectors.parallel(v.records, {}, signature);
}

test "cross SLH-DSA vectors" {
    const v = try vectors.Vectors.load("cross/slhdsa.txt", "signature");

    defer v.deinit();

    try parallelCostliestFirst(v.records, signature);
}

fn statefulKey(_: void, r: vectors.Record, allocator: Allocator) !void {
    const algorithm = named(pq.StatefulSignatureAlgorithm, &stateful, r.header.get("algorithm")) orelse return error.TestUnexpectedResult;

    const public = try field(allocator, r.values, "publicKey");

    const message = try field(allocator, r.values, "message");

    const expected = try field(allocator, r.values, "signature");

    const state = try field(allocator, r.values, "state");

    const after = try field(allocator, r.values, "stateAfter");

    const remaining = try vectors.number(u64, r.values.get("remaining"));

    var store: MemoryStore = .{ .allocator = allocator };

    var pair = try hazmat.generateStatefulKeyPair(algorithm, allocator, try parameters(allocator, r.values), try field(allocator, r.values, "seed"), try vectors.number(u64, r.values.get("index")), store.store(), .{});

    defer pair.private_key.deinit(allocator);

    try testing.expectEqualSlices(u8, state, store.state.?);

    try expectExport(allocator, public, &pair.public_key, .raw);

    for (encodings) |encoding| {
        const public_encoded = try encoded(allocator, r.values, "publicKey", encoding.suffix);

        try expectExport(allocator, public_encoded, &pair.public_key, encoding.format);

        const imported = try algorithm.importPublicKey(public_encoded, encoding.format);

        try testing.expect(imported.eql(&pair.public_key));
    }

    try testing.expectEqual(remaining, pair.private_key.remainingSignatures());

    try testing.expectEqualSlices(u8, expected, try pair.private_key.sign(allocator, message));

    try testing.expectEqualSlices(u8, after, store.state.?);

    try testing.expectEqual(remaining - 1, pair.private_key.remainingSignatures());

    try testing.expect(pair.public_key.verify(expected, message));

    // The key loaded from the first state signs at the same index, the same way.
    var loaded_store: MemoryStore = .{ .allocator = allocator, .state = state };

    var loaded = try algorithm.loadPrivateKey(allocator, loaded_store.store(), .{});

    defer loaded.deinit(allocator);

    const loaded_public = loaded.publicKey();

    try testing.expect(loaded_public.eql(&pair.public_key));

    try testing.expectEqual(remaining, loaded.remainingSignatures());

    try testing.expectEqualSlices(u8, expected, try loaded.sign(allocator, message));

    try testing.expectEqualSlices(u8, after, loaded_store.state.?);

    try testing.expectEqual(remaining - 1, loaded.remainingSignatures());
}

test "cross HSS vectors" {
    const v = try vectors.Vectors.load("cross/hss.txt", "stateAfter");

    defer v.deinit();

    try parallelCostliestFirst(v.records, statefulKey);
}

test "cross XMSS vectors" {
    const v = try vectors.Vectors.load("cross/xmss.txt", "stateAfter");

    defer v.deinit();

    try parallelCostliestFirst(v.records, statefulKey);
}

// Each export is made again, and every cache loads, or fails to, as the reference decided; a key
// that loads signs as the reference did.
fn treeCache(_: void, r: vectors.Record, allocator: Allocator) !void {
    errdefer std.debug.print("tree cache record failed: {s}: {s}\n", .{ r.header.get("algorithm"), r.values.get("name") });

    const algorithm = named(pq.StatefulSignatureAlgorithm, &stateful, r.header.get("algorithm")) orelse return error.TestUnexpectedResult;

    const state = try field(allocator, r.values, "state");

    const cache = try field(allocator, r.values, "treeCache");

    if (r.values.is("operation", "export")) {
        var store: MemoryStore = .{ .allocator = allocator };

        var pair = try hazmat.generateStatefulKeyPair(algorithm, allocator, try parameters(allocator, r.values), try field(allocator, r.values, "seed"), try vectors.number(u64, r.values.get("index")), store.store(), .{});

        defer pair.private_key.deinit(allocator);

        if (r.values.is("signed", "true")) _ = try pair.private_key.sign(allocator, try field(allocator, r.values, "message"));

        try testing.expectEqualSlices(u8, cache, try pair.private_key.exportTreeCache(allocator));

        try testing.expectEqualSlices(u8, state, store.state.?);
    }

    var store: MemoryStore = .{ .allocator = allocator, .state = state };

    var key = algorithm.loadPrivateKey(allocator, store.store(), .{ .tree_cache = cache }) catch |err| {
        try testing.expectEqualStrings(r.values.get("result"), code(err));

        return;
    };

    defer key.deinit(allocator);

    try testing.expectEqualStrings("ok", r.values.get("result"));

    const public_key = key.publicKey();

    try expectExport(allocator, try field(allocator, r.values, "publicKey"), &public_key, .raw);

    try testing.expectEqual(try vectors.number(u64, r.values.get("remaining")), key.remainingSignatures());

    if (r.values.find("signature") != null) {
        try testing.expectEqualSlices(u8, try field(allocator, r.values, "signature"), try key.sign(allocator, try field(allocator, r.values, "message")));
    }
}

test "cross tree cache vectors" {
    const v = try vectors.Vectors.load("cross/treecache.txt", "treeCache");

    defer v.deinit();

    try parallelCostliestFirst(v.records, treeCache);
}

// The result of one error-table record: "ok", "true", "false" or an error code, with the output
// and the remaining signatures it produced.
const Outcome = struct {
    result: []const u8,
    output: ?[]const u8 = null,
    remaining: ?u64 = null,
};

fn code(err: anyerror) []const u8 {
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

fn failed(err: anyerror) Outcome {
    return .{ .result = code(err) };
}

fn finished(result: anyerror![]const u8) Outcome {
    return .{ .result = "ok", .output = result catch |err| return failed(err) };
}

fn answered(value: bool) Outcome {
    return .{ .result = if (value) "true" else "false" };
}

fn is(operation: []const u8, expected: []const u8) bool {
    return std.mem.eql(u8, operation, expected);
}

fn execute(r: vectors.Record, allocator: Allocator) !Outcome {
    const name = r.header.get("algorithm");

    const operation = r.values.get("operation");

    const data = try field(allocator, r.values, "input");

    const key = try field(allocator, r.values, "key");

    const message = try field(allocator, r.values, "message");

    const randomness = try field(allocator, r.values, "randomness");

    const context = try field(allocator, r.values, "context");

    const pre_hash = try preHash(r.values.find("preHash"));

    const format: pq.KeyFormat = if (r.values.find("format")) |text| std.meta.stringToEnum(pq.KeyFormat, text) orelse return error.TestUnexpectedResult else .raw;

    if (named(pq.KemAlgorithm, &kems, name)) |algorithm| {
        if (is(operation, "importPublicKey")) {
            var public_key = algorithm.importPublicKey(allocator, data, format) catch |err| return failed(err);

            defer public_key.deinit();

            return finished(public_key.exportKey(allocator, .raw));
        }

        if (is(operation, "importPrivateKey") or is(operation, "decapsulate")) {
            var private_key = algorithm.importPrivateKey(allocator, if (is(operation, "decapsulate")) key else data, if (is(operation, "decapsulate")) .raw else format) catch |err| return failed(err);

            defer private_key.deinit();

            var public_key = private_key.publicKey();

            defer public_key.deinit();

            if (is(operation, "importPrivateKey")) return finished(public_key.exportKey(allocator, .raw));

            const shared_secret = private_key.decapsulate(data) catch |err| return failed(err);

            return .{ .result = "ok", .output = try allocator.dupe(u8, &shared_secret) };
        }

        if (is(operation, "exportPublicKey") or is(operation, "exportPrivateKey") or is(operation, "generate")) {
            var pair = hazmat.generateKemKeyPair(algorithm, allocator, if (is(operation, "generate")) data else key) catch |err| return failed(err);

            defer pair.private_key.deinit();

            defer pair.public_key.deinit();

            if (is(operation, "exportPrivateKey")) return finished(pair.private_key.exportKey(allocator, format));

            return finished(pair.public_key.exportKey(allocator, if (is(operation, "generate")) .raw else format));
        }

        if (is(operation, "encapsulate")) {
            var public_key = algorithm.importPublicKey(allocator, key, .raw) catch |err| return failed(err);

            defer public_key.deinit();

            const encapsulation = hazmat.encapsulate(&public_key, randomness) catch |err| return failed(err);

            return .{ .result = "ok", .output = try std.mem.concat(allocator, u8, &.{ &encapsulation.shared_secret, encapsulation.ciphertext() }) };
        }
    } else if (named(pq.SignatureAlgorithm, &signatures, name)) |algorithm| {
        if (is(operation, "importPublicKey")) {
            var public_key = algorithm.importPublicKey(allocator, data, format) catch |err| return failed(err);

            defer public_key.deinit();

            return finished(public_key.exportKey(allocator, .raw));
        }

        if (is(operation, "importPrivateKey") or is(operation, "sign") or is(operation, "hazmatSign")) {
            var private_key = algorithm.importPrivateKey(allocator, if (is(operation, "importPrivateKey")) data else key, if (is(operation, "importPrivateKey")) format else .raw) catch |err| return failed(err);

            defer private_key.deinit();

            var public_key = private_key.publicKey();

            defer public_key.deinit();

            if (is(operation, "importPrivateKey")) return finished(public_key.exportKey(allocator, .raw));

            if (is(operation, "sign")) return finished(private_key.sign(allocator, message, .{ .context = context, .deterministic = true, .pre_hash = pre_hash }));

            return finished(hazmat.sign(&private_key, allocator, message, randomness, .{ .context = context, .pre_hash = pre_hash }));
        }

        if (is(operation, "generate")) {
            var pair = hazmat.generateSignatureKeyPair(algorithm, allocator, data) catch |err| return failed(err);

            defer pair.private_key.deinit();

            defer pair.public_key.deinit();

            return finished(pair.public_key.exportKey(allocator, .raw));
        }

        if (is(operation, "verify") or is(operation, "hazmatVerify")) {
            var public_key = try algorithm.importPublicKey(allocator, key, .raw);

            defer public_key.deinit();

            const options: pq.VerifyOptions = .{ .context = context, .pre_hash = pre_hash };

            if (is(operation, "verify")) return answered(public_key.verify(data, message, options));

            return answered(hazmat.verify(&public_key, data, message, options));
        }
    } else if (named(pq.StatefulSignatureAlgorithm, &stateful, name)) |algorithm| {
        if (is(operation, "importPublicKey")) {
            const public_key = algorithm.importPublicKey(data, format) catch |err| return failed(err);

            return finished(public_key.exportKey(allocator, .raw));
        }

        if (is(operation, "verify")) {
            const public_key = try algorithm.importPublicKey(key, .raw);

            return answered(public_key.verify(data, message));
        }

        var store: MemoryStore = .{ .allocator = allocator };

        if (is(operation, "generate")) {
            var pair = hazmat.generateStatefulKeyPair(algorithm, allocator, try parameters(allocator, r.values), data, try vectors.number(u64, r.values.get("index")), store.store(), .{}) catch |err| return failed(err);

            defer pair.private_key.deinit(allocator);

            return .{ .result = "ok", .output = try pair.public_key.exportKey(allocator, .raw), .remaining = pair.private_key.remainingSignatures() };
        }

        store.state = data;

        if (is(operation, "loadPrivateKey") or is(operation, "sign")) {
            var private_key = algorithm.loadPrivateKey(allocator, store.store(), .{}) catch |err| return failed(err);

            defer private_key.deinit(allocator);

            if (is(operation, "sign")) return finished(private_key.sign(allocator, message));

            const public_key = private_key.publicKey();

            return .{ .result = "ok", .output = try public_key.exportKey(allocator, .raw), .remaining = private_key.remainingSignatures() };
        }
    }

    std.debug.print("unknown operation {s} for {s}\n", .{ operation, name });

    return error.TestUnexpectedResult;
}

fn errorCase(_: void, r: vectors.Record, allocator: Allocator) !void {
    const outcome = try execute(r, allocator);

    var same = std.mem.eql(u8, outcome.result, r.values.get("result"));

    if (r.values.find("output")) |text| {
        same = same and outcome.output != null and std.mem.eql(u8, try vectors.decode(allocator, text), outcome.output.?);
    }

    if (r.values.find("remaining")) |text| {
        same = same and outcome.remaining != null and outcome.remaining.? == try vectors.number(u64, text);
    }

    if (!same) {
        std.debug.print("{s}: {s}: got {s}, expected {s}\n", .{ r.header.get("algorithm"), r.values.get("name"), outcome.result, r.values.get("result") });

        return error.TestUnexpectedResult;
    }
}

// Every record runs, so that one run lists every disagreement.
test "cross error codes" {
    const v = try vectors.Vectors.load("cross/errors.txt", "result");

    defer v.deinit();

    try vectors.parallel(v.records, {}, errorCase);
}

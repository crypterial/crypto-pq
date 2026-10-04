const std = @import("std");
const pq = @import("crypto_pq");
const vectors = @import("vectors");

const testing = std.testing;

const hazmat = pq.hazmat;

const Allocator = std.mem.Allocator;

const small = [_]pq.HssLevel{.{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W1" }};

// A compare-and-swap store in memory; `broken` makes every update of an existing state fail, and
// `writes` counts the successful updates.
const MemoryStore = struct {
    state: ?[]u8 = null,
    broken: bool = false,
    writes: usize = 0,

    const vtable: pq.StateStore.VTable = .{ .read = read, .update = update };

    fn init(state: ?[]const u8) !MemoryStore {
        return .{ .state = if (state) |s| try testing.allocator.dupe(u8, s) else null };
    }

    fn deinit(self: *MemoryStore) void {
        if (self.state) |state| testing.allocator.free(state);
    }

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

        if (self.broken and previous != null) return error.DiskFull;

        const same = if (self.state) |state| previous != null and std.mem.eql(u8, state, previous.?) else previous == null;

        if (!same) return false;

        const copy = try testing.allocator.dupe(u8, next);

        self.deinit();

        self.state = copy;

        self.writes += 1;

        return true;
    }

    // The index that the stored state holds.
    fn index(self: *const MemoryStore) u64 {
        const state = self.state.?;

        return std.mem.readInt(u64, state[if (state[1] == 1) state.len - 24 else 6..][0..8], .big);
    }
};

const families = [_]struct { lms: []const u8, ots: []const u8, n: usize }{
    .{ .lms = "SHA256_M32", .ots = "SHA256_N32", .n = 32 },
    .{ .lms = "SHA256_M24", .ots = "SHA256_N24", .n = 24 },
    .{ .lms = "SHAKE_M32", .ots = "SHAKE_N32", .n = 32 },
    .{ .lms = "SHAKE_M24", .ots = "SHAKE_N24", .n = 24 },
};

const heights = [_]u6{ 5, 10, 15, 20, 25 };

const widths = [_]usize{ 1, 2, 4, 8 };

const lms_names = blk: {
    var names: [20][]const u8 = undefined;

    for (families, 0..) |family, i| {
        for (heights, 0..) |h, j| names[5 * i + j] = std.fmt.comptimePrint("LMS_{s}_H{d}", .{ family.lms, h });
    }

    break :blk names;
};

const ots_names = blk: {
    var names: [16][]const u8 = undefined;

    for (families, 0..) |family, i| {
        for (widths, 0..) |w, j| names[4 * i + j] = std.fmt.comptimePrint("LMOTS_{s}_W{d}", .{ family.ots, w });
    }

    break :blk names;
};

// The parameters of one HSS level, recovered from a public key so that the RFC vectors can be
// reproduced: the type names, the height, the hash size and the signature size.
const LevelInfo = struct {
    level: pq.HssLevel,
    h: u6,
    m: usize,
    signature_size: usize,
};

fn levelInfo(key: []const u8) LevelInfo {
    const lms = std.mem.readInt(u32, key[0..4], .big) - 5;

    const ots = std.mem.readInt(u32, key[4..8], .big) - 1;

    const h = heights[lms % 5];

    const m = families[lms / 5].n;

    const n = families[ots / 4].n;

    const w = widths[ots % 4];

    const u = (8 * n + w - 1) / w;

    const v = (std.math.log2_int(usize, ((@as(usize, 1) << @intCast(w)) - 1) * u) + 1 + w - 1) / w;

    return .{
        .level = .{ .lms = lms_names[lms], .ots = ots_names[ots] },
        .h = h,
        .m = m,
        .signature_size = 8 + 4 + n * (u + v + 1) + h * m,
    };
}

// The levels of an HSS key from its public key and the child keys in a signature, and the index
// that the signature was made with.
fn hssLevels(public: []const u8, signature: []const u8, levels: *[8]pq.HssLevel) struct { []const pq.HssLevel, u64, u6 } {
    const count = std.mem.readInt(u32, public[0..4], .big);

    var key = public[4..];

    var offset: usize = 4;

    var index: u64 = 0;

    var height: u6 = 0;

    for (0..count) |level| {
        const info = levelInfo(key);

        levels[level] = info.level;

        index = (index << info.h) | std.mem.readInt(u32, signature[offset..][0..4], .big);

        height += info.h;

        offset += info.signature_size;

        if (level + 1 < count) {
            key = signature[offset..][0 .. 24 + levelInfo(signature[offset..]).m];

            offset += key.len;
        }
    }

    return .{ levels[0..count], index, height };
}

fn acvpKeyGeneration(_: void, r: vectors.Record, allocator: Allocator) !void {
    var store: MemoryStore = .{};

    defer store.deinit();

    const levels = [_]pq.HssLevel{.{ .lms = r.header.get("lmsMode"), .ots = r.header.get("lmOtsMode") }};

    const seed = try std.mem.concat(allocator, u8, &.{ try vectors.decode(allocator, r.values.get("i")), try vectors.decode(allocator, r.values.get("seed")) });

    var pair = try hazmat.generateStatefulKeyPair(pq.hss_lms, allocator, .{ .levels = &levels }, seed, 0, store.store(), .{});

    defer pair.private_key.deinit(allocator);

    const expected = try std.mem.concat(allocator, u8, &.{ &.{ 0, 0, 0, 1 }, try vectors.decode(allocator, r.values.get("publicKey")) });

    try testing.expectEqualSlices(u8, expected, try pair.public_key.exportKey(allocator, .raw));
}

test "HSS ACVP key generation" {
    const v = try vectors.Vectors.load("acvp/LMS-keyGen.txt", "publicKey");

    defer v.deinit();

    try vectors.parallel(v.records, {}, acvpKeyGeneration);
}

fn acvpVerification(_: void, r: vectors.Record, allocator: Allocator) !void {
    const key = try std.mem.concat(allocator, u8, &.{ &.{ 0, 0, 0, 1 }, try vectors.decode(allocator, r.header.get("publicKey")) });

    const public_key = try pq.hss_lms.importPublicKey(key, .raw);

    const signature = try std.mem.concat(allocator, u8, &.{ &.{ 0, 0, 0, 0 }, try vectors.decode(allocator, r.values.get("signature")) });

    try testing.expectEqual(r.values.is("testPassed", "true"), public_key.verify(signature, try vectors.decode(allocator, r.values.get("message"))));
}

test "HSS ACVP verification" {
    const v = try vectors.Vectors.load("acvp/LMS-sigVer.txt", "signature");

    defer v.deinit();

    try vectors.parallel(v.records, {}, acvpVerification);
}

// RFC 8554 Test Case 2 and the RFC 9858 vectors are reproduced from their seeds; only the
// height-20 tree of RFC 9858 A.4 waits for CRYPTO_PQ_SLOW=1.
fn rfcVector(slow: bool, r: vectors.Record, allocator: Allocator) !void {
    const public = try vectors.decode(allocator, r.values.get("publicKey"));

    const message = try vectors.decode(allocator, r.values.get("message"));

    const signature = try vectors.decode(allocator, r.values.get("signature"));

    const public_key = try pq.hss_lms.importPublicKey(public, .raw);

    try testing.expect(public_key.verify(signature, message));

    const tampered = try allocator.dupe(u8, signature);

    tampered[tampered.len - 1] ^= 1;

    try testing.expect(!public_key.verify(tampered, message));

    try testing.expect(!public_key.verify(signature, try std.mem.concat(allocator, u8, &.{ message, &.{0} })));

    const seed = r.values.find("seed") orelse return;

    var buffer: [8]pq.HssLevel = undefined;

    const levels, const index, const height = hssLevels(public, signature, &buffer);

    if (height >= 20 and !slow) return;

    var store: MemoryStore = .{};

    defer store.deinit();

    const key_seed = try std.mem.concat(allocator, u8, &.{ try vectors.decode(allocator, r.values.get("i")), try vectors.decode(allocator, seed) });

    var pair = try hazmat.generateStatefulKeyPair(pq.hss_lms, allocator, .{ .levels = levels }, key_seed, index, store.store(), .{});

    defer pair.private_key.deinit(allocator);

    try testing.expectEqualSlices(u8, public, try pair.public_key.exportKey(allocator, .raw));

    try testing.expectEqualSlices(u8, signature, try pair.private_key.sign(allocator, message));
}

test "HSS RFC vectors" {
    const v = try vectors.Vectors.load("rfc/hss.txt", "signature");

    defer v.deinit();

    try vectors.parallel(v.records, vectors.slow(), rfcVector);
}

test "HSS state handling" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    var store: MemoryStore = .{};

    defer store.deinit();

    var pair = try pq.hss_lms.generateKeyPair(testing.allocator, .{ .levels = &small }, store.store(), .{});

    defer pair.private_key.deinit(testing.allocator);

    try testing.expectEqual(32, pair.private_key.remainingSignatures());

    const first = try pair.private_key.sign(allocator, "one");

    const second = try pair.private_key.sign(allocator, "two");

    try testing.expect(pair.public_key.verify(first, "one"));

    try testing.expect(pair.public_key.verify(second, "two"));

    try testing.expect(!pair.public_key.verify(first, "two"));

    try testing.expectEqual(30, pair.private_key.remainingSignatures());

    var loaded = try pq.hss_lms.loadPrivateKey(testing.allocator, store.store(), .{});

    defer loaded.deinit(testing.allocator);

    const loaded_public = loaded.publicKey();

    try testing.expect(loaded_public.eql(&pair.public_key));

    try testing.expectEqual(30, loaded.remainingSignatures());

    const third = try loaded.sign(allocator, "three");

    try testing.expectEqual(2, std.mem.readInt(u32, third[4..8], .big));

    try testing.expectError(error.StateConflict, pair.private_key.sign(allocator, "stale"));

    while (loaded.remainingSignatures() > 0) _ = try loaded.sign(allocator, "m");

    try testing.expectError(error.KeyExhausted, loaded.sign(allocator, "m"));

    try testing.expectError(error.StateConflict, pq.hss_lms.generateKeyPair(testing.allocator, .{ .levels = &small }, store.store(), .{}));
}

test "HSS store failures" {
    var broken: MemoryStore = .{ .broken = true };

    defer broken.deinit();

    var pair = try pq.hss_lms.generateKeyPair(testing.allocator, .{ .levels = &small }, broken.store(), .{});

    defer pair.private_key.deinit(testing.allocator);

    try testing.expectError(error.StatePersistFailed, pair.private_key.sign(testing.allocator, "m"));

    try testing.expectEqual(32, pair.private_key.remainingSignatures());

    var damaged = try MemoryStore.init(broken.state);

    defer damaged.deinit();

    damaged.state.?[damaged.state.?.len - 20] ^= 1;

    try testing.expectError(error.InvalidPrivateKey, pq.hss_lms.loadPrivateKey(testing.allocator, damaged.store(), .{}));

    var empty: MemoryStore = .{};

    try testing.expectError(error.InvalidPrivateKey, pq.hss_lms.loadPrivateKey(testing.allocator, empty.store(), .{}));

    var copy = try MemoryStore.init(broken.state);

    defer copy.deinit();

    try testing.expectError(error.AlgorithmMismatch, pq.xmss.loadPrivateKey(testing.allocator, copy.store(), .{}));
}

test "HSS parameters" {
    const h25: pq.HssLevel = .{ .lms = "LMS_SHA256_M24_H25", .ots = "LMOTS_SHA256_N24_W8" };

    const invalid = [_]pq.StatefulParameters{
        .{ .levels = &.{} },
        .{ .levels = &(small ** 9) },
        .{ .levels = &.{.{ .lms = "LMS_SHA256_M32_H5", .ots = "LMOTS_SHA256_N24_W1" }} },
        .{ .levels = &.{.{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHAKE_N24_W1" }} },
        .{ .name = "LMS_SHA256_M24_H5" },
        .{ .levels = &.{.{ .lms = "LMS_X", .ots = "LMOTS_SHA256_N24_W1" }} },
        .{ .levels = &.{ h25, h25, .{ .lms = "LMS_SHA256_M24_H15", .ots = "LMOTS_SHA256_N24_W8" } } },
    };

    for (invalid) |parameters| {
        var store: MemoryStore = .{};

        try testing.expectError(error.InvalidOption, pq.hss_lms.generateKeyPair(testing.allocator, parameters, store.store(), .{}));

        try testing.expect(store.state == null);
    }
}

test "HSS tree boundary" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const levels = [_]pq.HssLevel{.{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W4" }} ** 2;

    var store: MemoryStore = .{};

    defer store.deinit();

    const zeros: [40]u8 = @splat(0);

    var pair = try hazmat.generateStatefulKeyPair(pq.hss_lms, testing.allocator, .{ .levels = &levels }, &zeros, 31, store.store(), .{});

    defer pair.private_key.deinit(testing.allocator);

    const first = try pair.private_key.sign(allocator, &.{0});

    const second = try pair.private_key.sign(allocator, &.{1});

    try testing.expect(pair.public_key.verify(first, &.{0}));

    try testing.expect(pair.public_key.verify(second, &.{1}));

    try testing.expect(!std.mem.eql(u8, first[4..8], second[4..8]));
}

test "HSS formats" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    var store: MemoryStore = .{};

    defer store.deinit();

    var pair = try pq.hss_lms.generateKeyPair(testing.allocator, .{ .levels = &small }, store.store(), .{});

    defer pair.private_key.deinit(testing.allocator);

    for ([_]pq.KeyFormat{ .raw, .der, .pem }) |format| {
        const public_key = try pq.hss_lms.importPublicKey(try pair.public_key.exportKey(allocator, format), format);

        try testing.expect(public_key.eql(&pair.public_key));
    }

    const der = try pair.public_key.exportKey(allocator, .der);

    try testing.expect(std.mem.find(u8, der, &.{ 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x03, 0x11 }) != null);

    const raw = try pair.public_key.exportKey(allocator, .raw);

    try testing.expectError(error.InvalidPublicKey, pq.hss_lms.importPublicKey(try std.mem.concat(allocator, u8, &.{ &.{ 0, 0, 0, 9 }, raw[4..] }), .raw));

    try testing.expectError(error.AlgorithmMismatch, pq.xmss.importPublicKey(der, .der));
}

fn xmssVector(_: void, r: vectors.Record, allocator: Allocator) !void {
    const name = r.values.get("name");

    const algorithm = if (std.mem.startsWith(u8, name, "XMSSMT")) pq.xmss_mt else pq.xmss;

    const index = try vectors.number(u64, r.values.get("index"));

    const message = try vectors.decode(allocator, r.values.get("message"));

    const public = try vectors.decode(allocator, r.values.get("publicKey"));

    const signature = try vectors.decode(allocator, r.values.get("signature"));

    const public_key = try algorithm.importPublicKey(public, .raw);

    try testing.expect(public_key.verify(signature, message));

    const tampered = try allocator.dupe(u8, signature);

    tampered[tampered.len - 1] ^= 1;

    try testing.expect(!public_key.verify(tampered, message));

    var store: MemoryStore = .{};

    defer store.deinit();

    var pair = try hazmat.generateStatefulKeyPair(algorithm, allocator, .{ .name = name }, try vectors.decode(allocator, r.values.get("seed")), index, store.store(), .{});

    defer pair.private_key.deinit(allocator);

    try testing.expectEqualSlices(u8, public, try pair.public_key.exportKey(allocator, .raw));

    try testing.expectEqualSlices(u8, signature, try pair.private_key.sign(allocator, message));
}

test "XMSS reference vectors" {
    const v = try vectors.Vectors.load("xmss/xmss.txt", "signature");

    defer v.deinit();

    try vectors.parallel(v.records, {}, xmssVector);
}

test "XMSS state handling" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    var store: MemoryStore = .{};

    defer store.deinit();

    var pair = try pq.xmss_mt.generateKeyPair(testing.allocator, .{ .name = "XMSSMT-SHAKE256_20/4_192" }, store.store(), .{});

    defer pair.private_key.deinit(testing.allocator);

    const signature = try pair.private_key.sign(allocator, "message");

    try testing.expect(pair.public_key.verify(signature, "message"));

    var loaded = try pq.xmss_mt.loadPrivateKey(testing.allocator, store.store(), .{});

    defer loaded.deinit(testing.allocator);

    try testing.expectEqual((1 << 20) - 1, loaded.remainingSignatures());

    for ([_]pq.KeyFormat{ .raw, .der, .pem }) |format| {
        const public_key = try pq.xmss_mt.importPublicKey(try pair.public_key.exportKey(allocator, format), format);

        try testing.expect(public_key.eql(&pair.public_key));
    }

    var other: MemoryStore = .{};

    try testing.expectError(error.InvalidOption, pq.xmss.generateKeyPair(testing.allocator, .{ .name = "XMSSMT-SHAKE256_20/4_192" }, other.store(), .{}));
}

fn sequence(comptime n: usize) [n]u8 {
    var bytes: [n]u8 = undefined;

    for (&bytes, 0..) |*byte, i| byte.* = @intCast(i);

    return bytes;
}

fn expectHex(expected: []const u8, actual: []const u8) !void {
    var buffer: [512]u8 = undefined;

    try testing.expectEqualSlices(u8, try std.fmt.hexToBytes(&buffer, expected), actual);
}

// Values computed with the Python reference: every implementation writes byte-identical states.
test "stateful state compatibility" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    var store: MemoryStore = .{};

    defer store.deinit();

    var hss = try hazmat.generateStatefulKeyPair(pq.hss_lms, testing.allocator, .{ .levels = &small }, &sequence(40), 3, store.store(), .{});

    defer hss.private_key.deinit(testing.allocator);

    try expectHex("0101010000000a00000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627000000000000000332b414e1d42dc2866aeed26f724a5be7", store.state.?);

    try expectHex("000000010000000a00000005000102030405060708090a0b0c0d0e0f224f2491ed07b8b55134c2b6ea3163d0e60e423ce46b051b", try hss.public_key.exportKey(allocator, .raw));

    const signature = try hss.private_key.sign(allocator, "crypto-pq");

    try expectHex("0101010000000a00000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262700000000000000047bc402dcf96640ca1c7126fe316fef60", store.state.?);

    var digest: [32]u8 = undefined;

    pq.sha_256.digest(signature, &digest);

    try expectHex("07cb93b630cdd6b575402bcdbce2024b6a88bfdb419d9c7b920c250d7273a5a6", &digest);

    var xmss_store: MemoryStore = .{};

    defer xmss_store.deinit();

    var xmss = try hazmat.generateStatefulKeyPair(pq.xmss_mt, testing.allocator, .{ .name = "XMSSMT-SHAKE256_20/4_192" }, &sequence(72), 5, xmss_store.store(), .{});

    defer xmss.private_key.deinit(testing.allocator);

    try expectHex("0103000000320000000000000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647e0dc0d3f343f3dbd989a24e2ad453440", xmss_store.state.?);

    try expectHex("00000032296d594ddd9688b47a9c461c70e3d9f29e901b8cedcaaa4c303132333435363738393a3b3c3d3e3f4041424344454647", try xmss.public_key.exportKey(allocator, .raw));

    for ([_]struct { algorithm: pq.StatefulSignatureAlgorithm, state: []const u8, public_key: *const pq.StatefulPublicKey }{
        .{ .algorithm = pq.hss_lms, .state = store.state.?, .public_key = &hss.public_key },
        .{ .algorithm = pq.xmss_mt, .state = xmss_store.state.?, .public_key = &xmss.public_key },
    }) |case| {
        var fresh = try MemoryStore.init(case.state);

        defer fresh.deinit();

        var loaded = try case.algorithm.loadPrivateKey(testing.allocator, fresh.store(), .{});

        defer loaded.deinit(testing.allocator);

        const public_key = loaded.publicKey();

        try testing.expect(public_key.eql(case.public_key));
    }
}

// A store that tries to sign with the key while the key is writing its next state, standing in for
// a second thread: the inner call must be refused instead of reusing the index.
const ReentrantStore = struct {
    inner: MemoryStore = .{},
    key: ?*pq.StatefulPrivateKey = null,
    result: ?anyerror = null,
    remaining: ?u64 = null,

    const vtable: pq.StateStore.VTable = .{ .read = read, .update = update };

    fn store(self: *ReentrantStore) pq.StateStore {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn read(ptr: *anyopaque, allocator: Allocator) anyerror!?[]u8 {
        const self: *ReentrantStore = @ptrCast(@alignCast(ptr));

        return MemoryStore.read(&self.inner, allocator);
    }

    fn update(ptr: *anyopaque, previous: ?[]const u8, next: []const u8) anyerror!bool {
        const self: *ReentrantStore = @ptrCast(@alignCast(ptr));

        if (self.key) |key| {
            self.key = null;

            self.remaining = key.remainingSignatures();

            if (key.sign(testing.allocator, "inner")) |signature| {
                testing.allocator.free(signature);
            } else |err| {
                self.result = err;
            }
        }

        return MemoryStore.update(&self.inner, previous, next);
    }
};

test "stateful sign refuses a concurrent call" {
    var reentrant: ReentrantStore = .{};

    defer reentrant.inner.deinit();

    var pair = try pq.hss_lms.generateKeyPair(testing.allocator, .{ .levels = &small }, reentrant.store(), .{});

    defer pair.private_key.deinit(testing.allocator);

    reentrant.key = &pair.private_key;

    const signature = try pair.private_key.sign(testing.allocator, "outer");

    defer testing.allocator.free(signature);

    try testing.expectEqual(error.StateConflict, reentrant.result.?);

    // The store may read the count, which does not change before the update succeeds.
    try testing.expectEqual(32, reentrant.remaining.?);

    try testing.expect(pair.public_key.verify(signature, "outer"));

    try testing.expectEqual(31, pair.private_key.remainingSignatures());
}

// The leaf index of a one-level HSS signature: u32 Nspk = 0, then q.
fn hssIndex(signature: []const u8) u32 {
    return std.mem.readInt(u32, signature[4..8], .big);
}

// reserve = 5: one write claims five indices. The signatures are those of a key that writes every
// time, and a key loaded after a stop that left claimed indices unused starts after them, while
// the stopped key can still use only what it had claimed.
test "stateful reserve" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const seed = sequence(40);

    var store: MemoryStore = .{};

    defer store.deinit();

    var pair = try hazmat.generateStatefulKeyPair(pq.hss_lms, testing.allocator, .{ .levels = &small }, &seed, 0, store.store(), .{ .reserve = 5 });

    defer pair.private_key.deinit(testing.allocator);

    var reference_store: MemoryStore = .{};

    defer reference_store.deinit();

    var reference = try hazmat.generateStatefulKeyPair(pq.hss_lms, testing.allocator, .{ .levels = &small }, &seed, 0, reference_store.store(), .{});

    defer reference.private_key.deinit(testing.allocator);

    try testing.expectEqual(1, store.writes);

    try testing.expectEqual(0, store.index());

    for (0..12) |i| {
        const signature = try pair.private_key.sign(allocator, "message");

        try testing.expectEqualSlices(u8, try reference.private_key.sign(allocator, "message"), signature);

        try testing.expectEqual(i, hssIndex(signature));

        try testing.expectEqual(1 + i / 5 + 1, store.writes);

        try testing.expectEqual(5 * (i / 5 + 1), store.index());

        try testing.expectEqual(32 - i - 1, pair.private_key.remainingSignatures());
    }

    try testing.expectEqual(13, reference_store.writes);

    var loaded = try pq.hss_lms.loadPrivateKey(testing.allocator, store.store(), .{ .reserve = 5 });

    defer loaded.deinit(testing.allocator);

    try testing.expectEqual(32 - 15, loaded.remainingSignatures());

    try testing.expectEqual(15, hssIndex(try loaded.sign(allocator, "message")));

    try testing.expectEqual(20, store.index());

    for (12..15) |i| try testing.expectEqual(i, hssIndex(try pair.private_key.sign(allocator, "message")));

    try testing.expectError(error.StateConflict, pair.private_key.sign(allocator, "message"));

    // The last write claims only what is left.
    var reloaded = try pq.hss_lms.loadPrivateKey(testing.allocator, store.store(), .{ .reserve = 1000 });

    defer reloaded.deinit(testing.allocator);

    _ = try reloaded.sign(allocator, "message");

    try testing.expectEqual(32, store.index());

    while (reloaded.remainingSignatures() > 0) _ = try reloaded.sign(allocator, "message");

    try testing.expectError(error.KeyExhausted, reloaded.sign(allocator, "message"));

    var empty: MemoryStore = .{};

    try testing.expectError(error.InvalidOption, pq.hss_lms.generateKeyPair(testing.allocator, .{ .levels = &small }, empty.store(), .{ .reserve = 0 }));

    try testing.expectError(error.InvalidOption, hazmat.generateStatefulKeyPair(pq.hss_lms, testing.allocator, .{ .levels = &small }, &seed, 0, empty.store(), .{ .reserve = 0 }));

    try testing.expectError(error.InvalidOption, pq.hss_lms.loadPrivateKey(testing.allocator, store.store(), .{ .reserve = 0 }));

    try testing.expect(empty.state == null);
}

// XMSS^MT keeps the part of the signature that each upper layer adds until that layer moves on;
// signatures across the boundaries of every layer equal those of fresh keys at the same indices.
test "XMSS^MT layer cache" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const parameters: pq.StatefulParameters = .{ .name = "XMSSMT-SHA2_20/4_256" };

    const seed = sequence(96);

    const start = (1 << 10) - 3;

    var store: MemoryStore = .{};

    defer store.deinit();

    var pair = try hazmat.generateStatefulKeyPair(pq.xmss_mt, testing.allocator, parameters, &seed, start, store.store(), .{ .reserve = 8 });

    defer pair.private_key.deinit(testing.allocator);

    for (start..start + 6) |index| {
        const signature = try pair.private_key.sign(allocator, "message");

        try testing.expect(pair.public_key.verify(signature, "message"));

        var fresh_store: MemoryStore = .{};

        defer fresh_store.deinit();

        var fresh = try hazmat.generateStatefulKeyPair(pq.xmss_mt, testing.allocator, parameters, &seed, index, fresh_store.store(), .{});

        defer fresh.private_key.deinit(testing.allocator);

        try testing.expectEqualSlices(u8, try fresh.private_key.sign(allocator, "message"), signature);
    }
}

// remainingSignatures may be read from another thread while the key signs: every value read is
// one the count really had.
test "stateful remaining signatures read during signing" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;

    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    var store: MemoryStore = .{};

    defer store.deinit();

    var pair = try pq.hss_lms.generateKeyPair(testing.allocator, .{ .levels = &small }, store.store(), .{});

    defer pair.private_key.deinit(testing.allocator);

    const Reader = struct {
        fn run(key: *const pq.StatefulPrivateKey, done: *std.atomic.Value(bool), bad: *std.atomic.Value(bool)) void {
            var previous: u64 = 32;

            while (!done.load(.acquire)) {
                const remaining = key.remainingSignatures();

                if (remaining > previous or remaining < 32 - 24) bad.store(true, .release);

                previous = remaining;
            }
        }
    };

    var done: std.atomic.Value(bool) = .init(false);

    var bad: std.atomic.Value(bool) = .init(false);

    const thread = try std.Thread.spawn(.{}, Reader.run, .{ &pair.private_key, &done, &bad });

    for (0..24) |_| _ = try pair.private_key.sign(arena.allocator(), "message");

    done.store(true, .release);

    thread.join();

    try testing.expect(!bad.load(.acquire));

    try testing.expectEqual(32 - 24, pair.private_key.remainingSignatures());
}

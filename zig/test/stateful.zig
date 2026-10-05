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

// Tree caches. The levels and the parameter set are those of the Python tests.
const two_levels = [_]pq.HssLevel{
    .{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W4" },
    .{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W2" },
};

const three_levels = [_]pq.HssLevel{
    .{ .lms = "LMS_SHAKE_M32_H5", .ots = "LMOTS_SHAKE_N32_W2" },
    .{ .lms = "LMS_SHAKE_M32_H5", .ots = "LMOTS_SHAKE_N32_W1" },
    .{ .lms = "LMS_SHAKE_M32_H5", .ots = "LMOTS_SHAKE_N32_W2" },
};

const multi_tree: pq.StatefulParameters = .{ .name = "XMSSMT-SHA2_20/4_192" };

fn bigEndian(comptime T: type, value: T) [@sizeOf(T)]u8 {
    var out: [@sizeOf(T)]u8 = undefined;

    std.mem.writeInt(T, &out, value, .big);

    return out;
}

// The state that a key at `index` stored, its raw public key and the tree cache it exports, after
// a signature there when `sign` is set, so that it holds a tree on every level.
const Exported = struct {
    state: []u8,
    public_key: []u8,
    cache: []u8,
};

fn exportCache(allocator: Allocator, algorithm: pq.StatefulSignatureAlgorithm, parameters: pq.StatefulParameters, seed: []const u8, index: u64, sign: bool) !Exported {
    var store: MemoryStore = .{};

    defer store.deinit();

    var pair = try hazmat.generateStatefulKeyPair(algorithm, testing.allocator, parameters, seed, index, store.store(), .{});

    defer pair.private_key.deinit(testing.allocator);

    if (sign) testing.allocator.free(try pair.private_key.sign(testing.allocator, "first"));

    const cache = try pair.private_key.exportTreeCache(allocator);

    return .{ .state = try allocator.dupe(u8, store.state.?), .public_key = try pair.public_key.exportKey(allocator, .raw), .cache = cache };
}

// A copy of a state with another index, sealed again.
fn withIndex(allocator: Allocator, state: []const u8, index: u64) ![]u8 {
    const out = try allocator.dupe(u8, state);

    std.mem.writeInt(u64, out[if (out[1] == 1) out.len - 24 else 6..][0..8], index, .big);

    var digest: [32]u8 = undefined;

    pq.sha_256.digest(out[0 .. out.len - 16], &digest);

    @memcpy(out[out.len - 16 ..], digest[0..16]);

    return out;
}

fn flipped(allocator: Allocator, data: []const u8, position: usize, mask: u8) ![]u8 {
    const out = try allocator.dupe(u8, data);

    out[position] ^= mask;

    return out;
}

// A cache body closed by its tag under the key derived from `seed`, as only the key's holder can.
fn sealCache(allocator: Allocator, body: []const u8, seed: []const u8) ![]u8 {
    var key: [32]u8 = undefined;

    pq.hmac_sha_256.digest("crypto-pq tree cache v1", seed, &key);

    var tag: [32]u8 = undefined;

    pq.hmac_sha_256.digest(&key, body, &tag);

    return std.mem.concat(allocator, u8, &.{ body, &tag });
}

const CacheTree = struct {
    level: u8,
    tree: u64,
    low: u8,
    height: u8,
    n: u8,
    count: u32,
    nodes: []const u8,
};

// A tree cache taken apart, so that a test can change a field and seal the cache again: only then
// do the checks after the tag see the change.
const Cache = struct {
    version: u8,
    kind: u8,
    parameters: []const u8,
    public_key: []const u8,
    trees: std.ArrayList(CacheTree),

    fn parse(allocator: Allocator, data: []const u8) !Cache {
        const end: usize = if (data[1] == 1) 3 + 8 * @as(usize, data[2]) else 6;

        const size = std.mem.readInt(u32, data[end..][0..4], .big);

        var self: Cache = .{ .version = data[0], .kind = data[1], .parameters = data[2..end], .public_key = data[end + 4 ..][0..size], .trees = .empty };

        var offset = end + 5 + size;

        for (0..data[end + 4 + size]) |_| {
            const header = data[offset..][0..16];

            const count = std.mem.readInt(u32, header[12..16], .big);

            const nodes = data[offset + 16 ..][0 .. count * header[11]];

            try self.trees.append(allocator, .{ .level = header[0], .tree = std.mem.readInt(u64, header[1..9], .big), .low = header[9], .height = header[10], .n = header[11], .count = count, .nodes = nodes });

            offset += 16 + nodes.len;
        }

        return self;
    }

    // Where the nodes of tree i start.
    fn nodesAt(self: *const Cache, i: usize) usize {
        var offset = 7 + self.parameters.len + self.public_key.len + 16;

        for (self.trees.items[0..i]) |tree| offset += 16 + tree.nodes.len;

        return offset;
    }

    fn seal(self: *const Cache, allocator: Allocator, seed: []const u8) ![]u8 {
        var body: std.ArrayList(u8) = .empty;

        try body.appendSlice(allocator, &.{ self.version, self.kind });

        try body.appendSlice(allocator, self.parameters);

        try body.appendSlice(allocator, &bigEndian(u32, @intCast(self.public_key.len)));

        try body.appendSlice(allocator, self.public_key);

        try body.append(allocator, @intCast(self.trees.items.len));

        for (self.trees.items) |tree| {
            try body.append(allocator, tree.level);

            try body.appendSlice(allocator, &bigEndian(u64, tree.tree));

            try body.appendSlice(allocator, &.{ tree.low, tree.height, tree.n });

            try body.appendSlice(allocator, &bigEndian(u32, tree.count));

            try body.appendSlice(allocator, tree.nodes);
        }

        return sealCache(allocator, body.items, seed);
    }
};

fn expectRefused(expected: anyerror, algorithm: pq.StatefulSignatureAlgorithm, state: []const u8, cache: []const u8) !void {
    var store = try MemoryStore.init(state);

    defer store.deinit();

    if (algorithm.loadPrivateKey(testing.allocator, store.store(), .{ .tree_cache = cache })) |loaded| {
        var key = loaded;

        key.deinit(testing.allocator);

        return error.TestUnexpectedResult;
    } else |err| {
        try testing.expectEqual(expected, err);
    }
}

// A key loaded with the cache matches one loaded without it: the same public key and count, and
// the same next signature.
fn expectLoads(algorithm: pq.StatefulSignatureAlgorithm, state: []const u8, cache: []const u8) !void {
    var cached_store = try MemoryStore.init(state);

    defer cached_store.deinit();

    var cached = try algorithm.loadPrivateKey(testing.allocator, cached_store.store(), .{ .tree_cache = cache });

    defer cached.deinit(testing.allocator);

    var plain_store = try MemoryStore.init(state);

    defer plain_store.deinit();

    var plain = try algorithm.loadPrivateKey(testing.allocator, plain_store.store(), .{});

    defer plain.deinit(testing.allocator);

    const cached_public = cached.publicKey();

    const plain_public = plain.publicKey();

    try testing.expect(cached_public.eql(&plain_public));

    try testing.expectEqual(plain.remainingSignatures(), cached.remainingSignatures());

    if (plain.remainingSignatures() == 0) return;

    const expected = try plain.sign(testing.allocator, "next");

    defer testing.allocator.free(expected);

    const signature = try cached.sign(testing.allocator, "next");

    defer testing.allocator.free(signature);

    try testing.expectEqualSlices(u8, expected, signature);
}

// The leaves that a key's trees have computed since it was made.
fn leavesComputed(key: *const pq.StatefulPrivateKey) u64 {
    var total: u64 = 0;

    switch (key.signer) {
        .hss => |hss| for (hss.trees[0..hss.count]) |tree| {
            total += tree.merkle.computed;
        },
        .xmss => |signer| for (signer.layers[0..signer.hashes.p.d]) |layer| {
            total += layer.tree.computed;
        },
    }

    return total;
}

// A key loaded with its cache signs as the key that exported it and as one that built its trees,
// and exports the same cache.
test "stateful tree cache round trip" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const seed = sequence(72);

    const cases = [_]struct { algorithm: pq.StatefulSignatureAlgorithm, parameters: pq.StatefulParameters, seed_size: usize, index: u64 }{
        .{ .algorithm = pq.hss_lms, .parameters = .{ .levels = &two_levels }, .seed_size = 40, .index = 40 },
        .{ .algorithm = pq.hss_lms, .parameters = .{ .levels = &three_levels }, .seed_size = 48, .index = 5000 },
        .{ .algorithm = pq.xmss_mt, .parameters = multi_tree, .seed_size = 72, .index = 0x12345 },
        .{ .algorithm = pq.xmss, .parameters = .{ .name = "XMSS-SHA2_10_192" }, .seed_size = 72, .index = 1000 },
    };

    for (cases) |case| {
        var store: MemoryStore = .{};

        defer store.deinit();

        var pair = try hazmat.generateStatefulKeyPair(case.algorithm, testing.allocator, case.parameters, seed[0..case.seed_size], case.index, store.store(), .{});

        defer pair.private_key.deinit(testing.allocator);

        _ = try pair.private_key.sign(allocator, "first");

        const cache = try pair.private_key.exportTreeCache(allocator);

        var cached_store = try MemoryStore.init(store.state);

        defer cached_store.deinit();

        var loaded = try case.algorithm.loadPrivateKey(testing.allocator, cached_store.store(), .{ .tree_cache = cache });

        defer loaded.deinit(testing.allocator);

        var plain_store = try MemoryStore.init(store.state);

        defer plain_store.deinit();

        var plain = try case.algorithm.loadPrivateKey(testing.allocator, plain_store.store(), .{});

        defer plain.deinit(testing.allocator);

        const loaded_public = loaded.publicKey();

        try testing.expect(loaded_public.eql(&pair.public_key));

        try testing.expectEqualSlices(u8, cache, try loaded.exportTreeCache(allocator));

        for ([_][]const u8{ "second", "third" }) |message| {
            const signature = try loaded.sign(allocator, message);

            try testing.expect(pair.public_key.verify(signature, message));

            try testing.expectEqualSlices(u8, try plain.sign(allocator, message), signature);
        }

        try testing.expectEqualSlices(u8, try plain.exportTreeCache(allocator), try loaded.exportTreeCache(allocator));
    }
}

// The fields of a cache, which lists every tree that the key holds, top first, and its tag under
// the key derived from the seed.
test "stateful tree cache layout" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const seed = sequence(72);

    const hss = try exportCache(allocator, pq.hss_lms, .{ .levels = &two_levels }, seed[0..40], 40, true);

    var parts = try Cache.parse(allocator, hss.cache);

    try testing.expectEqual(1, parts.version);

    try testing.expectEqual(1, parts.kind);

    try expectHex("020000000a000000070000000a00000006", parts.parameters);

    try testing.expectEqualSlices(u8, hss.public_key, parts.public_key);

    try testing.expectEqual(2, parts.trees.items.len);

    for (parts.trees.items, [_][2]u64{ .{ 0, 0 }, .{ 1, 1 } }) |tree, expected| {
        try testing.expectEqual(expected[0], tree.level);

        try testing.expectEqual(expected[1], tree.tree);

        try testing.expectEqual(CacheTree{ .level = tree.level, .tree = tree.tree, .low = 0, .height = 5, .n = 24, .count = 63, .nodes = tree.nodes }, tree);
    }

    try testing.expectEqualSlices(u8, hss.public_key[hss.public_key.len - 24 ..], parts.trees.items[0].nodes[62 * 24 ..]);

    try testing.expectEqualSlices(u8, hss.cache, try parts.seal(allocator, seed[0..40]));

    const fresh = try exportCache(allocator, pq.hss_lms, .{ .levels = &two_levels }, seed[0..40], 40, false);

    const fresh_parts = try Cache.parse(allocator, fresh.cache);

    try testing.expectEqual(1, fresh_parts.trees.items.len);

    try testing.expectEqualSlices(u8, parts.trees.items[0].nodes, fresh_parts.trees.items[0].nodes);

    const mt = try exportCache(allocator, pq.xmss_mt, multi_tree, seed[0..72], 0x12345, true);

    parts = try Cache.parse(allocator, mt.cache);

    try testing.expectEqual(3, parts.kind);

    try expectHex("00000022", parts.parameters);

    try testing.expectEqual(4, parts.trees.items.len);

    for (parts.trees.items, [_][2]u64{ .{ 3, 0 }, .{ 2, 2 }, .{ 1, 72 }, .{ 0, 2330 } }) |tree, expected| {
        try testing.expectEqual(CacheTree{ .level = @intCast(expected[0]), .tree = expected[1], .low = 0, .height = 5, .n = 24, .count = 63, .nodes = tree.nodes }, tree);
    }

    try testing.expectEqualSlices(u8, mt.public_key[4..28], parts.trees.items[0].nodes[62 * 24 ..]);

    try testing.expectEqualSlices(u8, mt.cache, try parts.seal(allocator, seed[0..72]));
}

// The checks before the tag and of the state: each fails, and a stale tree is skipped.
test "stateful tree cache rejections" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const seed = sequence(40);

    const exported = try exportCache(allocator, pq.hss_lms, .{ .levels = &two_levels }, &seed, 40, true);

    const state = exported.state;

    const cache = exported.cache;

    const parts = try Cache.parse(allocator, cache);

    const zeros: [72]u8 = @splat(0);

    const invalid = [_][]const u8{
        try flipped(allocator, cache, parts.nodesAt(0) + 5, 1),
        try flipped(allocator, cache, parts.nodesAt(1) + 30, 1),
        try flipped(allocator, cache, cache.len - 32, 1),
        try flipped(allocator, cache, cache.len - 1, 1),
        try flipped(allocator, cache, 0, 1),
        try flipped(allocator, cache, 0, 3),
        try flipped(allocator, try flipped(allocator, cache, 0, 3), 1, 3),
        (try flipped(allocator, cache, 1, 3))[0 .. cache.len - 1],
        cache[0..10],
        try std.mem.concat(allocator, u8, &.{ cache, &.{0} }),
        try std.mem.concat(allocator, u8, &.{ cache, cache[cache.len - 32 ..] }),
        (try exportCache(allocator, pq.hss_lms, .{ .levels = &two_levels }, zeros[0..40], 40, true)).cache,
    };

    for (invalid) |data| try expectRefused(error.InvalidEncoding, pq.hss_lms, state, data);

    for (0..cache.len) |length| try expectRefused(error.InvalidEncoding, pq.hss_lms, state, cache[0..length]);

    // Another kind reads the HSS parameters with its own layout, or with none, and finds the
    // cache malformed; a cache made for another algorithm is AlgorithmMismatch.
    for ([_]u8{ 0, 2, 3, 4 }) |kind| try expectRefused(error.InvalidEncoding, pq.hss_lms, state, try flipped(allocator, cache, 1, 1 ^ kind));

    const mt = try exportCache(allocator, pq.xmss_mt, multi_tree, &sequence(72), 0x12345, true);

    try expectRefused(error.AlgorithmMismatch, pq.hss_lms, state, mt.cache);

    try expectRefused(error.AlgorithmMismatch, pq.xmss_mt, mt.state, cache);

    // The same seed with another type below the top: the public key and the tag key are the same,
    // and only the parameters tell the keys apart.
    for ([_]pq.HssLevel{ .{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W8" }, .{ .lms = "LMS_SHA256_M24_H10", .ots = "LMOTS_SHA256_N24_W2" } }) |lower| {
        const levels = [_]pq.HssLevel{ two_levels[0], lower };

        var store: MemoryStore = .{};

        defer store.deinit();

        var other = try hazmat.generateStatefulKeyPair(pq.hss_lms, testing.allocator, .{ .levels = &levels }, &seed, 41, store.store(), .{});

        other.private_key.deinit(testing.allocator);

        try expectRefused(error.InvalidEncoding, pq.hss_lms, store.state.?, cache);
    }

    // The same I with another SEED: the bytes of the public key that the state gives match, the
    // tag does not.
    const other_seed = seed[0..16].* ++ zeros[0..24].*;

    try expectRefused(error.InvalidEncoding, pq.hss_lms, (try exportCache(allocator, pq.hss_lms, .{ .levels = &two_levels }, &other_seed, 41, false)).state, cache);

    // The state is checked before the cache.
    try expectRefused(error.InvalidPrivateKey, pq.hss_lms, state[0 .. state.len - 1], cache);

    try expectRefused(error.InvalidPrivateKey, pq.hss_lms, try withIndex(allocator, state, 1025), cache);

    try expectLoads(pq.hss_lms, try withIndex(allocator, state, 1024), cache);

    // Index 64 has left tree 1 of level 1, which the next signature builds.
    try expectLoads(pq.hss_lms, try withIndex(allocator, state, 64), cache);

    try expectLoads(pq.hss_lms, state, cache);
}

// Changes sealed with the key's seed, which only the checks after the tag can catch.
test "stateful tree cache sealed changes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const seed = sequence(72);

    const hss = try exportCache(allocator, pq.hss_lms, .{ .levels = &two_levels }, seed[0..40], 40, true);

    // Index 64 has left tree 1 of level 1; at the capacity no lower tree is needed.
    const later = try withIndex(allocator, hss.state, 64);

    const capacity = try withIndex(allocator, hss.state, 1024);

    var parts = try Cache.parse(allocator, hss.cache);

    const original = try parts.trees.clone(allocator);

    const nodes = try allocator.dupe(u8, original.items[1].nodes);

    nodes[7] ^= 1;

    parts.trees.items[1].nodes = nodes;

    try expectRefused(error.InvalidEncoding, pq.hss_lms, hss.state, try parts.seal(allocator, seed[0..40]));

    try expectLoads(pq.hss_lms, later, try parts.seal(allocator, seed[0..40]));

    parts.trees.items[1] = original.items[1];

    const root = try allocator.dupe(u8, original.items[1].nodes);

    root[62 * 24] ^= 1;

    parts.trees.items[1].nodes = root;

    try expectRefused(error.InvalidEncoding, pq.hss_lms, hss.state, try parts.seal(allocator, seed[0..40]));

    // Tree 1 claimed as tree 2: stale at index 41, checked against tree 2 at index 64.
    parts.trees.items[1] = original.items[1];

    parts.trees.items[1].tree = 2;

    try expectLoads(pq.hss_lms, hss.state, try parts.seal(allocator, seed[0..40]));

    try expectRefused(error.InvalidEncoding, pq.hss_lms, later, try parts.seal(allocator, seed[0..40]));

    // A level out of order, twice or unknown, or a tree of another shape, stale or not.
    parts.trees.items[1] = original.items[1];

    std.mem.swap(CacheTree, &parts.trees.items[0], &parts.trees.items[1]);

    try expectRefused(error.InvalidEncoding, pq.hss_lms, hss.state, try parts.seal(allocator, seed[0..40]));

    parts.trees.items[0] = original.items[0];

    try expectRefused(error.InvalidEncoding, pq.hss_lms, hss.state, try parts.seal(allocator, seed[0..40]));

    parts.trees.items[1] = original.items[1];

    parts.trees.items[1].level = 2;

    try expectRefused(error.InvalidEncoding, pq.hss_lms, hss.state, try parts.seal(allocator, seed[0..40]));

    parts.trees.items[1] = .{ .level = 1, .tree = 0, .low = 0, .height = 6, .n = 24, .count = 127, .nodes = &(@as([127 * 24]u8, @splat(1))) };

    try expectRefused(error.InvalidEncoding, pq.hss_lms, later, try parts.seal(allocator, seed[0..40]));

    parts.trees.items[1] = original.items[1];

    parts.trees.items[1].count = 62;

    parts.trees.items[1].nodes = original.items[1].nodes[0 .. 62 * 24];

    try expectRefused(error.InvalidEncoding, pq.hss_lms, hss.state, try parts.seal(allocator, seed[0..40]));

    // No trees, the top only and level 1 only all load.
    parts.trees.items[1] = original.items[1];

    for ([_][]const CacheTree{ &.{}, original.items[0..1], original.items[1..2] }) |kept| {
        parts.trees.clearRetainingCapacity();

        try parts.trees.appendSlice(allocator, kept);

        try expectLoads(pq.hss_lms, hss.state, try parts.seal(allocator, seed[0..40]));
    }

    // The top tree numbered 1 is stale even at the capacity; numbered 0 there it is checked.
    parts.trees.clearRetainingCapacity();

    try parts.trees.appendSlice(allocator, original.items);

    const top = try allocator.dupe(u8, original.items[0].nodes);

    top[5] ^= 1;

    parts.trees.items[0].nodes = top;

    try expectRefused(error.InvalidEncoding, pq.hss_lms, capacity, try parts.seal(allocator, seed[0..40]));

    parts.trees.items[0].tree = 1;

    try expectLoads(pq.hss_lms, capacity, try parts.seal(allocator, seed[0..40]));

    // The public key and the parameters are checked against the state.
    parts.trees.items[0] = original.items[0];

    const public_key = try allocator.dupe(u8, hss.public_key);

    public_key[public_key.len - 1] ^= 1;

    parts.public_key = public_key;

    try expectRefused(error.InvalidEncoding, pq.hss_lms, hss.state, try parts.seal(allocator, seed[0..40]));

    parts.public_key = hss.public_key[0 .. hss.public_key.len - 1];

    try expectRefused(error.InvalidEncoding, pq.hss_lms, hss.state, try parts.seal(allocator, seed[0..40]));

    parts.public_key = hss.public_key;

    for ([_][]const u8{ "020000000a000000070000000a00000008", "010000000a00000007", "020000000a000000060000000a00000007" }) |hex| {
        parts.parameters = try vectors.decode(allocator, hex);

        try expectRefused(error.InvalidEncoding, pq.hss_lms, hss.state, try parts.seal(allocator, seed[0..40]));
    }

    parts.parameters = hss.state[2..19];

    try testing.expectEqualSlices(u8, hss.cache, try parts.seal(allocator, seed[0..40]));

    // XMSS^MT: a changed node of a needed layer, a stale layer 0, and no top layer.
    const mt = try exportCache(allocator, pq.xmss_mt, multi_tree, seed[0..72], 0x12345, true);

    const mt_later = try withIndex(allocator, mt.state, 0x12360);

    var mt_parts = try Cache.parse(allocator, mt.cache);

    const bottom = try allocator.dupe(u8, mt_parts.trees.items[3].nodes);

    bottom[40] ^= 1;

    const bottom_original = mt_parts.trees.items[3].nodes;

    mt_parts.trees.items[3].nodes = bottom;

    try expectRefused(error.InvalidEncoding, pq.xmss_mt, mt.state, try mt_parts.seal(allocator, seed[0..72]));

    try expectLoads(pq.xmss_mt, mt_later, try mt_parts.seal(allocator, seed[0..72]));

    mt_parts.trees.items[3].nodes = bottom_original;

    _ = mt_parts.trees.orderedRemove(0);

    try expectLoads(pq.xmss_mt, mt.state, try mt_parts.seal(allocator, seed[0..72]));

    const other_oid = bigEndian(u32, 0x21);

    mt_parts.parameters = &other_oid;

    try expectRefused(error.InvalidEncoding, pq.xmss_mt, mt.state, try mt_parts.seal(allocator, seed[0..72]));

    mt_parts.parameters = mt.state[2..6];

    mt_parts.kind = 2;

    try expectRefused(error.AlgorithmMismatch, pq.xmss_mt, mt.state, try mt_parts.seal(allocator, seed[0..72]));
}

// Every change of one byte is refused: the kind byte becomes 0 or 0x81, no kind at all.
test "stateful tree cache refuses every changed byte" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const exported = try exportCache(allocator, pq.hss_lms, .{ .levels = two_levels[0..1] }, &sequence(40), 5, true);

    for (0..exported.cache.len) |position| {
        for ([_]u8{ 0x01, 0x80 }) |mask| {
            try expectRefused(error.InvalidEncoding, pq.hss_lms, exported.state, try flipped(allocator, exported.cache, position, mask));
        }
    }
}

// A load with the cache computes no leaf; the trees that the next index has left are built.
test "stateful tree cache skips the build" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const seed = sequence(72);

    const cases = [_]struct { algorithm: pq.StatefulSignatureAlgorithm, parameters: pq.StatefulParameters, seed_size: usize, index: u64, later: u64, trees: u64 }{
        .{ .algorithm = pq.hss_lms, .parameters = .{ .levels = &two_levels }, .seed_size = 40, .index = 40, .later = 64, .trees = 2 },
        .{ .algorithm = pq.xmss_mt, .parameters = multi_tree, .seed_size = 72, .index = 0x12345, .later = 0x12360, .trees = 4 },
    };

    for (cases) |case| {
        const exported = try exportCache(allocator, case.algorithm, case.parameters, seed[0..case.seed_size], case.index, true);

        const stale = try withIndex(allocator, exported.state, case.later);

        for ([_]struct { state: []const u8, cache: ?[]const u8, leaves: u64 }{
            .{ .state = exported.state, .cache = exported.cache, .leaves = 0 },
            .{ .state = exported.state, .cache = null, .leaves = 32 * case.trees },
            .{ .state = stale, .cache = exported.cache, .leaves = 32 },
        }) |load| {
            var store = try MemoryStore.init(load.state);

            defer store.deinit();

            var key = try case.algorithm.loadPrivateKey(testing.allocator, store.store(), .{ .tree_cache = load.cache });

            defer key.deinit(testing.allocator);

            _ = try key.sign(allocator, "m");

            try testing.expectEqual(load.leaves, leavesComputed(&key));
        }
    }
}

// A store that exports the key's tree cache while the key writes its next state.
const ExportingStore = struct {
    inner: MemoryStore = .{},
    key: ?*pq.StatefulPrivateKey = null,
    result: ?anyerror = null,

    const vtable: pq.StateStore.VTable = .{ .read = read, .update = update };

    fn store(self: *ExportingStore) pq.StateStore {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn read(ptr: *anyopaque, allocator: Allocator) anyerror!?[]u8 {
        const self: *ExportingStore = @ptrCast(@alignCast(ptr));

        return MemoryStore.read(&self.inner, allocator);
    }

    fn update(ptr: *anyopaque, previous: ?[]const u8, next: []const u8) anyerror!bool {
        const self: *ExportingStore = @ptrCast(@alignCast(ptr));

        if (self.key) |key| {
            self.key = null;

            if (key.exportTreeCache(testing.allocator)) |cache| {
                testing.allocator.free(cache);
            } else |err| {
                self.result = err;
            }
        }

        return MemoryStore.update(&self.inner, previous, next);
    }
};

// A sign holds the trees as they change, so an export from inside the store fails at once.
test "stateful tree cache export during a sign" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    var exporting: ExportingStore = .{};

    defer exporting.inner.deinit();

    var pair = try pq.hss_lms.generateKeyPair(testing.allocator, .{ .levels = &small }, exporting.store(), .{});

    defer pair.private_key.deinit(testing.allocator);

    exporting.key = &pair.private_key;

    try testing.expect(pair.public_key.verify(try pair.private_key.sign(allocator, "m"), "m"));

    try testing.expectEqual(error.StateConflict, exporting.result.?);

    const parts = try Cache.parse(allocator, try pair.private_key.exportTreeCache(allocator));

    try testing.expectEqualSlices(u8, try pair.public_key.exportKey(allocator, .raw), parts.public_key);
}

// A tree cache belongs to a key that exists already.
test "stateful tree cache option" {
    var store: MemoryStore = .{};

    try testing.expectError(error.InvalidOption, pq.hss_lms.generateKeyPair(testing.allocator, .{ .levels = &small }, store.store(), .{ .tree_cache = "" }));

    try testing.expectError(error.InvalidOption, hazmat.generateStatefulKeyPair(pq.xmss_mt, testing.allocator, multi_tree, &sequence(72), 0, store.store(), .{ .tree_cache = "" }));

    try testing.expect(store.state == null);
}

fn now() i96 {
    return std.Io.Clock.awake.now(testing.io).nanoseconds;
}

// The load that the cache saves for one tree of height 10, with its 1024 leaves, against the
// parents alone.
test "stateful tree cache load time" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const levels = [_]pq.HssLevel{.{ .lms = "LMS_SHA256_M24_H10", .ots = "LMOTS_SHA256_N24_W2" }};

    const zeros: [40]u8 = @splat(0);

    const exported = try exportCache(allocator, pq.hss_lms, .{ .levels = &levels }, &zeros, 0, false);

    var store = try MemoryStore.init(exported.state);

    defer store.deinit();

    const start = now();

    var plain = try pq.hss_lms.loadPrivateKey(testing.allocator, store.store(), .{});

    defer plain.deinit(testing.allocator);

    const middle = now();

    var cached = try pq.hss_lms.loadPrivateKey(testing.allocator, store.store(), .{ .tree_cache = exported.cache });

    defer cached.deinit(testing.allocator);

    const end = now();

    const plain_public = plain.publicKey();

    const cached_public = cached.publicKey();

    try testing.expect(cached_public.eql(&plain_public));

    try testing.expect(4 * (end - middle) < middle - start);
}

// Random changes sealed with the seed, so that they pass the tag: a cache that still loads gives
// the signatures of a key that built its trees, and any other is refused as malformed or as a
// cache of another algorithm.
test "stateful tree cache random sealed changes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    var prng: std.Random.DefaultPrng = .init(5);

    const random = prng.random();

    const seed = sequence(72);

    const cases = [_]struct { algorithm: pq.StatefulSignatureAlgorithm, parameters: pq.StatefulParameters, seed_size: usize, index: u64, later: u64 }{
        .{ .algorithm = pq.hss_lms, .parameters = .{ .levels = &two_levels }, .seed_size = 40, .index = 40, .later = 64 },
        .{ .algorithm = pq.xmss_mt, .parameters = multi_tree, .seed_size = 72, .index = 0x12345, .later = 0x12360 },
    };

    var loads: usize = 0;

    for (cases) |case| {
        const exported = try exportCache(allocator, case.algorithm, case.parameters, seed[0..case.seed_size], case.index, true);

        const states = [_][]const u8{ exported.state, try withIndex(allocator, exported.state, case.later) };

        var expected: [2][]u8 = undefined;

        for (states, &expected) |state, *signature| {
            var store = try MemoryStore.init(state);

            defer store.deinit();

            var plain = try case.algorithm.loadPrivateKey(testing.allocator, store.store(), .{});

            defer plain.deinit(testing.allocator);

            signature.* = try plain.sign(allocator, "next");
        }

        const body = exported.cache[0 .. exported.cache.len - 32];

        for (0..150) |_| {
            var changed: std.ArrayList(u8) = .empty;

            try changed.appendSlice(allocator, body);

            for (0..1 + random.uintLessThan(usize, 3)) |_| {
                const position = random.uintLessThan(usize, changed.items.len);

                switch (random.uintLessThan(u8, 4)) {
                    0 => changed.items[position] ^= @as(u8, 1) << random.int(u3),
                    1 => changed.items[position] = random.int(u8),
                    2 => _ = changed.orderedRemove(position),
                    else => try changed.insert(allocator, position, random.int(u8)),
                }
            }

            const which = random.uintLessThan(usize, states.len);

            var store = try MemoryStore.init(states[which]);

            defer store.deinit();

            const sealed = try sealCache(allocator, changed.items, seed[0..case.seed_size]);

            var key = case.algorithm.loadPrivateKey(testing.allocator, store.store(), .{ .tree_cache = sealed }) catch |err| {
                if (err != error.InvalidEncoding and err != error.AlgorithmMismatch) return err;

                continue;
            };

            defer key.deinit(testing.allocator);

            loads += 1;

            try testing.expectEqualSlices(u8, expected[which], try key.sign(allocator, "next"));
        }
    }

    try testing.expect(loads > 0);
}

const std = @import("std");
const builtin = @import("builtin");
const pq = @import("crypto_pq");

const testing = std.testing;

const hazmat = pq.hazmat;

const Allocator = std.mem.Allocator;

// No operation may use more stack than this, in any build mode: threads often get far less than
// the 8 MiB of a main thread, 128 KiB under musl for instance.
const limit = 64 << 10;

// Stack painting: a thread with a large stack fills a window below its frame with a pattern, runs
// the operation, and finds the deepest byte that changed. Only Linux is measured, where a thread
// stack is one mapping that may be written anywhere.
const window = 1 << 20;

const pattern = 0xa5;

noinline fn paint() void {
    var buffer: [window + 4096]u8 = undefined;

    const bytes: [*]volatile u8 = &buffer;

    for (0..buffer.len) |i| bytes[i] = pattern;
}

// Reads below its own frame without a buffer of its own, which safe builds would fill.
noinline fn scan() usize {
    var marker: u8 = 0;

    const bytes: [*]const volatile u8 = @ptrFromInt(@intFromPtr(&marker) - window);

    var i: usize = 0;

    while (i < window and bytes[i] == pattern) i += 1;

    std.mem.doNotOptimizeAway(&marker);

    return window - i;
}

const Operation = struct {
    name: []const u8,
    run: *const fn () anyerror!void,
};

noinline fn call(operation: *const Operation) anyerror!void {
    return operation.run();
}

fn measure(operation: *const Operation, depth: *usize, result: *anyerror!void) void {
    paint();

    result.* = call(operation);

    depth.* = scan();
}

fn check(operations: []const Operation) !void {
    var worst: usize = 0;

    for (operations) |*operation| {
        var depth: usize = 0;

        var result: anyerror!void = {};

        const thread = try std.Thread.spawn(.{ .stack_size = 4 << 20 }, measure, .{ operation, &depth, &result });

        thread.join();

        result catch |err| {
            std.debug.print("{s} failed: {s}\n", .{ operation.name, @errorName(err) });

            return err;
        };

        worst = @max(worst, depth);

        if (depth > limit) {
            std.debug.print("{s} uses {d} bytes of stack, above {d}\n", .{ operation.name, depth, limit });

            return error.TestUnexpectedResult;
        }
    }

    try testing.expect(worst > 0);
}

const allocator = std.heap.smp_allocator;

const message = "crypto-pq stack check";

fn Kem(comptime algorithm: pq.KemAlgorithm) type {
    return struct {
        const xwing = algorithm.kind == .x_wing;

        const format: pq.KeyFormat = if (xwing) .raw else .pem;

        var pair: pq.KemKeyPair = undefined;

        var public_encoded: []u8 = undefined;

        var private_encoded: []u8 = undefined;

        var public_raw: []u8 = undefined;

        var private_raw: []u8 = undefined;

        var expanded: []const u8 = undefined;

        var ciphertext: [algorithm.ciphertext_size]u8 = undefined;

        var failing: std.testing.FailingAllocator = undefined;

        fn prepare() !void {
            pair = try algorithm.generateKeyPair(allocator, .{});

            public_encoded = try pair.public_key.exportKey(allocator, format);

            private_encoded = try pair.private_key.exportKey(allocator, format);

            public_raw = try pair.public_key.exportKey(allocator, .raw);

            private_raw = try pair.private_key.exportKey(allocator, .raw);

            expanded = pair.private_key.secret.dk[0 .. 768 * (algorithm.public_key_size / 384) + 96];

            ciphertext = (try pair.public_key.encapsulate()).ciphertext()[0..algorithm.ciphertext_size].*;

            failing = .init(allocator, .{ .fail_index = 1 });
        }

        fn release() void {
            pair.private_key.deinit();

            pair.public_key.deinit();

            for ([_][]u8{ public_encoded, private_encoded, public_raw, private_raw }) |buffer| allocator.free(buffer);
        }

        fn generate() !void {
            var fresh = try algorithm.generateKeyPair(allocator, .{});

            fresh.private_key.deinit();

            fresh.public_key.deinit();
        }

        // A key imported here has an empty cache, so its first use fills it.
        fn importAndEncapsulate() !void {
            var key = try algorithm.importPublicKey(allocator, public_encoded, format);

            defer key.deinit();

            _ = try key.encapsulate();
        }

        fn importAndDecapsulate() !void {
            var key = try algorithm.importPrivateKey(allocator, private_encoded, format);

            defer key.deinit();

            _ = try key.decapsulate(&ciphertext);
        }

        fn importExpanded() !void {
            var key = try algorithm.importPrivateKey(allocator, expanded, .raw);

            key.deinit();
        }

        // The shared part of the key fits in the allocator, its cache does not.
        fn withoutCache() !void {
            failing = .init(allocator, .{ .fail_index = 1 });

            var public_key = try algorithm.importPublicKey(failing.allocator(), public_raw, .raw);

            defer public_key.deinit();

            _ = try public_key.encapsulate();

            failing = .init(allocator, .{ .fail_index = 2 });

            var private_key = try algorithm.importPrivateKey(failing.allocator(), private_raw, .raw);

            defer private_key.deinit();

            _ = try private_key.decapsulate(&ciphertext);
        }

        fn hazmatGenerate() !void {
            var fresh = try hazmat.generateKemKeyPair(algorithm, allocator, pair.private_key.secret.seed[0..if (xwing) 32 else 64]);

            fresh.private_key.deinit();

            fresh.public_key.deinit();
        }

        fn exports() !void {
            allocator.free(try pair.private_key.exportKey(allocator, format));
        }

        const operations = [_]Operation{
            .{ .name = algorithm.name ++ " generateKeyPair", .run = generate },
            .{ .name = algorithm.name ++ " importPublicKey, encapsulate", .run = importAndEncapsulate },
            .{ .name = algorithm.name ++ " importPrivateKey, decapsulate", .run = importAndDecapsulate },
            .{ .name = algorithm.name ++ " without cache memory", .run = withoutCache },
            .{ .name = algorithm.name ++ " hazmat.generateKemKeyPair", .run = hazmatGenerate },
            .{ .name = algorithm.name ++ " exportKey", .run = exports },
        } ++ if (xwing) [_]Operation{} else [_]Operation{.{ .name = algorithm.name ++ " importPrivateKey(expanded)", .run = importExpanded }};
    };
}

fn Signature(comptime algorithm: pq.SignatureAlgorithm) type {
    return struct {
        const ml_dsa = algorithm.kind == .ml_dsa_44 or algorithm.kind == .ml_dsa_65 or algorithm.kind == .ml_dsa_87;

        var pair: pq.SignatureKeyPair = undefined;

        var public_encoded: []u8 = undefined;

        var private_encoded: []u8 = undefined;

        var public_raw: []u8 = undefined;

        var secret: []u8 = undefined;

        var signature: []u8 = undefined;

        var failing: std.testing.FailingAllocator = undefined;

        fn prepare() !void {
            pair = try algorithm.generateKeyPair(allocator, .{});

            public_encoded = try pair.public_key.exportKey(allocator, .pem);

            private_encoded = try pair.private_key.exportKey(allocator, .pem);

            public_raw = try pair.public_key.exportKey(allocator, .raw);

            secret = try allocator.dupe(u8, pair.private_key.secret.bytes[0..if (ml_dsa) secretSize() else 2 * algorithm.public_key_size]);

            signature = try pair.private_key.sign(allocator, message, .{});
        }

        fn release() void {
            pair.private_key.deinit();

            pair.public_key.deinit();

            for ([_][]u8{ public_encoded, private_encoded, public_raw, secret, signature }) |buffer| allocator.free(buffer);
        }

        fn secretSize() usize {
            return switch (algorithm.kind) {
                .ml_dsa_44 => 2560,
                .ml_dsa_65 => 4032,
                else => 4896,
            };
        }

        fn generate() !void {
            var fresh = try algorithm.generateKeyPair(allocator, .{});

            fresh.private_key.deinit();

            fresh.public_key.deinit();
        }

        // Keys imported here have empty caches, so their first use fills them.
        fn importAndSign() !void {
            var key = try algorithm.importPrivateKey(allocator, private_encoded, .pem);

            defer key.deinit();

            allocator.free(try key.sign(allocator, message, .{ .context = "context", .pre_hash = .{ .hash = pq.sha_512 } }));
        }

        fn importAndVerify() !void {
            var key = try algorithm.importPublicKey(allocator, public_encoded, .pem);

            defer key.deinit();

            if (!key.verify(signature, message, .{})) return error.TestUnexpectedResult;
        }

        fn importSecret() !void {
            var key = try algorithm.importPrivateKey(allocator, secret, .raw);

            key.deinit();
        }

        fn withoutCache() !void {
            failing = .init(allocator, .{ .fail_index = 1 });

            var key = try algorithm.importPublicKey(failing.allocator(), public_raw, .raw);

            defer key.deinit();

            if (!key.verify(signature, message, .{})) return error.TestUnexpectedResult;
        }

        fn hazmatSign() !void {
            const randomness: [32]u8 = @splat(1);

            allocator.free(try hazmat.sign(&pair.private_key, allocator, message, randomness[0..if (ml_dsa) 32 else algorithm.public_key_size / 2], .{}));
        }

        const operations = [_]Operation{
            .{ .name = algorithm.name ++ " generateKeyPair", .run = generate },
            .{ .name = algorithm.name ++ " importPrivateKey, sign", .run = importAndSign },
            .{ .name = algorithm.name ++ " importPublicKey, verify", .run = importAndVerify },
            .{ .name = algorithm.name ++ " importPrivateKey(expanded)", .run = importSecret },
            .{ .name = algorithm.name ++ " verify without cache memory", .run = withoutCache },
            .{ .name = algorithm.name ++ " hazmat.sign", .run = hazmatSign },
        };
    };
}

const MemoryStore = struct {
    state: ?[]u8 = null,

    const vtable: pq.StateStore.VTable = .{ .read = read, .update = update };

    fn store(self: *MemoryStore) pq.StateStore {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn deinit(self: *MemoryStore) void {
        if (self.state) |state| allocator.free(state);

        self.state = null;
    }

    fn read(ptr: *anyopaque, a: Allocator) anyerror!?[]u8 {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));

        return try a.dupe(u8, self.state orelse return null);
    }

    fn update(ptr: *anyopaque, previous: ?[]const u8, next: []const u8) anyerror!bool {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));

        const same = if (self.state) |state| previous != null and std.mem.eql(u8, state, previous.?) else previous == null;

        if (!same) return false;

        const copy = try allocator.dupe(u8, next);

        self.deinit();

        self.state = copy;

        return true;
    }
};

fn Stateful(comptime algorithm: pq.StatefulSignatureAlgorithm, comptime label: []const u8, comptime parameters: pq.StatefulParameters, comptime seed_size: usize, comptime index: u64) type {
    return struct {
        var store: MemoryStore = .{};

        var key: pq.StatefulPrivateKey = undefined;

        var public_key: pq.StatefulPublicKey = undefined;

        var signature: []u8 = undefined;

        const seed: [seed_size]u8 = @splat(5);

        fn prepare() !void {
            const pair = try hazmat.generateStatefulKeyPair(algorithm, allocator, parameters, &seed, index, store.store(), .{});

            key = pair.private_key;

            public_key = pair.public_key;

            signature = try key.sign(allocator, message);
        }

        fn release() void {
            key.deinit(allocator);

            allocator.free(signature);

            store.deinit();
        }

        fn generate() !void {
            var fresh: MemoryStore = .{};

            defer fresh.deinit();

            var pair = try algorithm.generateKeyPair(allocator, parameters, fresh.store(), .{});

            pair.private_key.deinit(allocator);
        }

        fn loadAndSign() !void {
            var loaded = try algorithm.loadPrivateKey(allocator, store.store(), .{});

            defer loaded.deinit(allocator);

            allocator.free(try loaded.sign(allocator, message));
        }

        // The trees of the key are those that the stored index signs with, so the loaded key
        // restores them all.
        fn loadCachedAndSign() !void {
            const cache = try key.exportTreeCache(allocator);

            defer allocator.free(cache);

            var loaded = try algorithm.loadPrivateKey(allocator, store.store(), .{ .tree_cache = cache });

            defer loaded.deinit(allocator);

            allocator.free(try loaded.sign(allocator, message));
        }

        // The next index of the generated key: for two HSS levels it is the first of a new tree.
        fn sign() !void {
            allocator.free(try key.sign(allocator, message));
        }

        fn verify() !void {
            if (!public_key.verify(signature, message)) return error.TestUnexpectedResult;
        }

        fn importPublic() !void {
            const pem = try public_key.exportKey(allocator, .pem);

            defer allocator.free(pem);

            _ = try algorithm.importPublicKey(pem, .pem);
        }

        // sign comes first: loading signs after the state the key holds.
        const operations = [_]Operation{
            .{ .name = label ++ " generateKeyPair", .run = generate },
            .{ .name = label ++ " sign", .run = sign },
            .{ .name = label ++ " loadPrivateKey, sign", .run = loadAndSign },
            .{ .name = label ++ " exportTreeCache, loadPrivateKey(tree_cache), sign", .run = loadCachedAndSign },
            .{ .name = label ++ " verify", .run = verify },
            .{ .name = label ++ " importPublicKey", .run = importPublic },
        };
    };
}

const Hashes = struct {
    var data: [1000]u8 = @splat(1);

    fn run() !void {
        var out: [64]u8 = undefined;

        pq.sha_256.digest(&data, out[0..32]);

        pq.sha_512.digest(&data, &out);

        pq.sha3_512.digest(&data, &out);

        pq.shake256.digest(&data, &out);

        pq.hmac_sha_512.digest("key", &data, &out);
    }

    // Every new function, with the longest options and keys, through its one-shot and streaming
    // forms.
    fn symmetric() !void {
        var out: [200]u8 = undefined;

        for ([_]pq.HashAlgorithm{ try pq.blake2b_512.configure(.{ .salt = data[0..16], .personalization = data[0..16] }), try pq.blake2s_256.configure(.{ .salt = data[0..8] }), pq.ascon_hash256 }) |hash| {
            hash.digest(&data, out[0..hash.digest_size]);

            var state = hash.create();

            state.update(&data);

            state.digest(out[0..hash.digest_size]);
        }

        for ([_]pq.XofAlgorithm{ try pq.cshake256.configure(.{ .customization = &data }), try pq.ascon_cxof128.configure(.{ .customization = data[0..256] }), pq.ascon_xof128 }) |xof| {
            xof.digest(&data, &out);

            var state = xof.create();

            state.update(&data);

            state.read(&out);
        }

        for ([_]pq.MacAlgorithm{ try pq.kmac256.configure(.{ .length = 200, .customization = &data, .xof = true }), try pq.blake2b_mac.configure(.{ .salt = data[0..16] }), pq.blake2s_mac, pq.hmac_sha_384 }) |mac| {
            const key = data[0..if (mac.kind == .blake2s) 32 else 64];

            mac.digest(key, &data, out[0..mac.digest_size]);

            _ = mac.verify(key, &data, out[0..mac.digest_size]);

            var state = mac.create(key);

            state.update(&data);

            _ = state.verify(out[0..mac.digest_size]);
        }

        for ([_]pq.KdfAlgorithm{ pq.hkdf_sha_256, pq.hkdf_sha_512 }) |kdf| {
            try kdf.derive(&data, &out, .{ .salt = &data, .info = &data });

            try kdf.expand(&data, &out, .{ .info = data[0..20] });
        }
    }

    const operations = [_]Operation{
        .{ .name = "hash functions", .run = run },
        .{ .name = "BLAKE2, Ascon, cSHAKE, KMAC, HKDF", .run = symmetric },
    };
};

fn supported() bool {
    return builtin.os.tag == .linux and !builtin.single_threaded;
}

test "stack: KEM operations" {
    if (!supported()) return error.SkipZigTest;

    inline for (.{ pq.ml_kem_512, pq.ml_kem_768, pq.ml_kem_1024, pq.x_wing }) |algorithm| {
        const K = Kem(algorithm);

        try K.prepare();

        defer K.release();

        try check(&K.operations);
    }

    try check(&Hashes.operations);
}

// The SLH-DSA frames depend on n and the hash family, not on s or f, so the faster sets stand
// for all.
test "stack: signature operations" {
    if (!supported()) return error.SkipZigTest;

    inline for (.{ pq.ml_dsa_44, pq.ml_dsa_65, pq.ml_dsa_87, pq.slh_dsa_sha2_128f, pq.slh_dsa_sha2_192f, pq.slh_dsa_sha2_256f, pq.slh_dsa_shake_128f, pq.slh_dsa_shake_192f, pq.slh_dsa_shake_256f }) |algorithm| {
        const S = Signature(algorithm);

        try S.prepare();

        defer S.release();

        try check(&S.operations);
    }
}

test "stack: stateful operations" {
    if (!supported()) return error.SkipZigTest;

    const h5 = [_]pq.HssLevel{.{ .lms = "LMS_SHA256_M32_H5", .ots = "LMOTS_SHA256_N32_W4" }};

    const two = [_]pq.HssLevel{ .{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W8" }, .{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W8" } };

    const shake = [_]pq.HssLevel{.{ .lms = "LMS_SHAKE_M32_H5", .ots = "LMOTS_SHAKE_N32_W4" }};

    inline for (.{
        Stateful(pq.hss_lms, "HSS H5", .{ .levels = &h5 }, 48, 0),
        Stateful(pq.hss_lms, "HSS H5/H5", .{ .levels = &two }, 40, 31),
        Stateful(pq.hss_lms, "HSS SHAKE H5", .{ .levels = &shake }, 48, 0),
        Stateful(pq.xmss, "XMSS-SHA2_10_256", .{ .name = "XMSS-SHA2_10_256" }, 96, 0),
        Stateful(pq.xmss_mt, "XMSSMT-SHA2_20/4_256", .{ .name = "XMSSMT-SHA2_20/4_256" }, 96, 31),
        Stateful(pq.xmss_mt, "XMSSMT-SHAKE256_20/4_256", .{ .name = "XMSSMT-SHAKE256_20/4_256" }, 96, 0),
    }) |S| {
        try S.prepare();

        defer S.release();

        try check(&S.operations);
    }
}

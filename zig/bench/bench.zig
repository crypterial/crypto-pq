const std = @import("std");
const pq = @import("crypto_pq");

const Allocator = std.mem.Allocator;

const Io = std.Io;

const min_time: i96 = std.time.ns_per_s;

// ML-DSA signing loops a message-dependent number of times, so its cases rotate through these.
const message_count = 16;

const slh_dsa = [_]pq.SignatureAlgorithm{
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

const MemoryStore = struct {
    allocator: Allocator,
    state: ?[]u8 = null,

    const vtable: pq.StateStore.VTable = .{ .read = read, .update = update };

    fn deinit(self: *MemoryStore) void {
        if (self.state) |state| self.allocator.free(state);

        self.state = null;
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

        const same = if (self.state) |state| previous != null and std.mem.eql(u8, state, previous.?) else previous == null;

        if (!same) return false;

        const copy = try self.allocator.dupe(u8, next);

        self.deinit();

        self.state = copy;

        return true;
    }
};

const Runner = struct {
    io: Io,
    allocator: Allocator,
    filter: ?[]const u8,
    out: *Io.Writer,

    fn selects(self: *const Runner, name: []const u8) bool {
        const filter = self.filter orelse return true;

        return std.mem.indexOf(u8, name, filter) != null;
    }

    fn now(self: *const Runner) i96 {
        return Io.Clock.awake.now(self.io).nanoseconds;
    }

    // context.batch(count) runs the operation count times and returns the nanoseconds it measured.
    // The batches grow until min_time is reached, so a slow case still runs once.
    fn case(self: *const Runner, name: []const u8, context: anytype) !void {
        if (!self.selects(name)) return;

        var iterations: u64 = 0;

        var elapsed: i96 = 0;

        var count: u64 = 1;

        while (elapsed < min_time) {
            elapsed += try context.batch(self, count);

            iterations += count;

            const per_operation = @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(iterations));

            const remaining: f64 = @floatFromInt(@max(min_time - elapsed, 0));

            count = std.math.clamp(@as(u64, @intFromFloat(@ceil(remaining / per_operation))), 1, 10 * iterations);
        }

        const micros = @as(f64, @floatFromInt(elapsed)) / 1000.0 / @as(f64, @floatFromInt(iterations));

        try self.out.print("{s:<32}  {d:>9}  {d:>14.3}\n", .{ name, iterations, micros });

        try self.out.flush();
    }
};

// The compiler must assume that the returned value is unknown, so no work is hoisted out of a loop.
fn blackBox(value: anytype) @TypeOf(value) {
    var copy = value;

    std.mem.doNotOptimizeAway(&copy);

    return copy;
}

fn bytes(comptime length: usize) [length]u8 {
    var out: [length]u8 = undefined;

    for (&out, 0..) |*byte, i| byte.* = @truncate(i);

    return out;
}

const Messages = struct {
    buffers: [message_count][64]u8,
    lengths: [message_count]usize,

    fn init() Messages {
        var self: Messages = undefined;

        for (&self.buffers, &self.lengths, 0..) |*buffer, *length, i| {
            length.* = (std.fmt.bufPrint(buffer, "crypto-pq benchmark message {d}", .{i}) catch unreachable).len;
        }

        return self;
    }

    fn get(self: *const Messages, index: usize) []const u8 {
        const i = index % message_count;

        return self.buffers[i][0..self.lengths[i]];
    }
};

fn names(buffer: *[3][64]u8, algorithm: []const u8) [3][]const u8 {
    var out: [3][]const u8 = undefined;

    for (&out, buffer, [_][]const u8{ "keygen", "sign", "verify" }) |*name, *storage, operation| {
        name.* = std.fmt.bufPrint(storage, "{s}/{s}", .{ algorithm, operation }) catch unreachable;
    }

    return out;
}

fn hashes(runner: *const Runner) !void {
    const data = bytes(1024);

    const Digest = struct {
        input: []const u8,
        kind: enum { sha256, sha512, sha3_256, shake128, shake256 },

        fn batch(self: *const @This(), r: *const Runner, count: u64) !i96 {
            var out: [64]u8 = undefined;

            const start = r.now();

            for (0..count) |_| {
                const input = blackBox(self.input);

                switch (self.kind) {
                    .sha256 => pq.sha_256.digest(input, out[0..32]),
                    .sha512 => pq.sha_512.digest(input, out[0..64]),
                    .sha3_256 => pq.sha3_256.digest(input, out[0..32]),
                    .shake128 => pq.shake128.digest(input, out[0..32]),
                    .shake256 => pq.shake256.digest(input, out[0..64]),
                }

                std.mem.doNotOptimizeAway(&out);
            }

            return r.now() - start;
        }
    };

    try runner.case("sha-256/64B", &Digest{ .input = data[0..64], .kind = .sha256 });

    try runner.case("sha-256/1KiB", &Digest{ .input = &data, .kind = .sha256 });

    try runner.case("sha-512/1KiB", &Digest{ .input = &data, .kind = .sha512 });

    try runner.case("sha3-256/1KiB", &Digest{ .input = &data, .kind = .sha3_256 });

    try runner.case("shake128/1KiB", &Digest{ .input = &data, .kind = .shake128 });

    try runner.case("shake256/1KiB", &Digest{ .input = &data, .kind = .shake256 });
}

// The symmetric functions of round E: every hash, XOF and MAC on 64 bytes and 1 KiB (XOFs give 32
// bytes, or 64 for cSHAKE256), keyed with 32 bytes, with the options configured once; HKDF from a
// 32-byte IKM.
fn symmetric(runner: *const Runner) !void {
    const data = bytes(1024);

    const key = bytes(32);

    const Function = union(enum) {
        hash: pq.HashAlgorithm,
        xof: struct { pq.XofAlgorithm, usize },
        mac: pq.MacAlgorithm,
        kdf: pq.KdfAlgorithm,
    };

    const Case = struct {
        function: Function,
        input: []const u8,
        key: *const [32]u8,
        size: usize,

        fn batch(self: *const @This(), r: *const Runner, count: u64) !i96 {
            var out: [128]u8 = undefined;

            const start = r.now();

            for (0..count) |_| {
                const input = blackBox(self.input);

                switch (self.function) {
                    .hash => |h| h.digest(input, out[0..h.digest_size]),
                    .xof => |x| x[0].digest(input, out[0..x[1]]),
                    .mac => |m| m.digest(self.key, input, out[0..m.digest_size]),
                    .kdf => |k| try k.derive(input, out[0..self.size], .{ .salt = self.key, .info = "crypto-pq benchmark" }),
                }

                std.mem.doNotOptimizeAway(&out);
            }

            return r.now() - start;
        }
    };

    const functions = [_]struct { []const u8, Function }{
        .{ "blake2b-160", .{ .hash = pq.blake2b_160 } },
        .{ "blake2b-256", .{ .hash = pq.blake2b_256 } },
        .{ "blake2b-384", .{ .hash = pq.blake2b_384 } },
        .{ "blake2b-512", .{ .hash = pq.blake2b_512 } },
        .{ "blake2s-128", .{ .hash = pq.blake2s_128 } },
        .{ "blake2s-160", .{ .hash = pq.blake2s_160 } },
        .{ "blake2s-224", .{ .hash = pq.blake2s_224 } },
        .{ "blake2s-256", .{ .hash = pq.blake2s_256 } },
        .{ "blake2b-512+salt", .{ .hash = try pq.blake2b_512.configure(.{ .salt = "crypto-pq salt", .personalization = "crypto-pq person" }) } },
        .{ "ascon-hash256", .{ .hash = pq.ascon_hash256 } },
        .{ "cshake128+S", .{ .xof = .{ try pq.cshake128.configure(.{ .customization = "Email Signature" }), 32 } } },
        .{ "cshake256+S", .{ .xof = .{ try pq.cshake256.configure(.{ .customization = "Email Signature" }), 64 } } },
        .{ "ascon-xof128", .{ .xof = .{ pq.ascon_xof128, 32 } } },
        .{ "ascon-cxof128+Z", .{ .xof = .{ try pq.ascon_cxof128.configure(.{ .customization = "crypto-pq" }), 32 } } },
        .{ "kmac128+S", .{ .mac = try pq.kmac128.configure(.{ .customization = "My Tagged Application" }) } },
        .{ "kmac256+S", .{ .mac = try pq.kmac256.configure(.{ .customization = "My Tagged Application" }) } },
        .{ "blake2b-mac", .{ .mac = pq.blake2b_mac } },
        .{ "blake2s-mac", .{ .mac = pq.blake2s_mac } },
    };

    for (functions) |entry| {
        const name, const function = entry;

        for ([_]usize{ 64, 1024 }, [_][]const u8{ "64B", "1KiB" }) |length, suffix| {
            var buffer: [64]u8 = undefined;

            try runner.case(try std.fmt.bufPrint(&buffer, "{s}/{s}", .{ name, suffix }), &Case{ .function = function, .input = data[0..length], .key = &key, .size = 0 });
        }
    }

    for ([_]pq.KdfAlgorithm{ pq.hkdf_sha_256, pq.hkdf_sha_384, pq.hkdf_sha_512 }, [_][]const u8{ "hkdf-sha-256", "hkdf-sha-384", "hkdf-sha-512" }) |algorithm, name| {
        for ([_]usize{ 32, 64, 128 }) |size| {
            var buffer: [64]u8 = undefined;

            try runner.case(try std.fmt.bufPrint(&buffer, "{s}/32B->{d}B", .{ name, size }), &Case{ .function = .{ .kdf = algorithm }, .input = data[0..32], .key = &key, .size = size });
        }
    }
}

fn kem(runner: *const Runner, algorithm: pq.KemAlgorithm, comptime seed_size: usize, comptime randomness_size: usize) !void {
    var storage: [3][64]u8 = undefined;

    const keygen = std.fmt.bufPrint(&storage[0], "{s}/keygen", .{algorithm.name}) catch unreachable;

    const encaps = std.fmt.bufPrint(&storage[1], "{s}/encaps", .{algorithm.name}) catch unreachable;

    const decaps = std.fmt.bufPrint(&storage[2], "{s}/decaps", .{algorithm.name}) catch unreachable;

    const seed = bytes(seed_size);

    const KeyGen = struct {
        algorithm: pq.KemAlgorithm,
        seed: []const u8,

        fn batch(self: *const @This(), r: *const Runner, count: u64) !i96 {
            const start = r.now();

            for (0..count) |_| {
                var pair = try pq.hazmat.generateKemKeyPair(self.algorithm, r.allocator, blackBox(self.seed));

                std.mem.doNotOptimizeAway(&pair);

                pair.private_key.deinit();

                pair.public_key.deinit();
            }

            return r.now() - start;
        }
    };

    try runner.case(keygen, &KeyGen{ .algorithm = algorithm, .seed = &seed });

    if (!runner.selects(encaps) and !runner.selects(decaps)) return;

    var pair = try pq.hazmat.generateKemKeyPair(algorithm, runner.allocator, &seed);

    defer pair.private_key.deinit();

    defer pair.public_key.deinit();

    const randomness = bytes(randomness_size);

    const Encaps = struct {
        public_key: *const pq.KemPublicKey,
        randomness: []const u8,

        fn batch(self: *const @This(), r: *const Runner, count: u64) !i96 {
            const start = r.now();

            for (0..count) |_| {
                const encapsulation = try pq.hazmat.encapsulate(self.public_key, blackBox(self.randomness));

                std.mem.doNotOptimizeAway(&encapsulation);
            }

            return r.now() - start;
        }
    };

    try runner.case(encaps, &Encaps{ .public_key = &pair.public_key, .randomness = &randomness });

    const encapsulation = try pq.hazmat.encapsulate(&pair.public_key, &randomness);

    const Decaps = struct {
        private_key: *const pq.KemPrivateKey,
        ciphertext: []const u8,

        fn batch(self: *const @This(), r: *const Runner, count: u64) !i96 {
            const start = r.now();

            for (0..count) |_| {
                const shared_secret = try self.private_key.decapsulate(blackBox(self.ciphertext));

                std.mem.doNotOptimizeAway(&shared_secret);
            }

            return r.now() - start;
        }
    };

    try runner.case(decaps, &Decaps{ .private_key = &pair.private_key, .ciphertext = encapsulation.ciphertext() });
}

// SLH-DSA signing costs the same for every message, so its cases use one message; ML-DSA rotates.
fn signature(runner: *const Runner, algorithm: pq.SignatureAlgorithm, seed_size: usize, rotate: bool) !void {
    var storage: [3][64]u8 = undefined;

    const keygen, const sign, const verify = names(&storage, algorithm.name);

    const seed_buffer = bytes(96);

    const seed = seed_buffer[0..seed_size];

    const KeyGen = struct {
        algorithm: pq.SignatureAlgorithm,
        seed: []const u8,

        fn batch(self: *const @This(), r: *const Runner, count: u64) !i96 {
            const start = r.now();

            for (0..count) |_| {
                var pair = try pq.hazmat.generateSignatureKeyPair(self.algorithm, r.allocator, blackBox(self.seed));

                std.mem.doNotOptimizeAway(&pair);

                pair.private_key.deinit();

                pair.public_key.deinit();
            }

            return r.now() - start;
        }
    };

    try runner.case(keygen, &KeyGen{ .algorithm = algorithm, .seed = seed });

    if (!runner.selects(sign) and !runner.selects(verify)) return;

    var pair = try pq.hazmat.generateSignatureKeyPair(algorithm, runner.allocator, seed);

    defer pair.private_key.deinit();

    defer pair.public_key.deinit();

    const messages: Messages = .init();

    const used: usize = if (rotate) message_count else 1;

    const Sign = struct {
        private_key: *const pq.SignaturePrivateKey,
        messages: *const Messages,
        used: usize,
        next: usize = 0,

        fn batch(self: *@This(), r: *const Runner, count: u64) !i96 {
            const start = r.now();

            for (0..count) |_| {
                const message = self.messages.get(self.next % self.used);

                self.next += 1;

                const out = try self.private_key.sign(r.allocator, blackBox(message), .{ .deterministic = true });

                std.mem.doNotOptimizeAway(out.ptr);

                r.allocator.free(out);
            }

            return r.now() - start;
        }
    };

    var signer: Sign = .{ .private_key = &pair.private_key, .messages = &messages, .used = used };

    try runner.case(sign, &signer);

    if (!runner.selects(verify)) return;

    var signatures: [message_count][]u8 = undefined;

    for (signatures[0..used], 0..) |*out, i| {
        out.* = try pair.private_key.sign(runner.allocator, messages.get(i), .{ .deterministic = true });
    }

    defer for (signatures[0..used]) |out| runner.allocator.free(out);

    const Verify = struct {
        public_key: *const pq.SignaturePublicKey,
        messages: *const Messages,
        signatures: []const []u8,
        next: usize = 0,

        fn batch(self: *@This(), r: *const Runner, count: u64) !i96 {
            const start = r.now();

            for (0..count) |_| {
                const i = self.next % self.signatures.len;

                self.next += 1;

                if (!self.public_key.verify(blackBox(self.signatures[i]), self.messages.get(i), .{})) return error.VerifyFailed;
            }

            return r.now() - start;
        }
    };

    var verifier: Verify = .{ .public_key = &pair.public_key, .messages = &messages, .signatures = signatures[0..used] };

    try runner.case(verify, &verifier);
}

const Stateful = struct {
    algorithm: pq.StatefulSignatureAlgorithm,
    parameters: pq.StatefulParameters,
    seed: []const u8,

    fn generate(self: *const Stateful, allocator: Allocator, store: *MemoryStore) !pq.StatefulKeyPair {
        store.deinit();

        return pq.hazmat.generateStatefulKeyPair(self.algorithm, allocator, self.parameters, self.seed, 0, store.store(), .{});
    }
};

fn stateful(runner: *const Runner, name: []const u8, setup: Stateful) !void {
    var storage: [3][64]u8 = undefined;

    const keygen, const sign, const verify = names(&storage, name);

    const KeyGen = struct {
        setup: *const Stateful,

        fn batch(self: *const @This(), r: *const Runner, count: u64) !i96 {
            var store: MemoryStore = .{ .allocator = r.allocator };

            defer store.deinit();

            const start = r.now();

            for (0..count) |_| {
                var pair = try self.setup.generate(r.allocator, &store);

                std.mem.doNotOptimizeAway(&pair);

                pair.private_key.deinit(r.allocator);
            }

            return r.now() - start;
        }
    };

    try runner.case(keygen, &KeyGen{ .setup = &setup });

    const messages: Messages = .init();

    // An exhausted key is replaced outside the measured time.
    const Sign = struct {
        setup: *const Stateful,
        messages: *const Messages,
        store: MemoryStore,
        key: ?pq.StatefulPrivateKey = null,
        next: usize = 0,

        fn batch(self: *@This(), r: *const Runner, count: u64) !i96 {
            var elapsed: i96 = 0;

            for (0..count) |_| {
                if (self.key == null or self.key.?.remainingSignatures() == 0) {
                    if (self.key) |*key| key.deinit(r.allocator);

                    self.key = (try self.setup.generate(r.allocator, &self.store)).private_key;
                }

                const message = self.messages.get(self.next);

                self.next += 1;

                const start = r.now();

                const out = try self.key.?.sign(r.allocator, blackBox(message));

                elapsed += r.now() - start;

                std.mem.doNotOptimizeAway(out.ptr);

                r.allocator.free(out);
            }

            return elapsed;
        }

        fn deinit(self: *@This(), allocator: Allocator) void {
            if (self.key) |*key| key.deinit(allocator);

            self.store.deinit();
        }
    };

    var signer: Sign = .{ .setup = &setup, .messages = &messages, .store = .{ .allocator = runner.allocator } };

    defer signer.deinit(runner.allocator);

    try runner.case(sign, &signer);

    if (!runner.selects(verify)) return;

    var store: MemoryStore = .{ .allocator = runner.allocator };

    defer store.deinit();

    var pair = try setup.generate(runner.allocator, &store);

    defer pair.private_key.deinit(runner.allocator);

    var signatures: [message_count][]u8 = undefined;

    for (&signatures, 0..) |*out, i| {
        out.* = try pair.private_key.sign(runner.allocator, messages.get(i));
    }

    defer for (signatures) |out| runner.allocator.free(out);

    const Verify = struct {
        public_key: *const pq.StatefulPublicKey,
        messages: *const Messages,
        signatures: []const []u8,
        next: usize = 0,

        fn batch(self: *@This(), r: *const Runner, count: u64) !i96 {
            const start = r.now();

            for (0..count) |_| {
                const i = self.next % message_count;

                self.next += 1;

                if (!self.public_key.verify(blackBox(self.signatures[i]), self.messages.get(i))) return error.VerifyFailed;
            }

            return r.now() - start;
        }
    };

    var verifier: Verify = .{ .public_key = &pair.public_key, .messages = &messages, .signatures = &signatures };

    try runner.case(verify, &verifier);
}

// Loading a key builds its trees from the leaves; with a tree cache it recomputes the parents of
// the cached nodes instead.
fn load(runner: *const Runner, name: []const u8, setup: Stateful) !void {
    var storage: [2][64]u8 = undefined;

    const plain = try std.fmt.bufPrint(&storage[0], "{s}/load", .{name});

    const cached = try std.fmt.bufPrint(&storage[1], "{s}/load+cache", .{name});

    if (!runner.selects(plain) and !runner.selects(cached)) return;

    var store: MemoryStore = .{ .allocator = runner.allocator };

    defer store.deinit();

    var pair = try setup.generate(runner.allocator, &store);

    defer pair.private_key.deinit(runner.allocator);

    const cache = try pair.private_key.exportTreeCache(runner.allocator);

    defer runner.allocator.free(cache);

    const Load = struct {
        algorithm: pq.StatefulSignatureAlgorithm,
        store: *MemoryStore,
        cache: ?[]const u8,

        fn batch(self: *const @This(), r: *const Runner, count: u64) !i96 {
            const start = r.now();

            for (0..count) |_| {
                var key = try self.algorithm.loadPrivateKey(r.allocator, self.store.store(), .{ .tree_cache = self.cache });

                key.deinit(r.allocator);
            }

            return r.now() - start;
        }
    };

    try runner.case(plain, &Load{ .algorithm = setup.algorithm, .store = &store, .cache = null });

    try runner.case(cached, &Load{ .algorithm = setup.algorithm, .store = &store, .cache = cache });
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var filter: ?[]const u8 = null;

    for (args[1..]) |arg| {
        if (!std.mem.startsWith(u8, arg, "--")) {
            filter = arg;

            break;
        }
    }

    var buffer: [4096]u8 = undefined;

    var writer: Io.File.Writer = .init(.stdout(), init.io, &buffer);

    const runner: Runner = .{ .io = init.io, .allocator = init.gpa, .filter = filter, .out = &writer.interface };

    try hashes(&runner);

    try symmetric(&runner);

    for ([_]pq.KemAlgorithm{ pq.ml_kem_512, pq.ml_kem_768, pq.ml_kem_1024 }) |algorithm| {
        try kem(&runner, algorithm, 64, 32);
    }

    try kem(&runner, pq.x_wing, 32, 64);

    for ([_]pq.SignatureAlgorithm{ pq.ml_dsa_44, pq.ml_dsa_65, pq.ml_dsa_87 }) |algorithm| {
        try signature(&runner, algorithm, 32, true);
    }

    for (slh_dsa) |algorithm| {
        try signature(&runner, algorithm, 3 * (algorithm.public_key_size / 2), false);
    }

    const seed = bytes(96);

    try stateful(&runner, "HSS-H10-W4", .{
        .algorithm = pq.hss_lms,
        .parameters = .{ .levels = &.{.{ .lms = "LMS_SHA256_M32_H10", .ots = "LMOTS_SHA256_N32_W4" }} },
        .seed = seed[0..48],
    });

    try stateful(&runner, "HSS-H5H5-W8", .{
        .algorithm = pq.hss_lms,
        .parameters = .{ .levels = &.{
            .{ .lms = "LMS_SHA256_M32_H5", .ots = "LMOTS_SHA256_N32_W8" },
            .{ .lms = "LMS_SHA256_M32_H5", .ots = "LMOTS_SHA256_N32_W8" },
        } },
        .seed = seed[0..48],
    });

    try stateful(&runner, "XMSS-SHA2_10_256", .{ .algorithm = pq.xmss, .parameters = .{ .name = "XMSS-SHA2_10_256" }, .seed = seed[0..96] });

    try stateful(&runner, "XMSSMT-SHA2_20/4_256", .{ .algorithm = pq.xmss_mt, .parameters = .{ .name = "XMSSMT-SHA2_20/4_256" }, .seed = seed[0..96] });

    try load(&runner, "HSS-H15-W4", .{
        .algorithm = pq.hss_lms,
        .parameters = .{ .levels = &.{.{ .lms = "LMS_SHA256_M32_H15", .ots = "LMOTS_SHA256_N32_W4" }} },
        .seed = seed[0..48],
    });

    // A tree of height 20 takes tens of seconds to build, so it runs only when a filter selects it.
    if (filter != null) {
        try load(&runner, "HSS-H20-W4", .{
            .algorithm = pq.hss_lms,
            .parameters = .{ .levels = &.{.{ .lms = "LMS_SHA256_M32_H20", .ots = "LMOTS_SHA256_N32_W4" }} },
            .seed = seed[0..48],
        });
    }
}

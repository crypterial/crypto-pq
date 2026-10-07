const std = @import("std");
const pq = @import("crypto_pq");

const hazmat = pq.hazmat;

const memcheck = std.valgrind.memcheck;

const Allocator = std.mem.Allocator;

// `zig build ct -Dct=true` runs this under valgrind's memcheck. Seeds and hazmat randomness are
// marked uninitialised here, and the library marks the operating system's random bytes the same
// way, so memcheck reports every branch and memory index that depends on a secret. The library
// declassifies only what the specifications make public; results are declassified here before
// they are compared.

const message = "crypto-pq constant-time check";

fn secretBytes(comptime size: usize, first: u8) [size]u8 {
    var bytes: [size]u8 = undefined;

    for (&bytes, 0..) |*byte, i| byte.* = first +% @as(u8, @truncate(i));

    memcheck.makeMemUndefined(&bytes);

    return bytes;
}

fn check(ok: bool) !void {
    if (!ok) return error.CheckFailed;
}

fn same(a: []const u8, b: []const u8) bool {
    memcheck.makeMemDefined(a);

    memcheck.makeMemDefined(b);

    return std.mem.eql(u8, a, b);
}

fn kem(allocator: Allocator, algorithm: pq.KemAlgorithm, comptime seed_size: usize, comptime randomness_size: usize) !void {
    const seed = secretBytes(seed_size, 1);

    var pair = try hazmat.generateKemKeyPair(algorithm, allocator, &seed);

    defer pair.private_key.deinit();

    defer pair.public_key.deinit();

    const randomness = secretBytes(randomness_size, 2);

    var encapsulation = try hazmat.encapsulate(&pair.public_key, &randomness);

    var shared_secret = try pair.private_key.decapsulate(encapsulation.ciphertext());

    // Implicit rejection takes the same path: a changed ciphertext gives an unrelated secret.
    encapsulation.ciphertext_buffer[0] ^= 1;

    var rejected = try pair.private_key.decapsulate(encapsulation.ciphertext());

    try check(same(&shared_secret, &encapsulation.shared_secret) and !same(&rejected, &shared_secret));

    var generated = try algorithm.generateKeyPair(allocator, .{});

    defer generated.private_key.deinit();

    defer generated.public_key.deinit();

    var fresh = try generated.public_key.encapsulate();

    var decapsulated = try generated.private_key.decapsulate(fresh.ciphertext());

    try check(same(&decapsulated, &fresh.shared_secret));
}

fn signature(allocator: Allocator, algorithm: pq.SignatureAlgorithm, comptime seed_size: usize, comptime randomness_size: usize) !void {
    const seed = secretBytes(seed_size, 3);

    var pair = try hazmat.generateSignatureKeyPair(algorithm, allocator, &seed);

    defer pair.private_key.deinit();

    defer pair.public_key.deinit();

    const randomness = secretBytes(randomness_size, 4);

    const signed = try hazmat.sign(&pair.private_key, allocator, message, &randomness, .{});

    defer allocator.free(signed);

    try check(pair.public_key.verify(signed, message, .{}));

    // Key generation signs and verifies once more as its pairwise self-test.
    var generated = try algorithm.generateKeyPair(allocator, .{});

    defer generated.private_key.deinit();

    defer generated.public_key.deinit();

    for ([_]bool{ false, true }) |deterministic| {
        const output = try generated.private_key.sign(allocator, message, .{ .deterministic = deterministic, .context = "context" });

        defer allocator.free(output);

        try check(generated.public_key.verify(output, message, .{ .context = "context" }));
    }
}

// A private key from outside is secret as a whole: the library declassifies only what it holds
// of the public key. Each key also goes out and back in as DER; PEM is only exported. Public keys
// come from the pair, from the private key and from their bytes, so the cached forms of the keys
// are built in every way there is: at generation, and on first use from either key of a pair.
fn importedKem(allocator: Allocator, algorithm: pq.KemAlgorithm) !void {
    var pair = try hazmat.generateKemKeyPair(algorithm, allocator, &secretBytes(64, 6));

    defer pair.private_key.deinit();

    defer pair.public_key.deinit();

    var imported_public = try algorithm.importPublicKey(allocator, pair.public_key.public.bytes[0..algorithm.public_key_size], .raw);

    defer imported_public.deinit();

    const size = 2 * algorithm.public_key_size + 32;

    var expanded = pair.private_key.secret.dk;

    memcheck.makeMemUndefined(expanded[0..size]);

    var imported = try algorithm.importPrivateKey(allocator, expanded[0..size], .raw);

    defer imported.deinit();

    for ([_]*const pq.KemPrivateKey{ &pair.private_key, &imported }) |key| {
        allocator.free(try key.exportKey(allocator, .pem));

        const der = try key.exportKey(allocator, .der);

        defer allocator.free(der);

        var again = try algorithm.importPrivateKey(allocator, der, .der);

        defer again.deinit();

        for ([_]*const pq.KemPrivateKey{ key, &again }) |decapsulator| {
            var derived = decapsulator.publicKey();

            defer derived.deinit();

            for ([_]*const pq.KemPublicKey{ &pair.public_key, &derived, &imported_public }) |encapsulator| {
                var encapsulation = try encapsulator.encapsulate();

                var shared_secret = try decapsulator.decapsulate(encapsulation.ciphertext());

                try check(same(&shared_secret, &encapsulation.shared_secret));
            }
        }
    }
}

fn importedSignature(allocator: Allocator, algorithm: pq.SignatureAlgorithm, comptime seed_size: usize, comptime secret_size: usize) !void {
    var pair = try hazmat.generateSignatureKeyPair(algorithm, allocator, &secretBytes(seed_size, 7));

    defer pair.private_key.deinit();

    defer pair.public_key.deinit();

    var imported_public = try algorithm.importPublicKey(allocator, pair.public_key.public.bytes[0..algorithm.public_key_size], .raw);

    defer imported_public.deinit();

    var raw = pair.private_key.secret.bytes[0..secret_size].*;

    memcheck.makeMemUndefined(&raw);

    var imported = try algorithm.importPrivateKey(allocator, &raw, .raw);

    defer imported.deinit();

    for ([_]*const pq.SignaturePrivateKey{ &pair.private_key, &imported }) |key| {
        allocator.free(try key.exportKey(allocator, .pem));

        const der = try key.exportKey(allocator, .der);

        defer allocator.free(der);

        var again = try algorithm.importPrivateKey(allocator, der, .der);

        defer again.deinit();

        for ([_]*const pq.SignaturePrivateKey{ key, &again }) |signer| {
            const signed = try signer.sign(allocator, message, .{});

            defer allocator.free(signed);

            var derived = signer.publicKey();

            defer derived.deinit();

            for ([_]*const pq.SignaturePublicKey{ &pair.public_key, &derived, &imported_public }) |verifier| {
                try check(verifier.verify(signed, message, .{}));
            }
        }
    }
}

// A store with a single writer: its states hold secret seeds, so it never compares them.
const Store = struct {
    allocator: Allocator,
    state: ?[]u8 = null,

    const vtable: pq.StateStore.VTable = .{ .read = read, .update = update };

    fn deinit(self: *Store) void {
        if (self.state) |state| self.allocator.free(state);
    }

    fn store(self: *Store) pq.StateStore {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn read(ptr: *anyopaque, allocator: Allocator) anyerror!?[]u8 {
        const self: *Store = @ptrCast(@alignCast(ptr));

        const state = self.state orelse return null;

        return try allocator.dupe(u8, state);
    }

    fn update(ptr: *anyopaque, previous: ?[]const u8, next: []const u8) anyerror!bool {
        const self: *Store = @ptrCast(@alignCast(ptr));

        _ = previous;

        const copy = try self.allocator.dupe(u8, next);

        self.deinit();

        self.state = copy;

        return true;
    }
};

fn signs(allocator: Allocator, public_key: *const pq.StatefulPublicKey, private_key: *pq.StatefulPrivateKey) !void {
    const signed = try private_key.sign(allocator, message);

    defer allocator.free(signed);

    try check(public_key.verify(signed, message));
}

fn stateful(allocator: Allocator, algorithm: pq.StatefulSignatureAlgorithm, parameters: pq.StatefulParameters, comptime seed_size: usize) !void {
    var store: Store = .{ .allocator = allocator };

    defer store.deinit();

    const seed = secretBytes(seed_size, 5);

    var pair = try hazmat.generateStatefulKeyPair(algorithm, allocator, parameters, &seed, 0, store.store(), .{});

    defer pair.private_key.deinit(allocator);

    try signs(allocator, &pair.public_key, &pair.private_key);

    // Loading rebuilds the trees from the seeds in the stored state.
    var loaded = try algorithm.loadPrivateKey(allocator, store.store(), .{});

    defer loaded.deinit(allocator);

    try signs(allocator, &pair.public_key, &loaded);

    // A tree cache is public, and its tag key comes from the seeds: loading with it checks the tag
    // and the nodes, and restores the trees that the stored index still signs with.
    const cache = try pair.private_key.exportTreeCache(allocator);

    defer allocator.free(cache);

    var restored = try algorithm.loadPrivateKey(allocator, store.store(), .{ .tree_cache = cache });

    defer restored.deinit(allocator);

    try signs(allocator, &pair.public_key, &restored);

    var fresh: Store = .{ .allocator = allocator };

    defer fresh.deinit();

    var generated = try algorithm.generateKeyPair(allocator, parameters, fresh.store(), .{});

    defer generated.private_key.deinit(allocator);

    try signs(allocator, &generated.public_key, &generated.private_key);
}

// A MAC's result is the answer the caller asked for: declassified before it is branched on.
fn verified(result: bool) bool {
    var copy = result;

    memcheck.makeMemDefined(std.mem.asBytes(&copy));

    return copy;
}

fn mac(algorithm: pq.MacAlgorithm, key: []const u8, data: []const u8) !void {
    var tag: [200]u8 = undefined;

    const out = tag[0..algorithm.digest_size];

    algorithm.digest(key, data, out);

    try check(verified(algorithm.verify(key, data, out)));

    var state = algorithm.create(key);

    const split = @min(7, data.len);

    state.update(data[0..split]);

    state.update(data[split..]);

    var streamed: [200]u8 = undefined;

    state.digest(streamed[0..out.len]);

    try check(same(out, streamed[0..out.len]) and verified(state.verify(out)));
}

// Keyed functions with secret keys and data; plain hashes and XOFs, whose input may be secret too.
fn symmetric() !void {
    const key = secretBytes(200, 11);

    const data = secretBytes(300, 12);

    for ([_]pq.MacAlgorithm{ pq.hmac_sha_224, pq.hmac_sha_256, pq.hmac_sha_384, pq.hmac_sha_512 }) |algorithm| {
        for ([_]usize{ 32, 200 }) |length| try mac(algorithm, key[0..length], &data);
    }

    for ([_]pq.MacAlgorithm{ pq.kmac128, pq.kmac256 }) |algorithm| {
        try mac(algorithm, key[0..32], &data);

        try mac(try algorithm.configure(.{ .length = 100, .customization = "customization", .xof = true }), &key, &data);

        try mac(try algorithm.configure(.{ .length = 4 }), key[0..16], data[0..10]);
    }

    for ([_]pq.MacAlgorithm{ pq.blake2b_mac, pq.blake2s_mac }, [_]usize{ 64, 32 }) |algorithm, max| {
        try mac(algorithm, key[0..max], &data);

        try mac(try algorithm.configure(.{ .length = 17, .salt = "salt", .personalization = "personal" }), key[0..1], &data);

        try mac(algorithm, key[0..max], data[0..0]);
    }

    for ([_]pq.KdfAlgorithm{ pq.hkdf_sha_256, pq.hkdf_sha_384, pq.hkdf_sha_512 }) |algorithm| {
        var okm: [300]u8 = undefined;

        try algorithm.derive(&data, &okm, .{ .salt = key[0..20], .info = "info" });

        var prk: [64]u8 = undefined;

        try algorithm.extract(&data, prk[0..algorithm.hashSize()], .{ .salt = key[0..20] });

        var expanded: [300]u8 = undefined;

        try algorithm.expand(prk[0..algorithm.hashSize()], &expanded, .{ .info = "info" });

        try check(same(&okm, &expanded));

        // A secret PRK longer than a block, and an info that takes the streaming path.
        try algorithm.expand(&key, &expanded, .{ .info = &data });
    }

    var out: [64]u8 = undefined;

    for ([_]pq.HashAlgorithm{ pq.blake2b_512, pq.blake2s_256, pq.blake2b_160, pq.ascon_hash256 }) |algorithm| {
        algorithm.digest(&data, out[0..algorithm.digest_size]);

        const configured = algorithm.configure(.{ .salt = "s", .personalization = "p" }) catch algorithm;

        var hasher = configured.create();

        hasher.update(&data);

        hasher.digest(out[0..algorithm.digest_size]);
    }

    for ([_]pq.XofAlgorithm{ pq.cshake128, pq.cshake256, pq.ascon_xof128, pq.ascon_cxof128 }) |algorithm| {
        const configured = algorithm.configure(.{ .customization = "customization" }) catch algorithm;

        configured.digest(&data, &out);

        var xof = configured.create();

        xof.update(&data);

        xof.read(&out);
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    try symmetric();

    std.debug.print("hashes, MACs and HKDF: ok\n", .{});

    for ([_]pq.KemAlgorithm{ pq.ml_kem_512, pq.ml_kem_768, pq.ml_kem_1024 }) |algorithm| {
        try kem(allocator, algorithm, 64, 32);

        try importedKem(allocator, algorithm);

        std.debug.print("{s}: ok\n", .{algorithm.name});
    }

    try kem(allocator, pq.x_wing, 32, 64);

    std.debug.print("{s}: ok\n", .{pq.x_wing.name});

    inline for (.{ pq.ml_dsa_44, pq.ml_dsa_65, pq.ml_dsa_87 }, .{ 2560, 4032, 4896 }) |algorithm, secret_size| {
        try signature(allocator, algorithm, 32, 32);

        try importedSignature(allocator, algorithm, 32, secret_size);

        std.debug.print("{s}: ok\n", .{algorithm.name});
    }

    inline for (.{ pq.slh_dsa_sha2_192f, pq.slh_dsa_shake_128f }) |algorithm| {
        const n = algorithm.public_key_size / 2;

        try signature(allocator, algorithm, 3 * n, n);

        try importedSignature(allocator, algorithm, 3 * n, 4 * n);

        std.debug.print("{s}: ok\n", .{algorithm.name});
    }

    const levels = [_]pq.HssLevel{
        .{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W4" },
        .{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W2" },
    };

    try stateful(allocator, pq.hss_lms, .{ .levels = &levels }, 16 + 24);

    try stateful(allocator, pq.hss_lms, .{ .levels = &.{.{ .lms = "LMS_SHAKE_M32_H5", .ots = "LMOTS_SHAKE_N32_W4" }} }, 16 + 32);

    std.debug.print("HSS/LMS: ok\n", .{});

    try stateful(allocator, pq.xmss_mt, .{ .name = "XMSSMT-SHA2_20/4_256" }, 3 * 32);

    try stateful(allocator, pq.xmss_mt, .{ .name = "XMSSMT-SHAKE256_20/4_192" }, 3 * 24);

    std.debug.print("XMSS^MT: ok\n", .{});
}

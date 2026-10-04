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

    var fresh: Store = .{ .allocator = allocator };

    defer fresh.deinit();

    var generated = try algorithm.generateKeyPair(allocator, parameters, fresh.store(), .{});

    defer generated.private_key.deinit(allocator);

    try signs(allocator, &generated.public_key, &generated.private_key);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

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

const std = @import("std");

const ct = @import("ct.zig");
const encoding = @import("encoding.zig");
const Error = @import("errors.zig").Error;
const keys = @import("keys.zig");
const mlkem = @import("mlkem.zig");
const rng = @import("rng.zig");
const xwing = @import("xwing.zig");

const Allocator = std.mem.Allocator;

const KeyFormat = keys.KeyFormat;

const KeyGenOptions = keys.KeyGenOptions;

const max_public_key_size = mlkem.ml_kem_1024.encapsulationKeySize();

const max_ciphertext_size = mlkem.ml_kem_1024.ciphertextSize();

const max_decapsulation_key_size = mlkem.ml_kem_1024.decapsulationKeySize();

const max_seed_size = 64;

pub const KemAlgorithm = struct {
    name: []const u8,
    public_key_size: usize,
    ciphertext_size: usize,
    shared_secret_size: usize,
    kind: Kind,

    pub const Kind = enum { ml_kem_512, ml_kem_768, ml_kem_1024, x_wing };

    pub fn generateKeyPair(self: KemAlgorithm, options: KeyGenOptions) Error!KemKeyPair {
        var seed: [max_seed_size]u8 = undefined;

        defer ct.wipe(&seed);

        const size = seedSize(self.kind);

        try rng.fill(seed[0..size]);

        var private_key = fromSeed(self, seed[0..size]);

        errdefer private_key.deinit();

        const public_key = private_key.publicKey();

        if (options.self_test) {
            var encapsulation = try public_key.encapsulate();

            defer ct.wipe(&encapsulation.shared_secret);

            var shared_secret = try private_key.decapsulate(encapsulation.ciphertext());

            defer ct.wipe(&shared_secret);

            if (!ct.equal(&shared_secret, &encapsulation.shared_secret)) return error.SelfTestFailed;
        }

        return .{ .public_key = public_key, .private_key = private_key };
    }

    pub fn importPublicKey(self: KemAlgorithm, data: []const u8, format: KeyFormat) Error!KemPublicKey {
        var buffer: keys.PemBuffer = undefined;

        const key = try keys.importPublic(format, data, objectIdentifier(self.kind), &buffer);

        if (key.len != publicKeySize(self.kind)) return if (format == .raw) error.InvalidLength else error.InvalidEncoding;

        if (!checkPublicKey(self.kind, key)) return error.InvalidPublicKey;

        var public_key: KemPublicKey = .{ .algorithm = self, .bytes = undefined };

        ct.wipe(&public_key.bytes);

        @memcpy(public_key.bytes[0..key.len], key);

        return public_key;
    }

    pub fn importPrivateKey(self: KemAlgorithm, data: []const u8, format: KeyFormat) Error!KemPrivateKey {
        var buffer: keys.PemBuffer = undefined;

        defer if (format == .pem) ct.wipe(&buffer);

        switch (try keys.importPrivate(format, data, objectIdentifier(self.kind), &buffer)) {
            .raw => |raw| {
                if (raw.len == seedSize(self.kind)) return fromSeed(self, raw);

                if (self.kind != .x_wing and raw.len == expandedSize(self.kind)) return fromExpanded(self, raw);

                return error.InvalidLength;
            },
            .pkcs8 => |pkcs8| {
                const choice = try keys.decodeSeedChoice(pkcs8.octets, max_seed_size, expandedSize(self.kind));

                var key = if (choice.seed) |seed| fromSeed(self, seed) else try fromExpanded(self, choice.expanded.?);

                errdefer key.deinit();

                if (choice.seed != null and choice.expanded != null) {
                    if (!ct.equal(choice.expanded.?, key.expanded())) return error.InvalidPrivateKey;
                }

                if (pkcs8.public_key) |public_key| {
                    if (!ct.equal(public_key, key.publicBytes())) return error.InvalidPrivateKey;
                }

                return key;
            },
        }
    }
};

pub const Encapsulation = struct {
    shared_secret: [32]u8,
    ciphertext_buffer: [max_ciphertext_size]u8,
    ciphertext_size: usize,

    pub fn ciphertext(self: *const Encapsulation) []const u8 {
        return self.ciphertext_buffer[0..self.ciphertext_size];
    }
};

pub const KemPublicKey = struct {
    algorithm: KemAlgorithm,
    bytes: [max_public_key_size]u8,

    pub fn encapsulate(self: *const KemPublicKey) Error!Encapsulation {
        var randomness: [xwing.randomness_size]u8 = undefined;

        defer ct.wipe(&randomness);

        const size = randomnessSize(self.algorithm.kind);

        try rng.fill(randomness[0..size]);

        return encapsulateWith(self, randomness[0..size]);
    }

    pub fn exportKey(self: *const KemPublicKey, allocator: Allocator, format: KeyFormat) (Error || Allocator.Error)![]u8 {
        return keys.exportPublic(allocator, format, objectIdentifier(self.algorithm.kind), self.raw());
    }

    pub fn eql(self: *const KemPublicKey, other: *const KemPublicKey) bool {
        return self.algorithm.kind == other.algorithm.kind and std.mem.eql(u8, self.raw(), other.raw());
    }

    fn raw(self: *const KemPublicKey) []const u8 {
        return self.bytes[0..publicKeySize(self.algorithm.kind)];
    }
};

pub const KemPrivateKey = struct {
    algorithm: KemAlgorithm,
    seed: [max_seed_size]u8,
    has_seed: bool,
    dk: [max_decapsulation_key_size]u8,
    scalar: [32]u8,
    public: [max_public_key_size]u8,

    pub fn publicKey(self: *const KemPrivateKey) KemPublicKey {
        return .{ .algorithm = self.algorithm, .bytes = self.public };
    }

    pub fn decapsulate(self: *const KemPrivateKey, ciphertext: []const u8) Error![32]u8 {
        switch (self.algorithm.kind) {
            inline .ml_kem_512, .ml_kem_768, .ml_kem_1024 => |kind| {
                const p = comptime parameters(kind);

                try keys.requireLength(ciphertext, p.ciphertextSize());

                return mlkem.decaps(p, self.dk[0..p.decapsulationKeySize()], ciphertext[0..p.ciphertextSize()]);
            },
            .x_wing => {
                try keys.requireLength(ciphertext, xwing.ciphertext_size);

                return xwing.decapsulate(self.dk[0..@sizeOf(xwing.DecapsulationKey)], &self.scalar, self.public[0..xwing.public_key_size], ciphertext[0..xwing.ciphertext_size]);
            },
        }
    }

    pub fn exportKey(self: *const KemPrivateKey, allocator: Allocator, format: KeyFormat) (Error || Allocator.Error)![]u8 {
        const oid = objectIdentifier(self.algorithm.kind);

        if (self.has_seed) return keys.exportPrivate(allocator, format, oid, encoding.context_0, self.seed[0..seedSize(self.algorithm.kind)]);

        return keys.exportPrivate(allocator, format, oid, encoding.octet_string, self.expanded());
    }

    pub fn deinit(self: *KemPrivateKey) void {
        ct.wipe(&self.seed);

        ct.wipe(&self.dk);

        ct.wipe(&self.scalar);
    }

    fn expanded(self: *const KemPrivateKey) []const u8 {
        return self.dk[0..expandedSize(self.algorithm.kind)];
    }

    fn publicBytes(self: *const KemPrivateKey) []const u8 {
        return self.public[0..publicKeySize(self.algorithm.kind)];
    }
};

pub const KemKeyPair = struct {
    public_key: KemPublicKey,
    private_key: KemPrivateKey,
};

fn parameters(comptime kind: KemAlgorithm.Kind) mlkem.Parameters {
    return switch (kind) {
        .ml_kem_512 => mlkem.ml_kem_512,
        .ml_kem_768 => mlkem.ml_kem_768,
        .ml_kem_1024 => mlkem.ml_kem_1024,
        .x_wing => unreachable,
    };
}

fn objectIdentifier(kind: KemAlgorithm.Kind) ?[]const u8 {
    return switch (kind) {
        .ml_kem_512 => encoding.objectIdentifier(&.{ 2, 16, 840, 1, 101, 3, 4, 4, 1 }),
        .ml_kem_768 => encoding.objectIdentifier(&.{ 2, 16, 840, 1, 101, 3, 4, 4, 2 }),
        .ml_kem_1024 => encoding.objectIdentifier(&.{ 2, 16, 840, 1, 101, 3, 4, 4, 3 }),
        .x_wing => null,
    };
}

pub fn seedSize(kind: KemAlgorithm.Kind) usize {
    return if (kind == .x_wing) xwing.seed_size else max_seed_size;
}

pub fn randomnessSize(kind: KemAlgorithm.Kind) usize {
    return if (kind == .x_wing) xwing.randomness_size else 32;
}

fn publicKeySize(kind: KemAlgorithm.Kind) usize {
    return switch (kind) {
        inline .ml_kem_512, .ml_kem_768, .ml_kem_1024 => |k| comptime parameters(k).encapsulationKeySize(),
        .x_wing => xwing.public_key_size,
    };
}

fn expandedSize(kind: KemAlgorithm.Kind) usize {
    return switch (kind) {
        inline .ml_kem_512, .ml_kem_768, .ml_kem_1024 => |k| comptime parameters(k).decapsulationKeySize(),
        .x_wing => unreachable,
    };
}

fn checkPublicKey(kind: KemAlgorithm.Kind, key: []const u8) bool {
    return switch (kind) {
        inline .ml_kem_512, .ml_kem_768, .ml_kem_1024 => |k| mlkem.checkEncapsulationKey(comptime parameters(k), key[0..comptime parameters(k).encapsulationKeySize()]),
        .x_wing => xwing.checkPublicKey(key[0..xwing.public_key_size]),
    };
}

fn empty(algorithm: KemAlgorithm) KemPrivateKey {
    var key: KemPrivateKey = .{ .algorithm = algorithm, .seed = undefined, .has_seed = false, .dk = undefined, .scalar = undefined, .public = undefined };

    inline for (.{ &key.seed, &key.dk, &key.scalar, &key.public }) |buffer| ct.wipe(buffer);

    return key;
}

// `seed` has the length of the algorithm's seed: d || z for ML-KEM, 32 bytes for X-Wing.
pub fn fromSeed(algorithm: KemAlgorithm, seed: []const u8) KemPrivateKey {
    var key = empty(algorithm);

    key.has_seed = true;

    @memcpy(key.seed[0..seed.len], seed);

    switch (algorithm.kind) {
        inline .ml_kem_512, .ml_kem_768, .ml_kem_1024 => |kind| {
            const p = comptime parameters(kind);

            mlkem.keyGen(p, seed[0..32], seed[32..64], key.public[0..p.encapsulationKeySize()], key.dk[0..p.decapsulationKeySize()]);
        },
        .x_wing => xwing.expand(seed[0..xwing.seed_size], key.public[0..xwing.public_key_size], key.dk[0..@sizeOf(xwing.DecapsulationKey)], &key.scalar),
    }

    return key;
}

fn fromExpanded(algorithm: KemAlgorithm, dk: []const u8) Error!KemPrivateKey {
    switch (algorithm.kind) {
        inline .ml_kem_512, .ml_kem_768, .ml_kem_1024 => |kind| {
            const p = comptime parameters(kind);

            const k: usize = p.k;

            if (!mlkem.checkDecapsulationKey(p, dk[0..p.decapsulationKeySize()])) return error.InvalidPrivateKey;

            var key = empty(algorithm);

            @memcpy(key.dk[0..dk.len], dk);

            @memcpy(key.public[0..p.encapsulationKeySize()], dk[384 * k ..][0..p.encapsulationKeySize()]);

            return key;
        },
        .x_wing => unreachable,
    }
}

// `randomness` has the algorithm's length: m for ML-KEM, the 64-byte eseed for X-Wing.
pub fn encapsulateWith(public_key: *const KemPublicKey, randomness: []const u8) Encapsulation {
    var encapsulation: Encapsulation = .{ .shared_secret = undefined, .ciphertext_buffer = undefined, .ciphertext_size = 0 };

    ct.wipe(&encapsulation.ciphertext_buffer);

    switch (public_key.algorithm.kind) {
        inline .ml_kem_512, .ml_kem_768, .ml_kem_1024 => |kind| {
            const p = comptime parameters(kind);

            encapsulation.ciphertext_size = p.ciphertextSize();

            mlkem.encaps(p, public_key.bytes[0..p.encapsulationKeySize()], randomness[0..32], &encapsulation.shared_secret, encapsulation.ciphertext_buffer[0..p.ciphertextSize()]);
        },
        .x_wing => {
            encapsulation.ciphertext_size = xwing.ciphertext_size;

            xwing.encapsulate(public_key.bytes[0..xwing.public_key_size], randomness[0..xwing.randomness_size], &encapsulation.shared_secret, encapsulation.ciphertext_buffer[0..xwing.ciphertext_size]);
        },
    }

    return encapsulation;
}

pub const ml_kem_512: KemAlgorithm = .{ .name = "ML-KEM-512", .public_key_size = 800, .ciphertext_size = 768, .shared_secret_size = 32, .kind = .ml_kem_512 };

pub const ml_kem_768: KemAlgorithm = .{ .name = "ML-KEM-768", .public_key_size = 1184, .ciphertext_size = 1088, .shared_secret_size = 32, .kind = .ml_kem_768 };

pub const ml_kem_1024: KemAlgorithm = .{ .name = "ML-KEM-1024", .public_key_size = 1568, .ciphertext_size = 1568, .shared_secret_size = 32, .kind = .ml_kem_1024 };

pub const x_wing: KemAlgorithm = .{ .name = "X-Wing", .public_key_size = 1216, .ciphertext_size = 1120, .shared_secret_size = 32, .kind = .x_wing };

const std = @import("std");

const cache = @import("cache.zig");
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

    // `allocator` provides the memory of the keys and of their cache. A key may fill its cache
    // from any thread that uses it, so the allocator must be thread-safe if the keys are.
    pub fn generateKeyPair(self: KemAlgorithm, allocator: Allocator, options: KeyGenOptions) (Error || Allocator.Error)!KemKeyPair {
        var seed: [max_seed_size]u8 = undefined;

        defer ct.wipe(&seed);

        const size = seedSize(self.kind);

        try rng.fill(seed[0..size]);

        var private_key = try fromSeed(self, allocator, seed[0..size], options.self_test);

        errdefer private_key.deinit();

        var public_key = private_key.publicKey();

        errdefer public_key.deinit();

        if (options.self_test) {
            var encapsulation = try public_key.encapsulate();

            defer ct.wipe(&encapsulation.shared_secret);

            var shared_secret = try private_key.decapsulate(encapsulation.ciphertext());

            defer ct.wipe(&shared_secret);

            // The outcome of the pairwise test is public: key generation fails on it.
            if (!ct.declassifyValue(bool, ct.equal(&shared_secret, &encapsulation.shared_secret))) return error.SelfTestFailed;
        }

        return .{ .public_key = public_key, .private_key = private_key };
    }

    // The key's cache is filled on its first use.
    pub fn importPublicKey(self: KemAlgorithm, allocator: Allocator, data: []const u8, format: KeyFormat) (Error || Allocator.Error)!KemPublicKey {
        const buffer = try keys.pemBuffer(allocator, format);

        defer keys.freePemBuffer(allocator, buffer);

        const key = try keys.importPublic(format, data, objectIdentifier(self.kind), buffer);

        if (key.len != publicKeySize(self.kind)) return if (format == .raw) error.InvalidLength else error.InvalidEncoding;

        if (!checkPublicKey(self.kind, key)) return error.InvalidPublicKey;

        const public = try createPublic(allocator);

        @memcpy(public.bytes[0..key.len], key);

        return .{ .algorithm = self, .public = public };
    }

    pub fn importPrivateKey(self: KemAlgorithm, allocator: Allocator, data: []const u8, format: KeyFormat) (Error || Allocator.Error)!KemPrivateKey {
        const buffer = try keys.pemBuffer(allocator, format);

        defer keys.freePemBuffer(allocator, buffer);

        switch (try keys.importPrivate(format, data, objectIdentifier(self.kind), buffer)) {
            .raw => |raw| {
                if (raw.len == seedSize(self.kind)) return fromSeed(self, allocator, raw, false);

                if (self.kind != .x_wing and raw.len == expandedSize(self.kind)) return fromExpanded(self, allocator, raw);

                return error.InvalidLength;
            },
            .pkcs8 => |pkcs8| {
                const choice = try keys.decodeSeedChoice(pkcs8.octets, max_seed_size, expandedSize(self.kind));

                var key = if (choice.seed) |seed| try fromSeed(self, allocator, seed, false) else try fromExpanded(self, allocator, choice.expanded.?);

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

// The public part of a key pair, which its keys share: the key, and the cache of its decoded form
// (the sampled matrix, t̂ and H(ek)), filled on first use.
const Public = struct {
    shared: cache.Shared,
    bytes: [max_public_key_size]u8,
};

// The secret part, which only the private key holds: the seed or the expanded key, and `s`, the
// decoded NTT-form secret that decryption uses. It is wiped before it is freed.
const Secret = struct {
    seed: [max_seed_size]u8,
    has_seed: bool,
    dk: [max_decapsulation_key_size]u8,
    scalar: [32]u8,
    s: [4]mlkem.Poly,
};

// The keys are small handles: the key material is in the heap, so copies stay cheap and the
// stack small. deinit releases the public part, which the last key of a pair frees.
pub const KemPublicKey = struct {
    algorithm: KemAlgorithm,
    public: *Public,

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

    pub fn deinit(self: *KemPublicKey) void {
        release(self.algorithm.kind, self.public);

        self.* = undefined;
    }

    fn raw(self: *const KemPublicKey) []const u8 {
        return self.public.bytes[0..publicKeySize(self.algorithm.kind)];
    }
};

pub const KemPrivateKey = struct {
    algorithm: KemAlgorithm,
    public: *Public,
    secret: *Secret,

    // The public key shares this key's public part and its cache; deinitialize it as well.
    pub fn publicKey(self: *const KemPrivateKey) KemPublicKey {
        self.public.shared.retain();

        return .{ .algorithm = self.algorithm, .public = self.public };
    }

    pub fn decapsulate(self: *const KemPrivateKey, ciphertext: []const u8) Error![32]u8 {
        switch (self.algorithm.kind) {
            inline .ml_kem_512, .ml_kem_768, .ml_kem_1024 => |kind| {
                const p = comptime parameters(kind);

                try keys.requireLength(ciphertext, p.ciphertextSize());

                return decapsulateMlKem(p, self, ciphertext[0..p.ciphertextSize()]);
            },
            .x_wing => {
                try keys.requireLength(ciphertext, xwing.ciphertext_size);

                return decapsulateXWing(self, ciphertext[0..xwing.ciphertext_size]);
            },
        }
    }

    pub fn exportKey(self: *const KemPrivateKey, allocator: Allocator, format: KeyFormat) (Error || Allocator.Error)![]u8 {
        const oid = objectIdentifier(self.algorithm.kind);

        if (self.secret.has_seed) return keys.exportPrivate(allocator, format, oid, encoding.context_0, self.secret.seed[0..seedSize(self.algorithm.kind)]);

        return keys.exportPrivate(allocator, format, oid, encoding.octet_string, self.expanded());
    }

    pub fn deinit(self: *KemPrivateKey) void {
        destroySecret(self.public.shared.allocator, self.secret);

        release(self.algorithm.kind, self.public);

        self.* = undefined;
    }

    fn expanded(self: *const KemPrivateKey) []const u8 {
        return self.secret.dk[0..expandedSize(self.algorithm.kind)];
    }

    fn publicBytes(self: *const KemPrivateKey) []const u8 {
        return self.public.bytes[0..publicKeySize(self.algorithm.kind)];
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

// The cache of ML-KEM with this k, X-Wing's included.
fn PublicForm(comptime kind: KemAlgorithm.Kind) type {
    return if (kind == .x_wing) xwing.EncapsulationKey else mlkem.EncapsulationKey(parameters(kind).k);
}

fn createPublic(allocator: Allocator) Allocator.Error!*Public {
    const public = try allocator.create(Public);

    public.shared = .{ .allocator = allocator };

    ct.wipe(&public.bytes);

    return public;
}

fn release(kind: KemAlgorithm.Kind, public: *Public) void {
    if (!public.shared.release()) return;

    const allocator = public.shared.allocator;

    switch (kind) {
        inline else => |tag| public.shared.cache.deinit(PublicForm(tag), allocator),
    }

    allocator.destroy(public);
}

fn createSecret(allocator: Allocator) Allocator.Error!*Secret {
    const secret = try allocator.create(Secret);

    ct.wipe(std.mem.asBytes(secret));

    secret.has_seed = false;

    return secret;
}

fn destroySecret(allocator: Allocator, secret: *Secret) void {
    ct.wipe(std.mem.asBytes(secret));

    allocator.destroy(secret);
}

// The cached form of an encapsulation key, filled on first use; null when it cannot be allocated,
// and then the operation computes the form for itself, in a function of its own so that the usual
// path keeps a small frame. Encapsulation and decapsulation never fail for lack of memory.
fn cachedForm(comptime Form: type, shared: *cache.Shared, ek: anytype) ?*const Form {
    return shared.cache.get(Form, shared.allocator, ek);
}

// One function per parameter set, not inlined, so that the dispatch holds one frame at a time.
noinline fn encapsulateMlKem(comptime p: mlkem.Parameters, public_key: *const KemPublicKey, m: *const [32]u8, encapsulation: *Encapsulation) void {
    const ek = public_key.public.bytes[0..p.encapsulationKeySize()];

    const c = encapsulation.ciphertext_buffer[0..p.ciphertextSize()];

    encapsulation.ciphertext_size = p.ciphertextSize();

    if (cachedForm(mlkem.EncapsulationKey(p.k), &public_key.public.shared, ek)) |form| return mlkem.encaps(p, form, m, &encapsulation.shared_secret, c);

    encapsulateUncached(p, ek, m, &encapsulation.shared_secret, c);
}

noinline fn encapsulateUncached(comptime p: mlkem.Parameters, ek: *const [p.encapsulationKeySize()]u8, m: *const [32]u8, shared_secret: *[32]u8, c: *[p.ciphertextSize()]u8) void {
    var form: mlkem.EncapsulationKey(p.k) = undefined;

    form.fill(ek);

    mlkem.encaps(p, &form, m, shared_secret, c);
}

noinline fn encapsulateXWing(public_key: *const KemPublicKey, eseed: *const [xwing.randomness_size]u8, encapsulation: *Encapsulation) void {
    const bytes = public_key.public.bytes[0..xwing.public_key_size];

    const c = encapsulation.ciphertext_buffer[0..xwing.ciphertext_size];

    encapsulation.ciphertext_size = xwing.ciphertext_size;

    if (cachedForm(xwing.EncapsulationKey, &public_key.public.shared, xwing.mlKemKey(bytes))) |form| return xwing.encapsulate(form, bytes, eseed, &encapsulation.shared_secret, c);

    encapsulateXWingUncached(bytes, eseed, &encapsulation.shared_secret, c);
}

noinline fn encapsulateXWingUncached(bytes: *const [xwing.public_key_size]u8, eseed: *const [xwing.randomness_size]u8, shared_secret: *[32]u8, c: *[xwing.ciphertext_size]u8) void {
    var form: xwing.EncapsulationKey = undefined;

    form.fill(xwing.mlKemKey(bytes));

    xwing.encapsulate(&form, bytes, eseed, shared_secret, c);
}

noinline fn decapsulateMlKem(comptime p: mlkem.Parameters, key: *const KemPrivateKey, ciphertext: *const [p.ciphertextSize()]u8) [32]u8 {
    const ek = key.public.bytes[0..p.encapsulationKeySize()];

    if (cachedForm(mlkem.EncapsulationKey(p.k), &key.public.shared, ek)) |form| return mlkem.decaps(p, key.secret.s[0..p.k], form, key.secret.dk[0..p.decapsulationKeySize()], ciphertext);

    return decapsulateUncached(p, key, ciphertext);
}

noinline fn decapsulateUncached(comptime p: mlkem.Parameters, key: *const KemPrivateKey, ciphertext: *const [p.ciphertextSize()]u8) [32]u8 {
    var form: mlkem.EncapsulationKey(p.k) = undefined;

    form.fill(key.public.bytes[0..p.encapsulationKeySize()]);

    return mlkem.decaps(p, key.secret.s[0..p.k], &form, key.secret.dk[0..p.decapsulationKeySize()], ciphertext);
}

noinline fn decapsulateXWing(key: *const KemPrivateKey, ciphertext: *const [xwing.ciphertext_size]u8) [32]u8 {
    const bytes = key.public.bytes[0..xwing.public_key_size];

    if (cachedForm(xwing.EncapsulationKey, &key.public.shared, xwing.mlKemKey(bytes))) |form| return xwing.decapsulate(key.secret.s[0..3], form, key.secret.dk[0..@sizeOf(xwing.DecapsulationKey)], &key.secret.scalar, bytes, ciphertext);

    return decapsulateXWingUncached(key, ciphertext);
}

noinline fn decapsulateXWingUncached(key: *const KemPrivateKey, ciphertext: *const [xwing.ciphertext_size]u8) [32]u8 {
    const bytes = key.public.bytes[0..xwing.public_key_size];

    var form: xwing.EncapsulationKey = undefined;

    form.fill(xwing.mlKemKey(bytes));

    return xwing.decapsulate(key.secret.s[0..3], &form, key.secret.dk[0..@sizeOf(xwing.DecapsulationKey)], &key.secret.scalar, bytes, ciphertext);
}

// `seed` has the length of the algorithm's seed: d || z for ML-KEM, 32 bytes for X-Wing. With
// `fill`, the cache is filled now from the matrix that key generation samples anyway, for a
// self-test that uses it at once; otherwise the key fills it on its first use, so that a key that
// is only generated or imported costs no more. The memory comes first, so that a failure leaves
// nothing secret behind.
pub fn fromSeed(algorithm: KemAlgorithm, allocator: Allocator, seed: []const u8, fill: bool) Allocator.Error!KemPrivateKey {
    const public = try createPublic(allocator);

    errdefer release(algorithm.kind, public);

    const secret = try createSecret(allocator);

    errdefer destroySecret(allocator, secret);

    switch (algorithm.kind) {
        inline .ml_kem_512, .ml_kem_768, .ml_kem_1024 => |kind| {
            const p = comptime parameters(kind);

            const form = if (fill) try public.shared.cache.allocate(PublicForm(kind), allocator) else null;

            secret.has_seed = true;

            @memcpy(secret.seed[0..seed.len], seed);

            mlkem.keyGen(p, seed[0..32], seed[32..64], public.bytes[0..p.encapsulationKeySize()], secret.dk[0..p.decapsulationKeySize()], secret.s[0..p.k], form);
        },
        .x_wing => {
            const form = if (fill) try public.shared.cache.allocate(xwing.EncapsulationKey, allocator) else null;

            secret.has_seed = true;

            @memcpy(secret.seed[0..seed.len], seed);

            xwing.expand(seed[0..xwing.seed_size], public.bytes[0..xwing.public_key_size], secret.dk[0..@sizeOf(xwing.DecapsulationKey)], &secret.scalar, secret.s[0..3], form);
        },
    }

    return .{ .algorithm = algorithm, .public = public, .secret = secret };
}

fn fromExpanded(algorithm: KemAlgorithm, allocator: Allocator, dk: []const u8) (Error || Allocator.Error)!KemPrivateKey {
    switch (algorithm.kind) {
        inline .ml_kem_512, .ml_kem_768, .ml_kem_1024 => |kind| {
            const p = comptime parameters(kind);

            const k: usize = p.k;

            if (!mlkem.checkDecapsulationKey(p, dk[0..p.decapsulationKeySize()])) return error.InvalidPrivateKey;

            const public = try createPublic(allocator);

            errdefer release(algorithm.kind, public);

            const secret = try createSecret(allocator);

            @memcpy(secret.dk[0..dk.len], dk);

            @memcpy(public.bytes[0..p.encapsulationKeySize()], dk[384 * k ..][0..p.encapsulationKeySize()]);

            mlkem.decodeSecret(p, secret.dk[0..p.decapsulationKeySize()], secret.s[0..k]);

            return .{ .algorithm = algorithm, .public = public, .secret = secret };
        },
        .x_wing => unreachable,
    }
}

// `randomness` has the algorithm's length: m for ML-KEM, the 64-byte eseed for X-Wing.
pub fn encapsulateWith(public_key: *const KemPublicKey, randomness: []const u8) Encapsulation {
    var encapsulation: Encapsulation = .{ .shared_secret = undefined, .ciphertext_buffer = undefined, .ciphertext_size = 0 };

    ct.wipe(&encapsulation.ciphertext_buffer);

    switch (public_key.algorithm.kind) {
        inline .ml_kem_512, .ml_kem_768, .ml_kem_1024 => |kind| encapsulateMlKem(comptime parameters(kind), public_key, randomness[0..32], &encapsulation),
        .x_wing => encapsulateXWing(public_key, randomness[0..xwing.randomness_size], &encapsulation),
    }

    return encapsulation;
}

pub const ml_kem_512: KemAlgorithm = .{ .name = "ML-KEM-512", .public_key_size = 800, .ciphertext_size = 768, .shared_secret_size = 32, .kind = .ml_kem_512 };

pub const ml_kem_768: KemAlgorithm = .{ .name = "ML-KEM-768", .public_key_size = 1184, .ciphertext_size = 1088, .shared_secret_size = 32, .kind = .ml_kem_768 };

pub const ml_kem_1024: KemAlgorithm = .{ .name = "ML-KEM-1024", .public_key_size = 1568, .ciphertext_size = 1568, .shared_secret_size = 32, .kind = .ml_kem_1024 };

pub const x_wing: KemAlgorithm = .{ .name = "X-Wing", .public_key_size = 1216, .ciphertext_size = 1120, .shared_secret_size = 32, .kind = .x_wing };

const std = @import("std");

const ct = @import("ct.zig");
const encoding = @import("encoding.zig");
const Error = @import("errors.zig").Error;
const hash = @import("hash.zig");
const keys = @import("keys.zig");
const mldsa = @import("mldsa.zig");
const rng = @import("rng.zig");
const slhdsa = @import("slhdsa.zig");

const Allocator = std.mem.Allocator;

const KeyFormat = keys.KeyFormat;

const KeyGenOptions = keys.KeyGenOptions;

const self_test_message = "crypto-pq pairwise consistency test";

const max_public_key_size = mldsa.ml_dsa_87.publicKeySize();

const max_secret_size = mldsa.ml_dsa_87.privateKeySize();

const max_signature_size = slhdsa.sha2_256f.signatureSize();

const max_seed_size = 3 * 32;

const max_randomness_size = 32;

pub const PreHash = union(enum) {
    hash: hash.HashAlgorithm,
    xof: hash.XofAlgorithm,
};

pub const SignOptions = struct {
    context: []const u8 = "",
    deterministic: bool = false,
    pre_hash: ?PreHash = null,
};

pub const VerifyOptions = struct {
    context: []const u8 = "",
    pre_hash: ?PreHash = null,
};

pub const SignatureAlgorithm = struct {
    name: []const u8,
    public_key_size: usize,
    signature_size: usize,
    kind: Kind,

    pub const Kind = enum {
        ml_dsa_44,
        ml_dsa_65,
        ml_dsa_87,
        slh_dsa_sha2_128s,
        slh_dsa_sha2_128f,
        slh_dsa_sha2_192s,
        slh_dsa_sha2_192f,
        slh_dsa_sha2_256s,
        slh_dsa_sha2_256f,
        slh_dsa_shake_128s,
        slh_dsa_shake_128f,
        slh_dsa_shake_192s,
        slh_dsa_shake_192f,
        slh_dsa_shake_256s,
        slh_dsa_shake_256f,
    };

    pub fn generateKeyPair(self: SignatureAlgorithm, options: KeyGenOptions) Error!SignatureKeyPair {
        var seed: [max_seed_size]u8 = undefined;

        defer ct.wipe(&seed);

        const size = seedSize(self.kind);

        try rng.fill(seed[0..size]);

        var private_key = fromSeed(self, seed[0..size]);

        errdefer private_key.deinit();

        const public_key = private_key.publicKey();

        if (options.self_test) {
            var buffer: [max_signature_size]u8 = undefined;

            const signature = buffer[0..signatureSize(self.kind)];

            var representative: Representative = undefined;

            representative.init(self_test_message, "", null);

            signRaw(self.kind, private_key.secret(), representative.parts(), deterministicRandomness(&private_key), signature);

            if (!public_key.verify(signature, self_test_message, .{})) return error.SelfTestFailed;
        }

        return .{ .public_key = public_key, .private_key = private_key };
    }

    pub fn importPublicKey(self: SignatureAlgorithm, data: []const u8, format: KeyFormat) Error!SignaturePublicKey {
        var buffer: keys.PemBuffer = undefined;

        const key = try keys.importPublic(format, data, objectIdentifier(self.kind), &buffer);

        if (key.len != publicKeySize(self.kind)) return if (format == .raw) error.InvalidLength else error.InvalidEncoding;

        var public_key: SignaturePublicKey = .{ .algorithm = self, .bytes = @splat(0) };

        @memcpy(public_key.bytes[0..key.len], key);

        return public_key;
    }

    pub fn importPrivateKey(self: SignatureAlgorithm, data: []const u8, format: KeyFormat) Error!SignaturePrivateKey {
        var buffer: keys.PemBuffer = undefined;

        defer if (format == .pem) ct.wipe(&buffer);

        const input = try keys.importPrivate(format, data, objectIdentifier(self.kind), &buffer);

        var key = switch (input) {
            .raw => |raw| try self.importRaw(raw),
            .pkcs8 => |pkcs8| try self.importOctets(pkcs8.octets),
        };

        errdefer key.deinit();

        if (input == .pkcs8) {
            if (input.pkcs8.public_key) |public_key| {
                if (!ct.equal(public_key, key.publicBytes())) return error.InvalidPrivateKey;
            }
        }

        return key;
    }

    fn importRaw(self: SignatureAlgorithm, raw: []const u8) Error!SignaturePrivateKey {
        if (isMlDsa(self.kind) and raw.len == seedSize(self.kind)) return fromSeed(self, raw);

        if (raw.len != secretSize(self.kind)) return error.InvalidLength;

        return fromSecret(self, raw);
    }

    // SLH-DSA stores its 4n-byte key directly in the PKCS#8 octets; ML-DSA uses the seed/expanded
    // CHOICE.
    fn importOctets(self: SignatureAlgorithm, octets: []const u8) Error!SignaturePrivateKey {
        if (!isMlDsa(self.kind)) {
            if (octets.len != secretSize(self.kind)) return error.InvalidEncoding;

            return fromSecret(self, octets);
        }

        const choice = try keys.decodeSeedChoice(octets, seedSize(self.kind), secretSize(self.kind));

        const seed = choice.seed orelse return fromSecret(self, choice.expanded.?);

        var key = fromSeed(self, seed);

        errdefer key.deinit();

        if (choice.expanded) |expanded| {
            if (!ct.equal(expanded, key.secret())) return error.InvalidPrivateKey;
        }

        return key;
    }
};

pub const SignaturePublicKey = struct {
    algorithm: SignatureAlgorithm,
    bytes: [max_public_key_size]u8,

    pub fn verify(self: *const SignaturePublicKey, signature: []const u8, message: []const u8, options: VerifyOptions) bool {
        return verifyWith(self, signature, message, options, true);
    }

    pub fn exportKey(self: *const SignaturePublicKey, allocator: Allocator, format: KeyFormat) (Error || Allocator.Error)![]u8 {
        return keys.exportPublic(allocator, format, objectIdentifier(self.algorithm.kind), self.raw());
    }

    pub fn eql(self: *const SignaturePublicKey, other: *const SignaturePublicKey) bool {
        return self.algorithm.kind == other.algorithm.kind and std.mem.eql(u8, self.raw(), other.raw());
    }

    fn raw(self: *const SignaturePublicKey) []const u8 {
        return self.bytes[0..publicKeySize(self.algorithm.kind)];
    }
};

pub const SignaturePrivateKey = struct {
    algorithm: SignatureAlgorithm,
    seed: [32]u8,
    has_seed: bool,
    secret_bytes: [max_secret_size]u8,
    public: [max_public_key_size]u8,

    pub fn publicKey(self: *const SignaturePrivateKey) SignaturePublicKey {
        return .{ .algorithm = self.algorithm, .bytes = self.public };
    }

    pub fn sign(self: *const SignaturePrivateKey, allocator: Allocator, message: []const u8, options: SignOptions) (Error || Allocator.Error)![]u8 {
        var randomness: [max_randomness_size]u8 = undefined;

        defer ct.wipe(&randomness);

        const entry = try checkSignOptions(self.algorithm.kind, options.context, options.pre_hash, true);

        const size = randomnessSize(self.algorithm.kind);

        if (options.deterministic) {
            @memcpy(randomness[0..size], deterministicRandomness(self));
        } else {
            try rng.fill(randomness[0..size]);
        }

        return signWith(self, allocator, message, randomness[0..size], options.context, entry);
    }

    pub fn exportKey(self: *const SignaturePrivateKey, allocator: Allocator, format: KeyFormat) (Error || Allocator.Error)![]u8 {
        const oid = objectIdentifier(self.algorithm.kind);

        if (!isMlDsa(self.algorithm.kind)) return keys.exportPrivate(allocator, format, oid, null, self.secret());

        if (self.has_seed) return keys.exportPrivate(allocator, format, oid, encoding.context_0, &self.seed);

        return keys.exportPrivate(allocator, format, oid, encoding.octet_string, self.secret());
    }

    pub fn deinit(self: *SignaturePrivateKey) void {
        ct.wipe(&self.seed);

        ct.wipe(&self.secret_bytes);
    }

    fn secret(self: *const SignaturePrivateKey) []const u8 {
        return self.secret_bytes[0..secretSize(self.algorithm.kind)];
    }

    fn publicBytes(self: *const SignaturePrivateKey) []const u8 {
        return self.public[0..publicKeySize(self.algorithm.kind)];
    }
};

pub const SignatureKeyPair = struct {
    public_key: SignaturePublicKey,
    private_key: SignaturePrivateKey,
};

const Family = union(enum) {
    ml_dsa: mldsa.Parameters,
    slh_dsa: slhdsa.Parameters,
};

fn family(comptime kind: SignatureAlgorithm.Kind) Family {
    return switch (kind) {
        .ml_dsa_44 => .{ .ml_dsa = mldsa.ml_dsa_44 },
        .ml_dsa_65 => .{ .ml_dsa = mldsa.ml_dsa_65 },
        .ml_dsa_87 => .{ .ml_dsa = mldsa.ml_dsa_87 },
        .slh_dsa_sha2_128s => .{ .slh_dsa = slhdsa.sha2_128s },
        .slh_dsa_sha2_128f => .{ .slh_dsa = slhdsa.sha2_128f },
        .slh_dsa_sha2_192s => .{ .slh_dsa = slhdsa.sha2_192s },
        .slh_dsa_sha2_192f => .{ .slh_dsa = slhdsa.sha2_192f },
        .slh_dsa_sha2_256s => .{ .slh_dsa = slhdsa.sha2_256s },
        .slh_dsa_sha2_256f => .{ .slh_dsa = slhdsa.sha2_256f },
        .slh_dsa_shake_128s => .{ .slh_dsa = slhdsa.shake_128s },
        .slh_dsa_shake_128f => .{ .slh_dsa = slhdsa.shake_128f },
        .slh_dsa_shake_192s => .{ .slh_dsa = slhdsa.shake_192s },
        .slh_dsa_shake_192f => .{ .slh_dsa = slhdsa.shake_192f },
        .slh_dsa_shake_256s => .{ .slh_dsa = slhdsa.shake_256s },
        .slh_dsa_shake_256f => .{ .slh_dsa = slhdsa.shake_256f },
    };
}

fn isMlDsa(kind: SignatureAlgorithm.Kind) bool {
    return @intFromEnum(kind) <= @intFromEnum(SignatureAlgorithm.Kind.ml_dsa_87);
}

fn objectIdentifier(kind: SignatureAlgorithm.Kind) []const u8 {
    return switch (kind) {
        inline else => |tag| encoding.objectIdentifier(&.{ 2, 16, 840, 1, 101, 3, 4, 3, 17 + @as(u64, @intFromEnum(tag)) }),
    };
}

fn publicKeySize(kind: SignatureAlgorithm.Kind) usize {
    return switch (kind) {
        inline else => |tag| switch (comptime family(tag)) {
            .ml_dsa => |p| p.publicKeySize(),
            .slh_dsa => |p| p.publicKeySize(),
        },
    };
}

fn signatureSize(kind: SignatureAlgorithm.Kind) usize {
    return switch (kind) {
        inline else => |tag| switch (comptime family(tag)) {
            .ml_dsa => |p| p.signatureSize(),
            .slh_dsa => |p| p.signatureSize(),
        },
    };
}

// ML-DSA keeps the expanded private key, SLH-DSA its 4n-byte key.
fn secretSize(kind: SignatureAlgorithm.Kind) usize {
    return switch (kind) {
        inline else => |tag| switch (comptime family(tag)) {
            .ml_dsa => |p| p.privateKeySize(),
            .slh_dsa => |p| p.privateKeySize(),
        },
    };
}

// ML-DSA: the 32-byte seed; SLH-DSA: SK.seed || SK.prf || PK.seed.
pub fn seedSize(kind: SignatureAlgorithm.Kind) usize {
    return switch (kind) {
        inline else => |tag| switch (comptime family(tag)) {
            .ml_dsa => 32,
            .slh_dsa => |p| 3 * @as(usize, p.n),
        },
    };
}

pub fn randomnessSize(kind: SignatureAlgorithm.Kind) usize {
    return switch (kind) {
        inline else => |tag| switch (comptime family(tag)) {
            .ml_dsa => 32,
            .slh_dsa => |p| p.n,
        },
    };
}

// The collision strength a pre-hash must reach: lambda for ML-DSA, 8n for SLH-DSA.
fn strength(kind: SignatureAlgorithm.Kind) u16 {
    return switch (kind) {
        inline else => |tag| switch (comptime family(tag)) {
            .ml_dsa => |p| p.lambda,
            .slh_dsa => |p| 8 * @as(u16, p.n),
        },
    };
}

// FIPS 204 and FIPS 205: deterministic signing uses rnd = 0^32 for ML-DSA and opt_rand = PK.seed
// for SLH-DSA.
const zero_randomness: [32]u8 = @splat(0);

fn deterministicRandomness(key: *const SignaturePrivateKey) []const u8 {
    if (isMlDsa(key.algorithm.kind)) return &zero_randomness;

    const n = randomnessSize(key.algorithm.kind);

    return key.secret_bytes[2 * n ..][0..n];
}

fn empty(algorithm: SignatureAlgorithm) SignaturePrivateKey {
    return .{ .algorithm = algorithm, .seed = @splat(0), .has_seed = false, .secret_bytes = @splat(0), .public = @splat(0) };
}

pub fn fromSeed(algorithm: SignatureAlgorithm, seed: []const u8) SignaturePrivateKey {
    var key = empty(algorithm);

    switch (algorithm.kind) {
        inline else => |tag| switch (comptime family(tag)) {
            .ml_dsa => |p| {
                key.has_seed = true;

                @memcpy(&key.seed, seed);

                mldsa.keyGen(p, seed[0..32], key.public[0..p.publicKeySize()], key.secret_bytes[0..p.privateKeySize()]);
            },
            .slh_dsa => |p| {
                const n: usize = p.n;

                slhdsa.Scheme(p).keyGen(seed[0..n], seed[n..][0..n], seed[2 * n ..][0..n], key.secret_bytes[0 .. 4 * n], key.public[0 .. 2 * n]);
            },
        },
    }

    return key;
}

// Validates an expanded ML-DSA key or an SLH-DSA key against the public key it implies.
fn fromSecret(algorithm: SignatureAlgorithm, bytes: []const u8) Error!SignaturePrivateKey {
    var key = empty(algorithm);

    errdefer key.deinit();

    @memcpy(key.secret_bytes[0..bytes.len], bytes);

    switch (algorithm.kind) {
        inline else => |tag| switch (comptime family(tag)) {
            .ml_dsa => |p| {
                if (!mldsa.checkPrivateKey(p, bytes[0..p.privateKeySize()], key.public[0..p.publicKeySize()])) return error.InvalidPrivateKey;
            },
            .slh_dsa => |p| {
                const n: usize = p.n;

                const root = slhdsa.Scheme(p).root(bytes[0..n], bytes[2 * n ..][0..n]);

                if (!ct.equal(&root, bytes[3 * n ..][0..n])) return error.InvalidPrivateKey;

                @memcpy(key.public[0 .. 2 * n], bytes[2 * n ..][0 .. 2 * n]);
            },
        },
    }

    return key;
}

const Entry = struct {
    arc: u8,
    strength: u16,
    pre_hash: PreHash,
};

const hash_entries = [_]Entry{
    .{ .arc = 4, .strength = 112, .pre_hash = .{ .hash = hash.sha_224 } },
    .{ .arc = 1, .strength = 128, .pre_hash = .{ .hash = hash.sha_256 } },
    .{ .arc = 2, .strength = 192, .pre_hash = .{ .hash = hash.sha_384 } },
    .{ .arc = 3, .strength = 256, .pre_hash = .{ .hash = hash.sha_512 } },
    .{ .arc = 5, .strength = 112, .pre_hash = .{ .hash = hash.sha_512_224 } },
    .{ .arc = 6, .strength = 128, .pre_hash = .{ .hash = hash.sha_512_256 } },
    .{ .arc = 7, .strength = 112, .pre_hash = .{ .hash = hash.sha3_224 } },
    .{ .arc = 8, .strength = 128, .pre_hash = .{ .hash = hash.sha3_256 } },
    .{ .arc = 9, .strength = 192, .pre_hash = .{ .hash = hash.sha3_384 } },
    .{ .arc = 10, .strength = 256, .pre_hash = .{ .hash = hash.sha3_512 } },
    // SHAKE128 and SHAKE256 produce 256 and 512 bits as FIPS 204 and FIPS 205 require.
    .{ .arc = 11, .strength = 128, .pre_hash = .{ .xof = hash.shake128 } },
    .{ .arc = 12, .strength = 256, .pre_hash = .{ .xof = hash.shake256 } },
};

fn sameHash(a: hash.HashAlgorithm, b: hash.HashAlgorithm) bool {
    return std.mem.eql(u8, a.name, b.name) and a.digest_size == b.digest_size and std.meta.eql(a.kind, b.kind);
}

fn sameXof(a: hash.XofAlgorithm, b: hash.XofAlgorithm) bool {
    return std.mem.eql(u8, a.name, b.name) and a.rate == b.rate;
}

// Only the hash layer's own constants are pre-hashes; a hand-built value matches none of them.
fn lookup(pre_hash: PreHash) ?Entry {
    for (hash_entries) |entry| {
        const same = switch (pre_hash) {
            .hash => |h| entry.pre_hash == .hash and sameHash(h, entry.pre_hash.hash),
            .xof => |x| entry.pre_hash == .xof and sameXof(x, entry.pre_hash.xof),
        };

        if (same) return entry;
    }

    return null;
}

// A pre-hash must give at least the collision strength of the signature (FIPS 204, 5.4, and
// FIPS 205, 10.2): signing with a weaker one is refused and verification fails closed. hazmat
// skips this policy because the ACVP vectors use every hash function.
fn checkSignOptions(kind: SignatureAlgorithm.Kind, context: []const u8, pre_hash: ?PreHash, policy: bool) Error!?Entry {
    var entry: ?Entry = null;

    if (pre_hash) |value| {
        entry = lookup(value) orelse return error.InvalidOption;

        if (policy and entry.?.strength < strength(kind)) return error.InvalidOption;
    }

    if (context.len > 255) return error.InvalidContext;

    return entry;
}

// FIPS 204 and FIPS 205: M' = 0 || |ctx| || ctx || M, or 1 || |ctx| || ctx || OID || PH(M). The
// parts point into this struct, so it must stay where `init` filled it.
const Representative = struct {
    header: [2]u8,
    oid: [11]u8,
    digest: [64]u8,
    slices: [4][]const u8,
    count: usize,

    fn init(self: *Representative, message: []const u8, context: []const u8, entry: ?Entry) void {
        self.header = .{ @intFromBool(entry != null), @intCast(context.len) };

        self.slices[0] = &self.header;

        self.slices[1] = context;

        const e = entry orelse {
            self.slices[2] = message;

            self.count = 3;

            return;
        };

        self.oid = [_]u8{ encoding.object_identifier, 9 } ++ encoding.objectIdentifier(&.{ 2, 16, 840, 1, 101, 3, 4, 2, 1 })[0..8].* ++ [1]u8{e.arc};

        const digest = switch (e.pre_hash) {
            .hash => |h| self.digest[0..h.digest_size],
            .xof => |x| self.digest[0..if (x.rate == hash.shake128.rate) 32 else 64],
        };

        switch (e.pre_hash) {
            .hash => |h| h.digest(message, digest),
            .xof => |x| x.digest(message, digest),
        }

        self.slices[2] = &self.oid;

        self.slices[3] = digest;

        self.count = 4;
    }

    fn parts(self: *const Representative) []const []const u8 {
        return self.slices[0..self.count];
    }
};

fn signRaw(kind: SignatureAlgorithm.Kind, secret: []const u8, message: []const []const u8, randomness: []const u8, out: []u8) void {
    switch (kind) {
        inline else => |tag| switch (comptime family(tag)) {
            .ml_dsa => |p| mldsa.sign(p, secret[0..p.privateKeySize()], message, randomness[0..32], out[0..p.signatureSize()]),
            .slh_dsa => |p| slhdsa.Scheme(p).sign(secret[0..p.privateKeySize()], message, randomness[0..p.n], out[0..p.signatureSize()]),
        },
    }
}

fn verifyRaw(kind: SignatureAlgorithm.Kind, public: []const u8, message: []const []const u8, signature: []const u8) bool {
    return switch (kind) {
        inline else => |tag| switch (comptime family(tag)) {
            .ml_dsa => |p| mldsa.verify(p, public[0..p.publicKeySize()], message, signature[0..p.signatureSize()]),
            .slh_dsa => |p| slhdsa.Scheme(p).verify(public[0..p.publicKeySize()], message, signature[0..p.signatureSize()]),
        },
    };
}

// The options were checked and `randomness` has the algorithm's length.
fn signWith(key: *const SignaturePrivateKey, allocator: Allocator, message: []const u8, randomness: []const u8, context: []const u8, entry: ?Entry) Allocator.Error![]u8 {
    const out = try allocator.alloc(u8, signatureSize(key.algorithm.kind));

    var representative: Representative = undefined;

    representative.init(message, context, entry);

    signRaw(key.algorithm.kind, key.secret(), representative.parts(), randomness, out);

    return out;
}

pub fn signDeterministic(key: *const SignaturePrivateKey, allocator: Allocator, message: []const u8, randomness: []const u8, options: SignOptions) (Error || Allocator.Error)![]u8 {
    try keys.requireLength(randomness, randomnessSize(key.algorithm.kind));

    const entry = try checkSignOptions(key.algorithm.kind, options.context, options.pre_hash, false);

    return signWith(key, allocator, message, randomness, options.context, entry);
}

pub fn verifyWith(key: *const SignaturePublicKey, signature: []const u8, message: []const u8, options: VerifyOptions, policy: bool) bool {
    const kind = key.algorithm.kind;

    const entry = if (options.pre_hash) |value| lookup(value) orelse return false else null;

    if (entry) |e| {
        if (policy and e.strength < strength(kind)) return false;
    }

    if (options.context.len > 255 or signature.len != signatureSize(kind)) return false;

    var representative: Representative = undefined;

    representative.init(message, options.context, entry);

    return verifyRaw(kind, key.raw(), representative.parts(), signature);
}

fn define(comptime kind: SignatureAlgorithm.Kind, name: []const u8) SignatureAlgorithm {
    return .{ .name = name, .public_key_size = publicKeySize(kind), .signature_size = signatureSize(kind), .kind = kind };
}

pub const ml_dsa_44 = define(.ml_dsa_44, "ML-DSA-44");

pub const ml_dsa_65 = define(.ml_dsa_65, "ML-DSA-65");

pub const ml_dsa_87 = define(.ml_dsa_87, "ML-DSA-87");

pub const slh_dsa_sha2_128s = define(.slh_dsa_sha2_128s, "SLH-DSA-SHA2-128s");

pub const slh_dsa_sha2_128f = define(.slh_dsa_sha2_128f, "SLH-DSA-SHA2-128f");

pub const slh_dsa_sha2_192s = define(.slh_dsa_sha2_192s, "SLH-DSA-SHA2-192s");

pub const slh_dsa_sha2_192f = define(.slh_dsa_sha2_192f, "SLH-DSA-SHA2-192f");

pub const slh_dsa_sha2_256s = define(.slh_dsa_sha2_256s, "SLH-DSA-SHA2-256s");

pub const slh_dsa_sha2_256f = define(.slh_dsa_sha2_256f, "SLH-DSA-SHA2-256f");

pub const slh_dsa_shake_128s = define(.slh_dsa_shake_128s, "SLH-DSA-SHAKE-128s");

pub const slh_dsa_shake_128f = define(.slh_dsa_shake_128f, "SLH-DSA-SHAKE-128f");

pub const slh_dsa_shake_192s = define(.slh_dsa_shake_192s, "SLH-DSA-SHAKE-192s");

pub const slh_dsa_shake_192f = define(.slh_dsa_shake_192f, "SLH-DSA-SHAKE-192f");

pub const slh_dsa_shake_256s = define(.slh_dsa_shake_256s, "SLH-DSA-SHAKE-256s");

pub const slh_dsa_shake_256f = define(.slh_dsa_shake_256f, "SLH-DSA-SHAKE-256f");

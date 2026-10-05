const std = @import("std");

const options = @import("capi_options");

const common = @import("common.zig");
const hashing = @import("hash.zig");

const cpu = @import("../cpu.zig");
const ct = @import("../ct.zig");
const hash = @import("../hash.zig");
const mldsa = @import("../mldsa.zig");
const primitives = @import("../primitives.zig");
const signatures = @import("../signature.zig");
const slhdsa = @import("../slhdsa.zig");

const Failure = common.Failure;

const Slot = common.Slot;

// Algorithm ids: 0-2 ML-DSA-44, -65, -87; 3-8 SLH-DSA-SHA2-128s, -128f, -192s, -192f, -256s,
// -256f; 9-14 SLH-DSA-SHAKE in the same order.
pub const count = 15;

pub fn enabled(comptime algorithm: u32) bool {
    return if (algorithm < 3) options.ml_dsa else options.slh_dsa;
}

// Keygen flag, as for the KEMs: fill the ML-DSA public cache from key generation's matrix.
pub const fill_cache: u32 = 1;

// Sign flags. `deterministic` signs with the randomness FIPS 204 and FIPS 205 fix (zero, or
// PK.seed), and then no randomness may be given. `hazmat` skips the pre-hash strength policy, as
// hazmat.sign and hazmat.verify do; verify accepts only this one.
pub const deterministic: u32 = 1;

pub const hazmat: u32 = 2;

// What cpq_sig_export_private returns: the ML-DSA seed of a key that kept it, or the private key
// (the expanded ML-DSA key, or SLH-DSA's 4n bytes).
pub const export_seed: u32 = 0;

pub const export_private: u32 = 1;

const zero_randomness: [32]u8 = @splat(0);

fn MlDsa(comptime p: mldsa.Parameters) type {
    return struct {
        pub const ml_dsa = true;

        pub const public_key_size = p.publicKeySize();

        pub const secret_size = p.privateKeySize();

        pub const signature_size = p.signatureSize();

        pub const seed_size = 32;

        pub const randomness_size = 32;

        pub const strength: u16 = p.lambda;

        const PublicCache = mldsa.PublicCache(p);

        const SecretCache = mldsa.SecretCache(p);

        // tr = H(pk, 64), and A with NTT(t1 * 2^d), filled on first use.
        pub const Public = struct {
            key: [public_key_size]u8,
            tr: [64]u8,
            form: common.Lazy(PublicCache),
        };

        // The NTT forms of s1, s2 and t0, filled on first use.
        pub const Private = struct {
            public: Public,
            seed: [seed_size]u8,
            key: [secret_size]u8,
            secrets: common.Lazy(SecretCache),
        };

        // The seed is copied into the slot first: the caller's buffer is read once.
        pub fn generate(private: *Private, seed: *const [seed_size]u8, fill: bool) void {
            private.seed = seed.*;

            private.public.form.init();

            private.secrets.init();

            mldsa.keyGen(p, &private.seed, &private.public.key, &private.key, if (fill) private.public.form.claim() else null);

            if (fill) private.public.form.publish();

            private.public.tr = private.key[64..128].*;
        }

        // An expanded key, checked against the public key it implies, on the copy that is kept.
        pub fn importSecret(private: *Private, bytes: *const [secret_size]u8) bool {
            private.key = bytes.*;

            if (!mldsa.checkPrivateKey(p, &private.key, &private.public.key)) return false;

            private.public.tr = private.key[64..128].*;

            private.public.form.init();

            private.secrets.init();

            @memset(&private.seed, 0);

            return true;
        }

        pub fn importPublic(public: *Public, bytes: *const [public_key_size]u8) void {
            public.key = bytes.*;

            primitives.shake256(&.{&public.key}, &public.tr);

            public.form.init();
        }

        pub fn deterministicRandomness(private: *const Private) *const [randomness_size]u8 {
            _ = private;

            return &zero_randomness;
        }

        pub fn sign(private: *Private, message: []const []const u8, randomness: *const [randomness_size]u8, out: *[signature_size]u8) Failure!void {
            const public = private.public.form.get(&private.public.key);

            const secrets = private.secrets.get(&private.key);

            if (public != null and secrets != null) return signWith(private, secrets.?, public.?, message, randomness, out);

            return signSpare(private, secrets, public, message, randomness, out);
        }

        // The workspace of one signature lives in this frame: calls on one key may run at once.
        noinline fn signWith(private: *const Private, secrets: *const SecretCache, public: *const PublicCache, message: []const []const u8, randomness: *const [32]u8, out: *[signature_size]u8) void {
            var work: mldsa.Workspace(p) = undefined;

            mldsa.sign(p, &private.key, secrets, public, &work, message, randomness, out);
        }

        // A cache that another call is filling is computed again in memory of this call's own.
        noinline fn signSpare(private: *const Private, secrets: ?*const SecretCache, public: ?*const PublicCache, message: []const []const u8, randomness: *const [32]u8, out: *[signature_size]u8) Failure!void {
            const Spare = struct {
                secrets: SecretCache,
                public: PublicCache,
            };

            const spare = common.allocator.create(Spare) catch return error.OutOfMemory;

            defer {
                ct.wipe(std.mem.asBytes(spare));

                common.allocator.destroy(spare);
            }

            const s = secrets orelse fill: {
                spare.secrets.fill(&private.key);

                break :fill &spare.secrets;
            };

            const a = public orelse fill: {
                spare.public.fill(&private.public.key);

                break :fill &spare.public;
            };

            signWith(private, s, a, message, randomness, out);
        }

        // Without its cache, which another call is filling, verification samples A again.
        pub fn verify(public: *Public, message: []const []const u8, signature: *const [signature_size]u8) bool {
            return mldsa.verify(p, &public.key, &public.tr, public.form.get(&public.key), message, signature);
        }

        pub fn seedBytes(private: *const Private) []const u8 {
            return &private.seed;
        }

        pub fn cacheFlags(public: *const Public) u32 {
            return @intFromBool(public.form.isReady());
        }

        pub fn secretCacheFlags(private: *const Private) u32 {
            return @as(u32, @intFromBool(private.secrets.isReady())) << 1;
        }
    };
}

fn SlhDsa(comptime p: slhdsa.Parameters) type {
    return struct {
        pub const ml_dsa = false;

        const n: usize = p.n;

        const Scheme = slhdsa.Scheme(p);

        pub const public_key_size = p.publicKeySize();

        pub const secret_size = p.privateKeySize();

        pub const signature_size = p.signatureSize();

        pub const seed_size = 3 * n;

        pub const randomness_size = n;

        pub const strength: u16 = 8 * @as(u16, p.n);

        pub const Public = struct {
            key: [public_key_size]u8,
        };

        pub const Private = struct {
            public: Public,
            key: [secret_size]u8,
        };

        // SK.seed || SK.prf || PK.seed, read once into the key that the slot keeps.
        pub fn generate(private: *Private, seed: *const [seed_size]u8, fill: bool) void {
            _ = fill;

            private.key[0..seed_size].* = seed.*;

            const copy = private.key[0..seed_size];

            Scheme.keyGen(copy[0..n], copy[n..][0..n], copy[2 * n ..][0..n], &private.key, &private.public.key);
        }

        // The key must hold the root that its seeds give, checked on the copy that is kept.
        pub fn importSecret(private: *Private, bytes: *const [secret_size]u8) bool {
            private.key = bytes.*;

            const key = &private.key;

            // PK.seed and PK.root are public, and so is whether the key is valid: importing it
            // fails otherwise.
            ct.declassify(key[2 * n ..]);

            const root = Scheme.root(key[0..n], key[2 * n ..][0..n]);

            if (!ct.declassifyValue(bool, ct.equal(&root, key[3 * n ..][0..n]))) return false;

            private.public.key = key[2 * n ..][0 .. 2 * n].*;

            return true;
        }

        pub fn importPublic(public: *Public, bytes: *const [public_key_size]u8) void {
            public.key = bytes.*;
        }

        pub fn deterministicRandomness(private: *const Private) *const [randomness_size]u8 {
            return private.key[2 * n ..][0..n];
        }

        pub fn sign(private: *Private, message: []const []const u8, randomness: *const [randomness_size]u8, out: *[signature_size]u8) Failure!void {
            Scheme.sign(&private.key, message, randomness, out);
        }

        pub fn verify(public: *Public, message: []const []const u8, signature: *const [signature_size]u8) bool {
            return Scheme.verify(&public.key, message, signature);
        }

        pub fn seedBytes(private: *const Private) []const u8 {
            _ = private;

            return &.{};
        }

        pub fn cacheFlags(public: *const Public) u32 {
            _ = public;

            return 0;
        }

        pub fn secretCacheFlags(private: *const Private) u32 {
            _ = private;

            return 0;
        }
    };
}

pub fn Set(comptime algorithm: u32) type {
    return switch (algorithm) {
        0 => MlDsa(mldsa.ml_dsa_44),
        1 => MlDsa(mldsa.ml_dsa_65),
        2 => MlDsa(mldsa.ml_dsa_87),
        3 => SlhDsa(slhdsa.sha2_128s),
        4 => SlhDsa(slhdsa.sha2_128f),
        5 => SlhDsa(slhdsa.sha2_192s),
        6 => SlhDsa(slhdsa.sha2_192f),
        7 => SlhDsa(slhdsa.sha2_256s),
        8 => SlhDsa(slhdsa.sha2_256f),
        9 => SlhDsa(slhdsa.shake_128s),
        10 => SlhDsa(slhdsa.shake_128f),
        11 => SlhDsa(slhdsa.shake_192s),
        12 => SlhDsa(slhdsa.shake_192f),
        13 => SlhDsa(slhdsa.shake_256s),
        14 => SlhDsa(slhdsa.shake_256f),
        else => unreachable,
    };
}

pub fn size(slot_type: common.SlotType, algorithm: u32) usize {
    switch (algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) return 0;

            return switch (slot_type) {
                .signature_public => common.slotSize(Set(a).Public),
                .signature_private => common.slotSize(Set(a).Private),
                else => 0,
            };
        },
        else => return 0,
    }
}

fn known(algorithm: u32) Failure!void {
    if (algorithm >= count) return error.BadArgument;
}

fn openPublic(memory: ?[*]u8, length: usize) Failure!Slot {
    return common.open(&.{ .signature_public, .signature_private }, memory, length, size, .shared);
}

fn openPrivate(memory: ?[*]u8, length: usize) Failure!Slot {
    return common.open(&.{.signature_private}, memory, length, size, .shared);
}

fn publicPart(comptime S: type, slot: Slot) *S.Public {
    return if (slot.slot_type == .signature_private) &slot.body(S.Private).public else slot.body(S.Public);
}

// Pre-hash ids: 0 none, 1-10 the hash functions in the order of their ids plus one (SHA-224 is 1,
// SHA3-512 is 10), 11 SHAKE128 and 12 SHAKE256.
pub const pre_hash_count = 13;

fn preHash(id: u32) Failure!?signatures.Entry {
    const value: signatures.PreHash = switch (id) {
        0 => return null,
        1...10 => .{ .hash = hashing.algorithms[id - 1] },
        11 => .{ .xof = hash.shake128 },
        12 => .{ .xof = hash.shake256 },
        else => return error.BadArgument,
    };

    return signatures.lookup(value).?;
}

pub fn keygen(algorithm: u32, seed: ?[*]const u8, seed_length: usize, flags: u32, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(generate(algorithm, seed, seed_length, flags, memory, length));
}

fn generate(algorithm: u32, seed_pointer: ?[*]const u8, seed_length: usize, flags: u32, memory: ?[*]u8, length: usize) Failure!void {
    try known(algorithm);

    if (flags & ~fill_cache != 0) return error.BadArgument;

    const slot = try common.place(.signature_private, algorithm, memory, length, size(.signature_private, algorithm));

    const seed = try common.input(seed_pointer, seed_length);

    try common.apart(&.{slot.bytes}, &.{seed});

    const dit = cpu.Dit.enter();

    defer dit.leave();

    switch (algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            const S = Set(a);

            if (seed.len != S.seed_size) return error.InvalidLength;

            @call(.never_inline, S.generate, .{ slot.body(S.Private), seed[0..S.seed_size], flags & fill_cache != 0 });

            slot.seal(if (S.ml_dsa) common.has_seed else 0);
        },
        else => unreachable,
    }
}

pub fn importPublic(algorithm: u32, key: ?[*]const u8, key_length: usize, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(importPublicKey(algorithm, key, key_length, memory, length));
}

fn importPublicKey(algorithm: u32, key: ?[*]const u8, key_length: usize, memory: ?[*]u8, length: usize) Failure!void {
    try known(algorithm);

    const slot = try common.place(.signature_public, algorithm, memory, length, size(.signature_public, algorithm));

    const bytes = try common.input(key, key_length);

    try common.apart(&.{slot.bytes}, &.{bytes});

    switch (algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            const S = Set(a);

            if (bytes.len != S.public_key_size) return error.InvalidLength;

            @call(.never_inline, S.importPublic, .{ slot.body(S.Public), bytes[0..S.public_key_size] });
        },
        else => unreachable,
    }

    slot.seal(0);
}

// A raw private key: the ML-DSA seed or expanded key, or SLH-DSA's 4n bytes, which must be
// consistent with the public key they imply.
pub fn importPrivate(algorithm: u32, key: ?[*]const u8, key_length: usize, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(importPrivateKey(algorithm, key, key_length, memory, length));
}

fn importPrivateKey(algorithm: u32, key: ?[*]const u8, key_length: usize, memory: ?[*]u8, length: usize) Failure!void {
    try known(algorithm);

    const slot = try common.place(.signature_private, algorithm, memory, length, size(.signature_private, algorithm));

    const bytes = try common.input(key, key_length);

    try common.apart(&.{slot.bytes}, &.{bytes});

    const dit = cpu.Dit.enter();

    defer dit.leave();

    switch (algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            const S = Set(a);

            if (bytes.len != S.secret_size and !(S.ml_dsa and bytes.len == S.seed_size)) return error.InvalidLength;

            // The slot may hold part of the key from here on.
            errdefer slot.discard();

            const private = slot.body(S.Private);

            if (S.ml_dsa and bytes.len == S.seed_size) {
                @call(.never_inline, S.generate, .{ private, bytes[0..S.seed_size], false });

                return slot.seal(common.has_seed);
            }

            if (!@call(.never_inline, S.importSecret, .{ private, bytes[0..S.secret_size] })) return error.InvalidPrivateKey;
        },
        else => unreachable,
    }

    slot.seal(0);
}

pub fn publicFromPrivate(private_memory: ?[*]u8, private_length: usize, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(derivePublic(private_memory, private_length, memory, length));
}

fn derivePublic(private_memory: ?[*]u8, private_length: usize, memory: ?[*]u8, length: usize) Failure!void {
    const private_slot = try openPrivate(private_memory, private_length);

    defer private_slot.close();

    const slot = try common.place(.signature_public, private_slot.algorithm, memory, length, size(.signature_public, private_slot.algorithm));

    try common.apart(&.{slot.bytes}, &.{private_slot.bytes});

    switch (private_slot.algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            const S = Set(a);

            const source = &private_slot.body(S.Private).public;

            const public = slot.body(S.Public);

            public.key = source.key;

            if (S.ml_dsa) {
                public.tr = source.tr;

                public.form.copyFrom(&source.form);
            }
        },
        else => unreachable,
    }

    try private_slot.confirm(&.{slot.bytes});

    slot.seal(0);
}

pub fn exportPublic(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(exportPublicKey(memory, length, out, out_length));
}

fn exportPublicKey(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    const slot = try openPublic(memory, length);

    defer slot.close();

    switch (slot.algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            const S = Set(a);

            const target = try common.exact(out, out_length, S.public_key_size);

            try common.apart(&.{target}, &.{slot.bytes});

            @memcpy(target, &publicPart(S, slot).key);

            try slot.confirm(&.{target});
        },
        else => unreachable,
    }
}

pub fn exportPrivate(memory: ?[*]u8, length: usize, which: u32, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(exportPrivateKey(memory, length, which, out, out_length));
}

fn exportPrivateKey(memory: ?[*]u8, length: usize, which: u32, out: ?[*]u8, out_length: usize) Failure!void {
    const slot = try openPrivate(memory, length);

    defer slot.close();

    if (which != export_seed and which != export_private) return error.BadArgument;

    const dit = cpu.Dit.enter();

    defer dit.leave();

    switch (slot.algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            const S = Set(a);

            const private = slot.body(S.Private);

            const source = if (which == export_seed) seed: {
                if (slot.flags & common.has_seed == 0) return error.Unsupported;

                break :seed S.seedBytes(private);
            } else &private.key;

            const target = try common.exact(out, out_length, source.len);

            try common.apart(&.{target}, &.{slot.bytes});

            @memcpy(target, source);

            try slot.confirm(&.{target});
        },
        else => unreachable,
    }
}

// `randomness` is rnd for ML-DSA and opt_rand for SLH-DSA, empty with the deterministic flag. The
// message representative, pre-hash included, is built here: 0 || |ctx| || ctx || M, or
// 1 || |ctx| || ctx || OID || PH(M).
pub fn sign(memory: ?[*]u8, length: usize, message: ?[*]const u8, message_length: usize, context: ?[*]const u8, context_length: usize, pre_hash: u32, randomness: ?[*]const u8, randomness_length: usize, flags: u32, signature: ?[*]u8, signature_length: usize) callconv(.c) c_int {
    return common.status(signChecked(memory, length, message, message_length, context, context_length, pre_hash, randomness, randomness_length, flags, signature, signature_length));
}

fn signChecked(memory: ?[*]u8, length: usize, message: ?[*]const u8, message_length: usize, context: ?[*]const u8, context_length: usize, pre_hash: u32, randomness: ?[*]const u8, randomness_length: usize, flags: u32, signature: ?[*]u8, signature_length: usize) Failure!void {
    const slot = try openPrivate(memory, length);

    defer slot.close();

    const m = try common.input(message, message_length);

    const ctx = try common.input(context, context_length);

    const random = try common.input(randomness, randomness_length);

    if (flags & ~(deterministic | hazmat) != 0) return error.BadArgument;

    if (flags & deterministic != 0 and random.len != 0) return error.BadArgument;

    const entry = try preHash(pre_hash);

    // Each parameter set signs in a frame of its own: unoptimized builds give every prong of an
    // inline switch its own stack slots, which would add up to the deepest signature's stack.
    switch (slot.algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            return @call(.never_inline, signAs, .{ Set(a), slot, m, ctx, random, flags, entry, signature, signature_length });
        },
        else => unreachable,
    }
}

fn signAs(comptime S: type, slot: Slot, m: []const u8, ctx: []const u8, random: []const u8, flags: u32, entry: ?signatures.Entry, signature: ?[*]u8, signature_length: usize) Failure!void {
    const out = try common.exact(signature, signature_length, S.signature_size);

    try common.apart(&.{ slot.bytes, out }, &.{ m, ctx, random });

    if (flags & deterministic == 0 and random.len != S.randomness_size) return error.InvalidLength;

    if (entry) |e| {
        if (flags & hazmat == 0 and e.strength < S.strength) return error.InvalidOption;
    }

    if (ctx.len > 255) return error.InvalidContext;

    const dit = cpu.Dit.enter();

    defer dit.leave();

    const private = slot.body(S.Private);

    const rnd = if (flags & deterministic != 0) S.deterministicRandomness(private) else random[0..S.randomness_size];

    var representative: signatures.Representative = undefined;

    representative.init(m, ctx, entry);

    try @call(.never_inline, S.sign, .{ private, representative.parts(), rnd, out[0..S.signature_size] });

    try slot.confirm(&.{out});
}

// rejected for a signature that does not verify, has the wrong length, comes with a context over
// 255 bytes or, without the hazmat flag, a pre-hash weaker than the algorithm.
pub fn verify(memory: ?[*]u8, length: usize, signature: ?[*]const u8, signature_length: usize, message: ?[*]const u8, message_length: usize, context: ?[*]const u8, context_length: usize, pre_hash: u32, flags: u32) callconv(.c) c_int {
    return common.status(verifyChecked(memory, length, signature, signature_length, message, message_length, context, context_length, pre_hash, flags));
}

fn verifyChecked(memory: ?[*]u8, length: usize, signature: ?[*]const u8, signature_length: usize, message: ?[*]const u8, message_length: usize, context: ?[*]const u8, context_length: usize, pre_hash: u32, flags: u32) Failure!void {
    const slot = try openPublic(memory, length);

    defer slot.close();

    const sig = try common.input(signature, signature_length);

    const m = try common.input(message, message_length);

    const ctx = try common.input(context, context_length);

    if (flags & ~hazmat != 0) return error.BadArgument;

    const entry = try preHash(pre_hash);

    try common.apart(&.{slot.bytes}, &.{ sig, m, ctx });

    switch (slot.algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            const S = Set(a);

            if (entry) |e| {
                if (flags & hazmat == 0 and e.strength < S.strength) return error.Rejected;
            }

            if (ctx.len > 255 or sig.len != S.signature_size) return error.Rejected;

            var representative: signatures.Representative = undefined;

            representative.init(m, ctx, entry);

            const valid = @call(.never_inline, S.verify, .{ publicPart(S, slot), representative.parts(), sig[0..S.signature_size] });

            try slot.confirm(&.{});

            if (!valid) return error.Rejected;
        },
        else => unreachable,
    }
}

// Bit 0: the public cache is filled; bit 1: the secret cache of a private slot is.
pub fn cacheFlags(slot: Slot) u32 {
    switch (slot.algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            const S = Set(a);

            const flags = S.cacheFlags(publicPart(S, slot));

            return if (slot.slot_type == .signature_private) flags | S.secretCacheFlags(slot.body(S.Private)) else flags;
        },
        else => unreachable,
    }
}

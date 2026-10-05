const std = @import("std");

const options = @import("capi_options");

const common = @import("common.zig");

const cpu = @import("../cpu.zig");
const ct = @import("../ct.zig");
const mlkem = @import("../mlkem.zig");
const xwing = @import("../xwing.zig");

const Failure = common.Failure;

const Slot = common.Slot;

// Algorithm ids: 0 ML-KEM-512, 1 ML-KEM-768, 2 ML-KEM-1024, 3 X-Wing.
pub const count = 4;

pub fn enabled(comptime algorithm: u32) bool {
    return if (algorithm < 3) options.ml_kem else options.x_wing;
}

// Keygen flag: fill the public key's cache from the matrix that key generation samples anyway, for
// a key that is used at once, by the pairwise self-test for instance.
pub const fill_cache: u32 = 1;

// What cpq_kem_export_private returns.
pub const export_seed: u32 = 0;

pub const export_expanded: u32 = 1;

fn MlKem(comptime p: mlkem.Parameters) type {
    return struct {
        pub const x_wing = false;

        pub const public_key_size = p.encapsulationKeySize();

        pub const ciphertext_size = p.ciphertextSize();

        pub const seed_size = 64;

        pub const randomness_size = 32;

        pub const expanded_size = p.decapsulationKeySize();

        // The transposed matrix, t̂ and H(ek), which encapsulation and the re-encryption of
        // decapsulation read.
        pub const Form = mlkem.EncapsulationKey(p.k);

        pub const Public = struct {
            key: [public_key_size]u8,
            form: common.Lazy(Form),

            pub fn ek(self: *const Public) *const [public_key_size]u8 {
                return &self.key;
            }
        };

        pub const Private = struct {
            public: Public,
            seed: [seed_size]u8,
            dk: [expanded_size]u8,
            s: [p.k]mlkem.Poly,
        };

        pub fn check(key: *const [public_key_size]u8) bool {
            return mlkem.checkEncapsulationKey(p, key);
        }

        pub fn generate(private: *Private, seed: *const [seed_size]u8, form: ?*Form) void {
            mlkem.keyGen(p, seed[0..32], seed[32..64], &private.public.key, &private.dk, &private.s, form);
        }

        // The checks of FIPS 203, 7.3, then the key's parts, as the core imports an expanded key.
        pub fn expand(private: *Private, dk: *const [expanded_size]u8) bool {
            if (!mlkem.checkDecapsulationKey(p, dk)) return false;

            private.dk = dk.*;

            private.public.key = dk[384 * @as(usize, p.k) ..][0..public_key_size].*;

            mlkem.decodeSecret(p, &private.dk, &private.s);

            return true;
        }

        pub fn encapsulate(form: *const Form, public: *const Public, randomness: *const [randomness_size]u8, ciphertext: *[ciphertext_size]u8, secret: *[32]u8) void {
            _ = public;

            mlkem.encaps(p, form, randomness, secret, ciphertext);
        }

        pub fn decapsulate(form: *const Form, private: *const Private, ciphertext: *const [ciphertext_size]u8) [32]u8 {
            return mlkem.decaps(p, &private.s, form, &private.dk, ciphertext);
        }
    };
}

const XWing = struct {
    pub const x_wing = true;

    pub const public_key_size = xwing.public_key_size;

    pub const ciphertext_size = xwing.ciphertext_size;

    pub const seed_size = xwing.seed_size;

    pub const randomness_size = xwing.randomness_size;

    pub const expanded_size = 0;

    pub const Form = xwing.EncapsulationKey;

    pub const Public = struct {
        key: [public_key_size]u8,
        form: common.Lazy(Form),

        pub fn ek(self: *const Public) *const [mlkem.ml_kem_768.encapsulationKeySize()]u8 {
            return xwing.mlKemKey(&self.key);
        }
    };

    pub const Private = struct {
        public: Public,
        seed: [seed_size]u8,
        dk: xwing.DecapsulationKey,
        scalar: [32]u8,
        s: xwing.Secret,
    };

    pub fn check(key: *const [public_key_size]u8) bool {
        return xwing.checkPublicKey(key);
    }

    pub fn generate(private: *Private, seed: *const [seed_size]u8, form: ?*Form) void {
        xwing.expand(seed, &private.public.key, &private.dk, &private.scalar, &private.s, form);
    }

    pub fn expand(private: *Private, dk: *const [expanded_size]u8) bool {
        _ = .{ private, dk };

        return false;
    }

    pub fn encapsulate(form: *const Form, public: *const Public, randomness: *const [randomness_size]u8, ciphertext: *[ciphertext_size]u8, secret: *[32]u8) void {
        xwing.encapsulate(form, &public.key, randomness, secret, ciphertext);
    }

    pub fn decapsulate(form: *const Form, private: *const Private, ciphertext: *const [ciphertext_size]u8) [32]u8 {
        return xwing.decapsulate(&private.s, form, &private.dk, &private.scalar, &private.public.key, ciphertext);
    }
};

pub fn Set(comptime algorithm: u32) type {
    return switch (algorithm) {
        0 => MlKem(mlkem.ml_kem_512),
        1 => MlKem(mlkem.ml_kem_768),
        2 => MlKem(mlkem.ml_kem_1024),
        3 => XWing,
        else => unreachable,
    };
}

// The bytes a slot of this type and algorithm takes, 0 for an algorithm this library lacks.
pub fn size(slot_type: common.SlotType, algorithm: u32) usize {
    switch (algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) return 0;

            return switch (slot_type) {
                .kem_public => common.slotSize(Set(a).Public),
                .kem_private => common.slotSize(Set(a).Private),
                else => 0,
            };
        },
        else => return 0,
    }
}

pub fn alignment(slot_type: common.SlotType, algorithm: u32) usize {
    return if (size(slot_type, algorithm) == 0) 0 else common.slot_alignment;
}

fn known(algorithm: u32) Failure!void {
    if (algorithm >= count) return error.BadArgument;
}

fn openPublic(memory: ?[*]u8, length: usize) Failure!Slot {
    return common.open(&.{ .kem_public, .kem_private }, memory, length, size);
}

fn openPrivate(memory: ?[*]u8, length: usize) Failure!Slot {
    return common.open(&.{.kem_private}, memory, length, size);
}

// The public part of a public or a private slot.
fn publicPart(comptime S: type, slot: Slot) *S.Public {
    return if (slot.slot_type == .kem_private) &slot.body(S.Private).public else slot.body(S.Public);
}

pub fn keygen(algorithm: u32, seed: ?[*]const u8, seed_length: usize, flags: u32, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(generate(algorithm, seed, seed_length, flags, memory, length));
}

fn generate(algorithm: u32, seed_pointer: ?[*]const u8, seed_length: usize, flags: u32, memory: ?[*]u8, length: usize) Failure!void {
    try known(algorithm);

    if (flags & ~fill_cache != 0) return error.BadArgument;

    const slot = try common.place(.kem_private, algorithm, memory, length, size(.kem_private, algorithm));

    const seed = try common.input(seed_pointer, seed_length);

    try common.apart(&.{slot.bytes}, &.{seed});

    const dit = cpu.Dit.enter();

    defer dit.leave();

    switch (algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            const S = Set(a);

            if (seed.len != S.seed_size) return error.InvalidLength;

            @call(.never_inline, fromSeed, .{ S, slot.body(S.Private), seed[0..S.seed_size], flags & fill_cache != 0 });
        },
        else => unreachable,
    }

    slot.seal(common.has_seed);
}

fn fromSeed(comptime S: type, private: *S.Private, seed: *const [S.seed_size]u8, fill: bool) void {
    private.public.form.init();

    S.generate(private, seed, if (fill) private.public.form.claim() else null);

    if (fill) private.public.form.publish();

    private.seed = seed.*;
}

pub fn importPublic(algorithm: u32, key: ?[*]const u8, key_length: usize, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(importPublicKey(algorithm, key, key_length, memory, length));
}

fn importPublicKey(algorithm: u32, key: ?[*]const u8, key_length: usize, memory: ?[*]u8, length: usize) Failure!void {
    try known(algorithm);

    const slot = try common.place(.kem_public, algorithm, memory, length, size(.kem_public, algorithm));

    const bytes = try common.input(key, key_length);

    try common.apart(&.{slot.bytes}, &.{bytes});

    switch (algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            const S = Set(a);

            if (bytes.len != S.public_key_size) return error.InvalidLength;

            if (!@call(.never_inline, S.check, .{bytes[0..S.public_key_size]})) return error.InvalidPublicKey;

            const public = slot.body(S.Public);

            public.key = bytes[0..S.public_key_size].*;

            public.form.init();
        },
        else => unreachable,
    }

    slot.seal(0);
}

// A raw private key: the seed, or for ML-KEM the expanded key, which must pass the checks of
// FIPS 203.
pub fn importPrivate(algorithm: u32, key: ?[*]const u8, key_length: usize, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(importPrivateKey(algorithm, key, key_length, memory, length));
}

fn importPrivateKey(algorithm: u32, key: ?[*]const u8, key_length: usize, memory: ?[*]u8, length: usize) Failure!void {
    try known(algorithm);

    const slot = try common.place(.kem_private, algorithm, memory, length, size(.kem_private, algorithm));

    errdefer slot.discard();

    const bytes = try common.input(key, key_length);

    try common.apart(&.{slot.bytes}, &.{bytes});

    const dit = cpu.Dit.enter();

    defer dit.leave();

    switch (algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            const S = Set(a);

            const private = slot.body(S.Private);

            if (bytes.len == S.seed_size) {
                @call(.never_inline, fromSeed, .{ S, private, bytes[0..S.seed_size], false });

                return slot.seal(common.has_seed);
            }

            if (S.x_wing or bytes.len != S.expanded_size) return error.InvalidLength;

            if (!@call(.never_inline, S.expand, .{ private, bytes[0..S.expanded_size] })) return error.InvalidPrivateKey;

            private.public.form.init();

            @memset(&private.seed, 0);
        },
        else => unreachable,
    }

    slot.seal(0);
}

// A public slot for the public part of a private slot. A cache that the private slot holds comes
// along.
pub fn publicFromPrivate(private_memory: ?[*]u8, private_length: usize, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(derivePublic(private_memory, private_length, memory, length));
}

fn derivePublic(private_memory: ?[*]u8, private_length: usize, memory: ?[*]u8, length: usize) Failure!void {
    const private_slot = try openPrivate(private_memory, private_length);

    const slot = try common.place(.kem_public, private_slot.algorithm, memory, length, size(.kem_public, private_slot.algorithm));

    try common.apart(&.{slot.bytes}, &.{private_slot.bytes});

    switch (private_slot.algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            const S = Set(a);

            const source = &private_slot.body(S.Private).public;

            const public = slot.body(S.Public);

            public.key = source.key;

            public.form.copyFrom(&source.form);
        },
        else => unreachable,
    }

    slot.seal(0);
}

pub fn exportPublic(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(exportPublicKey(memory, length, out, out_length));
}

fn exportPublicKey(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    const slot = try openPublic(memory, length);

    switch (slot.algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            const S = Set(a);

            const target = try common.exact(out, out_length, S.public_key_size);

            try common.apart(&.{target}, &.{slot.bytes});

            @memcpy(target, &publicPart(S, slot).key);
        },
        else => unreachable,
    }
}

// `which` is export_seed, for a key that kept its seed, or export_expanded, for ML-KEM.
pub fn exportPrivate(memory: ?[*]u8, length: usize, which: u32, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(exportPrivateKey(memory, length, which, out, out_length));
}

fn exportPrivateKey(memory: ?[*]u8, length: usize, which: u32, out: ?[*]u8, out_length: usize) Failure!void {
    const slot = try openPrivate(memory, length);

    if (which != export_seed and which != export_expanded) return error.BadArgument;

    const dit = cpu.Dit.enter();

    defer dit.leave();

    switch (slot.algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            const S = Set(a);

            const private = slot.body(S.Private);

            if (which == export_seed) {
                if (slot.flags & common.has_seed == 0) return error.Unsupported;

                const target = try common.exact(out, out_length, S.seed_size);

                try common.apart(&.{target}, &.{slot.bytes});

                @memcpy(target, &private.seed);
            } else {
                if (S.x_wing) return error.Unsupported;

                const target = try common.exact(out, out_length, S.expanded_size);

                try common.apart(&.{target}, &.{slot.bytes});

                @memcpy(target, &private.dk);
            }
        },
        else => unreachable,
    }
}

// `randomness` is m for ML-KEM and the 64-byte eseed for X-Wing; the slot is public or private.
pub fn encapsulate(memory: ?[*]u8, length: usize, randomness: ?[*]const u8, randomness_length: usize, ciphertext: ?[*]u8, ciphertext_length: usize, secret: ?[*]u8, secret_length: usize) callconv(.c) c_int {
    return common.status(encapsulateChecked(memory, length, randomness, randomness_length, ciphertext, ciphertext_length, secret, secret_length));
}

fn encapsulateChecked(memory: ?[*]u8, length: usize, randomness: ?[*]const u8, randomness_length: usize, ciphertext: ?[*]u8, ciphertext_length: usize, secret: ?[*]u8, secret_length: usize) Failure!void {
    const slot = try openPublic(memory, length);

    const random = try common.input(randomness, randomness_length);

    switch (slot.algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            const S = Set(a);

            const c = try common.exact(ciphertext, ciphertext_length, S.ciphertext_size);

            const shared = try common.exact(secret, secret_length, 32);

            try common.apart(&.{ slot.bytes, c, shared }, &.{random});

            if (random.len != S.randomness_size) return error.InvalidLength;

            const dit = cpu.Dit.enter();

            defer dit.leave();

            @call(.never_inline, encapsulateWith, .{ S, publicPart(S, slot), random[0..S.randomness_size], c[0..S.ciphertext_size], shared[0..32] });
        },
        else => unreachable,
    }
}

fn encapsulateWith(comptime S: type, public: *S.Public, randomness: *const [S.randomness_size]u8, ciphertext: *[S.ciphertext_size]u8, secret: *[32]u8) void {
    if (public.form.get(public.ek())) |form| return S.encapsulate(form, public, randomness, ciphertext, secret);

    encapsulateUncached(S, public, randomness, ciphertext, secret);
}

// While another call fills the cache, this one samples the matrix for itself, in a frame of its own
// so that the usual path keeps a small one.
noinline fn encapsulateUncached(comptime S: type, public: *const S.Public, randomness: *const [S.randomness_size]u8, ciphertext: *[S.ciphertext_size]u8, secret: *[32]u8) void {
    var form: S.Form = undefined;

    form.fill(public.ek());

    S.encapsulate(&form, public, randomness, ciphertext, secret);
}

pub fn decapsulate(memory: ?[*]u8, length: usize, ciphertext: ?[*]const u8, ciphertext_length: usize, secret: ?[*]u8, secret_length: usize) callconv(.c) c_int {
    return common.status(decapsulateChecked(memory, length, ciphertext, ciphertext_length, secret, secret_length));
}

fn decapsulateChecked(memory: ?[*]u8, length: usize, ciphertext: ?[*]const u8, ciphertext_length: usize, secret: ?[*]u8, secret_length: usize) Failure!void {
    const slot = try openPrivate(memory, length);

    const c = try common.input(ciphertext, ciphertext_length);

    switch (slot.algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            const S = Set(a);

            const shared = try common.exact(secret, secret_length, 32);

            try common.apart(&.{ slot.bytes, shared }, &.{c});

            if (c.len != S.ciphertext_size) return error.InvalidLength;

            const dit = cpu.Dit.enter();

            defer dit.leave();

            shared[0..32].* = @call(.never_inline, decapsulateWith, .{ S, slot.body(S.Private), c[0..S.ciphertext_size] });
        },
        else => unreachable,
    }
}

fn decapsulateWith(comptime S: type, private: *S.Private, ciphertext: *const [S.ciphertext_size]u8) [32]u8 {
    if (private.public.form.get(private.public.ek())) |form| return S.decapsulate(form, private, ciphertext);

    return decapsulateUncached(S, private, ciphertext);
}

noinline fn decapsulateUncached(comptime S: type, private: *const S.Private, ciphertext: *const [S.ciphertext_size]u8) [32]u8 {
    var form: S.Form = undefined;

    form.fill(private.public.ek());

    return S.decapsulate(&form, private, ciphertext);
}

// The pairwise consistency test of key generation, with the caller's randomness for the
// encapsulation: the shared secrets never leave the library.
pub fn selfTest(memory: ?[*]u8, length: usize, randomness: ?[*]const u8, randomness_length: usize) callconv(.c) c_int {
    return common.status(selfTestChecked(memory, length, randomness, randomness_length));
}

fn selfTestChecked(memory: ?[*]u8, length: usize, randomness: ?[*]const u8, randomness_length: usize) Failure!void {
    const slot = try openPrivate(memory, length);

    const random = try common.input(randomness, randomness_length);

    try common.apart(&.{slot.bytes}, &.{random});

    switch (slot.algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            const S = Set(a);

            if (random.len != S.randomness_size) return error.InvalidLength;

            const dit = cpu.Dit.enter();

            defer dit.leave();

            if (!@call(.never_inline, pairwise, .{ S, slot.body(S.Private), random[0..S.randomness_size] })) return error.SelfTestFailed;
        },
        else => unreachable,
    }
}

fn pairwise(comptime S: type, private: *S.Private, randomness: *const [S.randomness_size]u8) bool {
    var ciphertext: [S.ciphertext_size]u8 = undefined;

    var sent: [32]u8 = undefined;

    var received: [32]u8 = undefined;

    defer {
        ct.wipe(&sent);

        ct.wipe(&received);
    }

    encapsulateWith(S, &private.public, randomness, &ciphertext, &sent);

    received = decapsulateWith(S, private, &ciphertext);

    // The outcome is public: key generation fails on it.
    return ct.declassifyValue(bool, ct.equal(&sent, &received));
}

// Whether the slot's cache is filled: bit 0 for the public part's.
pub fn cacheFlags(slot: Slot) u32 {
    switch (slot.algorithm) {
        inline 0...count - 1 => |a| {
            if (comptime !enabled(a)) unreachable;

            return @intFromBool(publicPart(Set(a), slot).form.isReady());
        },
        else => unreachable,
    }
}

pub fn opensAs(slot_type: common.SlotType) bool {
    return slot_type == .kem_public or slot_type == .kem_private;
}

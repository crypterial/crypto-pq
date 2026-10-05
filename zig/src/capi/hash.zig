const std = @import("std");

const options = @import("capi_options");

const common = @import("common.zig");

const cpu = @import("../cpu.zig");
const ct = @import("../ct.zig");
const hash = @import("../hash.zig");
const Keccak = @import("../keccak.zig").Keccak;
const sha2 = @import("../sha2.zig");

const Failure = common.Failure;

const Slot = common.Slot;

// Hash ids 0-9, XOF ids 0-1 and HMAC ids 0-3, in these orders.
pub const algorithms = [_]hash.HashAlgorithm{
    hash.sha_224,
    hash.sha_256,
    hash.sha_384,
    hash.sha_512,
    hash.sha_512_224,
    hash.sha_512_256,
    hash.sha3_224,
    hash.sha3_256,
    hash.sha3_384,
    hash.sha3_512,
};

pub const hash_count = algorithms.len;

pub const xof_count = 2;

pub const hmac_count = 4;

// A state slot holds the engine of its algorithm itself, without a tag: the algorithm in the header
// names the engine's type, and every call checks the engine's fields before it uses them, so that
// a state that the binding damaged is refused rather than read or written out of bounds.
fn Sha2Engine(comptime E: type, comptime block_size: usize) type {
    return struct {
        pub const Engine = E;

        pub fn valid(engine: *const E) bool {
            const used = common.once(usize, &engine.used);

            return used < block_size and used == common.once(u64, &engine.length) % block_size;
        }
    };
}

const Sha256 = Sha2Engine(sha2.Sha256, 64);

const Sha512 = Sha2Engine(sha2.Sha512, 128);

// A Keccak sponge with its rate and suffix, in the absorbing phase or, for an XOF, squeezing.
fn sponge(engine: *const Keccak, rate: usize, suffix: u8, may_squeeze: bool) bool {
    const squeezing = common.once(u8, @ptrCast(&engine.squeezing));

    const position = common.once(usize, &engine.position);

    if (common.once(usize, &engine.rate) != rate or common.once(u8, &engine.suffix) != suffix) return false;

    return switch (squeezing) {
        0 => position < rate,
        1 => may_squeeze and position <= rate,
        else => false,
    };
}

fn Hash(comptime id: u32) type {
    const algorithm = algorithms[id];

    return struct {
        pub const digest_size = algorithm.digest_size;

        pub const Engine = switch (algorithm.kind) {
            .sha256 => sha2.Sha256,
            .sha512 => sha2.Sha512,
            .sha3 => Keccak,
        };

        const rate = 200 - 2 * digest_size;

        pub fn init(engine: *Engine) void {
            switch (algorithm.kind) {
                .sha256 => |iv| engine.* = .init(iv),
                .sha512 => |iv| engine.* = .init(iv),
                .sha3 => engine.* = .init(rate, 0x06),
            }
        }

        pub fn valid(engine: *const Engine) bool {
            return switch (algorithm.kind) {
                .sha256 => Sha256.valid(engine),
                .sha512 => Sha512.valid(engine),
                .sha3 => sponge(engine, rate, 0x06, false),
            };
        }

        // The digest of everything so far; the engine goes on.
        pub fn digest(engine: *const Engine, out: *[digest_size]u8) void {
            switch (algorithm.kind) {
                .sha256, .sha512 => {
                    var full = engine.digest();

                    defer ct.wipe(&full);

                    out.* = full[0..digest_size].*;
                },
                .sha3 => {
                    var copy = engine.*;

                    defer ct.wipe(std.mem.asBytes(&copy));

                    copy.read(out);
                },
            }
        }
    };
}

fn Xof(comptime id: u32) type {
    return struct {
        const rate: usize = if (id == 0) 168 else 136;

        pub fn init(engine: *Keccak) void {
            engine.* = .init(rate, 0x1f);
        }

        pub fn valid(engine: *const Keccak) bool {
            return sponge(engine, rate, 0x1f, true);
        }
    };
}

// HMAC (RFC 2104) on one of the SHA-2 engines: the inner and outer engines after their padded
// key blocks.
fn Hmac(comptime id: u32) type {
    const algorithm = algorithms[id];

    return struct {
        pub const digest_size = algorithm.digest_size;

        const Engine = if (algorithm.kind == .sha256) sha2.Sha256 else sha2.Sha512;

        const block = if (algorithm.kind == .sha256) 64 else 128;

        const iv = switch (algorithm.kind) {
            .sha256 => |words| words,
            .sha512 => |words| words,
            .sha3 => unreachable,
        };

        pub const State = struct {
            inner: Engine,
            outer: Engine,
        };

        // Built in place: no frame keeps a copy of the engines, whose states derive from the key.
        pub fn init(state: *State, key: []const u8) void {
            var pad: [block]u8 = @splat(0);

            defer ct.wipe(&pad);

            if (key.len > block) {
                state.inner = .init(iv);

                state.inner.update(key);

                var full = state.inner.digest();

                defer ct.wipe(&full);

                pad[0..digest_size].* = full[0..digest_size].*;
            } else {
                @memcpy(pad[0..key.len], key);
            }

            for (&pad) |*b| b.* ^= 0x36;

            state.inner = .init(iv);

            state.inner.update(&pad);

            for (&pad) |*b| b.* ^= 0x36 ^ 0x5c;

            state.outer = .init(iv);

            state.outer.update(&pad);
        }

        // The inner engine has taken its key block and any data; the outer one only its key block.
        pub fn valid(state: *const State) bool {
            if (!(if (block == 64) Sha256.valid(&state.inner) else Sha512.valid(&state.inner))) return false;

            if (common.once(u64, &state.inner.length) < block) return false;

            return common.once(usize, &state.outer.used) == 0 and common.once(u64, &state.outer.length) == block;
        }

        pub fn tag(state: *const State, out: *[digest_size]u8) void {
            var inner = state.inner.digest();

            defer ct.wipe(&inner);

            var outer = state.outer;

            defer ct.wipe(std.mem.asBytes(&outer));

            outer.update(inner[0..digest_size]);

            var full = outer.digest();

            defer ct.wipe(&full);

            out.* = full[0..digest_size].*;
        }

        // The comparison takes the same time whatever the tag holds; the expected tag is wiped.
        pub fn verify(state: *const State, given: *const [digest_size]u8) bool {
            var expected: [digest_size]u8 = undefined;

            defer ct.wipe(&expected);

            tag(state, &expected);

            return ct.equal(&expected, given);
        }
    };
}

pub fn size(slot_type: common.SlotType, algorithm: u32) usize {
    if (!options.hash) return 0;

    switch (slot_type) {
        .hasher => switch (algorithm) {
            inline 0...hash_count - 1 => |a| return common.slotSize(Hash(a).Engine),
            else => return 0,
        },
        .xof => return if (algorithm < xof_count) common.slotSize(Keccak) else 0,
        .hmac => switch (algorithm) {
            inline 0...hmac_count - 1 => |a| return common.slotSize(Hmac(hmacHash(a)).State),
            else => return 0,
        },
        else => return 0,
    }
}

// HMAC ids name SHA-224, SHA-256, SHA-384 and SHA-512, hash ids 0 to 3.
fn hmacHash(comptime id: u32) u32 {
    return id;
}

fn known(algorithm: u32, total: usize) Failure!void {
    if (algorithm >= total) return error.BadArgument;
}

pub fn digest(algorithm: u32, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(digestChecked(algorithm, data, data_length, out, out_length));
}

fn digestChecked(algorithm: u32, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    try known(algorithm, hash_count);

    const h = algorithms[algorithm];

    const bytes = try common.input(data, data_length);

    const target = try common.exact(out, out_length, h.digest_size);

    try common.apart(&.{target}, &.{bytes});

    var hasher = h.create();

    defer ct.wipe(std.mem.asBytes(&hasher));

    hasher.update(bytes);

    hasher.digest(target);
}

// A state held by this call alone until it closes, its engine checked. `read` and `written` are
// the call's other buffers, which must be apart from the state.
fn hold(comptime slot_type: common.SlotType, memory: ?[*]u8, length: usize, read: []const u8, written: []const u8) Failure!Slot {
    const slot = try common.open(&.{slot_type}, memory, length, size, .exclusive);

    errdefer slot.close();

    try common.apart(&.{ slot.bytes, written }, &.{read});

    const fine = switch (slot_type) {
        .hasher => switch (slot.algorithm) {
            inline 0...hash_count - 1 => |a| Hash(a).valid(slot.body(Hash(a).Engine)),
            else => unreachable,
        },
        .xof => switch (slot.algorithm) {
            inline 0...xof_count - 1 => |a| Xof(a).valid(slot.body(Keccak)),
            else => unreachable,
        },
        .hmac => switch (slot.algorithm) {
            inline 0...hmac_count - 1 => |a| Hmac(hmacHash(a)).valid(slot.body(Hmac(hmacHash(a)).State)),
            else => unreachable,
        },
        else => unreachable,
    };

    if (!fine) return error.BadSlot;

    return slot;
}

pub fn init(algorithm: u32, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(initChecked(algorithm, memory, length));
}

fn initChecked(algorithm: u32, memory: ?[*]u8, length: usize) Failure!void {
    try known(algorithm, hash_count);

    const slot = try common.place(.hasher, algorithm, memory, length, size(.hasher, algorithm));

    switch (algorithm) {
        inline 0...hash_count - 1 => |a| Hash(a).init(slot.body(Hash(a).Engine)),
        else => unreachable,
    }

    slot.seal(0);
}

pub fn update(memory: ?[*]u8, length: usize, data: ?[*]const u8, data_length: usize) callconv(.c) c_int {
    return common.status(updateChecked(memory, length, data, data_length));
}

fn updateChecked(memory: ?[*]u8, length: usize, data: ?[*]const u8, data_length: usize) Failure!void {
    const bytes = try common.input(data, data_length);

    const slot = try hold(.hasher, memory, length, bytes, &.{});

    defer slot.close();

    switch (slot.algorithm) {
        inline 0...hash_count - 1 => |a| slot.body(Hash(a).Engine).update(bytes),
        else => unreachable,
    }

    try slot.confirm(&.{});
}

// The digest of everything given so far; the state may go on.
pub fn final(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(finalChecked(memory, length, out, out_length));
}

fn finalChecked(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    const target = try common.output(out, out_length);

    const slot = try hold(.hasher, memory, length, &.{}, target);

    defer slot.close();

    switch (slot.algorithm) {
        inline 0...hash_count - 1 => |a| {
            const H = Hash(a);

            if (target.len != H.digest_size) return error.BadArgument;

            H.digest(slot.body(H.Engine), target[0..H.digest_size]);
        },
        else => unreachable,
    }

    try slot.confirm(&.{target});
}

pub fn xof(algorithm: u32, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(xofChecked(algorithm, data, data_length, out, out_length));
}

fn xofChecked(algorithm: u32, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    try known(algorithm, xof_count);

    const bytes = try common.input(data, data_length);

    const target = try common.output(out, out_length);

    try common.apart(&.{target}, &.{bytes});

    var engine: Keccak = undefined;

    defer ct.wipe(std.mem.asBytes(&engine));

    switch (algorithm) {
        inline 0...xof_count - 1 => |a| Xof(a).init(&engine),
        else => unreachable,
    }

    engine.update(bytes);

    engine.read(target);
}

pub fn xofInit(algorithm: u32, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(xofInitChecked(algorithm, memory, length));
}

fn xofInitChecked(algorithm: u32, memory: ?[*]u8, length: usize) Failure!void {
    try known(algorithm, xof_count);

    const slot = try common.place(.xof, algorithm, memory, length, size(.xof, algorithm));

    switch (algorithm) {
        inline 0...xof_count - 1 => |a| Xof(a).init(slot.body(Keccak)),
        else => unreachable,
    }

    slot.seal(0);
}

// Once reading has begun, an update is UNSUPPORTED, as in every crypto-pq.
pub fn xofUpdate(memory: ?[*]u8, length: usize, data: ?[*]const u8, data_length: usize) callconv(.c) c_int {
    return common.status(xofUpdateChecked(memory, length, data, data_length));
}

fn xofUpdateChecked(memory: ?[*]u8, length: usize, data: ?[*]const u8, data_length: usize) Failure!void {
    const bytes = try common.input(data, data_length);

    const slot = try hold(.xof, memory, length, bytes, &.{});

    defer slot.close();

    const engine = slot.body(Keccak);

    if (engine.squeezing) return error.Unsupported;

    engine.update(bytes);

    try slot.confirm(&.{});
}

// The next `out_length` bytes of the output stream.
pub fn xofRead(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(xofReadChecked(memory, length, out, out_length));
}

fn xofReadChecked(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    const target = try common.output(out, out_length);

    const slot = try hold(.xof, memory, length, &.{}, target);

    defer slot.close();

    slot.body(Keccak).read(target);

    try slot.confirm(&.{target});
}

pub fn hmac(algorithm: u32, key: ?[*]const u8, key_length: usize, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(hmacChecked(algorithm, key, key_length, data, data_length, out, out_length));
}

fn hmacChecked(algorithm: u32, key: ?[*]const u8, key_length: usize, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    try known(algorithm, hmac_count);

    const k = try common.input(key, key_length);

    const bytes = try common.input(data, data_length);

    switch (algorithm) {
        inline 0...hmac_count - 1 => |a| {
            const H = Hmac(hmacHash(a));

            const target = try common.exact(out, out_length, H.digest_size);

            try common.apart(&.{target}, &.{ k, bytes });

            const dit = cpu.Dit.enter();

            defer dit.leave();

            var state: H.State = undefined;

            defer ct.wipe(std.mem.asBytes(&state));

            H.init(&state, k);

            state.inner.update(bytes);

            H.tag(&state, target[0..H.digest_size]);
        },
        else => unreachable,
    }
}

// The tag must have the full length; the comparison takes the same time whatever the tag holds.
pub fn hmacVerify(algorithm: u32, key: ?[*]const u8, key_length: usize, data: ?[*]const u8, data_length: usize, tag: ?[*]const u8, tag_length: usize) callconv(.c) c_int {
    return common.status(hmacVerifyChecked(algorithm, key, key_length, data, data_length, tag, tag_length));
}

fn hmacVerifyChecked(algorithm: u32, key: ?[*]const u8, key_length: usize, data: ?[*]const u8, data_length: usize, tag: ?[*]const u8, tag_length: usize) Failure!void {
    try known(algorithm, hmac_count);

    const k = try common.input(key, key_length);

    const bytes = try common.input(data, data_length);

    const expected = try common.input(tag, tag_length);

    switch (algorithm) {
        inline 0...hmac_count - 1 => |a| {
            const H = Hmac(hmacHash(a));

            if (expected.len != H.digest_size) return error.Rejected;

            const dit = cpu.Dit.enter();

            defer dit.leave();

            var state: H.State = undefined;

            defer ct.wipe(std.mem.asBytes(&state));

            H.init(&state, k);

            state.inner.update(bytes);

            // Whether the tag matches is the answer the caller asked for.
            if (!ct.declassifyValue(bool, H.verify(&state, expected[0..H.digest_size]))) return error.Rejected;
        },
        else => unreachable,
    }
}

pub fn hmacInit(algorithm: u32, key: ?[*]const u8, key_length: usize, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(hmacInitChecked(algorithm, key, key_length, memory, length));
}

fn hmacInitChecked(algorithm: u32, key: ?[*]const u8, key_length: usize, memory: ?[*]u8, length: usize) Failure!void {
    try known(algorithm, hmac_count);

    const slot = try common.place(.hmac, algorithm, memory, length, size(.hmac, algorithm));

    const k = try common.input(key, key_length);

    try common.apart(&.{slot.bytes}, &.{k});

    const dit = cpu.Dit.enter();

    defer dit.leave();

    switch (algorithm) {
        inline 0...hmac_count - 1 => |a| {
            const H = Hmac(hmacHash(a));

            H.init(slot.body(H.State), k);
        },
        else => unreachable,
    }

    slot.seal(0);
}

pub fn hmacUpdate(memory: ?[*]u8, length: usize, data: ?[*]const u8, data_length: usize) callconv(.c) c_int {
    return common.status(hmacUpdateChecked(memory, length, data, data_length));
}

fn hmacUpdateChecked(memory: ?[*]u8, length: usize, data: ?[*]const u8, data_length: usize) Failure!void {
    const bytes = try common.input(data, data_length);

    const slot = try hold(.hmac, memory, length, bytes, &.{});

    defer slot.close();

    const dit = cpu.Dit.enter();

    defer dit.leave();

    switch (slot.algorithm) {
        inline 0...hmac_count - 1 => |a| slot.body(Hmac(hmacHash(a)).State).inner.update(bytes),
        else => unreachable,
    }

    try slot.confirm(&.{});
}

pub fn hmacFinal(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(hmacFinalChecked(memory, length, out, out_length));
}

fn hmacFinalChecked(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    const target = try common.output(out, out_length);

    const slot = try hold(.hmac, memory, length, &.{}, target);

    defer slot.close();

    const dit = cpu.Dit.enter();

    defer dit.leave();

    switch (slot.algorithm) {
        inline 0...hmac_count - 1 => |a| {
            const H = Hmac(hmacHash(a));

            if (target.len != H.digest_size) return error.BadArgument;

            H.tag(slot.body(H.State), target[0..H.digest_size]);
        },
        else => unreachable,
    }

    try slot.confirm(&.{target});
}

pub fn hmacFinalVerify(memory: ?[*]u8, length: usize, tag: ?[*]const u8, tag_length: usize) callconv(.c) c_int {
    return common.status(hmacFinalVerifyChecked(memory, length, tag, tag_length));
}

fn hmacFinalVerifyChecked(memory: ?[*]u8, length: usize, tag: ?[*]const u8, tag_length: usize) Failure!void {
    const expected = try common.input(tag, tag_length);

    const slot = try hold(.hmac, memory, length, expected, &.{});

    defer slot.close();

    const dit = cpu.Dit.enter();

    defer dit.leave();

    const matches = switch (slot.algorithm) {
        inline 0...hmac_count - 1 => |a| matches: {
            const H = Hmac(hmacHash(a));

            if (expected.len != H.digest_size) break :matches false;

            break :matches H.verify(slot.body(H.State), expected[0..H.digest_size]);
        },
        else => unreachable,
    };

    try slot.confirm(&.{});

    if (!ct.declassifyValue(bool, matches)) return error.Rejected;
}

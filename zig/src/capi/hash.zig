const std = @import("std");

const options = @import("capi_options");

const common = @import("common.zig");

const ascon = @import("../ascon.zig");
const blake2 = @import("../blake2.zig");
const cpu = @import("../cpu.zig");
const ct = @import("../ct.zig");
const hash = @import("../hash.zig");
const kdf = @import("../kdf.zig");
const Keccak = @import("../keccak.zig").Keccak;
const sha2 = @import("../sha2.zig");
const sp800_185 = @import("../sp800_185.zig");

const Failure = common.Failure;

const Slot = common.Slot;

// Hash ids 0-18, XOF ids 0-5, MAC ids 0-7 and KDF ids 0-2, in these orders. ABI version 1 had the
// first ten hashes, the first two XOFs and the four HMACs.
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
    hash.blake2b_160,
    hash.blake2b_256,
    hash.blake2b_384,
    hash.blake2b_512,
    hash.blake2s_128,
    hash.blake2s_160,
    hash.blake2s_224,
    hash.blake2s_256,
    hash.ascon_hash256,
};

pub const hash_count = algorithms.len;

pub const xofs = [_]hash.XofAlgorithm{
    hash.shake128,
    hash.shake256,
    hash.cshake128,
    hash.cshake256,
    hash.ascon_xof128,
    hash.ascon_cxof128,
};

pub const xof_count = xofs.len;

pub const macs = [_]hash.MacAlgorithm{
    hash.hmac_sha_224,
    hash.hmac_sha_256,
    hash.hmac_sha_384,
    hash.hmac_sha_512,
    hash.kmac128,
    hash.kmac256,
    hash.blake2b_mac,
    hash.blake2s_mac,
};

pub const mac_count = macs.len;

pub const hmac_count = 4;

pub const kdfs = [_]kdf.KdfAlgorithm{ kdf.hkdf_sha_256, kdf.hkdf_sha_384, kdf.hkdf_sha_512 };

pub const kdf_count = kdfs.len;

// Flags of cpq_mac_configure: KMACXOF, and a length given in `size` rather than the default.
pub const mac_xof: u32 = 1;

pub const mac_length: u32 = 2;

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

// cSHAKE is SHAKE until a function name or customization gives it a prefix and its own suffix.
fn cshakeSponge(engine: *const Keccak, rate: usize) bool {
    return sponge(engine, rate, 0x1f, true) or sponge(engine, rate, sp800_185.suffix, true);
}

// A BLAKE2 engine keeps at most a block, the last one, which takes the final flag.
fn blake2Engine(comptime B: type, engine: *const B.Engine) bool {
    return common.once(usize, &engine.used) <= B.block;
}

// An Ascon sponge absorbs fewer than eight bytes into its block; squeezing, it has read up to eight.
fn asconSponge(engine: *const ascon.Sponge, may_squeeze: bool) bool {
    const squeezing = common.once(u8, @ptrCast(&engine.squeezing));

    const used = common.once(usize, &engine.used);

    return switch (squeezing) {
        0 => used < 8,
        1 => may_squeeze and used <= 8,
        else => false,
    };
}

// A flag word of a configured algorithm or a state: 0 or 1.
fn flag(word: *const u32) ?bool {
    return switch (common.once(u32, word)) {
        0 => false,
        1 => true,
        else => null,
    };
}

pub fn Hash(comptime id: u32) type {
    const algorithm = algorithms[id];

    return struct {
        pub const digest_size = algorithm.digest_size;

        pub const Engine = switch (algorithm.kind) {
            .sha256 => sha2.Sha256,
            .sha512 => sha2.Sha512,
            .sha3 => Keccak,
            .blake2b => blake2.Blake2b.Engine,
            .blake2s => blake2.Blake2s.Engine,
            .ascon => ascon.Sponge,
        };

        // What configure computes: the chaining value of BLAKE2's parameter block; nothing for the
        // other hashes, which take no options.
        pub const Spec = switch (algorithm.kind) {
            .blake2b => [8]u64,
            .blake2s => [8]u32,
            else => [0]u8,
        };

        const rate = 200 - 2 * digest_size;

        // The engine's field in hash.zig's engine union.
        const tag = if (algorithm.kind == .sha3) "keccak" else @tagName(algorithm.kind);

        pub fn init(engine: *Engine, configured: hash.HashAlgorithm) void {
            const hasher = configured.create();

            engine.* = @field(hasher.engine, tag);
        }

        pub fn valid(engine: *const Engine) bool {
            return switch (algorithm.kind) {
                .sha256 => Sha256.valid(engine),
                .sha512 => Sha512.valid(engine),
                .sha3 => sponge(engine, rate, 0x06, false),
                .blake2b => blake2Engine(blake2.Blake2b, engine),
                .blake2s => blake2Engine(blake2.Blake2s, engine),
                .ascon => asconSponge(engine, false),
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
                .sha3, .ascon => {
                    var copy = engine.*;

                    defer ct.wipe(std.mem.asBytes(&copy));

                    copy.read(out);
                },
                .blake2b, .blake2s => engine.digest(out),
            }
        }

        pub fn configure(spec: *Spec, salt: []const u8, personalization: []const u8) Failure!void {
            const configured = try algorithm.configure(.{ .salt = salt, .personalization = personalization });

            switch (algorithm.kind) {
                .blake2b => spec.* = configured.kind.blake2b,
                .blake2s => spec.* = configured.kind.blake2s,
                else => {},
            }
        }

        // The hash that a configured slot holds, written where the caller keeps it: the callers
        // run this for one id of many, and a value per id would take a frame slot per id.
        pub fn fromSpec(spec: *const Spec, out: *hash.HashAlgorithm) void {
            out.* = algorithm;

            switch (algorithm.kind) {
                .blake2b => out.kind.blake2b = spec.*,
                .blake2s => out.kind.blake2s = spec.*,
                else => {},
            }
        }

        pub fn initFromSpec(engine: *Engine, spec: *const Spec) void {
            var configured: hash.HashAlgorithm = undefined;

            fromSpec(spec, &configured);

            @This().init(engine, configured);
        }
    };
}

pub fn Xof(comptime id: u32) type {
    const algorithm = xofs[id];

    return struct {
        pub const Engine = if (algorithm.rate == 8) ascon.Sponge else Keccak;

        // What configure computes: a cSHAKE's prefix state and whether it has one, an Ascon-CXOF's
        // state after its customization; nothing for the others.
        pub const Spec = switch (algorithm.kind) {
            .cshake => struct {
                state: [25]u64,
                prefixed: u32,
            },
            .ascon_cxof => ascon.State,
            else => [0]u8,
        };

        // The engine's field in hash.zig's Xof.
        const tag = if (algorithm.rate == 8) "ascon" else "keccak";

        pub fn init(engine: *Engine, configured: hash.XofAlgorithm) void {
            const created = configured.create();

            engine.* = @field(created.engine, tag);
        }

        pub fn valid(engine: *const Engine) bool {
            return switch (algorithm.kind) {
                .shake => sponge(engine, algorithm.rate, 0x1f, true),
                .cshake => cshakeSponge(engine, algorithm.rate),
                .ascon_xof, .ascon_cxof => asconSponge(engine, true),
            };
        }

        pub fn configure(spec: *Spec, function_name: []const u8, customization: []const u8) Failure!void {
            if (algorithm.kind != .cshake and function_name.len > 0) return error.InvalidOption;

            const configured = if (algorithm.kind == .cshake) try hash.configureCshake(algorithm, function_name, customization) else try algorithm.configure(.{ .customization = customization });

            switch (algorithm.kind) {
                .cshake => {
                    const prefix = configured.kind.cshake;

                    spec.* = .{ .state = prefix orelse @splat(0), .prefixed = @intFromBool(prefix != null) };
                },
                .ascon_cxof => spec.* = configured.kind.ascon_cxof,
                else => {},
            }
        }

        // As Hash(id).fromSpec; false for a slot that the binding damaged.
        pub fn fromSpec(spec: *const Spec, out: *hash.XofAlgorithm) bool {
            out.* = algorithm;

            switch (algorithm.kind) {
                .cshake => {
                    const prefixed = flag(&spec.prefixed) orelse return false;

                    if (prefixed) out.kind.cshake = spec.state;
                },
                .ascon_cxof => out.kind.ascon_cxof = spec.*,
                else => {},
            }

            return true;
        }

        pub fn initFromSpec(engine: *Engine, spec: *const Spec) bool {
            var configured: hash.XofAlgorithm = undefined;

            if (!fromSpec(spec, &configured)) return false;

            @This().init(engine, configured);

            return true;
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
            else => unreachable,
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

// A MAC of any kind: its configured form, which holds no key, and its state, which does. HMAC's
// state is Hmac(id)'s; KMAC's is the sponge after the key with the output length; BLAKE2's the
// keyed engine with the output length.
pub fn Mac(comptime id: u32) type {
    const algorithm = macs[id];

    return struct {
        const B = switch (algorithm.kind) {
            .blake2b => blake2.Blake2b,
            .blake2s => blake2.Blake2s,
            else => void,
        };

        const rate = if (algorithm.kind == .kmac) algorithm.kind.kmac.rate else 0;

        pub const State = switch (algorithm.kind) {
            .hmac => Hmac(id).State,
            .kmac => struct {
                sponge: Keccak,
                length: usize,
                xof: u32,
            },
            .blake2b, .blake2s => struct {
                engine: B.Engine,
                length: usize,
            },
        };

        pub const Spec = switch (algorithm.kind) {
            .hmac => [0]u8,
            .kmac => struct {
                state: [25]u64,
                length: usize,
                xof: u32,
            },
            .blake2b, .blake2s => struct {
                h0: @FieldType(B.Engine, "h"),
                length: usize,
            },
        };

        fn validLength(length: usize) bool {
            return switch (algorithm.kind) {
                .hmac => length == algorithm.digest_size,
                .kmac => length >= 4,
                .blake2b, .blake2s => length >= 1 and length <= B.max_size,
            };
        }

        pub fn configure(spec: *Spec, out_size: usize, flags: u32, first: []const u8, second: []const u8) Failure!void {
            if (flags & ~(mac_xof | mac_length) != 0 or (flags & mac_length == 0 and out_size != 0)) return error.BadArgument;

            const length: ?usize = if (flags & mac_length != 0) out_size else null;

            const extendable = flags & mac_xof != 0;

            // Each kind takes its own options; whatever else is given is refused by configure.
            const choice: hash.MacOptions = switch (algorithm.kind) {
                .blake2b, .blake2s => .{ .length = length, .xof = extendable, .salt = first, .personalization = second },
                else => .{ .length = length, .xof = extendable, .customization = first, .salt = second },
            };

            const configured = try algorithm.configure(choice);

            switch (algorithm.kind) {
                .hmac => {},
                .kmac => spec.* = .{ .state = configured.kind.kmac.state, .length = configured.digest_size, .xof = @intFromBool(configured.kind.kmac.xof) },
                inline .blake2b, .blake2s => |_, kind| spec.* = .{ .h0 = @field(configured.kind, @tagName(kind)), .length = configured.digest_size },
            }
        }

        // The MAC that a configured slot holds, as Hash(id).fromSpec; false for a slot that the
        // binding damaged.
        pub fn fromSpec(spec: *const Spec, out: *hash.MacAlgorithm) bool {
            out.* = algorithm;

            switch (algorithm.kind) {
                .hmac => {},
                .kmac => {
                    const extendable = flag(&spec.xof) orelse return false;

                    const length = common.once(usize, &spec.length);

                    if (!validLength(length)) return false;

                    out.digest_size = length;

                    out.kind.kmac.state = spec.state;

                    out.kind.kmac.xof = extendable;
                },
                inline .blake2b, .blake2s => |_, kind| {
                    const length = common.once(usize, &spec.length);

                    if (!validLength(length)) return false;

                    out.digest_size = length;

                    @field(out.kind, @tagName(kind)) = spec.h0;
                },
            }

            return true;
        }

        // Built in place, from a configured MAC of this id, under the caller's DIT guard.
        pub fn init(state: *State, mac: *const hash.MacAlgorithm, key: []const u8) void {
            switch (algorithm.kind) {
                .hmac => Hmac(id).init(state, key),
                .kmac => {
                    const k = mac.kind.kmac;

                    state.* = .{ .sponge = .{ .state = k.state, .rate = rate, .suffix = sp800_185.suffix }, .length = mac.digest_size, .xof = @intFromBool(k.xof) };

                    sp800_185.absorbKey(&state.sponge, key);
                },
                inline .blake2b, .blake2s => |_, kind| {
                    state.engine.initKeyed(&@field(mac.kind, @tagName(kind)), key);

                    state.length = mac.digest_size;
                },
            }
        }

        pub fn valid(state: *const State) bool {
            return switch (algorithm.kind) {
                .hmac => Hmac(id).valid(state),
                .kmac => sponge(&state.sponge, rate, sp800_185.suffix, false) and flag(&state.xof) != null and validLength(common.once(usize, &state.length)),
                .blake2b, .blake2s => blake2Engine(B, &state.engine) and validLength(common.once(usize, &state.length)),
            };
        }

        pub fn size(state: *const State) usize {
            return if (algorithm.kind == .hmac) algorithm.digest_size else state.length;
        }

        pub fn update(state: *State, data: []const u8) void {
            switch (algorithm.kind) {
                .hmac => state.inner.update(data),
                .kmac => state.sponge.update(data),
                .blake2b, .blake2s => state.engine.update(data),
            }
        }

        // out.len is the state's size.
        pub fn tag(state: *const State, out: []u8) void {
            switch (algorithm.kind) {
                .hmac => Hmac(id).tag(state, out[0..algorithm.digest_size]),
                .kmac => {
                    var copy = state.sponge;

                    defer ct.wipe(std.mem.asBytes(&copy));

                    sp800_185.absorbLength(&copy, out.len, state.xof != 0);

                    copy.read(out);
                },
                .blake2b, .blake2s => state.engine.digest(out),
            }
        }

        // given.len is the state's size.
        pub fn verify(state: *const State, given: []const u8) bool {
            switch (algorithm.kind) {
                .hmac => return Hmac(id).verify(state, given[0..algorithm.digest_size]),
                .kmac => {
                    var copy = state.sponge;

                    defer ct.wipe(std.mem.asBytes(&copy));

                    sp800_185.absorbLength(&copy, given.len, state.xof != 0);

                    return hash.matches(&copy, given);
                },
                .blake2b, .blake2s => {
                    var expected: [B.max_size]u8 = undefined;

                    defer ct.wipe(&expected);

                    state.engine.digest(expected[0..given.len]);

                    return ct.equal(expected[0..given.len], given);
                },
            }
        }
    };
}

pub fn size(slot_type: common.SlotType, algorithm: u32) usize {
    if (!options.hash) return 0;

    switch (slot_type) {
        inline .hasher, .configured_hash => |t| switch (algorithm) {
            inline 0...hash_count - 1 => |a| return common.slotSize(if (t == .hasher) Hash(a).Engine else Hash(a).Spec),
            else => return 0,
        },
        inline .xof, .configured_xof => |t| switch (algorithm) {
            inline 0...xof_count - 1 => |a| return common.slotSize(if (t == .xof) Xof(a).Engine else Xof(a).Spec),
            else => return 0,
        },
        inline .hmac, .configured_mac => |t| switch (algorithm) {
            inline 0...mac_count - 1 => |a| return common.slotSize(if (t == .hmac) Mac(a).State else Mac(a).Spec),
            else => return 0,
        },
        else => return 0,
    }
}

fn known(algorithm: u32, total: usize) Failure!void {
    if (algorithm >= total) return error.BadArgument;
}

// A BLAKE2 MAC takes keys of 1 to 64 (BLAKE2b) or 32 (BLAKE2s) bytes; the others any key.
fn checkKey(mac: *const hash.MacAlgorithm, key: []const u8) Failure!void {
    if (!mac.takes(key)) return error.InvalidLength;
}

// A configured algorithm, which calls only read: any number of them at once.
fn configuredSlot(comptime slot_type: common.SlotType, memory: ?[*]u8, length: usize) Failure!Slot {
    return common.open(&.{slot_type}, memory, length, size, .shared);
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

    h.digest(bytes, target);
}

// The digest of a configured hash, in one call.
pub fn digestWith(spec: ?[*]u8, spec_length: usize, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(digestWithChecked(spec, spec_length, data, data_length, out, out_length));
}

fn digestWithChecked(spec: ?[*]u8, spec_length: usize, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    const bytes = try common.input(data, data_length);

    const slot = try configuredSlot(.configured_hash, spec, spec_length);

    defer slot.close();

    const target = try common.exact(out, out_length, algorithms[slot.algorithm].digest_size);

    try common.apart(&.{target}, &.{ bytes, slot.bytes });

    // One value for every id: a value per id would take a frame slot per id.
    var configured: hash.HashAlgorithm = undefined;

    switch (slot.algorithm) {
        inline 0...hash_count - 1 => |a| @call(.never_inline, Hash(a).fromSpec, .{ slot.body(Hash(a).Spec), &configured }),
        else => unreachable,
    }

    configured.digest(bytes, target);

    try slot.confirm(&.{target});
}

// A hash with a salt and a personalization (BLAKE2 only), into a configured slot.
pub fn configureHash(algorithm: u32, salt: ?[*]const u8, salt_length: usize, personalization: ?[*]const u8, personalization_length: usize, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(configureHashChecked(algorithm, salt, salt_length, personalization, personalization_length, memory, length));
}

fn configureHashChecked(algorithm: u32, salt: ?[*]const u8, salt_length: usize, personalization: ?[*]const u8, personalization_length: usize, memory: ?[*]u8, length: usize) Failure!void {
    try known(algorithm, hash_count);

    const slot = try common.place(.configured_hash, algorithm, memory, length, size(.configured_hash, algorithm));

    const first = try common.input(salt, salt_length);

    const second = try common.input(personalization, personalization_length);

    try common.apart(&.{slot.bytes}, &.{ first, second });

    switch (algorithm) {
        inline 0...hash_count - 1 => |a| try Hash(a).configure(slot.body(Hash(a).Spec), first, second),
        else => unreachable,
    }

    slot.seal(0);
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
            inline 0...xof_count - 1 => |a| Xof(a).valid(slot.body(Xof(a).Engine)),
            else => unreachable,
        },
        .hmac => switch (slot.algorithm) {
            inline 0...mac_count - 1 => |a| Mac(a).valid(slot.body(Mac(a).State)),
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
        inline 0...hash_count - 1 => |a| @call(.never_inline, Hash(a).init, .{ slot.body(Hash(a).Engine), algorithms[a] }),
        else => unreachable,
    }

    slot.seal(0);
}

// A state of a configured hash.
pub fn initWith(spec: ?[*]u8, spec_length: usize, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(initWithChecked(spec, spec_length, memory, length));
}

fn initWithChecked(spec: ?[*]u8, spec_length: usize, memory: ?[*]u8, length: usize) Failure!void {
    const configured = try configuredSlot(.configured_hash, spec, spec_length);

    defer configured.close();

    const slot = try common.place(.hasher, configured.algorithm, memory, length, size(.hasher, configured.algorithm));

    try common.apart(&.{slot.bytes}, &.{configured.bytes});

    switch (configured.algorithm) {
        inline 0...hash_count - 1 => |a| @call(.never_inline, Hash(a).initFromSpec, .{ slot.body(Hash(a).Engine), configured.body(Hash(a).Spec) }),
        else => unreachable,
    }

    configured.confirm(&.{}) catch |err| {
        slot.discard();

        return err;
    };

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

    squeeze(xofs[algorithm], bytes, target);
}

// One-shot XOF output; the engine, which may have absorbed a secret, is wiped.
fn squeeze(algorithm: hash.XofAlgorithm, data: []const u8, out: []u8) void {
    var engine = algorithm.create();

    defer ct.wipe(std.mem.asBytes(&engine));

    engine.update(data);

    engine.read(out);
}

pub fn xofWith(spec: ?[*]u8, spec_length: usize, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(xofWithChecked(spec, spec_length, data, data_length, out, out_length));
}

fn xofWithChecked(spec: ?[*]u8, spec_length: usize, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    const bytes = try common.input(data, data_length);

    const target = try common.output(out, out_length);

    const slot = try configuredSlot(.configured_xof, spec, spec_length);

    defer slot.close();

    try common.apart(&.{target}, &.{ bytes, slot.bytes });

    var configured: hash.XofAlgorithm = undefined;

    const fine = switch (slot.algorithm) {
        inline 0...xof_count - 1 => |a| @call(.never_inline, Xof(a).fromSpec, .{ slot.body(Xof(a).Spec), &configured }),
        else => unreachable,
    };

    if (!fine) return error.BadSlot;

    squeeze(configured, bytes, target);

    try slot.confirm(&.{target});
}

// An XOF with a customization string (cSHAKE, Ascon-CXOF128) and, for cSHAKE only, a function
// name (hazmat), into a configured slot.
pub fn configureXof(algorithm: u32, function_name: ?[*]const u8, function_name_length: usize, customization: ?[*]const u8, customization_length: usize, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(configureXofChecked(algorithm, function_name, function_name_length, customization, customization_length, memory, length));
}

fn configureXofChecked(algorithm: u32, function_name: ?[*]const u8, function_name_length: usize, customization: ?[*]const u8, customization_length: usize, memory: ?[*]u8, length: usize) Failure!void {
    try known(algorithm, xof_count);

    const slot = try common.place(.configured_xof, algorithm, memory, length, size(.configured_xof, algorithm));

    const name = try common.input(function_name, function_name_length);

    const custom = try common.input(customization, customization_length);

    try common.apart(&.{slot.bytes}, &.{ name, custom });

    switch (algorithm) {
        inline 0...xof_count - 1 => |a| try Xof(a).configure(slot.body(Xof(a).Spec), name, custom),
        else => unreachable,
    }

    slot.seal(0);
}

pub fn xofInit(algorithm: u32, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(xofInitChecked(algorithm, memory, length));
}

fn xofInitChecked(algorithm: u32, memory: ?[*]u8, length: usize) Failure!void {
    try known(algorithm, xof_count);

    const slot = try common.place(.xof, algorithm, memory, length, size(.xof, algorithm));

    switch (algorithm) {
        inline 0...xof_count - 1 => |a| @call(.never_inline, Xof(a).init, .{ slot.body(Xof(a).Engine), xofs[a] }),
        else => unreachable,
    }

    slot.seal(0);
}

pub fn xofInitWith(spec: ?[*]u8, spec_length: usize, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(xofInitWithChecked(spec, spec_length, memory, length));
}

fn xofInitWithChecked(spec: ?[*]u8, spec_length: usize, memory: ?[*]u8, length: usize) Failure!void {
    const configured = try configuredSlot(.configured_xof, spec, spec_length);

    defer configured.close();

    const slot = try common.place(.xof, configured.algorithm, memory, length, size(.xof, configured.algorithm));

    try common.apart(&.{slot.bytes}, &.{configured.bytes});

    switch (configured.algorithm) {
        inline 0...xof_count - 1 => |a| if (!@call(.never_inline, Xof(a).initFromSpec, .{ slot.body(Xof(a).Engine), configured.body(Xof(a).Spec) })) return error.BadSlot,
        else => unreachable,
    }

    configured.confirm(&.{}) catch |err| {
        slot.discard();

        return err;
    };

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

    switch (slot.algorithm) {
        inline 0...xof_count - 1 => |a| {
            const engine = slot.body(Xof(a).Engine);

            if (engine.squeezing) return error.Unsupported;

            engine.update(bytes);
        },
        else => unreachable,
    }

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

    switch (slot.algorithm) {
        inline 0...xof_count - 1 => |a| slot.body(Xof(a).Engine).read(target),
        else => unreachable,
    }

    try slot.confirm(&.{target});
}

// cpq_hmac and cpq_mac: any MAC with its default options. The output has the MAC's length.
pub fn hmac(algorithm: u32, key: ?[*]const u8, key_length: usize, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(hmacChecked(algorithm, key, key_length, data, data_length, out, out_length));
}

fn hmacChecked(algorithm: u32, key: ?[*]const u8, key_length: usize, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    try known(algorithm, mac_count);

    const k = try common.input(key, key_length);

    const bytes = try common.input(data, data_length);

    const target = try common.exact(out, out_length, macs[algorithm].digest_size);

    try common.apart(&.{target}, &.{ k, bytes });

    try macDigest(&macs[algorithm], k, bytes, target);
}

fn macDigest(mac: *const hash.MacAlgorithm, key: []const u8, data: []const u8, out: []u8) Failure!void {
    try checkKey(mac, key);

    const dit = cpu.Dit.enterKeyed();

    defer dit.leave();

    mac.digest(key, data, out);
}

// The tag must have the full length; the comparison takes the same time whatever the tag holds.
pub fn hmacVerify(algorithm: u32, key: ?[*]const u8, key_length: usize, data: ?[*]const u8, data_length: usize, tag: ?[*]const u8, tag_length: usize) callconv(.c) c_int {
    return common.status(hmacVerifyChecked(algorithm, key, key_length, data, data_length, tag, tag_length));
}

fn hmacVerifyChecked(algorithm: u32, key: ?[*]const u8, key_length: usize, data: ?[*]const u8, data_length: usize, tag: ?[*]const u8, tag_length: usize) Failure!void {
    try known(algorithm, mac_count);

    const k = try common.input(key, key_length);

    const bytes = try common.input(data, data_length);

    const expected = try common.input(tag, tag_length);

    try macVerify(&macs[algorithm], k, bytes, expected);
}

// A key that the MAC cannot take, like a tag of another length, makes the answer no.
fn macVerify(mac: *const hash.MacAlgorithm, key: []const u8, data: []const u8, tag: []const u8) Failure!void {
    checkKey(mac, key) catch return error.Rejected;

    if (tag.len != mac.digest_size) return error.Rejected;

    const dit = cpu.Dit.enterKeyed();

    defer dit.leave();

    // Whether the tag matches is the answer the caller asked for.
    if (!ct.declassifyValue(bool, mac.verify(key, data, tag))) return error.Rejected;
}

// A MAC with its options, into a configured slot: KMAC takes size (at least 4), the xof flag and a
// customization (first); BLAKE2 size (1 to 64 or 32), a salt (first) and a personalization
// (second); HMAC nothing. Without mac_length in flags the length is the default and size 0.
pub fn configureMac(algorithm: u32, out_size: usize, flags: u32, first: ?[*]const u8, first_length: usize, second: ?[*]const u8, second_length: usize, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(configureMacChecked(algorithm, out_size, flags, first, first_length, second, second_length, memory, length));
}

fn configureMacChecked(algorithm: u32, out_size: usize, flags: u32, first: ?[*]const u8, first_length: usize, second: ?[*]const u8, second_length: usize, memory: ?[*]u8, length: usize) Failure!void {
    try known(algorithm, mac_count);

    const slot = try common.place(.configured_mac, algorithm, memory, length, size(.configured_mac, algorithm));

    const a = try common.input(first, first_length);

    const b = try common.input(second, second_length);

    try common.apart(&.{slot.bytes}, &.{ a, b });

    switch (algorithm) {
        inline 0...mac_count - 1 => |id| try Mac(id).configure(slot.body(Mac(id).Spec), out_size, flags, a, b),
        else => unreachable,
    }

    slot.seal(0);
}

// The MAC that a configured slot holds, into `mac`; the caller closes the slot.
fn configuredMac(slot: Slot, mac: *hash.MacAlgorithm) Failure!void {
    const fine = switch (slot.algorithm) {
        inline 0...mac_count - 1 => |a| @call(.never_inline, Mac(a).fromSpec, .{ slot.body(Mac(a).Spec), mac }),
        else => unreachable,
    };

    if (!fine) return error.BadSlot;
}

pub fn macWith(spec: ?[*]u8, spec_length: usize, key: ?[*]const u8, key_length: usize, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(macWithChecked(spec, spec_length, key, key_length, data, data_length, out, out_length));
}

fn macWithChecked(spec: ?[*]u8, spec_length: usize, key: ?[*]const u8, key_length: usize, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    const k = try common.input(key, key_length);

    const bytes = try common.input(data, data_length);

    const slot = try configuredSlot(.configured_mac, spec, spec_length);

    defer slot.close();

    var mac: hash.MacAlgorithm = undefined;

    try configuredMac(slot, &mac);

    const target = try common.exact(out, out_length, mac.digest_size);

    try common.apart(&.{target}, &.{ k, bytes, slot.bytes });

    try macDigest(&mac, k, bytes, target);

    try slot.confirm(&.{target});
}

pub fn macVerifyWith(spec: ?[*]u8, spec_length: usize, key: ?[*]const u8, key_length: usize, data: ?[*]const u8, data_length: usize, tag: ?[*]const u8, tag_length: usize) callconv(.c) c_int {
    return common.status(macVerifyWithChecked(spec, spec_length, key, key_length, data, data_length, tag, tag_length));
}

fn macVerifyWithChecked(spec: ?[*]u8, spec_length: usize, key: ?[*]const u8, key_length: usize, data: ?[*]const u8, data_length: usize, tag: ?[*]const u8, tag_length: usize) Failure!void {
    const k = try common.input(key, key_length);

    const bytes = try common.input(data, data_length);

    const expected = try common.input(tag, tag_length);

    const slot = try configuredSlot(.configured_mac, spec, spec_length);

    defer slot.close();

    var mac: hash.MacAlgorithm = undefined;

    try configuredMac(slot, &mac);

    const result = macVerify(&mac, k, bytes, expected);

    try slot.confirm(&.{});

    return result;
}

pub fn hmacInit(algorithm: u32, key: ?[*]const u8, key_length: usize, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(hmacInitChecked(algorithm, key, key_length, memory, length));
}

fn hmacInitChecked(algorithm: u32, key: ?[*]const u8, key_length: usize, memory: ?[*]u8, length: usize) Failure!void {
    try known(algorithm, mac_count);

    const slot = try common.place(.hmac, algorithm, memory, length, size(.hmac, algorithm));

    const k = try common.input(key, key_length);

    try common.apart(&.{slot.bytes}, &.{k});

    try macInit(slot, &macs[algorithm], k);

    slot.seal(0);
}

// The state of `mac`, whose id is the slot's, built in place under one keyed DIT guard.
fn macInit(slot: Slot, mac: *const hash.MacAlgorithm, key: []const u8) Failure!void {
    try checkKey(mac, key);

    const dit = cpu.Dit.enterKeyed();

    defer dit.leave();

    switch (slot.algorithm) {
        inline 0...mac_count - 1 => |a| @call(.never_inline, Mac(a).init, .{ slot.body(Mac(a).State), mac, key }),
        else => unreachable,
    }
}

// The state of a configured MAC.
pub fn macInitWith(spec: ?[*]u8, spec_length: usize, key: ?[*]const u8, key_length: usize, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(macInitWithChecked(spec, spec_length, key, key_length, memory, length));
}

fn macInitWithChecked(spec: ?[*]u8, spec_length: usize, key: ?[*]const u8, key_length: usize, memory: ?[*]u8, length: usize) Failure!void {
    const configured = try configuredSlot(.configured_mac, spec, spec_length);

    defer configured.close();

    var mac: hash.MacAlgorithm = undefined;

    try configuredMac(configured, &mac);

    const slot = try common.place(.hmac, configured.algorithm, memory, length, size(.hmac, configured.algorithm));

    const k = try common.input(key, key_length);

    try common.apart(&.{slot.bytes}, &.{ k, configured.bytes });

    try macInit(slot, &mac, k);

    // A state made from a configured slot that the binding changed meanwhile is not handed out.
    configured.confirm(&.{}) catch |err| {
        slot.discard();

        return err;
    };

    slot.seal(0);
}

pub fn hmacUpdate(memory: ?[*]u8, length: usize, data: ?[*]const u8, data_length: usize) callconv(.c) c_int {
    return common.status(hmacUpdateChecked(memory, length, data, data_length));
}

fn hmacUpdateChecked(memory: ?[*]u8, length: usize, data: ?[*]const u8, data_length: usize) Failure!void {
    const bytes = try common.input(data, data_length);

    const slot = try hold(.hmac, memory, length, bytes, &.{});

    defer slot.close();

    const dit = cpu.Dit.enterKeyed();

    defer dit.leave();

    switch (slot.algorithm) {
        inline 0...mac_count - 1 => |a| Mac(a).update(slot.body(Mac(a).State), bytes),
        else => unreachable,
    }

    try slot.confirm(&.{});
}

// The tag of everything given so far, which has the state's length; the state may go on.
pub fn hmacFinal(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(hmacFinalChecked(memory, length, out, out_length));
}

fn hmacFinalChecked(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    const target = try common.output(out, out_length);

    const slot = try hold(.hmac, memory, length, &.{}, target);

    defer slot.close();

    const dit = cpu.Dit.enterKeyed();

    defer dit.leave();

    switch (slot.algorithm) {
        inline 0...mac_count - 1 => |a| {
            const M = Mac(a);

            const state = slot.body(M.State);

            if (target.len != M.size(state)) return error.BadArgument;

            M.tag(state, target);
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

    const dit = cpu.Dit.enterKeyed();

    defer dit.leave();

    const matches = switch (slot.algorithm) {
        inline 0...mac_count - 1 => |a| matches: {
            const M = Mac(a);

            const state = slot.body(M.State);

            if (expected.len != M.size(state)) break :matches false;

            break :matches M.verify(state, expected);
        },
        else => unreachable,
    };

    try slot.confirm(&.{});

    if (!ct.declassifyValue(bool, matches)) return error.Rejected;
}

// HKDF: Extract then Expand into out, whose length is L (1 to 255 hash lengths, else
// INVALID_LENGTH).
pub fn kdfDerive(algorithm: u32, ikm: ?[*]const u8, ikm_length: usize, salt: ?[*]const u8, salt_length: usize, info: ?[*]const u8, info_length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(kdfDeriveChecked(algorithm, ikm, ikm_length, salt, salt_length, info, info_length, out, out_length));
}

fn kdfDeriveChecked(algorithm: u32, ikm: ?[*]const u8, ikm_length: usize, salt: ?[*]const u8, salt_length: usize, info: ?[*]const u8, info_length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    try known(algorithm, kdf_count);

    const secret = try common.input(ikm, ikm_length);

    const s = try common.input(salt, salt_length);

    const i = try common.input(info, info_length);

    const target = try common.output(out, out_length);

    try common.apart(&.{target}, &.{ secret, s, i });

    const dit = cpu.Dit.enterKeyed();

    defer dit.leave();

    try kdfs[algorithm].derive(secret, target, .{ .salt = s, .info = i });
}

// The PRK, of exactly the hash length.
pub fn kdfExtract(algorithm: u32, ikm: ?[*]const u8, ikm_length: usize, salt: ?[*]const u8, salt_length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(kdfExtractChecked(algorithm, ikm, ikm_length, salt, salt_length, out, out_length));
}

fn kdfExtractChecked(algorithm: u32, ikm: ?[*]const u8, ikm_length: usize, salt: ?[*]const u8, salt_length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    try known(algorithm, kdf_count);

    const secret = try common.input(ikm, ikm_length);

    const s = try common.input(salt, salt_length);

    const target = try common.exact(out, out_length, kdfs[algorithm].hashSize());

    try common.apart(&.{target}, &.{ secret, s });

    const dit = cpu.Dit.enterKeyed();

    defer dit.leave();

    try kdfs[algorithm].extract(secret, target, .{ .salt = s });
}

// Expand from a PRK of at least the hash length (else INVALID_LENGTH) into out, of length L.
pub fn kdfExpand(algorithm: u32, prk: ?[*]const u8, prk_length: usize, info: ?[*]const u8, info_length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(kdfExpandChecked(algorithm, prk, prk_length, info, info_length, out, out_length));
}

fn kdfExpandChecked(algorithm: u32, prk: ?[*]const u8, prk_length: usize, info: ?[*]const u8, info_length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    try known(algorithm, kdf_count);

    const key = try common.input(prk, prk_length);

    const i = try common.input(info, info_length);

    const target = try common.output(out, out_length);

    try common.apart(&.{target}, &.{ key, i });

    const dit = cpu.Dit.enterKeyed();

    defer dit.leave();

    try kdfs[algorithm].expand(key, target, .{ .info = i });
}

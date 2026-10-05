const std = @import("std");

const options = @import("capi_options");

const common = @import("common.zig");

const cpu = @import("../cpu.zig");
const ct = @import("../ct.zig");
const lms = @import("../lms.zig");
const merkle = @import("../merkle.zig");
const stateful = @import("../stateful.zig");
const xmss = @import("../xmss.zig");

const Allocator = std.mem.Allocator;

const Failure = common.Failure;

const Slot = common.Slot;

const Kind = stateful.StatefulSignatureAlgorithm.Kind;

// The stateful keys sign in two phases. The host keeps the state machine of every crypto-pq: it
// writes the state that claims an index to its store, compare-and-swap, and only then asks the
// signer for the signature at that index. The signer holds the Merkle trees and refuses any index
// below the next one it may use, so that a mistaken host cannot make it use a one-time key twice.
// The signer is internal to the bindings and never public.
//
// Kinds are the state blob's: 1 HSS/LMS, 2 XMSS, 3 XMSS^MT. Parameters are given as the state
// blob encodes them after its kind byte: HSS L || {u32 LMS type, u32 LM-OTS type} x L, top level
// first; XMSS and XMSS^MT the OID as a u32; all big-endian.

fn kindOf(value: u32) Failure!Kind {
    if (!options.stateful) return error.Unsupported;

    return switch (value) {
        1 => .hss_lms,
        2 => .xmss,
        3 => .xmss_mt,
        else => error.BadArgument,
    };
}

fn setupOf(kind: Kind, section: []const u8) Failure!stateful.Setup {
    if (kind == .hss_lms) {
        if (section.len < 1) return error.InvalidOption;

        const count = section[0];

        if (count < 1 or count > 8 or section.len != 1 + 8 * @as(usize, count)) return error.InvalidOption;

        var setup: stateful.Setup = .{ .hss = .{ .levels = undefined, .count = count } };

        for (setup.hss.levels[0..count], 0..) |*level, i| {
            level.* = .{
                .lms = lms.lmsByCode(std.mem.readInt(u32, section[1 + 8 * i ..][0..4], .big)) orelse return error.InvalidOption,
                .ots = lms.otsByCode(std.mem.readInt(u32, section[5 + 8 * i ..][0..4], .big)) orelse return error.InvalidOption,
            };
        }

        if (!lms.validLevels(setup.hss.levels[0..count])) return error.InvalidOption;

        return setup;
    }

    if (section.len != 4) return error.InvalidOption;

    const sets: []const xmss.Parameters = if (kind == .xmss_mt) &xmss.xmss_mt_sets else &xmss.xmss_sets;

    return .{ .xmss = xmss.byOid(sets, std.mem.readInt(u32, section[0..4], .big)) orelse return error.InvalidOption };
}

fn lmsSignatureSize(level: lms.Level) usize {
    return 8 + level.ots.signatureSize() + @as(usize, level.lms.h) * level.lms.m;
}

fn signatureSize(setup: stateful.Setup) usize {
    return switch (setup) {
        .hss => |hss| size: {
            var total: usize = 4 + lmsSignatureSize(hss.levels[hss.count - 1]);

            for (0..hss.count - 1) |i| total += lmsSignatureSize(hss.levels[i]) + hss.levels[i + 1].lms.publicKeySize();

            break :size total;
        },
        .xmss => |p| p.signatureSize(),
    };
}

fn publicKeySize(setup: stateful.Setup) usize {
    return switch (setup) {
        .hss => |hss| 28 + @as(usize, hss.levels[0].lms.m),
        .xmss => |p| p.publicKeySize(),
    };
}

fn stateSize(setup: stateful.Setup) usize {
    return switch (setup) {
        .hss => |hss| 3 + 8 * hss.count + 16 + hss.levels[0].lms.m + 8 + 16,
        .xmss => |p| 6 + 8 + 3 * p.n + 16,
    };
}

// The nodes a Merkle tree keeps: every level from max(0, height - 15) up, and the subtree under
// the last signed leaf.
fn treeBytes(height: u6, n: usize) usize {
    const low = height -| merkle.cached_height;

    var bytes = ((@as(usize, 2) << @intCast(height - low)) - 1) * n;

    if (low > 0) bytes += ((@as(usize, 2) << @intCast(low)) - 1) * n;

    return bytes;
}

// What the signer allocates: its trees, the signatures it keeps of the levels above, and itself.
fn memoryOf(setup: stateful.Setup) usize {
    var total: usize = @sizeOf(Object);

    switch (setup) {
        .hss => |hss| {
            total += @sizeOf(lms.Hss);

            for (hss.levels[0..hss.count]) |level| total += treeBytes(level.lms.h, level.lms.m);

            for (0..hss.count - 1) |i| total += lmsSignatureSize(hss.levels[i]) + hss.levels[i + 1].lms.publicKeySize();
        },
        .xmss => |p| {
            const height = p.h / p.d;

            total += @sizeOf(xmss.Xmss) + (@as(usize, p.d) - 1) * (2 * p.n + 3 + height) * p.n + @as(usize, p.d) * treeBytes(height, p.n);
        },
    }

    return total;
}

// The signer, in memory of the library. `next` is the lowest index it may still sign with.
pub const Object = struct {
    magic: u64,
    owner: usize,
    busy: common.Busy,
    kind: Kind,
    signer: stateful.Signer,
    state: stateful.State,
    next: u64,
    capacity: u64,
    memory: usize,
};

const object_magic: u64 = 0x7265_6e67_6973_7063;

// The slot holds the signer's address, and its own: a copy of the slot elsewhere is refused
// before the signer is touched.
const SignerSlot = struct {
    object: usize,
    owner: usize,
};

pub fn size(slot_type: common.SlotType, algorithm: u32) usize {
    if (!options.stateful or slot_type != .signer or algorithm < 1 or algorithm > 3) return 0;

    return common.slotSize(SignerSlot);
}

// Counts what the signer's build allocates.
const Counting = struct {
    child: Allocator,
    bytes: usize = 0,

    fn allocator(self: *Counting) Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = release } };
    }

    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(context));

        const memory = self.child.rawAlloc(len, alignment, ret) orelse return null;

        self.bytes += len;

        return memory;
    }

    fn resize(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) bool {
        const self: *Counting = @ptrCast(@alignCast(context));

        if (!self.child.rawResize(memory, alignment, new_len, ret)) return false;

        self.bytes = self.bytes - memory.len + new_len;

        return true;
    }

    fn remap(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(context));

        const moved = self.child.rawRemap(memory, alignment, new_len, ret) orelse return null;

        self.bytes = self.bytes - memory.len + new_len;

        return moved;
    }

    fn release(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret: usize) void {
        const self: *Counting = @ptrCast(@alignCast(context));

        self.child.rawFree(memory, alignment, ret);

        self.bytes -= memory.len;
    }
};

// out[0] the seed size, out[1] the state size, out[2] the public key size, out[3] the signature
// size, out[4] the capacity, out[5] the bytes the signer allocates.
pub fn info(kind: u32, parameters: ?[*]const u8, parameters_length: usize, out: ?*[6]u64) callconv(.c) c_int {
    return common.status(infoChecked(kind, parameters, parameters_length, out));
}

fn infoChecked(kind: u32, parameters: ?[*]const u8, parameters_length: usize, out: ?*[6]u64) Failure!void {
    const k = try kindOf(kind);

    const section = try common.input(parameters, parameters_length);

    const target = out orelse return error.BadArgument;

    try common.apart(&.{std.mem.asBytes(target)}, &.{section});

    const setup = try setupOf(k, section);

    target.* = .{ setup.seedSize(), stateSize(setup), publicKeySize(setup), signatureSize(setup), setup.capacity(), memoryOf(setup) };
}

fn place(kind: u32, memory: ?[*]u8, length: usize) Failure!Slot {
    return common.place(.signer, kind, memory, length, size(.signer, kind));
}

// Builds the signer of a key from its parameters and seed, at `index`, and writes the state blob
// that the host stores before any signature, sealed like every crypto-pq state.
pub fn create(kind: u32, parameters: ?[*]const u8, parameters_length: usize, seed: ?[*]const u8, seed_length: usize, index: u64, state: ?[*]u8, state_length: usize, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(createChecked(kind, parameters, parameters_length, seed, seed_length, index, state, state_length, memory, length));
}

fn createChecked(kind: u32, parameters: ?[*]const u8, parameters_length: usize, seed: ?[*]const u8, seed_length: usize, index: u64, state: ?[*]u8, state_length: usize, memory: ?[*]u8, length: usize) Failure!void {
    const k = try kindOf(kind);

    const slot = try place(kind, memory, length);

    const section = try common.input(parameters, parameters_length);

    const seed_bytes = try common.input(seed, seed_length);

    const setup = try setupOf(k, section);

    const out = try common.exact(state, state_length, stateSize(setup));

    try common.apart(&.{ slot.bytes, out }, &.{ section, seed_bytes });

    if (seed_bytes.len != setup.seedSize()) return error.InvalidLength;

    if (index > setup.capacity()) return error.InvalidOption;

    const dit = cpu.Dit.enter();

    defer dit.leave();

    const object = common.allocator.create(Object) catch return error.OutOfMemory;

    errdefer destroy(object);

    object.state = undefined;

    stateful.encode(k, setup, seed_bytes, index, &object.state);

    var counting: Counting = .{ .child = common.allocator };

    object.signer = stateful.Signer.build(counting.allocator(), setup, seed_bytes, &.{}) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => |e| e,
    };

    finish(object, slot, k, index, counting.bytes);

    @memcpy(out, object.state.slice());
}

fn finish(object: *Object, slot: Slot, kind: Kind, index: u64, allocated: usize) void {
    object.magic = object_magic;

    object.owner = @intFromPtr(slot.header);

    object.busy.init();

    object.kind = kind;

    object.next = index;

    object.capacity = object.signer.capacity();

    object.memory = @sizeOf(Object) + allocated;

    slot.body(SignerSlot).* = .{ .object = @intFromPtr(object), .owner = @intFromPtr(slot.header) };

    slot.seal(0);
}

fn destroy(object: *Object) void {
    ct.wipe(std.mem.asBytes(object));

    common.allocator.destroy(object);
}

// Load flag: a tree cache is given, which may be empty (and then refused, as everywhere).
pub const with_tree_cache: u32 = 1;

// Builds the signer of a stored state, checked as loading checks it, and writes its index to
// `index`. A tree cache from cpq_stateful_signer_export_tree_cache, given with the flag
// with_tree_cache, replaces the build of the trees that index signs with if it passes every check.
pub fn load(kind: u32, state: ?[*]const u8, state_length: usize, cache: ?[*]const u8, cache_length: usize, flags: u32, memory: ?[*]u8, length: usize, index: ?*u64) callconv(.c) c_int {
    return common.status(loadChecked(kind, state, state_length, cache, cache_length, flags, memory, length, index));
}

fn loadChecked(kind: u32, state: ?[*]const u8, state_length: usize, cache: ?[*]const u8, cache_length: usize, flags: u32, memory: ?[*]u8, length: usize, index: ?*u64) Failure!void {
    const k = try kindOf(kind);

    const slot = try place(kind, memory, length);

    const stored = try common.input(state, state_length);

    const cache_bytes = try common.input(cache, cache_length);

    const index_out = index orelse return error.BadArgument;

    if (flags & ~with_tree_cache != 0 or (flags == 0 and cache_bytes.len != 0)) return error.BadArgument;

    try common.apart(&.{ slot.bytes, std.mem.asBytes(index_out) }, &.{ stored, cache_bytes });

    // Private copies, so that what is checked is what is used whatever the caller's memory does.
    var blob: stateful.State = .{ .bytes = undefined, .size = stored.len };

    defer ct.wipe(&blob.bytes);

    if (stored.len > blob.bytes.len) return error.InvalidPrivateKey;

    @memcpy(blob.slice(), stored);

    const copy = if (flags == with_tree_cache) common.allocator.dupe(u8, cache_bytes) catch return error.OutOfMemory else null;

    defer if (copy) |bytes| common.allocator.free(bytes);

    const object = common.allocator.create(Object) catch return error.OutOfMemory;

    errdefer destroy(object);

    var counting: Counting = .{ .child = common.allocator };

    var opened = stateful.open(k, counting.allocator(), blob.slice(), copy) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => |e| e,
    };

    defer ct.wipe(&opened.state.bytes);

    object.signer = opened.signer;

    object.state = opened.state;

    finish(object, slot, k, opened.index, counting.bytes);

    index_out.* = opened.index;
}

const Held = struct {
    slot: Slot,
    object: *Object,
};

// A live signer slot at its own address, and its signer, held for this call: a call made while
// another one holds it fails with STATE_CONFLICT at once, as concurrent signing does everywhere.
fn hold(memory: ?[*]u8, length: usize) Failure!Held {
    const slot = try common.open(&.{.signer}, memory, length, size);

    const body: *const volatile SignerSlot = slot.body(SignerSlot);

    const address = body.object;

    if (body.owner != @intFromPtr(slot.header) or address == 0) return error.BadSlot;

    const object: *Object = @ptrFromInt(address);

    if (object.magic != object_magic or object.owner != @intFromPtr(slot.header)) return error.BadSlot;

    object.busy.acquire() catch return error.StateConflict;

    return .{ .slot = slot, .object = object };
}

fn unhold(held: Held) void {
    held.object.busy.release();
}

// Signs at `index`, which the host has already claimed in its store. An index below the next one
// the signer may use is STATE_CONFLICT, one at or past the capacity KEY_EXHAUSTED.
pub fn sign(memory: ?[*]u8, length: usize, index: u64, message: ?[*]const u8, message_length: usize, signature: ?[*]u8, signature_length: usize) callconv(.c) c_int {
    return common.status(signChecked(memory, length, index, message, message_length, signature, signature_length));
}

fn signChecked(memory: ?[*]u8, length: usize, index: u64, message: ?[*]const u8, message_length: usize, signature: ?[*]u8, signature_length: usize) Failure!void {
    const m = try common.input(message, message_length);

    const out = try common.output(signature, signature_length);

    const held = try hold(memory, length);

    defer unhold(held);

    const object = held.object;

    try common.apart(&.{out}, &.{ m, held.slot.bytes, std.mem.asBytes(object) });

    if (index < object.next) return error.StateConflict;

    if (index >= object.capacity) return error.KeyExhausted;

    if (out.len != object.signer.signatureSize()) return error.BadArgument;

    object.next = index + 1;

    object.signer.sign(index, m, out);
}

pub fn publicKey(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(publicKeyChecked(memory, length, out, out_length));
}

fn publicKeyChecked(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    const target = try common.output(out, out_length);

    const held = try hold(memory, length);

    defer unhold(held);

    var key: [stateful.max_public_key_size]u8 = undefined;

    const raw = held.object.signer.publicKey(&key);

    if (target.len != raw.len) return error.BadArgument;

    try common.apart(&.{target}, &.{ held.slot.bytes, std.mem.asBytes(held.object) });

    @memcpy(target, raw);
}

// out[0] the capacity, out[1] the next index the signer may use, out[2] the signature size,
// out[3] the bytes the signer holds.
pub fn signerInfo(memory: ?[*]u8, length: usize, out: ?*[4]u64) callconv(.c) c_int {
    return common.status(signerInfoChecked(memory, length, out));
}

fn signerInfoChecked(memory: ?[*]u8, length: usize, out: ?*[4]u64) Failure!void {
    const target = out orelse return error.BadArgument;

    const held = try hold(memory, length);

    defer unhold(held);

    try common.apart(&.{std.mem.asBytes(target)}, &.{held.slot.bytes});

    const object = held.object;

    target.* = .{ object.capacity, object.next, object.signer.signatureSize(), object.memory };
}

pub fn treeCacheSize(memory: ?[*]u8, length: usize, out: ?*u64) callconv(.c) c_int {
    return common.status(treeCacheSizeChecked(memory, length, out));
}

fn treeCacheSizeChecked(memory: ?[*]u8, length: usize, out: ?*u64) Failure!void {
    const target = out orelse return error.BadArgument;

    const held = try hold(memory, length);

    defer unhold(held);

    try common.apart(&.{std.mem.asBytes(target)}, &.{held.slot.bytes});

    const object = held.object;

    target.* = stateful.treeCacheSize(object.kind, object.state.slice(), object.signer);
}

// The authenticated tree cache, exactly as every crypto-pq writes it; `out_length` must be the
// size cpq_stateful_signer_tree_cache_size gives, which a signature that builds a new lower tree
// may change.
pub fn exportTreeCache(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(exportTreeCacheChecked(memory, length, out, out_length));
}

fn exportTreeCacheChecked(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    const target = try common.output(out, out_length);

    const held = try hold(memory, length);

    defer unhold(held);

    try common.apart(&.{target}, &.{ held.slot.bytes, std.mem.asBytes(held.object) });

    const object = held.object;

    if (target.len != stateful.treeCacheSize(object.kind, object.state.slice(), object.signer)) return error.BadArgument;

    const dit = cpu.Dit.enter();

    defer dit.leave();

    var key: [32]u8 = undefined;

    defer ct.wipe(&key);

    // The body is written in place: the only allocation it makes is the cache itself.
    var fixed = std.heap.FixedBufferAllocator.init(target);

    const cache = stateful.treeCacheBodyOf(fixed.allocator(), object.kind, object.state.slice(), object.signer, &key) catch return error.BadArgument;

    const body = cache[0 .. cache.len - stateful.tag_size];

    stateful.treeCacheTag(&key, body, cache[body.len..][0..stateful.tag_size]);

    ct.declassify(cache);
}

// Wipes and frees the signer, then wipes the slot. A signer that another call holds is not freed.
pub fn free(memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(freeChecked(memory, length));
}

fn freeChecked(memory: ?[*]u8, length: usize) Failure!void {
    const held = try hold(memory, length);

    held.object.signer.destroy(common.allocator);

    destroy(held.object);

    ct.wipe(held.slot.bytes);
}

// Whether a slot holds a live signer at its own address, for cpq_slot_wipe.
pub fn freeIfSigner(memory: [*]u8, length: usize) bool {
    freeChecked(memory, length) catch return false;

    return true;
}

pub fn verify(kind: u32, public_key: ?[*]const u8, public_key_length: usize, message: ?[*]const u8, message_length: usize, signature: ?[*]const u8, signature_length: usize) callconv(.c) c_int {
    return common.status(verifyChecked(kind, public_key, public_key_length, message, message_length, signature, signature_length));
}

fn algorithmOf(kind: Kind) stateful.StatefulSignatureAlgorithm {
    return switch (kind) {
        .hss_lms => stateful.hss_lms,
        .xmss => stateful.xmss,
        .xmss_mt => stateful.xmss_mt,
    };
}

fn verifyChecked(kind: u32, public_key: ?[*]const u8, public_key_length: usize, message: ?[*]const u8, message_length: usize, signature: ?[*]const u8, signature_length: usize) Failure!void {
    const k = try kindOf(kind);

    const key = try common.input(public_key, public_key_length);

    const m = try common.input(message, message_length);

    const sig = try common.input(signature, signature_length);

    if (key.len > stateful.max_public_key_size) return error.Rejected;

    var parsed: stateful.StatefulPublicKey = .{ .algorithm = algorithmOf(k), .bytes = @splat(0), .size = key.len };

    @memcpy(parsed.bytes[0..key.len], key);

    if (!parsed.verify(sig, m)) return error.Rejected;
}

// INVALID_PUBLIC_KEY for a key that import refuses.
pub fn checkPublicKey(kind: u32, public_key: ?[*]const u8, public_key_length: usize) callconv(.c) c_int {
    return common.status(checkPublicKeyChecked(kind, public_key, public_key_length));
}

fn checkPublicKeyChecked(kind: u32, public_key: ?[*]const u8, public_key_length: usize) Failure!void {
    const k = try kindOf(kind);

    const key = try common.input(public_key, public_key_length);

    if (!stateful.checkPublicKey(k, key)) return error.InvalidPublicKey;
}

// Rewrites a valid state with another index, at most the capacity, and seals it again: the state
// that claims the indices below `index`.
pub fn reseal(kind: u32, state: ?[*]u8, state_length: usize, index: u64) callconv(.c) c_int {
    return common.status(resealChecked(kind, state, state_length, index));
}

fn resealChecked(kind: u32, state: ?[*]u8, state_length: usize, index: u64) Failure!void {
    const k = try kindOf(kind);

    const target = try common.output(state, state_length);

    var blob: stateful.State = .{ .bytes = undefined, .size = target.len };

    defer ct.wipe(&blob.bytes);

    if (target.len > blob.bytes.len) return error.InvalidPrivateKey;

    @memcpy(blob.slice(), target);

    const decoded = try stateful.decode(k, blob.slice());

    if (index > decoded.setup.capacity()) return error.InvalidOption;

    stateful.reseal(k, blob.slice(), index);

    @memcpy(target, blob.slice());
}

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

// The largest seed: XMSS's SK_SEED || SK_PRF || PUB_SEED with n = 32.
const max_seed_size = 96;

// The nodes a Merkle tree keeps: every level from max(0, height - 15) up, and the subtree under
// the last signed leaf.
fn treeBytes(height: u6, n: u64) u64 {
    const low = height -| merkle.cached_height;

    var bytes = ((@as(u64, 2) << @intCast(height - low)) - 1) * n;

    if (low > 0) bytes += ((@as(u64, 2) << @intCast(low)) - 1) * n;

    return bytes;
}

// What the signer allocates: its trees, the signatures it keeps of the levels above, and itself,
// in 64-bit arithmetic whatever the target (the largest parameter set needs about 18 MB).
fn memoryOf(setup: stateful.Setup) u64 {
    var total: u64 = @sizeOf(Object);

    switch (setup) {
        .hss => |hss| {
            total += @sizeOf(lms.Hss);

            for (hss.levels[0..hss.count]) |level| total += treeBytes(level.lms.h, level.lms.m);

            for (0..hss.count - 1) |i| total += lmsSignatureSize(hss.levels[i]) + hss.levels[i + 1].lms.publicKeySize();
        },
        .xmss => |p| {
            const height = p.h / p.d;

            total += @sizeOf(xmss.Xmss) + (@as(u64, p.d) - 1) * (2 * p.n + 3 + height) * p.n + @as(u64, p.d) * treeBytes(height, p.n);
        },
    }

    return total;
}

// A signer that this target's address space can hold: always so for the defined parameter sets,
// checked before anything is allocated.
fn fits(setup: stateful.Setup) Failure!void {
    if (memoryOf(setup) > std.math.maxInt(usize) / 2) return error.OutOfMemory;
}

// What the signer's build allocated, every block of it: no output of a call on the signer may
// overlap its memory, or the call would write over its trees or its index guard.
const max_ranges = 64;

const Tracking = struct {
    child: Allocator,
    ranges: [max_ranges][]u8 = undefined,
    count: usize = 0,
    bytes: usize = 0,

    fn allocator(self: *Tracking) Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = release } };
    }

    fn find(self: *const Tracking, memory: []u8) ?usize {
        for (self.ranges[0..self.count], 0..) |range, i| {
            if (range.ptr == memory.ptr) return i;
        }

        return null;
    }

    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        const self: *Tracking = @ptrCast(@alignCast(context));

        if (self.count == max_ranges) return null;

        const memory = self.child.rawAlloc(len, alignment, ret) orelse return null;

        self.ranges[self.count] = memory[0..len];

        self.count += 1;

        self.bytes += len;

        return memory;
    }

    fn resize(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) bool {
        const self: *Tracking = @ptrCast(@alignCast(context));

        if (!self.child.rawResize(memory, alignment, new_len, ret)) return false;

        if (self.find(memory)) |i| self.ranges[i] = memory.ptr[0..new_len];

        self.bytes = self.bytes - memory.len + new_len;

        return true;
    }

    fn remap(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) ?[*]u8 {
        const self: *Tracking = @ptrCast(@alignCast(context));

        const moved = self.child.rawRemap(memory, alignment, new_len, ret) orelse return null;

        if (self.find(memory)) |i| self.ranges[i] = moved[0..new_len];

        self.bytes = self.bytes - memory.len + new_len;

        return moved;
    }

    fn release(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret: usize) void {
        const self: *Tracking = @ptrCast(@alignCast(context));

        if (self.find(memory)) |i| {
            self.count -= 1;

            self.ranges[i] = self.ranges[self.count];
        }

        self.child.rawFree(memory, alignment, ret);

        self.bytes -= memory.len;
    }
};

// The signer, in memory of the library. `next` is the lowest index it may still sign with.
pub const Object = struct {
    tracking: Tracking,
    signer: stateful.Signer,
    state: stateful.State,
    kind: Kind,
    next: u64,
    capacity: u64,

    pub fn overlaps(self: *const Object, buffer: []const u8) bool {
        if (common.overlap(buffer, std.mem.asBytes(self))) return true;

        for (self.tracking.ranges[0..self.tracking.count]) |range| {
            if (common.overlap(buffer, range)) return true;
        }

        return false;
    }

    fn held(self: *const Object) u64 {
        return @sizeOf(Object) + self.tracking.bytes;
    }
};

fn newObject() Failure!*Object {
    const object = common.allocator.create(Object) catch return error.OutOfMemory;

    object.tracking = .{ .child = common.allocator };

    return object;
}

// For an object whose signer was destroyed, or never built.
fn freeObject(object: *Object) void {
    ct.wipe(std.mem.asBytes(object));

    common.allocator.destroy(object);
}

fn destroyObject(object: *Object) void {
    object.signer.destroy(object.tracking.allocator());

    freeObject(object);
}

// The signers live in library memory and are named by the cell that holds them: a slot keeps a
// cell index and the cell's generation, never an address. A cell is never freed or moved, so a slot
// that outlived its signer, a copy of a slot, or bytes forged to look like one name a cell that can
// always be read, and that tells them apart: another generation, another owner (the slot's own
// address), or no signer. `busy` is the call that holds the signer; whoever frees the signer holds
// it first, so no call ever reaches a freed one.
pub const Cell = struct {
    busy: std.atomic.Value(u32),
    generation: std.atomic.Value(u32),
    owner: std.atomic.Value(usize),
    object: std.atomic.Value(usize),
    next_free: u32,
};

// The cells come in chunks that the registry adds as signers are created, and keeps: an index
// names a chunk in the directory and a cell in it. A directory entry is written once, before any
// index that reaches it exists, so a reader needs no lock. The registry grows until memory runs
// out: a million signers natively, a quarter of a million in a WebAssembly instance.
const chunk_bits = if (common.wasm) 6 else 8;

const chunk_size = 1 << chunk_bits;

const Chunk = [chunk_size]Cell;

const max_chunks = 1 << 12;

var directory: [max_chunks]std.atomic.Value(usize) = @splat(.init(0));

// Chunks added, cells handed out at least once, and the first free cell plus one, under `lock`,
// which the registry holds for a few instructions, or while it adds a chunk.
var chunk_count: u32 = 0;

var used: u32 = 0;

var free_head: u32 = 0;

var lock: std.atomic.Value(u32) = .init(0);

fn lockRegistry() void {
    while (lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
}

fn unlockRegistry() void {
    lock.store(0, .release);
}

// The cell of an index, or null for an index that names no cell yet.
pub fn cellAt(index: u32) ?*Cell {
    const chunk = index >> chunk_bits;

    if (chunk >= max_chunks) return null;

    const address = directory[chunk].load(.acquire);

    if (address == 0) return null;

    const cells: *Chunk = @ptrFromInt(address);

    return &cells[index & (chunk_size - 1)];
}

fn takeCell() ?u32 {
    lockRegistry();

    defer unlockRegistry();

    if (free_head != 0) {
        const index = free_head - 1;

        free_head = cellAt(index).?.next_free;

        return index;
    }

    if (used == chunk_count * chunk_size) {
        if (chunk_count == max_chunks) return null;

        const cells = common.allocator.create(Chunk) catch return null;

        cells.* = @splat(.{ .busy = .init(0), .generation = .init(0), .owner = .init(0), .object = .init(0), .next_free = 0 });

        directory[chunk_count].store(@intFromPtr(cells), .release);

        chunk_count += 1;
    }

    used += 1;

    return used - 1;
}

fn giveCell(index: u32) void {
    lockRegistry();

    defer unlockRegistry();

    cellAt(index).?.next_free = free_head;

    free_head = index + 1;
}

// Whether a buffer overlaps the registry, its directory or any of its chunks: no output may.
pub fn inRegistry(buffer: []const u8) bool {
    if (common.overlap(buffer, std.mem.asBytes(&directory))) return true;

    for (0..max_chunks) |chunk| {
        const address = directory[chunk].load(.acquire);

        if (address == 0) return false;

        if (common.overlap(buffer, @as([*]const u8, @ptrFromInt(address))[0..@sizeOf(Chunk)])) return true;
    }

    return false;
}

// The slot holds the cell index of its signer and the generation it got.
const SignerSlot = struct {
    index: u32,
    generation: u32,
};

pub fn size(slot_type: common.SlotType, algorithm: u32) usize {
    if (!options.stateful or slot_type != .signer or algorithm < 1 or algorithm > 3) return 0;

    return common.slotSize(SignerSlot);
}

// out[0] the seed size, out[1] the state size, out[2] the public key size, out[3] the signature
// size, out[4] the capacity, out[5] the bytes the signer allocates.
pub fn info(kind: u32, parameters: ?[*]const u8, parameters_length: usize, out: ?*anyopaque) callconv(.c) c_int {
    return common.status(infoChecked(kind, parameters, parameters_length, out));
}

fn infoChecked(kind: u32, parameters: ?[*]const u8, parameters_length: usize, out: ?*anyopaque) Failure!void {
    const k = try kindOf(kind);

    const section = try common.input(parameters, parameters_length);

    const target = try common.fixed([6]u64, out);

    try common.apart(&.{std.mem.asBytes(target)}, &.{section});

    const setup = try setupOf(k, section);

    target.* = .{ setup.seedSize(), stateSize(setup), publicKeySize(setup), signatureSize(setup), setup.capacity(), memoryOf(setup) };
}

fn place(kind: u32, memory: ?[*]u8, length: usize) Failure!Slot {
    return common.place(.signer, kind, memory, length, size(.signer, kind));
}

// Hands the built signer to a cell and the cell to the slot, which is sealed last.
fn register(object: *Object, slot: Slot, kind: Kind, index: u64) Failure!void {
    const cell_index = takeCell() orelse return error.OutOfMemory;

    const cell = cellAt(cell_index).?;

    object.kind = kind;

    object.next = index;

    object.capacity = object.signer.capacity();

    cell.owner.store(@intFromPtr(slot.header), .release);

    cell.object.store(@intFromPtr(object), .release);

    slot.body(SignerSlot).* = .{ .index = cell_index, .generation = cell.generation.load(.acquire) };

    slot.seal(0);
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

    const seed_input = try common.input(seed, seed_length);

    const setup = try setupOf(k, section);

    const out = try common.exact(state, state_length, stateSize(setup));

    try common.apart(&.{ slot.bytes, out }, &.{ section, seed_input });

    if (seed_input.len != setup.seedSize()) return error.InvalidLength;

    if (index > setup.capacity()) return error.InvalidOption;

    try fits(setup);

    const dit = cpu.Dit.enter();

    defer dit.leave();

    // The caller's seed is read once: the state blob and the trees come from the same copy.
    var seed_copy: [max_seed_size]u8 = undefined;

    defer ct.wipe(&seed_copy);

    const seed_bytes = seed_copy[0..seed_input.len];

    @memcpy(seed_bytes, seed_input);

    const object = try newObject();

    errdefer freeObject(object);

    stateful.encode(k, setup, seed_bytes, index, &object.state);

    object.signer = stateful.Signer.build(object.tracking.allocator(), setup, seed_bytes, &.{}) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => |e| e,
    };

    errdefer object.signer.destroy(object.tracking.allocator());

    // Memory that the build reused may be where the caller pointed.
    if (object.overlaps(out) or object.overlaps(slot.bytes)) return error.BadArgument;

    try register(object, slot, k, index);

    @memcpy(out, object.state.slice());
}

// Load flag: a tree cache is given, which may be empty (and then refused, as everywhere).
pub const with_tree_cache: u32 = 1;

// Builds the signer of a stored state, checked as loading checks it, and writes its index to
// `index`. A tree cache from cpq_stateful_signer_export_tree_cache, given with the flag
// with_tree_cache, replaces the build of the trees that index signs with if it passes every check.
pub fn load(kind: u32, state: ?[*]const u8, state_length: usize, cache: ?[*]const u8, cache_length: usize, flags: u32, memory: ?[*]u8, length: usize, index: ?*anyopaque) callconv(.c) c_int {
    return common.status(loadChecked(kind, state, state_length, cache, cache_length, flags, memory, length, index));
}

fn loadChecked(kind: u32, state: ?[*]const u8, state_length: usize, cache: ?[*]const u8, cache_length: usize, flags: u32, memory: ?[*]u8, length: usize, index: ?*anyopaque) Failure!void {
    const k = try kindOf(kind);

    const slot = try place(kind, memory, length);

    const stored = try common.input(state, state_length);

    const cache_bytes = try common.input(cache, cache_length);

    const index_out = try common.fixed(u64, index);

    if (flags & ~with_tree_cache != 0 or (flags == 0 and cache_bytes.len != 0)) return error.BadArgument;

    try common.apart(&.{ slot.bytes, std.mem.asBytes(index_out) }, &.{ stored, cache_bytes });

    const dit = cpu.Dit.enter();

    defer dit.leave();

    // Private copies, so that what is checked is what is used whatever the caller's memory does.
    var blob: stateful.State = .{ .bytes = undefined, .size = stored.len };

    defer ct.wipe(&blob.bytes);

    if (stored.len > blob.bytes.len) return error.InvalidPrivateKey;

    @memcpy(blob.slice(), stored);

    try fits((try stateful.decode(k, blob.slice())).setup);

    const copy = if (flags == with_tree_cache) common.allocator.dupe(u8, cache_bytes) catch return error.OutOfMemory else null;

    defer if (copy) |bytes| common.allocator.free(bytes);

    const object = try newObject();

    errdefer freeObject(object);

    var opened = stateful.open(k, object.tracking.allocator(), blob.slice(), copy) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => |e| e,
    };

    defer ct.wipe(&opened.state.bytes);

    object.signer = opened.signer;

    object.state = opened.state;

    errdefer object.signer.destroy(object.tracking.allocator());

    if (object.overlaps(std.mem.asBytes(index_out)) or object.overlaps(slot.bytes)) return error.BadArgument;

    try register(object, slot, k, opened.index);

    index_out.* = opened.index;
}

pub const Held = struct {
    slot: Slot,
    index: u32,
    cell: *Cell,
    object: *Object,
};

fn names(cell: *const Cell, generation: u32, slot: Slot) bool {
    return cell.generation.load(.acquire) == generation and cell.owner.load(.acquire) == @intFromPtr(slot.header) and cell.object.load(.acquire) != 0;
}

// A live signer slot at its own address, and its signer, held for this call: a call made while
// another one holds it fails with STATE_CONFLICT at once, as concurrent signing does everywhere.
// The cell is checked before it is taken, so that a stale slot cannot hold up the live signer,
// and again once held, when it can no longer change.
fn hold(memory: ?[*]u8, length: usize) Failure!Held {
    const slot = try common.peek(.signer, memory, length, size);

    const body = slot.body(SignerSlot);

    const index = common.once(u32, &body.index);

    const generation = common.once(u32, &body.generation);

    const cell = cellAt(index) orelse return error.BadSlot;

    if (!names(cell, generation, slot)) return error.BadSlot;

    if (cell.busy.cmpxchgStrong(0, 1, .acquire, .monotonic) != null) return error.StateConflict;

    errdefer cell.busy.store(0, .release);

    if (!names(cell, generation, slot) or common.loadMagic(slot.header) != common.magic(.signer)) return error.BadSlot;

    if (common.once(u32, &body.index) != index or common.once(u32, &body.generation) != generation) return error.BadSlot;

    return .{ .slot = slot, .index = index, .cell = cell, .object = @ptrFromInt(cell.object.load(.acquire)) };
}

fn unhold(held: Held) void {
    held.cell.busy.store(0, .release);
}

// Wipes and frees the held signer and ends its slot. The generation changes before the cell is
// let go, so that the slot, any copy of it and any slot that named this signer are refused.
pub fn retire(held: Held) void {
    const cell = held.cell;

    cell.object.store(0, .release);

    cell.owner.store(0, .release);

    _ = cell.generation.fetchAdd(1, .release);

    destroyObject(held.object);

    common.kill(.{ .header = held.slot.header, .slot_type = .signer, .size = held.slot.bytes.len }, held.slot.bytes);

    unhold(held);

    giveCell(held.index);
}

// For a wipe that found a signer slot header: the signer held for retiring, null for memory that
// holds no live signer at this address (a copy, a stale slot), STATE_CONFLICT while held.
pub fn claimAt(memory: []u8) Failure!?Held {
    return hold(memory.ptr, memory.len) catch |err| switch (err) {
        error.StateConflict => error.StateConflict,
        else => null,
    };
}

// A live signer slot at its own address, for cpq_slot_info: checked through its cell, not held.
pub fn inspect(memory: ?[*]u8, length: usize) Failure!Slot {
    const slot = try common.peek(.signer, memory, length, size);

    const body = slot.body(SignerSlot);

    const cell = cellAt(common.once(u32, &body.index)) orelse return error.BadSlot;

    if (!names(cell, common.once(u32, &body.generation), slot)) return error.BadSlot;

    return slot;
}

// Signs at `index`, which the host has already claimed in its store. An index below the next one
// the signer may use is STATE_CONFLICT, one at or past the capacity KEY_EXHAUSTED.
pub fn sign(memory: ?[*]u8, length: usize, index: u64, message: ?[*]const u8, message_length: usize, signature: ?[*]u8, signature_length: usize) callconv(.c) c_int {
    return common.status(signChecked(memory, length, index, message, message_length, signature, signature_length));
}

// An output of a call on the held signer: apart from the call's slot and inputs, the signer's
// memory and the registry.
fn written(held: Held, out: []const u8, read: []const []const u8) Failure!void {
    try common.apart(&.{out}, read);

    if (common.overlap(out, held.slot.bytes) or inRegistry(out) or held.object.overlaps(out)) return error.BadArgument;
}

fn signChecked(memory: ?[*]u8, length: usize, index: u64, message: ?[*]const u8, message_length: usize, signature: ?[*]u8, signature_length: usize) Failure!void {
    const m = try common.input(message, message_length);

    const out = try common.output(signature, signature_length);

    const held = try hold(memory, length);

    defer unhold(held);

    const object = held.object;

    try written(held, out, &.{m});

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

    try written(held, target, &.{});

    @memcpy(target, raw);
}

// out[0] the capacity, out[1] the next index the signer may use, out[2] the signature size,
// out[3] the bytes the signer holds.
pub fn signerInfo(memory: ?[*]u8, length: usize, out: ?*anyopaque) callconv(.c) c_int {
    return common.status(signerInfoChecked(memory, length, out));
}

fn signerInfoChecked(memory: ?[*]u8, length: usize, out: ?*anyopaque) Failure!void {
    const target = try common.fixed([4]u64, out);

    const held = try hold(memory, length);

    defer unhold(held);

    try written(held, std.mem.asBytes(target), &.{});

    const object = held.object;

    target.* = .{ object.capacity, object.next, object.signer.signatureSize(), object.held() };
}

pub fn treeCacheSize(memory: ?[*]u8, length: usize, out: ?*anyopaque) callconv(.c) c_int {
    return common.status(treeCacheSizeChecked(memory, length, out));
}

fn treeCacheSizeChecked(memory: ?[*]u8, length: usize, out: ?*anyopaque) Failure!void {
    const target = try common.fixed(u64, out);

    const held = try hold(memory, length);

    defer unhold(held);

    try written(held, std.mem.asBytes(target), &.{});

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

    try written(held, target, &.{});

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

// Wipes and frees the signer, then wipes the slot. A signer that another call holds is not freed:
// STATE_CONFLICT.
pub fn free(memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(freeChecked(memory, length));
}

fn freeChecked(memory: ?[*]u8, length: usize) Failure!void {
    retire(try hold(memory, length));
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

// Rewrites a valid state with a later index, at most the capacity, and seals it again: the state
// that claims the indices below `index`. An earlier index would give indices that were claimed,
// and perhaps signed with, back to the next load: STATE_CONFLICT.
pub fn reseal(kind: u32, state: ?[*]u8, state_length: usize, index: u64) callconv(.c) c_int {
    return common.status(resealChecked(kind, state, state_length, index));
}

fn resealChecked(kind: u32, state: ?[*]u8, state_length: usize, index: u64) Failure!void {
    const k = try kindOf(kind);

    const target = try common.output(state, state_length);

    const dit = cpu.Dit.enter();

    defer dit.leave();

    var blob: stateful.State = .{ .bytes = undefined, .size = target.len };

    defer ct.wipe(&blob.bytes);

    if (target.len > blob.bytes.len) return error.InvalidPrivateKey;

    @memcpy(blob.slice(), target);

    const decoded = try stateful.decode(k, blob.slice());

    if (index > decoded.setup.capacity()) return error.InvalidOption;

    if (index < decoded.index) return error.StateConflict;

    stateful.reseal(k, blob.slice(), index);

    @memcpy(target, blob.slice());
}

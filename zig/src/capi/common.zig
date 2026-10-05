const std = @import("std");
const builtin = @import("builtin");

const ct = @import("../ct.zig");
const Error = @import("../errors.zig").Error;

pub const wasm = builtin.cpu.arch.isWasm();

// What the native library allocates (the stateful signers, and the rare second copy of an ML-DSA
// cache that another thread is filling) comes from the page allocator: it is thread-safe, needs no
// thread-local storage and no libc. A WebAssembly instance allocates in its linear memory.
pub const allocator = if (wasm) std.heap.wasm_allocator else std.heap.page_allocator;

// Status codes. 1 to 13 are crypto-pq's error codes, in the order of errors.zig. The others belong
// to the ABI: `rejected` answers a well-formed question with no (a signature or a tag that does not
// verify), and the rest report a mistake of the binding, never of its user.
pub const ok: c_int = 0;

pub const rejected: c_int = 100;

pub const bad_argument: c_int = 101;

pub const bad_slot: c_int = 102;

pub const out_of_memory: c_int = 103;

pub const busy: c_int = 104;

pub const Failure = Error || error{ Rejected, BadArgument, BadSlot, OutOfMemory, Busy };

pub fn status(result: Failure!void) c_int {
    result catch |err| return code(err);

    return ok;
}

pub fn code(err: Failure) c_int {
    return switch (err) {
        error.InvalidLength => 1,
        error.InvalidEncoding => 2,
        error.AlgorithmMismatch => 3,
        error.InvalidPublicKey => 4,
        error.InvalidPrivateKey => 5,
        error.InvalidContext => 6,
        error.InvalidOption => 7,
        error.RngFailure => 8,
        error.SelfTestFailed => 9,
        error.KeyExhausted => 10,
        error.StatePersistFailed => 11,
        error.StateConflict => 12,
        error.Unsupported => 13,
        error.Rejected => rejected,
        error.BadArgument => bad_argument,
        error.BadSlot => bad_slot,
        error.OutOfMemory => out_of_memory,
        error.Busy => busy,
    };
}

// The stack occupies the start of a WebAssembly instance's linear memory and the module's own data
// follows it, up to __heap_base: a buffer there would let a call write over its own frames or the
// allocator's state, so every buffer lies above it.
extern var __heap_base: u8;

pub fn heapBase() usize {
    return if (wasm) @intFromPtr(&__heap_base) else 0;
}

// A buffer that the caller passes as a pointer and a length. Null is accepted only for an empty
// buffer, and a buffer may not wrap around the address space or, in WebAssembly, lie outside the
// heap of the linear memory: a binding's mistake then fails the call instead of trapping.
fn span(address: usize, length: usize) Failure!void {
    if (length > std.math.maxInt(usize) - address) return error.BadArgument;

    if (wasm) {
        if (address < heapBase() or address + length > @wasmMemorySize(0) * std.wasm.page_size) return error.BadArgument;
    }
}

pub fn input(pointer: ?[*]const u8, length: usize) Failure![]const u8 {
    if (length == 0) return &.{};

    const base = pointer orelse return error.BadArgument;

    try span(@intFromPtr(base), length);

    return base[0..length];
}

pub fn output(pointer: ?[*]u8, length: usize) Failure![]u8 {
    if (length == 0) return &.{};

    const base = pointer orelse return error.BadArgument;

    try span(@intFromPtr(base), length);

    return base[0..length];
}

// An output buffer whose length the call fixes.
pub fn exact(pointer: ?[*]u8, length: usize, size: usize) Failure![]u8 {
    if (length != size) return error.BadArgument;

    return output(pointer, length);
}

// An output of a fixed type (an array of words): present, aligned for its type and inside memory,
// checked like a byte buffer before anything is written.
pub fn fixed(comptime T: type, pointer: ?*anyopaque) Failure!*T {
    const address = @intFromPtr(pointer orelse return error.BadArgument);

    if (address % @alignOf(T) != 0) return error.BadArgument;

    try span(address, @sizeOf(T));

    return @ptrFromInt(address);
}

pub fn overlap(a: []const u8, b: []const u8) bool {
    if (a.len == 0 or b.len == 0) return false;

    const a_start = @intFromPtr(a.ptr);

    const b_start = @intFromPtr(b.ptr);

    return a_start < b_start + b.len and b_start < a_start + a.len;
}

// Every buffer or slot that a call writes, a slot whose cache it may fill included, must be apart
// from every other buffer and slot of the call, so that nothing it reads changes under it.
pub fn apart(written: []const []const u8, read: []const []const u8) Failure!void {
    for (written, 0..) |a, i| {
        for (written[i + 1 ..]) |b| {
            if (overlap(a, b)) return error.BadArgument;
        }

        for (read) |b| {
            if (overlap(a, b)) return error.BadArgument;
        }
    }
}

// The kinds of objects the caller holds in its own memory.
pub const SlotType = enum(u32) {
    kem_public = 1,
    kem_private = 2,
    signature_public = 3,
    signature_private = 4,
    hasher = 5,
    xof = 6,
    hmac = 7,
    signer = 8,
};

// Every slot starts with this header. The magic names the slot type and the ABI version, so that
// memory that was never a slot, a wiped one or one of another type is refused. `users` counts the
// calls inside the slot; its top bit marks a slot that a wipe ends, which no call enters any more,
// and the next one a wipe that is zeroing it. A wipe waits for no call: while calls are inside, it
// marks the slot and the last call out zeroes it.
pub const Header = extern struct {
    magic: u64,
    algorithm: u32,
    size: u32,
    flags: u32,
    users: u32,
};

pub const abi_version: u32 = 1;

// The little-endian bytes are the slot type, "cpq", the ABI version and "abi".
pub fn magic(slot_type: SlotType) u64 {
    return 0x6962_6100_7170_6300 | @as(u64, abi_version) << 32 | @intFromEnum(slot_type);
}

// The slot type that a header names, or null.
pub fn typeOf(value: u64) ?SlotType {
    if (value & ~@as(u64, 0xff) != magic(.kem_public) & ~@as(u64, 0xff)) return null;

    return std.enums.fromInt(SlotType, @as(u32, @truncate(value & 0xff)));
}

fn typeIn(comptime types: []const SlotType, value: u64) ?SlotType {
    inline for (types) |slot_type| {
        if (value == magic(slot_type)) return slot_type;
    }

    return null;
}

const ending: u32 = 1 << 31;

const zeroing: u32 = 1 << 30;

const calls: u32 = zeroing - 1;

// The magic is read and written as two 32-bit atomic halves, which every target has: a torn value
// mixes a live half with a zero one and names no slot type.
fn halves(header: *const Header) *const [2]u32 {
    return @ptrCast(&header.magic);
}

pub fn loadMagic(header: *const Header) u64 {
    const words = halves(header);

    return @bitCast([2]u32{ @atomicLoad(u32, &words[0], .acquire), @atomicLoad(u32, &words[1], .acquire) });
}

fn storeMagic(header: *Header, value: u64) void {
    const words: *[2]u32 = @ptrCast(&header.magic);

    const parts: [2]u32 = @bitCast(value);

    @atomicStore(u32, &words[0], parts[0], .release);

    @atomicStore(u32, &words[1], parts[1], .release);
}

// Every slot is aligned to this many bytes, whatever its type.
pub const slot_alignment = 16;

pub fn bodyOffset(comptime Body: type) usize {
    comptime std.debug.assert(@alignOf(Body) <= slot_alignment);

    return std.mem.alignForward(usize, @sizeOf(Header), @alignOf(Body));
}

pub fn slotSize(comptime Body: type) usize {
    return std.mem.alignForward(usize, bodyOffset(Body) + @sizeOf(Body), slot_alignment);
}

// A volatile read happens exactly once: the value checked is the value used, even if a mistaken
// binding writes the header meanwhile.
pub fn once(comptime T: type, pointer: *const T) T {
    return @as(*const volatile T, pointer).*;
}

// A slot as a call validated it, with its type, algorithm and flags as the check read them. A slot
// that `open` returned has the call registered in its header until `close`.
pub const Slot = struct {
    header: *Header,
    slot_type: SlotType,
    algorithm: u32,
    flags: u32,
    bytes: []u8,

    pub fn body(self: Slot, comptime Body: type) *Body {
        return @ptrFromInt(@intFromPtr(self.header) + bodyOffset(Body));
    }

    // The header is written last, once the body is complete, and the magic last of all: a call
    // that sees it sees the whole slot.
    pub fn seal(self: Slot, flags: u32) void {
        self.header.algorithm = self.algorithm;

        self.header.size = @intCast(self.bytes.len);

        self.header.flags = flags;

        @atomicStore(u32, &self.header.users, 0, .release);

        storeMagic(self.header, magic(self.slot_type));
    }

    // For a slot whose creation failed after it was written, and which may hold part of a secret.
    pub fn discard(self: Slot) void {
        ct.wipe(self.bytes);
    }

    // The call leaves the slot; the last one out of a slot that a wipe marked zeroes it.
    pub fn close(self: Slot) void {
        const previous = @atomicRmw(u32, &self.header.users, .Sub, 1, .acq_rel);

        if (previous != ending | 1) return;

        if (@cmpxchgStrong(u32, &self.header.users, ending, ending | zeroing, .acq_rel, .acquire) != null) return;

        kill(.{ .header = self.header, .slot_type = self.slot_type, .size = self.bytes.len }, self.bytes);
    }

    // The header still names what the call opened. The registration keeps wipes out, so a change
    // means that the binding wrote the slot's memory itself during the call: then nothing that the
    // call computed from it may come out.
    pub fn confirm(self: Slot, outputs: []const []u8) Failure!void {
        const same = loadMagic(self.header) == magic(self.slot_type) and once(u32, &self.header.algorithm) == self.algorithm and once(u32, &self.header.size) == self.bytes.len and once(u32, &self.header.flags) == self.flags;

        if (same) return;

        for (outputs) |out| ct.wipe(out);

        return error.BadSlot;
    }
};

fn aligned(memory: ?[*]u8, length: usize) Failure![*]u8 {
    const base = memory orelse return error.BadSlot;

    if (@intFromPtr(base) % slot_alignment != 0 or length < @sizeOf(Header)) return error.BadSlot;

    span(@intFromPtr(base), length) catch return error.BadSlot;

    return base;
}

// Memory for a new slot of `size` bytes, 0 for an algorithm that this library lacks: aligned, of
// exactly that length, and not holding a live slot, which must be wiped first. Nothing is written
// until the call's other checks pass.
pub fn place(slot_type: SlotType, algorithm: u32, memory: ?[*]u8, length: usize, size: usize) Failure!Slot {
    if (size == 0) return error.Unsupported;

    const base = try aligned(memory, length);

    if (length != size) return error.BadSlot;

    const header: *Header = @ptrCast(@alignCast(base));

    if (typeOf(loadMagic(header)) != null) return error.BadSlot;

    return .{ .header = header, .slot_type = slot_type, .algorithm = algorithm, .flags = 0, .bytes = base[0..length] };
}

// How a call uses a slot: keys are read by any number of calls at once; an incremental state
// changes under its call, which therefore holds it alone.
pub const Access = enum { shared, exclusive };

// A call enters only a slot that no wipe has marked: it never adds itself to one, so the calls that
// a wipe found inside are the last ones.
fn enter(header: *Header, comptime access: Access) Failure!void {
    switch (access) {
        .shared => {
            var users = @atomicLoad(u32, &header.users, .acquire);

            while (true) {
                if (users & (ending | zeroing) != 0) return error.BadSlot;

                if (users & calls == calls) return error.Busy;

                users = @cmpxchgWeak(u32, &header.users, users, users + 1, .acq_rel, .acquire) orelse return;
            }
        },
        .exclusive => {
            if (@cmpxchgStrong(u32, &header.users, 0, 1, .acq_rel, .acquire)) |found| {
                return if (found & (ending | zeroing) != 0) error.BadSlot else error.Busy;
            }
        },
    }
}

// A live slot of one of `types`, whose length is the one recorded at its creation and the one its
// algorithm requires (`sizeOf` gives 0 for an unknown algorithm), with the call registered in it.
// Memory that holds no such slot is refused without a write. The fields are read again once the
// call is registered, when no wipe can start any more, and they are the ones the call uses.
pub fn open(comptime types: []const SlotType, memory: ?[*]u8, length: usize, comptime sizeOf: fn (SlotType, u32) usize, comptime access: Access) Failure!Slot {
    const base = try aligned(memory, length);

    const header: *Header = @ptrCast(@alignCast(base));

    _ = try fields(types, header, length, sizeOf);

    try enter(header, access);

    // Only a binding that rewrites the header meanwhile makes the fields change: the call then
    // leaves as it came, and a wipe that marked the slot finishes on its next try.
    errdefer _ = @atomicRmw(u32, &header.users, .Sub, 1, .release);

    const found = try fields(types, header, length, sizeOf);

    return .{ .header = header, .slot_type = found.slot_type, .algorithm = found.algorithm, .flags = found.flags, .bytes = base[0..length] };
}

const Fields = struct {
    slot_type: SlotType,
    algorithm: u32,
    flags: u32,
};

fn fields(comptime types: []const SlotType, header: *const Header, length: usize, comptime sizeOf: fn (SlotType, u32) usize) Failure!Fields {
    const slot_type = typeIn(types, loadMagic(header)) orelse return error.BadSlot;

    const algorithm = once(u32, &header.algorithm);

    const recorded = once(u32, &header.size);

    const flags = once(u32, &header.flags);

    if (recorded != length or sizeOf(slot_type, algorithm) != length) return error.BadSlot;

    return .{ .slot_type = slot_type, .algorithm = algorithm, .flags = flags };
}

// A live slot of `slot_type` and its fields, read without registering: for the stateful signers,
// which their own registry guards, and for cpq_slot_info.
pub fn peek(comptime slot_type: SlotType, memory: ?[*]u8, length: usize, comptime sizeOf: fn (SlotType, u32) usize) Failure!Slot {
    const base = try aligned(memory, length);

    const header: *Header = @ptrCast(@alignCast(base));

    if (loadMagic(header) != magic(slot_type)) return error.BadSlot;

    const algorithm = once(u32, &header.algorithm);

    const recorded = once(u32, &header.size);

    const flags = once(u32, &header.flags);

    if (recorded != length or sizeOf(slot_type, algorithm) != length) return error.BadSlot;

    return .{ .header = header, .slot_type = slot_type, .algorithm = algorithm, .flags = flags, .bytes = base[0..length] };
}

// A slot that a wipe found in its range: claimed against every call, then killed. `size` is the
// part of the range that the slot covers.
pub const Found = struct {
    header: *Header,
    slot_type: SlotType,
    size: usize,
};

// Claims a key or hash slot for a wipe, which then zeroes it. While calls are inside, the slot is
// marked instead, so that no call enters it any more and the last one out zeroes it: BUSY, and the
// memory must stay allocated until then. BUSY too while another wipe zeroes it.
pub fn claim(header: *Header) Failure!void {
    var users = @atomicLoad(u32, &header.users, .acquire);

    while (true) {
        if (users & zeroing != 0) return error.Busy;

        if (users & calls != 0) {
            if (users & ending != 0) return error.Busy;

            users = @cmpxchgWeak(u32, &header.users, users, users | ending, .acq_rel, .acquire) orelse return error.Busy;

            continue;
        }

        users = @cmpxchgWeak(u32, &header.users, users, ending | zeroing, .acq_rel, .acquire) orelse return;
    }
}

// Ends a claimed slot: the magic goes first, then every other byte, and the claim last, so that a
// call that enters afterwards finds the magic gone.
pub fn kill(found: Found, bytes: []u8) void {
    storeMagic(found.header, 0);

    const users = @intFromPtr(&found.header.users) - @intFromPtr(bytes.ptr);

    ct.wipe(bytes[0..users]);

    ct.wipe(bytes[users + 4 ..]);

    @atomicStore(u32, &found.header.users, 0, .release);
}

// The first slot header in `bytes` (at a 16-byte boundary, the alignment of every slot), with the
// offset it lies at, or null. The body of a slot cannot name one: no slot holds another's header.
pub fn nextHeader(bytes: []u8, from: usize) ?usize {
    const start = @intFromPtr(bytes.ptr);

    var offset = std.mem.alignForward(usize, start + from, slot_alignment) - start;

    while (offset + @sizeOf(Header) <= bytes.len) : (offset += slot_alignment) {
        const header: *const Header = @ptrCast(@alignCast(bytes.ptr + offset));

        if (typeOf(loadMagic(header)) != null) return offset;
    }

    return null;
}

// Header flags.
pub const has_seed: u32 = 1;

// A value derived from a key, computed in the slot on first use. The first call to find it empty
// claims it and fills it; a call that finds it being filled computes the value for itself instead
// of waiting, so no call ever blocks on another, and at worst two compute the same value. Readers
// acquire the state that the filler released, which makes the value visible.
//
// The state names the value's own address: 0 empty, the address with its low bit set while a call
// fills it there, the address once it is filled there. A slot copied elsewhere (by memcpy, perhaps
// while a call was filling the original) finds an address that is not its own, whatever the copy
// caught, and fills its value again instead of trusting a value that may be torn.
pub fn Lazy(comptime T: type) type {
    return struct {
        state: std.atomic.Value(usize),
        value: T,

        const Self = @This();

        fn here(self: *const Self) usize {
            return @intFromPtr(&self.value);
        }

        pub fn init(self: *Self) void {
            self.state = .init(0);
        }

        // For a slot that no other call can reach yet, whose creation fills the value.
        pub fn claim(self: *Self) *T {
            self.state = .init(self.here() | 1);

            return &self.value;
        }

        pub fn publish(self: *Self) void {
            self.state.store(self.here(), .release);
        }

        pub fn isReady(self: *const Self) bool {
            return self.state.load(.acquire) == self.here();
        }

        // The value, or null while another call fills it.
        pub fn get(self: *Self, source: anytype) ?*const T {
            const here_ = self.here();

            const state = self.state.load(.acquire);

            if (state == here_) return &self.value;

            if (state == here_ | 1) return null;

            if (self.state.cmpxchgStrong(state, here_ | 1, .acquire, .acquire)) |found| return if (found == here_) &self.value else null;

            self.value.fill(source);

            self.publish();

            return &self.value;
        }

        // Copies a ready value into a slot that no other call can reach yet.
        pub fn copyFrom(self: *Self, other: *const Self) void {
            if (!other.isReady()) return self.init();

            self.value = other.value;

            self.state = .init(self.here());
        }
    };
}

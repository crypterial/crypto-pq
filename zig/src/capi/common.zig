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

// A buffer that the caller passes as a pointer and a length. Null is accepted only for an empty
// buffer, and a buffer may not wrap around the address space or, in WebAssembly, end beyond the
// linear memory: a binding's mistake then fails the call instead of trapping.
fn span(address: usize, length: usize) Failure!void {
    if (length > std.math.maxInt(usize) - address) return error.BadArgument;

    if (wasm and address + length > @wasmMemorySize(0) * std.wasm.page_size) return error.BadArgument;
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

fn overlap(a: []const u8, b: []const u8) bool {
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
// memory that was never a slot, a wiped one or one of another type is refused.
pub const Header = extern struct {
    magic: u64,
    algorithm: u32,
    size: u32,
    flags: u32,
    reserved: u32,
};

pub const abi_version: u32 = 1;

// The little-endian bytes are the slot type, "cpq", the ABI version and "abi".
pub fn magic(slot_type: SlotType) u64 {
    return 0x6962_6100_7170_6300 | @as(u64, abi_version) << 32 | @intFromEnum(slot_type);
}

fn live(value: u64) bool {
    inline for (comptime std.enums.values(SlotType)) |slot_type| {
        if (value == magic(slot_type)) return true;
    }

    return false;
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

// A slot as a call validated it, with its type, algorithm and flags as the check read them.
pub const Slot = struct {
    header: *Header,
    slot_type: SlotType,
    algorithm: u32,
    flags: u32,
    bytes: []u8,

    pub fn body(self: Slot, comptime Body: type) *Body {
        return @ptrFromInt(@intFromPtr(self.header) + bodyOffset(Body));
    }

    // The header is written last, once the body is complete.
    pub fn seal(self: Slot, flags: u32) void {
        self.header.* = .{ .magic = magic(self.slot_type), .algorithm = self.algorithm, .size = @intCast(self.bytes.len), .flags = flags, .reserved = 0 };
    }

    // For a slot whose creation failed and which may hold part of a secret.
    pub fn discard(self: Slot) void {
        ct.wipe(self.bytes);
    }
};

// A volatile read happens exactly once: the value checked is the value used, even if a mistaken
// binding writes the header meanwhile.
fn once(comptime T: type, pointer: *const T) T {
    return @as(*const volatile T, pointer).*;
}

fn aligned(memory: ?[*]u8, length: usize) Failure![*]u8 {
    const base = memory orelse return error.BadSlot;

    if (@intFromPtr(base) % slot_alignment != 0 or length < @sizeOf(Header)) return error.BadSlot;

    span(@intFromPtr(base), length) catch return error.BadSlot;

    return base;
}

// Memory for a new slot of `size` bytes, 0 for an algorithm that this library lacks: aligned, of
// exactly that length, and not holding a live slot, which must be wiped first.
pub fn place(slot_type: SlotType, algorithm: u32, memory: ?[*]u8, length: usize, size: usize) Failure!Slot {
    if (size == 0) return error.Unsupported;

    const base = try aligned(memory, length);

    if (length != size) return error.BadSlot;

    const header: *Header = @ptrCast(@alignCast(base));

    if (live(once(u64, &header.magic))) return error.BadSlot;

    return .{ .header = header, .slot_type = slot_type, .algorithm = algorithm, .flags = 0, .bytes = base[0..length] };
}

// A live slot of one of `types`, whose length is the one recorded at its creation and the one its
// algorithm requires (`sizeOf` gives 0 for an unknown algorithm).
pub fn open(comptime types: []const SlotType, memory: ?[*]u8, length: usize, comptime sizeOf: fn (SlotType, u32) usize) Failure!Slot {
    const base = try aligned(memory, length);

    const header: *Header = @ptrCast(@alignCast(base));

    const value = once(u64, &header.magic);

    const algorithm = once(u32, &header.algorithm);

    const recorded = once(u32, &header.size);

    const flags = once(u32, &header.flags);

    inline for (types) |slot_type| {
        if (value == magic(slot_type)) {
            if (recorded != length or sizeOf(slot_type, algorithm) != length) return error.BadSlot;

            return .{ .header = header, .slot_type = slot_type, .algorithm = algorithm, .flags = flags, .bytes = base[0..length] };
        }
    }

    return error.BadSlot;
}

// The slot type that a live header names, or null.
pub fn typeOf(value: u64) ?SlotType {
    inline for (comptime std.enums.values(SlotType)) |slot_type| {
        if (value == magic(slot_type)) return slot_type;
    }

    return null;
}

// Header flags.
pub const has_seed: u32 = 1;

// A value derived from a key, computed in the slot on first use. The first call to find it empty
// claims it and fills it; a call that finds it being filled computes the value for itself instead
// of waiting, so no call ever blocks on another, and at worst two compute the same value. Readers
// acquire the state that the filler released, which makes the value visible.
pub fn Lazy(comptime T: type) type {
    return struct {
        state: std.atomic.Value(u32),
        value: T,

        const Self = @This();

        const empty = 0;

        const filling = 1;

        const ready = 2;

        pub fn init(self: *Self) void {
            self.state = .init(empty);
        }

        // For a slot that no other call can reach yet, whose creation fills the value.
        pub fn claim(self: *Self) *T {
            self.state = .init(filling);

            return &self.value;
        }

        pub fn publish(self: *Self) void {
            self.state.store(ready, .release);
        }

        pub fn isReady(self: *const Self) bool {
            return self.state.load(.acquire) == ready;
        }

        // The value, or null while another call fills it.
        pub fn get(self: *Self, source: anytype) ?*const T {
            const state = self.state.load(.acquire);

            if (state == ready) return &self.value;

            if (state != empty) return null;

            if (self.state.cmpxchgStrong(empty, filling, .acquire, .acquire)) |found| return if (found == ready) &self.value else null;

            self.value.fill(source);

            self.publish();

            return &self.value;
        }

        // Copies a ready value into a slot that no other call can reach yet.
        pub fn copyFrom(self: *Self, other: *const Self) void {
            if (!other.isReady()) return self.init();

            self.value = other.value;

            self.state = .init(ready);
        }
    };
}

// A flag that one call at a time holds, for the objects whose calls change them. A second call
// fails at once instead of waiting.
pub const Busy = struct {
    state: std.atomic.Value(u32),

    pub fn init(self: *Busy) void {
        self.state = .init(0);
    }

    pub fn acquire(self: *Busy) Failure!void {
        if (self.state.cmpxchgStrong(0, 1, .acquire, .monotonic) != null) return error.Busy;
    }

    pub fn release(self: *Busy) void {
        self.state.store(0, .release);
    }
};

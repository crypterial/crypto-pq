const std = @import("std");

const ct = @import("ct.zig");

const Allocator = std.mem.Allocator;

// A value derived from a key, computed on first use and kept until the key is deinitialized.
// Threads that need it at the same time each compute their own copy and the first one published
// wins; the others free theirs, so no call ever waits for another. Readers acquire the pointer
// that the winner released, which makes the value it points to visible. `T` provides
// fill(self, source), and every value is wiped before it is freed, since some hold secrets.
pub const Slot = struct {
    pointer: std.atomic.Value(?*anyopaque) = .init(null),

    // null when the value cannot be allocated.
    pub fn get(self: *Slot, comptime T: type, allocator: Allocator, source: anytype) ?*const T {
        if (self.pointer.load(.acquire)) |pointer| return @ptrCast(@alignCast(pointer));

        const value = allocator.create(T) catch return null;

        value.fill(source);

        if (self.pointer.cmpxchgStrong(null, value, .acq_rel, .acquire)) |winner| {
            discard(T, allocator, value);

            return @ptrCast(@alignCast(winner.?));
        }

        return value;
    }

    // For a key that no other thread can reach yet, whose creation fills the value before the
    // key is handed out.
    pub fn allocate(self: *Slot, comptime T: type, allocator: Allocator) Allocator.Error!*T {
        const value = try allocator.create(T);

        self.pointer.store(value, .release);

        return value;
    }

    pub fn deinit(self: *Slot, comptime T: type, allocator: Allocator) void {
        const pointer = self.pointer.swap(null, .acquire) orelse return;

        discard(T, allocator, @ptrCast(@alignCast(pointer)));
    }
};

fn discard(comptime T: type, allocator: Allocator, value: *T) void {
    ct.wipe(std.mem.asBytes(value));

    allocator.destroy(value);
}

// The head of the object that holds the public part of a key pair, which its keys share so that
// the cached form exists once per pair: the cache, the allocator that the object and its cache
// come from, and how many keys hold it. The last key to be deinitialized frees the object.
pub const Shared = struct {
    references: std.atomic.Value(usize) = .init(1),
    allocator: Allocator,
    cache: Slot = .{},

    pub fn retain(self: *Shared) void {
        _ = self.references.fetchAdd(1, .monotonic);
    }

    // Whether the caller held the last reference and frees the object. The release and the
    // acquire load order every earlier use before the free.
    pub fn release(self: *Shared) bool {
        if (self.references.fetchSub(1, .release) != 1) return false;

        _ = self.references.load(.acquire);

        return true;
    }
};

const testing = std.testing;

const Counter = struct {
    value: u32,

    fn fill(self: *Counter, source: *std.atomic.Value(u32)) void {
        self.value = source.fetchAdd(1, .monotonic) + 1;
    }
};

test "slot computes once per winner and frees the losers" {
    var slot: Slot = .{};

    var fills: std.atomic.Value(u32) = .init(0);

    const first = slot.get(Counter, testing.allocator, &fills).?;

    const second = slot.get(Counter, testing.allocator, &fills).?;

    try testing.expectEqual(first, second);

    try testing.expectEqual(1, fills.load(.monotonic));

    slot.deinit(Counter, testing.allocator);

    slot.deinit(Counter, testing.allocator);

    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });

    try testing.expectEqual(null, slot.get(Counter, failing.allocator(), &fills));
}

test "slot under concurrent first use" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;

    var slot: Slot = .{};

    var fills: std.atomic.Value(u32) = .init(0);

    var results: [8]*const Counter = undefined;

    var threads: [8]std.Thread = undefined;

    const Worker = struct {
        fn run(s: *Slot, f: *std.atomic.Value(u32), out: **const Counter) void {
            out.* = s.get(Counter, std.heap.smp_allocator, f).?;
        }
    };

    for (&threads, &results) |*thread, *result| thread.* = try std.Thread.spawn(.{}, Worker.run, .{ &slot, &fills, result });

    for (threads) |thread| thread.join();

    for (results) |result| try testing.expectEqual(results[0], result);

    try testing.expect(fills.load(.monotonic) >= 1);

    slot.deinit(Counter, std.heap.smp_allocator);
}

test "shared references" {
    var shared: Shared = .{ .allocator = testing.allocator };

    shared.retain();

    try testing.expect(!shared.release());

    try testing.expect(shared.release());
}

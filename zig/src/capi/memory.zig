const std = @import("std");

const common = @import("common.zig");

const ct = @import("../ct.zig");

// WebAssembly only: the host places a call's inputs in linear memory and reads its outputs there,
// in blocks from this allocator, and zeroes the stack region after an operation on secrets.

// Each block carries its size behind a magic, so that a free with a wrong size, a double free or
// a pointer that never came from here is refused instead of corrupting the allocator.
const Block = extern struct {
    magic: u64,
    size: u64,
};

const block_magic: u64 = 0x6b63_6f6c_6271_7063;

const alignment = 16;

comptime {
    std.debug.assert(@sizeOf(Block) == alignment);
}

// A block of `size` bytes, aligned to 16, or 0 when memory cannot grow.
pub fn alloc(size: usize) callconv(.c) usize {
    const total = std.math.add(usize, size, alignment) catch return 0;

    const memory = common.allocator.alignedAlloc(u8, .fromByteUnits(alignment), total) catch return 0;

    const block: *Block = @ptrCast(memory.ptr);

    block.* = .{ .magic = block_magic, .size = size };

    return @intFromPtr(memory.ptr) + alignment;
}

// Zeroes the block, then frees it.
pub fn free(address: usize, size: usize) callconv(.c) c_int {
    if (address < alignment or address % alignment != 0) return common.bad_argument;

    if (size > @wasmMemorySize(0) * std.wasm.page_size - address) return common.bad_argument;

    const block: *Block = @ptrFromInt(address - alignment);

    if (block.magic != block_magic or block.size != size) return common.bad_argument;

    const memory: []align(alignment) u8 = @as([*]align(alignment) u8, @ptrCast(@alignCast(block)))[0 .. size + alignment];

    ct.wipe(memory);

    common.allocator.free(memory);

    return common.ok;
}

extern var __stack_low: u8;

extern var __stack_high: u8;

// The stack occupies [low, high) at the start of linear memory and grows down from high, so that
// an overflow traps instead of overwriting data. Every export returns with the stack pointer back
// at high; what an operation left below it is still there, and the host zeroes it.
pub fn stackLow() callconv(.c) usize {
    return @intFromPtr(&__stack_low);
}

pub fn stackHigh() callconv(.c) usize {
    return @intFromPtr(&__stack_high);
}

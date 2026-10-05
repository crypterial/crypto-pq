const std = @import("std");

const capi = @import("../capi.zig");
const common = @import("common.zig");

const ct = @import("../ct.zig");

// WebAssembly only: the host places a call's inputs in linear memory and reads its outputs there,
// in blocks from this allocator, and zeroes the stack region after an operation on secrets.

const alignment = 16;

// The blocks handed out and not yet freed, with their sizes, kept apart from the blocks: data that
// the host writes in a block can never look like a block, and a free must name one of these
// exactly. The table grows with the blocks, as long as memory does.
var blocks: std.AutoHashMapUnmanaged(usize, usize) = .empty;

// A freed block waits here, zeroed, before its memory can be handed out again: a second free of an
// address, or a use of one, right after the next allocation does not reach that allocation.
const quarantine_blocks = 16;

const quarantine_bytes = 256 << 10;

var quarantine: [quarantine_blocks][]align(alignment) u8 = undefined;

var quarantine_count: usize = 0;

var quarantine_first: usize = 0;

var quarantined_bytes: usize = 0;

fn release(memory: []align(alignment) u8) void {
    while (quarantine_count == quarantine_blocks or (quarantine_count > 0 and quarantined_bytes + memory.len > quarantine_bytes)) {
        const oldest = quarantine[quarantine_first];

        quarantine_first = (quarantine_first + 1) % quarantine_blocks;

        quarantine_count -= 1;

        quarantined_bytes -= oldest.len;

        common.allocator.free(oldest);
    }

    quarantine[(quarantine_first + quarantine_count) % quarantine_blocks] = memory;

    quarantine_count += 1;

    quarantined_bytes += memory.len;
}

// A block of `size` bytes, aligned to 16, or 0 when memory cannot grow.
pub fn alloc(size: usize) callconv(.c) usize {
    blocks.ensureUnusedCapacity(common.allocator, 1) catch return 0;

    const memory = common.allocator.alignedAlloc(u8, .fromByteUnits(alignment), @max(size, 1)) catch return 0;

    blocks.putAssumeCapacity(@intFromPtr(memory.ptr), size);

    return @intFromPtr(memory.ptr);
}

// Ends every slot in the block, as cpq_slot_wipe does (a stateful signer is freed: BUSY or
// STATE_CONFLICT while a call holds one, and the block stays), zeroes it, then frees it. An
// address that cpq_alloc did not return, or with another size, is BAD_ARGUMENT.
pub fn free(address: usize, size: usize) callconv(.c) c_int {
    const recorded = blocks.get(address) orelse return common.bad_argument;

    if (recorded != size) return common.bad_argument;

    const memory = @as([*]align(alignment) u8, @ptrFromInt(address))[0..@max(size, 1)];

    capi.wipeRange(memory[0..size]) catch |err| return common.code(err);

    ct.wipe(memory);

    _ = blocks.remove(address);

    release(memory);

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

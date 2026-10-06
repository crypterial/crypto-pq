//! The C ABI of crypto-pq. One source builds the native shared library, which Python loads
//! through ctypes, and the WebAssembly modules, one per family, which TypeScript embeds.
//!
//! Every buffer crosses as a pointer and a length, checked before the core sees it, and no
//! pointer the caller passes is kept after a call returns. Keys and incremental states live in
//! slots, memory the caller owns: fixed layouts without pointers, tagged with their type and
//! algorithm, holding the key caches that fill on first use. Randomness always comes from the
//! caller; the library never reads the operating system's. Calls return a status: 0, one of
//! crypto-pq's error codes 1-13, or one of the ABI's own codes from 100.

const std = @import("std");
const builtin = @import("builtin");

const options = @import("capi_options");

pub const common = @import("capi/common.zig");
pub const hash = @import("capi/hash.zig");
pub const kem = @import("capi/kem.zig");
pub const memory = @import("capi/memory.zig");
pub const signature = @import("capi/signature.zig");
pub const stateful = @import("capi/stateful.zig");

const cpu = @import("cpu.zig");
const ct = @import("ct.zig");
const keccak = @import("keccak.zig");

// A failed safety check traps: the process stops, or the WebAssembly instance, which the host then
// discards. Nothing returns to the host with memory in an unknown state, and the library carries no
// message printer and no thread-local storage.
pub const panic = std.debug.no_panic;

// Windows calls a library's entry point on load and unload; this one does nothing. Declaring it
// keeps the standard library's, which would bring thread-local storage, and it is not exported.
pub const _DllMainCRTStartup = dllMain;

fn dllMain(instance: ?*anyopaque, reason: u32, reserved: ?*anyopaque) callconv(.winapi) c_int {
    _ = .{ instance, reason, reserved };

    return 1;
}

comptime {
    if (builtin.os.tag == .windows and builtin.output_mode == .Lib) {
        @export(&dllMain, .{ .name = "_DllMainCRTStartup", .visibility = .hidden });
    }
}

pub fn abiVersion() callconv(.c) u32 {
    return common.abi_version;
}

const families = blk: {
    var text: []const u8 = "";

    for (.{ "ml_kem", "x_wing", "ml_dsa", "slh_dsa", "stateful", "hash" }) |name| {
        if (@field(options, name)) text = text ++ " " ++ name;
    }

    break :blk text;
};

const build_text = std.fmt.comptimePrint("crypto-pq abi {d}; zig {s}; {s}; {s}-{s}-{s}; cpu {s}; portable {}; families{s}", .{
    common.abi_version,
    builtin.zig_version_string,
    @tagName(builtin.mode),
    @tagName(builtin.cpu.arch),
    @tagName(builtin.os.tag),
    @tagName(builtin.abi),
    builtin.cpu.model.name,
    @import("build_options").portable,
    families,
});

// Copies as much of the build description as fits and returns its full length.
pub fn buildInfo(out: ?[*]u8, capacity: usize) callconv(.c) usize {
    const buffer = common.output(out, capacity) catch return build_text.len;

    const length = @min(buffer.len, build_text.len);

    @memcpy(buffer[0..length], build_text[0..length]);

    return build_text.len;
}

// The CPU-specific code in use, one bit per feature: 1 SHA-256 instructions, 2 SHA-512, 4 SHA3,
// 8 AVX2, 16 DIT, 32 NEON.
pub fn cpuFeatures() callconv(.c) u32 {
    var bits: u32 = 0;

    inline for (comptime std.enums.values(cpu.Feature)) |feature| {
        if (cpu.has(feature)) bits |= @as(u32, 1) << @intFromEnum(feature);
    }

    if (cpu.neon) bits |= 32;

    return bits;
}

// What the binding knows of the engine that runs a WebAssembly module, given before the module
// does any work. It picks between code shapes of equal results: bit 0, the engine compiles a
// rotation of 64-bit vector lanes faster as two added shifts (V8 before version 15); bit 1, it
// runs a single Keccak state faster with two rounds per iteration (V8); bit 2, it runs two Keccak
// states faster in the lanes of vectors (V8 from version 15, JavaScriptCore). Other bits are
// ignored.
pub fn wasmTune(flags: u32) callconv(.c) void {
    keccak.webassembly.tune(flags);
}

fn sizeOf(slot_type: common.SlotType, algorithm: u32) usize {
    return switch (slot_type) {
        .kem_public, .kem_private => kem.size(slot_type, algorithm),
        .signature_public, .signature_private => signature.size(slot_type, algorithm),
        .hasher, .xof, .hmac => hash.size(slot_type, algorithm),
        .signer => stateful.size(slot_type, algorithm),
    };
}

fn typed(slot_type: u32) ?common.SlotType {
    return std.enums.fromInt(common.SlotType, slot_type);
}

// The bytes a slot of this type and algorithm takes, or 0 when this library lacks the algorithm.
pub fn slotSize(slot_type: u32, algorithm: u32) callconv(.c) usize {
    return sizeOf(typed(slot_type) orelse return 0, algorithm);
}

// The alignment of that slot's memory, or 0.
pub fn slotAlign(slot_type: u32, algorithm: u32) callconv(.c) usize {
    return if (slotSize(slot_type, algorithm) == 0) 0 else common.slot_alignment;
}

// out[0] the slot type, out[1] the algorithm, out[2] the flags: bit 0 the key kept its seed, bit 8
// the public cache is filled, bit 9 the secret cache. A signer slot is checked through its signer:
// a copy, or a slot that outlived its signer, is BAD_SLOT.
pub fn slotInfo(memory_pointer: ?[*]u8, length: usize, out: ?*anyopaque) callconv(.c) c_int {
    return common.status(slotInfoChecked(memory_pointer, length, out));
}

fn slotInfoChecked(memory_pointer: ?[*]u8, length: usize, out: ?*anyopaque) common.Failure!void {
    const target = try common.fixed([3]u32, out);

    if (options.stateful) {
        if (stateful.inspect(memory_pointer, length)) |slot| {
            try common.apart(&.{std.mem.asBytes(target)}, &.{slot.bytes});

            target.* = .{ @intFromEnum(slot.slot_type), slot.algorithm, slot.flags };

            return;
        } else |_| {}
    }

    const slot = try common.open(&.{ .kem_public, .kem_private, .signature_public, .signature_private, .hasher, .xof, .hmac }, memory_pointer, length, sizeOf, .shared);

    defer slot.close();

    try common.apart(&.{std.mem.asBytes(target)}, &.{slot.bytes});

    const caches = switch (slot.slot_type) {
        .kem_public, .kem_private => kem.cacheFlags(slot),
        .signature_public, .signature_private => signature.cacheFlags(slot),
        else => 0,
    };

    target.* = .{ @intFromEnum(slot.slot_type), slot.algorithm, slot.flags | caches << 8 };
}

// Zeroes `length` bytes of the caller's memory, whatever they hold. Every slot whose header lies
// in them is ended first: a key or a state that a call is inside is BUSY, a signer that a call
// holds STATE_CONFLICT, and a signer is freed with its trees. A refused wipe has changed nothing
// from that slot on.
pub fn slotWipe(memory_pointer: ?[*]u8, length: usize) callconv(.c) c_int {
    const bytes = common.output(memory_pointer, length) catch return common.bad_argument;

    return common.status(wipeRange(bytes));
}

pub fn wipeRange(bytes: []u8) common.Failure!void {
    var done: usize = 0;

    var from: usize = 0;

    while (common.nextHeader(bytes, from)) |offset| {
        const header: *common.Header = @ptrCast(@alignCast(bytes.ptr + offset));

        const slot_type = common.typeOf(common.loadMagic(header)) orelse {
            from = offset + common.slot_alignment;

            continue;
        };

        // A slot that the range cuts short ends with the range.
        const recorded = common.once(u32, &header.size);

        const end = if (recorded >= @sizeOf(common.Header) and recorded <= bytes.len - offset) offset + recorded else bytes.len;

        if (slot_type == .signer) {
            const claimed: ?stateful.Held = if (options.stateful) try stateful.claimAt(bytes[offset..end]) else null;

            // Not a signer that lives here, such as a copy: plain memory.
            const signer = claimed orelse {
                from = offset + common.slot_alignment;

                continue;
            };

            ct.wipe(bytes[done..offset]);

            if (options.stateful) stateful.retire(signer);
        } else {
            try common.claim(header);

            ct.wipe(bytes[done..offset]);

            common.kill(.{ .header = header, .slot_type = slot_type, .size = end - offset }, bytes[offset..end]);
        }

        done = end;

        from = end;
    }

    ct.wipe(bytes[done..]);
}

fn exportAll(comptime list: anytype) void {
    inline for (list) |entry| @export(entry[1], .{ .name = entry[0] });
}

comptime {
    if (options.exports) {
        exportAll(.{
            .{ "cpq_abi_version", &abiVersion },
            .{ "cpq_build_info", &buildInfo },
            .{ "cpq_cpu_features", &cpuFeatures },
            .{ "cpq_slot_size", &slotSize },
            .{ "cpq_slot_align", &slotAlign },
            .{ "cpq_slot_info", &slotInfo },
            .{ "cpq_slot_wipe", &slotWipe },
        });

        if (common.wasm) {
            exportAll(.{
                .{ "cpq_alloc", &memory.alloc },
                .{ "cpq_free", &memory.free },
                .{ "cpq_stack_low", &memory.stackLow },
                .{ "cpq_stack_high", &memory.stackHigh },
                .{ "cpq_wasm_tune", &wasmTune },
            });
        }

        if (options.ml_kem or options.x_wing) {
            exportAll(.{
                .{ "cpq_kem_keygen", &kem.keygen },
                .{ "cpq_kem_import_public", &kem.importPublic },
                .{ "cpq_kem_import_private", &kem.importPrivate },
                .{ "cpq_kem_public_from_private", &kem.publicFromPrivate },
                .{ "cpq_kem_export_public", &kem.exportPublic },
                .{ "cpq_kem_export_private", &kem.exportPrivate },
                .{ "cpq_kem_encapsulate", &kem.encapsulate },
                .{ "cpq_kem_decapsulate", &kem.decapsulate },
                .{ "cpq_kem_self_test", &kem.selfTest },
            });
        }

        if (options.ml_dsa or options.slh_dsa) {
            exportAll(.{
                .{ "cpq_sig_keygen", &signature.keygen },
                .{ "cpq_sig_import_public", &signature.importPublic },
                .{ "cpq_sig_import_private", &signature.importPrivate },
                .{ "cpq_sig_public_from_private", &signature.publicFromPrivate },
                .{ "cpq_sig_export_public", &signature.exportPublic },
                .{ "cpq_sig_export_private", &signature.exportPrivate },
                .{ "cpq_sig_sign", &signature.sign },
                .{ "cpq_sig_verify", &signature.verify },
            });
        }

        if (options.stateful) {
            exportAll(.{
                .{ "cpq_stateful_info", &stateful.info },
                .{ "cpq_stateful_signer_create", &stateful.create },
                .{ "cpq_stateful_signer_load", &stateful.load },
                .{ "cpq_stateful_signer_sign", &stateful.sign },
                .{ "cpq_stateful_signer_public_key", &stateful.publicKey },
                .{ "cpq_stateful_signer_info", &stateful.signerInfo },
                .{ "cpq_stateful_signer_tree_cache_size", &stateful.treeCacheSize },
                .{ "cpq_stateful_signer_export_tree_cache", &stateful.exportTreeCache },
                .{ "cpq_stateful_signer_free", &stateful.free },
                .{ "cpq_stateful_verify", &stateful.verify },
                .{ "cpq_stateful_check_public_key", &stateful.checkPublicKey },
                .{ "cpq_stateful_state_reseal", &stateful.reseal },
            });
        }

        if (options.hash) {
            exportAll(.{
                .{ "cpq_hash", &hash.digest },
                .{ "cpq_hash_init", &hash.init },
                .{ "cpq_hash_update", &hash.update },
                .{ "cpq_hash_final", &hash.final },
                .{ "cpq_xof", &hash.xof },
                .{ "cpq_xof_init", &hash.xofInit },
                .{ "cpq_xof_update", &hash.xofUpdate },
                .{ "cpq_xof_read", &hash.xofRead },
                .{ "cpq_hmac", &hash.hmac },
                .{ "cpq_hmac_verify", &hash.hmacVerify },
                .{ "cpq_hmac_init", &hash.hmacInit },
                .{ "cpq_hmac_update", &hash.hmacUpdate },
                .{ "cpq_hmac_final", &hash.hmacFinal },
                .{ "cpq_hmac_final_verify", &hash.hmacFinalVerify },
            });
        }
    }
}

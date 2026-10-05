const std = @import("std");

const capi = @import("capi.zig");

const common = capi.common;

const memcheck = std.valgrind.memcheck;

const Allocator = std.mem.Allocator;

// `zig build ct -Dct=true` runs this under valgrind's memcheck, like test/ct.zig for the core: the
// C ABI's entry points that handle secrets are called as a C caller would, with every seed,
// randomness, private key and HMAC key marked uninitialised, so that memcheck reports any branch
// or memory index of the ABI layer that depends on one. Results are declassified here before they
// are compared.

const message = "crypto-pq constant-time check of the C ABI";

fn secretBytes(comptime size: usize, first: u8) [size]u8 {
    var bytes: [size]u8 = undefined;

    for (&bytes, 0..) |*byte, i| byte.* = first +% @as(u8, @truncate(i));

    memcheck.makeMemUndefined(&bytes);

    return bytes;
}

fn check(status: c_int) !void {
    if (status != common.ok) {
        std.debug.print("status {d}\n", .{status});

        return error.CheckFailed;
    }
}

fn same(a: []const u8, b: []const u8) bool {
    memcheck.makeMemDefined(a);

    memcheck.makeMemDefined(b);

    return std.mem.eql(u8, a, b);
}

const Slot = struct {
    bytes: []align(common.slot_alignment) u8,

    fn init(allocator: Allocator, slot_type: common.SlotType, algorithm: u32) !Slot {
        const size = capi.slotSize(@intFromEnum(slot_type), algorithm);

        return .{ .bytes = try allocator.alignedAlloc(u8, .fromByteUnits(common.slot_alignment), size) };
    }

    fn deinit(self: Slot, allocator: Allocator) void {
        _ = capi.slotWipe(self.bytes.ptr, self.bytes.len);

        allocator.free(self.bytes);
    }

    fn wipe(self: Slot) void {
        _ = capi.slotWipe(self.bytes.ptr, self.bytes.len);
    }
};

fn kem(allocator: Allocator, comptime id: u32) !void {
    const S = capi.kem.Set(id);

    const private = try Slot.init(allocator, .kem_private, id);

    defer private.deinit(allocator);

    const public = try Slot.init(allocator, .kem_public, id);

    defer public.deinit(allocator);

    const seed = secretBytes(S.seed_size, 1);

    var public_key: [S.public_key_size]u8 = undefined;

    var ciphertext: [S.ciphertext_size]u8 = undefined;

    var sent: [32]u8 = undefined;

    var received: [32]u8 = undefined;

    for ([_]u32{ 0, capi.kem.fill_cache }) |flags| {
        private.wipe();

        try check(capi.kem.keygen(id, &seed, seed.len, flags, private.bytes.ptr, private.bytes.len));

        try check(capi.kem.exportPublic(private.bytes.ptr, private.bytes.len, &public_key, public_key.len));

        // The public key is public; a public slot made from it fills its cache from public bytes.
        memcheck.makeMemDefined(&public_key);

        public.wipe();

        try check(capi.kem.importPublic(id, &public_key, public_key.len, public.bytes.ptr, public.bytes.len));

        for ([_]Slot{ public, private }) |encapsulator| {
            const randomness = secretBytes(S.randomness_size, 2);

            try check(capi.kem.encapsulate(encapsulator.bytes.ptr, encapsulator.bytes.len, &randomness, randomness.len, &ciphertext, ciphertext.len, &sent, 32));

            try check(capi.kem.decapsulate(private.bytes.ptr, private.bytes.len, &ciphertext, ciphertext.len, &received, 32));

            if (!same(&sent, &received)) return error.CheckFailed;

            // Implicit rejection takes the same path.
            ciphertext[0] ^= 1;

            try check(capi.kem.decapsulate(private.bytes.ptr, private.bytes.len, &ciphertext, ciphertext.len, &received, 32));

            if (same(&sent, &received)) return error.CheckFailed;
        }

        const test_randomness = secretBytes(S.randomness_size, 3);

        try check(capi.kem.selfTest(private.bytes.ptr, private.bytes.len, &test_randomness, test_randomness.len));
    }

    var exported: [@max(S.expanded_size, 64)]u8 = undefined;

    const which = if (S.x_wing) capi.kem.export_seed else capi.kem.export_expanded;

    const size = if (S.x_wing) S.seed_size else S.expanded_size;

    try check(capi.kem.exportPrivate(private.bytes.ptr, private.bytes.len, which, &exported, size));

    // A key from outside is secret as a whole; the library declassifies what it holds of the public
    // key once it has checked it.
    memcheck.makeMemUndefined(exported[0..size]);

    const imported = try Slot.init(allocator, .kem_private, id);

    defer imported.deinit(allocator);

    try check(capi.kem.importPrivate(id, &exported, size, imported.bytes.ptr, imported.bytes.len));

    const randomness = secretBytes(S.randomness_size, 4);

    try check(capi.kem.encapsulate(public.bytes.ptr, public.bytes.len, &randomness, randomness.len, &ciphertext, ciphertext.len, &sent, 32));

    try check(capi.kem.decapsulate(imported.bytes.ptr, imported.bytes.len, &ciphertext, ciphertext.len, &received, 32));

    if (!same(&sent, &received)) return error.CheckFailed;

    const derived = try Slot.init(allocator, .kem_public, id);

    defer derived.deinit(allocator);

    try check(capi.kem.publicFromPrivate(imported.bytes.ptr, imported.bytes.len, derived.bytes.ptr, derived.bytes.len));
}

fn signature(allocator: Allocator, comptime id: u32) !void {
    const S = capi.signature.Set(id);

    const private = try Slot.init(allocator, .signature_private, id);

    defer private.deinit(allocator);

    const public = try Slot.init(allocator, .signature_public, id);

    defer public.deinit(allocator);

    const signed = try allocator.alloc(u8, S.signature_size);

    defer allocator.free(signed);

    const seed = secretBytes(S.seed_size, 5);

    for ([_]u32{ 0, capi.signature.fill_cache }) |flags| {
        private.wipe();

        try check(capi.signature.keygen(id, &seed, seed.len, flags, private.bytes.ptr, private.bytes.len));

        public.wipe();

        try check(capi.signature.publicFromPrivate(private.bytes.ptr, private.bytes.len, public.bytes.ptr, public.bytes.len));

        const randomness = secretBytes(S.randomness_size, 6);

        try check(capi.signature.sign(private.bytes.ptr, private.bytes.len, message, message.len, "ctx", 3, 0, &randomness, randomness.len, 0, signed.ptr, signed.len));

        try check(capi.signature.verify(public.bytes.ptr, public.bytes.len, signed.ptr, signed.len, message, message.len, "ctx", 3, 0, 0));

        try check(capi.signature.sign(private.bytes.ptr, private.bytes.len, message, message.len, null, 0, 4, null, 0, capi.signature.deterministic, signed.ptr, signed.len));

        try check(capi.signature.verify(private.bytes.ptr, private.bytes.len, signed.ptr, signed.len, message, message.len, null, 0, 4, 0));
    }

    var exported: [S.secret_size]u8 = undefined;

    try check(capi.signature.exportPrivate(private.bytes.ptr, private.bytes.len, capi.signature.export_private, &exported, exported.len));

    memcheck.makeMemUndefined(&exported);

    const imported = try Slot.init(allocator, .signature_private, id);

    defer imported.deinit(allocator);

    try check(capi.signature.importPrivate(id, &exported, exported.len, imported.bytes.ptr, imported.bytes.len));

    const randomness = secretBytes(S.randomness_size, 7);

    try check(capi.signature.sign(imported.bytes.ptr, imported.bytes.len, message, message.len, null, 0, 0, &randomness, randomness.len, 0, signed.ptr, signed.len));

    try check(capi.signature.verify(public.bytes.ptr, public.bytes.len, signed.ptr, signed.len, message, message.len, null, 0, 0, 0));
}

fn hashes(allocator: Allocator) !void {
    const data = secretBytes(300, 8);

    const key = secretBytes(150, 9);

    var out: [200]u8 = undefined;

    const sizes = [_]usize{ 28, 32, 48, 64, 28, 32, 28, 32, 48, 64 };

    for (sizes, 0..) |size, id| try check(capi.hash.digest(@intCast(id), &data, data.len, &out, size));

    for (0..2) |id| try check(capi.hash.xof(@intCast(id), &data, data.len, &out, out.len));

    const state = try Slot.init(allocator, .hmac, 3);

    defer state.deinit(allocator);

    for ([_]usize{ 28, 32, 48, 64 }, 0..) |size, id| {
        for ([_]usize{ 20, 150 }) |length| {
            try check(capi.hash.hmac(@intCast(id), &key, length, &data, data.len, &out, size));

            // The tag is what the caller compares against; whether it matches is the answer.
            memcheck.makeMemDefined(out[0..size]);

            try check(capi.hash.hmacVerify(@intCast(id), &key, length, &data, data.len, &out, size));

            state.wipe();

            try check(capi.hash.hmacInit(@intCast(id), &key, length, state.bytes.ptr, state.bytes.len));

            try check(capi.hash.hmacUpdate(state.bytes.ptr, state.bytes.len, &data, data.len));

            try check(capi.hash.hmacFinalVerify(state.bytes.ptr, state.bytes.len, &out, size));
        }
    }

    const hasher = try Slot.init(allocator, .hasher, 7);

    defer hasher.deinit(allocator);

    try check(capi.hash.init(7, hasher.bytes.ptr, hasher.bytes.len));

    try check(capi.hash.update(hasher.bytes.ptr, hasher.bytes.len, &data, data.len));

    try check(capi.hash.final(hasher.bytes.ptr, hasher.bytes.len, &out, 32));

    const xof = try Slot.init(allocator, .xof, 1);

    defer xof.deinit(allocator);

    try check(capi.hash.xofInit(1, xof.bytes.ptr, xof.bytes.len));

    try check(capi.hash.xofUpdate(xof.bytes.ptr, xof.bytes.len, &data, data.len));

    try check(capi.hash.xofRead(xof.bytes.ptr, xof.bytes.len, &out, out.len));
}

// The seed is secret, and so is the state blob that holds it; the tree cache, the public key and
// the signatures are public.
fn signer(allocator: Allocator, kind: u32, section: []const u8, comptime seed_size: usize) !void {
    var sizes: [6]u64 = undefined;

    try check(capi.stateful.info(kind, section.ptr, section.len, &sizes));

    const slot = try Slot.init(allocator, .signer, kind);

    defer slot.deinit(allocator);

    const seed = secretBytes(seed_size, 10);

    var state: [139]u8 = undefined;

    const blob = state[0..@intCast(sizes[1])];

    try check(capi.stateful.create(kind, section.ptr, section.len, &seed, seed.len, 0, blob.ptr, blob.len, slot.bytes.ptr, slot.bytes.len));

    const signed = try allocator.alloc(u8, @intCast(sizes[3]));

    defer allocator.free(signed);

    var public_key: [68]u8 = undefined;

    const key = public_key[0..@intCast(sizes[2])];

    try check(capi.stateful.publicKey(slot.bytes.ptr, slot.bytes.len, key.ptr, key.len));

    for (0..2) |index| {
        try check(capi.stateful.reseal(kind, blob.ptr, blob.len, index + 1));

        try check(capi.stateful.sign(slot.bytes.ptr, slot.bytes.len, index, message, message.len, signed.ptr, signed.len));

        try check(capi.stateful.verify(kind, key.ptr, key.len, message, message.len, signed.ptr, signed.len));
    }

    var size: u64 = 0;

    try check(capi.stateful.treeCacheSize(slot.bytes.ptr, slot.bytes.len, &size));

    const cache = try allocator.alloc(u8, @intCast(size));

    defer allocator.free(cache);

    try check(capi.stateful.exportTreeCache(slot.bytes.ptr, slot.bytes.len, cache.ptr, cache.len));

    // The state's seed section and its checksum are secret, its version, kind, parameters and
    // index public, as a store holds them.
    const seed_section = if (kind == 1) blob[3 + 8 * @as(usize, blob[2]) .. blob.len - 24] else blob[14 .. blob.len - 16];

    memcheck.makeMemUndefined(seed_section);

    memcheck.makeMemUndefined(blob[blob.len - 16 ..]);

    for ([_]u32{ 0, capi.stateful.with_tree_cache }) |flags| {
        const loaded = try Slot.init(allocator, .signer, kind);

        defer loaded.deinit(allocator);

        var index: u64 = 0;

        const given: []const u8 = if (flags != 0) cache else &.{};

        try check(capi.stateful.load(kind, blob.ptr, blob.len, given.ptr, given.len, flags, loaded.bytes.ptr, loaded.bytes.len, &index));

        try check(capi.stateful.sign(loaded.bytes.ptr, loaded.bytes.len, index, message, message.len, signed.ptr, signed.len));

        try check(capi.stateful.verify(kind, key.ptr, key.len, message, message.len, signed.ptr, signed.len));
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    inline for (0..4) |id| {
        try kem(allocator, id);

        std.debug.print("C ABI KEM {d}: ok\n", .{id});
    }

    // The SLH-DSA sets differ in sizes, not in code paths; one per hash family, as for the core.
    inline for (.{ 0, 1, 2, 6, 10 }) |id| {
        try signature(allocator, id);

        std.debug.print("C ABI signature {d}: ok\n", .{id});
    }

    try hashes(allocator);

    std.debug.print("C ABI hashes: ok\n", .{});

    // HSS with two levels of SHA-256/192, and XMSS^MT with SHAKE256 on four layers.
    const hss = [_]u8{ 2, 0, 0, 0, 0x0a, 0, 0, 0, 0x07, 0, 0, 0, 0x0a, 0, 0, 0, 0x06 };

    try signer(allocator, 1, &hss, 40);

    std.debug.print("C ABI HSS/LMS signer: ok\n", .{});

    try signer(allocator, 3, &.{ 0, 0, 0, 0x2a }, 96);

    std.debug.print("C ABI XMSS^MT signer: ok\n", .{});
}

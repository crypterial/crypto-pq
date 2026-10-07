const std = @import("std");
const builtin = @import("builtin");
const vectors = @import("vectors");

const capi = @import("capi.zig");
const pq = @import("root.zig");

const testing = std.testing;

const Allocator = std.mem.Allocator;

const common = capi.common;

const ok = common.ok;

// The tests call the exported functions as a C caller does: pointers and lengths, slots in memory
// of their own, and status codes.

const kem_ids = [_]pq.KemAlgorithm{ pq.ml_kem_512, pq.ml_kem_768, pq.ml_kem_1024, pq.x_wing };

const signature_ids = [_]pq.SignatureAlgorithm{
    pq.ml_dsa_44,
    pq.ml_dsa_65,
    pq.ml_dsa_87,
    pq.slh_dsa_sha2_128s,
    pq.slh_dsa_sha2_128f,
    pq.slh_dsa_sha2_192s,
    pq.slh_dsa_sha2_192f,
    pq.slh_dsa_sha2_256s,
    pq.slh_dsa_sha2_256f,
    pq.slh_dsa_shake_128s,
    pq.slh_dsa_shake_128f,
    pq.slh_dsa_shake_192s,
    pq.slh_dsa_shake_192f,
    pq.slh_dsa_shake_256s,
    pq.slh_dsa_shake_256f,
};

const status_names = [_][]const u8{ "INVALID_LENGTH", "INVALID_ENCODING", "ALGORITHM_MISMATCH", "INVALID_PUBLIC_KEY", "INVALID_PRIVATE_KEY", "INVALID_CONTEXT", "INVALID_OPTION", "RNG_FAILURE", "SELF_TEST_FAILED", "KEY_EXHAUSTED", "STATE_PERSIST_FAILED", "STATE_CONFLICT", "UNSUPPORTED" };

fn statusName(status: c_int) []const u8 {
    if (status >= 1 and status <= status_names.len) return status_names[@intCast(status - 1)];

    return switch (status) {
        ok => "ok",
        common.rejected => "false",
        common.bad_argument => "BAD_ARGUMENT",
        common.bad_slot => "BAD_SLOT",
        common.out_of_memory => "OUT_OF_MEMORY",
        common.busy => "BUSY",
        else => "?",
    };
}

fn expectStatus(expected: c_int, actual: c_int) !void {
    if (expected != actual) {
        std.debug.print("expected {s}, got {s}\n", .{ statusName(expected), statusName(actual) });

        return error.TestUnexpectedResult;
    }
}

// Memory for one slot, aligned as the ABI requires and filled with garbage, as fresh memory of the
// caller may be.
const Memory = struct {
    bytes: []align(common.slot_alignment) u8,
    allocator: Allocator,

    fn init(allocator: Allocator, slot_type: common.SlotType, algorithm: u32) !Memory {
        const size = capi.slotSize(@intFromEnum(slot_type), algorithm);

        try testing.expect(size > 0);

        try testing.expectEqual(common.slot_alignment, capi.slotAlign(@intFromEnum(slot_type), algorithm));

        const bytes = try allocator.alignedAlloc(u8, .fromByteUnits(common.slot_alignment), size);

        @memset(bytes, 0xa5);

        return .{ .bytes = bytes, .allocator = allocator };
    }

    fn deinit(self: Memory) void {
        self.allocator.free(self.bytes);
    }

    fn ptr(self: Memory) [*]u8 {
        return self.bytes.ptr;
    }

    fn len(self: Memory) usize {
        return self.bytes.len;
    }

    fn wipe(self: Memory) !void {
        try expectStatus(ok, capi.slotWipe(self.ptr(), self.len()));
    }

    fn info(self: Memory) ![3]u32 {
        var out: [3]u32 = undefined;

        try expectStatus(ok, capi.slotInfo(self.ptr(), self.len(), &out));

        return out;
    }
};

fn pattern(comptime size: usize, first: u8) [size]u8 {
    @setEvalBranchQuota(100000);

    var out: [size]u8 = undefined;

    for (&out, 0..) |*b, i| b.* = first +% @as(u8, @truncate(i *% 31));

    return out;
}

// The KEM entry points over slices.
const Kem = struct {
    fn keygen(id: u32, seed: []const u8, flags: u32, slot: Memory) c_int {
        return capi.kem.keygen(id, seed.ptr, seed.len, flags, slot.ptr(), slot.len());
    }

    fn importPublic(id: u32, key: []const u8, slot: Memory) c_int {
        return capi.kem.importPublic(id, key.ptr, key.len, slot.ptr(), slot.len());
    }

    fn importPrivate(id: u32, key: []const u8, slot: Memory) c_int {
        return capi.kem.importPrivate(id, key.ptr, key.len, slot.ptr(), slot.len());
    }

    fn exportPublic(slot: Memory, out: []u8) c_int {
        return capi.kem.exportPublic(slot.ptr(), slot.len(), out.ptr, out.len);
    }

    fn exportPrivate(slot: Memory, which: u32, out: []u8) c_int {
        return capi.kem.exportPrivate(slot.ptr(), slot.len(), which, out.ptr, out.len);
    }

    fn encapsulate(slot: Memory, randomness: []const u8, ciphertext: []u8, secret: []u8) c_int {
        return capi.kem.encapsulate(slot.ptr(), slot.len(), randomness.ptr, randomness.len, ciphertext.ptr, ciphertext.len, secret.ptr, secret.len);
    }

    fn decapsulate(slot: Memory, ciphertext: []const u8, secret: []u8) c_int {
        return capi.kem.decapsulate(slot.ptr(), slot.len(), ciphertext.ptr, ciphertext.len, secret.ptr, secret.len);
    }

    fn publicFromPrivate(private: Memory, public: Memory) c_int {
        return capi.kem.publicFromPrivate(private.ptr(), private.len(), public.ptr(), public.len());
    }
};

const Sig = struct {
    fn keygen(id: u32, seed: []const u8, flags: u32, slot: Memory) c_int {
        return capi.signature.keygen(id, seed.ptr, seed.len, flags, slot.ptr(), slot.len());
    }

    fn importPublic(id: u32, key: []const u8, slot: Memory) c_int {
        return capi.signature.importPublic(id, key.ptr, key.len, slot.ptr(), slot.len());
    }

    fn importPrivate(id: u32, key: []const u8, slot: Memory) c_int {
        return capi.signature.importPrivate(id, key.ptr, key.len, slot.ptr(), slot.len());
    }

    fn exportPublic(slot: Memory, out: []u8) c_int {
        return capi.signature.exportPublic(slot.ptr(), slot.len(), out.ptr, out.len);
    }

    fn exportPrivate(slot: Memory, which: u32, out: []u8) c_int {
        return capi.signature.exportPrivate(slot.ptr(), slot.len(), which, out.ptr, out.len);
    }

    fn sign(slot: Memory, message: []const u8, context: []const u8, pre_hash: u32, randomness: []const u8, flags: u32, out: []u8) c_int {
        return capi.signature.sign(slot.ptr(), slot.len(), message.ptr, message.len, context.ptr, context.len, pre_hash, randomness.ptr, randomness.len, flags, out.ptr, out.len);
    }

    fn verify(slot: Memory, signature: []const u8, message: []const u8, context: []const u8, pre_hash: u32, flags: u32) c_int {
        return capi.signature.verify(slot.ptr(), slot.len(), signature.ptr, signature.len, message.ptr, message.len, context.ptr, context.len, pre_hash, flags);
    }

    fn publicFromPrivate(private: Memory, public: Memory) c_int {
        return capi.signature.publicFromPrivate(private.ptr(), private.len(), public.ptr(), public.len());
    }
};

fn kemSeedSize(id: u32) usize {
    return if (id == 3) 32 else 64;
}

fn kemRandomnessSize(id: u32) usize {
    return if (id == 3) 64 else 32;
}

// Codes 1-13 are the errors in the order errors.zig declares them, named as every crypto-pq names
// them.
test "the status codes follow errors.zig" {
    var lines = std.mem.tokenizeAny(u8, @embedFile("errors.zig"), " \n,");

    var count: usize = 0;

    while (lines.next()) |token| {
        inline for (@typeInfo(pq.Error).error_set.?) |e| {
            if (std.mem.eql(u8, token, e.name)) {
                count += 1;

                try testing.expectEqual(@as(c_int, @intCast(count)), common.code(@field(pq.Error, e.name)));

                var name: [32]u8 = undefined;

                var length: usize = 0;

                for (e.name, 0..) |c, i| {
                    if (i > 0 and std.ascii.isUpper(c)) {
                        name[length] = '_';

                        length += 1;
                    }

                    name[length] = std.ascii.toUpper(c);

                    length += 1;
                }

                try testing.expectEqualStrings(status_names[count - 1], name[0..length]);
            }
        }
    }

    try testing.expectEqual(status_names.len, count);

    try testing.expectEqual(status_names.len, @typeInfo(pq.Error).error_set.?.len);
}

test "slot sizes and alignment" {
    for (0..4) |id| {
        for ([_]common.SlotType{ .kem_public, .kem_private }) |t| {
            try testing.expect(capi.slotSize(@intFromEnum(t), @intCast(id)) > 0);
        }
    }

    for (0..15) |id| {
        for ([_]common.SlotType{ .signature_public, .signature_private }) |t| {
            try testing.expect(capi.slotSize(@intFromEnum(t), @intCast(id)) > 0);
        }
    }

    for ([_]struct { common.SlotType, u32 }{ .{ .hasher, 19 }, .{ .xof, 6 }, .{ .hmac, 8 }, .{ .configured_hash, 19 }, .{ .configured_xof, 6 }, .{ .configured_mac, 8 } }) |entry| {
        for (0..entry[1]) |id| try testing.expect(capi.slotSize(@intFromEnum(entry[0]), @intCast(id)) > 0);

        try testing.expectEqual(0, capi.slotSize(@intFromEnum(entry[0]), entry[1]));
    }

    try testing.expectEqual(0, capi.slotSize(@intFromEnum(common.SlotType.kem_public), 4));

    try testing.expectEqual(0, capi.slotSize(@intFromEnum(common.SlotType.signature_private), 15));

    try testing.expectEqual(0, capi.slotSize(0, 0));

    try testing.expectEqual(0, capi.slotSize(99, 0));

    try testing.expectEqual(0, capi.slotAlign(99, 0));

    try testing.expectEqual(1, capi.abiVersion());

    var text: [256]u8 = undefined;

    const length = capi.buildInfo(&text, text.len);

    try testing.expect(length > 0 and length <= text.len);

    try testing.expect(std.mem.startsWith(u8, text[0..length], "crypto-pq abi 1; zig 0.16.0;"));

    try testing.expectEqual(length, capi.buildInfo(null, 0));
}

test "KEM through the ABI equals the core" {
    inline for (kem_ids, 0..) |algorithm, id| {
        const seed = pattern(64, id);

        const randomness = pattern(64, 100 + id);

        var pair = try pq.hazmat.generateKemKeyPair(algorithm, testing.allocator, seed[0..kemSeedSize(id)]);

        defer pair.private_key.deinit();

        defer pair.public_key.deinit();

        const expected = try pq.hazmat.encapsulate(&pair.public_key, randomness[0..kemRandomnessSize(id)]);

        const core_public = try pair.public_key.exportKey(testing.allocator, .raw);

        defer testing.allocator.free(core_public);

        for ([_]u32{ 0, capi.kem.fill_cache }) |flags| {
            const private = try Memory.init(testing.allocator, .kem_private, id);

            defer private.deinit();

            try expectStatus(ok, Kem.keygen(id, seed[0..kemSeedSize(id)], flags, private));

            try testing.expectEqual([3]u32{ 2, id, 1 | @as(u32, if (flags != 0) 256 else 0) }, try private.info());

            var public_key: [algorithm.public_key_size]u8 = undefined;

            try expectStatus(ok, Kem.exportPublic(private, &public_key));

            try testing.expectEqualSlices(u8, core_public, &public_key);

            var exported_seed: [64]u8 = undefined;

            try expectStatus(ok, Kem.exportPrivate(private, capi.kem.export_seed, exported_seed[0..kemSeedSize(id)]));

            try testing.expectEqualSlices(u8, seed[0..kemSeedSize(id)], exported_seed[0..kemSeedSize(id)]);

            const public = try Memory.init(testing.allocator, .kem_public, id);

            defer public.deinit();

            try expectStatus(ok, Kem.importPublic(id, &public_key, public));

            try testing.expectEqual([3]u32{ 1, id, 0 }, try public.info());

            for ([_]Memory{ public, private }) |encapsulator| {
                var ciphertext: [algorithm.ciphertext_size]u8 = undefined;

                var secret: [32]u8 = undefined;

                try expectStatus(ok, Kem.encapsulate(encapsulator, randomness[0..kemRandomnessSize(id)], &ciphertext, &secret));

                try testing.expectEqualSlices(u8, expected.ciphertext(), &ciphertext);

                try testing.expectEqualSlices(u8, &expected.shared_secret, &secret);

                var decapsulated: [32]u8 = undefined;

                try expectStatus(ok, Kem.decapsulate(private, &ciphertext, &decapsulated));

                try testing.expectEqualSlices(u8, &secret, &decapsulated);

                ciphertext[1] ^= 4;

                const implicit = try pair.private_key.decapsulate(&ciphertext);

                try expectStatus(ok, Kem.decapsulate(private, &ciphertext, &decapsulated));

                try testing.expectEqualSlices(u8, &implicit, &decapsulated);
            }

            try testing.expectEqual(@as(u32, 256), (try public.info())[2] & 256);

            try testing.expectEqual(@as(u32, 256), (try private.info())[2] & 256);

            try expectStatus(ok, capi.kem.selfTest(private.ptr(), private.len(), &randomness, kemRandomnessSize(id)));

            // The derived public slot brings the filled cache along and encapsulates the same way.
            const derived = try Memory.init(testing.allocator, .kem_public, id);

            defer derived.deinit();

            try expectStatus(ok, Kem.publicFromPrivate(private, derived));

            try testing.expectEqual([3]u32{ 1, id, 256 }, try derived.info());

            var again: [algorithm.public_key_size]u8 = undefined;

            try expectStatus(ok, Kem.exportPublic(derived, &again));

            try testing.expectEqualSlices(u8, &public_key, &again);

            try private.wipe();

            for (private.bytes) |b| try testing.expectEqual(0, b);
        }

        if (id != 3) {
            const dk = pair.private_key.secret.dk[0 .. 2 * algorithm.public_key_size + 32];

            const expanded = try Memory.init(testing.allocator, .kem_private, id);

            defer expanded.deinit();

            try expectStatus(ok, Kem.importPrivate(id, dk, expanded));

            try testing.expectEqual([3]u32{ 2, id, 0 }, try expanded.info());

            var out: [3200]u8 = undefined;

            try expectStatus(ok, Kem.exportPrivate(expanded, capi.kem.export_expanded, out[0..dk.len]));

            try testing.expectEqualSlices(u8, dk, out[0..dk.len]);

            try expectStatus(common.code(error.Unsupported), Kem.exportPrivate(expanded, capi.kem.export_seed, out[0..64]));

            var ciphertext: [algorithm.ciphertext_size]u8 = expected.ciphertext()[0..algorithm.ciphertext_size].*;

            var secret: [32]u8 = undefined;

            try expectStatus(ok, Kem.decapsulate(expanded, &ciphertext, &secret));

            try testing.expectEqualSlices(u8, &expected.shared_secret, &secret);

            const seeded = try Memory.init(testing.allocator, .kem_private, id);

            defer seeded.deinit();

            try expectStatus(ok, Kem.importPrivate(id, seed[0..64], seeded));

            try expectStatus(ok, Kem.exportPrivate(seeded, capi.kem.export_expanded, out[0..dk.len]));

            try testing.expectEqualSlices(u8, dk, out[0..dk.len]);
        }
    }
}

test "KEM rejections" {
    const allocator = testing.allocator;

    const seed = pattern(64, 1);

    const randomness = pattern(64, 2);

    const private = try Memory.init(allocator, .kem_private, 1);

    defer private.deinit();

    const public = try Memory.init(allocator, .kem_public, 1);

    defer public.deinit();

    const small = try Memory.init(allocator, .kem_private, 0);

    defer small.deinit();

    // Unknown algorithms, flags, lengths and memory for a slot.
    try expectStatus(common.bad_argument, Kem.keygen(4, &seed, 0, private));

    try expectStatus(common.bad_argument, Kem.keygen(1, &seed, 2, private));

    try expectStatus(common.code(error.InvalidLength), Kem.keygen(1, seed[0..63], 0, private));

    const x_wing_seeded = try Memory.init(allocator, .kem_private, 3);

    defer x_wing_seeded.deinit();

    try expectStatus(common.code(error.InvalidLength), Kem.keygen(3, seed[0..64], 0, x_wing_seeded));

    try expectStatus(common.bad_argument, capi.kem.keygen(1, null, 64, 0, private.ptr(), private.len()));

    try expectStatus(common.bad_slot, Kem.keygen(1, &seed, 0, small));

    try expectStatus(common.bad_slot, capi.kem.keygen(1, &seed, 64, 0, null, private.len()));

    try expectStatus(common.bad_slot, capi.kem.keygen(1, &seed, 64, 0, private.ptr() + 8, private.len() - 16));

    try expectStatus(common.bad_slot, capi.kem.keygen(1, &seed, 64, 0, private.ptr(), private.len() - 16));

    try expectStatus(ok, Kem.keygen(1, &seed, 0, private));

    // A live slot is never overwritten.
    try expectStatus(common.bad_slot, Kem.keygen(1, &seed, 0, private));

    try expectStatus(common.bad_slot, Kem.importPublic(1, private.bytes[0..1184], private));

    var public_key: [1184]u8 = undefined;

    try expectStatus(ok, Kem.exportPublic(private, &public_key));

    try expectStatus(common.bad_argument, Kem.exportPublic(private, public_key[0..1183]));

    try expectStatus(common.bad_argument, capi.kem.exportPublic(private.ptr(), private.len(), null, 1184));

    try expectStatus(common.code(error.InvalidLength), Kem.importPublic(1, public_key[0..1183], public));

    var bad_key = public_key;

    bad_key[0] = 0xff;

    bad_key[1] = 0xff;

    try expectStatus(common.code(error.InvalidPublicKey), Kem.importPublic(1, &bad_key, public));

    try expectStatus(ok, Kem.importPublic(1, &public_key, public));

    var ciphertext: [1088]u8 = undefined;

    var secret: [32]u8 = undefined;

    try expectStatus(common.code(error.InvalidLength), Kem.encapsulate(public, randomness[0..31], &ciphertext, &secret));

    try expectStatus(common.bad_argument, Kem.encapsulate(public, randomness[0..32], ciphertext[0..1087], &secret));

    try expectStatus(common.bad_argument, Kem.encapsulate(public, randomness[0..32], &ciphertext, secret[0..31]));

    // Outputs may not overlap each other, the inputs or the slot.
    try expectStatus(common.bad_argument, Kem.encapsulate(public, ciphertext[0..32], &ciphertext, &secret));

    try expectStatus(common.bad_argument, Kem.encapsulate(public, randomness[0..32], &ciphertext, ciphertext[1000..1032]));

    try expectStatus(common.bad_argument, Kem.encapsulate(public, randomness[0..32], &ciphertext, public.bytes[64..96]));

    try expectStatus(ok, Kem.encapsulate(public, randomness[0..32], &ciphertext, &secret));

    try expectStatus(common.code(error.InvalidLength), Kem.decapsulate(private, ciphertext[0..1087], &secret));

    try expectStatus(common.code(error.InvalidLength), Kem.decapsulate(private, &.{}, &secret));

    try expectStatus(common.bad_argument, Kem.decapsulate(private, &ciphertext, secret[0..16]));

    try expectStatus(common.bad_argument, Kem.decapsulate(private, &ciphertext, ciphertext[0..32]));

    // A public slot cannot decapsulate; a signature slot is no KEM slot; neither is garbage.
    try expectStatus(common.bad_slot, Kem.decapsulate(public, &ciphertext, &secret));

    try expectStatus(common.bad_slot, Kem.exportPrivate(public, capi.kem.export_seed, secret[0..32]));

    const signature_slot = try Memory.init(allocator, .signature_public, 0);

    defer signature_slot.deinit();

    try expectStatus(ok, Sig.importPublic(0, &pattern(1312, 3), signature_slot));

    try expectStatus(common.bad_slot, capi.kem.encapsulate(signature_slot.ptr(), signature_slot.len(), &randomness, 32, &ciphertext, 1088, &secret, 32));

    try expectStatus(common.bad_slot, Kem.decapsulate(small, &ciphertext, &secret));

    // The wrong memory length for a live slot, or the slot seen at another address.
    try expectStatus(common.bad_slot, capi.kem.decapsulate(private.ptr(), private.len() - 16, &ciphertext, 1088, &secret, 32));

    try expectStatus(common.bad_slot, capi.kem.decapsulate(private.ptr() + 16, private.len() - 16, &ciphertext, 1088, &secret, 32));

    try expectStatus(common.bad_slot, capi.kem.decapsulate(private.ptr() + 1, private.len(), &ciphertext, 1088, &secret, 32));

    // A header claiming another algorithm than its memory fits.
    const header: *common.Header = @ptrCast(private.bytes.ptr);

    header.algorithm = 2;

    try expectStatus(common.bad_slot, Kem.decapsulate(private, &ciphertext, &secret));

    header.algorithm = 1;

    try expectStatus(ok, Kem.decapsulate(private, &ciphertext, &secret));

    try expectStatus(common.bad_argument, Kem.exportPrivate(private, 2, secret[0..32]));

    try expectStatus(common.bad_argument, capi.kem.selfTest(private.ptr(), private.len(), private.ptr() + 64, 32));

    try expectStatus(common.code(error.InvalidLength), capi.kem.selfTest(private.ptr(), private.len(), &randomness, 33));

    // A wiped slot is refused everywhere, and may then be used again.
    try private.wipe();

    try expectStatus(common.bad_slot, Kem.decapsulate(private, &ciphertext, &secret));

    try expectStatus(common.bad_slot, Kem.exportPublic(private, &public_key));

    try expectStatus(ok, Kem.importPrivate(1, &seed, private));

    // X-Wing has no expanded key; an expanded ML-KEM key must pass the FIPS 203 checks.
    const x_wing = try Memory.init(allocator, .kem_private, 3);

    defer x_wing.deinit();

    try expectStatus(common.code(error.InvalidLength), Kem.importPrivate(3, &pattern(2400, 1), x_wing));

    try expectStatus(ok, Kem.importPrivate(3, seed[0..32], x_wing));

    try expectStatus(common.code(error.Unsupported), Kem.exportPrivate(x_wing, capi.kem.export_expanded, secret[0..32]));

    var dk: [2400]u8 = undefined;

    try expectStatus(ok, Kem.exportPrivate(private, capi.kem.export_expanded, &dk));

    dk[2400 - 64] ^= 1;

    try private.wipe();

    try expectStatus(common.code(error.InvalidPrivateKey), Kem.importPrivate(1, &dk, private));

    // A refused import leaves the memory wiped, not half a key.
    for (private.bytes) |b| try testing.expectEqual(0, b);

    try expectStatus(common.code(error.InvalidLength), Kem.importPrivate(1, dk[0..2399], private));

    try expectStatus(common.bad_slot, Kem.publicFromPrivate(x_wing, public));

    try public.wipe();

    try expectStatus(common.bad_slot, Kem.publicFromPrivate(x_wing, public));

    try expectStatus(ok, Kem.importPrivate(1, &seed, private));

    try expectStatus(ok, Kem.publicFromPrivate(private, public));

    try expectStatus(common.bad_slot, Kem.publicFromPrivate(public, private));
}

test "signatures through the ABI equal the core" {
    const allocator = testing.allocator;

    const message = "crypto-pq C ABI";

    inline for (signature_ids, 0..) |algorithm, id| {
        // SLH-DSA "s" sets sign slowly in Debug builds; one of each family runs every mode.
        const thorough = id == 0 or id == 4 or id == 10 or builtin.mode != .Debug;

        if (thorough) {
            const seed = pattern(96, 7 + id);

            const seed_size = capi.signature.Set(id).seed_size;

            const randomness = pattern(32, 50);

            const randomness_size = capi.signature.Set(id).randomness_size;

            var pair = try pq.hazmat.generateSignatureKeyPair(algorithm, allocator, seed[0..seed_size]);

            defer pair.private_key.deinit();

            defer pair.public_key.deinit();

            const core_public = try pair.public_key.exportKey(allocator, .raw);

            defer allocator.free(core_public);

            const core_private = try pair.private_key.exportKey(allocator, .raw);

            defer allocator.free(core_private);

            const private = try Memory.init(allocator, .signature_private, id);

            defer private.deinit();

            try expectStatus(ok, Sig.keygen(id, seed[0..seed_size], 0, private));

            var public_key: [algorithm.public_key_size]u8 = undefined;

            try expectStatus(ok, Sig.exportPublic(private, &public_key));

            try testing.expectEqualSlices(u8, core_public, &public_key);

            const ml_dsa = id < 3;

            var secret: [4896]u8 = undefined;

            const exported = secret[0..core_private.len];

            try expectStatus(ok, Sig.exportPrivate(private, if (ml_dsa) capi.signature.export_seed else capi.signature.export_private, exported));

            try testing.expectEqualSlices(u8, core_private, exported);

            const signature = try allocator.alloc(u8, algorithm.signature_size);

            defer allocator.free(signature);

            const public = try Memory.init(allocator, .signature_public, id);

            defer public.deinit();

            try expectStatus(ok, Sig.importPublic(id, &public_key, public));

            // Deterministic, hedged with given randomness, with a context and a pre-hash.
            const expected_deterministic = try pair.private_key.sign(allocator, message, .{ .deterministic = true, .context = "ctx" });

            defer allocator.free(expected_deterministic);

            try expectStatus(ok, Sig.sign(private, message, "ctx", 0, &.{}, capi.signature.deterministic, signature));

            try testing.expectEqualSlices(u8, expected_deterministic, signature);

            try expectStatus(ok, Sig.verify(public, signature, message, "ctx", 0, 0));

            try expectStatus(ok, Sig.verify(private, signature, message, "ctx", 0, 0));

            try expectStatus(common.rejected, Sig.verify(public, signature, message, "ctz", 0, 0));

            const expected_hazmat = try pq.hazmat.sign(&pair.private_key, allocator, message, randomness[0..randomness_size], .{ .pre_hash = .{ .hash = pq.sha_512 } });

            defer allocator.free(expected_hazmat);

            try expectStatus(ok, Sig.sign(private, message, "", 4, randomness[0..randomness_size], 0, signature));

            try testing.expectEqualSlices(u8, expected_hazmat, signature);

            try expectStatus(ok, Sig.verify(public, signature, message, "", 4, 0));

            try expectStatus(common.rejected, Sig.verify(public, signature, message, "", 0, 0));

            signature[signature.len / 2] ^= 1;

            try expectStatus(common.rejected, Sig.verify(public, signature, message, "", 4, 0));

            // A pre-hash weaker than the algorithm signs only as hazmat, and verifies only so.
            const weak_expected = try pq.hazmat.sign(&pair.private_key, allocator, message, randomness[0..randomness_size], .{ .pre_hash = .{ .hash = pq.sha_224 } });

            defer allocator.free(weak_expected);

            try expectStatus(common.code(error.InvalidOption), Sig.sign(private, message, "", 1, randomness[0..randomness_size], 0, signature));

            try expectStatus(ok, Sig.sign(private, message, "", 1, randomness[0..randomness_size], capi.signature.hazmat, signature));

            try testing.expectEqualSlices(u8, weak_expected, signature);

            try expectStatus(common.rejected, Sig.verify(public, signature, message, "", 1, 0));

            try expectStatus(ok, Sig.verify(public, signature, message, "", 1, capi.signature.hazmat));

            try testing.expect(pq.hazmat.verify(&pair.public_key, signature, message, .{ .pre_hash = .{ .hash = pq.sha_224 } }));

            const derived = try Memory.init(allocator, .signature_public, id);

            defer derived.deinit();

            try expectStatus(ok, Sig.publicFromPrivate(private, derived));

            try expectStatus(ok, Sig.verify(derived, signature, message, "", 1, capi.signature.hazmat));

            if (ml_dsa) {
                try testing.expectEqual(@as(u32, 256 | 512 | 1), (try private.info())[2]);

                try testing.expectEqual(@as(u32, 256), (try derived.info())[2]);

                // The expanded key imports and signs the same way.
                const expanded = try Memory.init(allocator, .signature_private, id);

                defer expanded.deinit();

                const sk = pair.private_key.secret.bytes[0..switch (id) {
                    0 => 2560,
                    1 => 4032,
                    else => 4896,
                }];

                try expectStatus(ok, Sig.importPrivate(id, sk, expanded));

                try expectStatus(ok, Sig.sign(expanded, message, "ctx", 0, &.{}, capi.signature.deterministic, signature));

                try testing.expectEqualSlices(u8, expected_deterministic, signature);

                try expectStatus(ok, Sig.exportPrivate(expanded, capi.signature.export_private, secret[0..sk.len]));

                try testing.expectEqualSlices(u8, sk, secret[0..sk.len]);

                try expectStatus(common.code(error.Unsupported), Sig.exportPrivate(expanded, capi.signature.export_seed, secret[0..32]));

                try testing.expectEqual(@as(u32, 0), (try expanded.info())[2] & 1);
            } else {
                try expectStatus(common.code(error.Unsupported), Sig.exportPrivate(private, capi.signature.export_seed, secret[0..seed_size]));

                const imported = try Memory.init(allocator, .signature_private, id);

                defer imported.deinit();

                try expectStatus(ok, Sig.importPrivate(id, core_private, imported));

                try expectStatus(ok, Sig.sign(imported, message, "ctx", 0, &.{}, capi.signature.deterministic, signature));

                try testing.expectEqualSlices(u8, expected_deterministic, signature);
            }
        }
    }
}

test "signature rejections" {
    const allocator = testing.allocator;

    const seed = pattern(96, 9);

    const randomness = pattern(32, 10);

    const private = try Memory.init(allocator, .signature_private, 0);

    defer private.deinit();

    const public = try Memory.init(allocator, .signature_public, 0);

    defer public.deinit();

    try expectStatus(common.bad_argument, Sig.keygen(15, seed[0..32], 0, private));

    try expectStatus(common.bad_argument, Sig.keygen(0, seed[0..32], 4, private));

    try expectStatus(common.code(error.InvalidLength), Sig.keygen(0, seed[0..31], 0, private));

    try expectStatus(ok, Sig.keygen(0, seed[0..32], 0, private));

    var signature: [2420]u8 = undefined;

    const message = "m";

    // Randomness with the deterministic flag, unknown flags or pre-hashes, lengths.
    try expectStatus(common.bad_argument, Sig.sign(private, message, "", 0, &randomness, capi.signature.deterministic, &signature));

    try expectStatus(common.bad_argument, Sig.sign(private, message, "", 0, &randomness, 4, &signature));

    try expectStatus(common.bad_argument, Sig.sign(private, message, "", 13, &randomness, 0, &signature));

    try expectStatus(common.code(error.InvalidLength), Sig.sign(private, message, "", 0, randomness[0..31], 0, &signature));

    try expectStatus(common.code(error.InvalidLength), Sig.sign(private, message, "", 0, &.{}, 0, &signature));

    try expectStatus(common.bad_argument, Sig.sign(private, message, "", 0, &randomness, 0, signature[0..2419]));

    try expectStatus(common.code(error.InvalidContext), Sig.sign(private, message, &pattern(256, 1), 0, &randomness, 0, &signature));

    try expectStatus(ok, Sig.sign(private, message, &pattern(255, 1), 0, &randomness, 0, &signature));

    // The signature output overlapping the message or the slot.
    try expectStatus(common.bad_argument, Sig.sign(private, signature[0..10], "", 0, &randomness, 0, &signature));

    try expectStatus(common.bad_argument, capi.signature.sign(private.ptr(), private.len(), "m", 1, null, 0, 0, &randomness, 32, 0, private.ptr() + 64, 2420));

    try expectStatus(common.bad_argument, capi.signature.sign(private.ptr(), private.len(), null, 1, null, 0, 0, &randomness, 32, 0, &signature, 2420));

    try expectStatus(ok, Sig.sign(private, message, "", 0, &randomness, 0, &signature));

    try expectStatus(ok, Sig.publicFromPrivate(private, public));

    try expectStatus(ok, Sig.verify(public, &signature, message, "", 0, 0));

    try expectStatus(common.rejected, Sig.verify(public, signature[0..2419], message, "", 0, 0));

    try expectStatus(common.rejected, Sig.verify(public, &signature, message, &pattern(256, 1), 0, 0));

    try expectStatus(common.bad_argument, Sig.verify(public, &signature, message, "", 13, 0));

    try expectStatus(common.bad_argument, Sig.verify(public, &signature, message, "", 0, capi.signature.deterministic));

    try expectStatus(common.bad_slot, Sig.sign(public, message, "", 0, &randomness, 0, &signature));

    // An expanded key whose parts disagree, or an SLH-DSA key whose root is not its own.
    var sk: [2560]u8 = undefined;

    try expectStatus(ok, Sig.exportPrivate(private, capi.signature.export_private, &sk));

    sk[200] ^= 1;

    const other = try Memory.init(allocator, .signature_private, 0);

    defer other.deinit();

    try expectStatus(common.code(error.InvalidPrivateKey), Sig.importPrivate(0, &sk, other));

    for (other.bytes) |b| try testing.expectEqual(0, b);

    try expectStatus(common.code(error.InvalidLength), Sig.importPrivate(0, sk[0..2559], other));

    const slh = try Memory.init(allocator, .signature_private, 4);

    defer slh.deinit();

    var slh_key = pattern(64, 4);

    try expectStatus(common.code(error.InvalidPrivateKey), Sig.importPrivate(4, &slh_key, slh));

    try expectStatus(common.code(error.InvalidLength), Sig.importPrivate(4, slh_key[0..48], slh));

    const slh_public = try Memory.init(allocator, .signature_public, 4);

    defer slh_public.deinit();

    try expectStatus(common.code(error.InvalidLength), Sig.importPublic(4, slh_key[0..33], slh_public));

    try expectStatus(common.bad_slot, Sig.importPublic(4, slh_key[0..32], public));

    try expectStatus(common.bad_argument, Sig.exportPrivate(private, 2, &sk));

    try private.wipe();

    try expectStatus(common.bad_slot, Sig.sign(private, message, "", 0, &randomness, 0, &signature));

    try expectStatus(common.bad_slot, Sig.verify(private, &signature, message, "", 0, 0));
}

const hash_ids = capi.hash.algorithms;

const mac_ids = capi.hash.macs;

// Keys of every kind of length that a MAC takes: none, short, longer than a block for HMAC and
// KMAC; one byte, short and the longest for BLAKE2.
fn keyLengths(algorithm: pq.MacAlgorithm) [3]usize {
    return switch (algorithm.kind) {
        .blake2b => .{ 1, 20, 64 },
        .blake2s => .{ 1, 20, 32 },
        else => .{ 0, 20, 200 },
    };
}

test "hashes, XOFs and MACs through the ABI equal the core" {
    const allocator = testing.allocator;

    const data = pattern(1000, 3);

    for (hash_ids, 0..) |algorithm, id| {
        var expected: [64]u8 = undefined;

        algorithm.digest(&data, expected[0..algorithm.digest_size]);

        var out: [64]u8 = undefined;

        try expectStatus(ok, capi.hash.digest(@intCast(id), &data, data.len, &out, algorithm.digest_size));

        try testing.expectEqualSlices(u8, expected[0..algorithm.digest_size], out[0..algorithm.digest_size]);

        try expectStatus(common.bad_argument, capi.hash.digest(@intCast(id), &data, data.len, &out, algorithm.digest_size + 1));

        const state = try Memory.init(allocator, .hasher, @intCast(id));

        defer state.deinit();

        try expectStatus(ok, capi.hash.init(@intCast(id), state.ptr(), state.len()));

        try expectStatus(ok, capi.hash.update(state.ptr(), state.len(), &data, 1));

        try expectStatus(ok, capi.hash.update(state.ptr(), state.len(), null, 0));

        try expectStatus(ok, capi.hash.update(state.ptr(), state.len(), data[1..].ptr, 499));

        // The final digest leaves the state as it was.
        var partial: [64]u8 = undefined;

        try expectStatus(ok, capi.hash.final(state.ptr(), state.len(), &partial, algorithm.digest_size));

        algorithm.digest(data[0..500], expected[0..algorithm.digest_size]);

        try testing.expectEqualSlices(u8, expected[0..algorithm.digest_size], partial[0..algorithm.digest_size]);

        try expectStatus(ok, capi.hash.update(state.ptr(), state.len(), data[500..].ptr, 500));

        try expectStatus(ok, capi.hash.final(state.ptr(), state.len(), &out, algorithm.digest_size));

        algorithm.digest(&data, expected[0..algorithm.digest_size]);

        try testing.expectEqualSlices(u8, expected[0..algorithm.digest_size], out[0..algorithm.digest_size]);

        try expectStatus(common.bad_argument, capi.hash.final(state.ptr(), state.len(), &out, 3));

        try expectStatus(common.bad_argument, capi.hash.update(state.ptr(), state.len(), state.ptr() + 8, 8));

        try testing.expectEqual([3]u32{ 5, @intCast(id), 0 }, try state.info());
    }

    try expectStatus(common.bad_argument, capi.hash.digest(hash_ids.len, &data, data.len, null, 0));

    inline for (capi.hash.xofs, 0..) |algorithm, id| {
        var expected: [300]u8 = undefined;

        algorithm.digest(&data, &expected);

        var out: [300]u8 = undefined;

        try expectStatus(ok, capi.hash.xof(id, &data, data.len, &out, out.len));

        try testing.expectEqualSlices(u8, &expected, &out);

        const state = try Memory.init(allocator, .xof, id);

        defer state.deinit();

        try expectStatus(ok, capi.hash.xofInit(id, state.ptr(), state.len()));

        try expectStatus(ok, capi.hash.xofUpdate(state.ptr(), state.len(), &data, 700));

        try expectStatus(ok, capi.hash.xofUpdate(state.ptr(), state.len(), data[700..].ptr, 300));

        try expectStatus(ok, capi.hash.xofRead(state.ptr(), state.len(), &out, 1));

        try expectStatus(ok, capi.hash.xofRead(state.ptr(), state.len(), out[1..].ptr, 299));

        try testing.expectEqualSlices(u8, &expected, &out);

        // Reading has begun: an update is unsupported, as in every crypto-pq.
        try expectStatus(common.code(error.Unsupported), capi.hash.xofUpdate(state.ptr(), state.len(), &data, 1));

        try expectStatus(ok, capi.hash.xofRead(state.ptr(), state.len(), null, 0));
    }

    try expectStatus(common.bad_argument, capi.hash.xof(capi.hash.xofs.len, &data, data.len, null, 0));

    const key = pattern(200, 5);

    for (mac_ids, 0..) |algorithm, id| {
        for (keyLengths(algorithm)) |key_length| {
            var expected: [64]u8 = undefined;

            algorithm.digest(key[0..key_length], &data, expected[0..algorithm.digest_size]);

            var out: [64]u8 = undefined;

            try expectStatus(ok, capi.hash.hmac(@intCast(id), &key, key_length, &data, data.len, &out, algorithm.digest_size));

            try testing.expectEqualSlices(u8, expected[0..algorithm.digest_size], out[0..algorithm.digest_size]);

            try expectStatus(ok, capi.hash.hmacVerify(@intCast(id), &key, key_length, &data, data.len, &out, algorithm.digest_size));

            try expectStatus(common.rejected, capi.hash.hmacVerify(@intCast(id), &key, key_length, &data, data.len, &out, algorithm.digest_size - 1));

            out[0] ^= 1;

            try expectStatus(common.rejected, capi.hash.hmacVerify(@intCast(id), &key, key_length, &data, data.len, &out, algorithm.digest_size));

            const state = try Memory.init(allocator, .hmac, @intCast(id));

            defer state.deinit();

            try expectStatus(ok, capi.hash.hmacInit(@intCast(id), &key, key_length, state.ptr(), state.len()));

            try expectStatus(ok, capi.hash.hmacUpdate(state.ptr(), state.len(), &data, 10));

            try expectStatus(ok, capi.hash.hmacUpdate(state.ptr(), state.len(), data[10..].ptr, 990));

            try expectStatus(ok, capi.hash.hmacFinal(state.ptr(), state.len(), &out, algorithm.digest_size));

            try testing.expectEqualSlices(u8, expected[0..algorithm.digest_size], out[0..algorithm.digest_size]);

            try expectStatus(ok, capi.hash.hmacFinalVerify(state.ptr(), state.len(), &out, algorithm.digest_size));

            out[3] ^= 8;

            try expectStatus(common.rejected, capi.hash.hmacFinalVerify(state.ptr(), state.len(), &out, algorithm.digest_size));

            try expectStatus(common.bad_argument, capi.hash.hmacFinal(state.ptr(), state.len(), &out, 2));

            try state.wipe();

            try expectStatus(common.bad_slot, capi.hash.hmacUpdate(state.ptr(), state.len(), &data, 1));
        }
    }

    try expectStatus(common.bad_argument, capi.hash.hmac(mac_ids.len, &key, 1, &data, 1, null, 0));
}

// A BLAKE2 key outside 1 to 64 (BLAKE2b) or 32 (BLAKE2s) bytes is INVALID_LENGTH, and a
// verification with one says no.
test "BLAKE2 MAC keys through the ABI" {
    const key = pattern(65, 1);

    const data = "data";

    var out: [64]u8 = undefined;

    for ([_]u32{ 6, 7 }, [_]usize{ 64, 32 }) |id, max| {
        const size = mac_ids[id].digest_size;

        const state = try Memory.init(testing.allocator, .hmac, id);

        defer state.deinit();

        const spec = try Memory.init(testing.allocator, .configured_mac, id);

        defer spec.deinit();

        try expectStatus(ok, capi.hash.configureMac(id, 0, 0, null, 0, null, 0, spec.ptr(), spec.len()));

        for ([_]usize{ 0, max + 1 }) |length| {
            try expectStatus(common.code(error.InvalidLength), capi.hash.hmac(id, &key, length, data, data.len, &out, size));

            try expectStatus(common.rejected, capi.hash.hmacVerify(id, &key, length, data, data.len, &out, size));

            try expectStatus(common.code(error.InvalidLength), capi.hash.hmacInit(id, &key, length, state.ptr(), state.len()));

            try expectStatus(common.code(error.InvalidLength), capi.hash.macWith(spec.ptr(), spec.len(), &key, length, data, data.len, &out, size));

            try expectStatus(common.rejected, capi.hash.macVerifyWith(spec.ptr(), spec.len(), &key, length, data, data.len, &out, size));

            try expectStatus(common.code(error.InvalidLength), capi.hash.macInitWith(spec.ptr(), spec.len(), &key, length, state.ptr(), state.len()));
        }

        try expectStatus(ok, capi.hash.hmac(id, &key, max, data, data.len, &out, size));
    }
}

test "configured hashes, XOFs and MACs through the ABI equal the core" {
    const allocator = testing.allocator;

    const data = pattern(700, 9);

    const salt = pattern(16, 1);

    const personalization = pattern(16, 2);

    for (hash_ids, 0..) |algorithm, id| {
        const spec = try Memory.init(allocator, .configured_hash, @intCast(id));

        defer spec.deinit();

        const options = algorithm.kind == .blake2b or algorithm.kind == .blake2s;

        const width: usize = if (algorithm.kind == .blake2b) 16 else 8;

        // Options are BLAKE2's only.
        if (!options) {
            try expectStatus(common.code(error.InvalidOption), capi.hash.configureHash(@intCast(id), &salt, 1, null, 0, spec.ptr(), spec.len()));

            try expectStatus(common.code(error.InvalidOption), capi.hash.configureHash(@intCast(id), null, 0, &personalization, 1, spec.ptr(), spec.len()));
        } else {
            try expectStatus(common.code(error.InvalidOption), capi.hash.configureHash(@intCast(id), &salt, width + 1, null, 0, spec.ptr(), spec.len()));
        }

        const salt_length: usize = if (options) width else 0;

        const configured = try algorithm.configure(.{ .salt = salt[0..salt_length], .personalization = personalization[0..salt_length] });

        try expectStatus(ok, capi.hash.configureHash(@intCast(id), &salt, salt_length, &personalization, salt_length, spec.ptr(), spec.len()));

        try testing.expectEqual([3]u32{ 9, @intCast(id), 0 }, try spec.info());

        var expected: [64]u8 = undefined;

        configured.digest(&data, expected[0..algorithm.digest_size]);

        var out: [64]u8 = undefined;

        try expectStatus(ok, capi.hash.digestWith(spec.ptr(), spec.len(), &data, data.len, &out, algorithm.digest_size));

        try testing.expectEqualSlices(u8, expected[0..algorithm.digest_size], out[0..algorithm.digest_size]);

        try expectStatus(common.bad_argument, capi.hash.digestWith(spec.ptr(), spec.len(), &data, data.len, &out, algorithm.digest_size - 1));

        const state = try Memory.init(allocator, .hasher, @intCast(id));

        defer state.deinit();

        try expectStatus(ok, capi.hash.initWith(spec.ptr(), spec.len(), state.ptr(), state.len()));

        try expectStatus(ok, capi.hash.update(state.ptr(), state.len(), &data, 300));

        try expectStatus(ok, capi.hash.update(state.ptr(), state.len(), data[300..].ptr, 400));

        try expectStatus(ok, capi.hash.final(state.ptr(), state.len(), &out, algorithm.digest_size));

        try testing.expectEqualSlices(u8, expected[0..algorithm.digest_size], out[0..algorithm.digest_size]);

        // A configured slot is no state, and a state no configured slot.
        try expectStatus(common.bad_slot, capi.hash.update(spec.ptr(), spec.len(), &data, 1));

        try expectStatus(common.bad_slot, capi.hash.digestWith(state.ptr(), state.len(), &data, data.len, &out, algorithm.digest_size));
    }

    const customization = pattern(300, 4);

    inline for (capi.hash.xofs, 0..) |algorithm, id| {
        const spec = try Memory.init(allocator, .configured_xof, id);

        defer spec.deinit();

        const takes = algorithm.kind == .cshake or algorithm.kind == .ascon_cxof;

        const length: usize = if (takes) 256 else 0;

        if (!takes) try expectStatus(common.code(error.InvalidOption), capi.hash.configureXof(id, null, 0, &customization, 1, spec.ptr(), spec.len()));

        if (algorithm.kind == .ascon_cxof) try expectStatus(common.code(error.InvalidOption), capi.hash.configureXof(id, null, 0, &customization, 257, spec.ptr(), spec.len()));

        // A function name is for cSHAKE only.
        if (algorithm.kind != .cshake) try expectStatus(common.code(error.InvalidOption), capi.hash.configureXof(id, "N", 1, null, 0, spec.ptr(), spec.len()));

        const configured = if (algorithm.kind == .cshake) try pq.hazmat.configureCshake(algorithm, "N", customization[0..length]) else try algorithm.configure(.{ .customization = customization[0..length] });

        const name_length: usize = if (algorithm.kind == .cshake) 1 else 0;

        try expectStatus(ok, capi.hash.configureXof(id, "N", name_length, &customization, length, spec.ptr(), spec.len()));

        var expected: [300]u8 = undefined;

        configured.digest(&data, &expected);

        var out: [300]u8 = undefined;

        try expectStatus(ok, capi.hash.xofWith(spec.ptr(), spec.len(), &data, data.len, &out, out.len));

        try testing.expectEqualSlices(u8, &expected, &out);

        const state = try Memory.init(allocator, .xof, id);

        defer state.deinit();

        try expectStatus(ok, capi.hash.xofInitWith(spec.ptr(), spec.len(), state.ptr(), state.len()));

        try expectStatus(ok, capi.hash.xofUpdate(state.ptr(), state.len(), &data, 699));

        try expectStatus(ok, capi.hash.xofUpdate(state.ptr(), state.len(), data[699..].ptr, 1));

        try expectStatus(ok, capi.hash.xofRead(state.ptr(), state.len(), &out, 13));

        try expectStatus(ok, capi.hash.xofRead(state.ptr(), state.len(), out[13..].ptr, 287));

        try testing.expectEqualSlices(u8, &expected, &out);
    }

    const key = pattern(64, 7);

    for (mac_ids, 0..) |algorithm, id| {
        const spec = try Memory.init(allocator, .configured_mac, @intCast(id));

        defer spec.deinit();

        // Each kind's options, and a length that is not the default.
        const configured: pq.MacAlgorithm, const size: usize, const flags: u32, const first: []const u8, const second: []const u8 = switch (algorithm.kind) {
            .hmac => .{ algorithm, 0, 0, "", "" },
            .kmac => .{ try algorithm.configure(.{ .length = 100, .customization = customization[0..40], .xof = id == 5 }), 100, capi.hash.mac_length | @as(u32, if (id == 5) capi.hash.mac_xof else 0), customization[0..40], "" },
            .blake2b => .{ try algorithm.configure(.{ .length = 33, .salt = salt[0..16], .personalization = personalization[0..5] }), 33, capi.hash.mac_length, salt[0..16], personalization[0..5] },
            .blake2s => .{ try algorithm.configure(.{ .length = 17, .salt = salt[0..8], .personalization = personalization[0..8] }), 17, capi.hash.mac_length, salt[0..8], personalization[0..8] },
        };

        try expectStatus(ok, capi.hash.configureMac(@intCast(id), size, flags, first.ptr, first.len, second.ptr, second.len, spec.ptr(), spec.len()));

        const key_length: usize = if (algorithm.kind == .blake2s) 32 else 64;

        var expected: [100]u8 = undefined;

        configured.digest(key[0..key_length], &data, expected[0..configured.digest_size]);

        var out: [100]u8 = undefined;

        const tag = out[0..configured.digest_size];

        try expectStatus(ok, capi.hash.macWith(spec.ptr(), spec.len(), &key, key_length, &data, data.len, tag.ptr, tag.len));

        try testing.expectEqualSlices(u8, expected[0..configured.digest_size], tag);

        try expectStatus(ok, capi.hash.macVerifyWith(spec.ptr(), spec.len(), &key, key_length, &data, data.len, tag.ptr, tag.len));

        try expectStatus(common.rejected, capi.hash.macVerifyWith(spec.ptr(), spec.len(), &key, key_length, &data, data.len - 1, tag.ptr, tag.len));

        try expectStatus(common.bad_argument, capi.hash.macWith(spec.ptr(), spec.len(), &key, key_length, &data, data.len, tag.ptr, tag.len + 1));

        const state = try Memory.init(allocator, .hmac, @intCast(id));

        defer state.deinit();

        try expectStatus(ok, capi.hash.macInitWith(spec.ptr(), spec.len(), &key, key_length, state.ptr(), state.len()));

        try expectStatus(ok, capi.hash.hmacUpdate(state.ptr(), state.len(), &data, 500));

        try expectStatus(ok, capi.hash.hmacUpdate(state.ptr(), state.len(), data[500..].ptr, 200));

        @memset(tag, 0);

        try expectStatus(ok, capi.hash.hmacFinal(state.ptr(), state.len(), tag.ptr, tag.len));

        try testing.expectEqualSlices(u8, expected[0..configured.digest_size], tag);

        try expectStatus(ok, capi.hash.hmacFinalVerify(state.ptr(), state.len(), tag.ptr, tag.len));

        try expectStatus(common.rejected, capi.hash.hmacFinalVerify(state.ptr(), state.len(), tag.ptr, tag.len - 1));

        try expectStatus(common.bad_argument, capi.hash.hmacFinal(state.ptr(), state.len(), tag.ptr, tag.len + 1));
    }
}

test "configure through the ABI refuses what the core refuses" {
    const allocator = testing.allocator;

    const long = pattern(17, 1);

    for (mac_ids, 0..) |algorithm, id| {
        const spec = try Memory.init(allocator, .configured_mac, @intCast(id));

        defer spec.deinit();

        const invalid_option = common.code(error.InvalidOption);

        // Unknown flags, and a size without mac_length, are the binding's mistakes.
        try expectStatus(common.bad_argument, capi.hash.configureMac(@intCast(id), 0, 4, null, 0, null, 0, spec.ptr(), spec.len()));

        try expectStatus(common.bad_argument, capi.hash.configureMac(@intCast(id), 32, 0, null, 0, null, 0, spec.ptr(), spec.len()));

        switch (algorithm.kind) {
            .hmac => {
                try expectStatus(invalid_option, capi.hash.configureMac(@intCast(id), algorithm.digest_size, capi.hash.mac_length, null, 0, null, 0, spec.ptr(), spec.len()));

                try expectStatus(invalid_option, capi.hash.configureMac(@intCast(id), 0, capi.hash.mac_xof, null, 0, null, 0, spec.ptr(), spec.len()));

                try expectStatus(invalid_option, capi.hash.configureMac(@intCast(id), 0, 0, &long, 1, null, 0, spec.ptr(), spec.len()));
            },
            .kmac => {
                try expectStatus(invalid_option, capi.hash.configureMac(@intCast(id), 3, capi.hash.mac_length, null, 0, null, 0, spec.ptr(), spec.len()));

                try expectStatus(invalid_option, capi.hash.configureMac(@intCast(id), 0, 0, null, 0, &long, 1, spec.ptr(), spec.len()));
            },
            .blake2b, .blake2s => {
                const max: usize = if (algorithm.kind == .blake2b) 64 else 32;

                try expectStatus(invalid_option, capi.hash.configureMac(@intCast(id), 0, capi.hash.mac_length, null, 0, null, 0, spec.ptr(), spec.len()));

                try expectStatus(invalid_option, capi.hash.configureMac(@intCast(id), max + 1, capi.hash.mac_length, null, 0, null, 0, spec.ptr(), spec.len()));

                try expectStatus(invalid_option, capi.hash.configureMac(@intCast(id), 0, capi.hash.mac_xof, null, 0, null, 0, spec.ptr(), spec.len()));

                try expectStatus(invalid_option, capi.hash.configureMac(@intCast(id), 0, 0, &long, max / 4 + 1, null, 0, spec.ptr(), spec.len()));
            },
        }

        // The defaults.
        try expectStatus(ok, capi.hash.configureMac(@intCast(id), 0, 0, null, 0, null, 0, spec.ptr(), spec.len()));

        try testing.expectEqual([3]u32{ 11, @intCast(id), 0 }, try spec.info());

        // A live slot is not overwritten.
        try expectStatus(common.bad_slot, capi.hash.configureMac(@intCast(id), 0, 0, null, 0, null, 0, spec.ptr(), spec.len()));
    }

    try expectStatus(common.bad_argument, capi.hash.configureHash(hash_ids.len, null, 0, null, 0, null, 0));

    try expectStatus(common.bad_argument, capi.hash.configureXof(capi.hash.xofs.len, null, 0, null, 0, null, 0));

    try expectStatus(common.bad_argument, capi.hash.configureMac(mac_ids.len, 0, 0, null, 0, null, 0, null, 0));
}

// A configured slot that the binding damaged is refused, never used.
test "a damaged configured slot is refused" {
    const allocator = testing.allocator;

    var out: [64]u8 = undefined;

    const cshake = try Memory.init(allocator, .configured_xof, 2);

    defer cshake.deinit();

    try expectStatus(ok, capi.hash.configureXof(2, null, 0, "S", 1, cshake.ptr(), cshake.len()));

    const Spec = capi.hash.Xof(2).Spec;

    cshake.bytes[common.bodyOffset(Spec) + @offsetOf(Spec, "prefixed")] = 2;

    try expectStatus(common.bad_slot, capi.hash.xofWith(cshake.ptr(), cshake.len(), "data", 4, &out, out.len));

    const xof = try Memory.init(allocator, .xof, 2);

    defer xof.deinit();

    try expectStatus(common.bad_slot, capi.hash.xofInitWith(cshake.ptr(), cshake.len(), xof.ptr(), xof.len()));

    // A KMAC length below 4 and a BLAKE2 length of 0.
    inline for (.{ 4, 6 }) |id| {
        const spec = try Memory.init(allocator, .configured_mac, id);

        defer spec.deinit();

        try expectStatus(ok, capi.hash.configureMac(id, 0, 0, null, 0, null, 0, spec.ptr(), spec.len()));

        const MacSpec = capi.hash.Mac(id).Spec;

        @memset(spec.bytes[common.bodyOffset(MacSpec) + @offsetOf(MacSpec, "length") ..][0..@sizeOf(usize)], 0);

        try expectStatus(common.bad_slot, capi.hash.macWith(spec.ptr(), spec.len(), "key", 3, "data", 4, &out, 32));

        try expectStatus(common.bad_slot, capi.hash.macVerifyWith(spec.ptr(), spec.len(), "key", 3, "data", 4, &out, 32));

        const state = try Memory.init(allocator, .hmac, id);

        defer state.deinit();

        try expectStatus(common.bad_slot, capi.hash.macInitWith(spec.ptr(), spec.len(), "key", 3, state.ptr(), state.len()));

        // Nothing was made in the state's memory.
        try expectStatus(common.bad_slot, capi.hash.hmacUpdate(state.ptr(), state.len(), "x", 1));
    }
}

test "HKDF through the ABI equals the core" {
    const ikm = pattern(40, 1);

    const salt = pattern(20, 2);

    const info = pattern(30, 3);

    for (capi.hash.kdfs, 0..) |algorithm, id| {
        const n = algorithm.hashSize();

        var expected: [600]u8 = undefined;

        try algorithm.derive(&ikm, &expected, .{ .salt = &salt, .info = &info });

        var out: [600]u8 = undefined;

        try expectStatus(ok, capi.hash.kdfDerive(@intCast(id), &ikm, ikm.len, &salt, salt.len, &info, info.len, &out, out.len));

        try testing.expectEqualSlices(u8, &expected, &out);

        var prk: [64]u8 = undefined;

        try expectStatus(ok, capi.hash.kdfExtract(@intCast(id), &ikm, ikm.len, &salt, salt.len, &prk, n));

        try expectStatus(common.bad_argument, capi.hash.kdfExtract(@intCast(id), &ikm, ikm.len, &salt, salt.len, &prk, n - 1));

        @memset(&out, 0);

        try expectStatus(ok, capi.hash.kdfExpand(@intCast(id), &prk, n, &info, info.len, &out, out.len));

        try testing.expectEqualSlices(u8, &expected, &out);

        const invalid_length = common.code(error.InvalidLength);

        try expectStatus(invalid_length, capi.hash.kdfDerive(@intCast(id), &ikm, ikm.len, null, 0, null, 0, null, 0));

        try expectStatus(invalid_length, capi.hash.kdfExpand(@intCast(id), &prk, n - 1, null, 0, &out, 32));

        try expectStatus(invalid_length, capi.hash.kdfExpand(@intCast(id), &prk, n, null, 0, null, 0));

        const too_long = try testing.allocator.alloc(u8, 255 * n + 1);

        defer testing.allocator.free(too_long);

        try expectStatus(invalid_length, capi.hash.kdfDerive(@intCast(id), &ikm, ikm.len, null, 0, null, 0, too_long.ptr, too_long.len));

        try expectStatus(ok, capi.hash.kdfDerive(@intCast(id), &ikm, ikm.len, null, 0, null, 0, too_long.ptr, too_long.len - 1));

        // The output is apart from the inputs.
        try expectStatus(common.bad_argument, capi.hash.kdfDerive(@intCast(id), &out, 40, null, 0, null, 0, out[20..].ptr, 32));
    }

    try expectStatus(common.bad_argument, capi.hash.kdfDerive(capi.hash.kdfs.len, &ikm, ikm.len, null, 0, null, 0, null, 0));
}

test "a state in use by another call is busy" {
    const state = try Memory.init(testing.allocator, .hasher, 1);

    defer state.deinit();

    try expectStatus(ok, capi.hash.init(1, state.ptr(), state.len()));

    // Another call is inside the state.
    const inside = try common.open(&.{.hasher}, state.ptr(), state.len(), capi.hash.size, .exclusive);

    var out: [32]u8 = undefined;

    try expectStatus(common.busy, capi.hash.update(state.ptr(), state.len(), "abc", 3));

    try expectStatus(common.busy, capi.hash.final(state.ptr(), state.len(), &out, 32));

    inside.close();

    try expectStatus(ok, capi.hash.final(state.ptr(), state.len(), &out, 32));
}

// A cache that another call is filling: the call computes the value for itself, gets the right
// answer, and leaves the cache to the call that fills it.
test "a call never waits for a cache another call fills" {
    const allocator = testing.allocator;

    const seed = pattern(64, 11);

    const randomness = pattern(64, 12);

    inline for (0..4) |id| {
        const private = try Memory.init(allocator, .kem_private, id);

        defer private.deinit();

        try expectStatus(ok, Kem.keygen(id, seed[0..kemSeedSize(id)], 0, private));

        const S = capi.kem.Set(id);

        const body: *S.Private = @ptrFromInt(@intFromPtr(private.ptr()) + common.bodyOffset(S.Private));

        setCache(&body.public.form, .filling);

        var ciphertext: [S.ciphertext_size]u8 = undefined;

        var sent: [32]u8 = undefined;

        var received: [32]u8 = undefined;

        try expectStatus(ok, Kem.encapsulate(private, randomness[0..kemRandomnessSize(id)], &ciphertext, &sent));

        try expectStatus(ok, Kem.decapsulate(private, &ciphertext, &received));

        try testing.expectEqualSlices(u8, &sent, &received);

        try testing.expectEqual(@intFromPtr(&body.public.form.value) | 1, body.public.form.state.load(.acquire));

        setCache(&body.public.form, .empty);

        var again: [32]u8 = undefined;

        try expectStatus(ok, Kem.decapsulate(private, &ciphertext, &again));

        try testing.expectEqualSlices(u8, &sent, &again);
    }

    inline for (0..3) |id| {
        const private = try Memory.init(allocator, .signature_private, id);

        defer private.deinit();

        try expectStatus(ok, Sig.keygen(id, seed[0..32], 0, private));

        const S = capi.signature.Set(id);

        const body: *S.Private = @ptrFromInt(@intFromPtr(private.ptr()) + common.bodyOffset(S.Private));

        var expected: [S.signature_size]u8 = undefined;

        try expectStatus(ok, Sig.sign(private, "m", "", 0, &.{}, capi.signature.deterministic, &expected));

        var signature: [S.signature_size]u8 = undefined;

        for ([_][2]CacheState{ .{ .filling, .ready }, .{ .ready, .filling }, .{ .filling, .filling } }) |states| {
            setCache(&body.public.form, states[0]);

            setCache(&body.secrets, states[1]);

            try expectStatus(ok, Sig.sign(private, "m", "", 0, &.{}, capi.signature.deterministic, &signature));

            try testing.expectEqualSlices(u8, &expected, &signature);

            try expectStatus(ok, Sig.verify(private, &signature, "m", "", 0, 0));
        }
    }
}

const CacheState = enum { empty, filling, ready };

// What a call finds in a cache: nothing, another call filling it at this address, or its value.
fn setCache(lazy: anytype, state: CacheState) void {
    const here = @intFromPtr(&lazy.value);

    lazy.state.store(switch (state) {
        .empty => 0,
        .filling => here | 1,
        .ready => here,
    }, .release);
}

const Shared = struct {
    kem_public: Memory,
    kem_private: Memory,
    signature_private: Memory,
    signature_public: Memory,
    start: std.atomic.Value(u32) = .init(0),
    failures: std.atomic.Value(u32) = .init(0),

    const threads = 8;

    const rounds = 40;

    fn work(self: *Shared, index: usize) void {
        _ = self.start.fetchAdd(1, .acq_rel);

        while (self.start.load(.acquire) < threads) std.atomic.spinLoopHint();

        self.run(index) catch {
            _ = self.failures.fetchAdd(1, .monotonic);
        };
    }

    fn run(self: *Shared, index: usize) !void {
        for (0..rounds) |round| {
            var randomness = pattern(32, @truncate(index * rounds + round));

            var ciphertext: [1088]u8 = undefined;

            var sent: [32]u8 = undefined;

            var received: [32]u8 = undefined;

            try expectStatus(ok, Kem.encapsulate(self.kem_public, &randomness, &ciphertext, &sent));

            try expectStatus(ok, Kem.decapsulate(self.kem_private, &ciphertext, &received));

            if (!std.mem.eql(u8, &sent, &received)) return error.TestUnexpectedResult;

            var signature: [3309]u8 = undefined;

            try expectStatus(ok, Sig.sign(self.signature_private, &randomness, "", 0, &randomness, 0, &signature));

            try expectStatus(ok, Sig.verify(self.signature_public, &signature, &randomness, "", 0, 0));

            try expectStatus(ok, Sig.verify(self.signature_private, &signature, &randomness, "", 0, 0));
        }
    }
};

test "threads share one slot" {
    if (builtin.single_threaded) return error.SkipZigTest;

    const allocator = std.heap.smp_allocator;

    var shared: Shared = .{
        .kem_public = try Memory.init(allocator, .kem_public, 1),
        .kem_private = try Memory.init(allocator, .kem_private, 1),
        .signature_private = try Memory.init(allocator, .signature_private, 1),
        .signature_public = try Memory.init(allocator, .signature_public, 1),
    };

    defer {
        inline for (.{ shared.kem_public, shared.kem_private, shared.signature_private, shared.signature_public }) |memory| memory.deinit();
    }

    // Fresh slots, so that the threads race to fill every cache.
    try expectStatus(ok, Kem.importPrivate(1, &pattern(64, 1), shared.kem_private));

    var public_key: [1184]u8 = undefined;

    try expectStatus(ok, Kem.exportPublic(shared.kem_private, &public_key));

    try expectStatus(ok, Kem.importPublic(1, &public_key, shared.kem_public));

    try expectStatus(ok, Sig.importPrivate(1, &pattern(32, 2), shared.signature_private));

    var signature_key: [1952]u8 = undefined;

    try expectStatus(ok, Sig.exportPublic(shared.signature_private, &signature_key));

    try expectStatus(ok, Sig.importPublic(1, &signature_key, shared.signature_public));

    var threads: [Shared.threads]std.Thread = undefined;

    for (&threads, 0..) |*thread, i| thread.* = try std.Thread.spawn(.{}, Shared.work, .{ &shared, i });

    for (threads) |thread| thread.join();

    try testing.expectEqual(0, shared.failures.load(.monotonic));

    try testing.expectEqual(@as(u32, 256), (try shared.kem_public.info())[2]);

    try testing.expectEqual(@as(u32, 256 | 512 | 1), (try shared.signature_private.info())[2]);
}

// The vectors under vectors/cross, through the ABI: keys, encapsulations, hazmat and
// deterministic signatures with every pre-hash, implicit rejection, and the error code of every
// malformed input that reaches the core. DER and PEM are the bindings' encoding glue.

fn field(allocator: Allocator, values: vectors.Fields, name: []const u8) ![]u8 {
    return vectors.decode(allocator, values.find(name) orelse "");
}

fn kemId(name: []const u8) ?u32 {
    for (kem_ids, 0..) |algorithm, id| {
        if (std.mem.eql(u8, algorithm.name, name)) return @intCast(id);
    }

    return null;
}

fn signatureId(name: []const u8) ?u32 {
    for (signature_ids, 0..) |algorithm, id| {
        if (std.mem.eql(u8, algorithm.name, name)) return @intCast(id);
    }

    return null;
}

const pre_hash_names = [_][]const u8{ "none", "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-512/224", "SHA2-512/256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE-128", "SHAKE-256" };

fn preHashId(name: ?[]const u8) !u32 {
    const label = name orelse return 0;

    for (pre_hash_names, 0..) |known, id| {
        if (std.mem.eql(u8, known, label)) return @intCast(id);
    }

    return error.TestUnexpectedResult;
}

fn kemSizes(id: u32) struct { public: usize, ciphertext: usize, expanded: usize } {
    return switch (id) {
        inline 0...3 => |a| .{ .public = capi.kem.Set(a).public_key_size, .ciphertext = capi.kem.Set(a).ciphertext_size, .expanded = capi.kem.Set(a).expanded_size },
        else => unreachable,
    };
}

fn signatureSizes(id: u32) struct { public: usize, signature: usize, secret: usize } {
    return switch (id) {
        inline 0...14 => |a| .{ .public = capi.signature.Set(a).public_key_size, .signature = capi.signature.Set(a).signature_size, .secret = capi.signature.Set(a).secret_size },
        else => unreachable,
    };
}

fn crossKem(_: void, r: vectors.Record, allocator: Allocator) !void {
    const id = kemId(r.header.get("algorithm")) orelse return error.TestUnexpectedResult;

    const sizes = kemSizes(id);

    const seed = try field(allocator, r.values, "seed");

    const public_key = try field(allocator, r.values, "publicKey");

    const private = try Memory.init(allocator, .kem_private, id);

    try expectStatus(ok, Kem.keygen(id, seed, 0, private));

    const out = try allocator.alloc(u8, 4096);

    try expectStatus(ok, Kem.exportPublic(private, out[0..sizes.public]));

    try testing.expectEqualSlices(u8, public_key, out[0..sizes.public]);

    try expectStatus(ok, Kem.exportPrivate(private, capi.kem.export_seed, out[0..seed.len]));

    try testing.expectEqualSlices(u8, seed, out[0..seed.len]);

    const public = try Memory.init(allocator, .kem_public, id);

    try expectStatus(ok, Kem.importPublic(id, public_key, public));

    const from_seed = try Memory.init(allocator, .kem_private, id);

    try expectStatus(ok, Kem.importPrivate(id, seed, from_seed));

    var keys: [3]Memory = .{ private, from_seed, undefined };

    var count: usize = 2;

    if (r.values.find("expandedKey")) |text| {
        const expanded = try vectors.decode(allocator, text);

        try expectStatus(ok, Kem.exportPrivate(private, capi.kem.export_expanded, out[0..sizes.expanded]));

        try testing.expectEqualSlices(u8, expanded, out[0..sizes.expanded]);

        keys[2] = try Memory.init(allocator, .kem_private, id);

        try expectStatus(ok, Kem.importPrivate(id, expanded, keys[2]));

        try expectStatus(ok, Kem.exportPublic(keys[2], out[0..sizes.public]));

        try testing.expectEqualSlices(u8, public_key, out[0..sizes.public]);

        count = 3;
    }

    const randomness = try field(allocator, r.values, "randomness");

    const ciphertext = try allocator.alloc(u8, sizes.ciphertext);

    var secret: [32]u8 = undefined;

    try expectStatus(ok, Kem.encapsulate(public, randomness, ciphertext, &secret));

    try testing.expectEqualSlices(u8, try field(allocator, r.values, "ciphertext"), ciphertext);

    const shared_secret = try field(allocator, r.values, "sharedSecret");

    try testing.expectEqualSlices(u8, shared_secret, &secret);

    const tampered = try field(allocator, r.values, "tamperedCiphertext");

    const rejected = try field(allocator, r.values, "rejectedSecret");

    for (keys[0..count]) |key| {
        try expectStatus(ok, Kem.decapsulate(key, ciphertext, &secret));

        try testing.expectEqualSlices(u8, shared_secret, &secret);

        try expectStatus(ok, Kem.decapsulate(key, tampered, &secret));

        try testing.expectEqualSlices(u8, rejected, &secret);
    }
}

test "cross KEM vectors through the ABI" {
    const v = try vectors.Vectors.load("cross/kem.txt", "seed");

    defer v.deinit();

    try vectors.parallel(v.records, {}, crossKem);
}

fn crossSignature(_: void, r: vectors.Record, allocator: Allocator) !void {
    const id = signatureId(r.header.get("algorithm")) orelse return error.TestUnexpectedResult;

    const sizes = signatureSizes(id);

    const seed = try vectors.decode(allocator, r.header.get("seed"));

    const private = try Memory.init(allocator, .signature_private, id);

    try expectStatus(ok, Sig.keygen(id, seed, 0, private));

    const public = try Memory.init(allocator, .signature_public, id);

    try expectStatus(ok, Sig.publicFromPrivate(private, public));

    const out = try allocator.alloc(u8, @max(sizes.signature, 4896));

    if (r.values.find("signature") == null) {
        const public_key = try field(allocator, r.values, "publicKey");

        try expectStatus(ok, Sig.exportPublic(private, out[0..sizes.public]));

        try testing.expectEqualSlices(u8, public_key, out[0..sizes.public]);

        const imported = try Memory.init(allocator, .signature_public, id);

        try expectStatus(ok, Sig.importPublic(id, public_key, imported));

        // ML-DSA keeps its seed as the raw private key; SLH-DSA has the 4n-byte key.
        const raw: []const u8 = if (r.values.find("privateKey")) |text| try vectors.decode(allocator, text) else seed;

        try expectStatus(ok, Sig.exportPrivate(private, if (id < 3) capi.signature.export_seed else capi.signature.export_private, out[0..raw.len]));

        try testing.expectEqualSlices(u8, raw, out[0..raw.len]);

        const from_raw = try Memory.init(allocator, .signature_private, id);

        try expectStatus(ok, Sig.importPrivate(id, raw, from_raw));

        try expectStatus(ok, Sig.exportPublic(from_raw, out[0..sizes.public]));

        try testing.expectEqualSlices(u8, public_key, out[0..sizes.public]);

        const text = r.values.find("expandedKey") orelse return;

        const expanded = try vectors.decode(allocator, text);

        try expectStatus(ok, Sig.exportPrivate(private, capi.signature.export_private, out[0..expanded.len]));

        try testing.expectEqualSlices(u8, expanded, out[0..expanded.len]);

        const from_expanded = try Memory.init(allocator, .signature_private, id);

        try expectStatus(ok, Sig.importPrivate(id, expanded, from_expanded));

        try expectStatus(ok, Sig.exportPublic(from_expanded, out[0..sizes.public]));

        return testing.expectEqualSlices(u8, public_key, out[0..sizes.public]);
    }

    const message = try field(allocator, r.values, "message");

    const context = try field(allocator, r.values, "context");

    const pre_hash = try preHashId(r.values.find("preHash"));

    const signature = out[0..sizes.signature];

    if (r.values.is("mode", "hazmat")) {
        try expectStatus(ok, Sig.sign(private, message, context, pre_hash, try field(allocator, r.values, "randomness"), capi.signature.hazmat, signature));
    } else {
        try expectStatus(ok, Sig.sign(private, message, context, pre_hash, &.{}, capi.signature.deterministic, signature));
    }

    try testing.expectEqualSlices(u8, try field(allocator, r.values, "signature"), signature);

    try expectStatus(ok, Sig.verify(public, signature, message, context, pre_hash, capi.signature.hazmat));

    try expectStatus(if (r.values.is("publicVerify", "true")) ok else common.rejected, Sig.verify(public, signature, message, context, pre_hash, 0));
}

test "cross ML-DSA vectors through the ABI" {
    const v = try vectors.Vectors.load("cross/mldsa.txt", "signature");

    defer v.deinit();

    try vectors.parallel(v.records, {}, crossSignature);
}

test "cross SLH-DSA vectors through the ABI" {
    const v = try vectors.Vectors.load("cross/slhdsa.txt", "signature");

    defer v.deinit();

    try vectors.parallel(v.records, {}, crossSignature);
}

// The result of an error-table record: "ok" with an output, "true", "false" or an error code.
// null for a record that is not about the ABI: DER and PEM, and the stateful keys' stores.
const Outcome = struct {
    result: []const u8,
    output: ?[]const u8 = null,
    remaining: ?u64 = null,
};

fn finished(status: c_int, output: []const u8) Outcome {
    return if (status == ok) .{ .result = "ok", .output = output } else .{ .result = statusName(status) };
}

fn execute(r: vectors.Record, allocator: Allocator) !?Outcome {
    const name = r.header.get("algorithm");

    const operation = r.values.get("operation");

    if (r.values.find("format")) |format| {
        if (!std.mem.eql(u8, format, "raw")) return null;
    }

    const data = try field(allocator, r.values, "input");

    const key = try field(allocator, r.values, "key");

    const message = try field(allocator, r.values, "message");

    const randomness = try field(allocator, r.values, "randomness");

    const context = try field(allocator, r.values, "context");

    const pre_hash = try preHashId(r.values.find("preHash"));

    const out = try allocator.alloc(u8, 65536);

    if (kemId(name)) |id| {
        const sizes = kemSizes(id);

        const public = try Memory.init(allocator, .kem_public, id);

        const private = try Memory.init(allocator, .kem_private, id);

        if (is(operation, "importPublicKey")) {
            const status = Kem.importPublic(id, data, public);

            if (status != ok) return finished(status, &.{});

            return finished(Kem.exportPublic(public, out[0..sizes.public]), out[0..sizes.public]);
        }

        if (is(operation, "importPrivateKey") or is(operation, "decapsulate")) {
            const status = Kem.importPrivate(id, if (is(operation, "decapsulate")) key else data, private);

            if (status != ok) return finished(status, &.{});

            if (is(operation, "importPrivateKey")) return finished(Kem.exportPublic(private, out[0..sizes.public]), out[0..sizes.public]);

            return finished(Kem.decapsulate(private, data, out[0..32]), out[0..32]);
        }

        if (is(operation, "exportPublicKey") or is(operation, "generate")) {
            const status = Kem.keygen(id, if (is(operation, "generate")) data else key, 0, private);

            if (status != ok) return finished(status, &.{});

            return finished(Kem.exportPublic(private, out[0..sizes.public]), out[0..sizes.public]);
        }

        if (is(operation, "exportPrivateKey")) {
            const status = Kem.keygen(id, key, 0, private);

            if (status != ok) return finished(status, &.{});

            return finished(Kem.exportPrivate(private, capi.kem.export_seed, out[0..key.len]), out[0..key.len]);
        }

        if (is(operation, "encapsulate")) {
            const status = Kem.importPublic(id, key, public);

            if (status != ok) return finished(status, &.{});

            return finished(Kem.encapsulate(public, randomness, out[32..][0..sizes.ciphertext], out[0..32]), out[0 .. 32 + sizes.ciphertext]);
        }
    } else if (signatureId(name)) |id| {
        const sizes = signatureSizes(id);

        const public = try Memory.init(allocator, .signature_public, id);

        const private = try Memory.init(allocator, .signature_private, id);

        if (is(operation, "importPublicKey")) {
            const status = Sig.importPublic(id, data, public);

            if (status != ok) return finished(status, &.{});

            return finished(Sig.exportPublic(public, out[0..sizes.public]), out[0..sizes.public]);
        }

        if (is(operation, "importPrivateKey") or is(operation, "sign") or is(operation, "hazmatSign")) {
            const status = Sig.importPrivate(id, if (is(operation, "importPrivateKey")) data else key, private);

            if (status != ok) return finished(status, &.{});

            if (is(operation, "importPrivateKey")) return finished(Sig.exportPublic(private, out[0..sizes.public]), out[0..sizes.public]);

            const signature = out[0..sizes.signature];

            if (is(operation, "sign")) return finished(Sig.sign(private, message, context, pre_hash, &.{}, capi.signature.deterministic, signature), signature);

            return finished(Sig.sign(private, message, context, pre_hash, randomness, capi.signature.hazmat, signature), signature);
        }

        if (is(operation, "generate")) {
            const status = Sig.keygen(id, data, 0, private);

            if (status != ok) return finished(status, &.{});

            return finished(Sig.exportPublic(private, out[0..sizes.public]), out[0..sizes.public]);
        }

        if (is(operation, "verify") or is(operation, "hazmatVerify")) {
            try expectStatus(ok, Sig.importPublic(id, key, public));

            const status = Sig.verify(public, data, message, context, pre_hash, if (is(operation, "hazmatVerify")) capi.signature.hazmat else 0);

            return .{ .result = if (status == ok) "true" else if (status == common.rejected) "false" else statusName(status) };
        }
    } else if (kindId(name)) |kind| {
        return executeStateful(kind, r, operation, data, key, message, allocator);
    } else {
        return null;
    }

    std.debug.print("unknown operation {s} for {s}\n", .{ operation, name });

    return error.TestUnexpectedResult;
}

// The binding's part comes first: the parameter names become codes, and a name no crypto-pq knows
// is INVALID_OPTION before the ABI is called.
fn executeStateful(kind: u32, r: vectors.Record, operation: []const u8, data: []const u8, key: []const u8, message: []const u8, allocator: Allocator) !?Outcome {
    if (is(operation, "importPublicKey")) {
        const status = capi.stateful.checkPublicKey(kind, data.ptr, data.len);

        return finished(status, data);
    }

    if (is(operation, "verify")) {
        try expectStatus(ok, capi.stateful.checkPublicKey(kind, key.ptr, key.len));

        const status = Signer.verify(kind, key, message, data);

        return .{ .result = if (status == ok) "true" else if (status == common.rejected) "false" else statusName(status) };
    }

    const slot = try Memory.init(allocator, .signer, kind);

    var index: u64 = 0;

    if (is(operation, "generate")) {
        var buffer: [65]u8 = undefined;

        const parameters = sectionOf(kind, r.values, &buffer) orelse return .{ .result = "INVALID_OPTION" };

        var sizes: [6]u64 = undefined;

        const status = capi.stateful.info(kind, parameters.ptr, parameters.len, &sizes);

        if (status != ok) return .{ .result = statusName(status) };

        index = try vectors.number(u64, r.values.get("index"));

        const state = try allocator.alloc(u8, @intCast(sizes[1]));

        const created = Signer.create(kind, parameters, data, index, state, slot);

        if (created != ok) return .{ .result = statusName(created) };
    } else if (is(operation, "loadPrivateKey") or is(operation, "sign")) {
        const status = Signer.load(kind, data, null, slot, &index);

        if (status != ok) return .{ .result = statusName(status) };
    } else {
        return null;
    }

    defer _ = Signer.free(slot);

    const held = try Signer.signerInfo(slot);

    if (is(operation, "sign")) {
        // The host claims the index before the signer signs; an exhausted key fails first.
        if (index >= held[0]) return .{ .result = "KEY_EXHAUSTED" };

        const signature = try allocator.alloc(u8, @intCast(held[2]));

        return finished(Signer.sign(slot, index, message, signature), signature);
    }

    const public_key = try allocator.alloc(u8, 68);

    var size: usize = 0;

    while (size <= 68 and capi.stateful.publicKey(slot.ptr(), slot.len(), public_key.ptr, size) != ok) size += 1;

    return .{ .result = "ok", .output = public_key[0..size], .remaining = held[0] - index };
}

fn is(operation: []const u8, expected: []const u8) bool {
    return std.mem.eql(u8, operation, expected);
}

const Tally = struct {
    checked: std.atomic.Value(usize) = .init(0),
    skipped: std.atomic.Value(usize) = .init(0),
};

fn errorCase(tally: *Tally, r: vectors.Record, allocator: Allocator) !void {
    const outcome = try execute(r, allocator) orelse {
        _ = tally.skipped.fetchAdd(1, .monotonic);

        return;
    };

    _ = tally.checked.fetchAdd(1, .monotonic);

    var same = std.mem.eql(u8, outcome.result, r.values.get("result"));

    if (r.values.find("output")) |text| {
        same = same and outcome.output != null and std.mem.eql(u8, try vectors.decode(allocator, text), outcome.output.?);
    }

    if (r.values.find("remaining")) |text| {
        same = same and outcome.remaining != null and outcome.remaining.? == try vectors.number(u64, text);
    }

    if (!same) {
        std.debug.print("{s}: {s}: got {s}, expected {s}\n", .{ r.header.get("algorithm"), r.values.get("name"), outcome.result, r.values.get("result") });

        return error.TestUnexpectedResult;
    }
}

test "cross error codes through the ABI" {
    const v = try vectors.Vectors.load("cross/errors.txt", "result");

    defer v.deinit();

    var tally: Tally = .{};

    try vectors.parallel(v.records, &tally, errorCase);

    // Every record of the stateless algorithms in raw form reaches the ABI.
    var expected: usize = 0;

    for (v.records) |r| {
        const raw = if (r.values.find("format")) |format| std.mem.eql(u8, format, "raw") else true;

        if (raw and (kemId(r.header.get("algorithm")) != null or signatureId(r.header.get("algorithm")) != null or kindId(r.header.get("algorithm")) != null)) expected += 1;
    }

    try testing.expectEqual(expected, tally.checked.load(.monotonic));
}

// The deepest stack of every exported function, measured by painting a thread's stack, as
// test/stack.zig measures the core: no call may need more than 64 KiB.
const stack_limit = 64 << 10;

const window = 1 << 20;

const paint_byte = 0xa5;

noinline fn paint() void {
    var buffer: [window + 4096]u8 = undefined;

    const target: [*]volatile u8 = &buffer;

    for (0..buffer.len) |i| target[i] = paint_byte;
}

noinline fn scan() usize {
    var marker: u8 = 0;

    const below: [*]const volatile u8 = @ptrFromInt(@intFromPtr(&marker) - window);

    var i: usize = 0;

    while (i < window and below[i] == paint_byte) i += 1;

    std.mem.doNotOptimizeAway(&marker);

    return window - i;
}

const Probe = struct {
    name: []const u8,
    run: *const fn (*Fixture) anyerror!void,
};

// Slots and buffers that the probes share, prepared outside the measured calls.
const Fixture = struct {
    kem_private: [4]Memory,
    kem_public: [4]Memory,
    signature_private: [15]Memory,
    signature_public: [15]Memory,
    hasher: Memory,
    xof: Memory,
    hmac: Memory,
    configured_hash: Memory,
    configured_xof: Memory,
    configured_mac: Memory,
    blake2_hasher: Memory,
    kmac: Memory,
    blake2_mac: Memory,
    scratch: Memory,
    ciphertext: [1568]u8 = undefined,
    signature: []u8,
    data: [1000]u8 = pattern(1000, 1),
    id: u32 = 0,

    fn init(allocator: Allocator) !Fixture {
        var fixture: Fixture = undefined;

        for (0..4) |id| {
            fixture.kem_private[id] = try Memory.init(allocator, .kem_private, @intCast(id));

            fixture.kem_public[id] = try Memory.init(allocator, .kem_public, @intCast(id));
        }

        for (0..15) |id| {
            fixture.signature_private[id] = try Memory.init(allocator, .signature_private, @intCast(id));

            fixture.signature_public[id] = try Memory.init(allocator, .signature_public, @intCast(id));
        }

        fixture.hasher = try Memory.init(allocator, .hasher, 3);

        fixture.xof = try Memory.init(allocator, .xof, 1);

        fixture.hmac = try Memory.init(allocator, .hmac, 3);

        fixture.configured_hash = try Memory.init(allocator, .configured_hash, 13);

        fixture.configured_xof = try Memory.init(allocator, .configured_xof, 3);

        fixture.configured_mac = try Memory.init(allocator, .configured_mac, 5);

        fixture.blake2_hasher = try Memory.init(allocator, .hasher, 13);

        fixture.kmac = try Memory.init(allocator, .hmac, 5);

        fixture.blake2_mac = try Memory.init(allocator, .hmac, 6);

        fixture.scratch = try Memory.init(allocator, .signature_private, 2);

        fixture.signature = try allocator.alloc(u8, 49856);

        fixture.data = pattern(1000, 1);

        return fixture;
    }

    fn deinit(self: *Fixture, allocator: Allocator) void {
        for (self.kem_private ++ self.kem_public ++ self.signature_private ++ self.signature_public) |memory| memory.deinit();

        for ([_]Memory{ self.hasher, self.xof, self.hmac, self.configured_hash, self.configured_xof, self.configured_mac, self.blake2_hasher, self.kmac, self.blake2_mac, self.scratch }) |memory| memory.deinit();

        allocator.free(self.signature);
    }
};

fn measureOne(probe: *const Probe, fixture: *Fixture, depth: *usize, result: *anyerror!void) void {
    paint();

    result.* = probe.run(fixture);

    depth.* = scan();
}

fn measure(probe: *const Probe, fixture: *Fixture) !usize {
    var depth: usize = 0;

    var result: anyerror!void = {};

    const thread = try std.Thread.spawn(.{ .stack_size = 4 << 20 }, measureOne, .{ probe, fixture, &depth, &result });

    thread.join();

    result catch |err| {
        std.debug.print("{s} failed: {s}\n", .{ probe.name, @errorName(err) });

        return err;
    };

    return depth;
}

fn kemProbes(comptime id: u32) [6]Probe {
    const S = capi.kem.Set(id);

    const seed = pattern(64, 3);

    const randomness = pattern(64, 4);

    const Run = struct {
        fn keygen(f: *Fixture) !void {
            try f.kem_private[id].wipe();

            try expectStatus(ok, Kem.keygen(id, seed[0..S.seed_size], capi.kem.fill_cache, f.kem_private[id]));

            try f.kem_private[id].wipe();

            try expectStatus(ok, Kem.keygen(id, seed[0..S.seed_size], 0, f.kem_private[id]));
        }

        fn importPublic(f: *Fixture) !void {
            var key: [S.public_key_size]u8 = undefined;

            try expectStatus(ok, Kem.exportPublic(f.kem_private[id], &key));

            try f.kem_public[id].wipe();

            try expectStatus(ok, Kem.importPublic(id, &key, f.kem_public[id]));
        }

        // The first use fills the cache, the most a call does.
        fn encapsulate(f: *Fixture) !void {
            var secret: [32]u8 = undefined;

            try expectStatus(ok, Kem.encapsulate(f.kem_public[id], randomness[0..S.randomness_size], f.ciphertext[0..S.ciphertext_size], &secret));
        }

        fn decapsulate(f: *Fixture) !void {
            var secret: [32]u8 = undefined;

            try expectStatus(ok, Kem.decapsulate(f.kem_private[id], f.ciphertext[0..S.ciphertext_size], &secret));
        }

        fn importPrivate(f: *Fixture) !void {
            var key: [@max(S.expanded_size, 64)]u8 = undefined;

            const which = if (S.x_wing) capi.kem.export_seed else capi.kem.export_expanded;

            const size = if (S.x_wing) S.seed_size else S.expanded_size;

            try expectStatus(ok, Kem.exportPrivate(f.kem_private[id], which, key[0..size]));

            const other = f.kem_public[id];

            _ = other;

            try f.kem_private[id].wipe();

            try expectStatus(ok, Kem.importPrivate(id, key[0..size], f.kem_private[id]));
        }

        fn selfTest(f: *Fixture) !void {
            try expectStatus(ok, capi.kem.selfTest(f.kem_private[id].ptr(), f.kem_private[id].len(), &randomness, S.randomness_size));
        }
    };

    const name = kem_ids[id].name;

    return .{
        .{ .name = name ++ " keygen", .run = Run.keygen },
        .{ .name = name ++ " import_public", .run = Run.importPublic },
        .{ .name = name ++ " encapsulate", .run = Run.encapsulate },
        .{ .name = name ++ " decapsulate", .run = Run.decapsulate },
        .{ .name = name ++ " import_private, self_test", .run = Run.importPrivate },
        .{ .name = name ++ " self_test", .run = Run.selfTest },
    };
}

fn signatureProbes(comptime id: u32) [5]Probe {
    const S = capi.signature.Set(id);

    const seed = pattern(96, 5);

    const randomness = pattern(32, 6);

    const Run = struct {
        fn keygen(f: *Fixture) !void {
            try f.signature_private[id].wipe();

            try expectStatus(ok, Sig.keygen(id, seed[0..S.seed_size], capi.signature.fill_cache, f.signature_private[id]));

            try f.signature_private[id].wipe();

            try expectStatus(ok, Sig.keygen(id, seed[0..S.seed_size], 0, f.signature_private[id]));
        }

        fn importKeys(f: *Fixture) !void {
            var key: [S.public_key_size]u8 = undefined;

            try expectStatus(ok, Sig.exportPublic(f.signature_private[id], &key));

            try f.signature_public[id].wipe();

            try expectStatus(ok, Sig.importPublic(id, &key, f.signature_public[id]));

            var secret: [S.secret_size]u8 = undefined;

            try expectStatus(ok, Sig.exportPrivate(f.signature_private[id], capi.signature.export_private, &secret));

            try f.scratch.wipe();

            if (S.ml_dsa) {
                if (id == 2) try expectStatus(ok, Sig.importPrivate(id, &secret, f.scratch));
            } else {
                const temporary = try Memory.init(std.heap.page_allocator, .signature_private, id);

                defer temporary.deinit();

                try expectStatus(ok, Sig.importPrivate(id, &secret, temporary));
            }
        }

        // With empty caches, which signing fills.
        fn sign(f: *Fixture) !void {
            try expectStatus(ok, Sig.sign(f.signature_private[id], "message", "context", 4, randomness[0..S.randomness_size], 0, f.signature[0..S.signature_size]));
        }

        fn verify(f: *Fixture) !void {
            try expectStatus(ok, Sig.verify(f.signature_public[id], f.signature[0..S.signature_size], "message", "context", 4, 0));
        }

        fn deterministic(f: *Fixture) !void {
            try expectStatus(ok, Sig.sign(f.signature_private[id], "message", "", 0, &.{}, capi.signature.deterministic, f.signature[0..S.signature_size]));
        }
    };

    const name = signature_ids[id].name;

    return .{
        .{ .name = name ++ " keygen", .run = Run.keygen },
        .{ .name = name ++ " import_public, import_private", .run = Run.importKeys },
        .{ .name = name ++ " sign", .run = Run.sign },
        .{ .name = name ++ " verify", .run = Run.verify },
        .{ .name = name ++ " sign, deterministic", .run = Run.deterministic },
    };
}

fn statefulProbes(comptime number: usize) [1]Probe {
    const case = stateful_cases[number];

    const Run = struct {
        fn run(f: *Fixture) !void {
            _ = f;

            const allocator = std.heap.page_allocator;

            const sizes = try Signer.info(case.kind, case.section);

            const slot = try Memory.init(allocator, .signer, case.kind);

            defer slot.deinit();

            var state: [139]u8 = undefined;

            const blob = state[0..@intCast(sizes[1])];

            const start: u64 = if (case.section.len > 9) 31 else 0;

            try expectStatus(ok, Signer.create(case.kind, case.section, pattern(96, 2)[0..case.seed_size], start, blob, slot));

            const signature = try allocator.alloc(u8, @intCast(sizes[3]));

            defer allocator.free(signature);

            for (start..start + 2) |index| {
                try expectStatus(ok, Signer.reseal(case.kind, blob, index + 1));

                try expectStatus(ok, Signer.sign(slot, index, "message", signature));
            }

            var public_key: [68]u8 = undefined;

            try expectStatus(ok, Signer.publicKey(slot, public_key[0..@intCast(sizes[2])]));

            try expectStatus(ok, Signer.verify(case.kind, public_key[0..@intCast(sizes[2])], "message", signature));

            const cache = try Signer.treeCache(allocator, slot);

            defer allocator.free(cache);

            const loaded = try Memory.init(allocator, .signer, case.kind);

            defer loaded.deinit();

            var index: u64 = 0;

            try expectStatus(ok, Signer.load(case.kind, blob, cache, loaded, &index));

            try expectStatus(ok, Signer.sign(loaded, index, "message", signature));

            try expectStatus(ok, Signer.free(loaded));

            try expectStatus(ok, Signer.free(slot));
        }
    };

    return .{.{ .name = std.fmt.comptimePrint("stateful case {d}: create, sign, verify, export, load", .{number}), .run = Run.run }};
}

const hash_probes = [_]Probe{
    .{ .name = "hash, xof, mac", .run = struct {
        fn run(f: *Fixture) !void {
            var out: [200]u8 = undefined;

            for (hash_ids, 0..) |algorithm, id| try expectStatus(ok, capi.hash.digest(@intCast(id), &f.data, f.data.len, &out, algorithm.digest_size));

            for (0..capi.hash.xofs.len) |id| try expectStatus(ok, capi.hash.xof(@intCast(id), &f.data, f.data.len, &out, out.len));

            for (mac_ids, 0..) |algorithm, id| {
                const key_length = keyLengths(algorithm)[2];

                try expectStatus(ok, capi.hash.hmac(@intCast(id), &f.data, key_length, &f.data, f.data.len, &out, algorithm.digest_size));

                try expectStatus(ok, capi.hash.hmacVerify(@intCast(id), &f.data, key_length, &f.data, f.data.len, &out, algorithm.digest_size));
            }
        }
    }.run },
    .{ .name = "configured hash, xof, mac", .run = struct {
        fn run(f: *Fixture) !void {
            var out: [200]u8 = undefined;

            try f.configured_hash.wipe();

            try expectStatus(ok, capi.hash.configureHash(13, &f.data, 16, &f.data, 16, f.configured_hash.ptr(), f.configured_hash.len()));

            try expectStatus(ok, capi.hash.digestWith(f.configured_hash.ptr(), f.configured_hash.len(), &f.data, f.data.len, &out, 64));

            try f.configured_xof.wipe();

            try expectStatus(ok, capi.hash.configureXof(3, &f.data, 300, &f.data, 700, f.configured_xof.ptr(), f.configured_xof.len()));

            try expectStatus(ok, capi.hash.xofWith(f.configured_xof.ptr(), f.configured_xof.len(), &f.data, f.data.len, &out, out.len));

            try f.configured_mac.wipe();

            try expectStatus(ok, capi.hash.configureMac(5, 200, capi.hash.mac_length, &f.data, 500, null, 0, f.configured_mac.ptr(), f.configured_mac.len()));

            try expectStatus(ok, capi.hash.macWith(f.configured_mac.ptr(), f.configured_mac.len(), &f.data, 300, &f.data, f.data.len, &out, 200));

            try expectStatus(ok, capi.hash.macVerifyWith(f.configured_mac.ptr(), f.configured_mac.len(), &f.data, 300, &f.data, f.data.len, &out, 200));

            try f.blake2_hasher.wipe();

            try expectStatus(ok, capi.hash.initWith(f.configured_hash.ptr(), f.configured_hash.len(), f.blake2_hasher.ptr(), f.blake2_hasher.len()));

            try expectStatus(ok, capi.hash.update(f.blake2_hasher.ptr(), f.blake2_hasher.len(), &f.data, f.data.len));

            try expectStatus(ok, capi.hash.final(f.blake2_hasher.ptr(), f.blake2_hasher.len(), &out, 64));

            try f.xof.wipe();

            try expectStatus(ok, capi.hash.xofInitWith(f.configured_xof.ptr(), f.configured_xof.len(), f.xof.ptr(), f.xof.len()));

            try expectStatus(ok, capi.hash.xofUpdate(f.xof.ptr(), f.xof.len(), &f.data, f.data.len));

            try expectStatus(ok, capi.hash.xofRead(f.xof.ptr(), f.xof.len(), &out, out.len));

            try f.kmac.wipe();

            try expectStatus(ok, capi.hash.macInitWith(f.configured_mac.ptr(), f.configured_mac.len(), &f.data, 300, f.kmac.ptr(), f.kmac.len()));

            try expectStatus(ok, capi.hash.hmacUpdate(f.kmac.ptr(), f.kmac.len(), &f.data, f.data.len));

            try expectStatus(ok, capi.hash.hmacFinal(f.kmac.ptr(), f.kmac.len(), &out, 200));

            try expectStatus(ok, capi.hash.hmacFinalVerify(f.kmac.ptr(), f.kmac.len(), &out, 200));

            try f.blake2_mac.wipe();

            try expectStatus(ok, capi.hash.hmacInit(6, &f.data, 64, f.blake2_mac.ptr(), f.blake2_mac.len()));

            try expectStatus(ok, capi.hash.hmacUpdate(f.blake2_mac.ptr(), f.blake2_mac.len(), &f.data, f.data.len));

            try expectStatus(ok, capi.hash.hmacFinal(f.blake2_mac.ptr(), f.blake2_mac.len(), &out, 64));

            try expectStatus(ok, capi.hash.hmacFinalVerify(f.blake2_mac.ptr(), f.blake2_mac.len(), &out, 64));
        }
    }.run },
    .{ .name = "kdf derive, extract, expand", .run = struct {
        fn run(f: *Fixture) !void {
            var out: [600]u8 = undefined;

            for (capi.hash.kdfs, 0..) |algorithm, id| {
                try expectStatus(ok, capi.hash.kdfDerive(@intCast(id), &f.data, 100, &f.data, 200, &f.data, 300, &out, out.len));

                try expectStatus(ok, capi.hash.kdfExtract(@intCast(id), &f.data, 1000, &f.data, 300, &out, algorithm.hashSize()));

                try expectStatus(ok, capi.hash.kdfExpand(@intCast(id), &f.data, 200, &f.data, 1000, &out, out.len));
            }
        }
    }.run },
    .{ .name = "hash, xof, hmac states", .run = struct {
        fn run(f: *Fixture) !void {
            var out: [200]u8 = undefined;

            try f.hasher.wipe();

            try expectStatus(ok, capi.hash.init(3, f.hasher.ptr(), f.hasher.len()));

            try expectStatus(ok, capi.hash.update(f.hasher.ptr(), f.hasher.len(), &f.data, f.data.len));

            try expectStatus(ok, capi.hash.final(f.hasher.ptr(), f.hasher.len(), &out, 64));

            try f.xof.wipe();

            try expectStatus(ok, capi.hash.xofInit(1, f.xof.ptr(), f.xof.len()));

            try expectStatus(ok, capi.hash.xofUpdate(f.xof.ptr(), f.xof.len(), &f.data, f.data.len));

            try expectStatus(ok, capi.hash.xofRead(f.xof.ptr(), f.xof.len(), &out, out.len));

            try f.hmac.wipe();

            try expectStatus(ok, capi.hash.hmacInit(3, &f.data, 200, f.hmac.ptr(), f.hmac.len()));

            try expectStatus(ok, capi.hash.hmacUpdate(f.hmac.ptr(), f.hmac.len(), &f.data, f.data.len));

            try expectStatus(ok, capi.hash.hmacFinal(f.hmac.ptr(), f.hmac.len(), &out, 64));

            try expectStatus(ok, capi.hash.hmacFinalVerify(f.hmac.ptr(), f.hmac.len(), &out, 64));
        }
    }.run },
};

fn stackSupported() bool {
    return builtin.os.tag == .linux and !builtin.single_threaded;
}

test "stack: every exported function" {
    if (!stackSupported()) return error.SkipZigTest;

    const allocator = std.heap.page_allocator;

    var fixture = try Fixture.init(allocator);

    defer fixture.deinit(allocator);

    var worst: usize = 0;

    var worst_name: []const u8 = "";

    // CPQ_STACK_REPORT=1 prints every depth.
    const report = testing.environ.containsUnempty(testing.allocator, "CPQ_STACK_REPORT") catch false;

    const probes = comptime blk: {
        var list: []const Probe = &.{};

        for (0..4) |id| list = list ++ &kemProbes(id);

        for (0..15) |id| list = list ++ &signatureProbes(id);

        for (0..stateful_cases.len) |number| list = list ++ &statefulProbes(number);

        break :blk list ++ &hash_probes;
    };

    for (probes) |*probe| {
        // The SLH-DSA "s" sets take long in Debug builds and use the stack of their "f" twins.
        if (builtin.mode == .Debug and std.mem.endsWith(u8, probe.name[0..std.mem.indexOfScalar(u8, probe.name, ' ').?], "s")) {
            if (std.mem.startsWith(u8, probe.name, "SLH-DSA")) continue;
        }

        const depth = try measure(probe, &fixture);

        if (report) std.debug.print("stack {s}: {d}\n", .{ probe.name, depth });

        if (depth > worst) {
            worst = depth;

            worst_name = probe.name;
        }

        if (depth > stack_limit) {
            std.debug.print("{s} uses {d} bytes of stack, above {d}\n", .{ probe.name, depth, stack_limit });

            return error.TestUnexpectedResult;
        }
    }

    try testing.expect(worst > 0);

    if (report) std.debug.print("deepest: {s}, {d} bytes\n", .{ worst_name, worst });
}

// The stateful signer: two phases, the host's state machine and the core's trees.

const lms_core = @import("lms.zig");
const stateful_core = @import("stateful.zig");
const xmss_core = @import("xmss.zig");

const Signer = struct {
    fn create(kind: u32, section: []const u8, seed: []const u8, index: u64, state: []u8, slot: Memory) c_int {
        return capi.stateful.create(kind, section.ptr, section.len, seed.ptr, seed.len, index, state.ptr, state.len, slot.ptr(), slot.len());
    }

    fn load(kind: u32, state: []const u8, cache: ?[]const u8, slot: Memory, index: *u64) c_int {
        const bytes = cache orelse &.{};

        return capi.stateful.load(kind, state.ptr, state.len, bytes.ptr, bytes.len, if (cache != null) capi.stateful.with_tree_cache else 0, slot.ptr(), slot.len(), index);
    }

    fn sign(slot: Memory, index: u64, message: []const u8, out: []u8) c_int {
        return capi.stateful.sign(slot.ptr(), slot.len(), index, message.ptr, message.len, out.ptr, out.len);
    }

    fn publicKey(slot: Memory, out: []u8) c_int {
        return capi.stateful.publicKey(slot.ptr(), slot.len(), out.ptr, out.len);
    }

    fn info(kind: u32, section: []const u8) ![6]u64 {
        var out: [6]u64 = undefined;

        try expectStatus(ok, capi.stateful.info(kind, section.ptr, section.len, &out));

        return out;
    }

    fn signerInfo(slot: Memory) ![4]u64 {
        var out: [4]u64 = undefined;

        try expectStatus(ok, capi.stateful.signerInfo(slot.ptr(), slot.len(), &out));

        return out;
    }

    fn treeCache(allocator: Allocator, slot: Memory) ![]u8 {
        var size: u64 = 0;

        try expectStatus(ok, capi.stateful.treeCacheSize(slot.ptr(), slot.len(), &size));

        const cache = try allocator.alloc(u8, @intCast(size));

        try expectStatus(ok, capi.stateful.exportTreeCache(slot.ptr(), slot.len(), cache.ptr, cache.len));

        return cache;
    }

    fn reseal(kind: u32, state: []u8, index: u64) c_int {
        return capi.stateful.reseal(kind, state.ptr, state.len, index);
    }

    fn verify(kind: u32, key: []const u8, message: []const u8, signature: []const u8) c_int {
        return capi.stateful.verify(kind, key.ptr, key.len, message.ptr, message.len, signature.ptr, signature.len);
    }

    fn free(slot: Memory) c_int {
        return capi.stateful.free(slot.ptr(), slot.len());
    }
};

fn kindId(name: []const u8) ?u32 {
    if (std.mem.eql(u8, name, "HSS/LMS")) return 1;

    if (std.mem.eql(u8, name, "XMSS")) return 2;

    if (std.mem.eql(u8, name, "XMSS^MT")) return 3;

    return null;
}

// The parameter section, as a binding builds it from the names; null for a name no crypto-pq
// knows, which the binding refuses itself.
fn sectionOf(kind: u32, values: vectors.Fields, buffer: *[65]u8) ?[]const u8 {
    if (values.find("parameters")) |name| {
        const sets: []const xmss_core.Parameters = if (kind == 3) &xmss_core.xmss_mt_sets else &xmss_core.xmss_sets;

        const p = xmss_core.byName(sets, name) orelse return null;

        std.mem.writeInt(u32, buffer[0..4], p.oid, .big);

        return buffer[0..4];
    }

    var trees = std.mem.splitScalar(u8, values.get("lms"), ',');

    var ots = std.mem.splitScalar(u8, values.get("ots"), ',');

    var count: usize = 0;

    while (trees.next()) |tree| : (count += 1) {
        if (count == 8) return null;

        const l = lms_core.lmsByName(tree) orelse return null;

        const o = lms_core.otsByName(ots.next() orelse return null) orelse return null;

        std.mem.writeInt(u32, buffer[1 + 8 * count ..][0..4], l.code, .big);

        std.mem.writeInt(u32, buffer[5 + 8 * count ..][0..4], o.code, .big);
    }

    buffer[0] = @intCast(count);

    return buffer[0 .. 1 + 8 * count];
}

const StatefulCase = struct {
    kind: u32,
    algorithm: pq.StatefulSignatureAlgorithm,
    parameters: pq.StatefulParameters,
    section: []const u8,
    seed_size: usize,
};

const h5 = [_]pq.HssLevel{.{ .lms = "LMS_SHA256_M32_H5", .ots = "LMOTS_SHA256_N32_W8" }};

const h5h5 = [_]pq.HssLevel{ .{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W4" }, .{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W2" } };

fn codes(comptime levels: []const pq.HssLevel) [1 + 8 * levels.len]u8 {
    var out: [1 + 8 * levels.len]u8 = undefined;

    out[0] = levels.len;

    for (levels, 0..) |level, i| {
        std.mem.writeInt(u32, out[1 + 8 * i ..][0..4], lms_core.lmsByName(level.lms).?.code, .big);

        std.mem.writeInt(u32, out[5 + 8 * i ..][0..4], lms_core.otsByName(level.ots).?.code, .big);
    }

    return out;
}

fn oid(comptime sets: []const xmss_core.Parameters, comptime name: []const u8) [4]u8 {
    var out: [4]u8 = undefined;

    std.mem.writeInt(u32, &out, xmss_core.byName(sets, name).?.oid, .big);

    return out;
}

const stateful_cases = [_]StatefulCase{
    .{ .kind = 1, .algorithm = pq.hss_lms, .parameters = .{ .levels = &h5 }, .section = &codes(&h5), .seed_size = 48 },
    .{ .kind = 1, .algorithm = pq.hss_lms, .parameters = .{ .levels = &h5h5 }, .section = &codes(&h5h5), .seed_size = 40 },
    .{ .kind = 2, .algorithm = pq.xmss, .parameters = .{ .name = "XMSS-SHA2_10_256" }, .section = &oid(&xmss_core.xmss_sets, "XMSS-SHA2_10_256"), .seed_size = 96 },
    .{ .kind = 3, .algorithm = pq.xmss_mt, .parameters = .{ .name = "XMSSMT-SHAKE256_20/4_256" }, .section = &oid(&xmss_core.xmss_mt_sets, "XMSSMT-SHAKE256_20/4_256"), .seed_size = 96 },
};

const MemoryStore = struct {
    allocator: Allocator,
    state: ?[]u8 = null,

    const vtable: pq.StateStore.VTable = .{ .read = read, .update = update };

    fn store(self: *MemoryStore) pq.StateStore {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn read(ptr: *anyopaque, allocator: Allocator) anyerror!?[]u8 {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));

        return try allocator.dupe(u8, self.state orelse return null);
    }

    fn update(ptr: *anyopaque, previous: ?[]const u8, next: []const u8) anyerror!bool {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));

        const same = if (self.state) |state| previous != null and std.mem.eql(u8, state, previous.?) else previous == null;

        if (!same) return false;

        self.state = try self.allocator.dupe(u8, next);

        return true;
    }
};

test "stateful signer through the ABI equals the core" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    for (stateful_cases) |case| {
        const seed = pattern(96, @intCast(case.kind * 7));

        const start: u64 = if (case.kind == 1 and case.section.len > 9) 30 else 3;

        var store: MemoryStore = .{ .allocator = allocator };

        var pair = try pq.hazmat.generateStatefulKeyPair(case.algorithm, allocator, case.parameters, seed[0..case.seed_size], start, store.store(), .{});

        defer pair.private_key.deinit(allocator);

        const sizes = try Signer.info(case.kind, case.section);

        try testing.expectEqual(case.seed_size, sizes[0]);

        try testing.expectEqual(store.state.?.len, sizes[1]);

        try testing.expectEqual(pair.public_key.size, sizes[2]);

        try testing.expectEqual(pair.private_key.remainingSignatures() + start, sizes[4]);

        const slot = try Memory.init(allocator, .signer, case.kind);

        const state = try allocator.alloc(u8, @intCast(sizes[1]));

        try expectStatus(ok, Signer.create(case.kind, case.section, seed[0..case.seed_size], start, state, slot));

        try testing.expectEqualSlices(u8, store.state.?, state);

        // The signer allocates what info said it would.
        const held = try Signer.signerInfo(slot);

        try testing.expectEqual([4]u64{ sizes[4], start, sizes[3], sizes[5] }, held);

        var public_key: [68]u8 = undefined;

        try expectStatus(ok, Signer.publicKey(slot, public_key[0..@intCast(sizes[2])]));

        try testing.expectEqualSlices(u8, pair.public_key.bytes[0..pair.public_key.size], public_key[0..@intCast(sizes[2])]);

        const signature = try allocator.alloc(u8, @intCast(sizes[3]));

        // The host claims each index in its store before the signer signs with it.
        for (0..3) |i| {
            const index = start + i;

            const message = pattern(40, @intCast(i));

            const expected = try pair.private_key.sign(allocator, &message);

            try expectStatus(ok, Signer.reseal(case.kind, state, index + 1));

            try testing.expectEqualSlices(u8, store.state.?, state);

            try expectStatus(ok, Signer.sign(slot, index, &message, signature));

            try testing.expectEqualSlices(u8, expected, signature);

            try expectStatus(ok, Signer.verify(case.kind, public_key[0..@intCast(sizes[2])], &message, signature));

            signature[5] ^= 1;

            try expectStatus(common.rejected, Signer.verify(case.kind, public_key[0..@intCast(sizes[2])], &message, signature));
        }

        // An index at or below one the signer used is refused, whatever the host's state says.
        try expectStatus(common.code(error.StateConflict), Signer.sign(slot, start + 2, "again", signature));

        try expectStatus(common.code(error.StateConflict), Signer.sign(slot, start, "again", signature));

        try testing.expectEqual(start + 3, (try Signer.signerInfo(slot))[1]);

        // The tree cache is the core's, byte for byte, and loads into a signer that signs as the
        // core's loaded key does.
        const cache = try Signer.treeCache(allocator, slot);

        try testing.expectEqualSlices(u8, try pair.private_key.exportTreeCache(allocator), cache);

        const loaded = try Memory.init(allocator, .signer, case.kind);

        var index: u64 = 0;

        try expectStatus(ok, Signer.load(case.kind, state, cache, loaded, &index));

        try testing.expectEqual(start + 3, index);

        const message = "after loading";

        try expectStatus(ok, Signer.sign(loaded, index, message, signature));

        const expected = try pair.private_key.sign(allocator, message);

        try testing.expectEqualSlices(u8, expected, signature);

        const fresh = try Memory.init(allocator, .signer, case.kind);

        try expectStatus(ok, Signer.load(case.kind, state, null, fresh, &index));

        try expectStatus(ok, Signer.sign(fresh, index, message, signature));

        try testing.expectEqualSlices(u8, expected, signature);

        for ([_]Memory{ slot, loaded, fresh }) |memory| {
            try expectStatus(ok, Signer.free(memory));

            for (memory.bytes) |b| try testing.expectEqual(0, b);
        }
    }
}

test "stateful signer rejections" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);

    defer arena.deinit();

    const allocator = arena.allocator();

    const case = stateful_cases[0];

    const seed = pattern(48, 1);

    const slot = try Memory.init(allocator, .signer, 1);

    var state: [3 + 8 + 16 + 32 + 8 + 16]u8 = undefined;

    var section_bytes = case.section[0..9].*;

    // Unknown kinds and parameter sets, lengths, an index past the capacity.
    try expectStatus(common.bad_argument, Signer.create(4, case.section, &seed, 0, &state, slot));

    try expectStatus(common.bad_argument, Signer.create(0, case.section, &seed, 0, &state, slot));

    section_bytes[4] = 0x77;

    try expectStatus(common.code(error.InvalidOption), Signer.create(1, &section_bytes, &seed, 0, &state, slot));

    try expectStatus(common.code(error.InvalidOption), Signer.create(1, case.section[0..8], &seed, 0, &state, slot));

    try expectStatus(common.code(error.InvalidOption), Signer.create(2, case.section[0..4], &pattern(96, 1), 0, state[0..0], try Memory.init(allocator, .signer, 2)));

    try expectStatus(common.code(error.InvalidLength), Signer.create(1, case.section, seed[0..47], 0, &state, slot));

    try expectStatus(common.code(error.InvalidOption), Signer.create(1, case.section, &seed, 33, &state, slot));

    try expectStatus(common.bad_argument, Signer.create(1, case.section, &seed, 0, state[0..80], slot));

    try expectStatus(common.bad_slot, Signer.create(1, case.section, &seed, 0, &state, try Memory.init(allocator, .kem_public, 0)));

    // A key created at its capacity has nothing left to sign.
    try expectStatus(ok, Signer.create(1, case.section, &seed, 32, &state, slot));

    var signature: [4 + 8 + (4 + 32 * 35) + 5 * 32]u8 = undefined;

    try expectStatus(common.code(error.KeyExhausted), Signer.sign(slot, 32, "m", &signature));

    try expectStatus(common.code(error.StateConflict), Signer.sign(slot, 31, "m", &signature));

    try expectStatus(ok, Signer.free(slot));

    try expectStatus(ok, Signer.create(1, case.section, &seed, 0, &state, slot));

    try expectStatus(common.bad_argument, Signer.sign(slot, 0, "m", signature[0 .. signature.len - 1]));

    try expectStatus(common.bad_argument, Signer.sign(slot, 0, signature[0..4], &signature));

    try expectStatus(common.code(error.KeyExhausted), Signer.sign(slot, 32, "m", &signature));

    try expectStatus(ok, Signer.sign(slot, 31, "m", &signature));

    try expectStatus(common.code(error.StateConflict), Signer.sign(slot, 0, "m", &signature));

    // A live slot is never overwritten, a copy of a slot elsewhere is refused, and a signer that
    // another call holds is busy.
    try expectStatus(common.bad_slot, Signer.create(1, case.section, &seed, 0, &state, slot));

    const copy = try Memory.init(allocator, .signer, 1);

    @memcpy(copy.bytes, slot.bytes);

    try expectStatus(common.bad_slot, Signer.sign(copy, 31, "m", &signature));

    try expectStatus(common.bad_slot, Signer.free(copy));

    try expectStatus(ok, Signer.free(slot));

    try expectStatus(common.bad_slot, Signer.free(slot));

    try expectStatus(common.bad_slot, Signer.sign(slot, 31, "m", &signature));

    // cpq_slot_wipe frees a signer too.
    try expectStatus(ok, Signer.create(1, case.section, &seed, 0, &state, slot));

    try slot.wipe();

    try expectStatus(common.bad_slot, Signer.sign(slot, 0, "m", &signature));

    // Damaged states, and states of another kind.
    var index: u64 = 0;

    var damaged = state;

    damaged[10] ^= 1;

    try expectStatus(common.code(error.InvalidPrivateKey), Signer.load(1, &damaged, null, slot, &index));

    try expectStatus(common.code(error.AlgorithmMismatch), Signer.load(2, &state, null, try Memory.init(allocator, .signer, 2), &index));

    try expectStatus(common.code(error.InvalidPrivateKey), Signer.load(1, state[0..17], null, slot, &index));

    try expectStatus(common.code(error.InvalidPrivateKey), Signer.load(1, &pattern(200, 1), null, slot, &index));

    try expectStatus(common.bad_argument, capi.stateful.load(1, &state, state.len, null, 0, 0, slot.ptr(), slot.len(), null));

    try expectStatus(common.bad_argument, capi.stateful.load(1, &state, state.len, "x", 1, 0, slot.ptr(), slot.len(), &index));

    try expectStatus(common.bad_argument, capi.stateful.load(1, &state, state.len, null, 0, 2, slot.ptr(), slot.len(), &index));

    try expectStatus(common.code(error.InvalidEncoding), Signer.load(1, &state, "x", slot, &index));

    try expectStatus(common.code(error.InvalidEncoding), Signer.load(1, &state, "", slot, &index));

    try expectStatus(common.code(error.InvalidPrivateKey), Signer.reseal(1, &damaged, 1));

    try expectStatus(common.code(error.InvalidOption), Signer.reseal(1, &state, 33));

    try expectStatus(common.code(error.InvalidPublicKey), capi.stateful.checkPublicKey(1, "short", 5));

    try expectStatus(common.rejected, Signer.verify(1, "short", "m", &signature));

    try expectStatus(common.rejected, Signer.verify(2, &pattern(80, 1), "m", &signature));
}

test "a busy stateful signer refuses a second call" {
    const allocator = testing.allocator;

    const case = stateful_cases[0];

    const slot = try Memory.init(allocator, .signer, 1);

    defer slot.deinit();

    var state: [3 + 8 + 16 + 32 + 8 + 16]u8 = undefined;

    try expectStatus(ok, Signer.create(1, case.section, &pattern(48, 3), 0, &state, slot));

    defer _ = Signer.free(slot);

    // Another call holds the signer.
    const cell = cellOf(slot);

    cell.busy.store(1, .release);

    var signature: [4 + 8 + (4 + 32 * 35) + 5 * 32]u8 = undefined;

    var size: u64 = 0;

    try expectStatus(common.code(error.StateConflict), Signer.sign(slot, 0, "m", &signature));

    try expectStatus(common.code(error.StateConflict), capi.stateful.treeCacheSize(slot.ptr(), slot.len(), &size));

    try expectStatus(common.code(error.StateConflict), Signer.free(slot));

    try expectStatus(common.code(error.StateConflict), capi.slotWipe(slot.ptr(), slot.len()));

    cell.busy.store(0, .release);

    try expectStatus(ok, Signer.sign(slot, 0, "m", &signature));
}

// The registry cell that a signer slot names.
fn cellOf(slot: Memory) *capi.stateful.Cell {
    const body: *const [2]u32 = @ptrCast(@alignCast(slot.ptr() + common.bodyOffset([2]u32)));

    return capi.stateful.cellAt(body[0]).?;
}

fn objectOf(slot: Memory) *capi.stateful.Object {
    return @ptrFromInt(cellOf(slot).object.load(.acquire));
}

fn crossStateful(_: void, r: vectors.Record, allocator: Allocator) !void {
    const kind = kindId(r.header.get("algorithm")) orelse return error.TestUnexpectedResult;

    var buffer: [65]u8 = undefined;

    const parameters = sectionOf(kind, r.values, &buffer) orelse return error.TestUnexpectedResult;

    const sizes = try Signer.info(kind, parameters);

    const seed = try field(allocator, r.values, "seed");

    const index = try vectors.number(u64, r.values.get("index"));

    const slot = try Memory.init(allocator, .signer, kind);

    const state = try allocator.alloc(u8, @intCast(sizes[1]));

    try expectStatus(ok, Signer.create(kind, parameters, seed, index, state, slot));

    try testing.expectEqualSlices(u8, try field(allocator, r.values, "state"), state);

    const public_key = try allocator.alloc(u8, @intCast(sizes[2]));

    try expectStatus(ok, Signer.publicKey(slot, public_key));

    try testing.expectEqualSlices(u8, try field(allocator, r.values, "publicKey"), public_key);

    try testing.expectEqual(try vectors.number(u64, r.values.get("remaining")), sizes[4] - index);

    const message = try field(allocator, r.values, "message");

    const expected = try field(allocator, r.values, "signature");

    const signature = try allocator.alloc(u8, @intCast(sizes[3]));

    const loaded = try Memory.init(allocator, .signer, kind);

    var loaded_index: u64 = 0;

    try expectStatus(ok, Signer.load(kind, state, null, loaded, &loaded_index));

    try testing.expectEqual(index, loaded_index);

    try expectStatus(ok, Signer.reseal(kind, state, index + 1));

    try testing.expectEqualSlices(u8, try field(allocator, r.values, "stateAfter"), state);

    for ([_]Memory{ slot, loaded }) |signer| {
        try expectStatus(ok, Signer.sign(signer, index, message, signature));

        try testing.expectEqualSlices(u8, expected, signature);

        try expectStatus(ok, Signer.free(signer));
    }

    try expectStatus(ok, Signer.verify(kind, public_key, message, signature));
}

test "cross HSS vectors through the ABI" {
    const v = try vectors.Vectors.load("cross/hss.txt", "stateAfter");

    defer v.deinit();

    try vectors.parallel(v.records, {}, crossStateful);
}

test "cross XMSS vectors through the ABI" {
    const v = try vectors.Vectors.load("cross/xmss.txt", "stateAfter");

    defer v.deinit();

    try vectors.parallel(v.records, {}, crossStateful);
}

fn crossTreeCache(_: void, r: vectors.Record, allocator: Allocator) !void {
    errdefer std.debug.print("tree cache record failed: {s}: {s}\n", .{ r.header.get("algorithm"), r.values.get("name") });

    const kind = kindId(r.header.get("algorithm")) orelse return error.TestUnexpectedResult;

    const state = try field(allocator, r.values, "state");

    const cache = try field(allocator, r.values, "treeCache");

    if (r.values.is("operation", "export")) {
        var buffer: [65]u8 = undefined;

        const parameters = sectionOf(kind, r.values, &buffer) orelse return error.TestUnexpectedResult;

        const sizes = try Signer.info(kind, parameters);

        const slot = try Memory.init(allocator, .signer, kind);

        const index = try vectors.number(u64, r.values.get("index"));

        const created = try allocator.alloc(u8, @intCast(sizes[1]));

        try expectStatus(ok, Signer.create(kind, parameters, try field(allocator, r.values, "seed"), index, created, slot));

        if (r.values.is("signed", "true")) {
            try expectStatus(ok, Signer.reseal(kind, created, index + 1));

            try expectStatus(ok, Signer.sign(slot, index, try field(allocator, r.values, "message"), try allocator.alloc(u8, @intCast(sizes[3]))));
        }

        try testing.expectEqualSlices(u8, cache, try Signer.treeCache(allocator, slot));

        try testing.expectEqualSlices(u8, state, created);

        try expectStatus(ok, Signer.free(slot));
    }

    const slot = try Memory.init(allocator, .signer, kind);

    var index: u64 = 0;

    const status = Signer.load(kind, state, cache, slot, &index);

    try testing.expectEqualStrings(r.values.get("result"), statusName(status));

    if (status != ok) return;

    defer _ = Signer.free(slot);

    const held = try Signer.signerInfo(slot);

    var public_key: [68]u8 = undefined;

    const key_size = (try field(allocator, r.values, "publicKey")).len;

    try expectStatus(ok, Signer.publicKey(slot, public_key[0..key_size]));

    try testing.expectEqualSlices(u8, try field(allocator, r.values, "publicKey"), public_key[0..key_size]);

    try testing.expectEqual(try vectors.number(u64, r.values.get("remaining")), held[0] - index);

    if (r.values.find("signature") != null) {
        const signature = try allocator.alloc(u8, @intCast(held[2]));

        try expectStatus(ok, Signer.sign(slot, index, try field(allocator, r.values, "message"), signature));

        try testing.expectEqualSlices(u8, try field(allocator, r.values, "signature"), signature);
    }
}

test "cross tree cache vectors through the ABI" {
    const v = try vectors.Vectors.load("cross/treecache.txt", "treeCache");

    defer v.deinit();

    try vectors.parallel(v.records, {}, crossTreeCache);
}

// A key that a call is inside is not wiped under it: the wipe is BUSY, the key stays whole for
// that call, no new call enters, and the call zeroes the key as it leaves.
test "a wipe of a key that a call is inside ends it when the call leaves" {
    const allocator = testing.allocator;

    const kem_slot = try Memory.init(allocator, .kem_private, 1);

    defer kem_slot.deinit();

    try expectStatus(ok, Kem.keygen(1, &pattern(64, 1), 0, kem_slot));

    const sig_slot = try Memory.init(allocator, .signature_private, 1);

    defer sig_slot.deinit();

    try expectStatus(ok, Sig.keygen(1, &pattern(32, 2), 0, sig_slot));

    const hmac_slot = try Memory.init(allocator, .hmac, 1);

    defer hmac_slot.deinit();

    try expectStatus(ok, capi.hash.hmacInit(1, "key", 3, hmac_slot.ptr(), hmac_slot.len()));

    var seed: [64]u8 = undefined;

    try expectStatus(ok, Kem.exportPrivate(kem_slot, 0, &seed));

    const insides = [_]common.Slot{
        try common.open(&.{.kem_private}, kem_slot.ptr(), kem_slot.len(), capi.kem.size, .shared),
        try common.open(&.{.signature_private}, sig_slot.ptr(), sig_slot.len(), capi.signature.size, .shared),
        try common.open(&.{.hmac}, hmac_slot.ptr(), hmac_slot.len(), capi.hash.size, .exclusive),
    };

    for ([_]Memory{ kem_slot, sig_slot, hmac_slot }, insides) |slot, inside| {
        try expectStatus(common.busy, capi.slotWipe(slot.ptr(), slot.len()));

        // The key is whole for the call inside, and no new call enters.
        try testing.expect(common.typeOf(common.loadMagic(inside.header)) != null);

        var out: [3]u32 = undefined;

        try expectStatus(common.bad_slot, capi.slotInfo(slot.ptr(), slot.len(), &out));

        try expectStatus(common.busy, capi.slotWipe(slot.ptr(), slot.len()));

        inside.close();

        for (slot.bytes) |b| try testing.expectEqual(0, b);

        try expectStatus(common.bad_slot, capi.slotInfo(slot.ptr(), slot.len(), &out));

        try slot.wipe();
    }

    try testing.expectEqualSlices(u8, &pattern(64, 1), &seed);

    try expectStatus(common.bad_slot, Kem.exportPrivate(kem_slot, 0, &seed));
}

// The review's reproduction: a binding wipes a key while other threads use it. Every answer that
// comes back OK is the key's own, and none comes from a half-wiped key.
test "a wipe racing with calls never yields an answer from a half-wiped key" {
    const allocator = testing.allocator;

    const Race = struct {
        slot: Memory,
        go: std.atomic.Value(u32) = .init(0),
        stop: std.atomic.Value(u32) = .init(0),
        calls: std.atomic.Value(u32) = .init(0),
        wrong: std.atomic.Value(u32) = .init(0),
        ciphertext: *const [1088]u8,
        expected: *const [32]u8,

        // Until the key is gone, or the wiper has been refused and lets the calls end.
        fn decapsulate(self: *@This()) void {
            while (self.go.load(.acquire) == 0) std.atomic.spinLoopHint();

            while (self.stop.load(.acquire) == 0) {
                var secret: [32]u8 = undefined;

                const status = Kem.decapsulate(self.slot, self.ciphertext, &secret);

                _ = self.calls.fetchAdd(1, .release);

                if (status == ok and !std.mem.eql(u8, &secret, self.expected)) _ = self.wrong.fetchAdd(1, .monotonic);

                if (status != ok) return;
            }
        }
    };

    const slot = try Memory.init(allocator, .kem_private, 1);

    defer slot.deinit();

    const ciphertext = pattern(1088, 9);

    var expected: [32]u8 = undefined;

    var wrong: u32 = 0;

    var refused: u64 = 0;

    for (0..100) |_| {
        @memset(slot.bytes, 0);

        try expectStatus(ok, Kem.keygen(1, &pattern(64, 5), 0, slot));

        try expectStatus(ok, Kem.decapsulate(slot, &ciphertext, &expected));

        var race: Race = .{ .slot = slot, .ciphertext = &ciphertext, .expected = &expected };

        const threads = [_]std.Thread{ try std.Thread.spawn(.{}, Race.decapsulate, .{&race}), try std.Thread.spawn(.{}, Race.decapsulate, .{&race}) };

        race.go.store(1, .release);

        while (race.calls.load(.acquire) < 4) std.atomic.spinLoopHint();

        while (true) {
            const status = capi.slotWipe(slot.ptr(), slot.len());

            if (status == ok) break;

            try expectStatus(common.busy, status);

            refused += 1;

            // Calls that follow one another without a gap would hold the wipe off for as long as
            // they go on: the binding ends them first.
            if (refused % 1000 == 0) race.stop.store(1, .release);
        }

        race.stop.store(1, .release);

        for (threads) |thread| thread.join();

        wrong += race.wrong.load(.monotonic);

        var after: [32]u8 = undefined;

        try expectStatus(common.bad_slot, Kem.decapsulate(slot, &ciphertext, &after));
    }

    try testing.expectEqual(0, wrong);

    try testing.expect(refused > 0);
}

// A state wiped while another thread updates it: the wipe waits for nothing and refuses, and no
// byte after the slot is ever written.
test "a wipe racing with an update never writes past the state" {
    const allocator = testing.allocator;

    const size = capi.slotSize(@intFromEnum(common.SlotType.xof), 1);

    const memory = try allocator.alignedAlloc(u8, .fromByteUnits(common.slot_alignment), size + 4096);

    defer allocator.free(memory);

    const data = try allocator.alloc(u8, 1 << 16);

    defer allocator.free(data);

    @memset(data, 0x3c);

    const Update = struct {
        fn run(slot: []u8, bytes: []const u8, go: *std.atomic.Value(u32)) void {
            go.store(1, .release);

            for (0..8) |_| _ = capi.hash.xofUpdate(slot.ptr, slot.len, bytes.ptr, bytes.len);
        }
    };

    for (0..50) |_| {
        @memset(memory, 0);

        @memset(memory[size..], 0xcc);

        try expectStatus(ok, capi.hash.xofInit(1, memory.ptr, size));

        try expectStatus(ok, capi.hash.xofUpdate(memory.ptr, size, data.ptr, 1));

        var go: std.atomic.Value(u32) = .init(0);

        const thread = try std.Thread.spawn(.{}, Update.run, .{ memory[0..size], data, &go });

        while (go.load(.acquire) == 0) std.atomic.spinLoopHint();

        while (capi.slotWipe(memory.ptr, size) != ok) {}

        thread.join();

        for (memory[size..]) |b| try testing.expectEqual(0xcc, b);
    }
}

// The final check of a call: a slot whose header changed during the call gives nothing back.
test "a call whose slot changes under it returns nothing" {
    const slot = try Memory.init(testing.allocator, .kem_public, 0);

    defer slot.deinit();

    const private = try Memory.init(testing.allocator, .kem_private, 0);

    defer private.deinit();

    try expectStatus(ok, Kem.keygen(0, &pattern(64, 4), 0, private));

    try expectStatus(ok, Kem.publicFromPrivate(private, slot));

    const opened = try common.open(&.{.kem_public}, slot.ptr(), slot.len(), capi.kem.size, .shared);

    var out: [32]u8 = @splat(0x77);

    try opened.confirm(&.{&out});

    try testing.expectEqual(0x77, out[0]);

    // The binding's own memset reaches the header while the call runs.
    @memset(slot.bytes[0..8], 0);

    try testing.expectError(error.BadSlot, opened.confirm(&.{&out}));

    for (out) |b| try testing.expectEqual(0, b);

    opened.close();
}

// The review's reproduction: free racing signer_info on the same slot. No call ever reaches the
// freed signer: each one either holds it whole or finds it gone.
test "a signer free racing other calls never reaches a freed signer" {
    const allocator = testing.allocator;

    const case = stateful_cases[0];

    const slot = try Memory.init(allocator, .signer, 1);

    defer slot.deinit();

    var state: [3 + 8 + 16 + 32 + 8 + 16]u8 = undefined;

    const Hammer = struct {
        slot: Memory,
        go: std.atomic.Value(u32) = .init(0),
        calls: std.atomic.Value(u32) = .init(0),
        garbage: std.atomic.Value(u32) = .init(0),

        fn run(self: *@This()) void {
            while (self.go.load(.acquire) == 0) std.atomic.spinLoopHint();

            while (true) {
                var out: [4]u64 = undefined;

                const status = capi.stateful.signerInfo(self.slot.ptr(), self.slot.len(), &out);

                _ = self.calls.fetchAdd(1, .release);

                if (status == ok and out[0] != 32) _ = self.garbage.fetchAdd(1, .monotonic);

                if (status == common.bad_slot) return;
            }
        }
    };

    var conflicts: u32 = 0;

    for (0..100) |_| {
        @memset(slot.bytes, 0);

        try expectStatus(ok, Signer.create(1, case.section, &pattern(48, 6), 0, &state, slot));

        var hammer: Hammer = .{ .slot = slot };

        const threads = [_]std.Thread{ try std.Thread.spawn(.{}, Hammer.run, .{&hammer}), try std.Thread.spawn(.{}, Hammer.run, .{&hammer}) };

        hammer.go.store(1, .release);

        while (hammer.calls.load(.acquire) < 8) std.atomic.spinLoopHint();

        while (true) {
            const status = Signer.free(slot);

            if (status == ok) break;

            try expectStatus(common.code(error.StateConflict), status);

            conflicts += 1;
        }

        for (threads) |thread| thread.join();

        try testing.expectEqual(0, hammer.garbage.load(.monotonic));
    }

    try testing.expect(conflicts > 0);
}

// A copy of a signer slot, whether elsewhere or written back over the slot after its signer was
// freed, names a signer that is not its own: every call refuses it, and a wipe takes it as plain
// memory.
test "a stale or copied signer slot is refused everywhere" {
    const allocator = testing.allocator;

    const case = stateful_cases[0];

    const slot = try Memory.init(allocator, .signer, 1);

    defer slot.deinit();

    const copy = try Memory.init(allocator, .signer, 1);

    defer copy.deinit();

    var state: [3 + 8 + 16 + 32 + 8 + 16]u8 = undefined;

    try expectStatus(ok, Signer.create(1, case.section, &pattern(48, 7), 0, &state, slot));

    @memcpy(copy.bytes, slot.bytes);

    var out: [3]u32 = undefined;

    try expectStatus(common.bad_slot, capi.slotInfo(copy.ptr(), copy.len(), &out));

    try expectStatus(ok, capi.slotInfo(slot.ptr(), slot.len(), &out));

    try testing.expectEqual([3]u32{ 8, 1, 0 }, out);

    const saved = try allocator.dupe(u8, slot.bytes);

    defer allocator.free(saved);

    try expectStatus(ok, Signer.free(slot));

    // The binding writes the old bytes back: the slot names a signer that is gone.
    @memcpy(slot.bytes, saved);

    var signature: [4 + 8 + (4 + 32 * 35) + 5 * 32]u8 = undefined;

    var info: [4]u64 = undefined;

    try expectStatus(common.bad_slot, Signer.sign(slot, 0, "m", &signature));

    try expectStatus(common.bad_slot, capi.stateful.signerInfo(slot.ptr(), slot.len(), &info));

    try expectStatus(common.bad_slot, capi.slotInfo(slot.ptr(), slot.len(), &out));

    try expectStatus(common.bad_slot, Signer.free(slot));

    // Another signer may take the cell meanwhile: the old slot still names nothing of its own.
    const other = try Memory.init(allocator, .signer, 1);

    defer other.deinit();

    try expectStatus(ok, Signer.create(1, case.section, &pattern(48, 8), 0, &state, other));

    try expectStatus(common.bad_slot, Signer.sign(slot, 0, "m", &signature));

    try slot.wipe();

    try expectStatus(ok, Signer.sign(other, 0, "m", &signature));

    try expectStatus(ok, Signer.free(other));
}

fn cellIndexOf(slot: Memory) [2]u32 {
    return @as(*const [2]u32, @ptrCast(@alignCast(slot.ptr() + common.bodyOffset([2]u32)))).*;
}

// The registry adds chunks of cells as live signers fill the ones it has and never moves a cell:
// signers created across several chunks all stay reachable, a freed signer's cell goes to a later
// signer under a new generation, and the freed slot's bytes, written back at the address that a
// later signer took, are refused everywhere, even where the later signer took the same cell.
test "the signer registry grows and reuses its cells" {
    const allocator = testing.allocator;

    const levels = [_]pq.HssLevel{.{ .lms = "LMS_SHA256_M24_H5", .ots = "LMOTS_SHA256_N24_W2" }};

    const section = codes(&levels);

    const sizes = try Signer.info(1, &section);

    try testing.expectEqual(40, sizes[0]);

    // Live at once: more than two native chunks of 256 cells and eight WebAssembly chunks of 64.
    const count = 520;

    const slots = try allocator.alloc(Memory, count);

    defer allocator.free(slots);

    var made: usize = 0;

    defer for (slots[0..made]) |slot| slot.deinit();

    while (made < count) : (made += 1) slots[made] = try Memory.init(allocator, .signer, 1);

    const state = try allocator.alloc(u8, @intCast(sizes[1]));

    defer allocator.free(state);

    const key_size: usize = @intCast(sizes[2]);

    const keys = try allocator.alloc(u8, count * key_size);

    defer allocator.free(keys);

    const signature = try allocator.alloc(u8, @intCast(sizes[3]));

    defer allocator.free(signature);

    const cells = try allocator.alloc([2]u32, count);

    defer allocator.free(cells);

    const create = struct {
        fn run(parameters: []const u8, slot: Memory, salt: u8, number: usize, state_out: []u8, key: []u8) !void {
            var seed = pattern(40, salt);

            std.mem.writeInt(u32, seed[0..4], @intCast(number), .little);

            try expectStatus(ok, Signer.create(1, parameters, &seed, 0, state_out, slot));

            try expectStatus(ok, Signer.publicKey(slot, key));
        }
    }.run;

    for (slots, 0..) |slot, i| {
        try create(&section, slot, 9, i, state, keys[i * key_size ..][0..key_size]);

        cells[i] = cellIndexOf(slot);
    }

    const indices = try allocator.alloc(u32, count);

    defer allocator.free(indices);

    for (cells, 0..) |cell, i| indices[i] = cell[0];

    std.mem.sort(u32, indices, {}, std.sort.asc(u32));

    for (indices[1..], indices[0 .. count - 1]) |next, previous| try testing.expect(next != previous);

    for (slots, 0..) |slot, i| {
        try expectStatus(ok, Signer.sign(slot, 0, "grown", signature));

        try expectStatus(ok, Signer.verify(1, keys[i * key_size ..][0..key_size], "grown", signature));
    }

    const saved = try allocator.alloc(u8, count * slots[0].len());

    defer allocator.free(saved);

    // A quarter of the signers freed together, then created again: their cells come back in
    // another order, to slots at other addresses.
    for (slots, 0..) |slot, i| {
        if (i % 4 != 0) continue;

        @memcpy(saved[i * slot.len() ..][0..slot.len()], slot.bytes);

        try expectStatus(ok, Signer.free(slot));

        try testing.expect(std.mem.allEqual(u8, slot.bytes, 0));
    }

    var reused: usize = 0;

    for (slots, 0..) |slot, i| {
        if (i % 4 != 0) continue;

        try create(&section, slot, 10, i, state, keys[i * key_size ..][0..key_size]);

        const cell = cellIndexOf(slot);

        for (cells, 0..) |old, j| {
            if (j % 4 != 0 or old[0] != cell[0]) continue;

            try testing.expect(old[1] != cell[1]);

            reused += 1;
        }
    }

    try testing.expect(reused > 0);

    // Another quarter freed and created again one by one: the same cell returns to the same slot,
    // and only the generation tells the old bytes from the new.
    var same: usize = 0;

    for (slots, 0..) |slot, i| {
        if (i % 4 != 2) continue;

        @memcpy(saved[i * slot.len() ..][0..slot.len()], slot.bytes);

        try expectStatus(ok, Signer.free(slot));

        try create(&section, slot, 11, i, state, keys[i * key_size ..][0..key_size]);

        const cell = cellIndexOf(slot);

        if (cell[0] != cells[i][0]) continue;

        try testing.expect(cell[1] != cells[i][1]);

        same += 1;
    }

    try testing.expect(same > 0);

    var out: [3]u32 = undefined;

    var words: [4]u64 = undefined;

    for (slots, 0..) |slot, i| {
        if (i % 2 != 0) continue;

        const current = try allocator.dupe(u8, slot.bytes);

        defer allocator.free(current);

        @memcpy(slot.bytes, saved[i * slot.len() ..][0..slot.len()]);

        try expectStatus(common.bad_slot, Signer.sign(slot, 1, "stale", signature));

        try expectStatus(common.bad_slot, capi.stateful.signerInfo(slot.ptr(), slot.len(), &words));

        try expectStatus(common.bad_slot, capi.slotInfo(slot.ptr(), slot.len(), &out));

        try expectStatus(common.bad_slot, Signer.free(slot));

        @memcpy(slot.bytes, current);
    }

    for (slots, 0..) |slot, i| {
        const index: u64 = if (i % 2 == 0) 0 else 1;

        try expectStatus(ok, Signer.sign(slot, index, "after reuse", signature));

        try expectStatus(ok, Signer.verify(1, keys[i * key_size ..][0..key_size], "after reuse", signature));

        try expectStatus(ok, Signer.free(slot));

        try testing.expect(std.mem.allEqual(u8, slot.bytes, 0));
    }
}

// No output of a call on a signer may land on the signer's own memory: its object, where the index
// guard lives, any of the blocks its trees take, or the registry of signers.
test "outputs over the signer's memory are refused" {
    const allocator = testing.allocator;

    const case = stateful_cases[3];

    const slot = try Memory.init(allocator, .signer, case.kind);

    defer slot.deinit();

    const sizes = try Signer.info(case.kind, case.section);

    const state = try allocator.alloc(u8, @intCast(sizes[1]));

    defer allocator.free(state);

    try expectStatus(ok, Signer.create(case.kind, case.section, &pattern(96, 9), 0, state, slot));

    defer _ = Signer.free(slot);

    const signature = try allocator.alloc(u8, @intCast(sizes[3]));

    defer allocator.free(signature);

    try expectStatus(ok, Signer.sign(slot, 20000, "message A", signature));

    const object = objectOf(slot);

    try testing.expectEqual(20001, object.next);

    try expectStatus(common.bad_argument, capi.stateful.treeCacheSize(slot.ptr(), slot.len(), &object.next));

    const words: *[4]u64 = @ptrFromInt(@intFromPtr(&object.next) - 8);

    try expectStatus(common.bad_argument, capi.stateful.signerInfo(slot.ptr(), slot.len(), words));

    try testing.expectEqual(20001, object.next);

    try expectStatus(common.code(error.StateConflict), Signer.sign(slot, 20000, "message B", signature));

    // The blocks of its trees and its object, for the byte outputs.
    for (object.tracking.ranges[0..object.tracking.count]) |range| {
        if (range.len < sizes[3]) continue;

        try expectStatus(common.bad_argument, Signer.sign(slot, 20001, "m", range[0..@intCast(sizes[3])]));

        try expectStatus(common.bad_argument, Signer.publicKey(slot, range[0..@intCast(sizes[2])]));

        break;
    }

    const bytes = std.mem.asBytes(object);

    try expectStatus(common.bad_argument, Signer.publicKey(slot, bytes[0..@intCast(sizes[2])]));

    var size: u64 = 0;

    try expectStatus(ok, capi.stateful.treeCacheSize(slot.ptr(), slot.len(), &size));

    try expectStatus(common.bad_argument, capi.stateful.exportTreeCache(slot.ptr(), slot.len(), bytes.ptr, @intCast(size)));

    const cell: [*]u8 = @ptrCast(cellOf(slot));

    try expectStatus(common.bad_argument, Signer.publicKey(slot, cell[0..@intCast(sizes[2])]));

    try testing.expectEqual(20001, object.next);

    try expectStatus(ok, Signer.sign(slot, 20001, "message C", signature));
}

// A state can move forward only: an earlier index would hand indices that were claimed back to the
// next load.
test "reseal never moves a state back" {
    const case = stateful_cases[0];

    const slot = try Memory.init(testing.allocator, .signer, 1);

    defer slot.deinit();

    var state: [3 + 8 + 16 + 32 + 8 + 16]u8 = undefined;

    try expectStatus(ok, Signer.create(1, case.section, &pattern(48, 10), 5, &state, slot));

    try expectStatus(ok, Signer.free(slot));

    try expectStatus(common.code(error.StateConflict), Signer.reseal(1, &state, 4));

    try expectStatus(common.code(error.StateConflict), Signer.reseal(1, &state, 0));

    try expectStatus(ok, Signer.reseal(1, &state, 5));

    try expectStatus(ok, Signer.reseal(1, &state, 9));

    try expectStatus(common.code(error.StateConflict), Signer.reseal(1, &state, 8));

    var index: u64 = 0;

    try expectStatus(ok, Signer.load(1, &state, null, slot, &index));

    try testing.expectEqual(9, index);

    try expectStatus(ok, Signer.free(slot));
}

// Outputs of a fixed type are checked like byte buffers: present and aligned for their words.
test "fixed-size outputs are checked" {
    const allocator = testing.allocator;

    const case = stateful_cases[0];

    const slot = try Memory.init(allocator, .signer, 1);

    defer slot.deinit();

    var state: [3 + 8 + 16 + 32 + 8 + 16]u8 = undefined;

    try expectStatus(ok, Signer.create(1, case.section, &pattern(48, 11), 0, &state, slot));

    var words: [8]u64 align(16) = undefined;

    const unaligned: *anyopaque = @ptrFromInt(@intFromPtr(&words) + 1);

    const word: *anyopaque = @ptrFromInt(@intFromPtr(&words) + 4);

    // Misaligned for uint64_t, whose alignment the target's C ABI sets: 8, or 4 on 32-bit x86.
    const odd: *anyopaque = @ptrFromInt(@intFromPtr(&words) + @alignOf(u64) / 2);

    try expectStatus(common.bad_argument, capi.slotInfo(slot.ptr(), slot.len(), null));

    try expectStatus(common.bad_argument, capi.slotInfo(slot.ptr(), slot.len(), unaligned));

    try expectStatus(ok, capi.slotInfo(slot.ptr(), slot.len(), word));

    try expectStatus(common.bad_argument, capi.stateful.info(1, case.section.ptr, case.section.len, null));

    try expectStatus(common.bad_argument, capi.stateful.info(1, case.section.ptr, case.section.len, odd));

    try expectStatus(common.bad_argument, capi.stateful.signerInfo(slot.ptr(), slot.len(), odd));

    try expectStatus(common.bad_argument, capi.stateful.treeCacheSize(slot.ptr(), slot.len(), odd));

    try expectStatus(common.bad_argument, capi.stateful.treeCacheSize(slot.ptr(), slot.len(), null));

    const other = try Memory.init(allocator, .signer, 1);

    defer other.deinit();

    try expectStatus(common.bad_argument, capi.stateful.load(1, &state, state.len, null, 0, 0, other.ptr(), other.len(), odd));

    try expectStatus(ok, Signer.free(slot));
}

// The WebAssembly allocator, which also builds natively: blocks are known by their address and
// size alone, kept out of band, and a freed block waits before its memory is handed out again.
test "the allocator keeps its blocks out of band" {
    const a = capi.memory.alloc(100);

    try testing.expect(a != 0);

    const block: [*]u8 = @ptrFromInt(a);

    // Data in a block that looks like a block header names nothing.
    @memset(block[0..100], 0x5a);

    try expectStatus(common.bad_argument, capi.memory.free(a + 48, 16));

    try expectStatus(common.bad_argument, capi.memory.free(a, 99));

    try expectStatus(common.bad_argument, capi.memory.free(std.math.maxInt(usize) - 15, 16));

    try expectStatus(ok, capi.memory.free(a, 100));

    try expectStatus(common.bad_argument, capi.memory.free(a, 100));

    // The next block does not take the freed one's place, so a stale second free finds nothing.
    const b = capi.memory.alloc(100);

    try testing.expect(b != a);

    try expectStatus(common.bad_argument, capi.memory.free(a, 100));

    try expectStatus(ok, capi.memory.free(b, 100));

    const empty = capi.memory.alloc(0);

    try testing.expect(empty != 0);

    try expectStatus(ok, capi.memory.free(empty, 0));
}

// A block or a wipe range that holds a signer slot frees the signer with it (STATE_CONFLICT while
// a call holds it), whatever the length beyond the slot.
test "freeing a block or a wider range frees the signer in it" {
    const case = stateful_cases[0];

    const size = capi.slotSize(8, 1);

    var state: [3 + 8 + 16 + 32 + 8 + 16]u8 = undefined;

    const address = capi.memory.alloc(size + 64);

    const block = @as([*]align(common.slot_alignment) u8, @ptrFromInt(address))[0 .. size + 64];

    @memset(block, 0);

    const slot: Memory = .{ .bytes = block[0..size], .allocator = testing.allocator };

    try expectStatus(ok, Signer.create(1, case.section, &pattern(48, 12), 0, &state, slot));

    const cell = cellOf(slot);

    cell.busy.store(1, .release);

    try expectStatus(common.code(error.StateConflict), capi.memory.free(address, size + 64));

    try expectStatus(common.code(error.StateConflict), capi.slotWipe(block.ptr, block.len));

    cell.busy.store(0, .release);

    const generation = cell.generation.load(.acquire);

    try expectStatus(ok, capi.memory.free(address, size + 64));

    try testing.expectEqual(0, cell.object.load(.acquire));

    try testing.expect(cell.generation.load(.acquire) != generation);

    // cpq_slot_wipe of the slot and the slack after it.
    const memory = try testing.allocator.alignedAlloc(u8, .fromByteUnits(common.slot_alignment), size + 16);

    defer testing.allocator.free(memory);

    @memset(memory, 0);

    const wide: Memory = .{ .bytes = memory[0..size], .allocator = testing.allocator };

    try expectStatus(ok, Signer.create(1, case.section, &pattern(48, 13), 0, &state, wide));

    const wide_cell = cellOf(wide);

    try expectStatus(ok, capi.slotWipe(memory.ptr, memory.len));

    try testing.expectEqual(0, wide_cell.object.load(.acquire));

    for (memory) |b| try testing.expectEqual(0, b);
}

// An import refused for its arguments writes nothing: a key that lies in the slot memory is left as
// it was.
test "a refused import leaves its input alone" {
    const allocator = testing.allocator;

    const kem_slot = try Memory.init(allocator, .kem_private, 1);

    defer kem_slot.deinit();

    const kem_key = kem_slot.bytes[1024..][0..64];

    @memset(kem_key, 0x5a);

    try expectStatus(common.bad_argument, capi.kem.importPrivate(1, kem_key.ptr, kem_key.len, kem_slot.ptr(), kem_slot.len()));

    for (kem_key) |b| try testing.expectEqual(0x5a, b);

    const sig_slot = try Memory.init(allocator, .signature_private, 1);

    defer sig_slot.deinit();

    const sig_key = sig_slot.bytes[2048..][0..32];

    @memset(sig_key, 0x5a);

    try expectStatus(common.bad_argument, capi.signature.importPrivate(1, sig_key.ptr, sig_key.len, sig_slot.ptr(), sig_slot.len()));

    for (sig_key) |b| try testing.expectEqual(0x5a, b);

    // And a key that the checks refuse leaves no part of itself in the slot.
    var key = pattern(64, 3);

    try expectStatus(common.code(error.InvalidLength), capi.kem.importPrivate(1, &key, 63, kem_slot.ptr(), kem_slot.len()));

    for (kem_slot.bytes) |b| try testing.expect(b == 0xa5 or b == 0x5a);
}

// A state whose body the binding damaged is refused before any of it is used: no loop on a zero
// rate, no copy or write out of bounds, no tag that a zeroed state would predictably give.
test "a damaged state is refused, never used" {
    const allocator = testing.allocator;

    // A field of the engine, overwritten whole in the target's byte order.
    const Case = struct {
        slot_type: common.SlotType,
        algorithm: u32,
        offset: usize,
        width: usize,
        value: u64,
    };

    const sha256 = common.bodyOffset(@import("sha2.zig").Sha256);

    const keccak = common.bodyOffset(@import("keccak.zig").Keccak);

    const Keccak = @import("keccak.zig").Keccak;

    const Sha256 = @import("sha2.zig").Sha256;

    const cases = [_]Case{
        .{ .slot_type = .hasher, .algorithm = 1, .offset = sha256 + @offsetOf(Sha256, "used"), .width = @sizeOf(usize), .value = 200 },
        .{ .slot_type = .hasher, .algorithm = 1, .offset = sha256 + @offsetOf(Sha256, "length"), .width = 8, .value = 7 },
        .{ .slot_type = .hasher, .algorithm = 7, .offset = keccak + @offsetOf(Keccak, "rate"), .width = @sizeOf(usize), .value = 0 },
        .{ .slot_type = .hasher, .algorithm = 7, .offset = keccak + @offsetOf(Keccak, "squeezing"), .width = 1, .value = 1 },
        .{ .slot_type = .xof, .algorithm = 1, .offset = keccak + @offsetOf(Keccak, "rate"), .width = @sizeOf(usize), .value = 0 },
        .{ .slot_type = .xof, .algorithm = 1, .offset = keccak + @offsetOf(Keccak, "position"), .width = @sizeOf(usize), .value = 200 },
        .{ .slot_type = .xof, .algorithm = 1, .offset = keccak + @offsetOf(Keccak, "squeezing"), .width = 1, .value = 2 },
        .{ .slot_type = .xof, .algorithm = 0, .offset = keccak + @offsetOf(Keccak, "suffix"), .width = 1, .value = 0x06 },
    };

    for (cases) |case| {
        const size = capi.slotSize(@intFromEnum(case.slot_type), case.algorithm);

        const memory = try allocator.alignedAlloc(u8, .fromByteUnits(common.slot_alignment), size + 64);

        defer allocator.free(memory);

        @memset(memory, 0);

        @memset(memory[size..], 0xcc);

        const slot = memory[0..size];

        try expectStatus(ok, switch (case.slot_type) {
            .hasher => capi.hash.init(case.algorithm, slot.ptr, size),
            else => capi.hash.xofInit(case.algorithm, slot.ptr, size),
        });

        const damaged = slot[case.offset..][0..case.width];

        switch (case.width) {
            1 => damaged[0] = @intCast(case.value),
            4 => std.mem.writeInt(u32, damaged[0..4], @intCast(case.value), builtin.cpu.arch.endian()),
            8 => std.mem.writeInt(u64, damaged[0..8], case.value, builtin.cpu.arch.endian()),
            else => unreachable,
        }

        var out: [64]u8 = undefined;

        const data: [300]u8 = @splat(0x11);

        switch (case.slot_type) {
            .hasher => {
                try expectStatus(common.bad_slot, capi.hash.update(slot.ptr, size, &data, data.len));

                try expectStatus(common.bad_slot, capi.hash.final(slot.ptr, size, &out, if (case.algorithm == 1) 32 else 32));
            },
            else => {
                try expectStatus(common.bad_slot, capi.hash.xofUpdate(slot.ptr, size, &data, data.len));

                try expectStatus(common.bad_slot, capi.hash.xofRead(slot.ptr, size, &out, out.len));
            },
        }

        for (memory[size..]) |b| try testing.expectEqual(0xcc, b);

        try expectStatus(ok, capi.slotWipe(slot.ptr, size));
    }

    // An HMAC state with a zeroed body, as a wipe in the middle of a call would have left it.
    const hmac = try Memory.init(allocator, .hmac, 1);

    defer hmac.deinit();

    try expectStatus(ok, capi.hash.hmacInit(1, "key", 3, hmac.ptr(), hmac.len()));

    const body = common.bodyOffset([2]Sha256);

    @memset(hmac.bytes[body..], 0);

    var tag: [32]u8 = @splat(0);

    try expectStatus(common.bad_slot, capi.hash.hmacFinalVerify(hmac.ptr(), hmac.len(), &tag, 32));

    try expectStatus(common.bad_slot, capi.hash.hmacFinal(hmac.ptr(), hmac.len(), &tag, 32));
}

// A copy of a key slot, made while another call filled its cache, may hold a value that the copy
// caught half-written under a state that says it is filled. The state names the address it was
// filled at, so the copy never trusts it and fills its own: its answers are the key's.
test "a copied slot never trusts a cache filled elsewhere" {
    const allocator = testing.allocator;

    const S = capi.kem.Set(1);

    const private = try Memory.init(allocator, .kem_private, 1);

    defer private.deinit();

    try expectStatus(ok, Kem.keygen(1, &pattern(64, 21), capi.kem.fill_cache, private));

    const copy = try Memory.init(allocator, .kem_private, 1);

    defer copy.deinit();

    @memcpy(copy.bytes, private.bytes);

    // The value as a torn copy may hold it, under the original's ready state.
    const body: *S.Private = @ptrFromInt(@intFromPtr(copy.ptr()) + common.bodyOffset(S.Private));

    @memset(std.mem.asBytes(&body.public.form.value), 0);

    try testing.expect(!body.public.form.isReady());

    var flags: [3]u32 = undefined;

    try expectStatus(ok, capi.slotInfo(copy.ptr(), copy.len(), &flags));

    try testing.expectEqual(0, flags[2] & 0x100);

    const m = pattern(32, 22);

    var ciphertext: [S.ciphertext_size]u8 = undefined;

    var expected: [S.ciphertext_size]u8 = undefined;

    var secret: [32]u8 = undefined;

    try expectStatus(ok, Kem.encapsulate(private, &m, &expected, &secret));

    try expectStatus(ok, Kem.encapsulate(copy, &m, &ciphertext, &secret));

    try testing.expectEqualSlices(u8, &expected, &ciphertext);

    try testing.expect(body.public.form.isReady());

    try copy.wipe();

    try private.wipe();
}

const std = @import("std");
const builtin = @import("builtin");

const aarch64 = @import("aarch64.zig");
const cpu = @import("cpu.zig");
const keccak = @import("keccak.zig");
const mldsa = @import("mldsa.zig");
const mlkem = @import("mlkem.zig");
const sha2 = @import("sha2.zig");
const x86_64 = @import("x86_64.zig");

// Every CPU-specific kernel against the portable code, on random inputs and edge cases, whenever
// the CPU running the tests has its instructions. Nothing in the library imports this file, so
// these run once, from their own test binary.

const testing = std.testing;

const arch = builtin.cpu.arch;

const runs = 20_000;

// The first runs are edge cases: all zeros, all ones, and one byte flipped in either.
fn fill(random: std.Random, bytes: []u8, case: usize) void {
    switch (case) {
        0 => @memset(bytes, 0),
        1 => @memset(bytes, 0xff),
        2, 3 => {
            @memset(bytes, if (case == 2) 0 else 0xff);

            bytes[random.uintLessThan(usize, bytes.len)] ^= 0xff;
        },
        else => random.bytes(bytes),
    }
}

const Kernel256 = enum { aarch64, sha_ni, avx2 };

fn checkBlocks256(comptime kernel: Kernel256, random: std.Random) !void {
    for (0..runs) |case| {
        var state: [8]u32 = undefined;

        var blocks: [3 * 64]u8 = undefined;

        fill(random, std.mem.asBytes(&state), case);

        fill(random, &blocks, case);

        const count = 1 + case % 3;

        var expected = state;

        for (0..count) |b| sha2.portable.compress256(&expected, blocks[64 * b ..][0..64]);

        var got = state;

        switch (kernel) {
            .aarch64 => aarch64.sha256Blocks(&got, blocks[0 .. 64 * count]),
            .sha_ni => x86_64.sha256Blocks(&got, blocks[0 .. 64 * count]),
            .avx2 => unreachable,
        }

        try testing.expectEqualSlices(u32, &expected, &got);

        var words: [16]u32 = undefined;

        fill(random, std.mem.asBytes(&words), case);

        var portable = state;

        sha2.portable.rounds256(u32, &portable, &words);

        var instructions = state;

        switch (kernel) {
            .aarch64 => aarch64.sha256Rounds(u32, &instructions, &words),
            .sha_ni => x86_64.sha256Rounds(u32, &instructions, &words),
            .avx2 => unreachable,
        }

        try testing.expectEqualSlices(u32, &portable, &instructions);
    }
}

fn checkLanes256(comptime kernel: Kernel256, comptime L: usize, random: std.Random, count: usize) !void {
    const V = @Vector(L, u32);

    for (0..count) |case| {
        var state: [8]V = undefined;

        var words: [16]V = undefined;

        fill(random, std.mem.asBytes(&state), case);

        fill(random, std.mem.asBytes(&words), case);

        var expected = state;

        sha2.portable.rounds256(V, &expected, &words);

        var got = state;

        switch (kernel) {
            .aarch64 => aarch64.sha256Rounds(V, &got, &words),
            .sha_ni => x86_64.sha256Rounds(V, &got, &words),
            .avx2 => x86_64.sha256x8(&got, &words),
        }

        for (expected, got) |x, y| try testing.expectEqual(x, y);
    }
}

fn checkKeccak(comptime N: usize, comptime kernel: fn (*[N][25]u64) void, random: std.Random) !void {
    for (0..runs) |case| {
        var states: [N][25]u64 = undefined;

        fill(random, std.mem.asBytes(&states), case);

        var expected = states;

        for (&expected) |*state| keccak.portable.permute(state);

        kernel(&states);

        try testing.expectEqualSlices(u8, std.mem.asBytes(&expected), std.mem.asBytes(&states));
    }

    // Keccak-f[1600] of the zero state, from the Keccak team's known answers.
    var zero: [N][25]u64 = @splat(@splat(0));

    kernel(&zero);

    for (zero) |state| try testing.expectEqual(0xf1258f7940e1dde7, state[0]);
}

test "AArch64 SHA-256 instructions match the portable code" {
    if (comptime arch != .aarch64 or !cpu.possible(.sha256)) return error.SkipZigTest;

    if (!cpu.has(.sha256)) return error.SkipZigTest;

    var prng: std.Random.DefaultPrng = .init(0x256);

    const random = prng.random();

    try checkBlocks256(.aarch64, random);

    try checkLanes256(.aarch64, 8, random, runs);

    try checkLanes256(.aarch64, 1, random, runs / 10);

    try checkLanes256(.aarch64, 2, random, runs / 10);

    try checkLanes256(.aarch64, 6, random, runs / 10);

    try checkLanes256(.aarch64, 16, random, runs / 10);
}

fn checkLanes512(comptime L: usize, random: std.Random, count: usize) !void {
    const V = @Vector(L, u64);

    for (0..count) |case| {
        var state: [8]V = undefined;

        var words: [16]V = undefined;

        fill(random, std.mem.asBytes(&state), case);

        fill(random, std.mem.asBytes(&words), case);

        var expected = state;

        sha2.portable.rounds512(V, &expected, &words);

        var got = state;

        aarch64.sha512Rounds(V, &got, &words);

        for (expected, got) |x, y| try testing.expectEqual(x, y);
    }
}

test "AArch64 SHA-512 instructions match the portable code" {
    if (comptime arch != .aarch64 or !cpu.possible(.sha512)) return error.SkipZigTest;

    if (!cpu.has(.sha512)) return error.SkipZigTest;

    var prng: std.Random.DefaultPrng = .init(0x512);

    const random = prng.random();

    for (0..runs) |case| {
        var state: [8]u64 = undefined;

        var blocks: [3 * 128]u8 = undefined;

        fill(random, std.mem.asBytes(&state), case);

        fill(random, &blocks, case);

        const count = 1 + case % 3;

        var expected = state;

        for (0..count) |b| sha2.portable.compress512(&expected, blocks[128 * b ..][0..128]);

        var got = state;

        aarch64.sha512Blocks(&got, blocks[0 .. 128 * count]);

        try testing.expectEqualSlices(u64, &expected, &got);

        var words: [16]u64 = undefined;

        fill(random, std.mem.asBytes(&words), case);

        var portable = state;

        sha2.portable.rounds512(u64, &portable, &words);

        var instructions = state;

        aarch64.sha512Rounds(u64, &instructions, &words);

        try testing.expectEqualSlices(u64, &portable, &instructions);
    }

    try checkLanes512(8, random, runs);

    try checkLanes512(1, random, runs / 10);

    try checkLanes512(3, random, runs / 10);
}

test "AArch64 Keccak pairs with the SHA3 instructions match the portable permutation" {
    if (comptime arch != .aarch64 or !cpu.possible(.sha3)) return error.SkipZigTest;

    // The kernel runs on any core with the instructions; the dispatch picks it only on Apple's.
    const instructions = cpu.has(.sha3) or (builtin.os.tag == .linux and std.os.linux.getauxval(std.elf.AT_HWCAP) & 1 << 17 != 0);

    if (!instructions) return error.SkipZigTest;

    var prng: std.Random.DefaultPrng = .init(0x3);

    try checkKeccak(1, oneState, prng.random());

    try checkKeccak(2, aarch64.keccak2, prng.random());
}

fn oneState(states: *[1][25]u64) void {
    aarch64.keccak1(&states[0]);
}

// Every 16-bit input against the zetas and the extremes of the multipliers, and random 32-bit
// inputs with the ML-DSA zetas, edge values and random multipliers. b_qinv is always
// b * q^-1, as in every caller.
test "AArch64 Montgomery and Barrett reductions equal the portable formulas" {
    if (comptime !cpu.neon) return error.SkipZigTest;

    const V16 = @Vector(8, i16);

    const extremes = [_]i16{ 0, 1, -1, mlkem.q - 1, 1 - mlkem.q, std.math.maxInt(i16), std.math.minInt(i16) + 1 };

    for (0..65536 / 8) |chunk| {
        const a: V16 = @bitCast(@as(@Vector(8, u16), @splat(@intCast(8 * chunk))) + std.simd.iota(u16, 8));

        try testing.expectEqual(mlkem.portable.barrett(a), mlkem.barrett(a));

        for (mlkem.zetas ++ extremes) |zeta| {
            const b: V16 = @splat(zeta);

            const b_qinv = b *% @as(V16, @splat(mlkem.q_inverse));

            try testing.expectEqual(mlkem.portable.montgomery(a, b, b_qinv), mlkem.montgomery(a, b, b_qinv));
        }
    }

    const V32 = @Vector(8, i32);

    var prng: std.Random.DefaultPrng = .init(0x32);

    const random = prng.random();

    const edges = [_]i32{ 0, 1, -1, mldsa.q, -mldsa.q, std.math.maxInt(i32), std.math.minInt(i32) };

    for (0..runs) |case| {
        var a: [8]i32 = undefined;

        var b: [8]i32 = undefined;

        for (&a, &b, 0..) |*x, *y, lane| {
            x.* = if (case < edges.len) edges[case] else random.int(i32);

            const multiplier = random.int(i32);

            y.* = switch (lane % 4) {
                0 => mldsa.zetas[random.uintLessThan(usize, 256)],
                1 => if (multiplier == std.math.minInt(i32)) 0 else multiplier,
                2 => edges[random.uintLessThan(usize, edges.len - 1)],
                else => @intCast(random.intRangeAtMost(i64, -mldsa.q, mldsa.q)),
            };
        }

        const b_qinv = @as(V32, b) *% @as(V32, @splat(mldsa.q_inverse));

        try testing.expectEqual(mldsa.portable.montgomery(a, b, b_qinv), mldsa.montgomery(a, b, b_qinv));
    }
}

test "x86-64 SHA-NI matches the portable code" {
    if (comptime arch != .x86_64 or !cpu.possible(.sha256)) return error.SkipZigTest;

    if (!cpu.has(.sha256)) return error.SkipZigTest;

    var prng: std.Random.DefaultPrng = .init(0x256);

    const random = prng.random();

    try checkBlocks256(.sha_ni, random);

    try checkLanes256(.sha_ni, 8, random, runs);

    try checkLanes256(.sha_ni, 1, random, runs / 10);

    try checkLanes256(.sha_ni, 3, random, runs / 10);

    try checkLanes256(.sha_ni, 16, random, runs / 10);
}

test "x86-64 AVX2 SHA-256 in eight lanes matches the portable code" {
    if (comptime arch != .x86_64 or !cpu.possible(.avx2)) return error.SkipZigTest;

    if (!cpu.has(.avx2)) return error.SkipZigTest;

    var prng: std.Random.DefaultPrng = .init(0x8256);

    try checkLanes256(.avx2, 8, prng.random(), runs);
}

test "x86-64 AVX2 Keccak in four lanes matches the portable permutation" {
    if (comptime arch != .x86_64 or !cpu.possible(.avx2)) return error.SkipZigTest;

    if (!cpu.has(.avx2)) return error.SkipZigTest;

    var prng: std.Random.DefaultPrng = .init(0x4);

    try checkKeccak(4, x86_64.keccak4, prng.random());
}

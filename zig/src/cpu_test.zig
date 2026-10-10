const std = @import("std");
const builtin = @import("builtin");

const aarch64 = @import("aarch64.zig");
const blake2 = @import("blake2.zig");
const cpu = @import("cpu.zig");
const hash = @import("hash.zig");
const hazmat = @import("hazmat.zig");
const kdf = @import("kdf.zig");
const keccak = @import("keccak.zig");
const kem = @import("kem.zig");
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

// The digest of `absorbed` bytes already compressed into state followed by data, with the padding
// built byte by byte and every block through the portable code.
fn portableFinish(comptime Word: type, state: [8]Word, absorbed: usize, data: []const u8) [8]Word {
    const block = 16 * @sizeOf(Word);

    const field = 2 * @sizeOf(Word);

    var s = state;

    var buffer: [2 * block + 300]u8 = @splat(0);

    @memcpy(buffer[0..data.len], data);

    buffer[data.len] = 0x80;

    const end = (data.len + 1 + field + block - 1) / block * block;

    std.mem.writeInt(u64, buffer[end - 8 ..][0..8], (absorbed + data.len) * 8, .big);

    var offset: usize = 0;

    while (offset < end) : (offset += block) {
        if (Word == u32) sha2.portable.compress256(&s, buffer[offset..][0..block]) else sha2.portable.compress512(&s, buffer[offset..][0..block]);
    }

    return s;
}

fn portableKeyed(comptime Word: type, iv: *const [8]Word, key: []const u8) [2][8]Word {
    const block = 16 * @sizeOf(Word);

    var keyed: [2][8]Word = .{ iv.*, iv.* };

    for (&keyed, [_]u8{ 0x36, 0x5c }) |*state, pad| {
        var bytes: [block]u8 = @splat(pad);

        for (bytes[0..key.len], key) |*byte, k| byte.* ^= k;

        if (Word == u32) sha2.portable.compress256(state, &bytes) else sha2.portable.compress512(state, &bytes);
    }

    return keyed;
}

fn portableHmac(comptime Word: type, iv: *const [8]Word, key: []const u8, data: []const u8, size: usize) [64]u8 {
    const block = 16 * @sizeOf(Word);

    const keyed = portableKeyed(Word, iv, key);

    var inner: [64]u8 = undefined;

    for (portableFinish(Word, keyed[0], block, data), 0..) |word, i| std.mem.writeInt(Word, inner[@sizeOf(Word) * i ..][0..@sizeOf(Word)], word, .big);

    var tag: [64]u8 = undefined;

    for (portableFinish(Word, keyed[1], block, inner[0..size]), 0..) |word, i| std.mem.writeInt(Word, tag[@sizeOf(Word) * i ..][0..@sizeOf(Word)], word, .big);

    return tag;
}

test "AArch64 one-shot SHA-256 and HMAC-SHA-256 match the portable code" {
    if (comptime arch != .aarch64 or !cpu.possible(.sha256)) return error.SkipZigTest;

    if (!cpu.has(.sha256)) return error.SkipZigTest;

    var prng: std.Random.DefaultPrng = .init(0x48);

    const random = prng.random();

    var data: [300]u8 = undefined;

    for (0..data.len) |length| {
        fill(random, &data, length);

        const message = data[0..length];

        var state = sha2.iv_256;

        aarch64.sha256Finish(&state, message, length * 8);

        try testing.expectEqualSlices(u32, &portableFinish(u32, sha2.iv_256, 0, message), &state);

        const key = data[length / 3 ..][0 .. length % 65];

        for ([_]usize{ 32, 28 }, [_]*const [8]u32{ &sha2.iv_256, &sha2.iv_224 }) |size, iv| {
            var tag: [32]u8 = undefined;

            const expected = portableHmac(u32, iv, key, message, size);

            aarch64.hmac256(iv, key, message, tag[0..size]);

            try testing.expectEqualSlices(u8, expected[0..size], tag[0..size]);

            // The keyed states once, then tags from them.
            const keyed = aarch64.keyed256(iv, key);

            try testing.expectEqual(portableKeyed(u32, iv, key), keyed);

            @memset(&tag, 0);

            aarch64.hmacKeyed256(&keyed, message, tag[0..size]);

            try testing.expectEqualSlices(u8, expected[0..size], tag[0..size]);
        }
    }
}

test "AArch64 one-shot SHA-512 and HMAC-SHA-512 match the portable code" {
    if (comptime arch != .aarch64 or !cpu.possible(.sha512)) return error.SkipZigTest;

    if (!cpu.has(.sha512)) return error.SkipZigTest;

    var prng: std.Random.DefaultPrng = .init(0x96);

    const random = prng.random();

    var data: [300]u8 = undefined;

    for (0..data.len) |length| {
        fill(random, &data, length);

        const message = data[0..length];

        var state = sha2.iv_512;

        aarch64.sha512Finish(&state, message, length * 8);

        try testing.expectEqualSlices(u64, &portableFinish(u64, sha2.iv_512, 0, message), &state);

        const key = data[length / 3 ..][0 .. length % 129];

        for ([_]usize{ 64, 48 }, [_]*const [8]u64{ &sha2.iv_512, &sha2.iv_384 }) |size, iv| {
            var tag: [64]u8 = undefined;

            const expected = portableHmac(u64, iv, key, message, size);

            aarch64.hmac512(iv, key, message, tag[0..size]);

            try testing.expectEqualSlices(u8, expected[0..size], tag[0..size]);

            const keyed = aarch64.keyed512(iv, key);

            try testing.expectEqual(portableKeyed(u64, iv, key), keyed);

            @memset(&tag, 0);

            aarch64.hmacKeyed512(&keyed, message, tag[0..size]);

            try testing.expectEqualSlices(u8, expected[0..size], tag[0..size]);
        }
    }
}

test "AArch64 Keccak pairs with the SHA3 instructions match the portable permutation" {
    if (comptime arch != .aarch64 or !cpu.possible(.sha3)) return error.SkipZigTest;

    // The kernel runs on any core with the instructions; the dispatch picks it only on Apple's.
    const instructions = cpu.has(.sha3) or (builtin.os.tag == .linux and std.os.linux.getauxval(std.elf.AT_HWCAP) & 1 << 17 != 0);

    if (!instructions) return error.SkipZigTest;

    var prng: std.Random.DefaultPrng = .init(0x3);

    try checkKeccak(1, oneState, prng.random());

    try checkKeccak(2, aarch64.keccak2, prng.random());

    try checkKeccak(3, aarch64.keccak3, prng.random());
}

fn oneState(states: *[1][25]u64) void {
    aarch64.keccak1(&states[0]);
}

// The absorbing kernel against XOR and the portable permutation block by block, for every rate it
// takes and one to three blocks.
test "AArch64 Keccak absorption with the SHA3 instructions matches the portable code" {
    if (comptime arch != .aarch64 or !cpu.possible(.sha3)) return error.SkipZigTest;

    if (!cpu.has(.sha3)) return error.SkipZigTest;

    var prng: std.Random.DefaultPrng = .init(0xab5);

    const random = prng.random();

    const rates = [_]usize{ 72, 104, 136, 144, 168 };

    for (0..runs / 4) |case| {
        const rate = rates[case % rates.len];

        const blocks = 1 + case / 5 % 3;

        var state: [25]u64 = undefined;

        var data: [3 * 168]u8 = undefined;

        fill(random, std.mem.asBytes(&state), case / 15);

        fill(random, &data, case / 15);

        var expected = state;

        for (0..blocks) |b| {
            keccak.xorBytes(&expected, 0, data[rate * b ..][0..rate]);

            keccak.portable.permute(&expected);
        }

        aarch64.keccakAbsorb(&state, rate, data[0 .. rate * blocks]);

        try testing.expectEqualSlices(u64, &expected, &state);
    }
}

// A sponge fed in pieces of every length, which takes the absorbing kernel wherever whole blocks
// start at a block boundary, against a sponge built from the portable permutation.
test "Keccak sponges match the portable permutation for every split of the input" {
    var prng: std.Random.DefaultPrng = .init(0x5f0);

    const random = prng.random();

    var data: [1000]u8 = undefined;

    random.bytes(&data);

    for ([_]usize{ 72, 104, 136, 144, 168 }) |rate| {
        for ([_]usize{ 0, 1, 7, 8, 71, 72, 73, 135, 136, 137, 167, 168, 169, 400, 1000 }) |length| {
            for ([_]usize{ 1, 5, 64, 136, 168, 1000 }) |piece| {
                var sponge = keccak.Keccak.init(rate, 0x1f);

                var offset: usize = 0;

                while (offset < length) : (offset += piece) sponge.update(data[offset..@min(length, offset + piece)]);

                var got: [300]u8 = undefined;

                sponge.read(&got);

                var state: [25]u64 = @splat(0);

                var position: usize = 0;

                for (data[0..length]) |byte| {
                    keccak.xorBytes(&state, position, &.{byte});

                    position += 1;

                    if (position == rate) {
                        keccak.portable.permute(&state);

                        position = 0;
                    }
                }

                keccak.xorBytes(&state, position, &.{0x1f});

                keccak.xorBytes(&state, rate - 1, &.{0x80});

                var expected: [300]u8 = undefined;

                var written: usize = 0;

                while (written < expected.len) : (written += rate) {
                    keccak.portable.permute(&state);

                    const take = @min(rate, expected.len - written);

                    keccak.copyBytes(&state, 0, expected[written..][0..take]);
                }

                try testing.expectEqualSlices(u8, &expected, &got);
            }
        }
    }
}

// The dispatch of one to four states against the portable permutation; states past the count
// may be permuted too, as scratch.
test "Keccak batches of one to four states match the portable permutation" {
    var prng: std.Random.DefaultPrng = .init(0xb47);

    const random = prng.random();

    for (0..2000) |case| {
        const count = 1 + case % 4;

        var states: [4][25]u64 = undefined;

        fill(random, std.mem.asBytes(&states), case / 4);

        var expected = states;

        for (expected[0..count]) |*state| keccak.portable.permute(state);

        keccak.permuteSome(&states, count);

        for (expected[0..count], states[0..count]) |*e, *g| try testing.expectEqualSlices(u64, e, g);
    }
}

// Blocks for the rejection samplers: random ones after edge cases (all zeros accepts every
// candidate, all ones rejects every one), and blocks of candidates drawn from values around the
// bounds, in three-byte groups as the samplers read them.
fn fillCandidates(random: std.Random, block: []u8, case: usize) void {
    if (case < 4) return fill(random, block, case);

    switch (case % 4) {
        0 => {
            const edges = [_]u16{ 0, 1, mlkem.q - 1, mlkem.q, mlkem.q + 1, 4095 };

            var i: usize = 0;

            while (i + 3 <= block.len) : (i += 3) {
                const a = edges[random.uintLessThan(usize, edges.len)];

                const b = edges[random.uintLessThan(usize, edges.len)];

                block[i] = @truncate(a);

                block[i + 1] = @truncate((a >> 8) | (b << 4));

                block[i + 2] = @truncate(b >> 4);
            }
        },
        1 => {
            const edges = [_]u32{ 0, 1, mldsa.q - 1, mldsa.q, mldsa.q + 1, (1 << 23) - 1 };

            var i: usize = 0;

            while (i + 3 <= block.len) : (i += 3) {
                // The top bit of every third byte is not part of the candidate.
                const z = edges[random.uintLessThan(usize, edges.len)] | @as(u32, random.int(u1)) << 23;

                block[i] = @truncate(z);

                block[i + 1] = @truncate(z >> 8);

                block[i + 2] = @truncate(z >> 16);
            }
        },
        2 => {
            // Half-bytes at the bounds of both eta.
            const edges = [_]u8{ 0, 1, 4, 8, 9, 14, 15 };

            for (block) |*byte| byte.* = edges[random.uintLessThan(usize, edges.len)] | edges[random.uintLessThan(usize, edges.len)] << 4;
        },
        else => random.bytes(block),
    }
}

// Coefficients anywhere in (-q, q), the range the encoding takes, and its edges.
test "AArch64 ByteEncode_12 matches the portable code" {
    if (comptime !cpu.neon) return error.SkipZigTest;

    var prng: std.Random.DefaultPrng = .init(0xe12);

    const random = prng.random();

    const edges = [_]i16{ 0, 1, -1, mlkem.q - 1, 1 - mlkem.q, mlkem.q / 2, -(mlkem.q / 2) };

    for (0..runs / 4) |case| {
        var f: mlkem.Poly = undefined;

        for (&f, 0..) |*c, i| c.* = if (case < edges.len) edges[case] else if (case % 4 == 0) edges[i % edges.len] else random.intRangeAtMost(i16, 1 - mlkem.q, mlkem.q - 1);

        var expected: [384]u8 = undefined;

        var got: [384]u8 = undefined;

        mlkem.portable.encode12(&f, &expected);

        aarch64.encode12(&f, &got);

        try testing.expectEqualSlices(u8, &expected, &got);
    }
}

test "AArch64 rejection sampling matches the portable code" {
    if (comptime !cpu.neon) return error.SkipZigTest;

    var prng: std.Random.DefaultPrng = .init(0x5a);

    const random = prng.random();

    const starts = [_]usize{ 0, 1, 100, 200, 240, 247, 248, 249, 250, 252, 255 };

    for (0..runs) |case| {
        var block: [168]u8 = undefined;

        fillCandidates(random, &block, case);

        const start = if (case % 3 == 0) random.uintLessThan(usize, 256) else starts[case % starts.len];

        var prefix: [256]i32 = undefined;

        for (&prefix) |*value| value.* = random.int(i32);

        var expected12: [mlkem.sample_buffer]i16 = undefined;

        var got12: [mlkem.sample_buffer]i16 = undefined;

        for (expected12[0..start], got12[0..start], prefix[0..start]) |*e, *g, value| {
            e.* = @truncate(value);

            g.* = @truncate(value);
        }

        const e12 = @min(256, mlkem.portable.parseUniform(&expected12, start, &block));

        const g12 = @min(256, aarch64.uniform12(&got12, start, &block));

        try testing.expectEqual(e12, g12);

        try testing.expectEqualSlices(i16, expected12[0..e12], got12[0..g12]);

        var expected23: [256]i32 = undefined;

        var got23: [256]i32 = undefined;

        @memcpy(expected23[0..start], prefix[0..start]);

        @memcpy(got23[0..start], prefix[0..start]);

        const e23 = mldsa.portable.parseUniform(&expected23, start, &block);

        const g23 = aarch64.uniform23(&got23, start, &block);

        try testing.expectEqual(e23, g23);

        try testing.expectEqualSlices(i32, expected23[0..e23], got23[0..g23]);

        inline for (.{ 2, 4 }) |eta| {
            var expected: [mldsa.sample_buffer]i32 = undefined;

            var got: [mldsa.sample_buffer]i32 = undefined;

            @memcpy(expected[0..start], prefix[0..start]);

            @memcpy(got[0..start], prefix[0..start]);

            const e = @min(256, mldsa.portable.parseBounded(eta, &expected, start, block[0..136]));

            const g = @min(256, aarch64.bounded(eta, &got, start, block[0..136]));

            try testing.expectEqual(e, g);

            try testing.expectEqualSlices(i32, expected[0..e], got[0..g]);
        }
    }
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

fn blake2Words(comptime W: type, bytes: []const u8) [16]W {
    var m: [16]W = undefined;

    for (&m, 0..) |*x, i| x.* = std.mem.readInt(W, bytes[@sizeOf(W) * i ..][0..@sizeOf(W)], .little);

    return m;
}

// One to three blocks, and a last block with the final flag, against the portable compression;
// some counters sit just below the carry out of their low word.
fn checkBlake2(comptime B: type, random: std.Random) !void {
    const W = @typeInfo(@FieldType(B.Engine, "h")).array.child;

    for (0..runs) |case| {
        var h: [8]W = undefined;

        var data: [3 * B.block]u8 = undefined;

        fill(random, std.mem.asBytes(&h), case);

        fill(random, &data, case);

        const count = 1 + case % 3;

        var t = random.int(B.Counter);

        if (case % 4 == 1) t = @as(B.Counter, random.int(W)) << @bitSizeOf(W) | (std.math.maxInt(W) - random.uintLessThan(W, 3 * B.block));

        var expected = h;

        for (0..count) |b| B.portable(&expected, &blake2Words(W, data[B.block * b ..][0..B.block]), t +% B.block * (b + 1), false);

        var got = h;

        B.blocks(&got, data[0 .. B.block * count], t);

        try testing.expectEqual(expected, got);

        expected = h;

        B.portable(&expected, &blake2Words(W, data[0..B.block]), t, true);

        got = h;

        B.compress(&got, data[0..B.block], t, true);

        try testing.expectEqual(expected, got);
    }
}

test "AArch64 BLAKE2b and BLAKE2s match the portable code" {
    if (comptime !cpu.aarch64_base) return error.SkipZigTest;

    var prng: std.Random.DefaultPrng = .init(0xb2a);

    try checkBlake2(blake2.Blake2b, prng.random());

    try checkBlake2(blake2.Blake2s, prng.random());
}

test "x86-64 AVX2 BLAKE2b and BLAKE2s match the portable code" {
    if (comptime arch != .x86_64 or !cpu.possible(.avx2)) return error.SkipZigTest;

    if (!cpu.has(.avx2)) return error.SkipZigTest;

    var prng: std.Random.DefaultPrng = .init(0xb2);

    try checkBlake2(blake2.Blake2b, prng.random());

    try checkBlake2(blake2.Blake2s, prng.random());
}

// Checks the reads and writes of the DIT register on this thread since `trace`, which then moves
// on to now.
fn expectSince(trace: *@TypeOf(aarch64.dit_trace), reads: usize, writes: usize) !void {
    const now = aarch64.dit_trace;

    defer trace.* = now;

    try testing.expectEqual([2]usize{ reads, writes }, [2]usize{ now.reads - trace.reads, now.writes - trace.writes });
}

// Every keyed MAC and KDF call, each of which must read and write the DIT register as given.
fn checkKeyed(reads: usize, writes: usize) !void {
    var trace = aarch64.dit_trace;

    inline for (.{ hash.hmac_sha_256, hash.hmac_sha_512, hash.kmac128, hash.kmac256, hash.blake2b_mac, hash.blake2s_mac }) |mac| {
        var buffers: [2][64]u8 = undefined;

        const tag, const again = .{ buffers[0][0..mac.digest_size], buffers[1][0..mac.digest_size] };

        mac.digest("key", "data", tag);

        try expectSince(&trace, reads, writes);

        try testing.expect(mac.verify("key", "data", tag));

        try expectSince(&trace, reads, writes);

        var state = mac.create("key");

        try expectSince(&trace, reads, writes);

        state.update("data");

        try expectSince(&trace, reads, writes);

        state.digest(again);

        try expectSince(&trace, reads, writes);

        try testing.expect(state.verify(tag));

        try expectSince(&trace, reads, writes);

        try testing.expectEqualSlices(u8, tag, again);
    }

    inline for (.{ kdf.hkdf_sha_256, kdf.hkdf_sha_512 }) |algorithm| {
        var out: [42]u8 = undefined;

        var prk: [64]u8 = undefined;

        try algorithm.derive("ikm", &out, .{});

        try expectSince(&trace, reads, writes);

        try algorithm.extract("ikm", prk[0..algorithm.hashSize()], .{});

        try expectSince(&trace, reads, writes);

        try algorithm.expand(prk[0..algorithm.hashSize()], &out, .{});

        try expectSince(&trace, reads, writes);
    }
}

// MAC and KDF calls leave the DIT register alone until enableDataIndependentTiming, and then set
// and clear it as KEM decapsulation always does; under another guard they only read it.
test "MAC and KDF calls take DIT only after enableDataIndependentTiming" {
    cpu.keyed.store(false, .monotonic);

    defer cpu.keyed.store(false, .monotonic);

    const dit = cpu.has(.dit);

    try checkKeyed(0, 0);

    var pair = try hazmat.generateKemKeyPair(kem.ml_kem_768, testing.allocator, &([_]u8{3} ** 64));

    defer pair.private_key.deinit();

    defer pair.public_key.deinit();

    const sealed = try hazmat.encapsulate(&pair.public_key, &([_]u8{4} ** 32));

    const before = aarch64.dit_trace;

    try testing.expectEqual(sealed.shared_secret, try pair.private_key.decapsulate(sealed.ciphertext()));

    try testing.expectEqual(@as(usize, if (dit) 2 else 0), aarch64.dit_trace.writes - before.writes);

    try testing.expectEqual(dit, cpu.enableDataIndependentTiming());

    try checkKeyed(@intFromBool(dit), 2 * @as(usize, @intFromBool(dit)));

    if (comptime !cpu.possible(.dit)) return;

    if (!dit) return;

    try testing.expect(!aarch64.ditIsSet());

    const outer = cpu.Dit.enter();

    defer outer.leave();

    try checkKeyed(1, 0);

    try testing.expect(aarch64.ditIsSet());
}

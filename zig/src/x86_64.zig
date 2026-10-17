const std = @import("std");
const builtin = @import("builtin");

const ct = @import("ct.zig");
const keccak = @import("keccak.zig");
const sha2 = @import("sha2.zig");

// x86-64 kernels for the dispatch in cpu.zig: SHA-256 with SHA-NI; SHA-256 in eight lanes,
// Keccak-f[1600] in four and the BLAKE2 compressions with AVX2; SHA-256 and SHA-512 of one stream
// with AVX2 and BMI2, and Keccak-f[1600] on one state with BMI1 and BMI2, where a build for a
// baseline CPU must choose them at run time.
// Every instruction here is on Intel's data-operand-independent-timing list, and nothing branches
// on or indexes memory by data.

fn cpuid(leaf: u32, subleaf: u32) [4]u32 {
    var a: u32 = undefined;

    var b: u32 = undefined;

    var c: u32 = undefined;

    var d: u32 = undefined;

    asm volatile ("cpuid"
        : [a] "={eax}" (a),
          [b] "={ebx}" (b),
          [c] "={ecx}" (c),
          [d] "={edx}" (d),
        : [leaf] "{eax}" (leaf),
          [subleaf] "{ecx}" (subleaf),
    );

    return .{ a, b, c, d };
}

// The state components the operating system saves on a context switch (XCR0).
fn xgetbv() u64 {
    var low: u32 = undefined;

    var high: u32 = undefined;

    asm volatile ("xgetbv"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [register] "{ecx}" (@as(u32, 0)),
    );

    return @as(u64, high) << 32 | low;
}

pub const Features = struct {
    sha256: bool,
    avx2: bool,
};

// The x86-64-v3 level and the v2 level below it, as CPUID reports them: in CPUID.1:ECX, SSE3 (bit
// 0), SSSE3 (9), FMA (12), CMPXCHG16B (13), SSE4.1 (19), SSE4.2 (20), MOVBE (22), POPCNT (23),
// XSAVE (26), OSXSAVE (27), AVX (28) and F16C (29); in CPUID.(EAX=7,ECX=0):EBX, BMI1 (3), AVX2
// (5) and BMI2 (8); in CPUID.80000001H:ECX, LAHF/SAHF (0) and LZCNT (5). The level is what
// x86_64_v3.zig is compiled for.
const v3_leaf1: u32 = 1 << 0 | 1 << 9 | 1 << 12 | 1 << 13 | 1 << 19 | 1 << 20 | 1 << 22 | 1 << 23 | 1 << 26 | 1 << 27 | 1 << 28 | 1 << 29;

const v3_leaf7: u32 = 1 << 3 | 1 << 5 | 1 << 8;

const v3_extended: u32 = 1 << 0 | 1 << 5;

// SHA-NI is CPUID.(EAX=7,ECX=0):EBX bit 29, with SSSE3 and SSE4.1. XGETBV is defined only with
// OSXSAVE, and XCR0 bits 1 and 2 say that the xmm and ymm registers survive a context switch.
pub fn features() Features {
    if (cpuid(0, 0)[0] < 7) return .{ .sha256 = false, .avx2 = false };

    const leaf1 = cpuid(1, 0)[2];

    const leaf7 = cpuid(7, 0)[1];

    const extended = if (cpuid(0x80000000, 0)[0] >= 0x80000001) cpuid(0x80000001, 0)[2] else 0;

    const v3 = leaf1 & v3_leaf1 == v3_leaf1 and leaf7 & v3_leaf7 == v3_leaf7 and extended & v3_extended == v3_extended;

    return .{
        .sha256 = leaf7 & 1 << 29 != 0 and leaf1 & 1 << 9 != 0 and leaf1 & 1 << 19 != 0,
        .avx2 = v3 and xgetbv() & 6 == 6,
    };
}

// ---- SHA-256 with SHA-NI (FIPS 180-4) ----
//
// SHA256RNDS2 runs two rounds on the state held as ABEF and CDGH (A in the highest lane), taking
// W[t] + K[t] for both rounds from xmm0. SHA256MSG1 and SHA256MSG2 extend the schedule. One
// statement per instruction lets LLVM allocate registers and interleave independent streams.

const Words = @Vector(4, u32);

inline fn rounds2(cdgh: Words, abef: Words, wk: Words) Words {
    return asm ("sha256rnds2 %[wk], %[abef], %[d]"
        : [d] "=x" (-> Words),
        : [cdgh] "0" (cdgh),
          [abef] "x" (abef),
          [wk] "{xmm0}" (wk),
    );
}

inline fn message1(a: Words, b: Words) Words {
    return asm ("sha256msg1 %[b], %[d]"
        : [d] "=x" (-> Words),
        : [a] "0" (a),
          [b] "x" (b),
    );
}

inline fn message2(a: Words, b: Words) Words {
    return asm ("sha256msg2 %[b], %[d]"
        : [d] "=x" (-> Words),
        : [a] "0" (a),
          [b] "x" (b),
    );
}

// The shuffles around the rounds are written out as well: for a baseline target LLVM builds them
// from SHUFPS and other floating-point moves, which Intel's list of data-independent instructions
// does not include. PALIGNR (SSSE3) and PBLENDW (SSE4.1) come with every SHA-NI CPU.

// PSHUFD: lane i of the result is lane (order >> 2i) & 3 of a.
inline fn shuffle(a: Words, comptime order: u8) Words {
    return asm ("pshufd %[order], %[a], %[d]"
        : [d] "=x" (-> Words),
        : [a] "x" (a),
          [order] "i" (order),
    );
}

// PALIGNR: the 16 bytes from `bytes` on in low followed by high.
inline fn alignRight(high: Words, low: Words, comptime bytes: u8) Words {
    return asm ("palignr %[bytes], %[low], %[d]"
        : [d] "=x" (-> Words),
        : [high] "0" (high),
          [low] "x" (low),
          [bytes] "i" (bytes),
    );
}

// PBLENDW: the 16-bit words of b where mask has a bit, those of a elsewhere.
inline fn blend(a: Words, b: Words, comptime mask: u8) Words {
    return asm ("pblendw %[mask], %[b], %[d]"
        : [d] "=x" (-> Words),
        : [a] "0" (a),
          [b] "x" (b),
          [mask] "i" (mask),
    );
}

// PUNPCKLDQ, PUNPCKHDQ, PUNPCKLQDQ or PUNPCKHQDQ: the low or high halves of a and b interleaved
// by 32 or 64 bits.
inline fn unpack(comptime instruction: []const u8, a: Words, b: Words) Words {
    return asm (instruction ++ " %[b], %[d]"
        : [d] "=x" (-> Words),
        : [a] "0" (a),
          [b] "x" (b),
    );
}

// Four rows of four words become four columns.
inline fn transpose(rows: [4]Words) [4]Words {
    const low01 = unpack("punpckldq", rows[0], rows[1]);

    const low23 = unpack("punpckldq", rows[2], rows[3]);

    const high01 = unpack("punpckhdq", rows[0], rows[1]);

    const high23 = unpack("punpckhdq", rows[2], rows[3]);

    return .{
        unpack("punpcklqdq", low01, low23),
        unpack("punpckhqdq", low01, low23),
        unpack("punpcklqdq", high01, high23),
        unpack("punpckhqdq", high01, high23),
    };
}

// [a, b, c, d] and [e, f, g, h] to ABEF = [f, e, b, a] and CDGH = [h, g, d, c], and back.
inline fn toRegisters(abcd: Words, efgh: Words) [2]Words {
    const badc = shuffle(abcd, 0xb1);

    const hgfe = shuffle(efgh, 0x1b);

    return .{ alignRight(badc, hgfe, 8), blend(hgfe, badc, 0xf0) };
}

inline fn fromRegisters(abef: Words, cdgh: Words) [2]Words {
    const abef_reversed = shuffle(abef, 0x1b);

    const ghcd = shuffle(cdgh, 0xb1);

    return .{ blend(abef_reversed, ghcd, 0xf0), alignRight(ghcd, abef_reversed, 8) };
}

// Big-endian words from 16 bytes, with PSHUFB (SSSE3).
inline fn bigEndian(bytes: *const [16]u8) Words {
    const order: @Vector(16, u8) = .{ 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12 };

    return asm ("pshufb %[order], %[d]"
        : [d] "=x" (-> Words),
        : [x] "0" (@as(Words, @bitCast(bytes.*))),
          [order] "x" (order),
    );
}

// Debug builds give every temporary of every unrolled round its own stack slot, so they run the
// rounds as a loop with run-time indices.
const unrolled = builtin.mode != .Debug;

// One compression of N independent streams, interleaved instruction by instruction. m[i] holds
// stream i's message words, four per vector. The schedule follows Intel's order: the words seven
// back (the previous group shifted by one) and sigma1 enter through SHA256MSG2, and sigma0 was
// added by SHA256MSG1 two groups earlier.
inline fn sha256Streams(comptime N: usize, abef: *[N]Words, cdgh: *[N]Words, m: *[N][4]Words) void {
    @setEvalBranchQuota(100_000);

    const abef0 = abef.*;

    const cdgh0 = cdgh.*;

    if (unrolled) {
        inline for (0..16) |g| sha256Group(N, g, abef, cdgh, m);
    } else {
        for (0..16) |g| sha256Group(N, g, abef, cdgh, m);
    }

    inline for (0..N) |i| {
        abef[i] +%= abef0[i];

        cdgh[i] +%= cdgh0[i];
    }
}

inline fn sha256Group(comptime N: usize, g: usize, abef: *[N]Words, cdgh: *[N]Words, m: *[N][4]Words) void {
    const k: Words = sha2.k256[4 * g ..][0..4].*;

    inline for (0..N) |i| {
        const wk = m[i][g % 4] +% k;

        cdgh[i] = rounds2(cdgh[i], abef[i], wk);

        abef[i] = rounds2(abef[i], cdgh[i], shuffle(wk, 0x4e));

        if (g >= 3 and g < 15) {
            const following = (g + 1) % 4;

            const seven_back = alignRight(m[i][g % 4], m[i][(g + 3) % 4], 4);

            m[i][following] = message2(m[i][following] +% seven_back, m[i][g % 4]);
        }

        if (g >= 1 and g <= 12) m[i][(g + 3) % 4] = message1(m[i][(g + 3) % 4], m[i][g % 4]);
    }
}

pub fn sha256Blocks(state: *[8]u32, blocks: []const u8) void {
    var abef: [1]Words = undefined;

    var cdgh: [1]Words = undefined;

    abef[0], cdgh[0] = toRegisters(state[0..4].*, state[4..8].*);

    var offset: usize = 0;

    while (offset < blocks.len) : (offset += 64) {
        var m: [1][4]Words = undefined;

        inline for (0..4) |j| m[0][j] = bigEndian(blocks[offset + 16 * j ..][0..16]);

        sha256Streams(1, &abef, &cdgh, &m);
    }

    state[0..4].*, state[4..8].* = fromRegisters(abef[0], cdgh[0]);
}

// One stream for u32, and the lanes of crypto-pq's vector layout (state[word][lane],
// words[t][lane]) for vectors: four lanes at a time are transposed into each lane's words, and
// compressed as two pairs of interleaved streams.
pub fn sha256Rounds(comptime W: type, state: *[8]W, words: *const [16]W) void {
    @setEvalBranchQuota(100_000);

    if (W == u32) {
        var abef: [1]Words = undefined;

        var cdgh: [1]Words = undefined;

        abef[0], cdgh[0] = toRegisters(state[0..4].*, state[4..8].*);

        var m: [1][4]Words = undefined;

        inline for (0..4) |j| m[0][j] = words[4 * j ..][0..4].*;

        sha256Streams(1, &abef, &cdgh, &m);

        state[0..4].*, state[4..8].* = fromRegisters(abef[0], cdgh[0]);

        return;
    }

    const L = @typeInfo(W).vector.len;

    const padded = (L + 3) / 4 * 4;

    var s: [8][padded]u32 = @splat(@splat(0));

    var w: [16][padded]u32 = @splat(@splat(0));

    defer ct.wipe(std.mem.asBytes(&w));

    for (&s, state) |*lanes, vector| lanes[0..L].* = vector;

    for (&w, words) |*lanes, vector| lanes[0..L].* = vector;

    inline for (0..padded / 4) |group| {
        var abcd: [4]Words = undefined;

        var efgh: [4]Words = undefined;

        var m: [4][4]Words = undefined;

        inline for (0..2) |half| {
            var rows: [4]Words = undefined;

            inline for (&rows, 0..) |*row, i| row.* = s[4 * half + i][4 * group ..][0..4].*;

            if (half == 0) abcd = transpose(rows) else efgh = transpose(rows);
        }

        inline for (0..4) |j| {
            var rows: [4]Words = undefined;

            inline for (&rows, 0..) |*row, i| row.* = w[4 * j + i][4 * group ..][0..4].*;

            inline for (transpose(rows), 0..) |column, lane| m[lane][j] = column;
        }

        inline for (0..2) |pair| {
            var abef: [2]Words = undefined;

            var cdgh: [2]Words = undefined;

            inline for (0..2) |i| abef[i], cdgh[i] = toRegisters(abcd[2 * pair + i], efgh[2 * pair + i]);

            sha256Streams(2, &abef, &cdgh, m[2 * pair ..][0..2]);

            inline for (0..2) |i| abcd[2 * pair + i], efgh[2 * pair + i] = fromRegisters(abef[i], cdgh[i]);
        }

        inline for (transpose(abcd), transpose(efgh), 0..) |low, high, i| {
            s[i][4 * group ..][0..4].* = low;

            s[4 + i][4 * group ..][0..4].* = high;
        }

        ct.wipe(std.mem.asBytes(&m));
    }

    for (state, s) |*vector, lanes| vector.* = lanes[0..L].*;

    ct.wipe(std.mem.asBytes(&s));
}

// ---- AVX2 and BMI kernels in one statement each (tools/asm.zig) ----

fn clobbers(comptime extra: []const []const u8) std.builtin.assembly.Clobbers {
    @setEvalBranchQuota(100_000);

    var set = scalarClobbers(extra);

    for (0..16) |i| {
        @field(set, std.fmt.comptimePrint("xmm{d}", .{i})) = true;

        @field(set, std.fmt.comptimePrint("ymm{d}", .{i})) = true;
    }

    return set;
}

// Memory, the flags and `registers` alone, for the kernels without vector instructions: Windows
// keeps xmm6-xmm15 across calls, so naming them would make every call save and restore all ten.
fn scalarClobbers(comptime registers: []const []const u8) std.builtin.assembly.Clobbers {
    var set: std.builtin.assembly.Clobbers = .{ .memory = true, .cc = true };

    for (registers) |register| @field(set, register) = true;

    return set;
}

// The round constants repeated across the eight 32-bit lanes of a ymm register.
const k256_lanes: [64][8]u32 align(32) = blk: {
    var table: [64][8]u32 = undefined;

    for (&table, sha2.k256) |*row, k| row.* = @splat(k);

    break :blk table;
};

// Eight SHA-256 compressions on crypto-pq's vector layout.
pub fn sha256x8(state: *[8]@Vector(8, u32), words: *const [16]@Vector(8, u32)) void {
    var schedule: [16][8]u32 align(32) = undefined;

    defer ct.wipe(std.mem.asBytes(&schedule));

    asm volatile (@embedFile("asm/sha256_x8_avx2.s")
        :
        : [state] "{rdi}" (state),
          [words] "{rsi}" (words),
          [constants] "{rdx}" (&k256_lanes),
          [schedule] "{rcx}" (&schedule),
        : clobbers(&.{ "rax", "r8" }));
}

// SHA-256 and SHA-512 of one stream (tools/asm.zig, sha2Stream): the message schedule of two
// blocks at a time with AVX2, the rounds with RORX and ANDN. The frame holds W[t] + K[t] of the
// two blocks, a group of rounds per 32 bytes, and then the arguments of a call.
fn Sha2Frame(comptime groups: usize) type {
    return extern struct {
        schedule: [groups][32]u8 align(32),
        state: *anyopaque,
        second_state: *anyopaque,
        first: [*]const u8,
        second: [*]const u8,
        constants: *const anyopaque,
        count: usize,
        clear: usize,
    };
}

// The round constants of each group twice, one copy per block, then VPSHUFB orders: for
// SHA-256 the byte swap of 32-bit words and the moves of sigma1's two results into the low or
// the high half of each 128-bit lane (0x80 selects zero); for SHA-512 the byte swap of 64-bit
// words and the rotation by 8.
fn Sha2Constants(comptime Word: type) type {
    const groups = if (Word == u32) 16 else 40;

    return extern struct {
        k: [groups][32 / @sizeOf(Word)]Word,
        orders: [if (Word == u32) 3 else 2][32]u8,
    };
}

fn sha2Constants(comptime Word: type) Sha2Constants(Word) {
    @setEvalBranchQuota(10_000);

    const per = 16 / @sizeOf(Word);

    var self: Sha2Constants(Word) = undefined;

    const k = if (Word == u32) sha2.k256 else sha2.k512;

    for (&self.k, 0..) |*group, g| {
        for (group, 0..) |*constant, i| constant.* = k[per * g + i % per];
    }

    for (&self.orders, 0..) |*order, o| {
        for (order, 0..) |*index, i| {
            const lane = i % 16;

            index.* = switch (o) {
                0 => @intCast(lane / @sizeOf(Word) * @sizeOf(Word) + @sizeOf(Word) - 1 - lane % @sizeOf(Word)),
                1 => if (Word == u64) @intCast(lane / 8 * 8 + (lane + 1) % 8) else if (lane < 8) @intCast(lane / 4 * 8 + lane % 4) else 0x80,
                else => if (lane < 8) 0x80 else @intCast((lane - 8) / 4 * 8 + lane % 4),
            };
        }
    }

    return self;
}

const sha256_constants: Sha2Constants(u32) align(32) = sha2Constants(u32);

const sha512_constants: Sha2Constants(u64) align(32) = sha2Constants(u64);

// The whole blocks of `first` and then those of `second`, two at a time, into state; or, with
// second_state, `first` and `second` as one block each, of two streams that start from their
// own states. Not inlined: the kernel's code is large and appears once.
noinline fn sha2Stream(comptime Word: type, state: *[8]Word, second_state: ?*[8]Word, first: []const u8, second: []const u8) void {
    const block = 16 * @sizeOf(Word);

    var frame: Sha2Frame(if (Word == u32) 16 else 40) = undefined;

    frame.state = state;

    frame.second_state = second_state orelse state;

    frame.constants = if (Word == u32) &sha256_constants else &sha512_constants;

    var parts = [2][]const u8{ first, second };

    while (take(&parts, block)) |a| {
        const b = take(&parts, block);

        frame.first = a;

        frame.second = b orelse a;

        frame.count = if (b == null) 1 else 2;

        frame.clear = @intFromBool(parts[0].len == 0 and parts[1].len == 0);

        asm volatile (@embedFile(if (Word == u32) "asm/sha256_avx2.s" else "asm/sha512_avx2.s")
            :
            : [frame] "{rdi}" (&frame),
            : clobbers(&.{ "rax", "rbx", "rcx", "rdx", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" }));
    }
}

// The next block of the first part that has one.
fn take(parts: *[2][]const u8, block: usize) ?[*]const u8 {
    for (parts) |*part| {
        if (part.len == 0) continue;

        const start = part.ptr;

        part.* = part.*[block..];

        return start;
    }

    return null;
}

pub fn sha256Stream(state: *[8]u32, first: []const u8, second: []const u8) void {
    sha2Stream(u32, state, null, first, second);
}

pub fn sha512Stream(state: *[8]u64, first: []const u8, second: []const u8) void {
    sha2Stream(u64, state, null, first, second);
}

// One block for each of two states, as HMAC's key blocks.
pub fn sha256Pair(states: *[2][8]u32, first: *const [64]u8, second: *const [64]u8) void {
    sha2Stream(u32, &states[0], &states[1], first, second);
}

pub fn sha512Pair(states: *[2][8]u64, first: *const [128]u8, second: *const [128]u8) void {
    sha2Stream(u64, &states[0], &states[1], first, second);
}

// Keccak-f[1600] on one state with BMI1 and BMI2 (tools/asm.zig, keccakBmi). The rounds alternate
// between the state and the frame's buffer; the absorbing kernel reads its arguments from the
// frame.
const KeccakFrame = extern struct {
    other: [25]u64,
    first: [*]const u64,
    end: [*]const u64,
    data: [*]const u8,
    blocks: usize,
    lanes: usize,
};

fn keccakFrame() KeccakFrame {
    var frame: KeccakFrame = undefined;

    frame.first = &keccak.round_constants;

    frame.end = frame.first + keccak.round_constants.len;

    return frame;
}

pub noinline fn keccakBmi(state: *[25]u64) void {
    var frame = keccakFrame();

    defer ct.wipe(std.mem.asBytes(&frame.other));

    asm volatile (@embedFile("asm/keccak_x1_bmi.s")
        :
        : [state] "{rdi}" (state),
          [frame] "{rsi}" (&frame),
        : scalarClobbers(&.{ "rax", "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" }));
}

// Whole blocks of `rate` bytes (72, 104, 136, 144 or 168), each XORed into the state and permuted.
pub noinline fn keccakAbsorbBmi(state: *[25]u64, rate: usize, data: []const u8) void {
    std.debug.assert(data.len > 0 and data.len % rate == 0);

    var frame = keccakFrame();

    defer ct.wipe(std.mem.asBytes(&frame.other));

    frame.data = data.ptr;

    frame.blocks = data.len / rate;

    frame.lanes = rate / 8;

    asm volatile (@embedFile("asm/keccak_absorb_bmi.s")
        :
        : [state] "{rdi}" (state),
          [frame] "{rsi}" (&frame),
        : scalarClobbers(&.{ "rax", "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" }));
}

const keccak_lanes: [24][4]u64 align(32) = blk: {
    var table: [24][4]u64 = undefined;

    for (&table, keccak.round_constants) |*row, constant| row.* = @splat(constant);

    break :blk table;
};

// VPSHUFB orders that rotate every 64-bit lane left by 8 and by 56 bits: byte j of a lane takes
// byte j - 1 or j + 1 of the same lane, counted within its 128-bit half.
const rotations: [2][32]u8 align(32) = blk: {
    var table: [2][32]u8 = undefined;

    for (0..32) |i| {
        const lane = i % 16 / 8 * 8;

        table[0][i] = lane + (i + 7) % 8;

        table[1][i] = lane + (i + 1) % 8;
    }

    break :blk table;
};

// VPSHUFB orders that rotate every lane of `size` bytes right by whole bytes: byte j of a lane
// takes byte j + bytes of the same lane, counted within its 128-bit half.
fn byteRotations(comptime size: usize, comptime bytes: [2]usize) [2][32]u8 {
    var table: [2][32]u8 = undefined;

    for (&table, bytes) |*order, by| {
        for (order, 0..) |*index, i| index.* = i % 16 / size * size + (i % size + by) % size;
    }

    return table;
}

const blake2b_rotations: [2][32]u8 align(32) = byteRotations(8, .{ 3, 2 });

const blake2s_rotations: [2][32]u8 align(32) = byteRotations(4, .{ 2, 1 });

// BLAKE2b or BLAKE2s compressions of whole blocks. `rest` holds rows 2 and 3 of the working
// vector before the counter, the final flag applied, and then the counter of the first block;
// the counter grows by a block per block.
pub fn blake2(comptime W: type, h: *[8]W, blocks: []const u8, rest: *const [10]W) void {
    asm volatile (@embedFile(if (W == u64) "asm/blake2b_avx2.s" else "asm/blake2s_avx2.s")
        :
        : [h] "{rdi}" (h),
          [blocks] "{rsi}" (blocks.ptr),
          [count] "{rdx}" (blocks.len / (16 * @sizeOf(W))),
          [rest] "{rcx}" (rest),
          [rotations] "{r8}" (if (W == u64) &blake2b_rotations else &blake2s_rotations),
        : clobbers(&.{ "rax", "r9", "r10", "r11" }));
}

// Four permutations; the kernel moves the states into lane-major order and back.
pub fn keccak4(states: *[4][25]u64) void {
    var lanes: [2][25][4]u64 align(32) = undefined;

    defer ct.wipe(std.mem.asBytes(&lanes));

    asm volatile (@embedFile("asm/keccak_x4_avx2.s")
        :
        : [states] "{rdi}" (states),
          [lanes] "{rsi}" (&lanes),
          [constants] "{rdx}" (&keccak_lanes),
          [rotations] "{rcx}" (&rotations),
        : clobbers(&.{ "rax", "r8" }));
}

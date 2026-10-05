const std = @import("std");
const builtin = @import("builtin");

const ct = @import("ct.zig");
const keccak = @import("keccak.zig");
const sha2 = @import("sha2.zig");

// AArch64 kernels for SHA-256, SHA-512 and Keccak-f[1600], and the DIT and MIDR_EL1 accessors,
// for the dispatch in cpu.zig. Every instruction here is on Arm's data-independent-timing list,
// and nothing branches on or indexes memory by data. Each statement names the extension it needs
// with .arch_extension, so the code assembles for a baseline target and is chosen at run time.
const Words = @Vector(4, u32);

const Pair = @Vector(2, u64);

// ---- SHA-256 (FIPS 180-4) ----
//
// SHA256H and SHA256H2 run four rounds on the state held as ABCD and EFGH, given the four words
// W[t] + K[t]; SHA256SU0 and SHA256SU1 extend the schedule by four words. Small statements let
// LLVM allocate registers and interleave independent streams.

// Both halves of the state in one statement: the pair then issues back to back, which measured
// 13% faster for one stream than LLVM's placement of two statements. SHA256H2 takes ABCD as it
// was before SHA256H, hence the copy.
inline fn sha256Rounds4(abcd: *Words, efgh: *Words, wk: Words) void {
    var x = abcd.*;

    var y = efgh.*;

    var copy: Words = undefined;

    asm (
        \\.arch_extension sha2
        \\mov %[copy].16b, %[x].16b
        \\sha256h %[x:q], %[y:q], %[wk].4s
        \\sha256h2 %[y:q], %[copy:q], %[wk].4s
        : [x] "=w" (x),
          [y] "=w" (y),
          [copy] "=&w" (copy),
        : [_] "0" (x),
          [_] "1" (y),
          [wk] "w" (wk),
    );

    abcd.* = x;

    efgh.* = y;
}

inline fn sha256su0(w0: Words, w1: Words) Words {
    return asm (".arch_extension sha2\nsha256su0 %[d].4s, %[n].4s"
        : [d] "=w" (-> Words),
        : [w0] "0" (w0),
          [n] "w" (w1),
    );
}

inline fn sha256su1(t: Words, w2: Words, w3: Words) Words {
    return asm (".arch_extension sha2\nsha256su1 %[d].4s, %[n].4s, %[m].4s"
        : [d] "=w" (-> Words),
        : [t] "0" (t),
          [n] "w" (w2),
          [m] "w" (w3),
    );
}

// Debug builds give every temporary of every unrolled round its own stack slot, so they run the
// rounds as a loop with run-time indices.
const unrolled = builtin.mode != .Debug;

// One compression of N independent streams, interleaved instruction by instruction so that the
// latency of one stream hides behind the others. m[i] holds stream i's message words, four per
// vector.
inline fn sha256Streams(comptime N: usize, abcd: *[N]Words, efgh: *[N]Words, m: *[N][4]Words) void {
    @setEvalBranchQuota(100_000);

    const abcd0 = abcd.*;

    const efgh0 = efgh.*;

    if (unrolled) {
        inline for (0..16) |g| sha256Group(N, g, abcd, efgh, m);
    } else {
        for (0..16) |g| sha256Group(N, g, abcd, efgh, m);
    }

    inline for (0..N) |i| {
        abcd[i] +%= abcd0[i];

        efgh[i] +%= efgh0[i];
    }
}

// Rounds 4g .. 4g + 3; m[i][g % 4] then becomes the words of group g + 4.
inline fn sha256Group(comptime N: usize, g: usize, abcd: *[N]Words, efgh: *[N]Words, m: *[N][4]Words) void {
    const k: Words = sha2.k256[4 * g ..][0..4].*;

    inline for (0..N) |i| {
        sha256Rounds4(&abcd[i], &efgh[i], m[i][g % 4] +% k);

        if (g < 12) m[i][g % 4] = sha256su1(sha256su0(m[i][g % 4], m[i][(g + 1) % 4]), m[i][(g + 2) % 4], m[i][(g + 3) % 4]);
    }
}

// Whole 64-byte blocks of one stream, with the state kept in registers from block to block.
pub fn sha256Blocks(state: *[8]u32, blocks: []const u8) void {
    var abcd = [1]Words{state[0..4].*};

    var efgh = [1]Words{state[4..8].*};

    var offset: usize = 0;

    while (offset < blocks.len) : (offset += 64) {
        var m: [1][4]Words = undefined;

        inline for (0..4) |j| m[0][j] = @byteSwap(@as(Words, @bitCast(blocks[offset + 16 * j ..][0..16].*)));

        sha256Streams(1, &abcd, &efgh, &m);
    }

    state[0..4].* = abcd[0];

    state[4..8].* = efgh[0];
}

// The rounds on message words that are already native integers: one stream for u32 and the
// lanes of crypto-pq's vector layout (state[word][lane], words[t][lane]) for vectors, two lanes
// interleaved at a time. On Apple's cores the lanes run at the instructions' throughput with any
// interleaving; two keep cores with a smaller reorder window busy.
pub fn sha256Rounds(comptime W: type, state: *[8]W, words: *const [16]W) void {
    @setEvalBranchQuota(100_000);

    if (W == u32) {
        var abcd = [1]Words{state[0..4].*};

        var efgh = [1]Words{state[4..8].*};

        var m: [1][4]Words = undefined;

        inline for (0..4) |j| m[0][j] = words[4 * j ..][0..4].*;

        sha256Streams(1, &abcd, &efgh, &m);

        state[0..4].* = abcd[0];

        state[4..8].* = efgh[0];

        return;
    }

    const L = @typeInfo(W).vector.len;

    var s: [8][L]u32 = undefined;

    var w: [16][L]u32 = undefined;

    defer ct.wipe(std.mem.asBytes(&w));

    for (&s, state) |*lanes, vector| lanes.* = vector;

    for (&w, words) |*lanes, vector| lanes.* = vector;

    comptime var first = 0;

    inline while (first < L) : (first += 2) {
        const N = @min(2, L - first);

        var abcd: [N]Words = undefined;

        var efgh: [N]Words = undefined;

        var m: [N][4]Words = undefined;

        inline for (0..N) |i| {
            abcd[i] = .{ s[0][first + i], s[1][first + i], s[2][first + i], s[3][first + i] };

            efgh[i] = .{ s[4][first + i], s[5][first + i], s[6][first + i], s[7][first + i] };

            inline for (0..4) |j| m[i][j] = .{ w[4 * j][first + i], w[4 * j + 1][first + i], w[4 * j + 2][first + i], w[4 * j + 3][first + i] };
        }

        sha256Streams(N, &abcd, &efgh, &m);

        inline for (0..N) |i| {
            inline for (0..4) |j| {
                s[j][first + i] = abcd[i][j];

                s[4 + j][first + i] = efgh[i][j];
            }
        }
    }

    for (state, s) |*vector, lanes| vector.* = lanes;

    ct.wipe(std.mem.asBytes(&s));
}

// ---- SHA-512 (FIPS 180-4) ----
//
// SHA512H and SHA512H2 run two rounds. With the state held as [a, b], [c, d], [e, f] and [g, h]
// (low half first) and kw = W[t] + K[t] in the low half and W[t + 1] + K[t + 1] in the high
// half:
// - SHA512H, given [g, h] + [kw1, kw0], [f, g] and [d, e], returns [T1(t + 1), T1(t)];
// - [c, d] plus that is the new [e, f];
// - SHA512H2, given it, [c, d] and [a, b], returns the new [a, b].
// The new [c, d] and [g, h] are the old [a, b] and [e, f]. SHA512SU0 and SHA512SU1 extend the
// schedule two words at a time.

inline fn sha512h(sum: Pair, fg: Pair, de: Pair) Pair {
    return asm (".arch_extension sha3\nsha512h %[d:q], %[n:q], %[m].2d"
        : [d] "=w" (-> Pair),
        : [sum] "0" (sum),
          [n] "w" (fg),
          [m] "w" (de),
    );
}

inline fn sha512h2(t1: Pair, cd: Pair, ab: Pair) Pair {
    return asm (".arch_extension sha3\nsha512h2 %[d:q], %[n:q], %[m].2d"
        : [d] "=w" (-> Pair),
        : [t1] "0" (t1),
          [n] "w" (cd),
          [m] "w" (ab),
    );
}

inline fn sha512su0(w0: Pair, w1: Pair) Pair {
    return asm (".arch_extension sha3\nsha512su0 %[d].2d, %[n].2d"
        : [d] "=w" (-> Pair),
        : [w0] "0" (w0),
          [n] "w" (w1),
    );
}

inline fn sha512su1(t: Pair, w14: Pair, w9: Pair) Pair {
    return asm (".arch_extension sha3\nsha512su1 %[d].2d, %[n].2d, %[m].2d"
        : [d] "=w" (-> Pair),
        : [t] "0" (t),
          [n] "w" (w14),
          [m] "w" (w9),
    );
}

// The high half of x and the low half of y: one EXT instruction.
inline fn middle(x: Pair, y: Pair) Pair {
    return @shuffle(u64, x, y, @Vector(2, i32){ 1, ~@as(i32, 0) });
}

// The state of one SHA-512 stream as four pairs of words.
const State512 = [4]Pair;

inline fn sha512Streams(comptime N: usize, states: *[N]State512, m: *[N][8]Pair) void {
    @setEvalBranchQuota(100_000);

    const initial = states.*;

    if (unrolled) {
        inline for (0..40) |r| sha512Rounds2(N, r, states, m);
    } else {
        for (0..40) |r| sha512Rounds2(N, r, states, m);
    }

    inline for (0..N) |i| {
        inline for (0..4) |j| states[i][j] +%= initial[i][j];
    }
}

// Rounds 2r and 2r + 1. Pair r + 8 of the schedule then replaces pair r: W[2r + 16] =
// sigma1(W[2r + 14]) + W[2r + 9] + sigma0(W[2r + 1]) + W[2r], and likewise one word on.
inline fn sha512Rounds2(comptime N: usize, r: usize, states: *[N]State512, m: *[N][8]Pair) void {
    const k: Pair = sha2.k512[2 * r ..][0..2].*;

    inline for (0..N) |i| {
        const ab, const cd, const ef, const gh = states[i];

        const kw = m[i][r % 8] +% k;

        const t1 = sha512h(gh +% middle(kw, kw), middle(ef, gh), middle(cd, ef));

        states[i] = .{ sha512h2(t1, cd, ab), ab, cd +% t1, ef };

        if (r < 32) m[i][r % 8] = sha512su1(sha512su0(m[i][r % 8], m[i][(r + 1) % 8]), m[i][(r + 7) % 8], middle(m[i][(r + 4) % 8], m[i][(r + 5) % 8]));
    }
}

pub fn sha512Blocks(state: *[8]u64, blocks: []const u8) void {
    var s = [1]State512{.{ state[0..2].*, state[2..4].*, state[4..6].*, state[6..8].* }};

    var offset: usize = 0;

    while (offset < blocks.len) : (offset += 128) {
        var m: [1][8]Pair = undefined;

        inline for (0..8) |j| m[0][j] = @byteSwap(@as(Pair, @bitCast(blocks[offset + 16 * j ..][0..16].*)));

        sha512Streams(1, &s, &m);
    }

    inline for (0..4) |j| state[2 * j ..][0..2].* = s[0][j];
}

pub fn sha512Rounds(comptime W: type, state: *[8]W, words: *const [16]W) void {
    @setEvalBranchQuota(100_000);

    if (W == u64) {
        var s = [1]State512{.{ state[0..2].*, state[2..4].*, state[4..6].*, state[6..8].* }};

        var m: [1][8]Pair = undefined;

        inline for (0..8) |j| m[0][j] = words[2 * j ..][0..2].*;

        sha512Streams(1, &s, &m);

        inline for (0..4) |j| state[2 * j ..][0..2].* = s[0][j];

        return;
    }

    const L = @typeInfo(W).vector.len;

    var s: [8][L]u64 = undefined;

    var w: [16][L]u64 = undefined;

    defer ct.wipe(std.mem.asBytes(&w));

    for (&s, state) |*lanes, vector| lanes.* = vector;

    for (&w, words) |*lanes, vector| lanes.* = vector;

    comptime var first = 0;

    inline while (first < L) : (first += 2) {
        const N = @min(2, L - first);

        var states: [N]State512 = undefined;

        var m: [N][8]Pair = undefined;

        inline for (0..N) |i| {
            inline for (0..4) |j| states[i][j] = .{ s[2 * j][first + i], s[2 * j + 1][first + i] };

            inline for (0..8) |j| m[i][j] = .{ w[2 * j][first + i], w[2 * j + 1][first + i] };
        }

        sha512Streams(N, &states, &m);

        inline for (0..N) |i| {
            inline for (0..4) |j| {
                s[2 * j][first + i] = states[i][j][0];

                s[2 * j + 1][first + i] = states[i][j][1];
            }
        }
    }

    for (state, s) |*vector, lanes| vector.* = lanes;

    ct.wipe(std.mem.asBytes(&s));
}

// ---- Modular arithmetic for ML-KEM and ML-DSA ----
//
// AArch64 has no vector multiply-high for 16-bit or 32-bit lanes, so LLVM widens the products.
// SQDMULH returns the high half of the doubled product, floor(a * b / 2^(n - 1)) for n-bit lanes,
// saturating only when both operands are -2^(n - 1); SHSUB halves a difference without overflow.

pub inline fn doublingHigh16(a: @Vector(8, i16), b: @Vector(8, i16)) @Vector(8, i16) {
    return asm ("sqdmulh %[d].8h, %[a].8h, %[b].8h"
        : [d] "=w" (-> @Vector(8, i16)),
        : [a] "w" (a),
          [b] "w" (b),
    );
}

pub inline fn halvingSubtract16(a: @Vector(8, i16), b: @Vector(8, i16)) @Vector(8, i16) {
    return asm ("shsub %[d].8h, %[a].8h, %[b].8h"
        : [d] "=w" (-> @Vector(8, i16)),
        : [a] "w" (a),
          [b] "w" (b),
    );
}

pub inline fn doublingHigh32(a: @Vector(4, i32), b: @Vector(4, i32)) @Vector(4, i32) {
    return asm ("sqdmulh %[d].4s, %[a].4s, %[b].4s"
        : [d] "=w" (-> @Vector(4, i32)),
        : [a] "w" (a),
          [b] "w" (b),
    );
}

pub inline fn halvingSubtract32(a: @Vector(4, i32), b: @Vector(4, i32)) @Vector(4, i32) {
    return asm ("shsub %[d].4s, %[a].4s, %[b].4s"
        : [d] "=w" (-> @Vector(4, i32)),
        : [a] "w" (a),
          [b] "w" (b),
    );
}

// ---- Keccak-f[1600] (FIPS 202) ----

const keccak_clobbers: std.builtin.assembly.Clobbers = blk: {
    @setEvalBranchQuota(100_000);

    var clobbers: std.builtin.assembly.Clobbers = .{ .memory = true, .nzcv = true, .x2 = true, .x3 = true, .x4 = true };

    for (0..32) |i| @field(clobbers, std.fmt.comptimePrint("v{d}", .{i})) = true;

    break :blk clobbers;
};

// Permutations with the SHA3 instructions, in one statement with registers allocated by hand
// (tools/asm.zig): one inline statement per instruction measured 20% slower. One state costs
// nearly as much as two, so independent states go in pairs; alone, one still beats the scalar
// code (137 against 160 ns on Apple M3).
pub fn keccak1(state: *[25]u64) void {
    asm volatile (@embedFile("asm/keccak_x1_sha3.s")
        :
        : [states] "{x0}" (state),
          [constants] "{x1}" (&keccak.round_constants),
        : keccak_clobbers);
}

pub fn keccak2(states: *[2][25]u64) void {
    asm volatile (@embedFile("asm/keccak_x2_sha3.s")
        :
        : [states] "{x0}" (states),
          [constants] "{x1}" (&keccak.round_constants),
        : keccak_clobbers);
}

// ---- DIT and the CPU's implementer ----

// PSTATE.DIT is bit 24 of the DIT register, S3_3_C4_C2_5, writable at EL0.
pub fn ditIsSet() bool {
    const value = asm volatile ("mrs %[value], S3_3_C4_C2_5"
        : [value] "=r" (-> u64),
    );

    return value & 1 << 24 != 0;
}

// Sets DIT and returns whether it was clear before.
pub fn enterDit() bool {
    if (ditIsSet()) return false;

    asm volatile ("msr S3_3_C4_C2_5, %[value]"
        :
        : [value] "r" (@as(u64, 1 << 24)),
        : .{ .memory = true });

    return true;
}

pub fn leaveDit() void {
    asm volatile ("msr S3_3_C4_C2_5, xzr" ::: .{ .memory = true });
}

// Only when the kernel emulates MIDR_EL1 (HWCAP_CPUID); otherwise the read traps.
pub fn implementer() u8 {
    const midr = asm volatile ("mrs %[value], MIDR_EL1"
        : [value] "=r" (-> u64),
    );

    return @truncate(midr >> 24);
}

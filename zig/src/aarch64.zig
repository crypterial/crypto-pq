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

// ---- Rejection sampling (FIPS 203, Algorithm 7; FIPS 204, Algorithms 30 and 31) ----
//
// The candidates of a block are compared with their bound side by side, and TBL moves the
// accepted ones together, with shuffle indices from a table indexed by the pattern of accepted
// lanes. Each step stores a whole vector at the count and advances the count by the number
// accepted, so it writes past the last accepted value into slots that later values, or the room
// at the end of the buffer, take.

const Bytes = @Vector(16, u8);

inline fn lookup(table: Bytes, indices: Bytes) Bytes {
    return asm ("tbl %[d].16b, {%[t].16b}, %[i].16b"
        : [d] "=w" (-> Bytes),
        : [t] "w" (table),
          [i] "w" (indices),
    );
}

// Indices of eight or more give zero, so only the low half of the table register is read.
inline fn lookup8(table: @Vector(8, u8), indices: @Vector(8, u8)) @Vector(8, u8) {
    return asm ("tbl %[d].8b, {%[t].16b}, %[i].8b"
        : [d] "=w" (-> @Vector(8, u8)),
        : [t] "w" (table),
          [i] "w" (indices),
    );
}

// Shuffle indices that bring the accepted lanes of a vector of `lanes` lanes of `width` bytes to
// its start, in order, for every pattern of accepted lanes; 0xff selects zero for the rest.
fn compaction(comptime lanes: usize, comptime width: usize, comptime size: usize) [1 << lanes]@Vector(size, u8) {
    @setEvalBranchQuota(100_000);

    var table: [1 << lanes]@Vector(size, u8) = undefined;

    for (&table, 0..) |*entry, pattern| {
        var indices: [size]u8 = @splat(0xff);

        var next: usize = 0;

        for (0..lanes) |lane| {
            if (pattern & (1 << lane) == 0) continue;

            for (0..width) |byte| indices[width * next + byte] = width * lane + byte;

            next += 1;
        }

        entry.* = indices;
    }

    return table;
}

const compact16 = compaction(8, 2, 16);

const compact32 = compaction(4, 4, 16);

const compact8 = compaction(8, 1, 8);

// The number of accepted lanes of every pattern, read from memory rather than counted: AArch64
// counts bits only in vector registers, and the round trip to them is slower than a load.
const accepted_counts: [256]u8 = blk: {
    var table: [256]u8 = undefined;

    for (&table, 0..) |*count, pattern| count.* = @popCount(@as(u8, pattern));

    break :blk table;
};

// ML-KEM: two candidates of 12 bits from every three bytes. Each step takes 24 bytes as two
// vectors of eight candidates in 16-bit lanes, from bytes 0-11 and 12-23. The matrix is public,
// so the patterns may decide branches and index memory.
pub fn uniform12(buffer: *[256 + 8]i16, start: usize, block: *const [168]u8) usize {
    const pairs = Bytes{ 0, 1, 1, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11 };

    const shifts = @Vector(8, u4){ 0, 4, 0, 4, 0, 4, 0, 4 };

    const bits = @Vector(8, u16){ 1, 2, 4, 8, 16, 32, 64, 128 };

    var count = start;

    for (0..7) |step| {
        inline for (0..2) |half| {
            if (count >= 256) return count;

            const bytes: Bytes = block[24 * step + 8 * half ..][0..16].*;

            const words: @Vector(8, u16) = @bitCast(lookup(bytes, pairs + @as(Bytes, @splat(4 * half))));

            const candidates = (words >> shifts) & @as(@Vector(8, u16), @splat(0xfff));

            const accepted = candidates < @as(@Vector(8, u16), @splat(3329));

            const pattern = @reduce(.Add, @select(u16, accepted, bits, @as(@Vector(8, u16), @splat(0))));

            const kept: @Vector(8, i16) = @bitCast(lookup(@bitCast(candidates), compact16[pattern]));

            buffer[count..][0..8].* = kept;

            count += accepted_counts[pattern];
        }
    }

    return count;
}

// ML-DSA: a candidate of 23 bits from every three bytes. Each step takes 24 bytes as two vectors
// of four candidates in 32-bit lanes. Near the end of the polynomial the candidates go one by one,
// as in the portable code, so that nothing is written past it.
pub fn uniform23(out: *[256]i32, start: usize, block: *const [168]u8) usize {
    const triples = [2]Bytes{
        .{ 0, 1, 2, 0xff, 3, 4, 5, 0xff, 6, 7, 8, 0xff, 9, 10, 11, 0xff },
        .{ 4, 5, 6, 0xff, 7, 8, 9, 0xff, 10, 11, 12, 0xff, 13, 14, 15, 0xff },
    };

    const bits = @Vector(4, u32){ 1, 2, 4, 8 };

    var count = start;

    var step: usize = 0;

    while (step < 7 and count <= 256 - 8) : (step += 1) {
        inline for (0..2) |half| {
            const bytes: Bytes = block[24 * step + 8 * half ..][0..16].*;

            const candidates = @as(@Vector(4, u32), @bitCast(lookup(bytes, triples[half]))) & @as(@Vector(4, u32), @splat(0x7fffff));

            const accepted = candidates < @as(@Vector(4, u32), @splat(8380417));

            const pattern = @reduce(.Add, @select(u32, accepted, bits, @as(@Vector(4, u32), @splat(0))));

            const kept: @Vector(4, i32) = @bitCast(lookup(@bitCast(candidates), compact32[pattern]));

            out[count..][0..4].* = kept;

            count += accepted_counts[pattern];
        }
    }

    var offset = 24 * step;

    while (offset < block.len and count < 256) : (offset += 3) {
        const z = block[offset] | (@as(i32, block[offset + 1]) << 8) | (@as(i32, block[offset + 2] & 0x7f) << 16);

        if (z < 8380417) {
            out[count] = z;

            count += 1;
        }
    }

    return count;
}

// ML-DSA's secret vectors: eight half-bytes at a time in stream order, mapped to 2 - (x mod 5)
// for x below 15 (eta = 2) or to 4 - x for x below 9 (eta = 4). Which half-bytes are rejected is
// public, as the portable code explains, so the pattern is declassified before it selects the
// shuffle; the values never decide a branch or an address.
pub fn bounded(comptime eta: u8, buffer: *[256 + 8]i32, start: usize, block: *const [136]u8) usize {
    const U8 = @Vector(8, u8);

    const bits = U8{ 1, 2, 4, 8, 16, 32, 64, 128 };

    const orders = [2][8]i32{ .{ 0, -1, 1, -2, 2, -3, 3, -4 }, .{ 4, -5, 5, -6, 6, -7, 7, -8 } };

    var count = start;

    for (0..17) |lane| {
        const bytes: U8 = block[8 * lane ..][0..8].*;

        const low = bytes & @as(U8, @splat(0x0f));

        const high = bytes >> @splat(4);

        inline for (orders) |order| {
            if (count >= 256) return count;

            const x = @shuffle(u8, low, high, order);

            // x / 5 is 13x / 64 for x below 15.
            const values = if (eta == 2) @as(U8, @splat(2)) -% (x -% ((x *% @as(U8, @splat(13))) >> @splat(6)) *% @as(U8, @splat(5))) else @as(U8, @splat(4)) -% x;

            const accepted = x < @as(U8, @splat(if (eta == 2) 15 else 9));

            const pattern = ct.declassifyValue(u8, @reduce(.Add, @select(u8, accepted, bits, @as(U8, @splat(0)))));

            const kept: @Vector(8, i8) = @bitCast(lookup8(values, compact8[pattern]));

            buffer[count..][0..8].* = @as(@Vector(8, i32), kept);

            count += accepted_counts[pattern];
        }
    }

    return count;
}

// ---- ML-KEM's ByteEncode_12 (FIPS 203, Algorithm 5) ----

// Eight bytes from a table of sixteen.
inline fn lookupHalf(table: Bytes, indices: @Vector(8, u8)) @Vector(8, u8) {
    return asm ("tbl %[d].8b, {%[t].16b}, %[i].8b"
        : [d] "=w" (-> @Vector(8, u8)),
        : [t] "w" (table),
          [i] "w" (indices),
    );
}

// ML-KEM's ByteEncode_12 of coefficients in (-q, q), made canonical first: a pair (a, b) of 16-bit
// lanes, read as one 32-bit lane, is a + 2^16 b and becomes a + 2^12 b, whose three low bytes TBL
// gathers. Indices past the table give zero, so two lookups combine with an OR.
pub fn encode12(f: *const [256]i16, out: *[384]u8) void {
    const first = Bytes{ 0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 0xff, 0xff, 0xff, 0xff };

    const second = Bytes{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 1, 2, 4 };

    const third = @Vector(8, u8){ 5, 6, 8, 9, 10, 12, 13, 14 };

    for (0..16) |i| {
        var words: [2]Bytes = undefined;

        inline for (&words, 0..) |*w, h| {
            const a: @Vector(8, i16) = f[16 * i + 8 * h ..][0..8].*;

            const pairs: Words = @bitCast(a + (a >> @splat(15) & @as(@Vector(8, i16), @splat(3329))));

            w.* = @bitCast((pairs & @as(Words, @splat(0xfff))) | ((pairs >> @splat(4)) & @as(Words, @splat(0xfff000))));
        }

        out[24 * i ..][0..16].* = lookup(words[0], first) | lookup(words[1], second);

        out[24 * i + 16 ..][0..8].* = lookupHalf(words[1], third);
    }
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

const hybrid_clobbers: std.builtin.assembly.Clobbers = blk: {
    @setEvalBranchQuota(100_000);

    var clobbers: std.builtin.assembly.Clobbers = .{ .memory = true, .nzcv = true };

    for (0..32) |i| @field(clobbers, std.fmt.comptimePrint("v{d}", .{i})) = true;

    for (2..29) |i| {
        if (i != 18) @field(clobbers, std.fmt.comptimePrint("x{d}", .{i})) = true;
    }

    break :blk clobbers;
};

// Three permutations at once: two states with the SHA3 instructions and the third in
// general-purpose registers, interleaved so that both kinds of pipelines work (tools/asm.zig).
// Three states take little longer than two.
pub fn keccak3(states: *[3][25]u64) void {
    var first: usize = undefined;

    var second: usize = undefined;

    asm volatile (@embedFile("asm/keccak_x3_hybrid.s")
        : [first] "={x0}" (first),
          [second] "={x1}" (second),
        : [states] "{x0}" (states),
          [constants] "{x1}" (&keccak.round_constants),
        : hybrid_clobbers);
}

const absorb_clobbers: std.builtin.assembly.Clobbers = blk: {
    var clobbers = keccak_clobbers;

    clobbers.x2 = false;

    clobbers.x3 = false;

    clobbers.x6 = true;

    clobbers.x7 = true;

    clobbers.x8 = true;

    break :blk clobbers;
};

// Whole blocks of `rate` bytes (9, 13, 17, 18 or 21 lanes) XORed into one state and permuted,
// with the state kept in registers from one block to the next.
pub fn keccakAbsorb(state: *[25]u64, rate: usize, blocks: []const u8) void {
    std.debug.assert(blocks.len > 0 and blocks.len % rate == 0);

    asm volatile (@embedFile("asm/keccak_absorb_sha3.s")
        :
        : [state] "{x0}" (state),
          [constants] "{x1}" (&keccak.round_constants),
          [data] "{x2}" (blocks.ptr),
          [count] "{x3}" (blocks.len / rate),
          [lanes] "{x5}" (rate / 8),
        : absorb_clobbers);
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

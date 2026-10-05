const std = @import("std");

const Io = std.Io;

const Writer = Io.Writer;

// The kernels that run as one inline assembly statement each, with registers allocated by hand:
// LLVM cannot schedule around hundreds of separate statements, and a build for a baseline x86-64
// CPU has no ymm operands to give them. They are generated so that the register plans follow
// from the algorithms; `zig build asm` rewrites src/asm/, and `zig build test` fails when a file
// there is not what this program writes.
const Kernel = struct {
    name: []const u8,
    write: *const fn (*Writer) Writer.Error!void,
};

const kernels = [_]Kernel{
    .{ .name = "keccak_x1_sha3.s", .write = keccakSha3One },
    .{ .name = "keccak_x2_sha3.s", .write = keccakSha3Two },
    .{ .name = "keccak_absorb_sha3.s", .write = keccakSha3Absorb },
    .{ .name = "keccak_x3_hybrid.s", .write = keccakHybrid },
    .{ .name = "keccak_x4_avx2.s", .write = keccakAvx2 },
    .{ .name = "sha256_x8_avx2.s", .write = sha256Avx2 },
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    const usage = args.len != 3 or !(std.mem.eql(u8, args[1], "--write") or std.mem.eql(u8, args[1], "--check"));

    if (usage) {
        std.debug.print("usage: asm --write|--check <directory>\n", .{});

        std.process.exit(2);
    }

    const check = std.mem.eql(u8, args[1], "--check");

    var dir = try Io.Dir.cwd().openDir(init.io, args[2], .{});

    defer dir.close(init.io);

    var stale = false;

    for (kernels) |kernel| {
        var text: Writer.Allocating = .init(init.gpa);

        defer text.deinit();

        try kernel.write(&text.writer);

        if (!check) {
            try dir.writeFile(init.io, .{ .sub_path = kernel.name, .data = text.written() });

            continue;
        }

        const current = dir.readFileAlloc(init.io, kernel.name, init.gpa, .limited(1 << 20)) catch |err| switch (err) {
            error.FileNotFound => "",
            else => return err,
        };

        defer if (current.len > 0) init.gpa.free(current);

        if (!std.mem.eql(u8, current, text.written())) {
            std.debug.print("src/asm/{s} is not what tools/asm.zig writes: run zig build asm\n", .{kernel.name});

            stale = true;
        }
    }

    if (stale) std.process.exit(1);
}

fn line(w: *Writer, comptime format: []const u8, args: anytype) Writer.Error!void {
    try w.print(format ++ "\n", args);
}

// Keccak-f[1600] (FIPS 202): lane x + 5y, its rotation, and where pi moves it.
const rho = [25]u32{ 0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14 };

fn piTarget(s: usize) usize {
    const x = s % 5;

    const y = s / 5;

    return y + 5 * ((2 * x + 3 * y) % 5);
}

fn keccakSha3One(w: *Writer) Writer.Error!void {
    try keccakSha3(w, 1);
}

fn keccakSha3Two(w: *Writer) Writer.Error!void {
    try keccakSha3(w, 2);
}

// Keccak-f[1600] with the AArch64 SHA3 instructions on one state, or on two: lane i of both
// lives in vector register i, the first state in the low half. Inputs: x0 points to the states,
// x1 to the 24 round constants; x2, x3 and x4 are scratch.
fn keccakSha3(w: *Writer, states: usize) Writer.Error!void {
    try line(w, ".arch_extension sha3", .{});

    try moveStates(w, states, .load, "x0", "x2");

    try line(w, "mov x3, #24", .{});

    try line(w, "mov x4, x1", .{});

    try line(w, "1:", .{});

    try keccakRoundSha3(w);

    try line(w, "ld1r {{v26.2d}}, [x4], #8", .{});

    try line(w, "eor v0.16b, v0.16b, v26.16b", .{});

    try line(w, "subs x3, x3, #1", .{});

    try line(w, "b.ne 1b", .{});

    try moveStates(w, states, .store, "x0", "x2");
}

// Absorbs whole blocks into one state, which stays in the registers from block to block. Inputs:
// x0 points to the state, x1 to the round constants, x2 to the data, x3 holds the number of
// blocks (at least one) and x5 the rate in lanes (9, 13, 17, 18 or 21); x4, x6, x7 and x8 are
// scratch.
fn keccakSha3Absorb(w: *Writer) Writer.Error!void {
    try line(w, ".arch_extension sha3", .{});

    try moveStates(w, 1, .load, "x0", "x2");

    try line(w, "mov x6, x2", .{});

    try line(w, "mov x7, x3", .{});

    try line(w, "1:", .{});

    // The data lanes go through the free registers v25-v31 in turn; the rate decides where the
    // XOR stops. A d-register load clears the high half, which the lone state does not use.
    for (0..21) |i| {
        const scratch = 25 + i % 7;

        try line(w, "ldr d{d}, [x6], #8", .{scratch});

        try line(w, "eor v{d}.16b, v{d}.16b, v{d}.16b", .{ i, i, scratch });

        if (i + 1 == 9 or i + 1 == 13 or i + 1 == 17 or i + 1 == 18) {
            try line(w, "cmp x5, #{d}", .{i + 1});

            try line(w, "b.eq 2f", .{});
        }
    }

    try line(w, "2:", .{});

    try line(w, "mov x8, #24", .{});

    try line(w, "mov x4, x1", .{});

    try line(w, "3:", .{});

    try keccakRoundSha3(w);

    try line(w, "ld1r {{v26.2d}}, [x4], #8", .{});

    try line(w, "eor v0.16b, v0.16b, v26.16b", .{});

    try line(w, "subs x8, x8, #1", .{});

    try line(w, "b.ne 3b", .{});

    try line(w, "subs x7, x7, #1", .{});

    try line(w, "b.ne 1b", .{});

    try moveStates(w, 1, .store, "x0", "x2");
}

// One round but iota, with every lane back in its register: EOR3 sums the theta columns, RAX1
// forms D[x] = C[x - 1] ^ rol(C[x + 1], 1), XAR applies D and the rho rotation while lanes move
// along the 24-cycle of pi, and BCAX computes chi. v25-v31 are scratch, and v25 and v26 are free
// at the end. Register moves cost nothing on the cores that run this code.
fn keccakRoundSha3(w: *Writer) Writer.Error!void {
    // C[x] in v25 + x.
    for (0..5) |x| {
        try line(w, "eor3 v{d}.16b, v{d}.16b, v{d}.16b, v{d}.16b", .{ 25 + x, x, x + 5, x + 10 });

        try line(w, "eor3 v{d}.16b, v{d}.16b, v{d}.16b, v{d}.16b", .{ 25 + x, 25 + x, x + 15, x + 20 });
    }

    // RAX1 Vd, Vn, Vm computes Vn ^ rol(Vm, 1). D[0] and D[1] take the free registers, and D[2],
    // D[3] and D[4] replace C[1], C[2] and C[3], each after its last use.
    const d = [5]u32{ 30, 31, 26, 27, 28 };

    for (0..5) |x| {
        try line(w, "rax1 v{d}.2d, v{d}.2d, v{d}.2d", .{ d[x], 25 + (x + 4) % 5, 25 + (x + 1) % 5 });
    }

    // Walking the cycle backwards from lane 1, every lane is read before it is overwritten,
    // except lane 1 itself, which is saved in v25 (C[0] is no longer needed).
    var source: [25]usize = undefined;

    for (0..25) |s| source[piTarget(s)] = s;

    try line(w, "mov v25.16b, v1.16b", .{});

    var t: usize = 1;

    while (true) {
        const s = source[t];

        const from = if (s == 1) 25 else s;

        try line(w, "xar v{d}.2d, v{d}.2d, v{d}.2d, #{d}", .{ t, from, d[s % 5], 64 - rho[s] });

        if (s == 1) break;

        t = s;
    }

    try line(w, "eor v0.16b, v0.16b, v{d}.16b", .{d[0]});

    // BCAX Vd, Vn, Vm, Va computes Vn ^ (Vm & ~Va); chi is b[x] ^ (b[x + 2] & ~b[x + 1]). The
    // first two lanes of a row are overwritten before the last two use them, so they are saved
    // in v25 and v26.
    for (0..5) |y| {
        const r = 5 * y;

        try line(w, "mov v25.16b, v{d}.16b", .{r});

        try line(w, "mov v26.16b, v{d}.16b", .{r + 1});

        for (0..5) |x| {
            const two_on: usize = if (x < 3) r + x + 2 else 22 + x;

            const one_on: usize = if (x < 4) r + x + 1 else 25;

            try line(w, "bcax v{d}.16b, v{d}.16b, v{d}.16b, v{d}.16b", .{ r + x, r + x, two_on, one_on });
        }
    }
}

const Direction = enum { load, store };

// The first state's lanes move as the low halves (writing a d register clears the high half);
// the second's, 200 bytes on, as the high halves, with `walker` running over them.
fn moveStates(w: *Writer, states: usize, comptime direction: Direction, base: []const u8, walker: []const u8) Writer.Error!void {
    const scalar = if (direction == .load) "ldr" else "str";

    const lane = if (direction == .load) "ld1" else "st1";

    if (states == 2) try line(w, "add {s}, {s}, #200", .{ walker, base });

    for (0..25) |i| {
        try line(w, "{s} d{d}, [{s}, #{d}]", .{ scalar, i, base, 8 * i });

        if (states == 2) try line(w, "{s} {{v{d}.d}}[1], [{s}], #8", .{ lane, i, walker });
    }
}

// Three Keccak-f[1600] permutations at once: two states with the SHA3 instructions as in
// keccakSha3 and the third in general-purpose registers, the two instruction streams interleaved
// round by round so that the vector and the integer pipelines work at the same time; a loop of
// two rounds keeps the code small. The scalar state lives in x0-x17 and x19-x25 (x18 is the
// platform register on some systems, x29 the frame pointer and x30 the link register), x26-x28
// are its scratch registers, and the stack holds three spilled lanes, the states pointer and the
// pointers to the next and past the last round constant. Inputs: x0 points to the three states,
// x1 to the round constants.
fn keccakHybrid(w: *Writer) Writer.Error!void {
    try line(w, ".arch_extension sha3", .{});

    try line(w, "sub sp, sp, #48", .{});

    try line(w, "str x0, [sp, #24]", .{});

    try line(w, "add x2, x1, #192", .{});

    try line(w, "stp x1, x2, [sp, #32]", .{});

    try moveStates(w, 2, .load, "x0", "x2");

    for (1..25) |i| try line(w, "ldr {s}, [x0, #{d}]", .{ scalarLane(i), 400 + 8 * i });

    try line(w, "ldr x0, [x0, #400]", .{});

    try line(w, "1:", .{});

    for (0..2) |r| {
        var vector_buffer: [16 << 10]u8 = undefined;

        var vector: Writer = .fixed(&vector_buffer);

        try keccakRoundSha3(&vector);

        var scalar_buffer: [16 << 10]u8 = undefined;

        var scalar: Writer = .fixed(&scalar_buffer);

        try keccakRoundScalar(&scalar);

        try interleave(w, vector.buffered(), scalar.buffered());

        // Iota for both, from one load of the constant.
        try line(w, "ldr x26, [sp, #32]", .{});

        try line(w, "ldr x27, [x26], #8", .{});

        try line(w, "str x26, [sp, #32]", .{});

        try line(w, "eor x0, x0, x27", .{});

        try line(w, "dup v26.2d, x27", .{});

        try line(w, "eor v0.16b, v0.16b, v26.16b", .{});

        if (r == 1) {
            try line(w, "ldr x28, [sp, #40]", .{});

            try line(w, "cmp x26, x28", .{});

            try line(w, "b.ne 1b", .{});
        }
    }

    try line(w, "ldr x26, [sp, #24]", .{});

    for (0..25) |i| try line(w, "str {s}, [x26, #{d}]", .{ scalarLane(i), 400 + 8 * i });

    try moveStates(w, 2, .store, "x26", "x27");

    try line(w, "add sp, sp, #48", .{});
}

fn scalarLane(i: usize) []const u8 {
    const names = [25][]const u8{
        "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",  "x8",  "x9",
        "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20",
        "x21", "x22", "x23", "x24", "x25",
    };

    return names[i];
}

// One round but iota in general-purpose registers, every lane back in its own register at the
// end. Theta first sums column 4 into the register of lane 4, whose value waits on the stack
// with those of lanes 9 and 14; the other sums go to x26-x28 and lane 9's register, lane 14's
// register takes D[1] and D[2] in turn, and the sums turn into the other D[x] as their last use
// passes. Rho and pi move the lanes along the cycle with lane 1 parked in x26, and chi needs
// three scratch registers per row.
fn keccakRoundScalar(w: *Writer) Writer.Error!void {
    const lane = scalarLane;

    try line(w, "stp x4, x9, [sp]", .{});

    try line(w, "str x14, [sp, #16]", .{});

    try line(w, "eor x4, x4, x9", .{});

    for (2..5) |y| try line(w, "eor x4, x4, {s}", .{lane(4 + 5 * y)});

    const sums = [4][]const u8{ "x26", "x27", "x28", "x9" };

    for (sums, 0..) |sum, x| {
        try line(w, "eor {s}, {s}, {s}", .{ sum, lane(x), lane(x + 5) });

        for (2..5) |y| try line(w, "eor {s}, {s}, {s}", .{ sum, sum, lane(x + 5 * y) });
    }

    // rol(C, 1) is C rotated right by 63.
    try line(w, "eor x14, x26, x28, ror #63", .{});

    for (0..5) |y| try line(w, "eor {s}, {s}, x14", .{ lane(1 + 5 * y), lane(1 + 5 * y) });

    try line(w, "eor x14, x27, x9, ror #63", .{});

    try line(w, "eor x28, x28, x4, ror #63", .{});

    try line(w, "eor x9, x9, x26, ror #63", .{});

    try line(w, "eor x4, x4, x27, ror #63", .{});

    for (0..5) |y| try line(w, "eor {s}, {s}, x14", .{ lane(2 + 5 * y), lane(2 + 5 * y) });

    for (0..5) |y| try line(w, "eor {s}, {s}, x4", .{ lane(5 * y), lane(5 * y) });

    for (0..5) |y| try line(w, "eor {s}, {s}, x28", .{ lane(3 + 5 * y), lane(3 + 5 * y) });

    // D[4] is in lane 9's register, which takes lane 9 last.
    try line(w, "ldr x4, [sp]", .{});

    try line(w, "ldr x14, [sp, #16]", .{});

    try line(w, "ldr x26, [sp, #8]", .{});

    for ([_]usize{ 4, 14, 19, 24 }) |i| try line(w, "eor {s}, {s}, x9", .{ lane(i), lane(i) });

    try line(w, "eor x9, x26, x9", .{});

    var source: [25]usize = undefined;

    for (0..25) |s| source[piTarget(s)] = s;

    try line(w, "mov x26, {s}", .{lane(1)});

    var t: usize = 1;

    while (true) {
        const s = source[t];

        try line(w, "ror {s}, {s}, #{d}", .{ lane(t), if (s == 1) "x26" else lane(s), 64 - rho[s] });

        if (s == 1) break;

        t = s;
    }

    // BIC Xd, Xn, Xm computes Xn & ~Xm; chi is b[x] ^ (b[x + 2] & ~b[x + 1]).
    for (0..5) |y| {
        const b = [5][]const u8{ lane(5 * y), lane(5 * y + 1), lane(5 * y + 2), lane(5 * y + 3), lane(5 * y + 4) };

        try line(w, "bic x26, {s}, {s}", .{ b[2], b[1] });

        try line(w, "bic x27, {s}, {s}", .{ b[3], b[2] });

        try line(w, "bic x28, {s}, {s}", .{ b[4], b[3] });

        try line(w, "eor {s}, {s}, x28", .{ b[2], b[2] });

        try line(w, "bic x28, {s}, {s}", .{ b[0], b[4] });

        try line(w, "eor {s}, {s}, x28", .{ b[3], b[3] });

        try line(w, "bic x28, {s}, {s}", .{ b[1], b[0] });

        try line(w, "eor {s}, {s}, x28", .{ b[4], b[4] });

        try line(w, "eor {s}, {s}, x26", .{ b[0], b[0] });

        try line(w, "eor {s}, {s}, x27", .{ b[1], b[1] });
    }
}

// Merges two instruction streams so that each advances in proportion to its length.
fn interleave(w: *Writer, first: []const u8, second: []const u8) Writer.Error!void {
    const a = std.mem.count(u8, first, "\n");

    const b = std.mem.count(u8, second, "\n");

    var left = std.mem.splitScalar(u8, first, '\n');

    var right = std.mem.splitScalar(u8, second, '\n');

    var taken_a: usize = 0;

    var taken_b: usize = 0;

    while (taken_a < a or taken_b < b) {
        if (taken_b == b or (taken_a < a and taken_a * b <= taken_b * a)) {
            try line(w, "{s}", .{left.next().?});

            taken_a += 1;
        } else {
            try line(w, "{s}", .{right.next().?});

            taken_b += 1;
        }
    }
}

// Four Keccak-f[1600] permutations with AVX2: lane i of the four states is one ymm register.
// 25 lanes do not fit in 16 registers, so the states live in two buffers of 25 x 32 bytes that
// alternate as source and destination, two rounds per loop iteration. Inputs: rdi points to the
// four states (200 bytes each), rsi to the two buffers, rdx to the round constants repeated in
// every quarter of 32 bytes, rcx to the vpshufb masks for rotations by 8 and 56; r8 walks the
// constants and eax counts. Intel syntax: no register needs a % escape in a Zig template.
fn keccakAvx2(w: *Writer) Writer.Error!void {
    try line(w, ".intel_syntax noprefix", .{});

    try transpose4(w, .in);

    try line(w, "mov r8, rdx", .{});

    try line(w, "mov eax, 12", .{});

    try line(w, "1:", .{});

    try keccakRoundAvx2(w, 0, 800, 0);

    try keccakRoundAvx2(w, 800, 0, 32);

    try line(w, "add r8, 64", .{});

    try line(w, "dec eax", .{});

    try line(w, "jnz 1b", .{});

    try transpose4(w, .out);

    try line(w, "vzeroupper", .{});

    try line(w, ".att_syntax prefix", .{});
}

// Lanes 4k .. 4k + 3 of the four states form a 4 x 4 matrix of 64-bit words; unpacking pairs and
// exchanging 128-bit halves transposes it, in either direction. Lane 24 is moved word by word.
fn transpose4(w: *Writer, comptime direction: enum { in, out }) Writer.Error!void {
    for (0..6) |k| {
        for (0..4) |j| {
            if (direction == .in) {
                try line(w, "vmovdqu ymm{d}, ymmword ptr [rdi + {d}]", .{ j, 200 * j + 32 * k });
            } else {
                try line(w, "vmovdqu ymm{d}, ymmword ptr [rsi + {d}]", .{ j, 32 * (4 * k + j) });
            }
        }

        try line(w, "vpunpcklqdq ymm4, ymm0, ymm1", .{});

        try line(w, "vpunpckhqdq ymm5, ymm0, ymm1", .{});

        try line(w, "vpunpcklqdq ymm6, ymm2, ymm3", .{});

        try line(w, "vpunpckhqdq ymm7, ymm2, ymm3", .{});

        try line(w, "vperm2i128 ymm0, ymm4, ymm6, 32", .{});

        try line(w, "vperm2i128 ymm1, ymm5, ymm7, 32", .{});

        try line(w, "vperm2i128 ymm2, ymm4, ymm6, 49", .{});

        try line(w, "vperm2i128 ymm3, ymm5, ymm7, 49", .{});

        for (0..4) |j| {
            if (direction == .in) {
                try line(w, "vmovdqu ymmword ptr [rsi + {d}], ymm{d}", .{ 32 * (4 * k + j), j });
            } else {
                try line(w, "vmovdqu ymmword ptr [rdi + {d}], ymm{d}", .{ 200 * j + 32 * k, j });
            }
        }
    }

    if (direction == .in) {
        try line(w, "vmovq xmm0, qword ptr [rdi + 192]", .{});

        try line(w, "vpinsrq xmm0, xmm0, qword ptr [rdi + 392], 1", .{});

        try line(w, "vmovq xmm1, qword ptr [rdi + 592]", .{});

        try line(w, "vpinsrq xmm1, xmm1, qword ptr [rdi + 792], 1", .{});

        try line(w, "vinserti128 ymm0, ymm0, xmm1, 1", .{});

        try line(w, "vmovdqu ymmword ptr [rsi + 768], ymm0", .{});
    } else {
        try line(w, "vmovdqu ymm0, ymmword ptr [rsi + 768]", .{});

        try line(w, "vextracti128 xmm1, ymm0, 1", .{});

        try line(w, "vmovq qword ptr [rdi + 192], xmm0", .{});

        try line(w, "vpextrq qword ptr [rdi + 392], xmm0, 1", .{});

        try line(w, "vmovq qword ptr [rdi + 592], xmm1", .{});

        try line(w, "vpextrq qword ptr [rdi + 792], xmm1, 1", .{});
    }
}

// One round from the buffer at rsi + source to the one at rsi + target. C[x] takes ymm0-4 and
// D[x] ymm5-9; then each output row y computes its five values B[x] in ymm0-4 and chi in
// ymm11. Output lane x + 5y comes from input lane ((x + 3y) mod 5) + 5x.
fn keccakRoundAvx2(w: *Writer, source: usize, target: usize, constant: usize) Writer.Error!void {
    for (0..5) |x| {
        try line(w, "vmovdqa ymm{d}, ymmword ptr [rsi + {d}]", .{ x, source + 32 * x });

        for (1..5) |y| try line(w, "vpxor ymm{d}, ymm{d}, ymmword ptr [rsi + {d}]", .{ x, x, source + 32 * (x + 5 * y) });
    }

    for (0..5) |x| {
        const next = (x + 1) % 5;

        try line(w, "vpsrlq ymm10, ymm{d}, 63", .{next});

        try line(w, "vpaddq ymm11, ymm{d}, ymm{d}", .{ next, next });

        try line(w, "vpor ymm10, ymm10, ymm11", .{});

        try line(w, "vpxor ymm{d}, ymm10, ymm{d}", .{ 5 + x, (x + 4) % 5 });
    }

    for (0..5) |y| {
        for (0..5) |x| {
            const lane = (x + 3 * y) % 5 + 5 * x;

            const r = rho[lane];

            try line(w, "vpxor ymm{d}, ymm{d}, ymmword ptr [rsi + {d}]", .{ x, 5 + lane % 5, source + 32 * lane });

            switch (r) {
                0 => {},
                8 => try line(w, "vpshufb ymm{d}, ymm{d}, ymmword ptr [rcx]", .{ x, x }),
                56 => try line(w, "vpshufb ymm{d}, ymm{d}, ymmword ptr [rcx + 32]", .{ x, x }),
                else => {
                    try line(w, "vpsrlq ymm10, ymm{d}, {d}", .{ x, 64 - r });

                    try line(w, "vpsllq ymm{d}, ymm{d}, {d}", .{ x, x, r });

                    try line(w, "vpor ymm{d}, ymm{d}, ymm10", .{ x, x });
                },
            }
        }

        for (0..5) |x| {
            try line(w, "vpandn ymm11, ymm{d}, ymm{d}", .{ (x + 1) % 5, (x + 2) % 5 });

            try line(w, "vpxor ymm11, ymm11, ymm{d}", .{x});

            if (x == 0 and y == 0) try line(w, "vpxor ymm11, ymm11, ymmword ptr [r8 + {d}]", .{constant});

            try line(w, "vmovdqa ymmword ptr [rsi + {d}], ymm11", .{target + 32 * (x + 5 * y)});
        }
    }
}

// Eight SHA-256 compressions (FIPS 180-4) with AVX2: word i of the eight states is one ymm
// register, as are the message words. Variable i of round t lives in ymm((i - t) mod 8), so the
// eight working variables rotate by renaming; ymm8 and ymm9 are scratch, ymm10 and ymm11 carry
// a ^ b into the next round's Maj, and ymm12-15 extend the schedule. Inputs: rdi points to the
// state, rsi to the 16 message words, rdx to the 64 round constants repeated in every 4-byte
// lane of 32 bytes, rcx to a 512-byte schedule buffer; r8 walks the constants and eax counts.
fn sha256Avx2(w: *Writer) Writer.Error!void {
    try line(w, ".intel_syntax noprefix", .{});

    for (0..8) |i| try line(w, "vmovdqu ymm{d}, ymmword ptr [rdi + {d}]", .{ i, 32 * i });

    // b ^ c for the first round's Maj.
    try line(w, "vpxor ymm10, ymm1, ymm2", .{});

    for (0..16) |t| try sha256RoundAvx2(w, t, .load);

    try line(w, "lea r8, [rdx + 512]", .{});

    try line(w, "mov eax, 3", .{});

    try line(w, "1:", .{});

    for (16..32) |t| try sha256RoundAvx2(w, t, .schedule);

    try line(w, "add r8, 512", .{});

    try line(w, "dec eax", .{});

    try line(w, "jnz 1b", .{});

    for (0..8) |i| {
        try line(w, "vpaddd ymm{d}, ymm{d}, ymmword ptr [rdi + {d}]", .{ i, i, 32 * i });

        try line(w, "vmovdqu ymmword ptr [rdi + {d}], ymm{d}", .{ 32 * i, i });
    }

    try line(w, "vzeroupper", .{});

    try line(w, ".att_syntax prefix", .{});
}

// x rotated right by r, as (x >> r) ^ (x << (32 - r)) accumulated into `into` with `scratch`.
fn rotateXor(w: *Writer, into: usize, scratch: usize, x: usize, comptime rotations: [3]u32, comptime shift: bool) Writer.Error!void {
    try line(w, "vpsrld ymm{d}, ymm{d}, {d}", .{ into, x, rotations[0] });

    try line(w, "vpslld ymm{d}, ymm{d}, {d}", .{ scratch, x, 32 - rotations[0] });

    try line(w, "vpxor ymm{d}, ymm{d}, ymm{d}", .{ into, into, scratch });

    try line(w, "vpsrld ymm{d}, ymm{d}, {d}", .{ scratch, x, rotations[1] });

    try line(w, "vpxor ymm{d}, ymm{d}, ymm{d}", .{ into, into, scratch });

    try line(w, "vpslld ymm{d}, ymm{d}, {d}", .{ scratch, x, 32 - rotations[1] });

    try line(w, "vpxor ymm{d}, ymm{d}, ymm{d}", .{ into, into, scratch });

    try line(w, "vpsrld ymm{d}, ymm{d}, {d}", .{ scratch, x, rotations[2] });

    try line(w, "vpxor ymm{d}, ymm{d}, ymm{d}", .{ into, into, scratch });

    if (!shift) {
        try line(w, "vpslld ymm{d}, ymm{d}, {d}", .{ scratch, x, 32 - rotations[2] });

        try line(w, "vpxor ymm{d}, ymm{d}, ymm{d}", .{ into, into, scratch });
    }
}

// Round t: the first 16 copy their message word into the schedule buffer, the others compute
// W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16] in slot t mod 16, where
// W[t - 15], W[t - 7] and W[t - 2] sit at (t + 1), (t + 9) and (t + 14) mod 16.
fn sha256RoundAvx2(w: *Writer, t: usize, comptime word: enum { load, schedule }) Writer.Error!void {
    const a = (8 - t % 8) % 8;

    const b = (9 - t % 8) % 8;

    const d = (11 - t % 8) % 8;

    const e = (12 - t % 8) % 8;

    const f = (13 - t % 8) % 8;

    const g = (14 - t % 8) % 8;

    const h = (15 - t % 8) % 8;

    const carry = 10 + t % 2;

    const fresh = 11 - t % 2;

    const slot = 32 * (t % 16);

    switch (word) {
        .load => {
            try line(w, "vmovdqu ymm12, ymmword ptr [rsi + {d}]", .{slot});

            try line(w, "vmovdqa ymmword ptr [rcx + {d}], ymm12", .{slot});
        },
        .schedule => {
            try line(w, "vmovdqa ymm12, ymmword ptr [rcx + {d}]", .{32 * ((t + 1) % 16)});

            try rotateXor(w, 13, 14, 12, .{ 7, 18, 3 }, true);

            try line(w, "vmovdqa ymm12, ymmword ptr [rcx + {d}]", .{32 * ((t + 14) % 16)});

            try rotateXor(w, 14, 15, 12, .{ 17, 19, 10 }, true);

            try line(w, "vpaddd ymm13, ymm13, ymm14", .{});

            try line(w, "vpaddd ymm13, ymm13, ymmword ptr [rcx + {d}]", .{32 * ((t + 9) % 16)});

            try line(w, "vpaddd ymm12, ymm13, ymmword ptr [rcx + {d}]", .{slot});

            try line(w, "vmovdqa ymmword ptr [rcx + {d}], ymm12", .{slot});
        },
    }

    try rotateXor(w, 8, 9, e, .{ 6, 11, 25 }, false);

    try line(w, "vpxor ymm9, ymm{d}, ymm{d}", .{ f, g });

    try line(w, "vpand ymm9, ymm9, ymm{d}", .{e});

    try line(w, "vpxor ymm9, ymm9, ymm{d}", .{g});

    try line(w, "vpaddd ymm{d}, ymm{d}, ymm8", .{ h, h });

    try line(w, "vpaddd ymm{d}, ymm{d}, ymm9", .{ h, h });

    switch (word) {
        .load => try line(w, "vpaddd ymm{d}, ymm{d}, ymmword ptr [rdx + {d}]", .{ h, h, 32 * t }),
        .schedule => try line(w, "vpaddd ymm{d}, ymm{d}, ymmword ptr [r8 + {d}]", .{ h, h, 32 * (t - 16) }),
    }

    try line(w, "vpaddd ymm{d}, ymm{d}, ymm12", .{ h, h });

    try line(w, "vpaddd ymm{d}, ymm{d}, ymm{d}", .{ d, d, h });

    try rotateXor(w, 8, 9, a, .{ 2, 13, 22 }, false);

    // Maj(a, b, c) = ((a ^ b) & (b ^ c)) ^ b, where b ^ c is the previous round's a ^ b.
    try line(w, "vpxor ymm{d}, ymm{d}, ymm{d}", .{ fresh, a, b });

    try line(w, "vpand ymm{d}, ymm{d}, ymm{d}", .{ carry, carry, fresh });

    try line(w, "vpxor ymm{d}, ymm{d}, ymm{d}", .{ carry, carry, b });

    try line(w, "vpaddd ymm{d}, ymm{d}, ymm8", .{ h, h });

    try line(w, "vpaddd ymm{d}, ymm{d}, ymm{d}", .{ h, h, carry });
}

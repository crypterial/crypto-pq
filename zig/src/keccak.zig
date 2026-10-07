const std = @import("std");
const builtin = @import("builtin");

const cpu = @import("cpu.zig");
const ct = @import("ct.zig");

const isa = switch (builtin.cpu.arch) {
    .aarch64 => @import("aarch64.zig"),
    .x86_64 => @import("x86_64.zig"),
    .wasm32 => @import("wasm.zig"),
    else => struct {},
};

pub const round_constants = [24]u64{
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
};

const rotations = [25]u6{ 0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14 };

// One permutation: with the SHA3 instructions on the cores that run them fast, the WebAssembly
// code below, or the portable code.
pub fn permute(state: *[25]u64) void {
    if (comptime cpu.possible(.sha3)) {
        if (cpu.has(.sha3)) return isa.keccak1(state);
    }

    if (comptime cpu.wasm_simd) return webassembly.permute(state);

    portable.permute(state);
}

// Whole blocks XORed into a state and permuted, as many as `data` holds: with the SHA3
// instructions, which keep the state in registers between the blocks, on the cores that run them
// fast. Returns the number of bytes absorbed, zero where the code below takes them one by one.
fn absorbBlocks(state: *[25]u64, rate: usize, data: []const u8) usize {
    if (comptime cpu.possible(.sha3)) {
        const supported = rate == 72 or rate == 104 or rate == 136 or rate == 144 or rate == 168;

        if (supported and data.len >= rate and cpu.has(.sha3)) {
            const length = data.len - data.len % rate;

            isa.keccakAbsorb(state, rate, data[0..length]);

            return length;
        }
    }

    return 0;
}

// Four independent permutations: two pairs with the SHA3 instructions on the cores that run them
// fast, all four in AVX2 registers, the WebAssembly code below, or the portable code below.
pub fn permute4(states: *[4][25]u64) void {
    if (comptime cpu.possible(.sha3)) {
        if (cpu.has(.sha3)) {
            isa.keccak2(states[0..2]);

            return isa.keccak2(states[2..4]);
        }
    }

    if (comptime cpu.possible(.avx2)) {
        if (cpu.has(.avx2)) return isa.keccak4(states);
    }

    if (comptime cpu.wasm_simd) return webassembly.permute4(states);

    portable.permute4(states);
}

// The first `count` (one to four) of four independent states, permuted as cheaply as the CPU
// allows: with the SHA3 instructions a pair costs no more than one state and three little more
// than two, and the four-way code pays off from three states on.
pub fn permuteSome(states: *[4][25]u64, count: usize) void {
    std.debug.assert(count >= 1 and count <= 4);

    if (comptime cpu.possible(.sha3)) {
        if (cpu.has(.sha3)) {
            return switch (count) {
                1 => isa.keccak1(&states[0]),
                2 => isa.keccak2(states[0..2]),
                3 => isa.keccak3(states[0..3]),
                else => {
                    isa.keccak2(states[0..2]);

                    isa.keccak2(states[2..4]);
                },
            };
        }
    }

    if (comptime cpu.wasm_simd) {
        return switch (count) {
            1 => webassembly.permute(&states[0]),
            2 => webassembly.permute2(states[0..2]),
            3 => webassembly.permute3(states),
            else => webassembly.permute4(states),
        };
    }

    if (count >= 3) return permute4(states);

    for (states[0..count]) |*state| permute(state);
}

// How many of `remaining` independent sponges to run together, at most four: in threes where
// three states cost little more than two, with four as two pairs and the last one or two alone.
pub fn batch(remaining: usize) usize {
    if (comptime cpu.possible(.sha3)) {
        if (remaining > 2 and remaining != 4 and cpu.has(.sha3)) return 3;
    }

    return @min(4, remaining);
}

// The code for every target.
pub const portable = struct {
    pub const permute = portablePermute;

    pub const permute4 = portablePermute4;
};

// The state is copied into locals so that it can live in registers across the rounds.
fn portablePermute(state: *[25]u64) void {
    var a = state.*;

    for (round_constants) |constant| round(u64, &a, constant);

    state.* = a;
}

// Two states in the lanes of 2 x 64-bit vectors and two in integer registers, interleaved round
// by round so that the vector and the integer units work at the same time. Four states take about
// a fifth less time than four permutations in a row.
fn portablePermute4(states: *[4][25]u64) void {
    const W = @Vector(2, u64);

    var pair: [25]W = undefined;

    for (&pair, states[0], states[1]) |*lane, x, y| lane.* = .{ x, y };

    var third = states[2];

    var fourth = states[3];

    for (round_constants) |constant| {
        round(W, &pair, constant);

        round(u64, &third, constant);

        round(u64, &fourth, constant);
    }

    for (pair, &states[0], &states[1]) |lane, *x, *y| {
        x.* = lane[0];

        y.* = lane[1];
    }

    states[2] = third;

    states[3] = fourth;
}

// The code for WebAssembly, measured on V8 and JavaScriptCore, whose code generators allocate the
// registers and order the instructions themselves. Engines differ in which shapes of the code they
// compile well, and the binding says once which engine runs the module (tune). V8 before version
// 15 joins the two shifts of a rotation of vector lanes in two instructions on Arm (SHL and USRA)
// only when they are added, and runs three states fastest together, two in the lanes of 2 x 64-bit
// vectors and one in integer registers. V8 15 and JavaScriptCore compile the plain rotation well,
// fusing it on Arm with the XOR before it, and lose that to the addition: they run states in pairs
// in vector lanes far faster than in integer registers. V8 also runs a single state faster with two
// rounds per iteration, from one array of lanes into the other and back, which JavaScriptCore runs
// slower than the portable code. Other engines get the shapes that run best on average on those
// measured: three states together with plain rotations, the rest one by one.
pub const webassembly = struct {
    var adds = false;

    var unrolled = false;

    var pairs = false;

    // Bit 0: the engine adds the halves of a rotation faster than it rotates. Bit 1: it runs a
    // single state faster with two rounds per iteration. Bit 2: it runs two states faster in the
    // lanes of vectors than one after the other in integer registers.
    pub fn tune(flags: u32) void {
        adds = flags & 1 != 0;

        unrolled = flags & 2 != 0;

        pairs = flags & 4 != 0;
    }

    // The dispatches are functions of their own, so that the shapes' conditions stay in a few
    // places for the WebAssembly lint (zig build wasm-lint).
    noinline fn permute(state: *[25]u64) void {
        if (unrolled) return twoRounds(state);

        portable.permute(state);
    }

    noinline fn permute2(states: *[2][25]u64) void {
        if (pairs) return pair(states);

        for (states) |*state| webassembly.permute(state);
    }

    // The first three of the four states.
    noinline fn permute3(states: *[4][25]u64) void {
        if (adds) return hybrid(true, states);

        hybrid(false, states);
    }

    noinline fn permute4(states: *[4][25]u64) void {
        if (pairs) {
            pair(states[0..2]);

            return pair(states[2..4]);
        }

        permute3(states);

        webassembly.permute(&states[3]);
    }

    // Each shape is a function of its own: inlined into one, they ran markedly slower on
    // JavaScriptCore.
    noinline fn twoRounds(state: *[25]u64) void {
        var a = state.*;

        var e: [25]u64 = undefined;

        var i: usize = 0;

        while (i < round_constants.len) : (i += 2) {
            roundInto(u64, false, &a, &e, round_constants[i]);

            roundInto(u64, false, &e, &a, round_constants[i + 1]);
        }

        state.* = a;
    }

    // Two states in the lanes of 2 x 64-bit vectors, with the rounds of the portable code: the
    // engines that run pairs fast run this shape faster than two rounds per iteration.
    noinline fn pair(states: *[2][25]u64) void {
        const W = @Vector(2, u64);

        var lanes: [25]W = undefined;

        for (&lanes, states[0], states[1]) |*lane, x, y| lane.* = .{ x, y };

        for (round_constants) |constant| round(W, &lanes, constant);

        for (lanes, &states[0], &states[1]) |lane, *x, *y| {
            x.* = lane[0];

            y.* = lane[1];
        }
    }

    // The first two states in the lanes of vectors and the third in integer registers.
    noinline fn hybrid(comptime add: bool, states: *[4][25]u64) void {
        const W = @Vector(2, u64);

        var lanes: [25]W = undefined;

        for (&lanes, states[0], states[1]) |*lane, x, y| lane.* = .{ x, y };

        var third = states[2];

        var e: [25]W = undefined;

        var t: [25]u64 = undefined;

        var i: usize = 0;

        while (i < round_constants.len) : (i += 2) {
            roundInto(W, add, &lanes, &e, round_constants[i]);

            roundInto(u64, add, &third, &t, round_constants[i]);

            roundInto(W, add, &e, &lanes, round_constants[i + 1]);

            roundInto(u64, add, &t, &third, round_constants[i + 1]);
        }

        for (lanes, &states[0], &states[1]) |lane, *x, *y| {
            x.* = lane[0];

            y.* = lane[1];
        }

        states[2] = third;
    }
};

// Theta of a, then rho, pi and chi into e one output plane at a time, as XKCP's unrolled code
// does: lane x of output plane y comes from lane x' + 5x of a, with x' = (x + 3y) mod 5. Vector
// lanes rotate with the added shifts of isa.rotate when add is set.
inline fn roundInto(comptime W: type, comptime add: bool, a: *const [25]W, e: *[25]W, constant: u64) void {
    var c: [5]W = undefined;

    inline for (0..5) |x| {
        c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    }

    var d: [5]W = undefined;

    inline for (0..5) |x| {
        d[x] = c[(x + 4) % 5] ^ rotate(W, add, c[(x + 1) % 5], 1);
    }

    inline for (0..5) |y| {
        var b: [5]W = undefined;

        inline for (0..5) |x| {
            const column = (x + 3 * y) % 5;

            b[x] = rotate(W, add, a[column + 5 * x] ^ d[column], rotations[column + 5 * x]);
        }

        inline for (0..5) |x| {
            e[5 * y + x] = b[x] ^ (~b[(x + 1) % 5] & b[(x + 2) % 5]);
        }
    }

    e[0] ^= if (W == u64) constant else @as(W, @splat(constant));
}

inline fn rotate(comptime W: type, comptime add: bool, x: W, comptime k: u6) W {
    if (W == u64 or !add or k == 0) return std.math.rotl(W, x, k);

    return isa.rotate(x, k);
}

inline fn round(comptime W: type, a: *[25]W, constant: u64) void {
    var c: [5]W = undefined;

    inline for (0..5) |x| {
        c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    }

    var d: [5]W = undefined;

    inline for (0..5) |x| {
        d[x] = c[(x + 4) % 5] ^ std.math.rotl(W, c[(x + 1) % 5], 1);
    }

    var b: [25]W = undefined;

    // Theta, then rho and pi: lane x + 5y moves to y + 5((2x + 3y) mod 5).
    inline for (0..5) |y| {
        inline for (0..5) |x| {
            b[y + 5 * ((2 * x + 3 * y) % 5)] = std.math.rotl(W, a[x + 5 * y] ^ d[x], rotations[x + 5 * y]);
        }
    }

    inline for (0..5) |y| {
        inline for (0..5) |x| {
            a[5 * y + x] = b[5 * y + x] ^ (~b[5 * y + (x + 1) % 5] & b[5 * y + (x + 2) % 5]);
        }
    }

    a[0] ^= if (W == u64) constant else @as(W, @splat(constant));
}

// Bytes enter and leave the lanes in little-endian order: whole lanes at once where the offset
// is lane-aligned, single bytes at the edges.
pub fn xorBytes(state: *[25]u64, offset: usize, data: []const u8) void {
    var index = offset;

    var rest = data;

    while (rest.len > 0 and (index % 8 != 0 or rest.len < 8)) {
        state[index / 8] ^= @as(u64, rest[0]) << @intCast(8 * (index % 8));

        index += 1;

        rest = rest[1..];
    }

    while (rest.len >= 8) {
        state[index / 8] ^= std.mem.readInt(u64, rest[0..8], .little);

        index += 8;

        rest = rest[8..];
    }

    for (rest, index..) |value, i| {
        state[i / 8] ^= @as(u64, value) << @intCast(8 * (i % 8));
    }
}

pub fn copyBytes(state: *const [25]u64, offset: usize, out: []u8) void {
    var index = offset;

    var rest = out;

    while (rest.len > 0 and (index % 8 != 0 or rest.len < 8)) {
        rest[0] = @truncate(state[index / 8] >> @intCast(8 * (index % 8)));

        index += 1;

        rest = rest[1..];
    }

    while (rest.len >= 8) {
        std.mem.writeInt(u64, rest[0..8], state[index / 8], .little);

        index += 8;

        rest = rest[8..];
    }

    for (rest, index..) |*byte, i| {
        byte.* = @truncate(state[i / 8] >> @intCast(8 * (i % 8)));
    }
}

pub const Keccak = struct {
    state: [25]u64 = @splat(0),
    rate: usize,
    suffix: u8,
    position: usize = 0,
    squeezing: bool = false,

    pub fn init(rate: usize, suffix: u8) Keccak {
        return .{ .rate = rate, .suffix = suffix };
    }

    pub fn update(self: *Keccak, data: []const u8) void {
        if (self.squeezing) @panic("UNSUPPORTED: cannot update after read");

        var rest = data;

        while (rest.len > 0) {
            if (self.position == 0) {
                rest = rest[absorbBlocks(&self.state, self.rate, rest)..];

                if (rest.len == 0) break;
            }

            const take = @min(self.rate - self.position, rest.len);

            xorBytes(&self.state, self.position, rest[0..take]);

            self.position += take;

            rest = rest[take..];

            if (self.position == self.rate) {
                permute(&self.state);

                self.position = 0;
            }
        }
    }

    // Ends the block with zeros, as SP 800-185's bytepad does: a block that holds data is
    // permuted.
    pub fn fillBlock(self: *Keccak) void {
        if (self.position == 0) return;

        permute(&self.state);

        self.position = 0;
    }

    pub fn read(self: *Keccak, out: []u8) void {
        if (!self.squeezing) {
            xorBytes(&self.state, self.position, &.{self.suffix});

            xorBytes(&self.state, self.rate - 1, &.{0x80});

            permute(&self.state);

            self.position = 0;

            self.squeezing = true;
        }

        var rest = out;

        while (rest.len > 0) {
            if (self.position == self.rate) {
                permute(&self.state);

                self.position = 0;
            }

            const take = @min(self.rate - self.position, rest.len);

            copyBytes(&self.state, self.position, rest[0..take]);

            self.position += take;

            rest = rest[take..];
        }
    }
};

// Four sponges of one rate that absorb messages of one length and are then squeezed one block at
// a time, in lockstep with permute4. The caller wipes the states when they hold secrets.
pub const Sponge4 = struct {
    states: [4][25]u64,
    rate: usize,
    position: usize,
    count: usize = 4,

    // One to four sponges, each given a message shorter than a block, to be read block by block
    // with next and block: only the sponges in use are permuted. Filled in place, since the
    // states would otherwise be copied out.
    pub fn startSome(self: *Sponge4, rate: usize, suffix: u8, messages: []const []const u8) void {
        std.debug.assert(messages.len >= 1 and messages.len <= 4);

        self.rate = rate;

        self.position = 0;

        self.count = messages.len;

        ct.wipe(std.mem.asBytes(&self.states));

        for (self.states[0..messages.len], messages) |*state, message| {
            std.debug.assert(message.len < rate);

            xorBytes(state, 0, message);

            xorBytes(state, message.len, &.{suffix});

            xorBytes(state, rate - 1, &.{0x80});
        }
    }

    // An empty sponge, for messages that arrive in parts through absorb and end with finish.
    pub fn start(rate: usize) Sponge4 {
        var self: Sponge4 = .{ .states = undefined, .rate = rate, .position = 0 };

        ct.wipe(std.mem.asBytes(&self.states));

        return self;
    }

    // The next part of every message; the four parts have one length.
    pub fn absorb(self: *Sponge4, parts: [4][]const u8) void {
        const length = parts[0].len;

        var offset: usize = 0;

        while (offset < length) {
            const take = @min(self.rate - self.position, length - offset);

            for (&self.states, parts) |*state, part| {
                std.debug.assert(part.len == length);

                xorBytes(state, self.position, part[offset..][0..take]);
            }

            offset += take;

            self.position += take;

            if (self.position == self.rate) {
                permute4(&self.states);

                self.position = 0;
            }
        }
    }

    pub fn finish(self: *Sponge4, suffix: u8) void {
        for (&self.states) |*state| {
            xorBytes(state, self.position, &.{suffix});

            xorBytes(state, self.rate - 1, &.{0x80});
        }
    }

    // The next block of every sponge, the first out.len bytes of each.
    pub fn squeeze(self: *Sponge4, out: [4][]u8) void {
        permute4(&self.states);

        for (&self.states, out) |*state, bytes| copyBytes(state, 0, bytes);
    }

    // The next block of every sponge in use, read with block. A function of its own, as it was
    // when the permutations it calls were inlined into it: its conditions on the number of
    // sponges stay in one place for the WebAssembly lint.
    pub noinline fn next(self: *Sponge4) void {
        permuteSome(&self.states, self.count);
    }

    // The block that sponge i squeezed last: its state itself where lanes are stored
    // little-endian, which is the order of the output bytes, or else a copy in `buffer`.
    pub fn block(self: *const Sponge4, comptime rate: usize, i: usize, buffer: *[rate]u8) *const [rate]u8 {
        std.debug.assert(rate == self.rate);

        if (comptime builtin.cpu.arch.endian() == .little) return std.mem.asBytes(&self.states[i])[0..rate];

        copyBytes(&self.states[i], 0, buffer);

        return buffer;
    }

    pub fn wipe(self: *Sponge4) void {
        ct.wipe(std.mem.asBytes(&self.states));
    }
};

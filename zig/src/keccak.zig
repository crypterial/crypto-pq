const std = @import("std");

const ct = @import("ct.zig");

const round_constants = [24]u64{
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
};

const rotations = [25]u6{ 0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14 };

// The state is copied into locals so that it can live in registers across the rounds.
pub fn permute(state: *[25]u64) void {
    var a = state.*;

    for (round_constants) |constant| round(u64, &a, constant);

    state.* = a;
}

// Four independent permutations: two states in the lanes of 2 x 64-bit vectors and two in
// integer registers, interleaved round by round so that the vector and the integer units work at
// the same time. Four states take about a fifth less time than four permutations in a row.
pub fn permute4(states: *[4][25]u64) void {
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

    // Built in place rather than from start: SLH-DSA builds millions of these per signature, and
    // copying the state out of start made it 1.45 times slower.
    pub fn init(rate: usize, suffix: u8, messages: [4][]const u8) Sponge4 {
        var self: Sponge4 = .{ .states = undefined, .rate = rate, .position = 0 };

        ct.wipe(std.mem.asBytes(&self.states));

        const length = messages[0].len;

        var offset: usize = 0;

        while (length - offset >= rate) : (offset += rate) {
            for (&self.states, messages) |*state, message| xorBytes(state, 0, message[offset..][0..rate]);

            permute4(&self.states);
        }

        for (&self.states, messages) |*state, message| {
            std.debug.assert(message.len == length);

            xorBytes(state, 0, message[offset..length]);

            xorBytes(state, length - offset, &.{suffix});

            xorBytes(state, rate - 1, &.{0x80});
        }

        return self;
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

        for (&self.states, out) |*state, block| copyBytes(state, 0, block);
    }

    pub fn wipe(self: *Sponge4) void {
        ct.wipe(std.mem.asBytes(&self.states));
    }
};

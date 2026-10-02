const std = @import("std");

const round_constants = [24]u64{
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
};

const rotations = [25]u6{ 0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14 };

pub fn permute(a: *[25]u64) void {
    for (round_constants) |constant| {
        var c: [5]u64 = undefined;

        inline for (0..5) |x| {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }

        var d: [5]u64 = undefined;

        inline for (0..5) |x| {
            d[x] = c[(x + 4) % 5] ^ std.math.rotl(u64, c[(x + 1) % 5], 1);
        }

        var b: [25]u64 = undefined;

        // Theta, then rho and pi: lane x + 5y moves to y + 5((2x + 3y) mod 5).
        inline for (0..5) |y| {
            inline for (0..5) |x| {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = std.math.rotl(u64, a[x + 5 * y] ^ d[x], rotations[x + 5 * y]);
            }
        }

        inline for (0..5) |y| {
            inline for (0..5) |x| {
                a[5 * y + x] = b[5 * y + x] ^ (~b[5 * y + (x + 1) % 5] & b[5 * y + (x + 2) % 5]);
            }
        }

        a[0] ^= constant;
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
            if (self.position == 0 and rest.len >= self.rate) {
                for (0..self.rate / 8) |i| {
                    self.state[i] ^= std.mem.readInt(u64, rest[8 * i ..][0..8], .little);
                }

                permute(&self.state);

                rest = rest[self.rate..];

                continue;
            }

            const take = @min(self.rate - self.position, rest.len);

            for (rest[0..take], self.position..) |byte, index| {
                self.state[index / 8] ^= @as(u64, byte) << @intCast(8 * (index % 8));
            }

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
            const last = self.rate - 1;

            self.state[self.position / 8] ^= @as(u64, self.suffix) << @intCast(8 * (self.position % 8));

            self.state[last / 8] ^= @as(u64, 0x80) << @intCast(8 * (last % 8));

            permute(&self.state);

            self.position = 0;

            self.squeezing = true;
        }

        for (out) |*byte| {
            if (self.position == self.rate) {
                permute(&self.state);

                self.position = 0;
            }

            byte.* = @truncate(self.state[self.position / 8] >> @intCast(8 * (self.position % 8)));

            self.position += 1;
        }
    }
};

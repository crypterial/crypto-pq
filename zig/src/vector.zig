const std = @import("std");

const ct = @import("ct.zig");

// Two 8-lane vectors hold 16 consecutive coefficients. `split` separates the pairs of
// coefficients `step` apart (1, 2 or 4) into the first and the second element of every pair, so
// that a transform layer becomes lane-wise arithmetic; `join` puts them back.
pub fn split(comptime step: usize, a: anytype, b: @TypeOf(a)) [2]@TypeOf(a) {
    const T = @typeInfo(@TypeOf(a)).vector.child;

    return .{ @shuffle(T, a, b, splitMask(step, false)), @shuffle(T, a, b, splitMask(step, true)) };
}

pub fn join(comptime step: usize, x: anytype, y: @TypeOf(x)) [2]@TypeOf(x) {
    const T = @typeInfo(@TypeOf(x)).vector.child;

    return .{ @shuffle(T, x, y, joinMask(step, false)), @shuffle(T, x, y, joinMask(step, true)) };
}

fn splitMask(comptime step: usize, comptime second: bool) @Vector(8, i32) {
    var mask: [8]i32 = undefined;

    for (&mask, 0..) |*lane, i| {
        const source = (i % 4) / step * (2 * step) + (i % 4) % step + (if (second) step else 0);

        lane.* = if (i < 4) source else ~@as(i32, source);
    }

    return mask;
}

fn joinMask(comptime step: usize, comptime high: bool) @Vector(8, i32) {
    var mask: [8]i32 = undefined;

    for (&mask, 0..) |*lane, i| {
        const position = i + (if (high) 8 else 0);

        const pair = position / (2 * step) * step + position % step;

        lane.* = if (position % (2 * step) < step) pair else ~@as(i32, pair);
    }

    return mask;
}

// The most chains a one-time signature has: 265 for LM-OTS with n = 32 and w = 1.
const max_chains = 265;

// Runs hash chains of uneven length in L lanes. Chain i advances from step starts[i] to ends[i]
// on its value, m big-endian words at values[4 * m * i ..]. A lane whose chain ends takes the next
// one, longest first, so that few lanes idle at the end. The caller computes one step for every
// lane on `current()` (its chain and step numbers in `chain` and `step`) and passes the result to
// `advance`; idle lanes carry values that nobody reads.
pub fn ChainLanes(comptime L: usize, comptime m: usize) type {
    return struct {
        const Self = @This();

        chain: [L]u32,
        step: [L]u32,
        words: [m][L]u32,
        active: [L]bool,
        order: [max_chains]u16,
        next: usize,
        running: usize,
        starts: []const u32,
        ends: []const u32,
        values: []u8,

        pub fn init(starts: []const u32, ends: []const u32, values: []u8) Self {
            var self: Self = .{
                .chain = @splat(0),
                .step = @splat(0),
                .words = @splat(@splat(0)),
                .active = @splat(false),
                .order = undefined,
                .next = 0,
                .running = 0,
                .starts = starts,
                .ends = ends,
                .values = values,
            };

            for (self.order[0..starts.len], 0..) |*index, i| index.* = @intCast(i);

            std.sort.pdq(u16, self.order[0..starts.len], &self, longer);

            for (0..L) |l| {
                if (!self.take(l)) break;

                self.active[l] = true;

                self.running += 1;
            }

            return self;
        }

        pub fn current(self: *const Self) [m]@Vector(L, u32) {
            var out: [m]@Vector(L, u32) = undefined;

            for (&out, self.words) |*word, lanes| word.* = lanes;

            return out;
        }

        pub fn advance(self: *Self, value: *const [m]@Vector(L, u32)) void {
            for (&self.words, value) |*lanes, word| lanes.* = word;

            for (0..L) |l| {
                if (!self.active[l]) continue;

                self.step[l] += 1;

                if (self.step[l] < self.ends[self.chain[l]]) continue;

                for (self.words, 0..) |lanes, w| std.mem.writeInt(u32, self.values[4 * (m * self.chain[l] + w) ..][0..4], lanes[l], .big);

                if (!self.take(l)) {
                    self.active[l] = false;

                    self.running -= 1;
                }
            }
        }

        pub fn wipe(self: *Self) void {
            ct.wipe(std.mem.asBytes(&self.words));
        }

        fn longer(self: *const Self, a: u16, b: u16) bool {
            return self.ends[a] - self.starts[a] > self.ends[b] - self.starts[b];
        }

        // Loads the next chain with steps left into lane l.
        fn take(self: *Self, l: usize) bool {
            while (self.next < self.starts.len and self.starts[self.order[self.next]] == self.ends[self.order[self.next]]) self.next += 1;

            if (self.next == self.starts.len) return false;

            const i: usize = self.order[self.next];

            self.chain[l] = @intCast(i);

            self.step[l] = self.starts[i];

            for (&self.words, 0..) |*lanes, w| lanes[l] = std.mem.readInt(u32, self.values[4 * (m * i + w) ..][0..4], .big);

            self.next += 1;

            return true;
        }
    };
}

// Little-endian bit packing in groups that fill whole bytes: `count` values of `bits` bits in
// `size` bytes, with no carry between groups.
pub fn Group(comptime bits: u5) type {
    return struct {
        pub const width: usize = bits;

        pub const count = 8 / std.math.gcd(width, 8);

        pub const size = count * width / 8;

        pub const Word = if (count * width <= 64) u64 else u128;

        pub const mask = (1 << bits) - 1;

        pub fn read(bytes: *const [size]u8) Word {
            var word: Word = 0;

            inline for (0..size) |i| {
                word |= @as(Word, bytes[i]) << (8 * i);
            }

            return word;
        }

        pub fn write(word: Word, out: *[size]u8) void {
            inline for (0..size) |i| {
                out[i] = @truncate(word >> (8 * i));
            }
        }
    };
}

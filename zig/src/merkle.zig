const std = @import("std");

const Allocator = std.mem.Allocator;

const cached_height = 15;

const max_node_size = 32;

const max_low = 10;

// A Merkle tree that keeps its nodes from height `low` upwards, where low = max(0, h - 15).
//
// Building it computes every leaf once. An authentication path takes its upper nodes from the
// cache and rebuilds only the 2^low-leaf subtree under the signed leaf, so memory stays below
// 2^16 nodes for every height while trees of height 15 or less never recompute a leaf.
//
// `Context` provides leaf(index, out), or leaves(first, out) with a `lanes` count, and
// combine(z, j, left, right, out), where z is the height of the children and j the index of the
// parent; `out` may alias `left`. The node memory is allocated once, so that a tree can be rebuilt
// for another context without allocating.
pub fn MerkleTree(comptime Context: type) type {
    return struct {
        const Self = @This();

        context: Context,
        height: u6,
        low: u6,
        n: usize,
        nodes: []u8,
        root: [max_node_size]u8,

        pub fn init(allocator: Allocator, height: u6, n: usize) Allocator.Error!Self {
            const low = height -| cached_height;

            std.debug.assert(low <= max_low and n <= max_node_size);

            return .{
                .context = undefined,
                .height = height,
                .low = low,
                .n = n,
                .nodes = try allocator.alloc(u8, ((@as(usize, 2) << (height - low)) - 1) * n),
                .root = undefined,
            };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            allocator.free(self.nodes);
        }

        pub fn build(self: *Self, context: Context) void {
            const n = self.n;

            self.context = context;

            if (self.low == 0) {
                self.leaves(0, self.nodes[0 .. (@as(usize, 1) << self.height) * n]);
            } else {
                for (0..@as(usize, 1) << (self.height - self.low)) |chunk| {
                    var buffer: [(1 << max_low) * max_node_size]u8 = undefined;

                    self.subtree(chunk, &buffer, null);

                    @memcpy(self.node(self.low, chunk), buffer[0..n]);
                }
            }

            for (self.low..self.height) |z| {
                for (0..@as(usize, 1) << @intCast(self.height - z - 1)) |j| {
                    self.context.combine(@intCast(z), j, self.node(@intCast(z), 2 * j), self.node(@intCast(z), 2 * j + 1), self.node(@intCast(z + 1), j));
                }
            }

            @memcpy(self.root[0..n], self.node(self.height, 0));
        }

        // Leaves first .. first + out.len / n - 1, computed `Context.lanes` at a time by contexts
        // that provide leaves(first, out).
        fn leaves(self: *const Self, first: u64, out: []u8) void {
            const n = self.n;

            const count = out.len / n;

            if (!@hasDecl(Context, "leaves")) {
                for (0..count) |i| self.context.leaf(first + i, out[i * n ..][0..n]);

                return;
            }

            var i: usize = 0;

            while (i < count) : (i += Context.lanes) {
                self.context.leaves(first + i, out[i * n ..][0 .. @min(Context.lanes, count - i) * n]);
            }
        }

        // Level z holds 2^(height - z) nodes; the levels are stored from `low` upwards.
        fn node(self: *const Self, z: u6, index: usize) []u8 {
            var offset: usize = 0;

            for (self.low..z) |level| {
                offset += @as(usize, 1) << @intCast(self.height - level);
            }

            return self.nodes[(offset + index) * self.n ..][0..self.n];
        }

        // Reduces the 2^low leaves under `chunk` to their root in buffer[0..n], copying the
        // sibling of `index` at every height into `path` when it is given.
        fn subtree(self: *const Self, chunk: usize, buffer: []u8, path: ?struct { index: u64, out: []u8 }) void {
            const n = self.n;

            const base = chunk << self.low;

            self.leaves(base, buffer[0 .. (@as(usize, 1) << self.low) * n]);

            for (0..self.low) |z| {
                const count = @as(usize, 1) << @intCast(self.low - z);

                if (path) |p| {
                    const sibling: usize = @intCast(((p.index >> @intCast(z)) ^ 1) & (count - 1));

                    @memcpy(p.out[z * n ..][0..n], buffer[sibling * n ..][0..n]);
                }

                const offset = base >> @intCast(z + 1);

                for (0..count / 2) |j| {
                    self.context.combine(@intCast(z), offset + j, buffer[2 * j * n ..][0..n], buffer[(2 * j + 1) * n ..][0..n], buffer[j * n ..][0..n]);
                }
            }
        }

        pub fn authPath(self: *const Self, index: u64, out: []u8) void {
            const n = self.n;

            if (self.low > 0) {
                var buffer: [(1 << max_low) * max_node_size]u8 = undefined;

                self.subtree(@intCast(index >> self.low), &buffer, .{ .index = index, .out = out });
            }

            for (self.low..self.height) |z| {
                @memcpy(out[z * n ..][0..n], self.node(@intCast(z), @intCast((index >> @intCast(z)) ^ 1)));
            }
        }
    };
}

// Trees above height 15 rebuild the bottom of every authentication path; compare them with a
// tree kept whole.
test "merkle cache above the cached height" {
    const testing = std.testing;

    const hash = @import("hash.zig");

    const Context = struct {
        pub fn leaf(_: *const @This(), index: u64, out: []u8) void {
            var bytes: [8]u8 = undefined;

            std.mem.writeInt(u64, &bytes, index, .big);

            hash.sha_256.digest(&bytes, out[0..32]);
        }

        pub fn combine(_: *const @This(), z: u32, j: u64, left: []const u8, right: []const u8, out: []u8) void {
            var hasher = hash.sha_256.create();

            var position: [12]u8 = undefined;

            std.mem.writeInt(u32, position[0..4], z, .big);

            std.mem.writeInt(u64, position[4..12], j, .big);

            hasher.update(&position);

            hasher.update(left);

            hasher.update(right);

            hasher.digest(out[0..32]);
        }
    };

    const height = 17;

    var tree = try MerkleTree(Context).init(testing.allocator, height, 32);

    defer tree.deinit(testing.allocator);

    tree.build(.{});

    const context: Context = .{};

    var levels: [height + 1][][32]u8 = undefined;

    for (&levels, 0..) |*level, z| level.* = try testing.allocator.alloc([32]u8, @as(usize, 1) << @intCast(height - z));

    defer for (levels) |level| testing.allocator.free(level);

    for (levels[0], 0..) |*node, i| context.leaf(i, node);

    for (1..height + 1) |z| {
        for (levels[z], 0..) |*node, j| context.combine(@intCast(z - 1), j, &levels[z - 1][2 * j], &levels[z - 1][2 * j + 1], node);
    }

    try testing.expectEqualSlices(u8, &levels[height][0], tree.root[0..32]);

    for ([_]u64{ 0, 1, 2, 3, 77777, (1 << height) - 1 }) |index| {
        var path: [height * 32]u8 = undefined;

        tree.authPath(index, &path);

        for (0..height) |z| {
            try testing.expectEqualSlices(u8, &levels[z][@intCast((index >> @intCast(z)) ^ 1)], path[z * 32 ..][0..32]);
        }
    }
}

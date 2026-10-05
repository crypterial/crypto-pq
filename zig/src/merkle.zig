const std = @import("std");

const Error = @import("errors.zig").Error;

const Allocator = std.mem.Allocator;

pub const cached_height = 15;

const max_node_size = 32;

// The kept bottom subtree has 2^low leaves and 2^(low + 1) - 1 nodes: 64 KiB at low = 10, which
// today's largest tree (height 25) needs. A larger low is refused rather than allocated.
const max_low = 10;

// A tree as a tree cache lists it: its level or layer, its number there, the lowest height it
// keeps, its height, n, and its nodes from height `low` up, level by level, left to right.
pub const CachedTree = struct {
    level: u8,
    tree: u64,
    low: u8,
    height: u8,
    n: u8,
    nodes: []const u8,
};

// A Merkle tree that keeps its nodes from height `low` upwards, where low = max(0, h - 15).
//
// Building it computes every leaf once. An authentication path takes its upper nodes from the
// cache and its lower ones from the 2^low-leaf subtree under the signed leaf. That subtree is
// kept, every level of it, so the consecutive signatures under one subtree rebuild it once:
// memory stays below 2^16 nodes plus the subtree for every height, and trees of height 15 or less
// never recompute a leaf. The nodes of a tree cache replace the build: every parent is
// recomputed from its children, so only the nodes at height `low` are taken as given.
//
// `Context` provides leaf(index, out), or leaves(first, out) with a `lanes` count, and
// combine(z, j, left, right, out), where z is the height of the children and j the index of the
// parent. The node memory is allocated once, so that a tree can be rebuilt for another context
// without allocating. `computed` counts the leaves computed so far, which tests read to see that
// a restored tree computes none.
pub fn MerkleTree(comptime Context: type) type {
    return struct {
        const Self = @This();

        context: Context,
        height: u6,
        low: u6,
        n: usize,
        nodes: []u8,
        subtree: []u8,
        subtree_index: ?u64,
        root: [max_node_size]u8,
        computed: u64,

        pub fn init(allocator: Allocator, height: u6, n: usize) (Error || Allocator.Error)!Self {
            const low = height -| cached_height;

            // Checked in every build mode: the root holds at most max_node_size bytes, and the
            // subtree size grows as 2^low.
            if (low > max_low or n == 0 or n > max_node_size) return error.InvalidOption;

            const nodes = try allocator.alloc(u8, ((@as(usize, 2) << @intCast(height - low)) - 1) * n);

            errdefer allocator.free(nodes);

            const subtree = try allocator.alloc(u8, if (low == 0) 0 else ((@as(usize, 2) << @intCast(low)) - 1) * n);

            return .{ .context = undefined, .height = height, .low = low, .n = n, .nodes = nodes, .subtree = subtree, .subtree_index = null, .root = undefined, .computed = 0 };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            allocator.free(self.nodes);

            allocator.free(self.subtree);
        }

        pub fn build(self: *Self, context: Context) void {
            self.context = context;

            self.buildInPlace();
        }

        // The build with the context already in `self.context`: a context that holds a secret is
        // written there by its owner and never passed by value.
        pub fn buildInPlace(self: *Self) void {
            const n = self.n;

            self.subtree_index = null;

            if (self.low == 0) {
                self.leaves(0, self.nodes[0 .. (@as(usize, 1) << @intCast(self.height)) * n]);

                self.computed += @as(u64, 1) << self.height;
            } else {
                for (0..@as(usize, 1) << @intCast(self.height - self.low)) |chunk| {
                    self.rebuild(chunk);

                    @memcpy(self.node(self.low, chunk), self.subtreeNode(self.low, 0));
                }
            }

            for (self.low..self.height) |z| {
                for (0..@as(usize, 1) << @intCast(self.height - z - 1)) |j| {
                    self.context.combine(@intCast(z), j, self.node(@intCast(z), 2 * j), self.node(@intCast(z), 2 * j + 1), self.node(@intCast(z + 1), j));
                }
            }

            @memcpy(self.root[0..n], self.node(self.height, 0));
        }

        // Takes `nodes`, laid out as `self.nodes`, instead of building them, if every parent equals
        // what its children give; otherwise the tree must be built or restored again before use.
        pub fn restore(self: *Self, context: Context, nodes: []const u8) Error!void {
            if (nodes.len != self.nodes.len) return error.InvalidEncoding;

            self.context = context;

            return self.restoreInPlace(nodes);
        }

        pub fn restoreInPlace(self: *Self, nodes: []const u8) Error!void {
            const n = self.n;

            if (nodes.len != self.nodes.len) return error.InvalidEncoding;

            self.subtree_index = null;

            @memcpy(self.nodes, nodes);

            var parent: [max_node_size]u8 = undefined;

            for (self.low..self.height) |z| {
                for (0..@as(usize, 1) << @intCast(self.height - z - 1)) |j| {
                    self.context.combine(@intCast(z), j, self.node(@intCast(z), 2 * j), self.node(@intCast(z), 2 * j + 1), parent[0..n]);

                    if (!std.mem.eql(u8, parent[0..n], self.node(@intCast(z + 1), j))) return error.InvalidEncoding;
                }
            }

            @memcpy(self.root[0..n], self.node(self.height, 0));
        }

        // The tree as a tree cache lists it.
        pub fn cached(self: *const Self, level: u8, tree: u64) CachedTree {
            return .{ .level = level, .tree = tree, .low = self.low, .height = self.height, .n = @intCast(self.n), .nodes = self.nodes };
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

        // Level z of the kept subtree holds 2^(low - z) nodes, stored after the levels below it.
        fn subtreeNode(self: *const Self, z: usize, index: usize) []u8 {
            const offset = (@as(usize, 2) << @intCast(self.low)) - (@as(usize, 2) << @intCast(self.low - z));

            return self.subtree[(offset + index) * self.n ..][0..self.n];
        }

        // Every node of the subtree with 2^low leaves under `chunk`, its root last.
        fn rebuild(self: *Self, chunk: u64) void {
            const base = chunk << self.low;

            self.leaves(base, self.subtree[0 .. (@as(usize, 1) << @intCast(self.low)) * self.n]);

            self.computed += @as(u64, 1) << self.low;

            for (0..self.low) |z| {
                const offset = base >> @intCast(z + 1);

                for (0..@as(usize, 1) << @intCast(self.low - z - 1)) |j| {
                    self.context.combine(@intCast(z), offset + j, self.subtreeNode(z, 2 * j), self.subtreeNode(z, 2 * j + 1), self.subtreeNode(z + 1, j));
                }
            }

            self.subtree_index = chunk;
        }

        pub fn authPath(self: *Self, index: u64, out: []u8) void {
            const n = self.n;

            if (self.low > 0) {
                const chunk = index >> self.low;

                if (self.subtree_index != chunk) self.rebuild(chunk);

                for (0..self.low) |z| {
                    const sibling: usize = @intCast(((index >> @intCast(z)) ^ 1) & ((@as(u64, 1) << @intCast(self.low - z)) - 1));

                    @memcpy(out[z * n ..][0..n], self.subtreeNode(z, sibling));
                }
            }

            for (self.low..self.height) |z| {
                @memcpy(out[z * n ..][0..n], self.node(@intCast(z), @intCast((index >> @intCast(z)) ^ 1)));
            }
        }
    };
}

const TestContext = struct {
    calls: *usize,

    const hash = @import("hash.zig");

    pub fn leaf(self: *const TestContext, index: u64, out: []u8) void {
        self.calls.* += 1;

        var bytes: [8]u8 = undefined;

        std.mem.writeInt(u64, &bytes, index, .big);

        hash.sha_256.digest(&bytes, out[0..32]);
    }

    pub fn combine(_: *const TestContext, z: u32, j: u64, left: []const u8, right: []const u8, out: []u8) void {
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

// Trees above height 15 take the bottom of every authentication path from the subtree under the
// signed leaf, rebuilt only when the leaf moves to another subtree; compare them with a tree kept
// whole.
test "merkle cache above the cached height" {
    const testing = std.testing;

    const height = 17;

    var calls: usize = 0;

    const context: TestContext = .{ .calls = &calls };

    var tree = try MerkleTree(TestContext).init(testing.allocator, height, 32);

    defer tree.deinit(testing.allocator);

    tree.build(context);

    try testing.expectEqual(@as(usize, 1) << height, calls);

    var levels: [height + 1][][32]u8 = undefined;

    for (&levels, 0..) |*level, z| level.* = try testing.allocator.alloc([32]u8, @as(usize, 1) << @intCast(height - z));

    defer for (levels) |level| testing.allocator.free(level);

    for (levels[0], 0..) |*node, i| context.leaf(i, node);

    for (1..height + 1) |z| {
        for (levels[z], 0..) |*node, j| context.combine(@intCast(z - 1), j, &levels[z - 1][2 * j], &levels[z - 1][2 * j + 1], node);
    }

    try testing.expectEqualSlices(u8, &levels[height][0], tree.root[0..32]);

    // Index 0 starts in another subtree than the one left by the build, the next three share it,
    // and every later one moves to a new subtree.
    const cases = [_]struct { index: u64, rebuilt: bool }{
        .{ .index = 0, .rebuilt = true },
        .{ .index = 1, .rebuilt = false },
        .{ .index = 2, .rebuilt = false },
        .{ .index = 3, .rebuilt = false },
        .{ .index = 4, .rebuilt = true },
        .{ .index = 77777, .rebuilt = true },
        .{ .index = (1 << height) - 1, .rebuilt = true },
        .{ .index = (1 << height) - 2, .rebuilt = false },
    };

    for (cases) |case| {
        var path: [height * 32]u8 = undefined;

        calls = 0;

        tree.authPath(case.index, &path);

        try testing.expectEqual(@as(usize, if (case.rebuilt) 1 << (height - cached_height) else 0), calls);

        for (0..height) |z| {
            try testing.expectEqualSlices(u8, &levels[z][@intCast((case.index >> @intCast(z)) ^ 1)], path[z * 32 ..][0..32]);
        }
    }
}

// The nodes of a built tree restore it without computing a leaf, with the same root and paths, and
// a change of any one node is refused: every node but the root is a child of a recomputed parent.
test "merkle restore" {
    const testing = std.testing;

    var calls: usize = 0;

    const context: TestContext = .{ .calls = &calls };

    for ([_]u6{ 5, 17 }) |height| {
        var built = try MerkleTree(TestContext).init(testing.allocator, height, 32);

        defer built.deinit(testing.allocator);

        built.build(context);

        var restored = try MerkleTree(TestContext).init(testing.allocator, height, 32);

        defer restored.deinit(testing.allocator);

        calls = 0;

        try restored.restore(context, built.nodes);

        try testing.expectEqual(0, calls);

        try testing.expectEqual(0, restored.computed);

        try testing.expectEqualSlices(u8, built.root[0..32], restored.root[0..32]);

        const size = @as(usize, height) * 32;

        for ([_]u64{ 0, 5, (@as(u64, 1) << height) - 1 }) |index| {
            var expected: [17 * 32]u8 = undefined;

            var path: [17 * 32]u8 = undefined;

            built.authPath(index, expected[0..size]);

            restored.authPath(index, path[0..size]);

            try testing.expectEqualSlices(u8, expected[0..size], path[0..size]);
        }

        const nodes = try testing.allocator.dupe(u8, built.nodes);

        defer testing.allocator.free(nodes);

        const count = nodes.len / 32;

        const positions = [_]usize{ 0, 1, count / 2, count - 2, count - 1 };

        for (0..if (height == 5) count else positions.len) |i| {
            const position = if (height == 5) i else positions[i];

            nodes[32 * position + i % 32] ^= 1;

            try testing.expectError(error.InvalidEncoding, restored.restore(context, nodes));

            nodes[32 * position + i % 32] ^= 1;
        }

        try testing.expectError(error.InvalidEncoding, restored.restore(context, nodes[32..]));

        try restored.restore(context, nodes);

        try testing.expectEqualSlices(u8, built.root[0..32], restored.root[0..32]);
    }
}

test "merkle bounds are checked" {
    const testing = std.testing;

    try testing.expectError(error.InvalidOption, MerkleTree(TestContext).init(testing.allocator, cached_height + max_low + 1, 32));

    try testing.expectError(error.InvalidOption, MerkleTree(TestContext).init(testing.allocator, 5, max_node_size + 1));

    try testing.expectError(error.InvalidOption, MerkleTree(TestContext).init(testing.allocator, 5, 0));
}

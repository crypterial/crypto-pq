const std = @import("std");

const cpu = @import("cpu.zig");
const ct = @import("ct.zig");
const encoding = @import("encoding.zig");
const Error = @import("errors.zig").Error;
const hash = @import("hash.zig");
const keys = @import("keys.zig");
const lms = @import("lms.zig");
const merkle = @import("merkle.zig");
const primitives = @import("primitives.zig");
const rng = @import("rng.zig");
const xmss_scheme = @import("xmss.zig");

const Allocator = std.mem.Allocator;

const KeyFormat = keys.KeyFormat;

const version = 1;

pub const max_public_key_size = 68;

const tree_cache_version = 1;

const tree_cache_label = "crypto-pq tree cache v1";

pub const tag_size = 32;

// The most trees a key holds: one per HSS level or XMSS^MT layer.
const max_trees = 12;

pub const HssLevel = struct {
    lms: []const u8,
    ots: []const u8,
};

pub const StatefulParameters = union(enum) {
    levels: []const HssLevel,
    name: []const u8,
};

// reserve: how many indices one write to the store claims, a positive integer. The key then signs
// that many times before it writes again; a key that stops earlier loses the rest, because
// loading starts after them. It is not part of the stored state.
//
// tree_cache: bytes from exportTreeCache, for loadPrivateKey to take the trees they hold instead
// of building them. The key loads only if they pass every check; a key being created takes none.
pub const StatefulOptions = struct {
    reserve: u64 = 1,
    tree_cache: ?[]const u8 = null,
};

pub fn checkOptions(options: StatefulOptions) Error!void {
    if (options.reserve == 0) return error.InvalidOption;
}

pub const StateStore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        read: *const fn (ptr: *anyopaque, allocator: Allocator) anyerror!?[]u8,
        update: *const fn (ptr: *anyopaque, previous: ?[]const u8, next: []const u8) anyerror!bool,
    };

    // The returned state must be allocated with `allocator`; the caller takes ownership.
    pub fn read(self: StateStore, allocator: Allocator) anyerror!?[]u8 {
        return self.vtable.read(self.ptr, allocator);
    }

    // Compare-and-swap: replaces the stored state with `next` only if it still equals `previous`
    // (null for an empty store) and returns whether it did. `next` is not retained.
    pub fn update(self: StateStore, previous: ?[]const u8, next: []const u8) anyerror!bool {
        return self.vtable.update(self.ptr, previous, next);
    }
};

pub const StatefulSignatureAlgorithm = struct {
    name: []const u8,
    kind: Kind,

    pub const Kind = enum(u8) { hss_lms = 1, xmss = 2, xmss_mt = 3 };

    pub fn generateKeyPair(self: StatefulSignatureAlgorithm, allocator: Allocator, parameters: StatefulParameters, store: StateStore, options: StatefulOptions) (Error || Allocator.Error)!StatefulKeyPair {
        try checkOptions(options);

        const setup = try Setup.parse(self.kind, parameters);

        var seed: [16 + 3 * 32]u8 = undefined;

        defer ct.wipe(&seed);

        const size = setup.seedSize();

        try rng.fill(seed[0..size]);

        return create(self, allocator, setup, seed[0..size], 0, store, options);
    }

    // The stored index is the first one not handed out, so signing resumes there even when the
    // last key reserved more than it used. A tree cache from exportTreeCache replaces the build of
    // the trees it holds; the state is checked first, and the key loads only if the cache passes.
    pub fn loadPrivateKey(self: StatefulSignatureAlgorithm, allocator: Allocator, store: StateStore, options: StatefulOptions) (Error || Allocator.Error)!StatefulPrivateKey {
        try checkOptions(options);

        // A copy, so that the trees take the bytes that the tag covers even if the caller's buffer
        // changes meanwhile, as a mapped file may.
        const cache = if (options.tree_cache) |data| try allocator.dupe(u8, data) else null;

        defer if (cache) |data| allocator.free(data);

        const stored = (store.read(allocator) catch return error.StatePersistFailed) orelse return error.InvalidPrivateKey;

        defer {
            ct.wipe(stored);

            allocator.free(stored);
        }

        var opened = try open(self.kind, allocator, stored, cache);

        defer ct.wipe(&opened.state.bytes);

        return .{ .algorithm = self, .signer = opened.signer, .store = store, .state = opened.state, .index = .init(opened.index), .reserved = opened.index, .reserve = options.reserve };
    }

    pub fn importPublicKey(self: StatefulSignatureAlgorithm, data: []const u8, format: KeyFormat) Error!StatefulPublicKey {
        var buffer: keys.PemBuffer = undefined;

        const key = try keys.importPublic(format, data, objectIdentifier(self.kind), &buffer);

        if (!checkPublicKey(self.kind, key)) return error.InvalidPublicKey;

        var public_key: StatefulPublicKey = .{ .algorithm = self, .bytes = @splat(0), .size = key.len };

        @memcpy(public_key.bytes[0..key.len], key);

        return public_key;
    }
};

pub const StatefulPublicKey = struct {
    algorithm: StatefulSignatureAlgorithm,
    bytes: [max_public_key_size]u8,
    size: usize,

    pub fn verify(self: *const StatefulPublicKey, signature: []const u8, message: []const u8) bool {
        const key = self.raw();

        const kind = self.algorithm.kind;

        if (kind == .hss_lms) return lms.hssVerify(key, message, signature);

        if (!checkPublicKey(kind, key)) return false;

        return xmss_scheme.verify(xmss_scheme.byOid(xmssSets(kind), std.mem.readInt(u32, key[0..4], .big)).?, key, message, signature);
    }

    pub fn exportKey(self: *const StatefulPublicKey, allocator: Allocator, format: KeyFormat) (Error || Allocator.Error)![]u8 {
        return keys.exportPublic(allocator, format, objectIdentifier(self.algorithm.kind), self.raw());
    }

    pub fn eql(self: *const StatefulPublicKey, other: *const StatefulPublicKey) bool {
        return self.algorithm.kind == other.algorithm.kind and std.mem.eql(u8, self.raw(), other.raw());
    }

    fn raw(self: *const StatefulPublicKey) []const u8 {
        return self.bytes[0..self.size];
    }
};

// A u64 that one thread at a time writes and any thread reads without a lock, also on targets
// without 64-bit atomics: the halves are written between two increments of a sequence number, and
// a reader retries while that number is odd or changes under it.
const Counter = struct {
    sequence: std.atomic.Value(u32) = .init(0),
    high: std.atomic.Value(u32),
    low: std.atomic.Value(u32),

    fn init(value: u64) Counter {
        return .{ .high = .init(@truncate(value >> 32)), .low = .init(@truncate(value)) };
    }

    fn load(self: *const Counter) u64 {
        while (true) {
            const before = self.sequence.load(.acquire);

            const value = @as(u64, self.high.load(.acquire)) << 32 | self.low.load(.acquire);

            if (before % 2 == 0 and self.sequence.load(.monotonic) == before) return value;

            std.atomic.spinLoopHint();
        }
    }

    fn store(self: *Counter, value: u64) void {
        _ = self.sequence.fetchAdd(1, .acq_rel);

        self.high.store(@truncate(value >> 32), .release);

        self.low.store(@truncate(value), .release);

        _ = self.sequence.fetchAdd(1, .release);
    }
};

// `index` is the next index to sign with and `reserved` the one the stored state holds, never below
// it: the indices in between were claimed by an earlier write. `signing` is set while a sign call
// runs, and only that call writes `index`, `reserved`, `state` and the signer; remainingSignatures
// may read `index` at any time, from the store's update included.
pub const StatefulPrivateKey = struct {
    algorithm: StatefulSignatureAlgorithm,
    signer: Signer,
    store: StateStore,
    state: State,
    index: Counter,
    reserved: u64,
    reserve: u64,
    signing: std.atomic.Value(bool) = .init(false),

    pub fn publicKey(self: *const StatefulPrivateKey) StatefulPublicKey {
        var public_key: StatefulPublicKey = .{ .algorithm = self.algorithm, .bytes = @splat(0), .size = 0 };

        public_key.size = self.signer.publicKey(&public_key.bytes).len;

        return public_key;
    }

    pub fn remainingSignatures(self: *const StatefulPrivateKey) u64 {
        return self.signer.capacity() - self.index.load();
    }

    // The store holds an index above every one used before the signature exists, so a crash or a
    // failed write can waste indices but never use one twice. When the claimed indices run out,
    // one write claims the next `reserve` of them. A call made while another is signing with the
    // same key, from the store's update included, fails with StateConflict at once: locks in Zig
    // 0.16 need an Io, which this API omits, and waiting there could never end.
    pub fn sign(self: *StatefulPrivateKey, allocator: Allocator, message: []const u8) (Error || Allocator.Error)![]u8 {
        if (self.signing.swap(true, .acquire)) return error.StateConflict;

        defer self.signing.store(false, .release);

        const index = self.index.load();

        const capacity = self.signer.capacity();

        if (index >= capacity) return error.KeyExhausted;

        const out = try allocator.alloc(u8, self.signer.signatureSize());

        errdefer allocator.free(out);

        if (index == self.reserved) {
            const claimed = @min(index +| self.reserve, capacity);

            var next = self.state;

            defer ct.wipe(&next.bytes);

            reseal(self.algorithm.kind, next.slice(), claimed);

            const updated = self.store.update(self.state.slice(), next.slice()) catch return error.StatePersistFailed;

            if (!updated) return error.StateConflict;

            // The superseded state is overwritten in place, and the copy is wiped on return.
            self.state = next;

            self.reserved = claimed;
        }

        self.index.store(index + 1);

        self.signer.sign(index, message, out);

        return out;
    }

    // The trees that the key holds, for loadPrivateKey's tree_cache to skip their build. The bytes
    // hold nothing secret, and the caller owns them. A call made while the key signs, from another
    // thread or from the store's update, fails with StateConflict at once, as the trees are
    // changing, and so does a sign while the body is copied; the tag is computed after that.
    pub fn exportTreeCache(self: *StatefulPrivateKey, allocator: Allocator) (Error || Allocator.Error)![]u8 {
        var key: [32]u8 = undefined;

        defer ct.wipe(&key);

        const cache = try self.treeCacheBody(allocator, &key);

        const body = cache[0 .. cache.len - tag_size];

        treeCacheTag(&key, body, cache[body.len..][0..tag_size]);

        ct.declassify(cache);

        return cache;
    }

    // The body of the key's tree cache with room for the tag, and the tag key.
    fn treeCacheBody(self: *StatefulPrivateKey, allocator: Allocator, key: *[32]u8) (Error || Allocator.Error)![]u8 {
        if (self.signing.swap(true, .acquire)) return error.StateConflict;

        defer self.signing.store(false, .release);

        return treeCacheBodyOf(allocator, self.algorithm.kind, self.state.bytes[0..self.state.size], self.signer, key);
    }

    pub fn deinit(self: *StatefulPrivateKey, allocator: Allocator) void {
        std.debug.assert(!self.signing.load(.acquire));

        self.signer.destroy(allocator);

        ct.wipe(&self.state.bytes);

        self.* = undefined;
    }
};

// The size of the tree cache of a signer and its valid state, the tag included.
pub fn treeCacheSize(kind: StatefulSignatureAlgorithm.Kind, state: []const u8, signer: Signer) usize {
    var public_key: [max_public_key_size]u8 = undefined;

    var held: [max_trees]merkle.CachedTree = undefined;

    var size = 2 + parameterSection(kind, state).len + 4 + signer.publicKey(&public_key).len + 1 + tag_size;

    for (signer.cachedTrees(&held)) |tree| size += 16 + tree.nodes.len;

    return size;
}

// The body of the tree cache of a signer and its valid state, with room for the tag, and the tag
// key.
pub fn treeCacheBodyOf(allocator: Allocator, kind: StatefulSignatureAlgorithm.Kind, state: []const u8, signer: Signer, key: *[32]u8) (Error || Allocator.Error)![]u8 {
    const parameters = parameterSection(kind, state);

    var public_key: [max_public_key_size]u8 = undefined;

    const raw = signer.publicKey(&public_key);

    var held: [max_trees]merkle.CachedTree = undefined;

    const trees = signer.cachedTrees(&held);

    const cache = try allocator.alloc(u8, treeCacheSize(kind, state, signer));

    var writer: encoding.Writer = .{ .buffer = cache };

    writer.bytes(&.{ tree_cache_version, @intFromEnum(kind) });

    writer.bytes(parameters);

    writer.bytes(&bigEndian(u32, @intCast(raw.len)));

    writer.bytes(raw);

    writer.bytes(&.{@intCast(trees.len)});

    for (trees) |tree| {
        writer.bytes(&.{tree.level});

        writer.bytes(&bigEndian(u64, tree.tree));

        writer.bytes(&.{ tree.low, tree.height, tree.n });

        writer.bytes(&bigEndian(u32, @intCast(tree.nodes.len / tree.n)));

        writer.bytes(tree.nodes);
    }

    treeCacheKey(seedSection(kind, state), key);

    return cache;
}

pub const StatefulKeyPair = struct {
    public_key: StatefulPublicKey,
    private_key: StatefulPrivateKey,
};

fn objectIdentifier(kind: StatefulSignatureAlgorithm.Kind) []const u8 {
    return switch (kind) {
        .hss_lms => encoding.objectIdentifier(&.{ 1, 2, 840, 113549, 1, 9, 16, 3, 17 }),
        .xmss => encoding.objectIdentifier(&.{ 1, 3, 6, 1, 5, 5, 7, 6, 34 }),
        .xmss_mt => encoding.objectIdentifier(&.{ 1, 3, 6, 1, 5, 5, 7, 6, 35 }),
    };
}

fn xmssSets(kind: StatefulSignatureAlgorithm.Kind) []const xmss_scheme.Parameters {
    return if (kind == .xmss_mt) &xmss_scheme.xmss_mt_sets else &xmss_scheme.xmss_sets;
}

pub fn checkPublicKey(kind: StatefulSignatureAlgorithm.Kind, key: []const u8) bool {
    if (kind == .hss_lms) return lms.checkPublicKey(key);

    if (key.len < 4) return false;

    const p = xmss_scheme.byOid(xmssSets(kind), std.mem.readInt(u32, key[0..4], .big)) orelse return false;

    return key.len == p.publicKeySize();
}

// The validated parameters of a key: the HSS levels or one XMSS / XMSS^MT parameter set.
pub const Setup = union(enum) {
    hss: struct { levels: [8]lms.Level, count: usize },
    xmss: xmss_scheme.Parameters,

    pub fn parse(kind: StatefulSignatureAlgorithm.Kind, parameters: StatefulParameters) Error!Setup {
        if (kind != .hss_lms) {
            const name = switch (parameters) {
                .name => |name| name,
                .levels => return error.InvalidOption,
            };

            return .{ .xmss = xmss_scheme.byName(xmssSets(kind), name) orelse return error.InvalidOption };
        }

        const levels = switch (parameters) {
            .levels => |levels| levels,
            .name => return error.InvalidOption,
        };

        var setup: Setup = .{ .hss = .{ .levels = undefined, .count = levels.len } };

        if (levels.len < 1 or levels.len > 8) return error.InvalidOption;

        for (levels, setup.hss.levels[0..levels.len]) |level, *out| {
            out.* = .{ .lms = lms.lmsByName(level.lms) orelse return error.InvalidOption, .ots = lms.otsByName(level.ots) orelse return error.InvalidOption };
        }

        if (!lms.validLevels(setup.hss.levels[0..levels.len])) return error.InvalidOption;

        return setup;
    }

    fn hssLevels(self: *const Setup) []const lms.Level {
        return self.hss.levels[0..self.hss.count];
    }

    // HSS: I || SEED of the top tree; XMSS: SK_SEED || SK_PRF || PUB_SEED.
    pub fn seedSize(self: Setup) usize {
        return switch (self) {
            .hss => |hss| 16 + hss.levels[0].lms.m,
            .xmss => |p| 3 * p.n,
        };
    }

    pub fn capacity(self: Setup) u64 {
        var height: u6 = 0;

        switch (self) {
            .hss => |hss| for (hss.levels[0..hss.count]) |level| {
                height += level.lms.h;
            },
            .xmss => |p| height = p.h,
        }

        return @as(u64, 1) << height;
    }
};

pub const Signer = union(enum) {
    hss: *lms.Hss,
    xmss: *xmss_scheme.Xmss,

    // `cached` holds the trees of an opened tree cache that the next index signs with.
    pub fn build(allocator: Allocator, setup: Setup, seed: []const u8, cached: []const merkle.CachedTree) (Error || Allocator.Error)!Signer {
        const dit = cpu.Dit.enter();

        defer dit.leave();

        switch (setup) {
            .hss => {
                const hss = try allocator.create(lms.Hss);

                errdefer allocator.destroy(hss);

                hss.* = try .init(allocator, setup.hssLevels(), seed[0..16], seed[16..], cached);

                return .{ .hss = hss };
            },
            .xmss => |p| return .{ .xmss = try .create(allocator, p, seed, cached) },
        }
    }

    pub fn destroy(self: Signer, allocator: Allocator) void {
        switch (self) {
            .hss => |hss| {
                hss.deinit(allocator);

                allocator.destroy(hss);
            },
            .xmss => |signer| signer.destroy(allocator),
        }
    }

    pub fn capacity(self: Signer) u64 {
        return switch (self) {
            inline else => |signer| signer.capacity(),
        };
    }

    pub fn signatureSize(self: Signer) usize {
        return switch (self) {
            .hss => |hss| hss.signatureSize(),
            .xmss => |signer| signer.hashes.p.signatureSize(),
        };
    }

    pub fn publicKey(self: Signer, out: *[max_public_key_size]u8) []u8 {
        return switch (self) {
            .hss => |hss| hss.publicKey(out[0..60]),
            .xmss => |signer| signer.publicKey(out),
        };
    }

    fn cachedTrees(self: Signer, out: *[max_trees]merkle.CachedTree) []merkle.CachedTree {
        return switch (self) {
            inline else => |signer| signer.cachedTrees(out),
        };
    }

    pub fn sign(self: Signer, index: u64, message: []const u8, out: []u8) void {
        const dit = cpu.Dit.enter();

        defer dit.leave();

        switch (self) {
            inline else => |signer| signer.sign(index, message, out),
        }
    }
};

// The largest state belongs to an HSS key with eight levels of 32-byte hashes.
const max_state_size = 3 + 8 * 8 + 16 + 32 + 8 + 16;

pub const State = struct {
    bytes: [max_state_size]u8,
    size: usize,

    pub fn slice(self: *State) []u8 {
        return self.bytes[0..self.size];
    }
};

// State blob: version, kind, the parameters, the secret seeds and the next index, closed by the
// first 16 bytes of its SHA-256 so that a damaged state is refused rather than reused.
//   HSS:  01 01 L {u32 lms, u32 ots} x L  I(16) SEED(n)  index(u64)  checksum(16)
//   XMSS: 01 02|03 oid(u32) index(u64) SK_SEED SK_PRF PUB_SEED  checksum(16)
fn seal(state: []u8) void {
    const body = state[0 .. state.len - 16];

    var digest: [32]u8 = undefined;

    primitives.digest(hash.sha_256, &.{body}, &digest);

    @memcpy(state[state.len - 16 ..], digest[0..16]);
}

fn indexOffset(kind: StatefulSignatureAlgorithm.Kind, state: []const u8) usize {
    return if (kind == .hss_lms) state.len - 24 else 6;
}

pub fn reseal(kind: StatefulSignatureAlgorithm.Kind, state: []u8, index: u64) void {
    std.mem.writeInt(u64, state[indexOffset(kind, state)..][0..8], index, .big);

    seal(state);
}

pub fn encode(kind: StatefulSignatureAlgorithm.Kind, setup: Setup, seed: []const u8, index: u64, blob: *State) void {
    const header = switch (setup) {
        .hss => |hss| 3 + 8 * hss.count,
        .xmss => 6,
    };

    blob.* = .{ .bytes = @splat(0), .size = header + seed.len + 8 + 16 };

    const state = blob.slice();

    state[0] = version;

    state[1] = @intFromEnum(kind);

    switch (setup) {
        .hss => |hss| {
            state[2] = @intCast(hss.count);

            for (hss.levels[0..hss.count], 0..) |level, i| {
                std.mem.writeInt(u32, state[3 + 8 * i ..][0..4], level.lms.code, .big);

                std.mem.writeInt(u32, state[7 + 8 * i ..][0..4], level.ots.code, .big);
            }

            @memcpy(state[header..][0..seed.len], seed);
        },
        .xmss => |p| {
            std.mem.writeInt(u32, state[2..6], p.oid, .big);

            @memcpy(state[14..][0..seed.len], seed);
        },
    }

    reseal(kind, state, index);
}

pub const Decoded = struct {
    setup: Setup,
    seed: []const u8,
    index: u64,
};

pub fn decode(kind: StatefulSignatureAlgorithm.Kind, state: []const u8) Error!Decoded {
    if (state.len < 18) return error.InvalidPrivateKey;

    const body = state[0 .. state.len - 16];

    var digest: [32]u8 = undefined;

    primitives.digest(hash.sha_256, &.{body}, &digest);

    // Whether a stored state is intact is public: loading fails on it.
    if (!ct.declassifyValue(bool, ct.equal(digest[0..16], state[state.len - 16 ..])) or body[0] != version) return error.InvalidPrivateKey;

    if (body[1] != @intFromEnum(kind)) return error.AlgorithmMismatch;

    const rest = body[2..];

    if (kind == .hss_lms) {
        if (rest.len < 1 or rest.len < 1 + 8 * @as(usize, rest[0])) return error.InvalidPrivateKey;

        const count = rest[0];

        var setup: Setup = .{ .hss = .{ .levels = undefined, .count = count } };

        if (count < 1 or count > 8) return error.InvalidPrivateKey;

        for (setup.hss.levels[0..count], 0..) |*level, i| {
            level.* = .{
                .lms = lms.lmsByCode(std.mem.readInt(u32, rest[1 + 8 * i ..][0..4], .big)) orelse return error.InvalidPrivateKey,
                .ots = lms.otsByCode(std.mem.readInt(u32, rest[5 + 8 * i ..][0..4], .big)) orelse return error.InvalidPrivateKey,
            };
        }

        if (!lms.validLevels(setup.hss.levels[0..count])) return error.InvalidPrivateKey;

        const tail = rest[1 + 8 * @as(usize, count) ..];

        const size = setup.seedSize();

        if (tail.len != size + 8) return error.InvalidPrivateKey;

        return .{ .setup = setup, .seed = tail[0..size], .index = std.mem.readInt(u64, tail[size..][0..8], .big) };
    }

    if (rest.len < 4) return error.InvalidPrivateKey;

    const p = xmss_scheme.byOid(xmssSets(kind), std.mem.readInt(u32, rest[0..4], .big)) orelse return error.InvalidPrivateKey;

    if (rest.len != 12 + 3 * p.n) return error.InvalidPrivateKey;

    return .{ .setup = .{ .xmss = p }, .seed = rest[12..], .index = std.mem.readInt(u64, rest[4..12], .big) };
}

// The parameters and the secret seed of a valid state blob, where its layout puts them.
fn parameterSection(kind: StatefulSignatureAlgorithm.Kind, state: []const u8) []const u8 {
    return state[2..if (kind == .hss_lms) 3 + 8 * @as(usize, state[2]) else 6];
}

fn seedSection(kind: StatefulSignatureAlgorithm.Kind, state: []const u8) []const u8 {
    return if (kind == .hss_lms) state[3 + 8 * @as(usize, state[2]) .. state.len - 24] else state[14 .. state.len - 16];
}

fn bigEndian(comptime T: type, value: T) [@sizeOf(T)]u8 {
    var out: [@sizeOf(T)]u8 = undefined;

    std.mem.writeInt(T, &out, value, .big);

    return out;
}

// A tree cache holds public nodes only, but the signer trusts the root of a cached lower tree as
// the child key that its parent signs, and the public key covers only the top root and the top
// level's types, so the cache is authenticated with a key derived from the seed and names every
// level's parameters. The body is the version, the kind, the parameters as the state blob encodes
// them, the public key and every cached tree, top first: its level or layer, its number on that
// level, its lowest cached height, its height, n, its node count and its nodes, level by level
// from the lowest, left to right. The tag, HMAC-SHA-256 of the body, follows it.
//
// The tag key is HKDF-Extract (RFC 5869) of the seed section of the state, with the label as salt.
fn treeCacheKey(seed: []const u8, key: *[32]u8) void {
    var mac = hash.hmac_sha_256.create(tree_cache_label);

    defer ct.wipe(std.mem.asBytes(&mac));

    mac.update(seed);

    mac.digest(key);
}

pub fn treeCacheTag(key: *const [32]u8, body: []const u8, tag: *[tag_size]u8) void {
    var mac = hash.hmac_sha_256.create(key);

    defer ct.wipe(std.mem.asBytes(&mac));

    mac.update(body);

    mac.digest(tag);
}

// Reads the big-endian fields of a tree cache from the front.
const Reader = struct {
    data: []const u8,
    position: usize = 0,

    fn take(self: *Reader, size: u64) Error![]const u8 {
        if (size > self.data.len - self.position) return error.InvalidEncoding;

        const start = self.position;

        self.position += @intCast(size);

        return self.data[start..self.position];
    }

    fn int(self: *Reader, comptime T: type) Error!T {
        return std.mem.readInt(T, (try self.take(@sizeOf(T)))[0..@sizeOf(T)], .big);
    }
};

// Where the trees of a level or layer stand in a tree cache, top first, and their height and n.
const Shape = struct {
    position: usize,
    height: u6,
    n: usize,
};

fn treeShape(setup: Setup, level: u8) ?Shape {
    return switch (setup) {
        .hss => |hss| if (level < hss.count) .{ .position = level, .height = hss.levels[level].lms.h, .n = hss.levels[level].lms.m } else null,
        .xmss => |p| if (level < p.d) .{ .position = p.d - 1 - level, .height = p.h / p.d, .n = p.n } else null,
    };
}

// The number of the tree that `index` signs with on a level or layer; the top one has one tree.
fn treeNumber(setup: Setup, index: u64, level: u8) u64 {
    switch (setup) {
        .hss => |hss| {
            if (level == 0) return 0;

            var below: u6 = 0;

            for (hss.levels[level..hss.count]) |l| below += l.lms.h;

            return index >> below;
        },
        .xmss => |p| {
            if (level == p.d - 1) return 0;

            return index >> @intCast((@as(usize, level) + 1) * (p.h / p.d));
        },
    }
}

// Whether a public key has every byte that the state gives: all but the root. The seed is secret
// until it loads, so the comparison is constant-time and only its result is public.
fn matchesState(setup: Setup, seed: []const u8, public_key: []const u8) bool {
    switch (setup) {
        .hss => |hss| {
            var expected: [28]u8 = undefined;

            if (public_key.len != expected.len + hss.levels[0].lms.m) return false;

            expected[0..4].* = bigEndian(u32, @intCast(hss.count));

            expected[4..8].* = bigEndian(u32, hss.levels[0].lms.code);

            expected[8..12].* = bigEndian(u32, hss.levels[0].ots.code);

            @memcpy(expected[12..28], seed[0..16]);

            return ct.declassifyValue(bool, ct.equal(public_key[0..expected.len], &expected));
        },
        .xmss => |p| {
            if (public_key.len != p.publicKeySize() or !std.mem.eql(u8, public_key[0..4], &bigEndian(u32, p.oid))) return false;

            return ct.declassifyValue(bool, ct.equal(public_key[4 + p.n ..], seed[2 * p.n ..][0..p.n]));
        },
    }
}

const OpenedCache = struct {
    public_key: []const u8,
    trees: []const merkle.CachedTree,
};

// Checks a tree cache in this order: the structure, then the version, the kind, the parameters and
// the bytes of the public key that the state gives, then the tag in constant time, then each
// tree's level and shape. Every failure is InvalidEncoding except a cache of another algorithm,
// which is AlgorithmMismatch. A tree that the index does not sign with is stale: it is skipped and
// built again when needed. The others go to `out`, for the signer to recompute their parents; the
// caller then compares the signer's public key, and with it the top root, with the cache's.
fn openTreeCache(kind: StatefulSignatureAlgorithm.Kind, decoded: Decoded, state: []const u8, data: []const u8, out: *[max_trees]merkle.CachedTree) Error!OpenedCache {
    var reader: Reader = .{ .data = data };

    const cache_version = try reader.int(u8);

    const cache_kind = try reader.int(u8);

    // The parameters have the layout of the kind that the cache names: an HSS level count and a
    // pair of types per level, or an OID. A cache of no known kind cannot be read further.
    const start = reader.position;

    switch (cache_kind) {
        @intFromEnum(StatefulSignatureAlgorithm.Kind.hss_lms) => _ = try reader.take(8 * @as(u64, try reader.int(u8))),
        @intFromEnum(StatefulSignatureAlgorithm.Kind.xmss), @intFromEnum(StatefulSignatureAlgorithm.Kind.xmss_mt) => _ = try reader.take(4),
        else => return error.InvalidEncoding,
    }

    const parameters = data[start..reader.position];

    const public_key = try reader.take(try reader.int(u32));

    const count = try reader.int(u8);

    const first_tree = reader.position;

    for (0..count) |_| {
        _ = try reader.take(11);

        const n = try reader.int(u8);

        _ = try reader.take(@as(u64, try reader.int(u32)) * n);
    }

    const body = data[0..reader.position];

    const tag = try reader.take(tag_size);

    if (reader.position != data.len) return error.InvalidEncoding;

    if (cache_version != tree_cache_version) return error.InvalidEncoding;

    if (cache_kind != @intFromEnum(kind)) return error.AlgorithmMismatch;

    if (!std.mem.eql(u8, parameters, parameterSection(kind, state))) return error.InvalidEncoding;

    if (!matchesState(decoded.setup, decoded.seed, public_key)) return error.InvalidEncoding;

    var key: [32]u8 = undefined;

    defer ct.wipe(&key);

    treeCacheKey(decoded.seed, &key);

    var expected: [tag_size]u8 = undefined;

    treeCacheTag(&key, body, &expected);

    // Whether the cache is authentic is public: loading fails on it.
    if (!ct.declassifyValue(bool, ct.equal(&expected, tag))) return error.InvalidEncoding;

    var trees: Reader = .{ .data = body, .position = first_tree };

    var previous: ?usize = null;

    var used: usize = 0;

    for (0..count) |_| {
        const level = try trees.int(u8);

        const tree = try trees.int(u64);

        const low = try trees.int(u8);

        const height = try trees.int(u8);

        const n = try trees.int(u8);

        const nodes = try trees.int(u32);

        const shape = treeShape(decoded.setup, level) orelse return error.InvalidEncoding;

        if (previous != null and shape.position <= previous.?) return error.InvalidEncoding;

        previous = shape.position;

        const expected_low = shape.height -| merkle.cached_height;

        if (low != expected_low or height != shape.height or n != shape.n or nodes != (@as(u64, 2) << (shape.height - expected_low)) - 1) return error.InvalidEncoding;

        const bytes = try trees.take(@as(u64, nodes) * n);

        if (tree == treeNumber(decoded.setup, decoded.index, level)) {
            out[used] = .{ .level = level, .tree = tree, .low = low, .height = height, .n = n, .nodes = bytes };

            used += 1;
        }
    }

    return .{ .public_key = public_key, .trees = out[0..used] };
}

pub const Opened = struct {
    signer: Signer,
    state: State,
    index: u64,
};

// The signer of a stored state, and the trees of a tree cache when one is given: what
// loadPrivateKey does once it has read the store, and what the C ABI's signer starts from.
pub fn open(kind: StatefulSignatureAlgorithm.Kind, allocator: Allocator, stored: []const u8, cache: ?[]const u8) (Error || Allocator.Error)!Opened {
    const decoded = try decode(kind, stored);

    if (decoded.index > decoded.setup.capacity()) return error.InvalidPrivateKey;

    var trees: [max_trees]merkle.CachedTree = undefined;

    const opened = if (cache) |data| try openTreeCache(kind, decoded, stored, data, &trees) else null;

    var state: State = .{ .bytes = @splat(0), .size = stored.len };

    defer ct.wipe(&state.bytes);

    @memcpy(state.bytes[0..stored.len], stored);

    const restored: []const merkle.CachedTree = if (opened) |found| found.trees else &.{};

    const signer = try Signer.build(allocator, decoded.setup, decoded.seed, restored);

    errdefer signer.destroy(allocator);

    if (opened) |found| {
        var public_key: [max_public_key_size]u8 = undefined;

        if (!std.mem.eql(u8, signer.publicKey(&public_key), found.public_key)) return error.InvalidEncoding;
    }

    return .{ .signer = signer, .state = state, .index = decoded.index };
}

// Builds the signer, then writes the first state with update(null, state). The new state holds
// `index` itself: the first signature claims the reserve. The key is built in the result, so that
// the only other copy of the state, which holds the seed, is the local one wiped here.
pub fn create(algorithm: StatefulSignatureAlgorithm, allocator: Allocator, setup: Setup, seed: []const u8, index: u64, store: StateStore, options: StatefulOptions) (Error || Allocator.Error)!StatefulKeyPair {
    if (options.tree_cache != null) return error.InvalidOption;

    const signer = try Signer.build(allocator, setup, seed, &.{});

    errdefer signer.destroy(allocator);

    var state: State = undefined;

    encode(algorithm.kind, setup, seed, index, &state);

    defer ct.wipe(&state.bytes);

    const created = store.update(null, state.slice()) catch return error.StatePersistFailed;

    if (!created) return error.StateConflict;

    var public_key: StatefulPublicKey = .{ .algorithm = algorithm, .bytes = @splat(0), .size = 0 };

    public_key.size = signer.publicKey(&public_key.bytes).len;

    return .{
        .public_key = public_key,
        .private_key = .{ .algorithm = algorithm, .signer = signer, .store = store, .state = state, .index = .init(index), .reserved = index, .reserve = options.reserve },
    };
}

pub const hss_lms: StatefulSignatureAlgorithm = .{ .name = "HSS/LMS", .kind = .hss_lms };

pub const xmss: StatefulSignatureAlgorithm = .{ .name = "XMSS", .kind = .xmss };

pub const xmss_mt: StatefulSignatureAlgorithm = .{ .name = "XMSS^MT", .kind = .xmss_mt };

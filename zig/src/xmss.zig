const std = @import("std");

const ct = @import("ct.zig");
const hash = @import("hash.zig");
const merkle = @import("merkle.zig");
const primitives = @import("primitives.zig");
const sha2 = @import("sha2.zig");

const Allocator = std.mem.Allocator;

const max_n = 32;

const max_length = 2 * max_n + 3;

const ots_address = 0;

const ltree_address = 1;

const hash_tree_address = 2;

const f_prefix = 0;

const h_prefix = 1;

const h_msg_prefix = 2;

const prf_prefix = 3;

const prf_keygen_prefix = 4;

pub const Parameters = struct {
    name: []const u8,
    oid: u32,
    multi: bool,
    shake: bool,
    n: usize,
    h: u6,
    d: u6,

    fn padding(self: Parameters) usize {
        return if (self.n == 32) 32 else 4;
    }

    fn treeHeight(self: Parameters) u6 {
        return self.h / self.d;
    }

    fn length(self: Parameters) usize {
        return 2 * self.n + 3;
    }

    fn indexSize(self: Parameters) usize {
        return if (self.multi) (@as(usize, self.h) + 7) / 8 else 4;
    }

    pub fn publicKeySize(self: Parameters) usize {
        return 4 + 2 * self.n;
    }

    pub fn signatureSize(self: Parameters) usize {
        return self.indexSize() + self.n + (self.d * self.length() + self.h) * self.n;
    }
};

const families = [_]struct { name: []const u8, shake: bool, n: usize, bits: []const u8, xmss_oid: u32, xmss_mt_oid: u32 }{
    .{ .name = "SHA2", .shake = false, .n = 32, .bits = "256", .xmss_oid = 0x01, .xmss_mt_oid = 0x01 },
    .{ .name = "SHA2", .shake = false, .n = 24, .bits = "192", .xmss_oid = 0x0d, .xmss_mt_oid = 0x21 },
    .{ .name = "SHAKE256", .shake = true, .n = 32, .bits = "256", .xmss_oid = 0x10, .xmss_mt_oid = 0x29 },
    .{ .name = "SHAKE256", .shake = true, .n = 24, .bits = "192", .xmss_oid = 0x13, .xmss_mt_oid = 0x31 },
};

// The SP 800-208 parameter sets with their RFC 8391 and NIST code points.
pub const xmss_sets = blk: {
    var sets: [12]Parameters = undefined;

    for (families, 0..) |family, i| {
        for ([_]u6{ 10, 16, 20 }, 0..) |h, j| {
            sets[3 * i + j] = .{ .name = std.fmt.comptimePrint("XMSS-{s}_{d}_{s}", .{ family.name, h, family.bits }), .oid = family.xmss_oid + j, .multi = false, .shake = family.shake, .n = family.n, .h = h, .d = 1 };
        }
    }

    break :blk sets;
};

pub const xmss_mt_sets = blk: {
    var sets: [32]Parameters = undefined;

    const shapes = [_][2]u6{ .{ 20, 2 }, .{ 20, 4 }, .{ 40, 2 }, .{ 40, 4 }, .{ 40, 8 }, .{ 60, 3 }, .{ 60, 6 }, .{ 60, 12 } };

    for (families, 0..) |family, i| {
        for (shapes, 0..) |shape, j| {
            sets[8 * i + j] = .{ .name = std.fmt.comptimePrint("XMSSMT-{s}_{d}/{d}_{s}", .{ family.name, shape[0], shape[1], family.bits }), .oid = family.xmss_mt_oid + j, .multi = true, .shake = family.shake, .n = family.n, .h = shape[0], .d = shape[1] };
        }
    }

    break :blk sets;
};

pub fn byName(sets: []const Parameters, name: []const u8) ?Parameters {
    for (sets) |p| {
        if (std.mem.eql(u8, p.name, name)) return p;
    }

    return null;
}

pub fn byOid(sets: []const Parameters, oid: u32) ?Parameters {
    for (sets) |p| {
        if (p.oid == oid) return p;
    }

    return null;
}

const Address = [32]u8;

fn address(layer: u32, tree: u64, kind: u32) Address {
    var adrs: Address = @splat(0);

    std.mem.writeInt(u32, adrs[0..4], layer, .big);

    std.mem.writeInt(u64, adrs[4..12], tree, .big);

    std.mem.writeInt(u32, adrs[12..16], kind, .big);

    return adrs;
}

fn setWord(adrs: *Address, word: usize, value: u32) void {
    std.mem.writeInt(u32, adrs[4 * word ..][0..4], value, .big);
}

fn getWord(adrs: *const Address, word: usize) u32 {
    return std.mem.readInt(u32, adrs[4 * word ..][0..4], .big);
}

// H(toByte(prefix, padding) || key || message): SHA-256 truncated to n bytes or SHAKE256.
fn hashFunction(p: Parameters, prefix: u8, key: []const u8, message: []const []const u8, out: []u8) void {
    var head: [32]u8 = @splat(0);

    head[p.padding() - 1] = prefix;

    var parts: [6][]const u8 = undefined;

    parts[0] = head[0..p.padding()];

    parts[1] = key;

    @memcpy(parts[2..][0..message.len], message);

    const all = parts[0 .. 2 + message.len];

    var length: usize = 0;

    for (all) |part| length += part.len;

    if (p.shake and length <= 135) return primitives.shake256Short(all, out[0..p.n]);

    if (!p.shake and length <= 183) return primitives.sha256Finish(&sha2.iv_256, 0, all, out[0..p.n]);

    if (p.shake) {
        var xof = hash.shake256.create();

        defer ct.wipe(std.mem.asBytes(&xof));

        for (all) |part| xof.update(part);

        xof.read(out[0..p.n]);
    } else {
        var hasher = hash.sha_256.create();

        defer ct.wipe(std.mem.asBytes(&hasher));

        for (all) |part| hasher.update(part);

        var full: [32]u8 = undefined;

        hasher.digest(&full);

        @memcpy(out[0..p.n], full[0..p.n]);
    }
}

// The keyed hashes of one key. With SHA-256 and n = 32 the block toByte(3, 32) || PUB_SEED that
// starts every PRF call, and toByte(4, 32) || SK_SEED for PRF_keygen, are compressed once.
const Hashes = struct {
    p: Parameters,
    pub_seed: [max_n]u8,
    sk_seed: [max_n]u8,
    prf_state: ?[8]u32,
    keygen_state: ?[8]u32,

    fn init(p: Parameters, pub_seed: []const u8, sk_seed: []const u8) Hashes {
        var self: Hashes = .{ .p = p, .pub_seed = @splat(0), .sk_seed = @splat(0), .prf_state = null, .keygen_state = null };

        @memcpy(self.pub_seed[0..p.n], pub_seed);

        @memcpy(self.sk_seed[0..p.n], sk_seed);

        if (!p.shake and p.n == 32) {
            self.prf_state = precompute(prf_prefix, pub_seed);

            self.keygen_state = precompute(prf_keygen_prefix, sk_seed);
        }

        return self;
    }

    fn precompute(prefix: u8, key: []const u8) [8]u32 {
        var block: [64]u8 = @splat(0);

        defer ct.wipe(&block);

        block[31] = prefix;

        @memcpy(block[32..64], key);

        var state = sha2.iv_256;

        sha2.compress256(&state, &block);

        return state;
    }

    fn wipe(self: *Hashes) void {
        ct.wipe(&self.sk_seed);

        if (self.keygen_state) |*state| ct.wipe(std.mem.asBytes(state));
    }

    fn prf(self: *const Hashes, adrs: *const Address, out: []u8) void {
        if (self.prf_state) |*state| return primitives.sha256Finish(state, 64, &.{adrs}, out[0..self.p.n]);

        hashFunction(self.p, prf_prefix, self.pub_seed[0..self.p.n], &.{adrs}, out);
    }

    // SP 800-208: secret chain values come from PRF_keygen(SK_SEED, PUB_SEED || ADRS).
    fn prfKeygen(self: *const Hashes, adrs: *const Address, out: []u8) void {
        const n = self.p.n;

        if (self.keygen_state) |*state| return primitives.sha256Finish(state, 64, &.{ self.pub_seed[0..n], adrs }, out[0..n]);

        hashFunction(self.p, prf_keygen_prefix, self.sk_seed[0..n], &.{ self.pub_seed[0..n], adrs }, out);
    }

    fn chain(self: *const Hashes, x: []u8, start: usize, steps: usize, adrs: *Address) void {
        const n = self.p.n;

        for (start..start + steps) |k| {
            var key: [max_n]u8 = undefined;

            var mask: [max_n]u8 = undefined;

            setWord(adrs, 6, @intCast(k));

            setWord(adrs, 7, 0);

            self.prf(adrs, &key);

            setWord(adrs, 7, 1);

            self.prf(adrs, &mask);

            for (mask[0..n], x[0..n]) |*m, value| m.* ^= value;

            hashFunction(self.p, f_prefix, key[0..n], &.{mask[0..n]}, x);
        }
    }

    fn randHash(self: *const Hashes, left: []const u8, right: []const u8, adrs: *Address, out: []u8) void {
        const n = self.p.n;

        var key: [max_n]u8 = undefined;

        var masked: [2 * max_n]u8 = undefined;

        setWord(adrs, 7, 0);

        self.prf(adrs, &key);

        setWord(adrs, 7, 1);

        self.prf(adrs, masked[0..n]);

        setWord(adrs, 7, 2);

        self.prf(adrs, masked[n..][0..n]);

        for (masked[0..n], left[0..n]) |*m, value| m.* ^= value;

        for (masked[n..][0..n], right[0..n]) |*m, value| m.* ^= value;

        hashFunction(self.p, h_prefix, key[0..n], &.{masked[0 .. 2 * n]}, out);
    }

    fn secret(self: *const Hashes, adrs: *Address, i: usize, out: []u8) void {
        setWord(adrs, 5, @intCast(i));

        setWord(adrs, 6, 0);

        setWord(adrs, 7, 0);

        self.prfKeygen(adrs, out);
    }

    fn ltree(self: *const Hashes, values: []u8, adrs: *Address, out: []u8) void {
        const n = self.p.n;

        var count = values.len / n;

        setWord(adrs, 5, 0);

        while (count > 1) {
            for (0..count / 2) |i| {
                setWord(adrs, 6, @intCast(i));

                self.randHash(values[2 * i * n ..][0..n], values[(2 * i + 1) * n ..][0..n], adrs, values[i * n ..][0..n]);
            }

            if (count % 2 == 1) @memcpy(values[count / 2 * n ..][0..n], values[(count - 1) * n ..][0..n]);

            count = (count + 1) / 2;

            setWord(adrs, 5, getWord(adrs, 5) + 1);
        }

        @memcpy(out[0..n], values[0..n]);
    }

    fn leaf(self: *const Hashes, layer: u32, tree: u64, index: u32, out: []u8) void {
        const n = self.p.n;

        var values: [max_length * max_n]u8 = undefined;

        defer ct.wipe(&values);

        var ots = address(layer, tree, ots_address);

        setWord(&ots, 4, index);

        for (0..self.p.length()) |i| {
            const value = values[i * n ..][0..n];

            self.secret(&ots, i, value);

            self.chain(value, 0, 15, &ots);
        }

        var lt = address(layer, tree, ltree_address);

        setWord(&lt, 4, index);

        self.ltree(values[0 .. self.p.length() * n], &lt, out);
    }
};

fn wotsDigits(p: Parameters, message: []const u8, out: *[max_length]u32) void {
    var checksum: u32 = 0;

    for (message[0..p.n], 0..) |byte, i| {
        out[2 * i] = byte >> 4;

        out[2 * i + 1] = byte & 0x0f;

        checksum += 30 - out[2 * i] - out[2 * i + 1];
    }

    checksum <<= 4;

    for (0..3) |i| {
        out[2 * p.n + i] = (checksum >> @intCast(12 - 4 * i)) & 0x0f;
    }
}

const TreeContext = struct {
    hashes: *const Hashes,
    layer: u32,
    tree: u64,

    pub fn leaf(self: *const TreeContext, index: u64, out: []u8) void {
        self.hashes.leaf(self.layer, self.tree, @intCast(index), out);
    }

    pub fn combine(self: *const TreeContext, z: u32, j: u64, left: []const u8, right: []const u8, out: []u8) void {
        var adrs = address(self.layer, self.tree, hash_tree_address);

        setWord(&adrs, 5, z);

        setWord(&adrs, 6, @intCast(j));

        self.hashes.randHash(left, right, &adrs, out);
    }
};

fn computeRoot(hashes: *const Hashes, node: []u8, index: u32, auth: []const u8, layer: u32, tree: u64) void {
    const n = hashes.p.n;

    var adrs = address(layer, tree, hash_tree_address);

    for (0..hashes.p.treeHeight()) |k| {
        setWord(&adrs, 5, @intCast(k));

        setWord(&adrs, 6, index >> @intCast(k + 1));

        const sibling = auth[k * n ..][0..n];

        if ((index >> @intCast(k)) & 1 == 1) {
            hashes.randHash(sibling, node[0..n], &adrs, node);
        } else {
            hashes.randHash(node[0..n], sibling, &adrs, node);
        }
    }
}

fn messageDigest(p: Parameters, r: []const u8, root: []const u8, index: u64, message: []const u8, out: []u8) void {
    var key: [3 * max_n]u8 = @splat(0);

    @memcpy(key[0..p.n], r);

    @memcpy(key[p.n..][0..p.n], root);

    std.mem.writeInt(u64, key[3 * p.n - 8 ..][0..8], index, .big);

    hashFunction(p, h_msg_prefix, key[0 .. 3 * p.n], &.{message}, out);
}

pub fn verify(p: Parameters, public_key: []const u8, message: []const u8, signature: []const u8) bool {
    const n = p.n;

    if (public_key.len != p.publicKeySize() or signature.len != p.signatureSize()) return false;

    if (std.mem.readInt(u32, public_key[0..4], .big) != p.oid) return false;

    const root = public_key[4..][0..n];

    const unused: [max_n]u8 = @splat(0);

    const hashes = Hashes.init(p, public_key[4 + n ..][0..n], unused[0..n]);

    var index: u64 = 0;

    for (signature[0..p.indexSize()]) |byte| index = (index << 8) | byte;

    if (index >> p.h != 0) return false;

    var node: [max_n]u8 = undefined;

    messageDigest(p, signature[p.indexSize()..][0..n], root, index, message, &node);

    var offset = p.indexSize() + n;

    const th = p.treeHeight();

    for (0..p.d) |layer| {
        const leaf_index: u32 = @intCast(index & ((@as(u64, 1) << th) - 1));

        index >>= th;

        var ots = address(@intCast(layer), index, ots_address);

        setWord(&ots, 4, leaf_index);

        var digits: [max_length]u32 = undefined;

        wotsDigits(p, &node, &digits);

        var values: [max_length * max_n]u8 = undefined;

        @memcpy(values[0 .. p.length() * n], signature[offset..][0 .. p.length() * n]);

        for (digits[0..p.length()], 0..) |digit, i| {
            setWord(&ots, 5, @intCast(i));

            hashes.chain(values[i * n ..][0..n], digit, 15 - digit, &ots);
        }

        offset += p.length() * n;

        var lt = address(@intCast(layer), index, ltree_address);

        setWord(&lt, 4, leaf_index);

        hashes.ltree(values[0 .. p.length() * n], &lt, &node);

        computeRoot(&hashes, &node, leaf_index, signature[offset..][0 .. th * n], @intCast(layer), index);

        offset += th * n;
    }

    return std.mem.eql(u8, node[0..n], root);
}

// The signing side of an XMSS or XMSS^MT key, with one cached tree per layer. It is allocated so
// that the trees can point back at its hashes, and every layer has its tree memory from the start
// so that signing never allocates.
pub const Xmss = struct {
    hashes: Hashes,
    sk_prf: [max_n]u8,
    root: [max_n]u8,
    layers: [12]Layer,

    const Layer = struct {
        index: ?u64,
        tree: merkle.MerkleTree(TreeContext),
    };

    pub fn create(allocator: Allocator, p: Parameters, seed: []const u8) Allocator.Error!*Xmss {
        const n = p.n;

        const self = try allocator.create(Xmss);

        errdefer allocator.destroy(self);

        var built: usize = 0;

        errdefer for (self.layers[0..built]) |*layer| layer.tree.deinit(allocator);

        while (built < p.d) : (built += 1) {
            self.layers[built] = .{ .index = null, .tree = try .init(allocator, p.treeHeight(), n) };
        }

        self.hashes = .init(p, seed[2 * n ..][0..n], seed[0..n]);

        self.sk_prf = @splat(0);

        @memcpy(self.sk_prf[0..n], seed[n..][0..n]);

        @memcpy(self.root[0..n], self.tree(p.d - 1, 0).root[0..n]);

        return self;
    }

    pub fn destroy(self: *Xmss, allocator: Allocator) void {
        for (self.layers[0..self.hashes.p.d]) |*layer| layer.tree.deinit(allocator);

        self.hashes.wipe();

        ct.wipe(&self.sk_prf);

        allocator.destroy(self);
    }

    pub fn capacity(self: *const Xmss) u64 {
        return @as(u64, 1) << self.hashes.p.h;
    }

    pub fn publicKey(self: *const Xmss, out: *[68]u8) []u8 {
        const n = self.hashes.p.n;

        std.mem.writeInt(u32, out[0..4], self.hashes.p.oid, .big);

        @memcpy(out[4..][0..n], self.root[0..n]);

        @memcpy(out[4 + n ..][0..n], self.hashes.pub_seed[0..n]);

        return out[0 .. 4 + 2 * n];
    }

    fn tree(self: *Xmss, layer: usize, index: u64) *const merkle.MerkleTree(TreeContext) {
        const cached = &self.layers[layer];

        if (cached.index == null or cached.index.? != index) {
            cached.tree.build(.{ .hashes = &self.hashes, .layer = @intCast(layer), .tree = index });

            cached.index = index;
        }

        return &cached.tree;
    }

    pub fn sign(self: *Xmss, index: u64, message: []const u8, out: []u8) void {
        const p = self.hashes.p;

        const n = p.n;

        const th = p.treeHeight();

        var index_bytes: [32]u8 = @splat(0);

        std.mem.writeInt(u64, index_bytes[24..32], index, .big);

        for (out[0..p.indexSize()], 0..) |*byte, i| {
            byte.* = @truncate(index >> @intCast(8 * (p.indexSize() - 1 - i)));
        }

        const r = out[p.indexSize()..][0..n];

        hashFunction(p, prf_prefix, self.sk_prf[0..n], &.{&index_bytes}, r);

        var node: [max_n]u8 = undefined;

        messageDigest(p, r, self.root[0..n], index, message, &node);

        var offset = p.indexSize() + n;

        var rest = index;

        for (0..p.d) |layer| {
            const leaf_index: u32 = @intCast(rest & ((@as(u64, 1) << th) - 1));

            rest >>= th;

            var ots = address(@intCast(layer), rest, ots_address);

            setWord(&ots, 4, leaf_index);

            var digits: [max_length]u32 = undefined;

            wotsDigits(p, &node, &digits);

            for (digits[0..p.length()], 0..) |digit, i| {
                const value = out[offset + i * n ..][0..n];

                self.hashes.secret(&ots, i, value);

                self.hashes.chain(value, 0, digit, &ots);
            }

            offset += p.length() * n;

            const layer_tree = self.tree(layer, rest);

            layer_tree.authPath(leaf_index, out[offset..][0 .. th * n]);

            offset += th * n;

            @memcpy(node[0..n], layer_tree.root[0..n]);
        }
    }
};

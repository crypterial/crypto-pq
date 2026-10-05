const std = @import("std");

const ct = @import("ct.zig");
const Error = @import("errors.zig").Error;
const hash = @import("hash.zig");
const merkle = @import("merkle.zig");
const primitives = @import("primitives.zig");
const sha2 = @import("sha2.zig");
const vec = @import("vector.zig");

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
            if (!self.p.shake and count / 2 >= 3) {
                switch (n) {
                    inline 24, 32 => |size| Lanes(max_lanes, size / 4).ltreeLevel(self, adrs, count, values),
                    else => unreachable,
                }
            } else {
                for (0..count / 2) |i| {
                    setWord(adrs, 6, @intCast(i));

                    self.randHash(values[2 * i * n ..][0..n], values[(2 * i + 1) * n ..][0..n], adrs, values[i * n ..][0..n]);
                }
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

// Independent SHA-256 computations run side by side in the lanes of vectors. A target without
// vector registers computes one at a time: emulated lanes cost as much each and spill to the stack.
const max_lanes = if (std.simd.suggestVectorLength(u32) == null) 1 else 8;

// SHA-256 of L hashes at once, lane l of every vector belonging to the l-th, for SHA2 parameter
// sets with m-word values. Every input is a sequence of whole 32-bit words: the padded prefix,
// the key, the address words and the values.
fn Lanes(comptime L: usize, comptime m: usize) type {
    return struct {
        const V = @Vector(L, u32);

        const Value = [m]V;

        // With n = 32 the 32-byte prefix and the key fill a block, so the PRF keys are hashed once.
        const wide = m == 8;

        fn splat(value: u32) V {
            return @splat(value);
        }

        fn words(bytes: []const u8, out: []V) void {
            for (out, 0..) |*word, i| word.* = splat(std.mem.readInt(u32, bytes[4 * i ..][0..4], .big));
        }

        fn broadcast(state: *const [8]u32) [8]V {
            var out: [8]V = undefined;

            for (&out, state) |*word, value| word.* = @splat(value);

            return out;
        }

        // SHA-256 of `count` message words that follow `prefix_blocks` blocks already absorbed into
        // `start`; the padding word and the two length words round it up to whole blocks.
        fn digest(comptime count: usize, comptime prefix_blocks: usize, start: *const [8]V, message: *const [count]V, out: *Value) void {
            const blocks = (count + 18) / 16;

            var buffer: [16 * blocks]V = undefined;

            defer ct.wipe(std.mem.asBytes(&buffer));

            buffer[0..count].* = message.*;

            buffer[count] = splat(0x80000000);

            inline for (count + 1..16 * blocks - 1) |i| {
                buffer[i] = splat(0);
            }

            buffer[16 * blocks - 1] = splat((64 * prefix_blocks + 4 * count) * 8);

            var state = start.*;

            defer ct.wipe(std.mem.asBytes(&state));

            inline for (0..blocks) |b| {
                sha2.rounds256(V, &state, buffer[16 * b ..][0..16]);
            }

            out.* = state[0..m].*;
        }

        // The seeds of one key as words, and with n = 32 the states after their first block.
        const Keys = struct {
            pub_seed: Value,
            sk_seed: Value,
            prf_state: [8]V,
            keygen_state: [8]V,

            fn init(hashes: *const Hashes) Keys {
                var self: Keys = .{ .pub_seed = undefined, .sk_seed = undefined, .prf_state = broadcast(&sha2.iv_256), .keygen_state = broadcast(&sha2.iv_256) };

                words(&hashes.pub_seed, &self.pub_seed);

                words(&hashes.sk_seed, &self.sk_seed);

                if (wide) {
                    self.prf_state = broadcast(&hashes.prf_state.?);

                    self.keygen_state = broadcast(&hashes.keygen_state.?);
                }

                return self;
            }

            fn wipe(self: *Keys) void {
                ct.wipe(std.mem.asBytes(&self.sk_seed));

                ct.wipe(std.mem.asBytes(&self.keygen_state));
            }
        };

        fn prf(keys: *const Keys, adrs: *const [8]V, out: *Value) void {
            if (wide) return digest(8, 1, &keys.prf_state, adrs, out);

            const message = [1]V{splat(prf_prefix)} ++ keys.pub_seed ++ adrs.*;

            digest(message.len, 0, &keys.prf_state, &message, out);
        }

        fn prfKeygen(keys: *const Keys, adrs: *const [8]V, out: *Value) void {
            if (wide) {
                const message = keys.pub_seed ++ adrs.*;

                return digest(message.len, 1, &keys.keygen_state, &message, out);
            }

            var message = [1]V{splat(prf_keygen_prefix)} ++ keys.sk_seed ++ keys.pub_seed ++ adrs.*;

            defer ct.wipe(std.mem.asBytes(&message));

            digest(message.len, 0, &keys.keygen_state, &message, out);
        }

        fn prefix(comptime value: u32) [if (wide) 8 else 1]V {
            var out: [if (wide) 8 else 1]V = @splat(splat(0));

            out[out.len - 1] = splat(value);

            return out;
        }

        // F(KEY, M ^ BM) for a chain step.
        fn step(keys: *const Keys, adrs: *[8]V, value: *Value) void {
            var key: Value = undefined;

            var mask: Value = undefined;

            adrs[7] = splat(0);

            prf(keys, adrs, &key);

            adrs[7] = splat(1);

            prf(keys, adrs, &mask);

            for (&mask, value) |*word, x| word.* ^= x;

            var message = prefix(f_prefix) ++ key ++ mask;

            defer ct.wipe(std.mem.asBytes(&message));

            ct.wipe(std.mem.asBytes(&mask));

            digest(message.len, 0, &broadcast(&sha2.iv_256), &message, value);
        }

        fn randHash(keys: *const Keys, adrs: *[8]V, left: *const Value, right: *const Value, out: *Value) void {
            var key: Value = undefined;

            var masks: [2]Value = undefined;

            adrs[7] = splat(0);

            prf(keys, adrs, &key);

            adrs[7] = splat(1);

            prf(keys, adrs, &masks[0]);

            adrs[7] = splat(2);

            prf(keys, adrs, &masks[1]);

            for (&masks[0], left) |*word, x| word.* ^= x;

            for (&masks[1], right) |*word, x| word.* ^= x;

            const message = prefix(h_prefix) ++ key ++ masks[0] ++ masks[1];

            digest(message.len, 0, &broadcast(&sha2.iv_256), &message, out);
        }

        fn laneAddress(layer: u32, tree: u64, kind: u32, index: V) [8]V {
            return .{ splat(layer), splat(@truncate(tree >> 32)), splat(@truncate(tree)), splat(kind), index, splat(0), splat(0), splat(0) };
        }

        fn gather(bytes: []const u8, lanes: usize, stride: usize, out: *Value) void {
            var values: [m][L]u32 = @splat(@splat(0));

            for (0..lanes) |l| {
                for (0..m) |w| values[w][l] = std.mem.readInt(u32, bytes[l * stride + 4 * w ..][0..4], .big);
            }

            for (out, values) |*word, lane_values| word.* = lane_values;
        }

        fn scatter(value: *const Value, lanes: usize, stride: usize, out: []u8) void {
            for (value, 0..) |word, w| {
                const values: [L]u32 = word;

                for (0..lanes) |l| std.mem.writeInt(u32, out[l * stride + 4 * w ..][0..4], values[l], .big);
            }
        }

        // The leaves first .. first + out.len / n - 1 of a tree, one per lane: every WOTS chain
        // in full, then the L-tree.
        fn leaves(hashes: *const Hashes, layer: u32, tree: u64, first: u32, out: []u8) void {
            var keys: Keys = .init(hashes);

            defer keys.wipe();

            const index = std.simd.iota(u32, L) + splat(first);

            var values: [max_length]Value = undefined;

            defer ct.wipe(std.mem.asBytes(&values));

            const length = hashes.p.length();

            var adrs = laneAddress(layer, tree, ots_address, index);

            for (values[0..length], 0..) |*value, i| {
                adrs[5] = splat(@intCast(i));

                adrs[6] = splat(0);

                adrs[7] = splat(0);

                prfKeygen(&keys, &adrs, value);

                for (0..15) |j| {
                    adrs[6] = splat(@intCast(j));

                    step(&keys, &adrs, value);
                }
            }

            adrs = laneAddress(layer, tree, ltree_address, index);

            var count = length;

            while (count > 1) : (adrs[5] += splat(1)) {
                for (0..count / 2) |i| {
                    adrs[6] = splat(@intCast(i));

                    randHash(&keys, &adrs, &values[2 * i], &values[2 * i + 1], &values[i]);
                }

                if (count % 2 == 1) values[count / 2] = values[count - 1];

                count = (count + 1) / 2;
            }

            scatter(&values[0], out.len / (4 * m), 4 * m, out);
        }

        // Runs WOTS chain i of key pair `index` from step starts[i] to ends[i] on the values in
        // place.
        fn chains(hashes: *const Hashes, layer: u32, tree: u64, index: u32, starts: []const u32, ends: []const u32, values: []u8) void {
            var keys: Keys = .init(hashes);

            defer keys.wipe();

            var lanes: vec.ChainLanes(L, m) = .init(starts, ends, values);

            var value: Value = undefined;

            defer {
                lanes.wipe();

                ct.wipe(std.mem.asBytes(&value));
            }

            var adrs = laneAddress(layer, tree, ots_address, splat(index));

            while (lanes.running > 0) {
                value = lanes.current();

                adrs[5] = lanes.chain;

                adrs[6] = lanes.step;

                step(&keys, &adrs, &value);

                lanes.advance(&value);
            }
        }

        // The secret starting values of the WOTS chains of key pair `index`, one chain per lane.
        fn secrets(hashes: *const Hashes, layer: u32, tree: u64, index: u32, out: []u8) void {
            var keys: Keys = .init(hashes);

            defer keys.wipe();

            var value: Value = undefined;

            defer ct.wipe(std.mem.asBytes(&value));

            const length = out.len / (4 * m);

            var adrs = laneAddress(layer, tree, ots_address, splat(index));

            var i: usize = 0;

            while (i < length) : (i += L) {
                adrs[5] = std.simd.iota(u32, L) + splat(@intCast(i));

                prfKeygen(&keys, &adrs, &value);

                scatter(&value, @min(L, length - i), 4 * m, out[i * 4 * m ..]);
            }
        }

        // One level of an L-tree: the pairs of `count` nodes in place, one pair per lane.
        fn ltreeLevel(hashes: *const Hashes, adrs: *const Address, count: usize, values: []u8) void {
            var keys: Keys = .init(hashes);

            defer keys.wipe();

            var lane_adrs: [8]V = undefined;

            for (&lane_adrs, 0..) |*word, w| word.* = splat(getWord(adrs, w));

            var i: usize = 0;

            while (i < count / 2) : (i += L) {
                const lanes = @min(L, count / 2 - i);

                var left: Value = undefined;

                var right: Value = undefined;

                gather(values[2 * i * 4 * m ..], lanes, 8 * m, &left);

                gather(values[(2 * i + 1) * 4 * m ..], lanes, 8 * m, &right);

                lane_adrs[6] = std.simd.iota(u32, L) + splat(@intCast(i));

                randHash(&keys, &lane_adrs, &left, &right, &left);

                scatter(&left, lanes, 4 * m, values[i * 4 * m ..]);
            }
        }
    };
}

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

    pub const lanes = max_lanes;

    pub fn leaves(self: *const TreeContext, first: u64, out: []u8) void {
        const n = self.hashes.p.n;

        if (self.hashes.p.shake) {
            for (0..out.len / n) |i| self.leaf(first + i, out[i * n ..][0..n]);

            return;
        }

        switch (n) {
            inline 24, 32 => |size| Lanes(max_lanes, size / 4).leaves(self.hashes, self.layer, self.tree, @intCast(first), out),
            else => unreachable,
        }
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

        if (p.shake) {
            for (digits[0..p.length()], 0..) |digit, i| {
                setWord(&ots, 5, @intCast(i));

                hashes.chain(values[i * n ..][0..n], digit, 15 - digit, &ots);
            }
        } else {
            const ends: [max_length]u32 = @splat(15);

            switch (n) {
                inline 24, 32 => |size| Lanes(max_lanes, size / 4).chains(&hashes, @intCast(layer), index, leaf_index, digits[0..p.length()], ends[0..p.length()], values[0 .. p.length() * n]),
                else => unreachable,
            }
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
//
// The part of an XMSS^MT signature that layer L >= 1 contributes (the WOTS+ signature of the root
// below and the authentication path) depends only on index >> (L * h / d), so it is kept until
// that prefix changes, as HSS keeps the signed public keys of its child trees. A layer whose part
// is current has every layer above it current too.
//
// `cached` holds the trees of a verified tree cache that the next index signs with; each replaces
// the build of its layer, checked against its own nodes.
pub const Xmss = struct {
    hashes: Hashes,
    sk_prf: [max_n]u8,
    root: [max_n]u8,
    layers: [12]Layer,
    upper: []u8,
    upper_prefixes: [12]?u64,

    const Layer = struct {
        index: ?u64,
        tree: merkle.MerkleTree(TreeContext),
    };

    pub fn create(allocator: Allocator, p: Parameters, seed: []const u8, cached: []const merkle.CachedTree) (Error || Allocator.Error)!*Xmss {
        const n = p.n;

        const self = try allocator.create(Xmss);

        errdefer allocator.destroy(self);

        self.upper = try allocator.alloc(u8, (p.d - 1) * layerSize(p));

        errdefer allocator.free(self.upper);

        self.upper_prefixes = @splat(null);

        var built: usize = 0;

        errdefer for (self.layers[0..built]) |*layer| layer.tree.deinit(allocator);

        while (built < p.d) : (built += 1) {
            self.layers[built] = .{ .index = null, .tree = try .init(allocator, p.treeHeight(), n) };
        }

        // PUB_SEED is part of the public key.
        ct.declassify(seed[2 * n ..][0..n]);

        self.hashes = .init(p, seed[2 * n ..][0..n], seed[0..n]);

        self.sk_prf = @splat(0);

        @memcpy(self.sk_prf[0..n], seed[n..][0..n]);

        errdefer {
            self.hashes.wipe();

            ct.wipe(&self.sk_prf);
        }

        for (cached) |entry| {
            const layer = &self.layers[entry.level];

            try layer.tree.restore(.{ .hashes = &self.hashes, .layer = entry.level, .tree = entry.tree }, entry.nodes);

            layer.index = entry.tree;
        }

        @memcpy(self.root[0..n], self.tree(p.d - 1, 0).root[0..n]);

        return self;
    }

    // Every tree the key holds, top first, as a tree cache lists it.
    pub fn cachedTrees(self: *const Xmss, out: []merkle.CachedTree) []merkle.CachedTree {
        var count: usize = 0;

        var layer: usize = self.hashes.p.d;

        while (layer > 0) {
            layer -= 1;

            const held = &self.layers[layer];

            out[count] = held.tree.cached(@intCast(layer), held.index orelse continue);

            count += 1;
        }

        return out[0..count];
    }

    pub fn destroy(self: *Xmss, allocator: Allocator) void {
        for (self.layers[0..self.hashes.p.d]) |*layer| layer.tree.deinit(allocator);

        allocator.free(self.upper);

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

    // The bytes one layer adds to a signature: a WOTS+ signature and an authentication path.
    fn layerSize(p: Parameters) usize {
        return (p.length() + p.treeHeight()) * p.n;
    }

    fn tree(self: *Xmss, layer: usize, index: u64) *merkle.MerkleTree(TreeContext) {
        const cached = &self.layers[layer];

        if (cached.index == null or cached.index.? != index) {
            cached.tree.build(.{ .hashes = &self.hashes, .layer = @intCast(layer), .tree = index });

            // Each root is the public key or what the layer above signs.
            ct.declassify(&cached.tree.root);

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

        // R is part of the signature, so the message digest is public as well.
        ct.declassify(r);

        var node: [max_n]u8 = undefined;

        messageDigest(p, r, self.root[0..n], index, message, &node);

        var offset = p.indexSize() + n;

        var rest = index;

        const part = layerSize(p);

        for (0..p.d) |layer| {
            if (layer > 0 and self.upper_prefixes[layer] == rest) {
                const kept = self.upper[(layer - 1) * part ..];

                @memcpy(out[offset..][0..kept.len], kept);

                break;
            }

            const prefix = rest;

            const leaf_index: u32 = @intCast(rest & ((@as(u64, 1) << th) - 1));

            rest >>= th;

            var ots = address(@intCast(layer), rest, ots_address);

            setWord(&ots, 4, leaf_index);

            var digits: [max_length]u32 = undefined;

            wotsDigits(p, &node, &digits);

            if (p.shake) {
                for (digits[0..p.length()], 0..) |digit, i| {
                    const value = out[offset + i * n ..][0..n];

                    self.hashes.secret(&ots, i, value);

                    self.hashes.chain(value, 0, digit, &ots);
                }
            } else {
                const values = out[offset..][0 .. p.length() * n];

                const zeros: [max_length]u32 = @splat(0);

                switch (n) {
                    inline 24, 32 => |size| {
                        const lanes = Lanes(max_lanes, size / 4);

                        lanes.secrets(&self.hashes, @intCast(layer), rest, leaf_index, values);

                        lanes.chains(&self.hashes, @intCast(layer), rest, leaf_index, zeros[0..p.length()], digits[0..p.length()], values);
                    },
                    else => unreachable,
                }
            }

            offset += p.length() * n;

            const layer_tree = self.tree(layer, rest);

            layer_tree.authPath(leaf_index, out[offset..][0 .. th * n]);

            offset += th * n;

            @memcpy(node[0..n], layer_tree.root[0..n]);

            if (layer > 0) {
                // The root below and this layer's tree are public, and so is what they give.
                ct.declassify(out[offset - part .. offset]);

                @memcpy(self.upper[(layer - 1) * part ..][0..part], out[offset - part .. offset]);

                self.upper_prefixes[layer] = prefix;
            }
        }

        ct.declassify(out);
    }
};

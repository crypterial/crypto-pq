const std = @import("std");

const ct = @import("ct.zig");
const hash = @import("hash.zig");
const primitives = @import("primitives.zig");
const sha2 = @import("sha2.zig");

pub const Parameters = struct {
    shake: bool,
    n: u8,
    h: u8,
    d: u8,
    hp: u8,
    a: u8,
    k: u8,
    m: u8,

    pub inline fn length(comptime self: Parameters) usize {
        return 2 * @as(usize, self.n) + 3;
    }

    pub inline fn publicKeySize(comptime self: Parameters) usize {
        return 2 * @as(usize, self.n);
    }

    pub inline fn privateKeySize(comptime self: Parameters) usize {
        return 4 * @as(usize, self.n);
    }

    pub inline fn signatureSize(comptime self: Parameters) usize {
        return (1 + @as(usize, self.k) * (1 + self.a) + self.h + self.d * self.length()) * self.n;
    }
};

fn set(shake: bool, n: u8, h: u8, d: u8, hp: u8, a: u8, k: u8, m: u8) Parameters {
    return .{ .shake = shake, .n = n, .h = h, .d = d, .hp = hp, .a = a, .k = k, .m = m };
}

pub const sha2_128s = set(false, 16, 63, 7, 9, 12, 14, 30);

pub const sha2_128f = set(false, 16, 66, 22, 3, 6, 33, 34);

pub const sha2_192s = set(false, 24, 63, 7, 9, 14, 17, 39);

pub const sha2_192f = set(false, 24, 66, 22, 3, 8, 33, 42);

pub const sha2_256s = set(false, 32, 64, 8, 8, 14, 22, 47);

pub const sha2_256f = set(false, 32, 68, 17, 4, 9, 35, 49);

pub const shake_128s = set(true, 16, 63, 7, 9, 12, 14, 30);

pub const shake_128f = set(true, 16, 66, 22, 3, 6, 33, 34);

pub const shake_192s = set(true, 24, 63, 7, 9, 14, 17, 39);

pub const shake_192f = set(true, 24, 66, 22, 3, 8, 33, 42);

pub const shake_256s = set(true, 32, 64, 8, 8, 14, 22, 47);

pub const shake_256f = set(true, 32, 68, 17, 4, 9, 35, 49);

const wots_hash = 0;

const wots_pk = 1;

const tree = 2;

const fors_tree = 3;

const fors_roots = 4;

const wots_prf = 5;

const fors_prf = 6;

const Address = [32]u8;

fn setLayer(adrs: *Address, value: u32) void {
    std.mem.writeInt(u32, adrs[0..4], value, .big);
}

fn setTree(adrs: *Address, value: u64) void {
    @memset(adrs[4..8], 0);

    std.mem.writeInt(u64, adrs[8..16], value, .big);
}

fn setType(adrs: *Address, value: u32) void {
    std.mem.writeInt(u32, adrs[16..20], value, .big);

    @memset(adrs[20..32], 0);
}

fn setKeyPair(adrs: *Address, value: u32) void {
    std.mem.writeInt(u32, adrs[20..24], value, .big);
}

fn setChain(adrs: *Address, value: u32) void {
    std.mem.writeInt(u32, adrs[24..28], value, .big);
}

fn setHash(adrs: *Address, value: u32) void {
    std.mem.writeInt(u32, adrs[28..32], value, .big);
}

fn keyPair(adrs: *const Address) u32 {
    return std.mem.readInt(u32, adrs[20..24], .big);
}

fn treeIndex(adrs: *const Address) u32 {
    return std.mem.readInt(u32, adrs[28..32], .big);
}

const setTreeHeight = setChain;

const setTreeIndex = setHash;

// FIPS 205, section 11.2: the SHA-2 instances hash the 22-byte compressed address.
fn compressed(adrs: *const Address) [22]u8 {
    return [1]u8{adrs[3]} ++ adrs[8..16].* ++ [1]u8{adrs[19]} ++ adrs[20..32].*;
}

pub fn Scheme(comptime p: Parameters) type {
    return struct {
        const n: usize = p.n;

        const len = p.length();

        const hp: usize = p.hp;

        const a: usize = p.a;

        const k: usize = p.k;

        const d: usize = p.d;

        const xmss_size = (len + hp) * n;

        const fors_size = k * (a + 1) * n;

        const Node = [n]u8;

        const uses_sha512 = !p.shake and n > 16;

        // F, H, T and PRF bound to one public seed. For SHA-2 the block holding PK.seed and its
        // zero padding is hashed once and that state is copied for every call.
        const Hashes = struct {
            pk_seed: Node,
            sk_seed: Node,
            small: if (p.shake) void else sha2.Sha256,
            large: if (uses_sha512) sha2.Sha512 else void,

            fn init(pk_seed: *const Node, sk_seed: *const Node) Hashes {
                var self: Hashes = .{ .pk_seed = pk_seed.*, .sk_seed = sk_seed.*, .small = undefined, .large = undefined };

                if (!p.shake) {
                    var block: [128]u8 = @splat(0);

                    @memcpy(block[0..n], pk_seed);

                    self.small = .init(&sha2.iv_256);

                    self.small.update(block[0..64]);

                    if (uses_sha512) {
                        self.large = .init(&sha2.iv_512);

                        self.large.update(&block);
                    }
                }

                return self;
            }

            fn wipe(self: *Hashes) void {
                ct.wipe(&self.sk_seed);
            }

            // F and PRF take one Keccak permutation or one SHA-256 compression after the seed
            // block; so does H, with SHA-512 above category 1.
            fn short(self: *const Hashes, adrs: *const Address, message: []const u8, wide: bool, out: *Node) void {
                if (p.shake) {
                    primitives.shake256Short(&.{ &self.pk_seed, adrs, message }, out);

                    return;
                }

                const address = compressed(adrs);

                if (uses_sha512 and wide) {
                    primitives.sha512Finish(&self.large.state, 128, &.{ &address, message }, out);
                } else {
                    primitives.sha256Finish(&self.small.state, 64, &.{ &address, message }, out);
                }
            }

            fn f(self: *const Hashes, adrs: *const Address, message: *const Node, out: *Node) void {
                self.short(adrs, message, false, out);
            }

            fn h(self: *const Hashes, adrs: *const Address, message: *const [2 * n]u8, out: *Node) void {
                self.short(adrs, message, true, out);
            }

            fn t(self: *const Hashes, adrs: *const Address, message: []const u8, out: *Node) void {
                if (p.shake) {
                    var xof = hash.shake256.create();

                    xof.update(&self.pk_seed);

                    xof.update(adrs);

                    xof.update(message);

                    xof.read(out);
                } else {
                    const address = compressed(adrs);

                    var engine = if (uses_sha512) self.large else self.small;

                    engine.update(&address);

                    engine.update(message);

                    const digest = engine.digest();

                    out.* = digest[0..n].*;
                }
            }

            fn prf(self: *const Hashes, adrs: *const Address, out: *Node) void {
                self.f(adrs, &self.sk_seed, out);
            }
        };

        fn chain(hashes: *const Hashes, x: *Node, start: usize, steps: usize, adrs: *Address) void {
            for (start..start + steps) |j| {
                setHash(adrs, @intCast(j));

                hashes.f(adrs, x, x);
            }
        }

        fn base2b(data: []const u8, comptime b: u5, out: []u32) void {
            var total: u32 = 0;

            var bits: u5 = 0;

            var offset: usize = 0;

            for (out) |*value| {
                while (bits < b) : (bits += 8) {
                    total = (total << 8) | data[offset];

                    offset += 1;
                }

                bits -= b;

                value.* = (total >> bits) & ((1 << b) - 1);
            }
        }

        fn wotsDigits(message: *const Node) [len]u32 {
            var digits: [len]u32 = undefined;

            base2b(message, 4, digits[0 .. 2 * n]);

            var checksum: u32 = 0;

            for (digits[0 .. 2 * n]) |digit| checksum += 15 - digit;

            checksum <<= 4;

            const bytes = [2]u8{ @truncate(checksum >> 8), @truncate(checksum) };

            base2b(&bytes, 4, digits[2 * n ..]);

            return digits;
        }

        fn secretAddress(adrs: *const Address, kind: u32) Address {
            var sk_adrs = adrs.*;

            setType(&sk_adrs, kind);

            setKeyPair(&sk_adrs, keyPair(adrs));

            return sk_adrs;
        }

        fn wotsPublic(hashes: *const Hashes, adrs: *const Address, values: *const [len * n]u8, out: *Node) void {
            const pk_adrs = secretAddress(adrs, wots_pk);

            hashes.t(&pk_adrs, values, out);
        }

        fn wotsKeyGen(hashes: *const Hashes, adrs: *Address, out: *Node) void {
            var values: [len * n]u8 = undefined;

            var sk_adrs = secretAddress(adrs, wots_prf);

            for (0..len) |i| {
                const value = values[i * n ..][0..n];

                setChain(&sk_adrs, @intCast(i));

                hashes.prf(&sk_adrs, value);

                setChain(adrs, @intCast(i));

                chain(hashes, value, 0, 15, adrs);
            }

            wotsPublic(hashes, adrs, &values, out);
        }

        fn wotsSign(hashes: *const Hashes, message: *const Node, adrs: *Address, out: *[len * n]u8) void {
            const digits = wotsDigits(message);

            var sk_adrs = secretAddress(adrs, wots_prf);

            for (digits, 0..) |digit, i| {
                const value = out[i * n ..][0..n];

                setChain(&sk_adrs, @intCast(i));

                hashes.prf(&sk_adrs, value);

                setChain(adrs, @intCast(i));

                chain(hashes, value, 0, digit, adrs);
            }
        }

        fn wotsPublicFromSignature(hashes: *const Hashes, signature: *const [len * n]u8, message: *const Node, adrs: *Address, out: *Node) void {
            const digits = wotsDigits(message);

            var values: [len * n]u8 = signature.*;

            for (digits, 0..) |digit, i| {
                setChain(adrs, @intCast(i));

                chain(hashes, values[i * n ..][0..n], digit, 15 - digit, adrs);
            }

            wotsPublic(hashes, adrs, &values, out);
        }

        fn xmssNode(hashes: *const Hashes, i: u32, z: usize, adrs: *Address, out: *Node) void {
            if (z == 0) {
                setType(adrs, wots_hash);

                setKeyPair(adrs, i);

                wotsKeyGen(hashes, adrs, out);

                return;
            }

            var children: [2 * n]u8 = undefined;

            xmssNode(hashes, 2 * i, z - 1, adrs, children[0..n]);

            xmssNode(hashes, 2 * i + 1, z - 1, adrs, children[n..]);

            setType(adrs, tree);

            setTreeHeight(adrs, @intCast(z));

            setTreeIndex(adrs, i);

            hashes.h(adrs, &children, out);
        }

        fn xmssSign(hashes: *const Hashes, message: *const Node, index: u32, adrs: *Address, out: *[xmss_size]u8) void {
            for (0..hp) |j| {
                xmssNode(hashes, (index >> @intCast(j)) ^ 1, j, adrs, out[(len + j) * n ..][0..n]);
            }

            setType(adrs, wots_hash);

            setKeyPair(adrs, index);

            wotsSign(hashes, message, adrs, out[0 .. len * n]);
        }

        fn climb(hashes: *const Hashes, node: *Node, index: u32, auth: []const u8, adrs: *Address) void {
            var pair: [2 * n]u8 = undefined;

            for (0..auth.len / n) |j| {
                const sibling = auth[j * n ..][0..n];

                setTreeHeight(adrs, @intCast(j + 1));

                if ((index >> @intCast(j)) & 1 == 0) {
                    setTreeIndex(adrs, treeIndex(adrs) / 2);

                    pair = node.* ++ sibling.*;
                } else {
                    setTreeIndex(adrs, (treeIndex(adrs) - 1) / 2);

                    pair = sibling.* ++ node.*;
                }

                hashes.h(adrs, &pair, node);
            }
        }

        fn xmssPublicFromSignature(hashes: *const Hashes, index: u32, signature: *const [xmss_size]u8, message: *const Node, adrs: *Address, out: *Node) void {
            setType(adrs, wots_hash);

            setKeyPair(adrs, index);

            wotsPublicFromSignature(hashes, signature[0 .. len * n], message, adrs, out);

            setType(adrs, tree);

            setTreeIndex(adrs, index);

            climb(hashes, out, index, signature[len * n ..], adrs);
        }

        fn hypertreeSign(hashes: *const Hashes, message: *const Node, tree_index: u64, leaf_index: u32, out: *[d * xmss_size]u8) void {
            var adrs: Address = @splat(0);

            var idx_tree = tree_index;

            var leaf = leaf_index;

            var current: Node = message.*;

            setTree(&adrs, idx_tree);

            for (0..d) |j| {
                if (j > 0) {
                    leaf = @intCast(idx_tree & ((1 << hp) - 1));

                    idx_tree >>= @intCast(hp);

                    setLayer(&adrs, @intCast(j));

                    setTree(&adrs, idx_tree);
                }

                const part = out[j * xmss_size ..][0..xmss_size];

                xmssSign(hashes, &current, leaf, &adrs, part);

                if (j + 1 < d) {
                    const signed = current;

                    xmssPublicFromSignature(hashes, leaf, part, &signed, &adrs, &current);
                }
            }
        }

        fn hypertreeVerify(hashes: *const Hashes, message: *const Node, signature: *const [d * xmss_size]u8, tree_index: u64, leaf_index: u32, pk_root: *const Node) bool {
            var adrs: Address = @splat(0);

            var idx_tree = tree_index;

            var leaf = leaf_index;

            var node: Node = message.*;

            setTree(&adrs, idx_tree);

            for (0..d) |j| {
                if (j > 0) {
                    leaf = @intCast(idx_tree & ((1 << hp) - 1));

                    idx_tree >>= @intCast(hp);

                    setLayer(&adrs, @intCast(j));

                    setTree(&adrs, idx_tree);
                }

                const signed = node;

                xmssPublicFromSignature(hashes, leaf, signature[j * xmss_size ..][0..xmss_size], &signed, &adrs, &node);
            }

            return std.mem.eql(u8, &node, pk_root);
        }

        fn forsSecret(hashes: *const Hashes, adrs: *const Address, index: u32, out: *Node) void {
            var sk_adrs = secretAddress(adrs, fors_prf);

            setTreeIndex(&sk_adrs, index);

            hashes.prf(&sk_adrs, out);
        }

        fn forsNode(hashes: *const Hashes, i: u32, z: usize, adrs: *Address, out: *Node) void {
            if (z == 0) {
                var secret: Node = undefined;

                defer ct.wipe(&secret);

                forsSecret(hashes, adrs, i, &secret);

                setTreeHeight(adrs, 0);

                setTreeIndex(adrs, i);

                hashes.f(adrs, &secret, out);

                return;
            }

            var children: [2 * n]u8 = undefined;

            forsNode(hashes, 2 * i, z - 1, adrs, children[0..n]);

            forsNode(hashes, 2 * i + 1, z - 1, adrs, children[n..]);

            setTreeHeight(adrs, @intCast(z));

            setTreeIndex(adrs, i);

            hashes.h(adrs, &children, out);
        }

        fn forsIndices(digest: []const u8) [k]u32 {
            var indices: [k]u32 = undefined;

            base2b(digest, @intCast(a), &indices);

            return indices;
        }

        fn forsSign(hashes: *const Hashes, digest: []const u8, adrs: *Address, out: *[fors_size]u8) void {
            for (forsIndices(digest), 0..) |index, i| {
                const part = out[i * (a + 1) * n ..][0 .. (a + 1) * n];

                const base: u32 = @intCast(i << @intCast(a));

                forsSecret(hashes, adrs, base + index, part[0..n]);

                for (0..a) |j| {
                    const sibling: u32 = @intCast((i << @intCast(a - j)) + ((index >> @intCast(j)) ^ 1));

                    forsNode(hashes, sibling, j, adrs, part[(j + 1) * n ..][0..n]);
                }
            }
        }

        fn forsPublicFromSignature(hashes: *const Hashes, signature: *const [fors_size]u8, digest: []const u8, adrs: *Address, out: *Node) void {
            var roots: [k * n]u8 = undefined;

            for (forsIndices(digest), 0..) |index, i| {
                const part = signature[i * (a + 1) * n ..][0 .. (a + 1) * n];

                const node = roots[i * n ..][0..n];

                setTreeHeight(adrs, 0);

                setTreeIndex(adrs, @intCast((i << @intCast(a)) + index));

                hashes.f(adrs, part[0..n], node);

                climb(hashes, node, index, part[n..], adrs);
            }

            const pk_adrs = secretAddress(adrs, fors_roots);

            hashes.t(&pk_adrs, &roots, out);
        }

        pub fn root(sk_seed: *const Node, pk_seed: *const Node) Node {
            var hashes = Hashes.init(pk_seed, sk_seed);

            defer hashes.wipe();

            var adrs: Address = @splat(0);

            setLayer(&adrs, p.d - 1);

            var out: Node = undefined;

            xmssNode(&hashes, 0, hp, &adrs, &out);

            return out;
        }

        // H_msg (FIPS 205, section 11): SHAKE256, or MGF1 over SHA-256 or SHA-512 of the
        // randomizer, the public key and M'.
        fn messageDigest(r: *const Node, pk_seed: *const Node, pk_root: *const Node, message: []const []const u8) [p.m]u8 {
            var out: [p.m]u8 = undefined;

            if (p.shake) {
                var xof = hash.shake256.create();

                for ([_][]const u8{ r, pk_seed, pk_root }) |part| xof.update(part);

                for (message) |part| xof.update(part);

                xof.read(&out);

                return out;
            }

            const algorithm = if (n == 16) hash.sha_256 else hash.sha_512;

            const size = algorithm.digest_size;

            var hasher = algorithm.create();

            for ([_][]const u8{ r, pk_seed, pk_root }) |part| hasher.update(part);

            for (message) |part| hasher.update(part);

            var seed: [2 * n + size + 4]u8 = undefined;

            seed[0..n].* = r.*;

            seed[n..][0..n].* = pk_seed.*;

            hasher.digest(seed[2 * n ..][0..size]);

            var offset: usize = 0;

            var counter: u32 = 0;

            while (offset < out.len) : (counter += 1) {
                std.mem.writeInt(u32, seed[2 * n + size ..][0..4], counter, .big);

                var block: [size]u8 = undefined;

                algorithm.digest(&seed, &block);

                const take = @min(size, out.len - offset);

                @memcpy(out[offset..][0..take], block[0..take]);

                offset += take;
            }

            return out;
        }

        // PRF_msg: SHAKE256, or HMAC-SHA-256 or HMAC-SHA-512 truncated to n bytes.
        fn messageRandomizer(sk_prf: *const Node, opt_rand: *const Node, message: []const []const u8, out: *Node) void {
            if (p.shake) {
                var xof = hash.shake256.create();

                defer ct.wipe(std.mem.asBytes(&xof));

                xof.update(sk_prf);

                xof.update(opt_rand);

                for (message) |part| xof.update(part);

                xof.read(out);

                return;
            }

            const algorithm = if (n == 16) hash.hmac_sha_256 else hash.hmac_sha_512;

            var mac = algorithm.create(sk_prf);

            defer ct.wipe(std.mem.asBytes(&mac));

            mac.update(opt_rand);

            for (message) |part| mac.update(part);

            var full: [algorithm.digest_size]u8 = undefined;

            mac.digest(&full);

            out.* = full[0..n].*;
        }

        const Split = struct {
            digest: [(k * a + 7) / 8]u8,
            tree: u64,
            leaf: u32,
        };

        fn split(digest: *const [p.m]u8) Split {
            const md_size = (k * a + 7) / 8;

            const tree_bits = p.h - p.h / p.d;

            const tree_size = (tree_bits + 7) / 8;

            const leaf_size = (hp + 7) / 8;

            var tree_value: u64 = 0;

            for (digest[md_size..][0..tree_size]) |byte| tree_value = (tree_value << 8) | byte;

            var leaf_value: u32 = 0;

            for (digest[md_size + tree_size ..][0..leaf_size]) |byte| leaf_value = (leaf_value << 8) | byte;

            return .{
                .digest = digest[0..md_size].*,
                .tree = tree_value & (~@as(u64, 0) >> @intCast(64 - tree_bits)),
                .leaf = leaf_value & ((1 << hp) - 1),
            };
        }

        pub fn keyGen(sk_seed: *const Node, sk_prf: *const Node, pk_seed: *const Node, sk: *[4 * n]u8, pk: *[2 * n]u8) void {
            const pk_root = root(sk_seed, pk_seed);

            sk.* = sk_seed.* ++ sk_prf.* ++ pk_seed.* ++ pk_root;

            pk.* = pk_seed.* ++ pk_root;
        }

        pub fn sign(sk: *const [4 * n]u8, message: []const []const u8, opt_rand: *const Node, signature: *[p.signatureSize()]u8) void {
            const pk_seed = sk[2 * n ..][0..n];

            const pk_root = sk[3 * n ..][0..n];

            var hashes = Hashes.init(pk_seed, sk[0..n]);

            defer hashes.wipe();

            const r = signature[0..n];

            messageRandomizer(sk[n..][0..n], opt_rand, message, r);

            const digest = messageDigest(r, pk_seed, pk_root, message);

            const parts = split(&digest);

            var adrs: Address = @splat(0);

            setTree(&adrs, parts.tree);

            setType(&adrs, fors_tree);

            setKeyPair(&adrs, parts.leaf);

            const fors = signature[n..][0..fors_size];

            forsSign(&hashes, &parts.digest, &adrs, fors);

            var pk_fors: Node = undefined;

            forsPublicFromSignature(&hashes, fors, &parts.digest, &adrs, &pk_fors);

            hypertreeSign(&hashes, &pk_fors, parts.tree, parts.leaf, signature[n + fors_size ..]);
        }

        pub fn verify(pk: *const [2 * n]u8, message: []const []const u8, signature: *const [p.signatureSize()]u8) bool {
            const pk_seed = pk[0..n];

            const pk_root = pk[n..][0..n];

            const unused: Node = @splat(0);

            const hashes = Hashes.init(pk_seed, &unused);

            const digest = messageDigest(signature[0..n], pk_seed, pk_root, message);

            const parts = split(&digest);

            var adrs: Address = @splat(0);

            setTree(&adrs, parts.tree);

            setType(&adrs, fors_tree);

            setKeyPair(&adrs, parts.leaf);

            var pk_fors: Node = undefined;

            forsPublicFromSignature(&hashes, signature[n..][0..fors_size], &parts.digest, &adrs, &pk_fors);

            return hypertreeVerify(&hashes, &pk_fors, signature[n + fors_size ..], parts.tree, parts.leaf, pk_root);
        }
    };
}

const std = @import("std");
const builtin = @import("builtin");

const ct = @import("ct.zig");
const keccak = @import("keccak.zig");
const primitives = @import("primitives.zig");
const sha2 = @import("sha2.zig");
const vec = @import("vector.zig");

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

// Independent SHA-2 computations run side by side in the lanes of vectors. Eight lanes keep the
// vector units busy despite the serial rounds of each computation; more lanes cost as much per
// lane and leave more of them idle when the work does not fill them. A target without vector
// registers computes one at a time: emulated lanes cost as much each and spill to the stack.
// RV64 computes two: LLVM (Zig 0.16.0) miscompiles rotates of one-element vectors there.
const max_lanes = if (std.simd.suggestVectorLength(u32) != null) 8 else if (builtin.cpu.arch == .riscv64) 2 else 1;

// Trees are built from subtrees of at most 2^chunk_height leaves, so that the node buffers stay
// small for the FORS trees of height 14.
const chunk_height = 8;

const max_tree_height = 14;

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

            // H takes one Keccak permutation, or one SHA-2 compression after the seed block: SHA-256
            // in category 1 and SHA-512 above.
            fn h(self: *const Hashes, adrs: *const Address, message: *const [2 * n]u8, out: *Node) void {
                if (p.shake) return primitives.shake256Short(&.{ &self.pk_seed, adrs, message }, out);

                const address = compressed(adrs);

                if (uses_sha512) {
                    primitives.sha512Finish(&self.large.state, 128, &.{ &address, message }, out);
                } else {
                    primitives.sha256Finish(&self.small.state, 64, &.{ &address, message }, out);
                }
            }

            fn t(self: *const Hashes, adrs: *const Address, message: []const u8, out: *Node) void {
                if (p.shake) {
                    var xof = primitives.shake256Sponge();

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
        };

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

        // The WOTS signature of `keypair` under a hypertree layer, taken from the chains while
        // its leaf is computed.
        const Capture = struct {
            keypair: u32,
            digits: *const [len]u32,
            out: *[len * n]u8,
        };

        // The FORS secret value of leaf `index`, taken while its leaf is computed.
        const ForsCapture = struct {
            index: u32,
            out: *Node,
        };

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

        fn forsIndices(digest: []const u8) [k]u32 {
            var indices: [k]u32 = undefined;

            base2b(digest, @intCast(a), &indices);

            return indices;
        }

        // The SHA-2 hashes of L computations at once: lane l of every vector belongs to the l-th.
        // Messages are kept as big-endian 32-bit words; after the 22-byte compressed address they
        // sit at a two-byte offset, so every message word is split across two block words.
        fn Lanes(comptime L: usize) type {
            return struct {
                const V = @Vector(L, u32);

                const V64 = @Vector(L, u64);

                const words = n / 4;

                const Words = [words]V;

                // The layer and tree fields of an address, which every lane shares.
                const Base = struct {
                    first: V,
                    second: V,
                    third: u32,

                    fn init(adrs: *const Address) Base {
                        const c = compressed(adrs);

                        return .{
                            .first = splat(std.mem.readInt(u32, c[0..4], .big)),
                            .second = splat(std.mem.readInt(u32, c[4..8], .big)),
                            .third = @as(u32, c[8]) << 24,
                        };
                    }
                };

                // The compressed address as the first five block words, and the two bytes that
                // start the sixth in the high half of `low`.
                const Head = struct {
                    words: [5]V,
                    low: V,

                    fn init(base: Base, kind: u32, keypair: V, height: V, index: V) Head {
                        return .{
                            .words = .{
                                base.first,
                                base.second,
                                splat(base.third | kind << 16) | shr(keypair, 16),
                                shl(keypair, 16) | shr(height, 16),
                                shl(height, 16) | shr(index, 16),
                            },
                            .low = shl(index, 16),
                        };
                    }
                };

                fn splat(value: u32) V {
                    return @splat(value);
                }

                fn shl(x: V, comptime r: u5) V {
                    return x << @as(@Vector(L, u5), @splat(r));
                }

                fn shr(x: V, comptime r: u5) V {
                    return x >> @as(@Vector(L, u5), @splat(r));
                }

                fn join(high: V, low: V) V64 {
                    return @as(V64, @intCast(high)) << @as(@Vector(L, u6), @splat(32)) | @as(V64, @intCast(low));
                }

                // The block that follows the PK.seed block for an m-word message, counted in
                // 32-bit words: 16 for SHA-256, 32 for SHA-512.
                fn fill(comptime size: usize, comptime m: usize, head: Head, message: *const [m]V, out: *[size]V) void {
                    out[0..5].* = head.words;

                    out[5] = head.low | shr(message[0], 16);

                    inline for (1..m) |i| {
                        out[5 + i] = shl(message[i - 1], 16) | shr(message[i], 16);
                    }

                    out[5 + m] = shl(message[m - 1], 16) | splat(0x8000);

                    inline for (6 + m..size - 1) |i| {
                        out[i] = splat(0);
                    }

                    out[size - 1] = splat((4 * size + 22 + 4 * m) * 8);
                }

                fn seeded256(hashes: *const Hashes) [8]V {
                    var state: [8]V = undefined;

                    for (&state, hashes.small.state) |*word, value| word.* = @splat(value);

                    return state;
                }

                fn seeded512(hashes: *const Hashes) [8]V64 {
                    var state: [8]V64 = undefined;

                    for (&state, hashes.large.state) |*word, value| word.* = @splat(value);

                    return state;
                }

                fn compress512(state: *[8]V64, block: *const [32]V) void {
                    var wide: [16]V64 = undefined;

                    for (&wide, 0..) |*word, i| word.* = join(block[2 * i], block[2 * i + 1]);

                    sha2.rounds512(V64, state, &wide);
                }

                fn output512(state: *const [8]V64, out: *Words) void {
                    for (0..words / 2) |i| {
                        out[2 * i] = @truncate(state[i] >> @as(@Vector(L, u6), @splat(32)));

                        out[2 * i + 1] = @truncate(state[i]);
                    }
                }

                // F and PRF, which use SHA-256 in every parameter set.
                fn f(hashes: *const Hashes, head: Head, message: *const Words, out: *Words) void {
                    var block: [16]V = undefined;

                    defer ct.wipe(std.mem.asBytes(&block));

                    fill(16, words, head, message, &block);

                    var state = seeded256(hashes);

                    defer ct.wipe(std.mem.asBytes(&state));

                    sha2.rounds256(V, &state, &block);

                    out.* = state[0..words].*;
                }

                fn h(hashes: *const Hashes, head: Head, message: *const [2 * words]V, out: *Words) void {
                    if (uses_sha512) {
                        var block: [32]V = undefined;

                        fill(32, 2 * words, head, message, &block);

                        var state = seeded512(hashes);

                        compress512(&state, &block);

                        output512(&state, out);
                    } else {
                        var block: [16]V = undefined;

                        fill(16, 2 * words, head, message, &block);

                        var state = seeded256(hashes);

                        sha2.rounds256(V, &state, &block);

                        out.* = state[0..words].*;
                    }
                }

                // Lane l takes the big-endian words of sources[l]; the remaining lanes are zero.
                fn gather(comptime m: usize, sources: []const [4 * m]u8, out: *[m]V) void {
                    var lanes: [m][L]u32 = @splat(@splat(0));

                    for (sources, 0..) |*source, l| {
                        for (0..m) |w| lanes[w][l] = std.mem.readInt(u32, source[4 * w ..][0..4], .big);
                    }

                    for (out, lanes) |*word, values| word.* = values;
                }

                fn scatter(value: *const Words, out: []Node) void {
                    var lanes: [words][L]u32 = undefined;

                    for (&lanes, value) |*values, word| values.* = word;

                    for (out, 0..) |*node, l| {
                        for (0..words) |w| std.mem.writeInt(u32, node[4 * w ..][0..4], lanes[w][l], .big);
                    }
                }

                fn extract(value: *const Words, lane: usize, out: *Node) void {
                    for (value, 0..) |word, w| {
                        const values: [L]u32 = word;

                        std.mem.writeInt(u32, out[4 * w ..][0..4], values[lane], .big);
                    }
                }

                // T over the WOTS public keys of L leaves, fed one chain end at a time.
                const Stream = struct {
                    state: if (uses_sha512) [8]V64 else [8]V,
                    block: [size]V,
                    count: usize,
                    carry: V,

                    const size = if (uses_sha512) 32 else 16;

                    fn init(hashes: *const Hashes, head: Head) Stream {
                        var self: Stream = .{ .state = if (uses_sha512) seeded512(hashes) else seeded256(hashes), .block = undefined, .count = 5, .carry = head.low };

                        self.block[0..5].* = head.words;

                        return self;
                    }

                    fn compress(self: *Stream) void {
                        if (uses_sha512) compress512(&self.state, &self.block) else sha2.rounds256(V, &self.state, &self.block);
                    }

                    fn push(self: *Stream, word: V) void {
                        self.block[self.count] = word;

                        self.count += 1;

                        if (self.count == size) {
                            self.compress();

                            self.count = 0;
                        }
                    }

                    fn absorb(self: *Stream, value: *const Words) void {
                        for (value) |word| {
                            self.push(self.carry | shr(word, 16));

                            self.carry = shl(word, 16);
                        }
                    }

                    // `bytes` is the message length after the PK.seed block. The bit length fills
                    // the last two words of a block, four for SHA-512.
                    fn finish(self: *Stream, comptime bytes: usize, out: *Words) void {
                        const field = size / 8;

                        self.push(self.carry | splat(0x8000));

                        if (self.count > size - field) {
                            @memset(self.block[self.count..], splat(0));

                            self.compress();

                            self.count = 0;
                        }

                        @memset(self.block[self.count .. size - 1], splat(0));

                        self.block[size - 1] = splat((4 * size + bytes) * 8);

                        self.compress();

                        if (uses_sha512) output512(&self.state, out) else out.* = self.state[0..words].*;
                    }
                };

                // The WOTS public keys of key pairs first .. first + out.len - 1 of one tree,
                // one key pair per lane.
                fn leaves(hashes: *const Hashes, adrs: *const Address, first: u32, out: []Node, capture: ?*const Capture) void {
                    const base: Base = .init(adrs);

                    const keypair = std.simd.iota(u32, L) + splat(first);

                    var stream: Stream = .init(hashes, .init(base, wots_pk, keypair, splat(0), splat(0)));

                    var secret: Words = undefined;

                    var value: Words = undefined;

                    defer {
                        ct.wipe(std.mem.asBytes(&secret));

                        ct.wipe(std.mem.asBytes(&value));
                    }

                    for (&secret, 0..) |*word, i| word.* = splat(std.mem.readInt(u32, hashes.sk_seed[4 * i ..][0..4], .big));

                    var lane: ?usize = null;

                    if (capture) |c| {
                        if (c.keypair >= first and c.keypair - first < out.len) lane = c.keypair - first;
                    }

                    for (0..len) |i| {
                        const chain_index = splat(@intCast(i));

                        f(hashes, .init(base, wots_prf, keypair, chain_index, splat(0)), &secret, &value);

                        for (0..15) |j| {
                            if (lane) |l| {
                                if (capture.?.digits[i] == j) extract(&value, l, capture.?.out[i * n ..][0..n]);
                            }

                            f(hashes, .init(base, wots_hash, keypair, chain_index, splat(@intCast(j))), &value, &value);
                        }

                        if (lane) |l| {
                            if (capture.?.digits[i] == 15) extract(&value, l, capture.?.out[i * n ..][0..n]);
                        }

                        stream.absorb(&value);
                    }

                    var root_words: Words = undefined;

                    stream.finish(22 + len * n, &root_words);

                    scatter(&root_words, out);
                }

                // FORS leaves first .. first + out.len - 1 (tree indices), one per lane.
                fn forsLeaves(hashes: *const Hashes, adrs: *const Address, first: u32, out: []Node, capture: ?ForsCapture) void {
                    const base: Base = .init(adrs);

                    const keypair = splat(keyPair(adrs));

                    const index = std.simd.iota(u32, L) + splat(first);

                    var secret: Words = undefined;

                    var value: Words = undefined;

                    defer {
                        ct.wipe(std.mem.asBytes(&secret));

                        ct.wipe(std.mem.asBytes(&value));
                    }

                    for (&secret, 0..) |*word, i| word.* = splat(std.mem.readInt(u32, hashes.sk_seed[4 * i ..][0..4], .big));

                    f(hashes, .init(base, fors_prf, keypair, splat(0), index), &secret, &value);

                    if (capture) |c| {
                        if (c.index >= first and c.index - first < out.len) extract(&value, c.index - first, c.out);
                    }

                    var leaf: Words = undefined;

                    f(hashes, .init(base, fors_tree, keypair, splat(0), index), &value, &leaf);

                    scatter(&leaf, out);
                }

                // Parents first .. first + out.len - 1 at `height` of the children in pairs.
                fn parents(hashes: *const Hashes, adrs: *const Address, kind: u32, height: u32, first: u32, children: []const Node, out: []Node) void {
                    var message: [2 * words]V = undefined;

                    gather(2 * words, std.mem.bytesAsSlice([2 * n]u8, std.mem.sliceAsBytes(children)), &message);

                    var node: Words = undefined;

                    h(hashes, .init(.init(adrs), kind, splat(keyPair(adrs)), splat(height), std.simd.iota(u32, L) + splat(first)), &message, &node);

                    scatter(&node, out);
                }

                // The FORS roots implied by a signature, one tree per lane.
                fn forsRoots(hashes: *const Hashes, adrs: *const Address, signature: *const [fors_size]u8, indices: *const [k]u32, roots: *[k]Node) void {
                    const base: Base = .init(adrs);

                    const keypair = splat(keyPair(adrs));

                    var first: usize = 0;

                    while (first < k) : (first += L) {
                        const count: usize = @min(L, k - first);

                        var lanes: [L]u32 = @splat(0);

                        var nodes: [L]Node = undefined;

                        for (0..count) |l| {
                            lanes[l] = @intCast(((first + l) << a) + indices[first + l]);

                            nodes[l] = signature[(first + l) * (a + 1) * n ..][0..n].*;
                        }

                        var index: V = lanes;

                        var value: Words = undefined;

                        gather(words, nodes[0..count], &value);

                        var node: Words = undefined;

                        f(hashes, .init(base, fors_tree, keypair, splat(0), index), &value, &node);

                        for (0..a) |z| {
                            for (0..count) |l| nodes[l] = signature[(first + l) * (a + 1) * n + (z + 1) * n ..][0..n].*;

                            var sibling: Words = undefined;

                            gather(words, nodes[0..count], &sibling);

                            const right = (index & splat(1)) == splat(1);

                            var message: [2 * words]V = undefined;

                            for (0..words) |w| {
                                message[w] = @select(u32, right, sibling[w], node[w]);

                                message[words + w] = @select(u32, right, node[w], sibling[w]);
                            }

                            index = shr(index, 1);

                            h(hashes, .init(base, fors_tree, keypair, splat(@intCast(z + 1)), index), &message, &node);
                        }

                        scatter(&node, roots[first..][0..count]);
                    }
                }

                // Completes every WOTS chain of a signature from its digit to the end.
                fn chains(hashes: *const Hashes, adrs: *const Address, keypair: u32, digits: *const [len]u32, values: *[len * n]u8) void {
                    const base: Base = .init(adrs);

                    const ends: [len]u32 = @splat(15);

                    var lanes: vec.ChainLanes(L, words) = .init(digits, &ends, values);

                    while (lanes.running > 0) {
                        var value = lanes.current();

                        f(hashes, .init(base, wots_hash, splat(keypair), lanes.chain, lanes.step), &value, &value);

                        lanes.advance(&value);
                    }
                }
            };
        }

        // SHAKE256(PK.seed || ADRS || M) of four computations at once with keccak.permute4: lane l
        // of every batch belongs to the l-th. Missing lanes compute values that nobody reads.
        const Shake4 = struct {
            const lanes = 4;

            // F, H and PRF take m = n or 2n bytes, which with the seed and the address fill less
            // than one block, a whole number of lanes: each state is written lane by lane, padding
            // included, straight from the inputs. T over a WOTS public key, which is far longer,
            // is absorbed in parts by `leaves`. Verification hashes only public values, and leaves
            // its states unwiped.
            fn shake(hashes: *const Hashes, adrs: *const [lanes]Address, comptime m: usize, comptime secret: bool, messages: [lanes][]const u8, out: [lanes]*Node) void {
                const length = n + 32 + m;

                comptime std.debug.assert(length % 8 == 0 and length < 136);

                var seed: [n / 8]u64 = undefined;

                for (&seed, 0..) |*word, i| word.* = std.mem.readInt(u64, hashes.pk_seed[8 * i ..][0..8], .little);

                var states: [lanes][25]u64 = undefined;

                defer if (secret) ct.wipe(std.mem.asBytes(&states));

                for (&states, adrs, messages) |*state, *address, message| {
                    std.debug.assert(message.len == m);

                    state[0 .. n / 8].* = seed;

                    inline for (0..4) |i| state[n / 8 + i] = std.mem.readInt(u64, address[8 * i ..][0..8], .little);

                    inline for (0..m / 8) |i| state[(n + 32) / 8 + i] = std.mem.readInt(u64, message[8 * i ..][0..8], .little);

                    inline for (length / 8..25) |i| state[i] = 0;

                    state[length / 8] ^= 0x1f;

                    state[16] ^= @as(u64, 0x80) << 56;
                }

                keccak.permute4(&states);

                for (&states, out) |*state, node| {
                    inline for (0..n / 8) |i| std.mem.writeInt(u64, node[8 * i ..][0..8], state[i], .little);
                }
            }

            fn addresses(adrs: *const Address, kind: u32, keypair: [lanes]u32) [lanes]Address {
                var out: [lanes]Address = undefined;

                for (&out, keypair) |*address, pair| {
                    address.* = adrs.*;

                    setType(address, kind);

                    setKeyPair(address, pair);
                }

                return out;
            }

            fn same(message: []const u8) [lanes][]const u8 {
                return @splat(message);
            }

            fn consecutive(first: u32) [lanes]u32 {
                return .{ first, first + 1, first + 2, first + 3 };
            }

            // The WOTS public keys of key pairs first .. first + out.len - 1 of one tree. Each chain
            // end goes into the public key hash as soon as it is computed.
            fn leaves(hashes: *const Hashes, adrs: *const Address, first: u32, out: []Node, capture: ?*const Capture) void {
                var values: [lanes]Node = undefined;

                var public_key: keccak.Sponge4 = .start(136);

                defer {
                    ct.wipe(std.mem.asBytes(&values));

                    public_key.wipe();
                }

                public_key.absorb(same(&hashes.pk_seed));

                const pk_adrs = addresses(adrs, wots_pk, consecutive(first));

                public_key.absorb(.{ &pk_adrs[0], &pk_adrs[1], &pk_adrs[2], &pk_adrs[3] });

                var prf_adrs = addresses(adrs, wots_prf, consecutive(first));

                var chain_adrs = addresses(adrs, wots_hash, consecutive(first));

                var lane: ?usize = null;

                if (capture) |c| {
                    if (c.keypair >= first and c.keypair - first < out.len) lane = c.keypair - first;
                }

                const nodes: [lanes]*Node = .{ &values[0], &values[1], &values[2], &values[3] };

                const messages: [lanes][]const u8 = .{ &values[0], &values[1], &values[2], &values[3] };

                for (0..len) |i| {
                    for (&prf_adrs, &chain_adrs) |*prf_address, *chain_address| {
                        setChain(prf_address, @intCast(i));

                        setChain(chain_address, @intCast(i));
                    }

                    shake(hashes, &prf_adrs, n, true, same(&hashes.sk_seed), nodes);

                    for (0..16) |j| {
                        if (lane) |l| {
                            if (capture.?.digits[i] == j) capture.?.out[i * n ..][0..n].* = nodes[l].*;
                        }

                        if (j == 15) break;

                        for (&chain_adrs) |*address| setHash(address, @intCast(j));

                        shake(hashes, &chain_adrs, n, true, messages, nodes);
                    }

                    public_key.absorb(messages);
                }

                var spare: [lanes]Node = undefined;

                var roots: [lanes]*Node = undefined;

                for (&roots, &spare, 0..) |*root_node, *slot, l| root_node.* = if (l < out.len) &out[l] else slot;

                public_key.finish(0x1f);

                public_key.squeeze(.{ roots[0], roots[1], roots[2], roots[3] });
            }

            // FORS leaves first .. first + out.len - 1 (tree indices).
            fn forsLeaves(hashes: *const Hashes, adrs: *const Address, first: u32, out: []Node, capture: ?ForsCapture) void {
                var secrets: [lanes]Node = undefined;

                defer ct.wipe(std.mem.asBytes(&secrets));

                var prf_adrs = addresses(adrs, fors_prf, @splat(keyPair(adrs)));

                var leaf_adrs = addresses(adrs, fors_tree, @splat(keyPair(adrs)));

                for (&prf_adrs, &leaf_adrs, consecutive(first)) |*prf_address, *leaf_address, index| {
                    setTreeIndex(prf_address, index);

                    setTreeIndex(leaf_address, index);
                }

                shake(hashes, &prf_adrs, n, true, same(&hashes.sk_seed), .{ &secrets[0], &secrets[1], &secrets[2], &secrets[3] });

                if (capture) |c| {
                    if (c.index >= first and c.index - first < out.len) c.out.* = secrets[c.index - first];
                }

                var spare: [lanes]Node = undefined;

                var leaves_out: [lanes]*Node = undefined;

                for (&leaves_out, &spare, 0..) |*leaf, *slot, l| leaf.* = if (l < out.len) &out[l] else slot;

                shake(hashes, &leaf_adrs, n, true, .{ &secrets[0], &secrets[1], &secrets[2], &secrets[3] }, leaves_out);
            }

            // Parents first .. first + out.len - 1 at `height` of the children in pairs.
            fn parents(hashes: *const Hashes, adrs: *const Address, kind: u32, height: u32, first: u32, children: []const Node, out: []Node) void {
                var pairs: [lanes][2 * n]u8 = undefined;

                for (&pairs, 0..) |*pair, l| {
                    if (l < out.len) pair.* = children[2 * l] ++ children[2 * l + 1];
                }

                var node_adrs = addresses(adrs, kind, @splat(keyPair(adrs)));

                for (&node_adrs, consecutive(first)) |*address, index| {
                    setTreeHeight(address, height);

                    setTreeIndex(address, index);
                }

                var spare: [lanes]Node = undefined;

                var nodes: [lanes]*Node = undefined;

                for (&nodes, &spare, 0..) |*node, *slot, l| node.* = if (l < out.len) &out[l] else slot;

                shake(hashes, &node_adrs, 2 * n, true, .{ &pairs[0], &pairs[1], &pairs[2], &pairs[3] }, nodes);
            }

            // The FORS roots implied by a signature, one tree per lane.
            fn forsRoots(hashes: *const Hashes, adrs: *const Address, signature: *const [fors_size]u8, indices: *const [k]u32, roots: *[k]Node) void {
                var first: usize = 0;

                while (first < k) : (first += lanes) {
                    const count: usize = @min(lanes, k - first);

                    var node_adrs = addresses(adrs, fors_tree, @splat(keyPair(adrs)));

                    var index: [lanes]u32 = @splat(0);

                    var nodes: [lanes]Node = @splat(@splat(0));

                    for (0..count) |l| {
                        index[l] = @intCast(((first + l) << a) + indices[first + l]);

                        nodes[l] = signature[(first + l) * (a + 1) * n ..][0..n].*;
                    }

                    for (&node_adrs, index) |*address, value| setTreeIndex(address, value);

                    const targets: [lanes]*Node = .{ &nodes[0], &nodes[1], &nodes[2], &nodes[3] };

                    shake(hashes, &node_adrs, n, false, .{ &nodes[0], &nodes[1], &nodes[2], &nodes[3] }, targets);

                    for (0..a) |z| {
                        var pairs: [lanes][2 * n]u8 = undefined;

                        for (&pairs, &nodes, &index, &node_adrs, 0..) |*pair, *node, *value, *address, l| {
                            const sibling: Node = if (l < count) signature[(first + l) * (a + 1) * n + (z + 1) * n ..][0..n].* else node.*;

                            pair.* = if (value.* & 1 == 1) sibling ++ node.* else node.* ++ sibling;

                            value.* >>= 1;

                            setTreeHeight(address, @intCast(z + 1));

                            setTreeIndex(address, value.*);
                        }

                        shake(hashes, &node_adrs, 2 * n, false, .{ &pairs[0], &pairs[1], &pairs[2], &pairs[3] }, targets);
                    }

                    @memcpy(roots[first..][0..count], nodes[0..count]);
                }
            }

            // Completes every WOTS chain of a signature from its digit to the end.
            fn chains(hashes: *const Hashes, adrs: *const Address, keypair: u32, digits: *const [len]u32, values: *[len * n]u8) void {
                const ends: [len]u32 = @splat(15);

                var schedule: vec.ChainLanes(lanes, n / 4) = .init(digits, &ends, values);

                var chain_adrs = addresses(adrs, wots_hash, @splat(keypair));

                while (schedule.running > 0) {
                    var nodes: [lanes]Node = undefined;

                    for (&nodes, &chain_adrs, 0..) |*node, *address, l| {
                        for (schedule.words, 0..) |word, w| std.mem.writeInt(u32, node[4 * w ..][0..4], word[l], .big);

                        setChain(address, schedule.chain[l]);

                        setHash(address, schedule.step[l]);
                    }

                    shake(hashes, &chain_adrs, n, false, .{ &nodes[0], &nodes[1], &nodes[2], &nodes[3] }, .{ &nodes[0], &nodes[1], &nodes[2], &nodes[3] });

                    var next: [n / 4]@Vector(lanes, u32) = undefined;

                    for (&next, 0..) |*word, w| {
                        var lane_words: [lanes]u32 = undefined;

                        for (&lane_words, &nodes) |*value, *node| value.* = std.mem.readInt(u32, node[4 * w ..][0..4], .big);

                        word.* = lane_words;
                    }

                    schedule.advance(&next);
                }
            }
        };

        // The leaves of a hypertree layer's tree: WOTS public keys.
        const WotsLeaves = struct {
            hashes: *const Hashes,
            adrs: *const Address,
            capture: ?*const Capture,

            const lanes = if (p.shake) Shake4.lanes else @min(max_lanes, 1 << hp);

            const kind = tree;

            fn compute(self: *const WotsLeaves, first: u32, out: []Node) void {
                if (p.shake) {
                    Shake4.leaves(self.hashes, self.adrs, first, out, self.capture);
                } else {
                    Lanes(lanes).leaves(self.hashes, self.adrs, first, out, self.capture);
                }
            }
        };

        const ForsLeaves = struct {
            hashes: *const Hashes,
            adrs: *const Address,
            capture: ?ForsCapture,

            const lanes = if (p.shake) Shake4.lanes else max_lanes;

            const kind = fors_tree;

            fn compute(self: *const ForsLeaves, first: u32, out: []Node) void {
                if (p.shake) {
                    Shake4.forsLeaves(self.hashes, self.adrs, first, out, self.capture);
                } else {
                    Lanes(lanes).forsLeaves(self.hashes, self.adrs, first, out, self.capture);
                }
            }
        };

        // Combines the nodes at height - 1 in pairs into the parents first .. first + count - 1
        // at `height`, in place. Lanes that would mostly idle are replaced by single hashes.
        fn reduce(hashes: *const Hashes, adrs: *const Address, kind: u32, height: u32, first: u32, nodes: []Node) void {
            const count = nodes.len / 2;

            var j: usize = 0;

            while (count - j >= 4) {
                const batch: usize = @min(if (p.shake) Shake4.lanes else max_lanes, count - j);

                const children = nodes[2 * j ..][0 .. 2 * batch];

                if (p.shake) {
                    Shake4.parents(hashes, adrs, kind, height, @intCast(first + j), children, nodes[j..][0..batch]);
                } else {
                    Lanes(max_lanes).parents(hashes, adrs, kind, height, @intCast(first + j), children, nodes[j..][0..batch]);
                }

                j += batch;
            }

            var node_adrs = adrs.*;

            setType(&node_adrs, kind);

            setKeyPair(&node_adrs, keyPair(adrs));

            setTreeHeight(&node_adrs, height);

            while (j < count) : (j += 1) {
                const pair = nodes[2 * j] ++ nodes[2 * j + 1];

                setTreeIndex(&node_adrs, @intCast(first + j));

                hashes.h(&node_adrs, &pair, &nodes[j]);
            }
        }

        // The root of the tree of 2^height leaves whose first leaf has tree index `base`, with
        // the authentication path of leaf `target` (counted within the tree) written to `auth`.
        fn merkle(context: anytype, height: usize, base: u32, target: u32, auth: ?[]u8) Node {
            const Context = @TypeOf(context.*);

            const chunk: usize = @min(height, chunk_height);

            const chunks = @as(usize, 1) << @intCast(height - chunk);

            const size = @as(usize, 1) << @intCast(chunk);

            var buffer: [1 << chunk_height]Node = undefined;

            var tops: [1 << (max_tree_height - chunk_height)]Node = undefined;

            for (0..chunks) |c| {
                const start = c * size;

                var i: usize = 0;

                while (i < size) : (i += Context.lanes) {
                    context.compute(@intCast(base + start + i), buffer[i..][0..@min(Context.lanes, size - i)]);
                }

                for (0..chunk) |z| {
                    if (auth) |path| {
                        if (target / size == c) path[z * n ..][0..n].* = buffer[((target - start) >> @intCast(z)) ^ 1];
                    }

                    reduce(context.hashes, context.adrs, Context.kind, @intCast(z + 1), @intCast((base + start) >> @intCast(z + 1)), buffer[0 .. size >> @intCast(z)]);
                }

                tops[c] = buffer[0];
            }

            for (chunk..height) |z| {
                if (auth) |path| path[z * n ..][0..n].* = tops[(target >> @intCast(z)) ^ 1];

                reduce(context.hashes, context.adrs, Context.kind, @intCast(z + 1), base >> @intCast(z + 1), tops[0 .. chunks >> @intCast(z - chunk)]);
            }

            return tops[0];
        }

        // Not inlined, like sign and verify, so that callers that dispatch over the parameter sets
        // do not hold the frames of all of them at once.
        pub noinline fn root(sk_seed: *const Node, pk_seed: *const Node) Node {
            var hashes = Hashes.init(pk_seed, sk_seed);

            defer hashes.wipe();

            var adrs: Address = @splat(0);

            setLayer(&adrs, p.d - 1);

            const context: WotsLeaves = .{ .hashes = &hashes, .adrs = &adrs, .capture = null };

            return merkle(&context, hp, 0, 0, null);
        }

        // H_msg (FIPS 205, section 11): SHAKE256, or MGF1 over SHA-256 or SHA-512 of the
        // randomizer, the public key and M'.
        fn messageDigest(r: *const Node, pk_seed: *const Node, pk_root: *const Node, message: []const []const u8) [p.m]u8 {
            var out: [p.m]u8 = undefined;

            if (p.shake) {
                var xof = primitives.shake256Sponge();

                for ([_][]const u8{ r, pk_seed, pk_root }) |part| xof.update(part);

                for (message) |part| xof.update(part);

                xof.read(&out);

                return out;
            }

            const size = if (n == 16) 32 else 64;

            var hasher = if (n == 16) sha2.Sha256.init(&sha2.iv_256) else sha2.Sha512.init(&sha2.iv_512);

            for ([_][]const u8{ r, pk_seed, pk_root }) |part| hasher.update(part);

            for (message) |part| hasher.update(part);

            var seed: [2 * n + size + 4]u8 = undefined;

            seed[0..n].* = r.*;

            seed[n..][0..n].* = pk_seed.*;

            seed[2 * n ..][0..size].* = hasher.digest();

            var offset: usize = 0;

            var counter: u32 = 0;

            while (offset < out.len) : (counter += 1) {
                std.mem.writeInt(u32, seed[2 * n + size ..][0..4], counter, .big);

                var block: [size]u8 = undefined;

                if (n == 16) sha2.finish256(sha2.iv_256, 0, &seed, &block) else sha2.finish512(sha2.iv_512, 0, &seed, &block);

                const take = @min(size, out.len - offset);

                @memcpy(out[offset..][0..take], block[0..take]);

                offset += take;
            }

            return out;
        }

        // PRF_msg: SHAKE256, or HMAC-SHA-256 or HMAC-SHA-512 truncated to n bytes.
        fn messageRandomizer(sk_prf: *const Node, opt_rand: *const Node, message: []const []const u8, out: *Node) void {
            if (p.shake) {
                var xof = primitives.shake256Sponge();

                defer ct.wipe(std.mem.asBytes(&xof));

                xof.update(sk_prf);

                xof.update(opt_rand);

                for (message) |part| xof.update(part);

                xof.read(out);

                return;
            }

            primitives.hmac(if (n == 16) u32 else u64, sk_prf, opt_rand, message, out);
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

            ct.declassify(pk);

            ct.declassify(sk[2 * n ..]);
        }

        // Every tree is built whole: the signature parts (FORS secret values, WOTS signatures and
        // authentication paths) are taken on the way, and each tree's root is what the next
        // layer signs.
        pub noinline fn sign(sk: *const [4 * n]u8, message: []const []const u8, opt_rand: *const Node, signature: *[p.signatureSize()]u8) void {
            const pk_seed = sk[2 * n ..][0..n];

            const pk_root = sk[3 * n ..][0..n];

            var hashes = Hashes.init(pk_seed, sk[0..n]);

            defer hashes.wipe();

            const r = signature[0..n];

            messageRandomizer(sk[n..][0..n], opt_rand, message, r);

            // R opens the signature; the digest, and the indices taken from it, follow from R,
            // the public key and the message.
            ct.declassify(r);

            const digest = messageDigest(r, pk_seed, pk_root, message);

            ct.declassify(&digest);

            const parts = split(&digest);

            var adrs: Address = @splat(0);

            setTree(&adrs, parts.tree);

            setType(&adrs, fors_tree);

            setKeyPair(&adrs, parts.leaf);

            const fors = signature[n..][0..fors_size];

            var roots: [k * n]u8 = undefined;

            for (forsIndices(&parts.digest), 0..) |index, i| {
                const part = fors[i * (a + 1) * n ..][0 .. (a + 1) * n];

                const base: u32 = @intCast(i << @intCast(a));

                const context: ForsLeaves = .{ .hashes = &hashes, .adrs = &adrs, .capture = .{ .index = base + index, .out = part[0..n] } };

                roots[i * n ..][0..n].* = merkle(&context, a, base, index, part[n..]);
            }

            var current: Node = undefined;

            hashes.t(&secretAddress(&adrs, fors_roots), &roots, &current);

            // The FORS public key and the root of every tree are what the next layer signs; the
            // verifier recomputes each of them from the signature.
            ct.declassify(&current);

            var idx_tree = parts.tree;

            var leaf = parts.leaf;

            for (0..d) |j| {
                if (j > 0) {
                    leaf = @intCast(idx_tree & ((1 << hp) - 1));

                    idx_tree >>= @intCast(hp);
                }

                var layer_adrs: Address = @splat(0);

                setLayer(&layer_adrs, @intCast(j));

                setTree(&layer_adrs, idx_tree);

                const part = signature[n + fors_size + j * xmss_size ..][0..xmss_size];

                const digits = wotsDigits(&current);

                const capture: Capture = .{ .keypair = leaf, .digits = &digits, .out = part[0 .. len * n] };

                const context: WotsLeaves = .{ .hashes = &hashes, .adrs = &layer_adrs, .capture = &capture };

                current = merkle(&context, hp, 0, leaf, part[len * n ..]);

                ct.declassify(&current);
            }

            ct.declassify(signature);
        }

        pub noinline fn verify(pk: *const [2 * n]u8, message: []const []const u8, signature: *const [p.signatureSize()]u8) bool {
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

            const fors = signature[n..][0..fors_size];

            const indices = forsIndices(&parts.digest);

            var roots: [k]Node = undefined;

            if (p.shake) {
                Shake4.forsRoots(&hashes, &adrs, fors, &indices, &roots);
            } else {
                Lanes(max_lanes).forsRoots(&hashes, &adrs, fors, &indices, &roots);
            }

            var node: Node = undefined;

            hashes.t(&secretAddress(&adrs, fors_roots), std.mem.asBytes(&roots), &node);

            var idx_tree = parts.tree;

            var leaf = parts.leaf;

            for (0..d) |j| {
                if (j > 0) {
                    leaf = @intCast(idx_tree & ((1 << hp) - 1));

                    idx_tree >>= @intCast(hp);
                }

                var layer_adrs: Address = @splat(0);

                setLayer(&layer_adrs, @intCast(j));

                setTree(&layer_adrs, idx_tree);

                setKeyPair(&layer_adrs, leaf);

                const part = signature[n + fors_size + j * xmss_size ..][0..xmss_size];

                const digits = wotsDigits(&node);

                var values: [len * n]u8 = part[0 .. len * n].*;

                if (p.shake) {
                    Shake4.chains(&hashes, &layer_adrs, leaf, &digits, &values);
                } else {
                    Lanes(max_lanes).chains(&hashes, &layer_adrs, leaf, &digits, &values);
                }

                wotsPublic(&hashes, &layer_adrs, &values, &node);

                setType(&layer_adrs, tree);

                setTreeIndex(&layer_adrs, leaf);

                climb(&hashes, &node, leaf, part[len * n ..], &layer_adrs);
            }

            return std.mem.eql(u8, &node, pk_root);
        }
    };
}

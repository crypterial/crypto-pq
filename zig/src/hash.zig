const std = @import("std");

const cpu = @import("cpu.zig");
const ct = @import("ct.zig");
const Keccak = @import("keccak.zig").Keccak;
const sha2 = @import("sha2.zig");

const Kind = union(enum) {
    sha256: *const [8]u32,
    sha512: *const [8]u64,
    sha3,
};

const Engine = union(enum) {
    sha256: sha2.Sha256,
    sha512: sha2.Sha512,
    keccak: Keccak,

    fn update(self: *Engine, data: []const u8) void {
        switch (self.*) {
            inline else => |*engine| engine.update(data),
        }
    }

    fn digest(self: *const Engine, out: []u8) void {
        switch (self.*) {
            inline .sha256, .sha512 => |*engine| {
                var full = engine.digest();

                @memcpy(out, full[0..out.len]);

                ct.wipe(&full);
            },
            .keccak => |*engine| {
                var sponge = engine.*;

                sponge.read(out);

                ct.wipe(std.mem.asBytes(&sponge));
            },
        }
    }
};

fn checkLength(actual: usize, expected: usize) void {
    if (actual != expected) @panic("INVALID_LENGTH: the output must be exactly the digest size");
}

pub const HashAlgorithm = struct {
    name: []const u8,
    digest_size: usize,
    kind: Kind,

    // SHA-2 in one call, without an engine: the whole blocks of data go to the compression straight
    // from data, and the padding after them.
    pub fn digest(self: HashAlgorithm, data: []const u8, out: []u8) void {
        checkLength(out.len, self.digest_size);

        switch (self.kind) {
            .sha256 => |iv| sha2.finish256(iv.*, 0, data, out),
            .sha512 => |iv| sha2.finish512(iv.*, 0, data, out),
            .sha3 => {
                var hasher = self.create();

                hasher.update(data);

                hasher.digest(out);
            },
        }
    }

    pub fn create(self: HashAlgorithm) Hasher {
        const engine: Engine = switch (self.kind) {
            .sha256 => |iv| .{ .sha256 = .init(iv) },
            .sha512 => |iv| .{ .sha512 = .init(iv) },
            .sha3 => .{ .keccak = .init(self.blockSize(), 0x06) },
        };

        return .{ .engine = engine, .size = self.digest_size };
    }

    fn blockSize(self: HashAlgorithm) usize {
        return switch (self.kind) {
            .sha256 => 64,
            .sha512 => 128,
            .sha3 => 200 - 2 * self.digest_size,
        };
    }
};

pub const Hasher = struct {
    engine: Engine,
    size: usize,

    pub fn update(self: *Hasher, data: []const u8) void {
        self.engine.update(data);
    }

    pub fn digest(self: *const Hasher, out: []u8) void {
        checkLength(out.len, self.size);

        self.engine.digest(out);
    }
};

pub const XofAlgorithm = struct {
    name: []const u8,
    rate: usize,

    pub fn digest(self: XofAlgorithm, data: []const u8, out: []u8) void {
        var xof = self.create();

        xof.update(data);

        xof.read(out);
    }

    pub fn create(self: XofAlgorithm) Xof {
        return .{ .sponge = .init(self.rate, 0x1f) };
    }
};

pub const Xof = struct {
    sponge: Keccak,

    pub fn update(self: *Xof, data: []const u8) void {
        self.sponge.update(data);
    }

    pub fn read(self: *Xof, out: []u8) void {
        self.sponge.read(out);
    }
};

// HMAC runs under DIT because its key is secret; plain hashes do not know whether their input is.
// Each public function takes the guard once, around everything it does with the key, and the
// functions it calls take none of their own.
pub const HmacAlgorithm = struct {
    name: []const u8,
    digest_size: usize,
    hash: HashAlgorithm,

    pub fn digest(self: HmacAlgorithm, key: []const u8, data: []const u8, out: []u8) void {
        checkLength(out.len, self.digest_size);

        const dit = cpu.Dit.enter();

        defer dit.leave();

        self.mac(key, data, out);
    }

    pub fn create(self: HmacAlgorithm, key: []const u8) Hmac {
        var hmac: Hmac = undefined;

        defer ct.wipe(std.mem.asBytes(&hmac));

        self.init(&hmac, key);

        return hmac;
    }

    // Built in place: the engines' states derive from the key, and no other frame keeps them.
    pub fn init(self: HmacAlgorithm, hmac: *Hmac, key: []const u8) void {
        const dit = cpu.Dit.enter();

        defer dit.leave();

        var hashed: [64]u8 = undefined;

        defer ct.wipe(&hashed);

        const k = self.blockKey(key, &hashed);

        hmac.size = self.digest_size;

        switch (self.hash.kind) {
            .sha256 => |iv| {
                var keyed = sha2.keyed256(iv, k);

                defer ct.wipe(std.mem.asBytes(&keyed));

                hmac.inner = .{ .sha256 = .{ .state = keyed[0], .length = 64 } };

                hmac.outer = .{ .sha256 = .{ .state = keyed[1], .length = 64 } };
            },
            .sha512 => |iv| {
                var keyed = sha2.keyed512(iv, k);

                defer ct.wipe(std.mem.asBytes(&keyed));

                hmac.inner = .{ .sha512 = .{ .state = keyed[0], .length = 128 } };

                hmac.outer = .{ .sha512 = .{ .state = keyed[1], .length = 128 } };
            },
            .sha3 => unreachable,
        }
    }

    pub fn verify(self: HmacAlgorithm, key: []const u8, data: []const u8, tag: []const u8) bool {
        if (tag.len != self.digest_size) return false;

        const dit = cpu.Dit.enter();

        defer dit.leave();

        var expected: [64]u8 = undefined;

        defer ct.wipe(&expected);

        self.mac(key, data, expected[0..self.digest_size]);

        return ct.equal(expected[0..self.digest_size], tag);
    }

    fn mac(self: HmacAlgorithm, key: []const u8, data: []const u8, out: []u8) void {
        var hashed: [64]u8 = undefined;

        defer ct.wipe(&hashed);

        const k = self.blockKey(key, &hashed);

        switch (self.hash.kind) {
            .sha256 => |iv| sha2.hmac256(iv, k, data, out),
            .sha512 => |iv| sha2.hmac512(iv, k, data, out),
            .sha3 => unreachable,
        }
    }

    // RFC 2104: a key longer than a block is replaced by its hash, which `hashed` then holds.
    fn blockKey(self: HmacAlgorithm, key: []const u8, hashed: *[64]u8) []const u8 {
        if (key.len <= self.hash.blockSize()) return key;

        self.hash.digest(key, hashed[0..self.digest_size]);

        return hashed[0..self.digest_size];
    }
};

// The inner engine has absorbed the inner key block and the data so far; the outer one only the
// outer key block.
pub const Hmac = struct {
    inner: Engine,
    outer: Engine,
    size: usize,

    pub fn update(self: *Hmac, data: []const u8) void {
        const dit = cpu.Dit.enter();

        defer dit.leave();

        self.inner.update(data);
    }

    pub fn digest(self: *const Hmac, out: []u8) void {
        checkLength(out.len, self.size);

        const dit = cpu.Dit.enter();

        defer dit.leave();

        self.finish(out);
    }

    pub fn verify(self: *const Hmac, tag: []const u8) bool {
        if (tag.len != self.size) return false;

        const dit = cpu.Dit.enter();

        defer dit.leave();

        var expected: [64]u8 = undefined;

        defer ct.wipe(&expected);

        self.finish(expected[0..self.size]);

        return ct.equal(expected[0..self.size], tag);
    }

    // The inner hash and the outer key give the output, which may be a key itself.
    fn finish(self: *const Hmac, out: []u8) void {
        var inner: [64]u8 = undefined;

        defer ct.wipe(&inner);

        self.inner.digest(inner[0..self.size]);

        switch (self.outer) {
            .sha256 => |*outer| sha2.finish256(outer.state, outer.length, inner[0..self.size], out),
            .sha512 => |*outer| sha2.finish512(outer.state, outer.length, inner[0..self.size], out),
            .keccak => unreachable,
        }
    }
};

pub const sha_224: HashAlgorithm = .{ .name = "SHA-224", .digest_size = 28, .kind = .{ .sha256 = &sha2.iv_224 } };

pub const sha_256: HashAlgorithm = .{ .name = "SHA-256", .digest_size = 32, .kind = .{ .sha256 = &sha2.iv_256 } };

pub const sha_384: HashAlgorithm = .{ .name = "SHA-384", .digest_size = 48, .kind = .{ .sha512 = &sha2.iv_384 } };

pub const sha_512: HashAlgorithm = .{ .name = "SHA-512", .digest_size = 64, .kind = .{ .sha512 = &sha2.iv_512 } };

pub const sha_512_224: HashAlgorithm = .{ .name = "SHA-512/224", .digest_size = 28, .kind = .{ .sha512 = &sha2.iv_512_224 } };

pub const sha_512_256: HashAlgorithm = .{ .name = "SHA-512/256", .digest_size = 32, .kind = .{ .sha512 = &sha2.iv_512_256 } };

pub const sha3_224: HashAlgorithm = .{ .name = "SHA3-224", .digest_size = 28, .kind = .sha3 };

pub const sha3_256: HashAlgorithm = .{ .name = "SHA3-256", .digest_size = 32, .kind = .sha3 };

pub const sha3_384: HashAlgorithm = .{ .name = "SHA3-384", .digest_size = 48, .kind = .sha3 };

pub const sha3_512: HashAlgorithm = .{ .name = "SHA3-512", .digest_size = 64, .kind = .sha3 };

pub const shake128: XofAlgorithm = .{ .name = "SHAKE128", .rate = 168 };

pub const shake256: XofAlgorithm = .{ .name = "SHAKE256", .rate = 136 };

pub const hmac_sha_224: HmacAlgorithm = .{ .name = "HMAC-SHA-224", .digest_size = 28, .hash = sha_224 };

pub const hmac_sha_256: HmacAlgorithm = .{ .name = "HMAC-SHA-256", .digest_size = 32, .hash = sha_256 };

pub const hmac_sha_384: HmacAlgorithm = .{ .name = "HMAC-SHA-384", .digest_size = 48, .hash = sha_384 };

pub const hmac_sha_512: HmacAlgorithm = .{ .name = "HMAC-SHA-512", .digest_size = 64, .hash = sha_512 };

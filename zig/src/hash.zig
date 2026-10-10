const std = @import("std");
const builtin = @import("builtin");

const ascon = @import("ascon.zig");
const blake2 = @import("blake2.zig");
const cpu = @import("cpu.zig");
const ct = @import("ct.zig");
const Error = @import("errors.zig").Error;
const Keccak = @import("keccak.zig").Keccak;
const sha2 = @import("sha2.zig");
const sp800_185 = @import("sp800_185.zig");

const Blake2b = blake2.Blake2b;

const Blake2s = blake2.Blake2s;

// The other algorithms run out of line in WebAssembly, so that the frame of a call holds no other
// algorithm's buffers: the stack of a hashing call must stay well within the 4 KiB that the
// TypeScript binding wipes after it. Elsewhere the compiler decides.
const apart: std.builtin.CallModifier = if (builtin.cpu.arch.isWasm()) .never_inline else .auto;

const Kind = union(enum) {
    sha256: *const [8]u32,
    sha512: *const [8]u64,
    sha3,
    // The chaining value of the BLAKE2 parameter block, with the salt and personalization.
    blake2b: [8]u64,
    blake2s: [8]u32,
    ascon,
};

const Engine = union(enum) {
    sha256: sha2.Sha256,
    sha512: sha2.Sha512,
    keccak: Keccak,
    blake2b: Blake2b.Engine,
    blake2s: Blake2s.Engine,
    ascon: ascon.Sponge,

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
            inline .blake2b, .blake2s => |*engine| engine.digest(out),
            .ascon => |*engine| {
                var sponge = engine.*;

                sponge.read(out);

                sponge.wipe();
            },
        }
    }
};

fn checkLength(actual: usize, expected: usize) void {
    if (actual != expected) @panic("INVALID_LENGTH: the output must be exactly the digest size");
}

pub const HashOptions = struct {
    salt: []const u8 = "",
    personalization: []const u8 = "",
};

pub const HashAlgorithm = struct {
    name: []const u8,
    digest_size: usize,
    kind: Kind,

    // SHA-2, BLAKE2 and Ascon-Hash256 in one call, without an engine: the whole blocks of data go
    // to the compression or permutation straight from data, and the padding after them.
    pub fn digest(self: HashAlgorithm, data: []const u8, out: []u8) void {
        checkLength(out.len, self.digest_size);

        switch (self.kind) {
            .sha256 => |iv| sha2.finish256(iv.*, 0, data, out),
            .sha512 => |iv| sha2.finish512(iv.*, 0, data, out),
            .sha3 => @call(apart, sha3Digest, .{ self.blockSize(), data, out }),
            .blake2b => |*h0| @call(apart, Blake2b.hash, .{ h0, "", data, out }),
            .blake2s => |*h0| @call(apart, Blake2s.hash, .{ h0, "", data, out }),
            .ascon => @call(apart, ascon.digest, .{ &ascon.hash_iv, data, out }),
        }
    }

    pub fn create(self: HashAlgorithm) Hasher {
        const engine: Engine = switch (self.kind) {
            .sha256 => |iv| .{ .sha256 = .init(iv) },
            .sha512 => |iv| .{ .sha512 = .init(iv) },
            .sha3 => .{ .keccak = .init(self.blockSize(), 0x06) },
            .blake2b => |*h0| .{ .blake2b = .init(h0) },
            .blake2s => |*h0| .{ .blake2s = .init(h0) },
            .ascon => .{ .ascon = .{ .state = ascon.hash_iv } },
        };

        return .{ .engine = engine, .size = self.digest_size };
    }

    // The algorithm with these options and the defaults for the rest. Only BLAKE2 takes any: a
    // salt and a personalization of at most 16 bytes (BLAKE2b) or 8 (BLAKE2s), zero padded.
    pub fn configure(self: HashAlgorithm, options: HashOptions) Error!HashAlgorithm {
        var configured = self;

        switch (self.kind) {
            .blake2b => {
                if (options.salt.len > Blake2b.field or options.personalization.len > Blake2b.field) return error.InvalidOption;

                configured.kind = .{ .blake2b = Blake2b.initial(self.digest_size, 0, options.salt, options.personalization) };
            },
            .blake2s => {
                if (options.salt.len > Blake2s.field or options.personalization.len > Blake2s.field) return error.InvalidOption;

                configured.kind = .{ .blake2s = Blake2s.initial(self.digest_size, 0, options.salt, options.personalization) };
            },
            else => if (options.salt.len > 0 or options.personalization.len > 0) return error.InvalidOption,
        }

        return configured;
    }

    fn blockSize(self: HashAlgorithm) usize {
        return switch (self.kind) {
            .sha256 => 64,
            .sha512 => 128,
            .sha3 => 200 - 2 * self.digest_size,
            .blake2b => Blake2b.block,
            .blake2s => Blake2s.block,
            .ascon => 8,
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

pub const XofOptions = struct {
    customization: []const u8 = "",
};

const XofKind = union(enum) {
    shake,
    // cSHAKE: SHAKE itself until a function name or a customization gives it a prefix, whose
    // absorbed state this holds.
    cshake: ?[25]u64,
    ascon_xof,
    // The state after the customization string.
    ascon_cxof: ascon.State,
};

pub const XofAlgorithm = struct {
    name: []const u8,
    rate: usize,
    kind: XofKind,

    pub fn digest(self: XofAlgorithm, data: []const u8, out: []u8) void {
        switch (self.kind) {
            .ascon_xof => @call(apart, ascon.digest, .{ &ascon.xof_iv, data, out }),
            .ascon_cxof => |*state| @call(apart, ascon.digest, .{ state, data, out }),
            else => {
                var xof = self.create();

                xof.update(data);

                xof.read(out);
            },
        }
    }

    pub fn create(self: XofAlgorithm) Xof {
        return .{ .engine = switch (self.kind) {
            .shake => .{ .keccak = .init(self.rate, 0x1f) },
            .cshake => |prefix| .{ .keccak = if (prefix) |state| .{ .state = state, .rate = self.rate, .suffix = sp800_185.suffix } else .init(self.rate, 0x1f) },
            .ascon_xof => .{ .ascon = .{ .state = ascon.xof_iv } },
            .ascon_cxof => |state| .{ .ascon = .{ .state = state } },
        } };
    }

    // The algorithm with this customization string: any length for cSHAKE (whose function name
    // stays empty; hazmat sets one), at most 256 bytes for Ascon-CXOF128, none for the others.
    pub fn configure(self: XofAlgorithm, options: XofOptions) Error!XofAlgorithm {
        const customization = options.customization;

        var configured = self;

        switch (self.kind) {
            .cshake => return configureCshake(self, "", customization),
            .ascon_cxof => {
                if (customization.len > ascon.max_customization) return error.InvalidOption;

                configured.kind = .{ .ascon_cxof = ascon.customize(customization) };
            },
            else => if (customization.len > 0) return error.InvalidOption,
        }

        return configured;
    }
};

// cSHAKE with a function name N and a customization S (SP 800-185, 3.3); N and S both empty give
// SHAKE. N names functions that NIST defines, so only hazmat exposes it.
pub fn configureCshake(algorithm: XofAlgorithm, function_name: []const u8, customization: []const u8) Error!XofAlgorithm {
    if (algorithm.kind != .cshake) return error.InvalidOption;

    var configured = algorithm;

    configured.kind = .{ .cshake = if (function_name.len == 0 and customization.len == 0) null else sp800_185.prefix(algorithm.rate, function_name, customization) };

    return configured;
}

pub const Xof = struct {
    engine: union(enum) {
        keccak: Keccak,
        ascon: ascon.Sponge,
    },

    pub fn update(self: *Xof, data: []const u8) void {
        switch (self.engine) {
            inline else => |*engine| engine.update(data),
        }
    }

    pub fn read(self: *Xof, out: []u8) void {
        switch (self.engine) {
            inline else => |*engine| engine.read(out),
        }
    }
};

pub const MacOptions = struct {
    // The output length in bytes: at least 4 for KMAC (SP 800-185, 8.4.2), 1 to 64 (BLAKE2b) or
    // 32 (BLAKE2s); null keeps the algorithm's default.
    length: ?usize = null,
    customization: []const u8 = "",
    // KMACXOF: L is encoded as 0, so outputs of different lengths are prefixes of each other.
    xof: bool = false,
    salt: []const u8 = "",
    personalization: []const u8 = "",
};

const Kmac = struct {
    rate: usize,
    // The state after bytepad(encode_string("KMAC") || encode_string(S)).
    state: [25]u64,
    xof: bool,
};

const MacKind = union(enum) {
    hmac: HashAlgorithm,
    kmac: Kmac,
    // The chaining value of the parameter block, its key length field still zero.
    blake2b: [8]u64,
    blake2s: [8]u32,
};

// A MAC runs under the keyed DIT guard because its key is secret; plain hashes do not know whether
// their input is. Each public function takes the guard once, around everything it does with the
// key, and the functions it calls take none of their own.
pub const MacAlgorithm = struct {
    name: []const u8,
    digest_size: usize,
    kind: MacKind,

    pub fn digest(self: MacAlgorithm, key: []const u8, data: []const u8, out: []u8) void {
        checkLength(out.len, self.digest_size);

        self.checkKey(key);

        const dit = cpu.Dit.enterKeyed();

        defer dit.leave();

        self.mac(key, data, out);
    }

    pub fn create(self: MacAlgorithm, key: []const u8) Mac {
        var mac_state: Mac = undefined;

        defer ct.wipe(std.mem.asBytes(&mac_state));

        self.init(&mac_state, key);

        return mac_state;
    }

    // Built in place: the engines' states derive from the key, and no other frame keeps them.
    pub fn init(self: MacAlgorithm, mac_state: *Mac, key: []const u8) void {
        self.checkKey(key);

        const dit = cpu.Dit.enterKeyed();

        defer dit.leave();

        mac_state.size = self.digest_size;

        switch (self.kind) {
            .hmac => |h| {
                var hashed: [64]u8 = undefined;

                defer ct.wipe(&hashed);

                const k = blockKey(h, key, &hashed);

                switch (h.kind) {
                    .sha256 => |iv| {
                        var keyed = sha2.keyed256(iv, k);

                        defer ct.wipe(std.mem.asBytes(&keyed));

                        mac_state.engine = .{ .hmac = .{
                            .inner = .{ .sha256 = .{ .state = keyed[0], .length = 64 } },
                            .outer = .{ .sha256 = .{ .state = keyed[1], .length = 64 } },
                        } };
                    },
                    .sha512 => |iv| {
                        var keyed = sha2.keyed512(iv, k);

                        defer ct.wipe(std.mem.asBytes(&keyed));

                        mac_state.engine = .{ .hmac = .{
                            .inner = .{ .sha512 = .{ .state = keyed[0], .length = 128 } },
                            .outer = .{ .sha512 = .{ .state = keyed[1], .length = 128 } },
                        } };
                    },
                    else => unreachable,
                }
            },
            .kmac => |*k| {
                mac_state.engine = .{ .kmac = .{ .sponge = .{ .state = k.state, .rate = k.rate, .suffix = sp800_185.suffix }, .xof = k.xof } };

                sp800_185.absorbKey(&mac_state.engine.kmac.sponge, key);
            },
            .blake2b => |*h0| {
                mac_state.engine = .{ .blake2b = undefined };

                mac_state.engine.blake2b.initKeyed(h0, key);
            },
            .blake2s => |*h0| {
                mac_state.engine = .{ .blake2s = undefined };

                mac_state.engine.blake2s.initKeyed(h0, key);
            },
        }
    }

    // The tag must have the full length and a BLAKE2 key a length the MAC takes, or the answer is
    // no; the comparison takes the same time whatever the tag holds.
    pub fn verify(self: MacAlgorithm, key: []const u8, data: []const u8, tag: []const u8) bool {
        if (tag.len != self.digest_size or !self.takes(key)) return false;

        const dit = cpu.Dit.enterKeyed();

        defer dit.leave();

        if (self.kind == .kmac) return @call(apart, kmacVerify, .{ &self.kind.kmac, key, data, tag });

        var expected: [64]u8 = undefined;

        defer ct.wipe(&expected);

        self.mac(key, data, expected[0..tag.len]);

        return ct.equal(expected[0..tag.len], tag);
    }

    // The algorithm with these options and the defaults for the rest. KMAC takes a length, a
    // customization and xof; BLAKE2 a length, a salt and a personalization; HMAC none.
    pub fn configure(self: MacAlgorithm, options: MacOptions) Error!MacAlgorithm {
        var configured = self;

        switch (self.kind) {
            .hmac => {
                const given = options.length != null or options.customization.len > 0 or options.xof or options.salt.len > 0 or options.personalization.len > 0;

                if (given) return error.InvalidOption;
            },
            .kmac => |k| {
                if (options.salt.len > 0 or options.personalization.len > 0) return error.InvalidOption;

                const length = options.length orelse kmacLength(k.rate);

                if (length < 4) return error.InvalidOption;

                configured.digest_size = length;

                configured.kind = .{ .kmac = .{ .rate = k.rate, .state = sp800_185.prefix(k.rate, "KMAC", options.customization), .xof = options.xof } };
            },
            inline .blake2b, .blake2s => |_, tag| {
                const B = if (tag == .blake2b) Blake2b else Blake2s;

                if (options.customization.len > 0 or options.xof) return error.InvalidOption;

                if (options.salt.len > B.field or options.personalization.len > B.field) return error.InvalidOption;

                const length = options.length orelse B.max_size;

                if (length == 0 or length > B.max_size) return error.InvalidOption;

                configured.digest_size = length;

                configured.kind = @unionInit(MacKind, @tagName(tag), B.initial(length, 0, options.salt, options.personalization));
            },
        }

        return configured;
    }

    // A BLAKE2 key has 1 to 64 (BLAKE2b) or 32 (BLAKE2s) bytes; HMAC and KMAC take any key.
    pub fn takes(self: MacAlgorithm, key: []const u8) bool {
        const max: usize = switch (self.kind) {
            .blake2b => Blake2b.max_size,
            .blake2s => Blake2s.max_size,
            else => return true,
        };

        return key.len >= 1 and key.len <= max;
    }

    fn checkKey(self: MacAlgorithm, key: []const u8) void {
        if (!self.takes(key)) @panic("INVALID_LENGTH: a BLAKE2 key must have 1 to 64 (BLAKE2b) or 32 (BLAKE2s) bytes");
    }

    fn mac(self: MacAlgorithm, key: []const u8, data: []const u8, out: []u8) void {
        switch (self.kind) {
            .hmac => |h| {
                var hashed: [64]u8 = undefined;

                defer ct.wipe(&hashed);

                const k = blockKey(h, key, &hashed);

                switch (h.kind) {
                    .sha256 => |iv| sha2.hmac256(iv, k, data, out),
                    .sha512 => |iv| sha2.hmac512(iv, k, data, out),
                    else => unreachable,
                }
            },
            .kmac => |*k| @call(apart, kmacTag, .{ k, key, data, out }),
            .blake2b => |*h0| @call(apart, Blake2b.hash, .{ h0, key, data, out }),
            .blake2s => |*h0| @call(apart, Blake2s.hash, .{ h0, key, data, out }),
        }
    }
};

// The pre-hashes of ML-DSA and SLH-DSA, which are SHA-2, SHA-3 and SHAKE only: no other
// algorithm's code comes into their modules.
pub fn preHashDigest(algorithm: HashAlgorithm, data: []const u8, out: []u8) void {
    switch (algorithm.kind) {
        .sha256 => |iv| sha2.finish256(iv.*, 0, data, out),
        .sha512 => |iv| sha2.finish512(iv.*, 0, data, out),
        .sha3 => sha3Digest(algorithm.blockSize(), data, out),
        else => unreachable,
    }
}

fn sha3Digest(rate: usize, data: []const u8, out: []u8) void {
    var sponge = Keccak.init(rate, 0x06);

    defer ct.wipe(std.mem.asBytes(&sponge));

    sponge.update(data);

    sponge.read(out);
}

pub fn preHashXof(algorithm: XofAlgorithm, data: []const u8, out: []u8) void {
    var sponge = Keccak.init(algorithm.rate, 0x1f);

    defer ct.wipe(std.mem.asBytes(&sponge));

    sponge.update(data);

    sponge.read(out);
}

// RFC 2104: a key longer than a block is replaced by its hash, which `hashed` then holds. HMAC's
// hashes are SHA-2's.
fn blockKey(h: HashAlgorithm, key: []const u8, hashed: *[64]u8) []const u8 {
    if (key.len <= h.blockSize()) return key;

    switch (h.kind) {
        .sha256 => |iv| sha2.finish256(iv.*, 0, key, hashed[0..h.digest_size]),
        .sha512 => |iv| sha2.finish512(iv.*, 0, key, hashed[0..h.digest_size]),
        else => unreachable,
    }

    return hashed[0..h.digest_size];
}

fn kmacLength(rate: usize) usize {
    return if (rate == 168) 32 else 64;
}

fn kmacTag(k: *const Kmac, key: []const u8, data: []const u8, out: []u8) void {
    var sponge = kmacSponge(k, key, data, out.len);

    defer ct.wipe(std.mem.asBytes(&sponge));

    sponge.read(out);
}

fn kmacVerify(k: *const Kmac, key: []const u8, data: []const u8, tag: []const u8) bool {
    var sponge = kmacSponge(k, key, data, tag.len);

    defer ct.wipe(std.mem.asBytes(&sponge));

    return matches(&sponge, tag);
}

// The KMAC sponge after the key, the data and right_encode(L), ready to squeeze.
fn kmacSponge(k: *const Kmac, key: []const u8, data: []const u8, length: usize) Keccak {
    var sponge: Keccak = .{ .state = k.state, .rate = k.rate, .suffix = sp800_185.suffix };

    sp800_185.absorbKey(&sponge, key);

    sponge.update(data);

    sp800_185.absorbLength(&sponge, length, k.xof);

    return sponge;
}

// Whether the next tag.len bytes that the sponge squeezes equal tag, compared in pieces in the
// same time whatever they hold.
pub fn matches(sponge: *Keccak, tag: []const u8) bool {
    var expected: [64]u8 = undefined;

    defer ct.wipe(&expected);

    var difference: u8 = 0;

    var offset: usize = 0;

    while (offset < tag.len) {
        const take = @min(expected.len, tag.len - offset);

        sponge.read(expected[0..take]);

        for (expected[0..take], tag[offset..][0..take]) |x, y| difference |= x ^ y;

        offset += take;
    }

    const barrier: *volatile u8 = &difference;

    return barrier.* == 0;
}

const MacEngine = union(enum) {
    // The inner engine has absorbed the inner key block and the data so far; the outer one only
    // the outer key block.
    hmac: struct {
        inner: Engine,
        outer: Engine,
    },
    kmac: struct {
        sponge: Keccak,
        xof: bool,
    },
    blake2b: Blake2b.Engine,
    blake2s: Blake2s.Engine,
};

pub const Mac = struct {
    engine: MacEngine,
    size: usize,

    pub fn update(self: *Mac, data: []const u8) void {
        const dit = cpu.Dit.enterKeyed();

        defer dit.leave();

        switch (self.engine) {
            .hmac => |*engine| engine.inner.update(data),
            .kmac => |*engine| engine.sponge.update(data),
            inline .blake2b, .blake2s => |*engine| engine.update(data),
        }
    }

    pub fn digest(self: *const Mac, out: []u8) void {
        checkLength(out.len, self.size);

        const dit = cpu.Dit.enterKeyed();

        defer dit.leave();

        switch (self.engine) {
            .kmac => |*engine| {
                var sponge = engine.sponge;

                defer ct.wipe(std.mem.asBytes(&sponge));

                sp800_185.absorbLength(&sponge, self.size, engine.xof);

                sponge.read(out);
            },
            else => self.finish(out),
        }
    }

    pub fn verify(self: *const Mac, tag: []const u8) bool {
        if (tag.len != self.size) return false;

        const dit = cpu.Dit.enterKeyed();

        defer dit.leave();

        if (self.engine == .kmac) {
            var sponge = self.engine.kmac.sponge;

            defer ct.wipe(std.mem.asBytes(&sponge));

            sp800_185.absorbLength(&sponge, self.size, self.engine.kmac.xof);

            return matches(&sponge, tag);
        }

        var expected: [64]u8 = undefined;

        defer ct.wipe(&expected);

        self.finish(expected[0..self.size]);

        return ct.equal(expected[0..self.size], tag);
    }

    // The output of HMAC or BLAKE2, which may be a key itself; at most 64 bytes.
    fn finish(self: *const Mac, out: []u8) void {
        switch (self.engine) {
            .hmac => |*engine| {
                var inner: [64]u8 = undefined;

                defer ct.wipe(&inner);

                engine.inner.digest(inner[0..self.size]);

                switch (engine.outer) {
                    .sha256 => |*outer| sha2.finish256(outer.state, outer.length, inner[0..self.size], out),
                    .sha512 => |*outer| sha2.finish512(outer.state, outer.length, inner[0..self.size], out),
                    else => unreachable,
                }
            },
            inline .blake2b, .blake2s => |*engine| engine.digest(out),
            .kmac => unreachable,
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

fn blake2bHash(comptime name: []const u8, comptime size: usize) HashAlgorithm {
    return .{ .name = name, .digest_size = size, .kind = .{ .blake2b = Blake2b.initial(size, 0, "", "") } };
}

fn blake2sHash(comptime name: []const u8, comptime size: usize) HashAlgorithm {
    return .{ .name = name, .digest_size = size, .kind = .{ .blake2s = Blake2s.initial(size, 0, "", "") } };
}

pub const blake2b_160 = blake2bHash("BLAKE2b-160", 20);

pub const blake2b_256 = blake2bHash("BLAKE2b-256", 32);

pub const blake2b_384 = blake2bHash("BLAKE2b-384", 48);

pub const blake2b_512 = blake2bHash("BLAKE2b-512", 64);

pub const blake2s_128 = blake2sHash("BLAKE2s-128", 16);

pub const blake2s_160 = blake2sHash("BLAKE2s-160", 20);

pub const blake2s_224 = blake2sHash("BLAKE2s-224", 28);

pub const blake2s_256 = blake2sHash("BLAKE2s-256", 32);

pub const ascon_hash256: HashAlgorithm = .{ .name = "Ascon-Hash256", .digest_size = 32, .kind = .ascon };

pub const shake128: XofAlgorithm = .{ .name = "SHAKE128", .rate = 168, .kind = .shake };

pub const shake256: XofAlgorithm = .{ .name = "SHAKE256", .rate = 136, .kind = .shake };

pub const cshake128: XofAlgorithm = .{ .name = "cSHAKE128", .rate = 168, .kind = .{ .cshake = null } };

pub const cshake256: XofAlgorithm = .{ .name = "cSHAKE256", .rate = 136, .kind = .{ .cshake = null } };

pub const ascon_xof128: XofAlgorithm = .{ .name = "Ascon-XOF128", .rate = 8, .kind = .ascon_xof };

pub const ascon_cxof128: XofAlgorithm = .{ .name = "Ascon-CXOF128", .rate = 8, .kind = .{ .ascon_cxof = ascon.customize("") } };

pub const hmac_sha_224: MacAlgorithm = .{ .name = "HMAC-SHA-224", .digest_size = 28, .kind = .{ .hmac = sha_224 } };

pub const hmac_sha_256: MacAlgorithm = .{ .name = "HMAC-SHA-256", .digest_size = 32, .kind = .{ .hmac = sha_256 } };

pub const hmac_sha_384: MacAlgorithm = .{ .name = "HMAC-SHA-384", .digest_size = 48, .kind = .{ .hmac = sha_384 } };

pub const hmac_sha_512: MacAlgorithm = .{ .name = "HMAC-SHA-512", .digest_size = 64, .kind = .{ .hmac = sha_512 } };

pub const kmac128: MacAlgorithm = .{ .name = "KMAC128", .digest_size = 32, .kind = .{ .kmac = .{ .rate = 168, .state = sp800_185.prefix(168, "KMAC", ""), .xof = false } } };

pub const kmac256: MacAlgorithm = .{ .name = "KMAC256", .digest_size = 64, .kind = .{ .kmac = .{ .rate = 136, .state = sp800_185.prefix(136, "KMAC", ""), .xof = false } } };

pub const blake2b_mac: MacAlgorithm = .{ .name = "BLAKE2b-MAC", .digest_size = 64, .kind = .{ .blake2b = Blake2b.initial(64, 0, "", "") } };

pub const blake2s_mac: MacAlgorithm = .{ .name = "BLAKE2s-MAC", .digest_size = 32, .kind = .{ .blake2s = Blake2s.initial(32, 0, "", "") } };

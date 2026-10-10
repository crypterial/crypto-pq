const std = @import("std");
const builtin = @import("builtin");

const cpu = @import("cpu.zig");
const ct = @import("ct.zig");
const Error = @import("errors.zig").Error;
const sha2 = @import("sha2.zig");

// In WebAssembly the expansions run out of line, so that no frame holds the buffers of both (the
// TypeScript binding wipes 4 KiB of stack after a hashing call); elsewhere the compiler decides.
const apart: std.builtin.CallModifier = if (builtin.cpu.arch.isWasm()) .never_inline else .auto;

pub const KdfOptions = struct {
    salt: []const u8 = "",
    info: []const u8 = "",
};

pub const Hash = enum { sha256, sha384, sha512 };

// HKDF (RFC 5869) over HMAC-SHA-256, HMAC-SHA-384 or HMAC-SHA-512. Its keys, PRK and output are
// secret: each public function runs under one keyed DIT guard, and everything derived from them is
// wiped.
pub const KdfAlgorithm = struct {
    name: []const u8,
    hash: Hash,

    pub fn hashSize(self: KdfAlgorithm) usize {
        return switch (self.hash) {
            .sha256 => 32,
            .sha384 => 48,
            .sha512 => 64,
        };
    }

    // Extract, then Expand; out.len is L, at most 255 hash lengths.
    pub fn derive(self: KdfAlgorithm, ikm: []const u8, out: []u8, options: KdfOptions) Error!void {
        try self.checkOutput(out.len);

        const dit = cpu.Dit.enterKeyed();

        defer dit.leave();

        const size = self.hashSize();

        var prk: [64]u8 = undefined;

        defer ct.wipe(prk[0..size]);

        hmac(self.hash, options.salt, ikm, prk[0..size]);

        expandFrom(self.hash, prk[0..size], options.info, out);
    }

    // The pseudorandom key, out.len = the hash length. An absent salt is the empty one, which
    // HMAC pads to the same block as HashLen zeros.
    pub fn extract(self: KdfAlgorithm, ikm: []const u8, out: []u8, options: KdfOptions) Error!void {
        if (options.info.len > 0) return error.InvalidOption;

        if (out.len != self.hashSize()) return error.InvalidLength;

        const dit = cpu.Dit.enterKeyed();

        defer dit.leave();

        hmac(self.hash, options.salt, ikm, out);
    }

    // The output keying material from a PRK of at least the hash length.
    pub fn expand(self: KdfAlgorithm, prk: []const u8, out: []u8, options: KdfOptions) Error!void {
        if (options.salt.len > 0) return error.InvalidOption;

        if (prk.len < self.hashSize()) return error.InvalidLength;

        try self.checkOutput(out.len);

        const dit = cpu.Dit.enterKeyed();

        defer dit.leave();

        expandFrom(self.hash, prk, options.info, out);
    }

    fn checkOutput(self: KdfAlgorithm, length: usize) Error!void {
        if (length == 0 or length > 255 * self.hashSize()) return error.InvalidLength;
    }
};

fn blockSize(hash: Hash) usize {
    return if (hash == .sha256) 64 else 128;
}

// HMAC under any key: one longer than a block is replaced by its hash, which `hashed` holds.
fn blockKey(hash: Hash, key: []const u8, hashed: *[64]u8) []const u8 {
    if (key.len <= blockSize(hash)) return key;

    switch (hash) {
        .sha256 => sha2.finish256(sha2.iv_256, 0, key, hashed[0..32]),
        .sha384 => sha2.finish512(sha2.iv_384, 0, key, hashed[0..48]),
        .sha512 => sha2.finish512(sha2.iv_512, 0, key, hashed[0..64]),
    }

    return hashed[0..if (hash == .sha256) 32 else if (hash == .sha384) 48 else 64];
}

fn hmac(hash: Hash, key: []const u8, data: []const u8, out: []u8) void {
    var hashed: [64]u8 = undefined;

    defer if (key.len > blockSize(hash)) ct.wipe(&hashed);

    const k = blockKey(hash, key, &hashed);

    switch (hash) {
        .sha256 => sha2.hmac256(&sha2.iv_256, k, data, out),
        .sha384 => sha2.hmac512(&sha2.iv_384, k, data, out),
        .sha512 => sha2.hmac512(&sha2.iv_512, k, data, out),
    }
}

fn expandFrom(hash: Hash, prk: []const u8, info: []const u8, out: []u8) void {
    var hashed: [64]u8 = undefined;

    defer if (prk.len > blockSize(hash)) ct.wipe(&hashed);

    const k = blockKey(hash, prk, &hashed);

    switch (hash) {
        .sha256 => @call(apart, Expansion(u32).run, .{ &sha2.iv_256, 32, k, info, out }),
        .sha384 => @call(apart, Expansion(u64).run, .{ &sha2.iv_384, 48, k, info, out }),
        .sha512 => @call(apart, Expansion(u64).run, .{ &sha2.iv_512, 64, k, info, out }),
    }
}

// T(i) = HMAC(PRK, T(i - 1) || info || i). The keyed states of PRK are computed once, and each
// T(i) costs the compressions of its message and one more for the outer hash.
fn Expansion(comptime Word: type) type {
    const block = 16 * @sizeOf(Word);

    const Engine = if (Word == u32) sha2.Sha256 else sha2.Sha512;

    // T(i - 1) || info || i in one buffer, when it fits, for the one-shot path of sha2.
    const gathered = 256;

    return struct {
        fn finish(state: [8]Word, data: []const u8, out: []u8) void {
            if (Word == u32) return sha2.finish256(state, block, data, out);

            sha2.finish512(state, block, data, out);
        }

        // T(i) for an info too long for the buffer, through an engine.
        fn streamed(keyed: *const [2][8]Word, previous: []const u8, info: []const u8, counter: u8, t: []u8) void {
            var engine: Engine = .{ .state = keyed[0], .length = block };

            defer ct.wipe(std.mem.asBytes(&engine));

            engine.update(previous);

            engine.update(info);

            engine.update(&.{counter});

            var inner = engine.digest();

            defer ct.wipe(&inner);

            finish(keyed[1], inner[0..t.len], t);
        }

        fn run(iv: *const [8]Word, size: usize, key: []const u8, info: []const u8, out: []u8) void {
            var t: [64]u8 = undefined;

            defer ct.wipe(t[0..size]);

            var buffer: [gathered]u8 = undefined;

            const fits = size + info.len + 1 <= gathered;

            const used = if (fits) size + info.len + 1 else 0;

            defer ct.wipe(buffer[0..used]);

            if (fits) @memcpy(buffer[size..][0..info.len], info);

            // A single block takes the key blocks once anyway: HMAC in one pass.
            if (fits and out.len <= size) {
                buffer[size + info.len] = 1;

                if (Word == u32) sha2.hmac256(iv, key, buffer[size..used], t[0..size]) else sha2.hmac512(iv, key, buffer[size..used], t[0..size]);

                @memcpy(out, t[0..out.len]);

                return;
            }

            var keyed = if (Word == u32) sha2.keyed256(iv, key) else sha2.keyed512(iv, key);

            defer ct.wipe(std.mem.asBytes(&keyed));

            var offset: usize = 0;

            var counter: u8 = 1;

            while (offset < out.len) : (counter +%= 1) {
                const previous = if (counter == 1) 0 else size;

                if (fits) {
                    @memcpy(buffer[size - previous .. size], t[0..previous]);

                    buffer[size + info.len] = counter;

                    const data = buffer[size - previous .. size + info.len + 1];

                    if (Word == u32) sha2.hmacKeyed256(&keyed, data, t[0..size]) else sha2.hmacKeyed512(&keyed, data, t[0..size]);
                } else {
                    @call(apart, streamed, .{ &keyed, t[0..previous], info, counter, t[0..size] });
                }

                const take = @min(size, out.len - offset);

                @memcpy(out[offset..][0..take], t[0..take]);

                offset += take;
            }
        }
    };
}

pub const hkdf_sha_256: KdfAlgorithm = .{ .name = "HKDF-SHA-256", .hash = .sha256 };

pub const hkdf_sha_384: KdfAlgorithm = .{ .name = "HKDF-SHA-384", .hash = .sha384 };

pub const hkdf_sha_512: KdfAlgorithm = .{ .name = "HKDF-SHA-512", .hash = .sha512 };

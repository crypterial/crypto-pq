const std = @import("std");

const keccak = @import("keccak.zig");

const Keccak = keccak.Keccak;

// cSHAKE and KMAC (NIST SP 800-185) over the Keccak sponge of keccak.zig. Lengths are whole bytes;
// the encodings carry them in bits.

// cSHAKE's domain bits 00 and the first bit of the padding; SHAKE's are 1111.
pub const suffix = 0x04;

pub const Encoding = struct {
    bytes: [10]u8,
    len: usize,

    pub fn slice(self: *const Encoding) []const u8 {
        return self.bytes[0..self.len];
    }
};

// A number of at most 67 bits, the bit length of a byte string: `high` holds the bits above the
// 64 of `low`. Two words, so that no target needs 128-bit shifts.
const Number = struct {
    high: u8 = 0,
    low: u64,
};

fn bits(length: usize) Number {
    return .{ .high = @truncate(@as(u64, length) >> 61), .low = @as(u64, length) << 3 };
}

// The number big-endian in its fewest bytes, at least one.
fn bigEndian(x: Number, out: *[9]u8) usize {
    out[0] = x.high;

    std.mem.writeInt(u64, out[1..9], x.low, .big);

    return if (x.high != 0) 9 else @max(1, (64 - @as(usize, @clz(x.low)) + 7) / 8);
}

// left_encode(x) (2.3.1): the length of x in bytes, then x big-endian.
fn leftEncode(x: Number) Encoding {
    var full: [9]u8 = undefined;

    const n = bigEndian(x, &full);

    var encoding: Encoding = .{ .bytes = undefined, .len = n + 1 };

    encoding.bytes[0] = @intCast(n);

    @memcpy(encoding.bytes[1..][0..n], full[9 - n ..]);

    return encoding;
}

// right_encode(x): x big-endian, then its length in bytes.
fn rightEncode(x: Number) Encoding {
    var full: [9]u8 = undefined;

    const n = bigEndian(x, &full);

    var encoding: Encoding = .{ .bytes = undefined, .len = n + 1 };

    @memcpy(encoding.bytes[0..n], full[9 - n ..]);

    encoding.bytes[n] = @intCast(n);

    return encoding;
}

// The absorbing half of a sponge, which also runs at compile time, for the default states.
const Absorber = struct {
    state: [25]u64 = @splat(0),
    rate: usize,
    position: usize = 0,

    fn permute(self: *Absorber) void {
        if (@inComptime()) return keccak.portable.permute(&self.state);

        keccak.permute(&self.state);
    }

    fn update(self: *Absorber, data: []const u8) void {
        var rest = data;

        while (rest.len > 0) {
            const take = @min(self.rate - self.position, rest.len);

            keccak.xorBytes(&self.state, self.position, rest[0..take]);

            self.position += take;

            rest = rest[take..];

            if (self.position == self.rate) {
                self.permute();

                self.position = 0;
            }
        }
    }
};

// The state after bytepad(encode_string(N) || encode_string(S), rate), which every cSHAKE with a
// function name or customization starts from (3.3).
pub fn prefix(rate: usize, function_name: []const u8, customization: []const u8) [25]u64 {
    @setEvalBranchQuota(100_000);

    var absorber: Absorber = .{ .rate = rate };

    absorber.update(leftEncode(.{ .low = rate }).slice());

    absorber.update(leftEncode(bits(function_name.len)).slice());

    absorber.update(function_name);

    absorber.update(leftEncode(bits(customization.len)).slice());

    absorber.update(customization);

    if (absorber.position > 0) absorber.permute();

    return absorber.state;
}

// KMAC's bytepad(encode_string(K), rate) after its prefix (4.3).
pub fn absorbKey(sponge: *Keccak, key: []const u8) void {
    sponge.update(leftEncode(.{ .low = sponge.rate }).slice());

    sponge.update(leftEncode(bits(key.len)).slice());

    sponge.update(key);

    sponge.fillBlock();
}

// right_encode(L) of the output length in bytes, or of 0 for KMACXOF.
pub fn absorbLength(sponge: *Keccak, length: usize, xof: bool) void {
    sponge.update(rightEncode(if (xof) .{ .low = 0 } else bits(length)).slice());
}

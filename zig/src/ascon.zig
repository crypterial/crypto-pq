const std = @import("std");
const builtin = @import("builtin");

const ct = @import("ct.zig");

// Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 (NIST SP 800-232, section 5): a sponge of rate 64
// bits over the 320-bit Ascon permutation, bytes in little-endian order.

pub const State = [5]u64;

// The constants of rounds 4 to 15, the twelve rounds of Ascon-p[12].
const constants = [12]u64{ 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b };

// The states after Ascon-p[12](IV || 0^256) (SP 800-232, Appendix A.3).
pub const hash_iv: State = .{ 0x9b1e5494e934d681, 0x4bc3a01e333751d2, 0xae65396c6b34b81a, 0x3c7fd4a4d56a4db3, 0x1a5c464906c5976d };

pub const xof_iv: State = .{ 0xda82ce768d9447eb, 0xcc7ce6c75f1ef969, 0xe7508fd780085631, 0x0ee0ea53416b58cc, 0xe0547524db6f0bde };

pub const cxof_iv: State = .{ 0x675527c2a0e8de03, 0x43d12d7dc0377bbc, 0xe9901dec426e81b5, 0x2ab14907720780b6, 0x8f3f1d02d432bc46 };

// The longest customization string: 2048 bits.
pub const max_customization = 256;

// One round: the constant, the bitsliced 5-bit S-box and the linear layer, which XORs each word
// with two rotations of itself.
inline fn round(s: *State, constant: u64) void {
    var x0 = s[0];

    var x1 = s[1];

    var x2 = s[2] ^ constant;

    var x3 = s[3];

    var x4 = s[4];

    x0 ^= x4;

    x4 ^= x3;

    x2 ^= x1;

    const t0 = x0 ^ (~x1 & x2);

    const t1 = x1 ^ (~x2 & x3);

    const t2 = x2 ^ (~x3 & x4);

    const t3 = x3 ^ (~x4 & x0);

    const t4 = x4 ^ (~x0 & x1);

    x0 = t0 ^ t4;

    x1 = t1 ^ t0;

    x2 = ~t2;

    x3 = t3 ^ t2;

    x4 = t4;

    s[0] = linear(x0, 19, 28);

    s[1] = linear(x1, 61, 39);

    s[2] = linear(x2, 1, 6);

    s[3] = linear(x3, 10, 17);

    s[4] = linear(x4, 7, 41);
}

const barrier = builtin.zig_backend == .stage2_llvm and builtin.cpu.arch == .aarch64;

// x ^ rotr(x, a) ^ rotr(x, b). On AArch64 LLVM folds each rotation into its EOR, two instructions
// that each take two cycles one after the other; the rotations made opaque stay apart and run
// side by side, and the permutation, which waits on this chain, is shorter by a cycle a round.
inline fn linear(x: u64, comptime a: u6, comptime b: u6) u64 {
    return x ^ hidden(std.math.rotr(u64, x, a)) ^ hidden(std.math.rotr(u64, x, b));
}

inline fn hidden(x: u64) u64 {
    if (comptime !barrier) return x;

    if (@inComptime()) return x;

    return asm (""
        : [out] "=r" (-> u64),
        : [in] "0" (x),
    );
}

// Ascon-p[12]. The state is copied into locals so that it can live in registers across the rounds.
pub fn permute(state: *State) void {
    var s = state.*;

    rounds(&s);

    state.* = s;
}

inline fn rounds(s: *State) void {
    inline for (constants) |constant| round(s, constant);
}

// Fewer than eight bytes as the low bytes of a little-endian word.
fn partial(data: []const u8) u64 {
    var x: u64 = 0;

    for (data, 0..) |byte, i| x |= @as(u64, byte) << @intCast(8 * i);

    return x;
}

// The state after the customization string Z of Ascon-CXOF128: its length in bits as one block,
// then Z itself padded, a padded block even for an empty Z. The caller checks the length.
pub fn customize(customization: []const u8) State {
    @setEvalBranchQuota(100_000);

    var s = cxof_iv;

    s[0] ^= 8 * @as(u64, customization.len);

    permute(&s);

    var sponge: Sponge = .{ .state = s };

    sponge.update(customization);

    sponge.pad();

    return sponge.state;
}

// A sponge that absorbs a message and is then squeezed, eight bytes per block. Whole blocks are
// XORed in straight from the message; `used` counts the bytes of the current block.
pub const Sponge = struct {
    state: State,
    used: usize = 0,
    squeezing: bool = false,

    pub fn update(self: *Sponge, data: []const u8) void {
        if (self.squeezing) @panic("UNSUPPORTED: cannot update after read");

        var rest = data;

        if (self.used > 0) {
            const take = @min(8 - self.used, rest.len);

            self.state[0] ^= partial(rest[0..take]) << @intCast(8 * self.used);

            self.used += take;

            rest = rest[take..];

            if (self.used < 8) return;

            permute(&self.state);

            self.used = 0;
        }

        // The rounds inline here keep the state in registers from block to block.
        var s = self.state;

        while (rest.len >= 8) : (rest = rest[8..]) {
            s[0] ^= std.mem.readInt(u64, rest[0..8], .little);

            rounds(&s);
        }

        s[0] ^= partial(rest);

        self.state = s;

        self.used = rest.len;
    }

    // The padding byte after the message, and the permutation of the last block.
    fn pad(self: *Sponge) void {
        self.state[0] ^= @as(u64, 1) << @intCast(8 * self.used);

        permute(&self.state);

        self.used = 0;
    }

    // The next out.len bytes of output; the permutation runs between blocks only, never after the
    // last one read.
    pub fn read(self: *Sponge, out: []u8) void {
        if (!self.squeezing) {
            self.pad();

            self.squeezing = true;
        }

        var s = self.state;

        var used = self.used;

        var rest = out;

        while (rest.len > 0) {
            if (used == 8) {
                rounds(&s);

                used = 0;
            }

            const take = @min(8 - used, rest.len);

            const bytes = std.mem.toBytes(std.mem.nativeToLittle(u64, s[0]));

            @memcpy(rest[0..take], bytes[used..][0..take]);

            used += take;

            rest = rest[take..];
        }

        self.state = s;

        self.used = used;
    }

    pub fn wipe(self: *Sponge) void {
        ct.wipe(std.mem.asBytes(self));
    }
};

// One-shot: the whole blocks from data, the padded last block, and the output squeezed.
pub fn digest(initial: *const State, data: []const u8, out: []u8) void {
    var sponge: Sponge = .{ .state = initial.* };

    defer sponge.wipe();

    sponge.update(data);

    sponge.read(out);
}

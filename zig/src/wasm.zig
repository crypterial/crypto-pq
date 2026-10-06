const std = @import("std");

// WebAssembly SIMD kernels for the dispatch in cpu.zig. Each instruction here is a single
// arithmetic or shuffle instruction on the value stack, without branches or memory accesses that
// depend on data.

const I32x4 = @Vector(4, i32);

const I64x2 = @Vector(2, i64);

const U32x4 = @Vector(4, u32);

const U64x2 = @Vector(2, u64);

// The exact products of the low or the high two lanes of a and b. LLVM builds these only when it
// sees both operands sign-extended at the multiplication; a loop-invariant operand is extended
// once outside the loop instead, and the product becomes i64x2.mul, which engines emulate on CPUs
// without 64-bit lane multiplies (NEON, x86-64 before AVX-512).
inline fn productsLow(a: I32x4, b: I32x4) I64x2 {
    return asm ("local.get %[a]\nlocal.get %[b]\ni64x2.extmul_low_i32x4_s\nlocal.set %[r]"
        : [r] "=r" (-> I64x2),
        : [a] "r" (a),
          [b] "r" (b),
    );
}

inline fn productsHigh(a: I32x4, b: I32x4) I64x2 {
    return asm ("local.get %[a]\nlocal.get %[b]\ni64x2.extmul_high_i32x4_s\nlocal.set %[r]"
        : [r] "=r" (-> I64x2),
        : [a] "r" (a),
          [b] "r" (b),
    );
}

inline fn unsignedProductsLow(a: U32x4, b: U32x4) U64x2 {
    return asm ("local.get %[a]\nlocal.get %[b]\ni64x2.extmul_low_i32x4_u\nlocal.set %[r]"
        : [r] "=r" (-> U64x2),
        : [a] "r" (a),
          [b] "r" (b),
    );
}

inline fn unsignedProductsHigh(a: U32x4, b: U32x4) U64x2 {
    return asm ("local.get %[a]\nlocal.get %[b]\ni64x2.extmul_high_i32x4_u\nlocal.set %[r]"
        : [r] "=r" (-> U64x2),
        : [a] "r" (a),
          [b] "r" (b),
    );
}

// The lanes of x rotated left by k, with the two shifts added by an i64x2.add that LLVM cannot
// see through: LLVM would join them with an OR, its usual rotation, which V8 before version 15
// compiles in three instructions on Arm and the addition in two (SHL and USRA).
pub inline fn rotate(x: U64x2, comptime k: u6) U64x2 {
    comptime std.debug.assert(k != 0);

    const high = x << @splat(k);

    const low = x >> @splat(@as(u6, @intCast(64 - @as(u7, k))));

    return asm ("local.get %[a]\nlocal.get %[b]\ni64x2.add\nlocal.set %[r]"
        : [r] "=r" (-> U64x2),
        : [a] "r" (high),
          [b] "r" (low),
    );
}

// The high 32 bits of the four products a * b.
inline fn mulHigh(a: I32x4, b: I32x4) I32x4 {
    const low: I32x4 = @bitCast(productsLow(a, b));

    const high: I32x4 = @bitCast(productsHigh(a, b));

    return @shuffle(i32, low, high, [4]i32{ 1, 3, -2, -4 });
}

// ML-DSA's a * b * 2^-32 modulo q as mldsa.portable.montgomery computes it, four lanes at a time.
pub fn montgomery32(comptime q: i32, a: @Vector(8, i32), b: @Vector(8, i32), b_qinv: @Vector(8, i32)) @Vector(8, i32) {
    var out: [2]I32x4 = undefined;

    inline for (&out, 0..) |*half, h| {
        const lanes = [4]i32{ 4 * h, 4 * h + 1, 4 * h + 2, 4 * h + 3 };

        const x = @shuffle(i32, a, undefined, lanes);

        const y = @shuffle(i32, b, undefined, lanes);

        const t = x *% @shuffle(i32, b_qinv, undefined, lanes);

        half.* = mulHigh(x, y) - mulHigh(t, @splat(q));
    }

    return @shuffle(i32, out[0], out[1], [8]i32{ 0, 1, 2, 3, -1, -2, -3, -4 });
}

// The products a * m of eight lanes, shifted right by 32 + shift: ML-KEM's division by q.
pub fn productsShifted(a: @Vector(8, u32), comptime m: u32, comptime shift: u5) @Vector(8, u32) {
    var out: [2]U32x4 = undefined;

    inline for (&out, 0..) |*half, h| {
        const x = @shuffle(u32, a, undefined, [4]i32{ 4 * h, 4 * h + 1, 4 * h + 2, 4 * h + 3 });

        const low: U32x4 = @bitCast(unsignedProductsLow(x, @splat(m)));

        const high: U32x4 = @bitCast(unsignedProductsHigh(x, @splat(m)));

        half.* = @shuffle(u32, low, high, [4]i32{ 1, 3, -2, -4 }) >> @splat(shift);
    }

    return @shuffle(u32, out[0], out[1], [8]i32{ 0, 1, 2, 3, -1, -2, -3, -4 });
}

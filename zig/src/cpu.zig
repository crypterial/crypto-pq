const std = @import("std");
const builtin = @import("builtin");

const build_options = @import("build_options");

const aarch64 = @import("aarch64.zig");
const x86_64 = @import("x86_64.zig");

// Instructions of particular CPUs, on AArch64 and x86-64 only. A feature the build target
// guarantees is used without a check; any other is detected once at run time from the operating
// system or CPUID, never from Zig's own detection of the native CPU, which falls back to a
// generic CPU on cores it does not know. -Dportable=true leaves all of them out. Under -Dct=true
// only run-time detection counts, so that valgrind, which hides what it cannot run, decides.
pub const Feature = enum(u3) {
    // AArch64 SHA256H, SHA256H2, SHA256SU0 and SHA256SU1; x86-64 SHA-NI with SSSE3 and SSE4.1.
    sha256,
    // AArch64 SHA512H, SHA512H2, SHA512SU0 and SHA512SU1.
    sha512,
    // AArch64 EOR3, RAX1, XAR and BCAX, on cores where Keccak in vector registers beats the
    // scalar code: Apple's. Arm's Neoverse N2, V1 and V2 run them on one pipe only, and the
    // scalar code is reported faster there.
    sha3,
    // x86-64 AVX2, with the ymm state enabled by the operating system.
    avx2,
    // AArch64 PSTATE.DIT, data-independent timing.
    dit,
};

const arch = builtin.cpu.arch;

const os = builtin.os.tag;

// Big-endian AArch64 and the x32 ABI are left to the portable code, and so are Zig's own code
// generators (Debug builds for x86-64 use one): their assemblers lack these instructions.
const enabled = !build_options.portable and builtin.zig_backend == .stage2_llvm and (arch == .aarch64 or (arch == .x86_64 and @sizeOf(usize) == 8));

// Advanced SIMD is part of every AArch64 target that has vector registers, so its instructions
// need no detection: the lattice arithmetic uses the ones LLVM does not choose by itself.
pub const neon = enabled and arch == .aarch64 and builtin.cpu.has(.aarch64, .neon);

fn guaranteed(comptime feature: Feature) bool {
    if (!enabled or build_options.ct) return false;

    const cpu = builtin.cpu;

    return switch (arch) {
        .aarch64 => switch (feature) {
            .sha256 => cpu.has(.aarch64, .sha2),
            .sha512 => cpu.has(.aarch64, .sha3),
            .sha3 => cpu.has(.aarch64, .sha3) and (os.isDarwin() or std.mem.startsWith(u8, cpu.model.name, "apple")),
            .dit => cpu.has(.aarch64, .dit),
            .avx2 => false,
        },
        .x86_64 => switch (feature) {
            .sha256 => cpu.has(.x86, .sha) and cpu.has(.x86, .ssse3) and cpu.has(.x86, .sse4_1),
            .avx2 => cpu.has(.x86, .avx2),
            else => false,
        },
        else => false,
    };
}

fn detectable(comptime feature: Feature) bool {
    if (!enabled) return false;

    return switch (arch) {
        .aarch64 => if (os == .linux or os.isDarwin()) feature != .avx2 else if (os == .windows) feature == .sha256 or feature == .sha512 else false,
        .x86_64 => feature == .sha256 or feature == .avx2,
        else => false,
    };
}

// Whether the code for a feature can run on this target at all; when not, its kernels are not
// even compiled.
pub fn possible(comptime feature: Feature) bool {
    return guaranteed(feature) or detectable(feature);
}

pub inline fn has(comptime feature: Feature) bool {
    if (comptime guaranteed(feature)) return true;

    if (comptime !detectable(feature)) return false;

    return detected() & mask(feature) != 0;
}

fn mask(comptime feature: Feature) u8 {
    return @as(u8, 1) << @intFromEnum(feature);
}

// The features found, with bit 7 set once detection has run. Threads that detect at the same time
// store the same value.
var cache: std.atomic.Value(u8) = .init(0);

inline fn detected() u8 {
    const bits = cache.load(.monotonic);

    return if (bits != 0) bits else detect();
}

noinline fn detect() u8 {
    const bits = probe() | 0x80;

    cache.store(bits, .monotonic);

    return bits;
}

fn probe() u8 {
    var found: u8 = 0;

    if (!enabled) return found;

    switch (arch) {
        .aarch64 => if (os == .linux) {
            // HWCAP_SHA2, HWCAP_SHA512, HWCAP_SHA3 and HWCAP_DIT. With HWCAP_CPUID the kernel
            // emulates reads of MIDR_EL1, whose top byte names the implementer: 0x61 is Apple.
            const hwcap = auxiliary(std.elf.AT_HWCAP);

            if (hwcap & 1 << 6 != 0) found |= mask(.sha256);

            if (hwcap & 1 << 21 != 0) found |= mask(.sha512);

            if (hwcap & 1 << 17 != 0 and hwcap & 1 << 11 != 0 and aarch64.implementer() == 0x61) found |= mask(.sha3);

            if (hwcap & 1 << 24 != 0) found |= mask(.dit);
        } else if (os.isDarwin()) {
            // Every Apple core has fast SHA3 instructions.
            if (sysctl("hw.optional.arm.FEAT_SHA256")) found |= mask(.sha256);

            if (sysctl("hw.optional.arm.FEAT_SHA512")) found |= mask(.sha512);

            if (sysctl("hw.optional.arm.FEAT_SHA3")) found |= mask(.sha3);

            if (sysctl("hw.optional.arm.FEAT_DIT")) found |= mask(.dit);
        } else if (os == .windows) {
            // PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE and PF_ARM_SHA512_INSTRUCTIONS_AVAILABLE.
            // Windows on Arm runs on no Apple core, and it reports no DIT.
            if (windows.IsProcessorFeaturePresent(30) != 0) found |= mask(.sha256);

            if (windows.IsProcessorFeaturePresent(65) != 0) found |= mask(.sha512);
        },
        .x86_64 => {
            const features = x86_64.features();

            if (features.sha256) found |= mask(.sha256);

            if (features.avx2) found |= mask(.avx2);
        },
        else => {},
    }

    return found;
}

fn auxiliary(kind: usize) usize {
    if (builtin.link_libc) return std.c.getauxval(kind);

    return std.os.linux.getauxval(kind);
}

fn sysctl(name: [*:0]const u8) bool {
    var value: u64 = 0;

    var size: usize = @sizeOf(u64);

    return std.c.sysctlbyname(name, &value, &size, null, 0) == 0 and value != 0;
}

// std reads processor features below 64 from the shared user data; SHA-512's is 65.
const windows = struct {
    extern "kernel32" fn IsProcessorFeaturePresent(feature: u32) callconv(.winapi) c_int;
};

// PSTATE.DIT is set for the duration of an operation on secrets and then put back. With it, the
// instructions on Arm's data-independent-timing list take time independent of their operands, and
// Apple's cores also turn off the data memory-dependent prefetcher. A scope inside another leaves
// the bit to the outer one. valgrind cannot run the DIT instructions, so -Dct=true builds, which
// only detect at run time, see no DIT under it.
pub const Dit = struct {
    set: bool,

    pub inline fn enter() Dit {
        if (comptime !possible(.dit)) return .{ .set = false };

        if (!has(.dit)) return .{ .set = false };

        return .{ .set = aarch64.enterDit() };
    }

    pub inline fn leave(self: Dit) void {
        if (comptime !possible(.dit)) return;

        if (self.set) aarch64.leaveDit();
    }
};

test "the guaranteed features are detected" {
    inline for (comptime std.enums.values(Feature)) |feature| {
        if (comptime (guaranteed(feature) and detectable(feature))) {
            try std.testing.expect(detect() & mask(feature) != 0);
        }
    }
}

test "detection runs once and is cached" {
    const first = detected();

    try std.testing.expect(first & 0x80 != 0);

    try std.testing.expectEqual(first, detected());

    try std.testing.expectEqual(first, cache.load(.monotonic));
}

test "DIT is set inside a scope and restored after it" {
    if (comptime !possible(.dit)) return error.SkipZigTest;

    if (!has(.dit)) return error.SkipZigTest;

    const before = aarch64.ditIsSet();

    {
        const outer = Dit.enter();

        defer outer.leave();

        try std.testing.expect(aarch64.ditIsSet());

        {
            const inner = Dit.enter();

            defer inner.leave();

            try std.testing.expect(!inner.set);

            try std.testing.expect(aarch64.ditIsSet());
        }

        try std.testing.expect(aarch64.ditIsSet());
    }

    try std.testing.expectEqual(before, aarch64.ditIsSet());
}

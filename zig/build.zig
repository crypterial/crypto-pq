const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const ct = b.option(bool, "ct", "Mark secrets for valgrind's constant-time check (zig build ct)") orelse false;

    const portable = b.option(bool, "portable", "Use only the portable code: no SHA-2, SHA3, SHA-NI, AVX2 or NEON instructions, and no DIT") orelse false;

    const options = b.addOptions();

    options.addOption(bool, "ct", ct);

    options.addOption(bool, "portable", portable);

    const build_options = options.createModule();

    const crypto_pq = b.addModule("crypto_pq", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = &.{.{ .name = "build_options", .module = build_options }},
    });

    const vectors = b.createModule(.{
        .root_source_file = b.path("test/vectors.zig"),
        .target = target,
        .optimize = optimize,
    });

    const step = b.step("test", "Run the tests");

    const tests = b.addTest(.{
        .name = "main",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "crypto_pq", .module = crypto_pq },
                .{ .name = "vectors", .module = vectors },
            },
        }),
    });

    run(b, step, tests);

    // The test binaries also install, to run where the build cannot run them: under an emulator
    // given an explicit CPU model (one registered with binfmt_misc would run them with its default
    // CPU, whatever QEMU_CPU says), or on a machine where only a foreign Zig runs. They read
    // ../vectors, so they run from this directory.
    const binaries = b.step("test-binaries", "Install the test binaries in zig-out/bin");

    binaries.dependOn(&b.addInstallArtifact(tests, .{}).step);

    // X25519, the key caches, the Merkle cache and the CPU-specific kernels are internal, so their
    // tests live in their own files. The kernels' tests also run alone, for emulated CPU models.
    const kernels = b.step("kernels", "Run only the tests of the CPU-specific kernels");

    for ([_][2][]const u8{
        .{ "x25519", "src/x25519.zig" },
        .{ "cache", "src/cache.zig" },
        .{ "merkle", "src/merkle.zig" },
        .{ "kernels", "src/cpu_test.zig" },
    }) |entry| {
        const name, const path = entry;

        const artifact = b.addTest(.{
            .name = name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(path),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "vectors", .module = vectors },
                    .{ .name = "build_options", .module = build_options },
                },
            }),
        });

        run(b, step, artifact);

        binaries.dependOn(&b.addInstallArtifact(artifact, .{}).step);

        if (std.mem.eql(u8, name, "kernels")) run(b, kernels, artifact);
    }

    // The assembly in src/asm/ is generated; the tests check that it is current.
    const generator = b.addExecutable(.{
        .name = "asm",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/asm.zig"),
            .target = b.graph.host,
        }),
    });

    step.dependOn(generate(b, generator, "--check"));

    b.step("asm", "Rewrite src/asm/ from tools/asm.zig").dependOn(generate(b, generator, "--write"));

    const bench = b.addRunArtifact(b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/bench.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "crypto_pq", .module = crypto_pq }},
        }),
    }));

    if (b.args) |args| bench.addArgs(args);

    b.step("bench", "Run the benchmarks; an argument selects the cases whose names contain it").dependOn(&bench.step);

    capi(b, target, optimize, build_options, vectors, step, binaries);

    const check = b.step("ct", "Run the constant-time check under valgrind; needs -Dct=true");

    if (!ct) {
        check.dependOn(&b.addFail("zig build ct needs -Dct=true").step);

        return;
    }

    // Runtime safety checks branch on the values they check, secret ones included, so the check
    // runs on ReleaseFast code. X25519 is internal: its check is a test in its own file.
    const checker = b.addExecutable(.{
        .name = "ct",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/ct.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .valgrind = true,
            .imports = &.{.{ .name = "crypto_pq", .module = crypto_pq }},
        }),
    });

    const x25519 = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/x25519.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .valgrind = true,
            .imports = &.{
                .{ .name = "vectors", .module = vectors },
                .{ .name = "build_options", .module = build_options },
            },
        }),
        .filters = &.{"constant time"},
    });

    for ([_]*std.Build.Step.Compile{ checker, x25519, capiConstantTime(b, target, build_options) }) |artifact| {
        // The long unrolled AVX2 blocks of the vector code exhaust the temporary storage of
        // valgrind's translator unless it translates fewer instructions at a time; how much it
        // translates at once does not change what memcheck reports.
        const command = b.addSystemCommand(&.{
            "valgrind",
            "--error-exitcode=1",
            "-q",
            "--vex-guest-max-insns=10",
            "--vex-guest-chase=no",
            "--vex-iropt-unroll-thresh=0",
        });

        command.addArtifactArg(artifact);

        check.dependOn(&command.step);
    }
}

fn generate(b: *std.Build, generator: *std.Build.Step.Compile, mode: []const u8) *std.Build.Step {
    const command = b.addRunArtifact(generator);

    command.addArg(mode);

    command.addDirectoryArg(b.path("src/asm"));

    command.has_side_effects = true;

    return &command.step;
}

fn run(b: *std.Build, step: *std.Build.Step, artifact: *std.Build.Step.Compile) void {
    const command = b.addRunArtifact(artifact);

    command.setCwd(b.path("."));

    step.dependOn(&command.step);
}

const Families = struct {
    ml_kem: bool = false,
    x_wing: bool = false,
    ml_dsa: bool = false,
    slh_dsa: bool = false,
    stateful: bool = false,
    hash: bool = false,
};

const every_family: Families = .{ .ml_kem = true, .x_wing = true, .ml_dsa = true, .slh_dsa = true, .stateful = true, .hash = true };

// One WebAssembly module per family, so that an application compiles only what it uses.
const wasm_modules = [_]struct { []const u8, Families }{
    .{ "crypto_pq_ml_kem", .{ .ml_kem = true } },
    .{ "crypto_pq_ml_dsa", .{ .ml_dsa = true } },
    .{ "crypto_pq_slh_dsa", .{ .slh_dsa = true } },
    .{ "crypto_pq_stateful", .{ .stateful = true } },
    .{ "crypto_pq_x_wing_hash", .{ .x_wing = true, .hash = true } },
};

// The shared libraries that ship: Linux without libc, one file for glibc and musl alike (on
// AArch64 it takes getauxval, for the page size and the CPU features, from the process's libc),
// macOS 13 or later, and Windows. The CPU is each architecture's baseline; faster instructions are
// detected at run time.
const native_targets = [_]struct { []const u8, []const u8, []const u8 }{
    .{ "x86_64-linux-none", "x86_64-linux", "libcrypto_pq.so" },
    .{ "aarch64-linux-none", "aarch64-linux", "libcrypto_pq.so" },
    .{ "riscv64-linux-none", "riscv64-linux", "libcrypto_pq.so" },
    .{ "x86_64-macos.13.0", "x86_64-macos", "libcrypto_pq.dylib" },
    .{ "aarch64-macos.13.0", "aarch64-macos", "libcrypto_pq.dylib" },
    .{ "x86_64-windows-gnu", "x86_64-windows", "crypto_pq.dll" },
    .{ "aarch64-windows-gnu", "aarch64-windows", "crypto_pq.dll" },
};

// The stack of a WebAssembly instance sits below its data, so that an overflow traps instead of
// overwriting it. The core bounds every operation to 64 KiB (test/stack.zig); the deepest export
// measured in a module uses 35 KB.
const wasm_stack_size = 64 << 10;

fn capiOptions(b: *std.Build, families: Families, exports: bool) *std.Build.Module {
    const options = b.addOptions();

    inline for (@typeInfo(Families).@"struct".fields) |field| options.addOption(bool, field.name, @field(families, field.name));

    options.addOption(bool, "exports", exports);

    return options.createModule();
}

fn capiModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, build_options: *std.Build.Module, families: Families, strip: bool) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path("src/capi.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip,
        .single_threaded = if (target.result.cpu.arch.isWasm()) true else null,
        .imports = &.{
            .{ .name = "build_options", .module = build_options },
            .{ .name = "capi_options", .module = capiOptions(b, families, true) },
        },
    });
}

fn capiLibrary(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, build_options: *std.Build.Module) *std.Build.Step.Compile {
    const library = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "crypto_pq",
        .root_module = capiModule(b, target, optimize, build_options, every_family, optimize != .Debug),
    });

    // No build path may enter the binary.
    library.install_name = "@rpath/libcrypto_pq.dylib";

    return library;
}

fn capiWasm(b: *std.Build, name: []const u8, families: Families, build_options: *std.Build.Module, strip: bool) *std.Build.Step.Compile {
    const target = b.resolveTargetQuery(std.Target.Query.parse(.{ .arch_os_abi = "wasm32-freestanding", .cpu_features = "lime1+simd128" }) catch unreachable);

    const module = b.addExecutable(.{
        .name = name,
        .root_module = capiModule(b, target, .ReleaseFast, build_options, families, strip),
    });

    module.entry = .disabled;

    module.rdynamic = true;

    module.stack_size = wasm_stack_size;

    return module;
}

// The C ABI of src/capi.zig: `lib` builds the shared library for the target, `wasm` the
// WebAssembly modules, and `dist` every library and module that ships, always in ReleaseFast. The
// output of `dist` depends on nothing but the sources and the Zig version, so builds on different
// hosts compare byte for byte.
fn capi(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, build_options: *std.Build.Module, vectors: *std.Build.Module, tests: *std.Build.Step, binaries: *std.Build.Step) void {
    b.step("lib", "Build the C ABI shared library for the target").dependOn(&b.addInstallArtifact(capiLibrary(b, target, optimize, build_options), .{}).step);

    const wasm = b.step("wasm", "Build the C ABI WebAssembly modules, one per family");

    const dist = b.step("dist", "Build every shipped C ABI library and WebAssembly module into zig-out/dist");

    // The constant-time lint of the shipped modules, each with a twin built with names.
    const lint = b.addRunArtifact(b.addExecutable(.{
        .name = "wasm_lint",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/wasm_lint.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    }));

    if (b.args) |args| lint.addArgs(args);

    lint.addFileArg(b.path("tools/wasm_lint.txt"));

    b.step("wasm-lint", "Check the selects and branches of the WebAssembly modules against tools/wasm_lint.txt").dependOn(&lint.step);

    for (wasm_modules) |entry| {
        const name, const families = entry;

        const module = capiWasm(b, name, families, build_options, true);

        wasm.dependOn(&b.addInstallArtifact(module, .{}).step);

        dist.dependOn(&b.addInstallFileWithDir(module.getEmittedBin(), .{ .custom = "dist/wasm" }, b.fmt("{s}.wasm", .{name})).step);

        lint.addArg(name);

        lint.addArtifactArg(module);

        lint.addArtifactArg(capiWasm(b, name, families, build_options, false));
    }

    for (native_targets) |entry| {
        const query, const directory, const file = entry;

        const library = capiLibrary(b, b.resolveTargetQuery(std.Target.Query.parse(.{ .arch_os_abi = query }) catch unreachable), .ReleaseFast, build_options);

        dist.dependOn(&b.addInstallFileWithDir(library.getEmittedBin(), .{ .custom = b.fmt("dist/{s}", .{directory}) }, file).step);
    }

    const capi_tests = b.addTest(.{
        .name = "capi",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/capi_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "build_options", .module = build_options },
                .{ .name = "capi_options", .module = capiOptions(b, every_family, false) },
                .{ .name = "vectors", .module = vectors },
            },
        }),
    });

    run(b, tests, capi_tests);

    run(b, b.step("test-capi", "Run only the C ABI tests"), capi_tests);

    binaries.dependOn(&b.addInstallArtifact(capi_tests, .{}).step);
}

// The secret-handling entry points of the C ABI, driven as a C caller would with every secret
// marked undefined; like the library's own check, on ReleaseFast code.
fn capiConstantTime(b: *std.Build, target: std.Build.ResolvedTarget, build_options: *std.Build.Module) *std.Build.Step.Compile {
    return b.addExecutable(.{
        .name = "capi-ct",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/capi_ct.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .valgrind = true,
            .imports = &.{
                .{ .name = "build_options", .module = build_options },
                .{ .name = "capi_options", .module = capiOptions(b, every_family, false) },
            },
        }),
    });
}

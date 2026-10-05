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

    for ([_]*std.Build.Step.Compile{ checker, x25519 }) |artifact| {
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

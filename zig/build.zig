const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const ct = b.option(bool, "ct", "Mark secrets for valgrind's constant-time check (zig build ct)") orelse false;

    const options = b.addOptions();

    options.addOption(bool, "ct", ct);

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

    // X25519 and the Merkle cache are internal, so their tests live in their own files.
    for ([_][]const u8{ "src/x25519.zig", "src/merkle.zig" }) |path| {
        run(b, step, b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(path),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "vectors", .module = vectors },
                    .{ .name = "build_options", .module = build_options },
                },
            }),
        }));
    }

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
        const command = b.addSystemCommand(&.{ "valgrind", "--error-exitcode=1", "-q" });

        command.addArtifactArg(artifact);

        check.dependOn(&command.step);
    }
}

fn run(b: *std.Build, step: *std.Build.Step, artifact: *std.Build.Step.Compile) void {
    const command = b.addRunArtifact(artifact);

    command.setCwd(b.path("."));

    step.dependOn(&command.step);
}

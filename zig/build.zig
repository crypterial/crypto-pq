const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const crypto_pq = b.addModule("crypto_pq", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
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
                .imports = &.{.{ .name = "vectors", .module = vectors }},
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
}

fn run(b: *std.Build, step: *std.Build.Step, artifact: *std.Build.Step.Compile) void {
    const command = b.addRunArtifact(artifact);

    command.setCwd(b.path("."));

    step.dependOn(&command.step);
}

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const crypto_pq = b.addModule("crypto_pq", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/hash.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "crypto_pq", .module = crypto_pq }},
        }),
    });

    const run = b.addRunArtifact(tests);

    run.setCwd(b.path("."));

    b.step("test", "Run the tests").dependOn(&run.step);
}

const std = @import("std");
const builtin = @import("builtin");

const ct = @import("ct.zig");
const Error = @import("errors.zig").Error;

const os = builtin.os.tag;

extern "c" fn getrandom(buffer: [*]u8, length: usize, flags: c_uint) isize;

extern "c" fn getentropy(buffer: [*]u8, length: usize) c_int;

extern "bcryptprimitives" fn ProcessPrng(data: [*]u8, length: usize) callconv(.winapi) std.os.windows.BOOL;

// Fills `buffer` from the operating system's random number generator; there is no fallback.
// The constant-time check treats random bytes as secret until the library declassifies them.
pub fn fill(buffer: []u8) Error!void {
    try system(buffer);

    ct.secret(buffer);
}

fn system(buffer: []u8) Error!void {
    if (os == .linux) return linuxGetrandom(buffer);

    if (os.isDarwin() or os == .openbsd) return chunkedGetentropy(buffer);

    switch (os) {
        .freebsd, .netbsd, .dragonfly, .illumos => return libcGetrandom(buffer),
        .windows => if (!ProcessPrng(buffer.ptr, buffer.len).toBool()) return error.RngFailure,
        .wasi => if (std.os.wasi.random_get(buffer.ptr, buffer.len) != .SUCCESS) return error.RngFailure,
        else => return error.RngFailure,
    }
}

fn linuxGetrandom(buffer: []u8) Error!void {
    const linux = std.os.linux;

    var rest = buffer;

    while (rest.len > 0) {
        const result = linux.getrandom(rest.ptr, rest.len, 0);

        switch (linux.errno(result)) {
            .SUCCESS => {
                if (result == 0) return error.RngFailure;

                rest = rest[result..];
            },
            .INTR => {},
            else => return error.RngFailure,
        }
    }
}

fn libcGetrandom(buffer: []u8) Error!void {
    var rest = buffer;

    while (rest.len > 0) {
        const result = getrandom(rest.ptr, rest.len, 0);

        if (result > 0) {
            rest = rest[@intCast(result)..];
        } else if (result == 0 or std.c.errno(result) != .INTR) {
            return error.RngFailure;
        }
    }
}

// getentropy returns at most 256 bytes per call.
fn chunkedGetentropy(buffer: []u8) Error!void {
    var rest = buffer;

    while (rest.len > 0) {
        const size = @min(rest.len, 256);

        if (getentropy(rest.ptr, size) != 0) return error.RngFailure;

        rest = rest[size..];
    }
}

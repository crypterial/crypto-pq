const std = @import("std");

const testing = std.testing;

const Allocator = std.mem.Allocator;

pub const Fields = struct {
    keys: [16][]const u8 = undefined,
    values: [16][]const u8 = undefined,
    len: usize = 0,

    fn put(self: *Fields, key: []const u8, value: []const u8) void {
        for (self.keys[0..self.len], 0..) |existing, i| {
            if (std.mem.eql(u8, existing, key)) {
                self.values[i] = value;

                return;
            }
        }

        self.keys[self.len] = key;

        self.values[self.len] = value;

        self.len += 1;
    }

    pub fn find(self: Fields, key: []const u8) ?[]const u8 {
        for (self.keys[0..self.len], self.values[0..self.len]) |k, v| {
            if (std.mem.eql(u8, k, key)) return v;
        }

        return null;
    }

    pub fn get(self: Fields, key: []const u8) []const u8 {
        return self.find(key) orelse @panic("missing field");
    }

    pub fn is(self: Fields, key: []const u8, value: []const u8) bool {
        return std.mem.eql(u8, self.get(key), value);
    }
};

pub const Record = struct {
    header: Fields,
    values: Fields,
};

// Plain-text vectors: `[key = value]` header lines persist until replaced, records are `key =
// value` lines separated by blank lines, and `#` starts a comment.
pub const Vectors = struct {
    text: []u8,
    records: []Record,

    pub fn load(name: []const u8, field: []const u8) !Vectors {
        var path: [128]u8 = undefined;

        const text = try std.Io.Dir.cwd().readFileAlloc(testing.io, try std.fmt.bufPrint(&path, "../vectors/{s}", .{name}), testing.allocator, .unlimited);

        errdefer testing.allocator.free(text);

        var records: std.ArrayList(Record) = .empty;

        errdefer records.deinit(testing.allocator);

        var header: Fields = .{};

        var values: Fields = .{};

        var expected: usize = 0;

        var lines = std.mem.splitScalar(u8, text, '\n');

        while (true) {
            const raw = lines.next();

            const line = std.mem.trim(u8, raw orelse "", " \t\r");

            if (std.mem.startsWith(u8, line, field) and std.mem.startsWith(u8, line[field.len..], " =")) expected += 1;

            if (line.len >= 2 and line[0] == '[' and line[line.len - 1] == ']') {
                const key, const value = std.mem.cutScalar(u8, line[1 .. line.len - 1], '=') orelse .{ line[1 .. line.len - 1], "" };

                header.put(std.mem.trim(u8, key, " "), std.mem.trim(u8, value, " "));
            } else if (line.len > 0 and line[0] != '#' and std.mem.findScalar(u8, line, '=') != null) {
                const key, const value = std.mem.cutScalar(u8, line, '=').?;

                values.put(std.mem.trim(u8, key, " "), std.mem.trim(u8, value, " "));
            } else if (values.len > 0) {
                try records.append(testing.allocator, .{ .header = header, .values = values });

                values = .{};
            }

            if (raw == null) break;
        }

        var parsed: usize = 0;

        for (records.items) |r| {
            if (r.values.find(field) != null) parsed += 1;
        }

        if (expected == 0 or parsed != expected) {
            std.debug.print("{s}: parsed {d} records, expected {d}\n", .{ name, parsed, expected });

            return error.TestUnexpectedResult;
        }

        return .{ .text = text, .records = try records.toOwnedSlice(testing.allocator) };
    }

    pub fn deinit(self: Vectors) void {
        testing.allocator.free(self.records);

        testing.allocator.free(self.text);
    }
};

pub fn decode(allocator: Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);

    errdefer allocator.free(out);

    return std.fmt.hexToBytes(out, hex);
}

pub fn decodeArray(comptime n: usize, hex: []const u8) ![n]u8 {
    var out: [n]u8 = undefined;

    if (hex.len != 2 * n) return error.TestUnexpectedResult;

    _ = try std.fmt.hexToBytes(&out, hex);

    return out;
}

pub fn number(comptime T: type, text: []const u8) !T {
    return std.fmt.parseInt(T, text, 10);
}

// A minimal DER writer, so that tests can build encodings the library itself never produces.
pub fn der(allocator: Allocator, tag: u8, parts: []const []const u8) ![]u8 {
    var length: usize = 0;

    for (parts) |part| length += part.len;

    var header: [6]u8 = undefined;

    var size: usize = 2;

    header[0] = tag;

    if (length < 0x80) {
        header[1] = @intCast(length);
    } else {
        const bytes = (@as(usize, std.math.log2_int(usize, length)) + 8) / 8;

        header[1] = @intCast(0x80 | bytes);

        for (0..bytes) |i| {
            header[2 + i] = @truncate(length >> @intCast(8 * (bytes - 1 - i)));
        }

        size += bytes;
    }

    const out = try allocator.alloc(u8, size + length);

    @memcpy(out[0..size], header[0..size]);

    var offset = size;

    for (parts) |part| {
        @memcpy(out[offset..][0..part.len], part);

        offset += part.len;
    }

    return out;
}

// CRYPTO_PQ_SLOW=1 enables the two cases too slow for every run.
pub fn slow() bool {
    return testing.environ.containsUnempty(testing.allocator, "CRYPTO_PQ_SLOW") catch false;
}

const max_threads = 4;

// Runs `run` on every record from a few threads; the long vector suites take minutes otherwise.
// Each call gets an arena that is reset between records.
pub fn parallel(records: []const Record, context: anytype, comptime run: fn (@TypeOf(context), Record, Allocator) anyerror!void) !void {
    const Shared = struct {
        next: std.atomic.Value(usize) = .init(0),
        failures: std.atomic.Value(usize) = .init(0),
        records: []const Record,
        context: @TypeOf(context),

        fn work(shared: *@This()) void {
            var arena = std.heap.ArenaAllocator.init(testing.allocator);

            defer arena.deinit();

            while (true) {
                const index = shared.next.fetchAdd(1, .monotonic);

                if (index >= shared.records.len) return;

                _ = arena.reset(.retain_capacity);

                run(shared.context, shared.records[index], arena.allocator()) catch |err| {
                    _ = shared.failures.fetchAdd(1, .monotonic);

                    std.debug.print("record {d} (tcId {s}) failed: {s}\n", .{ index, shared.records[index].values.find("tcId") orelse "-", @errorName(err) });
                };
            }
        }
    };

    var shared: Shared = .{ .records = records, .context = context };

    {
        var threads: [max_threads]std.Thread = undefined;

        var spawned: usize = 0;

        defer for (threads[0..spawned]) |thread| thread.join();

        while (spawned < @min(std.Thread.getCpuCount() catch 1, max_threads)) : (spawned += 1) {
            threads[spawned] = try std.Thread.spawn(.{}, Shared.work, .{&shared});
        }
    }

    if (shared.failures.load(.monotonic) != 0) return error.TestUnexpectedResult;
}

// An allocator that records whether memory was freed while it still held one of `secrets`, so
// that a test can check that keys wipe what they free.
pub const WipeCheck = struct {
    child: Allocator,
    secrets: []const []const u8,
    leaked: bool = false,
    frees: usize = 0,

    pub fn allocator(self: *WipeCheck) Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        const self: *WipeCheck = @ptrCast(@alignCast(context));

        return self.child.rawAlloc(len, alignment, ret);
    }

    fn resize(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) bool {
        const self: *WipeCheck = @ptrCast(@alignCast(context));

        return self.child.rawResize(memory, alignment, new_len, ret);
    }

    fn remap(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret: usize) ?[*]u8 {
        const self: *WipeCheck = @ptrCast(@alignCast(context));

        return self.child.rawRemap(memory, alignment, new_len, ret);
    }

    fn free(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret: usize) void {
        const self: *WipeCheck = @ptrCast(@alignCast(context));

        for (self.secrets) |secret| {
            if (std.mem.indexOf(u8, memory, secret) != null) self.leaked = true;
        }

        self.frees += 1;

        self.child.rawFree(memory, alignment, ret);
    }
};

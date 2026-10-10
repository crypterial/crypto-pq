const std = @import("std");

const Io = std.Io;

const Allocator = std.mem.Allocator;

// A constant-time lint for the WebAssembly modules of the C ABI. WebAssembly promises nothing
// about timing, and V8's baseline compiler turns `select` into a branch on some CPUs, so every
// select, br_if, if and br_table in the code that the secret-handling exports reach, whose
// condition may depend on a value loaded from linear memory, must be in the reviewed list given
// as the first argument. Values from memory count as secret: secrets live there, and pointers
// and lengths arrive as arguments. Each module comes twice, as shipped and as built with names:
// the names, matched by function index, label what the list reviews.
//
//   wasm_lint <list> <name> <shipped.wasm> <named.wasm> [<name> <shipped.wasm> <named.wasm>...]
//   wasm_lint --print ...    prints the findings in the list's format instead of checking them

// The exports that handle no secret: queries, public keys and verification.
const public_exports = [_][]const u8{
    "cpq_abi_version",
    "cpq_build_info",
    "cpq_cpu_features",
    "cpq_enable_data_independent_timing",
    "cpq_slot_size",
    "cpq_slot_align",
    "cpq_slot_info",
    "cpq_stack_low",
    "cpq_stack_high",
    "cpq_alloc",
    "cpq_kem_import_public",
    "cpq_kem_export_public",
    "cpq_sig_import_public",
    "cpq_sig_export_public",
    "cpq_sig_verify",
    "cpq_stateful_info",
    "cpq_stateful_verify",
    "cpq_stateful_check_public_key",
};

const Kind = enum { select, br_if, @"if", br_table };

const Failure = error{ Malformed, Unsupported, Inconsistent } || Allocator.Error;

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    fn byte(self: *Reader) Failure!u8 {
        if (self.at >= self.bytes.len) return error.Malformed;

        self.at += 1;

        return self.bytes[self.at - 1];
    }

    fn take(self: *Reader, n: usize) Failure![]const u8 {
        if (n > self.bytes.len - self.at) return error.Malformed;

        self.at += n;

        return self.bytes[self.at - n .. self.at];
    }

    fn unsigned(self: *Reader) Failure!u64 {
        var result: u64 = 0;

        var shift: u7 = 0;

        while (true) {
            const b = try self.byte();

            if (shift > 63) return error.Malformed;

            result |= @as(u64, b & 0x7f) << @intCast(shift);

            if (b < 0x80) return result;

            shift += 7;
        }
    }

    fn signed(self: *Reader) Failure!i64 {
        var result: i64 = 0;

        var shift: u7 = 0;

        while (true) {
            const b = try self.byte();

            if (shift > 63) return error.Malformed;

            result |= @as(i64, b & 0x7f) << @intCast(shift);

            shift += 7;

            if (b < 0x80) {
                if (shift < 64 and b & 0x40 != 0) result |= @as(i64, -1) << @intCast(shift);

                return result;
            }
        }
    }

    fn index(self: *Reader) Failure!u32 {
        const value = try self.unsigned();

        if (value > std.math.maxInt(u32)) return error.Malformed;

        return @intCast(value);
    }

    fn name(self: *Reader) Failure![]const u8 {
        return self.take(try self.index());
    }
};

const FuncType = struct {
    params: u32,
    results: u32,
};

// Opcodes after 0xfc and 0xfd are numbered from 0x100 and 0x200 here.
const Instr = struct {
    op: u16,
    offset: u32,
    a: u32 = 0,
    b: u32 = 0,
    // block, loop and if: the instruction index of the matching end, and of else (0 for none).
    end: u32 = 0,
    @"else": u32 = 0,
};

const Function = struct {
    type: u32,
    locals: u32,
    code: []Instr,
    labels: []u32,
    // Where the instructions start in the file.
    start: usize,
};

const Module = struct {
    types: []FuncType,
    functions: []Function,
    exports: std.StringHashMapUnmanaged(u32) = .empty,
    table: []u32,
    imports: u32,
    sections: [12][]const u8 = @splat(&.{}),
    names: std.AutoHashMapUnmanaged(u32, []const u8) = .empty,
};

fn blockArity(module: *const Module, block_type: u32) Failure!FuncType {
    return switch (block_type) {
        0x40 => .{ .params = 0, .results = 0 },
        0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x70, 0x6f => .{ .params = 0, .results = 1 },
        else => {
            const index = block_type - 0x100;

            if (index >= module.types.len) return error.Malformed;

            return module.types[index];
        },
    };
}

fn parseCode(allocator: Allocator, reader: *Reader, labels: *std.ArrayList(u32)) Failure![]Instr {
    var code: std.ArrayList(Instr) = .empty;

    var open: std.ArrayList(u32) = .empty;

    defer open.deinit(allocator);

    const start = reader.at;

    while (reader.at < reader.bytes.len) {
        const offset: u32 = @intCast(reader.at - start);

        const first = try reader.byte();

        var instr: Instr = .{ .op = first, .offset = offset };

        switch (first) {
            0x00, 0x01, 0x0f, 0x1a, 0x1b, 0xd1 => {},
            0x02, 0x03, 0x04 => {
                const peek = reader.bytes[reader.at];

                if (peek == 0x40 or peek >= 0x6f and peek <= 0x7f) {
                    instr.a = try reader.byte();
                } else {
                    const value = try reader.signed();

                    if (value < 0) return error.Malformed;

                    instr.a = @as(u32, @intCast(value)) + 0x100;
                }

                try open.append(allocator, @intCast(code.items.len));
            },
            0x05 => {
                const owner = open.getLastOrNull() orelse return error.Malformed;

                code.items[owner].@"else" = @intCast(code.items.len);
            },
            0x0b => {
                if (open.pop()) |owner| code.items[owner].end = @intCast(code.items.len);
            },
            0x0c, 0x0d, 0x10, 0x12, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0xd2 => instr.a = try reader.index(),
            0x0e => {
                const count = try reader.index();

                instr.a = @intCast(labels.items.len);

                instr.b = count + 1;

                for (0..count + 1) |_| try labels.append(allocator, try reader.index());
            },
            0x11, 0x13 => {
                instr.a = try reader.index();

                instr.b = try reader.index();
            },
            0x1c => {
                const count = try reader.index();

                _ = try reader.take(count);
            },
            0x28...0x3e => {
                _ = try reader.index();

                _ = try reader.index();
            },
            0x3f, 0x40, 0xd0 => _ = try reader.byte(),
            0x41, 0x42 => _ = try reader.signed(),
            0x43 => _ = try reader.take(4),
            0x44 => _ = try reader.take(8),
            0x45...0xc4 => {},
            0xfc => {
                const sub = try reader.index();

                if (sub > 17) return error.Unsupported;

                instr.op = @intCast(0x100 + sub);

                switch (sub) {
                    0...7 => {},
                    8, 12, 14 => {
                        _ = try reader.index();

                        _ = try reader.index();
                    },
                    10 => _ = try reader.take(2),
                    11 => _ = try reader.byte(),
                    else => _ = try reader.index(),
                }
            },
            0xfd => {
                const sub = try reader.index();

                if (sub > 255) return error.Unsupported;

                instr.op = @intCast(0x200 + sub);

                switch (sub) {
                    0...11, 92, 93 => {
                        _ = try reader.index();

                        _ = try reader.index();
                    },
                    12, 13 => _ = try reader.take(16),
                    21...34 => _ = try reader.byte(),
                    84...91 => {
                        _ = try reader.index();

                        _ = try reader.index();

                        _ = try reader.byte();
                    },
                    else => {},
                }
            },
            else => return error.Unsupported,
        }

        try code.append(allocator, instr);
    }

    if (open.items.len != 0) return error.Malformed;

    return code.toOwnedSlice(allocator);
}

const simd_unary = [_]u8{ 77, 83, 94, 95, 96, 97, 98, 99, 100, 103, 104, 105, 106, 116, 117, 122, 124, 125, 126, 127, 128, 129, 131, 132, 135, 136, 137, 138, 148, 160, 161, 163, 164, 167, 168, 169, 170, 192, 193, 195, 196, 199, 200, 201, 202, 224, 225, 227, 236, 237, 239, 248, 249, 250, 251, 252, 253, 254, 255 };

const simd_unused = [_]u8{ 154, 162, 165, 166, 175, 176, 178, 179, 180, 187, 194, 197, 198, 207, 208, 210, 211, 212, 226, 238 };

// How many values an instruction without control flow pops and pushes.
fn effect(op: u16) Failure!struct { u8, u8 } {
    return switch (op) {
        0x01 => .{ 0, 0 },
        0x1a => .{ 1, 0 },
        0x25 => .{ 1, 1 },
        0x26 => .{ 2, 0 },
        0x28...0x35 => .{ 1, 1 },
        0x36...0x3e => .{ 2, 0 },
        0x3f => .{ 0, 1 },
        0x40 => .{ 1, 1 },
        0x41...0x44 => .{ 0, 1 },
        0x45, 0x50, 0x67...0x69, 0x79...0x7b, 0x8b...0x91, 0x99...0x9f, 0xa7...0xc4, 0xd1 => .{ 1, 1 },
        0x46...0x4f, 0x51...0x66, 0x6a...0x78, 0x7c...0x8a, 0x92...0x98, 0xa0...0xa6 => .{ 2, 1 },
        0xd0, 0xd2 => .{ 0, 1 },
        0x100...0x107 => .{ 1, 1 },
        0x108, 0x10a, 0x10b, 0x10c, 0x10e, 0x111 => .{ 3, 0 },
        0x109, 0x10d => .{ 0, 0 },
        0x10f => .{ 2, 1 },
        0x110 => .{ 0, 1 },
        0x200...0x2ff => {
            const sub: u8 = @intCast(op - 0x200);

            if (std.mem.indexOfScalar(u8, &simd_unused, sub) != null) return error.Unsupported;

            return switch (sub) {
                0...10, 92, 93 => .{ 1, 1 },
                11 => .{ 2, 0 },
                12 => .{ 0, 1 },
                13, 14 => .{ 2, 1 },
                15...20, 21, 22, 24, 25, 27, 29, 31, 33 => .{ 1, 1 },
                23, 26, 28, 30, 32, 34 => .{ 2, 1 },
                82 => .{ 3, 1 },
                84...87 => .{ 2, 1 },
                88...91 => .{ 2, 0 },
                else => if (std.mem.indexOfScalar(u8, &simd_unary, sub) != null) .{ 1, 1 } else .{ 2, 1 },
            };
        },
        else => error.Unsupported,
    };
}

fn parse(allocator: Allocator, bytes: []const u8, with_names: bool) Failure!Module {
    if (bytes.len < 8 or !std.mem.eql(u8, bytes[0..8], "\x00asm\x01\x00\x00\x00")) return error.Malformed;

    var module: Module = .{ .types = &.{}, .functions = &.{}, .table = &.{}, .imports = 0 };

    var reader: Reader = .{ .bytes = bytes, .at = 8 };

    var function_types: []u32 = &.{};

    var labels: std.ArrayList(u32) = .empty;

    while (reader.at < bytes.len) {
        const id = try reader.byte();

        const size = try reader.index();

        var section: Reader = .{ .bytes = try reader.take(size) };

        if (id < module.sections.len) module.sections[id] = section.bytes;

        switch (id) {
            0 => {
                if (!with_names or !std.mem.eql(u8, try section.name(), "name")) continue;

                while (section.at < section.bytes.len) {
                    const sub = try section.byte();

                    var part: Reader = .{ .bytes = try section.take(try section.index()) };

                    if (sub != 1) continue;

                    for (0..try part.index()) |_| {
                        const index = try part.index();

                        try module.names.put(allocator, index, try part.name());
                    }
                }
            },
            1 => {
                module.types = try allocator.alloc(FuncType, try section.index());

                for (module.types) |*t| {
                    if (try section.byte() != 0x60) return error.Unsupported;

                    const params = try section.index();

                    _ = try section.take(params);

                    const results = try section.index();

                    _ = try section.take(results);

                    t.* = .{ .params = params, .results = results };
                }
            },
            2 => module.imports = try section.index(),
            3 => {
                function_types = try allocator.alloc(u32, try section.index());

                for (function_types) |*t| t.* = try section.index();
            },
            7 => {
                for (0..try section.index()) |_| {
                    const export_name = try section.name();

                    const kind = try section.byte();

                    const index = try section.index();

                    if (kind == 0) try module.exports.put(allocator, export_name, index);
                }
            },
            9 => {
                var table: std.ArrayList(u32) = .empty;

                for (0..try section.index()) |_| {
                    const flags = try section.index();

                    if (flags != 0) return error.Unsupported;

                    // The offset: i32.const n, end.
                    if (try section.byte() != 0x41) return error.Unsupported;

                    _ = try section.signed();

                    if (try section.byte() != 0x0b) return error.Unsupported;

                    for (0..try section.index()) |_| try table.append(allocator, try section.index());
                }

                module.table = try table.toOwnedSlice(allocator);
            },
            10 => {
                const count = try section.index();

                if (count != function_types.len) return error.Malformed;

                module.functions = try allocator.alloc(Function, count);

                for (module.functions, function_types) |*function, t| {
                    var body: Reader = .{ .bytes = try section.take(try section.index()) };

                    var locals: u64 = 0;

                    for (0..try body.index()) |_| {
                        locals += try body.index();

                        _ = try body.byte();
                    }

                    if (t >= module.types.len) return error.Malformed;

                    const local_count = module.types[t].params + locals;

                    if (local_count > 1 << 20) return error.Malformed;

                    var rest: Reader = .{ .bytes = body.bytes[body.at..] };

                    function.* = .{ .type = t, .locals = @intCast(local_count), .code = try parseCode(allocator, &rest, &labels), .labels = &.{}, .start = @intFromPtr(rest.bytes.ptr) - @intFromPtr(bytes.ptr) };
                }
            },
            else => {},
        }
    }

    const all = try labels.toOwnedSlice(allocator);

    for (module.functions) |*function| function.labels = all;

    return module;
}

// The analysis: one taint bit per value, a value being tainted when it may depend on memory.
const State = struct {
    locals: std.DynamicBitSetUnmanaged,
    stack: std.ArrayList(bool),
    live: bool,

    fn clone(self: *const State, allocator: Allocator) Allocator.Error!State {
        return .{ .locals = try self.locals.clone(allocator), .stack = try self.stack.clone(allocator), .live = self.live };
    }

    fn deinit(self: *State, allocator: Allocator) void {
        self.locals.deinit(allocator);

        self.stack.deinit(allocator);
    }
};

const Frame = struct {
    loop: bool,
    height: usize,
    // The values a branch to this frame carries: the loop's parameters, or the block's results.
    arity: u32,
    results: u32,
    // What branches to this frame delivered: the locals and the carried values.
    reached: bool = false,
    locals: std.DynamicBitSetUnmanaged,
    values: std.DynamicBitSetUnmanaged,
};

const Finding = struct {
    function: u32,
    kind: Kind,
    offset: u32,
};

const Analysis = struct {
    allocator: Allocator,
    module: *const Module,
    params: []std.DynamicBitSetUnmanaged,
    returns: []std.DynamicBitSetUnmanaged,
    changed: bool = false,
    record: bool = false,
    // A loop runs until its head stops changing, so one instruction may be found more than once.
    findings: std.AutoArrayHashMapUnmanaged(Finding, void) = .empty,
    current: u32 = 0,
    frames: std.ArrayList(Frame) = .empty,

    fn pop(self: *Analysis, state: *State) Failure!bool {
        const frame = self.frames.items[self.frames.items.len - 1];

        if (state.stack.items.len <= frame.height) {
            if (!state.live) return false;

            return error.Inconsistent;
        }

        return state.stack.pop().?;
    }

    fn push(self: *Analysis, state: *State, value: bool) Failure!void {
        try state.stack.append(self.allocator, value);
    }

    fn flag(self: *Analysis, kind: Kind, instr: Instr, tainted: bool) Failure!void {
        if (!tainted or !self.record) return;

        try self.findings.put(self.allocator, .{ .function = self.current, .kind = kind, .offset = instr.offset }, {});
    }

    fn deliver(self: *Analysis, state: *const State, depth: u32) Failure!void {
        if (depth >= self.frames.items.len) return error.Malformed;

        const frame = &self.frames.items[self.frames.items.len - 1 - depth];

        if (!state.live) return;

        frame.reached = true;

        frame.locals.setUnion(state.locals);

        if (state.stack.items.len < frame.arity) return error.Inconsistent;

        const values = state.stack.items[state.stack.items.len - frame.arity ..];

        for (values, 0..) |v, i| {
            if (v) frame.values.set(i);
        }
    }

    fn returned(self: *Analysis, state: *const State) Failure!void {
        if (!state.live) return;

        const results = self.module.types[self.module.functions[self.current].type].results;

        if (state.stack.items.len < results) return error.Inconsistent;

        const values = state.stack.items[state.stack.items.len - results ..];

        const out = &self.returns[self.current];

        for (values, 0..) |v, i| {
            if (v and !out.isSet(i)) {
                out.set(i);

                self.changed = true;
            }
        }
    }

    fn call(self: *Analysis, state: *State, callee: u32) Failure!void {
        if (callee >= self.module.functions.len) return error.Malformed;

        const t = self.module.types[self.module.functions[callee].type];

        var i: usize = t.params;

        while (i > 0) {
            i -= 1;

            if (try self.pop(state) and !self.params[callee].isSet(i)) {
                self.params[callee].set(i);

                self.changed = true;
            }
        }

        for (0..t.results) |r| try self.push(state, self.returns[callee].isSet(r));
    }

    // The functions an indirect call of type `type_index` may reach.
    fn callIndirect(self: *Analysis, state: *State, type_index: u32) Failure!void {
        if (type_index >= self.module.types.len) return error.Malformed;

        const t = self.module.types[type_index];

        var args = try self.allocator.alloc(bool, t.params);

        defer self.allocator.free(args);

        var i: usize = t.params;

        while (i > 0) {
            i -= 1;

            args[i] = try self.pop(state);
        }

        var results: [16]bool = @splat(false);

        if (t.results > results.len) return error.Unsupported;

        for (self.module.table) |callee| {
            if (callee >= self.module.functions.len) return error.Malformed;

            const ct = self.module.types[self.module.functions[callee].type];

            if (ct.params != t.params or ct.results != t.results) continue;

            for (args, 0..) |v, p| {
                if (v and !self.params[callee].isSet(p)) {
                    self.params[callee].set(p);

                    self.changed = true;
                }
            }

            for (0..t.results) |r| results[r] = results[r] or self.returns[callee].isSet(r);
        }

        for (results[0..t.results]) |v| try self.push(state, v);
    }

    fn merge(self: *Analysis, into: *State, frame: *const Frame) Failure!void {
        if (!frame.reached) return;

        if (!into.live) {
            into.live = true;

            into.locals.unsetAll();

            into.locals.setUnion(frame.locals);

            if (into.stack.items.len < frame.height) return error.Inconsistent;

            into.stack.shrinkRetainingCapacity(frame.height);

            for (0..frame.results) |i| try self.push(into, frame.values.isSet(i));

            return;
        }

        into.locals.setUnion(frame.locals);

        if (into.stack.items.len != frame.height + frame.results) return error.Inconsistent;

        for (0..frame.results) |i| {
            if (frame.values.isSet(i)) into.stack.items[frame.height + i] = true;
        }
    }

    fn newFrame(self: *Analysis, state: *const State, loop: bool, arity: FuncType) Failure!Frame {
        if (state.stack.items.len < arity.params) return error.Inconsistent;

        return .{
            .loop = loop,
            .height = state.stack.items.len - arity.params,
            .arity = if (loop) arity.params else arity.results,
            .results = arity.results,
            .locals = try std.DynamicBitSetUnmanaged.initEmpty(self.allocator, state.locals.bit_length),
            .values = try std.DynamicBitSetUnmanaged.initEmpty(self.allocator, @max(arity.params, arity.results)),
        };
    }

    // Runs instructions [from, to) of the current function on `state`.
    fn run(self: *Analysis, code: []const Instr, labels: []const u32, from: u32, to: u32, state: *State) Failure!void {
        var i = from;

        while (i < to) : (i += 1) {
            if (!state.live) return;

            const instr = code[i];

            switch (instr.op) {
                0x00 => state.live = false,
                // Only the function's own end: the ends of blocks close their ranges.
                0x0b => {},
                0x02, 0x03, 0x04 => {
                    const arity = try blockArity(self.module, instr.a);

                    if (instr.op == 0x04) try self.flag(.@"if", instr, try self.pop(state));

                    try self.structured(code, labels, i, arity, state);

                    i = instr.end;
                },
                0x0c => {
                    try self.deliver(state, instr.a);

                    state.live = false;
                },
                0x0d => {
                    try self.flag(.br_if, instr, try self.pop(state));

                    try self.deliver(state, instr.a);
                },
                0x0e => {
                    try self.flag(.br_table, instr, try self.pop(state));

                    for (labels[instr.a..][0..instr.b]) |label| try self.deliver(state, label);

                    state.live = false;
                },
                0x0f => {
                    try self.returned(state);

                    state.live = false;
                },
                0x10 => try self.call(state, instr.a),
                0x11 => {
                    _ = try self.pop(state);

                    try self.callIndirect(state, instr.a);
                },
                0x12, 0x13 => return error.Unsupported,
                0x1b, 0x1c => {
                    const condition = try self.pop(state);

                    try self.flag(.select, instr, condition);

                    const b = try self.pop(state);

                    const a = try self.pop(state);

                    try self.push(state, a or b or condition);
                },
                0x20 => {
                    if (instr.a >= state.locals.bit_length) return error.Malformed;

                    try self.push(state, state.locals.isSet(instr.a));
                },
                0x21, 0x22 => {
                    if (instr.a >= state.locals.bit_length) return error.Malformed;

                    const v = try self.pop(state);

                    state.locals.setValue(instr.a, v);

                    if (instr.op == 0x22) try self.push(state, v);
                },
                0x23 => try self.push(state, false),
                0x24 => _ = try self.pop(state),
                else => {
                    const pops, const pushes = effect(instr.op) catch |err| {
                        std.debug.print("opcode 0x{x} at offset {d}\n", .{ instr.op, instr.offset });

                        return err;
                    };

                    var tainted = instr.op >= 0x28 and instr.op <= 0x35 or (instr.op >= 0x200 and instr.op <= 0x20a) or instr.op == 0x25c or instr.op == 0x25d or (instr.op >= 0x254 and instr.op <= 0x257);

                    for (0..pops) |_| tainted = try self.pop(state) or tainted;

                    for (0..pushes) |_| try self.push(state, tainted);
                },
            }
        }
    }

    fn structured(self: *Analysis, code: []const Instr, labels: []const u32, at: u32, arity: FuncType, state: *State) Failure!void {
        const instr = code[at];

        switch (instr.op) {
            0x02 => {
                try self.frames.append(self.allocator, try self.newFrame(state, false, arity));

                try self.run(code, labels, at + 1, instr.end, state);

                try self.leave(state);
            },
            0x03 => {
                // The loop head merges what enters and what branches back, until nothing changes.
                var head = try state.clone(self.allocator);

                defer head.deinit(self.allocator);

                while (true) {
                    try self.frames.append(self.allocator, try self.newFrame(&head, true, arity));

                    var body = try head.clone(self.allocator);

                    try self.run(code, labels, at + 1, instr.end, &body);

                    var frame = self.frames.pop().?;

                    defer {
                        frame.locals.deinit(self.allocator);

                        frame.values.deinit(self.allocator);
                    }

                    var grown = false;

                    if (frame.reached) {
                        var merged = try head.locals.clone(self.allocator);

                        defer merged.deinit(self.allocator);

                        merged.setUnion(frame.locals);

                        if (!merged.eql(head.locals)) {
                            head.locals.setUnion(frame.locals);

                            grown = true;
                        }

                        for (0..frame.arity) |p| {
                            const slot = frame.height + p;

                            if (frame.values.isSet(p) and !head.stack.items[slot]) {
                                head.stack.items[slot] = true;

                                grown = true;
                            }
                        }
                    }

                    if (!grown) {
                        state.deinit(self.allocator);

                        state.* = body;

                        if (state.live and state.stack.items.len != frame.height + frame.results) return error.Inconsistent;

                        return;
                    }

                    body.deinit(self.allocator);
                }
            },
            else => {
                try self.frames.append(self.allocator, try self.newFrame(state, false, arity));

                var other = try state.clone(self.allocator);

                defer other.deinit(self.allocator);

                const then_end = if (instr.@"else" != 0) instr.@"else" else instr.end;

                try self.run(code, labels, at + 1, then_end, state);

                if (instr.@"else" != 0) try self.run(code, labels, instr.@"else" + 1, instr.end, &other);

                // The two arms meet at the end, as branches to the frame do.
                const frame = &self.frames.items[self.frames.items.len - 1];

                if (other.live) {
                    if (other.stack.items.len != frame.height + frame.results) return error.Inconsistent;

                    frame.reached = true;

                    frame.locals.setUnion(other.locals);

                    for (0..frame.results) |r| {
                        if (other.stack.items[frame.height + r]) frame.values.set(r);
                    }
                }

                try self.leave(state);
            },
        }
    }

    fn leave(self: *Analysis, state: *State) Failure!void {
        var frame = self.frames.pop().?;

        defer {
            frame.locals.deinit(self.allocator);

            frame.values.deinit(self.allocator);
        }

        if (state.live and state.stack.items.len != frame.height + frame.results) return error.Inconsistent;

        try self.merge(state, &frame);
    }

    fn function(self: *Analysis, index: u32) Failure!void {
        const f = self.module.functions[index];

        const t = self.module.types[f.type];

        self.current = index;

        var state: State = .{ .locals = try .initEmpty(self.allocator, f.locals), .stack = .empty, .live = true };

        defer state.deinit(self.allocator);

        for (0..t.params) |p| state.locals.setValue(p, self.params[index].isSet(p));

        self.frames.clearRetainingCapacity();

        try self.frames.append(self.allocator, try self.newFrame(&state, false, .{ .params = 0, .results = t.results }));

        try self.run(f.code, f.labels, 0, @intCast(f.code.len), &state);

        // The function's own end is the last instruction.
        if (state.live and state.stack.items.len != t.results) return error.Inconsistent;

        try self.returned(&state);

        var frame = self.frames.pop().?;

        defer {
            frame.locals.deinit(self.allocator);

            frame.values.deinit(self.allocator);
        }

        for (0..t.results) |r| {
            if (frame.values.isSet(r) and !self.returns[index].isSet(r)) {
                self.returns[index].set(r);

                self.changed = true;
            }
        }
    }
};

// The functions that `roots` reach through calls, indirect ones to every function of the table.
fn reach(allocator: Allocator, module: *const Module, roots: []const u32) Failure![]bool {
    const seen = try allocator.alloc(bool, module.functions.len);

    @memset(seen, false);

    var work: std.ArrayList(u32) = .empty;

    for (roots) |root| try work.append(allocator, root);

    while (work.pop()) |index| {
        if (seen[index]) continue;

        seen[index] = true;

        for (module.functions[index].code) |instr| {
            if (instr.op == 0x10 or instr.op == 0x12) try work.append(allocator, instr.a);

            if (instr.op == 0x11 or instr.op == 0x13) {
                for (module.table) |callee| try work.append(allocator, callee);
            }
        }
    }

    return seen;
}

// Zig names generic instances with a counter that any change shifts; the list ignores it.
fn normalized(allocator: Allocator, raw: []const u8) Allocator.Error![]const u8 {
    const marker = "__anon_";

    var name = raw;

    while (std.mem.indexOf(u8, name, marker)) |at| {
        var end = at + marker.len;

        while (end < name.len and std.ascii.isDigit(name[end])) end += 1;

        name = try std.mem.concat(allocator, u8, &.{ name[0..at], name[end..] });
    }

    const compact = try allocator.alloc(u8, name.len);

    var length: usize = 0;

    for (name) |c| {
        if (c == ' ') continue;

        compact[length] = c;

        length += 1;
    }

    return compact[0..length];
}

const Key = struct {
    module: []const u8,
    function: []const u8,
};

// select, br_if, if and br_table, in the order of Kind.
const Tally = [4]u32;

const Counts = std.ArrayHashMapUnmanaged(Key, Tally, KeyContext, true);

const KeyContext = struct {
    pub fn hash(_: KeyContext, key: Key) u32 {
        var h = std.hash.Wyhash.init(0);

        h.update(key.module);

        h.update(key.function);

        return @truncate(h.final());
    }

    pub fn eql(_: KeyContext, a: Key, b: Key, _: usize) bool {
        return std.mem.eql(u8, a.module, b.module) and std.mem.eql(u8, a.function, b.function);
    }
};

fn lintModule(allocator: Allocator, name: []const u8, shipped: []const u8, named: []const u8, counts: *Counts) !void {
    const module = try parse(allocator, shipped, false);

    const twin = try parse(allocator, named, true);

    if (module.imports != 0) {
        std.debug.print("{s}: the module imports {d} entries; it must import nothing\n", .{ name, module.imports });

        return error.Imports;
    }

    // The twin labels functions by index: it must have the same functions, types, exports and
    // table, in the same order.
    for ([_]usize{ 1, 3, 4, 7, 9 }) |id| {
        if (!std.mem.eql(u8, module.sections[id], twin.sections[id])) {
            std.debug.print("{s}: section {d} of the named build differs from the shipped one\n", .{ name, id });

            return error.Twin;
        }
    }

    var roots: std.ArrayList(u32) = .empty;

    var exports = module.exports.iterator();

    while (exports.next()) |entry| {
        if (!std.mem.startsWith(u8, entry.key_ptr.*, "cpq_")) continue;

        for (public_exports) |public| {
            if (std.mem.eql(u8, entry.key_ptr.*, public)) break;
        } else try roots.append(allocator, entry.value_ptr.*);
    }

    const reached = try reach(allocator, &module, roots.items);

    var analysis: Analysis = .{
        .allocator = allocator,
        .module = &module,
        .params = try allocator.alloc(std.DynamicBitSetUnmanaged, module.functions.len),
        .returns = try allocator.alloc(std.DynamicBitSetUnmanaged, module.functions.len),
    };

    for (module.functions, analysis.params, analysis.returns) |f, *p, *r| {
        p.* = try .initEmpty(allocator, module.types[f.type].params);

        r.* = try .initEmpty(allocator, module.types[f.type].results);
    }

    // Taint only grows, so this reaches a fixed point; the last pass records the findings.
    while (true) {
        analysis.changed = false;

        for (reached, 0..) |yes, index| {
            if (yes) analysis.function(@intCast(index)) catch |err| {
                std.debug.print("{s}: function {d} ({s}): {s}\n", .{ name, index, twin.names.get(@intCast(index)) orelse "?", @errorName(err) });

                return err;
            };
        }

        if (analysis.changed) continue;

        if (analysis.record) break;

        analysis.record = true;
    }

    for (analysis.findings.keys()) |finding| {
        const raw = twin.names.get(finding.function) orelse "?";

        const key: Key = .{ .module = name, .function = try normalized(allocator, raw) };

        const entry = try counts.getOrPut(allocator, key);

        if (!entry.found_existing) entry.value_ptr.* = @splat(0);

        entry.value_ptr[@intFromEnum(finding.kind)] += 1;

        if (details) std.debug.print("{s} {s} {s} at 0x{x} (function {d})\n", .{ name, key.function, @tagName(finding.kind), module.functions[finding.function].start + finding.offset, finding.function });
    }
}

var details = false;

// The list: "<module> <function> <select> <br_if> <if> <br_table> <reason>". The module "*" stands
// for every module in which the function has findings, which must then match in each of them.
pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();

    var args = try init.minimal.args.toSlice(allocator);

    var print = false;

    while (args.len > 1 and std.mem.startsWith(u8, args[1], "--")) : (args = args[1..]) {
        if (std.mem.eql(u8, args[1], "--print")) print = true else if (std.mem.eql(u8, args[1], "--details")) details = true else break;
    }

    if (args.len < 5 or (args.len - 2) % 3 != 0) {
        std.debug.print("usage: wasm_lint [--print] [--details] <list> <name> <shipped.wasm> <named.wasm>...\n", .{});

        std.process.exit(2);
    }

    const cwd = Io.Dir.cwd();

    var counts: Counts = .empty;

    var i: usize = 2;

    while (i < args.len) : (i += 3) {
        const shipped = try cwd.readFileAlloc(init.io, args[i + 1], allocator, .limited(64 << 20));

        const named = try cwd.readFileAlloc(init.io, args[i + 2], allocator, .limited(256 << 20));

        try lintModule(allocator, args[i], shipped, named, &counts);
    }

    if (print) {
        for (counts.keys(), counts.values()) |key, tally| std.debug.print("{s} {s} {d} {d} {d} {d} ?\n", .{ key.module, key.function, tally[0], tally[1], tally[2], tally[3] });

        return;
    }

    const list = try cwd.readFileAlloc(init.io, args[1], allocator, .limited(4 << 20));

    var bad = false;

    const matched = try allocator.alloc(bool, counts.count());

    @memset(matched, false);

    var lines = std.mem.splitScalar(u8, list, '\n');

    var line_number: usize = 0;

    while (lines.next()) |line| {
        line_number += 1;

        const text = std.mem.trim(u8, line, " \t\r");

        if (text.len == 0 or text[0] == '#') continue;

        var fields = std.mem.tokenizeScalar(u8, text, ' ');

        const module_name = fields.next().?;

        const function_name = fields.next() orelse "";

        var allowed: Tally = undefined;

        for (&allowed) |*n| {
            n.* = std.fmt.parseInt(u32, fields.next() orelse "", 10) catch {
                std.debug.print("{s}:{d}: four counts expected\n", .{ args[1], line_number });

                std.process.exit(2);
            };
        }

        if (fields.rest().len == 0) {
            std.debug.print("{s}:{d}: no reason\n", .{ args[1], line_number });

            std.process.exit(2);
        }

        var used = false;

        for (counts.keys(), counts.values(), matched) |key, tally, *done| {
            if (!std.mem.eql(u8, key.function, function_name)) continue;

            if (!std.mem.eql(u8, module_name, "*") and !std.mem.eql(u8, module_name, key.module)) continue;

            used = true;

            done.* = true;

            if (!std.mem.eql(u32, &tally, &allowed)) {
                std.debug.print("{s} {s}: select {d}, br_if {d}, if {d}, br_table {d} on values from memory; the list (line {d}) allows {d} {d} {d} {d}\n", .{ key.module, key.function, tally[0], tally[1], tally[2], tally[3], line_number, allowed[0], allowed[1], allowed[2], allowed[3] });

                bad = true;
            }
        }

        if (!used) {
            std.debug.print("{s}:{d}: {s} {s} is no longer found; update the list\n", .{ args[1], line_number, module_name, function_name });

            bad = true;
        }
    }

    for (counts.keys(), counts.values(), matched) |key, tally, done| {
        if (done) continue;

        std.debug.print("{s} {s}: select {d}, br_if {d}, if {d}, br_table {d} on values from memory, not in the list\n", .{ key.module, key.function, tally[0], tally[1], tally[2], tally[3] });

        bad = true;
    }

    if (bad) std.process.exit(1);

    var total: u32 = 0;

    for (counts.values()) |tally| {
        for (tally) |n| total += n;
    }

    std.debug.print("wasm lint: {d} modules, {d} functions with {d} reviewed conditions on values from memory, nothing else\n", .{ (args.len - 2) / 3, counts.count(), total });
}

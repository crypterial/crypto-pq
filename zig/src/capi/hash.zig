const std = @import("std");

const options = @import("capi_options");

const common = @import("common.zig");

const ct = @import("../ct.zig");
const hash = @import("../hash.zig");

const Failure = common.Failure;

const Slot = common.Slot;

// Hash ids 0-9, XOF ids 0-1 and HMAC ids 0-3, in these orders.
pub const algorithms = [_]hash.HashAlgorithm{
    hash.sha_224,
    hash.sha_256,
    hash.sha_384,
    hash.sha_512,
    hash.sha_512_224,
    hash.sha_512_256,
    hash.sha3_224,
    hash.sha3_256,
    hash.sha3_384,
    hash.sha3_512,
};

const xofs = [_]hash.XofAlgorithm{ hash.shake128, hash.shake256 };

const hmacs = [_]hash.HmacAlgorithm{ hash.hmac_sha_224, hash.hmac_sha_256, hash.hmac_sha_384, hash.hmac_sha_512 };

// The incremental states. `busy` makes a second call on one state fail at once rather than race
// on it: an update tears the state of a concurrent one.
pub const HasherState = struct {
    busy: common.Busy,
    hasher: hash.Hasher,
};

pub const XofState = struct {
    busy: common.Busy,
    xof: hash.Xof,
};

pub const HmacState = struct {
    busy: common.Busy,
    hmac: hash.Hmac,
};

pub fn size(slot_type: common.SlotType, algorithm: u32) usize {
    if (!options.hash) return 0;

    return switch (slot_type) {
        .hasher => if (algorithm < algorithms.len) common.slotSize(HasherState) else 0,
        .xof => if (algorithm < xofs.len) common.slotSize(XofState) else 0,
        .hmac => if (algorithm < hmacs.len) common.slotSize(HmacState) else 0,
        else => 0,
    };
}

fn known(algorithm: u32, total: usize) Failure!void {
    if (algorithm >= total) return error.BadArgument;
}

pub fn digest(algorithm: u32, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(digestChecked(algorithm, data, data_length, out, out_length));
}

fn digestChecked(algorithm: u32, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    try known(algorithm, algorithms.len);

    const h = algorithms[algorithm];

    const bytes = try common.input(data, data_length);

    const target = try common.exact(out, out_length, h.digest_size);

    try common.apart(&.{target}, &.{bytes});

    var hasher = h.create();

    defer ct.wipe(std.mem.asBytes(&hasher));

    hasher.update(bytes);

    hasher.digest(target);
}

pub fn init(algorithm: u32, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(initChecked(algorithm, memory, length));
}

fn initChecked(algorithm: u32, memory: ?[*]u8, length: usize) Failure!void {
    try known(algorithm, algorithms.len);

    const slot = try common.place(.hasher, algorithm, memory, length, size(.hasher, algorithm));

    const state = slot.body(HasherState);

    state.busy.init();

    state.hasher = algorithms[algorithm].create();

    slot.seal(0);
}

// A state that this call holds until it releases it. `read` and `written` are the call's other
// buffers, which must be apart from the state.
fn hold(comptime T: type, comptime slot_type: common.SlotType, memory: ?[*]u8, length: usize, read: []const u8, written: []const u8) Failure!*T {
    const slot = try common.open(&.{slot_type}, memory, length, size);

    try common.apart(&.{ slot.bytes, written }, &.{read});

    const state = slot.body(T);

    try state.busy.acquire();

    return state;
}

pub fn update(memory: ?[*]u8, length: usize, data: ?[*]const u8, data_length: usize) callconv(.c) c_int {
    return common.status(updateChecked(memory, length, data, data_length));
}

fn updateChecked(memory: ?[*]u8, length: usize, data: ?[*]const u8, data_length: usize) Failure!void {
    const bytes = try common.input(data, data_length);

    const state = try hold(HasherState, .hasher, memory, length, bytes, &.{});

    defer state.busy.release();

    state.hasher.update(bytes);
}

// The digest of everything given so far; the state may go on.
pub fn final(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(finalChecked(memory, length, out, out_length));
}

fn finalChecked(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    const target = try common.output(out, out_length);

    const state = try hold(HasherState, .hasher, memory, length, &.{}, target);

    defer state.busy.release();

    if (target.len != state.hasher.size) return error.BadArgument;

    state.hasher.digest(target);
}

pub fn xof(algorithm: u32, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(xofChecked(algorithm, data, data_length, out, out_length));
}

fn xofChecked(algorithm: u32, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    try known(algorithm, xofs.len);

    const bytes = try common.input(data, data_length);

    const target = try common.output(out, out_length);

    try common.apart(&.{target}, &.{bytes});

    var sponge = xofs[algorithm].create();

    defer ct.wipe(std.mem.asBytes(&sponge));

    sponge.update(bytes);

    sponge.read(target);
}

pub fn xofInit(algorithm: u32, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(xofInitChecked(algorithm, memory, length));
}

fn xofInitChecked(algorithm: u32, memory: ?[*]u8, length: usize) Failure!void {
    try known(algorithm, xofs.len);

    const slot = try common.place(.xof, algorithm, memory, length, size(.xof, algorithm));

    const state = slot.body(XofState);

    state.busy.init();

    state.xof = xofs[algorithm].create();

    slot.seal(0);
}

// Once reading has begun, an update is UNSUPPORTED, as in every crypto-pq.
pub fn xofUpdate(memory: ?[*]u8, length: usize, data: ?[*]const u8, data_length: usize) callconv(.c) c_int {
    return common.status(xofUpdateChecked(memory, length, data, data_length));
}

fn xofUpdateChecked(memory: ?[*]u8, length: usize, data: ?[*]const u8, data_length: usize) Failure!void {
    const bytes = try common.input(data, data_length);

    const state = try hold(XofState, .xof, memory, length, bytes, &.{});

    defer state.busy.release();

    if (state.xof.sponge.squeezing) return error.Unsupported;

    state.xof.update(bytes);
}

// The next `out_length` bytes of the output stream.
pub fn xofRead(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(xofReadChecked(memory, length, out, out_length));
}

fn xofReadChecked(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    const target = try common.output(out, out_length);

    const state = try hold(XofState, .xof, memory, length, &.{}, target);

    defer state.busy.release();

    state.xof.read(target);
}

pub fn hmac(algorithm: u32, key: ?[*]const u8, key_length: usize, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(hmacChecked(algorithm, key, key_length, data, data_length, out, out_length));
}

fn hmacChecked(algorithm: u32, key: ?[*]const u8, key_length: usize, data: ?[*]const u8, data_length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    try known(algorithm, hmacs.len);

    const h = hmacs[algorithm];

    const k = try common.input(key, key_length);

    const bytes = try common.input(data, data_length);

    const target = try common.exact(out, out_length, h.digest_size);

    try common.apart(&.{target}, &.{ k, bytes });

    h.digest(k, bytes, target);
}

// The tag must have the full length; the comparison takes the same time whatever the tag holds.
pub fn hmacVerify(algorithm: u32, key: ?[*]const u8, key_length: usize, data: ?[*]const u8, data_length: usize, tag: ?[*]const u8, tag_length: usize) callconv(.c) c_int {
    return common.status(hmacVerifyChecked(algorithm, key, key_length, data, data_length, tag, tag_length));
}

fn hmacVerifyChecked(algorithm: u32, key: ?[*]const u8, key_length: usize, data: ?[*]const u8, data_length: usize, tag: ?[*]const u8, tag_length: usize) Failure!void {
    try known(algorithm, hmacs.len);

    const k = try common.input(key, key_length);

    const bytes = try common.input(data, data_length);

    const expected = try common.input(tag, tag_length);

    // Whether the tag matches is the answer the caller asked for.
    if (!ct.declassifyValue(bool, hmacs[algorithm].verify(k, bytes, expected))) return error.Rejected;
}

pub fn hmacInit(algorithm: u32, key: ?[*]const u8, key_length: usize, memory: ?[*]u8, length: usize) callconv(.c) c_int {
    return common.status(hmacInitChecked(algorithm, key, key_length, memory, length));
}

fn hmacInitChecked(algorithm: u32, key: ?[*]const u8, key_length: usize, memory: ?[*]u8, length: usize) Failure!void {
    try known(algorithm, hmacs.len);

    const slot = try common.place(.hmac, algorithm, memory, length, size(.hmac, algorithm));

    const k = try common.input(key, key_length);

    try common.apart(&.{slot.bytes}, &.{k});

    const state = slot.body(HmacState);

    state.busy.init();

    state.hmac = hmacs[algorithm].create(k);

    slot.seal(0);
}

pub fn hmacUpdate(memory: ?[*]u8, length: usize, data: ?[*]const u8, data_length: usize) callconv(.c) c_int {
    return common.status(hmacUpdateChecked(memory, length, data, data_length));
}

fn hmacUpdateChecked(memory: ?[*]u8, length: usize, data: ?[*]const u8, data_length: usize) Failure!void {
    const bytes = try common.input(data, data_length);

    const state = try hold(HmacState, .hmac, memory, length, bytes, &.{});

    defer state.busy.release();

    state.hmac.update(bytes);
}

pub fn hmacFinal(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) callconv(.c) c_int {
    return common.status(hmacFinalChecked(memory, length, out, out_length));
}

fn hmacFinalChecked(memory: ?[*]u8, length: usize, out: ?[*]u8, out_length: usize) Failure!void {
    const target = try common.output(out, out_length);

    const state = try hold(HmacState, .hmac, memory, length, &.{}, target);

    defer state.busy.release();

    if (target.len != state.hmac.size) return error.BadArgument;

    state.hmac.digest(target);
}

pub fn hmacFinalVerify(memory: ?[*]u8, length: usize, tag: ?[*]const u8, tag_length: usize) callconv(.c) c_int {
    return common.status(hmacFinalVerifyChecked(memory, length, tag, tag_length));
}

fn hmacFinalVerifyChecked(memory: ?[*]u8, length: usize, tag: ?[*]const u8, tag_length: usize) Failure!void {
    const expected = try common.input(tag, tag_length);

    const state = try hold(HmacState, .hmac, memory, length, expected, &.{});

    defer state.busy.release();

    if (!ct.declassifyValue(bool, state.hmac.verify(expected))) return error.Rejected;
}

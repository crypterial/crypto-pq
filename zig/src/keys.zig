const std = @import("std");

const ct = @import("ct.zig");
const encoding = @import("encoding.zig");
const Error = @import("errors.zig").Error;

const Allocator = std.mem.Allocator;

pub const KeyFormat = enum { raw, der, pem };

pub const KeyGenOptions = struct {
    self_test: bool = true,
};

// Every key this library exports fits in this many DER bytes (the largest is an expanded
// ML-DSA-87 private key).
const der_capacity = 8192;

// PEM input is decoded into a buffer of this size on the stack, because importing a key does not
// allocate; any DER encoding of a supported key is far smaller, and a longer one is read as a
// stream (see encoding.pemPublicKey).
const pem_capacity = 16384;

pub const PemBuffer = [pem_capacity]u8;

const public_label = "PUBLIC KEY";

const private_label = "PRIVATE KEY";

pub fn importPublic(format: KeyFormat, data: []const u8, oid: ?[]const u8, buffer: *PemBuffer) Error![]const u8 {
    if (format == .raw) return data;

    const expected = oid orelse return error.Unsupported;

    const decoded = if (format == .pem) try encoding.pemPublicKey(buffer, public_label, data) else try encoding.decodePublicKey(data);

    if (!std.mem.eql(u8, decoded.oid, expected)) return error.AlgorithmMismatch;

    return decoded.key;
}

const PrivateInput = union(enum) {
    raw: []const u8,
    pkcs8: struct {
        octets: []const u8,
        public_key: ?[]const u8,
    },
};

pub fn importPrivate(format: KeyFormat, data: []const u8, oid: ?[]const u8, buffer: *PemBuffer) Error!PrivateInput {
    if (format == .raw) return .{ .raw = data };

    const expected = oid orelse return error.Unsupported;

    const decoded = if (format == .pem) try encoding.pemPrivateKey(buffer, private_label, data) else try encoding.decodePrivateKey(data);

    if (!std.mem.eql(u8, decoded.oid, expected)) return error.AlgorithmMismatch;

    return .{ .pkcs8 = .{ .octets = decoded.octets, .public_key = decoded.public_key } };
}

const SeedChoice = struct {
    seed: ?[]const u8 = null,
    expanded: ?[]const u8 = null,
};

// ML-KEM and ML-DSA private keys: CHOICE { seed [0] IMPLICIT OCTET STRING, expandedKey OCTET
// STRING, both SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING } }.
pub fn decodeSeedChoice(octets: []const u8, seed_size: usize, expanded_size: usize) Error!SeedChoice {
    var choice: SeedChoice = .{};

    if (octets.len == 0) return error.InvalidEncoding;

    switch (octets[0]) {
        encoding.context_0 => choice.seed = try encoding.only(octets, encoding.context_0),
        encoding.octet_string => choice.expanded = try encoding.only(octets, encoding.octet_string),
        encoding.sequence => {
            var reader: encoding.Reader = .{ .data = try encoding.only(octets, encoding.sequence) };

            choice.seed = try reader.read(encoding.octet_string);

            choice.expanded = try reader.read(encoding.octet_string);

            try reader.finish();
        },
        else => return error.InvalidEncoding,
    }

    if (choice.seed) |seed| {
        if (seed.len != seed_size) return error.InvalidEncoding;
    }

    if (choice.expanded) |expanded| {
        if (expanded.len != expanded_size) return error.InvalidEncoding;
    }

    return choice;
}

fn finish(allocator: Allocator, format: KeyFormat, comptime label: []const u8, der: []const u8) Allocator.Error![]u8 {
    if (format == .der) return allocator.dupe(u8, der);

    const out = try allocator.alloc(u8, encoding.pemSize(label, der.len));

    _ = encoding.pemEncode(out, label, der);

    return out;
}

pub fn exportPublic(allocator: Allocator, format: KeyFormat, oid: ?[]const u8, raw: []const u8) (Error || Allocator.Error)![]u8 {
    if (format == .raw) return allocator.dupe(u8, raw);

    const algorithm = oid orelse return error.Unsupported;

    var buffer: [der_capacity]u8 = undefined;

    var writer: encoding.Writer = .{ .buffer = &buffer };

    encoding.encodePublicKey(&writer, algorithm, raw);

    return finish(allocator, format, public_label, writer.written());
}

// `octets_tag` wraps `key` in one more element inside the PKCS#8 privateKey OCTET STRING, as the
// ML-KEM and ML-DSA CHOICE requires; SLH-DSA passes null and stores its key directly.
pub fn exportPrivate(allocator: Allocator, format: KeyFormat, oid: ?[]const u8, octets_tag: ?u8, key: []const u8) (Error || Allocator.Error)![]u8 {
    if (format == .raw) return allocator.dupe(u8, key);

    const algorithm = oid orelse return error.Unsupported;

    var buffer: [der_capacity]u8 = undefined;

    defer ct.wipe(&buffer);

    var writer: encoding.Writer = .{ .buffer = &buffer };

    encoding.encodePrivateKey(&writer, algorithm, octets_tag, key);

    return finish(allocator, format, private_label, writer.written());
}

pub fn requireLength(data: []const u8, length: usize) Error!void {
    if (data.len != length) return error.InvalidLength;
}

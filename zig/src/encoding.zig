const std = @import("std");

const Error = @import("errors.zig").Error;

pub const sequence = 0x30;

const integer = 0x02;

const bit_string = 0x03;

pub const octet_string = 0x04;

pub const object_identifier = 0x06;

pub const context_0 = 0x80;

const context_0_constructed = 0xa0;

const context_1 = 0x81;

// The content octets of an OBJECT IDENTIFIER: the first two arcs share a byte and every further
// arc is base 128, most significant group first.
pub fn objectIdentifier(comptime arcs: []const u64) []const u8 {
    return comptime blk: {
        var out: [64]u8 = undefined;

        out[0] = 40 * arcs[0] + arcs[1];

        var length: usize = 1;

        for (arcs[2..]) |arc| {
            var groups: usize = 1;

            while (arc >> (7 * groups) != 0) groups += 1;

            for (0..groups) |i| {
                const group: u8 = @truncate(arc >> (7 * (groups - 1 - i)));

                out[length] = (group & 0x7f) | (if (i + 1 < groups) 0x80 else 0);

                length += 1;
            }
        }

        const encoded = out[0..length].*;

        break :blk &encoded;
    };
}

fn headerSize(length: usize) usize {
    if (length < 0x80) return 2;

    var size: usize = 2;

    var rest = length;

    while (rest != 0) : (rest >>= 8) size += 1;

    return size;
}

fn elementSize(length: usize) usize {
    return headerSize(length) + length;
}

pub const Writer = struct {
    buffer: []u8,
    length: usize = 0,

    pub fn header(self: *Writer, tag: u8, length: usize) void {
        const size = headerSize(length);

        const out = self.buffer[self.length..][0..size];

        out[0] = tag;

        if (size == 2) {
            out[1] = @intCast(length);
        } else {
            out[1] = @intCast(0x80 | (size - 2));

            for (out[2..], 0..) |*byte, i| {
                byte.* = @truncate(length >> @intCast(8 * (size - 3 - i)));
            }
        }

        self.length += size;
    }

    pub fn bytes(self: *Writer, data: []const u8) void {
        @memcpy(self.buffer[self.length..][0..data.len], data);

        self.length += data.len;
    }

    pub fn element(self: *Writer, tag: u8, content: []const u8) void {
        self.header(tag, content.len);

        self.bytes(content);
    }

    pub fn written(self: Writer) []u8 {
        return self.buffer[0..self.length];
    }
};

pub const Reader = struct {
    data: []const u8,
    offset: usize = 0,

    // DER only: a single-byte tag and the shortest definite length.
    pub fn read(self: *Reader, tag: u8) Error![]const u8 {
        const data = self.data;

        if (data.len - self.offset < 2 or data[self.offset] != tag) return error.InvalidEncoding;

        const first = data[self.offset + 1];

        var offset = self.offset + 2;

        var length: usize = first;

        if (first >= 0x80) {
            const size = first & 0x7f;

            if (size == 0 or size > 4 or data.len - offset < size or data[offset] == 0) return error.InvalidEncoding;

            length = 0;

            for (data[offset..][0..size]) |byte| {
                length = (length << 8) | byte;
            }

            offset += size;

            if (length < 0x80) return error.InvalidEncoding;
        }

        if (data.len - offset < length) return error.InvalidEncoding;

        self.offset = offset + length;

        return data[offset..][0..length];
    }

    pub fn peek(self: Reader) ?u8 {
        return if (self.offset < self.data.len) self.data[self.offset] else null;
    }

    pub fn finish(self: Reader) Error!void {
        if (self.offset != self.data.len) return error.InvalidEncoding;
    }
};

pub fn only(data: []const u8, tag: u8) Error![]const u8 {
    var reader: Reader = .{ .data = data };

    const content = try reader.read(tag);

    try reader.finish();

    return content;
}

fn algorithmIdentifierSize(oid: []const u8) usize {
    return elementSize(elementSize(oid.len));
}

fn algorithmIdentifier(writer: *Writer, oid: []const u8) void {
    writer.header(sequence, elementSize(oid.len));

    writer.element(object_identifier, oid);
}

fn readAlgorithm(reader: *Reader) Error![]const u8 {
    return only(try reader.read(sequence), object_identifier);
}

pub fn encodePublicKey(writer: *Writer, oid: []const u8, key: []const u8) void {
    writer.header(sequence, algorithmIdentifierSize(oid) + elementSize(1 + key.len));

    algorithmIdentifier(writer, oid);

    writer.header(bit_string, 1 + key.len);

    writer.bytes(&.{0});

    writer.bytes(key);
}

const PublicKey = struct {
    oid: []const u8,
    key: []const u8,
};

pub fn decodePublicKey(data: []const u8) Error!PublicKey {
    var reader: Reader = .{ .data = try only(data, sequence) };

    const oid = try readAlgorithm(&reader);

    const bits = try reader.read(bit_string);

    try reader.finish();

    if (bits.len == 0 or bits[0] != 0) return error.InvalidEncoding;

    return .{ .oid = oid, .key = bits[1..] };
}

// The privateKey octets are either the key itself or the key wrapped in one more element whose
// tag is `inner_tag`, as in the seed/expanded CHOICE of ML-KEM and ML-DSA.
pub fn encodePrivateKey(writer: *Writer, oid: []const u8, inner_tag: ?u8, key: []const u8) void {
    const octets = if (inner_tag != null) elementSize(key.len) else key.len;

    writer.header(sequence, 3 + algorithmIdentifierSize(oid) + elementSize(octets));

    writer.bytes(&.{ integer, 1, 0 });

    algorithmIdentifier(writer, oid);

    writer.header(octet_string, octets);

    if (inner_tag) |tag| writer.header(tag, key.len);

    writer.bytes(key);
}

const PrivateKey = struct {
    oid: []const u8,
    octets: []const u8,
    public_key: ?[]const u8,
};

// PKCS#8 OneAsymmetricKey (RFC 5958): version 0 or 1, attributes ignored, and the optional
// public key returned so that the caller can check that it matches.
pub fn decodePrivateKey(data: []const u8) Error!PrivateKey {
    var reader: Reader = .{ .data = try only(data, sequence) };

    const version = try reader.read(integer);

    if (version.len != 1 or version[0] > 1) return error.InvalidEncoding;

    const oid = try readAlgorithm(&reader);

    const octets = try reader.read(octet_string);

    var public_key: ?[]const u8 = null;

    if (reader.peek() == context_0_constructed) _ = try reader.read(context_0_constructed);

    if (reader.peek() == context_1) {
        if (version[0] != 1) return error.InvalidEncoding;

        const bits = try reader.read(context_1);

        if (bits.len == 0 or bits[0] != 0) return error.InvalidEncoding;

        public_key = bits[1..];
    }

    try reader.finish();

    return .{ .oid = oid, .octets = octets, .public_key = public_key };
}

fn base64Character(value: u8) u8 {
    const v: i32 = value;

    var character = v + 65;

    character += ((25 - v) >> 8) & 6;

    character -= ((51 - v) >> 8) & 75;

    character -= ((61 - v) >> 8) & 15;

    character += ((62 - v) >> 8) & 3;

    return @intCast(character);
}

// Arithmetic instead of table lookups, so that decoding a private key does not index memory
// with secret values; -1 marks a character outside the alphabet.
fn base64Value(character: u8) i32 {
    const c: i32 = character;

    var value: i32 = -1;

    value += (((0x40 - c) & (c - 0x5b)) >> 8) & (c - 64);

    value += (((0x60 - c) & (c - 0x7b)) >> 8) & (c - 70);

    value += (((0x2f - c) & (c - 0x3a)) >> 8) & (c + 5);

    value += (((0x2a - c) & (c - 0x2c)) >> 8) & 63;

    value += (((0x2e - c) & (c - 0x30)) >> 8) & 64;

    return value;
}

fn base64Size(length: usize) usize {
    return 4 * ((length + 2) / 3);
}

fn base64Encode(out: []u8, data: []const u8) void {
    var offset: usize = 0;

    var position: usize = 0;

    while (offset < data.len) : (offset += 3) {
        const used = @min(3, data.len - offset);

        var chunk: [3]u8 = @splat(0);

        @memcpy(chunk[0..used], data[offset..][0..used]);

        const value = (@as(u32, chunk[0]) << 16) | (@as(u32, chunk[1]) << 8) | chunk[2];

        for (out[position..][0..4], 0..) |*character, i| {
            character.* = if (i <= used) base64Character(@truncate((value >> @intCast(18 - 6 * i)) & 0x3f)) else '=';
        }

        position += 4;
    }
}

const whitespace = std.ascii.whitespace;

// Space, or one of tab, line feed, vertical tab, form feed and carriage return (9 to 13).
fn isWhitespace(character: u8) bool {
    return (@intFromBool(character == ' ') | @intFromBool(character -% 9 < 5)) != 0;
}

// Decodes the base64 characters of `text`, skipping whitespace. Invalid characters are counted
// instead of returned early, so that the time taken does not depend on where they are.
fn base64DecodeSpaced(out: []u8, text: []const u8) Error![]u8 {
    var count: usize = 0;

    for (text) |character| {
        count += @intFromBool(!isWhitespace(character));
    }

    if (count % 4 != 0 or count / 4 * 3 > out.len) return error.InvalidEncoding;

    var invalid: i32 = 0;

    var chunk: [4]u8 = undefined;

    var filled: usize = 0;

    var group: usize = 0;

    var length: usize = 0;

    for (text) |character| {
        if (isWhitespace(character)) continue;

        chunk[filled] = character;

        filled += 1;

        if (filled < 4) continue;

        filled = 0;

        group += 1;

        var padding: usize = 0;

        if (group == count / 4) {
            if (chunk[2] == '=' and chunk[3] == '=') {
                padding = 2;
            } else if (chunk[3] == '=') {
                padding = 1;
            }
        }

        var value: u32 = 0;

        for (chunk[0 .. 4 - padding]) |c| {
            const v = base64Value(c);

            invalid |= v;

            value = (value << 6) | (@as(u32, @bitCast(v)) & 0x3f);
        }

        value <<= @intCast(6 * padding);

        const low = (@as(u32, 1) << @intCast(8 * padding)) - 1;

        invalid |= -@as(i32, @intFromBool(value & low != 0));

        for (0..3 - padding) |i| {
            out[length] = @truncate(value >> @intCast(16 - 8 * i));

            length += 1;
        }
    }

    if (invalid < 0) return error.InvalidEncoding;

    return out[0..length];
}

pub fn pemSize(comptime label: []const u8, der_length: usize) usize {
    const body = base64Size(der_length);

    return 2 * label.len + 33 + body + (body + 63) / 64 -| 1;
}

pub fn pemEncode(out: []u8, comptime label: []const u8, der: []const u8) []u8 {
    var writer: Writer = .{ .buffer = out };

    writer.bytes("-----BEGIN " ++ label ++ "-----\n");

    const start = writer.length;

    const body = base64Size(der.len);

    base64Encode(out[start..][0..body], der);

    // Spread the base64 text into 64-character lines, starting from the last line so that no
    // character is overwritten before it moves.
    const lines = (body + 63) / 64;

    var line = lines;

    while (line > 0) {
        line -= 1;

        const from = start + 64 * line;

        const to = from + line;

        const size = @min(64, body - 64 * line);

        std.mem.copyBackwards(u8, out[to..][0..size], out[from..][0..size]);

        if (line > 0) out[to - 1] = '\n';
    }

    writer.length = start + body + lines -| 1;

    writer.bytes("\n-----END " ++ label ++ "-----\n");

    return writer.written();
}

pub fn pemDecode(out: []u8, comptime label: []const u8, data: []const u8) Error![]u8 {
    const begin = "-----BEGIN " ++ label ++ "-----";

    const end = "-----END " ++ label ++ "-----";

    const text = std.mem.trim(u8, data, &whitespace);

    if (text.len < begin.len + end.len or !std.mem.startsWith(u8, text, begin) or !std.mem.endsWith(u8, text, end)) return error.InvalidEncoding;

    const body = text[begin.len .. text.len - end.len];

    for (body) |character| {
        if (character > 0x7f) return error.InvalidEncoding;
    }

    return base64DecodeSpaced(out, body);
}

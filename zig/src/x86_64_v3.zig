const std = @import("std");

const ascon = @import("ascon.zig");
const cpu = @import("cpu.zig");
const mldsa = @import("mldsa.zig");
const mlkem = @import("mlkem.zig");
const xwing = @import("xwing.zig");

// The x86-64-v3 build. Zig compiles a source file once, for the CPU features of its module, so a
// build for a baseline x86-64 CPU gives the lattice arithmetic SSE2 vectors and Ascon and X25519
// no BMI instructions. build.zig therefore compiles this file a second time, as the root of an
// object for the x86-64-v3 level (AVX2, BMI1, BMI2 and the rest of it), and links the object into
// every build for an x86-64 CPU below that level (cpu.v3_object). The functions below are the
// object's, exported under hidden names; in the build they are linked into, each entry point
// takes them when the CPU has the level. Both builds run the same source on the same data, so
// their results are the same.

// A failed safety check stops the process, as in the C ABI: the object carries no message
// printer.
pub const panic = std.debug.no_panic;

// Whether to take the object's code: never while evaluating at compile time.
pub inline fn use() bool {
    if (comptime !cpu.v3_object) return false;

    if (@inComptime()) return false;

    return cpu.has(.avx2);
}

// The object's function `name` of the group T, called from the other build.
pub fn entry(comptime T: type, comptime name: []const u8) *const @TypeOf(@field(T, name)) {
    return @extern(*const @TypeOf(@field(T, name)), .{ .name = symbol(T, name), .visibility = .hidden });
}

// The calls that this file's entry points replace are made out of line in the build that takes
// them, so that a frame holds either the choice or the work, not both: on the path through the
// object the stack then carries one frame of the work, not two.
pub const apart: std.builtin.CallModifier = if (cpu.v3_object) .never_inline else .auto;

fn symbol(comptime T: type, comptime name: []const u8) []const u8 {
    return "cpq_x86_64_v3_" ++ T.group ++ "_" ++ name;
}

// The object has functions for the three standard parameter sets of ML-KEM and of ML-DSA only,
// exported under names that carry k alone: any other set is refused at compile time, so that its
// calls cannot reach the functions of the standard set with the same k.
pub fn MlKem(comptime p: mlkem.Parameters) type {
    if (!std.meta.eql(p, mlKemSet(p.k))) @compileError("the x86-64-v3 object has only the standard ML-KEM parameter sets");

    const k: usize = p.k;

    return struct {
        pub const group = std.fmt.comptimePrint("ml_kem_{d}", .{256 * k});

        pub fn keyGen(d: *const [32]u8, z: *const [32]u8, ek: *[p.encapsulationKeySize()]u8, dk: *[p.decapsulationKeySize()]u8, s_hat: *[k]mlkem.Poly, public: ?*mlkem.EncapsulationKey(k)) callconv(.c) void {
            mlkem.keyGen(p, d, z, ek, dk, s_hat, public);
        }

        pub fn encaps(key: *const mlkem.EncapsulationKey(k), m: *const [32]u8, shared_secret: *[32]u8, c: *[p.ciphertextSize()]u8) callconv(.c) void {
            mlkem.encaps(p, key, m, shared_secret, c);
        }

        pub fn decaps(s_hat: *const [k]mlkem.Poly, key: *const mlkem.EncapsulationKey(k), dk: *const [p.decapsulationKeySize()]u8, c: *const [p.ciphertextSize()]u8, shared_secret: *[32]u8) callconv(.c) void {
            mlkem.decapsInto(p, s_hat, key, dk, c, shared_secret);
        }

        pub fn fill(key: *mlkem.EncapsulationKey(k), ek: *const [p.encapsulationKeySize()]u8) callconv(.c) void {
            key.fill(ek);
        }
    };
}

// The standard ML-KEM parameter set with k, for the key form, which depends on k alone.
pub fn mlKemSet(comptime k: usize) mlkem.Parameters {
    return switch (k) {
        2 => mlkem.ml_kem_512,
        3 => mlkem.ml_kem_768,
        4 => mlkem.ml_kem_1024,
        else => @compileError("ML-KEM has no standard parameter set with this k"),
    };
}

pub fn MlDsa(comptime p: mldsa.Parameters) type {
    const standard = switch (p.k) {
        4 => mldsa.ml_dsa_44,
        6 => mldsa.ml_dsa_65,
        8 => mldsa.ml_dsa_87,
        else => @compileError("ML-DSA has no standard parameter set with this k"),
    };

    if (!std.meta.eql(p, standard)) @compileError("the x86-64-v3 object has only the standard ML-DSA parameter sets");

    return struct {
        pub const group = switch (p.k) {
            4 => "ml_dsa_44",
            6 => "ml_dsa_65",
            8 => "ml_dsa_87",
            else => unreachable,
        };

        pub fn keyGen(seed: *const [32]u8, pk: *[p.publicKeySize()]u8, sk: *[p.privateKeySize()]u8, public: ?*mldsa.PublicCache(p)) callconv(.c) void {
            mldsa.keyGen(p, seed, pk, sk, public);
        }

        pub fn checkPrivateKey(sk: *const [p.privateKeySize()]u8, pk: *[p.publicKeySize()]u8) callconv(.c) bool {
            return mldsa.checkPrivateKey(p, sk, pk);
        }

        pub fn sign(sk: *const [p.privateKeySize()]u8, secret: *const mldsa.SecretCache(p), public: *const mldsa.PublicCache(p), work: *mldsa.Workspace(p), message: *const []const []const u8, rnd: *const [32]u8, signature: *[p.signatureSize()]u8) callconv(.c) void {
            mldsa.sign(p, sk, secret, public, work, message.*, rnd, signature);
        }

        pub fn verify(pk: *const [p.publicKeySize()]u8, tr: *const [64]u8, public: ?*const mldsa.PublicCache(p), message: *const []const []const u8, signature: *const [p.signatureSize()]u8) callconv(.c) bool {
            return mldsa.verify(p, pk, tr, public, message.*, signature);
        }

        pub fn fillPublic(cache: *mldsa.PublicCache(p), pk: *const [p.publicKeySize()]u8) callconv(.c) void {
            cache.fill(pk);
        }

        pub fn fillSecret(cache: *mldsa.SecretCache(p), sk: *const [p.privateKeySize()]u8) callconv(.c) void {
            cache.fill(sk);
        }
    };
}

pub const XWing = struct {
    pub const group = "x_wing";

    pub fn expand(seed: *const [xwing.seed_size]u8, public_key: *[xwing.public_key_size]u8, dk: *xwing.DecapsulationKey, scalar: *[32]u8, s_hat: *xwing.Secret, public: ?*xwing.EncapsulationKey) callconv(.c) void {
        xwing.expand(seed, public_key, dk, scalar, s_hat, public);
    }

    pub fn encapsulate(key: *const xwing.EncapsulationKey, public_key: *const [xwing.public_key_size]u8, eseed: *const [xwing.randomness_size]u8, shared_secret: *[32]u8, ciphertext: *[xwing.ciphertext_size]u8) callconv(.c) void {
        xwing.encapsulate(key, public_key, eseed, shared_secret, ciphertext);
    }

    pub fn decapsulate(s_hat: *const xwing.Secret, key: *const xwing.EncapsulationKey, dk: *const xwing.DecapsulationKey, scalar: *const [32]u8, public_key: *const [xwing.public_key_size]u8, ciphertext: *const [xwing.ciphertext_size]u8, shared_secret: *[32]u8) callconv(.c) void {
        xwing.decapsulateInto(s_hat, key, dk, scalar, public_key, ciphertext, shared_secret);
    }
};

pub const Ascon = struct {
    pub const group = "ascon";

    pub fn update(sponge: *ascon.Sponge, data: *const []const u8) callconv(.c) void {
        sponge.update(data.*);
    }

    pub fn read(sponge: *ascon.Sponge, out: *const []u8) callconv(.c) void {
        sponge.read(out.*);
    }
};

const groups = .{ MlKem(mlkem.ml_kem_512), MlKem(mlkem.ml_kem_768), MlKem(mlkem.ml_kem_1024), MlDsa(mldsa.ml_dsa_44), MlDsa(mldsa.ml_dsa_65), MlDsa(mldsa.ml_dsa_87), XWing, Ascon };

// Only the object, which this file is the root of, exports the functions.
comptime {
    if (@This() == @import("root")) {
        for (groups) |T| {
            for (@typeInfo(T).@"struct".decls) |decl| {
                if (@typeInfo(@TypeOf(@field(T, decl.name))) == .@"fn") {
                    @export(&@field(T, decl.name), .{ .name = symbol(T, decl.name), .visibility = .hidden });
                }
            }
        }
    }
}

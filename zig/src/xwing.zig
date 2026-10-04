const ct = @import("ct.zig");
const hash = @import("hash.zig");
const mlkem = @import("mlkem.zig");
const primitives = @import("primitives.zig");
const x25519 = @import("x25519.zig");

const params = mlkem.ml_kem_768;

const label = "\\.//^\\";

pub const public_key_size = 1216;

pub const ciphertext_size = 1120;

pub const seed_size = 32;

pub const randomness_size = 64;

pub const DecapsulationKey = [params.decapsulationKeySize()]u8;

const ek_size = params.encapsulationKeySize();

const ct_size = params.ciphertextSize();

// SHAKE256(seed) gives the ML-KEM-768 seeds d and z, then the X25519 private scalar.
pub fn expand(seed: *const [seed_size]u8, public_key: *[public_key_size]u8, dk: *DecapsulationKey, scalar: *[32]u8, key: *mlkem.DecapsulationKey) void {
    var expanded: [96]u8 = undefined;

    defer ct.wipe(&expanded);

    primitives.shake256(&.{seed}, &expanded);

    mlkem.keyGen(params, expanded[0..32], expanded[32..64], public_key[0..ek_size], dk, key);

    scalar.* = expanded[64..96].*;

    public_key[ek_size..].* = x25519.x25519Base(scalar);

    ct.declassify(public_key[ek_size..]);
}

fn combine(ss_m: *const [32]u8, ss_x: *const [32]u8, ct_x: *const [32]u8, pk_x: *const [32]u8) [32]u8 {
    var out: [32]u8 = undefined;

    primitives.digest(hash.sha3_256, &.{ ss_m, ss_x, ct_x, pk_x, label }, &out);

    return out;
}

pub fn checkPublicKey(public_key: *const [public_key_size]u8) bool {
    return mlkem.checkEncapsulationKey(params, public_key[0..ek_size]);
}

// The form of the ML-KEM part of a valid public key that encapsulation uses.
pub fn expandPublic(public_key: *const [public_key_size]u8, key: *mlkem.EncapsulationKey) void {
    var h: [32]u8 = undefined;

    primitives.digest(hash.sha3_256, &.{public_key[0..ek_size]}, &h);

    mlkem.expandPublic(params, public_key[0..ek_size], &h, key);
}

pub fn encapsulate(key: *const mlkem.EncapsulationKey, public_key: *const [public_key_size]u8, eseed: *const [randomness_size]u8, shared_secret: *[32]u8, ciphertext: *[ciphertext_size]u8) void {
    const pk_x = public_key[ek_size..];

    var ss_m: [32]u8 = undefined;

    var ss_x: [32]u8 = undefined;

    defer {
        ct.wipe(&ss_m);

        ct.wipe(&ss_x);
    }

    mlkem.encaps(params, key, eseed[0..32], &ss_m, ciphertext[0..ct_size]);

    ciphertext[ct_size..].* = x25519.x25519Base(eseed[32..64]);

    ct.declassify(ciphertext[ct_size..]);

    ss_x = x25519.x25519(eseed[32..64], pk_x);

    shared_secret.* = combine(&ss_m, &ss_x, ciphertext[ct_size..], pk_x);
}

pub fn decapsulate(key: *const mlkem.DecapsulationKey, dk: *const DecapsulationKey, scalar: *const [32]u8, public_key: *const [public_key_size]u8, ciphertext: *const [ciphertext_size]u8) [32]u8 {
    const ct_x = ciphertext[ct_size..];

    var ss_m = mlkem.decaps(params, key, dk, ciphertext[0..ct_size]);

    var ss_x = x25519.x25519(scalar, ct_x);

    defer {
        ct.wipe(&ss_m);

        ct.wipe(&ss_x);
    }

    return combine(&ss_m, &ss_x, ct_x, public_key[ek_size..]);
}

//! Deterministic operations for test vectors. Production code must not call them: reusing a seed
//! or randomness value with a different key, message or ciphertext breaks the scheme, and these
//! functions skip the pre-hash strength policy of the public API.

const std = @import("std");

const Error = @import("errors.zig").Error;
const kem = @import("kem.zig");
const keys = @import("keys.zig");
const signatures = @import("signature.zig");
const stateful = @import("stateful.zig");

const Allocator = std.mem.Allocator;

pub fn generateKemKeyPair(algorithm: kem.KemAlgorithm, seed: []const u8) Error!kem.KemKeyPair {
    try keys.requireLength(seed, kem.seedSize(algorithm.kind));

    var pair: kem.KemKeyPair = undefined;

    kem.fromSeed(&pair.private_key, algorithm, seed);

    pair.public_key = pair.private_key.publicKey();

    return pair;
}

// Seeds are 32 bytes for ML-DSA and SK.seed || SK.prf || PK.seed for SLH-DSA.
pub fn generateSignatureKeyPair(algorithm: signatures.SignatureAlgorithm, seed: []const u8) Error!signatures.SignatureKeyPair {
    try keys.requireLength(seed, signatures.seedSize(algorithm.kind));

    const private_key = signatures.fromSeed(algorithm, seed);

    return .{ .public_key = private_key.publicKey(), .private_key = private_key };
}

// Stateful seeds are I || SEED of the top LMS tree, or SK_SEED || SK_PRF || PUB_SEED for XMSS.
// The key starts at `index`, which may not exceed the number of one-time keys.
pub fn generateStatefulKeyPair(algorithm: stateful.StatefulSignatureAlgorithm, allocator: Allocator, parameters: stateful.StatefulParameters, seed: []const u8, index: u64, store: stateful.StateStore) (Error || Allocator.Error)!stateful.StatefulKeyPair {
    const setup = try stateful.Setup.parse(algorithm.kind, parameters);

    try keys.requireLength(seed, setup.seedSize());

    if (index > setup.capacity()) return error.InvalidOption;

    return stateful.create(algorithm, allocator, setup, seed, index, store);
}

pub fn encapsulate(public_key: *const kem.KemPublicKey, randomness: []const u8) Error!kem.Encapsulation {
    try keys.requireLength(randomness, kem.randomnessSize(public_key.algorithm.kind));

    return kem.encapsulateWith(public_key, randomness);
}

// `randomness` is rnd for ML-DSA and opt_rand for SLH-DSA; options.deterministic is ignored.
pub fn sign(private_key: *const signatures.SignaturePrivateKey, allocator: Allocator, message: []const u8, randomness: []const u8, options: signatures.SignOptions) (Error || Allocator.Error)![]u8 {
    return signatures.signDeterministic(private_key, allocator, message, randomness, options);
}

pub fn verify(public_key: *const signatures.SignaturePublicKey, signature: []const u8, message: []const u8, options: signatures.VerifyOptions) bool {
    return signatures.verifyWith(public_key, signature, message, options, false);
}

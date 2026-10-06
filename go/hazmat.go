package cryptopq

import "bytes"

// Deterministic operations for test vectors. Production code must not call them: reusing a seed
// or randomness value with a different key, message or ciphertext breaks the scheme, and these
// functions skip the pre-hash strength policy of the public API.
type hazmat struct{}

var Hazmat hazmat

func (hazmat) GenerateKemKeyPair(algorithm KemAlgorithm, seed []byte) (*KemKeyPair, error) {
	defer ditLeave(ditEnter())

	spec := algorithm.spec()

	if len(seed) != spec.seedSize {
		return nil, lengthError("seed", spec.seedSize)
	}

	privateKey := algorithm.fromSeed(bytes.Clone(seed)).protect()

	return &KemKeyPair{privateKey.PublicKey(), privateKey}, nil
}

func (hazmat) Encapsulate(publicKey *KemPublicKey, randomness []byte) (*Encapsulation, error) {
	defer ditLeave(ditEnter())

	spec := publicKey.algorithm.spec()

	if len(randomness) != spec.randomnessSize {
		return nil, lengthError("randomness", spec.randomnessSize)
	}

	return publicKey.encapsulate(randomness), nil
}

// The seed is xi for ML-DSA and SK.seed || SK.prf || PK.seed for SLH-DSA.
func (hazmat) GenerateSignatureKeyPair(algorithm SignatureAlgorithm, seed []byte) (*SignatureKeyPair, error) {
	defer ditLeave(ditEnter())

	spec := algorithm.spec()

	if len(seed) != spec.seedSize {
		return nil, lengthError("seed", spec.seedSize)
	}

	privateKey := algorithm.fromSeed(bytes.Clone(seed)).protect()

	return &SignatureKeyPair{privateKey.PublicKey(), privateKey}, nil
}

// Signs with the given randomness (rnd for ML-DSA, opt_rand for SLH-DSA); Deterministic is
// ignored.
func (hazmat) Sign(privateKey *SignaturePrivateKey, message, randomness []byte, options *SignOptions) ([]byte, error) {
	defer ditLeave(ditEnter())

	spec := privateKey.algorithm.spec()

	if len(randomness) != spec.randomnessSize {
		return nil, lengthError("randomness", spec.randomnessSize)
	}

	var opts SignOptions

	if options != nil {
		opts = *options
	}

	return privateKey.sign(message, randomness, opts.Context, opts.PreHash, false)
}

// Creates a stateful key at the given index; seeds are I || SEED of the top LMS tree, or
// SK_SEED || SK_PRF || PUB_SEED for XMSS and XMSS^MT.
func (hazmat) GenerateStatefulKeyPair(algorithm StatefulSignatureAlgorithm, options *StatefulKeyGenOptions, seed []byte, index uint64) (*StatefulKeyPair, error) {
	parameters, err := algorithm.parameters(options)

	if err != nil {
		return nil, err
	}

	if len(seed) != parameters.seedSize() {
		return nil, lengthError("seed", parameters.seedSize())
	}

	if options.StateStore == nil {
		return nil, invalidOption("a StateStore is required")
	}

	if index > parameters.capacity() {
		return nil, invalidOption("the index must not exceed the key's capacity")
	}

	return algorithm.create(parameters, bytes.Clone(seed), index, options.StateStore, options.Reserve)
}

func (hazmat) Verify(publicKey *SignaturePublicKey, signature, message []byte, options *VerifyOptions) bool {
	var opts VerifyOptions

	if options != nil {
		opts = *options
	}

	return publicKey.verify(signature, message, opts.Context, opts.PreHash, false)
}

// ConfigureCshake sets cSHAKE's function name N as well as its customization S. SP 800-185
// reserves N for functions NIST defines, so the public Configure takes S only; this one exists for
// test vectors. Both empty give SHAKE.
func (hazmat) ConfigureCshake(algorithm XofAlgorithm, functionName, customization []byte) (XofAlgorithm, error) {
	if algorithm.id != xofCSHAKE128 && algorithm.id != xofCSHAKE256 {
		return XofAlgorithm{}, invalidOption("ConfigureCshake takes CSHAKE128 or CSHAKE256")
	}

	return cshakeAlgorithm(algorithm.id, functionName, customization), nil
}

package cryptopq

import (
	"bytes"
	"fmt"
	"runtime"
)

type KemAlgorithm uint8

const (
	ML_KEM_512 KemAlgorithm = iota + 1
	ML_KEM_768
	ML_KEM_1024
	X_WING
)

type kemSpec struct {
	name             string
	oid              []byte
	params           *mlkemParams
	seedSize         int
	randomnessSize   int
	expandedSize     int
	publicKeySize    int
	ciphertextSize   int
	sharedSecretSize int
}

func mlkemSpec(name string, params *mlkemParams, arc uint64) kemSpec {
	return kemSpec{
		name:             name,
		oid:              objectIdentifier(2, 16, 840, 1, 101, 3, 4, 4, arc),
		params:           params,
		seedSize:         64,
		randomnessSize:   32,
		expandedSize:     params.decapsulationKeySize(),
		publicKeySize:    params.encapsulationKeySize(),
		ciphertextSize:   params.ciphertextSize(),
		sharedSecretSize: 32,
	}
}

var kemSpecs = [...]kemSpec{
	ML_KEM_512:  mlkemSpec("ML-KEM-512", &mlkem512, 1),
	ML_KEM_768:  mlkemSpec("ML-KEM-768", &mlkem768, 2),
	ML_KEM_1024: mlkemSpec("ML-KEM-1024", &mlkem1024, 3),
	X_WING:      {name: "X-Wing", seedSize: 32, randomnessSize: 64, publicKeySize: xwingPublicKeySize, ciphertextSize: xwingCiphertextSize, sharedSecretSize: 32},
}

func (a KemAlgorithm) spec() *kemSpec {
	if a == 0 || int(a) >= len(kemSpecs) {
		panic("cryptopq: invalid KemAlgorithm")
	}

	return &kemSpecs[a]
}

func (a KemAlgorithm) Name() string {
	return a.spec().name
}

func (a KemAlgorithm) String() string {
	return a.Name()
}

func (a KemAlgorithm) PublicKeySize() int {
	return a.spec().publicKeySize
}

func (a KemAlgorithm) CiphertextSize() int {
	return a.spec().ciphertextSize
}

func (a KemAlgorithm) SharedSecretSize() int {
	return a.spec().sharedSecretSize
}

type KeyGenOptions struct {
	SkipSelfTest bool
}

type KemKeyPair struct {
	PublicKey  *KemPublicKey
	PrivateKey *KemPrivateKey
}

type Encapsulation struct {
	SharedSecret []byte
	Ciphertext   []byte
}

func (a KemAlgorithm) GenerateKeyPair(options *KeyGenOptions) (*KemKeyPair, error) {
	defer ditLeave(ditEnter())

	seed, err := randomBytes(a.spec().seedSize)

	if err != nil {
		return nil, err
	}

	privateKey := a.fromSeed(seed)

	publicKey := privateKey.PublicKey()

	if options == nil || !options.SkipSelfTest {
		encapsulation, err := publicKey.Encapsulate()

		if err != nil {
			return nil, err
		}

		sharedSecret, err := privateKey.Decapsulate(encapsulation.Ciphertext)

		if err != nil || !equal(sharedSecret, encapsulation.SharedSecret) {
			privateKey.wipe()

			return nil, newError(SELF_TEST_FAILED, "the new key pair failed its consistency test")
		}
	}

	return &KemKeyPair{publicKey, privateKey.protect()}, nil
}

// The seed becomes part of the key, so callers pass a buffer they no longer use.
func (a KemAlgorithm) fromSeed(seed []byte) *KemPrivateKey {
	key := &KemPrivateKey{algorithm: a, seed: seed}

	params := a.spec().params

	if params != nil {
		key.public, key.dk = mlkemKeyGen(params, seed[:32], seed[32:])
	} else {
		params = &mlkem768

		key.public, key.dk, key.scalar, key.point = xwingExpand(seed)
	}

	return key.withCaches(params)
}

func (a KemAlgorithm) fromExpanded(dk []byte) (*KemPrivateKey, error) {
	params := a.spec().params

	if !mlkemCheckDecapsulationKey(params, dk) {
		return nil, mismatch("the decapsulation key fails the FIPS 203 checks")
	}

	public := bytes.Clone(dk[384*params.k : 768*params.k+32])

	return (&KemPrivateKey{algorithm: a, dk: dk, public: public}).withCaches(params), nil
}

func (s *kemSpec) validPublicKey(key []byte) bool {
	if s.params != nil {
		return mlkemCheckEncapsulationKey(s.params, key)
	}

	return xwingCheckPublicKey(key)
}

// The cache of a public key, with H(ek) of its ML-KEM part for X-Wing.
func (s *kemSpec) cache(key []byte) *mlkemPublic {
	if s.params == nil {
		key = key[:xwingMlkemSize]
	}

	var h [32]byte

	sha3Sum256(h[:], key)

	return newMlkemPublic(h[:])
}

func (a KemAlgorithm) ImportPublicKey(data []byte, format KeyFormat) (*KemPublicKey, error) {
	spec := a.spec()

	key, err := importPublic(format, data, spec.oid, spec.publicKeySize)

	if err != nil {
		return nil, err
	}

	if !spec.validPublicKey(key) {
		return nil, newError(INVALID_PUBLIC_KEY, "the public key fails the encoding checks")
	}

	return &KemPublicKey{algorithm: a, key: key, cache: spec.cache(key)}, nil
}

func (a KemAlgorithm) ImportPrivateKey(data []byte, format KeyFormat) (*KemPrivateKey, error) {
	defer ditLeave(ditEnter())

	spec := a.spec()

	raw, octets, publicKey, err := importPrivate(format, data, spec.oid)

	if err != nil {
		return nil, err
	}

	defer clear(octets)

	var key *KemPrivateKey

	switch {
	case format != RAW:
		key, err = a.fromSeedChoice(octets)
	case len(raw) == spec.seedSize:
		key = a.fromSeed(raw)
	case spec.expandedSize > 0 && len(raw) == spec.expandedSize:
		key, err = a.fromExpanded(raw)
	default:
		clear(raw)

		err = newError(INVALID_LENGTH, "the private key has the wrong length")
	}

	if err != nil {
		return nil, err
	}

	if publicKey != nil && !equal(publicKey, key.public) {
		key.wipe()

		return nil, mismatch("the embedded public key does not match the private key")
	}

	return key.protect(), nil
}

func (a KemAlgorithm) fromSeedChoice(octets []byte) (*KemPrivateKey, error) {
	spec := a.spec()

	seed, expanded, err := decodeSeedChoice(octets, spec.seedSize, spec.expandedSize)

	if err != nil {
		return nil, err
	}

	if seed == nil {
		return a.fromExpanded(bytes.Clone(expanded))
	}

	key := a.fromSeed(bytes.Clone(seed))

	if expanded != nil && !equal(expanded, key.dk) {
		key.wipe()

		return nil, mismatch("the seed and the expanded key do not match")
	}

	return key, nil
}

type KemPublicKey struct {
	algorithm KemAlgorithm
	key       []byte
	cache     *mlkemPublic
}

func (k *KemPublicKey) Algorithm() KemAlgorithm {
	return k.algorithm
}

func (k *KemPublicKey) Encapsulate() (*Encapsulation, error) {
	defer ditLeave(ditEnter())

	randomness, err := randomBytes(k.algorithm.spec().randomnessSize)

	if err != nil {
		return nil, err
	}

	defer clear(randomness)

	return k.encapsulate(randomness), nil
}

func (k *KemPublicKey) encapsulate(randomness []byte) *Encapsulation {
	var sharedSecret, ciphertext []byte

	if params := k.algorithm.spec().params; params != nil {
		sharedSecret, ciphertext = mlkemEncapsulate(params, k.key, k.cache, randomness)
	} else {
		sharedSecret, ciphertext = xwingEncapsulate(k.key, k.cache, randomness)
	}

	return &Encapsulation{SharedSecret: sharedSecret, Ciphertext: ciphertext}
}

func (k *KemPublicKey) ExportKey(format KeyFormat) ([]byte, error) {
	return exportPublic(format, k.algorithm.spec().oid, k.key)
}

func (k *KemPublicKey) Equal(other *KemPublicKey) bool {
	if k == nil || other == nil {
		return k == other
	}

	return k.algorithm == other.algorithm && bytes.Equal(k.key, other.key)
}

func (k *KemPublicKey) String() string {
	return "<KemPublicKey " + k.algorithm.Name() + ">"
}

// cache and secret hold what the key derives from dk, the ML-KEM-768 key for X-Wing; cache is shared
// with the public keys it returns.
type KemPrivateKey struct {
	algorithm KemAlgorithm
	seed      []byte
	dk        []byte
	scalar    []byte
	point     []byte
	public    []byte
	cache     *mlkemPublic
	secret    *mlkemSecret
}

// The decapsulation key holds H(ek).
func (k *KemPrivateKey) withCaches(params *mlkemParams) *KemPrivateKey {
	k.cache, k.secret = newMlkemPublic(k.dk[768*params.k+32:768*params.k+64]), &mlkemSecret{}

	return k
}

func (k *KemPrivateKey) protect() *KemPrivateKey {
	wipeWhenUnreachable(k, k.seed, k.dk, k.scalar)

	runtime.AddCleanup(k, func(secret *mlkemSecret) { clear(secret.s) }, k.secret)

	return k
}

func (k *KemPrivateKey) wipe() {
	clear(k.seed)

	clear(k.dk)

	clear(k.scalar)

	clear(k.secret.s)
}

func (k *KemPrivateKey) Algorithm() KemAlgorithm {
	return k.algorithm
}

func (k *KemPrivateKey) PublicKey() *KemPublicKey {
	return &KemPublicKey{algorithm: k.algorithm, key: k.public, cache: k.cache}
}

func (k *KemPrivateKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	defer ditLeave(ditEnter())

	defer runtime.KeepAlive(k)

	spec := k.algorithm.spec()

	if len(ciphertext) != spec.ciphertextSize {
		return nil, lengthError("ciphertext", spec.ciphertextSize)
	}

	if spec.params != nil {
		return mlkemDecapsulate(spec.params, k.dk, k.secret, k.cache, ciphertext), nil
	}

	return xwingDecapsulate(k.dk, k.secret, k.cache, k.scalar, k.point, ciphertext), nil
}

func (k *KemPrivateKey) ExportKey(format KeyFormat) ([]byte, error) {
	defer ditLeave(ditEnter())

	defer runtime.KeepAlive(k)

	return exportSeedChoice(format, k.algorithm.spec().oid, k.seed, k.dk)
}

// Formatting shows only the algorithm, never key material.
func (k *KemPrivateKey) Format(state fmt.State, verb rune) {
	fmt.Fprintf(state, "<KemPrivateKey %s>", k.algorithm.Name())
}

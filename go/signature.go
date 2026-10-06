package cryptopq

import (
	"bytes"
	"fmt"
	"runtime"
)

var selfTestMessage = []byte("crypto-pq pairwise consistency test")

type PreHash interface {
	preHash()
}

func (HashAlgorithm) preHash() {}

func (XofAlgorithm) preHash() {}

type preHashSpec struct {
	name     string
	oid      []byte
	strength int
	digest   func([]byte) []byte
}

func newPreHash(name string, arc uint64, strength int, digest func([]byte) []byte) preHashSpec {
	oid := derElement(tagObjectIdentifier, objectIdentifier(2, 16, 840, 1, 101, 3, 4, 2, arc))

	return preHashSpec{name: name, oid: oid, strength: strength, digest: digest}
}

func hashPreHash(algorithm HashAlgorithm, arc uint64, strength int) preHashSpec {
	return newPreHash(algorithm.Name(), arc, strength, algorithm.Digest)
}

// Collision strength in bits of each approved pre-hash; SHAKE128 and SHAKE256 produce 256 and
// 512 bits as FIPS 204 and FIPS 205 require.
var hashPreHashes = [...]preHashSpec{
	hashSHA224:     hashPreHash(SHA_224, 4, 112),
	hashSHA256:     hashPreHash(SHA_256, 1, 128),
	hashSHA384:     hashPreHash(SHA_384, 2, 192),
	hashSHA512:     hashPreHash(SHA_512, 3, 256),
	hashSHA512_224: hashPreHash(SHA_512_224, 5, 112),
	hashSHA512_256: hashPreHash(SHA_512_256, 6, 128),
	hashSHA3_224:   hashPreHash(SHA3_224, 7, 112),
	hashSHA3_256:   hashPreHash(SHA3_256, 8, 128),
	hashSHA3_384:   hashPreHash(SHA3_384, 9, 192),
	hashSHA3_512:   hashPreHash(SHA3_512, 10, 256),
}

var xofPreHashes = [...]preHashSpec{
	xofSHAKE128: newPreHash("SHAKE128", 11, 128, func(message []byte) []byte { return SHAKE128.Digest(message, 32) }),
	xofSHAKE256: newPreHash("SHAKE256", 12, 256, func(message []byte) []byte { return SHAKE256.Digest(message, 64) }),
}

func preHashOf(preHash PreHash) (*preHashSpec, error) {
	switch algorithm := preHash.(type) {
	case nil:
		return nil, nil
	case HashAlgorithm:
		if algorithm.id > 0 && int(algorithm.id) < len(hashPreHashes) {
			return &hashPreHashes[algorithm.id], nil
		}
	case XofAlgorithm:
		if algorithm.id > 0 && int(algorithm.id) < len(xofPreHashes) {
			return &xofPreHashes[algorithm.id], nil
		}
	}

	return nil, invalidOption("PreHash must be a SHA-2, SHA-3 or SHAKE function that FIPS 204 and FIPS 205 list")
}

// FIPS 204 and FIPS 205: M' = 0 || |ctx| || ctx || M, or 1 || |ctx| || ctx || OID || PH(M).
func messageRepresentative(message, context []byte, entry *preHashSpec) []byte {
	if entry == nil {
		out := make([]byte, 0, 2+len(context)+len(message))

		out = append(out, 0, byte(len(context)))

		out = append(out, context...)

		return append(out, message...)
	}

	digest := entry.digest(message)

	out := make([]byte, 0, 2+len(context)+len(entry.oid)+len(digest))

	out = append(out, 1, byte(len(context)))

	out = append(out, context...)

	out = append(out, entry.oid...)

	return append(out, digest...)
}

type SignatureAlgorithm uint8

const (
	ML_DSA_44 SignatureAlgorithm = iota + 1
	ML_DSA_65
	ML_DSA_87
	SLH_DSA_SHA2_128S
	SLH_DSA_SHA2_128F
	SLH_DSA_SHA2_192S
	SLH_DSA_SHA2_192F
	SLH_DSA_SHA2_256S
	SLH_DSA_SHA2_256F
	SLH_DSA_SHAKE_128S
	SLH_DSA_SHAKE_128F
	SLH_DSA_SHAKE_192S
	SLH_DSA_SHAKE_192F
	SLH_DSA_SHAKE_256S
	SLH_DSA_SHAKE_256F
)

type signatureSpec struct {
	name           string
	oid            []byte
	mldsa          *mldsaParams
	slh            *slhParams
	seedSize       int
	expandedSize   int
	publicKeySize  int
	signatureSize  int
	randomnessSize int
	strength       int
}

func mldsaSpec(name string, params *mldsaParams, arc uint64) signatureSpec {
	return signatureSpec{
		name:           name,
		oid:            objectIdentifier(2, 16, 840, 1, 101, 3, 4, 3, arc),
		mldsa:          params,
		seedSize:       32,
		expandedSize:   params.privateKeySize(),
		publicKeySize:  params.publicKeySize(),
		signatureSize:  params.signatureSize(),
		randomnessSize: 32,
		strength:       params.lambda,
	}
}

func slhSpec(name string, index int) signatureSpec {
	params := &slhSets[index]

	return signatureSpec{
		name:           name,
		oid:            objectIdentifier(2, 16, 840, 1, 101, 3, 4, 3, uint64(20+index)),
		slh:            params,
		seedSize:       3 * params.n,
		publicKeySize:  2 * params.n,
		signatureSize:  params.signatureSize(),
		randomnessSize: params.n,
		strength:       8 * params.n,
	}
}

var signatureSpecs = [...]signatureSpec{
	ML_DSA_44:          mldsaSpec("ML-DSA-44", &mldsa44, 17),
	ML_DSA_65:          mldsaSpec("ML-DSA-65", &mldsa65, 18),
	ML_DSA_87:          mldsaSpec("ML-DSA-87", &mldsa87, 19),
	SLH_DSA_SHA2_128S:  slhSpec("SLH-DSA-SHA2-128s", 0),
	SLH_DSA_SHA2_128F:  slhSpec("SLH-DSA-SHA2-128f", 1),
	SLH_DSA_SHA2_192S:  slhSpec("SLH-DSA-SHA2-192s", 2),
	SLH_DSA_SHA2_192F:  slhSpec("SLH-DSA-SHA2-192f", 3),
	SLH_DSA_SHA2_256S:  slhSpec("SLH-DSA-SHA2-256s", 4),
	SLH_DSA_SHA2_256F:  slhSpec("SLH-DSA-SHA2-256f", 5),
	SLH_DSA_SHAKE_128S: slhSpec("SLH-DSA-SHAKE-128s", 6),
	SLH_DSA_SHAKE_128F: slhSpec("SLH-DSA-SHAKE-128f", 7),
	SLH_DSA_SHAKE_192S: slhSpec("SLH-DSA-SHAKE-192s", 8),
	SLH_DSA_SHAKE_192F: slhSpec("SLH-DSA-SHAKE-192f", 9),
	SLH_DSA_SHAKE_256S: slhSpec("SLH-DSA-SHAKE-256s", 10),
	SLH_DSA_SHAKE_256F: slhSpec("SLH-DSA-SHAKE-256f", 11),
}

func (a SignatureAlgorithm) spec() *signatureSpec {
	if a == 0 || int(a) >= len(signatureSpecs) {
		panic("cryptopq: invalid SignatureAlgorithm")
	}

	return &signatureSpecs[a]
}

func (a SignatureAlgorithm) Name() string {
	return a.spec().name
}

func (a SignatureAlgorithm) String() string {
	return a.Name()
}

func (a SignatureAlgorithm) PublicKeySize() int {
	return a.spec().publicKeySize
}

func (a SignatureAlgorithm) SignatureSize() int {
	return a.spec().signatureSize
}

type SignatureKeyPair struct {
	PublicKey  *SignaturePublicKey
	PrivateKey *SignaturePrivateKey
}

type SignOptions struct {
	Context       []byte
	Deterministic bool
	PreHash       PreHash
}

type VerifyOptions struct {
	Context []byte
	PreHash PreHash
}

func (a SignatureAlgorithm) GenerateKeyPair(options *KeyGenOptions) (*SignatureKeyPair, error) {
	defer ditLeave(ditEnter())

	seed, err := randomBytes(a.spec().seedSize)

	if err != nil {
		return nil, err
	}

	privateKey := a.fromSeed(seed)

	publicKey := privateKey.PublicKey()

	if options == nil || !options.SkipSelfTest {
		signature, err := privateKey.Sign(selfTestMessage, &SignOptions{Deterministic: true})

		if err != nil || !publicKey.Verify(signature, selfTestMessage, nil) {
			privateKey.wipe()

			return nil, newError(SELF_TEST_FAILED, "the new key pair failed its consistency test")
		}
	}

	return &SignatureKeyPair{publicKey, privateKey.protect()}, nil
}

// ML-DSA keeps the seed as its private key; SLH-DSA keeps the 4n-byte key, so its seed buffer
// is cleared. Either way the caller hands over the buffer.
func (a SignatureAlgorithm) fromSeed(seed []byte) *SignaturePrivateKey {
	spec := a.spec()

	if spec.mldsa != nil {
		public, private := mldsaKeyGen(spec.mldsa, seed)

		return &SignaturePrivateKey{algorithm: a, seed: seed, private: private, public: public, cache: newDsaPublic(private[64:128]), secrets: &dsaSecrets{}}
	}

	n := spec.slh.n

	private, public := slhKeyGen(spec.slh, seed[:n], seed[n:2*n], seed[2*n:])

	clear(seed)

	return &SignaturePrivateKey{algorithm: a, private: private, public: public}
}

func (a SignatureAlgorithm) fromExpanded(sk []byte) (*SignaturePrivateKey, error) {
	public := mldsaCheckPrivateKey(a.spec().mldsa, sk)

	if public == nil {
		clear(sk)

		return nil, mismatch("the private key fails the consistency checks")
	}

	return &SignaturePrivateKey{algorithm: a, private: sk, public: public, cache: newDsaPublic(sk[64:128]), secrets: &dsaSecrets{}}, nil
}

func (a SignatureAlgorithm) fromSlhPrivateKey(sk []byte) (*SignaturePrivateKey, error) {
	p := a.spec().slh

	n := p.n

	if !equal(slhRoot(p, sk[:n], sk[2*n:3*n]), sk[3*n:]) {
		clear(sk)

		return nil, mismatch("the private key does not match its public root")
	}

	return &SignaturePrivateKey{algorithm: a, private: sk, public: bytes.Clone(sk[2*n:])}, nil
}

func (a SignatureAlgorithm) ImportPublicKey(data []byte, format KeyFormat) (*SignaturePublicKey, error) {
	spec := a.spec()

	key, err := importPublic(format, data, spec.oid, spec.publicKeySize)

	if err != nil {
		return nil, err
	}

	public := &SignaturePublicKey{algorithm: a, key: key}

	if spec.mldsa != nil {
		var tr [64]byte

		shake256Sum(tr[:], key)

		public.cache = newDsaPublic(tr[:])
	}

	return public, nil
}

func (a SignatureAlgorithm) ImportPrivateKey(data []byte, format KeyFormat) (*SignaturePrivateKey, error) {
	defer ditLeave(ditEnter())

	spec := a.spec()

	raw, octets, publicKey, err := importPrivate(format, data, spec.oid)

	if err != nil {
		return nil, err
	}

	defer clear(octets)

	var key *SignaturePrivateKey

	switch {
	case spec.slh != nil && format != RAW:
		if len(octets) != 4*spec.slh.n {
			return nil, invalidEncoding("the private key has the wrong length")
		}

		key, err = a.fromSlhPrivateKey(bytes.Clone(octets))
	case spec.slh != nil:
		if len(raw) != 4*spec.slh.n {
			clear(raw)

			return nil, lengthError("private key", 4*spec.slh.n)
		}

		key, err = a.fromSlhPrivateKey(raw)
	case format != RAW:
		key, err = a.fromSeedChoice(octets)
	case len(raw) == spec.seedSize:
		key = a.fromSeed(raw)
	case len(raw) == spec.expandedSize:
		key, err = a.fromExpanded(raw)
	default:
		clear(raw)

		err = lengthError("private key", spec.expandedSize)
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

func (a SignatureAlgorithm) fromSeedChoice(octets []byte) (*SignaturePrivateKey, error) {
	spec := a.spec()

	seed, expanded, err := decodeSeedChoice(octets, spec.seedSize, spec.expandedSize)

	if err != nil {
		return nil, err
	}

	if seed == nil {
		return a.fromExpanded(bytes.Clone(expanded))
	}

	key := a.fromSeed(bytes.Clone(seed))

	if expanded != nil && !equal(expanded, key.private) {
		key.wipe()

		return nil, mismatch("the seed and the expanded key do not match")
	}

	return key, nil
}

// cache holds what ML-DSA derives from the key; SLH-DSA keys have none.
type SignaturePublicKey struct {
	algorithm SignatureAlgorithm
	key       []byte
	cache     *dsaPublic
}

func (k *SignaturePublicKey) Algorithm() SignatureAlgorithm {
	return k.algorithm
}

func (k *SignaturePublicKey) Verify(signature, message []byte, options *VerifyOptions) bool {
	var opts VerifyOptions

	if options != nil {
		opts = *options
	}

	return k.verify(signature, message, opts.Context, opts.PreHash, true)
}

// A pre-hash must give at least the collision strength of the signature (FIPS 204, 5.4, and
// FIPS 205, 10.2): verification with a weaker one fails closed, as does any invalid option.
func (k *SignaturePublicKey) verify(signature, message, context []byte, preHash PreHash, policy bool) bool {
	spec := k.algorithm.spec()

	entry, err := preHashOf(preHash)

	if err != nil || policy && entry != nil && entry.strength < spec.strength || len(context) > 255 || len(signature) != spec.signatureSize {
		return false
	}

	representative := messageRepresentative(message, context, entry)

	if spec.mldsa != nil {
		return mldsaVerify(spec.mldsa, k.key, k.cache, representative, signature)
	}

	return slhVerify(spec.slh, representative, signature, k.key)
}

func (k *SignaturePublicKey) ExportKey(format KeyFormat) ([]byte, error) {
	return exportPublic(format, k.algorithm.spec().oid, k.key)
}

func (k *SignaturePublicKey) Equal(other *SignaturePublicKey) bool {
	if k == nil || other == nil {
		return k == other
	}

	return k.algorithm == other.algorithm && bytes.Equal(k.key, other.key)
}

func (k *SignaturePublicKey) String() string {
	return "<SignaturePublicKey " + k.algorithm.Name() + ">"
}

// An ML-DSA key shares cache with its public keys and decodes secrets on first use; SLH-DSA keys
// have neither.
type SignaturePrivateKey struct {
	algorithm SignatureAlgorithm
	seed      []byte
	private   []byte
	public    []byte
	cache     *dsaPublic
	secrets   *dsaSecrets
}

func (k *SignaturePrivateKey) protect() *SignaturePrivateKey {
	wipeWhenUnreachable(k, k.seed, k.private)

	if k.secrets != nil {
		runtime.AddCleanup(k, func(secrets *dsaSecrets) { clear(secrets.polys) }, k.secrets)
	}

	return k
}

func (k *SignaturePrivateKey) wipe() {
	clear(k.seed)

	clear(k.private)

	if k.secrets != nil {
		clear(k.secrets.polys)
	}
}

func (k *SignaturePrivateKey) Algorithm() SignatureAlgorithm {
	return k.algorithm
}

func (k *SignaturePrivateKey) PublicKey() *SignaturePublicKey {
	return &SignaturePublicKey{algorithm: k.algorithm, key: k.public, cache: k.cache}
}

// deterministic: ML-DSA signs with rnd = 32 zero bytes and SLH-DSA with opt_rand = PK.seed.
func (k *SignaturePrivateKey) Sign(message []byte, options *SignOptions) ([]byte, error) {
	defer ditLeave(ditEnter())

	defer runtime.KeepAlive(k)

	var opts SignOptions

	if options != nil {
		opts = *options
	}

	spec := k.algorithm.spec()

	var randomness []byte

	switch {
	case !opts.Deterministic:
		var err error

		if randomness, err = randomBytes(spec.randomnessSize); err != nil {
			return nil, err
		}

		defer clear(randomness)
	case spec.mldsa != nil:
		randomness = make([]byte, 32)
	default:
		randomness = k.private[2*spec.slh.n : 3*spec.slh.n]
	}

	return k.sign(message, randomness, opts.Context, opts.PreHash, true)
}

func (k *SignaturePrivateKey) sign(message, randomness, context []byte, preHash PreHash, policy bool) ([]byte, error) {
	defer runtime.KeepAlive(k)

	spec := k.algorithm.spec()

	entry, err := preHashOf(preHash)

	if err != nil {
		return nil, err
	}

	if policy && entry != nil && entry.strength < spec.strength {
		return nil, invalidOption(entry.name + " is weaker than the signature algorithm")
	}

	if len(context) > 255 {
		return nil, newError(INVALID_CONTEXT, "the context must be at most 255 bytes")
	}

	representative := messageRepresentative(message, context, entry)

	if p := spec.mldsa; p != nil {
		a, secrets := k.cache.matrix(p, k.public[:32]), k.secrets.get(p, k.private)

		return mldsaSign(p, k.private, a, secrets, representative, randomness), nil
	}

	return slhSign(spec.slh, representative, k.private, randomness), nil
}

func (k *SignaturePrivateKey) ExportKey(format KeyFormat) ([]byte, error) {
	defer ditLeave(ditEnter())

	defer runtime.KeepAlive(k)

	spec := k.algorithm.spec()

	if spec.slh != nil {
		return exportPrivate(format, spec.oid, k.private, k.private)
	}

	return exportSeedChoice(format, spec.oid, k.seed, k.private)
}

// Formatting shows only the algorithm, never key material.
func (k *SignaturePrivateKey) Format(state fmt.State, verb rune) {
	fmt.Fprintf(state, "<SignaturePrivateKey %s>", k.algorithm.Name())
}

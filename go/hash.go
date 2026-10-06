package cryptopq

import "encoding/binary"

type engine interface {
	update(data []byte)
	digest() []byte
	digestInto(out []byte)
	clone() engine
}

type sha3Engine struct {
	sponge keccak
	size   int
}

func newSha3(size int) engine {
	return &sha3Engine{sponge: keccak{rate: 200 - 2*size, suffix: 0x06}, size: size}
}

func sha3DigestInto(data, out []byte) {
	e := sha3Engine{sponge: keccak{rate: 200 - 2*len(out), suffix: 0x06}, size: len(out)}

	e.update(data)

	e.digestInto(out)
}

func (e *sha3Engine) update(data []byte) {
	e.sponge.update(data)
}

func (e *sha3Engine) digest() []byte {
	out := make([]byte, e.size)

	e.digestInto(out)

	return out
}

func (e *sha3Engine) digestInto(out []byte) {
	sponge := e.sponge

	sponge.read(out)
}

func (e *sha3Engine) clone() engine {
	copied := *e

	return &copied
}

type HashAlgorithm uint8

const (
	SHA_224 HashAlgorithm = iota + 1
	SHA_256
	SHA_384
	SHA_512
	SHA_512_224
	SHA_512_256
	SHA3_224
	SHA3_256
	SHA3_384
	SHA3_512
)

type hashSpec struct {
	name       string
	digestSize int
	blockSize  int
	create     func() engine
}

var hashSpecs = [...]hashSpec{
	SHA_224:     {"SHA-224", 28, 64, func() engine { return newSha256(&iv224, 28) }},
	SHA_256:     {"SHA-256", 32, 64, func() engine { return newSha256(&iv256, 32) }},
	SHA_384:     {"SHA-384", 48, 128, func() engine { return newSha512(&iv384, 48) }},
	SHA_512:     {"SHA-512", 64, 128, func() engine { return newSha512(&iv512, 64) }},
	SHA_512_224: {"SHA-512/224", 28, 128, func() engine { return newSha512(&iv512224, 28) }},
	SHA_512_256: {"SHA-512/256", 32, 128, func() engine { return newSha512(&iv512256, 32) }},
	SHA3_224:    {"SHA3-224", 28, 144, func() engine { return newSha3(28) }},
	SHA3_256:    {"SHA3-256", 32, 136, func() engine { return newSha3(32) }},
	SHA3_384:    {"SHA3-384", 48, 104, func() engine { return newSha3(48) }},
	SHA3_512:    {"SHA3-512", 64, 72, func() engine { return newSha3(64) }},
}

func (a HashAlgorithm) spec() *hashSpec {
	if a == 0 || int(a) >= len(hashSpecs) {
		panic("cryptopq: invalid HashAlgorithm")
	}

	return &hashSpecs[a]
}

func (a HashAlgorithm) Name() string {
	return a.spec().name
}

func (a HashAlgorithm) DigestSize() int {
	return a.spec().digestSize
}

func (a HashAlgorithm) Digest(data []byte) []byte {
	out := make([]byte, a.spec().digestSize)

	a.DigestInto(data, out)

	return out
}

// DigestInto writes the digest into out, which must be DigestSize bytes long, without allocating.
// Each hash is called directly rather than through a function value, so that its buffers stay on
// the stack together with out.
func (a HashAlgorithm) DigestInto(data, out []byte) {
	checkDigestLength(len(out), a.spec().digestSize)

	switch a {
	case SHA_224:
		sha256Finish(iv224, 0, data, out)
	case SHA_256:
		sha256Finish(iv256, 0, data, out)
	case SHA_384:
		sha512Finish(iv384, 0, data, out)
	case SHA_512:
		sha512Finish(iv512, 0, data, out)
	case SHA_512_224:
		sha512Finish(iv512224, 0, data, out)
	case SHA_512_256:
		sha512Finish(iv512256, 0, data, out)
	default:
		sha3DigestInto(data, out)
	}
}

func (a HashAlgorithm) Create() *Hasher {
	spec := a.spec()

	return &Hasher{engine: spec.create(), size: spec.digestSize}
}

// An output buffer of another length is a programming error, as an index out of range is.
func checkDigestLength(actual, expected int) {
	if actual != expected {
		panic("cryptopq: INVALID_LENGTH: the output must be exactly the digest size")
	}
}

func (a HashAlgorithm) String() string {
	return a.Name()
}

type Hasher struct {
	engine engine
	size   int
}

func (h *Hasher) Update(data []byte) {
	h.engine.update(data)
}

func (h *Hasher) Digest() []byte {
	return h.engine.digest()
}

func (h *Hasher) DigestInto(out []byte) {
	checkDigestLength(len(out), h.size)

	h.engine.digestInto(out)
}

type XofAlgorithm uint8

const (
	SHAKE128 XofAlgorithm = iota + 1
	SHAKE256
)

type xofSpec struct {
	name string
	rate int
}

var xofSpecs = [...]xofSpec{
	SHAKE128: {"SHAKE128", 168},
	SHAKE256: {"SHAKE256", 136},
}

func (a XofAlgorithm) spec() *xofSpec {
	if a == 0 || int(a) >= len(xofSpecs) {
		panic("cryptopq: invalid XofAlgorithm")
	}

	return &xofSpecs[a]
}

func (a XofAlgorithm) Name() string {
	return a.spec().name
}

func (a XofAlgorithm) Digest(data []byte, length int) []byte {
	sponge := keccak{rate: a.spec().rate, suffix: 0x1f}

	sponge.update(data)

	return squeeze(&sponge, length)
}

// DigestInto fills out with output, without allocating.
func (a XofAlgorithm) DigestInto(data, out []byte) {
	sponge := keccak{rate: a.spec().rate, suffix: 0x1f}

	sponge.update(data)

	sponge.read(out)
}

func (a XofAlgorithm) Create() *Xof {
	return &Xof{sponge: keccak{rate: a.spec().rate, suffix: 0x1f}}
}

func (a XofAlgorithm) String() string {
	return a.Name()
}

type Xof struct {
	sponge keccak
}

func (x *Xof) Update(data []byte) {
	x.sponge.update(data)
}

func (x *Xof) Read(length int) []byte {
	return squeeze(&x.sponge, length)
}

func (x *Xof) ReadInto(out []byte) {
	x.sponge.read(out)
}

func squeeze(sponge *keccak, length int) []byte {
	if length < 0 {
		panic("cryptopq: INVALID_LENGTH: length must not be negative")
	}

	out := make([]byte, length)

	sponge.read(out)

	return out
}

type HmacAlgorithm uint8

const (
	HMAC_SHA_224 HmacAlgorithm = iota + 1
	HMAC_SHA_256
	HMAC_SHA_384
	HMAC_SHA_512
)

type hmacSpec struct {
	name string
	hash HashAlgorithm
}

var hmacSpecs = [...]hmacSpec{
	HMAC_SHA_224: {"HMAC-SHA-224", SHA_224},
	HMAC_SHA_256: {"HMAC-SHA-256", SHA_256},
	HMAC_SHA_384: {"HMAC-SHA-384", SHA_384},
	HMAC_SHA_512: {"HMAC-SHA-512", SHA_512},
}

func (a HmacAlgorithm) spec() *hmacSpec {
	if a == 0 || int(a) >= len(hmacSpecs) {
		panic("cryptopq: invalid HmacAlgorithm")
	}

	return &hmacSpecs[a]
}

func (a HmacAlgorithm) Name() string {
	return a.spec().name
}

func (a HmacAlgorithm) DigestSize() int {
	return a.spec().hash.DigestSize()
}

func (a HmacAlgorithm) Digest(key, data []byte) []byte {
	out := make([]byte, a.DigestSize())

	a.DigestInto(key, data, out)

	return out
}

// DigestInto writes the tag into out, which must be DigestSize bytes long, without allocating.
func (a HmacAlgorithm) DigestInto(key, data, out []byte) {
	hash := a.spec().hash

	checkDigestLength(len(out), hash.DigestSize())

	defer ditLeave(ditEnter())

	hmacInto(hash, key, data, out)
}

func (a HmacAlgorithm) Create(key []byte) *Hmac {
	defer ditLeave(ditEnter())

	hash := a.spec().hash

	spec := hash.spec()

	var block [128]byte

	hmacKey(hash, key, &block)

	h := &Hmac{size: spec.digestSize}

	if spec.blockSize == 64 {
		keyed := hmacKeys256(hashIV256(hash), &block)

		h.inner = &sha256Engine{state: [8]uint32(keyed[:8]), length: 64, size: spec.digestSize}

		h.outer = &sha256Engine{state: [8]uint32(keyed[8:]), length: 64, size: spec.digestSize}

		clear(keyed[:])
	} else {
		keyed := hmacKeys512(hashIV512(hash), &block)

		h.inner = &sha512Engine{state: keyed[0], length: 128, size: spec.digestSize}

		h.outer = &sha512Engine{state: keyed[1], length: 128, size: spec.digestSize}

		clear(keyed[0][:])

		clear(keyed[1][:])
	}

	clear(block[:])

	return h
}

func (a HmacAlgorithm) Verify(key, data, tag []byte) bool {
	defer ditLeave(ditEnter())

	var expected [64]byte

	size := a.DigestSize()

	hmacInto(a.spec().hash, key, data, expected[:size])

	ok := equal(expected[:size], tag)

	clear(expected[:])

	return ok
}

func (a HmacAlgorithm) String() string {
	return a.Name()
}

// HMAC (RFC 2104) with every buffer on the stack, where it is cleared, so that a call allocates
// nothing; the callers hold DIT. The inner and outer key blocks are compressed side by side where
// the CPU can, and the inner and outer hashes are finished without engines.
func hmacInto(hash HashAlgorithm, key, data, out []byte) {
	var block [128]byte

	hmacKey(hash, key, &block)

	if hash.spec().blockSize == 64 {
		keyed := hmacKeys256(hashIV256(hash), &block)

		var inner [32]byte

		sha256Finish([8]uint32(keyed[:8]), 64, data, inner[:len(out)])

		sha256Finish([8]uint32(keyed[8:]), 64, inner[:len(out)], out)

		clear(keyed[:])

		clear(inner[:])
	} else {
		keyed := hmacKeys512(hashIV512(hash), &block)

		var inner [64]byte

		sha512Finish(keyed[0], 128, data, inner[:len(out)])

		sha512Finish(keyed[1], 128, inner[:len(out)], out)

		clear(keyed[0][:])

		clear(keyed[1][:])

		clear(inner[:])
	}

	clear(block[:])
}

// The key padded with zeros to a block, or its hash if it is longer than a block.
func hmacKey(hash HashAlgorithm, key []byte, block *[128]byte) {
	spec := hash.spec()

	if len(key) > spec.blockSize {
		hash.DigestInto(key, block[:spec.digestSize])
	} else {
		copy(block[:], key)
	}
}

// The states after the inner and the outer key block, inner then outer, which sha256Lanes
// compresses side by side.
func hmacKeys256(iv *[8]uint32, block *[128]byte) [16]uint32 {
	var words [32]uint32

	for i := range 16 {
		w := binary.BigEndian.Uint32(block[4*i:])

		words[i], words[16+i] = w^0x36363636, w^0x5c5c5c5c
	}

	var keyed [16]uint32

	sha256Lanes(iv, words[:], 1, keyed[:])

	clear(words[:])

	return keyed
}

func hmacKeys512(iv *[8]uint64, block *[128]byte) [2][8]uint64 {
	var pads [2][128]byte

	for i := range block {
		pads[0][i], pads[1][i] = block[i]^0x36, block[i]^0x5c
	}

	keyed := [2][8]uint64{*iv, *iv}

	compress512(&keyed[0], pads[0][:])

	compress512(&keyed[1], pads[1][:])

	clear(pads[0][:])

	clear(pads[1][:])

	return keyed
}

func hashIV256(hash HashAlgorithm) *[8]uint32 {
	if hash == SHA_224 {
		return &iv224
	}

	return &iv256
}

func hashIV512(hash HashAlgorithm) *[8]uint64 {
	if hash == SHA_384 {
		return &iv384
	}

	return &iv512
}

// Hmac holds the inner engine, which has absorbed the inner key block and the data so far, and the
// outer one, which has absorbed the outer key block only.
type Hmac struct {
	inner engine
	outer engine
	size  int
}

func (h *Hmac) Update(data []byte) {
	defer ditLeave(ditEnter())

	h.inner.update(data)
}

func (h *Hmac) Digest() []byte {
	out := make([]byte, h.size)

	h.DigestInto(out)

	return out
}

func (h *Hmac) DigestInto(out []byte) {
	checkDigestLength(len(out), h.size)

	defer ditLeave(ditEnter())

	h.finish(out)
}

func (h *Hmac) Verify(tag []byte) bool {
	defer ditLeave(ditEnter())

	var expected [64]byte

	h.finish(expected[:h.size])

	ok := equal(expected[:h.size], tag)

	clear(expected[:])

	return ok
}

// The inner hash and the outer key give the output, which may be a key itself.
func (h *Hmac) finish(out []byte) {
	var inner [64]byte

	h.inner.digestInto(inner[:h.size])

	switch outer := h.outer.(type) {
	case *sha256Engine:
		sha256Finish(outer.state, 64, inner[:h.size], out)
	case *sha512Engine:
		sha512Finish(outer.state, 128, inner[:h.size], out)
	}

	clear(inner[:])
}

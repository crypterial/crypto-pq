package cryptopq

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
// Each engine is called directly rather than through a function value, so that it stays on the
// stack together with out.
func (a HashAlgorithm) DigestInto(data, out []byte) {
	checkDigestLength(len(out), a.spec().digestSize)

	switch a {
	case SHA_224:
		sha256DigestInto(&iv224, data, out)
	case SHA_256:
		sha256DigestInto(&iv256, data, out)
	case SHA_384:
		sha512DigestInto(&iv384, data, out)
	case SHA_512:
		sha512DigestInto(&iv512, data, out)
	case SHA_512_224:
		sha512DigestInto(&iv512224, data, out)
	case SHA_512_256:
		sha512DigestInto(&iv512256, data, out)
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
	defer ditLeave(ditEnter())

	hmac := a.Create(key)

	hmac.Update(data)

	return hmac.Digest()
}

func (a HmacAlgorithm) DigestInto(key, data, out []byte) {
	defer ditLeave(ditEnter())

	hmac := a.Create(key)

	hmac.Update(data)

	hmac.DigestInto(out)
}

func (a HmacAlgorithm) Create(key []byte) *Hmac {
	defer ditLeave(ditEnter())

	hash := a.spec().hash.spec()

	pad := make([]byte, hash.blockSize)

	if len(key) > hash.blockSize {
		hashed := hash.create()

		hashed.update(key)

		digest := hashed.digest()

		copy(pad, digest)

		clear(digest)
	} else {
		copy(pad, key)
	}

	for i := range pad {
		pad[i] ^= 0x36
	}

	inner := hash.create()

	inner.update(pad)

	for i := range pad {
		pad[i] ^= 0x36 ^ 0x5c
	}

	outer := hash.create()

	outer.update(pad)

	// Best effort: Go cannot promise that no other copy of the key remains.
	clear(pad)

	return &Hmac{inner: inner, outer: outer, size: hash.digestSize}
}

func (a HmacAlgorithm) Verify(key, data, tag []byte) bool {
	defer ditLeave(ditEnter())

	hmac := a.Create(key)

	hmac.Update(data)

	return hmac.Verify(tag)
}

func (a HmacAlgorithm) String() string {
	return a.Name()
}

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
	defer ditLeave(ditEnter())

	checkDigestLength(len(out), h.size)

	outer := h.outer.clone()

	// The inner hash and the outer key give the output, which may be a key itself.
	inner := h.inner.digest()

	outer.update(inner)

	clear(inner)

	outer.digestInto(out)
}

func (h *Hmac) Verify(tag []byte) bool {
	defer ditLeave(ditEnter())

	return equal(h.Digest(), tag)
}

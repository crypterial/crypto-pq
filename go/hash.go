package cryptopq

type engine interface {
	update(data []byte)
	digest() []byte
	clone() engine
}

type sha3Engine struct {
	sponge keccak
	size   int
}

func newSha3(size int) engine {
	return &sha3Engine{sponge: keccak{rate: 200 - 2*size, suffix: 0x06}, size: size}
}

func sha3Digest(size int, data []byte) []byte {
	e := sha3Engine{sponge: keccak{rate: 200 - 2*size, suffix: 0x06}, size: size}

	e.update(data)

	return e.digest()
}

func (e *sha3Engine) update(data []byte) {
	e.sponge.update(data)
}

func (e *sha3Engine) digest() []byte {
	out := make([]byte, e.size)

	sponge := e.sponge

	sponge.read(out)

	return out
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

// sum is the one-shot digest, on an engine that stays on the stack rather than behind a Hasher.
type hashSpec struct {
	name       string
	digestSize int
	blockSize  int
	create     func() engine
	sum        func([]byte) []byte
}

var hashSpecs = [...]hashSpec{
	SHA_224:     {"SHA-224", 28, 64, func() engine { return newSha256(&iv224, 28) }, func(data []byte) []byte { return sha256Digest(&iv224, 28, data) }},
	SHA_256:     {"SHA-256", 32, 64, func() engine { return newSha256(&iv256, 32) }, func(data []byte) []byte { return sha256Digest(&iv256, 32, data) }},
	SHA_384:     {"SHA-384", 48, 128, func() engine { return newSha512(&iv384, 48) }, func(data []byte) []byte { return sha512Digest(&iv384, 48, data) }},
	SHA_512:     {"SHA-512", 64, 128, func() engine { return newSha512(&iv512, 64) }, func(data []byte) []byte { return sha512Digest(&iv512, 64, data) }},
	SHA_512_224: {"SHA-512/224", 28, 128, func() engine { return newSha512(&iv512224, 28) }, func(data []byte) []byte { return sha512Digest(&iv512224, 28, data) }},
	SHA_512_256: {"SHA-512/256", 32, 128, func() engine { return newSha512(&iv512256, 32) }, func(data []byte) []byte { return sha512Digest(&iv512256, 32, data) }},
	SHA3_224:    {"SHA3-224", 28, 144, func() engine { return newSha3(28) }, func(data []byte) []byte { return sha3Digest(28, data) }},
	SHA3_256:    {"SHA3-256", 32, 136, func() engine { return newSha3(32) }, func(data []byte) []byte { return sha3Digest(32, data) }},
	SHA3_384:    {"SHA3-384", 48, 104, func() engine { return newSha3(48) }, func(data []byte) []byte { return sha3Digest(48, data) }},
	SHA3_512:    {"SHA3-512", 64, 72, func() engine { return newSha3(64) }, func(data []byte) []byte { return sha3Digest(64, data) }},
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
	return a.spec().sum(data)
}

func (a HashAlgorithm) Create() *Hasher {
	return &Hasher{engine: a.spec().create()}
}

func (a HashAlgorithm) String() string {
	return a.Name()
}

type Hasher struct {
	engine engine
}

func (h *Hasher) Update(data []byte) {
	h.engine.update(data)
}

func (h *Hasher) Digest() []byte {
	return h.engine.digest()
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
	hmac := a.Create(key)

	hmac.Update(data)

	return hmac.Digest()
}

func (a HmacAlgorithm) Create(key []byte) *Hmac {
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

	return &Hmac{inner: inner, outer: outer}
}

func (a HmacAlgorithm) Verify(key, data, tag []byte) bool {
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
}

func (h *Hmac) Update(data []byte) {
	h.inner.update(data)
}

func (h *Hmac) Digest() []byte {
	outer := h.outer.clone()

	outer.update(h.inner.digest())

	return outer.digest()
}

func (h *Hmac) Verify(tag []byte) bool {
	return equal(h.Digest(), tag)
}

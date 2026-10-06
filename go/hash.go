package cryptopq

import (
	"encoding/binary"
	"strconv"
)

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

// HashAlgorithm names a hash function. A BLAKE2 hash also carries the salt and personalization
// that Configure gave it, as the parameter-block words they fill (zero by default), so that a
// configured value needs no heap and keeps no reference to the caller's buffers.
type HashAlgorithm struct {
	id     uint8
	params [4]uint64
}

const (
	hashSHA224 = iota + 1
	hashSHA256
	hashSHA384
	hashSHA512
	hashSHA512_224
	hashSHA512_256
	hashSHA3_224
	hashSHA3_256
	hashSHA3_384
	hashSHA3_512
	hashBLAKE2b160
	hashBLAKE2b256
	hashBLAKE2b384
	hashBLAKE2b512
	hashBLAKE2s128
	hashBLAKE2s160
	hashBLAKE2s224
	hashBLAKE2s256
	hashAsconHash256
)

var (
	SHA_224       = HashAlgorithm{id: hashSHA224}
	SHA_256       = HashAlgorithm{id: hashSHA256}
	SHA_384       = HashAlgorithm{id: hashSHA384}
	SHA_512       = HashAlgorithm{id: hashSHA512}
	SHA_512_224   = HashAlgorithm{id: hashSHA512_224}
	SHA_512_256   = HashAlgorithm{id: hashSHA512_256}
	SHA3_224      = HashAlgorithm{id: hashSHA3_224}
	SHA3_256      = HashAlgorithm{id: hashSHA3_256}
	SHA3_384      = HashAlgorithm{id: hashSHA3_384}
	SHA3_512      = HashAlgorithm{id: hashSHA3_512}
	BLAKE2B_160   = HashAlgorithm{id: hashBLAKE2b160}
	BLAKE2B_256   = HashAlgorithm{id: hashBLAKE2b256}
	BLAKE2B_384   = HashAlgorithm{id: hashBLAKE2b384}
	BLAKE2B_512   = HashAlgorithm{id: hashBLAKE2b512}
	BLAKE2S_128   = HashAlgorithm{id: hashBLAKE2s128}
	BLAKE2S_160   = HashAlgorithm{id: hashBLAKE2s160}
	BLAKE2S_224   = HashAlgorithm{id: hashBLAKE2s224}
	BLAKE2S_256   = HashAlgorithm{id: hashBLAKE2s256}
	ASCON_HASH256 = HashAlgorithm{id: hashAsconHash256}
)

// HashOptions configures a BLAKE2 hash: a salt and a personalization of at most 16 bytes for
// BLAKE2b and 8 for BLAKE2s, shorter ones zero-padded as the BLAKE2 specification says. The other
// hashes take no options.
type HashOptions struct {
	Salt            []byte
	Personalization []byte
}

// field is the size of a BLAKE2 salt or personalization, 0 for the hashes without them.
type hashSpec struct {
	name       string
	digestSize int
	blockSize  int
	field      int
	create     func(params [4]uint64, size int) engine
}

func newBlake2bHash(params [4]uint64, size int) engine {
	return newBlake2b(&params, size, nil)
}

func newBlake2sHash(params [4]uint64, size int) engine {
	return newBlake2s(&params, size, nil)
}

var hashSpecs = [...]hashSpec{
	hashSHA224:       {"SHA-224", 28, 64, 0, func([4]uint64, int) engine { return newSha256(&iv224, 28) }},
	hashSHA256:       {"SHA-256", 32, 64, 0, func([4]uint64, int) engine { return newSha256(&iv256, 32) }},
	hashSHA384:       {"SHA-384", 48, 128, 0, func([4]uint64, int) engine { return newSha512(&iv384, 48) }},
	hashSHA512:       {"SHA-512", 64, 128, 0, func([4]uint64, int) engine { return newSha512(&iv512, 64) }},
	hashSHA512_224:   {"SHA-512/224", 28, 128, 0, func([4]uint64, int) engine { return newSha512(&iv512224, 28) }},
	hashSHA512_256:   {"SHA-512/256", 32, 128, 0, func([4]uint64, int) engine { return newSha512(&iv512256, 32) }},
	hashSHA3_224:     {"SHA3-224", 28, 144, 0, func([4]uint64, int) engine { return newSha3(28) }},
	hashSHA3_256:     {"SHA3-256", 32, 136, 0, func([4]uint64, int) engine { return newSha3(32) }},
	hashSHA3_384:     {"SHA3-384", 48, 104, 0, func([4]uint64, int) engine { return newSha3(48) }},
	hashSHA3_512:     {"SHA3-512", 64, 72, 0, func([4]uint64, int) engine { return newSha3(64) }},
	hashBLAKE2b160:   {"BLAKE2b-160", 20, 128, 16, newBlake2bHash},
	hashBLAKE2b256:   {"BLAKE2b-256", 32, 128, 16, newBlake2bHash},
	hashBLAKE2b384:   {"BLAKE2b-384", 48, 128, 16, newBlake2bHash},
	hashBLAKE2b512:   {"BLAKE2b-512", 64, 128, 16, newBlake2bHash},
	hashBLAKE2s128:   {"BLAKE2s-128", 16, 64, 8, newBlake2sHash},
	hashBLAKE2s160:   {"BLAKE2s-160", 20, 64, 8, newBlake2sHash},
	hashBLAKE2s224:   {"BLAKE2s-224", 28, 64, 8, newBlake2sHash},
	hashBLAKE2s256:   {"BLAKE2s-256", 32, 64, 8, newBlake2sHash},
	hashAsconHash256: {"Ascon-Hash256", 32, 8, 0, func([4]uint64, int) engine { return &asconHashEngine{sponge: asconSponge{state: asconHashIV}} }},
}

func hashSpecOf(id uint8) *hashSpec {
	if id == 0 || int(id) >= len(hashSpecs) {
		panic("cryptopq: invalid HashAlgorithm")
	}

	return &hashSpecs[id]
}

func (a HashAlgorithm) Name() string {
	return hashSpecOf(a.id).name
}

func (a HashAlgorithm) DigestSize() int {
	return hashSpecOf(a.id).digestSize
}

// Configure returns the algorithm with the options applied, or INVALID_OPTION; nil options leave
// it as it is.
func (a HashAlgorithm) Configure(options *HashOptions) (HashAlgorithm, error) {
	spec := hashSpecOf(a.id)

	if options == nil {
		return a, nil
	}

	if len(options.Salt) > spec.field || len(options.Personalization) > spec.field {
		if spec.field == 0 {
			return HashAlgorithm{}, invalidOption(spec.name + " takes no salt or personalization")
		}

		return HashAlgorithm{}, invalidOption(spec.name + " takes a salt and a personalization of at most " + strconv.Itoa(spec.field) + " bytes")
	}

	configured := HashAlgorithm{id: a.id}

	if spec.field > 0 {
		configured.params = blake2Params(options.Salt, options.Personalization, spec.field)
	}

	return configured, nil
}

func (a HashAlgorithm) Digest(data []byte) []byte {
	out := make([]byte, hashSpecOf(a.id).digestSize)

	a.DigestInto(data, out)

	return out
}

// DigestInto writes the digest into out, which must be DigestSize bytes long, without allocating.
// Each hash is called directly rather than through a function value, so that its buffers stay on
// the stack together with out.
func (a HashAlgorithm) DigestInto(data, out []byte) {
	checkDigestLength(len(out), hashSpecOf(a.id).digestSize)

	switch a.id {
	case hashSHA224:
		sha256Finish(iv224, 0, data, out)
	case hashSHA256:
		sha256Finish(iv256, 0, data, out)
	case hashSHA384:
		sha512Finish(iv384, 0, data, out)
	case hashSHA512:
		sha512Finish(iv512, 0, data, out)
	case hashSHA512_224:
		sha512Finish(iv512224, 0, data, out)
	case hashSHA512_256:
		sha512Finish(iv512256, 0, data, out)
	case hashBLAKE2b160, hashBLAKE2b256, hashBLAKE2b384, hashBLAKE2b512:
		blake2bSum(&a.params, nil, data, out)
	case hashBLAKE2s128, hashBLAKE2s160, hashBLAKE2s224, hashBLAKE2s256:
		blake2sSum(&a.params, nil, data, out)
	case hashAsconHash256:
		asconSum(asconHashIV, data, out)
	default:
		sha3DigestInto(data, out)
	}
}

func (a HashAlgorithm) Create() *Hasher {
	spec := hashSpecOf(a.id)

	return &Hasher{engine: spec.create(a.params, spec.digestSize), size: spec.digestSize}
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

// XofAlgorithm names an extendable-output function. A configured cSHAKE carries the Keccak state
// after its customization block, and Ascon-XOF128 and Ascon-CXOF128 their state after the IV (and
// the customization) in the first five words, so that this part is absorbed once, not per call.
type XofAlgorithm struct {
	id         uint8
	customized bool
	state      [25]uint64
}

const (
	xofSHAKE128 = iota + 1
	xofSHAKE256
	xofCSHAKE128
	xofCSHAKE256
	xofAsconXOF128
	xofAsconCXOF128
)

var (
	SHAKE128      = XofAlgorithm{id: xofSHAKE128}
	SHAKE256      = XofAlgorithm{id: xofSHAKE256}
	CSHAKE128     = XofAlgorithm{id: xofCSHAKE128}
	CSHAKE256     = XofAlgorithm{id: xofCSHAKE256}
	ASCON_XOF128  = XofAlgorithm{id: xofAsconXOF128, state: asconStateWords(asconXofIV)}
	ASCON_CXOF128 = asconCustomized(nil)
)

// XofOptions configures cSHAKE and Ascon-CXOF128 with a customization string, which is at most 256
// bytes for Ascon-CXOF128. SHAKE and Ascon-XOF128 take none.
type XofOptions struct {
	Customization []byte
}

// rate is the Keccak rate in bytes, 0 for Ascon.
type xofSpec struct {
	name string
	rate int
}

var xofSpecs = [...]xofSpec{
	xofSHAKE128:     {"SHAKE128", 168},
	xofSHAKE256:     {"SHAKE256", 136},
	xofCSHAKE128:    {"cSHAKE128", 168},
	xofCSHAKE256:    {"cSHAKE256", 136},
	xofAsconXOF128:  {"Ascon-XOF128", 0},
	xofAsconCXOF128: {"Ascon-CXOF128", 0},
}

func xofSpecOf(id uint8) *xofSpec {
	if id == 0 || int(id) >= len(xofSpecs) {
		panic("cryptopq: invalid XofAlgorithm")
	}

	return &xofSpecs[id]
}

func (a XofAlgorithm) Name() string {
	return xofSpecOf(a.id).name
}

// Configure returns the algorithm with the options applied, or INVALID_OPTION; nil options leave
// it as it is. cSHAKE without a customization is SHAKE, as SP 800-185 defines it.
func (a XofAlgorithm) Configure(options *XofOptions) (XofAlgorithm, error) {
	spec := xofSpecOf(a.id)

	if options == nil {
		return a, nil
	}

	switch a.id {
	case xofCSHAKE128, xofCSHAKE256:
		return cshakeAlgorithm(a.id, nil, options.Customization), nil
	case xofAsconCXOF128:
		if len(options.Customization) > asconCustomizationLimit {
			return XofAlgorithm{}, invalidOption("the Ascon-CXOF128 customization is at most 256 bytes")
		}

		return asconCustomized(options.Customization), nil
	}

	if len(options.Customization) > 0 {
		return XofAlgorithm{}, invalidOption(spec.name + " takes no customization")
	}

	return a, nil
}

// The domain bits of the padding: SHAKE's 1111, or cSHAKE's 00 after a customization.
func (a *XofAlgorithm) suffix() byte {
	if a.customized {
		return 0x04
	}

	return 0x1f
}

func (a XofAlgorithm) Digest(data []byte, length int) []byte {
	if length < 0 {
		panic("cryptopq: INVALID_LENGTH: length must not be negative")
	}

	out := make([]byte, length)

	a.digestInto(data, out)

	return out
}

// DigestInto fills out with output, without allocating.
func (a XofAlgorithm) DigestInto(data, out []byte) {
	a.digestInto(data, out)
}

// The receiver is a copy, so the configured state becomes the working state in place.
func (a *XofAlgorithm) digestInto(data, out []byte) {
	spec := xofSpecOf(a.id)

	if spec.rate == 0 {
		asconXof((*[5]uint64)(a.state[:5]), data, out)

		return
	}

	keccakXof(&a.state, spec.rate, a.suffix(), data, out)
}

func (a XofAlgorithm) Create() *Xof {
	spec := xofSpecOf(a.id)

	if spec.rate == 0 {
		return &Xof{ascon: true, asconSponge: asconSponge{state: [5]uint64(a.state[:5])}}
	}

	return &Xof{sponge: keccak{state: a.state, rate: spec.rate, suffix: a.suffix()}}
}

func (a XofAlgorithm) String() string {
	return a.Name()
}

type Xof struct {
	sponge      keccak
	asconSponge asconSponge
	ascon       bool
}

func (x *Xof) Update(data []byte) {
	if x.ascon {
		x.asconSponge.update(data)

		return
	}

	x.sponge.update(data)
}

func (x *Xof) Read(length int) []byte {
	if length < 0 {
		panic("cryptopq: INVALID_LENGTH: length must not be negative")
	}

	out := make([]byte, length)

	x.ReadInto(out)

	return out
}

func (x *Xof) ReadInto(out []byte) {
	if x.ascon {
		x.asconSponge.read(out)

		return
	}

	x.sponge.read(out)
}

// The salt and personalization, each zero-padded to field bytes, as the little-endian words they
// fill in the parameter block: words 4-7 of BLAKE2b, or words 4-7 of BLAKE2s packed two by two.
func blake2Params(salt, personalization []byte, field int) [4]uint64 {
	var block [32]byte

	copy(block[:field], salt)

	copy(block[field:2*field], personalization)

	var params [4]uint64

	for i := range 2 * field / 8 {
		params[i] = binary.LittleEndian.Uint64(block[8*i:])
	}

	return params
}

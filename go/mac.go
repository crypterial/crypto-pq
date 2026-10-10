package cryptopq

import (
	"encoding/binary"
	"runtime"
	"strconv"
)

// MacAlgorithm names a keyed function: HMAC, KMAC or keyed BLAKE2. A configured KMAC carries its
// output length, the XOF flag and the cSHAKE state after the bytepad("KMAC", customization) block;
// a configured BLAKE2 MAC its output length and its salt and personalization words in state[0:4].
type MacAlgorithm struct {
	id     uint8
	xof    bool
	length int
	state  [25]uint64
}

const (
	macHMACSHA224 = iota + 1
	macHMACSHA256
	macHMACSHA384
	macHMACSHA512
	macKMAC128
	macKMAC256
	macBLAKE2b
	macBLAKE2s
)

var kmacName = []byte("KMAC")

var (
	HMAC_SHA_224 = MacAlgorithm{id: macHMACSHA224, length: 28}
	HMAC_SHA_256 = MacAlgorithm{id: macHMACSHA256, length: 32}
	HMAC_SHA_384 = MacAlgorithm{id: macHMACSHA384, length: 48}
	HMAC_SHA_512 = MacAlgorithm{id: macHMACSHA512, length: 64}
	KMAC128      = MacAlgorithm{id: macKMAC128, length: 32, state: cshakeState(168, kmacName, nil)}
	KMAC256      = MacAlgorithm{id: macKMAC256, length: 64, state: cshakeState(136, kmacName, nil)}
	BLAKE2B_MAC  = MacAlgorithm{id: macBLAKE2b, length: 64}
	BLAKE2S_MAC  = MacAlgorithm{id: macBLAKE2s, length: 32}
)

// MacOptions configures KMAC and keyed BLAKE2. Length is the output length in bytes, 0 for the
// default: at least 4 for KMAC (32 for KMAC128 and 64 for KMAC256 by default), 1 to 64 for BLAKE2b
// and 1 to 32 for BLAKE2s (their full size by default). KMAC takes a Customization, and Xof selects
// KMACXOF, which encodes the length as 0 but still returns Length bytes; BLAKE2 takes a Salt and a
// Personalization as HashOptions does. HMAC takes no options.
type MacOptions struct {
	Length          int
	Customization   []byte
	Xof             bool
	Salt            []byte
	Personalization []byte
}

const (
	macKindHMAC = iota
	macKindKMAC
	macKindBLAKE2
)

// rate is KMAC's Keccak rate; field and maximum are a BLAKE2 MAC's salt and key size.
type macSpec struct {
	name    string
	kind    int
	hash    HashAlgorithm
	rate    int
	field   int
	maximum int
}

var macSpecs = [...]macSpec{
	macHMACSHA224: {name: "HMAC-SHA-224", hash: SHA_224},
	macHMACSHA256: {name: "HMAC-SHA-256", hash: SHA_256},
	macHMACSHA384: {name: "HMAC-SHA-384", hash: SHA_384},
	macHMACSHA512: {name: "HMAC-SHA-512", hash: SHA_512},
	macKMAC128:    {name: "KMAC128", kind: macKindKMAC, rate: 168},
	macKMAC256:    {name: "KMAC256", kind: macKindKMAC, rate: 136},
	macBLAKE2b:    {name: "BLAKE2b-MAC", kind: macKindBLAKE2, field: 16, maximum: 64},
	macBLAKE2s:    {name: "BLAKE2s-MAC", kind: macKindBLAKE2, field: 8, maximum: 32},
}

func macSpecOf(id uint8) *macSpec {
	if id == 0 || int(id) >= len(macSpecs) {
		panic("cryptopq: invalid MacAlgorithm")
	}

	return &macSpecs[id]
}

func (a MacAlgorithm) Name() string {
	return macSpecOf(a.id).name
}

func (a MacAlgorithm) DigestSize() int {
	macSpecOf(a.id)

	return a.length
}

// KMAC encodes the output length in bits, which must fit in 64 bits here.
const kmacLengthLimit = 1 << 61

// Configure returns the algorithm with the options applied, or INVALID_OPTION; nil options leave
// it as it is.
func (a MacAlgorithm) Configure(options *MacOptions) (MacAlgorithm, error) {
	spec := macSpecOf(a.id)

	if options == nil {
		return a, nil
	}

	salted := len(options.Salt) > 0 || len(options.Personalization) > 0

	switch spec.kind {
	case macKindKMAC:
		if salted {
			return MacAlgorithm{}, invalidOption("KMAC takes no salt or personalization")
		}

		length := 64

		if a.id == macKMAC128 {
			length = 32
		}

		if options.Length != 0 {
			if options.Length < 4 || uint64(options.Length) >= kmacLengthLimit {
				return MacAlgorithm{}, invalidOption("the KMAC output is at least 4 bytes")
			}

			length = options.Length
		}

		return MacAlgorithm{id: a.id, xof: options.Xof, length: length, state: cshakeState(spec.rate, kmacName, options.Customization)}, nil
	case macKindBLAKE2:
		if len(options.Customization) > 0 || options.Xof {
			return MacAlgorithm{}, invalidOption(spec.name + " takes no customization or XOF mode")
		}

		if options.Length < 0 || options.Length > spec.maximum {
			return MacAlgorithm{}, invalidOption(spec.name + " outputs 1 to " + strconv.Itoa(spec.maximum) + " bytes")
		}

		if len(options.Salt) > spec.field || len(options.Personalization) > spec.field {
			return MacAlgorithm{}, invalidOption(spec.name + " takes a salt and a personalization of at most " + strconv.Itoa(spec.field) + " bytes")
		}

		configured := MacAlgorithm{id: a.id, length: spec.maximum}

		if options.Length != 0 {
			configured.length = options.Length
		}

		params := blake2Params(options.Salt, options.Personalization, spec.field)

		copy(configured.state[:4], params[:])

		return configured, nil
	}

	if options.Length != 0 || len(options.Customization) > 0 || options.Xof || salted {
		return MacAlgorithm{}, invalidOption(spec.name + " takes no options")
	}

	return a, nil
}

// A BLAKE2 key outside 1 to the hash size is a programming error, as an output buffer of the wrong
// length is.
func checkBlake2Key(spec *macSpec, key []byte) {
	if len(key) == 0 || len(key) > spec.maximum {
		panic("cryptopq: INVALID_LENGTH: a " + spec.name + " key is 1 to " + strconv.Itoa(spec.maximum) + " bytes")
	}
}

func (a MacAlgorithm) Digest(key, data []byte) []byte {
	macSpecOf(a.id)

	out := make([]byte, a.length)

	a.digestInto(key, data, out)

	return out
}

// DigestInto writes the tag into out, which must be DigestSize bytes long, without allocating.
func (a MacAlgorithm) DigestInto(key, data, out []byte) {
	a.digestInto(key, data, out)
}

// The receiver is a copy, so KMAC absorbs into its state in place; the keyed DIT bracket is held
// around everything done with the key.
func (a *MacAlgorithm) digestInto(key, data, out []byte) {
	spec := macSpecOf(a.id)

	checkDigestLength(len(out), a.length)

	if spec.kind == macKindBLAKE2 {
		checkBlake2Key(spec, key)
	}

	if keyedDit() {
		defer ditLeave(ditEnter())
	}

	switch spec.kind {
	case macKindHMAC:
		hmacInto(spec.hash, key, data, out)
	case macKindKMAC:
		kmacSum(&a.state, spec.rate, key, data, out, a.xof)
	default:
		blake2MacSum(spec, a, key, data, out)
	}
}

func blake2MacSum(spec *macSpec, a *MacAlgorithm, key, data, out []byte) {
	params := (*[4]uint64)(a.state[:4])

	if spec.field == 16 {
		blake2bSum(params, key, data, out)
	} else {
		blake2sSum(params, key, data, out)
	}
}

func (a MacAlgorithm) Create(key []byte) *Mac {
	spec := macSpecOf(a.id)

	if spec.kind == macKindBLAKE2 {
		checkBlake2Key(spec, key)
	}

	if keyedDit() {
		defer ditLeave(ditEnter())
	}

	switch spec.kind {
	case macKindHMAC:
		return newMac(newHmacEngine(spec.hash, key), a.length)
	case macKindKMAC:
		e := &kmacEngine{sponge: keccak{state: a.state, rate: spec.rate, suffix: 0x04}, length: a.length, xof: a.xof}

		kmacAbsorbKey(&e.sponge, key)

		return newMac(e, a.length)
	}

	params := (*[4]uint64)(a.state[:4])

	if spec.field == 16 {
		e := &blake2bMac{}

		e.init(params, a.length, key)

		return newMac(e, a.length)
	}

	e := &blake2sMac{}

	e.init(params, a.length, key)

	return newMac(e, a.length)
}

// Verify reports in constant time whether tag is the full-length tag of data under key.
func (a MacAlgorithm) Verify(key, data, tag []byte) bool {
	spec := macSpecOf(a.id)

	if spec.kind == macKindBLAKE2 {
		checkBlake2Key(spec, key)
	}

	if keyedDit() {
		defer ditLeave(ditEnter())
	}

	if spec.kind == macKindKMAC {
		if len(tag) != a.length {
			return false
		}

		return kmacVerify(&a.state, spec.rate, key, data, tag, a.xof)
	}

	var expected [64]byte

	switch spec.kind {
	case macKindHMAC:
		hmacInto(spec.hash, key, data, expected[:a.length])
	default:
		blake2MacSum(spec, &a, key, data, expected[:a.length])
	}

	ok := equal(expected[:a.length], tag)

	clear(expected[:])

	return ok
}

func (a MacAlgorithm) String() string {
	return a.Name()
}

// HMAC (RFC 2104) with every buffer on the stack, where it is cleared, so that a call allocates
// nothing; the callers decide on DIT. The inner and outer key blocks are compressed side by side
// where the CPU can, and the inner and outer hashes are finished without engines.
func hmacInto(hash HashAlgorithm, key, data, out []byte) {
	var block [128]byte

	hmacKey(hash, key, &block)

	if hashSpecOf(hash.id).blockSize == 64 {
		keyed := hmacKeys256(hashIV256(hash), &block)

		var inner [32]byte

		sha256FinishSecret([8]uint32(keyed[:8]), 64, data, inner[:len(out)])

		sha256FinishSecret([8]uint32(keyed[8:]), 64, inner[:len(out)], out)

		clear(keyed[:])

		clear(inner[:])
	} else {
		keyed := hmacKeys512(hashIV512(hash), &block)

		var inner [64]byte

		sha512FinishSecret(keyed[0], 128, data, inner[:len(out)])

		sha512FinishSecret(keyed[1], 128, inner[:len(out)], out)

		clear(keyed[0][:])

		clear(keyed[1][:])

		clear(inner[:])
	}

	clear(block[:])
}

// The key padded with zeros to a block, or its hash if it is longer than a block.
func hmacKey(hash HashAlgorithm, key []byte, block *[128]byte) {
	spec := hashSpecOf(hash.id)

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
	if hash.id == hashSHA224 {
		return &iv224
	}

	return &iv256
}

func hashIV512(hash HashAlgorithm) *[8]uint64 {
	if hash.id == hashSHA384 {
		return &iv384
	}

	return &iv512
}

// Mac is a keyed function in progress; its state derives from the key.
type Mac struct {
	engine macEngine
	size   int
}

// finish writes the tag without changing the state; verify compares the full-length tag in
// constant time; wipe clears the keyed state.
type macEngine interface {
	update(data []byte)
	finish(out []byte)
	verify(tag []byte) bool
	wipe()
}

// Go has no destructors, so the keyed state is cleared once the Mac becomes unreachable.
func newMac(e macEngine, size int) *Mac {
	m := &Mac{engine: e, size: size}

	runtime.AddCleanup(m, func(e macEngine) { e.wipe() }, e)

	return m
}

func (m *Mac) Update(data []byte) {
	if keyedDit() {
		defer ditLeave(ditEnter())
	}

	m.engine.update(data)
}

func (m *Mac) Digest() []byte {
	out := make([]byte, m.size)

	m.DigestInto(out)

	return out
}

func (m *Mac) DigestInto(out []byte) {
	checkDigestLength(len(out), m.size)

	if keyedDit() {
		defer ditLeave(ditEnter())
	}

	m.engine.finish(out)
}

func (m *Mac) Verify(tag []byte) bool {
	if keyedDit() {
		defer ditLeave(ditEnter())
	}

	return m.engine.verify(tag)
}

// A tag of at most 64 bytes compared through a stack buffer, which is cleared.
func verifyFinished(e macEngine, size int, tag []byte) bool {
	var expected [64]byte

	e.finish(expected[:size])

	ok := equal(expected[:size], tag)

	clear(expected[:])

	return ok
}

// hmacEngine holds the inner engine, which has absorbed the inner key block and the data so far,
// and the outer one, which has absorbed the outer key block only.
type hmacEngine struct {
	inner engine
	outer engine
	size  int
}

func newHmacEngine(hash HashAlgorithm, key []byte) *hmacEngine {
	spec := hashSpecOf(hash.id)

	var block [128]byte

	hmacKey(hash, key, &block)

	e := &hmacEngine{size: spec.digestSize}

	if spec.blockSize == 64 {
		keyed := hmacKeys256(hashIV256(hash), &block)

		e.inner = &sha256Engine{state: [8]uint32(keyed[:8]), length: 64, size: spec.digestSize}

		e.outer = &sha256Engine{state: [8]uint32(keyed[8:]), length: 64, size: spec.digestSize}

		clear(keyed[:])
	} else {
		keyed := hmacKeys512(hashIV512(hash), &block)

		e.inner = &sha512Engine{state: keyed[0], length: 128, size: spec.digestSize}

		e.outer = &sha512Engine{state: keyed[1], length: 128, size: spec.digestSize}

		clear(keyed[0][:])

		clear(keyed[1][:])
	}

	clear(block[:])

	return e
}

func (e *hmacEngine) update(data []byte) {
	e.inner.update(data)
}

// The inner hash and the outer key give the output, which may be a key itself.
func (e *hmacEngine) finish(out []byte) {
	var inner [64]byte

	e.inner.digestInto(inner[:e.size])

	switch outer := e.outer.(type) {
	case *sha256Engine:
		sha256FinishSecret(outer.state, 64, inner[:e.size], out)
	case *sha512Engine:
		sha512FinishSecret(outer.state, 128, inner[:e.size], out)
	}

	clear(inner[:])
}

func (e *hmacEngine) verify(tag []byte) bool {
	return verifyFinished(e, e.size, tag)
}

func (e *hmacEngine) wipe() {
	for _, half := range []engine{e.inner, e.outer} {
		switch h := half.(type) {
		case *sha256Engine:
			clear(h.state[:])

			clear(h.buffer[:])
		case *sha512Engine:
			clear(h.state[:])

			clear(h.buffer[:])
		}
	}
}

// kmacEngine holds the sponge after the key block and the data so far.
type kmacEngine struct {
	sponge keccak
	length int
	xof    bool
}

func (e *kmacEngine) update(data []byte) {
	e.sponge.update(data)
}

func (e *kmacEngine) finish(out []byte) {
	sponge := e.sponge

	kmacFinish(&sponge, len(out), e.xof)

	sponge.read(out)

	clear(sponge.state[:])
}

func (e *kmacEngine) verify(tag []byte) bool {
	if len(tag) != e.length {
		return false
	}

	sponge := e.sponge

	kmacFinish(&sponge, e.length, e.xof)

	ok := squeezeEqual(&sponge, tag)

	clear(sponge.state[:])

	return ok
}

func (e *kmacEngine) wipe() {
	clear(e.sponge.state[:])
}

type blake2bMac struct {
	blake2bEngine
}

func (e *blake2bMac) finish(out []byte) {
	e.digestInto(out)
}

func (e *blake2bMac) verify(tag []byte) bool {
	return verifyFinished(e, e.size, tag)
}

func (e *blake2bMac) wipe() {
	clear(e.h[:])

	clear(e.buffer[:])
}

type blake2sMac struct {
	blake2sEngine
}

func (e *blake2sMac) finish(out []byte) {
	e.digestInto(out)
}

func (e *blake2sMac) verify(tag []byte) bool {
	return verifyFinished(e, e.size, tag)
}

func (e *blake2sMac) wipe() {
	clear(e.h[:])

	clear(e.buffer[:])
}

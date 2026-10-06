package cryptopq

import (
	"encoding/binary"
	"math/bits"
)

// Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 (NIST SP 800-232). The state words S0-S4 load
// and store bytes little-endian; the rate is S0.

// The states after Ascon-p[12] of the IV and 256 zero bits (SP 800-232, Appendix A.3).
var (
	asconHashIV = [5]uint64{0x9b1e5494e934d681, 0x4bc3a01e333751d2, 0xae65396c6b34b81a, 0x3c7fd4a4d56a4db3, 0x1a5c464906c5976d}
	asconXofIV  = [5]uint64{0xda82ce768d9447eb, 0xcc7ce6c75f1ef969, 0xe7508fd780085631, 0x0ee0ea53416b58cc, 0xe0547524db6f0bde}
	asconCxofIV = [5]uint64{0x675527c2a0e8de03, 0x43d12d7dc0377bbc, 0xe9901dec426e81b5, 0x2ab14907720780b6, 0x8f3f1d02d432bc46}
)

// SP 800-232 limits the Ascon-CXOF128 customization string to 2048 bits.
const asconCustomizationLimit = 256

// One round of Ascon-p: the constant, the substitution layer (the bitsliced 5-bit S-box) and the
// linear layer, where x ^ (x >>> a) ^ (x >>> b) is computed as x ^ ((x ^ (x >>> (b - a))) >>> a).
func asconRound(x0, x1, x2, x3, x4, c uint64) (uint64, uint64, uint64, uint64, uint64) {
	x2 ^= c

	x0 ^= x4

	x4 ^= x3

	x2 ^= x1

	t0, t1, t2, t3, t4 := x0^(x2&^x1), x1^(x3&^x2), x2^(x4&^x3), x3^(x0&^x4), x4^(x1&^x0)

	t1 ^= t0

	t0 ^= t4

	t3 ^= t2

	t2 = ^t2

	x0 = t0 ^ bits.RotateLeft64(t0^bits.RotateLeft64(t0, -9), -19)

	x1 = t1 ^ bits.RotateLeft64(t1^bits.RotateLeft64(t1, -22), -39)

	x2 = t2 ^ bits.RotateLeft64(t2^bits.RotateLeft64(t2, -5), -1)

	x3 = t3 ^ bits.RotateLeft64(t3^bits.RotateLeft64(t3, -7), -10)

	x4 = t4 ^ bits.RotateLeft64(t4^bits.RotateLeft64(t4, -34), -7)

	return x0, x1, x2, x3, x4
}

// Ascon-p[12], the round constants 0xf0, 0xe1, ..., 0x4b as immediates. This is the portable form
// of asconPermute.
func asconPermuteGeneric(s *[5]uint64) {
	x0, x1, x2, x3, x4 := s[0], s[1], s[2], s[3], s[4]

	x0, x1, x2, x3, x4 = asconRound(x0, x1, x2, x3, x4, 0xf0)

	x0, x1, x2, x3, x4 = asconRound(x0, x1, x2, x3, x4, 0xe1)

	x0, x1, x2, x3, x4 = asconRound(x0, x1, x2, x3, x4, 0xd2)

	x0, x1, x2, x3, x4 = asconRound(x0, x1, x2, x3, x4, 0xc3)

	x0, x1, x2, x3, x4 = asconRound(x0, x1, x2, x3, x4, 0xb4)

	x0, x1, x2, x3, x4 = asconRound(x0, x1, x2, x3, x4, 0xa5)

	x0, x1, x2, x3, x4 = asconRound(x0, x1, x2, x3, x4, 0x96)

	x0, x1, x2, x3, x4 = asconRound(x0, x1, x2, x3, x4, 0x87)

	x0, x1, x2, x3, x4 = asconRound(x0, x1, x2, x3, x4, 0x78)

	x0, x1, x2, x3, x4 = asconRound(x0, x1, x2, x3, x4, 0x69)

	x0, x1, x2, x3, x4 = asconRound(x0, x1, x2, x3, x4, 0x5a)

	x0, x1, x2, x3, x4 = asconRound(x0, x1, x2, x3, x4, 0x4b)

	s[0], s[1], s[2], s[3], s[4] = x0, x1, x2, x3, x4
}

// Each whole 8-byte word of data XORed into S0 and permuted; the portable form of
// asconAbsorbWords.
func asconAbsorbWordsGeneric(s *[5]uint64, data []byte) {
	for ; len(data) >= 8; data = data[8:] {
		s[0] ^= binary.LittleEndian.Uint64(data)

		asconPermuteGeneric(s)
	}
}

// Absorbs data and its padding (a 1 bit after the last byte, then zeros to the end of the word),
// permuting after every word.
func asconAbsorb(s *[5]uint64, data []byte) {
	asconAbsorbWords(s, data)

	data = data[len(data)&^7:]

	var last [8]byte

	copy(last[:], data)

	last[len(data)] = 0x01

	s[0] ^= binary.LittleEndian.Uint64(last[:])

	asconPermute(s)
}

// Writes out from S0, permuting between words.
func asconSqueeze(s *[5]uint64, out []byte) {
	for len(out) >= 8 {
		binary.LittleEndian.PutUint64(out, s[0])

		if out = out[8:]; len(out) > 0 {
			asconPermute(s)
		}
	}

	if len(out) > 0 {
		var last [8]byte

		binary.LittleEndian.PutUint64(last[:], s[0])

		copy(out, last[:])
	}
}

// The hash or XOF of data from the initial state s into out.
func asconSum(s [5]uint64, data, out []byte) {
	asconXof(&s, data, out)
}

func asconXof(s *[5]uint64, data, out []byte) {
	asconAbsorb(s, data)

	asconSqueeze(s, out)
}

func asconStateWords(s [5]uint64) [25]uint64 {
	var words [25]uint64

	copy(words[:], s[:])

	return words
}

// Ascon-CXOF128 after the customization: its bit length as one word, then the string padded.
func asconCustomized(customization []byte) XofAlgorithm {
	s := asconCxofIV

	s[0] ^= 8 * uint64(len(customization))

	asconPermute(&s)

	asconAbsorb(&s, customization)

	return XofAlgorithm{id: xofAsconCXOF128, state: asconStateWords(s)}
}

// asconSponge absorbs whole words as they come and pads at the first read; then used counts the
// bytes of S0 already output.
type asconSponge struct {
	state     [5]uint64
	buffer    [8]byte
	used      int
	squeezing bool
}

func (s *asconSponge) update(data []byte) {
	if s.squeezing {
		panic("cryptopq: UNSUPPORTED: cannot update after read")
	}

	if s.used > 0 {
		n := copy(s.buffer[s.used:], data)

		s.used += n

		data = data[n:]

		if s.used < len(s.buffer) {
			return
		}

		s.state[0] ^= binary.LittleEndian.Uint64(s.buffer[:])

		asconPermute(&s.state)

		s.used = 0
	}

	asconAbsorbWords(&s.state, data)

	s.used = copy(s.buffer[:], data[len(data)&^7:])
}

func (s *asconSponge) read(out []byte) {
	if !s.squeezing {
		clear(s.buffer[s.used:])

		s.buffer[s.used] = 0x01

		s.state[0] ^= binary.LittleEndian.Uint64(s.buffer[:])

		asconPermute(&s.state)

		s.squeezing, s.used = true, 0
	}

	for len(out) > 0 {
		if s.used == 8 {
			asconPermute(&s.state)

			s.used = 0
		}

		binary.LittleEndian.PutUint64(s.buffer[:], s.state[0])

		n := copy(out, s.buffer[s.used:])

		s.used += n

		out = out[n:]
	}
}

type asconHashEngine struct {
	sponge asconSponge
}

func (e *asconHashEngine) update(data []byte) {
	e.sponge.update(data)
}

func (e *asconHashEngine) digest() []byte {
	out := make([]byte, 32)

	e.digestInto(out)

	return out
}

func (e *asconHashEngine) digestInto(out []byte) {
	sponge := e.sponge

	sponge.read(out)
}

func (e *asconHashEngine) clone() engine {
	copied := *e

	return &copied
}

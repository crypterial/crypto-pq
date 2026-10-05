package cryptopq

import (
	"encoding/binary"
	"math/bits"
)

var roundConstants = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// Keccak-f[1600], two rounds per iteration, from the a lanes into the e lanes and back. Lane x + 5y
// is a{x + 5y}; rho and pi move it to y + 5((2x + 3y) mod 5), so each output plane of chi comes from
// five input lanes, which are combined just before the plane is written. The lanes are locals, and
// the compiler decides which to spill: with them in arrays instead, which needs fewer instructions,
// the speed came to depend on where the arrays sat in memory, by up to a fifth on arm64. This is
// the portable form of permute.
func permuteGeneric(s *[25]uint64) {
	a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24 := s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15], s[16], s[17], s[18], s[19], s[20], s[21], s[22], s[23], s[24]

	var e0, e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12, e13, e14, e15, e16, e17, e18, e19, e20, e21, e22, e23, e24 uint64

	for i := 0; i < 24; i += 2 {
		c0, c1, c2, c3, c4 := a0^a5^a10^a15^a20, a1^a6^a11^a16^a21, a2^a7^a12^a17^a22, a3^a8^a13^a18^a23, a4^a9^a14^a19^a24

		d0, d1, d2, d3, d4 := c4^bits.RotateLeft64(c1, 1), c0^bits.RotateLeft64(c2, 1), c1^bits.RotateLeft64(c3, 1), c2^bits.RotateLeft64(c4, 1), c3^bits.RotateLeft64(c0, 1)

		b0, b1, b2, b3, b4 := a0^d0, bits.RotateLeft64(a6^d1, 44), bits.RotateLeft64(a12^d2, 43), bits.RotateLeft64(a18^d3, 21), bits.RotateLeft64(a24^d4, 14)

		e0, e1, e2, e3, e4 = b0^(b2&^b1)^roundConstants[i], b1^(b3&^b2), b2^(b4&^b3), b3^(b0&^b4), b4^(b1&^b0)

		b0, b1, b2, b3, b4 = bits.RotateLeft64(a3^d3, 28), bits.RotateLeft64(a9^d4, 20), bits.RotateLeft64(a10^d0, 3), bits.RotateLeft64(a16^d1, 45), bits.RotateLeft64(a22^d2, 61)

		e5, e6, e7, e8, e9 = b0^(b2&^b1), b1^(b3&^b2), b2^(b4&^b3), b3^(b0&^b4), b4^(b1&^b0)

		b0, b1, b2, b3, b4 = bits.RotateLeft64(a1^d1, 1), bits.RotateLeft64(a7^d2, 6), bits.RotateLeft64(a13^d3, 25), bits.RotateLeft64(a19^d4, 8), bits.RotateLeft64(a20^d0, 18)

		e10, e11, e12, e13, e14 = b0^(b2&^b1), b1^(b3&^b2), b2^(b4&^b3), b3^(b0&^b4), b4^(b1&^b0)

		b0, b1, b2, b3, b4 = bits.RotateLeft64(a4^d4, 27), bits.RotateLeft64(a5^d0, 36), bits.RotateLeft64(a11^d1, 10), bits.RotateLeft64(a17^d2, 15), bits.RotateLeft64(a23^d3, 56)

		e15, e16, e17, e18, e19 = b0^(b2&^b1), b1^(b3&^b2), b2^(b4&^b3), b3^(b0&^b4), b4^(b1&^b0)

		b0, b1, b2, b3, b4 = bits.RotateLeft64(a2^d2, 62), bits.RotateLeft64(a8^d3, 55), bits.RotateLeft64(a14^d4, 39), bits.RotateLeft64(a15^d0, 41), bits.RotateLeft64(a21^d1, 2)

		e20, e21, e22, e23, e24 = b0^(b2&^b1), b1^(b3&^b2), b2^(b4&^b3), b3^(b0&^b4), b4^(b1&^b0)

		c0, c1, c2, c3, c4 = e0^e5^e10^e15^e20, e1^e6^e11^e16^e21, e2^e7^e12^e17^e22, e3^e8^e13^e18^e23, e4^e9^e14^e19^e24

		d0, d1, d2, d3, d4 = c4^bits.RotateLeft64(c1, 1), c0^bits.RotateLeft64(c2, 1), c1^bits.RotateLeft64(c3, 1), c2^bits.RotateLeft64(c4, 1), c3^bits.RotateLeft64(c0, 1)

		b0, b1, b2, b3, b4 = e0^d0, bits.RotateLeft64(e6^d1, 44), bits.RotateLeft64(e12^d2, 43), bits.RotateLeft64(e18^d3, 21), bits.RotateLeft64(e24^d4, 14)

		a0, a1, a2, a3, a4 = b0^(b2&^b1)^roundConstants[i+1], b1^(b3&^b2), b2^(b4&^b3), b3^(b0&^b4), b4^(b1&^b0)

		b0, b1, b2, b3, b4 = bits.RotateLeft64(e3^d3, 28), bits.RotateLeft64(e9^d4, 20), bits.RotateLeft64(e10^d0, 3), bits.RotateLeft64(e16^d1, 45), bits.RotateLeft64(e22^d2, 61)

		a5, a6, a7, a8, a9 = b0^(b2&^b1), b1^(b3&^b2), b2^(b4&^b3), b3^(b0&^b4), b4^(b1&^b0)

		b0, b1, b2, b3, b4 = bits.RotateLeft64(e1^d1, 1), bits.RotateLeft64(e7^d2, 6), bits.RotateLeft64(e13^d3, 25), bits.RotateLeft64(e19^d4, 8), bits.RotateLeft64(e20^d0, 18)

		a10, a11, a12, a13, a14 = b0^(b2&^b1), b1^(b3&^b2), b2^(b4&^b3), b3^(b0&^b4), b4^(b1&^b0)

		b0, b1, b2, b3, b4 = bits.RotateLeft64(e4^d4, 27), bits.RotateLeft64(e5^d0, 36), bits.RotateLeft64(e11^d1, 10), bits.RotateLeft64(e17^d2, 15), bits.RotateLeft64(e23^d3, 56)

		a15, a16, a17, a18, a19 = b0^(b2&^b1), b1^(b3&^b2), b2^(b4&^b3), b3^(b0&^b4), b4^(b1&^b0)

		b0, b1, b2, b3, b4 = bits.RotateLeft64(e2^d2, 62), bits.RotateLeft64(e8^d3, 55), bits.RotateLeft64(e14^d4, 39), bits.RotateLeft64(e15^d0, 41), bits.RotateLeft64(e21^d1, 2)

		a20, a21, a22, a23, a24 = b0^(b2&^b1), b1^(b3&^b2), b2^(b4&^b3), b3^(b0&^b4), b4^(b1&^b0)
	}

	s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15], s[16], s[17], s[18], s[19], s[20], s[21], s[22], s[23], s[24] = a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24
}

// The portable form of permuteLanes.
func permuteLanesGeneric(states [][25]uint64) {
	for i := range states {
		permuteGeneric(&states[i])
	}
}

// The most sponges keccakLanes runs together: the 2k noise samples of ML-KEM-1024 key generation,
// a group of ML-DSA secret vectors.
const keccakMaxLanes = 8

// SHAKE sponges of one rate in lockstep, for independent outputs whose inputs fit in one block, so
// that every permutation is a batch of the lane kernels. Sponge l absorbs prefix || tail_l, tail_l
// being tails[l] as tailBytes little-endian bytes; squeeze then permutes every sponge, after which
// read gives each one's next block. When the outputs are secret the caller calls wipe.
type keccakLanes struct {
	states [keccakMaxLanes][25]uint64
	count  int
	rate   int
}

func (k *keccakLanes) start(rate int, prefix []byte, tails []uint16, tailBytes int) {
	k.count, k.rate = len(tails), rate

	var block [200]byte

	copy(block[:], prefix)

	end := len(prefix) + tailBytes

	block[end] = 0x1f

	block[rate-1] ^= 0x80

	for l, tail := range tails {
		block[len(prefix)] = byte(tail)

		if tailBytes == 2 {
			block[len(prefix)+1] = byte(tail >> 8)
		}

		s := &k.states[l]

		*s = [25]uint64{}

		for i := range rate / 8 {
			s[i] = binary.LittleEndian.Uint64(block[8*i:])
		}
	}

	clear(block[:])
}

func (k *keccakLanes) squeeze() {
	permuteLanes(k.states[:k.count])
}

// The rate bytes that sponge l outputs next, into out.
func (k *keccakLanes) read(l int, out []byte) {
	for i, lane := range k.states[l][:k.rate/8] {
		binary.LittleEndian.PutUint64(out[8*i:], lane)
	}
}

func (k *keccakLanes) wipe() {
	clear(k.states[:])
}

type keccak struct {
	state     [25]uint64
	rate      int
	suffix    byte
	position  int
	squeezing bool
}

func (k *keccak) update(data []byte) {
	if k.squeezing {
		panic("cryptopq: UNSUPPORTED: cannot update after read")
	}

	for len(data) > 0 {
		if k.position%8 == 0 && len(data) >= 8 {
			lanes, first := min(len(data), k.rate-k.position)/8, k.position/8

			for i, lane := range k.state[first : first+lanes] {
				k.state[first+i] = lane ^ binary.LittleEndian.Uint64(data[8*i:])
			}

			k.position += 8 * lanes

			data = data[8*lanes:]
		} else {
			k.state[k.position/8] ^= uint64(data[0]) << (8 * (k.position % 8))

			k.position++

			data = data[1:]
		}

		if k.position == k.rate {
			permute(&k.state)

			k.position = 0
		}
	}
}

func (k *keccak) read(out []byte) {
	if !k.squeezing {
		last := k.rate - 1

		k.state[k.position/8] ^= uint64(k.suffix) << (8 * (k.position % 8))

		k.state[last/8] ^= 0x80 << (8 * (last % 8))

		permute(&k.state)

		k.position = 0

		k.squeezing = true
	}

	for len(out) > 0 {
		if k.position == k.rate {
			permute(&k.state)

			k.position = 0
		}

		if k.position%8 == 0 && len(out) >= 8 {
			lanes, first := min(len(out), k.rate-k.position)/8, k.position/8

			for i, lane := range k.state[first : first+lanes] {
				binary.LittleEndian.PutUint64(out[8*i:], lane)
			}

			k.position += 8 * lanes

			out = out[8*lanes:]
		} else {
			out[0] = byte(k.state[k.position/8] >> (8 * (k.position % 8)))

			k.position++

			out = out[1:]
		}
	}
}

// One-shot Keccak hash or XOF of the concatenated parts into out; the state is cleared after.
func keccakSum(rate int, suffix byte, out []byte, parts ...[]byte) {
	sponge := keccak{rate: rate, suffix: suffix}

	for _, part := range parts {
		sponge.update(part)
	}

	sponge.read(out)

	clear(sponge.state[:])
}

func sha3Sum256(out []byte, parts ...[]byte) {
	keccakSum(136, 0x06, out[:32], parts...)
}

func sha3Sum512(out []byte, parts ...[]byte) {
	keccakSum(72, 0x06, out[:64], parts...)
}

func shake256Sum(out []byte, parts ...[]byte) {
	keccakSum(136, 0x1f, out, parts...)
}

// SHAKE256 of fewer than 136 input bytes into at most 136 output bytes: a single permutation,
// without the byte-wise buffering of keccak.update. The block is indexed on the stack directly,
// so that the race detector checks one range per call rather than every byte.
func shake256Short(data, out []byte) {
	var block [136]byte

	copy(block[:], data)

	block[len(data)] ^= 0x1f

	block[135] ^= 0x80

	var state [25]uint64

	for i := range 17 {
		state[i] = uint64(block[8*i]) | uint64(block[8*i+1])<<8 | uint64(block[8*i+2])<<16 | uint64(block[8*i+3])<<24 |
			uint64(block[8*i+4])<<32 | uint64(block[8*i+5])<<40 | uint64(block[8*i+6])<<48 | uint64(block[8*i+7])<<56
	}

	permute(&state)

	for i := range (len(out) + 7) / 8 {
		for j := range 8 {
			block[8*i+j] = byte(state[i] >> (8 * j))
		}
	}

	copy(out, block[:])
}

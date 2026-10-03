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

// Keccak-f[1600], unrolled. Lane x + 5y is a{x + 5y}; rho and pi move it to b{y + 5((2x + 3y) mod 5)}.
func permute(a *[25]uint64) {
	a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24 := a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15], a[16], a[17], a[18], a[19], a[20], a[21], a[22], a[23], a[24]

	for _, constant := range roundConstants {
		c0 := a0 ^ a5 ^ a10 ^ a15 ^ a20

		c1 := a1 ^ a6 ^ a11 ^ a16 ^ a21

		c2 := a2 ^ a7 ^ a12 ^ a17 ^ a22

		c3 := a3 ^ a8 ^ a13 ^ a18 ^ a23

		c4 := a4 ^ a9 ^ a14 ^ a19 ^ a24

		d0 := c4 ^ bits.RotateLeft64(c1, 1)

		d1 := c0 ^ bits.RotateLeft64(c2, 1)

		d2 := c1 ^ bits.RotateLeft64(c3, 1)

		d3 := c2 ^ bits.RotateLeft64(c4, 1)

		d4 := c3 ^ bits.RotateLeft64(c0, 1)

		a0 ^= d0

		a1 ^= d1

		a2 ^= d2

		a3 ^= d3

		a4 ^= d4

		a5 ^= d0

		a6 ^= d1

		a7 ^= d2

		a8 ^= d3

		a9 ^= d4

		a10 ^= d0

		a11 ^= d1

		a12 ^= d2

		a13 ^= d3

		a14 ^= d4

		a15 ^= d0

		a16 ^= d1

		a17 ^= d2

		a18 ^= d3

		a19 ^= d4

		a20 ^= d0

		a21 ^= d1

		a22 ^= d2

		a23 ^= d3

		a24 ^= d4

		b0 := a0

		b1 := bits.RotateLeft64(a6, 44)

		b2 := bits.RotateLeft64(a12, 43)

		b3 := bits.RotateLeft64(a18, 21)

		b4 := bits.RotateLeft64(a24, 14)

		b5 := bits.RotateLeft64(a3, 28)

		b6 := bits.RotateLeft64(a9, 20)

		b7 := bits.RotateLeft64(a10, 3)

		b8 := bits.RotateLeft64(a16, 45)

		b9 := bits.RotateLeft64(a22, 61)

		b10 := bits.RotateLeft64(a1, 1)

		b11 := bits.RotateLeft64(a7, 6)

		b12 := bits.RotateLeft64(a13, 25)

		b13 := bits.RotateLeft64(a19, 8)

		b14 := bits.RotateLeft64(a20, 18)

		b15 := bits.RotateLeft64(a4, 27)

		b16 := bits.RotateLeft64(a5, 36)

		b17 := bits.RotateLeft64(a11, 10)

		b18 := bits.RotateLeft64(a17, 15)

		b19 := bits.RotateLeft64(a23, 56)

		b20 := bits.RotateLeft64(a2, 62)

		b21 := bits.RotateLeft64(a8, 55)

		b22 := bits.RotateLeft64(a14, 39)

		b23 := bits.RotateLeft64(a15, 41)

		b24 := bits.RotateLeft64(a21, 2)

		a0 = b0 ^ (^b1 & b2) ^ constant

		a1 = b1 ^ (^b2 & b3)

		a2 = b2 ^ (^b3 & b4)

		a3 = b3 ^ (^b4 & b0)

		a4 = b4 ^ (^b0 & b1)

		a5 = b5 ^ (^b6 & b7)

		a6 = b6 ^ (^b7 & b8)

		a7 = b7 ^ (^b8 & b9)

		a8 = b8 ^ (^b9 & b5)

		a9 = b9 ^ (^b5 & b6)

		a10 = b10 ^ (^b11 & b12)

		a11 = b11 ^ (^b12 & b13)

		a12 = b12 ^ (^b13 & b14)

		a13 = b13 ^ (^b14 & b10)

		a14 = b14 ^ (^b10 & b11)

		a15 = b15 ^ (^b16 & b17)

		a16 = b16 ^ (^b17 & b18)

		a17 = b17 ^ (^b18 & b19)

		a18 = b18 ^ (^b19 & b15)

		a19 = b19 ^ (^b15 & b16)

		a20 = b20 ^ (^b21 & b22)

		a21 = b21 ^ (^b22 & b23)

		a22 = b22 ^ (^b23 & b24)

		a23 = b23 ^ (^b24 & b20)

		a24 = b24 ^ (^b20 & b21)
	}

	a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15], a[16], a[17], a[18], a[19], a[20], a[21], a[22], a[23], a[24] = a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24
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
		if k.position == 0 && len(data) >= k.rate {
			for i := range k.rate / 8 {
				k.state[i] ^= binary.LittleEndian.Uint64(data[8*i:])
			}

			permute(&k.state)

			data = data[k.rate:]

			continue
		}

		n := min(k.rate-k.position, len(data))

		for i, b := range data[:n] {
			index := k.position + i

			k.state[index/8] ^= uint64(b) << (8 * (index % 8))
		}

		k.position += n

		data = data[n:]

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

	for i := range out {
		if k.position == k.rate {
			permute(&k.state)

			k.position = 0
		}

		out[i] = byte(k.state[k.position/8] >> (8 * (k.position % 8)))

		k.position++
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

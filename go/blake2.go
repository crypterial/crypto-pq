package cryptopq

import (
	"encoding/binary"
	"math/bits"
)

// BLAKE2b and BLAKE2s (RFC 7693, with the salt and personalization of the BLAKE2 specification).

var blake2bIV = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

// Round r takes the message words in the order of row r mod 10; BLAKE2s runs the first ten rows.
var blake2Sigma = [12][16]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
}

// Every whole 128-byte block of blocks is compressed into h, the counter first growing by the
// block; flag, the final-block mask, goes into v14 of the last block only. The four G functions of a
// step are interleaved, and the message word is added before b, which arrives last. The masks only spare bounds checks: the
// schedule entries are below 16. This is the portable form of blake2bBlocks.
func blake2bBlocksGeneric(h *[8]uint64, counter *[2]uint64, flag uint64, blocks []byte) {
	var m [16]uint64

	c0, c1 := counter[0], counter[1]

	for ; len(blocks) >= 128; blocks = blocks[128:] {
		c0 += 128

		if c0 < 128 {
			c1++
		}

		for i := range m {
			m[i] = binary.LittleEndian.Uint64(blocks[8*i:])
		}

		v0, v1, v2, v3, v4, v5, v6, v7 := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]

		v8, v9, v10, v11 := blake2bIV[0], blake2bIV[1], blake2bIV[2], blake2bIV[3]

		last := uint64(0)

		if len(blocks) < 256 {
			last = flag
		}

		v12, v13, v14, v15 := blake2bIV[4]^c0, blake2bIV[5]^c1, blake2bIV[6]^last, blake2bIV[7]

		for r := range blake2Sigma {
			s := &blake2Sigma[r]

			v0, v1, v2, v3 = v0+m[s[0]&15], v1+m[s[2]&15], v2+m[s[4]&15], v3+m[s[6]&15]

			v0, v1, v2, v3 = v0+v4, v1+v5, v2+v6, v3+v7

			v12, v13, v14, v15 = bits.RotateLeft64(v12^v0, -32), bits.RotateLeft64(v13^v1, -32), bits.RotateLeft64(v14^v2, -32), bits.RotateLeft64(v15^v3, -32)

			v8, v9, v10, v11 = v8+v12, v9+v13, v10+v14, v11+v15

			v4, v5, v6, v7 = bits.RotateLeft64(v4^v8, -24), bits.RotateLeft64(v5^v9, -24), bits.RotateLeft64(v6^v10, -24), bits.RotateLeft64(v7^v11, -24)

			v0, v1, v2, v3 = v0+m[s[1]&15], v1+m[s[3]&15], v2+m[s[5]&15], v3+m[s[7]&15]

			v0, v1, v2, v3 = v0+v4, v1+v5, v2+v6, v3+v7

			v12, v13, v14, v15 = bits.RotateLeft64(v12^v0, -16), bits.RotateLeft64(v13^v1, -16), bits.RotateLeft64(v14^v2, -16), bits.RotateLeft64(v15^v3, -16)

			v8, v9, v10, v11 = v8+v12, v9+v13, v10+v14, v11+v15

			v4, v5, v6, v7 = bits.RotateLeft64(v4^v8, -63), bits.RotateLeft64(v5^v9, -63), bits.RotateLeft64(v6^v10, -63), bits.RotateLeft64(v7^v11, -63)

			v0, v1, v2, v3 = v0+m[s[8]&15], v1+m[s[10]&15], v2+m[s[12]&15], v3+m[s[14]&15]

			v0, v1, v2, v3 = v0+v5, v1+v6, v2+v7, v3+v4

			v15, v12, v13, v14 = bits.RotateLeft64(v15^v0, -32), bits.RotateLeft64(v12^v1, -32), bits.RotateLeft64(v13^v2, -32), bits.RotateLeft64(v14^v3, -32)

			v10, v11, v8, v9 = v10+v15, v11+v12, v8+v13, v9+v14

			v5, v6, v7, v4 = bits.RotateLeft64(v5^v10, -24), bits.RotateLeft64(v6^v11, -24), bits.RotateLeft64(v7^v8, -24), bits.RotateLeft64(v4^v9, -24)

			v0, v1, v2, v3 = v0+m[s[9]&15], v1+m[s[11]&15], v2+m[s[13]&15], v3+m[s[15]&15]

			v0, v1, v2, v3 = v0+v5, v1+v6, v2+v7, v3+v4

			v15, v12, v13, v14 = bits.RotateLeft64(v15^v0, -16), bits.RotateLeft64(v12^v1, -16), bits.RotateLeft64(v13^v2, -16), bits.RotateLeft64(v14^v3, -16)

			v10, v11, v8, v9 = v10+v15, v11+v12, v8+v13, v9+v14

			v5, v6, v7, v4 = bits.RotateLeft64(v5^v10, -63), bits.RotateLeft64(v6^v11, -63), bits.RotateLeft64(v7^v8, -63), bits.RotateLeft64(v4^v9, -63)
		}

		h[0] ^= v0 ^ v8

		h[1] ^= v1 ^ v9

		h[2] ^= v2 ^ v10

		h[3] ^= v3 ^ v11

		h[4] ^= v4 ^ v12

		h[5] ^= v5 ^ v13

		h[6] ^= v6 ^ v14

		h[7] ^= v7 ^ v15
	}

	counter[0], counter[1] = c0, c1

	clear(m[:])
}

// The BLAKE2s counterpart of blake2bBlocksGeneric: 64-byte blocks, 32-bit words, ten rounds; the
// portable form of blake2sBlocks.
func blake2sBlocksGeneric(h *[8]uint32, counter *[2]uint32, flag uint32, blocks []byte) {
	var m [16]uint32

	c0, c1 := counter[0], counter[1]

	for ; len(blocks) >= 64; blocks = blocks[64:] {
		c0 += 64

		if c0 < 64 {
			c1++
		}

		for i := range m {
			m[i] = binary.LittleEndian.Uint32(blocks[4*i:])
		}

		v0, v1, v2, v3, v4, v5, v6, v7 := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]

		v8, v9, v10, v11 := iv256[0], iv256[1], iv256[2], iv256[3]

		last := uint32(0)

		if len(blocks) < 128 {
			last = flag
		}

		v12, v13, v14, v15 := iv256[4]^c0, iv256[5]^c1, iv256[6]^last, iv256[7]

		for r := range blake2Sigma[:10] {
			s := &blake2Sigma[r]

			v0, v1, v2, v3 = v0+m[s[0]&15], v1+m[s[2]&15], v2+m[s[4]&15], v3+m[s[6]&15]

			v0, v1, v2, v3 = v0+v4, v1+v5, v2+v6, v3+v7

			v12, v13, v14, v15 = bits.RotateLeft32(v12^v0, -16), bits.RotateLeft32(v13^v1, -16), bits.RotateLeft32(v14^v2, -16), bits.RotateLeft32(v15^v3, -16)

			v8, v9, v10, v11 = v8+v12, v9+v13, v10+v14, v11+v15

			v4, v5, v6, v7 = bits.RotateLeft32(v4^v8, -12), bits.RotateLeft32(v5^v9, -12), bits.RotateLeft32(v6^v10, -12), bits.RotateLeft32(v7^v11, -12)

			v0, v1, v2, v3 = v0+m[s[1]&15], v1+m[s[3]&15], v2+m[s[5]&15], v3+m[s[7]&15]

			v0, v1, v2, v3 = v0+v4, v1+v5, v2+v6, v3+v7

			v12, v13, v14, v15 = bits.RotateLeft32(v12^v0, -8), bits.RotateLeft32(v13^v1, -8), bits.RotateLeft32(v14^v2, -8), bits.RotateLeft32(v15^v3, -8)

			v8, v9, v10, v11 = v8+v12, v9+v13, v10+v14, v11+v15

			v4, v5, v6, v7 = bits.RotateLeft32(v4^v8, -7), bits.RotateLeft32(v5^v9, -7), bits.RotateLeft32(v6^v10, -7), bits.RotateLeft32(v7^v11, -7)

			v0, v1, v2, v3 = v0+m[s[8]&15], v1+m[s[10]&15], v2+m[s[12]&15], v3+m[s[14]&15]

			v0, v1, v2, v3 = v0+v5, v1+v6, v2+v7, v3+v4

			v15, v12, v13, v14 = bits.RotateLeft32(v15^v0, -16), bits.RotateLeft32(v12^v1, -16), bits.RotateLeft32(v13^v2, -16), bits.RotateLeft32(v14^v3, -16)

			v10, v11, v8, v9 = v10+v15, v11+v12, v8+v13, v9+v14

			v5, v6, v7, v4 = bits.RotateLeft32(v5^v10, -12), bits.RotateLeft32(v6^v11, -12), bits.RotateLeft32(v7^v8, -12), bits.RotateLeft32(v4^v9, -12)

			v0, v1, v2, v3 = v0+m[s[9]&15], v1+m[s[11]&15], v2+m[s[13]&15], v3+m[s[15]&15]

			v0, v1, v2, v3 = v0+v5, v1+v6, v2+v7, v3+v4

			v15, v12, v13, v14 = bits.RotateLeft32(v15^v0, -8), bits.RotateLeft32(v12^v1, -8), bits.RotateLeft32(v13^v2, -8), bits.RotateLeft32(v14^v3, -8)

			v10, v11, v8, v9 = v10+v15, v11+v12, v8+v13, v9+v14

			v5, v6, v7, v4 = bits.RotateLeft32(v5^v10, -7), bits.RotateLeft32(v6^v11, -7), bits.RotateLeft32(v7^v8, -7), bits.RotateLeft32(v4^v9, -7)
		}

		h[0] ^= v0 ^ v8

		h[1] ^= v1 ^ v9

		h[2] ^= v2 ^ v10

		h[3] ^= v3 ^ v11

		h[4] ^= v4 ^ v12

		h[5] ^= v5 ^ v13

		h[6] ^= v6 ^ v14

		h[7] ^= v7 ^ v15
	}

	counter[0], counter[1] = c0, c1

	clear(m[:])
}

// The chaining value of the parameter block: digest length, key length, fanout and depth 1, then
// the salt and personalization words.
func blake2bStart(h *[8]uint64, params *[4]uint64, size, keySize int) {
	*h = blake2bIV

	h[0] ^= 0x01010000 | uint64(keySize)<<8 | uint64(size)

	h[4] ^= params[0]

	h[5] ^= params[1]

	h[6] ^= params[2]

	h[7] ^= params[3]
}

func blake2sStart(h *[8]uint32, params *[4]uint64, size, keySize int) {
	*h = iv256

	h[0] ^= 0x01010000 | uint32(keySize)<<8 | uint32(size)

	h[4] ^= uint32(params[0])

	h[5] ^= uint32(params[0] >> 32)

	h[6] ^= uint32(params[1])

	h[7] ^= uint32(params[1] >> 32)
}

// Compresses the last block, tail padded with zeros, which brings the counter to counter plus
// len(tail), and writes the first len(out) bytes of h.
func blake2bFinal(h *[8]uint64, counter [2]uint64, tail, out []byte) {
	var block [128]byte

	copy(block[:], tail)

	low, carry := bits.Add64(counter[0], uint64(len(tail)), 0)

	low, borrow := bits.Sub64(low, 128, 0)

	counter = [2]uint64{low, counter[1] + carry - borrow}

	blake2bBlocks(h, &counter, ^uint64(0), block[:])

	blake2bOutput(h, out)

	clear(block[:])
}

func blake2bOutput(h *[8]uint64, out []byte) {
	words := len(out) / 8

	for i := range words {
		binary.LittleEndian.PutUint64(out[8*i:], h[i])
	}

	for j := range len(out) % 8 {
		out[8*words+j] = byte(h[words] >> (8 * j))
	}
}

func blake2sFinal(h *[8]uint32, counter [2]uint32, tail, out []byte) {
	var block [64]byte

	copy(block[:], tail)

	total := uint64(counter[1])<<32 | uint64(counter[0])

	total += uint64(len(tail)) - 64

	counter = [2]uint32{uint32(total), uint32(total >> 32)}

	blake2sBlocks(h, &counter, ^uint32(0), block[:])

	blake2sOutput(h, out)

	clear(block[:])
}

func blake2sOutput(h *[8]uint32, out []byte) {
	words := len(out) / 4

	for i := range words {
		binary.LittleEndian.PutUint32(out[4*i:], h[i])
	}

	for j := range len(out) % 4 {
		out[4*words+j] = byte(h[words] >> (8 * j))
	}
}

// BLAKE2b of data into out, len(out) being the digest size, keyed when key is not empty (the
// callers check its length): the key padded to a block comes first, the final block when data is
// empty. Whole blocks are compressed straight from data, a last one that is whole included, and
// nothing is allocated.
func blake2bSum(params *[4]uint64, key, data, out []byte) {
	var h [8]uint64

	var counter [2]uint64

	blake2bStart(&h, params, len(out), len(key))

	if len(key) > 0 {
		var block [128]byte

		copy(block[:], key)

		flag := uint64(0)

		if len(data) == 0 {
			flag = ^uint64(0)
		}

		blake2bBlocks(&h, &counter, flag, block[:])

		clear(block[:])
	}

	switch whole := len(data) &^ 127; {
	case len(data) > 0 && whole == len(data):
		blake2bBlocks(&h, &counter, ^uint64(0), data)

		blake2bOutput(&h, out)
	case len(data) > 0 || len(key) == 0:
		blake2bBlocks(&h, &counter, 0, data[:whole])

		blake2bFinal(&h, counter, data[whole:], out)
	default:
		blake2bOutput(&h, out)
	}

	clear(h[:])
}

func blake2sSum(params *[4]uint64, key, data, out []byte) {
	var h [8]uint32

	var counter [2]uint32

	blake2sStart(&h, params, len(out), len(key))

	if len(key) > 0 {
		var block [64]byte

		copy(block[:], key)

		flag := uint32(0)

		if len(data) == 0 {
			flag = ^uint32(0)
		}

		blake2sBlocks(&h, &counter, flag, block[:])

		clear(block[:])
	}

	switch whole := len(data) &^ 63; {
	case len(data) > 0 && whole == len(data):
		blake2sBlocks(&h, &counter, ^uint32(0), data)

		blake2sOutput(&h, out)
	case len(data) > 0 || len(key) == 0:
		blake2sBlocks(&h, &counter, 0, data[:whole])

		blake2sFinal(&h, counter, data[whole:], out)
	default:
		blake2sOutput(&h, out)
	}

	clear(h[:])
}

// blake2bEngine keeps the last block buffered, since only the end of the input decides whether it
// is the final one; a keyed engine starts with the key block there.
type blake2bEngine struct {
	h       [8]uint64
	counter [2]uint64
	buffer  [128]byte
	used    int
	size    int
}

func newBlake2b(params *[4]uint64, size int, key []byte) *blake2bEngine {
	e := &blake2bEngine{}

	e.init(params, size, key)

	return e
}

func (e *blake2bEngine) init(params *[4]uint64, size int, key []byte) {
	blake2bStart(&e.h, params, size, len(key))

	e.size = size

	if len(key) > 0 {
		copy(e.buffer[:], key)

		e.used = len(e.buffer)
	}
}

func (e *blake2bEngine) update(data []byte) {
	if e.used > 0 {
		n := copy(e.buffer[e.used:], data)

		e.used += n

		data = data[n:]

		if len(data) == 0 {
			return
		}

		blake2bBlocks(&e.h, &e.counter, 0, e.buffer[:])

		e.used = 0
	}

	if len(data) > 128 {
		whole := (len(data) - 1) &^ 127

		blake2bBlocks(&e.h, &e.counter, 0, data[:whole])

		data = data[whole:]
	}

	e.used = copy(e.buffer[:], data)
}

func (e *blake2bEngine) digest() []byte {
	out := make([]byte, e.size)

	e.digestInto(out)

	return out
}

func (e *blake2bEngine) digestInto(out []byte) {
	h := e.h

	blake2bFinal(&h, e.counter, e.buffer[:e.used], out)

	clear(h[:])
}

func (e *blake2bEngine) clone() engine {
	copied := *e

	return &copied
}

type blake2sEngine struct {
	h       [8]uint32
	counter [2]uint32
	buffer  [64]byte
	used    int
	size    int
}

func newBlake2s(params *[4]uint64, size int, key []byte) *blake2sEngine {
	e := &blake2sEngine{}

	e.init(params, size, key)

	return e
}

func (e *blake2sEngine) init(params *[4]uint64, size int, key []byte) {
	blake2sStart(&e.h, params, size, len(key))

	e.size = size

	if len(key) > 0 {
		copy(e.buffer[:], key)

		e.used = len(e.buffer)
	}
}

func (e *blake2sEngine) update(data []byte) {
	if e.used > 0 {
		n := copy(e.buffer[e.used:], data)

		e.used += n

		data = data[n:]

		if len(data) == 0 {
			return
		}

		blake2sBlocks(&e.h, &e.counter, 0, e.buffer[:])

		e.used = 0
	}

	if len(data) > 64 {
		whole := (len(data) - 1) &^ 63

		blake2sBlocks(&e.h, &e.counter, 0, data[:whole])

		data = data[whole:]
	}

	e.used = copy(e.buffer[:], data)
}

func (e *blake2sEngine) digest() []byte {
	out := make([]byte, e.size)

	e.digestInto(out)

	return out
}

func (e *blake2sEngine) digestInto(out []byte) {
	h := e.h

	blake2sFinal(&h, e.counter, e.buffer[:e.used], out)

	clear(h[:])
}

func (e *blake2sEngine) clone() engine {
	copied := *e

	return &copied
}

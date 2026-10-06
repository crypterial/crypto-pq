package cryptopq

import (
	"encoding/binary"
	"math/bits"
)

// cSHAKE and KMAC (NIST SP 800-185) over the Keccak sponge, byte-oriented: lengths are whole
// bytes, encoded in bits.

// left_encode(x) (SP 800-185, 2.3.1): the byte count n, then x big-endian in n bytes.
func leftEncode(buf *[9]byte, x uint64) []byte {
	n := max(1, (bits.Len64(x)+7)/8)

	buf[0] = byte(n)

	for i := range n {
		buf[1+i] = byte(x >> (8 * (n - 1 - i)))
	}

	return buf[:1+n]
}

// right_encode(x): x big-endian in n bytes, then n.
func rightEncode(buf *[9]byte, x uint64) []byte {
	n := max(1, (bits.Len64(x)+7)/8)

	for i := range n {
		buf[i] = byte(x >> (8 * (n - 1 - i)))
	}

	buf[n] = byte(n)

	return buf[:n+1]
}

// The zeros of bytepad change nothing but the position: a started block is permuted.
func bytepadEnd(sponge *keccak) {
	if sponge.position > 0 {
		permute(&sponge.state)

		sponge.position = 0
	}
}

// The state after bytepad(encode_string(N) || encode_string(S), rate), from which every input of
// cSHAKE with function name N and customization S starts.
func cshakeState(rate int, functionName, customization []byte) [25]uint64 {
	sponge := keccak{rate: rate, suffix: 0x04}

	var buf [9]byte

	sponge.update(leftEncode(&buf, uint64(rate)))

	sponge.update(leftEncode(&buf, 8*uint64(len(functionName))))

	sponge.update(functionName)

	sponge.update(leftEncode(&buf, 8*uint64(len(customization))))

	sponge.update(customization)

	bytepadEnd(&sponge)

	return sponge.state
}

// cSHAKE with N and S both empty is SHAKE.
func cshakeAlgorithm(id uint8, functionName, customization []byte) XofAlgorithm {
	if len(functionName) == 0 && len(customization) == 0 {
		return XofAlgorithm{id: id}
	}

	return XofAlgorithm{id: id, customized: true, state: cshakeState(xofSpecs[id].rate, functionName, customization)}
}

// SHAKE or cSHAKE of data into out, state being at a block boundary (zero for SHAKE): every byte is
// absorbed straight from data, and the padding touches only the lane after the data and the last
// lane of the block, without allocating.
func keccakXof(state *[25]uint64, rate int, suffix byte, data, out []byte) {
	lanes := rate / 8

	for ; len(data) >= rate; data = data[rate:] {
		block := data[:rate]

		for i := range lanes {
			state[i] ^= binary.LittleEndian.Uint64(block[8*i:])
		}

		permute(state)
	}

	whole := len(data) / 8

	for i := range whole {
		state[i] ^= binary.LittleEndian.Uint64(data[8*i:])
	}

	word := uint64(suffix) << (8 * (len(data) % 8))

	for j, b := range data[8*whole:] {
		word |= uint64(b) << (8 * j)
	}

	state[whole] ^= word

	state[lanes-1] ^= 0x80 << 56

	for {
		permute(state)

		n := min(len(out), rate)

		for i := range n / 8 {
			binary.LittleEndian.PutUint64(out[8*i:], state[i])
		}

		for j := n &^ 7; j < n; j++ {
			out[j] = byte(state[j/8] >> (8 * (j % 8)))
		}

		if out = out[n:]; len(out) == 0 {
			return
		}
	}
}

// KMAC's key block, bytepad(encode_string(K), rate).
func kmacAbsorbKey(sponge *keccak, key []byte) {
	var buf [9]byte

	sponge.update(leftEncode(&buf, uint64(sponge.rate)))

	sponge.update(leftEncode(&buf, 8*uint64(len(key))))

	sponge.update(key)

	bytepadEnd(sponge)
}

// right_encode(L) after the data: L is the output length in bits, or 0 for KMACXOF.
func kmacFinish(sponge *keccak, length int, xof bool) {
	var buf [9]byte

	encoded := uint64(0)

	if !xof {
		encoded = 8 * uint64(length)
	}

	sponge.update(rightEncode(&buf, encoded))
}

// KMAC of data under key into out, from the configured state; the sponge is cleared after.
func kmacSum(state *[25]uint64, rate int, key, data, out []byte, xof bool) {
	sponge := keccak{state: *state, rate: rate, suffix: 0x04}

	kmacAbsorbKey(&sponge, key)

	sponge.update(data)

	kmacFinish(&sponge, len(out), xof)

	sponge.read(out)

	clear(sponge.state[:])
}

func kmacVerify(state *[25]uint64, rate int, key, data, tag []byte, xof bool) bool {
	sponge := keccak{state: *state, rate: rate, suffix: 0x04}

	kmacAbsorbKey(&sponge, key)

	sponge.update(data)

	kmacFinish(&sponge, len(tag), xof)

	ok := squeezeEqual(&sponge, tag)

	clear(sponge.state[:])

	return ok
}

// Whether the next len(tag) output bytes equal tag, compared a block at a time without a branch on
// their contents, so that a tag of any length needs no buffer of its size.
func squeezeEqual(sponge *keccak, tag []byte) bool {
	var block [168]byte

	var difference byte

	for len(tag) > 0 {
		n := min(len(tag), len(block))

		sponge.read(block[:n])

		for i := range n {
			difference |= block[i] ^ tag[i]
		}

		tag = tag[n:]
	}

	clear(block[:])

	return difference == 0
}

package cryptopq

import (
	"encoding/binary"
	"math/bits"
)

var iv224 = [8]uint32{0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4}

var iv256 = [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}

var iv384 = [8]uint64{
	0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
	0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
}

var iv512 = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

var iv512224 = [8]uint64{
	0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
	0x0f6d2b697bd44da8, 0x77e36f7304c48942, 0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1,
}

var iv512256 = [8]uint64{
	0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd,
	0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2,
}

// One SHA-256 round. The caller rotates the roles of the working variables instead of moving
// them: the new e and the new a replace the variables that held d and h. Ch(e, f, g) is the sum of
// its two disjoint halves, and Maj(a, b, c) is ((a ^ b) & (b ^ c)) ^ b, where b ^ c is the a ^ b of
// the previous round: the caller passes it as bc and keeps the returned a ^ b for the next round.
// Both forms take fewer instructions than the textbook ones.
func sha256Round(a, b, bc, d, e, f, g, h, w, k uint32) (uint32, uint32, uint32) {
	t1 := h + k + w + e&f + g&^e + (bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25))

	ab := a ^ b

	return d + t1, t1 + (bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)) + (ab&bc ^ b), ab
}

// The schedule word W[t] from W[t-2], W[t-7], W[t-15] and W[t-16].
func sha256Schedule(w2, w7, w15, w16 uint32) uint32 {
	return (bits.RotateLeft32(w2, -17) ^ bits.RotateLeft32(w2, -19) ^ w2>>10) + w7 + (bits.RotateLeft32(w15, -7) ^ bits.RotateLeft32(w15, -18) ^ w15>>3) + w16
}

// One block of big-endian words compressed into state, unrolled: the round constants are
// immediates and the message schedule lives in sixteen locals, so the rounds touch no memory. This
// is the portable form of sha256Block, which uses the CPU's SHA-256 instructions where it has them;
// the pointers spare both a copy of their arrays.
func sha256BlockGeneric(state *[8]uint32, w *[16]uint32) {
	a, b, c, d, e, f, g, h := state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]

	w0, w1, w2, w3, w4, w5, w6, w7 := w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]

	w8, w9, w10, w11, w12, w13, w14, w15 := w[8], w[9], w[10], w[11], w[12], w[13], w[14], w[15]

	bc := b ^ c

	d, h, bc = sha256Round(a, b, bc, d, e, f, g, h, w0, 0x428a2f98)

	c, g, bc = sha256Round(h, a, bc, c, d, e, f, g, w1, 0x71374491)

	b, f, bc = sha256Round(g, h, bc, b, c, d, e, f, w2, 0xb5c0fbcf)

	a, e, bc = sha256Round(f, g, bc, a, b, c, d, e, w3, 0xe9b5dba5)

	h, d, bc = sha256Round(e, f, bc, h, a, b, c, d, w4, 0x3956c25b)

	g, c, bc = sha256Round(d, e, bc, g, h, a, b, c, w5, 0x59f111f1)

	f, b, bc = sha256Round(c, d, bc, f, g, h, a, b, w6, 0x923f82a4)

	e, a, bc = sha256Round(b, c, bc, e, f, g, h, a, w7, 0xab1c5ed5)

	d, h, bc = sha256Round(a, b, bc, d, e, f, g, h, w8, 0xd807aa98)

	c, g, bc = sha256Round(h, a, bc, c, d, e, f, g, w9, 0x12835b01)

	b, f, bc = sha256Round(g, h, bc, b, c, d, e, f, w10, 0x243185be)

	a, e, bc = sha256Round(f, g, bc, a, b, c, d, e, w11, 0x550c7dc3)

	h, d, bc = sha256Round(e, f, bc, h, a, b, c, d, w12, 0x72be5d74)

	g, c, bc = sha256Round(d, e, bc, g, h, a, b, c, w13, 0x80deb1fe)

	f, b, bc = sha256Round(c, d, bc, f, g, h, a, b, w14, 0x9bdc06a7)

	e, a, bc = sha256Round(b, c, bc, e, f, g, h, a, w15, 0xc19bf174)

	w0 = sha256Schedule(w14, w9, w1, w0)

	d, h, bc = sha256Round(a, b, bc, d, e, f, g, h, w0, 0xe49b69c1)

	w1 = sha256Schedule(w15, w10, w2, w1)

	c, g, bc = sha256Round(h, a, bc, c, d, e, f, g, w1, 0xefbe4786)

	w2 = sha256Schedule(w0, w11, w3, w2)

	b, f, bc = sha256Round(g, h, bc, b, c, d, e, f, w2, 0x0fc19dc6)

	w3 = sha256Schedule(w1, w12, w4, w3)

	a, e, bc = sha256Round(f, g, bc, a, b, c, d, e, w3, 0x240ca1cc)

	w4 = sha256Schedule(w2, w13, w5, w4)

	h, d, bc = sha256Round(e, f, bc, h, a, b, c, d, w4, 0x2de92c6f)

	w5 = sha256Schedule(w3, w14, w6, w5)

	g, c, bc = sha256Round(d, e, bc, g, h, a, b, c, w5, 0x4a7484aa)

	w6 = sha256Schedule(w4, w15, w7, w6)

	f, b, bc = sha256Round(c, d, bc, f, g, h, a, b, w6, 0x5cb0a9dc)

	w7 = sha256Schedule(w5, w0, w8, w7)

	e, a, bc = sha256Round(b, c, bc, e, f, g, h, a, w7, 0x76f988da)

	w8 = sha256Schedule(w6, w1, w9, w8)

	d, h, bc = sha256Round(a, b, bc, d, e, f, g, h, w8, 0x983e5152)

	w9 = sha256Schedule(w7, w2, w10, w9)

	c, g, bc = sha256Round(h, a, bc, c, d, e, f, g, w9, 0xa831c66d)

	w10 = sha256Schedule(w8, w3, w11, w10)

	b, f, bc = sha256Round(g, h, bc, b, c, d, e, f, w10, 0xb00327c8)

	w11 = sha256Schedule(w9, w4, w12, w11)

	a, e, bc = sha256Round(f, g, bc, a, b, c, d, e, w11, 0xbf597fc7)

	w12 = sha256Schedule(w10, w5, w13, w12)

	h, d, bc = sha256Round(e, f, bc, h, a, b, c, d, w12, 0xc6e00bf3)

	w13 = sha256Schedule(w11, w6, w14, w13)

	g, c, bc = sha256Round(d, e, bc, g, h, a, b, c, w13, 0xd5a79147)

	w14 = sha256Schedule(w12, w7, w15, w14)

	f, b, bc = sha256Round(c, d, bc, f, g, h, a, b, w14, 0x06ca6351)

	w15 = sha256Schedule(w13, w8, w0, w15)

	e, a, bc = sha256Round(b, c, bc, e, f, g, h, a, w15, 0x14292967)

	w0 = sha256Schedule(w14, w9, w1, w0)

	d, h, bc = sha256Round(a, b, bc, d, e, f, g, h, w0, 0x27b70a85)

	w1 = sha256Schedule(w15, w10, w2, w1)

	c, g, bc = sha256Round(h, a, bc, c, d, e, f, g, w1, 0x2e1b2138)

	w2 = sha256Schedule(w0, w11, w3, w2)

	b, f, bc = sha256Round(g, h, bc, b, c, d, e, f, w2, 0x4d2c6dfc)

	w3 = sha256Schedule(w1, w12, w4, w3)

	a, e, bc = sha256Round(f, g, bc, a, b, c, d, e, w3, 0x53380d13)

	w4 = sha256Schedule(w2, w13, w5, w4)

	h, d, bc = sha256Round(e, f, bc, h, a, b, c, d, w4, 0x650a7354)

	w5 = sha256Schedule(w3, w14, w6, w5)

	g, c, bc = sha256Round(d, e, bc, g, h, a, b, c, w5, 0x766a0abb)

	w6 = sha256Schedule(w4, w15, w7, w6)

	f, b, bc = sha256Round(c, d, bc, f, g, h, a, b, w6, 0x81c2c92e)

	w7 = sha256Schedule(w5, w0, w8, w7)

	e, a, bc = sha256Round(b, c, bc, e, f, g, h, a, w7, 0x92722c85)

	w8 = sha256Schedule(w6, w1, w9, w8)

	d, h, bc = sha256Round(a, b, bc, d, e, f, g, h, w8, 0xa2bfe8a1)

	w9 = sha256Schedule(w7, w2, w10, w9)

	c, g, bc = sha256Round(h, a, bc, c, d, e, f, g, w9, 0xa81a664b)

	w10 = sha256Schedule(w8, w3, w11, w10)

	b, f, bc = sha256Round(g, h, bc, b, c, d, e, f, w10, 0xc24b8b70)

	w11 = sha256Schedule(w9, w4, w12, w11)

	a, e, bc = sha256Round(f, g, bc, a, b, c, d, e, w11, 0xc76c51a3)

	w12 = sha256Schedule(w10, w5, w13, w12)

	h, d, bc = sha256Round(e, f, bc, h, a, b, c, d, w12, 0xd192e819)

	w13 = sha256Schedule(w11, w6, w14, w13)

	g, c, bc = sha256Round(d, e, bc, g, h, a, b, c, w13, 0xd6990624)

	w14 = sha256Schedule(w12, w7, w15, w14)

	f, b, bc = sha256Round(c, d, bc, f, g, h, a, b, w14, 0xf40e3585)

	w15 = sha256Schedule(w13, w8, w0, w15)

	e, a, bc = sha256Round(b, c, bc, e, f, g, h, a, w15, 0x106aa070)

	w0 = sha256Schedule(w14, w9, w1, w0)

	d, h, bc = sha256Round(a, b, bc, d, e, f, g, h, w0, 0x19a4c116)

	w1 = sha256Schedule(w15, w10, w2, w1)

	c, g, bc = sha256Round(h, a, bc, c, d, e, f, g, w1, 0x1e376c08)

	w2 = sha256Schedule(w0, w11, w3, w2)

	b, f, bc = sha256Round(g, h, bc, b, c, d, e, f, w2, 0x2748774c)

	w3 = sha256Schedule(w1, w12, w4, w3)

	a, e, bc = sha256Round(f, g, bc, a, b, c, d, e, w3, 0x34b0bcb5)

	w4 = sha256Schedule(w2, w13, w5, w4)

	h, d, bc = sha256Round(e, f, bc, h, a, b, c, d, w4, 0x391c0cb3)

	w5 = sha256Schedule(w3, w14, w6, w5)

	g, c, bc = sha256Round(d, e, bc, g, h, a, b, c, w5, 0x4ed8aa4a)

	w6 = sha256Schedule(w4, w15, w7, w6)

	f, b, bc = sha256Round(c, d, bc, f, g, h, a, b, w6, 0x5b9cca4f)

	w7 = sha256Schedule(w5, w0, w8, w7)

	e, a, bc = sha256Round(b, c, bc, e, f, g, h, a, w7, 0x682e6ff3)

	w8 = sha256Schedule(w6, w1, w9, w8)

	d, h, bc = sha256Round(a, b, bc, d, e, f, g, h, w8, 0x748f82ee)

	w9 = sha256Schedule(w7, w2, w10, w9)

	c, g, bc = sha256Round(h, a, bc, c, d, e, f, g, w9, 0x78a5636f)

	w10 = sha256Schedule(w8, w3, w11, w10)

	b, f, bc = sha256Round(g, h, bc, b, c, d, e, f, w10, 0x84c87814)

	w11 = sha256Schedule(w9, w4, w12, w11)

	a, e, bc = sha256Round(f, g, bc, a, b, c, d, e, w11, 0x8cc70208)

	w12 = sha256Schedule(w10, w5, w13, w12)

	h, d, bc = sha256Round(e, f, bc, h, a, b, c, d, w12, 0x90befffa)

	w13 = sha256Schedule(w11, w6, w14, w13)

	g, c, bc = sha256Round(d, e, bc, g, h, a, b, c, w13, 0xa4506ceb)

	w14 = sha256Schedule(w12, w7, w15, w14)

	f, b, bc = sha256Round(c, d, bc, f, g, h, a, b, w14, 0xbef9a3f7)

	w15 = sha256Schedule(w13, w8, w0, w15)

	e, a, bc = sha256Round(b, c, bc, e, f, g, h, a, w15, 0xc67178f2)

	*state = [8]uint32{state[0] + a, state[1] + b, state[2] + c, state[3] + d, state[4] + e, state[5] + f, state[6] + g, state[7] + h}
}

// Every whole 64-byte block of p is compressed into state. Each block is copied to the stack
// and indexed there directly, so that the race detector checks one range per block rather
// than every byte. This is the portable form of compress256.
func compress256Generic(state *[8]uint32, p []byte) {
	s := *state

	var block [64]byte

	var w [16]uint32

	for ; len(p) >= 64; p = p[64:] {
		copy(block[:], p)

		for i := range w {
			w[i] = uint32(block[4*i])<<24 | uint32(block[4*i+1])<<16 | uint32(block[4*i+2])<<8 | uint32(block[4*i+3])
		}

		sha256BlockGeneric(&s, &w)
	}

	*state = s
}

// Lane kernels take out / outWords lanes of blockWords words each. Other sizes are a bug in the
// caller, stopped here before assembly could read past a slice.
func checkLanes(blocks, blockWords, out, outWords int) {
	if blockWords <= 0 || out%outWords != 0 || blocks != out/outWords*blockWords {
		panic("cryptopq: internal error: lane buffers of mismatched sizes")
	}
}

// A lane record of sha256Chains: the block template in words 0-15, the chain value in 16-23 (its
// length in words, then zeros), the first step in 24 and the number of steps in 25.
const chainRecord = 32

// The masks that keep the value words of a chain value of 4, 6 or 8 words.
var chainMasks = [3][8]uint32{
	{^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0)},
	{^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0)},
	{^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0)},
}

func checkChains(lanes []uint32, words int, shift uint) {
	if len(lanes)%chainRecord != 0 || words != 4 && words != 6 && words != 8 || shift != 16 && shift != 24 {
		panic("cryptopq: internal error: malformed chain lanes")
	}
}

// The block of a chain step: the template, with the step counter in the bits of word 5 above the
// value and the value's words shifted right by shift bits from word 5 on. SLH-DSA (shift 16) and
// LM-OTS (shift 24) place the value two and three bytes into word 5.
func chainBlock(w *[16]uint32, record []uint32, step uint32, shift uint) {
	copy(w[:], record[:16])

	v := record[16:24]

	c := 32 - shift

	w[5] |= step<<c | v[0]>>shift

	for m := 1; m < 8; m++ {
		w[5+m] |= v[m-1]<<c | v[m]>>shift
	}

	w[13] |= v[7] << c
}

// The portable form of sha256Chains: every lane runs its steps in turn, one sha256Block each.
func sha256ChainsSerial(init *[8]uint32, lanes []uint32, words int, shift uint) {
	var w [16]uint32

	for r := 0; r < len(lanes); r += chainRecord {
		record := lanes[r : r+chainRecord]

		start, count := record[24], record[25]

		for step := start; step < start+count; step++ {
			chainBlock(&w, record, step, shift)

			state := *init

			sha256Block(&state, &w)

			copy(record[16:16+words], state[:words])
		}
	}

	clear(w[:])
}

// sha256Chains through sha256Lanes: groups of up to 32 lanes go in lockstep, the lanes that take a
// step forming one batch, whose independent blocks a CPU can overlap.
func sha256ChainsLockstep(init *[8]uint32, lanes []uint32, words int, shift uint) {
	var blocks [32 * 16]uint32

	var out [32 * 8]uint32

	var active [32]int

	for first := 0; first < len(lanes); first += 32 * chainRecord {
		group := lanes[first:min(first+32*chainRecord, len(lanes))]

		for step := uint32(0); ; step++ {
			count := 0

			for r := 0; r < len(group); r += chainRecord {
				if record := group[r : r+chainRecord]; step < record[25] {
					chainBlock((*[16]uint32)(blocks[16*count:]), record, record[24]+step, shift)

					active[count] = r

					count++
				}
			}

			if count == 0 {
				break
			}

			sha256Lanes(init, blocks[:16*count], 1, out[:8*count])

			for k, r := range active[:count] {
				copy(group[r+16:r+16+words], out[8*k:8*k+words])
			}
		}
	}

	clear(blocks[:])

	clear(out[:])
}

// The portable form of sha256Lanes: lane i starts from init, compresses the nb blocks of words at
// blocks[16 nb i:] and leaves its state in out[8i:8i + 8].
func sha256LanesGeneric(init *[8]uint32, blocks []uint32, nb int, out []uint32) {
	for lane := range len(out) / 8 {
		state := *init

		for b := range nb {
			sha256BlockGeneric(&state, (*[16]uint32)(blocks[16*(nb*lane+b):]))
		}

		copy(out[8*lane:8*lane+8], state[:])
	}
}

// The SHA-512 counterpart of sha256Round.
func sha512Round(a, b, bc, d, e, f, g, h, w, k uint64) (uint64, uint64, uint64) {
	t1 := h + k + w + e&f + g&^e + (bits.RotateLeft64(e, -14) ^ bits.RotateLeft64(e, -18) ^ bits.RotateLeft64(e, -41))

	ab := a ^ b

	return d + t1, t1 + (bits.RotateLeft64(a, -28) ^ bits.RotateLeft64(a, -34) ^ bits.RotateLeft64(a, -39)) + (ab&bc ^ b), ab
}

func sha512Schedule(w2, w7, w15, w16 uint64) uint64 {
	return (bits.RotateLeft64(w2, -19) ^ bits.RotateLeft64(w2, -61) ^ w2>>6) + w7 + (bits.RotateLeft64(w15, -1) ^ bits.RotateLeft64(w15, -8) ^ w15>>7) + w16
}

// The 80 rounds of SHA-512 on one block, unrolled like sha256BlockGeneric; the portable form of
// sha512Block.
func sha512BlockGeneric(state *[8]uint64, w *[16]uint64) {
	a, b, c, d, e, f, g, h := state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]

	w0, w1, w2, w3, w4, w5, w6, w7 := w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]

	w8, w9, w10, w11, w12, w13, w14, w15 := w[8], w[9], w[10], w[11], w[12], w[13], w[14], w[15]

	bc := b ^ c

	d, h, bc = sha512Round(a, b, bc, d, e, f, g, h, w0, 0x428a2f98d728ae22)

	c, g, bc = sha512Round(h, a, bc, c, d, e, f, g, w1, 0x7137449123ef65cd)

	b, f, bc = sha512Round(g, h, bc, b, c, d, e, f, w2, 0xb5c0fbcfec4d3b2f)

	a, e, bc = sha512Round(f, g, bc, a, b, c, d, e, w3, 0xe9b5dba58189dbbc)

	h, d, bc = sha512Round(e, f, bc, h, a, b, c, d, w4, 0x3956c25bf348b538)

	g, c, bc = sha512Round(d, e, bc, g, h, a, b, c, w5, 0x59f111f1b605d019)

	f, b, bc = sha512Round(c, d, bc, f, g, h, a, b, w6, 0x923f82a4af194f9b)

	e, a, bc = sha512Round(b, c, bc, e, f, g, h, a, w7, 0xab1c5ed5da6d8118)

	d, h, bc = sha512Round(a, b, bc, d, e, f, g, h, w8, 0xd807aa98a3030242)

	c, g, bc = sha512Round(h, a, bc, c, d, e, f, g, w9, 0x12835b0145706fbe)

	b, f, bc = sha512Round(g, h, bc, b, c, d, e, f, w10, 0x243185be4ee4b28c)

	a, e, bc = sha512Round(f, g, bc, a, b, c, d, e, w11, 0x550c7dc3d5ffb4e2)

	h, d, bc = sha512Round(e, f, bc, h, a, b, c, d, w12, 0x72be5d74f27b896f)

	g, c, bc = sha512Round(d, e, bc, g, h, a, b, c, w13, 0x80deb1fe3b1696b1)

	f, b, bc = sha512Round(c, d, bc, f, g, h, a, b, w14, 0x9bdc06a725c71235)

	e, a, bc = sha512Round(b, c, bc, e, f, g, h, a, w15, 0xc19bf174cf692694)

	w0 = sha512Schedule(w14, w9, w1, w0)

	d, h, bc = sha512Round(a, b, bc, d, e, f, g, h, w0, 0xe49b69c19ef14ad2)

	w1 = sha512Schedule(w15, w10, w2, w1)

	c, g, bc = sha512Round(h, a, bc, c, d, e, f, g, w1, 0xefbe4786384f25e3)

	w2 = sha512Schedule(w0, w11, w3, w2)

	b, f, bc = sha512Round(g, h, bc, b, c, d, e, f, w2, 0x0fc19dc68b8cd5b5)

	w3 = sha512Schedule(w1, w12, w4, w3)

	a, e, bc = sha512Round(f, g, bc, a, b, c, d, e, w3, 0x240ca1cc77ac9c65)

	w4 = sha512Schedule(w2, w13, w5, w4)

	h, d, bc = sha512Round(e, f, bc, h, a, b, c, d, w4, 0x2de92c6f592b0275)

	w5 = sha512Schedule(w3, w14, w6, w5)

	g, c, bc = sha512Round(d, e, bc, g, h, a, b, c, w5, 0x4a7484aa6ea6e483)

	w6 = sha512Schedule(w4, w15, w7, w6)

	f, b, bc = sha512Round(c, d, bc, f, g, h, a, b, w6, 0x5cb0a9dcbd41fbd4)

	w7 = sha512Schedule(w5, w0, w8, w7)

	e, a, bc = sha512Round(b, c, bc, e, f, g, h, a, w7, 0x76f988da831153b5)

	w8 = sha512Schedule(w6, w1, w9, w8)

	d, h, bc = sha512Round(a, b, bc, d, e, f, g, h, w8, 0x983e5152ee66dfab)

	w9 = sha512Schedule(w7, w2, w10, w9)

	c, g, bc = sha512Round(h, a, bc, c, d, e, f, g, w9, 0xa831c66d2db43210)

	w10 = sha512Schedule(w8, w3, w11, w10)

	b, f, bc = sha512Round(g, h, bc, b, c, d, e, f, w10, 0xb00327c898fb213f)

	w11 = sha512Schedule(w9, w4, w12, w11)

	a, e, bc = sha512Round(f, g, bc, a, b, c, d, e, w11, 0xbf597fc7beef0ee4)

	w12 = sha512Schedule(w10, w5, w13, w12)

	h, d, bc = sha512Round(e, f, bc, h, a, b, c, d, w12, 0xc6e00bf33da88fc2)

	w13 = sha512Schedule(w11, w6, w14, w13)

	g, c, bc = sha512Round(d, e, bc, g, h, a, b, c, w13, 0xd5a79147930aa725)

	w14 = sha512Schedule(w12, w7, w15, w14)

	f, b, bc = sha512Round(c, d, bc, f, g, h, a, b, w14, 0x06ca6351e003826f)

	w15 = sha512Schedule(w13, w8, w0, w15)

	e, a, bc = sha512Round(b, c, bc, e, f, g, h, a, w15, 0x142929670a0e6e70)

	w0 = sha512Schedule(w14, w9, w1, w0)

	d, h, bc = sha512Round(a, b, bc, d, e, f, g, h, w0, 0x27b70a8546d22ffc)

	w1 = sha512Schedule(w15, w10, w2, w1)

	c, g, bc = sha512Round(h, a, bc, c, d, e, f, g, w1, 0x2e1b21385c26c926)

	w2 = sha512Schedule(w0, w11, w3, w2)

	b, f, bc = sha512Round(g, h, bc, b, c, d, e, f, w2, 0x4d2c6dfc5ac42aed)

	w3 = sha512Schedule(w1, w12, w4, w3)

	a, e, bc = sha512Round(f, g, bc, a, b, c, d, e, w3, 0x53380d139d95b3df)

	w4 = sha512Schedule(w2, w13, w5, w4)

	h, d, bc = sha512Round(e, f, bc, h, a, b, c, d, w4, 0x650a73548baf63de)

	w5 = sha512Schedule(w3, w14, w6, w5)

	g, c, bc = sha512Round(d, e, bc, g, h, a, b, c, w5, 0x766a0abb3c77b2a8)

	w6 = sha512Schedule(w4, w15, w7, w6)

	f, b, bc = sha512Round(c, d, bc, f, g, h, a, b, w6, 0x81c2c92e47edaee6)

	w7 = sha512Schedule(w5, w0, w8, w7)

	e, a, bc = sha512Round(b, c, bc, e, f, g, h, a, w7, 0x92722c851482353b)

	w8 = sha512Schedule(w6, w1, w9, w8)

	d, h, bc = sha512Round(a, b, bc, d, e, f, g, h, w8, 0xa2bfe8a14cf10364)

	w9 = sha512Schedule(w7, w2, w10, w9)

	c, g, bc = sha512Round(h, a, bc, c, d, e, f, g, w9, 0xa81a664bbc423001)

	w10 = sha512Schedule(w8, w3, w11, w10)

	b, f, bc = sha512Round(g, h, bc, b, c, d, e, f, w10, 0xc24b8b70d0f89791)

	w11 = sha512Schedule(w9, w4, w12, w11)

	a, e, bc = sha512Round(f, g, bc, a, b, c, d, e, w11, 0xc76c51a30654be30)

	w12 = sha512Schedule(w10, w5, w13, w12)

	h, d, bc = sha512Round(e, f, bc, h, a, b, c, d, w12, 0xd192e819d6ef5218)

	w13 = sha512Schedule(w11, w6, w14, w13)

	g, c, bc = sha512Round(d, e, bc, g, h, a, b, c, w13, 0xd69906245565a910)

	w14 = sha512Schedule(w12, w7, w15, w14)

	f, b, bc = sha512Round(c, d, bc, f, g, h, a, b, w14, 0xf40e35855771202a)

	w15 = sha512Schedule(w13, w8, w0, w15)

	e, a, bc = sha512Round(b, c, bc, e, f, g, h, a, w15, 0x106aa07032bbd1b8)

	w0 = sha512Schedule(w14, w9, w1, w0)

	d, h, bc = sha512Round(a, b, bc, d, e, f, g, h, w0, 0x19a4c116b8d2d0c8)

	w1 = sha512Schedule(w15, w10, w2, w1)

	c, g, bc = sha512Round(h, a, bc, c, d, e, f, g, w1, 0x1e376c085141ab53)

	w2 = sha512Schedule(w0, w11, w3, w2)

	b, f, bc = sha512Round(g, h, bc, b, c, d, e, f, w2, 0x2748774cdf8eeb99)

	w3 = sha512Schedule(w1, w12, w4, w3)

	a, e, bc = sha512Round(f, g, bc, a, b, c, d, e, w3, 0x34b0bcb5e19b48a8)

	w4 = sha512Schedule(w2, w13, w5, w4)

	h, d, bc = sha512Round(e, f, bc, h, a, b, c, d, w4, 0x391c0cb3c5c95a63)

	w5 = sha512Schedule(w3, w14, w6, w5)

	g, c, bc = sha512Round(d, e, bc, g, h, a, b, c, w5, 0x4ed8aa4ae3418acb)

	w6 = sha512Schedule(w4, w15, w7, w6)

	f, b, bc = sha512Round(c, d, bc, f, g, h, a, b, w6, 0x5b9cca4f7763e373)

	w7 = sha512Schedule(w5, w0, w8, w7)

	e, a, bc = sha512Round(b, c, bc, e, f, g, h, a, w7, 0x682e6ff3d6b2b8a3)

	w8 = sha512Schedule(w6, w1, w9, w8)

	d, h, bc = sha512Round(a, b, bc, d, e, f, g, h, w8, 0x748f82ee5defb2fc)

	w9 = sha512Schedule(w7, w2, w10, w9)

	c, g, bc = sha512Round(h, a, bc, c, d, e, f, g, w9, 0x78a5636f43172f60)

	w10 = sha512Schedule(w8, w3, w11, w10)

	b, f, bc = sha512Round(g, h, bc, b, c, d, e, f, w10, 0x84c87814a1f0ab72)

	w11 = sha512Schedule(w9, w4, w12, w11)

	a, e, bc = sha512Round(f, g, bc, a, b, c, d, e, w11, 0x8cc702081a6439ec)

	w12 = sha512Schedule(w10, w5, w13, w12)

	h, d, bc = sha512Round(e, f, bc, h, a, b, c, d, w12, 0x90befffa23631e28)

	w13 = sha512Schedule(w11, w6, w14, w13)

	g, c, bc = sha512Round(d, e, bc, g, h, a, b, c, w13, 0xa4506cebde82bde9)

	w14 = sha512Schedule(w12, w7, w15, w14)

	f, b, bc = sha512Round(c, d, bc, f, g, h, a, b, w14, 0xbef9a3f7b2c67915)

	w15 = sha512Schedule(w13, w8, w0, w15)

	e, a, bc = sha512Round(b, c, bc, e, f, g, h, a, w15, 0xc67178f2e372532b)

	w0 = sha512Schedule(w14, w9, w1, w0)

	d, h, bc = sha512Round(a, b, bc, d, e, f, g, h, w0, 0xca273eceea26619c)

	w1 = sha512Schedule(w15, w10, w2, w1)

	c, g, bc = sha512Round(h, a, bc, c, d, e, f, g, w1, 0xd186b8c721c0c207)

	w2 = sha512Schedule(w0, w11, w3, w2)

	b, f, bc = sha512Round(g, h, bc, b, c, d, e, f, w2, 0xeada7dd6cde0eb1e)

	w3 = sha512Schedule(w1, w12, w4, w3)

	a, e, bc = sha512Round(f, g, bc, a, b, c, d, e, w3, 0xf57d4f7fee6ed178)

	w4 = sha512Schedule(w2, w13, w5, w4)

	h, d, bc = sha512Round(e, f, bc, h, a, b, c, d, w4, 0x06f067aa72176fba)

	w5 = sha512Schedule(w3, w14, w6, w5)

	g, c, bc = sha512Round(d, e, bc, g, h, a, b, c, w5, 0x0a637dc5a2c898a6)

	w6 = sha512Schedule(w4, w15, w7, w6)

	f, b, bc = sha512Round(c, d, bc, f, g, h, a, b, w6, 0x113f9804bef90dae)

	w7 = sha512Schedule(w5, w0, w8, w7)

	e, a, bc = sha512Round(b, c, bc, e, f, g, h, a, w7, 0x1b710b35131c471b)

	w8 = sha512Schedule(w6, w1, w9, w8)

	d, h, bc = sha512Round(a, b, bc, d, e, f, g, h, w8, 0x28db77f523047d84)

	w9 = sha512Schedule(w7, w2, w10, w9)

	c, g, bc = sha512Round(h, a, bc, c, d, e, f, g, w9, 0x32caab7b40c72493)

	w10 = sha512Schedule(w8, w3, w11, w10)

	b, f, bc = sha512Round(g, h, bc, b, c, d, e, f, w10, 0x3c9ebe0a15c9bebc)

	w11 = sha512Schedule(w9, w4, w12, w11)

	a, e, bc = sha512Round(f, g, bc, a, b, c, d, e, w11, 0x431d67c49c100d4c)

	w12 = sha512Schedule(w10, w5, w13, w12)

	h, d, bc = sha512Round(e, f, bc, h, a, b, c, d, w12, 0x4cc5d4becb3e42b6)

	w13 = sha512Schedule(w11, w6, w14, w13)

	g, c, bc = sha512Round(d, e, bc, g, h, a, b, c, w13, 0x597f299cfc657e2a)

	w14 = sha512Schedule(w12, w7, w15, w14)

	f, b, bc = sha512Round(c, d, bc, f, g, h, a, b, w14, 0x5fcb6fab3ad6faec)

	w15 = sha512Schedule(w13, w8, w0, w15)

	e, a, bc = sha512Round(b, c, bc, e, f, g, h, a, w15, 0x6c44198c4a475817)

	*state = [8]uint64{state[0] + a, state[1] + b, state[2] + c, state[3] + d, state[4] + e, state[5] + f, state[6] + g, state[7] + h}
}

// Every whole 128-byte block of p is compressed into state, read from a stack copy as in
// compress256Generic; the portable form of compress512.
func compress512Generic(state *[8]uint64, p []byte) {
	s := *state

	var block [128]byte

	var w [16]uint64

	for ; len(p) >= 128; p = p[128:] {
		copy(block[:], p)

		for i := range w {
			w[i] = uint64(block[8*i])<<56 | uint64(block[8*i+1])<<48 | uint64(block[8*i+2])<<40 | uint64(block[8*i+3])<<32 |
				uint64(block[8*i+4])<<24 | uint64(block[8*i+5])<<16 | uint64(block[8*i+6])<<8 | uint64(block[8*i+7])
		}

		sha512BlockGeneric(&s, &w)
	}

	*state = s
}

type sha256Engine struct {
	state  [8]uint32
	buffer [64]byte
	used   int
	length uint64
	size   int
}

func newSha256(iv *[8]uint32, size int) *sha256Engine {
	return &sha256Engine{state: *iv, size: size}
}

// The digest of data into out, on an engine that stays on the stack.
func sha256DigestInto(iv *[8]uint32, data, out []byte) {
	e := sha256Engine{state: *iv, size: len(out)}

	e.update(data)

	e.digestInto(out)
}

func (e *sha256Engine) update(data []byte) {
	e.length += uint64(len(data))

	if e.used > 0 {
		n := copy(e.buffer[e.used:], data)

		e.used += n

		data = data[n:]

		if e.used < len(e.buffer) {
			return
		}

		compress256(&e.state, e.buffer[:])

		e.used = 0
	}

	if n := len(data) &^ (len(e.buffer) - 1); n > 0 {
		compress256(&e.state, data[:n])

		data = data[n:]
	}

	e.used = copy(e.buffer[:], data)
}

// FIPS 180-4, 5.1: the 0x80 marker, zeros, then the message length in bits, big-endian.
func (e *sha256Engine) digest() []byte {
	out := make([]byte, e.size)

	e.digestInto(out)

	return out
}

func (e *sha256Engine) digestInto(out []byte) {
	state := e.state

	var tail [128]byte

	copy(tail[:], e.buffer[:e.used])

	tail[e.used] = 0x80

	end := 64

	if e.used+1+8 > 64 {
		end = 128
	}

	binary.BigEndian.PutUint64(tail[end-8:], e.length*8)

	compress256(&state, tail[:end])

	var full [32]byte

	for i, word := range state {
		binary.BigEndian.PutUint32(full[4*i:], word)
	}

	copy(out, full[:e.size])
}

func (e *sha256Engine) clone() engine {
	copied := *e

	return &copied
}

type sha512Engine struct {
	state  [8]uint64
	buffer [128]byte
	used   int
	length uint64
	size   int
}

func newSha512(iv *[8]uint64, size int) *sha512Engine {
	return &sha512Engine{state: *iv, size: size}
}

// The digest of data into out, on an engine that stays on the stack.
func sha512DigestInto(iv *[8]uint64, data, out []byte) {
	e := sha512Engine{state: *iv, size: len(out)}

	e.update(data)

	e.digestInto(out)
}

func (e *sha512Engine) update(data []byte) {
	e.length += uint64(len(data))

	if e.used > 0 {
		n := copy(e.buffer[e.used:], data)

		e.used += n

		data = data[n:]

		if e.used < len(e.buffer) {
			return
		}

		compress512(&e.state, e.buffer[:])

		e.used = 0
	}

	if n := len(data) &^ (len(e.buffer) - 1); n > 0 {
		compress512(&e.state, data[:n])

		data = data[n:]
	}

	e.used = copy(e.buffer[:], data)
}

// The 128-bit length field holds length*8; its upper half is length>>61.
func (e *sha512Engine) digest() []byte {
	out := make([]byte, e.size)

	e.digestInto(out)

	return out
}

func (e *sha512Engine) digestInto(out []byte) {
	state := e.state

	var tail [256]byte

	copy(tail[:], e.buffer[:e.used])

	tail[e.used] = 0x80

	end := 128

	if e.used+1+16 > 128 {
		end = 256
	}

	binary.BigEndian.PutUint64(tail[end-16:], e.length>>61)

	binary.BigEndian.PutUint64(tail[end-8:], e.length*8)

	compress512(&state, tail[:end])

	var full [64]byte

	for i, word := range state {
		binary.BigEndian.PutUint64(full[8*i:], word)
	}

	copy(out, full[:e.size])
}

func (e *sha512Engine) clone() engine {
	copied := *e

	return &copied
}

// Completes a SHA-256 hash whose first absorbed bytes, a multiple of 64, are already compressed
// into state, and writes the first len(out) bytes of the digest. Nothing is allocated, and the
// stack buffers are indexed directly for the race detector's sake, as in compress256.
func sha256Finish(state [8]uint32, absorbed int, data, out []byte) {
	whole := len(data) &^ 63

	compress256(&state, data[:whole])

	var tail [128]byte

	used := copy(tail[:], data[whole:])

	tail[used] = 0x80

	end := 64

	if used+1+8 > 64 {
		end = 128
	}

	length := uint64(absorbed+len(data)) * 8

	for i := range 8 {
		tail[end-1-i] = byte(length >> (8 * i))
	}

	compress256(&state, tail[:end])

	var digest [32]byte

	for i, word := range state {
		digest[4*i], digest[4*i+1], digest[4*i+2], digest[4*i+3] = byte(word>>24), byte(word>>16), byte(word>>8), byte(word)
	}

	copy(out, digest[:])
}

// The SHA-512 counterpart of sha256Finish, with 128-byte blocks; absorbed stays below 2^61.
func sha512Finish(state [8]uint64, absorbed int, data, out []byte) {
	whole := len(data) &^ 127

	compress512(&state, data[:whole])

	var tail [256]byte

	used := copy(tail[:], data[whole:])

	tail[used] = 0x80

	end := 128

	if used+1+16 > 128 {
		end = 256
	}

	length := uint64(absorbed+len(data)) * 8

	for i := range 8 {
		tail[end-1-i] = byte(length >> (8 * i))
	}

	compress512(&state, tail[:end])

	var digest [64]byte

	for i, word := range state {
		for j := range 8 {
			digest[8*i+j] = byte(word >> (56 - 8*j))
		}
	}

	copy(out, digest[:])
}

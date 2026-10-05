//go:build !purego

package cryptopq

import "encoding/binary"

//go:noescape
func x25519MULX(out *[32]byte, work *[17][4]uint64)

// The ladder in assembly with 64-bit limbs where the CPU has BMI2 and ADX, as on arm64; the
// workspace holds the clamped scalar and every intermediate value, so it is cleared after.
func x25519(scalar, u []byte) [32]byte {
	if !x86.mulx {
		return x25519Generic(scalar, u)
	}

	var work [17][4]uint64

	for i := range 4 {
		work[0][i] = binary.LittleEndian.Uint64(u[8*i:])
	}

	work[0][3] &= 1<<63 - 1

	work[1][0], work[3], work[4][0] = 1, work[0], 1

	var k [32]byte

	copy(k[:], scalar)

	k[0] &= 248

	k[31] &= 127

	k[31] |= 64

	for i := range 4 {
		work[15][i] = binary.LittleEndian.Uint64(k[8*i:])
	}

	var out [32]byte

	x25519MULX(&out, &work)

	clear(work[:])

	clear(k[:])

	return out
}

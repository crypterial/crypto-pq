//go:build !purego

package cryptopq

import "encoding/binary"

//go:noescape
func x25519ADX(out *[32]byte, work *[17][4]uint64)

//go:noescape
func x25519BMI2(out *[32]byte, work *[17][4]uint64)

//go:noescape
func x25519BaseADX(out *[32]byte, digits *[64]int8, work *[19][4]uint64)

//go:noescape
func x25519BaseBMI2(out *[32]byte, digits *[64]int8, work *[19][4]uint64)

// The ladder in assembly with 64-bit limbs where the CPU has BMI2, as on arm64: with ADX the
// products carry two chains at once, without it one.
func x25519(scalar, u []byte) [32]byte {
	switch {
	case x86.mulx:
		return x25519Ladder(scalar, u, true)
	case useAVX2BMI2:
		return x25519Ladder(scalar, u, false)
	}

	return x25519Generic(scalar, u)
}

// The workspace holds the clamped scalar and every intermediate value, so it is cleared after.
func x25519Ladder(scalar, u []byte, adx bool) [32]byte {
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

	if adx {
		x25519ADX(&out, &work)
	} else {
		x25519BMI2(&out, &work)
	}

	clear(work[:])

	clear(k[:])

	return out
}

// The comb of x25519BaseGeneric in assembly, which selects the table entries with AVX2.
func x25519Base(scalar []byte) [32]byte {
	if !useAVX2BMI2 {
		return x25519BaseGeneric(scalar)
	}

	return x25519Comb(scalar, x86.adx)
}

// The digits and the workspace are secret, so they are cleared after.
func x25519Comb(scalar []byte, adx bool) [32]byte {
	var digits [64]int8

	x25519BaseDigits(scalar, &digits)

	var work [19][4]uint64

	var out [32]byte

	if adx {
		x25519BaseADX(&out, &digits, &work)
	} else {
		x25519BaseBMI2(&out, &digits, &work)
	}

	clear(work[:])

	clear(digits[:])

	return out
}

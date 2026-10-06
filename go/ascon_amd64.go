//go:build !purego

package cryptopq

//go:noescape
func asconPermuteAMD(s *[5]uint64)

//go:noescape
func asconAbsorbAMD(s *[5]uint64, data []byte)

// The kernels need only the base instruction set.

func asconPermute(s *[5]uint64) {
	asconPermuteAMD(s)
}

// XORs each whole 8-byte word of data into S0 and permutes after it.
func asconAbsorbWords(s *[5]uint64, data []byte) {
	if n := len(data) &^ 7; n > 0 {
		asconAbsorbAMD(s, data[:n])
	}
}

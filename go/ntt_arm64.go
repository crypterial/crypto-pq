//go:build !purego

package cryptopq

//go:noescape
func dsaNTTARM(w *[256]uint32)

//go:noescape
func dsaInverseNTTARM(w *[256]uint32)

//go:noescape
func kemNTTARM(f *[256]uint16)

//go:noescape
func kemInverseNTTARM(f *[256]uint16)

// Every arm64 CPU has NEON (Advanced SIMD), so these need no detection.

func dsaNTT(w *dsaPoly) {
	dsaNTTARM((*[256]uint32)(w))
}

func dsaInverseNTT(w *dsaPoly) {
	dsaInverseNTTARM((*[256]uint32)(w))
}

func kemNTT(f *kemPoly) {
	kemNTTARM((*[256]uint16)(f))
}

func kemInverseNTT(f *kemPoly) {
	kemInverseNTTARM((*[256]uint16)(f))
}

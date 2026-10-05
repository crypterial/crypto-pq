//go:build (!arm64 && !amd64) || purego

package cryptopq

func dsaNTT(w *dsaPoly) {
	dsaNTTGeneric(w)
}

func dsaInverseNTT(w *dsaPoly) {
	dsaInverseNTTGeneric(w)
}

func kemNTT(f *kemPoly) {
	kemNTTGeneric(f)
}

func kemInverseNTT(f *kemPoly) {
	kemInverseNTTGeneric(f)
}

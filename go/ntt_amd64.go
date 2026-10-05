//go:build !purego

package cryptopq

//go:noescape
func kemNTTAVX2(f *[256]uint16)

//go:noescape
func kemInverseNTTAVX2(f *[256]uint16)

//go:noescape
func dsaNTTAVX2(w *[256]uint32)

//go:noescape
func dsaInverseNTTAVX2(w *[256]uint32)

func kemNTT(f *kemPoly) {
	if !useAVX2 {
		kemNTTGeneric(f)

		return
	}

	kemNTTAVX2((*[256]uint16)(f))
}

func kemInverseNTT(f *kemPoly) {
	if !useAVX2 {
		kemInverseNTTGeneric(f)

		return
	}

	kemInverseNTTAVX2((*[256]uint16)(f))
}

func dsaNTT(w *dsaPoly) {
	if !useAVX2 {
		dsaNTTGeneric(w)

		return
	}

	dsaNTTAVX2((*[256]uint32)(w))
}

func dsaInverseNTT(w *dsaPoly) {
	if !useAVX2 {
		dsaInverseNTTGeneric(w)

		return
	}

	dsaInverseNTTAVX2((*[256]uint32)(w))
}

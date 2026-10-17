//go:build !amd64 || purego

package cryptopq

func dsaChallengeOne() uint32 {
	return 1
}

func dsaSparse() bool {
	return false
}

func dsaSparseProduct(d *[256]int16, starts *[64]uint16, n int, in []byte, eta int) {
	dsaSparseProductGeneric(d, starts, n, in, eta)
}

func dsaUnpackAdd(z *dsaPoly, in []byte, d *[256]int16, gamma1 uint32, width int, bound uint32) uint32 {
	return dsaUnpackAddGeneric(z, in, d, gamma1, width, bound)
}

func dsaSubSmallLow(w *dsaPoly, d *[256]int16, gamma2, bound uint32) uint32 {
	return dsaSubSmallLowGeneric(w, d, gamma2, bound)
}

func dsaRowProduct(out *dsaPoly, a, b []dsaPoly) {
	dsaRowProductGeneric(out, a, b)
}

func dsaRowProductSub(out *dsaPoly, a, b []dsaPoly, c, t *dsaPoly) {
	dsaRowProductSubGeneric(out, a, b, c, t)
}

func dsaProduct(out, c, s, y *dsaPoly) {
	dsaProductGeneric(out, c, s, y)
}

func dsaBeyond(w *dsaPoly, bound uint32) uint32 {
	return dsaBeyondGeneric(w, bound)
}

func dsaSubLow(w, p *dsaPoly, gamma2, bound uint32) uint32 {
	return dsaSubLowGeneric(w, p, gamma2, bound)
}

func dsaHints(hints *[4]uint64, w, p *dsaPoly, gamma2 uint32) (beyond, count uint32) {
	return dsaHintsGeneric(hints, w, p, gamma2)
}

func dsaHighBits(out []byte, w *dsaPoly, gamma2 uint32, width int) {
	dsaHighBitsGeneric(out[:32*width], w, gamma2, width)
}

// w is overwritten.
func dsaUseHints(out []byte, w *dsaPoly, hints *[4]uint64, gamma2 uint32, width int) {
	dsaUseHintsGeneric(out[:32*width], w, hints, gamma2, width)
}

func dsaUnpackGamma1(w *dsaPoly, in []byte, gamma1 uint32, width int) {
	dsaUnpack(w, in, gamma1, width)
}

func dsaPackGamma1(out []byte, w *dsaPoly, gamma1 uint32, width int) {
	dsaPack(out[:32*width], w, gamma1, width)
}

func dsaRejUniformLane(f *dsaPoly, count int, state *[25]uint64) int {
	return dsaRejUniformLaneGeneric(f, count, state)
}

func dsaPower2RoundPack(t1, t0 []byte, t *dsaPoly) {
	dsaPower2RoundPackGeneric(t1[:320], t0[:32*dsaD], t)
}

func dsaPackEta(out []byte, s *dsaPoly, eta, width int) {
	dsaPack(out[:32*width], s, uint32(eta), width)
}

func dsaUnpackT1(w *dsaPoly, in []byte) {
	dsaUnpackT1Generic(w, in)
}

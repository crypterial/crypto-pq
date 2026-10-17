//go:build !purego

package cryptopq

import "encoding/binary"

//go:noescape
func dsaDotAVX2(out, a, b *[256]uint32, n int)

//go:noescape
func dsaDotSubAVX2(out, a, b *[256]uint32, n int, c, t *[256]uint32)

//go:noescape
func dsaMulAVX2(out, a, b *[256]uint32)

//go:noescape
func dsaMulAddAVX2(out, a, b, y *[256]uint32)

//go:noescape
func dsaInverseNTTUnscaleAVX2(w *[256]uint32)

//go:noescape
func dsaBeyondAVX2(w *[256]uint32, bound uint32) uint32

//go:noescape
func dsaSubLow32AVX2(w, p *[256]uint32, bound uint32) uint32

//go:noescape
func dsaSubLow88AVX2(w, p *[256]uint32, bound uint32) uint32

//go:noescape
func dsaHints32AVX2(hints *[4]uint64, w, p *[256]uint32) (beyond, count uint32)

//go:noescape
func dsaHints88AVX2(hints *[4]uint64, w, p *[256]uint32) (beyond, count uint32)

//go:noescape
func dsaHighBits32AVX2(out *byte, w *[256]uint32)

//go:noescape
func dsaHighBits88AVX2(out *byte, w *[256]uint32)

//go:noescape
func dsaUseHints32AVX2(out *byte, w *[256]uint32, hints *[4]uint64)

//go:noescape
func dsaUseHints88AVX2(out *byte, w *[256]uint32, hints *[4]uint64)

//go:noescape
func dsaUnpack18AVX2(w *[256]uint32, in *byte)

//go:noescape
func dsaUnpack20AVX2(w *[256]uint32, in *byte)

//go:noescape
func dsaPack18AVX2(out *byte, w *[256]uint32)

//go:noescape
func dsaPack20AVX2(out *byte, w *[256]uint32)

//go:noescape
func dsaRejUniformAVX2(out *[256]uint32, count int, state *[25]uint64) (newCount, consumed int)

//go:noescape
func dsaPower2RoundAVX2(t1, t0 *byte, t *[256]uint32)

//go:noescape
func dsaUnpackT1AVX2(w *[256]uint32, in *byte)

//go:noescape
func dsaPackEta3AVX2(out *byte, s *[256]uint32)

//go:noescape
func dsaPackEta4AVX2(out *byte, s *[256]uint32)

//go:noescape
func dsaSparseAVX2(out *[256]int16, ext *[512]int16, starts *[64]uint16, n int)

//go:noescape
func dsaExtend3AVX2(ext *[512]int16, in *byte)

//go:noescape
func dsaExtend4AVX2(ext *[512]int16, in *byte)

//go:noescape
func dsaUnpackAdd18AVX2(z *[256]uint32, in *byte, d *[256]int16, bound uint32) uint32

//go:noescape
func dsaUnpackAdd20AVX2(z *[256]uint32, in *byte, d *[256]int16, bound uint32) uint32

//go:noescape
func dsaSubSmallLow32AVX2(w *[256]uint32, d *[256]int16, bound uint32) uint32

//go:noescape
func dsaSubSmallLow88AVX2(w *[256]uint32, d *[256]int16, bound uint32) uint32

// Whether signing multiplies the challenge by s1 and s2 as sparse polynomials, small integers in
// [-eta, eta], instead of through the NTT: with the kernels this skips the inverse NTTs of c s1
// and c s2.
func dsaSparse() bool {
	return useAVX2
}

// d = c s, small integers, for the challenge given by its window starts (dsaChallengeStarts) and
// the secret polynomial packed at in, of which the kernels read 130 bytes.
func dsaSparseProduct(d *[256]int16, starts *[64]uint16, n int, in []byte, eta int) {
	if !useAVX2 || len(in) < 130 {
		dsaSparseProductGeneric(d, starts, n, in, eta)

		return
	}

	var ext [512]int16

	if eta == 2 {
		dsaExtend3AVX2(&ext, &in[0])
	} else {
		dsaExtend4AVX2(&ext, &in[0])
	}

	dsaSparseAVX2(d, &ext, starts, min(n, len(starts)))

	clear(ext[:])
}

// z = y + d for y unpacked from in (BitUnpack with b = gamma1), and 1 when the centered absolute
// value of some coefficient of z reaches bound, otherwise 0.
func dsaUnpackAdd(z *dsaPoly, in []byte, d *[256]int16, gamma1 uint32, width int, bound uint32) uint32 {
	switch {
	case !useAVX2 || len(in) < 32*width+7:
		return dsaUnpackAddGeneric(z, in, d, gamma1, width, bound)
	case width == 18:
		return dsaUnpackAdd18AVX2((*[256]uint32)(z), &in[0], d, bound)
	default:
		return dsaUnpackAdd20AVX2((*[256]uint32)(z), &in[0], d, bound)
	}
}

// dsaSubLow with the small integers d.
func dsaSubSmallLow(w *dsaPoly, d *[256]int16, gamma2, bound uint32) uint32 {
	switch {
	case !useAVX2:
		return dsaSubSmallLowGeneric(w, d, gamma2, bound)
	case gamma2 == (dsaQ-1)/32:
		return dsaSubSmallLow32AVX2((*[256]uint32)(w), d, bound)
	default:
		return dsaSubSmallLow88AVX2((*[256]uint32)(w), d, bound)
	}
}

// The value of 1 in the challenge whose NTT meets the Montgomery products: with the kernels, its
// products then come out exact.
func dsaChallengeOne() uint32 {
	if !useAVX2 {
		return 1
	}

	return dsaMontR
}

// The row products take 4, 5 or 7 polynomials, ML-DSA's l; b may be longer than a.
func dsaRowFits(a, b []dsaPoly) bool {
	return (len(a) == 4 || len(a) == 5 || len(a) == 7) && len(b) >= len(a)
}

// NTT^-1 of the sum of a[j] b[j], a row of the matrix times a vector in the NTT domain.
func dsaRowProduct(out *dsaPoly, a, b []dsaPoly) {
	if !useAVX2 || !dsaRowFits(a, b) {
		dsaRowProductGeneric(out, a, b)

		return
	}

	dsaDotAVX2((*[256]uint32)(out), (*[256]uint32)(&a[0]), (*[256]uint32)(&b[0]), len(a))

	dsaInverseNTTUnscaleAVX2((*[256]uint32)(out))
}

// NTT^-1(sum of a[j] b[j] - c t), verification's row.
func dsaRowProductSub(out *dsaPoly, a, b []dsaPoly, c, t *dsaPoly) {
	if !useAVX2 || !dsaRowFits(a, b) {
		dsaRowProductSubGeneric(out, a, b, c, t)

		return
	}

	dsaDotSubAVX2((*[256]uint32)(out), (*[256]uint32)(&a[0]), (*[256]uint32)(&b[0]), len(a), (*[256]uint32)(c), (*[256]uint32)(t))

	dsaInverseNTTUnscaleAVX2((*[256]uint32)(out))
}

// NTT^-1(c s + y), or NTT^-1(c s) for a nil y, for the NTT of the challenge scaled by
// dsaChallengeOne (dsaScaleChallenge): the kernel's factor 2^-32 meets c's 2^32.
func dsaProduct(out, c, s, y *dsaPoly) {
	if !useAVX2 {
		dsaProductGeneric(out, c, s, y)

		return
	}

	if y == nil {
		dsaMulAVX2((*[256]uint32)(out), (*[256]uint32)(c), (*[256]uint32)(s))
	} else {
		dsaMulAddAVX2((*[256]uint32)(out), (*[256]uint32)(c), (*[256]uint32)(s), (*[256]uint32)(y))
	}

	dsaInverseNTT(out)
}

// 1 when the centered absolute value of some coefficient of w is at least bound, otherwise 0.
func dsaBeyond(w *dsaPoly, bound uint32) uint32 {
	if !useAVX2 {
		return dsaBeyondGeneric(w, bound)
	}

	return dsaBeyondAVX2((*[256]uint32)(w), bound)
}

// w = w - p, and 1 when Decompose's centered r0 of some new coefficient reaches bound in absolute
// value, otherwise 0.
func dsaSubLow(w, p *dsaPoly, gamma2, bound uint32) uint32 {
	switch {
	case !useAVX2:
		return dsaSubLowGeneric(w, p, gamma2, bound)
	case gamma2 == (dsaQ-1)/32:
		return dsaSubLow32AVX2((*[256]uint32)(w), (*[256]uint32)(p), bound)
	default:
		return dsaSubLow88AVX2((*[256]uint32)(w), (*[256]uint32)(p), bound)
	}
}

// The hints of a signature from w - c s2 and p = c t0, as bits, with the c t0 bound and the count.
func dsaHints(hints *[4]uint64, w, p *dsaPoly, gamma2 uint32) (beyond, count uint32) {
	switch {
	case !useAVX2:
		return dsaHintsGeneric(hints, w, p, gamma2)
	case gamma2 == (dsaQ-1)/32:
		return dsaHints32AVX2(hints, (*[256]uint32)(w), (*[256]uint32)(p))
	default:
		return dsaHints88AVX2(hints, (*[256]uint32)(w), (*[256]uint32)(p))
	}
}

// w1Encode of the high bits of w, width bits each, into out[:32 width].
func dsaHighBits(out []byte, w *dsaPoly, gamma2 uint32, width int) {
	out = out[:32*width]

	switch {
	case !useAVX2:
		dsaHighBitsGeneric(out, w, gamma2, width)
	case gamma2 == (dsaQ-1)/32:
		dsaHighBits32AVX2(&out[0], (*[256]uint32)(w))
	default:
		dsaHighBits88AVX2(&out[0], (*[256]uint32)(w))
	}
}

// w1Encode of UseHint(hints, w), hints as bits, width bits each, into out[:32 width]; w is
// overwritten.
func dsaUseHints(out []byte, w *dsaPoly, hints *[4]uint64, gamma2 uint32, width int) {
	out = out[:32*width]

	switch {
	case !useAVX2:
		dsaUseHintsGeneric(out, w, hints, gamma2, width)
	case gamma2 == (dsaQ-1)/32:
		dsaUseHints32AVX2(&out[0], (*[256]uint32)(w), hints)
	default:
		dsaUseHints88AVX2(&out[0], (*[256]uint32)(w), hints)
	}
}

// BitUnpack of y or z with b = gamma1 from in; the kernels read 32 width + 7 bytes.
func dsaUnpackGamma1(w *dsaPoly, in []byte, gamma1 uint32, width int) {
	switch {
	case !useAVX2 || len(in) < 32*width+7:
		dsaUnpack(w, in, gamma1, width)
	case width == 18:
		dsaUnpack18AVX2((*[256]uint32)(w), &in[0])
	default:
		dsaUnpack20AVX2((*[256]uint32)(w), &in[0])
	}
}

// BitPack of z with b = gamma1 into out[:32 width].
func dsaPackGamma1(out []byte, w *dsaPoly, gamma1 uint32, width int) {
	out = out[:32*width]

	switch {
	case !useAVX2:
		dsaPack(out, w, gamma1, width)
	case width == 18:
		dsaPack18AVX2(&out[0], (*[256]uint32)(w))
	default:
		dsaPack20AVX2(&out[0], (*[256]uint32)(w))
	}
}

// RejNTTPoly's candidates from the rate bytes of a SHAKE128 state appended to f from count on;
// returns the new count. The kernel stops early near the end of f; the rest of the block goes
// through the portable loop.
func dsaRejUniformLane(f *dsaPoly, count int, state *[25]uint64) int {
	if !useAVX2 {
		return dsaRejUniformLaneGeneric(f, count, state)
	}

	count, consumed := dsaRejUniformAVX2((*[256]uint32)(f), count, state)

	if count < 256 && consumed < 168 {
		var block [168]byte

		for i, lane := range state[:21] {
			binary.LittleEndian.PutUint64(block[8*i:], lane)
		}

		count = dsaRejUniformGeneric(f, count, block[consumed:])
	}

	return count
}

// Power2Round of t: t1 packed with 10 bits into t1[:320], t0 as skEncode packs it into t0[:416].
func dsaPower2RoundPack(t1, t0 []byte, t *dsaPoly) {
	t1, t0 = t1[:320], t0[:32*dsaD]

	if !useAVX2 {
		dsaPower2RoundPackGeneric(t1, t0, t)

		return
	}

	dsaPower2RoundAVX2(&t1[0], &t0[0], (*[256]uint32)(t))
}

// BitPack of s with b = eta into out[:32 width].
func dsaPackEta(out []byte, s *dsaPoly, eta, width int) {
	out = out[:32*width]

	switch {
	case !useAVX2:
		dsaPack(out, s, uint32(eta), width)
	case eta == 2:
		dsaPackEta3AVX2(&out[0], (*[256]uint32)(s))
	default:
		dsaPackEta4AVX2(&out[0], (*[256]uint32)(s))
	}
}

// t1 2^d from the 10-bit values at in; the kernel reads 331 bytes, which the last polynomial of a
// public key does not have, so it goes through the portable code.
func dsaUnpackT1(w *dsaPoly, in []byte) {
	if !useAVX2 || len(in) < 331 {
		dsaUnpackT1Generic(w, in)

		return
	}

	dsaUnpackT1AVX2((*[256]uint32)(w), &in[0])
}

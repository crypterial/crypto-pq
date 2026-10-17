package cryptopq

import (
	"encoding/binary"
	"math/rand/v2"
	"testing"
)

// The ML-DSA operations that have kernels (dsa_amd64.go) against their portable forms, on random
// and edge inputs and, for the rounding, on every value below q. Without the kernels both sides
// run the portable code.

var dsaGammas = []struct {
	gamma2 uint32
	width  int
}{{(dsaQ - 1) / 32, 4}, {(dsaQ - 1) / 88, 6}}

func randomDsaPoly(r *rand.Rand, w *dsaPoly) {
	for x := range w {
		w[x] = r.Uint32N(dsaQ)
	}
}

// Polynomials whose coefficients sit at the edges of the reductions and of Decompose: 0, q - 1,
// around (q - 1) / 2 and around the multiples of 2 gamma2.
func edgeDsaPoly(r *rand.Rand, w *dsaPoly, gamma2 uint32) {
	for x := range w {
		switch r.IntN(6) {
		case 0:
			w[x] = []uint32{0, 1, dsaQ - 1, dsaQ - 2}[r.IntN(4)]
		case 1:
			w[x] = (dsaQ-1)/2 - 2 + r.Uint32N(5)
		case 2:
			k := r.Uint32N((dsaQ-1)/(2*gamma2) + 1)

			w[x] = min(k*2*gamma2+gamma2-2+r.Uint32N(5), dsaQ-1)
		case 3:
			k := r.Uint32N((dsaQ-1)/(2*gamma2) + 1)

			w[x] = min(k*2*gamma2+r.Uint32N(3), dsaQ-1)

			if r.IntN(2) == 0 && w[x] > 2 {
				w[x] -= 1 + r.Uint32N(2)
			}
		default:
			w[x] = r.Uint32N(dsaQ)
		}
	}
}

func scaleDsaPoly(out, w *dsaPoly, factor uint32) {
	for x := range w {
		out[x] = dsaMul(w[x], factor)
	}
}

func TestDsaRowProductKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 65))

	var a, b [8]dsaPoly

	var c, tt dsaPoly

	for i := range 300 {
		for j := range a {
			randomDsaPoly(r, &a[j])

			randomDsaPoly(r, &b[j])
		}

		randomDsaPoly(r, &c)

		randomDsaPoly(r, &tt)

		if i < 8 {
			for j := range a {
				for x := range a[j] {
					a[j][x], b[j][x] = uint32(i%2)*(dsaQ-1), uint32(i/2%2)*(dsaQ-1)
				}
			}

			for x := range c {
				c[x], tt[x] = uint32(i/4%2)*(dsaQ-1), uint32(i%2)*(dsaQ-1)
			}
		}

		for n := 1; n <= 8; n++ {
			var got, want dsaPoly

			dsaRowProduct(&got, a[:n], b[:])

			dsaRowProductGeneric(&want, a[:n], b[:])

			if got != want {
				t.Fatalf("case %d: dsaRowProduct of %d products differs from the portable code", i, n)
			}

			dsaRowProductSub(&got, a[:n], b[:], &c, &tt)

			dsaRowProductSubGeneric(&want, a[:n], b[:], &c, &tt)

			if got != want {
				t.Fatalf("case %d: dsaRowProductSub of %d products differs from the portable code", i, n)
			}
		}
	}
}

func TestDsaProductKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(2, 65))

	one := dsaChallengeOne()

	for i := range 2000 {
		var c, scaled, s, y, got, want dsaPoly

		randomDsaPoly(r, &c)

		randomDsaPoly(r, &s)

		randomDsaPoly(r, &y)

		if i < 4 {
			for x := range c {
				c[x], s[x], y[x] = uint32(i%2)*(dsaQ-1), dsaQ-1, uint32(i/2)*(dsaQ-1)
			}
		}

		scaleDsaPoly(&scaled, &c, one)

		dsaProduct(&got, &scaled, &s, &y)

		dsaProductGeneric(&want, &c, &s, &y)

		if got != want {
			t.Fatalf("case %d: dsaProduct with y differs from the portable code", i)
		}

		dsaProduct(&got, &scaled, &s, nil)

		dsaProductGeneric(&want, &c, &s, nil)

		if got != want {
			t.Fatalf("case %d: dsaProduct differs from the portable code", i)
		}
	}
}

// The scaled challenge is that multiple of the plain one, and its window starts select it.
func TestDsaChallengeScaled(t *testing.T) {
	seed := make([]byte, 48)

	for i := range seed {
		seed[i] = byte(i)
	}

	for _, tau := range []int{39, 49, 60} {
		var plain, scaled, want dsaPoly

		dsaSampleInBall(&plain, seed, tau)

		scaled = plain

		dsaScaleChallenge(&scaled, dsaMontR)

		scaleDsaPoly(&want, &plain, dsaMontR)

		if scaled != want {
			t.Fatalf("tau %d: the scaled challenge is not 2^32 times the plain one", tau)
		}

		var starts [64]uint16

		if n := dsaChallengeStarts(&starts, &plain); n != tau {
			t.Fatalf("tau %d: %d window starts", tau, n)
		}
	}
}

// A random challenge with tau coefficients +-1, as SampleInBall makes them.
func randomChallenge(r *rand.Rand, c *dsaPoly, tau int) {
	*c = dsaPoly{}

	for _, x := range r.Perm(256)[:tau] {
		c[x] = []uint32{1, dsaQ - 1}[r.IntN(2)]
	}
}

// A packed secret polynomial (BitPack with b = eta): valid values, or any bytes.
func randomPackedSecret(r *rand.Rand, in []byte, eta int, valid bool) {
	fillBytes(r, in)

	if valid {
		var values dsaPoly

		for x := range values {
			values[x] = dsaFromSigned(int32(r.IntN(2*eta+1) - eta))
		}

		width := 4

		if eta == 2 {
			width = 3
		}

		dsaPack(in, &values, uint32(eta), width)
	}
}

func TestDsaSparseKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 65))

	for i := range 2000 {
		eta, tau := []int{2, 4, 2}[i%3], []int{39, 49, 60}[i%3]

		in := make([]byte, 130)

		randomPackedSecret(r, in, eta, i%4 != 0)

		var c dsaPoly

		randomChallenge(r, &c, tau)

		var starts [64]uint16

		n := dsaChallengeStarts(&starts, &c)

		var got, want [256]int16

		dsaSparseProduct(&got, &starts, n, in, eta)

		dsaSparseProductGeneric(&want, &starts, n, in, eta)

		if got != want {
			t.Fatalf("case %d: dsaSparseProduct differs from the portable code", i)
		}

		// c s through the NTT agrees with the windows.
		var s, ntt dsaPoly

		width := 4

		if eta == 2 {
			width = 3
		}

		dsaUnpack(&s, in, uint32(eta), width)

		cHat := c

		dsaNTT(&cHat)

		dsaNTT(&s)

		dsaProductGeneric(&ntt, &cHat, &s, nil)

		for x := range ntt {
			if dsaFromSigned(int32(got[x])) != ntt[x] {
				t.Fatalf("case %d: the sparse product differs from c s through the NTT at %d", i, x)
			}
		}

		for _, width := range []int{18, 20} {
			gamma1 := uint32(1) << (width - 1)

			stream := make([]byte, 32*width+7)

			fillBytes(r, stream)

			for _, bound := range []uint32{1, gamma1 - 196, gamma1 - 78, gamma1} {
				var gotZ, wantZ dsaPoly

				a, b := dsaUnpackAdd(&gotZ, stream, &got, gamma1, width, bound), dsaUnpackAddGeneric(&wantZ, stream, &got, gamma1, width, bound)

				if a != b || gotZ != wantZ {
					t.Fatalf("case %d: dsaUnpackAdd of %d bits with bound %d differs from the portable code", i, width, bound)
				}
			}
		}

		for _, g := range dsaGammas {
			var w dsaPoly

			edgeDsaPoly(r, &w, g.gamma2)

			for _, bound := range []uint32{1, g.gamma2 - 196, g.gamma2 - 78} {
				gotW, wantW := w, w

				a, b := dsaSubSmallLow(&gotW, &got, g.gamma2, bound), dsaSubSmallLowGeneric(&wantW, &got, g.gamma2, bound)

				if a != b || gotW != wantW {
					t.Fatalf("case %d: dsaSubSmallLow with gamma2 %d differs from the portable code", i, g.gamma2)
				}
			}
		}
	}
}

func TestDsaCheckKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 65))

	for i := range 3000 {
		for _, g := range dsaGammas {
			var w, p dsaPoly

			if i%2 == 0 {
				randomDsaPoly(r, &w)

				randomDsaPoly(r, &p)
			} else {
				edgeDsaPoly(r, &w, g.gamma2)

				edgeDsaPoly(r, &p, g.gamma2)
			}

			if i%3 == 0 {
				// Mostly small values, as c s2 and c t0 have, so that both answers occur.
				for x := range p {
					p[x] = dsaFromSigned(int32(r.IntN(2*int(g.gamma2))) - int32(g.gamma2))
				}
			}

			for _, bound := range []uint32{1, 2, g.gamma2 - 78, g.gamma2 - 196, g.gamma2, 1<<17 - 78, 1<<19 - 196, (dsaQ - 1) / 2, (dsaQ + 1) / 2} {
				if got, want := dsaBeyond(&w, bound), dsaBeyondGeneric(&w, bound); got != want {
					t.Fatalf("case %d: dsaBeyond with bound %d gives %d, want %d", i, bound, got, want)
				}

				gotW, wantW := w, w

				if got, want := dsaSubLow(&gotW, &p, g.gamma2, bound), dsaSubLowGeneric(&wantW, &p, g.gamma2, bound); got != want || gotW != wantW {
					t.Fatalf("case %d: dsaSubLow with gamma2 %d and bound %d differs from the portable code", i, g.gamma2, bound)
				}
			}

			var gotHints, wantHints [4]uint64

			gotBeyond, gotCount := dsaHints(&gotHints, &w, &p, g.gamma2)

			wantBeyond, wantCount := dsaHintsGeneric(&wantHints, &w, &p, g.gamma2)

			if gotBeyond != wantBeyond || gotCount != wantCount || gotHints != wantHints {
				t.Fatalf("case %d: dsaHints with gamma2 %d differs from the portable code", i, g.gamma2)
			}
		}
	}
}

func TestDsaRoundingKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(4, 65))

	for _, g := range dsaGammas {
		var got, want [32 * 6]byte

		// Every value below q, 256 at a time, with random hints.
		for first := uint32(0); first < dsaQ; first += 256 {
			var w dsaPoly

			hints := [4]uint64{r.Uint64(), r.Uint64(), r.Uint64(), r.Uint64()}

			for x := range w {
				w[x] = min(first+uint32(x), dsaQ-1)
			}

			dsaHighBits(got[:], &w, g.gamma2, g.width)

			dsaHighBitsGeneric(want[:32*g.width], &w, g.gamma2, g.width)

			if got != want {
				t.Fatalf("dsaHighBits with gamma2 %d differs from the portable code from %d on", g.gamma2, first)
			}

			gotW, wantW := w, w

			dsaUseHints(got[:], &gotW, &hints, g.gamma2, g.width)

			dsaUseHintsGeneric(want[:32*g.width], &wantW, &hints, g.gamma2, g.width)

			if got != want || gotW != wantW {
				t.Fatalf("dsaUseHints with gamma2 %d differs from the portable code from %d on", g.gamma2, first)
			}

			gotW, wantW = w, w

			var zero dsaPoly

			if a, b := dsaSubLow(&gotW, &zero, g.gamma2, g.gamma2-78), dsaSubLowGeneric(&wantW, &zero, g.gamma2, g.gamma2-78); a != b || gotW != wantW {
				t.Fatalf("dsaSubLow with gamma2 %d differs from the portable code from %d on", g.gamma2, first)
			}
		}
	}
}

func TestDsaPackingKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 65))

	for _, width := range []int{18, 20} {
		gamma1 := uint32(1) << (width - 1)

		for i := range 3000 {
			stream := make([]byte, 32*width+7)

			for j := range stream {
				stream[j] = byte(r.Uint32())
			}

			if i < len(kernelEdges) {
				edgeBytes(i, stream)
			}

			var got, want dsaPoly

			dsaUnpackGamma1(&got, stream, gamma1, width)

			dsaUnpack(&want, stream, gamma1, width)

			if got != want {
				t.Fatalf("case %d: dsaUnpackGamma1 of %d bits differs from the portable code", i, width)
			}

			// z as signing leaves it: centered values in (-gamma1, gamma1].
			var z dsaPoly

			for x := range z {
				z[x] = dsaFromSigned(int32(gamma1) - int32(r.Uint32N(2*gamma1)))

				if i < 2 {
					z[x] = dsaFromSigned(int32(gamma1) - int32(uint32(i)*(2*gamma1-1)))
				}
			}

			gotBytes, wantBytes := make([]byte, 32*width+16), make([]byte, 32*width+16)

			dsaPackGamma1(gotBytes, &z, gamma1, width)

			dsaPack(wantBytes, &z, gamma1, width)

			if string(gotBytes) != string(wantBytes) {
				t.Fatalf("case %d: dsaPackGamma1 of %d bits differs from the portable code", i, width)
			}

			dsaUnpackGamma1(&got, append(gotBytes[:32*width:32*width], make([]byte, 7)...), gamma1, width)

			if got != z {
				t.Fatalf("case %d: dsaPackGamma1 of %d bits does not unpack to its input", i, width)
			}
		}
	}
}

func TestDsaKeyPackingKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(8, 65))

	for i := range 3000 {
		var w dsaPoly

		randomDsaPoly(r, &w)

		if i < 2 {
			for x := range w {
				w[x] = uint32(i) * (dsaQ - 1)
			}
		}

		if i%3 == 0 {
			// Around the rounding boundary of Power2Round: low bits 4095 to 4097.
			for x := range w {
				w[x] = min(r.Uint32N(1024)<<13+4095+r.Uint32N(3), dsaQ-1)
			}
		}

		gotT1, wantT1 := make([]byte, 336), make([]byte, 336)

		gotT0, wantT0 := make([]byte, 432), make([]byte, 432)

		dsaPower2RoundPack(gotT1, gotT0, &w)

		dsaPower2RoundPackGeneric(wantT1[:320], wantT0[:416], &w)

		if string(gotT1) != string(wantT1) || string(gotT0) != string(wantT0) {
			t.Fatalf("case %d: dsaPower2RoundPack differs from the portable code", i)
		}

		packed := make([]byte, 331)

		fillBytes(r, packed)

		var gotDecoded, wantDecoded dsaPoly

		dsaUnpackT1(&gotDecoded, packed)

		dsaUnpackT1Generic(&wantDecoded, packed)

		if gotDecoded != wantDecoded {
			t.Fatalf("case %d: dsaUnpackT1 differs from the portable code", i)
		}

		for _, eta := range []int{2, 4} {
			var s dsaPoly

			for x := range s {
				s[x] = dsaFromSigned(int32(r.IntN(2*eta+1) - eta))
			}

			width := 4

			if eta == 2 {
				width = 3
			}

			got, want := make([]byte, 32*width+16), make([]byte, 32*width+16)

			dsaPackEta(got, &s, eta, width)

			dsaPack(want, &s, uint32(eta), width)

			if string(got) != string(want) {
				t.Fatalf("case %d: dsaPackEta with eta %d differs from the portable code", i, eta)
			}
		}
	}
}

func TestDsaRejUniformKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(6, 65))

	for i := range 3000 {
		// Each three-byte candidate is rejected with the case's probability, so that every mask
		// of a group of eight occurs.
		var block [200]byte

		fillBytes(r, block[:])

		reject := []int{0, 1, 4, 8, 12, 15, 16}[i%7]

		for c := 0; c+3 <= 168; c += 3 {
			if r.IntN(16) < reject {
				block[c+1], block[c+2] = 0xe0|block[c+1], 0x7f|block[c+2]
			}
		}

		var state [25]uint64

		for j := range state {
			state[j] = binary.LittleEndian.Uint64(block[8*j:])
		}

		var got, want dsaPoly

		randomDsaPoly(r, &got)

		want = got

		count := []int{0, 1, 100, 200, 230, 240, 247, 248, 249, 250, 254, 255, 256}[i%13]

		gotCount := dsaRejUniformLane(&got, count, &state)

		wantCount := dsaRejUniformLaneGeneric(&want, count, &state)

		if gotCount != wantCount || !equalWords(got[:gotCount], want[:wantCount]) {
			t.Fatalf("case %d: dsaRejUniformLane from %d differs from the portable code", i, count)
		}
	}
}

// Every 4 KiB of input makes the operands of each kernel: polynomials from 32-bit words reduced
// modulo q, bytes for the packings and hints.
func FuzzDsaKernels(f *testing.F) {
	f.Add(make([]byte, 4096), uint8(5))

	f.Add([]byte{1, 2, 3}, uint8(7))

	f.Fuzz(func(t *testing.T, data []byte, n uint8) {
		if len(data) == 0 {
			return
		}

		input := make([]byte, 9*1024+256+8)

		for i := range input {
			input[i] = data[i%len(data)] ^ byte(i/len(data))
		}

		var polys [9]dsaPoly

		for j := range polys {
			for x := range polys[j] {
				polys[j][x] = binary.LittleEndian.Uint32(input[1024*j+4*x:]) % dsaQ
			}
		}

		var hints [4]uint64

		for j := range hints {
			hints[j] = binary.LittleEndian.Uint64(input[9*1024+8*j:])
		}

		terms := int(n)%8 + 1

		var got, want dsaPoly

		dsaRowProduct(&got, polys[:terms], polys[1:])

		dsaRowProductGeneric(&want, polys[:terms], polys[1:])

		if got != want {
			t.Fatalf("dsaRowProduct differs from the portable code")
		}

		dsaRowProductSub(&got, polys[:terms], polys[1:], &polys[7], &polys[8])

		dsaRowProductSubGeneric(&want, polys[:terms], polys[1:], &polys[7], &polys[8])

		if got != want {
			t.Fatalf("dsaRowProductSub differs from the portable code")
		}

		var scaled dsaPoly

		scaleDsaPoly(&scaled, &polys[0], dsaChallengeOne())

		dsaProduct(&got, &scaled, &polys[1], &polys[2])

		dsaProductGeneric(&want, &polys[0], &polys[1], &polys[2])

		if got != want {
			t.Fatalf("dsaProduct differs from the portable code")
		}

		for _, g := range dsaGammas {
			bound := uint32(binary.LittleEndian.Uint16(input[9*1024+256:])) + 1

			if dsaBeyond(&polys[3], bound) != dsaBeyondGeneric(&polys[3], bound) {
				t.Fatalf("dsaBeyond differs from the portable code")
			}

			gotW, wantW := polys[4], polys[4]

			if dsaSubLow(&gotW, &polys[5], g.gamma2, bound) != dsaSubLowGeneric(&wantW, &polys[5], g.gamma2, bound) || gotW != wantW {
				t.Fatalf("dsaSubLow differs from the portable code")
			}

			var gotHints, wantHints [4]uint64

			b1, c1 := dsaHints(&gotHints, &polys[4], &polys[5], g.gamma2)

			b2, c2 := dsaHintsGeneric(&wantHints, &polys[4], &polys[5], g.gamma2)

			if b1 != b2 || c1 != c2 || gotHints != wantHints {
				t.Fatalf("dsaHints differs from the portable code")
			}

			var gotBytes, wantBytes [192]byte

			dsaHighBits(gotBytes[:], &polys[6], g.gamma2, g.width)

			dsaHighBitsGeneric(wantBytes[:32*g.width], &polys[6], g.gamma2, g.width)

			if gotBytes != wantBytes {
				t.Fatalf("dsaHighBits differs from the portable code")
			}

			gotW, wantW = polys[6], polys[6]

			dsaUseHints(gotBytes[:], &gotW, &hints, g.gamma2, g.width)

			dsaUseHintsGeneric(wantBytes[:32*g.width], &wantW, &hints, g.gamma2, g.width)

			if gotBytes != wantBytes || gotW != wantW {
				t.Fatalf("dsaUseHints differs from the portable code")
			}
		}

		for _, width := range []int{18, 20} {
			dsaUnpackGamma1(&got, input[:32*width+7], 1<<(width-1), width)

			dsaUnpack(&want, input[:32*width+7], 1<<(width-1), width)

			if got != want {
				t.Fatalf("dsaUnpackGamma1 differs from the portable code")
			}
		}

		var c dsaPoly

		for j, x := range input[:60] {
			c[x] = []uint32{1, dsaQ - 1}[input[100+j]&1]
		}

		var starts [64]uint16

		taus := dsaChallengeStarts(&starts, &c)

		for _, eta := range []int{2, 4} {
			var gotSmall, wantSmall [256]int16

			dsaSparseProduct(&gotSmall, &starts, taus, input[200:330], eta)

			dsaSparseProductGeneric(&wantSmall, &starts, taus, input[200:330], eta)

			if gotSmall != wantSmall {
				t.Fatalf("dsaSparseProduct differs from the portable code")
			}

			gotW, wantW := polys[4], polys[4]

			if dsaSubSmallLow(&gotW, &gotSmall, (dsaQ-1)/32, 1000) != dsaSubSmallLowGeneric(&wantW, &gotSmall, (dsaQ-1)/32, 1000) || gotW != wantW {
				t.Fatalf("dsaSubSmallLow differs from the portable code")
			}

			gotW, wantW = polys[4], polys[4]

			if dsaUnpackAdd(&gotW, input[:647], &gotSmall, 1<<19, 20, 1<<19-196) != dsaUnpackAddGeneric(&wantW, input[:647], &gotSmall, 1<<19, 20, 1<<19-196) || gotW != wantW {
				t.Fatalf("dsaUnpackAdd differs from the portable code")
			}
		}

		var state [25]uint64

		for j := range state {
			state[j] = binary.LittleEndian.Uint64(input[8*j:])
		}

		count := int(n)

		got, want = polys[7], polys[7]

		if c1, c2 := dsaRejUniformLane(&got, count, &state), dsaRejUniformLaneGeneric(&want, count, &state); c1 != c2 || !equalWords(got[:c1], want[:c2]) {
			t.Fatalf("dsaRejUniformLane differs from the portable code")
		}
	})
}

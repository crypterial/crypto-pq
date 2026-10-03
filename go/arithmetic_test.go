package cryptopq

import "testing"

// The multiply-shift reductions are checked against plain division, exhaustively where the input
// range allows it and on the edges and a dense sample elsewhere.

func TestKemArithmetic(t *testing.T) {
	for a := range uint32(1 << 16) {
		if got := kemReduce16(uint16(a)); uint32(got) != a%kemQ {
			t.Fatalf("kemReduce16(%d) = %d", a, got)
		}

		for i := range kemZetas {
			got := uint32(kemMulShoup(uint16(a), uint32(kemZetas[i]), uint32(kemShoup[i])))

			if got >= 2*kemQ || got%kemQ != a*uint32(kemZetas[i])%kemQ {
				t.Fatalf("kemMulShoup(%d, %d) = %d", a, kemZetas[i], got)
			}
		}
	}

	for _, a := range []uint32{0, 1, kemQ - 1, kemQ, 1<<24 - 1, 1<<31 + 12345, 1<<32 - 1} {
		if got := kemReduce(a); uint32(got) != a%kemQ {
			t.Fatalf("kemReduce(%d) = %d", a, got)
		}
	}
}

func TestDsaArithmetic(t *testing.T) {
	samples := []uint32{0, 1, dsaQ - 1, dsaQ, 2*dsaQ - 1, 17*dsaQ - 1, 256*dsaQ - 1, 1<<32 - 1}

	for a := uint32(0); a < 1<<32-9973; a += 9973 {
		samples = append(samples, a)
	}

	for _, a := range samples {
		if got := dsaReduce32(a); got != a%dsaQ {
			t.Fatalf("dsaReduce32(%d) = %d", a, got)
		}

		for _, i := range []int{1, 2, 3, 127, 128, 255} {
			got := uint64(dsaMulShoup(a, dsaZetas[i], dsaShoup[i]))

			if got >= 2*dsaQ || got%dsaQ != uint64(a)*uint64(dsaZetas[i])%dsaQ {
				t.Fatalf("dsaMulShoup(%d, %d) = %d", a, dsaZetas[i], got)
			}
		}
	}
}

// FIPS 204, Algorithm 36, as written.
func decomposeDefinition(r, gamma2 int32) (int32, int32) {
	alpha := 2 * gamma2

	r0 := r % alpha

	if r0 > gamma2 {
		r0 -= alpha
	}

	if r-r0 == dsaQ-1 {
		return 0, r0 - 1
	}

	return (r - r0) / alpha, r0
}

func TestDsaDecompose(t *testing.T) {
	for _, gamma2 := range []uint32{(dsaQ - 1) / 88, (dsaQ - 1) / 32} {
		for r := range uint32(dsaQ) {
			r1, r0 := dsaDecompose(r, gamma2)

			if w1, w0 := decomposeDefinition(int32(r), int32(gamma2)); r1 != w1 || r0 != w0 {
				t.Fatalf("Decompose(%d) with gamma2 %d = (%d, %d), want (%d, %d)", r, gamma2, r1, r0, w1, w0)
			}
		}
	}
}

// FIPS 203, Algorithms 9 and 10, with a full reduction after every operation.
func kemNTTReference(f *kemPoly, inverse bool) {
	if !inverse {
		i := 1

		for length := 128; length >= 2; length /= 2 {
			for start := 0; start < 256; start += 2 * length {
				zeta := uint32(kemZetas[i])

				i++

				for j := start; j < start+length; j++ {
					t := zeta * uint32(f[j+length]) % kemQ

					f[j+length], f[j] = uint16((uint32(f[j])+kemQ-t)%kemQ), uint16((uint32(f[j])+t)%kemQ)
				}
			}
		}

		return
	}

	i := 127

	for length := 2; length <= 128; length *= 2 {
		for start := 0; start < 256; start += 2 * length {
			zeta := uint32(kemZetas[i])

			i--

			for j := start; j < start+length; j++ {
				t := uint32(f[j])

				f[j], f[j+length] = uint16((t+uint32(f[j+length]))%kemQ), uint16(zeta*((uint32(f[j+length])+kemQ-t)%kemQ)%kemQ)
			}
		}
	}

	for j := range f {
		f[j] = uint16(uint32(f[j]) * 3303 % kemQ)
	}
}

// FIPS 204, Algorithms 41 and 42, in the same way.
func dsaNTTReference(w *dsaPoly, inverse bool) {
	if !inverse {
		m := 0

		for length := 128; length >= 1; length /= 2 {
			for start := 0; start < 256; start += 2 * length {
				m++

				zeta := uint64(dsaZetas[m])

				for j := start; j < start+length; j++ {
					t := zeta * uint64(w[j+length]) % dsaQ

					w[j+length], w[j] = uint32((uint64(w[j])+dsaQ-t)%dsaQ), uint32((uint64(w[j])+t)%dsaQ)
				}
			}
		}

		return
	}

	m := 256

	for length := 1; length < 256; length *= 2 {
		for start := 0; start < 256; start += 2 * length {
			m--

			zeta := uint64(dsaQ - dsaZetas[m])

			for j := start; j < start+length; j++ {
				t := uint64(w[j])

				w[j], w[j+length] = uint32((t+uint64(w[j+length]))%dsaQ), uint32(zeta*((t+dsaQ-uint64(w[j+length]))%dsaQ)%dsaQ)
			}
		}
	}

	for j := range w {
		w[j] = uint32(uint64(w[j]) * 8347681 % dsaQ)
	}
}

// The lazily reduced transforms against the references, on inputs that drive the unreduced
// intermediate values to their bounds: blocks of q - 1 and of zeros of every size, which make the
// sums and differences of the butterflies extreme, and random mixes of extreme and ordinary values.
func TestNTTBounds(t *testing.T) {
	var inputs []func(int, uint32) uint32

	for size := 1; size <= 128; size *= 2 {
		inputs = append(inputs, func(i int, q uint32) uint32 { return (q - 1) * uint32(i/size&1) }, func(i int, q uint32) uint32 { return (q - 1) * uint32(1-i/size&1) })
	}

	// Values whose products with zeta_1 come out of the Shoup multiplication above q, opposite
	// zeros: the first layer then subtracts the most from the least.
	kemValue, dsaValue := uint32(kemQ-1), uint32(dsaQ-1)

	for kemMulShoup(uint16(kemValue), uint32(kemZetas[1]), uint32(kemShoup[1])) <= kemQ && kemValue > 0 {
		kemValue--
	}

	for dsaMulShoup(dsaValue, dsaZetas[1], dsaShoup[1]) <= dsaQ && dsaValue > 0 {
		dsaValue--
	}

	if kemValue == 0 || dsaValue == 0 {
		t.Fatal("no product above q")
	}

	inputs = append(inputs, func(i int, q uint32) uint32 {
		if q == kemQ {
			return kemValue * uint32(i/128)
		}

		return dsaValue * uint32(i/128)
	})

	state := uint32(1)

	for range 64 {
		inputs = append(inputs, func(_ int, q uint32) uint32 {
			state = state*1664525 + 1013904223

			return [4]uint32{0, q - 1, state >> 8 % q, 1}[state>>30]
		})
	}

	for n, input := range inputs {
		for _, inverse := range []bool{false, true} {
			var f, g kemPoly

			for i := range f {
				f[i] = uint16(input(i, kemQ))
			}

			g = f

			kemNTTReference(&g, inverse)

			if inverse {
				kemInverseNTT(&f)
			} else {
				kemNTT(&f)
			}

			if f != g {
				t.Fatalf("ML-KEM input %d, inverse %v: transforms differ", n, inverse)
			}

			var v, w dsaPoly

			for i := range v {
				v[i] = input(i, dsaQ)
			}

			w = v

			dsaNTTReference(&w, inverse)

			if inverse {
				dsaInverseNTT(&v)
			} else {
				dsaNTT(&v)
			}

			if v != w {
				t.Fatalf("ML-DSA input %d, inverse %v: transforms differ", n, inverse)
			}
		}
	}
}

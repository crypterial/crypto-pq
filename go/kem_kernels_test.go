package cryptopq

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

// The ML-KEM kernels against their portable twins and a plain reference of the base case, on random
// and edge inputs, exhaustively over the coefficient values where those are few. Without the kernels
// both sides run the portable code.

const kemKernelCases = 2000

func kemRandomPoly(r *rand.Rand, f *kemPoly) {
	for x := range f {
		f[x] = uint16(r.IntN(kemQ))
	}
}

// Case i below 3 sets every coefficient to 0, q - 1 or alternately both.
func kemEdgePoly(i int, f *kemPoly) {
	for x := range f {
		switch i {
		case 0:
			f[x] = 0
		case 1:
			f[x] = kemQ - 1
		default:
			f[x] = uint16(x%2) * (kemQ - 1)
		}
	}
}

// FIPS 203, Algorithms 11 and 12 with plain arithmetic: out = add + sum of factors[j] vectors[j].
func kemProductReference(out *kemPoly, factors, vectors []kemPoly, add *kemPoly) {
	for i := range 128 {
		var even, odd uint64

		if add != nil {
			even, odd = uint64(add[2*i]), uint64(add[2*i+1])
		}

		for j := range factors {
			a0, a1 := uint64(factors[j][2*i]), uint64(factors[j][2*i+1])

			b0, b1 := uint64(vectors[j][2*i]), uint64(vectors[j][2*i+1])

			even += a0*b0 + a1*b1%kemQ*uint64(kemGammas[i])

			odd += a0*b1 + a1*b0
		}

		out[2*i], out[2*i+1] = uint16(even%kemQ), uint16(odd%kemQ)
	}
}

func checkKemProduct(t *testing.T, label string, n, stride, first int, polys []kemPoly, vectors [4]kemPoly, add *kemPoly) {
	t.Helper()

	factors := make([]kemFactor, len(polys))

	plain := make([]kemPoly, n)

	for x := range polys {
		factors[x].f = polys[x]

		factors[x].prepare()
	}

	for j := range n {
		plain[j] = polys[first+j*stride]
	}

	var want, got kemPoly

	kemProductReference(&want, plain, vectors[:n], add)

	var prepared kemPrepared

	kemPrepareVectors(&prepared, vectors[:n])

	kemProduct(&got, factors, first, stride, vectors[:n], &prepared, add)

	if got != want {
		t.Fatalf("%s: kemProduct of %d products differs from the reference", label, n)
	}
}

func TestKemProductKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(203, 12))

	for i := range kemKernelCases {
		n := 2 + i%3

		stride := 1 + i%2*(n-1)

		first := (i / 3) % stride

		polys := make([]kemPoly, n*stride)

		var vectors [4]kemPoly

		var add kemPoly

		for x := range polys {
			kemRandomPoly(r, &polys[x])
		}

		for j := range n {
			kemRandomPoly(r, &vectors[j])
		}

		kemRandomPoly(r, &add)

		if i < 9 {
			for x := range polys {
				kemEdgePoly(i/3, &polys[x])
			}

			for j := range n {
				kemEdgePoly(i%3, &vectors[j])
			}

			kemEdgePoly(i/3, &add)
		}

		if i%4 == 0 {
			checkKemProduct(t, "no addend", n, stride, first, polys, vectors, nil)
		} else {
			checkKemProduct(t, "addend", n, stride, first, polys, vectors, &add)
		}
	}
}

func TestKemCBDKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(203, 8))

	var data [192]byte

	for i := range kemKernelCases {
		fillBytes(r, data[:])

		if i < len(kernelEdges) {
			edgeBytes(i, data[:])
		}

		for _, eta := range []int{2, 3} {
			var want, got kemPoly

			kemSampleCBDGeneric(&want, data[:64*eta], eta)

			kemSampleCBD(&got, data[:64*eta], eta)

			if got != want {
				t.Fatalf("case %d: kemSampleCBD with eta %d differs from the portable code", i, eta)
			}
		}
	}
}

// The polynomials whose coefficients, with e = 0, run through every value below q.
func kemRamps() []kemPoly {
	var ramps []kemPoly

	for start := 0; start < kemQ; start += 256 {
		var f kemPoly

		for x := range f {
			f[x] = uint16((start + x) % kemQ)
		}

		ramps = append(ramps, f)
	}

	return ramps
}

func TestKemCompressKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(203, 9))

	ramps := kemRamps()

	for i := range kemKernelCases {
		var u, e kemPoly

		var m [32]byte

		kemRandomPoly(r, &u)

		kemRandomPoly(r, &e)

		fillBytes(r, m[:])

		switch {
		case i < len(ramps):
			u, e = ramps[i], kemPoly{}
		case i < 2*len(ramps):
			u, e = ramps[i-len(ramps)], kemPoly{}

			for x := range m {
				m[x] = 0xff
			}
		case i < 2*len(ramps)+9:
			kemEdgePoly((i-2*len(ramps))/3, &u)

			kemEdgePoly((i-2*len(ramps))%3, &e)
		}

		for _, d := range []int{10, 11} {
			want, got := make([]byte, 32*d), make([]byte, 32*d)

			uw, ug := u, u

			kemCompressUGeneric(want, &uw, &e, d)

			kemCompressU(got, &ug, &e, d)

			if !bytes.Equal(got, want) {
				t.Fatalf("case %d: kemCompressU with d = %d differs from the portable code", i, d)
			}
		}

		for _, d := range []int{4, 5} {
			want, got := make([]byte, 32*d), make([]byte, 32*d)

			uw, ug := u, u

			kemCompressVGeneric(want, &uw, &e, m[:], d)

			kemCompressV(got, &ug, &e, m[:], d)

			if !bytes.Equal(got, want) {
				t.Fatalf("case %d: kemCompressV with d = %d differs from the portable code", i, d)
			}
		}
	}
}

// Packed bytes whose d-bit values run through every value below 2^d from start on.
func kemPackedRamp(start, d int) []byte {
	var values [256]uint16

	for x := range values {
		values[x] = uint16((start + x) % (1 << d))
	}

	out := make([]byte, 32*d)

	packBits(out, values[:], d)

	return out
}

func TestKemDecompressKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(203, 10))

	for i := range kemKernelCases {
		in := make([]byte, 352)

		fillBytes(r, in)

		if i < len(kernelEdges) {
			edgeBytes(i, in)
		}

		var w kemPoly

		kemRandomPoly(r, &w)

		if i >= len(kernelEdges) && i < len(kernelEdges)+3 {
			kemEdgePoly(i-len(kernelEdges), &w)
		}

		for _, d := range []int{10, 11} {
			packed := in[:32*d]

			if i < 8 {
				packed = kemPackedRamp(256*i, d)
			}

			var want, got kemPoly

			kemDecompressUGeneric(&want, packed, d)

			kemDecompressU(&got, packed, d)

			if got != want {
				t.Fatalf("case %d: kemDecompressU with d = %d differs from the portable code", i, d)
			}
		}

		for _, d := range []int{4, 5} {
			packed := in[:32*d]

			if i < 2 {
				packed = kemPackedRamp(0, d)
			}

			var want, got [32]byte

			kemDecodeMessageGeneric(want[:], packed, &w, d)

			kemDecodeMessage(got[:], packed, &w, d)

			if got != want {
				t.Fatalf("case %d: kemDecodeMessage with d = %d differs from the portable code", i, d)
			}
		}
	}

	// Every decompressed value against every value of w, for d = 4 and 5.
	for start := 0; start < kemQ; start += 256 {
		var w kemPoly

		for x := range w {
			w[x] = uint16((start + x) % kemQ)
		}

		for value := range 32 {
			packed := kemPackedRamp(value, 5)

			var want, got [32]byte

			kemDecodeMessageGeneric(want[:], packed, &w, 5)

			kemDecodeMessage(got[:], packed, &w, 5)

			if got != want {
				t.Fatalf("kemDecodeMessage with d = 5 differs from the portable code for w from %d", start)
			}

			packed = kemPackedRamp(value, 4)

			kemDecodeMessageGeneric(want[:], packed, &w, 4)

			kemDecodeMessage(got[:], packed, &w, 4)

			if got != want {
				t.Fatalf("kemDecodeMessage with d = 4 differs from the portable code for w from %d", start)
			}
		}
	}
}

func TestKemEncodeKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(203, 11))

	for i := range kemKernelCases {
		var f kemPoly

		kemRandomPoly(r, &f)

		if i < 3 {
			kemEdgePoly(i, &f)
		}

		want, got := make([]byte, 384), make([]byte, 384)

		kemEncode12Generic(want, &f)

		kemEncode12(got, &f)

		if !bytes.Equal(got, want) {
			t.Fatalf("case %d: kemEncode12 differs from the portable code", i)
		}

		in := make([]byte, 384)

		fillBytes(r, in)

		if i < len(kernelEdges) {
			edgeBytes(i, in)
		}

		var wantF, gotF kemPoly

		kemDecode12Generic(&wantF, in)

		kemDecode12(&gotF, in)

		if gotF != wantF {
			t.Fatalf("case %d: kemDecode12 differs from the portable code", i)
		}

		if kemCheck12(in) != kemCheck12Generic(in) {
			t.Fatalf("case %d: kemCheck12 of random bytes differs from the portable code", i)
		}

		// A valid encoding, and the same with one value out of range.
		if !kemCheck12(want) {
			t.Fatalf("case %d: kemCheck12 rejects a valid encoding", i)
		}

		x := r.IntN(256)

		value := uint16(kemQ + r.IntN(4096-kemQ))

		f[x] = value

		kemEncode12Generic(want, &f)

		if kemCheck12(want) || kemCheck12Generic(want) {
			t.Fatalf("case %d: kemCheck12 accepts %d at %d", i, value, x)
		}
	}
}

func TestKemNoiseKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(203, 6))

	var seed [32]byte

	for i := range kemKernelCases / 4 {
		fillBytes(r, seed[:])

		n := 1 + i%keccakMaxLanes

		eta := 2 + i/keccakMaxLanes%2

		var nonces [keccakMaxLanes]uint16

		var want, got [keccakMaxLanes]kemPoly

		wantPolys, gotPolys := make([]*kemPoly, n), make([]*kemPoly, n)

		for l := range n {
			nonces[l] = uint16(r.Uint32() % 256)

			wantPolys[l], gotPolys[l] = &want[l], &got[l]
		}

		var wantSponges, gotSponges keccakLanes

		wantSponges.start(136, seed[:], nonces[:n], 1)

		gotSponges.start(136, seed[:], nonces[:n], 1)

		kemSampleNoisesGeneric(wantPolys, &wantSponges, eta)

		kemSampleNoises(gotPolys, &gotSponges, eta)

		if got != want {
			t.Fatalf("case %d: kemSampleNoises of %d sponges with eta %d differs from the portable code", i, n, eta)
		}
	}
}

func TestKemSampleKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(203, 7))

	var rho [32]byte

	for i := range kemKernelCases / 4 {
		fillBytes(r, rho[:])

		if i < len(kernelEdges) {
			edgeBytes(i, rho[:])
		}

		n := 1 + i%kemRowLanes

		var positions [kemRowLanes]uint16

		var want, got [kemRowLanes]kemPoly

		wantRow, gotRow := make([]*kemPoly, n), make([]*kemPoly, n)

		for l := range n {
			positions[l] = uint16(r.Uint32())

			wantRow[l], gotRow[l] = &want[l], &got[l]
		}

		kemSampleNTTsGeneric(wantRow, rho[:], positions[:n])

		kemSampleNTTs(gotRow, rho[:], positions[:n])

		if got != want {
			t.Fatalf("case %d: kemSampleNTTs of %d entries differs from the portable code", i, n)
		}
	}
}

// Rows of the matrix sampled together against each entry sampled by the portable code alone.
func TestKemSampleMatrix(t *testing.T) {
	r := rand.New(rand.NewPCG(203, 5))

	var rho [32]byte

	for i := range 40 {
		fillBytes(r, rho[:])

		k := 2 + i%3

		first := r.IntN(k)

		rows := 1 + r.IntN(k-first)

		got := make([]kemFactor, rows*k)

		kemSampleMatrix(got, rho[:], first, rows, k)

		for x := range got {
			var want kemPoly

			kemSampleNTTsGeneric([]*kemPoly{&want}, rho[:], []uint16{uint16(x%k) | uint16(first+x/k)<<8})

			if got[x].f != want {
				t.Fatalf("case %d: entry %d of rows %d to %d of a %d by %d matrix differs", i, x, first, first+rows-1, k, k)
			}
		}
	}
}

// Inputs from the fuzzer, cut into the operands of every kernel.
func FuzzKemKernels(f *testing.F) {
	f.Add(make([]byte, 64))

	f.Add(bytes.Repeat([]byte{0xff}, 1200))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 2 {
			return
		}

		buffer := make([]byte, 4096)

		for i := range buffer {
			buffer[i] = data[i%len(data)] ^ byte(i/len(data))
		}

		var polys [6]kemPoly

		for p := range polys {
			for x := range polys[p] {
				polys[p][x] = uint16(int(buffer[512*p+2*x])|int(buffer[512*p+2*x+1])<<8) % kemQ
			}
		}

		n := 2 + int(data[0])%3

		var vectors [4]kemPoly

		copy(vectors[:], polys[2:2+n])

		checkKemProduct(t, "fuzz", n, 1, 0, polys[:n], vectors, &polys[5])

		for _, eta := range []int{2, 3} {
			var want, got kemPoly

			kemSampleCBDGeneric(&want, buffer[:64*eta], eta)

			kemSampleCBD(&got, buffer[:64*eta], eta)

			if got != want {
				t.Fatalf("kemSampleCBD with eta %d differs from the portable code", eta)
			}
		}

		for _, d := range []int{4, 5, 10, 11} {
			want, got := make([]byte, 32*d), make([]byte, 32*d)

			uw, ug := polys[0], polys[0]

			if d > 5 {
				kemCompressUGeneric(want, &uw, &polys[1], d)

				kemCompressU(got, &ug, &polys[1], d)
			} else {
				kemCompressVGeneric(want, &uw, &polys[1], buffer[:32], d)

				kemCompressV(got, &ug, &polys[1], buffer[:32], d)
			}

			if !bytes.Equal(got, want) {
				t.Fatalf("compression with d = %d differs from the portable code", d)
			}

			if d > 5 {
				var wantF, gotF kemPoly

				kemDecompressUGeneric(&wantF, buffer[1000:1000+32*d], d)

				kemDecompressU(&gotF, buffer[1000:1000+32*d], d)

				if gotF != wantF {
					t.Fatalf("kemDecompressU with d = %d differs from the portable code", d)
				}
			} else {
				var wantM, gotM [32]byte

				kemDecodeMessageGeneric(wantM[:], buffer[1000:1000+32*d], &polys[2], d)

				kemDecodeMessage(gotM[:], buffer[1000:1000+32*d], &polys[2], d)

				if gotM != wantM {
					t.Fatalf("kemDecodeMessage with d = %d differs from the portable code", d)
				}
			}
		}

		var wantF, gotF kemPoly

		kemDecode12Generic(&wantF, buffer[2000:2384])

		kemDecode12(&gotF, buffer[2000:2384])

		if gotF != wantF || kemCheck12(buffer[2000:2384]) != kemCheck12Generic(buffer[2000:2384]) {
			t.Fatalf("kemDecode12 or kemCheck12 differs from the portable code")
		}
	})
}

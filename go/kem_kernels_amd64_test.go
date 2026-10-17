//go:build !purego

package cryptopq

import (
	"math/rand/v2"
	"slices"
	"testing"
)

// The amd64 kernels that the portable tests reach only through larger functions, against their
// Go twins directly: the preparation and the products, and the rejection of one block.

// SampleNTT's rejection of the 168 rate bytes of state in groups of 24 bytes, stopping after the
// group that reaches 256, as kemRejectAVX2 does.
func kemRejectReference(accepted *[kemRejectSize]uint16, count int, state *[25]uint64) int {
	var block [200]byte

	for i, lane := range state {
		for j := range 8 {
			block[8*i+j] = byte(lane >> (8 * j))
		}
	}

	for g := range 7 {
		for b := 24 * g; b < 24*g+24; b += 3 {
			d1 := uint16(block[b]) | uint16(block[b+1]&0x0f)<<8

			d2 := uint16(block[b+1]>>4) | uint16(block[b+2])<<4

			for _, d := range []uint16{d1, d2} {
				if d < kemQ {
					accepted[count] = d

					count++
				}
			}
		}

		if count >= 256 {
			break
		}
	}

	return count
}

func TestKemRejectKernel(t *testing.T) {
	if !useAVX2 {
		t.Skip("no AVX2")
	}

	r := rand.New(rand.NewPCG(203, 13))

	for i := range kemKernelCases {
		var state [25]uint64

		fillWords64(r, state[:])

		switch i % 4 {
		case 1:
			// Mostly candidates of 4095, rejected.
			for x := range state {
				state[x] |= r.Uint64() | r.Uint64()
			}
		case 2:
			// Mostly small candidates, accepted.
			for x := range state {
				state[x] &= r.Uint64() & r.Uint64() & r.Uint64()
			}
		}

		if i < len(kernelEdges) {
			for x := range state {
				state[x] = kernelEdges[i]
			}
		}

		count := r.IntN(256)

		var want, got [kemRejectSize]uint16

		wantCount := kemRejectReference(&want, count, &state)

		gotCount := kemRejectAVX2(&got, count, &state)

		if gotCount != wantCount || !slices.Equal(got[count:gotCount], want[count:wantCount]) {
			t.Fatalf("case %d: kemRejectAVX2 from %d gives %d candidates, the reference %d", i, count, gotCount, wantCount)
		}
	}
}

func TestKemPrepareKernels(t *testing.T) {
	if !useAVX2 {
		t.Skip("no AVX2")
	}

	r := rand.New(rand.NewPCG(203, 14))

	for i := range kemKernelCases / 4 {
		n := 2 + i%3

		var vectors [4]kemPoly

		for j := range n {
			kemRandomPoly(r, &vectors[j])

			if i < 3 {
				kemEdgePoly(i, &vectors[j])
			}
		}

		want, got := vectors, vectors

		var preparedWant, preparedGot kemPrepared

		kemPrepareVectorsGeneric(&preparedWant, want[:n])

		kemPrepareVectors(&preparedGot, got[:n])

		if got != want || preparedGot.swapped != preparedWant.swapped {
			t.Fatalf("case %d: kemPrepareVectors of %d vectors differs from the portable code", i, n)
		}

		factors := make([]kemFactor, 4*n)

		for x := range factors {
			kemRandomPoly(r, &factors[x].f)
		}

		var add kemPoly

		kemRandomPoly(r, &add)

		var wantOut, gotOut kemPoly

		kemProductGeneric(&wantOut, factors, i%n, n, want[:n], &preparedWant, &add)

		kemProduct(&gotOut, factors, i%n, n, got[:n], &preparedGot, &add)

		if gotOut != wantOut {
			t.Fatalf("case %d: kemProduct of %d products differs from the portable code", i, n)
		}
	}
}

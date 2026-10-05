package cryptopq

import (
	"encoding/binary"
	"math/rand/v2"
	"testing"
)

// The CPU-specific kernels against the portable code they replace, on random and edge inputs. On
// a CPU or build without them both sides run the portable code. The fuzz targets do the same with
// inputs from the fuzzer.

const kernelCases = 20000

// Edge words: zero, all ones, the extreme single bits and the alternating patterns.
var kernelEdges = []uint64{0, ^uint64(0), 1, 1 << 63, 0x5555555555555555, 0xaaaaaaaaaaaaaaaa, 0x0000000100000001, 0x8000000080000000}

func fillBytes(r *rand.Rand, out []byte) {
	for i := range out {
		out[i] = byte(r.Uint32())
	}
}

func fillWords32(r *rand.Rand, out []uint32) {
	for i := range out {
		out[i] = r.Uint32()
	}
}

func fillWords64(r *rand.Rand, out []uint64) {
	for i := range out {
		out[i] = r.Uint64()
	}
}

// Case i below len(kernelEdges) sets every word, and every byte, to that edge value.
func edgeBytes(i int, out []byte) {
	for j := range out {
		out[j] = byte(kernelEdges[i] >> (8 * (j % 8)))
	}
}

func TestKernelSelection(t *testing.T) {
	t.Log(kernelReport())
}

func TestSHA256Kernels(t *testing.T) {
	r := rand.New(rand.NewPCG(256, 1))

	var data [4*64 + 13]byte

	for i := range kernelCases {
		var state [8]uint32

		var w [16]uint32

		fillWords32(r, state[:])

		fillWords32(r, w[:])

		size := 64*(i%4) + 13*(i%5/4) + 64

		fillBytes(r, data[:size])

		if i < len(kernelEdges) {
			for j := range state {
				state[j], w[j], w[j+8] = uint32(kernelEdges[i]), uint32(kernelEdges[i]>>32), uint32(kernelEdges[i])
			}

			edgeBytes(i, data[:size])
		}

		want, got := state, state

		compress256Generic(&want, data[:size])

		compress256(&got, data[:size])

		if got != want {
			t.Fatalf("case %d: compress256 of %d bytes differs from the portable code", i, size)
		}

		want, got = state, state

		sha256BlockGeneric(&want, &w)

		sha256Block(&got, &w)

		if got != want {
			t.Fatalf("case %d: sha256Block differs from the portable code", i)
		}
	}

	var init [8]uint32

	blocks := make([]uint32, 16*3*9)

	for lanes := range 10 {
		for nb := 1; nb <= 3; nb++ {
			for range 50 {
				fillWords32(r, init[:])

				fillWords32(r, blocks)

				want, got := make([]uint32, 8*lanes), make([]uint32, 8*lanes)

				sha256LanesGeneric(&init, blocks[:16*nb*lanes], nb, want)

				sha256Lanes(&init, blocks[:16*nb*lanes], nb, got)

				if !equalWords(got, want) {
					t.Fatalf("sha256Lanes with %d lanes of %d blocks differs from the portable code", lanes, nb)
				}
			}
		}
	}
}

func TestSHA512Kernels(t *testing.T) {
	r := rand.New(rand.NewPCG(512, 1))

	var data [3*128 + 29]byte

	for i := range kernelCases {
		var state [8]uint64

		var w [16]uint64

		fillWords64(r, state[:])

		fillWords64(r, w[:])

		size := 128*(i%3) + 29*(i%5/4) + 128

		fillBytes(r, data[:size])

		if i < len(kernelEdges) {
			for j := range state {
				state[j], w[j], w[j+8] = kernelEdges[i], kernelEdges[i], ^kernelEdges[i]
			}

			edgeBytes(i, data[:size])
		}

		want, got := state, state

		compress512Generic(&want, data[:size])

		compress512(&got, data[:size])

		if got != want {
			t.Fatalf("case %d: compress512 of %d bytes differs from the portable code", i, size)
		}

		want, got = state, state

		sha512BlockGeneric(&want, &w)

		sha512Block(&got, &w)

		if got != want {
			t.Fatalf("case %d: sha512Block differs from the portable code", i)
		}
	}
}

func TestKeccakKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(1600, 1))

	for i := range kernelCases {
		var state [25]uint64

		fillWords64(r, state[:])

		if i < len(kernelEdges) {
			for j := range state {
				state[j] = kernelEdges[i]
			}
		}

		want, got := state, state

		permuteGeneric(&want)

		permute(&got)

		if got != want {
			t.Fatalf("case %d: permute differs from the portable code", i)
		}
	}

	for n := range 10 {
		for range 200 {
			states := make([][25]uint64, n)

			for j := range states {
				fillWords64(r, states[j][:])
			}

			want := append([][25]uint64{}, states...)

			permuteLanesGeneric(want)

			permuteLanes(states)

			for j := range states {
				if states[j] != want[j] {
					t.Fatalf("permuteLanes of %d states differs from the portable code at state %d", n, j)
				}
			}
		}
	}
}

// sha256Chains against the steps written out with the portable block function.
func chainReference(init *[8]uint32, lanes []uint32, words int, shift uint) {
	var w [16]uint32

	for r := 0; r < len(lanes); r += chainRecord {
		record := lanes[r : r+chainRecord]

		for step := record[24]; step < record[24]+record[25]; step++ {
			chainBlock(&w, record, step, shift)

			state := *init

			sha256BlockGeneric(&state, &w)

			copy(record[16:16+words], state[:words])
		}
	}
}

// Random templates, values of each length (zero beyond it), first steps and counts, in random
// order, so that pairs of lanes take unequal numbers of steps.
func randomChains(r *rand.Rand, lanes, words int, shift uint) []uint32 {
	records := make([]uint32, chainRecord*lanes)

	limit := uint32(1) << (32 - shift)

	for l := range lanes {
		record := records[chainRecord*l : chainRecord*(l+1)]

		fillWords32(r, record[:16+words])

		record[24] = r.Uint32N(min(limit-20, 40))

		record[25] = r.Uint32N(20)
	}

	return records
}

// Every combination of shift, value length and lane count up to 8 runs until over 20,000 lanes,
// with over 200,000 steps, have been compared.
func TestSHA256ChainKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(2, 22))

	var init [8]uint32

	for _, shift := range []uint{16, 24} {
		for _, words := range []int{4, 6, 8} {
			for lanes := range 9 {
				for range 500 {
					fillWords32(r, init[:])

					got := randomChains(r, lanes, words, shift)

					want := append([]uint32{}, got...)

					chainReference(&init, want, words, shift)

					sha256Chains(&init, got, words, shift)

					if !equalWords(got, want) {
						t.Fatalf("sha256Chains with %d lanes of %d words, shift %d, differs from the portable code", lanes, words, shift)
					}
				}
			}
		}
	}
}

// x25519 against the portable ladder on random scalars and points, and on the u values at the
// edges: 0, 1, p - 1, p, p + 1 and 2^255 - 1, which is non-canonical, also with bit 255 set.
func TestX25519Kernels(t *testing.T) {
	r := rand.New(rand.NewPCG(25519, 1))

	edges := [][32]byte{{}, {1}}

	for _, low := range []byte{0xec, 0xed, 0xee, 0xff} {
		var u [32]byte

		u[0] = low

		for i := 1; i < 31; i++ {
			u[i] = 0xff
		}

		u[31] = 0x7f

		edges = append(edges, u)

		u[31] = 0xff

		edges = append(edges, u)
	}

	var scalar, u [32]byte

	for i := range kernelCases {
		fillBytes(r, scalar[:])

		fillBytes(r, u[:])

		if i < len(edges) {
			u = edges[i]
		}

		if got, want := x25519(scalar[:], u[:]), x25519Generic(scalar[:], u[:]); got != want {
			t.Fatalf("case %d: x25519(%x, %x) = %x, want %x", i, scalar, u, got, want)
		}
	}
}

// The ML-DSA NTT and inverse against the portable code on random canonical coefficients and on
// the edges: all zero, all q - 1, and a single coefficient at each value.
func TestDsaNTTKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(8380417, 1))

	for i := range kernelCases {
		var w dsaPoly

		for x := range w {
			w[x] = r.Uint32N(dsaQ)
		}

		switch i {
		case 0:
			w = dsaPoly{}
		case 1:
			for x := range w {
				w[x] = dsaQ - 1
			}
		case 2, 3:
			w = dsaPoly{}

			w[r.IntN(256)] = uint32(1 + (i-2)*(dsaQ-2))
		}

		want, got := w, w

		dsaNTTGeneric(&want)

		dsaNTT(&got)

		if got != want {
			t.Fatalf("case %d: dsaNTT differs from the portable code", i)
		}

		dsaInverseNTTGeneric(&want)

		dsaInverseNTT(&got)

		if got != want {
			t.Fatalf("case %d: dsaInverseNTT differs from the portable code", i)
		}

		want, got = w, w

		dsaInverseNTTGeneric(&want)

		dsaInverseNTT(&got)

		if got != want {
			t.Fatalf("case %d: dsaInverseNTT of the input differs from the portable code", i)
		}
	}
}

// The ML-KEM NTT and inverse against the portable code, on random and edge inputs as for ML-DSA.
func TestKemNTTKernels(t *testing.T) {
	r := rand.New(rand.NewPCG(3329, 1))

	for i := range kernelCases {
		var f kemPoly

		for x := range f {
			f[x] = uint16(r.Uint32N(kemQ))
		}

		switch i {
		case 0:
			f = kemPoly{}
		case 1:
			for x := range f {
				f[x] = kemQ - 1
			}
		case 2, 3:
			f = kemPoly{}

			f[r.IntN(256)] = uint16(1 + (i-2)*(kemQ-2))
		}

		want, got := f, f

		kemNTTGeneric(&want)

		kemNTT(&got)

		if got != want {
			t.Fatalf("case %d: kemNTT differs from the portable code", i)
		}

		want, got = f, f

		kemInverseNTTGeneric(&want)

		kemInverseNTT(&got)

		if got != want {
			t.Fatalf("case %d: kemInverseNTT differs from the portable code", i)
		}
	}
}

// Known answers, in case both sides shared a mistake: SHA-256 and SHA-512 of "abc" and
// Keccak-f[1600] of the zero state.
func TestKernelKnownAnswers(t *testing.T) {
	var block [64]byte

	copy(block[:], "abc\x80")

	block[63] = 24

	state := iv256

	compress256(&state, block[:])

	if state != [8]uint32{0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad} {
		t.Fatalf("SHA-256(abc) = %08x", state)
	}

	var wide [128]byte

	copy(wide[:], "abc\x80")

	wide[127] = 24

	state512 := iv512

	compress512(&state512, wide[:])

	if state512[0] != 0xddaf35a193617aba || state512[7] != 0x2a9ac94fa54ca49f {
		t.Fatalf("SHA-512(abc) = %016x", state512)
	}

	var zero [25]uint64

	permute(&zero)

	if zero[0] != 0xf1258f7940e1dde7 || zero[24] != 0xeaf1ff7b5ceca249 {
		t.Fatalf("Keccak-f[1600](0) = %016x", zero)
	}
}

func equalWords[T uint32 | uint64](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

// The first 32 bytes are the state, the rest the message; lanes take the blocks of the message
// that remain after the first, in as many lanes of one block as fit.
func FuzzSHA256Kernels(f *testing.F) {
	f.Add(make([]byte, 32+64))

	f.Add(make([]byte, 32+5*64+7))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 32 {
			return
		}

		var state [8]uint32

		for i := range state {
			state[i] = binary.BigEndian.Uint32(data[4*i:])
		}

		message := data[32:]

		want, got := state, state

		compress256Generic(&want, message)

		compress256(&got, message)

		if got != want {
			t.Fatalf("compress256 differs from the portable code")
		}

		blocks := make([]uint32, len(message)/4&^15)

		for i := range blocks {
			blocks[i] = binary.BigEndian.Uint32(message[4*i:])
		}

		lanes := len(blocks) / 16

		wantLanes, gotLanes := make([]uint32, 8*lanes), make([]uint32, 8*lanes)

		sha256LanesGeneric(&state, blocks, 1, wantLanes)

		sha256Lanes(&state, blocks, 1, gotLanes)

		if !equalWords(gotLanes, wantLanes) {
			t.Fatalf("sha256Lanes differs from the portable code")
		}

		if lanes > 0 {
			single, generic := state, state

			sha256Block(&single, (*[16]uint32)(blocks))

			sha256BlockGeneric(&generic, (*[16]uint32)(blocks))

			if single != generic {
				t.Fatalf("sha256Block differs from the portable code")
			}
		}
	})
}

// The first byte picks the value length and shift, the next 32 the initial state; every further
// 104 bytes make a lane record, with up to 31 steps.
func FuzzSHA256Chains(f *testing.F) {
	f.Add(make([]byte, 33+3*104))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 33 {
			return
		}

		words, shift := 4+2*int(data[0]%3), uint(16+8*(data[0]>>2&1))

		var init [8]uint32

		for i := range init {
			init[i] = binary.BigEndian.Uint32(data[1+4*i:])
		}

		data = data[33:]

		// At most 80 lanes: past two of the lockstep path's 32-lane groups, and small enough that the
		// fuzzer keeps a high rate.
		lanes := make([]uint32, chainRecord*min(len(data)/104, 80))

		for l := range len(lanes) / chainRecord {
			record := lanes[chainRecord*l:]

			for i := range 16 + words {
				record[i] = binary.BigEndian.Uint32(data[104*l+4*i:])
			}

			record[24], record[25] = uint32(data[104*l+100]), uint32(data[104*l+101]&31)
		}

		want := append([]uint32{}, lanes...)

		chainReference(&init, want, words, shift)

		sha256Chains(&init, lanes, words, shift)

		if !equalWords(lanes, want) {
			t.Fatalf("sha256Chains differs from the portable code")
		}
	})
}

// The first 32 bytes are the scalar, the next 32 the point.
func FuzzX25519Kernels(f *testing.F) {
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 64 {
			return
		}

		if x25519(data[:32], data[32:64]) != x25519Generic(data[:32], data[32:64]) {
			t.Fatalf("x25519 differs from the portable code")
		}
	})
}

// The bytes become ML-DSA and ML-KEM coefficients, reduced below q, for both transforms.
func FuzzNTTKernels(f *testing.F) {
	f.Add(make([]byte, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 1024 {
			return
		}

		var w dsaPoly

		var k kemPoly

		for i := range 256 {
			w[i] = binary.LittleEndian.Uint32(data[4*i:]) % dsaQ

			k[i] = binary.LittleEndian.Uint16(data[2*i:]) % kemQ
		}

		for _, inverse := range []bool{false, true} {
			wantW, gotW, wantK, gotK := w, w, k, k

			if inverse {
				dsaInverseNTTGeneric(&wantW)

				dsaInverseNTT(&gotW)

				kemInverseNTTGeneric(&wantK)

				kemInverseNTT(&gotK)
			} else {
				dsaNTTGeneric(&wantW)

				dsaNTT(&gotW)

				kemNTTGeneric(&wantK)

				kemNTT(&gotK)
			}

			if gotW != wantW || gotK != wantK {
				t.Fatalf("an NTT differs from the portable code (inverse %v)", inverse)
			}
		}
	})
}

func FuzzSHA512Kernels(f *testing.F) {
	f.Add(make([]byte, 64+128))

	f.Add(make([]byte, 64+2*128+3))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 64 {
			return
		}

		var state [8]uint64

		for i := range state {
			state[i] = binary.BigEndian.Uint64(data[8*i:])
		}

		message := data[64:]

		want, got := state, state

		compress512Generic(&want, message)

		compress512(&got, message)

		if got != want {
			t.Fatalf("compress512 differs from the portable code")
		}

		if len(message) >= 128 {
			var w [16]uint64

			for i := range w {
				w[i] = binary.BigEndian.Uint64(message[8*i:])
			}

			single, generic := state, state

			sha512Block(&single, &w)

			sha512BlockGeneric(&generic, &w)

			if single != generic {
				t.Fatalf("sha512Block differs from the portable code")
			}
		}
	})
}

// Every 200 bytes make one state; the states are permuted one by one and as lanes.
func FuzzKeccakKernels(f *testing.F) {
	f.Add(make([]byte, 200))

	f.Add(make([]byte, 3*200))

	f.Fuzz(func(t *testing.T, data []byte) {
		states := make([][25]uint64, len(data)/200)

		for i := range states {
			for j := range states[i] {
				states[i][j] = binary.LittleEndian.Uint64(data[200*i+8*j:])
			}
		}

		want := append([][25]uint64{}, states...)

		permuteLanesGeneric(want)

		for i := range states {
			single := states[i]

			permute(&single)

			if single != want[i] {
				t.Fatalf("permute differs from the portable code")
			}
		}

		permuteLanes(states)

		for i := range states {
			if states[i] != want[i] {
				t.Fatalf("permuteLanes differs from the portable code")
			}
		}
	})
}

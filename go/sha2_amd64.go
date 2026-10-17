//go:build !purego

package cryptopq

//go:noescape
func sha256BlocksNI(state *[8]uint32, p []byte)

//go:noescape
func sha256WordsNI(state *[8]uint32, w *[16]uint32)

//go:noescape
func sha256LanesNI(init *[8]uint32, blocks []uint32, nb int, out []uint32)

//go:noescape
func sha256LanesAVX2(init *[8]uint32, blocks []uint32, nb int, out []uint32, scratch *[72][8]uint32)

//go:noescape
func sha256BlocksAVX2(state *[8]uint32, p []byte)

//go:noescape
func sha256WordsAVX2(state *[8]uint32, w *[16]uint32)

//go:noescape
func sha512BlocksAVX2(state *[8]uint64, p []byte)

// The assembly reads whole blocks only, so the lengths are settled here. Without the SHA
// extensions a single stream runs on AVX2 and BMI2; x86 has no common SHA-512 instructions, so
// SHA-512 always does.

// Whether sha256Lanes beats compressing the blocks one by one; callers batch only then, since
// gathering the batch costs the portable code time.
func sha256LanesFast() bool {
	return useSHANI || useAVX2
}

// Whether compress256 hashes two blocks for little more than the price of one, which the
// single-stream AVX2 kernel does: its message schedule takes both at once.
func sha256PairsFast() bool {
	return !useSHANI && useAVX2BMI2
}

func compress256(state *[8]uint32, p []byte) {
	n := len(p) &^ 63

	switch {
	case n == 0:
	case useSHANI:
		sha256BlocksNI(state, p[:n])
	case useAVX2BMI2:
		sha256BlocksAVX2(state, p[:n])
	default:
		compress256Generic(state, p)
	}
}

func sha256Block(state *[8]uint32, w *[16]uint32) {
	switch {
	case useSHANI:
		sha256WordsNI(state, w)
	case useAVX2BMI2:
		sha256WordsAVX2(state, w)
	default:
		sha256BlockGeneric(state, w)
	}
}

// With the SHA extensions the lanes go one by one; with AVX2 alone eight at a time, a last group
// of two to seven padded to eight, while a single lane is cheaper through sha256Block.
func sha256Lanes(init *[8]uint32, blocks []uint32, nb int, out []uint32) {
	checkLanes(len(blocks), 16*nb, len(out), 8)

	switch lanes := len(out) / 8; {
	case useSHANI:
		sha256LanesNI(init, blocks, nb, out)
	case !useAVX2 || lanes < 2 || nb > 3:
		sha256LanesSerial(init, blocks, nb, out)
	default:
		var scratch [72][8]uint32

		whole := lanes &^ 7

		if whole > 0 {
			sha256LanesAVX2(init, blocks[:16*nb*whole], nb, out[:8*whole], &scratch)
		}

		if rest := lanes - whole; rest == 1 {
			sha256LanesSerial(init, blocks[16*nb*whole:], nb, out[8*whole:])
		} else if rest > 1 {
			var group [8 * 16 * 3]uint32

			var states [8 * 8]uint32

			copy(group[:], blocks[16*nb*whole:])

			sha256LanesAVX2(init, group[:16*nb*8], nb, states[:], &scratch)

			copy(out[8*whole:], states[:8*rest])

			clear(group[:])

			clear(states[:])
		}

		clear(scratch[:])
	}
}

// sha256LanesGeneric with sha256Block, which has a kernel for single blocks.
func sha256LanesSerial(init *[8]uint32, blocks []uint32, nb int, out []uint32) {
	for lane := range len(out) / 8 {
		state := *init

		for b := range nb {
			sha256Block(&state, (*[16]uint32)(blocks[16*(nb*lane+b):]))
		}

		copy(out[8*lane:8*lane+8], state[:])
	}
}

// Runs hash chains whose values have words words, placed shift bits into word 5 (see chainBlock).
func sha256Chains(init *[8]uint32, lanes []uint32, words int, shift uint) {
	checkChains(lanes, words, shift)

	if sha256LanesFast() {
		sha256ChainsLockstep(init, lanes, words, shift)
	} else {
		sha256ChainsSerial(init, lanes, words, shift)
	}
}

func compress512(state *[8]uint64, p []byte) {
	if !useAVX2BMI2 {
		compress512Generic(state, p)

		return
	}

	if n := len(p) &^ 127; n > 0 {
		sha512BlocksAVX2(state, p[:n])
	}
}

func sha512Block(state *[8]uint64, w *[16]uint64) {
	sha512BlockGeneric(state, w)
}

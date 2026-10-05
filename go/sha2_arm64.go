//go:build !purego

package cryptopq

//go:noescape
func sha256BlocksARM(state *[8]uint32, p []byte)

//go:noescape
func sha256WordsARM(state *[8]uint32, w *[16]uint32)

//go:noescape
func sha256LanesARM(init *[8]uint32, blocks []uint32, nb int, out []uint32)

//go:noescape
func sha256Chains16ARM(init *[8]uint32, lanes []uint32, mask *[8]uint32)

//go:noescape
func sha256Chains24ARM(init *[8]uint32, lanes []uint32, mask *[8]uint32)

//go:noescape
func sha512BlocksARM(state *[8]uint64, p []byte)

//go:noescape
func sha512WordsARM(state *[8]uint64, w *[16]uint64)

// The assembly reads whole blocks only, so the lengths are settled here.

// Whether sha256Lanes beats compressing the blocks one by one; callers batch only then, since
// gathering the batch costs the portable code time.
func sha256LanesFast() bool {
	return useSHA2
}

func compress256(state *[8]uint32, p []byte) {
	if !useSHA2 {
		compress256Generic(state, p)

		return
	}

	if n := len(p) &^ 63; n > 0 {
		sha256BlocksARM(state, p[:n])
	}
}

func sha256Block(state *[8]uint32, w *[16]uint32) {
	if !useSHA2 {
		sha256BlockGeneric(state, w)

		return
	}

	sha256WordsARM(state, w)
}

func sha256Lanes(init *[8]uint32, blocks []uint32, nb int, out []uint32) {
	checkLanes(len(blocks), 16*nb, len(out), 8)

	if !useSHA2 {
		sha256LanesGeneric(init, blocks, nb, out)

		return
	}

	sha256LanesARM(init, blocks, nb, out)
}

// Runs hash chains whose values have words words, placed shift bits into word 5 (see chainBlock).
func sha256Chains(init *[8]uint32, lanes []uint32, words int, shift uint) {
	checkChains(lanes, words, shift)

	switch {
	case !useSHA2:
		sha256ChainsSerial(init, lanes, words, shift)
	case shift == 16:
		sha256Chains16ARM(init, lanes, &chainMasks[words/2-2])
	default:
		sha256Chains24ARM(init, lanes, &chainMasks[words/2-2])
	}
}

func compress512(state *[8]uint64, p []byte) {
	if !useSHA512 {
		compress512Generic(state, p)

		return
	}

	if n := len(p) &^ 127; n > 0 {
		sha512BlocksARM(state, p[:n])
	}
}

func sha512Block(state *[8]uint64, w *[16]uint64) {
	if !useSHA512 {
		sha512BlockGeneric(state, w)

		return
	}

	sha512WordsARM(state, w)
}

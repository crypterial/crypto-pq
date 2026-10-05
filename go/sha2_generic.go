//go:build (!arm64 && !amd64) || purego

package cryptopq

// The portable code gains nothing from batches.
func sha256LanesFast() bool {
	return false
}

func compress256(state *[8]uint32, p []byte) {
	compress256Generic(state, p)
}

func sha256Block(state *[8]uint32, w *[16]uint32) {
	sha256BlockGeneric(state, w)
}

func sha256Lanes(init *[8]uint32, blocks []uint32, nb int, out []uint32) {
	checkLanes(len(blocks), 16*nb, len(out), 8)

	sha256LanesGeneric(init, blocks, nb, out)
}

// Runs hash chains whose values have words words, placed shift bits into word 5 (see chainBlock).
func sha256Chains(init *[8]uint32, lanes []uint32, words int, shift uint) {
	checkChains(lanes, words, shift)

	sha256ChainsSerial(init, lanes, words, shift)
}

func compress512(state *[8]uint64, p []byte) {
	compress512Generic(state, p)
}

func sha512Block(state *[8]uint64, w *[16]uint64) {
	sha512BlockGeneric(state, w)
}

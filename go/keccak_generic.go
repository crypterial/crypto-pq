//go:build (!arm64 && !amd64) || purego

package cryptopq

func permute(s *[25]uint64) {
	permuteGeneric(s)
}

// Absorbs data, whole blocks of rate bytes, into the state.
func keccakAbsorb(state *[25]uint64, data []byte, rate int) {
	keccakAbsorbGeneric(state, data, rate)
}

// The portable code gains nothing from batches.
func permuteLanesFast() bool {
	return false
}

// Permutes every state.
func permuteLanes(states [][25]uint64) {
	permuteLanesGeneric(states)
}

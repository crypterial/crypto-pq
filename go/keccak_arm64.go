//go:build !purego

package cryptopq

//go:noescape
func keccak1ARM(s *[25]uint64)

//go:noescape
func keccakLanesARM(states *[25]uint64, n int)

func permute(s *[25]uint64) {
	if !useKeccakSHA3 {
		permuteGeneric(s)

		return
	}

	keccak1ARM(s)
}

// Whether permuteLanes beats permuting the states one by one; callers batch only then.
func permuteLanesFast() bool {
	return useKeccakSHA3
}

// Permutes every state; the SHA3 instructions take them two at a time.
func permuteLanes(states [][25]uint64) {
	if !useKeccakSHA3 || len(states) == 0 {
		permuteLanesGeneric(states)

		return
	}

	keccakLanesARM(&states[0], len(states))
}

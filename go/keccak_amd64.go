//go:build !purego

package cryptopq

//go:noescape
func keccakLanesAVX2(states *[25]uint64, n int, scratch *[50][4]uint64)

// One state alone stays scalar: the AVX2 kernel costs the same for one state as for four.
func permute(s *[25]uint64) {
	permuteGeneric(s)
}

// Whether permuteLanes beats permuting the states one by one; callers batch only then.
func permuteLanesFast() bool {
	return useAVX2
}

// Permutes every state, four at a time with AVX2; a last group of two or three is padded to four,
// and a single last state goes alone. The interleaved copies in scratch may hold secret states.
func permuteLanes(states [][25]uint64) {
	if !useAVX2 || len(states) < 2 {
		permuteLanesGeneric(states)

		return
	}

	var scratch [50][4]uint64

	whole := len(states) &^ 3

	if whole > 0 {
		keccakLanesAVX2(&states[0], whole, &scratch)
	}

	switch rest := states[whole:]; len(rest) {
	case 0:
	case 1:
		permuteGeneric(&rest[0])
	default:
		var group [4][25]uint64

		copy(group[:], rest)

		keccakLanesAVX2(&group[0], 4, &scratch)

		copy(rest, group[:len(rest)])

		clear(group[:])
	}

	clear(scratch[:])
}

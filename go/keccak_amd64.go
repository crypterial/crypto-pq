//go:build !purego

package cryptopq

//go:noescape
func keccakLanesAVX2(states *[25]uint64, n int, scratch *[50][4]uint64)

//go:noescape
func keccakF1600BMI(s *[25]uint64)

//go:noescape
func keccakAbsorbBMI(s *[25]uint64, data []byte, lanes int)

func permute(s *[25]uint64) {
	if !useAVX2BMI2 {
		permuteGeneric(s)

		return
	}

	keccakF1600BMI(s)
}

// Absorbs data, whole blocks of rate bytes, into the state; the kernel does it without returning
// between blocks.
func keccakAbsorb(state *[25]uint64, data []byte, rate int) {
	if !useAVX2BMI2 || !absorbRateBMI(rate) {
		keccakAbsorbGeneric(state, data, rate)

		return
	}

	keccakAbsorbBMI(state, data[:len(data)-len(data)%rate], rate/8)
}

// The rates the absorb kernel has code for (SHA3-224/256/384/512, SHAKE128/256); any other rate
// would come out wrong, so it takes the generic code.
func absorbRateBMI(rate int) bool {
	switch rate {
	case 72, 104, 136, 144, 168:
		return true
	}

	return false
}

// Whether permuteLanes beats permuting the states one by one; callers batch only then.
func permuteLanesFast() bool {
	return useAVX2
}

// Permutes every state, four at a time with AVX2; a last group of two or three is padded to four,
// and a single last state goes alone. The interleaved copies in scratch may hold secret states.
func permuteLanes(states [][25]uint64) {
	if !useAVX2 || len(states) < 2 {
		for i := range states {
			permute(&states[i])
		}

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
		permute(&rest[0])
	default:
		var group [4][25]uint64

		copy(group[:], rest)

		keccakLanesAVX2(&group[0], 4, &scratch)

		copy(rest, group[:len(rest)])

		clear(group[:])
	}

	clear(scratch[:])
}

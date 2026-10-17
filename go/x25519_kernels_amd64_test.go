//go:build !purego

package cryptopq

// The ladder of each tier runs on any CPU with what it needs, BMI2 for one and BMI2 with ADX for
// the other; the combs also need AVX2.
func x25519Kernels() []x25519Kernel {
	out := []x25519Kernel{{"dispatch", x25519}}

	if x86.mulx {
		out = append(out, x25519Kernel{"BMI2 and ADX", func(scalar, u []byte) [32]byte { return x25519Ladder(scalar, u, true) }})
	}

	if x86.bmi2 {
		out = append(out, x25519Kernel{"BMI2", func(scalar, u []byte) [32]byte { return x25519Ladder(scalar, u, false) }})
	}

	return out
}

func x25519BaseKernels() []x25519BaseKernel {
	out := []x25519BaseKernel{{"dispatch", x25519Base}}

	if useAVX2BMI2 && x86.adx {
		out = append(out, x25519BaseKernel{"AVX2, BMI2 and ADX", func(scalar []byte) [32]byte { return x25519Comb(scalar, true) }})
	}

	if useAVX2BMI2 {
		out = append(out, x25519BaseKernel{"AVX2 and BMI2", func(scalar []byte) [32]byte { return x25519Comb(scalar, false) }})
	}

	return out
}

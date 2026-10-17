//go:build !purego

package cryptopq

func cpuid(leaf, subleaf uint32) (eax, ebx, ecx, edx uint32)

func xgetbv() (eax, edx uint32)

// What the CPU offers, asked once when the package is initialized; the purego build tag leaves
// all of it out and runs the portable code.
type x86Features struct {
	shani, avx2, bmi1, bmi2, adx, mulx bool
}

// CPUID leaf 1 reports SSSE3 (ECX bit 9), SSE4.1 (19), POPCNT (23), OSXSAVE (27) and AVX (28); leaf
// 7 reports BMI1 (EBX bit 3), AVX2 (5), BMI2 (8), ADX (19) and the SHA extensions (29). AVX2 also
// needs the operating system to save the YMM registers, which XCR0 bits 1 and 2 show, and counts as
// present only with POPCNT, which the AVX2 kernels of ML-KEM and ML-DSA use (every AVX2 CPU has it).
func x86Detect() x86Features {
	top, _, _, _ := cpuid(0, 0)

	_, _, ecx1, _ := cpuid(1, 0)

	var ebx7 uint32

	if top >= 7 {
		_, ebx7, _, _ = cpuid(7, 0)
	}

	ymm := false

	if ecx1&(1<<27) != 0 {
		xcr0, _ := xgetbv()

		ymm = xcr0&6 == 6
	}

	f := x86Features{
		shani: ebx7&(1<<29) != 0 && ecx1&(1<<9) != 0 && ecx1&(1<<19) != 0,
		avx2:  ebx7&(1<<5) != 0 && ecx1&(1<<28) != 0 && ecx1&(1<<23) != 0 && ymm,
		bmi1:  ebx7&(1<<3) != 0,
		bmi2:  ebx7&(1<<8) != 0,
		adx:   ebx7&(1<<19) != 0,
	}

	f.mulx = f.bmi2 && f.adx

	return f
}

var x86 = x86Detect()

var useSHANI = x86.shani

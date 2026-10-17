//go:build !purego && !amd64.v3

package cryptopq

var useAVX2 = x86.avx2

// The scalar kernels that use BMI1 and BMI2 (ANDN, RORX and MULX) run where the AVX2 ones do,
// on the CPUs from 2013 on (Intel Haswell, AMD Excavator and Zen), which have both.
var useAVX2BMI2 = x86.avx2 && x86.bmi1 && x86.bmi2

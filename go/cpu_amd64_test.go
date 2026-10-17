//go:build !purego

package cryptopq

import "fmt"

func kernelReport() string {
	return fmt.Sprintf("amd64: CPU %+v; SHA extensions %v, AVX2 %v, MULX and ADX %v; AVX2 with BMI1 and BMI2 %v", x86, useSHANI, useAVX2, x86.mulx, useAVX2BMI2)
}

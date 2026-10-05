//go:build !purego

package cryptopq

import "fmt"

func kernelReport() string {
	return fmt.Sprintf("amd64: CPU %+v; SHA extensions %v, AVX2 %v, MULX and ADX %v", x86, useSHANI, useAVX2, x86.mulx)
}

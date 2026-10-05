//go:build !purego && !amd64.v3

package cryptopq

var useAVX2 = x86.avx2

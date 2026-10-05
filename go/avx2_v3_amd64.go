//go:build !purego && amd64.v3

package cryptopq

// GOAMD64=v3 and above guarantee AVX2, which the Go runtime checks when the program starts.
const useAVX2 = true

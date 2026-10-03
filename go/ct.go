package cryptopq

import "runtime"

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var difference byte

	for i := range a {
		difference |= a[i] ^ b[i]
	}

	return difference == 0
}

// 1 when the equally long inputs match and 0 otherwise, without a branch on their contents.
func equalBit(a, b []byte) int {
	var difference byte

	for i := range a {
		difference |= a[i] ^ b[i]
	}

	return int((uint32(difference) - 1) >> 31)
}

// out = a when bit is 1 and b when it is 0.
func selectBytes(bit int, a, b, out []byte) {
	mask := byte(-bit)

	for i := range out {
		out[i] = b[i] ^ (mask & (a[i] ^ b[i]))
	}
}

// Go has no destructors, so the secret buffers of a key are cleared once the key becomes
// unreachable; every method that reads them keeps the key alive until it returns.
func wipeWhenUnreachable[T any](owner *T, buffers ...[]byte) {
	runtime.AddCleanup(owner, func(buffers [][]byte) {
		for _, buffer := range buffers {
			clear(buffer)
		}
	}, buffers)
}

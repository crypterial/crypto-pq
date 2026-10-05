//go:build !arm64 || purego

package cryptopq

// Without PSTATE.DIT, the brackets around operations on secrets do nothing.
func ditEnter() bool {
	return false
}

func ditLeave(bool) {}

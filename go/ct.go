package cryptopq

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

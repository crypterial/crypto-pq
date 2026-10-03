package cryptopq

import "crypto/rand"

func randomBytes(length int) ([]byte, error) {
	out := make([]byte, length)

	if n, err := rand.Read(out); err != nil || n != length {
		return nil, newError(RNG_FAILURE, "the operating system did not provide random bytes")
	}

	return out, nil
}

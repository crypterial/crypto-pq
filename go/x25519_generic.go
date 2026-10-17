//go:build (!arm64 && !amd64) || purego

package cryptopq

func x25519(scalar, u []byte) [32]byte {
	return x25519Generic(scalar, u)
}

func x25519Base(scalar []byte) [32]byte {
	return x25519BaseGeneric(scalar)
}

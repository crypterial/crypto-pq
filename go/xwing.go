package cryptopq

// X-Wing (draft-connolly-cfrg-xwing-kem): ML-KEM-768 and X25519 combined with SHA3-256.

const (
	xwingPublicKeySize  = 1216
	xwingCiphertextSize = 1120
	xwingMlkemSize      = 1184
	xwingLabel          = `\.//^\`
)

// The private key is the ML-KEM-768 decapsulation key, the X25519 scalar and its public point.
func xwingExpand(seed []byte) (public, dk, scalar, point []byte) {
	var expanded [96]byte

	shake256Sum(expanded[:], seed)

	ek, dk := mlkemKeyGenInto(&mlkem768, expanded[:32], expanded[32:64], make([]byte, xwingMlkemSize, xwingPublicKeySize))

	scalar = make([]byte, 32)

	copy(scalar, expanded[64:])

	clear(expanded[:])

	base := x25519Base(scalar)

	public = append(ek, base[:]...)

	return public, dk, scalar, public[xwingMlkemSize:]
}

func xwingCombine(ssM, ssX, ctX, pkX []byte) []byte {
	sharedSecret := make([]byte, 32)

	sha3Sum256(sharedSecret, ssM, ssX, ctX, pkX, []byte(xwingLabel))

	return sharedSecret
}

func xwingCheckPublicKey(pk []byte) bool {
	return len(pk) == xwingPublicKeySize && mlkemCheckEncapsulationKey(&mlkem768, pk[:xwingMlkemSize])
}

// key holds what the ML-KEM part of pk derives.
func xwingEncapsulate(pk []byte, key *mlkemPublic, eseed []byte) (sharedSecret, ciphertext []byte) {
	pkM, pkX := pk[:xwingMlkemSize], pk[xwingMlkemSize:]

	ciphertext = make([]byte, xwingCiphertextSize)

	var ssM [32]byte

	mlkemEncapsulateInto(&mlkem768, pkM, key, eseed[:32], ssM[:], ciphertext[:xwingCiphertextSize-32])

	ctX := x25519Base(eseed[32:])

	ssX := x25519(eseed[32:], pkX)

	copy(ciphertext[xwingCiphertextSize-32:], ctX[:])

	sharedSecret = xwingCombine(ssM[:], ssX[:], ctX[:], pkX)

	clear(ssM[:])

	clear(ssX[:])

	return sharedSecret, ciphertext
}

func xwingDecapsulate(dk []byte, secret *mlkemSecret, key *mlkemPublic, scalar, point, ciphertext []byte) []byte {
	ctM, ctX := ciphertext[:1088], ciphertext[1088:]

	var ssM [32]byte

	mlkemDecapsulateInto(&mlkem768, dk, secret, key, ctM, ssM[:])

	ssX := x25519(scalar, ctX)

	sharedSecret := xwingCombine(ssM[:], ssX[:], ctX, point)

	clear(ssM[:])

	clear(ssX[:])

	return sharedSecret
}

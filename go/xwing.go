package cryptopq

// X-Wing (draft-connolly-cfrg-xwing-kem): ML-KEM-768 and X25519 combined with SHA3-256.

const (
	xwingPublicKeySize  = 1216
	xwingCiphertextSize = 1120
	xwingLabel          = `\.//^\`
)

// The private key is the ML-KEM-768 decapsulation key, the X25519 scalar and its public point.
func xwingExpand(seed []byte) (public, dk, scalar, point []byte) {
	var expanded [96]byte

	shake256Sum(expanded[:], seed)

	ek, dk := mlkemKeyGen(&mlkem768, expanded[:32], expanded[32:64])

	scalar = make([]byte, 32)

	copy(scalar, expanded[64:])

	clear(expanded[:])

	base := x25519(scalar, x25519Base[:])

	point = base[:]

	return append(ek, point...), dk, scalar, point
}

func xwingCombine(ssM, ssX, ctX, pkX []byte) []byte {
	sharedSecret := make([]byte, 32)

	sha3Sum256(sharedSecret, ssM, ssX, ctX, pkX, []byte(xwingLabel))

	return sharedSecret
}

func xwingCheckPublicKey(pk []byte) bool {
	return len(pk) == xwingPublicKeySize && mlkemCheckEncapsulationKey(&mlkem768, pk[:1184])
}

func xwingEncapsulate(pk, eseed []byte) (sharedSecret, ciphertext []byte) {
	pkM, pkX := pk[:1184], pk[1184:]

	ssM, ctM := mlkemEncapsulate(&mlkem768, pkM, eseed[:32])

	ctX := x25519(eseed[32:], x25519Base[:])

	ssX := x25519(eseed[32:], pkX)

	sharedSecret = xwingCombine(ssM, ssX[:], ctX[:], pkX)

	clear(ssM)

	clear(ssX[:])

	return sharedSecret, append(ctM, ctX[:]...)
}

func xwingDecapsulate(dk, scalar, point, ciphertext []byte) []byte {
	ctM, ctX := ciphertext[:1088], ciphertext[1088:]

	ssM := mlkemDecapsulate(&mlkem768, dk, ctM)

	ssX := x25519(scalar, ctX)

	sharedSecret := xwingCombine(ssM, ssX[:], ctX, point)

	clear(ssM)

	clear(ssX[:])

	return sharedSecret
}

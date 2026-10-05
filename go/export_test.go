package cryptopq

// Test-only access to internals that are not part of the public API.

var X25519, X25519Base = x25519, x25519Base

// The name, tree height and node size of an LMS type code.
func LmsType(code uint32) (string, int, int) {
	if t := lmsByCode(code); t != nil {
		return t.name, t.h, t.m
	}

	return "", 0, 0
}

// The name and signature size of an LM-OTS type code.
func LmotsType(code uint32) (string, int) {
	if t := lmotsByCode(code); t != nil {
		return t.name, t.signatureSize()
	}

	return "", 0
}

// Whether two KEM keys share one cache, and whether the matrix in it has been computed.
func KemCache(public *KemPublicKey, private *KemPrivateKey) (shared, expanded bool) {
	return public.cache == private.cache, private.cache.a != nil
}

// Whether two ML-DSA keys share one cache, and whether the matrix in it has been computed.
func SignatureCache(public *SignaturePublicKey, private *SignaturePrivateKey) (shared, expanded bool) {
	return public.cache == private.cache, private.cache.a != nil
}

// The leaves that the trees a stateful key holds have computed.
func LeavesComputed(key *StatefulPrivateKey) uint64 {
	var total uint64

	for _, held := range key.signer.cached() {
		total += held.merkle.leaves
	}

	return total
}

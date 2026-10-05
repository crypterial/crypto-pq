//go:build !ios && !purego

package cryptopq

// macOS on arm64 runs on Apple M-series cores, which all have SHA2, SHA512, SHA3 and DIT.
func armDetect() armFeatures {
	return armFeatures{sha2: true, sha512: true, sha3: true, dit: true, apple: true}
}

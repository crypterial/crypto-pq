//go:build (!arm64 && !amd64) || purego

package cryptopq

func asconPermute(s *[5]uint64) {
	asconPermuteGeneric(s)
}

func asconAbsorbWords(s *[5]uint64, data []byte) {
	asconAbsorbWordsGeneric(s, data)
}

//go:build (!arm64 && !amd64) || purego

package cryptopq

func kernelReport() string {
	return "portable code only"
}

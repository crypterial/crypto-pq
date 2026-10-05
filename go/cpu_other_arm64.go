//go:build !linux && !darwin && !windows && !purego

package cryptopq

// The BSDs and other systems run the portable code.
func armDetect() armFeatures {
	return armFeatures{}
}

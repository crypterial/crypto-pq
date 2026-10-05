//go:build !purego

package cryptopq

import "syscall"

// The PF_ARM_* values of IsProcessorFeaturePresent: 30 covers the ARMv8 crypto instructions,
// SHA-256 among them. Windows reports nothing for DIT, and its arm64 machines are not Apple's.
const (
	pfArmV8Crypto = 30
	pfArmSHA3     = 64
	pfArmSHA512   = 65
)

func armDetect() armFeatures {
	present := syscall.NewLazyDLL("kernel32.dll").NewProc("IsProcessorFeaturePresent")

	if present.Find() != nil {
		return armFeatures{}
	}

	has := func(feature uintptr) bool {
		r, _, _ := present.Call(feature)

		return r != 0
	}

	return armFeatures{sha2: has(pfArmV8Crypto), sha512: has(pfArmSHA512), sha3: has(pfArmSHA3)}
}

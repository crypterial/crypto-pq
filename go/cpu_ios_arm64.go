//go:build !purego

package cryptopq

import "syscall"

// Older iPhone and iPad cores lack some of the extensions, which iOS reports through sysctl as an
// integer; its first byte is 1 when the feature is present. Every arm64 Apple core has SHA2.
func sysctlFeature(name string) bool {
	value, err := syscall.Sysctl(name)

	return err == nil && len(value) > 0 && value[0] == 1
}

func armDetect() armFeatures {
	return armFeatures{
		sha2:   true,
		sha512: sysctlFeature("hw.optional.arm.FEAT_SHA512"),
		sha3:   sysctlFeature("hw.optional.arm.FEAT_SHA3"),
		dit:    sysctlFeature("hw.optional.arm.FEAT_DIT"),
		apple:  true,
	}
}

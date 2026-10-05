//go:build !purego

package cryptopq

import (
	"encoding/binary"
	"os"
)

// The HWCAP bits of the arm64 Linux kernel (arch/arm64/include/uapi/asm/hwcap.h).
const (
	hwcapSHA2   = 1 << 6
	hwcapCPUID  = 1 << 11
	hwcapSHA3   = 1 << 17
	hwcapSHA512 = 1 << 21
	hwcapDIT    = 1 << 24
)

// AT_HWCAP from the auxiliary vector, which /proc/self/auxv holds as pairs of 64-bit little-endian
// words, key then value. Without /proc the result is 0 and the portable code runs.
func hwcap() uint64 {
	data, err := os.ReadFile("/proc/self/auxv")

	if err != nil {
		return 0
	}

	for i := 0; i+16 <= len(data); i += 16 {
		if binary.LittleEndian.Uint64(data[i:]) == 16 {
			return binary.LittleEndian.Uint64(data[i+8:])
		}
	}

	return 0
}

// Linux emulates reading MIDR_EL1 when it reports HWCAP_CPUID; implementer 0x61 is Apple. On a
// system with several kinds of core the value is that of the core the thread runs on.
func armDetect() armFeatures {
	caps := hwcap()

	return armFeatures{
		sha2:   caps&hwcapSHA2 != 0,
		sha512: caps&hwcapSHA512 != 0,
		sha3:   caps&hwcapSHA3 != 0,
		dit:    caps&hwcapDIT != 0,
		apple:  caps&hwcapCPUID != 0 && midr()>>24&0xff == 0x61,
	}
}

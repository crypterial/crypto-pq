//go:build !purego

package cryptopq

import (
	"bytes"
	"os"
	"slices"
	"testing"
)

// The features from the auxiliary vector agree with the kernel's own list in /proc/cpuinfo.
func TestLinuxFeatures(t *testing.T) {
	info, err := os.ReadFile("/proc/cpuinfo")

	if err != nil {
		t.Skip("no /proc/cpuinfo")
	}

	var names []string

	for line := range bytes.Lines(info) {
		if name, value, ok := bytes.Cut(line, []byte(":")); ok && string(bytes.TrimSpace(name)) == "Features" {
			for _, field := range bytes.Fields(value) {
				names = append(names, string(field))
			}

			break
		}
	}

	caps := hwcap()

	t.Logf("HWCAP %#x, MIDR %#x, features %v", caps, midr(), names)

	for _, feature := range []struct {
		name string
		bit  uint64
	}{{"sha2", hwcapSHA2}, {"cpuid", hwcapCPUID}, {"sha3", hwcapSHA3}, {"sha512", hwcapSHA512}, {"dit", hwcapDIT}} {
		if slices.Contains(names, feature.name) != (caps&feature.bit != 0) {
			t.Errorf("/proc/cpuinfo and HWCAP disagree on %s", feature.name)
		}
	}
}

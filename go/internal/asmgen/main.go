// Command asmgen writes the assembly of crypto-pq's CPU-specific kernels, so that every instruction
// comes from code that can be read and rerun. Run it in the go directory of the repository; with
// -check it changes nothing and fails when a file differs from what it would write, which is how
// CI keeps the committed files and the generator in step.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
)

type output struct {
	name     string
	generate func(*asm)
}

var outputs = []output{
	{"cpu_arm64.s", cpuArm64},
	{"sha2_arm64.s", sha2Arm64},
	{"keccak_arm64.s", keccakArm64},
	{"x25519_arm64.s", x25519Arm64},
	{"ntt_arm64.s", nttArm64},
	{"kemntt_arm64.s", kemNTTArm64},
	{"cpu_amd64.s", cpuAmd64},
	{"sha2_amd64.s", sha2Amd64},
	{"keccak_amd64.s", keccakAmd64},
	{"ntt_amd64.s", nttAmd64},
	{"x25519_amd64.s", x25519Amd64},
}

func main() {
	check := flag.Bool("check", false, "report files that differ instead of writing them")

	flag.Parse()

	stale := false

	for _, o := range outputs {
		a := newAsm()

		o.generate(a)

		text := a.bytes()

		if !*check {
			if err := os.WriteFile(o.name, text, 0o644); err != nil {
				fmt.Fprintln(os.Stderr, err)

				os.Exit(1)
			}

			continue
		}

		current, err := os.ReadFile(o.name)

		if err != nil || !bytes.Equal(current, text) {
			fmt.Fprintf(os.Stderr, "%s differs from the output of internal/asmgen\n", o.name)

			stale = true
		}
	}

	if stale {
		os.Exit(1)
	}
}

package main

// The CPU queries and PSTATE.DIT on arm64.

func cpuArm64(a *asm) {
	a.function("midr", "func midr() uint64", 8,
		"MIDR_EL1, which Linux emulates for user space when it reports HWCAP_CPUID; elsewhere the",
		"instruction traps.")

	a.op("MRS\tMIDR_EL1, R0")

	a.op("MOVD\tR0, ret+0(FP)")

	a.op("RET")

	a.function("ditSet", "func ditSet() bool", 1,
		"Sets PSTATE.DIT and reports whether it was set already; the CPU must have FEAT_DIT. MRS",
		"returns the bit in position 24.")

	a.op("MRS\tDIT, R0")

	a.op("UBFX\t$24, R0, $1, R0")

	a.op("MOVB\tR0, ret+0(FP)")

	a.op("MSR\t$1, DIT")

	a.op("RET")

	a.function("ditClear", "func ditClear()", 0, "Clears PSTATE.DIT.")

	a.op("MSR\t$0, DIT")

	a.op("RET")
}

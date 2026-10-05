package main

// The CPU queries on amd64.

func cpuAmd64(a *asm) {
	a.function("cpuid", "func cpuid(leaf, subleaf uint32) (eax, ebx, ecx, edx uint32)", 24)

	a.op("MOVL\tleaf+0(FP), AX")

	a.op("MOVL\tsubleaf+4(FP), CX")

	a.op("CPUID")

	a.op("MOVL\tAX, eax+8(FP)")

	a.op("MOVL\tBX, ebx+12(FP)")

	a.op("MOVL\tCX, ecx+16(FP)")

	a.op("MOVL\tDX, edx+20(FP)")

	a.op("RET")

	a.function("xgetbv", "func xgetbv() (eax, edx uint32)", 8, "XCR0, the register states the operating system saves; the CPU must have OSXSAVE.")

	a.op("MOVL\t$0, CX")

	a.op("XGETBV")

	a.op("MOVL\tAX, eax+0(FP)")

	a.op("MOVL\tDX, edx+4(FP)")

	a.op("RET")
}

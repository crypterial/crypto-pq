package main

// Keccak-f[1600] with the ARMv8.2 SHA3 instructions, which work on whole 128-bit registers: lane
// i of two states sits in Vi, one state in each half. One state alone leaves the high halves
// computing the permutation of zero, at the same cost as two.

func keccakArm64(a *asm) {
	keccak1Arm(a)

	keccakLanesArm(a)

	a.table("keccakRC", 8, keccakConstants())
}

var keccakRho = [25]int{0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14}

// The 24 rounds on V0-V24, with the round constants read through R2 and R3 counting down; label
// names the loop, which must be unique in its function.
//
// Theta puts the column parities C[x] in V25-V29 (EOR3), then D[x] = C[x - 1] ^ rol(C[x + 1], 1)
// (RAX1) in V30, V31, V26, V27 and V28, overwriting parities no longer needed. Rho and pi move
// lane x + 5y to y + 5((2x + 3y) mod 5): lanes 1 to 24 form one cycle, walked backwards so that
// each lane is written just after its old value was read (XAR xors D in and rotates), with lane 1
// saved in V25 first; lane 0 does not move or rotate. Chi works plane by plane (BCAX) with copies
// of the first two lanes in V25 and V26, and iota xors the round constant, loaded into both
// halves, into lane 0.
func keccakRounds(a *asm, label string) {
	a.op("MOVD\t$keccakRC<>(SB), R2")

	a.op("MOVD\t$24, R3")

	a.label(label)

	for x := range 5 {
		a.op("VEOR3\tV%d.B16, V%d.B16, V%d.B16, V%d.B16", x+10, x+5, x, 25+x)

		a.op("VEOR3\tV%d.B16, V%d.B16, V%d.B16, V%d.B16", x+20, x+15, 25+x, 25+x)
	}

	a.op("VRAX1\tV26.D2, V29.D2, V30.D2")

	a.op("VRAX1\tV27.D2, V25.D2, V31.D2")

	a.op("VRAX1\tV28.D2, V26.D2, V26.D2")

	a.op("VRAX1\tV29.D2, V27.D2, V27.D2")

	a.op("VRAX1\tV25.D2, V28.D2, V28.D2")

	d := [5]int{30, 31, 26, 27, 28}

	var source [25]int

	for s := range 25 {
		x, y := s%5, s/5

		source[y+5*((2*x+3*y)%5)] = s
	}

	a.op("VMOV\tV1.B16, V25.B16")

	for t := 1; ; {
		s := source[t]

		from := s

		if s == 1 {
			from = 25
		}

		a.op("VXAR\t$%d, V%d.D2, V%d.D2, V%d.D2", 64-keccakRho[s], d[s%5], from, t)

		if s == 1 {
			break
		}

		t = s
	}

	a.op("VEOR\tV30.B16, V0.B16, V0.B16")

	for y := range 5 {
		r := func(x int) int { return 5*y + x }

		a.op("VMOV\tV%d.B16, V25.B16", r(0))

		a.op("VMOV\tV%d.B16, V26.B16", r(1))

		a.op("VBCAX\tV%d.B16, V%d.B16, V%d.B16, V%d.B16", r(1), r(2), r(0), r(0))

		a.op("VBCAX\tV%d.B16, V%d.B16, V%d.B16, V%d.B16", r(2), r(3), r(1), r(1))

		a.op("VBCAX\tV%d.B16, V%d.B16, V%d.B16, V%d.B16", r(3), r(4), r(2), r(2))

		a.op("VBCAX\tV%d.B16, V25.B16, V%d.B16, V%d.B16", r(4), r(3), r(3))

		a.op("VBCAX\tV25.B16, V26.B16, V%d.B16, V%d.B16", r(4), r(4))
	}

	a.op("VLD1R.P\t8(R2), [V26.D2]")

	a.op("VEOR\tV26.B16, V0.B16, V0.B16")

	a.op("SUBS\t$1, R3, R3")

	a.op("BNE\t%s", label)
}

// Loading a lane into Fi clears the high half of Vi.
func keccak1Arm(a *asm) {
	a.function("keccak1ARM", "func keccak1ARM(s *[25]uint64)", 8, "Permutes one state.")

	a.op("MOVD\ts+0(FP), R0")

	for i := range 25 {
		a.op("FMOVD\t%d(R0), F%d", 8*i, i)
	}

	keccakRounds(a, "round")

	for i := range 25 {
		a.op("FMOVD\tF%d, %d(R0)", i, 8*i)
	}

	a.op("RET")
}

// States 2j and 2j + 1 go together, the first in the low halves and the second in the high
// halves; an odd last state goes alone.
func keccakLanesArm(a *asm) {
	a.function("keccakLanesARM", "func keccakLanesARM(states *[25]uint64, n int)", 16, "Permutes the n consecutive states at states.")

	a.op("MOVD\tstates+0(FP), R0")

	a.op("MOVD\tn+8(FP), R4")

	a.label("pair")

	a.op("CMP\t$2, R4")

	a.op("BLT\tsingle")

	a.op("ADD\t$200, R0, R1")

	a.op("MOVD\tR1, R5")

	for i := range 25 {
		a.op("FMOVD\t%d(R0), F%d", 8*i, i)

		a.op("VLD1.P\t8(R1), V%d.D[1]", i)
	}

	keccakRounds(a, "pairRound")

	for i := range 25 {
		a.op("FMOVD\tF%d, %d(R0)", i, 8*i)

		a.op("VST1.P\tV%d.D[1], 8(R5)", i)
	}

	a.op("ADD\t$400, R0, R0")

	a.op("SUB\t$2, R4, R4")

	a.op("B\tpair")

	a.label("single")

	a.op("CBZ\tR4, done")

	for i := range 25 {
		a.op("FMOVD\t%d(R0), F%d", 8*i, i)
	}

	keccakRounds(a, "singleRound")

	for i := range 25 {
		a.op("FMOVD\tF%d, %d(R0)", i, 8*i)
	}

	a.label("done")

	a.op("RET")
}

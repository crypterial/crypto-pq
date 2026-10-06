package main

// Ascon-p[12] (SP 800-232) on the general registers: x0-x4 in R0-R4, scratch in R5-R10. The S-box
// uses BIC for the and-not terms; the linear layer computes x ^ (x >>> a) ^ (x >>> b) as
// x ^ ((x ^ (x >>> (b - a))) >>> a), word by word. The complement of x2 that ends the S-box is
// folded into its last XOR (EON), and the next round's constant is XORed into x2's S-box output
// while the linear layer runs, so neither lengthens the dependency chain. On Apple M3 separate ROR
// and EOR instructions measured 7% faster than EORs with a rotated operand, which take two cycles
// and issue on fewer pipes.

var asconRotations = [5][2]int{{19, 28}, {39, 61}, {1, 6}, {10, 17}, {7, 41}}

// The round constants of p[12] (const_4 to const_15 of SP 800-232, Table 5): 0xf0, 0xe1, ..., 0x4b.
func asconConstants() []int {
	var out []int

	for r := range 12 {
		out = append(out, (15-r)<<4|r)
	}

	return out
}

func asconArm64(a *asm) {
	asconPermuteArm(a)

	asconAbsorbArm(a)
}

// The twelve rounds on R0-R4, x2 already holding the first constant.
func asconRoundsArm(a *asm) {
	constants := asconConstants()

	for r := range 12 {
		a.op("EOR\tR4, R0, R0")

		a.op("EOR\tR3, R4, R4")

		a.op("EOR\tR1, R2, R2")

		for i := range 5 {
			a.op("BIC\tR%d, R%d, R%d", (i+1)%5, (i+2)%5, 5+i)
		}

		for i := range 5 {
			a.op("EOR\tR%d, R%d, R%d", 5+i, i, i)
		}

		a.op("EOR\tR0, R1, R1")

		a.op("EOR\tR4, R0, R0")

		a.op("EOR\tR2, R3, R3")

		if r < 11 {
			a.op("EOR\t$%#x, R2, R10", constants[r+1])
		}

		asconLinearArm(a, r < 11)
	}
}

func asconLoad(a *asm, pointer string) {
	a.op("LDP\t(%s), (R0, R1)", pointer)

	a.op("LDP\t16(%s), (R2, R3)", pointer)

	a.op("MOVD\t32(%s), R4", pointer)
}

func asconStore(a *asm, pointer string) {
	a.op("STP\t(R0, R1), (%s)", pointer)

	a.op("STP\t(R2, R3), 16(%s)", pointer)

	a.op("MOVD\tR4, 32(%s)", pointer)
}

func asconPermuteArm(a *asm) {
	a.function("asconPermuteARM", "func asconPermuteARM(s *[5]uint64)", 8, "Ascon-p[12] on s.")

	a.op("MOVD\ts+0(FP), R11")

	asconLoad(a, "R11")

	a.op("EOR\t$%#x, R2, R2", asconConstants()[0])

	asconRoundsArm(a)

	asconStore(a, "R11")

	a.op("RET")
}

func asconAbsorbArm(a *asm) {
	a.function("asconAbsorbARM", "func asconAbsorbARM(s *[5]uint64, data []byte)", 32,
		"XORs each 8-byte word of data into S0 and applies Ascon-p[12]; len(data) is a multiple of 8.")

	a.op("MOVD\ts+0(FP), R11")

	a.op("MOVD\tdata_base+8(FP), R12")

	a.op("MOVD\tdata_len+16(FP), R13")

	a.op("CBZ\tR13, done")

	asconLoad(a, "R11")

	a.label("loop")

	a.op("MOVD.P\t8(R12), R5")

	a.op("EOR\tR5, R0, R0")

	a.op("EOR\t$%#x, R2, R2", asconConstants()[0])

	asconRoundsArm(a)

	a.op("SUBS\t$8, R13, R13")

	a.op("BNE\tloop")

	asconStore(a, "R11")

	a.label("done")

	a.op("RET")
}

func asconFirstStage(a *asm, i int) {
	rotation := asconRotations[i]

	a.op("ROR\t$%d, R%d, R%d", rotation[1]-rotation[0], i, 5+i)

	a.op("EOR\tR%d, R%d, R%d", i, 5+i, 5+i)
}

func asconSecondStage(a *asm, i int, folded bool) {
	a.op("ROR\t$%d, R%d, R%d", asconRotations[i][0], 5+i, 5+i)

	switch {
	case i != 2:
		a.op("EOR\tR%d, R%d, R%d", 5+i, i, i)
	case folded:
		a.op("EON\tR%d, R10, R%d", 5+i, i)
	default:
		a.op("EON\tR%d, R%d, R%d", 5+i, i, i)
	}
}

// The linear layer; folded says that R10 holds x2 XOR the next round's constant.
func asconLinearArm(a *asm, folded bool) {
	for i := range 5 {
		asconFirstStage(a, i)

		asconSecondStage(a, i, folded)
	}
}

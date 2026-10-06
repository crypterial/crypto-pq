package main

// Ascon-p[12] on the x86-64 general registers: x0-x4 in R8-R12, scratch in AX, BX, CX, DX and SI,
// the state kept in registers from one absorbed word to the next. The and-not terms take a NOT and
// an AND (ANDN would need BMI1), and the linear layer computes x ^ (x >>> a) ^ (x >>> b) as
// x ^ ((x ^ (x >>> (b - a))) >>> a).

var asconX = [5]string{"R8", "R9", "R10", "R11", "R12"}

var asconT = [5]string{"AX", "BX", "CX", "DX", "SI"}

func asconAmd64(a *asm) {
	asconPermuteAmd(a)

	asconAbsorbAmd(a)
}

func asconRoundsAmd(a *asm) {
	for _, c := range asconConstants() {
		a.op("XORQ\t$%#x, %s", c, asconX[2])

		a.op("XORQ\t%s, %s", asconX[4], asconX[0])

		a.op("XORQ\t%s, %s", asconX[3], asconX[4])

		a.op("XORQ\t%s, %s", asconX[1], asconX[2])

		for i := range 5 {
			a.op("MOVQ\t%s, %s", asconX[(i+1)%5], asconT[i])

			a.op("NOTQ\t%s", asconT[i])

			a.op("ANDQ\t%s, %s", asconX[(i+2)%5], asconT[i])
		}

		for i := range 5 {
			a.op("XORQ\t%s, %s", asconT[i], asconX[i])
		}

		a.op("XORQ\t%s, %s", asconX[0], asconX[1])

		a.op("XORQ\t%s, %s", asconX[4], asconX[0])

		a.op("XORQ\t%s, %s", asconX[2], asconX[3])

		a.op("NOTQ\t%s", asconX[2])

		for i, rotation := range asconRotations {
			x, t := asconX[i], asconT[i]

			a.op("MOVQ\t%s, %s", x, t)

			a.op("RORQ\t$%d, %s", rotation[1]-rotation[0], t)

			a.op("XORQ\t%s, %s", x, t)

			a.op("RORQ\t$%d, %s", rotation[0], t)

			a.op("XORQ\t%s, %s", t, x)
		}
	}
}

func asconLoadAmd(a *asm, pointer string) {
	for i, x := range asconX {
		a.op("MOVQ\t%d(%s), %s", 8*i, pointer, x)
	}
}

func asconStoreAmd(a *asm, pointer string) {
	for i, x := range asconX {
		a.op("MOVQ\t%s, %d(%s)", x, 8*i, pointer)
	}
}

func asconPermuteAmd(a *asm) {
	a.function("asconPermuteAMD", "func asconPermuteAMD(s *[5]uint64)", 8, "Ascon-p[12] on s.")

	a.op("MOVQ\ts+0(FP), DI")

	asconLoadAmd(a, "DI")

	asconRoundsAmd(a)

	asconStoreAmd(a, "DI")

	a.op("RET")
}

func asconAbsorbAmd(a *asm) {
	a.function("asconAbsorbAMD", "func asconAbsorbAMD(s *[5]uint64, data []byte)", 32,
		"XORs each 8-byte word of data into S0 and applies Ascon-p[12]; len(data) is a multiple of 8.")

	a.op("MOVQ\ts+0(FP), DI")

	a.op("MOVQ\tdata_base+8(FP), R13")

	a.op("MOVQ\tdata_len+16(FP), R14")

	a.op("TESTQ\tR14, R14")

	a.op("JZ\tdone")

	asconLoadAmd(a, "DI")

	a.label("loop")

	a.op("XORQ\t(R13), %s", asconX[0])

	a.op("ADDQ\t$8, R13")

	asconRoundsAmd(a)

	a.op("SUBQ\t$8, R14")

	a.op("JNZ\tloop")

	asconStoreAmd(a, "DI")

	a.label("done")

	a.op("RET")
}

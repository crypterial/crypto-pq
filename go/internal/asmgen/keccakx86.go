package main

import "fmt"

// Keccak-f[1600] on four states with AVX2: lane i of the four states fills Yi of a 256-bit
// register, one state per 64-bit element. The 25 lanes do not fit in the sixteen registers, so a
// round reads its input lanes from one interleaved copy of the states and writes the output lanes
// to another, and the next round goes back, as the portable code alternates its a and e lanes. The
// rounds loop in pairs, which keeps the code small.

func keccakAmd64(a *asm) {
	keccakLanesAVX2(a)

	keccakF1600BMI(a)

	keccakAbsorbBMI(a)

	a.table("keccakRC", 8, keccakConstants())

	var constants []uint64

	for _, rc := range keccakConstants() {
		constants = append(constants, rc, rc, rc, rc)
	}

	a.table("keccakRC4", 8, constants)

	// VPSHUFB patterns that rotate each 64-bit element left by 8 and by 56 bits.
	a.table("rotate8", 8, []uint64{0x0605040302010007, 0x0e0d0c0b0a09080f, 0x0605040302010007, 0x0e0d0c0b0a09080f})

	a.table("rotate56", 8, []uint64{0x0007060504030201, 0x080f0e0d0c0b0a09, 0x0007060504030201, 0x080f0e0d0c0b0a09})
}

// Lane i of an interleaved copy at base: 32 bytes per lane.
func lane(base string, i int) string {
	return fmt.Sprintf("%d(%s)", 32*i, base)
}

// reg = rol(reg, r) with tmp as a temporary; 8 and 56 are byte shuffles.
func rotateLeft(a *asm, reg, tmp string, r int) {
	switch r {
	case 0:
	case 8:
		a.op("VPSHUFB\trotate8<>(SB), %s, %s", reg, reg)
	case 56:
		a.op("VPSHUFB\trotate56<>(SB), %s, %s", reg, reg)
	default:
		a.op("VPSLLQ\t$%d, %s, %s", r, reg, tmp)

		a.op("VPSRLQ\t$%d, %s, %s", 64-r, reg, reg)

		a.op("VPOR\t%s, %s, %s", tmp, reg, reg)
	}
}

// One round from the interleaved lanes at in to those at out, with the round constant at offset
// from R12, which walks keccakRC4. Theta: the column parities C in Y0-Y4, then D[x] = C[x - 1] ^ rol(C[x + 1],
// 1) in Y5-Y9. Each output plane y takes its five lanes B[x] = rol(A[s] ^ D[s mod 5], rho[s]) from
// the input lanes s that pi moves to it, into Y0-Y4, and chi writes B[x] ^ (~B[x + 1] & B[x + 2]).
func keccakRoundAVX2(a *asm, in, out string, offset int) {
	for x := range 5 {
		a.op("VMOVDQU\t%s, Y%d", lane(in, x), x)

		for y := 1; y < 5; y++ {
			a.op("VPXOR\t%s, Y%d, Y%d", lane(in, x+5*y), x, x)
		}
	}

	for x := range 5 {
		next, previous := (x+1)%5, (x+4)%5

		a.op("VPSRLQ\t$63, Y%d, Y10", next)

		a.op("VPADDQ\tY%d, Y%d, Y%d", next, next, 5+x)

		a.op("VPOR\tY10, Y%d, Y%d", 5+x, 5+x)

		a.op("VPXOR\tY%d, Y%d, Y%d", previous, 5+x, 5+x)
	}

	var source [25]int

	for s := range 25 {
		x, y := s%5, s/5

		source[y+5*((2*x+3*y)%5)] = s
	}

	for y := range 5 {
		for x := range 5 {
			s := source[5*y+x]

			a.op("VPXOR\t%s, Y%d, Y%d", lane(in, s), 5+s%5, x)

			rotateLeft(a, fmt.Sprintf("Y%d", x), "Y10", keccakRho[s])
		}

		for x := range 5 {
			a.op("VPANDN\tY%d, Y%d, Y11", (x+2)%5, (x+1)%5)

			a.op("VPXOR\tY%d, Y11, Y11", x)

			if y == 0 && x == 0 {
				a.op("VPXOR\t%d(R12), Y11, Y11", offset)
			}

			a.op("VMOVDQU\tY11, %s", lane(out, 5*y+x))
		}
	}
}

// Moves lanes i to i + 3 of the four states at R8-R11 into the interleaved copy at DI, or back:
// the 4x4 transposition of 64-bit elements is its own inverse.
func transpose4(a *asm, i int, toStates bool) {
	states := []string{"R8", "R9", "R10", "R11"}

	for l, s := range states {
		if toStates {
			a.op("VMOVDQU\t%s, Y%d", lane("DI", i+l), l)
		} else {
			a.op("VMOVDQU\t%d(%s), Y%d", 8*i, s, l)
		}
	}

	a.op("VPUNPCKLQDQ\tY1, Y0, Y4")

	a.op("VPUNPCKHQDQ\tY1, Y0, Y5")

	a.op("VPUNPCKLQDQ\tY3, Y2, Y6")

	a.op("VPUNPCKHQDQ\tY3, Y2, Y7")

	a.op("VPERM2I128\t$0x20, Y6, Y4, Y0")

	a.op("VPERM2I128\t$0x20, Y7, Y5, Y1")

	a.op("VPERM2I128\t$0x31, Y6, Y4, Y2")

	a.op("VPERM2I128\t$0x31, Y7, Y5, Y3")

	for l, s := range states {
		if toStates {
			a.op("VMOVDQU\tY%d, %d(%s)", l, 8*i, s)
		} else {
			a.op("VMOVDQU\tY%d, %s", l, lane("DI", i+l))
		}
	}
}

// Lane 24 of the four states, one element at a time.
func lastLane(a *asm, toStates bool) {
	if toStates {
		a.op("VMOVDQU\t%s, Y0", lane("DI", 24))

		a.op("VEXTRACTI128\t$1, Y0, X1")

		a.op("VMOVQ\tX0, 192(R8)")

		a.op("VPEXTRQ\t$1, X0, 192(R9)")

		a.op("VMOVQ\tX1, 192(R10)")

		a.op("VPEXTRQ\t$1, X1, 192(R11)")

		return
	}

	a.op("VMOVQ\t192(R8), X0")

	a.op("VPINSRQ\t$1, 192(R9), X0, X0")

	a.op("VMOVQ\t192(R10), X1")

	a.op("VPINSRQ\t$1, 192(R11), X1, X1")

	a.op("VINSERTI128\t$1, X1, Y0, Y0")

	a.op("VMOVDQU\tY0, %s", lane("DI", 24))
}

func keccakLanesAVX2(a *asm) {
	a.function("keccakLanesAVX2", "func keccakLanesAVX2(states *[25]uint64, n int, scratch *[50][4]uint64)", 24,
		"Permutes the n consecutive states at states, n a multiple of four, four at a time; scratch",
		"holds the two interleaved copies.")

	a.op("MOVQ\tstates+0(FP), R8")

	a.op("MOVQ\tn+8(FP), CX")

	a.op("MOVQ\tscratch+16(FP), DI")

	a.op("LEAQ\t800(DI), SI")

	a.op("SHRQ\t$2, CX")

	a.op("JZ\tdone")

	a.label("group")

	a.op("LEAQ\t200(R8), R9")

	a.op("LEAQ\t400(R8), R10")

	a.op("LEAQ\t600(R8), R11")

	for i := 0; i < 24; i += 4 {
		transpose4(a, i, false)
	}

	lastLane(a, false)

	a.op("LEAQ\tkeccakRC4<>(SB), R12")

	a.op("MOVQ\t$12, BX")

	a.label("rounds")

	keccakRoundAVX2(a, "DI", "SI", 0)

	keccakRoundAVX2(a, "SI", "DI", 32)

	a.op("ADDQ\t$64, R12")

	a.op("DECQ\tBX")

	a.op("JNZ\trounds")

	for i := 0; i < 24; i += 4 {
		transpose4(a, i, true)
	}

	lastLane(a, true)

	a.op("ADDQ\t$800, R8")

	a.op("DECQ\tCX")

	a.op("JNZ\tgroup")

	a.label("done")

	a.op("VZEROUPPER")

	a.op("RET")
}

// Keccak-f[1600] on one state in the general-purpose registers, with ANDN (BMI1) for chi and RORX
// (BMI2) for D. The 25 lanes do not fit in the fifteen registers, so a round reads its input lanes
// from memory and writes its output lanes to the other copy, the state at DI and a copy in the
// frame alternating, as the four-state kernel does. The rounds loop in pairs: the unrolled
// permutation is too long for the decoded-instruction cache, and the decoders would then limit it.
//
// Registers: DI the state; the column parities C[0]-C[4] of the input lanes in AX, BX, CX, DX, SI;
// D[0], D[1], D[2] in BP, R8, R9; one plane's B[0]-B[4] in R10-R14; R15 an output lane. D[3] and
// D[4] are computed into R13 and R14, which the first plane of the round reads, and are kept in the
// frame for the four planes after it. That first plane's output lanes start the parities of the
// next round, and every later plane adds to them, so a round begins with its parities in registers.
// The frame holds the copy (bytes 0-199), the pointer to the next round constants (200), the count
// of round pairs left (208), D[3] (216) and D[4] (224). The copy may hold secret lanes and D secret
// parities, so the frame is cleared before return.

var (
	keccakC = [5]string{"AX", "BX", "CX", "DX", "SI"}
	keccakD = [3]string{"BP", "R8", "R9"}
	keccakB = [5]string{"R10", "R11", "R12", "R13", "R14"}
)

const keccakT = "R15"

func stateLane(i int) string {
	return fmt.Sprintf("%d(DI)", 8*i)
}

func frameLane(i int) string {
	return fmt.Sprintf("%d(SP)", 8*i)
}

// Output plane y lane x takes B from the input lane source[5y + x] (rho and pi).
func keccakSources() (source [25]int) {
	for s := range 25 {
		x, y := s%5, s/5

		source[y+5*((2*x+3*y)%5)] = s
	}

	return source
}

// D[x] = C[x - 1] ^ rol(C[x + 1], 1) into register r.
func keccakTheta(a *asm, x int, r string) {
	a.op("RORXQ\t$63, %s, %s", keccakC[(x+1)%5], r)

	a.op("XORQ\t%s, %s", keccakC[(x+4)%5], r)
}

// One round from the lanes at in to those at out, with the round constant at offset rc from the
// pointer in the frame. Chi writes B[x] ^ (~B[x + 1] & B[x + 2]) in the order x = 1, 2, 3, 4, 0, so
// that R13 is free for the pointer when lane 0 takes the round constant.
func keccakRoundBMI(a *asm, in, out func(int) string, rc int) {
	source := keccakSources()

	for x := range 3 {
		keccakTheta(a, x, keccakD[x])
	}

	keccakTheta(a, 3, keccakB[3])

	keccakTheta(a, 4, keccakB[4])

	a.op("MOVQ\t%s, 216(SP)", keccakB[3])

	a.op("MOVQ\t%s, 224(SP)", keccakB[4])

	for y := range 5 {
		for x := range 5 {
			s := source[5*y+x]

			column := s % 5

			switch {
			case y == 0 && column >= 3:
				a.op("XORQ\t%s, %s", in(s), keccakB[x])
			case column >= 3:
				a.op("MOVQ\t%s, %s", in(s), keccakB[x])

				a.op("XORQ\t%d(SP), %s", 216+8*(column-3), keccakB[x])
			default:
				a.op("MOVQ\t%s, %s", in(s), keccakB[x])

				a.op("XORQ\t%s, %s", keccakD[column], keccakB[x])
			}

			if keccakRho[s] != 0 {
				a.op("ROLQ\t$%d, %s", keccakRho[s], keccakB[x])
			}
		}

		for _, x := range []int{1, 2, 3, 4, 0} {
			lane := keccakT

			if y == 0 {
				lane = keccakC[x]
			}

			a.op("ANDNQ\t%s, %s, %s", keccakB[(x+2)%5], keccakB[(x+1)%5], lane)

			a.op("XORQ\t%s, %s", keccakB[x], lane)

			if y == 0 && x == 0 {
				a.op("MOVQ\t200(SP), R13")

				a.op("XORQ\t%d(R13), %s", rc, lane)
			}

			a.op("MOVQ\t%s, %s", lane, out(5*y+x))

			if y > 0 {
				a.op("XORQ\t%s, %s", lane, keccakC[x])
			}
		}
	}
}

// The 24 rounds on the state at DI, the round constants' pointer and the pair count in the frame.
func keccakPermutationBMI(a *asm) {
	a.op("LEAQ\tkeccakRC<>(SB), R15")

	a.op("MOVQ\tR15, 200(SP)")

	a.op("MOVQ\t$12, 208(SP)")

	for x := range 5 {
		a.op("MOVQ\t%s, %s", stateLane(x), keccakC[x])

		for y := 1; y < 5; y++ {
			a.op("XORQ\t%s, %s", stateLane(x+5*y), keccakC[x])
		}
	}

	a.label("rounds")

	keccakRoundBMI(a, stateLane, frameLane, 0)

	keccakRoundBMI(a, frameLane, stateLane, 8)

	a.op("ADDQ\t$16, 200(SP)")

	a.op("DECQ\t208(SP)")

	a.op("JNZ\trounds")
}

// Clears the frame's n bytes (a multiple of 8) and leaves. The bytes from n on are the saved frame
// pointer and the caller's, so no store may reach them.
func keccakLeaveBMI(a *asm, n int) {
	a.op("VPXOR\tY0, Y0, Y0")

	i := 0

	for ; i+32 <= n; i += 32 {
		a.op("VMOVDQU\tY0, %d(SP)", i)
	}

	if i+16 <= n {
		a.op("VMOVDQU\tX0, %d(SP)", i)

		i += 16
	}

	if i < n {
		a.op("VMOVQ\tX0, %d(SP)", i)
	}

	a.op("VZEROUPPER")

	a.op("RET")
}

func keccakF1600BMI(a *asm) {
	a.text.WriteString("\n")

	a.comment("Keccak-f[1600] of the state s, for CPUs with BMI1, BMI2 and AVX (which clears the",
		"frame).",
		"func keccakF1600BMI(s *[25]uint64)")

	a.text.WriteString("TEXT ·keccakF1600BMI(SB), NOSPLIT, $232-8\n")

	a.op("MOVQ\ts+0(FP), DI")

	keccakPermutationBMI(a)

	keccakLeaveBMI(a, 232)
}

// The sponge's absorption of whole blocks: each block of lanes 64-bit words of data is xored into
// the state and the state permuted, without returning to Go between blocks. The rates of SHA-3,
// SHAKE and cSHAKE have 9, 13, 17, 18 or 21 lanes: the first nine are xored unconditionally, the
// rest in steps that compare against lanes. The frame adds the data pointer (232), its end (240)
// and lanes (248) to the permutation's.
func keccakAbsorbBMI(a *asm) {
	a.text.WriteString("\n")

	a.comment("Absorbs data, whole blocks of 8 lanes bytes, into s and permutes after each block.",
		"func keccakAbsorbBMI(s *[25]uint64, data []byte, lanes int)")

	a.text.WriteString("TEXT ·keccakAbsorbBMI(SB), NOSPLIT, $256-40\n")

	a.op("MOVQ\ts+0(FP), DI")

	a.op("MOVQ\tdata_base+8(FP), SI")

	a.op("MOVQ\tdata_len+16(FP), AX")

	a.op("MOVQ\tlanes+32(FP), CX")

	a.op("TESTQ\tAX, AX")

	a.op("JZ\tdone")

	a.op("ADDQ\tSI, AX")

	a.op("MOVQ\tSI, 232(SP)")

	a.op("MOVQ\tAX, 240(SP)")

	a.op("MOVQ\tCX, 248(SP)")

	a.label("block")

	a.op("MOVQ\t232(SP), SI")

	a.op("MOVQ\t248(SP), CX")

	xor := func(i int) {
		a.op("MOVQ\t%d(SI), AX", 8*i)

		a.op("XORQ\tAX, %s", stateLane(i))
	}

	for i := range 9 {
		xor(i)
	}

	for _, step := range [][2]int{{9, 13}, {13, 17}, {17, 18}, {18, 21}} {
		a.op("CMPQ\tCX, $%d", step[1])

		a.op("JB\txored")

		for i := step[0]; i < step[1]; i++ {
			xor(i)
		}
	}

	a.label("xored")

	a.op("LEAQ\t(SI)(CX*8), SI")

	a.op("MOVQ\tSI, 232(SP)")

	keccakPermutationBMI(a)

	a.op("MOVQ\t232(SP), SI")

	a.op("CMPQ\tSI, 240(SP)")

	a.op("JB\tblock")

	keccakLeaveBMI(a, 256)

	a.label("done")

	a.op("RET")
}

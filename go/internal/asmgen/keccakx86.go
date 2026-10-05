package main

import "fmt"

// Keccak-f[1600] on four states with AVX2: lane i of the four states fills Yi of a 256-bit
// register, one state per 64-bit element. The 25 lanes do not fit in the sixteen registers, so a
// round reads its input lanes from one interleaved copy of the states and writes the output lanes
// to another, and the next round goes back, as the portable code alternates its a and e lanes. The
// rounds loop in pairs, which keeps the code small.

func keccakAmd64(a *asm) {
	keccakLanesAVX2(a)

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

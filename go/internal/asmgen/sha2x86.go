package main

import "fmt"

// SHA-256 with the x86 SHA extensions. SHA256RNDS2 does two rounds on the state split as ABEF and
// CDGH, here X1 and X2, taking W + K from X0; the new ABEF replaces CDGH, and the old ABEF is the
// new CDGH, so two calls return the halves to their registers. The schedule words are in X3-X6.

func sha2Amd64(a *asm) {
	sha256BlocksNI(a)

	sha256WordsNI(a)

	sha256LanesNI(a)

	sha256AVX2(a)

	a.table("k256", 4, sha256Constants())

	a.table("flip", 8, []uint64{0x0405060700010203, 0x0c0d0e0f08090a0b})
}

var sha256Schedule = [4]string{"X3", "X4", "X5", "X6"}

// Turns the state words a-d and e-h in X1 and X2 into ABEF and CDGH; X7 is a temporary.
func sha256Split(a *asm) {
	a.op("PSHUFD\t$0xb1, X1, X1")

	a.op("PSHUFD\t$0x1b, X2, X2")

	a.op("MOVO\tX1, X7")

	a.op("PALIGNR\t$8, X2, X1")

	a.op("PBLENDW\t$0xf0, X7, X2")
}

// The inverse of sha256Split.
func sha256Join(a *asm) {
	a.op("PSHUFD\t$0x1b, X1, X1")

	a.op("PSHUFD\t$0xb1, X2, X2")

	a.op("MOVO\tX1, X7")

	a.op("PBLENDW\t$0xf0, X2, X1")

	a.op("PALIGNR\t$8, X7, X2")
}

// One block on ABEF and CDGH with the schedule loaded, the round constants at AX. Group g adds the
// constants to its four schedule words; SHA256MSG1 and SHA256MSG2 with the words of seven rounds
// earlier (PALIGNR) produce the schedule words twelve and four rounds ahead.
func sha256BlockNI(a *asm) {
	a.op("MOVO\tX1, X9")

	a.op("MOVO\tX2, X10")

	w := sha256Schedule

	for g := range 16 {
		a.op("MOVOU\t%d(AX), X0", 16*g)

		a.op("PADDL\t%s, X0", w[g%4])

		a.op("SHA256RNDS2\tX0, X1, X2")

		if g >= 3 && g <= 14 {
			a.op("MOVO\t%s, X7", w[g%4])

			a.op("PALIGNR\t$4, %s, X7", w[(g+3)%4])

			a.op("PADDL\tX7, %s", w[(g+1)%4])

			a.op("SHA256MSG2\t%s, %s", w[g%4], w[(g+1)%4])
		}

		a.op("PSHUFD\t$0x0e, X0, X0")

		a.op("SHA256RNDS2\tX0, X2, X1")

		if g >= 1 && g <= 12 {
			a.op("SHA256MSG1\t%s, %s", w[g%4], w[(g+3)%4])
		}
	}

	a.op("PADDL\tX9, X1")

	a.op("PADDL\tX10, X2")
}

func sha256BlocksNI(a *asm) {
	a.function("sha256BlocksNI", "func sha256BlocksNI(state *[8]uint32, p []byte)", 32,
		"Compresses every 64-byte block of p into state; len(p) is a multiple of 64.")

	a.op("MOVQ\tstate+0(FP), DI")

	a.op("MOVQ\tp_base+8(FP), SI")

	a.op("MOVQ\tp_len+16(FP), DX")

	a.op("SHRQ\t$6, DX")

	a.op("JZ\tdone")

	a.op("MOVOU\t(DI), X1")

	a.op("MOVOU\t16(DI), X2")

	sha256Split(a)

	a.op("MOVOU\tflip<>(SB), X8")

	a.op("LEAQ\tk256<>(SB), AX")

	a.label("loop")

	for i, reg := range sha256Schedule {
		a.op("MOVOU\t%d(SI), %s", 16*i, reg)

		a.op("PSHUFB\tX8, %s", reg)
	}

	sha256BlockNI(a)

	a.op("ADDQ\t$64, SI")

	a.op("DECQ\tDX")

	a.op("JNZ\tloop")

	sha256Join(a)

	a.op("MOVOU\tX1, (DI)")

	a.op("MOVOU\tX2, 16(DI)")

	a.label("done")

	a.op("RET")
}

func sha256WordsNI(a *asm) {
	a.function("sha256WordsNI", "func sha256WordsNI(state *[8]uint32, w *[16]uint32)", 16,
		"Compresses one block, given as its sixteen big-endian words, into state.")

	a.op("MOVQ\tstate+0(FP), DI")

	a.op("MOVQ\tw+8(FP), SI")

	a.op("MOVOU\t(DI), X1")

	a.op("MOVOU\t16(DI), X2")

	sha256Split(a)

	a.op("LEAQ\tk256<>(SB), AX")

	for i, reg := range sha256Schedule {
		a.op("MOVOU\t%d(SI), %s", 16*i, reg)
	}

	sha256BlockNI(a)

	sha256Join(a)

	a.op("MOVOU\tX1, (DI)")

	a.op("MOVOU\tX2, 16(DI)")

	a.op("RET")
}

// The lanes run one after another, each from the split initial state kept in X11 and X12.
func sha256LanesNI(a *asm) {
	a.function("sha256LanesNI", "func sha256LanesNI(init *[8]uint32, blocks []uint32, nb int, out []uint32)", 64,
		"Hashes len(out) / 8 independent lanes: lane i starts from init and compresses nb blocks of",
		"big-endian words, blocks[16 nb i:16 nb (i + 1)], and its state goes to out[8i:8i + 8].")

	a.op("MOVQ\tinit+0(FP), DI")

	a.op("MOVQ\tblocks_base+8(FP), SI")

	a.op("MOVQ\tnb+32(FP), BX")

	a.op("MOVQ\tout_base+40(FP), R8")

	a.op("MOVQ\tout_len+48(FP), CX")

	a.op("SHRQ\t$3, CX")

	a.op("JZ\tdone")

	a.op("TESTQ\tBX, BX")

	a.op("JZ\tdone")

	a.op("MOVOU\t(DI), X1")

	a.op("MOVOU\t16(DI), X2")

	sha256Split(a)

	a.op("MOVO\tX1, X11")

	a.op("MOVO\tX2, X12")

	a.op("LEAQ\tk256<>(SB), AX")

	a.label("lane")

	a.op("MOVO\tX11, X1")

	a.op("MOVO\tX12, X2")

	a.op("MOVQ\tBX, DX")

	a.label("block")

	for i, reg := range sha256Schedule {
		a.op("MOVOU\t%d(SI), %s", 16*i, reg)
	}

	sha256BlockNI(a)

	a.op("ADDQ\t$64, SI")

	a.op("DECQ\tDX")

	a.op("JNZ\tblock")

	sha256Join(a)

	a.op("MOVOU\tX1, (R8)")

	a.op("MOVOU\tX2, 16(R8)")

	a.op("ADDQ\t$32, R8")

	a.op("DECQ\tCX")

	a.op("JNZ\tlane")

	a.label("done")

	a.op("RET")
}

// SHA-256 on eight lanes with AVX2, for CPUs without the SHA extensions: Yi holds state word i of
// all eight lanes. The 16 registers hold the state, four temporaries and two for Maj, so the
// message schedule lives in the scratch memory the caller gives. Blocks arrive lane by lane and
// are transposed eight words at a time; so are the states at the end.

func sha256AVX2(a *asm) {
	sha256LanesAVX2(a)

	var replicated []uint64

	for _, k := range sha256Constants() {
		for range 8 {
			replicated = append(replicated, k)
		}
	}

	a.table("k256x8", 4, replicated)
}

// reg = rotations of x by the three amounts, xored together, through tmp: SHA-256's Sigma.
func sigmaAVX2(a *asm, x, reg, tmp string, r [3]int) {
	a.op("VPSRLD\t$%d, %s, %s", r[0], x, reg)

	a.op("VPSLLD\t$%d, %s, %s", 32-r[0], x, tmp)

	a.op("VPXOR\t%s, %s, %s", tmp, reg, reg)

	for _, n := range r[1:] {
		a.op("VPSRLD\t$%d, %s, %s", n, x, tmp)

		a.op("VPXOR\t%s, %s, %s", tmp, reg, reg)

		a.op("VPSLLD\t$%d, %s, %s", 32-n, x, tmp)

		a.op("VPXOR\t%s, %s, %s", tmp, reg, reg)
	}
}

// reg = rotations of x by r0 and r1 and x >> shift, xored together: the schedule's sigma.
func smallSigmaAVX2(a *asm, x, reg, tmp string, r0, r1, shift int) {
	a.op("VPSRLD\t$%d, %s, %s", shift, x, reg)

	for _, n := range []int{r0, r1} {
		a.op("VPSRLD\t$%d, %s, %s", n, x, tmp)

		a.op("VPXOR\t%s, %s, %s", tmp, reg, reg)

		a.op("VPSLLD\t$%d, %s, %s", 32-n, x, tmp)

		a.op("VPXOR\t%s, %s, %s", tmp, reg, reg)
	}
}

// Transposes the 8x8 words in rows (one row per lane) into words (one register per word), with
// the eight others as temporaries; rows and words may be the same registers.
func transpose8x8(a *asm, rows, temps [8]string) {
	t := temps

	for i := 0; i < 8; i += 2 {
		a.op("VPUNPCKLDQ\t%s, %s, %s", rows[i+1], rows[i], t[i])

		a.op("VPUNPCKHDQ\t%s, %s, %s", rows[i+1], rows[i], t[i+1])
	}

	for i := 0; i < 8; i += 4 {
		a.op("VPUNPCKLQDQ\t%s, %s, %s", t[i+2], t[i], rows[i])

		a.op("VPUNPCKHQDQ\t%s, %s, %s", t[i+2], t[i], rows[i+1])

		a.op("VPUNPCKLQDQ\t%s, %s, %s", t[i+3], t[i+1], rows[i+2])

		a.op("VPUNPCKHQDQ\t%s, %s, %s", t[i+3], t[i+1], rows[i+3])
	}

	for i := range 4 {
		a.op("VPERM2I128\t$0x20, %s, %s, %s", rows[i+4], rows[i], t[i])

		a.op("VPERM2I128\t$0x31, %s, %s, %s", rows[i+4], rows[i], t[i+4])
	}
}

// The scratch memory at DI: words 0-63 of the schedule (32 bytes each), then the state before
// the block. In the round loop R13 points at the schedule word and R14 at the round constants of
// its first round, so that round t of the eight reads offset 32t.
func scheduleWord(t int) string {
	return fmt.Sprintf("%d(DI)", 32*t)
}

func loopWord(t int) string {
	return fmt.Sprintf("%d(R13)", 32*t)
}

func savedState(i int) string {
	return fmt.Sprintf("%d(DI)", 32*64+32*i)
}

// One round on the state registers named in st (a to h), with b ^ c in bc; returns the names
// after the round and the register that holds the next b ^ c. Y8-Y10 are temporaries.
func sha256RoundAVX2(a *asm, t int, st [8]string, bc, ab string) ([8]string, string, string) {
	sa, sb, sc, sd, se, sf, sg, sh := st[0], st[1], st[2], st[3], st[4], st[5], st[6], st[7]

	sigmaAVX2(a, se, "Y8", "Y9", [3]int{6, 11, 25})

	a.op("VPXOR\t%s, %s, Y9", sg, sf)

	a.op("VPAND\t%s, Y9, Y9", se)

	a.op("VPXOR\t%s, Y9, Y9", sg)

	a.op("VPADDD\tY9, Y8, Y8")

	a.op("VPADDD\t%s, Y8, Y8", sh)

	a.op("VPADDD\t%d(R14), Y8, Y8", 32*t)

	a.op("VPADDD\t%s, Y8, Y8", loopWord(t))

	a.op("VPADDD\tY8, %s, %s", sd, sd)

	sigmaAVX2(a, sa, "Y9", "Y10", [3]int{2, 13, 22})

	a.op("VPXOR\t%s, %s, %s", sb, sa, ab)

	a.op("VPAND\t%s, %s, Y10", ab, bc)

	a.op("VPXOR\t%s, Y10, Y10", sb)

	a.op("VPADDD\tY10, Y9, Y9")

	a.op("VPADDD\tY9, Y8, %s", sh)

	return [8]string{sh, sa, sb, sc, sd, se, sf, sg}, ab, bc
}

func sha256LanesAVX2(a *asm) {
	a.function("sha256LanesAVX2", "func sha256LanesAVX2(init *[8]uint32, blocks []uint32, nb int, out []uint32, scratch *[72][8]uint32)", 72,
		"Hashes len(out) / 8 lanes, a multiple of eight, as sha256LanesNI does, eight at a time;",
		"scratch holds the message schedule and the state of the lanes in flight.")

	a.op("MOVQ\tinit+0(FP), R8")

	a.op("MOVQ\tblocks_base+8(FP), SI")

	a.op("MOVQ\tnb+32(FP), R9")

	a.op("MOVQ\tout_base+40(FP), R10")

	a.op("MOVQ\tout_len+48(FP), CX")

	a.op("MOVQ\tscratch+64(FP), DI")

	a.op("SHRQ\t$6, CX")

	a.op("JZ\tdone")

	a.op("TESTQ\tR9, R9")

	a.op("JZ\tdone")

	a.comment("R12 is the distance between the lanes' blocks, 64 nb bytes.")

	a.op("MOVQ\tR9, R12")

	a.op("SHLQ\t$6, R12")

	a.label("group")

	for i := range 8 {
		a.op("VPBROADCASTD\t%d(R8), Y%d", 4*i, i)
	}

	a.op("MOVQ\tSI, R11")

	a.op("MOVQ\tR9, DX")

	a.label("block")

	for i := range 8 {
		a.op("VMOVDQU\tY%d, %s", i, savedState(i))
	}

	var rows, temps [8]string

	for i := range 8 {
		rows[i], temps[i] = fmt.Sprintf("Y%d", i), fmt.Sprintf("Y%d", 8+i)
	}

	for half := range 2 {
		a.op("MOVQ\tR11, BX")

		for i := range 8 {
			a.op("VMOVDQU\t%d(BX), %s", 32*half, rows[i])

			if i < 7 {
				a.op("ADDQ\tR12, BX")
			}
		}

		transpose8x8(a, rows, temps)

		for w := range 8 {
			a.op("VMOVDQU\t%s, %s", temps[w], scheduleWord(8*half+w))
		}
	}

	a.comment("The rest of the schedule, W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16],",
		"with R13 at W[t].")

	a.op("LEAQ\t%s, R13", scheduleWord(16))

	a.op("MOVQ\t$48, BX")

	a.label("schedule")

	a.op("VMOVDQU\t%s, Y0", loopWord(-2))

	smallSigmaAVX2(a, "Y0", "Y1", "Y2", 17, 19, 10)

	a.op("VMOVDQU\t%s, Y0", loopWord(-15))

	smallSigmaAVX2(a, "Y0", "Y3", "Y2", 7, 18, 3)

	a.op("VPADDD\tY3, Y1, Y1")

	a.op("VPADDD\t%s, Y1, Y1", loopWord(-7))

	a.op("VPADDD\t%s, Y1, Y1", loopWord(-16))

	a.op("VMOVDQU\tY1, %s", loopWord(0))

	a.op("ADDQ\t$32, R13")

	a.op("DECQ\tBX")

	a.op("JNZ\tschedule")

	for i := range 8 {
		a.op("VMOVDQU\t%s, Y%d", savedState(i), i)
	}

	st := [8]string{"Y0", "Y1", "Y2", "Y3", "Y4", "Y5", "Y6", "Y7"}

	bc, ab := "Y12", "Y13"

	a.op("VPXOR\t%s, %s, %s", st[2], st[1], bc)

	a.comment("Eight rounds a pass: the names of the state registers, and of the two for Maj, come",
		"back after eight.")

	a.op("MOVQ\tDI, R13")

	a.op("LEAQ\tk256x8<>(SB), R14")

	a.op("MOVQ\t$8, BX")

	a.label("rounds")

	for t := range 8 {
		st, bc, ab = sha256RoundAVX2(a, t, st, bc, ab)
	}

	a.op("ADDQ\t$256, R13")

	a.op("ADDQ\t$256, R14")

	a.op("DECQ\tBX")

	a.op("JNZ\trounds")

	for i := range 8 {
		a.op("VPADDD\t%s, %s, %s", savedState(i), st[i], st[i])
	}

	a.op("ADDQ\t$64, R11")

	a.op("DECQ\tDX")

	a.op("JNZ\tblock")

	transpose8x8(a, rows, temps)

	for l := range 8 {
		a.op("VMOVDQU\t%s, %d(R10)", temps[l], 32*l)
	}

	a.op("ADDQ\t$256, R10")

	a.op("LEAQ\t(SI)(R12*8), SI")

	a.op("DECQ\tCX")

	a.op("JNZ\tgroup")

	a.label("done")

	a.op("VZEROUPPER")

	a.op("RET")
}

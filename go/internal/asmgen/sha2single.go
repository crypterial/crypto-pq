package main

import "fmt"

// Single-stream SHA-256 and SHA-512 with AVX2 and BMI2, for the CPUs without the SHA extensions.
// The rounds run in the general-purpose registers with RORX and ANDN, Ch as the sum of its two
// disjoint halves and Maj as ((a ^ b) & (b ^ c)) ^ b with the b ^ c of the previous round, as the
// portable code computes them. The message schedule runs in the vector registers, four words per
// instruction (for SHA-256 two blocks at once, one in each 128-bit half), interleaved with the
// rounds sixteen rounds ahead of the words; W[t] + K[t] goes to a buffer in the frame, which the
// rounds read. The buffer may hold words of secret messages and is cleared before return.
//
// Registers: the state a-h in AX, BX, CX, DX, R8-R11, renamed every round instead of moved; R12,
// R13 and BP temporaries (the frame keeps BP's value); R14 and R15 a ^ b and b ^ c, which swap
// roles every round; SI the offset of the current sixteen rounds in the buffer; DI the round
// constants. Y0-Y3 hold the last sixteen schedule words, Y4-Y9 are temporaries.

var sha2Registers = [8]string{"AX", "BX", "CX", "DX", "R8", "R9", "R10", "R11"}

type sha2Spec struct {
	suffix string // L or Q
	sigma1 [3]int // Sigma1, on e
	sigma0 [3]int // Sigma0, on a
}

var (
	sha256Spec = sha2Spec{"L", [3]int{6, 11, 25}, [3]int{2, 13, 22}}
	sha512Spec = sha2Spec{"Q", [3]int{14, 18, 41}, [3]int{28, 34, 39}}
)

// One round on the state named st (a to h), reading W[t] + K[t] at wk, with b ^ c in bc and ab
// free; returns its instructions and the names after it, ab and bc swapped. The e side comes first
// and ends with the new e, so that the next round's e side can start while the a side finishes,
// whose Maj goes before Sigma0; three temporaries let the three rotations of each Sigma issue
// together. Of the orders timed on the VPS (a Broadwell core) this one was fastest.
func sha2Round(sp sha2Spec, st [8]string, ab, bc, wk string) ([]string, [8]string, string, string) {
	a, b, d, e, f, g, h := st[0], st[1], st[3], st[4], st[5], st[6], st[7]

	s := sp.suffix

	op := func(format string, args ...any) string {
		return fmt.Sprintf(format, args...)
	}

	ops := []string{
		op("ADD%s\t%s, %s", s, wk, h),
		op("RORX%s\t$%d, %s, R12", s, sp.sigma1[0], e),
		op("RORX%s\t$%d, %s, R13", s, sp.sigma1[1], e),
		op("RORX%s\t$%d, %s, BP", s, sp.sigma1[2], e),
		op("XOR%s\tR13, R12", s),
		op("ANDN%s\t%s, %s, R13", s, g, e),
		op("XOR%s\tBP, R12", s),
		op("MOV%s\t%s, BP", s, f),
		op("AND%s\t%s, BP", s, e),
		op("ADD%s\tR13, %s", s, h),
		op("ADD%s\tBP, %s", s, h),
		op("ADD%s\tR12, %s", s, h),
		op("ADD%s\t%s, %s", s, h, d),
		op("MOV%s\t%s, %s", s, a, ab),
		op("XOR%s\t%s, %s", s, b, ab),
		op("AND%s\t%s, %s", s, ab, bc),
		op("XOR%s\t%s, %s", s, b, bc),
		op("RORX%s\t$%d, %s, R12", s, sp.sigma0[0], a),
		op("RORX%s\t$%d, %s, R13", s, sp.sigma0[1], a),
		op("RORX%s\t$%d, %s, BP", s, sp.sigma0[2], a),
		op("XOR%s\tR13, R12", s),
		op("ADD%s\t%s, %s", s, bc, h),
		op("XOR%s\tBP, R12", s),
		op("ADD%s\tR12, %s", s, h),
	}

	return ops, [8]string{h, a, b, st[2], d, e, f, g}, bc, ab
}

// Four rounds with the vector instructions of one schedule group spread among them; wk gives the
// memory operand of round r of the four.
func sha2Rounds(a *asm, sp sha2Spec, st [8]string, ab, bc string, wk func(r int) string, vector []string) ([8]string, string, string) {
	var scalar []string

	for r := range 4 {
		var ops []string

		ops, st, ab, bc = sha2Round(sp, st, ab, bc, wk(r))

		scalar = append(scalar, ops...)
	}

	next := 0

	for i, s := range scalar {
		a.op("%s", s)

		for next < len(vector) && (next+1)*len(scalar) <= (i+1)*(len(vector)+1) {
			a.op("%s", vector[next])

			next++
		}
	}

	for ; next < len(vector); next++ {
		a.op("%s", vector[next])
	}

	return st, ab, bc
}

func ymm(i int) string {
	return fmt.Sprintf("Y%d", i)
}

// SHA-512's sigma1 of the words in x into Y7, Y8 a temporary: rotations by 19 and 61, shift by 6.
func sha512Sigma1(x string) []string {
	return []string{
		fmt.Sprintf("VPSRLQ\t$19, %s, Y7", x),
		fmt.Sprintf("VPSLLQ\t$45, %s, Y8", x),
		"VPXOR\tY8, Y7, Y7",
		fmt.Sprintf("VPSRLQ\t$61, %s, Y8", x),
		"VPXOR\tY8, Y7, Y7",
		fmt.Sprintf("VPSLLQ\t$3, %s, Y8", x),
		"VPXOR\tY8, Y7, Y7",
		fmt.Sprintf("VPSRLQ\t$6, %s, Y8", x),
		"VPXOR\tY8, Y7, Y7",
	}
}

// The SHA-512 schedule words W[t..t+3] into x[0] from x = W[t-16..t-13], W[t-12..t-9], W[t-8..t-5]
// and W[t-4..t-1], and W + K stored at offset off from SI in the buffer, with K at off from DI.
// Y10 rotates each word right by 8 bits (VPSHUFB). W[t+2] and W[t+3] need sigma1 of W[t] and
// W[t+1], so sigma1 runs twice, on the low and then on the high 128-bit half.
func sha512ScheduleAVX2(x [4]string, off int) []string {
	ops := []string{
		fmt.Sprintf("VPERM2I128\t$0x21, %s, %s, Y4", x[3], x[2]),
		fmt.Sprintf("VPALIGNR\t$8, %s, Y4, Y4", x[2]),
		fmt.Sprintf("VPERM2I128\t$0x21, %s, %s, Y5", x[1], x[0]),
		fmt.Sprintf("VPALIGNR\t$8, %s, Y5, Y5", x[0]),
		fmt.Sprintf("VPADDQ\t%s, Y4, Y4", x[0]),
		"VPSRLQ\t$1, Y5, Y6",
		"VPSLLQ\t$63, Y5, Y7",
		"VPXOR\tY7, Y6, Y6",
		"VPSRLQ\t$7, Y5, Y7",
		"VPXOR\tY7, Y6, Y6",
		"VPSHUFB\tY10, Y5, Y7",
		"VPXOR\tY7, Y6, Y6",
		"VPADDQ\tY6, Y4, Y4",
		fmt.Sprintf("VPERM2I128\t$0x81, %s, %s, Y6", x[3], x[3]),
	}

	ops = append(ops, sha512Sigma1("Y6")...)

	ops = append(ops, "VPADDQ\tY7, Y4, Y4", "VPERM2I128\t$0x08, Y4, Y4, Y6")

	ops = append(ops, sha512Sigma1("Y6")...)

	return append(ops,
		fmt.Sprintf("VPADDQ\tY7, Y4, %s", x[0]),
		fmt.Sprintf("VPADDQ\t%d(DI)(SI*1), %s, Y5", off, x[0]),
		fmt.Sprintf("VMOVDQU\tY5, %d(SP)(SI*1)", off))
}

// Adds the state registers into the words at R12, as the block's end does.
func sha2AddState(a *asm, sp sha2Spec, size int) {
	for i, r := range sha2Registers {
		a.op("ADD%s\t%d(R12), %s", sp.suffix, size*i, r)

		a.op("MOV%s\t%s, %d(R12)", sp.suffix, r, size*i)
	}
}

// Clears the first n bytes of the frame (n a multiple of 32) and leaves.
func sha2Leave(a *asm, n int) {
	a.op("VPXOR\tY4, Y4, Y4")

	for i := 0; i < n; i += 32 {
		a.op("VMOVDQU\tY4, %d(SP)", i)
	}

	a.op("VZEROUPPER")

	a.op("RET")
}

func sha512BlocksAVX2(a *asm) {
	sp := sha512Spec

	a.text.WriteString("\n")

	a.comment("Compresses every 128-byte block of p into state; len(p) is a multiple of 128. The",
		"frame holds W + K of the 80 rounds (bytes 0-639), the next block (640) and the end of p",
		"(648).",
		"func sha512BlocksAVX2(state *[8]uint64, p []byte)")

	a.text.WriteString("TEXT ·sha512BlocksAVX2(SB), $656-32\n")

	a.op("MOVQ\tp_base+8(FP), R12")

	a.op("MOVQ\tp_len+16(FP), R13")

	a.op("ANDQ\t$-128, R13")

	a.op("JZ\tdone")

	a.op("MOVQ\tR12, 640(SP)")

	a.op("ADDQ\tR12, R13")

	a.op("MOVQ\tR13, 648(SP)")

	a.op("MOVQ\tstate+0(FP), R12")

	for i, r := range sha2Registers {
		a.op("MOVQ\t%d(R12), %s", 8*i, r)
	}

	a.op("VMOVDQU\tsha512Rotate8<>(SB), Y10")

	a.op("VMOVDQU\tsha512Flip<>(SB), Y11")

	a.op("LEAQ\tk512<>(SB), DI")

	a.label("block")

	a.op("MOVQ\t640(SP), R12")

	for g := range 4 {
		a.op("VMOVDQU\t%d(R12), %s", 32*g, ymm(g))

		a.op("VPSHUFB\tY11, %s, %s", ymm(g), ymm(g))

		a.op("VPADDQ\t%d(DI), %s, Y4", 32*g, ymm(g))

		a.op("VMOVDQU\tY4, %d(SP)", 32*g)
	}

	a.op("MOVQ\tBX, R15")

	a.op("XORQ\tCX, R15")

	a.op("XORQ\tSI, SI")

	st, ab, bc := sha2Registers, "R14", "R15"

	a.comment("Rounds 0-63, each group of four computing the schedule words of sixteen rounds later.")

	a.label("schedule")

	x := [4]string{"Y0", "Y1", "Y2", "Y3"}

	for g := range 4 {
		wk := func(r int) string { return fmt.Sprintf("%d(SP)(SI*1)", 32*g+8*r) }

		st, ab, bc = sha2Rounds(a, sp, st, ab, bc, wk, sha512ScheduleAVX2(x, 128+32*g))

		x = [4]string{x[1], x[2], x[3], x[0]}
	}

	a.op("ADDQ\t$128, SI")

	a.op("CMPQ\tSI, $512")

	a.op("JB\tschedule")

	a.comment("Rounds 64-79.")

	for g := range 4 {
		wk := func(r int) string { return fmt.Sprintf("%d(SP)", 512+32*g+8*r) }

		st, ab, bc = sha2Rounds(a, sp, st, ab, bc, wk, nil)
	}

	a.op("MOVQ\tstate+0(FP), R12")

	sha2AddState(a, sp, 8)

	a.op("MOVQ\t640(SP), R12")

	a.op("ADDQ\t$128, R12")

	a.op("MOVQ\tR12, 640(SP)")

	a.op("CMPQ\tR12, 648(SP)")

	a.op("JB\tblock")

	sha2Leave(a, 640)

	a.label("done")

	a.op("RET")
}

// SHA-256's sigma1 of the words t-2 and t-1 (or t and t + 1) in each half, picked from x by the
// VPSHUFD pattern pick into the low halves of the quadwords, so that the quadword shifts by 17
// and 19 rotate them; the results go into the words the VPSHUFB pattern in place selects, the
// others zero, and are added to Y4. Y6-Y8 are temporaries.
func sha256Sigma1(x string, pick int, place string) []string {
	return []string{
		fmt.Sprintf("VPSHUFD\t$%#x, %s, Y6", pick, x),
		"VPSRLD\t$10, Y6, Y7",
		"VPSRLQ\t$17, Y6, Y8",
		"VPXOR\tY8, Y7, Y7",
		"VPSRLQ\t$19, Y6, Y8",
		"VPXOR\tY8, Y7, Y7",
		fmt.Sprintf("VPSHUFB\t%s, Y7, Y7", place),
		"VPADDD\tY7, Y4, Y4",
	}
}

// The SHA-256 schedule words W[t..t+3] of both blocks into x[0], W + K stored at offset off from SI
// in the buffer with K at off from DI, as sha512ScheduleAVX2; Y11 and Y12 are the VPSHUFB patterns
// that put sigma1's results into words 0-1 and 2-3.
func sha256ScheduleAVX2(x [4]string, off int) []string {
	ops := []string{
		fmt.Sprintf("VPALIGNR\t$4, %s, %s, Y5", x[0], x[1]),
		fmt.Sprintf("VPALIGNR\t$4, %s, %s, Y4", x[2], x[3]),
		fmt.Sprintf("VPADDD\t%s, Y4, Y4", x[0]),
		"VPSRLD\t$7, Y5, Y6",
		"VPSLLD\t$25, Y5, Y7",
		"VPXOR\tY7, Y6, Y6",
		"VPSRLD\t$18, Y5, Y7",
		"VPXOR\tY7, Y6, Y6",
		"VPSLLD\t$14, Y5, Y7",
		"VPXOR\tY7, Y6, Y6",
		"VPSRLD\t$3, Y5, Y7",
		"VPXOR\tY7, Y6, Y6",
		"VPADDD\tY6, Y4, Y4",
	}

	ops = append(ops, sha256Sigma1(x[3], 0xfa, "Y11")...)

	ops = append(ops, sha256Sigma1("Y4", 0x50, "Y12")...)

	return append(ops,
		fmt.Sprintf("VMOVDQA\tY4, %s", x[0]),
		fmt.Sprintf("VPADDD\t%d(DI)(SI*1), %s, Y5", off, x[0]),
		fmt.Sprintf("VMOVDQU\tY5, %d(SP)(SI*1)", off))
}

// Sixteen rounds of one block without schedule work, reading W + K at offset base from SI plus 32
// bytes per group of four rounds and 4 per round.
func sha256PlainRounds(a *asm, st [8]string, ab, bc string, base int) ([8]string, string, string) {
	for g := range 4 {
		wk := func(r int) string { return fmt.Sprintf("%d(SP)(SI*1)", base+32*g+4*r) }

		st, ab, bc = sha2Rounds(a, sha256Spec, st, ab, bc, wk, nil)
	}

	return st, ab, bc
}

func sha256BlocksAVX2(a *asm) {
	sp := sha256Spec

	a.text.WriteString("\n")

	a.comment("Compresses every 64-byte block of p into state; len(p) is a multiple of 64. Two blocks",
		"go together, the first in the low and the second in the high 128-bit half of the schedule;",
		"a last single block fills both halves and only the first is used. The frame holds W + K of",
		"the 64 rounds of both blocks, 32 bytes per group of four rounds, the first block's 16 bytes",
		"of a group first (bytes 0-511), the next blocks (512) and the end of p (520).",
		"func sha256BlocksAVX2(state *[8]uint32, p []byte)")

	a.text.WriteString("TEXT ·sha256BlocksAVX2(SB), $528-32\n")

	a.op("MOVQ\tp_base+8(FP), R12")

	a.op("MOVQ\tp_len+16(FP), R13")

	a.op("ANDQ\t$-64, R13")

	a.op("JZ\tdone")

	a.op("MOVQ\tR12, 512(SP)")

	a.op("ADDQ\tR12, R13")

	a.op("MOVQ\tR13, 520(SP)")

	a.op("MOVQ\tstate+0(FP), R12")

	for i, r := range sha2Registers {
		a.op("MOVL\t%d(R12), %s", 4*i, r)
	}

	a.op("VMOVDQU\tsha256Flip<>(SB), Y10")

	a.op("VMOVDQU\tsha256Low<>(SB), Y11")

	a.op("VMOVDQU\tsha256High<>(SB), Y12")

	a.op("LEAQ\tk256x2<>(SB), DI")

	a.label("block")

	a.op("MOVQ\t512(SP), R12")

	a.op("MOVQ\t520(SP), R13")

	a.op("SUBQ\tR12, R13")

	a.op("CMPQ\tR13, $64")

	a.op("JE\tsingle")

	for g := range 4 {
		a.op("VMOVDQU\t%d(R12), X%d", 16*g, g)

		a.op("VINSERTI128\t$1, %d(R12), %s, %s", 64+16*g, ymm(g), ymm(g))
	}

	a.op("JMP\tloaded")

	a.label("single")

	for g := range 4 {
		a.op("VBROADCASTI128\t%d(R12), %s", 16*g, ymm(g))
	}

	a.label("loaded")

	for g := range 4 {
		a.op("VPSHUFB\tY10, %s, %s", ymm(g), ymm(g))

		a.op("VPADDD\t%d(DI), %s, Y4", 32*g, ymm(g))

		a.op("VMOVDQU\tY4, %d(SP)", 32*g)
	}

	a.op("MOVL\tBX, R15")

	a.op("XORL\tCX, R15")

	a.op("XORQ\tSI, SI")

	st, ab, bc := sha2Registers, "R14", "R15"

	a.comment("Rounds 0-47 of the first block, each group of four computing the schedule words of",
		"sixteen rounds later for both blocks.")

	a.label("schedule")

	x := [4]string{"Y0", "Y1", "Y2", "Y3"}

	for g := range 4 {
		wk := func(r int) string { return fmt.Sprintf("%d(SP)(SI*1)", 32*g+4*r) }

		st, ab, bc = sha2Rounds(a, sp, st, ab, bc, wk, sha256ScheduleAVX2(x, 128+32*g))

		x = [4]string{x[1], x[2], x[3], x[0]}
	}

	a.op("ADDQ\t$128, SI")

	a.op("CMPQ\tSI, $384")

	a.op("JB\tschedule")

	a.comment("Rounds 48-63 of the first block.")

	st, ab, bc = sha256PlainRounds(a, st, ab, bc, 0)

	a.op("MOVQ\tstate+0(FP), R12")

	sha2AddState(a, sp, 4)

	a.op("MOVQ\t512(SP), R12")

	a.op("MOVQ\t520(SP), R13")

	a.op("SUBQ\tR12, R13")

	a.op("CMPQ\tR13, $64")

	a.op("JE\tleave")

	a.comment("The 64 rounds of the second block, from the high halves.")

	a.op("MOVL\tBX, R15")

	a.op("XORL\tCX, R15")

	a.op("MOVQ\t$16, SI")

	a.label("second")

	st, ab, bc = sha256PlainRounds(a, st, ab, bc, 0)

	a.op("ADDQ\t$128, SI")

	a.op("CMPQ\tSI, $512")

	a.op("JB\tsecond")

	a.op("MOVQ\tstate+0(FP), R12")

	sha2AddState(a, sp, 4)

	a.op("MOVQ\t512(SP), R12")

	a.op("ADDQ\t$128, R12")

	a.op("MOVQ\tR12, 512(SP)")

	a.op("CMPQ\tR12, 520(SP)")

	a.op("JB\tblock")

	a.label("leave")

	sha2Leave(a, 512)

	a.label("done")

	a.op("RET")

	_, _, _ = st, ab, bc
}

func sha256WordsAVX2(a *asm) {
	sp := sha256Spec

	a.text.WriteString("\n")

	a.comment("Compresses the block of words w, decoded already, into state, as sha256BlocksAVX2",
		"does a single block; the frame holds W + K.",
		"func sha256WordsAVX2(state *[8]uint32, w *[16]uint32)")

	a.text.WriteString("TEXT ·sha256WordsAVX2(SB), $512-16\n")

	a.op("MOVQ\tstate+0(FP), R12")

	for i, r := range sha2Registers {
		a.op("MOVL\t%d(R12), %s", 4*i, r)
	}

	a.op("VMOVDQU\tsha256Low<>(SB), Y11")

	a.op("VMOVDQU\tsha256High<>(SB), Y12")

	a.op("LEAQ\tk256x2<>(SB), DI")

	a.op("MOVQ\tw+8(FP), R13")

	for g := range 4 {
		a.op("VBROADCASTI128\t%d(R13), %s", 16*g, ymm(g))

		a.op("VPADDD\t%d(DI), %s, Y4", 32*g, ymm(g))

		a.op("VMOVDQU\tY4, %d(SP)", 32*g)
	}

	a.op("MOVL\tBX, R15")

	a.op("XORL\tCX, R15")

	a.op("XORQ\tSI, SI")

	st, ab, bc := sha2Registers, "R14", "R15"

	a.label("schedule")

	x := [4]string{"Y0", "Y1", "Y2", "Y3"}

	for g := range 4 {
		wk := func(r int) string { return fmt.Sprintf("%d(SP)(SI*1)", 32*g+4*r) }

		st, ab, bc = sha2Rounds(a, sp, st, ab, bc, wk, sha256ScheduleAVX2(x, 128+32*g))

		x = [4]string{x[1], x[2], x[3], x[0]}
	}

	a.op("ADDQ\t$128, SI")

	a.op("CMPQ\tSI, $384")

	a.op("JB\tschedule")

	st, ab, bc = sha256PlainRounds(a, st, ab, bc, 0)

	a.op("MOVQ\tstate+0(FP), R12")

	sha2AddState(a, sp, 4)

	sha2Leave(a, 512)

	_, _, _ = st, ab, bc
}

func sha2SingleTables(a *asm) {
	var k512 []uint64

	k512 = append(k512, sha512Constants()...)

	a.table("k512", 8, k512)

	k := sha256Constants()

	var doubled []uint64

	for g := 0; g < 64; g += 4 {
		for range 2 {
			doubled = append(doubled, k[g:g+4]...)
		}
	}

	a.table("k256x2", 4, doubled)

	a.table("sha512Rotate8", 8, []uint64{0x0007060504030201, 0x080f0e0d0c0b0a09, 0x0007060504030201, 0x080f0e0d0c0b0a09})

	a.table("sha512Flip", 8, []uint64{0x0001020304050607, 0x08090a0b0c0d0e0f, 0x0001020304050607, 0x08090a0b0c0d0e0f})

	a.table("sha256Flip", 8, []uint64{0x0405060700010203, 0x0c0d0e0f08090a0b, 0x0405060700010203, 0x0c0d0e0f08090a0b})

	// Words 0 and 2 (the quadwords' low halves) into words 0 and 1, or into words 2 and 3; 0xff
	// bytes zero the rest.
	a.table("sha256Low", 8, []uint64{0x0b0a090803020100, 0xffffffffffffffff, 0x0b0a090803020100, 0xffffffffffffffff})

	a.table("sha256High", 8, []uint64{0xffffffffffffffff, 0x0b0a090803020100, 0xffffffffffffffff, 0x0b0a090803020100})
}

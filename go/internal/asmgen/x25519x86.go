package main

import (
	"fmt"
	"math/big"
)

// X25519 on amd64 with the same four 64-bit limbs as on arm64 and the same ladder and inversion
// (ladderStep, feInvert), in two tiers. With BMI2 and ADX, MULX multiplies by DX without touching
// the flags, so that ADCX and ADOX carry two chains at once, one for the low halves of a row's
// products and one for the high halves. With BMI2 alone (Intel Haswell, AMD Excavator, and virtual
// machines that hide ADX), a row's four products are summed in two passes of ADD and ADC, the low
// halves and then the high halves, which takes as many additions with the one carry flag. A
// square forms the six cross products once, doubles them and adds the four squares: ten products
// instead of sixteen. Registers: R8-R15 the product t, AX and BX a product's halves, CX zero in
// the ADX code, DX the multiplier; the MULX-only rows also hold high halves in BX, CX and SI, so
// the ladders keep their bit index in the workspace, while squares leave SI to the counter of
// squareTimes.
//
// The fixed-base multiplication runs the comb of x25519BaseGeneric on the same field code, with a
// table of the multiples in the read-only data, derived here from the base point.

func x25519Amd64(a *asm) {
	x25519Invert(a, true)

	x25519Invert(a, false)

	x25519Ladder(a, true)

	x25519Ladder(a, false)

	x25519Comb(a, true)

	x25519Comb(a, false)

	x25519BaseTable(a)
}

func tierName(adx bool) string {
	if adx {
		return "ADX"
	}

	return "BMI2"
}

// The inversion of feInvert as a subroutine of the file, which the ladder and the comb of a tier
// call with DI at their workspace: slot 2 in, slots 5-13 and every general register but DI used,
// the result in slot 13.
func x25519Invert(a *asm, adx bool) {
	a.text.WriteString("\n")

	a.comment("z^(p - 2) of slot 2 into slot 13 (feInvert) on the workspace at DI.")

	fmt.Fprintf(&a.text, "TEXT x25519Invert%s<>(SB), NOSPLIT, $0-0\n", tierName(adx))

	feInvert(x86Field{a, adx})

	a.op("RET")
}

var feT86 = [8]string{"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}

func slotWord(slot, i int) string {
	return fmt.Sprintf("%d(DI)", 32*slot+8*i)
}

type x86Field struct {
	a   *asm
	adx bool
}

func (f x86Field) store(dst int) {
	for i := range 4 {
		f.a.op("MOVQ\t%s, %s", feT86[i], slotWord(dst, i))
	}
}

func (f x86Field) load(src int) {
	for i := range 4 {
		f.a.op("MOVQ\t%s, %s", slotWord(src, i), feT86[i])
	}
}

// A carry out of t[0:4] comes back as 38 (SBB makes the mask); a second fold cannot carry, the
// first having left t[0] small.
func (f x86Field) foldCarry(second bool) {
	a := f.a

	a.op("SBBQ\tAX, AX")

	a.op("ANDQ\t$38, AX")

	a.op("ADDQ\tAX, R8")

	if second {
		return
	}

	for _, r := range feT86[1:4] {
		a.op("ADCQ\t$0, %s", r)
	}

	f.foldCarry(true)
}

// dst = x * y, or x squared when the slots are the same.
func (f x86Field) mul(dst, x, y int) {
	switch {
	case x == y && f.adx:
		f.a.comment(fmt.Sprintf("slot %d = slot %d squared", dst, x))

		f.squareADX(x)
	case x == y:
		f.a.comment(fmt.Sprintf("slot %d = slot %d squared", dst, x))

		f.squareBMI2(x)
	case f.adx:
		f.a.comment(fmt.Sprintf("slot %d = slot %d * slot %d", dst, x, y))

		f.productADX(x, y)
	default:
		f.a.comment(fmt.Sprintf("slot %d = slot %d * slot %d", dst, x, y))

		f.productBMI2(x, y)
	}

	if f.adx {
		f.reduceADX()
	} else {
		f.reduceBMI2()
	}

	f.store(dst)
}

// t = x * y in R8-R15, row by row with two carry chains.
func (f x86Field) productADX(x, y int) {
	a, t := f.a, feT86

	a.op("MOVQ\t%s, DX", slotWord(y, 0))

	a.op("MULXQ\t%s, R8, R9", slotWord(x, 0))

	for i := 1; i < 4; i++ {
		a.op("MULXQ\t%s, AX, %s", slotWord(x, i), t[i+1])

		op := "ADCQ"

		if i == 1 {
			op = "ADDQ"
		}

		a.op("%s\tAX, %s", op, t[i])
	}

	a.op("ADCQ\t$0, R12")

	for j := 1; j < 4; j++ {
		a.op("MOVQ\t%s, DX", slotWord(y, j))

		a.op("XORQ\tCX, CX")

		for i := range 3 {
			a.op("MULXQ\t%s, AX, BX", slotWord(x, i))

			a.op("ADCXQ\tAX, %s", t[i+j])

			a.op("ADOXQ\tBX, %s", t[i+j+1])
		}

		a.op("MULXQ\t%s, AX, %s", slotWord(x, 3), t[j+4])

		a.op("ADCXQ\tAX, %s", t[j+3])

		a.op("ADOXQ\tCX, %s", t[j+4])

		a.op("ADCXQ\tCX, %s", t[j+4])
	}
}

// t = x * y in R8-R15 with one carry chain: each row adds its low halves, then its high halves,
// whose top word takes the carries. The partial sums stay below 2^(64(j + 5)) after row j, so no
// carry leaves the top word.
func (f x86Field) productBMI2(x, y int) {
	a, t := f.a, feT86

	a.op("MOVQ\t%s, DX", slotWord(y, 0))

	a.op("MULXQ\t%s, R8, R9", slotWord(x, 0))

	for i := 1; i < 4; i++ {
		a.op("MULXQ\t%s, AX, %s", slotWord(x, i), t[i+1])

		op := "ADCQ"

		if i == 1 {
			op = "ADDQ"
		}

		a.op("%s\tAX, %s", op, t[i])
	}

	a.op("ADCQ\t$0, R12")

	high := [3]string{"BX", "CX", "SI"}

	for j := 1; j < 4; j++ {
		a.op("MOVQ\t%s, DX", slotWord(y, j))

		for i := range 3 {
			a.op("MULXQ\t%s, AX, %s", slotWord(x, i), high[i])

			op := "ADCQ"

			if i == 0 {
				op = "ADDQ"
			}

			a.op("%s\tAX, %s", op, t[i+j])
		}

		a.op("MULXQ\t%s, AX, %s", slotWord(x, 3), t[j+4])

		a.op("ADCQ\tAX, %s", t[j+3])

		a.op("ADCQ\t$0, %s", t[j+4])

		for i := range 3 {
			op := "ADCQ"

			if i == 0 {
				op = "ADDQ"
			}

			a.op("%s\t%s, %s", op, high[i], t[i+j+1])
		}

		a.op("ADCQ\t$0, %s", t[j+4])
	}
}

// The cross products x_i x_j (i < j) of a square into t[1:7], without ADX: the rows of x_0, x_1
// and x_2, each summed before it is added.
func (f x86Field) crossBMI2(x int) {
	a := f.a

	a.op("MOVQ\t%s, DX", slotWord(x, 0))

	a.op("MULXQ\t%s, R9, R10", slotWord(x, 1))

	a.op("MULXQ\t%s, AX, R11", slotWord(x, 2))

	a.op("ADDQ\tAX, R10")

	a.op("MULXQ\t%s, AX, R12", slotWord(x, 3))

	a.op("ADCQ\tAX, R11")

	a.op("ADCQ\t$0, R12")

	a.op("MOVQ\t%s, DX", slotWord(x, 1))

	a.op("MULXQ\t%s, AX, BX", slotWord(x, 2))

	a.op("MULXQ\t%s, CX, R13", slotWord(x, 3))

	a.op("ADDQ\tBX, CX")

	a.op("ADCQ\t$0, R13")

	a.op("ADDQ\tAX, R11")

	a.op("ADCQ\tCX, R12")

	a.op("ADCQ\t$0, R13")

	a.op("MOVQ\t%s, DX", slotWord(x, 2))

	a.op("MULXQ\t%s, AX, R14", slotWord(x, 3))

	a.op("ADDQ\tAX, R13")

	a.op("ADCQ\t$0, R14")
}

func (f x86Field) squareBMI2(x int) {
	a := f.a

	f.crossBMI2(x)

	a.comment("Twice the cross products, then the squares added.")

	a.op("XORQ\tR15, R15")

	a.op("ADDQ\tR9, R9")

	for _, r := range feT86[2:7] {
		a.op("ADCQ\t%s, %s", r, r)
	}

	a.op("ADCQ\t$0, R15")

	a.op("MOVQ\t%s, DX", slotWord(x, 0))

	a.op("MULXQ\tDX, R8, AX")

	a.op("ADDQ\tAX, R9")

	for i := 1; i < 4; i++ {
		a.op("MOVQ\t%s, DX", slotWord(x, i))

		a.op("MULXQ\tDX, AX, BX")

		a.op("ADCQ\tAX, %s", feT86[2*i])

		a.op("ADCQ\tBX, %s", feT86[2*i+1])
	}
}

// The square with ADX: the cross products as in crossBMI2 but the row of x_1 on two chains, then
// the doubling on the carry chain and the squares on the overflow chain together.
func (f x86Field) squareADX(x int) {
	a := f.a

	a.op("MOVQ\t%s, DX", slotWord(x, 0))

	a.op("MULXQ\t%s, R9, R10", slotWord(x, 1))

	a.op("MULXQ\t%s, AX, R11", slotWord(x, 2))

	a.op("MULXQ\t%s, BX, R12", slotWord(x, 3))

	a.op("ADDQ\tAX, R10")

	a.op("ADCQ\tBX, R11")

	a.op("ADCQ\t$0, R12")

	a.op("MOVQ\t%s, DX", slotWord(x, 1))

	a.op("XORQ\tCX, CX")

	a.op("MULXQ\t%s, AX, BX", slotWord(x, 2))

	a.op("ADCXQ\tAX, R11")

	a.op("ADOXQ\tBX, R12")

	a.op("MULXQ\t%s, AX, R13", slotWord(x, 3))

	a.op("ADCXQ\tAX, R12")

	a.op("ADOXQ\tCX, R13")

	a.op("ADCXQ\tCX, R13")

	a.op("MOVQ\t%s, DX", slotWord(x, 2))

	a.op("MULXQ\t%s, AX, R14", slotWord(x, 3))

	a.op("ADDQ\tAX, R13")

	a.op("ADCQ\t$0, R14")

	a.comment("Twice the cross products on the carry chain, the squares on the overflow chain.")

	a.op("MOVQ\t%s, DX", slotWord(x, 0))

	a.op("XORQ\tR15, R15")

	a.op("MULXQ\tDX, R8, AX")

	a.op("ADCXQ\tR9, R9")

	a.op("ADOXQ\tAX, R9")

	for i := 1; i < 4; i++ {
		a.op("MOVQ\t%s, DX", slotWord(x, i))

		a.op("MULXQ\tDX, AX, BX")

		a.op("ADCXQ\t%s, %s", feT86[2*i], feT86[2*i])

		a.op("ADOXQ\tAX, %s", feT86[2*i])

		a.op("ADCXQ\t%s, %s", feT86[2*i+1], feT86[2*i+1])

		a.op("ADOXQ\tBX, %s", feT86[2*i+1])
	}
}

// t[0:4] + 38 t[4:8] into R8-R11 with two chains, then what overflows limb 3, at most 38, folded
// as 38 times itself.
func (f x86Field) reduceADX() {
	a, t := f.a, feT86

	a.op("MOVQ\t$38, DX")

	a.op("XORQ\tCX, CX")

	for j := range 3 {
		a.op("MULXQ\t%s, AX, BX", t[4+j])

		a.op("ADCXQ\tAX, %s", t[j])

		a.op("ADOXQ\tBX, %s", t[j+1])
	}

	a.op("MULXQ\tR15, AX, R12")

	a.op("ADCXQ\tAX, R11")

	a.op("ADOXQ\tCX, R12")

	a.op("ADCXQ\tCX, R12")

	a.op("IMUL3Q\t$38, R12, R12")

	a.op("ADDQ\tR12, R8")

	for _, r := range t[1:4] {
		a.op("ADCQ\t$0, %s", r)
	}

	f.foldCarry(true)
}

// The same reduction with one chain: the low halves of 38 t[4:8], then the high halves; the top
// word, at most 39, is folded as 38 times itself.
func (f x86Field) reduceBMI2() {
	a, t := f.a, feT86

	a.op("MOVQ\t$38, DX")

	for j := range 4 {
		a.op("MULXQ\t%s, AX, %s", t[4+j], t[4+j])

		op := "ADCQ"

		if j == 0 {
			op = "ADDQ"
		}

		a.op("%s\tAX, %s", op, t[j])
	}

	a.op("ADCQ\t$0, R15")

	a.op("ADDQ\tR12, R9")

	a.op("ADCQ\tR13, R10")

	a.op("ADCQ\tR14, R11")

	a.op("ADCQ\t$0, R15")

	a.op("IMUL3Q\t$38, R15, R15")

	a.op("ADDQ\tR15, R8")

	for _, r := range t[1:4] {
		a.op("ADCQ\t$0, %s", r)
	}

	f.foldCarry(true)
}

func (f x86Field) add(dst, x, y int) {
	a := f.a

	a.comment(fmt.Sprintf("slot %d = slot %d + slot %d", dst, x, y))

	f.load(x)

	a.op("ADDQ\t%s, R8", slotWord(y, 0))

	for i := 1; i < 4; i++ {
		a.op("ADCQ\t%s, %s", slotWord(y, i), feT86[i])
	}

	f.foldCarry(false)

	f.store(dst)
}

// As feSub on arm64: a borrow takes 38 off, and a second borrow 38 more from limb 0 alone.
func (f x86Field) sub(dst, x, y int) {
	a := f.a

	a.comment(fmt.Sprintf("slot %d = slot %d - slot %d", dst, x, y))

	f.load(x)

	a.op("SUBQ\t%s, R8", slotWord(y, 0))

	for i := 1; i < 4; i++ {
		a.op("SBBQ\t%s, %s", slotWord(y, i), feT86[i])
	}

	a.op("SBBQ\tAX, AX")

	a.op("ANDQ\t$38, AX")

	a.op("SUBQ\tAX, R8")

	for _, r := range feT86[1:4] {
		a.op("SBBQ\t$0, %s", r)
	}

	a.op("SBBQ\tAX, AX")

	a.op("ANDQ\t$38, AX")

	a.op("SUBQ\tAX, R8")

	f.store(dst)
}

func (f x86Field) mulA24(dst, x int) {
	a := f.a

	a.comment(fmt.Sprintf("slot %d = slot %d * 121665", dst, x))

	a.op("MOVQ\t$121665, DX")

	a.op("MULXQ\t%s, R8, R9", slotWord(x, 0))

	for i := 1; i < 4; i++ {
		a.op("MULXQ\t%s, AX, %s", slotWord(x, i), feT86[i+1])

		op := "ADCQ"

		if i == 1 {
			op = "ADDQ"
		}

		a.op("%s\tAX, %s", op, feT86[i])
	}

	a.op("ADCQ\t$0, R12")

	a.op("IMUL3Q\t$38, R12, R12")

	a.op("ADDQ\tR12, R8")

	for _, r := range feT86[1:4] {
		a.op("ADCQ\t$0, %s", r)
	}

	f.foldCarry(true)

	f.store(dst)
}

func (f x86Field) copy(dst, src int) {
	f.load(src)

	f.store(dst)
}

// The squares leave SI alone, so it counts them.
func (f x86Field) squareTimes(slot, count int, label string) {
	f.a.op("MOVQ\t$%d, SI", count)

	f.a.label(label)

	f.mul(slot, slot, slot)

	f.a.op("DECQ\tSI")

	f.a.op("JNZ\t%s", label)
}

// Swaps x2 with x3 and z2 with z3 when DX is all ones, without a branch, sixteen bytes at a time
// with SSE2, which every amd64 CPU has.
func (f x86Field) swapPoints() {
	a := f.a

	a.op("MOVQ\tDX, X15")

	a.op("PUNPCKLQDQ\tX15, X15")

	for _, pair := range [][2]int{{slotX2, slotX3}, {slotZ2, slotZ3}} {
		for half := range 2 {
			x, y := 32*pair[0]+16*half, 32*pair[1]+16*half

			a.op("MOVOU\t%d(DI), X0", x)

			a.op("MOVOU\t%d(DI), X1", y)

			a.op("MOVOU\tX0, X2")

			a.op("PXOR\tX1, X2")

			a.op("PAND\tX15, X2")

			a.op("PXOR\tX2, X0")

			a.op("PXOR\tX2, X1")

			a.op("MOVOU\tX0, %d(DI)", x)

			a.op("MOVOU\tX1, %d(DI)", y)
		}
	}
}

// Writes slot, which is below 2^256, below p to out: bit 255 folded in as 19, then p subtracted,
// by adding 19 and clearing bit 255, when that sets bit 255.
func (f x86Field) freeze(slot int) {
	a := f.a

	a.comment("Below p: fold bit 255 in as 19, then subtract p, by adding 19 and clearing bit 255,",
		"when that sets bit 255.")

	f.load(slot)

	a.op("MOVQ\tR11, AX")

	a.op("SHRQ\t$63, AX")

	a.op("BTRQ\t$63, R11")

	a.op("IMUL3Q\t$19, AX, AX")

	a.op("ADDQ\tAX, R8")

	for _, r := range feT86[1:4] {
		a.op("ADCQ\t$0, %s", r)
	}

	for i := range 4 {
		a.op("MOVQ\t%s, %s", feT86[i], feT86[i+4])
	}

	a.op("ADDQ\t$19, R12")

	for _, r := range feT86[5:8] {
		a.op("ADCQ\t$0, %s", r)
	}

	a.op("BTRQ\t$63, R15")

	for i := range 4 {
		a.op("CMOVQCS\t%s, %s", feT86[i+4], feT86[i])
	}

	a.op("MOVQ\tout+0(FP), AX")

	for i := range 4 {
		a.op("MOVQ\t%s, %d(AX)", feT86[i], 8*i)
	}
}

// The workspace's seventeenth slot holds the pending swap in word 0 and the bit index in word 1.
func x25519Ladder(a *asm, adx bool) {
	name, needs := "x25519BMI2", "BMI2"

	if adx {
		name, needs = "x25519ADX", "BMI2 and ADX"
	}

	a.function(name, "func "+name+"(out *[32]byte, work *[17][4]uint64)", 16,
		"X25519 on the workspace as x25519ARM, with the pending swap and the bit index in slot 16;",
		"the CPU must have "+needs+".")

	f := x86Field{a, adx}

	const swapWord, indexWord = 32 * 16, 32*16 + 8

	a.op("MOVQ\twork+8(FP), DI")

	a.op("MOVQ\t$254, %d(DI)", indexWord)

	a.label("ladder")

	a.op("MOVQ\t%d(DI), SI", indexWord)

	a.op("MOVQ\tSI, CX")

	a.op("SHRQ\t$6, CX")

	a.op("MOVQ\t%d(DI)(CX*8), AX", 32*slotK)

	a.op("MOVQ\tSI, CX")

	a.op("ANDQ\t$63, CX")

	a.op("SHRQ\tCX, AX")

	a.op("ANDQ\t$1, AX")

	a.op("MOVQ\t%d(DI), DX", swapWord)

	a.op("XORQ\tAX, DX")

	a.op("MOVQ\tAX, %d(DI)", swapWord)

	a.op("NEGQ\tDX")

	f.swapPoints()

	ladderStep(f)

	a.op("DECQ\t%d(DI)", indexWord)

	a.op("JGE\tladder")

	a.op("MOVQ\t%d(DI), DX", swapWord)

	a.op("NEGQ\tDX")

	f.swapPoints()

	a.op("CALL\tx25519Invert%s<>(SB)", tierName(adx))

	f.mul(slotTemp, slotX2, 13)

	f.freeze(slotTemp)

	a.op("RET")
}

// The comb's workspace slots: the point h = (X : Y : Z : T), the selected table entry as y + x,
// y - x and 2dxy, the temporaries of the addition and the doubling, and in slot 18 the step and
// doubling counters. The inversion takes Z - Y in slot 2 and uses slots 5-13 (feInvert).
const (
	combX, combY, combZ, combT     = 0, 1, 2, 3
	combPlus, combMinus, combXY    = 4, 5, 6
	combStepWord, combDoublingWord = 32 * 18, 32*18 + 8
	combNumerator, combResult      = 14, 15
	combRows, combEntries          = 32, 8
	combEntryBytes                 = 96
)

// The entry of the table row at R8 for the digit in AX, into slots 4-6: VPCMPEQQ masks keep the
// one of the eight entries whose multiple is the digit's magnitude, or the neutral (1, 1, 0) for
// digit 0, so every entry is read; a negative digit then swaps y + x with y - x and replaces 2dxy
// by p - 2dxy (below p, as the table is), with masks again.
func combSelect(a *asm) {
	a.op("MOVQ\tAX, BX")

	a.op("SARQ\t$63, BX")

	a.op("XORQ\tBX, AX")

	a.op("SUBQ\tBX, AX")

	a.op("VMOVQ\tAX, X0")

	a.op("VPBROADCASTQ\tX0, Y0")

	a.op("VPCMPEQQ\tY5, Y5, Y5")

	a.op("VPSRLQ\t$63, Y5, Y5")

	a.op("VPXOR\tY1, Y1, Y1")

	a.op("VPCMPEQQ\tY1, Y0, Y4")

	a.op("MOVQ\t$1, CX")

	a.op("VMOVQ\tCX, X6")

	a.op("VPAND\tY6, Y4, Y2")

	a.op("VMOVDQA\tY2, Y3")

	a.op("VPXOR\tY8, Y8, Y8")

	a.op("VMOVDQA\tY5, Y9")

	for j := range combEntries {
		a.op("VPCMPEQQ\tY9, Y0, Y4")

		for k, acc := range []string{"Y2", "Y3", "Y8"} {
			a.op("VPAND\t%d(R8), Y4, Y10", combEntryBytes*j+32*k)

			a.op("VPOR\tY10, %s, %s", acc, acc)
		}

		if j < combEntries-1 {
			a.op("VPADDQ\tY5, Y9, Y9")
		}
	}

	a.op("VMOVQ\tBX, X11")

	a.op("VPBROADCASTQ\tX11, Y11")

	a.op("VPXOR\tY2, Y3, Y10")

	a.op("VPAND\tY11, Y10, Y10")

	a.op("VPXOR\tY10, Y2, Y2")

	a.op("VPXOR\tY10, Y3, Y3")

	a.op("VMOVDQU\tY2, %d(DI)", 32*combPlus)

	a.op("VMOVDQU\tY3, %d(DI)", 32*combMinus)

	a.op("VMOVDQU\tY8, %d(DI)", 32*combXY)

	a.op("MOVQ\t$-19, R9")

	a.op("MOVQ\t$-1, R10")

	a.op("MOVQ\t$-1, R11")

	a.op("MOVQ\t$0x7fffffffffffffff, R12")

	a.op("SUBQ\t%s, R9", slotWord(combXY, 0))

	for i, r := range []string{"R10", "R11", "R12"} {
		a.op("SBBQ\t%s, %s", slotWord(combXY, i+1), r)
	}

	for i, r := range []string{"R9", "R10", "R11", "R12"} {
		a.op("MOVQ\t%s, AX", slotWord(combXY, i))

		a.op("XORQ\tAX, %s", r)

		a.op("ANDQ\tBX, %s", r)

		a.op("XORQ\tAX, %s", r)

		a.op("MOVQ\t%s, %s", r, slotWord(combXY, i))
	}
}

// h += the entry (add-2008-hwcd-3 with k = 2d and Z2 = 1), as edwardsPoint.addAffine.
func combAdd(f x86Field) {
	const yPlusX, yMinusX, a, b, c, d, e, ff, g, h = 7, 8, 9, 10, 11, 12, 13, 14, 15, 16

	f.add(yPlusX, combY, combX)

	f.sub(yMinusX, combY, combX)

	f.mul(a, yMinusX, combMinus)

	f.mul(b, yPlusX, combPlus)

	f.mul(c, combT, combXY)

	f.add(d, combZ, combZ)

	f.sub(e, b, a)

	f.add(h, b, a)

	f.sub(ff, d, c)

	f.add(g, d, c)

	f.mul(combX, e, ff)

	f.mul(combY, g, h)

	f.mul(combZ, ff, g)

	f.mul(combT, e, h)
}

// h = 2h with every coordinate negated (dbl-2008-hwcd with a = -1), as edwardsPoint.double.
func combDouble(f x86Field) {
	const aa, bb, zz, s, e, minusH, c, g, minusF = 9, 10, 11, 12, 13, 14, 15, 16, 17

	f.mul(aa, combX, combX)

	f.mul(bb, combY, combY)

	f.mul(zz, combZ, combZ)

	f.add(s, combX, combY)

	f.mul(e, s, s)

	f.add(minusH, aa, bb)

	f.add(c, zz, zz)

	f.sub(g, bb, aa)

	f.sub(e, e, minusH)

	f.sub(minusF, c, g)

	f.mul(combX, e, minusF)

	f.mul(combY, g, minusH)

	f.mul(combZ, minusF, g)

	f.mul(combT, e, minusH)
}

// Steps 0-31 add the entries for the odd digits 1, 3, ..., 63 (rows 0-31), then four doublings
// multiply by 16, and steps 32-63 add those for the even digits 0, 2, ..., 62; the step, row and
// digit position are public, the digit secret.
func x25519Comb(a *asm, adx bool) {
	name, needs := "x25519BaseBMI2", "AVX2 and BMI2"

	if adx {
		name, needs = "x25519BaseADX", "AVX2, BMI2 and ADX"
	}

	a.function(name, "func "+name+"(out *[32]byte, digits *[64]int8, work *[19][4]uint64)", 24,
		"[k]B for the signed radix-16 digits of k (x25519BaseGeneric) and the u-coordinate (Z + Y) /",
		"(Z - Y) of the result in out; the CPU must have "+needs+".")

	f := x86Field{a, adx}

	a.op("MOVQ\twork+16(FP), DI")

	a.op("XORQ\tAX, AX")

	for slot := range 4 {
		for i := range 4 {
			a.op("MOVQ\tAX, %s", slotWord(slot, i))
		}
	}

	a.op("MOVQ\t$1, %s", slotWord(combY, 0))

	a.op("MOVQ\t$1, %s", slotWord(combZ, 0))

	a.op("MOVQ\tAX, %d(DI)", combStepWord)

	a.label("step")

	a.op("MOVQ\t%d(DI), CX", combStepWord)

	a.op("MOVQ\tCX, BX")

	a.op("ANDQ\t$%d, BX", combRows-1)

	a.op("SHRQ\t$5, CX")

	a.op("LEAQ\t1(BX)(BX*1), SI")

	a.op("SUBQ\tCX, SI")

	a.op("MOVQ\tdigits+8(FP), AX")

	a.op("MOVBQSX\t(AX)(SI*1), AX")

	a.comment("The row at 768 times its index.")

	a.op("LEAQ\t(BX)(BX*2), BX")

	a.op("SHLQ\t$8, BX")

	a.op("LEAQ\tx25519BaseTable<>(SB), R8")

	a.op("ADDQ\tBX, R8")

	combSelect(a)

	combAdd(f)

	a.op("INCQ\t%d(DI)", combStepWord)

	a.op("CMPQ\t%d(DI), $%d", combStepWord, combRows)

	a.op("JNE\tnext")

	a.op("MOVQ\t$4, %d(DI)", combDoublingWord)

	a.label("double")

	combDouble(f)

	a.op("DECQ\t%d(DI)", combDoublingWord)

	a.op("JNZ\tdouble")

	a.label("next")

	a.op("CMPQ\t%d(DI), $%d", combStepWord, 2*combRows)

	a.op("JLT\tstep")

	a.comment("u = (Z + Y) / (Z - Y).")

	f.add(combNumerator, combZ, combY)

	f.sub(slotZ2, combZ, combY)

	a.op("CALL\tx25519Invert%s<>(SB)", tierName(adx))

	f.mul(combResult, combNumerator, 13)

	f.freeze(combResult)

	a.op("VZEROUPPER")

	a.op("RET")
}

// The table of x25519BaseGeneric, entry [i][j] being (j + 1) 256^i B as y + x, y - x and 2dxy
// modulo p, each below p in four little-endian words, from affine arithmetic on the twisted
// Edwards curve -x^2 + y^2 = 1 + d x^2 y^2 with d = -121665 / 121666 (RFC 7748, 4.1) and B the
// point with y = 4/5 and an even x (RFC 8032, 5.1).
func x25519BaseTable(a *asm) {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

	mod := func(v *big.Int) *big.Int {
		return v.Mod(v, p)
	}

	inverse := func(v *big.Int) *big.Int {
		return new(big.Int).ModInverse(v, p)
	}

	mul := func(x, y *big.Int) *big.Int {
		return mod(new(big.Int).Mul(x, y))
	}

	d := mul(big.NewInt(-121665), inverse(big.NewInt(121666)))

	y := mul(big.NewInt(4), inverse(big.NewInt(5)))

	// x^2 = (y^2 - 1) / (d y^2 + 1); p = 5 mod 8, so a root is u^((p + 3) / 8) or that times
	// sqrt(-1) = 2^((p - 1) / 4).
	y2 := mul(y, y)

	u := mul(mod(new(big.Int).Sub(y2, big.NewInt(1))), inverse(mod(new(big.Int).Add(mul(d, y2), big.NewInt(1)))))

	x := new(big.Int).Exp(u, new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(3)), 3), p)

	if mul(x, x).Cmp(u) != 0 {
		x = mul(x, new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 2), p))
	}

	if mul(x, x).Cmp(u) != 0 {
		panic("asmgen: no square root for the base point")
	}

	if x.Bit(0) == 1 {
		x.Sub(p, x)
	}

	add := func(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
		t := mul(d, mul(mul(x1, x2), mul(y1, y2)))

		x3 := mul(mod(new(big.Int).Add(mul(x1, y2), mul(y1, x2))), inverse(mod(new(big.Int).Add(big.NewInt(1), t))))

		y3 := mul(mod(new(big.Int).Add(mul(y1, y2), mul(x1, x2))), inverse(mod(new(big.Int).Sub(big.NewInt(1), t))))

		return x3, y3
	}

	var words []uint64

	put := func(v *big.Int) {
		for i := range 4 {
			words = append(words, new(big.Int).Rsh(v, uint(64*i)).Uint64())
		}
	}

	rowX, rowY := x, y

	for range combRows {
		ex, ey := rowX, rowY

		for j := range combEntries {
			if j > 0 {
				ex, ey = add(ex, ey, rowX, rowY)
			}

			put(mod(new(big.Int).Add(ey, ex)))

			put(mod(new(big.Int).Sub(ey, ex)))

			put(mul(mul(big.NewInt(2), d), mul(ex, ey)))
		}

		for range 8 {
			rowX, rowY = add(rowX, rowY, rowX, rowY)
		}
	}

	a.table("x25519BaseTable", 8, words)
}

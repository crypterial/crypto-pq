package main

import "fmt"

// X25519 on amd64 with the same four 64-bit limbs as on arm64 and the same ladder and inversion
// (ladderStep, feInvert), for CPUs with BMI2 and ADX: MULX multiplies by DX without touching the
// flags, so that ADCX and ADOX can carry two chains at once, one for the low halves of a row's
// products and one for the high halves. The workspace at DI has a seventeenth slot whose first
// word holds the pending swap. Registers: R8-R15 the product t, AX and BX a product's halves, CX
// zero, DX the multiplier, SI the ladder's bit index and the squarings' counter.

func x25519Amd64(a *asm) {
	x25519MULX(a)
}

var feT86 = [8]string{"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}

func slotWord(slot, i int) string {
	return fmt.Sprintf("%d(DI)", 32*slot+8*i)
}

type x86Field struct {
	a *asm
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

func (f x86Field) mul(dst, x, y int) {
	a, t := f.a, feT86

	a.comment(fmt.Sprintf("slot %d = slot %d * slot %d", dst, x, y))

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

	a.comment("t[0:4] + 38 t[4:8], then what overflows limb 3, at most 38, folded as 38 times itself.")

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

	f.store(dst)
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

func (f x86Field) squareTimes(slot, count int, label string) {
	f.a.op("MOVQ\t$%d, SI", count)

	f.a.label(label)

	f.mul(slot, slot, slot)

	f.a.op("DECQ\tSI")

	f.a.op("JNZ\t%s", label)
}

// Swaps slots x and y when DX is all ones, without a branch.
func (f x86Field) swap(x, y int) {
	a := f.a

	for i := range 4 {
		a.op("MOVQ\t%s, AX", slotWord(x, i))

		a.op("MOVQ\t%s, BX", slotWord(y, i))

		a.op("MOVQ\tAX, CX")

		a.op("XORQ\tBX, CX")

		a.op("ANDQ\tDX, CX")

		a.op("XORQ\tCX, AX")

		a.op("XORQ\tCX, BX")

		a.op("MOVQ\tAX, %s", slotWord(x, i))

		a.op("MOVQ\tBX, %s", slotWord(y, i))
	}
}

func x25519MULX(a *asm) {
	a.function("x25519MULX", "func x25519MULX(out *[32]byte, work *[17][4]uint64)", 16,
		"X25519 on the workspace as x25519ARM, with the pending swap in slot 16; the CPU must have",
		"BMI2 and ADX.")

	f := x86Field{a}

	const swapWord = 32 * 16

	a.op("MOVQ\twork+8(FP), DI")

	a.op("MOVQ\t$254, SI")

	a.label("ladder")

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

	f.swap(slotX2, slotX3)

	f.swap(slotZ2, slotZ3)

	ladderStep(f)

	a.op("DECQ\tSI")

	a.op("JGE\tladder")

	a.op("MOVQ\t%d(DI), DX", swapWord)

	a.op("NEGQ\tDX")

	f.swap(slotX2, slotX3)

	f.swap(slotZ2, slotZ3)

	feInvert(f)

	f.mul(slotTemp, slotX2, 13)

	a.comment("Below p: fold bit 255 in as 19, then subtract p, by adding 19 and clearing bit 255,",
		"when that sets bit 255.")

	f.load(slotTemp)

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

	a.op("RET")
}

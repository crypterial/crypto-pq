package main

import "fmt"

// X25519 (RFC 7748) on arm64 with field elements as four 64-bit limbs, products from MUL and UMULH.
// An element is any value below 2^256 congruent to it modulo p = 2^255 - 19; since 2^256 = 38 mod
// p, a reduction adds 38 times the high half of a product to its low half. The whole ladder, the
// inversion and the final reduction below p run in one call, on a workspace of 32-byte slots from
// which every operation reads its operands and to which it writes its result.

func x25519Arm64(a *asm) {
	x25519Arm(a)
}

// Registers: R0 holds the workspace, a = R1-R4 and b = R5-R8 the operands, t = R9-R16 a product,
// u = R17 and R19-R22 a row of it or the high parts of a reduction, R23 a temporary and R24 the
// constant 38; R25 counts and R26 is the pending swap. MUL, UMULH, MOVD and the logical operations
// without S leave the flags alone, so they can sit inside carry chains.
var (
	feA = [4]string{"R1", "R2", "R3", "R4"}
	feB = [4]string{"R5", "R6", "R7", "R8"}
	feT = [8]string{"R9", "R10", "R11", "R12", "R13", "R14", "R15", "R16"}
	feU = [5]string{"R17", "R19", "R20", "R21", "R22"}
)

const (
	feX  = "R23"
	fe38 = "R24"
)

// The workspace slots: the ladder's x1, x2, z2, x3 and z3, its intermediate values, and the
// clamped scalar.
const (
	slotX1, slotX2, slotZ2, slotX3, slotZ3 = 0, 1, 2, 3, 4
	slotA, slotB, slotC, slotD             = 5, 6, 7, 8
	slotAA, slotBB, slotE, slotDA, slotCB  = 9, 10, 11, 12, 13
	slotTemp, slotK                        = 14, 15
	feSlots                                = 16
)

func feLoad(a *asm, regs [4]string, slot int) {
	a.op("LDP\t%d(R0), (%s, %s)", 32*slot, regs[0], regs[1])

	a.op("LDP\t%d(R0), (%s, %s)", 32*slot+16, regs[2], regs[3])
}

func feStore(a *asm, regs [4]string, slot int) {
	a.op("STP\t(%s, %s), %d(R0)", regs[0], regs[1], 32*slot)

	a.op("STP\t(%s, %s), %d(R0)", regs[2], regs[3], 32*slot+16)
}

// Row i of the product of a and b: dst = a_i * b as five limbs, summed from the low and high
// halves of the four products a_i b_j, at limbs j and j + 1.
func feRow(a *asm, ai string, b [4]string, dst [5]string) {
	a.op("MUL\t%s, %s, %s", b[0], ai, dst[0])

	a.op("UMULH\t%s, %s, %s", b[0], ai, dst[1])

	for j := 1; j < 4; j++ {
		a.op("MUL\t%s, %s, %s", b[j], ai, feX)

		a.op("UMULH\t%s, %s, %s", b[j], ai, dst[j+1])

		op := "ADCS"

		if j == 1 {
			op = "ADDS"
		}

		a.op("%s\t%s, %s, %s", op, feX, dst[j], dst[j])
	}

	a.op("ADC\tZR, %s, %s", dst[4], dst[4])
}

// t = a * b as eight limbs: row 0 into t[0:5], then each row i into u, added to t[i:i + 4] with
// the carry and the row's top limb going to t[i + 4]. The partial sums stay below 2^(64(i + 5)), so
// no carry leaves the top limb.
func feProduct(a *asm) {
	feRow(a, feA[0], feB, [5]string{feT[0], feT[1], feT[2], feT[3], feT[4]})

	for i := 1; i < 4; i++ {
		feRow(a, feA[i], feB, feU)

		for j := range 4 {
			op := "ADCS"

			if j == 0 {
				op = "ADDS"
			}

			a.op("%s\t%s, %s, %s", op, feU[j], feT[i+j], feT[i+j])
		}

		a.op("ADC\tZR, %s, %s", feU[4], feT[i+4])
	}
}

// Folds a carry out of t[0:4] back in as 38; the second fold cannot carry, because a carry leaves
// t[0] small.
func feFoldCarry(a *asm) {
	a.op("CSEL\tCS, %s, ZR, %s", fe38, feX)

	a.op("ADDS\t%s, %s, %s", feX, feT[0], feT[0])

	for j := 1; j < 4; j++ {
		a.op("ADCS\tZR, %s, %s", feT[j], feT[j])
	}

	a.op("CSEL\tCS, %s, ZR, %s", fe38, feX)

	a.op("ADD\t%s, %s, %s", feX, feT[0], feT[0])
}

// t[0:4] = t[0:4] + 38 t[4:8] modulo 2^256 and p: the products 38 t[4 + j] are low halves u[j]
// and high halves (below 38) that replace t[4 + j]; the low halves add at limbs j and the high ones
// at j + 1, and what overflows limb 3, below 41, is folded in as 38 times itself.
func feReduce(a *asm) {
	t := feT

	for j := range 4 {
		a.op("MUL\t%s, %s, %s", fe38, t[4+j], feU[j])

		a.op("UMULH\t%s, %s, %s", fe38, t[4+j], t[4+j])
	}

	a.op("ADDS\t%s, %s, %s", feU[0], t[0], t[0])

	for j := 1; j < 4; j++ {
		a.op("ADCS\t%s, %s, %s", feU[j], t[j], t[j])
	}

	a.op("ADC\tZR, %s, %s", t[7], t[7])

	a.op("ADDS\t%s, %s, %s", t[4], t[1], t[1])

	a.op("ADCS\t%s, %s, %s", t[5], t[2], t[2])

	a.op("ADCS\t%s, %s, %s", t[6], t[3], t[3])

	a.op("ADC\tZR, %s, %s", t[7], t[7])

	a.op("MUL\t%s, %s, %s", fe38, t[7], feX)

	a.op("ADDS\t%s, %s, %s", feX, t[0], t[0])

	for j := 1; j < 4; j++ {
		a.op("ADCS\tZR, %s, %s", t[j], t[j])
	}

	feFoldCarry(a)
}

// t = a^2 as eight limbs from ten products: the six cross products a_i a_j (i < j), summed in the
// rows of a_0, a_1 and a_2, are doubled by a carry chain, then the squares a_i^2 add at limbs 2i
// and 2i + 1.
func feSquareProduct(a *asm) {
	t, u, x := feT, feU, feX

	a.op("MUL\t%s, %s, %s", feA[1], feA[0], t[1])

	a.op("UMULH\t%s, %s, %s", feA[1], feA[0], t[2])

	a.op("MUL\t%s, %s, %s", feA[2], feA[0], x)

	a.op("UMULH\t%s, %s, %s", feA[2], feA[0], t[3])

	a.op("ADDS\t%s, %s, %s", x, t[2], t[2])

	a.op("MUL\t%s, %s, %s", feA[3], feA[0], x)

	a.op("UMULH\t%s, %s, %s", feA[3], feA[0], t[4])

	a.op("ADCS\t%s, %s, %s", x, t[3], t[3])

	a.op("ADC\tZR, %s, %s", t[4], t[4])

	a.op("MUL\t%s, %s, %s", feA[2], feA[1], u[0])

	a.op("UMULH\t%s, %s, %s", feA[2], feA[1], u[1])

	a.op("MUL\t%s, %s, %s", feA[3], feA[1], x)

	a.op("UMULH\t%s, %s, %s", feA[3], feA[1], t[5])

	a.op("ADDS\t%s, %s, %s", x, u[1], u[1])

	a.op("ADC\tZR, %s, %s", t[5], t[5])

	a.op("ADDS\t%s, %s, %s", u[0], t[3], t[3])

	a.op("ADCS\t%s, %s, %s", u[1], t[4], t[4])

	a.op("ADC\tZR, %s, %s", t[5], t[5])

	a.op("MUL\t%s, %s, %s", feA[3], feA[2], x)

	a.op("UMULH\t%s, %s, %s", feA[3], feA[2], t[6])

	a.op("ADDS\t%s, %s, %s", x, t[5], t[5])

	a.op("ADC\tZR, %s, %s", t[6], t[6])

	a.op("ADDS\t%s, %s, %s", t[1], t[1], t[1])

	for j := 2; j < 7; j++ {
		a.op("ADCS\t%s, %s, %s", t[j], t[j], t[j])
	}

	a.op("ADC\tZR, ZR, %s", t[7])

	squares := [8]string{t[0], u[0], u[1], u[2], u[3], u[4], x, feB[0]}

	for i := range 4 {
		a.op("MUL\t%s, %s, %s", feA[i], feA[i], squares[2*i])

		a.op("UMULH\t%s, %s, %s", feA[i], feA[i], squares[2*i+1])
	}

	a.op("ADDS\t%s, %s, %s", squares[1], t[1], t[1])

	for j := 2; j < 7; j++ {
		a.op("ADCS\t%s, %s, %s", squares[j], t[j], t[j])
	}

	a.op("ADC\t%s, %s, %s", squares[7], t[7], t[7])
}

func feMul(a *asm, dst, x, y int) {
	feLoad(a, feA, x)

	if y == x {
		a.comment(fmt.Sprintf("slot %d = slot %d squared", dst, x))

		feSquareProduct(a)
	} else {
		a.comment(fmt.Sprintf("slot %d = slot %d * slot %d", dst, x, y))

		feLoad(a, feB, y)

		feProduct(a)
	}

	feReduce(a)

	feStore(a, [4]string(feT[:4]), dst)
}

func feAdd(a *asm, dst, x, y int) {
	a.comment(fmt.Sprintf("slot %d = slot %d + slot %d", dst, x, y))

	feLoad(a, feA, x)

	feLoad(a, feB, y)

	a.op("ADDS\t%s, %s, %s", feB[0], feA[0], feT[0])

	for j := 1; j < 4; j++ {
		a.op("ADCS\t%s, %s, %s", feB[j], feA[j], feT[j])
	}

	feFoldCarry(a)

	feStore(a, [4]string(feT[:4]), dst)
}

// x - y: a borrow means the limbs hold x - y + 2^256, so 38 comes off; a second borrow, possible
// only when the limbs were below 38, takes 38 more, which leaves limb 0 at least 2^64 - 76.
func feSub(a *asm, dst, x, y int) {
	a.comment(fmt.Sprintf("slot %d = slot %d - slot %d", dst, x, y))

	feLoad(a, feA, x)

	feLoad(a, feB, y)

	a.op("SUBS\t%s, %s, %s", feB[0], feA[0], feT[0])

	for j := 1; j < 4; j++ {
		a.op("SBCS\t%s, %s, %s", feB[j], feA[j], feT[j])
	}

	a.op("CSEL\tCC, %s, ZR, %s", fe38, feX)

	a.op("SUBS\t%s, %s, %s", feX, feT[0], feT[0])

	for j := 1; j < 4; j++ {
		a.op("SBCS\tZR, %s, %s", feT[j], feT[j])
	}

	a.op("CSEL\tCC, %s, ZR, %s", fe38, feX)

	a.op("SUB\t%s, %s, %s", feX, feT[0], feT[0])

	feStore(a, [4]string(feT[:4]), dst)
}

// x * 121665, the (A - 2) / 4 of RFC 7748: five limbs, the top one below 2^17 and folded as 38
// times itself.
func feMulA24(a *asm, dst, x int) {
	a.comment(fmt.Sprintf("slot %d = slot %d * 121665", dst, x))

	feLoad(a, feA, x)

	a.op("MOVD\t$121665, %s", feB[0])

	feRow(a, feB[0], feA, [5]string{feT[0], feT[1], feT[2], feT[3], feT[4]})

	a.op("MUL\t%s, %s, %s", fe38, feT[4], feX)

	a.op("ADDS\t%s, %s, %s", feX, feT[0], feT[0])

	for j := 1; j < 4; j++ {
		a.op("ADCS\tZR, %s, %s", feT[j], feT[j])
	}

	feFoldCarry(a)

	feStore(a, [4]string(feT[:4]), dst)
}

// Swaps slots x and y when mask is all ones and leaves them when it is zero, without a branch.
func feSwap(a *asm, x, y int, mask string) {
	for half := range 2 {
		a.op("LDP\t%d(R0), (R1, R2)", 32*x+16*half)

		a.op("LDP\t%d(R0), (R5, R6)", 32*y+16*half)

		for i, pair := range [2][2]string{{"R1", "R5"}, {"R2", "R6"}} {
			t := feT[i]

			a.op("EOR\t%s, %s, %s", pair[1], pair[0], t)

			a.op("AND\t%s, %s, %s", mask, t, t)

			a.op("EOR\t%s, %s, %s", t, pair[0], pair[0])

			a.op("EOR\t%s, %s, %s", t, pair[1], pair[1])
		}

		a.op("STP\t(R1, R2), %d(R0)", 32*x+16*half)

		a.op("STP\t(R5, R6), %d(R0)", 32*y+16*half)
	}
}

// The field operations on workspace slots that the ladder and the inversion are written in, so
// that both architectures share them.
type field interface {
	mul(dst, x, y int)
	add(dst, x, y int)
	sub(dst, x, y int)
	mulA24(dst, x int)
	copy(dst, src int)
	squareTimes(slot, count int, label string)
}

type armField struct {
	a *asm
}

func (f armField) mul(dst, x, y int) {
	feMul(f.a, dst, x, y)
}

func (f armField) add(dst, x, y int) {
	feAdd(f.a, dst, x, y)
}

func (f armField) sub(dst, x, y int) {
	feSub(f.a, dst, x, y)
}

func (f armField) mulA24(dst, x int) {
	feMulA24(f.a, dst, x)
}

func (f armField) copy(dst, src int) {
	for half := range 2 {
		f.a.op("LDP\t%d(R0), (R1, R2)", 32*src+16*half)

		f.a.op("STP\t(R1, R2), %d(R0)", 32*dst+16*half)
	}
}

func (f armField) squareTimes(slot, count int, label string) {
	feSquareTimes(f.a, slot, count, label)
}

// slot = slot^(2^count), in a loop named label counted by R25.
func feSquareTimes(a *asm, slot, count int, label string) {
	a.op("MOVD\t$%d, R25", count)

	a.label(label)

	feMul(a, slot, slot, slot)

	a.op("SUBS\t$1, R25, R25")

	a.op("BNE\t%s", label)
}

// One step of the ladder (RFC 7748, section 5), with independent operations next to each other
// so that they overlap: the four sums and differences, the two squares and two products that use
// them, then the five products of the new coordinates. In the order of the RFC the ladder took 30
// microseconds on Apple M3, in this one 23. Slot 14 and slot 5, whose A is no longer needed, hold
// the intermediate values of z3 and z2.
func ladderStep(f field) {
	f.add(slotA, slotX2, slotZ2)

	f.sub(slotB, slotX2, slotZ2)

	f.add(slotC, slotX3, slotZ3)

	f.sub(slotD, slotX3, slotZ3)

	f.mul(slotAA, slotA, slotA)

	f.mul(slotBB, slotB, slotB)

	f.mul(slotDA, slotD, slotA)

	f.mul(slotCB, slotC, slotB)

	f.sub(slotE, slotAA, slotBB)

	f.add(slotX3, slotDA, slotCB)

	f.sub(slotTemp, slotDA, slotCB)

	f.mulA24(slotA, slotE)

	f.mul(slotX3, slotX3, slotX3)

	f.mul(slotTemp, slotTemp, slotTemp)

	f.add(slotA, slotAA, slotA)

	f.mul(slotX2, slotAA, slotBB)

	f.mul(slotZ3, slotX1, slotTemp)

	f.mul(slotZ2, slotE, slotA)
}

// z^(p - 2) of slot 2 into slot 13, through 254 squarings and 11 multiplications; slots 5-13 hold
// the powers z^2, z^(2^k - 1) and the running value in slot 6.
func feInvert(f field) {
	const z, z2, t, z9, z11, z5, z10, z20, z50, z100 = slotZ2, 5, 6, 7, 8, 9, 10, 11, 12, 13

	f.mul(z2, z, z)

	f.mul(t, z2, z2)

	f.mul(t, t, t)

	f.mul(z9, t, z)

	f.mul(z11, z9, z2)

	f.mul(t, z11, z11)

	f.mul(z5, t, z9)

	steps := []struct {
		from, count, by, to int
	}{
		{z5, 5, z5, z10},
		{z10, 10, z10, z20},
		{z20, 20, z20, t},
		{t, 10, z10, z50},
		{z50, 50, z50, z100},
		{z100, 100, z100, t},
		{t, 50, z50, t},
		{t, 5, z11, z100},
	}

	for i, s := range steps {
		if s.from != t {
			f.copy(t, s.from)
		}

		f.squareTimes(t, s.count, fmt.Sprintf("square%d", i))

		f.mul(s.to, t, s.by)
	}
}

func x25519Arm(a *asm) {
	a.function("x25519ARM", "func x25519ARM(out *[32]byte, work *[16][4]uint64)", 16,
		"X25519 on the workspace: slot 0 holds u below 2^255, slots 1-4 the ladder's starting x2 =",
		"1, z2 = 0, x3 = u and z3 = 1, slot 15 the clamped scalar. out receives the canonical",
		"little-endian u-coordinate of the result.")

	a.op("MOVD\twork+8(FP), R0")

	a.op("MOVD\t$38, %s", fe38)

	a.op("MOVD\t$254, R25")

	a.op("MOVD\tZR, R26")

	a.label("ladder")

	a.op("LSR\t$6, R25, R1")

	a.op("ADD\t$%d, R0, R2", 32*slotK)

	a.op("MOVD\t(R2)(R1<<3), R3")

	a.op("AND\t$63, R25, R4")

	a.op("LSR\tR4, R3, R3")

	a.op("AND\t$1, R3, R3")

	a.op("EOR\tR3, R26, R26")

	a.op("NEG\tR26, R7")

	a.op("MOVD\tR3, R26")

	feSwap(a, slotX2, slotX3, "R7")

	feSwap(a, slotZ2, slotZ3, "R7")

	ladderStep(armField{a})

	a.op("SUBS\t$1, R25, R25")

	a.op("BGE\tladder")

	a.op("NEG\tR26, R7")

	feSwap(a, slotX2, slotX3, "R7")

	feSwap(a, slotZ2, slotZ3, "R7")

	feInvert(armField{a})

	feMul(a, slotTemp, slotX2, 13)

	a.comment("Below p: fold bit 255 in as 19, then subtract p, by adding 19 and clearing bit 255,",
		"when that sets bit 255.")

	feLoad(a, feA, slotTemp)

	a.op("LSR\t$63, R4, R5")

	a.op("AND\t$0x7fffffffffffffff, R4, R4")

	a.op("MOVD\t$19, R6")

	a.op("MUL\tR6, R5, R5")

	a.op("ADDS\tR5, R1, R1")

	a.op("ADCS\tZR, R2, R2")

	a.op("ADCS\tZR, R3, R3")

	a.op("ADC\tZR, R4, R4")

	a.op("ADDS\t$19, R1, R9")

	a.op("ADCS\tZR, R2, R10")

	a.op("ADCS\tZR, R3, R11")

	a.op("ADC\tZR, R4, R12")

	a.op("TST\t$0x8000000000000000, R12")

	a.op("AND\t$0x7fffffffffffffff, R12, R12")

	for i, pair := range [4][2]string{{"R9", "R1"}, {"R10", "R2"}, {"R11", "R3"}, {"R12", "R4"}} {
		a.op("CSEL\tNE, %s, %s, %s", pair[0], pair[1], feA[i])
	}

	a.op("MOVD\tout+0(FP), R8")

	a.op("STP\t(R1, R2), (R8)")

	a.op("STP\t(R3, R4), 16(R8)")

	a.op("RET")
}

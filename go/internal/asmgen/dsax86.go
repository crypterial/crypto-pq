package main

import "fmt"

// ML-DSA with AVX2 beyond the NTTs of nttx86.go: the products in the NTT domain, the sparse
// products with the challenge, the rounding, hints and norm checks of signing and verification,
// the bit packing of y, z and w1, and the rejection sampling of the matrix. Every kernel returns
// exactly what the portable code in mldsa.go returns.
//
// The products use Montgomery's reduction: the 64-bit sums of 32 x 32-bit products, from VPMULUDQ
// on the even lanes and on the odd lanes moved down, become x 2^-32 mod q with three more VPMULUDQ
// per four lanes and no 64-bit high multiplication, which AVX2 lacks. The factor 2^-32 is undone
// for free: by dsaInverseNTTUnscaleAVX2, an inverse NTT whose last factors carry 2^32, or, for the
// products with the challenge, by a challenge whose nonzero coefficients are +-2^32 mod q.

const dsaR = (1 << 32) % dsaQ

// -q^-1 mod 2^32 by Newton's iteration: an odd q is its own inverse modulo 8, and every step
// doubles the number of correct bits.
func dsaQinvNeg() uint64 {
	x := uint64(dsaQ)

	for range 5 {
		x = x * (2 - dsaQ*x) & 0xffffffff
	}

	return -x & 0xffffffff
}

func dsaAmd64(a *asm) {
	dsaDotAVX2(a, false)

	dsaDotAVX2(a, true)

	dsaMulAVX2(a, false)

	dsaMulAVX2(a, true)

	dsaInverseNTTUnscaleAVX2(a)

	dsaBeyondAVX2(a)

	for _, wide := range []bool{false, true} {
		dsaSubLowAVX2(a, wide, false)

		dsaSubLowAVX2(a, wide, true)

		dsaHintsAVX2(a, wide)

		dsaHighBitsAVX2(a, wide)

		dsaUseHintsAVX2(a, wide)
	}

	for _, width := range []int{18, 20} {
		dsaUnpackGamma1AVX2(a, width)

		dsaPackGamma1AVX2(a, width)

		dsaUnpackAddAVX2(a, width)
	}

	dsaRejUniformAVX2(a)

	dsaPower2RoundAVX2(a)

	dsaUnpackT1AVX2(a)

	dsaPackEtaAVX2(a, 3)

	dsaPackEtaAVX2(a, 4)

	dsaSparseAVX2(a)

	for _, width := range []int{3, 4} {
		dsaExtendAVX2(a, width)
	}

	dsaInverseTables(a)

	a.table("dsaMont", 4, []uint64{dsaQ, dsaQinvNeg(), 127, (dsaQ - 1) / 2, 1 << 17, 1 << 19})

	// HighBits per gamma2, (q - 1) / 32 then (q - 1) / 88: the multipliers of the two rounding
	// steps, the mask or the largest r1, and r1's factor 2 gamma2 / 512.
	a.table("dsaRound", 2, []uint64{1025, 512, 15, 1023, 11275, 128, 43, 372})

	// Byte selections, the same in both 128-bit lanes: the three bytes of each 20-bit (and 18-bit)
	// value of the packed y and z, with their shifts; the bytes of the eight 23-bit candidates of
	// RejNTTPoly after VPERMQ; and the order of the w1 bytes.
	var unpack20, unpack18, candidates, w1Order4 []uint64

	for lane := range 2 {
		for i := range 4 {
			for j, starts := range [][]int{{0, 2, 5, 7}, {0, 2, 4, 6}} {
				table := &unpack20

				if j == 1 {
					table = &unpack18
				}

				b := starts[i]

				*table = append(*table, uint64(b), uint64(b+1), uint64(b+2), 0x80)
			}

			first := 3 * i

			if lane == 1 {
				first = 4 + 3*i
			}

			candidates = append(candidates, uint64(first), uint64(first+1), uint64(first+2), 0x80)
		}

		w1Order4 = append(w1Order4, 0, 1, 8, 9, 2, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15)
	}

	a.table("dsaUnpack20", 1, unpack20)

	a.table("dsaUnpack18", 1, unpack18)

	a.table("dsaCandidates", 1, candidates)

	a.table("dsaW1Order4", 1, w1Order4)

	a.table("dsaShifts", 4, []uint64{0, 4, 0, 4, 0, 4, 0, 4, 0, 2, 4, 6, 0, 2, 4, 6})

	// The 6-bit w1 order: the three low bytes of every doubleword, then four bytes that the stores
	// leave out.
	a.table("dsaW1Order6", 1, []uint64{0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 0x80, 0x80, 0x80, 0x80, 0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 0x80, 0x80, 0x80, 0x80})

	a.table("dsaInterleave", 4, []uint64{0, 4, 1, 5, 2, 6, 3, 7})

	a.table("dsaHintBits", 4, []uint64{1, 2, 4, 8, 16, 32, 64, 128, 0, 1, 2, 3, 4, 5, 6, 7})

	dsaEtaTable(a, 3)

	dsaEtaTable(a, 4)

	// The two bytes of each 10-bit value of t1 and its shift, the same in both lanes.
	var unpack10 []uint64

	for range 2 {
		for i := range 4 {
			b := 10 * i / 8

			unpack10 = append(unpack10, uint64(b), uint64(b+1), 0x80, 0x80)
		}
	}

	a.table("dsaUnpack10", 1, unpack10)

	a.table("dsaShifts10", 4, []uint64{0, 2, 4, 6, 0, 2, 4, 6})

	a.table("dsaThree", 1, []uint64{0, 1, 2, 8, 9, 10, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 1, 2, 8, 9, 10, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80})

	a.table("dsaFive", 1, []uint64{0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80})

	// For each 8-bit mask of accepted candidates, the lanes that hold them, in order.
	var compress []uint64

	for mask := range 256 {
		n := 0

		for lane := range 8 {
			if mask>>lane&1 == 1 {
				compress = append(compress, uint64(lane))

				n++
			}
		}

		for ; n < 8; n++ {
			compress = append(compress, 0)
		}
	}

	a.table("dsaCompress", 1, compress)
}

// Y15 = q and Y14 = -q^-1 mod 2^32 in every lane, from the table at AX.
func dsaMontConstants(a *asm) {
	a.op("LEAQ\tdsaMont<>(SB), AX")

	a.op("VPBROADCASTD\t(AX), Y15")

	a.op("VPBROADCASTD\t4(AX), Y14")
}

// out = x 2^-32 mod q, canonical, for the 64-bit sums x of the even lanes in even and of the odd
// lanes in odd (each below q 2^32): m = x * (-q^-1) mod 2^32 makes x + m q divisible by 2^32, and
// (x + m q) / 2^32 is below 2q, so one subtraction of q finishes.
func dsaMontReduce(a *asm, even, odd, out, t1, t2 string) {
	a.op("VPMULUDQ\tY14, %s, %s", even, t1)

	a.op("VPMULUDQ\tY14, %s, %s", odd, t2)

	a.op("VPMULUDQ\tY15, %s, %s", t1, t1)

	a.op("VPMULUDQ\tY15, %s, %s", t2, t2)

	a.op("VPADDQ\t%s, %s, %s", even, t1, t1)

	a.op("VPADDQ\t%s, %s, %s", odd, t2, t2)

	a.op("VPSHUFD\t$0xf5, %s, %s", t1, t1)

	a.op("VPBLENDD\t$0xaa, %s, %s, %s", t2, t1, out)

	a.op("VPSUBD\tY15, %s, %s", out, t1)

	a.op("VPMINUD\t%s, %s, %s", t1, out, out)
}

// One product of x (a register) and the vector at mem, added to the sums in Y0 (even lanes) and
// Y1 (odd lanes), or starting them; two sets of temporaries let consecutive products overlap.
func dsaProductTerm(a *asm, x, mem string, first bool, set int) {
	odd, other, product := "Y3", "Y4", "Y5"

	if set == 1 {
		odd, other, product = "Y6", "Y7", "Y8"
	}

	a.op("VPSHUFD\t$0xf5, %s, %s", x, odd)

	a.op("VPSHUFD\t$0xf5, %s, %s", mem, other)

	if first {
		a.op("VPMULUDQ\t%s, %s, Y0", mem, x)

		a.op("VPMULUDQ\t%s, %s, Y1", other, odd)

		return
	}

	a.op("VPMULUDQ\t%s, %s, %s", mem, x, product)

	a.op("VPMULUDQ\t%s, %s, %s", other, odd, odd)

	a.op("VPADDQ\t%s, Y0, Y0", product)

	a.op("VPADDQ\t%s, Y1, Y1", odd)
}

// dsaDotAVX2: out = 2^-32 sum of a[j] b[j] over the n polynomials at a and b, for n = 4, 5 or 7
// (the l of the three parameter sets); with sub, verification's row adds c (q - t). Eight
// products stay below 2^50, far below q 2^32.
func dsaDotAVX2(a *asm, sub bool) {
	if sub {
		a.function("dsaDotSubAVX2", "func dsaDotSubAVX2(out, a, b *[256]uint32, n int, c, t *[256]uint32)", 48,
			"out = 2^-32 (sum of a[j] b[j] + c (q - t)) mod q for the n = 4, 5 or 7 polynomials at a and b.")
	} else {
		a.function("dsaDotAVX2", "func dsaDotAVX2(out, a, b *[256]uint32, n int)", 32,
			"out = 2^-32 sum of a[j] b[j] mod q for the n = 4, 5 or 7 polynomials at a and b.")
	}

	a.op("MOVQ\tout+0(FP), DI")

	a.op("MOVQ\ta+8(FP), SI")

	a.op("MOVQ\tb+16(FP), DX")

	a.op("MOVQ\tn+24(FP), BX")

	if sub {
		a.op("MOVQ\tc+32(FP), R8")

		a.op("MOVQ\tt+40(FP), R9")
	}

	dsaMontConstants(a)

	a.op("MOVQ\t$32, CX")

	a.op("CMPQ\tBX, $4")

	a.op("JEQ\tterms4")

	a.op("CMPQ\tBX, $5")

	a.op("JEQ\tterms5")

	a.op("CMPQ\tBX, $7")

	a.op("JEQ\tterms7")

	a.op("VZEROUPPER")

	a.op("RET")

	for _, n := range []int{4, 5, 7} {
		a.label(fmt.Sprintf("terms%d", n))

		for j := range n {
			a.op("VMOVDQU\t%d(SI), Y2", 1024*j)

			dsaProductTerm(a, "Y2", fmt.Sprintf("%d(DX)", 1024*j), j == 0, j%2)
		}

		if sub {
			a.op("VMOVDQU\t(R8), Y2")

			a.op("VMOVDQU\t(R9), Y9")

			a.op("VPSUBD\tY9, Y15, Y9")

			dsaProductTerm(a, "Y2", "Y9", false, n%2)

			a.op("ADDQ\t$32, R8")

			a.op("ADDQ\t$32, R9")
		}

		dsaMontReduce(a, "Y0", "Y1", "Y2", "Y3", "Y4")

		a.op("VMOVDQU\tY2, (DI)")

		a.op("ADDQ\t$32, SI")

		a.op("ADDQ\t$32, DX")

		a.op("ADDQ\t$32, DI")

		a.op("DECQ\tCX")

		a.op("JNZ\tterms%d", n)

		a.op("VZEROUPPER")

		a.op("RET")
	}
}

// dsaMulAVX2: out = 2^-32 a b mod q; with add, out = 2^-32 a b + y mod q.
func dsaMulAVX2(a *asm, add bool) {
	if add {
		a.function("dsaMulAddAVX2", "func dsaMulAddAVX2(out, a, b, y *[256]uint32)", 32,
			"out = 2^-32 a b + y mod q, coefficient by coefficient, for canonical y.")
	} else {
		a.function("dsaMulAVX2", "func dsaMulAVX2(out, a, b *[256]uint32)", 24,
			"out = 2^-32 a b mod q, coefficient by coefficient.")
	}

	a.op("MOVQ\tout+0(FP), DI")

	a.op("MOVQ\ta+8(FP), SI")

	a.op("MOVQ\tb+16(FP), DX")

	if add {
		a.op("MOVQ\ty+24(FP), R8")
	}

	dsaMontConstants(a)

	a.op("MOVQ\t$32, CX")

	a.label("loop")

	a.op("VMOVDQU\t(SI), Y2")

	dsaProductTerm(a, "Y2", "(DX)", true, 0)

	dsaMontReduce(a, "Y0", "Y1", "Y2", "Y3", "Y4")

	if add {
		a.op("VPADDD\t(R8), Y2, Y2")

		a.op("VPSUBD\tY15, Y2, Y3")

		a.op("VPMINUD\tY3, Y2, Y2")

		a.op("ADDQ\t$32, R8")
	}

	a.op("VMOVDQU\tY2, (DI)")

	a.op("ADDQ\t$32, SI")

	a.op("ADDQ\t$32, DX")

	a.op("ADDQ\t$32, DI")

	a.op("DECQ\tCX")

	a.op("JNZ\tloop")

	a.op("VZEROUPPER")

	a.op("RET")
}

// The tables of dsaInverseNTTUnscaleAVX2, which reads them as dsaInverseNTTAVX2 of nttx86.go reads
// its own: per block b of pass 1 the broadcast zetas of layers 8 and 16, then those of layers 32
// and 64 and the last layer's factors, which carry 2^32; per pair of registers the zetas of layers
// 1, 2 and 4; the constants q, 2q and the offsets 2^i q.
func dsaInverseTables(a *asm) {
	zetas, _ := dsaZetaTables()

	reversed := func(i int) uint64 { return zetas[255-i] }

	var broadcast []uint64

	put := func(values ...uint64) {
		for _, v := range values {
			for range 8 {
				broadcast = append(broadcast, v)
			}

			for range 8 {
				broadcast = append(broadcast, v<<32/dsaQ)
			}
		}
	}

	for b := range 8 {
		put(reversed(224+2*b), reversed(225+2*b), reversed(240+b))
	}

	put(reversed(248), reversed(249), reversed(250), reversed(251), reversed(252), reversed(253), zetas[1]*dsaNInv%dsaQ*dsaR%dsaQ, dsaNInv*dsaR%dsaQ)

	a.table("dsaBroadcast", 4, broadcast)

	var lanes []uint64

	spread := func(values []uint64, each int) {
		for _, table := range [][]uint64{values, shoupsOf(values)} {
			for _, v := range table {
				for range each {
					lanes = append(lanes, v)
				}
			}
		}
	}

	for v := 0; v < 32; v += 2 {
		var one []uint64

		for i := range 8 {
			one = append(one, reversed(4*v+i))
		}

		spread(one, 1)

		spread([]uint64{reversed(128 + 2*v), reversed(129 + 2*v), reversed(130 + 2*v), reversed(131 + 2*v)}, 2)

		spread([]uint64{reversed(192 + v), reversed(193 + v)}, 4)
	}

	a.table("dsaLanes", 4, lanes)

	var constants []uint64

	for _, c := range []uint64{dsaQ, 2 * dsaQ} {
		for range 8 {
			constants = append(constants, c)
		}
	}

	for shift := range 8 {
		for range 8 {
			constants = append(constants, dsaQ<<shift)
		}
	}

	a.table("dsaAVX2Constants", 4, constants)
}

// dsaInverseNTTAVX2 of nttx86.go step for step, with the factors of the last layer multiplied by
// 2^32 mod q.
func dsaInverseNTTUnscaleAVX2(a *asm) {
	a.function("dsaInverseNTTUnscaleAVX2", "func dsaInverseNTTUnscaleAVX2(w *[256]uint32)", 8,
		"NTT^-1(2^32 w) of canonical coefficients, left canonical: the inverse NTT of FIPS 204,",
		"Algorithm 42, that also undoes the factor 2^-32 of the Montgomery products.")

	a.op("MOVQ\tw+0(FP), DI")

	dsaAVX2Constants(a)

	a.comment("Pass 1: layers 1, 2 and 4 inside pairs of registers, then 8 and 16 on blocks of",
		"four registers.")

	a.op("MOVQ\tDI, SI")

	a.op("MOVQ\t$8, CX")

	a.label("inner")

	for i := range 4 {
		a.op("VMOVDQU\t%d(SI), %s", 32*i, data(i))
	}

	for _, pair := range [][2]string{{"Y0", "Y1"}, {"Y2", "Y3"}} {
		shuffle8(a, pair[0], pair[1], "Y4", "Y5")

		shuffle4(a, "Y4", "Y5", "Y6", "Y7")

		shuffle2With(a, "Y6", "Y7", "Y4", "Y5", "Y8")

		dsaOffsetAVX2(a, 0)

		dsaNextLanes(a)

		dsaInverseAVX2(a, "Y4", "Y5")

		shuffle2With(a, "Y4", "Y5", "Y6", "Y7", "Y8")

		dsaOffsetAVX2(a, 1)

		dsaNextLanes(a)

		dsaInverseAVX2(a, "Y6", "Y7")

		shuffle4(a, "Y6", "Y7", "Y4", "Y5")

		dsaOffsetAVX2(a, 2)

		dsaNextLanes(a)

		dsaInverseAVX2(a, "Y4", "Y5")

		shuffle8(a, "Y4", "Y5", pair[0], pair[1])
	}

	dsaOffsetAVX2(a, 3)

	dsaNextBroadcast(a)

	dsaInverseAVX2(a, "Y0", "Y1")

	dsaNextBroadcast(a)

	dsaInverseAVX2(a, "Y2", "Y3")

	dsaOffsetAVX2(a, 4)

	dsaNextBroadcast(a)

	dsaInverseAVX2(a, "Y0", "Y2")

	dsaInverseAVX2(a, "Y1", "Y3")

	for i := range 4 {
		a.op("VMOVDQU\t%s, %d(SI)", data(i), 32*i)
	}

	a.op("ADDQ\t$128, SI")

	a.op("DECQ\tCX")

	a.op("JNZ\tinner")

	a.comment("Pass 2: layers 32 and 64, then 128 with the factor 2^32 / 256 folded into its zetas,",
		"on the registers j, j + 4, ..., j + 28.")

	a.op("MOVQ\tDI, SI")

	a.op("MOVQ\t$4, CX")

	a.label("outer")

	for i := range 8 {
		a.op("VMOVDQU\t%d(SI), %s", 128*i, data(i))
	}

	a.op("MOVQ\tR8, R10")

	dsaOffsetAVX2(a, 5)

	for i := range 4 {
		dsaNextBroadcast(a)

		dsaInverseAVX2(a, data(2*i), data(2*i+1))
	}

	dsaOffsetAVX2(a, 6)

	dsaNextBroadcast(a)

	dsaInverseAVX2(a, "Y0", "Y2")

	dsaInverseAVX2(a, "Y1", "Y3")

	dsaNextBroadcast(a)

	dsaInverseAVX2(a, "Y4", "Y6")

	dsaInverseAVX2(a, "Y5", "Y7")

	dsaOffsetAVX2(a, 7)

	for i := range 4 {
		x, y := data(i), data(i+4)

		a.op("VPSUBD\t%s, %s, Y15", x, y)

		a.op("VPADDD\t%s, %s, %s", y, x, x)

		a.op("VPADDD\tY14, Y15, %s", y)

		a.op("VMOVDQU\t64(R8), Y11")

		a.op("VMOVDQU\t96(R8), Y12")

		a.op("VMOVDQA\tY12, Y15")

		dsaShoupAVX2(a, x)

		a.op("VMOVDQA\tY10, %s", x)

		dsaReduceOnceAVX2(a, x)

		a.op("VMOVDQU\t(R8), Y11")

		a.op("VMOVDQU\t32(R8), Y12")

		a.op("VMOVDQA\tY12, Y15")

		dsaShoupAVX2(a, y)

		a.op("VMOVDQA\tY10, %s", y)

		dsaReduceOnceAVX2(a, y)
	}

	a.op("MOVQ\tR10, R8")

	for i := range 8 {
		a.op("VMOVDQU\t%s, %d(SI)", data(i), 128*i)
	}

	a.op("ADDQ\t$32, SI")

	a.op("DECQ\tCX")

	a.op("JNZ\touter")

	a.op("VZEROUPPER")

	a.op("RET")
}

// Leaves 1 in AX when some lane of acc is set, otherwise 0.
func dsaAnySet(a *asm, acc string) {
	a.op("XORL\tAX, AX")

	a.op("VPTEST\t%s, %s", acc, acc)

	a.op("SETNE\tAL")
}

// The absolute value of x as a centered representative, min(x, q - x), for canonical x; Y15 = q.
func dsaCenteredAbs(a *asm, x, t string) {
	a.op("VPSUBD\t%s, Y15, %s", x, t)

	a.op("VPMINUD\t%s, %s, %s", t, x, x)
}

// Sets the lanes of acc where x exceeds the bound minus one in Y13; x is overwritten.
func dsaFlagBeyond(a *asm, x, acc string) {
	a.op("VPCMPGTD\tY13, %s, %s", x, x)

	a.op("VPOR\t%s, %s, %s", x, acc, acc)
}

// Broadcasts the 32-bit argument at the given frame offset, minus one, into Y13.
func dsaBoundMinusOne(a *asm, arg string) {
	a.op("MOVL\t%s, BX", arg)

	a.op("DECL\tBX")

	a.op("MOVL\tBX, X13")

	a.op("VPBROADCASTD\tX13, Y13")
}

func dsaBeyondAVX2(a *asm) {
	a.function("dsaBeyondAVX2", "func dsaBeyondAVX2(w *[256]uint32, bound uint32) uint32", 20,
		"1 when some canonical coefficient of w is at least bound in centered absolute value, else 0.")

	a.op("MOVQ\tw+0(FP), DI")

	dsaMontConstants(a)

	dsaBoundMinusOne(a, "bound+8(FP)")

	a.op("VPXOR\tY0, Y0, Y0")

	a.op("MOVQ\t$32, CX")

	a.label("loop")

	a.op("VMOVDQU\t(DI), Y1")

	dsaCenteredAbs(a, "Y1", "Y2")

	dsaFlagBeyond(a, "Y1", "Y0")

	a.op("ADDQ\t$32, DI")

	a.op("DECQ\tCX")

	a.op("JNZ\tloop")

	dsaAnySet(a, "Y0")

	a.op("MOVL\tAX, ret+16(FP)")

	a.op("VZEROUPPER")

	a.op("RET")
}

// The rounding constants for gamma2 = (q - 1) / 32, or (q - 1) / 88 when wide: Y12 = 127, Y11 and
// Y10 the multipliers, Y9 the mask 15 or the largest r1, 43, Y8 = 2 gamma2 / 512 in the low half
// of each doubleword, Y7 = (q - 1) / 2.
func dsaRoundConstants(a *asm, wide bool) {
	a.op("VPBROADCASTD\t8(AX), Y12")

	a.op("VPBROADCASTD\t12(AX), Y7")

	a.op("LEAQ\tdsaRound<>(SB), BX")

	offset := 0

	if wide {
		offset = 8
	}

	a.op("VPBROADCASTW\t%d(BX), Y11", offset)

	a.op("VPBROADCASTW\t%d(BX), Y10", offset+2)

	a.op("VPBROADCASTD\t%d(BX), Y9", offset+4)

	a.op("VPSRLD\t$16, Y9, Y8")

	a.op("VPSLLD\t$16, Y9, Y9")

	a.op("VPSRLD\t$16, Y9, Y9")
}

// r1 of Decompose (FIPS 204, Algorithm 36) for canonical w into out, as dsaDecompose computes it:
// x = (w + 127) / 128 is below 2^16, its product with 1025 (11275) shifted right by 16 is exact in
// the high half of a 16-bit product, and VPMULHRSW by 512 (128) adds 32 (128) and shifts by 6 (8),
// which together round x * 1025 / 2^22 (x * 11275 / 2^24) as the portable code does. Then the mask
// 15, or r1 = 0 where it reached 44.
func dsaHighBitsOf(a *asm, w, out, t string, wide bool) {
	a.op("VPADDD\tY12, %s, %s", w, out)

	a.op("VPSRLD\t$7, %s, %s", out, out)

	a.op("VPMULHUW\tY11, %s, %s", out, out)

	a.op("VPMULHRSW\tY10, %s, %s", out, out)

	if !wide {
		a.op("VPAND\tY9, %s, %s", out, out)

		return
	}

	a.op("VPCMPGTD\tY9, %s, %s", out, t)

	a.op("VPANDN\t%s, %s, %s", out, t, out)
}

// r0 of Decompose, centered, into out for canonical w and its r1: w - 2 gamma2 r1, with q
// subtracted when it exceeds (q - 1) / 2. 2 gamma2 r1 is (r1 * 2 gamma2 / 512) * 512, the product
// fitting in 16 bits.
func dsaLowBitsOf(a *asm, w, r1, out, t string) {
	a.op("VPMULLW\tY8, %s, %s", r1, t)

	a.op("VPSLLD\t$9, %s, %s", t, t)

	a.op("VPSUBD\t%s, %s, %s", t, w, out)

	a.op("VPCMPGTD\tY7, %s, %s", out, t)

	a.op("VPAND\tY15, %s, %s", t, t)

	a.op("VPSUBD\t%s, %s, %s", t, out, out)
}

func gammaName(wide bool) string {
	if wide {
		return "88"
	}

	return "32"
}

// dsaSubLowAVX2: w = w - p, then 1 when some |r0| reaches bound; with small, p is a polynomial of
// 16-bit integers (a sparse product), which w - p leaves in (-2^15, q + 2^15).
func dsaSubLowAVX2(a *asm, wide, small bool) {
	name, declaration := "dsaSubLow"+gammaName(wide)+"AVX2", "(w, p *[256]uint32, bound uint32) uint32"

	if small {
		name, declaration = "dsaSubSmallLow"+gammaName(wide)+"AVX2", "(w *[256]uint32, d *[256]int16, bound uint32) uint32"
	}

	a.function(name, "func "+name+declaration, 28,
		fmt.Sprintf("w = w - p mod q, then 1 when the centered r0 of Decompose with gamma2 = (q - 1) / %s reaches", gammaName(wide)),
		"bound in absolute value somewhere, else 0.")

	a.op("MOVQ\tw+0(FP), DI")

	if small {
		a.op("MOVQ\td+8(FP), SI")
	} else {
		a.op("MOVQ\tp+8(FP), SI")
	}

	dsaMontConstants(a)

	dsaBoundMinusOne(a, "bound+16(FP)")

	dsaRoundConstants(a, wide)

	a.op("VPXOR\tY6, Y6, Y6")

	a.op("MOVQ\t$32, CX")

	a.label("loop")

	a.op("VMOVDQU\t(DI), Y0")

	if small {
		a.op("VPMOVSXWD\t(SI), Y1")

		a.op("VPSUBD\tY1, Y0, Y0")

		a.op("VPSRAD\t$31, Y0, Y1")

		a.op("VPAND\tY15, Y1, Y1")

		a.op("VPADDD\tY1, Y0, Y0")
	} else {
		a.op("VPSUBD\t(SI), Y0, Y0")

		a.op("VPADDD\tY15, Y0, Y0")
	}

	a.op("VPSUBD\tY15, Y0, Y1")

	a.op("VPMINUD\tY1, Y0, Y0")

	a.op("VMOVDQU\tY0, (DI)")

	dsaHighBitsOf(a, "Y0", "Y1", "Y2", wide)

	dsaLowBitsOf(a, "Y0", "Y1", "Y1", "Y2")

	a.op("VPABSD\tY1, Y1")

	dsaFlagBeyond(a, "Y1", "Y6")

	a.op("ADDQ\t$32, DI")

	if small {
		a.op("ADDQ\t$16, SI")
	} else {
		a.op("ADDQ\t$32, SI")
	}

	a.op("DECQ\tCX")

	a.op("JNZ\tloop")

	dsaAnySet(a, "Y6")

	a.op("MOVL\tAX, ret+24(FP)")

	a.op("VZEROUPPER")

	a.op("RET")
}

// dsaHintsAVX2: for w = w0 - c s2 and p = c t0, beyond when |p| reaches gamma2, and the hints
// HighBits(w + p) != HighBits(w) as bits, with their count. Four vectors at a time make the masks
// of 32 coefficients, packed to bytes in order, whose sign bits VPMOVMSKB gathers.
func dsaHintsAVX2(a *asm, wide bool) {
	name := "dsaHints" + gammaName(wide) + "AVX2"

	a.function(name, fmt.Sprintf("func %s(hints *[4]uint64, w, p *[256]uint32) (beyond, count uint32)", name), 32,
		fmt.Sprintf("hints = MakeHint(-p, w + p) with gamma2 = (q - 1) / %s as bits, and their count; beyond is 1", gammaName(wide)),
		"when the centered p reaches gamma2 in absolute value somewhere, else 0.")

	a.op("MOVQ\thints+0(FP), R8")

	a.op("MOVQ\tw+8(FP), DI")

	a.op("MOVQ\tp+16(FP), SI")

	dsaMontConstants(a)

	dsaRoundConstants(a, wide)

	gamma2 := (dsaQ - 1) / 32

	if wide {
		gamma2 = (dsaQ - 1) / 88
	}

	a.comment("Y13 = gamma2 - 1, Y6 the beyond flags, Y5 the byte order, DX the count.")

	a.op("MOVL\t$%d, BX", gamma2-1)

	a.op("MOVL\tBX, X13")

	a.op("VPBROADCASTD\tX13, Y13")

	a.op("VPXOR\tY6, Y6, Y6")

	a.op("LEAQ\tdsaInterleave<>(SB), BX")

	a.op("VMOVDQU\t(BX), Y5")

	a.op("XORL\tDX, DX")

	a.op("MOVQ\t$8, CX")

	a.label("loop")

	agree := []string{"Y7", "Y8", "Y3", "Y4"}

	for v, out := range agree {
		a.op("VMOVDQU\t%d(DI), Y0", 32*v)

		a.op("VMOVDQU\t%d(SI), Y1", 32*v)

		a.op("VMOVDQA\tY1, Y2")

		dsaCenteredAbs(a, "Y2", "Y14")

		dsaFlagBeyond(a, "Y2", "Y6")

		a.op("VPADDD\tY1, Y0, Y1")

		a.op("VPSUBD\tY15, Y1, Y2")

		a.op("VPMINUD\tY2, Y1, Y1")

		dsaHighBitsOf(a, "Y0", "Y2", "Y14", wide)

		dsaHighBitsOf(a, "Y1", "Y1", "Y14", wide)

		a.op("VPCMPEQD\tY2, Y1, %s", out)
	}

	a.comment("The agreement masks as bytes in order; the hints are where they disagree.")

	a.op("VPACKSSDW\tY8, Y7, Y0")

	a.op("VPACKSSDW\tY4, Y3, Y1")

	a.op("VPACKSSWB\tY1, Y0, Y0")

	a.op("VPERMD\tY0, Y5, Y0")

	a.op("VPMOVMSKB\tY0, AX")

	a.op("NOTL\tAX")

	a.op("MOVL\tAX, (R8)")

	a.op("POPCNTL\tAX, AX")

	a.op("ADDL\tAX, DX")

	a.op("ADDQ\t$128, DI")

	a.op("ADDQ\t$128, SI")

	a.op("ADDQ\t$4, R8")

	a.op("DECQ\tCX")

	a.op("JNZ\tloop")

	a.op("MOVL\tDX, count+28(FP)")

	dsaAnySet(a, "Y6")

	a.op("MOVL\tAX, beyond+24(FP)")

	a.op("VZEROUPPER")

	a.op("RET")
}

// w1Encode (FIPS 204, Algorithm 28) of the values below 16 in Y0-Y7, 64 coefficients, into the 32
// bytes at DI: doublewords to words to bytes, VPMADDUBSW by 1 and 16 joins neighbours into one
// byte, and the packing order of the lanes is undone by VPERMQ and the byte order in Y14. Y13
// holds the factors 1 and 16.
func dsaPackW1Four(a *asm) {
	a.op("VPACKUSDW\tY1, Y0, Y0")

	a.op("VPACKUSDW\tY3, Y2, Y2")

	a.op("VPACKUSWB\tY2, Y0, Y0")

	a.op("VPACKUSDW\tY5, Y4, Y4")

	a.op("VPACKUSDW\tY7, Y6, Y6")

	a.op("VPACKUSWB\tY6, Y4, Y4")

	a.op("VPMADDUBSW\tY13, Y0, Y0")

	a.op("VPMADDUBSW\tY13, Y4, Y4")

	a.op("VPACKUSWB\tY4, Y0, Y0")

	a.op("VPERMQ\t$0xd8, Y0, Y0")

	a.op("VPSHUFB\tY14, Y0, Y0")

	a.op("VMOVDQU\tY0, (DI)")
}

// w1Encode of the values below 64 in Y0-Y3, 32 coefficients, into the 24 bytes at DI: bytes in
// order (VPERMD by Y13), VPMADDUBSW by 1 and 64 and VPMADDWD by 1 and 4096 join four values into
// the low three bytes of a doubleword, which VPSHUFB by Y14 gathers, twelve per 128-bit lane.
// Y4 is overwritten; Y5 holds the byte factors and Y6 the word factors.
func dsaPackW1Six(a *asm) {
	a.op("VPACKUSDW\tY1, Y0, Y0")

	a.op("VPACKUSDW\tY3, Y2, Y2")

	a.op("VPACKUSWB\tY2, Y0, Y0")

	a.op("VPERMD\tY0, Y13, Y0")

	a.op("VPMADDUBSW\tY5, Y0, Y0")

	a.op("VPMADDWD\tY6, Y0, Y0")

	a.op("VPSHUFB\tY14, Y0, Y0")

	a.op("VMOVQ\tX0, (DI)")

	a.op("VPEXTRD\t$2, X0, 8(DI)")

	a.op("VEXTRACTI128\t$1, Y0, X4")

	a.op("VMOVQ\tX4, 12(DI)")

	a.op("VPEXTRD\t$2, X4, 20(DI)")
}

// The constants of the w1 packing: Y13 and Y14 (and Y5 and Y6 when wide) as dsaPackW1Four and
// dsaPackW1Six read them; BX is overwritten.
func dsaPackW1Constants(a *asm, wide bool) {
	if !wide {
		a.op("MOVL\t$0x10011001, BX")

		a.op("MOVL\tBX, X13")

		a.op("VPBROADCASTD\tX13, Y13")

		a.op("LEAQ\tdsaW1Order4<>(SB), BX")

		a.op("VMOVDQU\t(BX), Y14")

		return
	}

	a.op("LEAQ\tdsaInterleave<>(SB), BX")

	a.op("VMOVDQU\t(BX), Y13")

	a.op("LEAQ\tdsaW1Order6<>(SB), BX")

	a.op("VMOVDQU\t(BX), Y14")

	a.op("MOVL\t$0x40014001, BX")

	a.op("MOVL\tBX, X5")

	a.op("VPBROADCASTD\tX5, Y5")

	a.op("MOVL\t$0x10000001, BX")

	a.op("MOVL\tBX, X6")

	a.op("VPBROADCASTD\tX6, Y6")
}

// dsaHighBitsAVX2: w1Encode of the high bits of w.
func dsaHighBitsAVX2(a *asm, wide bool) {
	name := "dsaHighBits" + gammaName(wide) + "AVX2"

	bits := 4

	if wide {
		bits = 6
	}

	a.function(name, fmt.Sprintf("func %s(out *byte, w *[256]uint32)", name), 16,
		fmt.Sprintf("out = w1Encode of the high bits of w for gamma2 = (q - 1) / %s, %d bits each, %d bytes.", gammaName(wide), bits, 32*bits))

	a.op("MOVQ\tout+0(FP), DI")

	a.op("MOVQ\tw+8(FP), SI")

	a.op("LEAQ\tdsaMont<>(SB), AX")

	dsaRoundConstants(a, wide)

	dsaPackW1Constants(a, wide)

	vectors := 8

	if wide {
		vectors = 4
	}

	a.op("MOVQ\t$%d, CX", 32/vectors)

	a.label("loop")

	for v := range vectors {
		a.op("VMOVDQU\t%d(SI), %s", 32*v, data(v))

		dsaHighBitsOf(a, data(v), data(v), "Y15", wide)
	}

	if wide {
		dsaPackW1Six(a)

		a.op("ADDQ\t$24, DI")
	} else {
		dsaPackW1Four(a)

		a.op("ADDQ\t$32, DI")
	}

	a.op("ADDQ\t$%d, SI", 32*vectors)

	a.op("DECQ\tCX")

	a.op("JNZ\tloop")

	a.op("VZEROUPPER")

	a.op("RET")
}

// dsaUseHintsAVX2: w = UseHint(hints, w) in place, then w1Encode of w.
func dsaUseHintsAVX2(a *asm, wide bool) {
	name := "dsaUseHints" + gammaName(wide) + "AVX2"

	bits := 4

	if wide {
		bits = 6
	}

	a.function(name, fmt.Sprintf("func %s(out *byte, w *[256]uint32, hints *[4]uint64)", name), 24,
		fmt.Sprintf("w = UseHint(hints, w) for gamma2 = (q - 1) / %s with the hints as bits, then out = w1Encode", gammaName(wide)),
		fmt.Sprintf("of w, %d bits each.", bits))

	a.op("MOVQ\tout+0(FP), DI")

	a.op("MOVQ\tw+8(FP), SI")

	a.op("MOVQ\thints+16(FP), DX")

	dsaMontConstants(a)

	dsaRoundConstants(a, wide)

	a.comment("Y6 = 0, Y5 all ones, Y4 = m = 44 when wide, Y13 the bit of each lane and Y14 its position.")

	a.op("LEAQ\tdsaHintBits<>(SB), BX")

	a.op("VMOVDQU\t(BX), Y13")

	a.op("VMOVDQU\t32(BX), Y14")

	a.op("VPXOR\tY6, Y6, Y6")

	a.op("VPCMPEQD\tY5, Y5, Y5")

	if wide {
		a.op("MOVL\t$44, BX")

		a.op("MOVL\tBX, X4")

		a.op("VPBROADCASTD\tX4, Y4")
	}

	a.op("MOVQ\tSI, R8")

	a.op("MOVQ\t$32, CX")

	a.label("hint")

	a.op("VMOVDQU\t(R8), Y0")

	dsaHighBitsOf(a, "Y0", "Y1", "Y2", wide)

	dsaLowBitsOf(a, "Y0", "Y1", "Y2", "Y3")

	a.comment("delta = 1 where r0 > 0 and -1 elsewhere, kept where the hint is set.")

	a.op("VPCMPGTD\tY6, Y2, Y2")

	a.op("VPADDD\tY2, Y2, Y2")

	a.op("VPXOR\tY5, Y2, Y2")

	a.op("VPBROADCASTB\t(DX), Y3")

	a.op("VPAND\tY13, Y3, Y3")

	a.op("VPSRLVD\tY14, Y3, Y3")

	a.op("VPSIGND\tY3, Y2, Y2")

	a.op("VPADDD\tY2, Y1, Y1")

	if wide {
		a.op("VPSRAD\t$31, Y1, Y2")

		a.op("VPAND\tY4, Y2, Y2")

		a.op("VPADDD\tY2, Y1, Y1")

		a.op("VPCMPEQD\tY4, Y1, Y2")

		a.op("VPANDN\tY1, Y2, Y1")
	} else {
		a.op("VPAND\tY9, Y1, Y1")
	}

	a.op("VMOVDQU\tY1, (R8)")

	a.op("ADDQ\t$32, R8")

	a.op("INCQ\tDX")

	a.op("DECQ\tCX")

	a.op("JNZ\thint")

	dsaPackW1Constants(a, wide)

	vectors := 8

	if wide {
		vectors = 4
	}

	a.op("MOVQ\t$%d, CX", 32/vectors)

	a.label("pack")

	for v := range vectors {
		a.op("VMOVDQU\t%d(SI), %s", 32*v, data(v))
	}

	if wide {
		dsaPackW1Six(a)

		a.op("ADDQ\t$24, DI")
	} else {
		dsaPackW1Four(a)

		a.op("ADDQ\t$32, DI")
	}

	a.op("ADDQ\t$%d, SI", 32*vectors)

	a.op("DECQ\tCX")

	a.op("JNZ\tpack")

	a.op("VZEROUPPER")

	a.op("RET")
}

// gamma1 for the packed width, and the offset of the second 128-bit lane's bytes: the 18-bit form
// of ML-DSA-44 and the 20-bit form of ML-DSA-65 and ML-DSA-87.
func gamma1Form(width int) (gammaOffset, laneBytes int) {
	if width == 18 {
		return 16, 9
	}

	return 20, 10
}

// dsaUnpackGamma1AVX2: BitUnpack with b = gamma1 (FIPS 204, Algorithm 19) of y and z: eight
// values per step, each 128-bit lane loaded from its first byte, every doubleword gathering the
// three bytes of its value, shifted and masked, then gamma1 - x as a canonical coefficient.
func dsaUnpackGamma1AVX2(a *asm, width int) {
	name := fmt.Sprintf("dsaUnpack%dAVX2", width)

	a.function(name, fmt.Sprintf("func %s(w *[256]uint32, in *byte)", name), 16,
		fmt.Sprintf("w = gamma1 - x mod q for the %d-bit values x at in, which must have %d readable bytes.", width, 32*width+6))

	gammaOffset, laneBytes := gamma1Form(width)

	a.op("MOVQ\tw+0(FP), DI")

	a.op("MOVQ\tin+8(FP), SI")

	dsaMontConstants(a)

	a.op("VPBROADCASTD\t%d(AX), Y10", gammaOffset)

	a.op("LEAQ\tdsaUnpack%d<>(SB), BX", width)

	a.op("VMOVDQU\t(BX), Y13")

	a.op("LEAQ\tdsaShifts<>(SB), BX")

	if width == 18 {
		a.op("VMOVDQU\t32(BX), Y12")
	} else {
		a.op("VMOVDQU\t(BX), Y12")
	}

	a.op("VPCMPEQD\tY11, Y11, Y11")

	a.op("VPSRLD\t$%d, Y11, Y11", 32-width)

	a.op("MOVQ\t$32, CX")

	a.label("loop")

	a.op("VMOVDQU\t(SI), X0")

	a.op("VINSERTI128\t$1, %d(SI), Y0, Y0", laneBytes)

	a.op("VPSHUFB\tY13, Y0, Y0")

	a.op("VPSRLVD\tY12, Y0, Y0")

	a.op("VPAND\tY11, Y0, Y0")

	a.op("VPSUBD\tY0, Y10, Y0")

	a.op("VPSRAD\t$31, Y0, Y1")

	a.op("VPAND\tY15, Y1, Y1")

	a.op("VPADDD\tY1, Y0, Y0")

	a.op("VMOVDQU\tY0, (DI)")

	a.op("ADDQ\t$%d, SI", 2*laneBytes)

	a.op("ADDQ\t$32, DI")

	a.op("DECQ\tCX")

	a.op("JNZ\tloop")

	a.op("VZEROUPPER")

	a.op("RET")
}

// dsaPackGamma1AVX2: BitPack with b = gamma1 (FIPS 204, Algorithm 17) of z, whose coefficients
// pass the norm check: v = gamma1 - z centered, joined in pairs within quadwords (v_even | v_odd
// << width), then 20-bit pairs as five bytes, 18-bit pairs as two 36-bit halves of nine bytes per
// 128-bit lane, stored exactly.
func dsaPackGamma1AVX2(a *asm, width int) {
	name := fmt.Sprintf("dsaPack%dAVX2", width)

	a.function(name, fmt.Sprintf("func %s(out *byte, w *[256]uint32)", name), 16,
		fmt.Sprintf("out = the %d-bit values gamma1 - w, w centered, %d bytes.", width, 32*width))

	gammaOffset, laneBytes := gamma1Form(width)

	a.op("MOVQ\tout+0(FP), DI")

	a.op("MOVQ\tw+8(FP), SI")

	dsaMontConstants(a)

	a.op("VPBROADCASTD\t%d(AX), Y10", gammaOffset)

	a.op("VPBROADCASTD\t12(AX), Y7")

	a.op("VPCMPEQD\tY11, Y11, Y11")

	a.op("VPSRLQ\t$%d, Y11, Y11", 64-width)

	if width == 20 {
		a.op("LEAQ\tdsaFive<>(SB), BX")

		a.op("VMOVDQU\t(BX), Y13")
	}

	a.op("MOVQ\t$32, CX")

	a.label("loop")

	a.op("VMOVDQU\t(SI), Y0")

	a.op("VPCMPGTD\tY7, Y0, Y1")

	a.op("VPAND\tY15, Y1, Y1")

	a.op("VPSUBD\tY0, Y10, Y0")

	a.op("VPADDD\tY1, Y0, Y0")

	a.op("VPSRLQ\t$%d, Y0, Y1", 32-width)

	a.op("VPANDN\tY1, Y11, Y1")

	a.op("VPAND\tY11, Y0, Y0")

	a.op("VPOR\tY1, Y0, Y0")

	if width == 20 {
		a.op("VPSHUFB\tY13, Y0, Y0")

		a.op("VMOVQ\tX0, (DI)")

		a.op("VPEXTRW\t$4, X0, 8(DI)")

		a.op("VEXTRACTI128\t$1, Y0, X1")

		a.op("VMOVQ\tX1, 10(DI)")

		a.op("VPEXTRW\t$4, X1, 18(DI)")
	} else {
		a.op("VPSLLQ\t$36, Y0, Y1")

		a.op("VPSHUFD\t$0x4e, Y1, Y1")

		a.op("VPOR\tY1, Y0, Y1")

		a.op("VPSRLQ\t$28, Y0, Y2")

		a.op("VPBLENDD\t$0xcc, Y2, Y1, Y1")

		a.op("VMOVQ\tX1, (DI)")

		a.op("VPEXTRB\t$8, X1, 8(DI)")

		a.op("VEXTRACTI128\t$1, Y1, X2")

		a.op("VMOVQ\tX2, 9(DI)")

		a.op("VPEXTRB\t$8, X2, 17(DI)")
	}

	a.op("ADDQ\t$32, SI")

	a.op("ADDQ\t$%d, DI", 2*laneBytes)

	a.op("DECQ\tCX")

	a.op("JNZ\tloop")

	a.op("VZEROUPPER")

	a.op("RET")
}

// dsaRejUniformAVX2: RejNTTPoly's candidates (FIPS 204, Algorithm 30) from the 168 rate bytes of
// a SHAKE128 state, eight per 24 bytes: VPERMQ and VPSHUFB spread them into doublewords, the
// accepted ones (below q) are moved to the front by VPERMD with the lanes from dsaCompress for
// their mask, and all eight are stored at the count, which advances by the number accepted. The
// data is public. It stops before a group when more than 248 values are in, so that every store
// stays inside the polynomial, and returns the count and the bytes it consumed.
func dsaRejUniformAVX2(a *asm) {
	a.function("dsaRejUniformAVX2", "func dsaRejUniformAVX2(out *[256]uint32, count int, state *[25]uint64) (newCount, consumed int)", 40,
		"Appends RejNTTPoly's accepted candidates from the rate of state to out at count.")

	a.op("MOVQ\tout+0(FP), DI")

	a.op("MOVQ\tcount+8(FP), CX")

	a.op("MOVQ\tstate+16(FP), SI")

	dsaMontConstants(a)

	a.op("VPCMPEQD\tY14, Y14, Y14")

	a.op("VPSRLD\t$9, Y14, Y14")

	a.op("LEAQ\tdsaCandidates<>(SB), BX")

	a.op("VMOVDQU\t(BX), Y13")

	a.op("LEAQ\tdsaCompress<>(SB), R10")

	a.op("XORQ\tDX, DX")

	a.label("loop")

	a.op("CMPQ\tCX, $248")

	a.op("JA\tdone")

	a.op("CMPQ\tDX, $168")

	a.op("JAE\tdone")

	a.op("VMOVDQU\t(SI)(DX*1), Y0")

	a.op("VPERMQ\t$0x94, Y0, Y0")

	a.op("VPSHUFB\tY13, Y0, Y0")

	a.op("VPAND\tY14, Y0, Y0")

	a.op("VPCMPGTD\tY0, Y15, Y1")

	a.op("VMOVMSKPS\tY1, BX")

	a.op("VPMOVZXBD\t(R10)(BX*8), Y2")

	a.op("VPERMD\tY0, Y2, Y0")

	a.op("VMOVDQU\tY0, (DI)(CX*4)")

	a.op("POPCNTL\tBX, BX")

	a.op("ADDQ\tBX, CX")

	a.op("ADDQ\t$24, DX")

	a.op("JMP\tloop")

	a.label("done")

	a.op("MOVQ\tCX, newCount+24(FP)")

	a.op("MOVQ\tDX, consumed+32(FP)")

	a.op("VZEROUPPER")

	a.op("RET")
}

// dsaUnpackAddAVX2: z = y + d for y unpacked as dsaUnpackGamma1AVX2 does and the sparse product d:
// gamma1 - x + d lies in (-q, q), so adding q to the negative sums makes z canonical, and its
// absolute value is the centered one for the norm check.
func dsaUnpackAddAVX2(a *asm, width int) {
	name := fmt.Sprintf("dsaUnpackAdd%dAVX2", width)

	a.function(name, fmt.Sprintf("func %s(z *[256]uint32, in *byte, d *[256]int16, bound uint32) uint32", name), 36,
		fmt.Sprintf("z = gamma1 - x + d mod q for the %d-bit values x at in (%d readable bytes); 1 when the", width, 32*width+7),
		"centered absolute value of some coefficient of z reaches bound, else 0.")

	gammaOffset, laneBytes := gamma1Form(width)

	a.op("MOVQ\tz+0(FP), DI")

	a.op("MOVQ\tin+8(FP), SI")

	a.op("MOVQ\td+16(FP), DX")

	dsaMontConstants(a)

	a.op("VPBROADCASTD\t%d(AX), Y10", gammaOffset)

	a.op("LEAQ\tdsaUnpack%d<>(SB), BX", width)

	a.op("VMOVDQU\t(BX), Y9")

	a.op("LEAQ\tdsaShifts<>(SB), BX")

	if width == 18 {
		a.op("VMOVDQU\t32(BX), Y12")
	} else {
		a.op("VMOVDQU\t(BX), Y12")
	}

	a.op("VPCMPEQD\tY11, Y11, Y11")

	a.op("VPSRLD\t$%d, Y11, Y11", 32-width)

	dsaBoundMinusOne(a, "bound+24(FP)")

	a.op("VPXOR\tY6, Y6, Y6")

	a.op("MOVQ\t$32, CX")

	a.label("loop")

	a.op("VMOVDQU\t(SI), X0")

	a.op("VINSERTI128\t$1, %d(SI), Y0, Y0", laneBytes)

	a.op("VPSHUFB\tY9, Y0, Y0")

	a.op("VPSRLVD\tY12, Y0, Y0")

	a.op("VPAND\tY11, Y0, Y0")

	a.op("VPSUBD\tY0, Y10, Y0")

	a.op("VPMOVSXWD\t(DX), Y1")

	a.op("VPADDD\tY1, Y0, Y0")

	a.op("VPABSD\tY0, Y2")

	dsaFlagBeyond(a, "Y2", "Y6")

	a.op("VPSRAD\t$31, Y0, Y1")

	a.op("VPAND\tY15, Y1, Y1")

	a.op("VPADDD\tY1, Y0, Y0")

	a.op("VMOVDQU\tY0, (DI)")

	a.op("ADDQ\t$%d, SI", 2*laneBytes)

	a.op("ADDQ\t$16, DX")

	a.op("ADDQ\t$32, DI")

	a.op("DECQ\tCX")

	a.op("JNZ\tloop")

	dsaAnySet(a, "Y6")

	a.op("MOVL\tAX, ret+32(FP)")

	a.op("VZEROUPPER")

	a.op("RET")
}

// dsaSparseAVX2: c s as the sum of tau windows of [-s, s], each 256 16-bit integers, for the starts
// of dsaChallengeStarts. The low bits of a start, the coefficient's position, are public and pick
// the window; bit 15, its sign, is secret and only masks: the window is xored with m, 0 or all ones,
// which leaves w or -w - 1, and the count of the negative windows, added at the end, makes the
// latter -w. Two passes of eight accumulators leave registers for m and a temporary.
func dsaSparseAVX2(a *asm) {
	a.function("dsaSparseAVX2", "func dsaSparseAVX2(out *[256]int16, ext *[512]int16, starts *[64]uint16, n int)", 32,
		"out = the sum of the windows ext[start:start+256] for the first n starts, the start in bits 0-8",
		"of each entry (at most 256) and the window negated where bit 15 is set.")

	a.op("MOVQ\tout+0(FP), DI")

	a.op("MOVQ\text+8(FP), SI")

	for half := range 2 {
		for i := range 8 {
			a.op("VPXOR\t%s, %s, %s", data(i), data(i), data(i))
		}

		a.op("MOVQ\tstarts+16(FP), DX")

		a.op("MOVQ\tn+24(FP), CX")

		a.op("XORQ\tR8, R8")

		a.op("TESTQ\tCX, CX")

		a.op("JZ\tstore%d", half)

		a.label(fmt.Sprintf("window%d", half))

		a.op("MOVWQZX\t(DX), AX")

		a.op("MOVQ\tAX, BX")

		a.op("SHRQ\t$15, BX")

		a.op("ADDQ\tBX, R8")

		a.op("NEGQ\tBX")

		a.op("VMOVQ\tBX, X8")

		a.op("VPBROADCASTQ\tX8, Y8")

		a.op("ANDQ\t$0x1ff, AX")

		a.op("LEAQ\t(SI)(AX*2), BX")

		for i := range 8 {
			a.op("VPXOR\t%d(BX), Y8, Y9", 256*half+32*i)

			a.op("VPADDW\tY9, %s, %s", data(i), data(i))
		}

		a.op("ADDQ\t$2, DX")

		a.op("DECQ\tCX")

		a.op("JNZ\twindow%d", half)

		a.label(fmt.Sprintf("store%d", half))

		a.op("VMOVQ\tR8, X8")

		a.op("VPBROADCASTW\tX8, Y8")

		for i := range 8 {
			a.op("VPADDW\tY8, %s, %s", data(i), data(i))

			a.op("VMOVDQU\t%s, %d(DI)", data(i), 256*half+32*i)
		}
	}

	a.op("VZEROUPPER")

	a.op("RET")
}

// dsaExtendAVX2: [-s, s] for the secret polynomial packed at in with width 3 (eta = 2) or 4
// (eta = 4) bits: sixteen values from eight bytes broadcast to both lanes, each 16-bit lane taking
// the two bytes around its value (VPSHUFB), shifted up so the value ends at the top (VPMULLW) and
// then down (VPSRLW); s = eta - x.
func dsaExtendAVX2(a *asm, width int) {
	name := fmt.Sprintf("dsaExtend%dAVX2", width)

	eta := 4

	if width == 3 {
		eta = 2
	}

	a.function(name, fmt.Sprintf("func %s(ext *[512]int16, in *byte)", name), 16,
		fmt.Sprintf("ext = [-s, s] for s = %d - x, the %d-bit values x at in (%d readable bytes).", eta, width, 30*width+8))

	a.op("MOVQ\text+0(FP), DI")

	a.op("MOVQ\tin+8(FP), SI")

	a.op("LEAQ\tdsaEta%d<>(SB), BX", width)

	a.op("VMOVDQU\t(BX), Y15")

	a.op("VMOVDQU\t32(BX), Y14")

	a.op("MOVL\t$%#x, AX", eta|eta<<16)

	a.op("MOVL\tAX, X13")

	a.op("VPBROADCASTD\tX13, Y13")

	a.op("VPXOR\tY12, Y12, Y12")

	a.op("MOVQ\t$16, CX")

	a.label("loop")

	a.op("VPBROADCASTQ\t(SI), Y0")

	a.op("VPSHUFB\tY15, Y0, Y0")

	a.op("VPMULLW\tY14, Y0, Y0")

	a.op("VPSRLW\t$%d, Y0, Y0", 16-width)

	a.op("VPSUBW\tY0, Y13, Y1")

	a.op("VPSUBW\tY1, Y12, Y2")

	a.op("VMOVDQU\tY2, (DI)")

	a.op("VMOVDQU\tY1, 512(DI)")

	a.op("ADDQ\t$%d, SI", 2*width)

	a.op("ADDQ\t$32, DI")

	a.op("DECQ\tCX")

	a.op("JNZ\tloop")

	a.op("VZEROUPPER")

	a.op("RET")
}

// The byte selection and the multipliers of dsaExtendAVX2 for one width: 16-bit lane k takes
// bytes j and j + 1 around bit width k (byte 8 lies outside the eight loaded bytes and is not
// needed there), then multiplies by 2^(16 - width - offset).
func dsaEtaTable(a *asm, width int) {
	var bytes, multipliers []uint64

	for k := range 16 {
		bit := width * k

		j, offset := bit/8, bit%8

		next := uint64(j + 1)

		if j+1 >= 8 {
			next = 0x80
		}

		bytes = append(bytes, uint64(j), next)

		multipliers = append(multipliers, 1<<(16-width-offset))
	}

	var table []uint64

	table = append(table, bytes...)

	for _, m := range multipliers {
		table = append(table, m&0xff, m>>8)
	}

	a.table(fmt.Sprintf("dsaEta%d", width), 1, table)
}

// dsaPower2RoundAVX2: Power2Round (FIPS 204, Algorithm 35) of t, t1 packed with 10 bits (pkEncode)
// and t0 as skEncode packs it, 2^12 - t0 with 13 bits. Within each quadword the odd value joins the
// even one, then within each 128-bit lane the upper quadword the lower: 40 bits of t1 per lane,
// five bytes stored exactly, and 52 bits of t0 per lane, which a general-purpose register joins
// across the lanes into thirteen bytes.
func dsaPower2RoundAVX2(a *asm) {
	a.function("dsaPower2RoundAVX2", "func dsaPower2RoundAVX2(t1, t0 *byte, t *[256]uint32)", 24,
		"Power2Round of the canonical t: t1 into 320 bytes of 10-bit values, 2^12 - t0 into 416 bytes of",
		"13-bit values.")

	a.op("MOVQ\tt1+0(FP), DI")

	a.op("MOVQ\tt0+8(FP), R8")

	a.op("MOVQ\tt+16(FP), SI")

	a.comment("Y13 = 2^13 - 1, Y12 = 2^12, Y11 = 2^13, Y10 and Y9 the low 20 and 26 bits of each quadword.")

	a.op("VPCMPEQD\tY13, Y13, Y13")

	a.op("VPSRLQ\t$44, Y13, Y10")

	a.op("VPSRLQ\t$38, Y13, Y9")

	a.op("VPSRLD\t$19, Y13, Y13")

	a.op("VPSRLD\t$12, Y13, Y12")

	a.op("VPSLLD\t$12, Y12, Y12")

	a.op("VPADDD\tY12, Y12, Y11")

	a.op("MOVQ\t$32, CX")

	a.label("loop")

	a.op("VMOVDQU\t(SI), Y0")

	a.op("VPAND\tY13, Y0, Y1")

	a.op("VPCMPGTD\tY12, Y1, Y2")

	a.op("VPAND\tY11, Y2, Y2")

	a.op("VPSUBD\tY2, Y1, Y1")

	a.op("VPSUBD\tY1, Y0, Y2")

	a.op("VPSRLD\t$13, Y2, Y2")

	a.op("VPSUBD\tY1, Y12, Y1")

	a.comment("t1: five bytes per lane.")

	a.op("VPSRLQ\t$22, Y2, Y3")

	a.op("VPOR\tY3, Y2, Y3")

	a.op("VPAND\tY10, Y3, Y3")

	a.op("VPSLLQ\t$20, Y3, Y4")

	a.op("VPSHUFD\t$0x4e, Y4, Y4")

	a.op("VPOR\tY4, Y3, Y3")

	a.op("VMOVD\tX3, (DI)")

	a.op("VPEXTRB\t$4, X3, 4(DI)")

	a.op("VEXTRACTI128\t$1, Y3, X4")

	a.op("VMOVD\tX4, 5(DI)")

	a.op("VPEXTRB\t$4, X4, 9(DI)")

	a.comment("t0: 52 bits per lane, joined in AX and BX.")

	a.op("VPSRLQ\t$19, Y1, Y3")

	a.op("VPOR\tY3, Y1, Y3")

	a.op("VPAND\tY9, Y3, Y3")

	a.op("VPSLLQ\t$26, Y3, Y4")

	a.op("VPSHUFD\t$0x4e, Y4, Y4")

	a.op("VPOR\tY4, Y3, Y3")

	a.op("VMOVQ\tX3, AX")

	a.op("VEXTRACTI128\t$1, Y3, X4")

	a.op("VMOVQ\tX4, BX")

	a.op("MOVQ\tBX, DX")

	a.op("SHLQ\t$52, DX")

	a.op("ORQ\tDX, AX")

	a.op("SHRQ\t$12, BX")

	a.op("MOVQ\tAX, (R8)")

	a.op("MOVL\tBX, 8(R8)")

	a.op("SHRQ\t$32, BX")

	a.op("MOVB\tBX, 12(R8)")

	a.op("ADDQ\t$32, SI")

	a.op("ADDQ\t$10, DI")

	a.op("ADDQ\t$13, R8")

	a.op("DECQ\tCX")

	a.op("JNZ\tloop")

	a.op("VZEROUPPER")

	a.op("RET")
}

// dsaPackEtaAVX2: BitPack with b = eta (FIPS 204, Algorithm 17) of a canonical polynomial with
// coefficients in [-eta, eta]: v = eta - s centered, then 4-bit values as dsaPackW1Four packs w1,
// or 3-bit values eight to three bytes: bytes in order, VPMADDUBSW by 1 and 8 and VPMADDWD by 1
// and 64 make 12 bits per doubleword, two of which join in each quadword, three bytes each.
func dsaPackEtaAVX2(a *asm, width int) {
	name := fmt.Sprintf("dsaPackEta%dAVX2", width)

	eta := 4

	if width == 3 {
		eta = 2
	}

	a.function(name, fmt.Sprintf("func %s(out *byte, s *[256]uint32)", name), 16,
		fmt.Sprintf("out = the %d-bit values %d - s, s centered, %d bytes.", width, eta, 32*width))

	a.op("MOVQ\tout+0(FP), DI")

	a.op("MOVQ\ts+8(FP), SI")

	dsaMontConstants(a)

	a.op("VPBROADCASTD\t12(AX), Y12")

	a.op("MOVL\t$%d, BX", eta)

	a.op("MOVL\tBX, X11")

	a.op("VPBROADCASTD\tX11, Y11")

	vectors := 8

	if width == 3 {
		vectors = 4

		a.op("LEAQ\tdsaInterleave<>(SB), BX")

		a.op("VMOVDQU\t(BX), Y13")

		a.op("LEAQ\tdsaThree<>(SB), BX")

		a.op("VMOVDQU\t(BX), Y14")

		a.op("MOVL\t$0x08010801, BX")

		a.op("MOVL\tBX, X9")

		a.op("VPBROADCASTD\tX9, Y9")

		a.op("MOVL\t$0x00400001, BX")

		a.op("MOVL\tBX, X10")

		a.op("VPBROADCASTD\tX10, Y10")
	} else {
		dsaPackW1Constants(a, false)
	}

	a.op("MOVQ\t$%d, CX", 32/vectors)

	a.label("loop")

	for v := range vectors {
		x := data(v)

		a.op("VMOVDQU\t%d(SI), %s", 32*v, x)

		a.op("VPCMPGTD\tY12, %s, Y8", x)

		a.op("VPAND\tY15, Y8, Y8")

		a.op("VPSUBD\t%s, Y11, %s", x, x)

		a.op("VPADDD\tY8, %s, %s", x, x)
	}

	if width == 4 {
		dsaPackW1Four(a)

		a.op("ADDQ\t$32, DI")
	} else {
		a.op("VPACKUSDW\tY1, Y0, Y0")

		a.op("VPACKUSDW\tY3, Y2, Y2")

		a.op("VPACKUSWB\tY2, Y0, Y0")

		a.op("VPERMD\tY0, Y13, Y0")

		a.op("VPMADDUBSW\tY9, Y0, Y0")

		a.op("VPMADDWD\tY10, Y0, Y0")

		a.op("VPSRLQ\t$20, Y0, Y1")

		a.op("VPOR\tY1, Y0, Y0")

		a.op("VPSHUFB\tY14, Y0, Y0")

		a.op("VMOVD\tX0, (DI)")

		a.op("VPEXTRW\t$2, X0, 4(DI)")

		a.op("VEXTRACTI128\t$1, Y0, X1")

		a.op("VMOVD\tX1, 6(DI)")

		a.op("VPEXTRW\t$2, X1, 10(DI)")

		a.op("ADDQ\t$12, DI")
	}

	a.op("ADDQ\t$%d, SI", 32*vectors)

	a.op("DECQ\tCX")

	a.op("JNZ\tloop")

	a.op("VZEROUPPER")

	a.op("RET")
}

// dsaUnpackT1AVX2: pkDecode's t1 (10-bit values) times 2^d: eight values from ten bytes, each
// 128-bit lane loaded from its first byte, each doubleword taking its two bytes (VPSHUFB), shifted
// (VPSRLVD), masked and shifted up by d = 13.
func dsaUnpackT1AVX2(a *asm) {
	a.function("dsaUnpackT1AVX2", "func dsaUnpackT1AVX2(w *[256]uint32, in *byte)", 16,
		"w = 2^13 t1 for the 10-bit values t1 at in, which must have 331 readable bytes.")

	a.op("MOVQ\tw+0(FP), DI")

	a.op("MOVQ\tin+8(FP), SI")

	a.op("LEAQ\tdsaUnpack10<>(SB), BX")

	a.op("VMOVDQU\t(BX), Y13")

	a.op("LEAQ\tdsaShifts10<>(SB), BX")

	a.op("VMOVDQU\t(BX), Y12")

	a.op("VPCMPEQD\tY11, Y11, Y11")

	a.op("VPSRLD\t$22, Y11, Y11")

	a.op("MOVQ\t$32, CX")

	a.label("loop")

	a.op("VMOVDQU\t(SI), X0")

	a.op("VINSERTI128\t$1, 5(SI), Y0, Y0")

	a.op("VPSHUFB\tY13, Y0, Y0")

	a.op("VPSRLVD\tY12, Y0, Y0")

	a.op("VPAND\tY11, Y0, Y0")

	a.op("VPSLLD\t$13, Y0, Y0")

	a.op("VMOVDQU\tY0, (DI)")

	a.op("ADDQ\t$10, SI")

	a.op("ADDQ\t$32, DI")

	a.op("DECQ\tCX")

	a.op("JNZ\tloop")

	a.op("VZEROUPPER")

	a.op("RET")
}

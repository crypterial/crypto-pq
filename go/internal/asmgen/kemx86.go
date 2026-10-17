package main

import "fmt"

// The ML-KEM kernels for AVX2 beside the NTTs: the products of the NTT domain, CBD sampling,
// compression with packing and its inverse, ByteEncode_12 and ByteDecode_12, and the rejection
// sampling of the matrix. Each one computes what its portable twin in mlkem.go or kem_amd64.go
// computes, with sixteen 16-bit coefficients per Y register.
//
// The products take one side of every product in a form prepared once per operation: v' = (v0,
// v1 gamma) and v^s = (v1, v0) per pair, so that a pair of the base case (FIPS 203, Algorithm 12) is
// two VPMADDWD, each summing two 16-bit products into 32 bits. The sums of up to four products are
// reduced once, by a Montgomery step in the 32-bit lanes (t = low half times q^-1 mod 2^16 by
// VPMULLW, t q by VPMADDWD with q in the even word, then the difference shifted down by 16) and a
// 16-bit Montgomery multiplication by R^2 mod q that cancels its factor R^-1.
//
// Compress_d(x) = floor((2^d x + 1664) / q) mod 2^d starts from VPMULHRSW of x by floor(2^(15 + d) /
// q), which is the quotient or one less for every x below q: the remainder 2^d x + 1664 - c q,
// computed modulo 2^16, lies below 2q and shows which. Decompress_d(y) = (y q + 2^(d - 1)) >> d is
// exactly VPMULHRSW of y 2^(15 - d) by q.

const (
	kemQInverse = 62209 // q^-1 mod 2^16
	kemR2       = 1353  // 2^32 mod q
)

type kemConstPool struct {
	name   string
	words  []uint64
	offset map[string]int
}

func newKemConstPool(name string) *kemConstPool {
	return &kemConstPool{name: name, offset: map[string]int{}}
}

func (c *kemConstPool) bytes(key string, b []byte) {
	if len(b)%8 != 0 {
		panic("constant " + key + " is not a whole number of words")
	}

	if _, ok := c.offset[key]; ok {
		panic("constant " + key + " defined twice")
	}

	c.offset[key] = 8 * len(c.words)

	for i := 0; i < len(b); i += 8 {
		var w uint64

		for j := 7; j >= 0; j-- {
			w = w<<8 | uint64(b[i+j])
		}

		c.words = append(c.words, w)
	}
}

func (c *kemConstPool) words16(key string, values []uint16) {
	var b []byte

	for _, v := range values {
		b = append(b, byte(v), byte(v>>8))
	}

	c.bytes(key, b)
}

func (c *kemConstPool) words32(key string, values []uint32) {
	var b []byte

	for _, v := range values {
		b = append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	}

	c.bytes(key, b)
}

func (c *kemConstPool) splat16(key string, v uint16) {
	values := make([]uint16, 16)

	for i := range values {
		values[i] = v
	}

	c.words16(key, values)
}

func (c *kemConstPool) splat32(key string, v uint32) {
	values := make([]uint32, 8)

	for i := range values {
		values[i] = v
	}

	c.words32(key, values)
}

// The memory operand of a constant; R13 holds the pool's address in every kernel.
func (c *kemConstPool) at(key string) string {
	off, ok := c.offset[key]

	if !ok {
		panic("no constant " + key)
	}

	return fmt.Sprintf("%d(R13)", off)
}

func (c *kemConstPool) emit(a *asm) {
	a.table(c.name, 8, c.words)
}

// A window brings the packed bytes of one register's worth of coefficients into the two lanes of a
// Y register: a 32-byte load at load, which never reaches past the end of the buffer, then VPERMQ
// with imm, after which the bytes of lane l start at byte offs[l] of that lane.
type kemWindow struct {
	load, imm int
	offs      [2]int
}

// The window for the bytes [start, start + n0) of lane 0 and [start + half, start + half + n1) of
// lane 1 inside a buffer of total bytes.
func kemWindowFor(start, half, n0, n1, total int) kemWindow {
	load := min(start, total-32)

	delta := start - load

	var w kemWindow

	w.load = load

	var q [2]int

	for l, r := range [2][2]int{{delta, delta + n0}, {delta + half, delta + half + n1}} {
		q[l] = r[0] / 8

		if q[l] > 2 || r[1] > 8*q[l]+16 {
			panic(fmt.Sprintf("no window for bytes %v of a load at %d", r, load))
		}

		w.offs[l] = r[0] - 8*q[l]
	}

	w.imm = q[0] | (q[0]+1)<<2 | q[1]<<4 | (q[1]+1)<<6

	return w
}

// A VPSHUFB control for both lanes: entry j of the lane's list is the source byte of destination
// byte j relative to the lane's offset, or -1 for zero.
func kemShuffleControl(sources []int, offs [2]int) []byte {
	b := make([]byte, 32)

	for l := range 2 {
		for j := range 16 {
			s := -1

			if j < len(sources) {
				s = sources[j]
			}

			if s < 0 {
				b[16*l+j] = 0x80

				continue
			}

			if s+offs[l] > 15 {
				panic("a shuffle reaches past its lane")
			}

			b[16*l+j] = byte(s + offs[l])
		}
	}

	return b
}

func kemControlKey(name string, offs [2]int) string {
	return fmt.Sprintf("%s_%d_%d", name, offs[0], offs[1])
}

// The per-vector loads of a kernel that reads 16 coefficients' worth of packed bytes per register.
type kemPackedVector struct {
	w   kemWindow
	key string
}

// Plans the windows of the 16 vectors of a buffer of total bytes holding bytesPer bytes per vector,
// half of them per lane, and registers the shuffle controls built by sources.
func kemPlanWindows(c *kemConstPool, name string, bytesPer, need, total int, sources []int) []kemPackedVector {
	var plan []kemPackedVector

	for v := range 16 {
		w := kemWindowFor(bytesPer*v, bytesPer/2, need, need, total)

		key := kemControlKey(name, w.offs)

		if _, ok := c.offset[key]; !ok {
			c.bytes(key, kemShuffleControl(sources, w.offs))
		}

		plan = append(plan, kemPackedVector{w, key})
	}

	return plan
}

func kemAmd64(a *asm) {
	c := newKemConstPool("kemX86")

	kemX86Constants(c)

	kemPrepareKernel(a, c)

	kemProductKernel(a, c)

	kemCBD2Kernel(a, c, false)

	kemCBD2Kernel(a, c, true)

	kemCBD3Kernel(a, c)

	kemCompressUKernel(a, c, 10)

	kemCompressUKernel(a, c, 11)

	kemCompressVKernel(a, c, 4)

	kemCompressVKernel(a, c, 5)

	kemDecompressKernel(a, c, 10)

	kemDecompressKernel(a, c, 11)

	kemMessageKernel(a, c, 4)

	kemMessageKernel(a, c, 5)

	kemEncode12Kernel(a, c)

	kemDecode12Kernel(a, c, false)

	kemDecode12Kernel(a, c, true)

	kemRejectKernel(a, c)

	c.emit(a)

	kemRejectTable(a)
}

func kemGammaValues() []uint64 {
	var gammas []uint64

	for i := range 128 {
		g := uint64(1)

		for range 2*bitReverse7(i) + 1 {
			g = g * 17 % kemQ
		}

		gammas = append(gammas, g)
	}

	return gammas
}

func kemX86Constants(c *kemConstPool) {
	c.splat16("q", kemQ)

	c.splat16("qm1", kemQ-1)

	c.splat16("qm3", kemQ-3)

	c.splat16("qinv16", kemQInverse)

	c.splat32("q32", kemQ)

	c.splat32("q32high", kemQ<<16)

	var lowUp, highDown []int

	for i := range 8 {
		lowUp = append(lowUp, -1, -1, 4*i, 4*i+1)

		highDown = append(highDown, 4*i+2, 4*i+3, -1, -1)
	}

	c.bytes("lowup", kemShuffleControl(lowUp[:16], [2]int{}))

	c.bytes("highdown", kemShuffleControl(highDown[:16], [2]int{}))

	c.splat16("r2", kemR2)

	c.splat16("r2qinv", kemR2*kemQInverse%65536)

	var swap []byte

	for i := range 32 {
		swap = append(swap, byte(i^2))
	}

	c.bytes("swap", swap)

	// Per vector v: (1, gamma_8v, 1, gamma_8v+1, ...) and the Shoup companions.
	gammas := kemGammaValues()

	var table []uint16

	for v := range 16 {
		var pairs []uint64

		for i := range 8 {
			pairs = append(pairs, 1, gammas[8*v+i])
		}

		for _, list := range [][]uint64{pairs, kemShoupsOf(pairs)} {
			for _, x := range list {
				table = append(table, uint16(x))
			}
		}
	}

	c.words16("gamma", table)

	c.bytes("m55", kemRepeatByte(0x55))

	c.bytes("m33", kemRepeatByte(0x33))

	c.bytes("m0f", kemRepeatByte(0x0f))

	c.splat32("m249", 0x249249)

	c.splat32("m1c71c7", 0x1c71c7)

	c.splat32("c0c30c3", 0x0c30c3)

	c.splat32("m3f", 0x3f)

	c.splat32("m3f0000", 0x3f0000)

	c.splat16("c1664", 1664)

	c.splat16("c1665", 1665)

	c.splat16("c832", 832)

	c.splat16("c2497", 2497)

	for _, d := range []int{4, 5, 10, 11} {
		c.splat16(fmt.Sprintf("mul%d", d), uint16((int(1)<<(15+d))/kemQ))

		c.splat16(fmt.Sprintf("mask%d", d), uint16(1<<d-1))
	}

	var bits []uint16

	for i := range 16 {
		bits = append(bits, 1<<i)
	}

	c.words16("bits", bits)

	for _, d := range []int{10, 11} {
		var madd []uint16

		var shifts []uint32

		for range 8 {
			madd = append(madd, 1, 1<<d)
		}

		for range 4 {
			shifts = append(shifts, uint32(32-2*d), 0)
		}

		c.words16(fmt.Sprintf("madd%d", d), madd)

		c.words32(fmt.Sprintf("sllv%d", d), shifts)
	}

	c.words32("sllvq11", []uint32{0, 0, 4, 0, 0, 0, 4, 0})

	c.bytes("shuf10", kemShuffleControl([]int{0, 1, 2, 3, 4, 8, 9, 10, 11, 12}, [2]int{}))

	c.bytes("shuf11a", kemShuffleControl([]int{0, 1, 2, 3, 4, 5}, [2]int{}))

	c.bytes("shuf11b", kemShuffleControl([]int{-1, -1, -1, -1, -1, 8, 9, 10, 11, 12, 13}, [2]int{}))

	var ub4, ub5 []byte

	for range 16 {
		ub4 = append(ub4, 1, 16)

		ub5 = append(ub5, 1, 32)
	}

	c.bytes("maddub4", ub4)

	c.bytes("maddub5", ub5)

	var madd5 []uint16

	var sllv5 []uint32

	for range 8 {
		madd5 = append(madd5, 1, 1024)
	}

	for range 4 {
		sllv5 = append(sllv5, 12, 0)
	}

	c.words16("madd5", madd5)

	c.words32("sllv5", sllv5)

	c.bytes("shuf5", kemShuffleControl([]int{0, 1, 2, 3, 4, 8, 9, 10, 11, 12}, [2]int{}))

	// Decompression: d = 10 left-aligns each 10-bit value at bit 15 by a multiplication, d = 11
	// shifts each 22-bit pair down by a lane-dependent count.
	c.words16("dmul10", []uint16{64, 16, 4, 1, 64, 16, 4, 1, 64, 16, 4, 1, 64, 16, 4, 1})

	c.splat16("m7fe0", 0x7fe0)

	c.words32("dsrlv11", []uint32{0, 6, 4, 2, 0, 6, 4, 2})

	c.splat32("m7ff07ff0", 0x7ff07ff0)

	c.words16("mmul5", []uint16{2048, 64, 512, 16, 128, 1024, 32, 256, 2048, 64, 512, 16, 128, 1024, 32, 256})

	c.splat16("m7c00", 0x7c00)

	var madd12 []uint16

	for range 8 {
		madd12 = append(madd12, 1, 4096)
	}

	c.words16("madd12", madd12)

	c.bytes("eshuf12", kemShuffleControl([]int{0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14}, [2]int{}))

	c.words32("eperm12", []uint32{0, 1, 2, 4, 5, 6, 7, 7})

	c.splat16("m0fff", 0x0fff)
}

func kemRepeatByte(v byte) []byte {
	b := make([]byte, 32)

	for i := range b {
		b[i] = v
	}

	return b
}

// The byte sources of 12-bit values: word 2i takes bytes 3i and 3i + 1, word 2i + 1 bytes 3i + 1 and
// 3i + 2.
func kemSources12() []int {
	var s []int

	for i := range 4 {
		s = append(s, 3*i, 3*i+1, 3*i+1, 3*i+2)
	}

	return s
}

// The byte sources of 10-bit values: word j takes the two bytes from floor(10 j / 8).
func kemSources10() []int {
	var s []int

	for j := range 8 {
		b := 10 * j / 8

		s = append(s, b, b+1)
	}

	return s
}

// The byte sources of 11-bit values in pairs: dword i takes the bytes from floor(22 i / 8) that its
// 22 bits reach, the rest zero.
func kemSources11() []int {
	var s []int

	for i := range 4 {
		first := 22 * i / 8

		last := (22*i + 21) / 8

		for b := first; b < first+4; b++ {
			if b <= last {
				s = append(s, b)
			} else {
				s = append(s, -1)
			}
		}
	}

	return s
}

// The byte sources of 5-bit values: word j takes the byte from floor(5 j / 8) and the next one when
// the value reaches into it.
func kemSources5() []int {
	var s []int

	for j := range 8 {
		b := 5 * j / 8

		if 5*j%8+5 > 8 {
			s = append(s, b, b+1)
		} else {
			s = append(s, b, -1)
		}
	}

	return s
}

// x = x mod q for x below 2q.
func kemReduceOnceX86(a *asm, x, q, t string) {
	a.op("VPSUBW\t%s, %s, %s", q, x, t)

	a.op("VPMINUW\t%s, %s, %s", t, x, x)
}

// v and its swapped twin from v at (DI) into (SI), with gamma's entry at (R8).
func kemPrepareKernel(a *asm, c *kemConstPool) {
	a.function("kemPrepareAVX2", "func kemPrepareAVX2(vectors, swapped *kemPoly, n int)", 24,
		"Pair i of each of the n vectors becomes (v0, v1 gamma_i mod q) by Shoup's multiplication, with",
		"1 in the even lanes, and the same pair of its swapped twin (v1, v0).")

	a.op("MOVQ\tvectors+0(FP), DI")

	a.op("MOVQ\tswapped+8(FP), SI")

	a.op("MOVQ\tn+16(FP), CX")

	a.op("LEAQ\tkemX86<>(SB), R13")

	a.op("VMOVDQU\t%s, Y15", c.at("q"))

	a.op("VMOVDQU\t%s, Y14", c.at("swap"))

	a.label("polynomial")

	a.op("LEAQ\t%s, R8", c.at("gamma"))

	a.op("MOVQ\t$16, DX")

	a.label("vector")

	a.op("VMOVDQU\t(DI), Y0")

	a.op("VPSHUFB\tY14, Y0, Y1")

	a.op("VMOVDQU\tY1, (SI)")

	a.op("VPMULLW\t(R8), Y0, Y2")

	a.op("VPMULHUW\t32(R8), Y0, Y3")

	a.op("VPMULLW\tY15, Y3, Y3")

	a.op("VPSUBW\tY3, Y2, Y2")

	kemReduceOnceX86(a, "Y2", "Y15", "Y3")

	a.op("VMOVDQU\tY2, (DI)")

	a.op("ADDQ\t$32, DI")

	a.op("ADDQ\t$32, SI")

	a.op("ADDQ\t$64, R8")

	a.op("DECQ\tDX")

	a.op("JNZ\tvector")

	a.op("DECQ\tCX")

	a.op("JNZ\tpolynomial")

	a.op("VZEROUPPER")

	a.op("RET")
}

// Registers: R8-R11 the factors, BX the vectors, DX their swapped twins, R12 add, DI out, AX the
// byte offset of the coefficients; Y15 q^-1 mod 2^16, Y14 q in the even words, Y9 q in the odd
// words, Y13 q, Y12 R^2 mod q, Y11 R^2 q^-1 mod 2^16, Y10 and Y8 the controls that move the low word
// of each doubleword up and the high word down.
func kemProductKernel(a *asm, c *kemConstPool) {
	a.function("kemProductAVX2", "func kemProductAVX2(out *kemPoly, factors *[4]*kemPoly, n int, vectors, swapped, add *kemPoly)", 48,
		"out = add + sum over j < n of factors[j] vectors[j] in the NTT domain, canonical, for prepared",
		"vectors (kemPrepareVectors) and canonical factors and add; n is 2, 3 or 4.")

	a.op("MOVQ\tout+0(FP), DI")

	a.op("MOVQ\tfactors+8(FP), SI")

	a.op("MOVQ\tn+16(FP), CX")

	a.op("MOVQ\tvectors+24(FP), BX")

	a.op("MOVQ\tswapped+32(FP), DX")

	a.op("MOVQ\tadd+40(FP), R12")

	a.op("LEAQ\tkemX86<>(SB), R13")

	for i, r := range []string{"R8", "R9", "R10", "R11"} {
		a.op("MOVQ\t%d(SI), %s", 8*i, r)
	}

	for _, k := range []struct{ key, reg string }{{"qinv16", "Y15"}, {"q32", "Y14"}, {"q32high", "Y9"}, {"q", "Y13"}, {"r2", "Y12"}, {"r2qinv", "Y11"}, {"lowup", "Y10"}, {"highdown", "Y8"}} {
		a.op("VMOVDQU\t%s, %s", c.at(k.key), k.reg)
	}

	a.op("XORQ\tAX, AX")

	a.op("CMPQ\tCX, $3")

	a.op("JEQ\tthree")

	a.op("JLT\ttwo")

	for _, n := range []int{4, 3, 2} {
		name := map[int]string{2: "two", 3: "three", 4: "four"}[n]

		a.label(name)

		kemProductLoop(a, n, name+"loop")

		a.op("VZEROUPPER")

		a.op("RET")
	}
}

func kemProductLoop(a *asm, n int, loop string) {
	factors := []string{"R8", "R9", "R10", "R11"}

	a.label(loop)

	a.op("VMOVDQU\t(R8)(AX*1), Y0")

	a.op("VPMADDWD\t(BX)(AX*1), Y0, Y1")

	a.op("VPMADDWD\t(DX)(AX*1), Y0, Y2")

	for j := 1; j < n; j++ {
		a.op("VMOVDQU\t(%s)(AX*1), Y0", factors[j])

		a.op("VPMADDWD\t%d(BX)(AX*1), Y0, Y3", 512*j)

		a.op("VPMADDWD\t%d(DX)(AX*1), Y0, Y4", 512*j)

		a.op("VPADDD\tY3, Y1, Y1")

		a.op("VPADDD\tY4, Y2, Y2")
	}

	a.comment("Montgomery reductions of the even and the odd 32-bit sums, t from both low words at once:",
		"the differences are multiples of 2^16, whose high words interleave to the reduced words.")

	a.op("VPSHUFB\tY10, Y2, Y3")

	a.op("VPBLENDW\t$0xaa, Y3, Y1, Y3")

	a.op("VPMULLW\tY15, Y3, Y3")

	a.op("VPMADDWD\tY14, Y3, Y4")

	a.op("VPMADDWD\tY9, Y3, Y3")

	a.op("VPSUBD\tY4, Y1, Y1")

	a.op("VPSUBD\tY3, Y2, Y2")

	a.op("VPSHUFB\tY8, Y1, Y1")

	a.op("VPBLENDW\t$0xaa, Y2, Y1, Y1")

	a.comment("Times R^2 by a Montgomery multiplication, in (-q, q), then canonical, plus add.")

	a.op("VPMULLW\tY11, Y1, Y3")

	a.op("VPMULHW\tY12, Y1, Y4")

	a.op("VPMULHW\tY13, Y3, Y3")

	a.op("VPSUBW\tY3, Y4, Y4")

	a.op("VPADDW\tY13, Y4, Y4")

	kemReduceOnceX86(a, "Y4", "Y13", "Y3")

	a.op("VPADDW\t(R12)(AX*1), Y4, Y4")

	kemReduceOnceX86(a, "Y4", "Y13", "Y3")

	a.op("VMOVDQU\tY4, (DI)(AX*1)")

	a.op("ADDQ\t$32, AX")

	a.op("CMPQ\tAX, $512")

	a.op("JNE\t%s", loop)
}

// x + (q - 3) reduced once, for x the CBD value plus 3, in [1, 5] or [0, 6].
func kemCBDCanonical(a *asm, x, qm3, q, t string) {
	a.op("VPADDW\t%s, %s, %s", qm3, x, x)

	kemReduceOnceX86(a, x, q, t)
}

// SamplePolyCBD_2 of 128 bytes, or of the first 128 bytes of a Keccak state for state.
func kemCBD2Kernel(a *asm, c *kemConstPool, state bool) {
	if state {
		a.function("kemCBD2StateAVX2", "func kemCBD2StateAVX2(f *kemPoly, state *[25]uint64)", 16,
			"kemCBD2AVX2 of the first 128 bytes of a Keccak state.")

		a.op("MOVQ\tf+0(FP), DI")

		a.op("MOVQ\tstate+8(FP), SI")
	} else {
		a.function("kemCBD2AVX2", "func kemCBD2AVX2(f *kemPoly, data *[128]byte)", 16,
			"SamplePolyCBD_2 (FIPS 203, Algorithm 8): per nibble the bit-pair sums a and b, a + 3 - b without",
			"a borrow, then minus 3 modulo q; 32 bytes make 64 coefficients.")

		a.op("MOVQ\tf+0(FP), DI")

		a.op("MOVQ\tdata+8(FP), SI")
	}

	a.op("LEAQ\tkemX86<>(SB), R13")

	for _, k := range []struct{ key, reg string }{{"m55", "Y15"}, {"m33", "Y14"}, {"m0f", "Y13"}, {"q", "Y12"}, {"qm3", "Y11"}} {
		a.op("VMOVDQU\t%s, %s", c.at(k.key), k.reg)
	}

	a.op("MOVQ\t$4, CX")

	a.label("loop")

	a.op("VMOVDQU\t(SI), Y0")

	a.op("VPSRLW\t$1, Y0, Y1")

	a.op("VPAND\tY15, Y0, Y0")

	a.op("VPAND\tY15, Y1, Y1")

	a.op("VPADDB\tY1, Y0, Y0")

	a.op("VPSRLW\t$2, Y0, Y1")

	a.op("VPAND\tY14, Y0, Y0")

	a.op("VPAND\tY14, Y1, Y1")

	a.op("VPADDB\tY14, Y0, Y0")

	a.op("VPSUBB\tY1, Y0, Y0")

	a.op("VPSRLW\t$4, Y0, Y1")

	a.op("VPAND\tY13, Y0, Y0")

	a.op("VPAND\tY13, Y1, Y1")

	a.comment("Bytes 0-7 and 16-23 make coefficients 0-15 and 32-47, bytes 8-15 and 24-31 the others.")

	a.op("VPUNPCKLBW\tY1, Y0, Y2")

	a.op("VPUNPCKHBW\tY1, Y0, Y3")

	a.op("VPMOVZXBW\tX2, Y4")

	a.op("VPMOVZXBW\tX3, Y5")

	a.op("VEXTRACTI128\t$1, Y2, X6")

	a.op("VEXTRACTI128\t$1, Y3, X7")

	a.op("VPMOVZXBW\tX6, Y6")

	a.op("VPMOVZXBW\tX7, Y7")

	for i, r := range []string{"Y4", "Y5", "Y6", "Y7"} {
		kemCBDCanonical(a, r, "Y11", "Y12", "Y8")

		a.op("VMOVDQU\t%s, %d(DI)", r, 32*i)
	}

	a.op("ADDQ\t$32, SI")

	a.op("ADDQ\t$128, DI")

	a.op("DECQ\tCX")

	a.op("JNZ\tloop")

	a.op("VZEROUPPER")

	a.op("RET")
}

func kemCBD3Kernel(a *asm, c *kemConstPool) {
	var cbd3 []int

	for i := range 4 {
		cbd3 = append(cbd3, 3*i, 3*i+1, 3*i+2, -1)
	}

	var plan []kemPackedVector

	for it := range 8 {
		w := kemWindowFor(24*it, 12, 12, 12, 192)

		key := kemControlKey("cbd3", w.offs)

		if _, ok := c.offset[key]; !ok {
			c.bytes(key, kemShuffleControl(cbd3, w.offs))
		}

		plan = append(plan, kemPackedVector{w, key})
	}

	a.function("kemCBD3AVX2", "func kemCBD3AVX2(f *kemPoly, data *[192]byte)", 16,
		"SamplePolyCBD_3 (FIPS 203, Algorithm 8): each three bytes in a doubleword, the bit-triple sums,",
		"then a + 3 - b per six-bit slot and the four slots spread to words; 24 bytes make 32 coefficients.")

	a.op("MOVQ\tf+0(FP), DI")

	a.op("MOVQ\tdata+8(FP), SI")

	a.op("LEAQ\tkemX86<>(SB), R13")

	for _, k := range []struct{ key, reg string }{{"m249", "Y15"}, {"m1c71c7", "Y14"}, {"c0c30c3", "Y13"}, {"m3f", "Y12"}, {"m3f0000", "Y11"}, {"qm3", "Y10"}, {"q", "Y9"}} {
		a.op("VMOVDQU\t%s, %s", c.at(k.key), k.reg)
	}

	for it, p := range plan {
		a.op("VMOVDQU\t%d(SI), Y0", p.w.load)

		a.op("VPERMQ\t$%#x, Y0, Y0", p.w.imm)

		a.op("VPSHUFB\t%s, Y0, Y0", c.at(p.key))

		a.op("VPSRLD\t$1, Y0, Y1")

		a.op("VPSRLD\t$2, Y0, Y2")

		a.op("VPAND\tY15, Y0, Y0")

		a.op("VPAND\tY15, Y1, Y1")

		a.op("VPAND\tY15, Y2, Y2")

		a.op("VPADDD\tY1, Y0, Y0")

		a.op("VPADDD\tY2, Y0, Y0")

		a.op("VPSRLD\t$3, Y0, Y1")

		a.op("VPAND\tY14, Y0, Y0")

		a.op("VPAND\tY14, Y1, Y1")

		a.op("VPADDD\tY13, Y0, Y0")

		a.op("VPSUBD\tY1, Y0, Y0")

		a.comment("Slots 0 and 1 to the words of P, slots 2 and 3 to those of Q.")

		a.op("VPAND\tY12, Y0, Y1")

		a.op("VPSLLD\t$10, Y0, Y2")

		a.op("VPAND\tY11, Y2, Y2")

		a.op("VPOR\tY2, Y1, Y1")

		a.op("VPSRLD\t$12, Y0, Y2")

		a.op("VPAND\tY12, Y2, Y2")

		a.op("VPSRLD\t$2, Y0, Y3")

		a.op("VPAND\tY11, Y3, Y3")

		a.op("VPOR\tY3, Y2, Y2")

		a.op("VPUNPCKLDQ\tY2, Y1, Y3")

		a.op("VPUNPCKHDQ\tY2, Y1, Y4")

		a.op("VPERM2I128\t$0x20, Y4, Y3, Y5")

		a.op("VPERM2I128\t$0x31, Y4, Y3, Y6")

		kemCBDCanonical(a, "Y5", "Y10", "Y9", "Y7")

		kemCBDCanonical(a, "Y6", "Y10", "Y9", "Y7")

		a.op("VMOVDQU\tY5, %d(DI)", 64*it)

		a.op("VMOVDQU\tY6, %d(DI)", 64*it+32)
	}

	a.op("VZEROUPPER")

	a.op("RET")
}

// Registers of compression: Y15 q, Y14 floor(2^(15 + d) / q), Y13 1664, Y12 q - 1, Y11 2^d - 1.
func kemCompressConstants(a *asm, c *kemConstPool, d int) {
	for _, k := range []struct{ key, reg string }{{"q", "Y15"}, {fmt.Sprintf("mul%d", d), "Y14"}, {"c1664", "Y13"}, {"qm1", "Y12"}, {fmt.Sprintf("mask%d", d), "Y11"}} {
		a.op("VMOVDQU\t%s, %s", c.at(k.key), k.reg)
	}
}

// Compress_d of the canonical x into x; t1 and t2 are temporaries.
func kemCompressValues(a *asm, d int, x, t1, t2 string) {
	a.op("VPMULHRSW\tY14, %s, %s", x, t1)

	a.op("VPSLLW\t$%d, %s, %s", d, x, t2)

	a.op("VPADDW\tY13, %s, %s", t2, t2)

	a.op("VPMULLW\tY15, %s, %s", t1, x)

	a.op("VPSUBW\t%s, %s, %s", x, t2, t2)

	a.op("VPCMPGTW\tY12, %s, %s", t2, t2)

	a.op("VPSUBW\t%s, %s, %s", t2, t1, x)

	a.op("VPAND\tY11, %s, %s", x, x)
}

// out (DI) = ByteEncode_d(Compress_d(u (SI) + e (DX))) for d = 10 or 11: the words to 2d-bit
// doublewords by VPMADDWD, to 4d-bit quadwords by shifts, then d bytes per lane by VPSHUFB, stored
// 16 bytes at a time; the last lane is stored exactly.
func kemCompressUKernel(a *asm, c *kemConstPool, d int) {
	name := fmt.Sprintf("kemCompress%dAVX2", d)

	a.function(name, fmt.Sprintf("func %s(out *[%d]byte, u, e *kemPoly)", name, 32*d), 24,
		fmt.Sprintf("ByteEncode_%d(Compress_%d(u + e)) for canonical u and e.", d, d))

	a.op("MOVQ\tout+0(FP), DI")

	a.op("MOVQ\tu+8(FP), SI")

	a.op("MOVQ\te+16(FP), DX")

	a.op("LEAQ\tkemX86<>(SB), R13")

	kemCompressConstants(a, c, d)

	a.op("VMOVDQU\t%s, Y10", c.at(fmt.Sprintf("madd%d", d)))

	a.op("VMOVDQU\t%s, Y9", c.at(fmt.Sprintf("sllv%d", d)))

	if d == 10 {
		a.op("VMOVDQU\t%s, Y8", c.at("shuf10"))
	} else {
		a.op("VMOVDQU\t%s, Y8", c.at("shuf11a"))

		a.op("VMOVDQU\t%s, Y7", c.at("shuf11b"))

		a.op("VMOVDQU\t%s, Y6", c.at("sllvq11"))
	}

	a.op("MOVQ\t$15, CX")

	body := func() {
		a.op("VMOVDQU\t(SI), Y0")

		a.op("VPADDW\t(DX), Y0, Y0")

		kemReduceOnceX86(a, "Y0", "Y15", "Y1")

		kemCompressValues(a, d, "Y0", "Y1", "Y2")

		a.op("VPMADDWD\tY10, Y0, Y0")

		a.op("VPSLLVD\tY9, Y0, Y0")

		a.op("VPSRLQ\t$%d, Y0, Y0", 32-2*d)

		if d == 10 {
			a.op("VPSHUFB\tY8, Y0, Y0")
		} else {
			a.op("VPSLLVQ\tY6, Y0, Y0")

			a.op("VPSHUFB\tY7, Y0, Y1")

			a.op("VPSHUFB\tY8, Y0, Y0")

			a.op("VPOR\tY1, Y0, Y0")
		}

		a.op("VEXTRACTI128\t$1, Y0, X1")
	}

	a.label("loop")

	body()

	a.op("VMOVDQU\tX0, (DI)")

	a.op("VMOVDQU\tX1, %d(DI)", d)

	a.op("ADDQ\t$32, SI")

	a.op("ADDQ\t$32, DX")

	a.op("ADDQ\t$%d, DI", 2*d)

	a.op("DECQ\tCX")

	a.op("JNZ\tloop")

	body()

	a.op("VMOVDQU\tX0, (DI)")

	a.op("VMOVQ\tX1, %d(DI)", d)

	a.op("VPEXTRW\t$4, X1, AX")

	a.op("MOVW\tAX, %d(DI)", d+8)

	if d == 11 {
		a.op("VPEXTRB\t$10, X1, AX")

		a.op("MOVB\tAX, %d(DI)", d+10)
	}

	a.op("VZEROUPPER")

	a.op("RET")
}

// out (DI) = ByteEncode_d(Compress_d(u (SI) + e (DX) + Decompress_1(m (R8)))) for d = 4 or 5, two
// registers of coefficients at a time: bytes by VPACKUSWB, then for d = 4 two per byte by
// VPMADDUBSW, for d = 5 eight per 40-bit quadword.
func kemCompressVKernel(a *asm, c *kemConstPool, d int) {
	name := fmt.Sprintf("kemCompress%dAVX2", d)

	a.function(name, fmt.Sprintf("func %s(out *[%d]byte, u, e *kemPoly, m *[32]byte)", name, 32*d), 32,
		fmt.Sprintf("ByteEncode_%d(Compress_%d(u + e + Decompress_1(m))) for canonical u and e; bit i of m", d, d),
		"adds 1665 to coefficient i.")

	a.op("MOVQ\tout+0(FP), DI")

	a.op("MOVQ\tu+8(FP), SI")

	a.op("MOVQ\te+16(FP), DX")

	a.op("MOVQ\tm+24(FP), R8")

	a.op("LEAQ\tkemX86<>(SB), R13")

	kemCompressConstants(a, c, d)

	a.op("VMOVDQU\t%s, Y10", c.at("bits"))

	a.op("VMOVDQU\t%s, Y9", c.at("c1665"))

	a.op("VMOVDQU\t%s, Y8", c.at(fmt.Sprintf("maddub%d", d)))

	if d == 5 {
		a.op("VMOVDQU\t%s, Y7", c.at("madd5"))

		a.op("VMOVDQU\t%s, Y6", c.at("sllv5"))

		a.op("VMOVDQU\t%s, Y5", c.at("shuf5"))
	}

	coefficients := func(off int, x string) {
		a.op("VMOVDQU\t%d(SI), %s", off, x)

		a.op("VPADDW\t%d(DX), %s, %s", off, x, x)

		kemReduceOnceX86(a, x, "Y15", "Y4")

		a.op("VPBROADCASTW\t%d(R8), Y4", off/16)

		a.op("VPAND\tY10, Y4, Y4")

		a.op("VPCMPEQW\tY10, Y4, Y4")

		a.op("VPAND\tY9, Y4, Y4")

		a.op("VPADDW\tY4, %s, %s", x, x)

		kemReduceOnceX86(a, x, "Y15", "Y4")

		kemCompressValues(a, d, x, "Y3", "Y4")
	}

	pair := func(off int) {
		coefficients(off, "Y0")

		coefficients(off+32, "Y1")

		a.op("VPACKUSWB\tY1, Y0, Y0")

		a.op("VPERMQ\t$0xd8, Y0, Y0")

		a.op("VPMADDUBSW\tY8, Y0, Y0")

		if d == 4 {
			a.op("VPACKUSWB\tY0, Y0, Y0")

			a.op("VPERMQ\t$0x08, Y0, Y0")

			return
		}

		a.op("VPMADDWD\tY7, Y0, Y0")

		a.op("VPSLLVD\tY6, Y0, Y0")

		a.op("VPSRLQ\t$12, Y0, Y0")

		a.op("VPSHUFB\tY5, Y0, Y0")

		a.op("VEXTRACTI128\t$1, Y0, X1")
	}

	if d == 4 {
		a.op("MOVQ\t$8, CX")
	} else {
		a.op("MOVQ\t$7, CX")
	}

	a.label("loop")

	pair(0)

	if d == 4 {
		a.op("VMOVDQU\tX0, (DI)")

		a.op("ADDQ\t$16, DI")
	} else {
		a.op("VMOVDQU\tX0, (DI)")

		a.op("VMOVDQU\tX1, 10(DI)")

		a.op("ADDQ\t$20, DI")
	}

	a.op("ADDQ\t$64, SI")

	a.op("ADDQ\t$64, DX")

	a.op("ADDQ\t$4, R8")

	a.op("DECQ\tCX")

	a.op("JNZ\tloop")

	if d == 5 {
		pair(0)

		a.op("VMOVDQU\tX0, (DI)")

		a.op("VMOVQ\tX1, 10(DI)")

		a.op("VPEXTRW\t$4, X1, AX")

		a.op("MOVW\tAX, 18(DI)")
	}

	a.op("VZEROUPPER")

	a.op("RET")
}

// u (DI) = Decompress_d(ByteDecode_d(in (SI))) for d = 10 or 11.
func kemDecompressKernel(a *asm, c *kemConstPool, d int) {
	name := fmt.Sprintf("kemDecompress%dAVX2", d)

	var plan []kemPackedVector

	if d == 10 {
		plan = kemPlanWindows(c, "dshuf10", 20, 10, 320, kemSources10())
	} else {
		plan = kemPlanWindows(c, "dshuf11", 22, 11, 352, kemSources11())
	}

	a.function(name, fmt.Sprintf("func %s(u *kemPoly, in *[%d]byte)", name, 32*d), 16,
		fmt.Sprintf("Decompress_%d(ByteDecode_%d(in)): each value moved to bits %d-14 of its word, then", d, d, 15-d),
		"VPMULHRSW by q.")

	a.op("MOVQ\tu+0(FP), DI")

	a.op("MOVQ\tin+8(FP), SI")

	a.op("LEAQ\tkemX86<>(SB), R13")

	a.op("VMOVDQU\t%s, Y15", c.at("q"))

	if d == 10 {
		a.op("VMOVDQU\t%s, Y14", c.at("dmul10"))

		a.op("VMOVDQU\t%s, Y13", c.at("m7fe0"))
	} else {
		a.op("VMOVDQU\t%s, Y14", c.at("dsrlv11"))

		a.op("VMOVDQU\t%s, Y13", c.at("m7ff07ff0"))
	}

	for v, p := range plan {
		a.op("VMOVDQU\t%d(SI), Y0", p.w.load)

		a.op("VPERMQ\t$%#x, Y0, Y0", p.w.imm)

		a.op("VPSHUFB\t%s, Y0, Y0", c.at(p.key))

		if d == 10 {
			a.op("VPMULLW\tY14, Y0, Y0")

			a.op("VPSRLW\t$1, Y0, Y0")

			a.op("VPAND\tY13, Y0, Y0")
		} else {
			a.op("VPSRLVD\tY14, Y0, Y0")

			a.op("VPSLLD\t$4, Y0, Y1")

			a.op("VPSLLD\t$9, Y0, Y0")

			a.op("VPBLENDW\t$0xaa, Y0, Y1, Y0")

			a.op("VPAND\tY13, Y0, Y0")
		}

		a.op("VPMULHRSW\tY15, Y0, Y0")

		a.op("VMOVDQU\tY0, %d(DI)", 32*v)
	}

	a.op("VZEROUPPER")

	a.op("RET")
}

// m (DI) = ByteEncode_1(Compress_1(Decompress_d(ByteDecode_d(in (SI))) - w (DX))) for d = 4 or 5.
// Compress_1(x) is 1 for 833 <= x <= 2496. For d = 5 each 16 bytes from 10 v (from 144 for the last
// register, which ends the buffer) are broadcast to both lanes, whose controls pick their halves.
func kemMessageKernel(a *asm, c *kemConstPool, d int) {
	name := fmt.Sprintf("kemMessage%dAVX2", d)

	a.function(name, fmt.Sprintf("func %s(m *[32]byte, in *[%d]byte, w *kemPoly)", name, 32*d), 24,
		fmt.Sprintf("ByteEncode_1(Compress_1(Decompress_%d(ByteDecode_%d(in)) - w)) for canonical w.", d, d))

	a.op("MOVQ\tm+0(FP), DI")

	a.op("MOVQ\tin+8(FP), SI")

	a.op("MOVQ\tw+16(FP), DX")

	a.op("LEAQ\tkemX86<>(SB), R13")

	for _, k := range []struct{ key, reg string }{{"q", "Y15"}, {"c832", "Y14"}, {"c2497", "Y13"}} {
		a.op("VMOVDQU\t%s, %s", c.at(k.key), k.reg)
	}

	var plan []kemPackedVector

	if d == 4 {
		a.op("VMOVDQU\t%s, Y12", c.at("m0f"))
	} else {
		for v := range 16 {
			load := min(10*v, 160-16)

			delta := 10*v - load

			offs := [2]int{delta, delta + 5}

			key := kemControlKey("mshuf5", offs)

			if _, ok := c.offset[key]; !ok {
				c.bytes(key, kemShuffleControl(kemSources5(), offs))
			}

			plan = append(plan, kemPackedVector{kemWindow{load: load, offs: offs}, key})
		}

		a.op("VMOVDQU\t%s, Y12", c.at("mmul5"))

		a.op("VMOVDQU\t%s, Y11", c.at("m7c00"))
	}

	// Decompressed, minus w, to the mask of Compress_1 in x.
	bit := func(v int, x string) {
		a.op("VPMULHRSW\tY15, %s, %s", x, x)

		a.op("VPSUBW\t%d(DX), %s, %s", 32*v, x, x)

		a.op("VPADDW\tY15, %s, %s", x, x)

		kemReduceOnceX86(a, x, "Y15", "Y4")

		a.op("VPCMPGTW\tY14, %s, Y4", x)

		a.op("VPCMPGTW\t%s, Y13, %s", x, x)

		a.op("VPAND\tY4, %s, %s", x, x)
	}

	for pair := range 8 {
		if d == 4 {
			a.op("VMOVDQU\t%d(SI), X0", 16*pair)

			a.op("VPSRLW\t$4, X0, X1")

			a.op("VPAND\tX12, X0, X0")

			a.op("VPAND\tX12, X1, X1")

			a.op("VPUNPCKLBW\tX1, X0, X2")

			a.op("VPUNPCKHBW\tX1, X0, X3")

			a.op("VPMOVZXBW\tX2, Y0")

			a.op("VPMOVZXBW\tX3, Y1")

			a.op("VPSLLW\t$11, Y0, Y0")

			a.op("VPSLLW\t$11, Y1, Y1")
		} else {
			for i, x := range []string{"Y0", "Y1"} {
				p := plan[2*pair+i]

				a.op("VBROADCASTI128\t%d(SI), Y5", p.w.load)

				a.op("VPSHUFB\t%s, Y5, %s", c.at(p.key), x)

				a.op("VPMULLW\tY12, %s, %s", x, x)

				a.op("VPSRLW\t$1, %s, %s", x, x)

				a.op("VPAND\tY11, %s, %s", x, x)
			}
		}

		bit(2*pair, "Y0")

		bit(2*pair+1, "Y1")

		a.op("VPACKSSWB\tY1, Y0, Y0")

		a.op("VPERMQ\t$0xd8, Y0, Y0")

		a.op("VPMOVMSKB\tY0, AX")

		a.op("MOVL\tAX, %d(DI)", 4*pair)
	}

	a.op("VZEROUPPER")

	a.op("RET")
}

// out (DI) = ByteEncode_12(f (SI)): pairs to 24-bit doublewords by VPMADDWD, three bytes of each by
// VPSHUFB, and the 24 bytes together by VPERMD.
func kemEncode12Kernel(a *asm, c *kemConstPool) {
	a.function("kemEncode12AVX2", "func kemEncode12AVX2(out *[384]byte, f *kemPoly)", 16,
		"ByteEncode_12 of canonical coefficients.")

	a.op("MOVQ\tout+0(FP), DI")

	a.op("MOVQ\tf+8(FP), SI")

	a.op("LEAQ\tkemX86<>(SB), R13")

	a.op("VMOVDQU\t%s, Y15", c.at("madd12"))

	a.op("VMOVDQU\t%s, Y14", c.at("eshuf12"))

	a.op("VMOVDQU\t%s, Y13", c.at("eperm12"))

	a.op("MOVQ\t$16, CX")

	a.label("loop")

	a.op("VMOVDQU\t(SI), Y0")

	a.op("VPMADDWD\tY15, Y0, Y0")

	a.op("VPSHUFB\tY14, Y0, Y0")

	a.op("VPERMD\tY0, Y13, Y0")

	a.op("VMOVDQU\tX0, (DI)")

	a.op("VEXTRACTI128\t$1, Y0, X1")

	a.op("VMOVQ\tX1, 16(DI)")

	a.op("ADDQ\t$32, SI")

	a.op("ADDQ\t$24, DI")

	a.op("DECQ\tCX")

	a.op("JNZ\tloop")

	a.op("VZEROUPPER")

	a.op("RET")
}

// ByteDecode_12 of in (SI): f (DI) reduced modulo q, or for check whether every value is below q.
func kemDecode12Kernel(a *asm, c *kemConstPool, check bool) {
	plan := kemPlanWindows(c, "d12shuf", 24, 12, 384, kemSources12())

	if check {
		a.function("kemCheck12AVX2", "func kemCheck12AVX2(in *[384]byte) bool", 9,
			"Whether every 12-bit value of ByteDecode_12(in) is below q (FIPS 203, 7.2).")

		a.op("MOVQ\tin+0(FP), SI")
	} else {
		a.function("kemDecode12AVX2", "func kemDecode12AVX2(f *kemPoly, in *[384]byte)", 16,
			"ByteDecode_12 reduced modulo q.")

		a.op("MOVQ\tf+0(FP), DI")

		a.op("MOVQ\tin+8(FP), SI")
	}

	a.op("LEAQ\tkemX86<>(SB), R13")

	a.op("VMOVDQU\t%s, Y15", c.at("q"))

	a.op("VMOVDQU\t%s, Y14", c.at("m0fff"))

	if check {
		a.op("VMOVDQU\t%s, Y13", c.at("qm1"))

		a.op("VPXOR\tY12, Y12, Y12")
	}

	for v, p := range plan {
		a.op("VMOVDQU\t%d(SI), Y0", p.w.load)

		a.op("VPERMQ\t$%#x, Y0, Y0", p.w.imm)

		a.op("VPSHUFB\t%s, Y0, Y0", c.at(p.key))

		a.op("VPSRLW\t$4, Y0, Y1")

		a.op("VPAND\tY14, Y0, Y0")

		a.op("VPBLENDW\t$0xaa, Y1, Y0, Y0")

		if check {
			a.op("VPCMPGTW\tY13, Y0, Y0")

			a.op("VPOR\tY0, Y12, Y12")

			continue
		}

		kemReduceOnceX86(a, "Y0", "Y15", "Y1")

		a.op("VMOVDQU\tY0, %d(DI)", 32*v)
	}

	if check {
		a.op("VPTEST\tY12, Y12")

		a.op("SETEQ\tret+8(FP)")
	}

	a.op("VZEROUPPER")

	a.op("RET")
}

// Appends the candidates below q of the 168 rate bytes of state (SI) to accepted (DI) from count
// (CX): sixteen 12-bit candidates per group of 24 bytes, compared with q, and each lane's accepted
// words gathered to its front by VPSHUFB with a control from a table indexed by the lane's mask
// (public data), stored at the count, which grows by the mask's population count.
func kemRejectKernel(a *asm, c *kemConstPool) {
	a.function("kemRejectAVX2", "func kemRejectAVX2(accepted *[kemRejectSize]uint16, count int, state *[25]uint64) int", 32,
		"SampleNTT's rejection (FIPS 203, Algorithm 7) of one squeezed block; stops after the group of",
		"sixteen that reaches 256 and returns the new count.")

	a.op("MOVQ\taccepted+0(FP), DI")

	a.op("MOVQ\tcount+8(FP), CX")

	a.op("MOVQ\tstate+16(FP), SI")

	a.op("LEAQ\tkemX86<>(SB), R13")

	a.op("LEAQ\tkemRejectTable<>(SB), R12")

	plan := kemWindowFor(0, 12, 12, 12, 200)

	a.op("VMOVDQU\t%s, Y15", c.at(kemControlKey("d12shuf", plan.offs)))

	a.op("VMOVDQU\t%s, Y14", c.at("m0fff"))

	a.op("VMOVDQU\t%s, Y13", c.at("q"))

	for g := range 7 {
		a.op("VMOVDQU\t%d(SI), Y0", 24*g)

		a.op("VPERMQ\t$%#x, Y0, Y0", plan.imm)

		a.op("VPSHUFB\tY15, Y0, Y0")

		a.op("VPSRLW\t$4, Y0, Y1")

		a.op("VPAND\tY14, Y0, Y0")

		a.op("VPBLENDW\t$0xaa, Y1, Y0, Y0")

		a.op("VPCMPGTW\tY0, Y13, Y1")

		a.op("VPACKSSWB\tY1, Y1, Y1")

		a.op("VPMOVMSKB\tY1, AX")

		a.op("MOVL\tAX, BX")

		a.op("ANDL\t$0xff, AX")

		a.op("SHRL\t$16, BX")

		a.op("ANDL\t$0xff, BX")

		a.op("MOVQ\tAX, R8")

		a.op("SHLQ\t$4, R8")

		a.op("VMOVDQU\t(R12)(R8*1), X2")

		a.op("VPSHUFB\tX2, X0, X3")

		a.op("VMOVDQU\tX3, (DI)(CX*2)")

		a.op("POPCNTL\tAX, AX")

		a.op("ADDQ\tAX, CX")

		a.op("VEXTRACTI128\t$1, Y0, X4")

		a.op("MOVQ\tBX, R9")

		a.op("SHLQ\t$4, R9")

		a.op("VMOVDQU\t(R12)(R9*1), X2")

		a.op("VPSHUFB\tX2, X4, X3")

		a.op("VMOVDQU\tX3, (DI)(CX*2)")

		a.op("POPCNTL\tBX, BX")

		a.op("ADDQ\tBX, CX")

		if g < 6 {
			a.op("CMPQ\tCX, $256")

			a.op("JGE\tdone")
		}
	}

	a.label("done")

	a.op("MOVQ\tCX, ret+24(FP)")

	a.op("VZEROUPPER")

	a.op("RET")
}

// Entry m gathers the words of the lanes whose bits are set in m to the front, in order.
func kemRejectTable(a *asm) {
	var b []byte

	for m := range 256 {
		var entry []byte

		for j := range 8 {
			if m>>j&1 == 1 {
				entry = append(entry, byte(2*j), byte(2*j+1))
			}
		}

		for len(entry) < 16 {
			entry = append(entry, 0x80)
		}

		b = append(b, entry...)
	}

	var words []uint64

	for i := 0; i < len(b); i += 8 {
		var w uint64

		for j := 7; j >= 0; j-- {
			w = w<<8 | uint64(b[i+j])
		}

		words = append(words, w)
	}

	a.table("kemRejectTable", 8, words)
}

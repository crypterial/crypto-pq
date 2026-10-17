package cryptopq

import (
	"encoding/binary"
	"math/bits"
	"sync"
)

// ML-DSA (FIPS 204). Coefficients stay in [0, q); products are reduced with a Barrett estimate
// from a 64x64-bit multiplication, and the functions on secret coefficients use masks instead of
// branches. Only the final accept or reject decision of the signing loop branches.

const (
	dsaQ = 8380417
	dsaD = 13

	// 2^32 mod q. Montgomery products carry the factor 2^-32, which a challenge with +-2^32 in
	// place of +-1 cancels (dsaChallengeOne).
	dsaMontR = 4193792
)

type mldsaParams struct {
	k, l, eta, tau, lambda, omega int
	gamma1, gamma2                uint32
}

var (
	mldsa44 = mldsaParams{k: 4, l: 4, eta: 2, tau: 39, lambda: 128, omega: 80, gamma1: 1 << 17, gamma2: (dsaQ - 1) / 88}
	mldsa65 = mldsaParams{k: 6, l: 5, eta: 4, tau: 49, lambda: 192, omega: 55, gamma1: 1 << 19, gamma2: (dsaQ - 1) / 32}
	mldsa87 = mldsaParams{k: 8, l: 7, eta: 2, tau: 60, lambda: 256, omega: 75, gamma1: 1 << 19, gamma2: (dsaQ - 1) / 32}
)

func (p *mldsaParams) beta() uint32 {
	return uint32(p.tau * p.eta)
}

func (p *mldsaParams) etaBits() int {
	return bits.Len(uint(2 * p.eta))
}

func (p *mldsaParams) gamma1Bits() int {
	return 1 + bits.Len32(p.gamma1-1)
}

func (p *mldsaParams) w1Bits() int {
	return bits.Len32((dsaQ-1)/(2*p.gamma2) - 1)
}

func (p *mldsaParams) publicKeySize() int {
	return 32 + 320*p.k
}

func (p *mldsaParams) privateKeySize() int {
	return 128 + 32*((p.k+p.l)*p.etaBits()+dsaD*p.k)
}

func (p *mldsaParams) signatureSize() int {
	return p.lambda/4 + 32*p.l*p.gamma1Bits() + p.omega + p.k
}

type dsaPoly [256]uint32

// The twiddle factors zeta = 1753^BitRev8(i) with their Shoup companions floor(zeta * 2^32 / q).
var dsaZetas, dsaShoup = func() (zetas, shoup [256]uint32) {
	for i := range zetas {
		zetas[i] = uint32(powMod(1753, uint64(bitReverse(i, 8)), dsaQ))

		shoup[i] = uint32((uint64(zetas[i]) << 32) / dsaQ)
	}

	return zetas, shoup
}()

// a < 2q: subtracts q when a >= q. A negative a - q wraps to at least 2^32 - q, setting bit 31.
func dsaReduceOnce(a uint32) uint32 {
	a -= dsaQ

	return a + dsaQ&-(a>>31)
}

// x mod q for any 64-bit x: the estimate x * floor(2^64 / q) / 2^64 is the quotient or one less.
func dsaReduce(x uint64) uint32 {
	quotient, _ := bits.Mul64(x, (1<<64)/dsaQ)

	return dsaReduceOnce(uint32(x - quotient*dsaQ))
}

// x mod q for any 32-bit x: q < 2^23, and x / 2^23 is below x / q by less than one.
func dsaReduce32(x uint32) uint32 {
	return dsaReduceOnce(x - (x>>23)*dsaQ)
}

// a * zeta mod q, or that plus q, for any 32-bit a, where shoup = floor(zeta * 2^32 / q): the
// quotient estimate a * shoup / 2^32 is exact or one too small (Shoup's modular multiplication).
func dsaMulShoup(a, zeta, shoup uint32) uint32 {
	return a*zeta - uint32((uint64(a)*uint64(shoup))>>32)*dsaQ
}

func dsaAdd(a, b uint32) uint32 {
	return dsaReduceOnce(a + b)
}

func dsaSub(a, b uint32) uint32 {
	return dsaReduceOnce(a - b + dsaQ)
}

func dsaMul(a, b uint32) uint32 {
	return dsaReduce(uint64(a) * uint64(b))
}

// v in (-q, q) as a field element.
func dsaFromSigned(v int32) uint32 {
	return uint32(v) + dsaQ&uint32(v>>31)
}

// The representative in (-(q-1)/2, (q-1)/2].
func dsaCentered(x uint32) int32 {
	return int32(x) - int32(dsaQ&-(((dsaQ-1)/2-x)>>31))
}

// 1 when the centered absolute value of x is at least bound (both below 2^31), otherwise 0.
func dsaAtLeast(x uint32, bound uint32) uint32 {
	v := dsaCentered(x)

	sign := v >> 31

	return (bound - 1 - uint32((v^sign)-sign)) >> 31
}

// NTT (FIPS 204, Algorithm 41) of canonical coefficients. A butterfly adds less than 2q to its
// outputs, so after eight layers they stay below 17q and one reduction at the end suffices. The
// layers go in pairs over groups of four coefficients held in locals, which halves the memory
// traffic; the last pair also reduces. This is the portable form of dsaNTT.
func dsaNTTGeneric(w *dsaPoly) {
	for length := 128; length >= 8; length /= 4 {
		half := length / 2

		for k := range 128 / length {
			block := w[2*length*k : 2*length*(k+1)]

			q0, q1, q2, q3 := block[:half], block[half:length], block[length:length+half], block[length+half:]

			_, _, _ = q1[len(q0)-1], q2[len(q0)-1], q3[len(q0)-1]

			zeta, shoup := dsaZetas[128/length+k], dsaShoup[128/length+k]

			zetaLow, shoupLow := dsaZetas[256/length+2*k], dsaShoup[256/length+2*k]

			zetaHigh, shoupHigh := dsaZetas[256/length+2*k+1], dsaShoup[256/length+2*k+1]

			for j, a0 := range q0 {
				a1, a2, a3 := q1[j], q2[j], q3[j]

				t0, t1 := dsaMulShoup(a2, zeta, shoup), dsaMulShoup(a3, zeta, shoup)

				a0, a1, a2, a3 = a0+t0, a1+t1, a0-t0+2*dsaQ, a1-t1+2*dsaQ

				t0, t1 = dsaMulShoup(a1, zetaLow, shoupLow), dsaMulShoup(a3, zetaHigh, shoupHigh)

				q0[j], q1[j], q2[j], q3[j] = a0+t0, a0-t0+2*dsaQ, a2+t1, a2-t1+2*dsaQ
			}
		}
	}

	for k := range 64 {
		f := (*[4]uint32)(w[4*k : 4*k+4])

		zeta, shoup := dsaZetas[64+k], dsaShoup[64+k]

		t0, t1 := dsaMulShoup(f[2], zeta, shoup), dsaMulShoup(f[3], zeta, shoup)

		a0, a1, a2, a3 := f[0]+t0, f[1]+t1, f[0]-t0+2*dsaQ, f[1]-t1+2*dsaQ

		t0, t1 = dsaMulShoup(a1, dsaZetas[128+2*k], dsaShoup[128+2*k]), dsaMulShoup(a3, dsaZetas[129+2*k], dsaShoup[129+2*k])

		f[0], f[1], f[2], f[3] = dsaReduce32(a0+t0), dsaReduce32(a0-t0+2*dsaQ), dsaReduce32(a2+t1), dsaReduce32(a2-t1+2*dsaQ)
	}
}

// The last layer of the inverse NTT multiplies by zeta_1 and then by 1/256; the factors are folded.
var dsaLastZeta = dsaMul(dsaZetas[1], 8347681)

// Inverse NTT (FIPS 204, Algorithm 42) of canonical coefficients, with zeta (w[j + len] - w[j]) in
// place of -zeta (w[j] - w[j + len]). The sums at most double per layer and stay below 256q < 2^32
// without reduction, while the differences, offset by a multiple of q to stay positive, are
// multiplied back below 2q. As in dsaNTTGeneric the layers go in pairs; the last pair also applies
// the factor 1/256 and reduces. This is the portable form of dsaInverseNTT.
func dsaInverseNTTGeneric(w *dsaPoly) {
	for k := range 64 {
		f := (*[4]uint32)(w[4*k : 4*k+4])

		a0, a1 := f[0]+f[1], dsaMulShoup(f[1]-f[0]+dsaQ, dsaZetas[255-2*k], dsaShoup[255-2*k])

		a2, a3 := f[2]+f[3], dsaMulShoup(f[3]-f[2]+dsaQ, dsaZetas[254-2*k], dsaShoup[254-2*k])

		zeta, shoup := dsaZetas[127-k], dsaShoup[127-k]

		f[0], f[1], f[2], f[3] = a0+a2, a1+a3, dsaMulShoup(a2-a0+2*dsaQ, zeta, shoup), dsaMulShoup(a3-a1+2*dsaQ, zeta, shoup)
	}

	offset := uint32(4 * dsaQ)

	for length := 8; length <= 32; length *= 4 {
		half := length / 2

		for k := range 128 / length {
			block := w[2*length*k : 2*length*(k+1)]

			q0, q1, q2, q3 := block[:half], block[half:length], block[length:length+half], block[length+half:]

			_, _, _ = q1[len(q0)-1], q2[len(q0)-1], q3[len(q0)-1]

			zetaLow, shoupLow := dsaZetas[512/length-1-2*k], dsaShoup[512/length-1-2*k]

			zetaHigh, shoupHigh := dsaZetas[512/length-2-2*k], dsaShoup[512/length-2-2*k]

			zeta, shoup := dsaZetas[256/length-1-k], dsaShoup[256/length-1-k]

			for j, a0 := range q0 {
				a1, a2, a3 := q1[j], q2[j], q3[j]

				a0, a1 = a0+a1, dsaMulShoup(a1-a0+offset, zetaLow, shoupLow)

				a2, a3 = a2+a3, dsaMulShoup(a3-a2+offset, zetaHigh, shoupHigh)

				q0[j], q1[j], q2[j], q3[j] = a0+a2, a1+a3, dsaMulShoup(a2-a0+2*offset, zeta, shoup), dsaMulShoup(a3-a1+2*offset, zeta, shoup)
			}
		}

		offset *= 4
	}

	q0, q1, q2, q3 := w[:64], w[64:128], w[128:192], w[192:]

	zeta, shoup := dsaLastZeta, uint32((uint64(dsaLastZeta)<<32)/dsaQ)

	for j, a0 := range q0 {
		a1, a2, a3 := q1[j], q2[j], q3[j]

		a0, a1 = a0+a1, dsaMulShoup(a1-a0+64*dsaQ, dsaZetas[3], dsaShoup[3])

		a2, a3 = a2+a3, dsaMulShoup(a3-a2+64*dsaQ, dsaZetas[2], dsaShoup[2])

		q0[j], q1[j] = dsaReduceOnce(dsaMulShoup(a0+a2, 8347681, (8347681<<32)/dsaQ)), dsaReduceOnce(dsaMulShoup(a1+a3, 8347681, (8347681<<32)/dsaQ))

		q2[j], q3[j] = dsaReduceOnce(dsaMulShoup(a2-a0+128*dsaQ, zeta, shoup)), dsaReduceOnce(dsaMulShoup(a3-a1+128*dsaQ, zeta, shoup))
	}
}

// out = sum of a[j] * b[j] in the NTT domain; at most eight products stay far below 2^64.
func dsaDot(out *dsaPoly, a, b []dsaPoly) {
	for x := range out {
		var sum uint64

		for j := range a {
			sum += uint64(a[j][x]) * uint64(b[j][x])
		}

		out[x] = dsaReduce(sum)
	}
}

func dsaPointwise(out, a, b *dsaPoly) {
	for x := range out {
		out[x] = dsaMul(a[x], b[x])
	}
}

// The products of the scheme, each ending in the inverse NTT; the kernels compute the same values
// another way (dsa_amd64.go). This is the portable form of dsaRowProduct: NTT^-1 of the sum of
// a[j] b[j], a row of the matrix times a vector, both in the NTT domain.
func dsaRowProductGeneric(out *dsaPoly, a, b []dsaPoly) {
	dsaDot(out, a, b)

	dsaInverseNTT(out)
}

// The portable form of dsaRowProductSub: NTT^-1(sum of a[j] b[j] - c t), verification's row.
func dsaRowProductSubGeneric(out *dsaPoly, a, b []dsaPoly, c, t *dsaPoly) {
	var product dsaPoly

	dsaDot(out, a, b)

	dsaPointwise(&product, c, t)

	for x := range out {
		out[x] = dsaSub(out[x], product[x])
	}

	dsaInverseNTT(out)
}

// The portable form of dsaProduct: NTT^-1(c s + y), y being nil for NTT^-1(c s); out may be y. c
// is the challenge scaled by dsaChallengeOne.
func dsaProductGeneric(out, c, s, y *dsaPoly) {
	if y == nil {
		dsaPointwise(out, c, s)
	} else {
		for x := range out {
			out[x] = dsaAdd(dsaMul(c[x], s[x]), y[x])
		}
	}

	dsaInverseNTT(out)
}

// The portable form of dsaBeyond: 1 when the centered absolute value of some coefficient of w is
// at least bound, otherwise 0.
func dsaBeyondGeneric(w *dsaPoly, bound uint32) uint32 {
	var beyond uint32

	for _, x := range w {
		beyond |= dsaAtLeast(x, bound)
	}

	return beyond
}

// The portable form of dsaSubLow: w = w - p, and 1 when the centered low bits of some new
// coefficient (Decompose's r0) are at least bound in absolute value, otherwise 0.
func dsaSubLowGeneric(w, p *dsaPoly, gamma2, bound uint32) uint32 {
	var beyond uint32

	for x := range w {
		w[x] = dsaSub(w[x], p[x])

		_, r0 := dsaDecompose(w[x], gamma2)

		beyond |= dsaAtLeast(dsaFromSigned(r0), bound)
	}

	return beyond
}

// The portable form of dsaHints for the vector w - c s2 and p = c t0: beyond is 1 when the
// centered c t0 reaches gamma2 somewhere; bit x of hints is MakeHint(-p, w + p), and count their
// sum.
func dsaHintsGeneric(hints *[4]uint64, w, p *dsaPoly, gamma2 uint32) (beyond, count uint32) {
	*hints = [4]uint64{}

	for x := range w {
		beyond |= dsaAtLeast(p[x], gamma2)

		hint := dsaMakeHint(dsaSub(0, p[x]), dsaAdd(w[x], p[x]), gamma2)

		hints[x/64] |= uint64(hint) << (x % 64)

		count += hint
	}

	return beyond, count
}

// The portable form of dsaHighBits: w1Encode of the high bits of w, width bits each.
func dsaHighBitsGeneric(out []byte, w *dsaPoly, gamma2 uint32, width int) {
	var high [256]uint32

	for x := range high {
		r1, _ := dsaDecompose(w[x], gamma2)

		high[x] = uint32(r1)
	}

	packBits(out, high[:], width)
}

// The portable form of dsaUseHints: w = UseHint(hints, w) with the hints as bits, then its
// w1Encode, width bits each.
func dsaUseHintsGeneric(out []byte, w *dsaPoly, hints *[4]uint64, gamma2 uint32, width int) {
	m := int32((dsaQ - 1) / (2 * gamma2))

	for x := range w {
		w[x] = dsaUseHint(uint32(hints[x/64]>>(x%64)&1), w[x], gamma2, m)
	}

	packBits(out, w[:], width)
}

// BitPack (FIPS 204, Algorithm 17): stores b - w for coefficients w in [-a, b].
func dsaPack(out []byte, w *dsaPoly, b uint32, width int) {
	var values [256]uint32

	for i, x := range w {
		values[i] = uint32(int32(b) - dsaCentered(x))
	}

	packBits(out, values[:], width)

	clear(values[:])
}

// The portable form of dsaUnpackT1: t1 2^d from the 10-bit values at in (pkDecode).
func dsaUnpackT1Generic(w *dsaPoly, in []byte) {
	unpackBits(w[:], in[:320], 10)

	for x := range w {
		w[x] <<= dsaD
	}
}

// The portable form of dsaPower2RoundPack: Power2Round of t, t1 packed with 10 bits (pkEncode)
// into t1 and t0 as skEncode packs it (BitPack with b = 2^12, 13 bits) into t0.
func dsaPower2RoundPackGeneric(t1, t0 []byte, t *dsaPoly) {
	var high, low dsaPoly

	for x := range t {
		r1, r0 := dsaPower2Round(t[x])

		high[x], low[x] = r1, dsaFromSigned(r0)
	}

	packBits(t1, high[:], 10)

	dsaPack(t0, &low, 1<<(dsaD-1), dsaD)

	clear(low[:])
}

func dsaUnpack(w *dsaPoly, in []byte, b uint32, width int) {
	unpackBits(w[:], in[:32*width], width)

	for i, x := range w {
		w[i] = dsaFromSigned(int32(b) - int32(x))
	}
}

// The most entries sampled together: a row of the ML-DSA-87 matrix, and a group of secret vectors.
const dsaRowLanes, dsaBoundedLanes = 8, 4

// RejNTTPoly's candidates, three bytes each, from block appended to f from count on while it is
// below 256; returns the new count. The data is public.
func dsaRejUniformGeneric(f *dsaPoly, count int, block []byte) int {
	for rest := block; len(rest) >= 3 && count < 256; rest = rest[3:] {
		z := uint32(rest[0]) | uint32(rest[1])<<8 | uint32(rest[2]&0x7f)<<16

		if z < dsaQ {
			f[count] = z

			count++
		}
	}

	return count
}

// The portable form of dsaRejUniformLane: dsaRejUniformGeneric of the 168 rate bytes of a SHAKE128
// state.
func dsaRejUniformLaneGeneric(f *dsaPoly, count int, state *[25]uint64) int {
	var block [168]byte

	for i, lane := range state[:21] {
		binary.LittleEndian.PutUint64(block[8*i:], lane)
	}

	return dsaRejUniformGeneric(f, count, block[:])
}

// RejNTTPoly (FIPS 204, Algorithm 30) of one entry, as dsaSampleUniforms does many.
func dsaSampleUniform(f *dsaPoly, rho []byte, s, r byte) {
	sponge := keccak{rate: 168, suffix: 0x1f}

	sponge.update(rho)

	sponge.update([]byte{s, r})

	var block [168]byte

	count := 0

	for count < 256 {
		sponge.read(block[:])

		count = dsaRejUniformGeneric(f, count, block[:])
	}
}

// RejBoundedPoly (FIPS 204, Algorithm 31) of one seed, as dsaSampleBoundeds does many.
func dsaSampleBounded(f *dsaPoly, seed []byte, eta int) {
	sponge := keccak{rate: 136, suffix: 0x1f}

	sponge.update(seed)

	var block [136]byte

	var accepted [257]uint32

	count := 0

	for count < 256 {
		sponge.read(block[:])

		for _, b := range block {
			if count >= 256 {
				break
			}

			low, high := uint32(b)&15, uint32(b)>>4

			if eta == 2 {
				accepted[count] = dsaFromSigned(2 - int32(low-5*((low*205)>>10)))

				count += int((low - 15) >> 31)

				accepted[count] = dsaFromSigned(2 - int32(high-5*((high*205)>>10)))

				count += int((high - 15) >> 31)
			} else {
				accepted[count] = dsaFromSigned(4 - int32(low))

				count += int((low - 9) >> 31)

				accepted[count] = dsaFromSigned(4 - int32(high))

				count += int((high - 9) >> 31)
			}
		}
	}

	copy(f[:], accepted[:256])

	clear(block[:])

	clear(accepted[:])

	clear(sponge.state[:])
}

// RejNTTPoly (FIPS 204, Algorithm 30) of rho || s || r for the entries (s, r) given as s + 256 r, all
// at once where the lane kernels are fast, over public data.
func dsaSampleUniforms(polys []*dsaPoly, rho []byte, positions []uint16) {
	if !permuteLanesFast() {
		for l, f := range polys {
			dsaSampleUniform(f, rho, byte(positions[l]), byte(positions[l]>>8))
		}

		return
	}

	var sponges keccakLanes

	sponges.start(168, rho, positions, 2)

	var counts [dsaRowLanes]int

	for remaining := len(polys); remaining > 0; {
		sponges.squeeze()

		for l, f := range polys {
			count := counts[l]

			if count >= 256 {
				continue
			}

			count = dsaRejUniformLane(f, count, &sponges.states[l])

			counts[l] = count

			if count >= 256 {
				remaining--
			}
		}
	}
}

// Row r of the matrix: A[r][s] = RejNTTPoly(rho || s || r) for every s.
func dsaSampleRow(row []*dsaPoly, rho []byte, r int) {
	var positions [dsaRowLanes]uint16

	for s := range row {
		positions[s] = uint16(s) | uint16(r)<<8
	}

	dsaSampleUniforms(row, rho, positions[:len(row)])
}

// RejBoundedPoly (FIPS 204, Algorithm 31) of rho' || r for r = first, first + 1, ..., one per
// polynomial, all at once where the lane kernels are fast. Each candidate is stored and then kept
// or overwritten by advancing the count or not, so that no branch depends on a secret nibble; the
// kept value is computed without division (half mod 5 by a multiply-shift). The slot after the last
// one absorbs a candidate beyond the 256th.
func dsaSampleBoundeds(polys []*dsaPoly, rhoPrime []byte, first, eta int) {
	if !permuteLanesFast() {
		var seed [66]byte

		copy(seed[:], rhoPrime)

		for l, f := range polys {
			binary.LittleEndian.PutUint16(seed[64:], uint16(first+l))

			dsaSampleBounded(f, seed[:], eta)
		}

		clear(seed[:])

		return
	}

	var nonces [dsaBoundedLanes]uint16

	for l := range polys {
		nonces[l] = uint16(first + l)
	}

	var sponges keccakLanes

	sponges.start(136, rhoPrime, nonces[:len(polys)], 2)

	var block [136]byte

	var accepted [dsaBoundedLanes][257]uint32

	var counts [dsaBoundedLanes]int

	for remaining := len(polys); remaining > 0; {
		sponges.squeeze()

		for l, f := range polys {
			count := counts[l]

			if count >= 256 {
				continue
			}

			sponges.read(l, block[:])

			for _, b := range block {
				if count >= 256 {
					break
				}

				low, high := uint32(b)&15, uint32(b)>>4

				if eta == 2 {
					accepted[l][count] = dsaFromSigned(2 - int32(low-5*((low*205)>>10)))

					count += int((low - 15) >> 31)

					accepted[l][count] = dsaFromSigned(2 - int32(high-5*((high*205)>>10)))

					count += int((high - 15) >> 31)
				} else {
					accepted[l][count] = dsaFromSigned(4 - int32(low))

					count += int((low - 9) >> 31)

					accepted[l][count] = dsaFromSigned(4 - int32(high))

					count += int((high - 9) >> 31)
				}
			}

			counts[l] = count

			if count >= 256 {
				copy(f[:], accepted[l][:256])

				remaining--
			}
		}
	}

	clear(block[:])

	clear(accepted[:])

	sponges.wipe()
}

// Entry r * l + s is A[r][s] = RejNTTPoly(rho || s || r).
func dsaExpandA(a []dsaPoly, rho []byte, p *mldsaParams) {
	var row [dsaRowLanes]*dsaPoly

	for r := range p.k {
		for s := range p.l {
			row[s] = &a[r*p.l+s]
		}

		dsaSampleRow(row[:p.l], rho, r)
	}
}

// ExpandS (FIPS 204, Algorithm 33) into s1 and s2, which may lie apart; groups of four keep the
// sampling buffers of dsaSampleBoundeds small.
func dsaExpandS(s1, s2 []dsaPoly, rhoPrime []byte, p *mldsaParams) {
	var group [dsaBoundedLanes]*dsaPoly

	total := len(s1) + len(s2)

	for first := 0; first < total; first += dsaBoundedLanes {
		count := min(dsaBoundedLanes, total-first)

		for l := range count {
			if i := first + l; i < len(s1) {
				group[l] = &s1[i]
			} else {
				group[l] = &s2[i-len(s1)]
			}
		}

		dsaSampleBoundeds(group[:count], rhoPrime, first, p.eta)
	}
}

// The SHAKE256 output of each y[r], kept by the caller for the sparse products (dsaSparse): five
// blocks of 136 bytes, more than the 640 bytes that the largest gamma1 takes.
type dsaMaskStreams [dsaMaxL][680]byte

// ExpandMask (FIPS 204, Algorithm 34): y[r] from SHAKE256(rho' || kappa + r), all at once where the
// lane kernels are fast. streams receives the packed form of each y[r]; the caller wipes it.
func dsaExpandMask(y []dsaPoly, streams *dsaMaskStreams, rhoPrime []byte, kappa int, p *mldsaParams) {
	width := p.gamma1Bits()

	if !permuteLanesFast() {
		var nonce [2]byte

		for r := range y {
			binary.LittleEndian.PutUint16(nonce[:], uint16(kappa+r))

			shake256Sum(streams[r][:32*width], rhoPrime, nonce[:])

			dsaUnpackGamma1(&y[r], streams[r][:], p.gamma1, width)
		}

		return
	}

	var nonces [dsaRowLanes]uint16

	for r := range y {
		nonces[r] = uint16(kappa + r)
	}

	var sponges keccakLanes

	sponges.start(136, rhoPrime, nonces[:len(y)], 2)

	for offset := 0; offset < 32*width; offset += 136 {
		sponges.squeeze()

		for r := range y {
			sponges.read(r, streams[r][offset:])
		}
	}

	for r := range y {
		dsaUnpackGamma1(&y[r], streams[r][:], p.gamma1, width)
	}

	sponges.wipe()
}

// SampleInBall (FIPS 204, Algorithm 29) from the commitment hash, which the signature reveals; the
// stream is read a block at a time.
func dsaSampleInBall(c *dsaPoly, seed []byte, tau int) {
	sponge := keccak{rate: 136, suffix: 0x1f}

	sponge.update(seed)

	var block [136]byte

	sponge.read(block[:])

	signs := binary.LittleEndian.Uint64(block[:8])

	position := 8

	clear(c[:])

	for i := 256 - tau; i < 256; i++ {
		var j int

		for {
			if position == len(block) {
				sponge.read(block[:])

				position = 0
			}

			j = int(block[position])

			position++

			if j <= i {
				break
			}
		}

		c[i] = c[j]

		c[j] = dsaFromSigned(1 - 2*int32(signs&1))

		signs >>= 1
	}
}

// The challenge's coefficients +-1 become +-one, so that its products can absorb a constant
// factor (dsaChallengeOne).
func dsaScaleChallenge(c *dsaPoly, one uint32) {
	if one == 1 {
		return
	}

	for x, v := range c {
		c[x] = one&-(v&1) | (dsaQ-one)&-(v>>22&1)
	}
}

// The challenge as the starts of the windows of the extended secret [-s, s] whose signed sum is c s
// (dsaSparseProductGeneric): a coefficient +-1 at x adds +-s shifted by x, which is the window at
// 256 - x. The positions are public but the signs of a rejected attempt are not, so a sign only
// sets bit 15 of its start, which the products apply with masks, never with an address. Returns
// the number of windows, tau.
func dsaChallengeStarts(starts *[64]uint16, c *dsaPoly) int {
	n := 0

	for x, v := range c {
		starts[n] = uint16(256-x) | uint16(v>>22&1)<<15

		n += int(v&1 | v>>22&1)
	}

	return n
}

// The small secret polynomial packed at in (BitPack with b = eta, 3 or 4 bits) as [-s, s].
func dsaExtendGeneric(ext *[512]int16, in []byte, eta int) {
	var raw [256]uint32

	width := 4

	if eta == 2 {
		width = 3
	}

	unpackBits(raw[:], in[:32*width], width)

	for x, v := range raw {
		s := int16(eta) - int16(v)

		ext[x], ext[256+x] = -s, s
	}

	clear(raw[:])
}

// The portable form of dsaSparseProduct: d = c s as small integers, for the challenge given by its
// window starts and the secret polynomial packed at in. A negative window is xored with all ones,
// -w - 1, and the count of those adds the ones back.
func dsaSparseProductGeneric(d *[256]int16, starts *[64]uint16, n int, in []byte, eta int) {
	var ext [512]int16

	dsaExtendGeneric(&ext, in, eta)

	clear(d[:])

	var negative int16

	for _, start := range starts[:n] {
		window := ext[start&0x1ff : int(start&0x1ff)+256]

		mask := -int16(start >> 15)

		for x := range d {
			d[x] += window[x] ^ mask
		}

		negative -= mask
	}

	for x := range d {
		d[x] += negative
	}

	clear(ext[:])
}

// The portable form of dsaUnpackAdd: z = y + d for y unpacked from in, and 1 when the centered
// absolute value of some coefficient of z is at least bound, otherwise 0.
func dsaUnpackAddGeneric(z *dsaPoly, in []byte, d *[256]int16, gamma1 uint32, width int, bound uint32) uint32 {
	dsaUnpack(z, in, gamma1, width)

	for x := range z {
		z[x] = dsaAdd(z[x], dsaFromSigned(int32(d[x])))
	}

	return dsaBeyondGeneric(z, bound)
}

// The portable form of dsaSubSmallLow: dsaSubLow with the small integers d.
func dsaSubSmallLowGeneric(w *dsaPoly, d *[256]int16, gamma2, bound uint32) uint32 {
	var p dsaPoly

	for x := range p {
		p[x] = dsaFromSigned(int32(d[x]))
	}

	beyond := dsaSubLowGeneric(w, &p, gamma2, bound)

	clear(p[:])

	return beyond
}

// Power2Round (FIPS 204, Algorithm 35) for r in [0, q).
func dsaPower2Round(r uint32) (r1 uint32, r0 int32) {
	low := int32(r & (1<<dsaD - 1))

	low -= (1 << dsaD) & ((1<<(dsaD-1) - low) >> 31)

	return uint32((int32(r) - low) >> dsaD), low
}

// Decompose (FIPS 204, Algorithm 36) for r in [0, q), as in the reference implementation: r1 =
// round(r / 2 gamma2) comes from a multiply-shift fitted to each gamma2, with the value
// (q - 1) / 2 gamma2 wrapped to 0, and r0 = r - 2 gamma2 r1 is then centered modulo q, which turns
// the wrapped case into the r0 - 1 the standard prescribes.
func dsaDecompose(r, gamma2 uint32) (r1, r0 int32) {
	r1 = (int32(r) + 127) >> 7

	if gamma2 == (dsaQ-1)/32 {
		r1 = (r1*1025 + 1<<21) >> 22 & 15
	} else {
		r1 = (r1*11275 + 1<<23) >> 24

		r1 ^= (43 - r1) >> 31 & r1
	}

	r0 = int32(r) - r1*2*int32(gamma2)

	r0 -= ((dsaQ-1)/2 - r0) >> 31 & dsaQ

	return r1, r0
}

// MakeHint (FIPS 204, Algorithm 39) as 1 when the high bits of r and r + z differ.
func dsaMakeHint(z, r, gamma2 uint32) uint32 {
	a, _ := dsaDecompose(r, gamma2)

	b, _ := dsaDecompose(dsaAdd(r, z), gamma2)

	difference := uint32(a ^ b)

	return (difference | -difference) >> 31
}

// UseHint (FIPS 204, Algorithm 40) with m = (q - 1) / 2 gamma2; verification works on public data
// only.
func dsaUseHint(h, r, gamma2 uint32, m int32) uint32 {
	r1, r0 := dsaDecompose(r, gamma2)

	switch {
	case h == 0:
		return uint32(r1)
	case r0 > 0 && r1 == m-1:
		return 0
	case r0 > 0:
		return uint32(r1 + 1)
	case r1 == 0:
		return uint32(m - 1)
	default:
		return uint32(r1 - 1)
	}
}

// t = NTT^-1(A * NTT(s1)) + s2 for t holding s2, with each row of A sampled just before its
// products are added.
func dsaPublicT(t []dsaPoly, rho []byte, s1Hat []dsaPoly) {
	var a [dsaMaxL]dsaPoly

	var row [dsaMaxL]*dsaPoly

	for j := range s1Hat {
		row[j] = &a[j]
	}

	var product dsaPoly

	for i := range t {
		dsaSampleRow(row[:len(s1Hat)], rho, i)

		dsaRowProduct(&product, a[:len(s1Hat)], s1Hat)

		for x := range t[i] {
			t[i][x] = dsaAdd(product[x], t[i][x])
		}
	}

	clear(product[:])
}

// What verification and signing derive from a public key, kept by the key: tr = H(pk, 64), set when
// the key is made, and computed on first use Â in the NTT domain and t̂1 = NTT(t1 2^d), which only
// verification reads. A private key shares it with the public keys it returns.
type dsaPublic struct {
	tr     [64]byte
	once   sync.Once
	a      []dsaPoly
	t1Once sync.Once
	t1     []dsaPoly
}

func newDsaPublic(tr []byte) *dsaPublic {
	c := &dsaPublic{}

	copy(c.tr[:], tr)

	return c
}

func (c *dsaPublic) matrix(p *mldsaParams, rho []byte) []dsaPoly {
	c.once.Do(func() {
		c.a = make([]dsaPoly, p.k*p.l)

		dsaExpandA(c.a, rho, p)
	})

	return c.a
}

func (c *dsaPublic) t1Hat(p *mldsaParams, pk []byte) []dsaPoly {
	c.t1Once.Do(func() {
		t1 := make([]dsaPoly, p.k)

		for i := range t1 {
			dsaUnpackT1(&t1[i], pk[32+320*i:])

			dsaNTT(&t1[i])
		}

		c.t1 = t1
	})

	return c.t1
}

// t̂0 of a private key, after ŝ1 and ŝ2 unless signing takes s1 and s2 from the key bytes
// (dsaSparse), in one slice: decoded on first use and wiped with the key.
type dsaSecrets struct {
	once  sync.Once
	polys []dsaPoly
}

func (c *dsaSecrets) get(p *mldsaParams, sk []byte) []dsaPoly {
	c.once.Do(func() {
		// Signing with sparse products reads s1 and s2 from the key itself.
		if dsaSparse() {
			t0 := make([]dsaPoly, p.k)

			offset := 128 + 32*(p.l+p.k)*p.etaBits()

			for i := range t0 {
				dsaUnpack(&t0[i], sk[offset:], 1<<(dsaD-1), dsaD)

				dsaNTT(&t0[i])

				offset += 32 * dsaD
			}

			c.polys = t0

			return
		}

		polys := make([]dsaPoly, p.l+2*p.k)

		dsaDecodePrivateKey(polys[:p.l+p.k], polys[p.l+p.k:], sk, p)

		for i := range polys {
			dsaNTT(&polys[i])
		}

		c.polys = polys
	})

	return c.polys
}

func dsaEncodePublicKey(rho []byte, t []dsaPoly, p *mldsaParams) []byte {
	pk := make([]byte, p.publicKeySize())

	copy(pk, rho)

	var t1 [256]uint32

	for i := range t {
		for x := range t1 {
			t1[x], _ = dsaPower2Round(t[i][x])
		}

		packBits(pk[32+320*i:], t1[:], 10)
	}

	return pk
}

// The vectors below have the largest parameter set's capacity, so that they live on the stack.
const dsaMaxK, dsaMaxL = 8, 7

func mldsaKeyGen(p *mldsaParams, xi []byte) (pk, sk []byte) {
	var expanded [128]byte

	shake256Sum(expanded[:], xi, []byte{byte(p.k), byte(p.l)})

	rho, rhoPrime, key := expanded[:32], expanded[32:96], expanded[96:]

	// s2 goes where t is computed, which adds it.
	s1, t := make([]dsaPoly, p.l, dsaMaxL), make([]dsaPoly, p.k, dsaMaxK)

	dsaExpandS(s1, t, rhoPrime, p)

	pk, sk = make([]byte, p.publicKeySize()), make([]byte, p.privateKeySize())

	copy(pk, rho)

	copy(sk, rho)

	copy(sk[32:], key)

	width := p.etaBits()

	offset := 128

	for _, part := range [][]dsaPoly{s1, t} {
		for i := range part {
			dsaPackEta(sk[offset:], &part[i], p.eta, width)

			offset += 32 * width
		}
	}

	// Once packed, s1 makes way for NTT(s1).
	for i := range s1 {
		dsaNTT(&s1[i])
	}

	dsaPublicT(t, rho, s1)

	for i := range t {
		dsaPower2RoundPack(pk[32+320*i:], sk[offset+32*dsaD*i:], &t[i])
	}

	shake256Sum(sk[64:128], pk)

	clear(expanded[:])

	clear(s1)

	clear(t)

	return pk, sk
}

// s1 and s2 in one slice, then t0; out of range is 1 when an s coefficient lies outside
// [-eta, eta], which only a malformed key can contain.
func dsaDecodePrivateKey(s, t0 []dsaPoly, sk []byte, p *mldsaParams) (outOfRange uint32) {
	width := p.etaBits()

	offset := 128

	var raw [256]uint32

	for i := range s {
		unpackBits(raw[:], sk[offset:offset+32*width], width)

		for x, value := range raw {
			outOfRange |= (uint32(2*p.eta) - value) >> 31

			s[i][x] = dsaFromSigned(int32(p.eta) - int32(value))
		}

		offset += 32 * width
	}

	for i := range t0 {
		dsaUnpack(&t0[i], sk[offset:], 1<<(dsaD-1), dsaD)

		offset += 32 * dsaD
	}

	clear(raw[:])

	return outOfRange
}

// An expanded private key carries everything needed to rebuild the public key, so a key whose
// parts disagree is rejected instead of producing signatures that never verify. Returns the
// public key, or nil.
func mldsaCheckPrivateKey(p *mldsaParams, sk []byte) []byte {
	s, t0 := make([]dsaPoly, p.l+p.k, dsaMaxL+dsaMaxK), make([]dsaPoly, p.k, dsaMaxK)

	invalid := dsaDecodePrivateKey(s, t0, sk, p)

	for i := range p.l {
		dsaNTT(&s[i])
	}

	t := make([]dsaPoly, p.k, dsaMaxK)

	copy(t, s[p.l:])

	dsaPublicT(t, sk[:32], s[:p.l])

	var difference uint32

	for i := range t {
		for x := range t[i] {
			_, low := dsaPower2Round(t[i][x])

			difference |= dsaFromSigned(low) ^ t0[i][x]
		}
	}

	pk := dsaEncodePublicKey(sk[:32], t, p)

	var tr [64]byte

	shake256Sum(tr[:], pk)

	invalid |= (difference | -difference) >> 31

	invalid |= uint32(1 - equalBit(tr[:], sk[64:128]))

	clear(s)

	clear(t0)

	clear(t)

	if invalid != 0 {
		return nil
	}

	return pk
}

// a is Â and secrets what dsaSecrets keeps: t̂0, after ŝ1 and ŝ2 without the sparse products.
func mldsaSign(p *mldsaParams, sk []byte, a, secrets []dsaPoly, message, rnd []byte) []byte {
	k, l := p.k, p.l

	t0 := secrets[len(secrets)-k:]

	var s1Hat, s2Hat []dsaPoly

	if len(secrets) > k {
		s1Hat, s2Hat = secrets[:l], secrets[l:l+k]
	}

	var mu, rhoPrime [64]byte

	shake256Sum(mu[:], sk[64:128], message)

	shake256Sum(rhoPrime[:], sk[32:64], rnd, mu[:])

	// z = y + c s1 takes the place of NTT(y), which only the products of w need before it.
	yHat := make([]dsaPoly, l, dsaMaxL)

	z := yHat

	w, hints := make([]dsaPoly, k, dsaMaxK), make([][4]uint64, k, dsaMaxK)

	w1 := make([]byte, 32*k*p.w1Bits(), 32*dsaMaxK*6)

	cTilde := make([]byte, p.lambda/4, 64)

	var c, product dsaPoly

	var streams dsaMaskStreams

	var starts [64]uint16

	var small [256]int16

	gamma1Bound, gamma2Bound := p.gamma1-p.beta(), p.gamma2-p.beta()

	// s1 and s2 as packed in the private key, for the sparse products, which may read a little past
	// a polynomial.
	packed := 32 * p.etaBits()

	s1, s2 := sk[128:], sk[128+l*packed:]

	// y lives in the NTT domain only, and in its packed form in streams: z = y + c s1 is either
	// NTT^-1(NTT(y) + c NTT(s1)) or y + c s1 from the sparse product of c and s1.
	for kappa := 0; ; kappa += l {
		dsaExpandMask(yHat, &streams, rhoPrime[:], kappa, p)

		for i := range yHat {
			dsaNTT(&yHat[i])
		}

		for i := range w {
			dsaRowProduct(&w[i], a[i*l:(i+1)*l], yHat)

			dsaHighBits(w1[32*p.w1Bits()*i:], &w[i], p.gamma2, p.w1Bits())
		}

		shake256Sum(cTilde, mu[:], w1)

		dsaSampleInBall(&c, cTilde, p.tau)

		var reject uint32

		if dsaSparse() {
			n := dsaChallengeStarts(&starts, &c)

			for r := range z {
				dsaSparseProduct(&small, &starts, n, s1[packed*r:], p.eta)

				reject |= dsaUnpackAdd(&z[r], streams[r][:], &small, p.gamma1, p.gamma1Bits(), gamma1Bound)
			}

			for i := range w {
				dsaSparseProduct(&small, &starts, n, s2[packed*i:], p.eta)

				reject |= dsaSubSmallLow(&w[i], &small, p.gamma2, gamma2Bound)
			}

			if reject != 0 {
				continue
			}

			dsaScaleChallenge(&c, dsaChallengeOne())

			dsaNTT(&c)
		} else {
			dsaScaleChallenge(&c, dsaChallengeOne())

			dsaNTT(&c)

			for r := range z {
				dsaProduct(&z[r], &c, &s1Hat[r], &yHat[r])

				reject |= dsaBeyond(&z[r], gamma1Bound)
			}

			for i := range w {
				dsaProduct(&product, &c, &s2Hat[i], nil)

				reject |= dsaSubLow(&w[i], &product, p.gamma2, gamma2Bound)
			}

			if reject != 0 {
				continue
			}
		}

		var count uint32

		for i := range w {
			dsaProduct(&product, &c, &t0[i], nil)

			beyond, n := dsaHints(&hints[i], &w[i], &product, p.gamma2)

			reject |= beyond

			count += n
		}

		// The ct0 bound and the hint count make one restart decision, as in the Rust and Zig
		// implementations, so which of the two failed stays hidden.
		if reject|((uint32(p.omega)-count)>>31) != 0 {
			continue
		}

		signature := make([]byte, p.signatureSize())

		copy(signature, cTilde)

		offset := len(cTilde)

		for r := range z {
			dsaPackGamma1(signature[offset:], &z[r], p.gamma1, p.gamma1Bits())

			offset += 32 * p.gamma1Bits()
		}

		dsaPackHints(signature[offset:], hints, p)

		clear(z)

		clear(w)

		clear(rhoPrime[:])

		clear(product[:])

		clear(streams[:])

		clear(small[:])

		return signature
	}
}

// HintBitPack (FIPS 204, Algorithm 20) of an accepted signature, whose hints are public.
func dsaPackHints(out []byte, hints [][4]uint64, p *mldsaParams) {
	index := 0

	for i := range hints {
		for j, word := range hints[i] {
			for ; word != 0; word &= word - 1 {
				out[index] = byte(64*j + bits.TrailingZeros64(word))

				index++
			}
		}

		out[p.omega+i] = byte(index)
	}
}

// HintBitUnpack (FIPS 204, Algorithm 21): the encoding must be canonical, with strictly
// increasing indices and zero padding, or the signature is rejected.
func dsaUnpackHints(hints [][4]uint64, data []byte, p *mldsaParams) bool {
	index := 0

	for i := range hints {
		end := int(data[p.omega+i])

		if end < index || end > p.omega {
			return false
		}

		for first := index; index < end; index++ {
			if index > first && data[index-1] >= data[index] {
				return false
			}

			hints[i][data[index]/64] |= 1 << (data[index] % 64)
		}
	}

	for _, b := range data[index:p.omega] {
		if b != 0 {
			return false
		}
	}

	return true
}

// public holds tr, Â and t̂1, which the key keeps.
func mldsaVerify(p *mldsaParams, pk []byte, public *dsaPublic, message, signature []byte) bool {
	k, l := p.k, p.l

	if len(pk) != p.publicKeySize() || len(signature) != p.signatureSize() {
		return false
	}

	cTilde := signature[:p.lambda/4]

	z := make([]dsaPoly, l, dsaMaxL)

	offset := len(cTilde)

	var notBelow uint32

	for r := range z {
		dsaUnpackGamma1(&z[r], signature[offset:], p.gamma1, p.gamma1Bits())

		offset += 32 * p.gamma1Bits()

		notBelow |= dsaBeyond(&z[r], p.gamma1-p.beta())
	}

	hints := make([][4]uint64, k, dsaMaxK)

	if !dsaUnpackHints(hints, signature[offset:], p) || notBelow != 0 {
		return false
	}

	var mu [64]byte

	shake256Sum(mu[:], public.tr[:], message)

	var c, w dsaPoly

	dsaSampleInBall(&c, cTilde, p.tau)

	dsaNTT(&c)

	for r := range z {
		dsaNTT(&z[r])
	}

	w1 := make([]byte, 32*k*p.w1Bits(), 32*dsaMaxK*6)

	a, t1 := public.matrix(p, pk[:32]), public.t1Hat(p, pk)

	for i := range k {
		dsaRowProductSub(&w, a[i*l:(i+1)*l], z, &c, &t1[i])

		dsaUseHints(w1[32*p.w1Bits()*i:], &w, &hints[i], p.gamma2, p.w1Bits())
	}

	expected := make([]byte, len(cTilde), 64)

	shake256Sum(expected, mu[:], w1)

	return equal(expected, cTilde)
}

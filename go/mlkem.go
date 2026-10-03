package cryptopq

import "encoding/binary"

// ML-KEM (FIPS 203). Coefficients are canonical, in [0, q), except inside the NTTs, which reduce
// lazily. Every reduction is a multiply-shift or a masked subtraction, so no branch or memory index
// depends on secret data.

const kemQ = 3329

type mlkemParams struct {
	k, eta1, eta2, du, dv int
}

var (
	mlkem512  = mlkemParams{k: 2, eta1: 3, eta2: 2, du: 10, dv: 4}
	mlkem768  = mlkemParams{k: 3, eta1: 2, eta2: 2, du: 10, dv: 4}
	mlkem1024 = mlkemParams{k: 4, eta1: 2, eta2: 2, du: 11, dv: 5}
)

func (p *mlkemParams) encapsulationKeySize() int {
	return 384*p.k + 32
}

func (p *mlkemParams) decapsulationKeySize() int {
	return 768*p.k + 96
}

func (p *mlkemParams) ciphertextSize() int {
	return 32 * (p.du*p.k + p.dv)
}

type kemPoly [256]uint16

func bitReverse(value, width int) int {
	reversed := 0

	for range width {
		reversed = reversed<<1 | value&1

		value >>= 1
	}

	return reversed
}

func powMod(base, exponent, modulus uint64) uint64 {
	result := uint64(1)

	for ; exponent > 0; exponent >>= 1 {
		if exponent&1 == 1 {
			result = result * base % modulus
		}

		base = base * base % modulus
	}

	return result
}

// The twiddle factors zeta = 17^BitRev7(i) with their Shoup companions floor(zeta * 2^16 / q), and
// the base-case factors gamma = 17^(2 BitRev7(i) + 1).
var kemZetas, kemShoup, kemGammas = kemTables()

func kemTables() (zetas, shoup, gammas [128]uint16) {
	for i := range 128 {
		r := uint64(bitReverse(i, 7))

		zetas[i] = uint16(powMod(17, r, kemQ))

		shoup[i] = uint16((uint32(zetas[i]) << 16) / kemQ)

		gammas[i] = uint16(powMod(17, 2*r+1, kemQ))
	}

	return zetas, shoup, gammas
}

// a < 2q: subtracts q when a >= q. A negative a - q wraps to at least 2^16 - q, setting bit 15.
func kemReduceOnce(a uint16) uint16 {
	a -= kemQ

	return a + kemQ&-(a>>15)
}

// a < 4q: subtracts 2q when a >= 2q, as kemReduceOnce does q.
func kemReduceTwice(a uint16) uint16 {
	a -= 2 * kemQ

	return a + 2*kemQ&-(a>>15)
}

// Barrett reduction of a < 2^32: the estimate a * floor(2^32 / q) / 2^32 is the quotient or one
// less, so one conditional subtraction finishes.
func kemReduce(a uint32) uint16 {
	quotient := uint32((uint64(a) * ((1 << 32) / kemQ)) >> 32)

	return kemReduceOnce(uint16(a - quotient*kemQ))
}

// The same for a < 2^16 with 32-bit arithmetic: a * floor(2^26 / q) / 2^26 is the quotient or one
// less.
func kemReduce16(a uint16) uint16 {
	return kemReduceOnce(a - uint16((uint32(a)*((1<<26)/kemQ))>>26)*kemQ)
}

// a * zeta mod q, or that plus q, for any 16-bit a, where shoup = floor(zeta * 2^16 / q): the
// quotient estimate a * shoup / 2^16 is exact or one too small (Shoup's modular multiplication).
func kemMulShoup(a uint16, zeta, shoup uint32) uint16 {
	return uint16(uint32(a)*zeta - (uint32(a)*shoup>>16)*kemQ)
}

func kemAdd(a, b uint16) uint16 {
	return kemReduceOnce(a + b)
}

func kemSub(a, b uint16) uint16 {
	return kemReduceOnce(a - b + kemQ)
}

// NTT (FIPS 203, Algorithm 9) of canonical coefficients. A butterfly adds less than 2q to its
// outputs, so after seven layers they stay below 15q < 2^16 and one reduction at the end suffices.
// The layers go in pairs over groups of four coefficients held in locals, which halves the memory
// traffic; the last layer also reduces.
func kemNTT(f *kemPoly) {
	for length := 128; length >= 8; length /= 4 {
		half := length / 2

		for k := range 128 / length {
			block := f[2*length*k : 2*length*(k+1)]

			q0, q1, q2, q3 := block[:half], block[half:length], block[length:length+half], block[length+half:]

			_, _, _ = q1[len(q0)-1], q2[len(q0)-1], q3[len(q0)-1]

			zeta, shoup := uint32(kemZetas[128/length+k]), uint32(kemShoup[128/length+k])

			zetaLow, shoupLow := uint32(kemZetas[256/length+2*k]), uint32(kemShoup[256/length+2*k])

			zetaHigh, shoupHigh := uint32(kemZetas[256/length+2*k+1]), uint32(kemShoup[256/length+2*k+1])

			for j, a0 := range q0 {
				a1, a2, a3 := q1[j], q2[j], q3[j]

				t0, t1 := kemMulShoup(a2, zeta, shoup), kemMulShoup(a3, zeta, shoup)

				a0, a1, a2, a3 = a0+t0, a1+t1, a0-t0+2*kemQ, a1-t1+2*kemQ

				t0, t1 = kemMulShoup(a1, zetaLow, shoupLow), kemMulShoup(a3, zetaHigh, shoupHigh)

				q0[j], q1[j], q2[j], q3[j] = a0+t0, a0-t0+2*kemQ, a2+t1, a2-t1+2*kemQ
			}
		}
	}

	for k := range 64 {
		g := (*[4]uint16)(f[4*k : 4*k+4])

		zeta, shoup := uint32(kemZetas[64+k]), uint32(kemShoup[64+k])

		t0, t1 := kemMulShoup(g[2], zeta, shoup), kemMulShoup(g[3], zeta, shoup)

		g[0], g[1], g[2], g[3] = kemReduce16(g[0]+t0), kemReduce16(g[1]+t1), kemReduce16(g[0]-t0+2*kemQ), kemReduce16(g[1]-t1+2*kemQ)
	}
}

// The last layer of the inverse NTT multiplies by zeta_1 and then by 1/128; the factors are folded.
var kemLastZeta = kemReduce(uint32(kemZetas[1]) * 3303)

// Inverse NTT (FIPS 203, Algorithm 10) of canonical coefficients, which every butterfly keeps below
// 2q. As in kemNTT the layers after the first go in pairs; the last pair also applies the factor
// 1/128 and reduces.
func kemInverseNTT(f *kemPoly) {
	for k := range 64 {
		g := (*[4]uint16)(f[4*k : 4*k+4])

		zeta, shoup := uint32(kemZetas[127-k]), uint32(kemShoup[127-k])

		g[0], g[1], g[2], g[3] = g[0]+g[2], g[1]+g[3], kemMulShoup(g[2]-g[0]+2*kemQ, zeta, shoup), kemMulShoup(g[3]-g[1]+2*kemQ, zeta, shoup)
	}

	for length := 8; length <= 32; length *= 4 {
		half := length / 2

		for k := range 128 / length {
			block := f[2*length*k : 2*length*(k+1)]

			q0, q1, q2, q3 := block[:half], block[half:length], block[length:length+half], block[length+half:]

			_, _, _ = q1[len(q0)-1], q2[len(q0)-1], q3[len(q0)-1]

			zetaLow, shoupLow := uint32(kemZetas[512/length-1-2*k]), uint32(kemShoup[512/length-1-2*k])

			zetaHigh, shoupHigh := uint32(kemZetas[512/length-2-2*k]), uint32(kemShoup[512/length-2-2*k])

			zeta, shoup := uint32(kemZetas[256/length-1-k]), uint32(kemShoup[256/length-1-k])

			for j, a0 := range q0 {
				a1, a2, a3 := q1[j], q2[j], q3[j]

				a0, a1 = kemReduceTwice(a0+a1), kemMulShoup(a1-a0+2*kemQ, zetaLow, shoupLow)

				a2, a3 = kemReduceTwice(a2+a3), kemMulShoup(a3-a2+2*kemQ, zetaHigh, shoupHigh)

				q0[j], q1[j], q2[j], q3[j] = kemReduceTwice(a0+a2), kemReduceTwice(a1+a3), kemMulShoup(a2-a0+2*kemQ, zeta, shoup), kemMulShoup(a3-a1+2*kemQ, zeta, shoup)
			}
		}
	}

	q0, q1, q2, q3 := f[:64], f[64:128], f[128:192], f[192:]

	zeta, shoup := uint32(kemLastZeta), (uint32(kemLastZeta)<<16)/kemQ

	for j, a0 := range q0 {
		a1, a2, a3 := q1[j], q2[j], q3[j]

		a0, a1 = kemReduceTwice(a0+a1), kemMulShoup(a1-a0+2*kemQ, uint32(kemZetas[3]), uint32(kemShoup[3]))

		a2, a3 = kemReduceTwice(a2+a3), kemMulShoup(a3-a2+2*kemQ, uint32(kemZetas[2]), uint32(kemShoup[2]))

		q0[j], q1[j] = kemReduceOnce(kemMulShoup(a0+a2, 3303, (3303<<16)/kemQ)), kemReduceOnce(kemMulShoup(a1+a3, 3303, (3303<<16)/kemQ))

		q2[j], q3[j] = kemReduceOnce(kemMulShoup(a2-a0+2*kemQ, zeta, shoup)), kemReduceOnce(kemMulShoup(a3-a1+2*kemQ, zeta, shoup))
	}
}

// acc += f * g in the NTT domain (FIPS 203, Algorithms 11 and 12) for canonical f and g, without the
// final reduction: a product adds less than 2q^2 to a coefficient, so a canonical start plus k <= 4
// products stays far below 2^32.
func kemMultiplyAdd(acc *[256]uint32, f, g *kemPoly) {
	for i := range 128 {
		a0, a1 := uint32(f[2*i]), uint32(f[2*i+1])

		b0, b1 := uint32(g[2*i]), uint32(g[2*i+1])

		acc[2*i] += a0*b0 + uint32(kemReduce(a1*b1))*uint32(kemGammas[i])

		acc[2*i+1] += a0*b1 + a1*b0
	}
}

func kemReduceAll(f *kemPoly, acc *[256]uint32) {
	for x, c := range acc {
		f[x] = kemReduce(c)
	}
}

// Packs the 256 d-bit values of a polynomial into 32d bytes, least significant bits first (FIPS 203
// ByteEncode, FIPS 204 SimpleBitPack), 32 bits at a time; unpackBits reads them the same way.
func packBits[T uint16 | uint32](out []byte, values []T, d int) {
	var accumulator uint64

	bits, o := 0, 0

	for _, value := range values {
		accumulator |= uint64(value) << bits

		bits += d

		if bits >= 32 {
			binary.LittleEndian.PutUint32(out[o:], uint32(accumulator))

			o += 4

			accumulator >>= 32

			bits -= 32
		}
	}
}

func unpackBits[T uint16 | uint32](values []T, in []byte, d int) {
	var accumulator uint64

	bits, o := 0, 0

	mask := uint64(1)<<d - 1

	for i := range values {
		if bits < d {
			accumulator |= uint64(binary.LittleEndian.Uint32(in[o:])) << bits

			o += 4

			bits += 32
		}

		values[i] = T(accumulator & mask)

		accumulator >>= d

		bits -= d
	}
}

// ByteEncode_12 of canonical coefficients, two in three bytes.
func kemEncode12(out []byte, f *kemPoly) {
	out = out[:384]

	for i := range 128 {
		a, b := f[2*i], f[2*i+1]

		out[3*i], out[3*i+1], out[3*i+2] = byte(a), byte(a>>8)|byte(b<<4), byte(b>>4)
	}
}

// ByteDecode_12 reduces modulo q; every 12-bit value is below 2q.
func kemDecode12(f *kemPoly, in []byte) {
	in = in[:384]

	for i := range 128 {
		x, y, z := uint16(in[3*i]), uint16(in[3*i+1]), uint16(in[3*i+2])

		f[2*i], f[2*i+1] = kemReduceOnce(x|(y&0x0f)<<8), kemReduceOnce(y>>4|z<<4)
	}
}

// round(2^d * x / q) mod 2^d as floor((2^d * x + 1664) / q): the dividend is below 2^24, where
// t * ceil(2^36 / q) >> 36 equals floor(t / q).
func kemCompress(x uint16, d int) uint16 {
	t := uint64(x)<<d + 1664

	return uint16((t*((1<<36+kemQ-1)/kemQ))>>36) & (1<<d - 1)
}

func kemDecompress(y uint16, d int) uint16 {
	return uint16((uint32(y)*kemQ + 1<<(d-1)) >> d)
}

// SamplePolyCBD (FIPS 203, Algorithm 8). Masks add up each pair (eta = 2) or triple (eta = 3) of
// neighbouring bits in place; a coefficient is the difference of two such sums.
func kemSampleCBD(f *kemPoly, data []byte, eta int) {
	if eta == 2 {
		for i := range 32 {
			t := binary.LittleEndian.Uint32(data[4*i:])

			t = t&0x55555555 + t>>1&0x55555555

			for j := range 8 {
				f[8*i+j] = kemReduceOnce(uint16(t>>(4*j)&3 + kemQ - t>>(4*j+2)&3))
			}
		}

		return
	}

	for i := range 64 {
		t := uint32(data[3*i]) | uint32(data[3*i+1])<<8 | uint32(data[3*i+2])<<16

		t = t&0x249249 + t>>1&0x249249 + t>>2&0x249249

		for j := range 4 {
			f[4*i+j] = kemReduceOnce(uint16(t>>(6*j)&7 + kemQ - t>>(6*j+3)&7))
		}
	}
}

// PRF_eta(s, b) followed by SamplePolyCBD_eta.
func kemNoise(f *kemPoly, seed []byte, nonce byte, eta int) {
	var data [192]byte

	shake256Sum(data[:64*eta], seed, []byte{nonce})

	kemSampleCBD(f, data[:64*eta], eta)

	clear(data[:])
}

// SampleNTT (FIPS 203, Algorithm 7): rejection sampling over public data. Each candidate is stored
// and then kept or overwritten by advancing the count or not, which avoids a hard-to-predict branch;
// the slot after the last one absorbs a candidate beyond the 256th.
func kemSampleNTT(f *kemPoly, rho []byte, j, i byte) {
	sponge := keccak{rate: 168, suffix: 0x1f}

	sponge.update(rho)

	sponge.update([]byte{j, i})

	var block [168]byte

	var accepted [257]uint16

	count := 0

	for count < 256 {
		sponge.read(block[:])

		for rest := block[:]; len(rest) >= 3 && count < 256; rest = rest[3:] {
			d1 := uint32(rest[0]) | uint32(rest[1]&0x0f)<<8

			d2 := uint32(rest[1]>>4) | uint32(rest[2])<<4

			accepted[count] = uint16(d1)

			count += int((d1 - kemQ) >> 31)

			accepted[count] = uint16(d2)

			count += int((d2 - kemQ) >> 31)
		}
	}

	copy(f[:], accepted[:256])
}

// K-PKE.KeyGen (FIPS 203, Algorithm 13). Each entry A[i][j] = SampleNTT(rho || j || i) is folded into
// t as soon as it is sampled, so the matrix is never stored.
func kpkeKeyGen(p *mlkemParams, d, ek, dkPKE []byte) {
	k := p.k

	var g [64]byte

	sha3Sum512(g[:], d, []byte{byte(k)})

	rho, sigma := g[:32], g[32:]

	var s, e [4]kemPoly

	for n := range k {
		kemNoise(&s[n], sigma, byte(n), p.eta1)

		kemNTT(&s[n])
	}

	for n := range k {
		kemNoise(&e[n], sigma, byte(k+n), p.eta1)

		kemNTT(&e[n])
	}

	var a kemPoly

	var acc [256]uint32

	for i := range k {
		for x, c := range e[i] {
			acc[x] = uint32(c)
		}

		for j := range k {
			kemSampleNTT(&a, rho, byte(j), byte(i))

			kemMultiplyAdd(&acc, &a, &s[j])
		}

		kemReduceAll(&a, &acc)

		kemEncode12(ek[384*i:], &a)
	}

	copy(ek[384*k:], rho)

	for i := range k {
		kemEncode12(dkPKE[384*i:], &s[i])
	}

	clear(g[:])

	clear(s[:])

	clear(e[:])
}

// K-PKE.Encrypt (FIPS 203, Algorithm 14), with the transposed matrix sampled entry by entry.
func kpkeEncrypt(p *mlkemParams, ek, m, r, c []byte) {
	k, du, dv := p.k, p.du, p.dv

	rho := ek[384*k : 384*k+32]

	var y [4]kemPoly

	var a, e, u kemPoly

	var acc [256]uint32

	for n := range k {
		kemNoise(&y[n], r, byte(n), p.eta1)

		kemNTT(&y[n])
	}

	for i := range k {
		clear(acc[:])

		for j := range k {
			kemSampleNTT(&a, rho, byte(i), byte(j))

			kemMultiplyAdd(&acc, &a, &y[j])
		}

		kemReduceAll(&u, &acc)

		kemInverseNTT(&u)

		kemNoise(&e, r, byte(k+i), p.eta2)

		for x := range u {
			u[x] = kemCompress(kemAdd(u[x], e[x]), du)
		}

		packBits(c[32*du*i:], u[:], du)
	}

	clear(acc[:])

	for j := range k {
		kemDecode12(&a, ek[384*j:])

		kemMultiplyAdd(&acc, &a, &y[j])
	}

	kemReduceAll(&u, &acc)

	kemInverseNTT(&u)

	kemNoise(&e, r, byte(2*k), p.eta2)

	var mu kemPoly

	unpackBits(mu[:], m, 1)

	for x := range u {
		u[x] = kemCompress(kemAdd(kemAdd(u[x], e[x]), kemDecompress(mu[x], 1)), dv)
	}

	packBits(c[32*du*k:], u[:], dv)

	clear(y[:])

	clear(e[:])

	clear(mu[:])

	clear(u[:])

	clear(acc[:])
}

// K-PKE.Decrypt (FIPS 203, Algorithm 15).
func kpkeDecrypt(p *mlkemParams, dkPKE, c, m []byte) {
	k, du, dv := p.k, p.du, p.dv

	var u, s, w kemPoly

	var acc [256]uint32

	for i := range k {
		unpackBits(u[:], c[32*du*i:32*du*(i+1)], du)

		for x := range u {
			u[x] = kemDecompress(u[x], du)
		}

		kemNTT(&u)

		kemDecode12(&s, dkPKE[384*i:])

		kemMultiplyAdd(&acc, &s, &u)
	}

	kemReduceAll(&u, &acc)

	kemInverseNTT(&u)

	unpackBits(w[:], c[32*du*k:], dv)

	for x := range w {
		w[x] = kemCompress(kemSub(kemDecompress(w[x], dv), u[x]), 1)
	}

	packBits(m, w[:], 1)

	clear(s[:])

	clear(u[:])

	clear(w[:])

	clear(acc[:])
}

func mlkemKeyGen(p *mlkemParams, d, z []byte) (ek, dk []byte) {
	k := p.k

	ek = make([]byte, p.encapsulationKeySize())

	dk = make([]byte, p.decapsulationKeySize())

	kpkeKeyGen(p, d, ek, dk[:384*k])

	copy(dk[384*k:], ek)

	sha3Sum256(dk[768*k+32:], ek)

	copy(dk[768*k+64:], z)

	return ek, dk
}

func mlkemEncapsulate(p *mlkemParams, ek, m []byte) (sharedSecret, ciphertext []byte) {
	var h [32]byte

	var g [64]byte

	sha3Sum256(h[:], ek)

	sha3Sum512(g[:], m, h[:])

	ciphertext = make([]byte, p.ciphertextSize())

	kpkeEncrypt(p, ek, m, g[32:], ciphertext)

	sharedSecret = make([]byte, 32)

	copy(sharedSecret, g[:32])

	clear(g[:])

	return sharedSecret, ciphertext
}

// Implicit rejection: a ciphertext that does not re-encrypt to itself yields J(z || c), chosen
// with a mask rather than a branch.
func mlkemDecapsulate(p *mlkemParams, dk, c []byte) []byte {
	k := p.k

	dkPKE, ek, h, z := dk[:384*k], dk[384*k:768*k+32], dk[768*k+32:768*k+64], dk[768*k+64:]

	var m [32]byte

	var g [64]byte

	var rejected [32]byte

	var reencrypted [1568]byte

	kpkeDecrypt(p, dkPKE, c, m[:])

	sha3Sum512(g[:], m[:], h)

	shake256Sum(rejected[:], z, c)

	kpkeEncrypt(p, ek, m[:], g[32:], reencrypted[:len(c)])

	sharedSecret := make([]byte, 32)

	selectBytes(equalBit(c, reencrypted[:len(c)]), g[:32], rejected[:], sharedSecret)

	clear(m[:])

	clear(g[:])

	clear(rejected[:])

	clear(reencrypted[:])

	return sharedSecret
}

// FIPS 203, 7.2: every coefficient of the encoded vector must already be reduced modulo q.
func mlkemCheckEncapsulationKey(p *mlkemParams, ek []byte) bool {
	if len(ek) != p.encapsulationKeySize() {
		return false
	}

	for i := 0; i < 384*p.k; i += 3 {
		d1 := uint16(ek[i]) | uint16(ek[i+1]&0x0f)<<8

		d2 := uint16(ek[i+1]>>4) | uint16(ek[i+2])<<4

		if d1 >= kemQ || d2 >= kemQ {
			return false
		}
	}

	return true
}

// FIPS 203, 7.3: the embedded encapsulation key passes its check and H(ek) matches.
func mlkemCheckDecapsulationKey(p *mlkemParams, dk []byte) bool {
	k := p.k

	if len(dk) != p.decapsulationKeySize() {
		return false
	}

	ek := dk[384*k : 768*k+32]

	var h [32]byte

	sha3Sum256(h[:], ek)

	return mlkemCheckEncapsulationKey(p, ek) && equal(h[:], dk[768*k+32:768*k+64])
}

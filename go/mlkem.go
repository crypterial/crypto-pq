package cryptopq

// ML-KEM (FIPS 203). Coefficients stay in [0, q) and every reduction is a multiply-shift or a
// masked subtraction, so no branch or memory index depends on secret data.

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

var kemZetas, kemGammas = kemTables()

func kemTables() (zetas, gammas [128]uint16) {
	for i := range 128 {
		r := uint64(bitReverse(i, 7))

		zetas[i] = uint16(powMod(17, r, kemQ))

		gammas[i] = uint16(powMod(17, 2*r+1, kemQ))
	}

	return zetas, gammas
}

// a < 2q: subtracts q when a >= q. A negative a - q wraps to at least 2^16 - q, setting bit 15.
func kemReduceOnce(a uint16) uint16 {
	a -= kemQ

	return a + kemQ&-(a>>15)
}

// Barrett reduction of a < 2^32: the estimate a * floor(2^32 / q) / 2^32 is the quotient or one
// less, so one conditional subtraction finishes.
func kemReduce(a uint32) uint16 {
	quotient := uint32((uint64(a) * ((1 << 32) / kemQ)) >> 32)

	return kemReduceOnce(uint16(a - quotient*kemQ))
}

func kemAdd(a, b uint16) uint16 {
	return kemReduceOnce(a + b)
}

func kemSub(a, b uint16) uint16 {
	return kemReduceOnce(a - b + kemQ)
}

func kemNTT(f *kemPoly) {
	i := 1

	for length := 128; length >= 2; length /= 2 {
		for start := 0; start < 256; start += 2 * length {
			zeta := uint32(kemZetas[i])

			i++

			for j := start; j < start+length; j++ {
				t := kemReduce(zeta * uint32(f[j+length]))

				f[j+length] = kemSub(f[j], t)

				f[j] = kemAdd(f[j], t)
			}
		}
	}
}

func kemInverseNTT(f *kemPoly) {
	i := 127

	for length := 2; length <= 128; length *= 2 {
		for start := 0; start < 256; start += 2 * length {
			zeta := uint32(kemZetas[i])

			i--

			for j := start; j < start+length; j++ {
				t := f[j]

				f[j] = kemAdd(t, f[j+length])

				f[j+length] = kemReduce(zeta * uint32(kemSub(f[j+length], t)))
			}
		}
	}

	for j := range f {
		f[j] = kemReduce(uint32(f[j]) * 3303)
	}
}

// acc += f * g in the NTT domain (FIPS 203, Algorithms 11 and 12).
func kemMultiplyAdd(acc, f, g *kemPoly) {
	for i := range 128 {
		a0, a1 := uint32(f[2*i]), uint32(f[2*i+1])

		b0, b1 := uint32(g[2*i]), uint32(g[2*i+1])

		c0 := kemReduce(a0*b0 + uint32(kemReduce(a1*b1))*uint32(kemGammas[i]))

		c1 := kemReduce(a0*b1 + a1*b0)

		acc[2*i] = kemAdd(acc[2*i], c0)

		acc[2*i+1] = kemAdd(acc[2*i+1], c1)
	}
}

// Packs len(values) d-bit values into out, least significant bits first (FIPS 203 ByteEncode,
// FIPS 204 SimpleBitPack).
func packBits[T uint16 | uint32](out []byte, values []T, d int) {
	var accumulator uint64

	bits, o := 0, 0

	for _, value := range values {
		accumulator |= uint64(value) << bits

		bits += d

		for bits >= 8 {
			out[o] = byte(accumulator)

			o++

			accumulator >>= 8

			bits -= 8
		}
	}
}

func unpackBits[T uint16 | uint32](values []T, in []byte, d int) {
	var accumulator uint64

	bits, i := 0, 0

	mask := uint64(1)<<d - 1

	for _, b := range in {
		accumulator |= uint64(b) << bits

		bits += 8

		for bits >= d && i < len(values) {
			values[i] = T(accumulator & mask)

			i++

			accumulator >>= d

			bits -= d
		}
	}
}

// ByteDecode_12 reduces modulo q; every 12-bit value is below 2q.
func kemDecode12(f *kemPoly, in []byte) {
	unpackBits(f[:], in[:384], 12)

	for i := range f {
		f[i] = kemReduceOnce(f[i])
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

// SamplePolyCBD (FIPS 203, Algorithm 8) with the bits counted arithmetically.
func kemSampleCBD(f *kemPoly, data []byte, eta int) {
	var accumulator uint32

	bits, o := 0, 0

	for i := range f {
		for bits < 2*eta {
			accumulator |= uint32(data[o]) << bits

			o++

			bits += 8
		}

		var x, y uint16

		for j := range eta {
			x += uint16(accumulator>>j) & 1

			y += uint16(accumulator>>(eta+j)) & 1
		}

		accumulator >>= 2 * eta

		bits -= 2 * eta

		f[i] = kemSub(x, y)
	}
}

// PRF_eta(s, b) followed by SamplePolyCBD_eta.
func kemNoise(f *kemPoly, seed []byte, nonce byte, eta int) {
	var data [192]byte

	shake256Sum(data[:64*eta], seed, []byte{nonce})

	kemSampleCBD(f, data[:64*eta], eta)

	clear(data[:])
}

// SampleNTT (FIPS 203, Algorithm 7): rejection sampling over public data.
func kemSampleNTT(f *kemPoly, rho []byte, j, i byte) {
	sponge := keccak{rate: 168, suffix: 0x1f}

	sponge.update(rho)

	sponge.update([]byte{j, i})

	var block [168]byte

	count := 0

	for count < 256 {
		sponge.read(block[:])

		for offset := 0; offset < len(block) && count < 256; offset += 3 {
			d1 := uint16(block[offset]) | uint16(block[offset+1]&0x0f)<<8

			d2 := uint16(block[offset+1]>>4) | uint16(block[offset+2])<<4

			if d1 < kemQ {
				f[count] = d1

				count++
			}

			if d2 < kemQ && count < 256 {
				f[count] = d2

				count++
			}
		}
	}
}

// Entry i * k + j is A[i][j] = SampleNTT(rho || j || i).
func kemMatrix(rho []byte, k int) []kemPoly {
	a := make([]kemPoly, k*k)

	for i := range k {
		for j := range k {
			kemSampleNTT(&a[i*k+j], rho, byte(j), byte(i))
		}
	}

	return a
}

// K-PKE.KeyGen (FIPS 203, Algorithm 13).
func kpkeKeyGen(p *mlkemParams, d, ek, dkPKE []byte) {
	k := p.k

	var g [64]byte

	sha3Sum512(g[:], d, []byte{byte(k)})

	rho, sigma := g[:32], g[32:]

	a := kemMatrix(rho, k)

	s := make([]kemPoly, k)

	e := make([]kemPoly, k)

	for n := range k {
		kemNoise(&s[n], sigma, byte(n), p.eta1)

		kemNTT(&s[n])
	}

	for n := range k {
		kemNoise(&e[n], sigma, byte(k+n), p.eta1)

		kemNTT(&e[n])
	}

	for i := range k {
		t := e[i]

		for j := range k {
			kemMultiplyAdd(&t, &a[i*k+j], &s[j])
		}

		packBits(ek[384*i:], t[:], 12)
	}

	copy(ek[384*k:], rho)

	for i := range k {
		packBits(dkPKE[384*i:], s[i][:], 12)
	}

	clear(g[:])

	clear(s)

	clear(e)
}

// K-PKE.Encrypt (FIPS 203, Algorithm 14).
func kpkeEncrypt(p *mlkemParams, ek, m, r, c []byte) {
	k, du, dv := p.k, p.du, p.dv

	t := make([]kemPoly, k)

	for i := range k {
		kemDecode12(&t[i], ek[384*i:])
	}

	a := kemMatrix(ek[384*k:], k)

	y := make([]kemPoly, k)

	e1 := make([]kemPoly, k)

	var e2, mu, u, v kemPoly

	for n := range k {
		kemNoise(&y[n], r, byte(n), p.eta1)

		kemNTT(&y[n])
	}

	for n := range k {
		kemNoise(&e1[n], r, byte(k+n), p.eta2)
	}

	kemNoise(&e2, r, byte(2*k), p.eta2)

	for i := range k {
		clear(u[:])

		for j := range k {
			kemMultiplyAdd(&u, &a[j*k+i], &y[j])
		}

		kemInverseNTT(&u)

		for x := range u {
			u[x] = kemCompress(kemAdd(u[x], e1[i][x]), du)
		}

		packBits(c[32*du*i:], u[:], du)
	}

	unpackBits(mu[:], m, 1)

	for j := range k {
		kemMultiplyAdd(&v, &t[j], &y[j])
	}

	kemInverseNTT(&v)

	for x := range v {
		v[x] = kemCompress(kemAdd(kemAdd(v[x], e2[x]), kemDecompress(mu[x], 1)), dv)
	}

	packBits(c[32*du*k:], v[:], dv)

	clear(y)

	clear(e1)

	clear(e2[:])

	clear(mu[:])

	clear(u[:])

	clear(v[:])
}

// K-PKE.Decrypt (FIPS 203, Algorithm 15).
func kpkeDecrypt(p *mlkemParams, dkPKE, c, m []byte) {
	k, du, dv := p.k, p.du, p.dv

	var u, s, product, w kemPoly

	for i := range k {
		unpackBits(u[:], c[32*du*i:32*du*(i+1)], du)

		for x := range u {
			u[x] = kemDecompress(u[x], du)
		}

		kemNTT(&u)

		kemDecode12(&s, dkPKE[384*i:])

		kemMultiplyAdd(&product, &s, &u)
	}

	kemInverseNTT(&product)

	unpackBits(w[:], c[32*du*k:], dv)

	for x := range w {
		w[x] = kemCompress(kemSub(kemDecompress(w[x], dv), product[x]), 1)
	}

	packBits(m, w[:], 1)

	clear(s[:])

	clear(product[:])

	clear(w[:])
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

	kpkeDecrypt(p, dkPKE, c, m[:])

	sha3Sum512(g[:], m[:], h)

	shake256Sum(rejected[:], z, c)

	reencrypted := make([]byte, len(c))

	kpkeEncrypt(p, ek, m[:], g[32:], reencrypted)

	sharedSecret := make([]byte, 32)

	selectBytes(equalBit(c, reencrypted), g[:32], rejected[:], sharedSecret)

	clear(m[:])

	clear(g[:])

	clear(rejected[:])

	clear(reencrypted)

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

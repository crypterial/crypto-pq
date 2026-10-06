package main

import (
	"math"
	"math/big"
)

// The constants are derived from their definitions rather than copied, and the kernels that use
// them are tested against the portable code, which has its own copies.

func primes(count int) []int64 {
	var out []int64

	for candidate := int64(2); len(out) < count; candidate++ {
		prime := true

		for _, p := range out {
			if p*p > candidate {
				break
			}

			if candidate%p == 0 {
				prime = false

				break
			}
		}

		if prime {
			out = append(out, candidate)
		}
	}

	return out
}

// The first width bits of the fractional part of the cube root of p (FIPS 180-4, 4.2.2 and
// 4.2.3), from Newton's iteration at 256 bits of precision.
func cubeRootFraction(p int64, width int) uint64 {
	const precision = 256

	value := new(big.Float).SetPrec(precision).SetInt64(p)

	three := new(big.Float).SetPrec(precision).SetInt64(3)

	root := new(big.Float).SetPrec(precision).SetFloat64(math.Cbrt(float64(p)))

	for range 8 {
		square := new(big.Float).SetPrec(precision).Mul(root, root)

		quotient := new(big.Float).SetPrec(precision).Quo(value, square)

		root.Add(root, root)

		root.Add(root, quotient)

		root.Quo(root, three)
	}

	whole, _ := root.Int(nil)

	fraction := new(big.Float).SetPrec(precision).Sub(root, new(big.Float).SetPrec(precision).SetInt(whole))

	fraction.SetMantExp(fraction, width)

	bits, _ := fraction.Int(nil)

	return bits.Uint64()
}

func sha256Constants() []uint64 {
	var out []uint64

	for _, p := range primes(64) {
		out = append(out, cubeRootFraction(p, 32))
	}

	return out
}

func sha512Constants() []uint64 {
	var out []uint64

	for _, p := range primes(80) {
		out = append(out, cubeRootFraction(p, 64))
	}

	return out
}

// rc(t) of FIPS 202, Algorithm 5: the low bit of an LFSR with feedback x^8 + x^6 + x^5 + x^4 + 1.
func keccakBit(t int) uint64 {
	r := uint16(1)

	for range t % 255 {
		r <<= 1

		if r&0x100 != 0 {
			r ^= 0x171
		}
	}

	return uint64(r & 1)
}

// The round constants of iota (FIPS 202, Algorithm 6): bit 2^j - 1 of round i is rc(j + 7i).
func keccakConstants() []uint64 {
	var out []uint64

	for i := range 24 {
		var constant uint64

		for j := range 7 {
			constant |= keccakBit(j+7*i) << (1<<j - 1)
		}

		out = append(out, constant)
	}

	return out
}

// The first width bits of the fractional part of the square root of p (FIPS 180-4, 5.3.3 and
// 5.3.5), which are also the BLAKE2 IVs.
func squareRootFraction(p int64, width int) uint64 {
	const precision = 256

	root := new(big.Float).SetPrec(precision).SetInt64(p)

	root.Sqrt(root)

	whole, _ := root.Int(nil)

	fraction := new(big.Float).SetPrec(precision).Sub(root, new(big.Float).SetPrec(precision).SetInt(whole))

	fraction.SetMantExp(fraction, width)

	bits, _ := fraction.Int(nil)

	return bits.Uint64()
}

func sha256InitialValues() []uint64 {
	var out []uint64

	for _, p := range primes(8) {
		out = append(out, squareRootFraction(p, 32))
	}

	return out
}

func sha512InitialValues() []uint64 {
	var out []uint64

	for _, p := range primes(8) {
		out = append(out, squareRootFraction(p, 64))
	}

	return out
}

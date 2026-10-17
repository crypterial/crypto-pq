//go:build !amd64 || purego

package cryptopq

// A polynomial in the NTT domain prepared as the fixed factor of kemMultiplyAdd: odd[i] holds
// f[2i + 1] gamma_i mod q, which the base case would otherwise reduce at every use. Key material
// that is multiplied again and again is kept in this form.
type kemFactor struct {
	f   kemPoly
	odd [128]uint16
}

func (f *kemFactor) prepare() {
	for i := range f.odd {
		f.odd[i] = kemReduce(uint32(f.f[2*i+1]) * uint32(kemGammas[i]))
	}
}

// acc += f * g in the NTT domain (FIPS 203, Algorithms 11 and 12) for canonical f and g, without any
// reduction: a product adds less than 2q^2 to a coefficient, so a canonical start plus k <= 4
// products stays far below 2^32.
func kemMultiplyAdd(acc *[256]uint32, f *kemFactor, g *kemPoly) {
	for i := range f.odd {
		a0, a1, odd := uint32(f.f[2*i]), uint32(f.f[2*i+1]), uint32(f.odd[i])

		b0, b1 := uint32(g[2*i]), uint32(g[2*i+1])

		acc[2*i] += a0*b0 + odd*b1

		acc[2*i+1] += a0*b1 + a1*b0
	}
}

func kemReduceAll(f *kemPoly, acc *[256]uint32) {
	for x, c := range acc {
		f[x] = kemReduce(c)
	}
}

// The portable products read the vectors as they are.
type kemPrepared struct{}

func kemPrepareVectors(*kemPrepared, []kemPoly) {}

func (*kemPrepared) wipe() {}

// out = add + sum over j of factors[first + j stride] vectors[j] in the NTT domain, canonical; add
// may be nil.
func kemProduct(out *kemPoly, factors []kemFactor, first, stride int, vectors []kemPoly, _ *kemPrepared, add *kemPoly) {
	var acc [256]uint32

	if add != nil {
		for x, c := range add {
			acc[x] = uint32(c)
		}
	}

	for j := range vectors {
		kemMultiplyAdd(&acc, &factors[first+j*stride], &vectors[j])
	}

	kemReduceAll(out, &acc)

	clear(acc[:])
}

// t̂_i = ê_i + sum over j of Â[i][j] ŝ[j], encoded into ek, for each row of Â sampled just before its
// products; ŝ is the factor that every row reuses.
func kemKeyGenRows(ek, rho []byte, s []kemFactor, e []kemPoly) {
	k := len(s)

	var a [4]kemPoly

	var t kemPoly

	row := []*kemPoly{&a[0], &a[1], &a[2], &a[3]}[:k]

	for i := range k {
		kemSampleRow(row, rho, i)

		kemProduct(&t, s, 0, 1, a[:k], nil, &e[i])

		kemEncode12(ek[384*i:384*(i+1)], &t)
	}

	clear(a[:])

	clear(t[:])
}

// Row i of the matrix: A[i][j] = SampleNTT(rho || j || i) for every j.
func kemSampleRow(row []*kemPoly, rho []byte, i int) {
	var positions [kemRowLanes]uint16

	for j := range row {
		positions[j] = uint16(j) | uint16(i)<<8
	}

	kemSampleNTTs(row, rho, positions[:len(row)])
}

// Rows first to first + rows - 1 of Â for k by k matrices, entry (i - first) k + j of a holding
// A[i][j] = SampleNTT(rho || j || i), a row at a time.
func kemSampleMatrix(a []kemFactor, rho []byte, first, rows, k int) {
	var row [kemRowLanes]*kemPoly

	for i := range rows {
		for j := range k {
			row[j] = &a[i*k+j].f
		}

		kemSampleRow(row[:k], rho, first+i)
	}
}

func kemSampleCBD(f *kemPoly, data []byte, eta int) {
	kemSampleCBDGeneric(f, data, eta)
}

func kemSampleNoises(polys []*kemPoly, sponges *keccakLanes, eta int) {
	kemSampleNoisesGeneric(polys, sponges, eta)
}

func kemSampleNTTs(polys []*kemPoly, rho []byte, positions []uint16) {
	kemSampleNTTsGeneric(polys, rho, positions)
}

func kemEncode12(out []byte, f *kemPoly) {
	kemEncode12Generic(out, f)
}

func kemDecode12(f *kemPoly, in []byte) {
	kemDecode12Generic(f, in)
}

func kemCheck12(in []byte) bool {
	return kemCheck12Generic(in)
}

func kemCompressU(out []byte, u, e *kemPoly, d int) {
	kemCompressUGeneric(out, u, e, d)
}

func kemCompressV(out []byte, u, e *kemPoly, m []byte, d int) {
	kemCompressVGeneric(out, u, e, m, d)
}

func kemDecompressU(u *kemPoly, in []byte, d int) {
	kemDecompressUGeneric(u, in, d)
}

func kemDecodeMessage(m, in []byte, w *kemPoly, d int) {
	kemDecodeMessageGeneric(m, in, w, d)
}

//go:build !purego

package cryptopq

// The ML-KEM kernels for AVX2 (kem_amd64.s). The products of the NTT domain run as VPMADDWD on
// pairs: with the vector side prepared once per operation as v' = (v0, v1 gamma) and v^s = (v1, v0)
// per pair, f * v is (f . v', f . v^s) pair by pair, two 16-bit products summed into 32 bits, so the
// factors of a key are kept as plain polynomials. The portable code on x86-64 computes the same way.

//go:noescape
func kemPrepareAVX2(vectors, swapped *kemPoly, n int)

//go:noescape
func kemProductAVX2(out *kemPoly, factors *[4]*kemPoly, n int, vectors, swapped, add *kemPoly)

//go:noescape
func kemCBD2AVX2(f *kemPoly, data *[128]byte)

//go:noescape
func kemCBD2StateAVX2(f *kemPoly, state *[25]uint64)

//go:noescape
func kemCBD3AVX2(f *kemPoly, data *[192]byte)

//go:noescape
func kemCompress10AVX2(out *[320]byte, u, e *kemPoly)

//go:noescape
func kemCompress11AVX2(out *[352]byte, u, e *kemPoly)

//go:noescape
func kemCompress4AVX2(out *[128]byte, u, e *kemPoly, m *[32]byte)

//go:noescape
func kemCompress5AVX2(out *[160]byte, u, e *kemPoly, m *[32]byte)

//go:noescape
func kemDecompress10AVX2(u *kemPoly, in *[320]byte)

//go:noescape
func kemDecompress11AVX2(u *kemPoly, in *[352]byte)

//go:noescape
func kemMessage4AVX2(m *[32]byte, in *[128]byte, w *kemPoly)

//go:noescape
func kemMessage5AVX2(m *[32]byte, in *[160]byte, w *kemPoly)

//go:noescape
func kemEncode12AVX2(out *[384]byte, f *kemPoly)

//go:noescape
func kemDecode12AVX2(f *kemPoly, in *[384]byte)

//go:noescape
func kemCheck12AVX2(in *[384]byte) bool

//go:noescape
func kemRejectAVX2(accepted *[kemRejectSize]uint16, count int, state *[25]uint64) int

// A factor of the products: the polynomial alone, which the products read as it is.
type kemFactor struct {
	f kemPoly
}

func (*kemFactor) prepare() {}

// The swapped halves of the prepared vectors, n of them in use; the vectors themselves hold v'.
type kemPrepared struct {
	swapped [4]kemPoly
	n       int
}

func (p *kemPrepared) wipe() {
	clear(p.swapped[:p.n])
}

// Prepares at most four vectors in place for kemProduct: pair i of a vector becomes (v0, v1 gamma_i
// mod q), and the same pair of its swapped twin (v1, v0).
func kemPrepareVectors(prepared *kemPrepared, vectors []kemPoly) {
	prepared.n = max(prepared.n, len(vectors))

	if !useAVX2 {
		kemPrepareVectorsGeneric(prepared, vectors)

		return
	}

	kemPrepareAVX2(&vectors[0], &prepared.swapped[0], len(vectors))
}

// The portable form of kemPrepareVectors.
func kemPrepareVectorsGeneric(prepared *kemPrepared, vectors []kemPoly) {
	for j := range vectors {
		v, s := &vectors[j], &prepared.swapped[j]

		for i := range 128 {
			v0, v1 := v[2*i], v[2*i+1]

			s[2*i], s[2*i+1] = v1, v0

			v[2*i+1] = kemReduce(uint32(v1) * uint32(kemGammas[i]))
		}
	}
}

// The addend of the products that have none; never written.
var kemZero kemPoly

// out = add + sum over j of factors[first + j stride] vectors[j] in the NTT domain, canonical, for
// vectors that kemPrepareVectors prepared; add may be nil.
func kemProduct(out *kemPoly, factors []kemFactor, first, stride int, vectors []kemPoly, prepared *kemPrepared, add *kemPoly) {
	if !useAVX2 {
		kemProductGeneric(out, factors, first, stride, vectors, prepared, add)

		return
	}

	var pointers [4]*kemPoly

	for j := range vectors {
		pointers[j] = &factors[first+j*stride].f
	}

	if add == nil {
		add = &kemZero
	}

	kemProductAVX2(out, &pointers, len(vectors), &vectors[0], &prepared.swapped[0], add)
}

// The portable form of kemProduct: every pair's two sums of products stay below 2^27.
func kemProductGeneric(out *kemPoly, factors []kemFactor, first, stride int, vectors []kemPoly, prepared *kemPrepared, add *kemPoly) {
	for i := range 128 {
		var even, odd uint32

		if add != nil {
			even, odd = uint32(add[2*i]), uint32(add[2*i+1])
		}

		for j := range vectors {
			f, v, s := &factors[first+j*stride].f, &vectors[j], &prepared.swapped[j]

			f0, f1 := uint32(f[2*i]), uint32(f[2*i+1])

			even += f0*uint32(v[2*i]) + f1*uint32(v[2*i+1])

			odd += f0*uint32(s[2*i]) + f1*uint32(s[2*i+1])
		}

		out[2*i], out[2*i+1] = kemReduce(even), kemReduce(odd)
	}
}

// t̂_i = ê_i + sum over j of Â[i][j] ŝ[j], encoded into ek, with ŝ prepared once as the vectors and
// the entries of Â as the factors. The entries are sampled four at a time (kemSampleMatrix), so the
// smaller matrices are sampled whole, and those of ML-KEM-1024 a row at a time.
func kemKeyGenRows(ek, rho []byte, s []kemFactor, e []kemPoly) {
	k := len(s)

	var vectors [4]kemPoly

	for j := range s {
		vectors[j] = s[j].f
	}

	var prepared kemPrepared

	kemPrepareVectors(&prepared, vectors[:k])

	batch := k

	if k == 4 {
		batch = 1
	}

	var a [9]kemFactor

	var t kemPoly

	for first := 0; first < k; first += batch {
		kemSampleMatrix(a[:batch*k], rho, first, batch, k)

		for i := range batch {
			kemProduct(&t, a[:], i*k, 1, vectors[:k], &prepared, &e[first+i])

			kemEncode12(ek[384*(first+i):384*(first+i+1)], &t)
		}
	}

	clear(vectors[:])

	clear(t[:])

	prepared.wipe()
}

// Rows first to first + rows - 1 of Â for k by k matrices, entry (i - first) k + j of a holding
// A[i][j] = SampleNTT(rho || j || i), four entries at a time whatever rows they belong to, which
// keeps every lane of the Keccak kernel busy for k = 2 and 3.
func kemSampleMatrix(a []kemFactor, rho []byte, first, rows, k int) {
	var polys [kemRowLanes]*kemPoly

	var positions [kemRowLanes]uint16

	for start := 0; start < rows*k; start += kemRowLanes {
		n := min(kemRowLanes, rows*k-start)

		for l := range n {
			x := start + l

			polys[l], positions[l] = &a[x].f, uint16(x%k)|uint16(first+x/k)<<8
		}

		kemSampleNTTs(polys[:n], rho, positions[:n])
	}
}

func kemSampleCBD(f *kemPoly, data []byte, eta int) {
	switch {
	case !useAVX2:
		kemSampleCBDGeneric(f, data, eta)
	case eta == 2:
		kemCBD2AVX2(f, (*[128]byte)(data))
	default:
		kemCBD3AVX2(f, (*[192]byte)(data))
	}
}

// For eta = 2 the 128 bytes come from one squeeze, which the kernel reads straight from the states.
func kemSampleNoises(polys []*kemPoly, sponges *keccakLanes, eta int) {
	if !useAVX2 || eta != 2 {
		kemSampleNoisesGeneric(polys, sponges, eta)

		return
	}

	sponges.squeeze()

	for l, f := range polys {
		kemCBD2StateAVX2(f, &sponges.states[l])
	}
}

// The candidates the kernel may write past the 256th: it stops after the group of sixteen that
// reaches 256, and its stores write eight entries at a time.
const kemRejectSize = 256 + 16 + 8

// kemSampleNTTs with the rejection sampling of each block in the kernel, which reads the rate bytes
// straight from the sponge states.
func kemSampleNTTs(polys []*kemPoly, rho []byte, positions []uint16) {
	if !useAVX2 {
		kemSampleNTTsGeneric(polys, rho, positions)

		return
	}

	var sponges keccakLanes

	sponges.start(168, rho, positions, 2)

	var accepted [kemRowLanes][kemRejectSize]uint16

	var counts [kemRowLanes]int

	for remaining := len(polys); remaining > 0; {
		sponges.squeeze()

		for l, f := range polys {
			if counts[l] >= 256 {
				continue
			}

			counts[l] = kemRejectAVX2(&accepted[l], counts[l], &sponges.states[l])

			if counts[l] >= 256 {
				copy(f[:], accepted[l][:256])

				remaining--
			}
		}
	}
}

func kemEncode12(out []byte, f *kemPoly) {
	if !useAVX2 {
		kemEncode12Generic(out, f)

		return
	}

	kemEncode12AVX2((*[384]byte)(out), f)
}

func kemDecode12(f *kemPoly, in []byte) {
	if !useAVX2 {
		kemDecode12Generic(f, in)

		return
	}

	kemDecode12AVX2(f, (*[384]byte)(in))
}

func kemCheck12(in []byte) bool {
	if !useAVX2 {
		return kemCheck12Generic(in)
	}

	return kemCheck12AVX2((*[384]byte)(in))
}

func kemCompressU(out []byte, u, e *kemPoly, d int) {
	switch {
	case !useAVX2:
		kemCompressUGeneric(out, u, e, d)
	case d == 10:
		kemCompress10AVX2((*[320]byte)(out), u, e)
	default:
		kemCompress11AVX2((*[352]byte)(out), u, e)
	}
}

func kemCompressV(out []byte, u, e *kemPoly, m []byte, d int) {
	switch {
	case !useAVX2:
		kemCompressVGeneric(out, u, e, m, d)
	case d == 4:
		kemCompress4AVX2((*[128]byte)(out), u, e, (*[32]byte)(m))
	default:
		kemCompress5AVX2((*[160]byte)(out), u, e, (*[32]byte)(m))
	}
}

func kemDecompressU(u *kemPoly, in []byte, d int) {
	switch {
	case !useAVX2:
		kemDecompressUGeneric(u, in, d)
	case d == 10:
		kemDecompress10AVX2(u, (*[320]byte)(in))
	default:
		kemDecompress11AVX2(u, (*[352]byte)(in))
	}
}

func kemDecodeMessage(m, in []byte, w *kemPoly, d int) {
	switch {
	case !useAVX2:
		kemDecodeMessageGeneric(m, in, w, d)
	case d == 4:
		kemMessage4AVX2((*[32]byte)(m), (*[128]byte)(in), w)
	default:
		kemMessage5AVX2((*[32]byte)(m), (*[160]byte)(in), w)
	}
}

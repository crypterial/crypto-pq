package cryptopq

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Trees above the cached height take the lower part of each authentication path from the last
// subtree they rebuilt; a plain tree that keeps every level checks both shapes with a cheap node
// function, and a leaf counter checks that consecutive paths rebuild each subtree once.
func TestMerkleTree(t *testing.T) {
	leaves := 0

	leaf := func(index uint64, out []byte) {
		var data [8]byte

		binary.BigEndian.PutUint64(data[:], index)

		sha256Finish(iv256, 0, data[:], out[:16])

		leaves++
	}

	combine := func(z int, j uint64, left, right, out []byte) {
		var data [48]byte

		binary.BigEndian.PutUint64(data[:], uint64(z))

		binary.BigEndian.PutUint64(data[8:], j)

		copy(data[16:], left)

		copy(data[32:], right)

		sha256Finish(iv256, 0, data[:], out[:16])
	}

	for _, height := range []int{3, 15, 17} {
		levels := [][]byte{make([]byte, 16<<height)}

		for i := range uint64(1) << height {
			leaf(i, levels[0][16*i:])
		}

		for z := range height {
			below := levels[z]

			level := make([]byte, len(below)/2)

			for j := range uint64(len(level) / 16) {
				combine(z, j, below[32*j:32*j+16], below[32*j+16:32*j+32], level[16*j:])
			}

			levels = append(levels, level)
		}

		path := func(index uint64) []byte {
			var expected []byte

			for z := range height {
				sibling := (index >> z) ^ 1

				expected = append(expected, levels[z][16*sibling:16*sibling+16]...)
			}

			return expected
		}

		leaves = 0

		tree := newMerkleTree(height, 16, leaf, combine)

		if !bytes.Equal(tree.root(), levels[height]) || len(tree.levels) != min(height, merkleCachedHeight)+1 || leaves != 1<<height {
			t.Fatalf("height %d: root or cache", height)
		}

		for _, index := range []uint64{0, 1, 2, 5, 1<<height - 1, 1<<height/3 + 1} {
			if !bytes.Equal(tree.authPath(index), path(index)) {
				t.Fatalf("height %d: path of leaf %d", height, index)
			}
		}

		// Two whole subtrees, then a return to the first one.
		low := tree.low

		start := uint64(1) << (height - 1)

		leaves = 0

		for index := start; index < start+2<<low; index++ {
			if !bytes.Equal(tree.authPath(index), path(index)) {
				t.Fatalf("height %d: path of leaf %d", height, index)
			}
		}

		if !bytes.Equal(tree.authPath(start), path(start)) {
			t.Fatalf("height %d: path of leaf %d again", height, start)
		}

		if want := 3 << low; low > 0 && leaves != want || low == 0 && leaves != 0 {
			t.Fatalf("height %d: %d leaves computed", height, leaves)
		}
	}
}

// An upper XMSS^MT layer's signature part is reused while its leaf stays the same: a change made
// to the kept part shows in the next signature, and the next leaf computes its own part.
func TestXmssMtPartReuse(t *testing.T) {
	p := xmssByName(xmssMtSets, "XMSSMT-SHAKE256_20/4_192")

	newSigner := func() *xmssSigner {
		seed := fuzzPattern(3*p.n, 0)

		return newXmssSigner(p, seed[:p.n], seed[p.n:2*p.n], seed[2*p.n:])
	}

	signer := newSigner()

	signer.sign(0, nil)

	part := signer.layers[1].part

	part[0] ^= 1

	changed := part[0]

	offset := p.indexSize() + p.n + (p.wotsLength()+p.treeHeight())*p.n

	if signature := signer.sign(1, nil); signature[offset] != changed {
		t.Fatal("the part was computed again")
	}

	if !bytes.Equal(signer.sign(32, nil), newSigner().sign(32, nil)) {
		t.Fatal("the part of the next leaf")
	}
}

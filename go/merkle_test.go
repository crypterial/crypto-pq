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

// A tree restored from the cached levels of a built one computes no leaf, has the same levels and
// gives the same paths: below the cached height, its first path builds the subtree under the
// leaf, chunk 0 included. Nodes that do not fill the levels, or a node that its children do not
// give, are refused.
func TestMerkleTreeRestore(t *testing.T) {
	leaf := func(index uint64, out []byte) {
		var data [8]byte

		binary.BigEndian.PutUint64(data[:], index)

		sha256Finish(iv256, 0, data[:], out[:16])
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
		built := newMerkleTree(height, 16, leaf, combine)

		nodes := built.appendNodes(nil)

		if len(nodes) != 16*built.cachedNodes() {
			t.Fatalf("height %d: %d node bytes", height, len(nodes))
		}

		restored := restoreMerkleTree(height, 16, leaf, combine, nodes)

		if restored == nil || restored.leaves != 0 || !bytes.Equal(restored.appendNodes(nil), nodes) || !bytes.Equal(restored.root(), built.root()) {
			t.Fatalf("height %d: restore", height)
		}

		clear(nodes)

		if !bytes.Equal(restored.appendNodes(nil), built.appendNodes(nil)) {
			t.Fatalf("height %d: the restored tree shares the given nodes", height)
		}

		for _, index := range []uint64{0, 1, 2, 1<<height/3 + 1, 1<<height - 1, 3} {
			if !bytes.Equal(restored.authPath(index), built.authPath(index)) {
				t.Fatalf("height %d: path of leaf %d", height, index)
			}
		}

		// Below the cached height: chunk 0, the chunks of the next two leaves, then chunk 0 again.
		if want := uint64(4) << restored.low; restored.low > 0 && restored.leaves != want || restored.low == 0 && restored.leaves != 0 {
			t.Fatalf("height %d: %d leaves computed", height, restored.leaves)
		}

		nodes = built.appendNodes(nil)

		for _, position := range []int{0, 16 << (height - built.low), len(nodes) - 1} {
			changed := bytes.Clone(nodes)

			changed[position] ^= 1

			if restoreMerkleTree(height, 16, leaf, combine, changed) != nil {
				t.Fatalf("height %d: a node changed at byte %d", height, position)
			}
		}

		if restoreMerkleTree(height, 16, leaf, combine, nodes[16:]) != nil || restoreMerkleTree(height, 16, leaf, combine, append(nodes, make([]byte, 16)...)) != nil {
			t.Fatalf("height %d: nodes of another size", height)
		}
	}
}

// An upper XMSS^MT layer's signature part is reused while its leaf stays the same: a change made
// to the kept part shows in the next signature, and the next leaf computes its own part.
func TestXmssMtPartReuse(t *testing.T) {
	p := xmssByName(xmssMtSets, "XMSSMT-SHAKE256_20/4_192")

	newSigner := func() *xmssSigner {
		seed := fuzzPattern(3*p.n, 0)

		return newXmssSigner(p, seed[:p.n], seed[p.n:2*p.n], seed[2*p.n:], nil)
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

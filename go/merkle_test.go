package cryptopq

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Trees above the cached height rebuild a subtree for every authentication path; a plain tree
// that keeps every level checks both shapes with a cheap node function.
func TestMerkleTree(t *testing.T) {
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

		tree := newMerkleTree(height, 16, leaf, combine)

		if !bytes.Equal(tree.root(), levels[height]) || len(tree.levels) != min(height, merkleCachedHeight)+1 {
			t.Fatalf("height %d: root or cache", height)
		}

		for _, index := range []uint64{0, 1, 2, 5, 1<<height - 1, 1<<height/3 + 1} {
			var expected []byte

			for z := range height {
				sibling := (index >> z) ^ 1

				expected = append(expected, levels[z][16*sibling:16*sibling+16]...)
			}

			if !bytes.Equal(tree.authPath(index), expected) {
				t.Fatalf("height %d: path of leaf %d", height, index)
			}
		}
	}
}

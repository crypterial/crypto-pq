package cryptopq

import "bytes"

const merkleCachedHeight = 15

// A Merkle tree that keeps its nodes from height low = max(0, h - 15) upwards, plus every level of
// the 2^low-leaf subtree it built last. Building it computes every leaf once. An authentication
// path takes its upper nodes from the cache and its lower ones from the subtree under the signed
// leaf, which is rebuilt only when the leaf leaves the kept one: consecutive signatures rebuild it
// once per 2^low leaves instead of once each. Memory stays below 2^16 + 2^(low+1) nodes, while
// trees of height 15 or less never recompute a leaf. Nodes are n bytes; combine(z, j, ...) joins
// two nodes of height z into node j of height z + 1. leaves counts the leaves the tree computed,
// which tests read to see that a tree from a tree cache computes none.
type merkleTree struct {
	height, low, n int
	levels         [][]byte
	bottom         []byte
	chunk          uint64
	leaves         uint64
	leaf           func(index uint64, out []byte)
	combine        func(z int, j uint64, left, right, out []byte)
}

func emptyMerkleTree(height, n int, leaf func(uint64, []byte), combine func(int, uint64, []byte, []byte, []byte)) *merkleTree {
	low := max(0, height-merkleCachedHeight)

	return &merkleTree{height: height, low: low, n: n, bottom: make([]byte, (2<<low-1)*n), leaf: leaf, combine: combine}
}

func newMerkleTree(height, n int, leaf func(uint64, []byte), combine func(int, uint64, []byte, []byte, []byte)) *merkleTree {
	t := emptyMerkleTree(height, n, leaf, combine)

	chunks := 1 << (height - t.low)

	nodes := make([]byte, chunks*n)

	for chunk := range chunks {
		t.build(uint64(chunk))

		copy(nodes[chunk*n:], t.bottom[len(t.bottom)-n:])
	}

	t.levels = [][]byte{nodes}

	for z := t.low; z < height; z++ {
		above := make([]byte, len(nodes)/2)

		t.parents(nodes, above, z, 0)

		nodes = above

		t.levels = append(t.levels, nodes)
	}

	return t
}

// The tree whose cached levels a tree cache holds: nodes are the levels from height low up, each
// left to right. Every parent is recomputed from its children, so only the nodes at height low
// are taken as given, and the tree keeps its own copy of them. The result is nil when the nodes
// do not fill the levels or a parent differs from the one its children give.
func restoreMerkleTree(height, n int, leaf func(uint64, []byte), combine func(int, uint64, []byte, []byte, []byte), nodes []byte) *merkleTree {
	t := emptyMerkleTree(height, n, leaf, combine)

	if len(nodes) != t.cachedNodes()*n {
		return nil
	}

	// No chunk has this number, so the first path below low builds its subtree.
	t.chunk = ^uint64(0)

	nodes = bytes.Clone(nodes)

	for z := t.low; z <= height; z++ {
		size := n << (height - z)

		t.levels = append(t.levels, nodes[:size:size])

		nodes = nodes[size:]
	}

	parent := make([]byte, n)

	for z := t.low; z < height; z++ {
		children, above := t.levels[z-t.low], t.levels[z-t.low+1]

		for j := range len(above) / n {
			combine(z, uint64(j), children[2*j*n:(2*j+1)*n], children[(2*j+1)*n:(2*j+2)*n], parent)

			if !bytes.Equal(parent, above[j*n:(j+1)*n]) {
				return nil
			}
		}
	}

	return t
}

// How many nodes the cached levels hold: 2^(height - low + 1) - 1.
func (t *merkleTree) cachedNodes() int {
	return 2<<(t.height-t.low) - 1
}

// The cached levels as a tree cache lists them, from height low up, each left to right.
func (t *merkleTree) appendNodes(out []byte) []byte {
	for _, level := range t.levels {
		out = append(out, level...)
	}

	return out
}

func (t *merkleTree) parents(nodes, out []byte, z int, offset uint64) {
	n := t.n

	for j := range len(out) / n {
		t.combine(z, offset+uint64(j), nodes[2*j*n:(2*j+1)*n], nodes[(2*j+1)*n:(2*j+2)*n], out[j*n:(j+1)*n])
	}
}

func (t *merkleTree) root() []byte {
	return t.levels[len(t.levels)-1]
}

// Fills bottom with every level of the 2^low-leaf subtree number chunk, from its 2^low leaves up
// to its root, each level right after the one below it.
func (t *merkleTree) build(chunk uint64) {
	n := t.n

	base := chunk << t.low

	level := t.bottom[:n<<t.low]

	for i := range 1 << t.low {
		t.leaf(base+uint64(i), level[i*n:(i+1)*n])
	}

	t.leaves += 1 << t.low

	start := 0

	for z := range t.low {
		above := t.bottom[start+len(level) : start+len(level)+len(level)/2]

		t.parents(level, above, z, base>>(z+1))

		start += len(level)

		level = above
	}

	t.chunk = chunk
}

func (t *merkleTree) authPath(index uint64) []byte {
	n := t.n

	path := make([]byte, 0, t.height*n)

	if t.low > 0 {
		if index>>t.low != t.chunk {
			t.build(index >> t.low)
		}

		start := 0

		for z := range t.low {
			sibling := start + int((index>>z^1)&(1<<(t.low-z)-1))

			path = append(path, t.bottom[sibling*n:(sibling+1)*n]...)

			start += 1 << (t.low - z)
		}
	}

	for z := t.low; z < t.height; z++ {
		sibling := (index >> z) ^ 1

		path = append(path, t.levels[z-t.low][sibling*uint64(n):(sibling+1)*uint64(n)]...)
	}

	return path
}

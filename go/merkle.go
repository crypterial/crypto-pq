package cryptopq

const merkleCachedHeight = 15

// A Merkle tree that keeps its nodes from height low = max(0, h - 15) upwards. Building it
// computes every leaf once. An authentication path takes its upper nodes from the cache and
// rebuilds only the 2^low-leaf subtree under the signed leaf, so memory stays below 2^16 nodes
// for every height while trees of height 15 or less never recompute a leaf. Nodes are n bytes;
// combine(z, j, ...) joins two nodes of height z into node j of height z + 1.
type merkleTree struct {
	height, low, n int
	levels         [][]byte
	leaf           func(index uint64, out []byte)
	combine        func(z int, j uint64, left, right, out []byte)
}

func newMerkleTree(height, n int, leaf func(uint64, []byte), combine func(int, uint64, []byte, []byte, []byte)) *merkleTree {
	t := &merkleTree{height: height, low: max(0, height-merkleCachedHeight), n: n, leaf: leaf, combine: combine}

	chunks := 1 << (height - t.low)

	nodes := make([]byte, chunks*n)

	for chunk := range chunks {
		levels := t.subtree(uint64(chunk))

		copy(nodes[chunk*n:], levels[t.low])
	}

	t.levels = [][]byte{nodes}

	for z := t.low; z < height; z++ {
		nodes = t.parents(nodes, z, 0)

		t.levels = append(t.levels, nodes)
	}

	return t
}

func (t *merkleTree) parents(nodes []byte, z int, offset uint64) []byte {
	n := t.n

	out := make([]byte, len(nodes)/2)

	for j := range len(out) / n {
		t.combine(z, offset+uint64(j), nodes[2*j*n:(2*j+1)*n], nodes[(2*j+1)*n:(2*j+2)*n], out[j*n:(j+1)*n])
	}

	return out
}

func (t *merkleTree) root() []byte {
	return t.levels[len(t.levels)-1]
}

// Every level of the 2^low-leaf subtree number chunk, from its leaves to its root.
func (t *merkleTree) subtree(chunk uint64) [][]byte {
	n := t.n

	base := chunk << t.low

	level := make([]byte, n<<t.low)

	for i := range 1 << t.low {
		t.leaf(base+uint64(i), level[i*n:(i+1)*n])
	}

	levels := [][]byte{level}

	for z := range t.low {
		level = t.parents(level, z, base>>(z+1))

		levels = append(levels, level)
	}

	return levels
}

func (t *merkleTree) authPath(index uint64) []byte {
	n := t.n

	path := make([]byte, 0, t.height*n)

	if t.low > 0 {
		levels := t.subtree(index >> t.low)

		for z := range t.low {
			sibling := ((index >> z) ^ 1) & (1<<(t.low-z) - 1)

			path = append(path, levels[z][sibling*uint64(n):(sibling+1)*uint64(n)]...)
		}
	}

	for z := t.low; z < t.height; z++ {
		sibling := (index >> z) ^ 1

		path = append(path, t.levels[z-t.low][sibling*uint64(n):(sibling+1)*uint64(n)]...)
	}

	return path
}

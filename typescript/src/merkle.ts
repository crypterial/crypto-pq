const CACHED_HEIGHT = 15;

export type Leaf = (index: number) => Uint8Array;

export type Combine = (z: number, j: number, left: Uint8Array, right: Uint8Array) => Uint8Array;

// A Merkle tree of n-byte nodes that keeps every node from height low = max(0, h - 15) upwards, one
// buffer per level rather than one object per node, so that it holds fewer than 2^16 nodes whatever
// its height. Building it computes every leaf once. Below low, an authentication path takes its
// nodes from the 2^low-leaf subtree under the signed leaf; the tree keeps the last subtree it
// rebuilt, so that consecutive leaves share one rebuild, and a tree of height 15 or less never
// recomputes a leaf.
export class MerkleTree {
  readonly height: number;

  readonly low: number;

  readonly root: Uint8Array;

  readonly #n: number;

  // Entry z - low holds the 2^(height - z) nodes at height z, for z from low to height.
  readonly #levels: Uint8Array[] = [];

  // Entry z holds the nodes at height z of the subtree under node #chunk at height low; #chunk is
  // -1 while they belong to no subtree.
  readonly #bottom: Uint8Array[] = [];

  #chunk = -1;

  readonly #leaf: Leaf;

  readonly #combine: Combine;

  constructor(height: number, n: number, leaf: Leaf, combine: Combine) {
    this.height = height;

    this.low = Math.max(0, height - CACHED_HEIGHT);

    this.#n = n;

    this.#leaf = leaf;

    this.#combine = combine;

    for (let z = 0; z < this.low; z++) {
      this.#bottom.push(new Uint8Array(2 ** (this.low - z) * n));
    }

    let level = new Uint8Array(2 ** (height - this.low) * n);

    for (let chunk = 0; chunk < 2 ** (height - this.low); chunk++) {
      level.set(this.#subtree(chunk), chunk * n);
    }

    this.#levels.push(level);

    for (let z = this.low; z < height; z++) {
      const parents = new Uint8Array(level.length / 2);

      combineLevel(combine, z, 0, level, parents, n);

      level = parents;

      this.#levels.push(level);
    }

    this.root = level;
  }

  // The node at height low over the leaves from chunk * 2^low on: the leaf itself when low is 0,
  // and otherwise the root of the subtree that this rebuilds into #bottom.
  #subtree(chunk: number): Uint8Array {
    const n = this.#n;

    const low = this.low;

    if (low === 0) {
      return this.#leaf(chunk);
    }

    const bottom = this.#bottom;

    const root = new Uint8Array(n);

    this.#chunk = -1;

    for (let i = 0; i < 2 ** low; i++) {
      bottom[0].set(this.#leaf(chunk * 2 ** low + i), i * n);
    }

    for (let z = 0; z < low; z++) {
      combineLevel(this.#combine, z, chunk * 2 ** (low - z - 1), bottom[z], z + 1 < low ? bottom[z + 1] : root, n);
    }

    this.#chunk = chunk;

    return root;
  }

  // The siblings of the path from a leaf to the root, n bytes each, from height 0 up.
  authPath(index: number): Uint8Array {
    const n = this.#n;

    const low = this.low;

    const path = new Uint8Array(this.height * n);

    if (low > 0 && index >>> low !== this.#chunk) {
      this.#subtree(index >>> low);
    }

    for (let z = 0; z < this.height; z++) {
      const sibling = (index >>> z) ^ 1;

      const level = z < low ? this.#bottom[z] : this.#levels[z - low];

      // Below low, nodes are numbered within the kept subtree.
      const position = z < low ? sibling & ((1 << (low - z)) - 1) : sibling;

      path.set(level.subarray(position * n, (position + 1) * n), z * n);
    }

    return path;
  }
}

// Writes the parents of the nodes in children, which lie at height z, into parents; the first
// parent has index first at height z + 1.
function combineLevel(
  combine: Combine,
  z: number,
  first: number,
  children: Uint8Array,
  parents: Uint8Array,
  n: number,
): void {
  for (let j = 0; j < parents.length / n; j++) {
    const left = children.subarray(2 * j * n, (2 * j + 1) * n);

    const right = children.subarray((2 * j + 1) * n, (2 * j + 2) * n);

    parents.set(combine(z, first + j, left, right), j * n);
  }
}

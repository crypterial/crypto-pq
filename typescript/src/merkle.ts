import { concat } from "./bytes.ts";
import { invalid } from "./encoding.ts";

export const CACHED_HEIGHT = 15;

// The hashes of a tree's nodes, which write each node where the tree keeps it.
export interface TreeHashes {
  // Leaf index, into out[offset .. offset + n).
  leaf(index: number, out: Uint8Array, offset: number): void;

  // The count nodes from index first on at height z + 1, into out from offset on, from their children,
  // which lie in order from children[from] on.
  combine(
    z: number,
    first: number,
    count: number,
    children: Uint8Array,
    from: number,
    out: Uint8Array,
    offset: number,
  ): void;
}

// The levels of a tree in a tree cache, from height low up: its number on its level or layer, and
// each level's nodes left to right.
export type CachedLevels = readonly [bigint, readonly Uint8Array[]];

// A tree that a key holds, as a tree cache lists it.
export interface CachedTree {
  readonly level: number;

  readonly tree: bigint;

  readonly merkle: MerkleTree;
}

// The leaves that every tree has computed, which tests read to see that a tree from a cache
// computes none.
let computed = 0;

export function leavesComputed(): number {
  return computed;
}

// The parents that the check of a tree cache recomputes at a time.
const CHECKED = 64;

// A Merkle tree of n-byte nodes that keeps every node from height low = max(0, h - 15) upwards, one
// buffer per level rather than one object per node, so that it holds fewer than 2^16 nodes whatever
// its height. Building it computes every leaf once. Below low, an authentication path takes its
// nodes from the 2^low-leaf subtree under the signed leaf; the tree keeps the last subtree it
// rebuilt, so that consecutive leaves share one rebuild, and a tree of height 15 or less never
// recomputes a leaf. The levels of a tree cache replace the build, and the tree keeps them: every
// parent is recomputed from its children, so only the nodes at height low are taken as given.
export class MerkleTree {
  readonly height: number;

  readonly low: number;

  readonly n: number;

  readonly root: Uint8Array;

  // Entry z - low holds the 2^(height - z) nodes at height z, for z from low to height.
  readonly #levels: Uint8Array[] = [];

  // Entry z holds the nodes at height z of the subtree under node #chunk at height low; #chunk is
  // -1 while they belong to no subtree.
  readonly #bottom: Uint8Array[] = [];

  #chunk = -1;

  readonly #hashes: TreeHashes;

  constructor(height: number, n: number, hashes: TreeHashes, levels?: readonly Uint8Array[]) {
    this.height = height;

    this.low = Math.max(0, height - CACHED_HEIGHT);

    this.n = n;

    this.#hashes = hashes;

    for (let z = 0; z < this.low; z++) {
      this.#bottom.push(new Uint8Array(2 ** (this.low - z) * n));
    }

    if (levels === undefined) {
      this.#build();
    } else {
      this.#restore(levels);
    }

    this.root = this.#levels[this.#levels.length - 1];
  }

  #build(): void {
    const n = this.n;

    let level = new Uint8Array(2 ** (this.height - this.low) * n);

    for (let chunk = 0; chunk < 2 ** (this.height - this.low); chunk++) {
      this.#subtree(chunk, level, chunk * n);
    }

    this.#levels.push(level);

    for (let z = this.low; z < this.height; z++) {
      const parents = new Uint8Array(level.length / 2);

      this.#hashes.combine(z, 0, parents.length / n, level, 0, parents, 0);

      level = parents;

      this.#levels.push(level);
    }
  }

  #restore(levels: readonly Uint8Array[]): void {
    const n = this.n;

    const scratch = new Uint8Array(CHECKED * n);

    for (let z = this.low; z < this.height; z++) {
      const parents = levels[z - this.low + 1];

      const count = parents.length / n;

      for (let first = 0; first < count; first += CHECKED) {
        const size = Math.min(CHECKED, count - first) * n;

        this.#hashes.combine(z, first, size / n, levels[z - this.low], 2 * first * n, scratch, 0);

        for (let i = 0; i < size; i++) {
          if (scratch[i] !== parents[first * n + i]) {
            throw invalid("the tree cache holds a node that its children do not give");
          }
        }
      }
    }

    this.#levels.push(...levels);
  }

  // The node at height low over the leaves from chunk * 2^low on, into out at offset: the leaf itself
  // when low is 0, and otherwise the root of the subtree that this rebuilds into #bottom. Without
  // out, only #bottom is rebuilt.
  #subtree(chunk: number, out: Uint8Array | null, offset: number): void {
    const n = this.n;

    const low = this.low;

    const hashes = this.#hashes;

    computed += 2 ** low;

    if (low === 0) {
      hashes.leaf(chunk, out as Uint8Array, offset);

      return;
    }

    const bottom = this.#bottom;

    this.#chunk = -1;

    for (let i = 0; i < 2 ** low; i++) {
      hashes.leaf(chunk * 2 ** low + i, bottom[0], i * n);
    }

    for (let z = 0; z + 1 < low; z++) {
      hashes.combine(z, chunk * 2 ** (low - z - 1), 2 ** (low - z - 1), bottom[z], 0, bottom[z + 1], 0);
    }

    if (out !== null) {
      hashes.combine(low - 1, chunk, 1, bottom[low - 1], 0, out, offset);
    }

    this.#chunk = chunk;
  }

  // The siblings of the path from a leaf to the root, n bytes each from height 0 up, into out from
  // offset on.
  authPath(index: number, out: Uint8Array, offset: number): void {
    const n = this.n;

    const low = this.low;

    if (low > 0 && index >>> low !== this.#chunk) {
      this.#subtree(index >>> low, null, 0);
    }

    for (let z = 0; z < this.height; z++) {
      const sibling = (index >>> z) ^ 1;

      const level = z < low ? this.#bottom[z] : this.#levels[z - low];

      // Below low, nodes are numbered within the kept subtree.
      const position = z < low ? sibling & ((1 << (low - z)) - 1) : sibling;

      for (let i = 0; i < n; i++) {
        out[offset + z * n + i] = level[position * n + i];
      }
    }
  }

  // The cached nodes as a tree cache lists them: level by level from height low, left to right.
  nodes(): Uint8Array {
    return concat(...this.#levels);
  }
}

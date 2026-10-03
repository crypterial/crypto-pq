const CACHED_HEIGHT = 15;

export type Leaf = (index: number) => Uint8Array;

export type Combine = (z: number, j: number, left: Uint8Array, right: Uint8Array) => Uint8Array;

// A Merkle tree that keeps its nodes from height low = max(0, h - 15) upwards. Building it computes
// every leaf once. An authentication path takes its upper nodes from the cache and rebuilds only
// the 2^low-leaf subtree under the signed leaf, so memory stays below 2^16 nodes for every height
// while trees of height 15 or less never recompute a leaf.
export class MerkleTree {
  readonly height: number;

  readonly low: number;

  readonly root: Uint8Array;

  readonly #levels: Uint8Array[][];

  readonly #leaf: Leaf;

  readonly #combine: Combine;

  constructor(height: number, leaf: Leaf, combine: Combine) {
    this.height = height;

    this.low = Math.max(0, height - CACHED_HEIGHT);

    this.#leaf = leaf;

    this.#combine = combine;

    let nodes: Uint8Array[] = [];

    for (let chunk = 0; chunk < 2 ** (height - this.low); chunk++) {
      nodes.push(this.#subtree(chunk)[this.low][0]);
    }

    this.#levels = [nodes];

    for (let z = this.low; z < height; z++) {
      nodes = pairs(nodes, (j, left, right) => combine(z, j, left, right));

      this.#levels.push(nodes);
    }

    this.root = nodes[0];
  }

  #subtree(chunk: number): Uint8Array[][] {
    const base = chunk * 2 ** this.low;

    let level: Uint8Array[] = [];

    for (let i = 0; i < 2 ** this.low; i++) {
      level.push(this.#leaf(base + i));
    }

    const levels = [level];

    for (let z = 0; z < this.low; z++) {
      const offset = Math.floor(base / 2 ** (z + 1));

      level = pairs(level, (j, left, right) => this.#combine(z, offset + j, left, right));

      levels.push(level);
    }

    return levels;
  }

  authPath(index: number): Uint8Array[] {
    const path: Uint8Array[] = [];

    if (this.low > 0) {
      const levels = this.#subtree(Math.floor(index / 2 ** this.low));

      for (let z = 0; z < this.low; z++) {
        path.push(levels[z][((index >>> z) ^ 1) & ((1 << (this.low - z)) - 1)]);
      }
    }

    for (let z = this.low; z < this.height; z++) {
      path.push(this.#levels[z - this.low][(index >>> z) ^ 1]);
    }

    return path;
  }
}

function pairs(
  nodes: Uint8Array[],
  combine: (j: number, left: Uint8Array, right: Uint8Array) => Uint8Array,
): Uint8Array[] {
  const out: Uint8Array[] = [];

  for (let j = 0; j < nodes.length / 2; j++) {
    out.push(combine(j, nodes[2 * j], nodes[2 * j + 1]));
  }

  return out;
}

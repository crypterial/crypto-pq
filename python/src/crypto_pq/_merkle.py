CACHED_HEIGHT = 15

# Leaves per request when the tree is taller than the cache, so that each request still batches
# many hashes.
BATCH = 1024


class MerkleTree:
    """A Merkle tree that keeps its nodes from height `low` upwards, where low = max(0, h - 15).

    Building it computes every leaf once. An authentication path takes its upper nodes from the
    cache and rebuilds only the 2^low-leaf subtree under the signed leaf, so memory stays below
    2^16 nodes for every height while trees of height 15 or less never recompute a leaf.

    leaves(first, count) returns the leaves first .. first + count - 1, and combine(z, first,
    lefts, rights) the parents at height z + 1, numbered from `first`, of the pairs of nodes at
    height z, so that both can hash many nodes at once.
    """

    __slots__ = ("height", "low", "levels", "root", "_leaves", "_combine")

    def __init__(self, height, leaves, combine):
        self.height = height

        self.low = max(0, height - CACHED_HEIGHT)

        self._leaves = leaves

        self._combine = combine

        total = 1 << (height - self.low)

        per_request = max(1, BATCH >> self.low) if self.low else total

        nodes = []

        for first in range(0, total, per_request):
            nodes += self._subtrees(first, min(per_request, total - first))[-1]

        self.levels = [nodes]

        for z in range(self.low, height):
            nodes = combine(z, 0, nodes[0::2], nodes[1::2])

            self.levels.append(nodes)

        self.root = nodes[0]

    # Every level up to height `low` of `count` consecutive subtrees of 2^low leaves.
    def _subtrees(self, first, count):
        base = first << self.low

        level = self._leaves(base, count << self.low)

        levels = [level]

        for z in range(self.low):
            level = self._combine(z, base >> (z + 1), level[0::2], level[1::2])

            levels.append(level)

        return levels

    def auth_path(self, index):
        path = []

        if self.low:
            levels = self._subtrees(index >> self.low, 1)

            for z in range(self.low):
                path.append(levels[z][((index >> z) ^ 1) & ((1 << (self.low - z)) - 1)])

        for z in range(self.low, self.height):
            path.append(self.levels[z - self.low][(index >> z) ^ 1])

        return path

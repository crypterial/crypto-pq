CACHED_HEIGHT = 15


class MerkleTree:
    """A Merkle tree that keeps its nodes from height `low` upwards, where low = max(0, h - 15).

    Building it computes every leaf once. An authentication path takes its upper nodes from the
    cache and rebuilds only the 2^low-leaf subtree under the signed leaf, so memory stays below
    2^16 nodes for every height while trees of height 15 or less never recompute a leaf.
    """

    __slots__ = ("height", "low", "levels", "root", "_leaf", "_combine")

    def __init__(self, height, leaf, combine):
        self.height = height

        self.low = max(0, height - CACHED_HEIGHT)

        self._leaf = leaf

        self._combine = combine

        nodes = [self._subtree(chunk)[-1][0] for chunk in range(1 << (height - self.low))]

        self.levels = [nodes]

        for z in range(self.low, height):
            nodes = [combine(z, j, nodes[2 * j], nodes[2 * j + 1]) for j in range(len(nodes) // 2)]

            self.levels.append(nodes)

        self.root = nodes[0]

    def _subtree(self, chunk):
        base = chunk << self.low

        level = [self._leaf(base + i) for i in range(1 << self.low)]

        levels = [level]

        for z in range(self.low):
            offset = base >> (z + 1)

            level = [self._combine(z, offset + j, level[2 * j], level[2 * j + 1]) for j in range(len(level) // 2)]

            levels.append(level)

        return levels

    def auth_path(self, index):
        path = []

        if self.low:
            levels = self._subtree(index >> self.low)

            for z in range(self.low):
                path.append(levels[z][((index >> z) ^ 1) & ((1 << (self.low - z)) - 1)])

        for z in range(self.low, self.height):
            path.append(self.levels[z - self.low][(index >> z) ^ 1])

        return path

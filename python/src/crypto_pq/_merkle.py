from ._encoding import invalid

CACHED_HEIGHT = 15

# Leaves per request when the tree is taller than the cache, which bounds the leaves that one
# request holds.
BATCH = 1024


class MerkleTree:
    """A Merkle tree that keeps its nodes from height `low` upwards, where low = max(0, h - 15),
    each level as one bytes object rather than one object per node.

    Building it computes every leaf once. An authentication path takes its upper nodes from the
    cache and its lower ones from the 2^low-leaf subtree under the signed leaf. The last such
    subtree is kept, so the consecutive leaves that signatures use rebuild it once rather than
    once per signature. Memory stays below 2^16 + 2^(low + 1) nodes for every height, and trees
    of height 15 or less never recompute a leaf.

    leaves(first, count) returns the leaves first .. first + count - 1, and combine(z, first,
    lefts, rights) the parents at height z + 1, numbered from `first`, of the pairs of nodes at
    height z, so that both can hash many nodes at once.

    `levels`, the cached levels of an exported tree from height `low` up, replaces the build: every
    parent is recomputed from its children, so only the nodes at height `low` are taken as given.
    """

    __slots__ = ("height", "low", "size", "levels", "root", "_leaves", "_combine", "_kept")

    def __init__(self, height, leaves, combine, levels=None):
        self.height = height

        self.low = max(0, height - CACHED_HEIGHT)

        self._leaves = leaves

        self._combine = combine

        self._kept = None

        if levels is None:
            levels = self._build()
        else:
            self._check(levels)

        self.levels = levels

        self.size = len(levels[-1])

        self.root = levels[-1]

    def _build(self):
        total = 1 << (self.height - self.low)

        per_request = max(1, BATCH >> self.low) if self.low else total

        nodes = []

        for first in range(0, total, per_request):
            nodes += self._subtrees(first, min(per_request, total - first))[-1]

        levels = [b"".join(nodes)]

        for z in range(self.low, self.height):
            nodes = self._combine(z, 0, nodes[0::2], nodes[1::2])

            levels.append(b"".join(nodes))

        return levels

    def _check(self, levels):
        size = len(levels[-1])

        for z in range(self.low, self.height):
            level = levels[z - self.low]

            nodes = [level[i : i + size] for i in range(0, len(level), size)]

            if b"".join(self._combine(z, 0, nodes[0::2], nodes[1::2])) != levels[z - self.low + 1]:
                raise invalid("the tree cache holds a node that its children do not give")

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
        low, size = self.low, self.size

        path = []

        if low:
            chunk = index >> low

            # The subtree and its number change in one assignment, so an interrupted rebuild
            # leaves the previous pair intact.
            if self._kept is None or self._kept[0] != chunk:
                self._kept = chunk, [b"".join(level) for level in self._subtrees(chunk, 1)[:-1]]

            subtree = self._kept[1]

            for z in range(low):
                i = ((index >> z) ^ 1) & ((1 << (low - z)) - 1)

                path.append(subtree[z][i * size : (i + 1) * size])

        for z in range(low, self.height):
            i = (index >> z) ^ 1

            path.append(self.levels[z - low][i * size : (i + 1) * size])

        return path

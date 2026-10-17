from ._bytes import Output
from ._encoding import invalid

CACHED_HEIGHT = 15

# Leaves per request, which bounds the leaves that one request holds, and pairs per check of a
# cached level.
BATCH = 256


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

    # Each request's subtrees are hashed up to their common root, their levels written in place
    # into the cached levels; the levels above come from those roots.
    def _build(self):
        low, height = self.low, self.height

        total = 1 << (height - low)

        per_request = min(total, max(1, BATCH >> low))

        top = per_request.bit_length() - 1

        levels, roots = [], []

        for first in range(0, total, per_request):
            nodes = self._subtrees(first, per_request)[-1]

            if not levels:
                size = len(nodes[0])

                levels = [Output((total >> r) * size) for r in range(height - low + 1)]

            for r in range(top + 1):
                start = (first >> r) * size

                levels[r].view[start : start + len(nodes) * size] = b"".join(nodes)

                if r < top:
                    nodes = self._combine(low + r, first >> (r + 1), nodes[0::2], nodes[1::2])

            roots.append(nodes[0])

        for r in range(top, height - low):
            roots = self._combine(low + r, 0, roots[0::2], roots[1::2])

            levels[r + 1].view[:] = b"".join(roots)

        return [level.finish() for level in levels]

    def _check(self, levels):
        size = len(levels[-1])

        for z in range(self.low, self.height):
            level, parents = levels[z - self.low], levels[z - self.low + 1]

            for start in range(0, len(level), 2 * BATCH * size):
                nodes = [level[i : i + size] for i in range(start, min(start + 2 * BATCH * size, len(level)), size)]

                first = start // (2 * size)

                if b"".join(self._combine(z, first, nodes[0::2], nodes[1::2])) != parents[first * size : (first + len(nodes) // 2) * size]:
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

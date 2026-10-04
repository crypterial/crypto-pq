import unittest

from crypto_pq._merkle import MerkleTree

MODULUS = (1 << 61) - 1


def leaf(index):
    return ((index * 0x9E3779B97F4A7C15 + 1) % MODULUS).to_bytes(8, "big")


def node(z, index, left, right):
    return ((int.from_bytes(left, "big") * 1000003 + int.from_bytes(right, "big") * 999983 + z * 65537 + index) % MODULUS).to_bytes(8, "big")


def full_tree(height):
    levels = [[leaf(i) for i in range(1 << height)]]

    for z in range(height):
        levels.append([node(z, j, levels[z][2 * j], levels[z][2 * j + 1]) for j in range(len(levels[z]) // 2)])

    return levels


class MerkleTreeTest(unittest.TestCase):
    # The cache keeps only the upper levels of trees taller than 15, and their auth paths rebuild
    # a subtree; 8-byte integer "hashes" make a full tree of height 17 cheap enough to compare
    # against.
    def setUp(self):
        self.requests = []

    def leaves(self, first, count):
        self.requests.append((first, count))

        return [leaf(i) for i in range(first, first + count)]

    def combine(self, z, first, lefts, rights):
        return [node(z, first + j, a, b) for j, (a, b) in enumerate(zip(lefts, rights))]

    def test_against_full_tree(self):
        for height in (1, 4, 15, 17):
            with self.subTest(height=height):
                self.requests.clear()

                tree = MerkleTree(height, self.leaves, self.combine)

                levels = full_tree(height)

                self.assertEqual(tree.root, levels[-1][0])

                self.assertLessEqual(max(count for _, count in self.requests), max(1 << 15, 1024))

                # One bytes object per cached level, from height max(0, h - 15) up to the root.
                top = min(height, 15)

                self.assertEqual([len(level) for level in tree.levels], [8 << (top - z) for z in range(top + 1)])

                for index in {0, 1, (1 << height) // 3, (1 << height) - 1}:
                    self.assertEqual(tree.auth_path(index), [levels[z][(index >> z) ^ 1] for z in range(height)])

    # Consecutive leaves of a tall tree share the subtree under them, which is rebuilt only when
    # a leaf of another subtree signs.
    def test_kept_subtree(self):
        tree = MerkleTree(17, self.leaves, self.combine)

        levels = full_tree(17)

        self.requests.clear()

        for index in (8, 9, 10, 11, 12, 15, 13, 8, 0):
            self.assertEqual(tree.auth_path(index), [levels[z][(index >> z) ^ 1] for z in range(17)])

        self.assertEqual(self.requests, [(8, 4), (12, 4), (8, 4), (0, 4)])


if __name__ == "__main__":
    unittest.main()

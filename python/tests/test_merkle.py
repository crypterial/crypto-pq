import unittest

from crypto_pq._merkle import MerkleTree

MODULUS = (1 << 61) - 1


def leaf(index):
    return (index * 0x9E3779B97F4A7C15 + 1) % MODULUS


def node(z, index, left, right):
    return (left * 1000003 + right * 999983 + z * 65537 + index) % MODULUS


class MerkleTreeTest(unittest.TestCase):
    # The cache keeps only the upper levels of trees taller than 15, and their auth paths rebuild
    # a subtree; integer "hashes" make a full tree of height 17 cheap enough to compare against.
    def test_against_full_tree(self):
        for height in (1, 4, 15, 17):
            with self.subTest(height=height):
                requests = []

                def leaves(first, count):
                    requests.append(count)

                    return [leaf(i) for i in range(first, first + count)]

                def combine(z, first, lefts, rights):
                    return [node(z, first + j, a, b) for j, (a, b) in enumerate(zip(lefts, rights))]

                tree = MerkleTree(height, leaves, combine)

                levels = [[leaf(i) for i in range(1 << height)]]

                for z in range(height):
                    levels.append([node(z, j, levels[z][2 * j], levels[z][2 * j + 1]) for j in range(len(levels[z]) // 2)])

                self.assertEqual(tree.root, levels[-1][0])

                self.assertLessEqual(max(requests), max(1 << 15, 1024))

                for index in {0, 1, (1 << height) // 3, (1 << height) - 1}:
                    self.assertEqual(tree.auth_path(index), [levels[z][(index >> z) ^ 1] for z in range(height)])


if __name__ == "__main__":
    unittest.main()

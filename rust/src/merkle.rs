use alloc::vec;
use alloc::vec::Vec;

pub(crate) type Node = [u8; 32];

const CACHED_HEIGHT: u32 = 15;

// Leaves are requested at least this many at a time (2^4), so that hashers can compute them side
// by side.
const LEAF_BATCH: u32 = 4;

pub(crate) trait TreeHasher {
    // The leaves first, first + 1, ... filling out.
    fn leaves(&self, first: u32, out: &mut [Node]);

    // The parent at height + 1 and position index of two nodes at height.
    fn combine(&self, height: u32, index: u32, left: &Node, right: &Node) -> Node;
}

// A Merkle tree that keeps its nodes from height low = max(0, h - 15) upwards. Building it
// computes every leaf once. An authentication path takes its upper nodes from the cache and
// rebuilds only the 2^low-leaf subtree under the signed leaf, so memory stays below 2^16 nodes
// for every height while trees of height 15 or less never recompute a leaf.
pub(crate) struct MerkleTree {
    height: u32,
    low: u32,
    levels: Vec<Vec<Node>>,
}

impl MerkleTree {
    pub(crate) fn new(height: u32, hasher: &impl TreeHasher) -> Self {
        let low = height.saturating_sub(CACHED_HEIGHT);

        let mut tree = Self {
            height,
            low,
            levels: Vec::with_capacity((height - low + 1) as usize),
        };

        let batch = low.max(LEAF_BATCH).min(height);

        let mut nodes = Vec::with_capacity(1 << (height - low));

        for first in (0..1 << height).step_by(1 << batch) {
            nodes.extend_from_slice(&levels(first, batch, low, hasher)[low as usize]);
        }

        for z in low..height {
            let parents = nodes
                .as_chunks::<2>()
                .0
                .iter()
                .enumerate()
                .map(|(j, pair)| hasher.combine(z, j as u32, &pair[0], &pair[1]))
                .collect();

            tree.levels.push(core::mem::replace(&mut nodes, parents));
        }

        tree.levels.push(nodes);

        tree
    }

    pub(crate) fn root(&self) -> &Node {
        &self.levels[(self.height - self.low) as usize][0]
    }

    // The siblings from the leaf upwards, n bytes each.
    pub(crate) fn auth_path(&self, index: u32, n: usize, hasher: &impl TreeHasher) -> Vec<u8> {
        let mut path = Vec::with_capacity(self.height as usize * n);

        if self.low > 0 {
            let first = index >> self.low << self.low;

            let levels = levels(first, self.low, self.low, hasher);

            for (z, level) in levels.iter().take(self.low as usize).enumerate() {
                let sibling = ((index >> z) ^ 1) & ((1 << (self.low - z as u32)) - 1);

                path.extend_from_slice(&level[sibling as usize][..n]);
            }
        }

        for z in self.low..self.height {
            let level = &self.levels[(z - self.low) as usize];

            path.extend_from_slice(&level[((index >> z) ^ 1) as usize][..n]);
        }

        path
    }
}

// The levels 0 to top of the subtree of 2^size leaves from first on, from the leaves up.
fn levels(first: u32, size: u32, top: u32, hasher: &impl TreeHasher) -> Vec<Vec<Node>> {
    let mut level = vec![[0; 32]; 1 << size];

    hasher.leaves(first, &mut level);

    let mut levels = Vec::with_capacity(top as usize + 1);

    for z in 0..top {
        let offset = first >> (z + 1);

        let parents = level
            .as_chunks::<2>()
            .0
            .iter()
            .enumerate()
            .map(|(j, pair)| hasher.combine(z, offset + j as u32, &pair[0], &pair[1]))
            .collect();

        levels.push(core::mem::replace(&mut level, parents));
    }

    levels.push(level);

    levels
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{MerkleTree, Node, TreeHasher};
    use crate::primitives::sha256;

    struct Tagged;

    impl Tagged {
        fn leaf(index: u32) -> Node {
            sha256(&[&index.to_be_bytes()])
        }
    }

    impl TreeHasher for Tagged {
        fn leaves(&self, first: u32, out: &mut [Node]) {
            for (index, node) in (first..).zip(out) {
                *node = Self::leaf(index);
            }
        }

        fn combine(&self, height: u32, index: u32, left: &Node, right: &Node) -> Node {
            sha256(&[&height.to_be_bytes(), &index.to_be_bytes(), left, right])
        }
    }

    // Every level of the tree, kept whole, to compare with the cache.
    fn full_tree(height: u32) -> Vec<Vec<Node>> {
        let mut levels = Vec::new();

        let mut level: Vec<Node> = (0..1 << height).map(Tagged::leaf).collect();

        for z in 0..height {
            let parents = level
                .as_chunks::<2>()
                .0
                .iter()
                .enumerate()
                .map(|(j, pair)| Tagged.combine(z, j as u32, &pair[0], &pair[1]))
                .collect();

            levels.push(core::mem::replace(&mut level, parents));
        }

        levels.push(level);

        levels
    }

    // Heights above 15 rebuild the subtree under the leaf, which only the slow vectors reach.
    #[test]
    fn cached_paths_match_the_full_tree() {
        for height in [2, 5, 15, 16, 18] {
            let levels = full_tree(height);

            let tree = MerkleTree::new(height, &Tagged);

            assert_eq!(tree.root(), &levels[height as usize][0]);

            let last = (1 << height) - 1;

            for index in [0, 1, 2, last / 3, last / 2 + 1, last - 1, last] {
                let expected: Vec<u8> = (0..height as usize)
                    .flat_map(|z| levels[z][((index >> z) ^ 1) as usize][..24].to_vec())
                    .collect();

                assert_eq!(
                    tree.auth_path(index, 24, &Tagged),
                    expected,
                    "{height} {index}"
                );
            }
        }
    }
}

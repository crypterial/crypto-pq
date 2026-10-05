use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

pub(crate) type Node = [u8; 32];

pub(crate) const CACHED_HEIGHT: u32 = 15;

// Leaves are requested at least this many at a time (2^4), so that hashers can compute them side
// by side.
const LEAF_BATCH: u32 = 4;

pub(crate) trait TreeHasher {
    // The leaves first, first + 1, ... filling out.
    fn leaves(&self, first: u32, out: &mut [Node]);

    // The parent at height + 1 and position index of two nodes at height.
    fn combine(&self, height: u32, index: u32, left: &Node, right: &Node) -> Node;
}

// A tree as a tree cache holds it: its level or layer, its number there, and its nodes from height
// low up, level by level, left to right.
pub(crate) struct CachedTree<'a> {
    pub(crate) level: u8,
    pub(crate) tree: u64,
    pub(crate) nodes: &'a [u8],
}

// A tree that a key holds, with its level or layer, its number there and its node size, as a tree
// cache lists it.
pub(crate) struct HeldTree<'a> {
    pub(crate) level: u8,
    pub(crate) tree: u64,
    pub(crate) n: usize,
    pub(crate) merkle: &'a MerkleTree,
}

// The leaves that this thread has computed, which tests read to see that a restored tree computes
// none.
#[cfg(test)]
std::thread_local! {
    pub(crate) static LEAVES_COMPUTED: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

// A Merkle tree that keeps its nodes from height low = max(0, h - 15) upwards. Building it
// computes every leaf once. An authentication path takes its upper nodes from the cache and
// rebuilds only the 2^low-leaf subtree under the signed leaf, so memory stays below 2^16 nodes
// for every height while trees of height 15 or less never recompute a leaf. The last rebuilt
// subtree is kept, levels 0 to low - 1 with its first leaf: signatures follow the index, so the
// next 2^low of them read it instead of rebuilding it, for 2^(low + 1) nodes more at most. The
// nodes of a tree cache replace the build: every parent is recomputed from its children, so only
// the nodes at height low are taken as given.
pub(crate) struct MerkleTree {
    height: u32,
    low: u32,
    levels: Vec<Vec<Node>>,
    last: Option<(u32, Vec<Vec<Node>>)>,
}

impl MerkleTree {
    pub(crate) fn new(height: u32, hasher: &impl TreeHasher) -> Self {
        let low = height.saturating_sub(CACHED_HEIGHT);

        let mut tree = Self {
            height,
            low,
            levels: Vec::with_capacity((height - low + 1) as usize),
            last: None,
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

    // The tree from cached nodes, laid out as write_nodes writes them, if every parent equals what
    // its children give.
    pub(crate) fn restore(
        height: u32,
        n: usize,
        nodes: &[u8],
        hasher: &impl TreeHasher,
    ) -> Result<Self, Error> {
        let low = height.saturating_sub(CACHED_HEIGHT);

        let mut levels: Vec<Vec<Node>> = Vec::with_capacity((height - low + 1) as usize);

        let mut rest = nodes;

        for z in low..=height {
            let (level, after) = rest
                .split_at_checked(n << (height - z))
                .ok_or(Error::InvalidEncoding)?;

            levels.push(
                level
                    .chunks_exact(n)
                    .map(|bytes| {
                        let mut node = [0; 32];

                        node[..n].copy_from_slice(bytes);

                        node
                    })
                    .collect(),
            );

            rest = after;
        }

        if !rest.is_empty() {
            return Err(Error::InvalidEncoding);
        }

        for z in low..height {
            let children = &levels[(z - low) as usize];

            let parents = &levels[(z - low + 1) as usize];

            let consistent = children
                .as_chunks::<2>()
                .0
                .iter()
                .zip(parents)
                .enumerate()
                .all(|(j, (pair, parent))| {
                    hasher.combine(z, j as u32, &pair[0], &pair[1])[..n] == parent[..n]
                });

            if !consistent {
                return Err(Error::InvalidEncoding);
            }
        }

        Ok(Self {
            height,
            low,
            levels,
            last: None,
        })
    }

    pub(crate) const fn height(&self) -> u32 {
        self.height
    }

    pub(crate) const fn low(&self) -> u32 {
        self.low
    }

    pub(crate) fn node_count(&self) -> usize {
        self.levels.iter().map(Vec::len).sum()
    }

    // The cached nodes as a tree cache lists them: level by level from height low, left to right,
    // n bytes each.
    pub(crate) fn write_nodes(&self, n: usize, out: &mut Vec<u8>) {
        for node in self.levels.iter().flatten() {
            out.extend_from_slice(&node[..n]);
        }
    }

    pub(crate) fn root(&self) -> &Node {
        &self.levels[(self.height - self.low) as usize][0]
    }

    // The siblings from the leaf upwards, n bytes each.
    pub(crate) fn auth_path(&mut self, index: u32, n: usize, hasher: &impl TreeHasher) -> Vec<u8> {
        let mut path = Vec::with_capacity(self.height as usize * n);

        if self.low > 0 {
            let first = index >> self.low << self.low;

            let low = self.low;

            let (_, subtree) = match &mut self.last {
                Some(last) if last.0 == first => last,
                last => last.insert((first, subtree(first, low, hasher))),
            };

            for (z, level) in subtree.iter().enumerate() {
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

// Levels 0 to low - 1 of the subtree of 2^low leaves from first on; the tree caches level low.
fn subtree(first: u32, low: u32, hasher: &impl TreeHasher) -> Vec<Vec<Node>> {
    let mut levels = levels(first, low, low, hasher);

    levels.truncate(low as usize);

    levels
}

// The levels 0 to top of the subtree of 2^size leaves from first on, from the leaves up.
fn levels(first: u32, size: u32, top: u32, hasher: &impl TreeHasher) -> Vec<Vec<Node>> {
    let mut level = vec![[0; 32]; 1 << size];

    hasher.leaves(first, &mut level);

    #[cfg(test)]
    LEAVES_COMPUTED.with(|count| count.set(count.get() + level.len() as u64));

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
    use core::cell::Cell;

    use super::{MerkleTree, Node, TreeHasher};
    use crate::primitives::sha256;

    // Counts the leaves it computes.
    #[derive(Default)]
    struct Tagged {
        leaves: Cell<usize>,
    }

    impl Tagged {
        fn leaf(index: u32) -> Node {
            sha256(&[&index.to_be_bytes()])
        }
    }

    impl TreeHasher for Tagged {
        fn leaves(&self, first: u32, out: &mut [Node]) {
            self.leaves.set(self.leaves.get() + out.len());

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
                .map(|(j, pair)| Tagged::default().combine(z, j as u32, &pair[0], &pair[1]))
                .collect();

            levels.push(core::mem::replace(&mut level, parents));
        }

        levels.push(level);

        levels
    }

    fn expected_path(levels: &[Vec<Node>], height: u32, index: u32) -> Vec<u8> {
        (0..height as usize)
            .flat_map(|z| levels[z][((index >> z) ^ 1) as usize][..24].to_vec())
            .collect()
    }

    // Heights above 15 rebuild the subtree under the leaf, which only the slow vectors reach.
    #[test]
    fn cached_paths_match_the_full_tree() {
        for height in [2, 5, 15, 16, 18] {
            let levels = full_tree(height);

            let hasher = Tagged::default();

            let mut tree = MerkleTree::new(height, &hasher);

            assert_eq!(tree.root(), &levels[height as usize][0]);

            let last = (1 << height) - 1;

            for index in [0, 1, 2, last / 3, last / 2 + 1, last - 1, last] {
                assert_eq!(
                    tree.auth_path(index, 24, &hasher),
                    expected_path(&levels, height, index),
                    "{height} {index}"
                );
            }
        }
    }

    // Consecutive leaves of one subtree rebuild it once; the next subtree replaces it.
    #[test]
    fn the_last_subtree_is_kept() {
        let height = 18;

        let levels = full_tree(height);

        let hasher = Tagged::default();

        let mut tree = MerkleTree::new(height, &hasher);

        assert_eq!(hasher.leaves.get(), 1 << height);

        for (index, rebuilt) in [(8, 8), (9, 0), (15, 0), (16, 8), (8, 8), (12, 0)] {
            hasher.leaves.set(0);

            let path = tree.auth_path(index, 24, &hasher);

            assert_eq!(path, expected_path(&levels, height, index), "{index}");

            assert_eq!(hasher.leaves.get(), rebuilt, "{index}");
        }

        let (first, subtree) = tree.last.as_ref().unwrap();

        assert_eq!(*first, 8);

        assert_eq!(subtree.iter().map(Vec::len).collect::<Vec<_>>(), [8, 4, 2]);
    }

    // The nodes of a built tree restore it without computing a leaf, with the same root and paths,
    // and a change of any one node is refused: every node but the root is a child of a recomputed
    // parent.
    #[test]
    fn restored_trees_match_and_refuse_changes() {
        for height in [5, 17] {
            let hasher = Tagged::default();

            let mut built = MerkleTree::new(height, &hasher);

            let mut nodes = Vec::new();

            built.write_nodes(32, &mut nodes);

            assert_eq!(nodes.len(), 32 * built.node_count());

            hasher.leaves.set(0);

            let mut restored = MerkleTree::restore(height, 32, &nodes, &hasher).unwrap();

            assert_eq!(hasher.leaves.get(), 0);

            assert_eq!(restored.root(), built.root());

            for index in [0, 5, (1 << height) - 1] {
                assert_eq!(
                    restored.auth_path(index, 32, &hasher),
                    built.auth_path(index, 32, &hasher)
                );
            }

            let count = nodes.len() / 32;

            let positions: Vec<usize> = if height == 5 {
                (0..count).collect()
            } else {
                alloc::vec![0, 1, count / 2, count - 2, count - 1]
            };

            for position in positions {
                nodes[32 * position + position % 32] ^= 1;

                assert!(MerkleTree::restore(height, 32, &nodes, &hasher).is_err());

                nodes[32 * position + position % 32] ^= 1;
            }

            assert!(MerkleTree::restore(height, 32, &nodes[32..], &hasher).is_err());

            let longer = [&nodes[..], &[0; 32]].concat();

            assert!(MerkleTree::restore(height, 32, &longer, &hasher).is_err());

            assert!(MerkleTree::restore(height, 32, &nodes, &hasher).is_ok());
        }
    }
}

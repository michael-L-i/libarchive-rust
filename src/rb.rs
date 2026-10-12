/*-
 * Copyright (c) 2001 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Matt Thomas <matt@3am-software.com>.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Based on: NetBSD: rb.c,v 1.6 2010/04/30 13:58:09 joerg Exp
 */

// Ported from libarchive/archive_rb.c.

//! The red-black tree, for the one user whose comparison is not a total
//! order: the ISO9660 writer's identifier resolver. Where a comparison
//! contradicts itself, the shape the rebalancing gives the tree decides
//! which nodes compare as duplicates and how they iterate, so a std
//! collection would not reproduce upstream. Only insertion, lookup and
//! in-order iteration are ported. Nodes are the indices `0..capacity`; the
//! caller keeps what each index stands for.

const LEFT: usize = 0;
const RIGHT: usize = 1;

#[derive(Clone, Copy, Default)]
struct Node {
    nodes: [Option<usize>; 2],
    /// `None` for the root, whose father is the tree itself.
    father: Option<usize>,
    red: bool,
    /// Which child of its father the node is.
    position: usize,
}

#[derive(Default)]
pub(crate) struct RbTree {
    nodes: Vec<Node>,
    root: Option<usize>,
}

impl RbTree {
    /// `__archive_rb_tree_init` for nodes `0..capacity`.
    pub(crate) fn new(capacity: usize) -> Result<Self, std::collections::TryReserveError> {
        let mut nodes = Vec::new();
        nodes.try_reserve_exact(capacity)?;
        nodes.resize(capacity, Node::default());
        Ok(RbTree { nodes, root: None })
    }

    fn red(&self, n: Option<usize>) -> bool {
        n.is_some_and(|n| self.nodes[n].red)
    }

    fn set_child(&mut self, father: Option<usize>, position: usize, child: Option<usize>) {
        match father {
            Some(f) => self.nodes[f].nodes[position] = child,
            None => self.root = child,
        }
    }

    /// `__archive_rb_tree_find_node`. `compare_key(node)` is upstream's
    /// `rbto_compare_key(node, key)`.
    pub(crate) fn find_node(&self, mut compare_key: impl FnMut(usize) -> i32) -> Option<usize> {
        let mut parent = self.root;
        while let Some(p) = parent {
            let diff = compare_key(p);
            if diff == 0 {
                return Some(p);
            }
            parent = self.nodes[p].nodes[usize::from(diff > 0)];
        }
        None
    }

    /// `__archive_rb_tree_insert_node`: false if a node compares equal.
    /// `compare_nodes(node)` is upstream's `rbto_compare_nodes(node, self)`.
    /// `id` must be below the capacity and not in the tree.
    pub(crate) fn insert_node(
        &mut self,
        id: usize,
        mut compare_nodes: impl FnMut(usize) -> i32,
    ) -> bool {
        let mut tmp = self.root;
        let mut parent = None;
        let mut position = LEFT;

        // Find out where to place this new leaf.
        while let Some(t) = tmp {
            let diff = compare_nodes(t);
            if diff == 0 {
                // Node already exists; don't insert.
                return false;
            }
            parent = Some(t);
            position = usize::from(diff > 0);
            tmp = self.nodes[t].nodes[position];
        }

        // Initialize the node and insert as a leaf into the tree.
        // All new nodes are colored red, except the root, which is always
        // black. We only need to rebalance if our parent is also red.
        let rebalance = self.red(parent);
        self.nodes[id] = Node {
            nodes: [None, None],
            father: parent,
            red: parent.is_some(),
            position,
        };
        self.set_child(parent, position, Some(id));

        // Rebalance tree after insertion
        if rebalance {
            self.insert_rebalance(id);
        }
        true
    }

    /// Swap the location and colors of `old_father` and its child at
    /// `which`. The child can not be a sentinel node. This is our rotation
    /// function. However, since it preserves coloring, it great simplifies
    /// both insertion and removal since rotation almost always involves the
    /// exchanging of colors as a separate step.
    fn reparent_nodes(&mut self, old_father: usize, which: usize) {
        let other = which ^ RIGHT;
        let grandpa = self.nodes[old_father].father;
        let Some(new_father) = self.nodes[old_father].nodes[which] else {
            return;
        };
        let new_child = old_father;

        // Exchange descendant linkages.
        self.set_child(grandpa, self.nodes[old_father].position, Some(new_father));
        self.nodes[new_child].nodes[which] = self.nodes[new_father].nodes[other];
        self.nodes[new_father].nodes[other] = Some(new_child);

        // Update ancestor linkages
        self.nodes[new_father].father = grandpa;
        self.nodes[new_child].father = Some(new_father);

        // Exchange properties between new_father and new_child. The only
        // change is that new_child's position is now on the other side.
        let red = self.nodes[new_father].red;
        self.nodes[new_father].red = self.nodes[new_child].red;
        self.nodes[new_father].position = self.nodes[new_child].position;
        self.nodes[new_child].red = red;
        self.nodes[new_child].position = other;

        // Make sure to reparent the new child to ourself.
        if let Some(n) = self.nodes[new_child].nodes[which] {
            self.nodes[n].father = Some(new_child);
            self.nodes[n].position = which;
        }
    }

    fn insert_rebalance(&mut self, mut this: usize) {
        let mut father = self.nodes[this].father;
        let (grandpa, which, other);
        loop {
            // We are red and our parent is red, therefore we must have a
            // grandfather and he must be black.
            let (Some(f), Some(g)) = (father, father.and_then(|f| self.nodes[f].father)) else {
                return;
            };
            let w = usize::from(self.nodes[g].nodes[RIGHT] == Some(f));
            let o = w ^ RIGHT;
            let uncle = self.nodes[g].nodes[o];
            if !self.red(uncle) {
                (grandpa, which, other) = (g, w, o);
                break;
            }

            // Case 1: our uncle is red
            //   Simply invert the colors of our parent and uncle and make
            //   our grandparent red. And then solve the problem up at his
            //   level.
            if let Some(u) = uncle {
                self.nodes[u].red = false;
            }
            self.nodes[f].red = false;
            if self.root == Some(g) {
                // If our grandpa is root, don't bother setting him to red,
                // just return.
                return;
            }
            self.nodes[g].red = true;
            this = g;
            father = self.nodes[this].father;
            if !self.red(father) {
                // If our great-grandpa is black, we're done.
                return;
            }
        }

        // Case 2&3: our uncle is black.
        let Some(f) = father else { return };
        if self.nodes[f].nodes[other] == Some(this) {
            // Case 2: we are on the same side as our uncle
            //   Swap ourselves with our parent so this case becomes case 3.
            //   Basically our parent becomes our child.
            self.reparent_nodes(f, other);
        }
        // Case 3: we are opposite a child of a black uncle.
        //   Swap our parent and grandparent. Since our grandfather is black,
        //   our father will become black and our new sibling (former
        //   grandparent) will become red.
        self.reparent_nodes(grandpa, which);

        // Final step: Set the root to black.
        if let Some(r) = self.root {
            self.nodes[r].red = false;
        }
    }

    /// The nodes in order, as `ARCHIVE_RB_TREE_FOREACH` visits them.
    pub(crate) fn in_order(&self) -> Vec<usize> {
        let mut out = Vec::new();
        let mut stack = Vec::new();
        let mut n = self.root;
        while n.is_some() || !stack.is_empty() {
            while let Some(x) = n {
                stack.push(x);
                n = self.nodes[x].nodes[LEFT];
            }
            if let Some(x) = stack.pop() {
                out.push(x);
                n = self.nodes[x].nodes[RIGHT];
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The red-black invariants: a black root, no red node with a red
    /// child, the same number of black nodes on every path, and fathers and
    /// positions that match the links. Returns the black height.
    fn check(t: &RbTree, n: Option<usize>, father: Option<usize>, position: usize) -> usize {
        let Some(x) = n else { return 1 };
        let node = t.nodes[x];
        assert_eq!(node.father, father);
        if father.is_some() {
            assert_eq!(node.position, position);
        }
        if node.red {
            assert!(!t.red(node.nodes[LEFT]) && !t.red(node.nodes[RIGHT]));
        }
        let l = check(t, node.nodes[LEFT], Some(x), LEFT);
        let r = check(t, node.nodes[RIGHT], Some(x), RIGHT);
        assert_eq!(l, r);
        l + usize::from(!node.red)
    }

    #[test]
    fn inserts_keep_order_and_balance() {
        let keys: Vec<i32> = (0..200).map(|i| (i * 7919) % 211).collect();
        let mut t = RbTree::new(keys.len() + 1).unwrap();
        for (id, &k) in keys.iter().enumerate() {
            assert!(t.insert_node(id, |n| k - keys[n]));
            assert!(!t.red(t.root));
            check(&t, t.root, None, LEFT);
        }
        let dup = keys.len();
        assert!(!t.insert_node(dup, |n| keys[3] - keys[n]));
        let sorted: Vec<i32> = t.in_order().iter().map(|&n| keys[n]).collect();
        let mut expect = keys.clone();
        expect.sort();
        assert_eq!(sorted, expect);
        assert_eq!(t.find_node(|n| keys[17] - keys[n]), Some(17));
        assert_eq!(t.find_node(|n| 1000 - keys[n]), None);
    }

    #[test]
    fn a_self_contradicting_comparison_follows_the_tree_shape() {
        // Node 1 claims to be smaller than node 0 and node 0 smaller than
        // node 1: the later insertion goes left of the earlier one.
        let mut t = RbTree::new(2).unwrap();
        assert!(t.insert_node(0, |_| -1));
        assert!(t.insert_node(1, |_| -1));
        assert_eq!(t.in_order(), vec![1, 0]);
    }
}

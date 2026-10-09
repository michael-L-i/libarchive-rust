/*-
* Copyright (c) 2003-2007 Tim Kientzle
* Copyright (c) 2011 Andres Mejia
* All rights reserved.
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
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// Ported from libarchive/archive_read_support_format_rar.c.

//! The Huffman codes of RAR's LZSS blocks: a binary tree built from the code
//! lengths, and a lookup table over its first levels.

/// A leaf of the tree has equal branches, the symbol; `[-1, -2]` is a node
/// whose children are not set yet.
type Node = [i32; 2];

#[derive(Clone, Copy, Default)]
pub struct Entry {
    /// The bits the symbol takes; one more than `table_size` means that
    /// `value` is the tree node to continue from.
    pub length: u32,
    pub value: i32,
}

#[derive(Default)]
pub struct Code {
    tree: Vec<Node>,
    min_length: i32,
    max_length: i32,
    table_size: u32,
    /// Allocated by `make_table`, even when that fails; dropped by every
    /// `add_value`.
    table: Option<Vec<Entry>>,
}

impl Code {
    /// `create_code`: the code for symbols `0..lengths.len()`, which take
    /// `lengths[i]` bits (0 for none) up to `max_length`. The error is the
    /// message upstream sets.
    pub fn create(lengths: &[u8], max_length: i32) -> Result<Code, &'static str> {
        let mut code = Code {
            tree: vec![[-1, -2]],
            min_length: i32::MAX,
            max_length: i32::MIN,
            ..Code::default()
        };
        let mut codebits: i32 = 0;
        let mut symbols_left = lengths.len();
        for length in 1..=max_length {
            for (j, &l) in lengths.iter().enumerate() {
                if i32::from(l) != length {
                    continue;
                }
                code.add_value(j as i32, codebits, length)?;
                codebits = codebits.wrapping_add(1);
                symbols_left -= 1;
                if symbols_left == 0 {
                    break;
                }
            }
            if symbols_left == 0 {
                break;
            }
            codebits = codebits.wrapping_shl(1);
        }
        Ok(code)
    }

    fn node(&self, i: usize) -> Node {
        self.tree.get(i).copied().unwrap_or([-1, -2])
    }

    fn add_value(&mut self, value: i32, codebits: i32, length: i32) -> Result<(), &'static str> {
        self.table = None;
        self.max_length = self.max_length.max(length);
        self.min_length = self.min_length.min(length);

        let mut last = 0;
        for bitpos in (0..length).rev() {
            let bit = ((codebits >> bitpos) & 1) as usize;
            let [b0, b1] = self.node(last);
            // Leaf node check.
            if b0 == b1 {
                return Err("Prefix found");
            }
            // Open branch check.
            if [b0, b1][bit] < 0 {
                let new = self.tree.len() as i32;
                self.tree.push([-1, -2]);
                if let Some(n) = self.tree.get_mut(last) {
                    n[bit] = new;
                }
            }
            last = usize::try_from(self.node(last)[bit]).unwrap_or(0);
        }
        if self.node(last) != [-1, -2] {
            return Err("Prefix found");
        }
        if let Some(n) = self.tree.get_mut(last) {
            *n = [value, value];
        }
        Ok(())
    }

    /// `make_table`.
    pub fn make_table(&mut self) -> Result<(), &'static str> {
        self.table_size = if self.max_length < self.min_length || self.max_length > 10 {
            10
        } else {
            self.max_length as u32
        };
        let mut table = vec![Entry::default(); 1 << self.table_size];
        let result = self.make_table_recurse(0, &mut table, 0, self.table_size);
        self.table = Some(table);
        result
    }

    fn make_table_recurse(
        &self,
        node: i32,
        table: &mut [Entry],
        depth: u32,
        max_depth: u32,
    ) -> Result<(), &'static str> {
        if self.tree.is_empty() {
            return Err("Huffman tree was not created");
        }
        let Some(&[b0, b1]) = usize::try_from(node).ok().and_then(|n| self.tree.get(n)) else {
            return Err("Invalid location to Huffman tree specified");
        };
        let size = 1usize << (max_depth - depth);
        if b0 == b1 {
            for e in table.iter_mut().take(size) {
                *e = Entry {
                    length: depth,
                    value: b0,
                };
            }
            Ok(())
        } else if depth == max_depth {
            if let Some(e) = table.first_mut() {
                *e = Entry {
                    length: max_depth + 1,
                    value: node,
                };
            }
            Ok(())
        } else {
            let (low, high) = table.split_at_mut(size / 2);
            let first = self.make_table_recurse(b0, low, depth + 1, max_depth);
            let second = self.make_table_recurse(b1, high, depth + 1, max_depth);
            second.and(first)
        }
    }

    /// `table_size` bits to look ahead, once the table exists.
    pub fn table_size(&self) -> u32 {
        self.table_size
    }

    pub fn has_table(&self) -> bool {
        self.table.is_some()
    }

    /// The table entry for the next `table_size` bits of input.
    pub fn lookup(&self, bits: u32) -> Entry {
        self.table
            .as_ref()
            .and_then(|t| t.get(bits as usize))
            .copied()
            .unwrap_or_default()
    }

    /// The branches of tree node `node`.
    pub fn branches(&self, node: i32) -> Option<[i32; 2]> {
        usize::try_from(node)
            .ok()
            .and_then(|n| self.tree.get(n))
            .copied()
    }
}

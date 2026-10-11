//! Huffman literal encoding, ported from libzstd 1.5.7 (`huf_compress.c`).

use super::fse::{self, highbit32, FseCTable};

/// `HUF_TABLELOG_MAX`, also zstd's `LitHufLog`.
pub(crate) const MAX_TABLE_LOG: u32 = 11;
const MAX_FSE_TABLE_LOG_FOR_WEIGHTS: u32 = 6;

/// `HUF_CElt` entries: the code length in the low byte and the code in the
/// top bits, as libzstd's encoder loop expects.
#[derive(Clone, Debug)]
pub(crate) struct HufCTable {
    table_log: u32,
    max_symbol: u32,
    elts: [u64; 256],
}

impl Default for HufCTable {
    fn default() -> Self {
        Self {
            table_log: 0,
            max_symbol: 0,
            elts: [0; 256],
        }
    }
}

#[derive(Copy, Clone, Default)]
struct Node {
    count: u32,
    parent: u16,
    byte: u8,
    nb_bits: u8,
}

impl HufCTable {
    fn nb_bits(&self, symbol: usize) -> u32 {
        (self.elts[symbol] & 0xFF) as u32
    }

    /// `HUF_buildCTable_wksp()`: a Huffman code limited to `max_nb_bits`.
    /// Returns the actual maximum code length.
    pub(crate) fn build(&mut self, count: &[u32], max_nb_bits: u32) -> u32 {
        // huffNode[-1] is a sentinel; nodes 256.. are internal.
        let mut nodes = [Node::default(); 2 * 256 + 1];
        let huff = &mut nodes[1..];
        sort(huff, count);
        let non_null_rank = build_tree(&mut nodes, count.len());
        let huff = &mut nodes[1..];
        let max_nb_bits = set_max_height(huff, non_null_rank, max_nb_bits);
        debug_assert!(max_nb_bits <= MAX_TABLE_LOG);

        // HUF_buildCTableFromTree()
        let mut nb_per_rank = [0u16; MAX_TABLE_LOG as usize + 1];
        let mut val_per_rank = [0u16; MAX_TABLE_LOG as usize + 1];
        for node in &huff[..=non_null_rank] {
            nb_per_rank[node.nb_bits as usize] += 1;
        }
        let mut min = 0u16;
        for n in (1..=max_nb_bits as usize).rev() {
            val_per_rank[n] = min;
            min += nb_per_rank[n];
            min >>= 1;
        }
        self.elts = [0; 256];
        for node in &huff[..count.len()] {
            self.elts[node.byte as usize] = u64::from(node.nb_bits);
        }
        for elt in &mut self.elts[..count.len()] {
            let nb_bits = *elt as u32;
            if nb_bits > 0 {
                let value = &mut val_per_rank[nb_bits as usize];
                *elt |= u64::from(*value) << (64 - nb_bits);
                *value += 1;
            }
        }
        self.table_log = max_nb_bits;
        self.max_symbol = count.len() as u32 - 1;
        max_nb_bits
    }

    /// `HUF_writeCTable_wksp()`: the table description. Returns its size,
    /// or `None` if `out` is too small.
    pub(crate) fn write(&self, out: &mut [u8]) -> Option<usize> {
        let max_symbol = self.max_symbol as usize;
        let mut weights = [0u8; 256];
        for (s, w) in weights[..max_symbol].iter_mut().enumerate() {
            let nb_bits = self.nb_bits(s);
            *w = if nb_bits == 0 {
                0
            } else {
                (self.table_log + 1 - nb_bits) as u8
            };
        }
        // Attempt weights compression by FSE.
        let h_size = compress_weights(out.get_mut(1..)?, &weights[..max_symbol])?;
        if h_size > 1 && h_size < max_symbol / 2 {
            out[0] = h_size as u8;
            return Some(h_size + 1);
        }
        // Write raw values as 4-bits (max: 15).
        if max_symbol > 128 {
            return None;
        }
        let size = max_symbol.div_ceil(2) + 1;
        let out = out.get_mut(..size)?;
        out[0] = (128 + max_symbol - 1) as u8;
        for (o, pair) in out[1..].iter_mut().zip(weights[..max_symbol + 1].chunks(2)) {
            *o = (pair[0] << 4) + pair.get(1).copied().unwrap_or(0);
        }
        Some(size)
    }

    /// `HUF_estimateCompressedSize()`, in bytes.
    pub(crate) fn estimate(&self, count: &[u32]) -> usize {
        let bits: usize = count
            .iter()
            .enumerate()
            .map(|(s, &c)| self.nb_bits(s) as usize * c as usize)
            .sum();
        bits >> 3
    }

    /// `HUF_validateCTable()`: whether every counted symbol has a code.
    pub(crate) fn validate(&self, count: &[u32]) -> bool {
        self.max_symbol as usize + 1 >= count.len()
            && count
                .iter()
                .enumerate()
                .all(|(s, &c)| c == 0 || self.nb_bits(s) != 0)
    }

    /// `HUF_compress1X_usingCTable()` or `HUF_compress4X_usingCTable()`.
    /// Returns 0 if the result does not fit.
    pub(crate) fn compress(&self, out: &mut [u8], src: &[u8], four_streams: bool) -> usize {
        if !four_streams {
            return self.compress1x(out, src);
        }
        // Four streams with a jump table of their first three sizes.
        let segment = src.len().div_ceil(4);
        if out.len() < 6 + 1 + 1 + 1 + 8 || src.len() < 12 {
            return 0;
        }
        let mut op = 6;
        for (n, part) in src.chunks(segment).enumerate() {
            let size = self.compress1x(&mut out[op..], part);
            if size == 0 || size > 65535 {
                return 0;
            }
            if n < 3 {
                out[2 * n..2 * n + 2].copy_from_slice(&(size as u16).to_le_bytes());
            }
            op += size;
        }
        op
    }

    /// `HUF_compress1X_usingCTable_internal_body()`.
    fn compress1x(&self, out: &mut [u8], src: &[u8]) -> usize {
        if out.len() < 8 {
            return 0;
        }
        let Some(mut bits) = HufStream::new(out) else {
            return 0;
        };
        // Symbols are written last to first; the decoder reads backwards.
        // Groups of four codes of at most 11 bits fit beside the 7 pending
        // bits. As in libzstd, every other group is built in a second
        // container and merged, so the two chains of shifts overlap.
        let mut octets = src.rchunks_exact(8);
        for octet in &mut octets {
            for &symbol in octet[4..].iter().rev() {
                bits.add(self.elts[symbol as usize]);
            }
            bits.flush();
            let mut second = HufContainer::default();
            for &symbol in octet[..4].iter().rev() {
                second.add(self.elts[symbol as usize]);
            }
            bits.merge(second);
            bits.flush();
        }
        let rest = octets.remainder();
        for (n, &symbol) in rest.iter().rev().enumerate() {
            bits.add(self.elts[symbol as usize]);
            if n == 3 {
                bits.flush();
            }
        }
        bits.close()
    }
}

/// A bit container filled from the top: each code shifts the previous ones
/// down. Like libzstd's fast variant, the code length is ORed in with the
/// code, leaving up to four dirty bits at the bottom that are never flushed.
#[derive(Default)]
struct HufContainer {
    bits: u64,
    count: u32,
}

impl HufContainer {
    #[inline(always)]
    fn add(&mut self, elt: u64) {
        // The low 32 bits of an entry are its code length.
        self.bits = self.bits.wrapping_shr(elt as u32) | elt;
        self.count += elt as u32;
        debug_assert!(self.count <= 60);
    }
}

/// `HUF_CStream_t`.
struct HufStream<'a> {
    out: &'a mut [u8],
    pos: usize,
    end: usize,
    container: HufContainer,
}

impl<'a> HufStream<'a> {
    fn new(out: &'a mut [u8]) -> Option<Self> {
        let end = out.len().checked_sub(8).filter(|&end| end > 0)?;
        Some(Self {
            out,
            pos: 0,
            end,
            container: HufContainer::default(),
        })
    }

    #[inline(always)]
    fn add(&mut self, elt: u64) {
        self.container.add(elt);
    }

    /// `HUF_mergeIndex1()`.
    #[inline(always)]
    fn merge(&mut self, second: HufContainer) {
        let first = &mut self.container;
        first.bits = first.bits.wrapping_shr(second.count) | second.bits;
        first.count += second.count;
    }

    /// Write out the whole bytes; the remaining bits stay at the top.
    #[inline(always)]
    fn flush(&mut self) {
        let count = self.container.count;
        let bits = self.container.bits.checked_shr(64 - count).unwrap_or(0);
        // As in `BitStream::flush()`, the clamp only drops the bounds check.
        let pos = self.pos.min(self.end);
        self.out[pos..pos + 8].copy_from_slice(&bits.to_le_bytes());
        self.pos = (pos + (count >> 3) as usize).min(self.end);
        self.container.count &= 7;
    }

    fn close(mut self) -> usize {
        self.add((1 << 63) | 1);
        self.flush();
        if self.pos >= self.end {
            return 0;
        }
        self.pos + usize::from(self.container.count > 0)
    }
}

/// `HUF_compressWeights()`: FSE-compress the weights. Returns 0 if they are
/// not compressible, 1 if they are a single repeated value and `None` on
/// libzstd's errors.
fn compress_weights(out: &mut [u8], weights: &[u8]) -> Option<usize> {
    if weights.len() <= 1 {
        return Some(0);
    }
    let mut count = [0u32; MAX_TABLE_LOG as usize + 1];
    let mut max_symbol = MAX_TABLE_LOG;
    let max_count = fse::histogram(&mut count, &mut max_symbol, weights);
    if max_count as usize == weights.len() {
        return Some(1);
    }
    if max_count == 1 {
        return Some(0);
    }
    let count = &count[..=max_symbol as usize];
    let log = fse::optimal_table_log(MAX_FSE_TABLE_LOG_FOR_WEIGHTS, weights.len(), max_symbol, 2);
    let mut norm = [0i16; MAX_TABLE_LOG as usize + 1];
    let norm = &mut norm[..count.len()];
    fse::normalize_count(norm, log, count, weights.len(), false)?;
    let h_size = fse::write_ncount(out, norm, log)?;
    let mut table = FseCTable::default();
    table.build(norm, log);
    Some(
        match fse::compress_using_ctable(&mut out[h_size..], weights, &table) {
            0 => 0,
            size => h_size + size,
        },
    )
}

/// `HUF_optimalTableLog()` without the optimal-depth search, which libzstd
/// enables only for btultra and above.
pub(crate) fn optimal_table_log(src_size: usize, max_symbol: u32) -> u32 {
    fse::optimal_table_log(MAX_TABLE_LOG, src_size, max_symbol, 1)
}

/// `HUF_getIndex()`: bucket for `HUF_sort()`.
fn bucket(count: u32) -> usize {
    const LOG_BUCKETS_BEGIN: u32 = 158;
    const DISTINCT_COUNT_CUTOFF: u32 = 166;
    if count < DISTINCT_COUNT_CUTOFF {
        count as usize
    } else {
        (highbit32(count) + LOG_BUCKETS_BEGIN) as usize
    }
}

/// `HUF_sort()`: symbols by decreasing count, bucketed then sorted per bucket.
fn sort(huff: &mut [Node], count: &[u32]) {
    const TABLE_SIZE: usize = 192;
    const DISTINCT_COUNT_CUTOFF: usize = 166;
    let mut base = [0u16; TABLE_SIZE];
    let mut curr = [0u16; TABLE_SIZE];
    for &c in count {
        base[bucket(c)] += 1;
    }
    for n in (1..TABLE_SIZE).rev() {
        base[n - 1] += base[n];
        curr[n - 1] = base[n - 1];
    }
    for (s, &c) in count.iter().enumerate() {
        let r = bucket(c) + 1;
        let pos = curr[r] as usize;
        curr[r] += 1;
        huff[pos] = Node {
            count: c,
            byte: s as u8,
            ..Node::default()
        };
    }
    for n in DISTINCT_COUNT_CUTOFF..TABLE_SIZE - 1 {
        let start = base[n] as usize;
        let size = curr[n] as usize - start;
        if size > 1 {
            quick_sort(&mut huff[start..start + size], 0, size as isize - 1);
        }
    }
    debug_assert!(huff[..count.len()]
        .windows(2)
        .all(|w| w[0].count >= w[1].count));
}

/// `HUF_simpleQuickSort()` over `arr[low..=high]`, by decreasing count.
fn quick_sort(arr: &mut [Node], mut low: isize, mut high: isize) {
    if high - low < 8 {
        // HUF_insertionSort()
        for i in low + 1..=high {
            let key = arr[i as usize];
            let mut j = i - 1;
            while j >= low && arr[j as usize].count < key.count {
                arr[j as usize + 1] = arr[j as usize];
                j -= 1;
            }
            arr[(j + 1) as usize] = key;
        }
        return;
    }
    while low < high {
        // HUF_quickSortPartition(), rightmost element as pivot.
        let pivot = arr[high as usize].count;
        let mut i = low - 1;
        for j in low..high {
            if arr[j as usize].count > pivot {
                i += 1;
                arr.swap(i as usize, j as usize);
            }
        }
        let idx = i + 1;
        arr.swap(idx as usize, high as usize);
        if idx - low < high - idx {
            quick_sort(arr, low, idx - 1);
            low = idx + 1;
        } else {
            quick_sort(arr, idx + 1, high);
            high = idx - 1;
        }
    }
}

/// `HUF_buildTree()`: an unlimited-depth tree over the sorted symbols in
/// `nodes[1..]` (`nodes[0]` is the sentinel). Returns the last non-zero rank.
fn build_tree(nodes: &mut [Node], symbols: usize) -> usize {
    const START: usize = 256 + 1;
    let mut non_null_rank = symbols - 1;
    while nodes[non_null_rank + 1].count == 0 {
        non_null_rank -= 1;
    }
    // Indices below are into `nodes`, offset by one from libzstd's huffNode.
    let mut low_s = non_null_rank + 1;
    let node_root = START + non_null_rank - 1;
    let mut low_n = START;
    let mut node_nb = START;
    nodes[node_nb].count = nodes[low_s].count + nodes[low_s - 1].count;
    nodes[low_s].parent = (node_nb - 1) as u16;
    nodes[low_s - 1].parent = (node_nb - 1) as u16;
    node_nb += 1;
    low_s -= 2;
    for node in &mut nodes[node_nb..=node_root] {
        node.count = 1 << 30;
    }
    nodes[0].count = 1 << 31;
    while node_nb <= node_root {
        let mut pick = || {
            if nodes[low_s].count < nodes[low_n].count {
                low_s -= 1;
                low_s + 1
            } else {
                low_n += 1;
                low_n - 1
            }
        };
        let n1 = pick();
        let n2 = pick();
        nodes[node_nb].count = nodes[n1].count + nodes[n2].count;
        nodes[n1].parent = (node_nb - 1) as u16;
        nodes[n2].parent = (node_nb - 1) as u16;
        node_nb += 1;
    }
    nodes[node_root].nb_bits = 0;
    for n in (START..node_root).rev() {
        nodes[n].nb_bits = nodes[nodes[n].parent as usize + 1].nb_bits + 1;
    }
    for n in 1..=non_null_rank + 1 {
        nodes[n].nb_bits = nodes[nodes[n].parent as usize + 1].nb_bits + 1;
    }
    non_null_rank
}

/// `HUF_setMaxHeight()`: enforce `target_nb_bits` on the sorted tree in
/// `huff`, keeping it a valid prefix code. Returns the maximum code length.
fn set_max_height(huff: &mut [Node], last_non_null: usize, target_nb_bits: u32) -> u32 {
    let largest_bits = u32::from(huff[last_non_null].nb_bits);
    if largest_bits <= target_nb_bits {
        return largest_bits;
    }
    const NO_SYMBOL: u32 = 0xF0F0F0F0;
    let target = target_nb_bits as u8;
    let mut total_cost: i32 = 0;
    let base_cost = 1i32 << (largest_bits - target_nb_bits);
    let mut n = last_non_null as isize;
    // Adjust any ranks > target to target, measuring the excess.
    while huff[n as usize].nb_bits > target {
        total_cost += base_cost - (1 << (largest_bits - u32::from(huff[n as usize].nb_bits)));
        huff[n as usize].nb_bits = target;
        n -= 1;
    }
    while huff[n as usize].nb_bits == target {
        n -= 1;
    }
    total_cost >>= largest_bits - target_nb_bits;

    // Repay the normalized cost. rank_last[k] is the position of the last
    // (smallest) symbol using target - k bits.
    let mut rank_last = [NO_SYMBOL; MAX_TABLE_LOG as usize + 2];
    let mut current_nb_bits = target;
    for pos in (0..=n).rev() {
        let bits = huff[pos as usize].nb_bits;
        if bits >= current_nb_bits {
            continue;
        }
        current_nb_bits = bits;
        rank_last[(target - bits) as usize] = pos as u32;
    }
    while total_cost > 0 {
        // Reduce the next power of 2 above total_cost: it gains back half
        // the rank.
        let mut nb_bits_to_decrease = highbit32(total_cost as u32) as usize + 1;
        while nb_bits_to_decrease > 1 {
            let high_pos = rank_last[nb_bits_to_decrease];
            let low_pos = rank_last[nb_bits_to_decrease - 1];
            if high_pos == NO_SYMBOL {
                nb_bits_to_decrease -= 1;
                continue;
            }
            if low_pos == NO_SYMBOL {
                break;
            }
            let high_total = huff[high_pos as usize].count;
            let low_total = 2 * huff[low_pos as usize].count;
            if high_total <= low_total {
                break;
            }
            nb_bits_to_decrease -= 1;
        }
        // Only reached when no rank 1 symbol is left: take the closest one.
        while nb_bits_to_decrease <= MAX_TABLE_LOG as usize
            && rank_last[nb_bits_to_decrease] == NO_SYMBOL
        {
            nb_bits_to_decrease += 1;
        }
        total_cost -= 1 << (nb_bits_to_decrease - 1);
        let pos = rank_last[nb_bits_to_decrease] as usize;
        huff[pos].nb_bits += 1;
        if rank_last[nb_bits_to_decrease - 1] == NO_SYMBOL {
            rank_last[nb_bits_to_decrease - 1] = pos as u32;
        }
        if rank_last[nb_bits_to_decrease] == 0 {
            rank_last[nb_bits_to_decrease] = NO_SYMBOL;
        } else {
            rank_last[nb_bits_to_decrease] -= 1;
            let last = rank_last[nb_bits_to_decrease] as usize;
            if u32::from(huff[last].nb_bits) != target_nb_bits - nb_bits_to_decrease as u32 {
                rank_last[nb_bits_to_decrease] = NO_SYMBOL;
            }
        }
    }
    // Repair an overshoot by moving the largest rank-0 nodes to rank 1.
    while total_cost < 0 {
        if rank_last[1] == NO_SYMBOL {
            while huff[n as usize].nb_bits == target {
                n -= 1;
            }
            huff[n as usize + 1].nb_bits -= 1;
            rank_last[1] = n as u32 + 1;
            total_cost += 1;
            continue;
        }
        huff[rank_last[1] as usize + 1].nb_bits -= 1;
        rank_last[1] += 1;
        total_cost += 1;
    }
    target_nb_bits
}

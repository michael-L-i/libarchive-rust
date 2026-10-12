//! LZ in window and match finder API, ported from liblzma 5.8.4
//! (`lz/lz_encoder.c`, `lz/lz_encoder.h`; Igor Pavlov, Lasse Collin; 0BSD).

use alloc::{vec, vec::Vec};

/// Match finders to use when encoding.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfType {
    /// Hash chain for 3 byte entries.
    Hc3,
    /// Hash chain for 4 bytes entries (lower quality but faster).
    #[default]
    Hc4,
    /// Binary tree for 4 byte entries (higher quality but slower).
    Bt4,
}

impl MfType {
    /// How many bytes the match finder hashes in its initial step.
    /// This is also the minimum nice_len value with the match finder.
    pub(crate) fn hash_bytes(self) -> u32 {
        match self {
            MfType::Hc3 => 3,
            MfType::Hc4 | MfType::Bt4 => 4,
        }
    }
}

/// `lzma_memcmplen()` may read this many bytes past its limit.
pub(crate) const MEMCMPLEN_EXTRA: u32 = 8;

pub(crate) const HASH_2_SIZE: usize = 1 << 10;
pub(crate) const HASH_3_SIZE: usize = 1 << 16;

/// A repeat proven by the match finder; see `Mf::run`.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Run {
    pub(crate) delta: u32,
    pub(crate) start: u32,
    pub(crate) len: u32,
}

/// The encoder's view of `lzma_action`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Run,
    SyncFlush,
    Finish,
}

/// A length-distance pair found by the match finder.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Match {
    pub(crate) len: u32,
    pub(crate) dist: u32,
}

pub(crate) struct LzOptions<'a> {
    /// Extra amount of data to keep available before the "actual" dictionary.
    pub(crate) before_size: u32,
    pub(crate) dict_size: u32,
    /// Extra amount of data to keep available after the "actual" dictionary.
    pub(crate) after_size: u32,
    pub(crate) match_len_max: u32,
    pub(crate) nice_len: u32,
    pub(crate) match_finder: MfType,
    pub(crate) depth: u32,
    pub(crate) preset_dict: Option<&'a [u8]>,
}

/// History buffer and match finder (`lzma_mf`).
pub(crate) struct Mf {
    /// Data to be compressed, followed by `MEMCMPLEN_EXTRA` padding bytes.
    pub(crate) buffer: Vec<u8>,
    /// Size of the buffer without the padding.
    size: u32,
    /// Number of bytes that must be kept available in our input history.
    keep_size_before: u32,
    /// Number of bytes that must be kept in buffer after read_pos.
    keep_size_after: u32,
    /// Match finders store locations of matches using 32-bit integers.
    /// `buffer[value_in_hash_table - offset]` is the byte pointed by
    /// `value_in_hash_table`.
    pub(crate) offset: u32,
    /// `buffer[read_pos]` is the next byte to run through the match finder.
    pub(crate) read_pos: u32,
    /// Bytes that have been ran through the match finder but not encoded yet.
    pub(crate) read_ahead: u32,
    /// As long as read_pos is less than read_limit, there is enough
    /// input available in buffer for at least one encoding loop.
    pub(crate) read_limit: u32,
    /// `buffer[write_pos]` is the first byte that doesn't contain valid
    /// uncompressed data.
    pub(crate) write_pos: u32,
    /// Number of bytes not hashed before read_pos. This is needed to
    /// restart the match finder after a sync flush.
    pub(crate) pending: u32,
    pub(crate) kind: MfType,
    pub(crate) hash2: Vec<u32>,
    pub(crate) hash3: Vec<u32>,
    pub(crate) hash: Vec<u32>,
    pub(crate) son: Vec<u32>,
    /// Hash indices and chain head loaded ahead for a position:
    /// (position, hash_2_value, hash_3_value, hash_value, head).
    pub(crate) hash4_hint: Option<(u32, usize, usize, usize, u32)>,
    /// Bytes the BT4 skip proved to repeat: `buffer[p] == buffer[p - delta]`
    /// for the positions `p` (`read_pos + offset`) in `[start, start + len)`.
    pub(crate) run: Run,
    pub(crate) cyclic_pos: u32,
    /// Must be dictionary size + 1.
    pub(crate) cyclic_size: u32,
    pub(crate) hash_mask: u32,
    /// Maximum number of loops in the match finder.
    pub(crate) depth: u32,
    /// Maximum length of a match that the match finder will try to find.
    pub(crate) nice_len: u32,
    /// Maximum length of a match supported by the LZ-based encoder.
    pub(crate) match_len_max: u32,
    pub(crate) action: Action,
}

/// The dictionary sizes the encoder accepts.
pub(crate) fn is_enc_dict_size_valid(size: u32) -> bool {
    (crate::DICT_SIZE_MIN..=(1 << 30) + (1 << 29)).contains(&size)
}

impl Mf {
    /// Sets up the window and match finder (`lz_encoder_prepare()` and
    /// `lz_encoder_init()`). The caller has validated the options.
    pub(crate) fn new(o: &LzOptions) -> Self {
        debug_assert!(is_enc_dict_size_valid(o.dict_size) && o.nice_len <= o.match_len_max);
        debug_assert!(o.match_finder.hash_bytes() <= o.nice_len);
        let keep_size_before = o.before_size + o.dict_size;
        let keep_size_after = o.after_size + o.match_len_max;
        let size = buffer_size(o);
        let cyclic_size = o.dict_size + 1;
        let hash_bytes = o.match_finder.hash_bytes();
        let is_bt = o.match_finder == MfType::Bt4;
        let hs = hash_mask(o);

        let depth = match o.depth {
            0 if is_bt => 16 + o.nice_len / 2,
            0 => 4 + o.nice_len / 4,
            depth => depth,
        };

        let mut mf = Self {
            buffer: Vec::with_capacity((size + MEMCMPLEN_EXTRA) as usize),
            size,
            keep_size_before,
            keep_size_after,
            // Use cyclic_size as initial offset. This allows avoiding a
            // few branches in the match finders.
            offset: cyclic_size,
            read_pos: 0,
            read_ahead: 0,
            read_limit: 0,
            write_pos: 0,
            pending: 0,
            kind: o.match_finder,
            hash2: vec![0; HASH_2_SIZE],
            hash3: vec![0; if hash_bytes > 3 { HASH_3_SIZE } else { 0 }],
            hash: vec![0; hs as usize + 1],
            son: Vec::with_capacity(cyclic_size as usize * if is_bt { 2 } else { 1 }),
            hash4_hint: None,
            run: Run::default(),
            cyclic_pos: 0,
            cyclic_size,
            hash_mask: hs,
            depth,
            nice_len: o.nice_len,
            match_len_max: o.match_len_max,
            action: Action::Run,
        };

        if let Some(dict) = o.preset_dict.filter(|d| !d.is_empty()) {
            // If the preset dictionary is bigger than the actual
            // dictionary, use only the tail.
            let len = dict.len().min(size as usize);
            mf.initialize(len, len);
            mf.buffer[..len].copy_from_slice(&dict[dict.len() - len..]);
            mf.write_pos = len as u32;
            mf.action = Action::SyncFlush;
            mf.skip_raw(mf.write_pos);
        }
        mf.action = Action::Run;
        mf
    }

    /// Initialize only the history and nodes this input can reach. Hashes
    /// still cover the full configured dictionary; untouched nodes cannot
    /// be referenced until their positions have passed the match finder.
    fn initialize(&mut self, end: usize, positions: usize) {
        let needed = end + MEMCMPLEN_EXTRA as usize;
        if needed > self.buffer.len() {
            self.buffer.resize(needed, 0);
        }
        let nodes = (self.cyclic_pos as usize + positions).min(self.cyclic_size as usize)
            * if self.kind == MfType::Bt4 { 2 } else { 1 };
        if nodes > self.son.len() {
            self.son.resize(nodes, 0);
        }
    }

    /// Number of bytes that haven't been ran through the match finder yet.
    #[inline(always)]
    pub(crate) fn avail(&self) -> u32 {
        self.write_pos - self.read_pos
    }

    /// Number of bytes that haven't been encoded yet.
    #[inline(always)]
    pub(crate) fn unencoded(&self) -> u32 {
        self.write_pos - self.read_pos + self.read_ahead
    }

    /// Skips the given number of bytes. This is used when a good match was
    /// found.
    #[inline(always)]
    pub(crate) fn skip(&mut self, amount: u32) {
        if amount != 0 {
            self.skip_raw(amount);
            self.read_ahead += amount;
        }
    }

    /// Moves the data in the input window to free space for new data,
    /// keeping `keep_size_before` bytes of history.
    fn move_window(&mut self) {
        // Align the move to a multiple of 16 bytes. LZMA uses the lowest
        // bits of read_pos to know the alignment of the uncompressed data.
        debug_assert!(self.read_pos > self.keep_size_before);
        let move_offset = (self.read_pos - self.keep_size_before) & !15;
        debug_assert!(self.write_pos > move_offset);
        let move_size = self.write_pos - move_offset;
        self.buffer
            .copy_within(move_offset as usize..(move_offset + move_size) as usize, 0);
        self.offset = self.offset.wrapping_add(move_offset);
        self.read_pos -= move_offset;
        // read_limit can be below the offset (a preset dictionary leaves it
        // at 0); liblzma's unsigned subtraction wraps, and fill_window sets
        // it again before it is read.
        self.read_limit = self.read_limit.wrapping_sub(move_offset);
        self.write_pos -= move_offset;
    }

    /// Tries to fill the input window from `input` (`fill_window()`).
    /// Returns the number of bytes consumed.
    pub(crate) fn fill_window(&mut self, input: &[u8], action: Action) -> usize {
        debug_assert!(self.read_pos <= self.write_pos);

        // Move the sliding window if needed.
        if self.read_pos >= self.size - self.keep_size_after {
            self.move_window();
        }

        let write_pos = self.write_pos as usize;
        let len = input.len().min(self.size as usize - write_pos);
        self.initialize(
            write_pos + len,
            (self.write_pos - self.read_pos + self.pending) as usize + len,
        );
        self.buffer[write_pos..write_pos + len].copy_from_slice(&input[..len]);
        self.write_pos += len as u32;
        let end = self.write_pos as usize;
        self.buffer[end..end + MEMCMPLEN_EXTRA as usize].fill(0);

        // If end of stream has been reached or flushing completed, we allow
        // the encoder to process all the input (that is, read_pos is allowed
        // to reach write_pos). Otherwise we keep keep_size_after bytes
        // available as prebuffer.
        if action != Action::Run && len == input.len() {
            self.action = action;
            self.read_limit = self.write_pos;
        } else if self.write_pos > self.keep_size_after {
            // This needs to be done conditionally, because if we got
            // only little new input, there may be too little input
            // to do any encoding yet.
            self.read_limit = self.write_pos - self.keep_size_after;
        }

        // Restart the match finder after finished sync flush.
        if self.pending > 0 && self.read_pos < self.read_limit {
            // Rewind read_pos so that the match finder can hash
            // the pending bytes.
            let pending = self.pending;
            self.pending = 0;
            debug_assert!(self.read_pos >= pending);
            self.read_pos -= pending;
            self.skip_raw(pending);
        }
        len
    }
}

/// Total size of the history buffer: To avoid constant memmove()s,
/// allocate some extra space. Since memmove()s become more expensive when
/// the size of the buffer increases, we reserve more space when a large
/// dictionary is used to make the memmove() calls rarer.
fn buffer_size(o: &LzOptions) -> u32 {
    let mut reserve = o.dict_size / 2;
    if reserve > 1 << 30 {
        reserve /= 2;
    }
    reserve += (o.before_size + o.match_len_max + o.after_size) / 2 + (1 << 19);
    o.before_size + o.dict_size + reserve + o.after_size + o.match_len_max
}

/// Rounds the dictionary size up to the next 2^n - 1 so it can be used
/// as a hash mask.
fn hash_mask(o: &LzOptions) -> u32 {
    let mut hs = o.dict_size - 1;
    hs |= hs >> 1;
    hs |= hs >> 2;
    hs |= hs >> 4;
    hs |= hs >> 8;
    hs >>= 1;
    hs |= 0xFFFF;
    if hs > 1 << 24 {
        if o.match_finder.hash_bytes() == 3 {
            hs = (1 << 24) - 1;
        } else {
            hs >>= 1;
        }
    }
    hs
}

/// Memory usage of the window and match finder in bytes
/// (`lzma_lz_encoder_memusage()`).
pub(crate) fn memusage(o: &LzOptions) -> u64 {
    let hash = u64::from(hash_mask(o))
        + 1
        + HASH_2_SIZE as u64
        + if o.match_finder.hash_bytes() > 3 {
            HASH_3_SIZE as u64
        } else {
            0
        };
    let sons = (u64::from(o.dict_size) + 1) * if o.match_finder == MfType::Bt4 { 2 } else { 1 };
    (hash + sons) * 4 + u64::from(buffer_size(o))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(kind: MfType, dict_size: u32) -> (Mf, Mf) {
        let options = LzOptions {
            before_size: 16,
            dict_size,
            after_size: 32,
            match_len_max: 273,
            nice_len: 32,
            match_finder: kind,
            depth: 0,
            preset_dict: None,
        };
        let lazy = Mf::new(&options);
        let mut full = Mf::new(&options);
        full.buffer.resize(full.buffer.capacity(), 0);
        full.son.resize(full.son.capacity(), 0);
        (lazy, full)
    }

    fn same_state(lazy: &Mf, full: &Mf) {
        assert_eq!(lazy.offset, full.offset);
        assert_eq!(lazy.read_pos, full.read_pos);
        assert_eq!(lazy.read_ahead, full.read_ahead);
        assert_eq!(lazy.write_pos, full.write_pos);
        assert_eq!(lazy.read_limit, full.read_limit);
        assert_eq!(lazy.cyclic_pos, full.cyclic_pos);
        assert_eq!(lazy.pending, full.pending);
        assert_eq!(lazy.hash4_hint, full.hash4_hint);
        assert_eq!(
            (lazy.run.delta, lazy.run.start, lazy.run.len),
            (full.run.delta, full.run.start, full.run.len)
        );
        assert_eq!(lazy.hash2, full.hash2);
        assert_eq!(lazy.hash3, full.hash3);
        assert_eq!(lazy.hash, full.hash);
        assert_eq!(lazy.son, full.son[..lazy.son.len()]);
        assert!(full.son[lazy.son.len()..].iter().all(|&v| v == 0));
        let end = lazy.write_pos as usize + MEMCMPLEN_EXTRA as usize;
        assert_eq!(lazy.buffer[..end], full.buffer[..end]);
    }

    fn drain(lazy: &mut Mf, full: &mut Mf) {
        let mut a = [Match::default(); 273];
        let mut b = a;
        while lazy.read_pos < lazy.read_limit {
            let found = lazy.find(&mut a);
            assert_eq!(found, full.find(&mut b));
            for (a, b) in a.iter().zip(&b).take(found.1 as usize) {
                assert_eq!((a.len, a.dist), (b.len, b.dist));
            }
            let skip = (lazy.read_limit - lazy.read_pos).min(7);
            lazy.skip(skip);
            full.skip(skip);
            lazy.read_ahead = 0;
            full.read_ahead = 0;
        }
        same_state(lazy, full);
    }

    #[test]
    fn partial_nodes_preserve_matches_through_window_moves_and_ring_wraps() {
        let data: Vec<u8> = (0..600_003)
            .map(|i| ((i % 251) ^ ((i / 997) % 17)) as u8)
            .collect();
        for kind in [MfType::Hc3, MfType::Hc4, MfType::Bt4] {
            let (mut lazy, mut full) = pair(kind, 4096);
            let capacities = (lazy.buffer.capacity(), lazy.son.capacity());
            let mut wrapped = false;
            let mut pending = false;
            let mut pos = 0;
            while pos < data.len() {
                let part = &data[pos..data.len().min(pos + 4093)];
                let used = lazy.fill_window(part, Action::Run);
                assert_eq!(used, full.fill_window(part, Action::Run));
                assert!(used > 0);
                pos += used;
                let cyclic = lazy.cyclic_pos;
                drain(&mut lazy, &mut full);
                wrapped |= lazy.cyclic_pos < cyclic;
                lazy.fill_window(&[], Action::SyncFlush);
                full.fill_window(&[], Action::SyncFlush);
                drain(&mut lazy, &mut full);
                pending |= lazy.pending > 0;
                lazy.action = Action::Run;
                full.action = Action::Run;
            }
            assert!(lazy.offset > lazy.cyclic_size);
            assert!(wrapped && pending);
            assert_eq!(capacities, (lazy.buffer.capacity(), lazy.son.capacity()));
        }
    }

    #[test]
    fn partial_nodes_normalize_with_pending_bytes_and_empty_fills() {
        let data: Vec<u8> = (0..601).map(|i| (i % 17) as u8).collect();
        for kind in [MfType::Hc3, MfType::Hc4, MfType::Bt4] {
            let (mut lazy, mut full) = pair(kind, 65536);
            assert!(lazy.buffer.is_empty() && lazy.son.is_empty());
            lazy.offset = u32::MAX - 257;
            full.offset = lazy.offset;
            for action in [Action::Run, Action::SyncFlush, Action::Finish] {
                assert_eq!(lazy.fill_window(&[], action), 0);
                assert_eq!(full.fill_window(&[], action), 0);
                same_state(&lazy, &full);
            }
            for part in data.chunks(127) {
                lazy.action = Action::Run;
                full.action = Action::Run;
                assert_eq!(
                    lazy.fill_window(part, Action::SyncFlush),
                    full.fill_window(part, Action::SyncFlush)
                );
                drain(&mut lazy, &mut full);
                assert!(lazy.pending > 0);
            }
            assert!(lazy.offset < lazy.cyclic_size);
            assert!(lazy.son.len() < full.son.len());
            assert_eq!(lazy.buffer.len(), data.len() + MEMCMPLEN_EXTRA as usize);
        }
    }
}

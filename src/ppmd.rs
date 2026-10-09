/* Ppmd.h -- PPMD codec common code
2010-03-12 : Igor Pavlov : Public domain
This code is based on PPMd var.H (2001): Dmitry Shkarin : Public domain */

// Ported from libarchive/archive_ppmd_private.h.

//! Code shared by the PPMd var. H (`ppmd7`) and var. I (`ppmd8`) models.
//!
//! Upstream keeps the model in one allocated arena, addressed by 32-bit
//! offsets from its base, and walks it through casted pointers. Here the
//! arena is a `Vec<u8>` and every access is bounds-checked. An access
//! outside the arena reads as zero, is ignored when writing, and marks the
//! arena `bad`; the decoders then fail with the "invalid data" result.
//! A model that the decoder itself built never leaves the arena, so this
//! only triggers if the model's invariants break.

use std::cell::Cell;

/// Reads the next compressed byte; returns 0 at end of data or on error,
/// like upstream's `IByteIn::Read`. The reader remembers the failure.
pub trait ByteIn {
    fn read_byte(&mut self) -> u8;
}

impl<F: FnMut() -> u8> ByteIn for F {
    fn read_byte(&mut self) -> u8 {
        self()
    }
}

pub(crate) const PPMD_INT_BITS: u32 = 7;
pub(crate) const PPMD_PERIOD_BITS: u32 = 7;
pub(crate) const PPMD_BIN_SCALE: u32 = 1 << (PPMD_INT_BITS + PPMD_PERIOD_BITS);
pub(crate) const PPMD_NUM_INDEXES: usize = 38;
pub(crate) const MAX_FREQ: u32 = 124;
pub(crate) const UNIT_SIZE: u32 = 12;
/// Size of a `CPpmd_State`: symbol, freq, successor (low and high halves).
pub(crate) const STATE_SIZE: u32 = 6;

pub(crate) const K_INIT_BIN_ESC: [u16; 8] = [
    0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051,
];
pub(crate) const K_EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];

/// Update after a mispredicted bit (`PPMD_UPDATE_PROB_0` / `_1`).
pub(crate) fn update_prob_0(prob: u16) -> u16 {
    let p = u32::from(prob);
    (p + (1 << PPMD_INT_BITS) - ((p + (1 << (PPMD_PERIOD_BITS - 2))) >> PPMD_PERIOD_BITS)) as u16
}

pub(crate) fn update_prob_1(prob: u16) -> u16 {
    let p = u32::from(prob);
    (p.wrapping_sub((p + (1 << (PPMD_PERIOD_BITS - 2))) >> PPMD_PERIOD_BITS)) as u16
}

/// SEE-contexts for PPM-contexts with masked symbols.
#[derive(Clone, Copy, Default)]
pub(crate) struct See {
    pub summ: u16,
    /// Speed of Freq change; low shift is for fast change.
    pub shift: u8,
    /// Count to next change of shift.
    pub count: u8,
}

impl See {
    pub fn update(&mut self) {
        if u32::from(self.shift) < PPMD_PERIOD_BITS {
            self.count = self.count.wrapping_sub(1);
            if self.count == 0 {
                self.summ = self.summ.wrapping_shl(1);
                self.count = (3u32 << self.shift) as u8;
                self.shift += 1;
            }
        }
    }

    /// Takes the escape frequency out of the context (`r`, at least 1).
    pub fn take_esc_freq(&mut self) -> u32 {
        let r = u32::from(self.summ >> (self.shift & 15));
        self.summ = self.summ.wrapping_sub(r as u16);
        r + u32::from(r == 0)
    }
}

/// The tables `Ppmd{7,8}_Construct` builds: units per index and its inverse.
pub(crate) fn unit_tables() -> ([u8; PPMD_NUM_INDEXES], [u8; 128]) {
    let mut indx2units = [0; PPMD_NUM_INDEXES];
    let mut units2indx = [0; 128];
    let mut k = 0;
    for (i, units) in indx2units.iter_mut().enumerate() {
        let step = if i >= 12 { 4 } else { (i >> 2) + 1 };
        for _ in 0..step {
            units2indx[k] = i as u8;
            k += 1;
        }
        *units = k as u8;
    }
    (indx2units, units2indx)
}

/// The model's memory. Offsets are from the start of the allocation, like
/// upstream's `REF`, so they never need translating.
#[derive(Default)]
pub(crate) struct Arena {
    mem: Vec<u8>,
    bad: Cell<bool>,
}

impl Arena {
    /// A zeroed arena of `len` bytes, or `None` if it can't be allocated.
    /// Upstream's `malloc` leaves it uninitialized; zero is one of the
    /// values that can read back.
    pub fn alloc(len: u64) -> Option<Arena> {
        let len = usize::try_from(len).ok()?;
        let mut mem = Vec::new();
        mem.try_reserve_exact(len).ok()?;
        mem.resize(len, 0);
        Some(Arena {
            mem,
            bad: Cell::new(false),
        })
    }

    pub fn is_allocated(&self) -> bool {
        !self.mem.is_empty()
    }

    pub fn is_bad(&self) -> bool {
        self.bad.get()
    }

    /// Starts over with a fresh model in the same memory.
    pub fn clear_bad(&self) {
        self.bad.set(false);
    }

    /// Records an access or structure the model can't have built.
    #[cold]
    pub fn fail(&self) {
        self.bad.set(true);
    }

    #[inline]
    fn read<const N: usize>(&self, off: u32) -> [u8; N] {
        match self
            .mem
            .get(off as usize..)
            .and_then(|s| s.first_chunk::<N>())
        {
            Some(b) => *b,
            None => {
                self.fail();
                [0; N]
            }
        }
    }

    #[inline]
    fn write<const N: usize>(&mut self, off: u32, v: [u8; N]) {
        match self
            .mem
            .get_mut(off as usize..)
            .and_then(|s| s.first_chunk_mut::<N>())
        {
            Some(b) => *b = v,
            None => self.fail(),
        }
    }

    #[inline]
    pub fn r8(&self, off: u32) -> u8 {
        let [b] = self.read(off);
        b
    }

    #[inline]
    pub fn r16(&self, off: u32) -> u16 {
        u16::from_le_bytes(self.read(off))
    }

    #[inline]
    pub fn r32(&self, off: u32) -> u32 {
        u32::from_le_bytes(self.read(off))
    }

    #[inline]
    pub fn w8(&mut self, off: u32, v: u8) {
        self.write(off, [v]);
    }

    #[inline]
    pub fn w16(&mut self, off: u32, v: u16) {
        self.write(off, v.to_le_bytes());
    }

    #[inline]
    pub fn w32(&mut self, off: u32, v: u32) {
        self.write(off, v.to_le_bytes());
    }

    /// Copies `n` bytes; the blocks don't overlap in a sound model.
    pub fn copy(&mut self, dst: u32, src: u32, n: u32) {
        let (d, s, n) = (dst as usize, src as usize, n as usize);
        let len = self.mem.len();
        if s.checked_add(n).is_none_or(|e| e > len) || d.checked_add(n).is_none_or(|e| e > len) {
            self.fail();
        } else {
            self.mem.copy_within(s..s + n, d);
        }
    }

    // A state (`CPpmd_State`) at `s`: symbol, freq, 32-bit successor.

    #[inline]
    pub fn sym(&self, s: u32) -> u8 {
        self.r8(s)
    }

    #[inline]
    pub fn freq(&self, s: u32) -> u8 {
        self.r8(s.wrapping_add(1))
    }

    #[inline]
    pub fn set_freq(&mut self, s: u32, v: u8) {
        self.w8(s.wrapping_add(1), v);
    }

    #[inline]
    pub fn add_freq(&mut self, s: u32, d: u8) -> u8 {
        let v = self.freq(s).wrapping_add(d);
        self.set_freq(s, v);
        v
    }

    #[inline]
    pub fn succ(&self, s: u32) -> u32 {
        self.r32(s.wrapping_add(2))
    }

    #[inline]
    pub fn set_succ(&mut self, s: u32, v: u32) {
        self.w32(s.wrapping_add(2), v);
    }

    pub fn state(&self, s: u32) -> [u8; STATE_SIZE as usize] {
        self.read(s)
    }

    pub fn set_state(&mut self, s: u32, v: [u8; STATE_SIZE as usize]) {
        self.write(s, v);
    }

    pub fn swap_states(&mut self, a: u32, b: u32) {
        let (x, y) = (self.state(a), self.state(b));
        self.set_state(a, y);
        self.set_state(b, x);
    }

    /// The state of `stats[0..n]` with symbol `sym`, as upstream's
    /// `for (s = STATS(c); s->Symbol != sym; s++);`, but bounded by the
    /// number of states the context has.
    pub fn find_state(&self, stats: u32, n: u32, sym: u8) -> u32 {
        let mut s = stats;
        for _ in 0..n {
            if self.sym(s) == sym {
                return s;
            }
            s = s.wrapping_add(STATE_SIZE);
        }
        self.fail();
        stats
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    pub fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The text the test vectors compress: words picked by xorshift32.
    pub fn text(n: usize) -> Vec<u8> {
        const WORDS: [&str; 16] = [
            "archive", "entry", "the", "format", "reader", "ppmd", "model", "context", "symbol",
            "of", "and", "stream", "zip", "rar", "7z", "data",
        ];
        let mut st = 12345u32;
        let mut out = Vec::new();
        while out.len() < n {
            st ^= st << 13;
            st ^= st >> 17;
            st ^= st << 5;
            out.extend_from_slice(WORDS[(st >> 28) as usize].as_bytes());
            out.push(b' ');
        }
        out.truncate(n);
        out
    }

    /// Damaged copies of `stream`: bit flips, truncations, zeroed or
    /// 0xFF-filled runs and pure noise.
    pub fn mutations(stream: &[u8], count: usize) -> Vec<Vec<u8>> {
        let mut st = 0x9E37_79B9u32;
        let mut next = move |n: usize| {
            st ^= st << 13;
            st ^= st >> 17;
            st ^= st << 5;
            st as usize % n.max(1)
        };
        (0..count)
            .map(|i| {
                let mut d = stream.to_vec();
                match i % 5 {
                    0 => {
                        for _ in 0..1 + next(8) {
                            let p = next(d.len());
                            d[p] ^= 1 << next(8);
                        }
                    }
                    1 => d.truncate(next(d.len())),
                    2 => {
                        let (p, n) = (next(d.len()), 1 + next(64));
                        d.iter_mut().skip(p).take(n).for_each(|b| *b = 0);
                    }
                    3 => {
                        let (p, n) = (next(d.len()), 1 + next(8));
                        d.iter_mut().skip(p).take(n).for_each(|b| *b = 0xFF);
                    }
                    _ => d = (0..200 + next(2000)).map(|_| next(256) as u8).collect(),
                }
                d
            })
            .collect()
    }
}

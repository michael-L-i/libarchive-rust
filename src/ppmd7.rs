/* Ppmd7.c -- PPMdH codec
2010-03-12 : Igor Pavlov : Public domain
This code is based on PPMd var.H (2001): Dmitry Shkarin : Public domain */

// Ported from libarchive/archive_ppmd7.c.
#![allow(dead_code)] // used by the 7zip and rar readers

//! PPMd var. H model, encoder, and the 7z and RAR range decoders.
//!
//! The readers hold one long-lived [`Ppmd7`] and call, as upstream does:
//! `free` / `alloc` / `init` to (re)start a model, [`Ppmd7RangeDec::init`]
//! and [`Ppmd7::decode_symbol`] to decode. RAR sets [`Ppmd7::init_esc`]
//! from the block header before `init`, and `free` keeps it, as
//! `Ppmd7_Free` followed by `Ppmd7_Construct` does.

use crate::ppmd::{
    Arena, ByteIn, K_EXP_ESCAPE, K_INIT_BIN_ESC, MAX_FREQ, PPMD_BIN_SCALE, PPMD_NUM_INDEXES,
    PPMD_PERIOD_BITS, STATE_SIZE, See, UNIT_SIZE, unit_tables, update_prob_0, update_prob_1,
};

pub const PPMD7_MIN_ORDER: u32 = 2;
pub const PPMD7_MAX_ORDER: u32 = 64;
pub const PPMD7_MIN_MEM_SIZE: u32 = 1 << 11;
pub const PPMD7_MAX_MEM_SIZE: u32 = 0xFFFF_FFFF - 12 * 3;

const K_TOP_VALUE: u32 = 1 << 24;
const DUMMY_SEE: usize = 25 * 16;
const NI: u32 = PPMD_NUM_INDEXES as u32;

// A context (`CPpmd7_Context`) at `c`: NumStats u16, SummFreq u16, Stats u32,
// Suffix u32. With one state, that state sits at `c + 2` over SummFreq
// and Stats. A free node: Stamp u16 at 0 (0 means free), NU u16, Next, Prev.
const CTX_SUMM_FREQ: u32 = 2;
const CTX_STATS: u32 = 4;
const CTX_SUFFIX: u32 = 8;
const ONE_STATE: u32 = 2;

pub struct Ppmd7 {
    a: Arena,
    min_context: u32,
    max_context: u32,
    found_state: u32,
    order_fall: u32,
    /// RAR stores it in the block header; the model sets it on escapes.
    pub init_esc: u32,
    prev_success: u32,
    max_order: u32,
    hi_bits_flag: u32,
    run_length: i32,
    init_rl: i32,
    size: u32,
    glue_count: u32,
    lo_unit: u32,
    hi_unit: u32,
    text: u32,
    units_start: u32,
    align_offset: u32,
    indx2units: [u8; PPMD_NUM_INDEXES],
    units2indx: [u8; 128],
    free_list: [u32; PPMD_NUM_INDEXES],
    ns2indx: [u8; 256],
    ns2bsindx: [u8; 256],
    hb2flag: [u8; 256],
    /// `See[25][16]`, then the dummy one.
    see: [See; 25 * 16 + 1],
    bin_summ: [[u16; 64]; 128],
}

impl Default for Ppmd7 {
    fn default() -> Self {
        Self::new()
    }
}

impl Ppmd7 {
    /// `Ppmd7_Construct`.
    pub fn new() -> Ppmd7 {
        let (indx2units, units2indx) = unit_tables();
        let mut ns2bsindx = [3 << 1; 256];
        ns2bsindx[0] = 0;
        ns2bsindx[1] = 1 << 1;
        ns2bsindx[2..11].fill(2 << 1);

        let mut ns2indx = [0u8; 256];
        for (i, v) in ns2indx.iter_mut().enumerate().take(3) {
            *v = i as u8;
        }
        let (mut m, mut k) = (3u32, 1u32);
        for v in ns2indx.iter_mut().skip(3) {
            *v = m as u8;
            k -= 1;
            if k == 0 {
                m += 1;
                k = m - 2;
            }
        }

        let mut hb2flag = [8; 256];
        hb2flag[..0x40].fill(0);

        Ppmd7 {
            a: Arena::default(),
            min_context: 0,
            max_context: 0,
            found_state: 0,
            order_fall: 0,
            init_esc: 0,
            prev_success: 0,
            max_order: 0,
            hi_bits_flag: 0,
            run_length: 0,
            init_rl: 0,
            size: 0,
            glue_count: 0,
            lo_unit: 0,
            hi_unit: 0,
            text: 0,
            units_start: 0,
            align_offset: 0,
            indx2units,
            units2indx,
            free_list: [0; PPMD_NUM_INDEXES],
            ns2indx,
            ns2bsindx,
            hb2flag,
            see: [See::default(); 25 * 16 + 1],
            bin_summ: [[0; 64]; 128],
        }
    }

    /// `Ppmd7_Free`.
    pub fn free(&mut self) {
        self.a = Arena::default();
        self.size = 0;
    }

    pub fn was_allocated(&self) -> bool {
        self.a.is_allocated()
    }

    /// `Ppmd7_Alloc`: false if `size` is too small or the memory isn't
    /// available.
    pub fn alloc(&mut self, size: u32) -> bool {
        if !self.a.is_allocated() || self.size != size {
            // RestartModel() below assumes that size >= UNIT_SIZE (see the
            // calculation of the root context).
            if size < UNIT_SIZE {
                return false;
            }
            self.free();
            self.align_offset = 4 - (size & 3);
            // One more unit at the end for GlueFreeBlocks' list head.
            let total = u64::from(self.align_offset) + u64::from(size) + u64::from(UNIT_SIZE);
            match Arena::alloc(total) {
                Some(a) => self.a = a,
                None => return false,
            }
            self.size = size;
        }
        true
    }

    fn i2u(&self, indx: u32) -> u32 {
        self.indx2units
            .get(indx as usize)
            .map_or(0, |&u| u32::from(u))
    }

    fn u2i(&self, nu: u32) -> u32 {
        u32::from(self.units2indx[(nu.wrapping_sub(1) & 127) as usize])
    }

    fn u2b(nu: u32) -> u32 {
        nu.wrapping_mul(UNIT_SIZE)
    }

    fn fl(&self, indx: u32) -> u32 {
        self.free_list.get(indx as usize).copied().unwrap_or(0)
    }

    fn set_fl(&mut self, indx: u32, v: u32) {
        match self.free_list.get_mut(indx as usize) {
            Some(f) => *f = v,
            None => self.a.fail(),
        }
    }

    // Context fields.

    fn num_stats(&self, c: u32) -> u32 {
        u32::from(self.a.r16(c))
    }

    fn summ_freq(&self, c: u32) -> u32 {
        u32::from(self.a.r16(c.wrapping_add(CTX_SUMM_FREQ)))
    }

    fn add_summ_freq(&mut self, c: u32, d: u32) {
        let v = self
            .a
            .r16(c.wrapping_add(CTX_SUMM_FREQ))
            .wrapping_add(d as u16);
        self.a.w16(c.wrapping_add(CTX_SUMM_FREQ), v);
    }

    fn stats(&self, c: u32) -> u32 {
        self.a.r32(c.wrapping_add(CTX_STATS))
    }

    fn suffix(&self, c: u32) -> u32 {
        self.a.r32(c.wrapping_add(CTX_SUFFIX))
    }

    // Free-block bookkeeping.

    fn insert_node(&mut self, node: u32, indx: u32) {
        self.a.w32(node, self.fl(indx));
        self.set_fl(indx, node);
    }

    fn remove_node(&mut self, indx: u32) -> u32 {
        let node = self.fl(indx);
        let next = self.a.r32(node);
        self.set_fl(indx, next);
        node
    }

    fn split_block(&mut self, ptr: u32, old_indx: u32, new_indx: u32) {
        let nu = self.i2u(old_indx).wrapping_sub(self.i2u(new_indx));
        let ptr = ptr.wrapping_add(Self::u2b(self.i2u(new_indx)));
        let mut i = self.u2i(nu);
        if self.i2u(i) != nu {
            i = i.wrapping_sub(1);
            let k = self.i2u(i);
            self.insert_node(
                ptr.wrapping_add(Self::u2b(k)),
                nu.wrapping_sub(k).wrapping_sub(1),
            );
        }
        self.insert_node(ptr, i);
    }

    fn glue_free_blocks(&mut self) {
        // Node fields.
        const NU: u32 = 2;
        const NEXT: u32 = 4;
        const PREV: u32 = 8;
        let head = self.align_offset.wrapping_add(self.size);
        let mut n = head;
        // A sound model has at most `size / UNIT_SIZE` free blocks, and each
        // of the three passes takes at most one step per block.
        let mut budget = self.size / UNIT_SIZE * 3 + 2;
        self.glue_count = 255;

        // Create doubly-linked list of free blocks.
        for i in 0..NI {
            let nu = self.i2u(i) as u16;
            let mut next = self.fl(i);
            self.set_fl(i, 0);
            while next != 0 {
                budget = budget.saturating_sub(1);
                if budget == 0 {
                    self.a.fail();
                    return;
                }
                let node = next;
                self.a.w32(node.wrapping_add(NEXT), n);
                self.a.w32(n.wrapping_add(PREV), next);
                n = next;
                next = self.a.r32(node);
                self.a.w16(node, 0);
                self.a.w16(node.wrapping_add(NU), nu);
            }
        }
        self.a.w16(head, 1);
        self.a.w32(head.wrapping_add(NEXT), n);
        self.a.w32(n.wrapping_add(PREV), head);
        if self.lo_unit != self.hi_unit {
            self.a.w16(self.lo_unit, 1);
        }

        // Glue free blocks.
        while n != head {
            budget = budget.saturating_sub(1);
            if budget == 0 || self.a.is_bad() {
                self.a.fail();
                return;
            }
            let node = n;
            let mut nu = u32::from(self.a.r16(node.wrapping_add(NU)));
            loop {
                let node2 = n.wrapping_add(Self::u2b(nu));
                nu = nu.wrapping_add(u32::from(self.a.r16(node2.wrapping_add(NU))));
                if self.a.r16(node2) != 0 || nu >= 0x10000 || self.a.is_bad() {
                    break;
                }
                let (prev2, next2) = (
                    self.a.r32(node2.wrapping_add(PREV)),
                    self.a.r32(node2.wrapping_add(NEXT)),
                );
                self.a.w32(prev2.wrapping_add(NEXT), next2);
                self.a.w32(next2.wrapping_add(PREV), prev2);
                self.a.w16(node.wrapping_add(NU), nu as u16);
            }
            n = self.a.r32(node.wrapping_add(NEXT));
        }

        // Fill lists of free blocks.
        n = self.a.r32(head.wrapping_add(NEXT));
        while n != head {
            budget = budget.saturating_sub(1);
            if budget == 0 || self.a.is_bad() {
                self.a.fail();
                return;
            }
            let mut node = n;
            let next = self.a.r32(node.wrapping_add(NEXT));
            let mut nu = u32::from(self.a.r16(node.wrapping_add(NU)));
            while nu > 128 {
                self.insert_node(node, NI - 1);
                nu -= 128;
                node = node.wrapping_add(Self::u2b(128));
            }
            let mut i = self.u2i(nu);
            if self.i2u(i) != nu {
                i = i.wrapping_sub(1);
                let k = self.i2u(i);
                self.insert_node(
                    node.wrapping_add(Self::u2b(k)),
                    nu.wrapping_sub(k).wrapping_sub(1),
                );
            }
            self.insert_node(node, i);
            n = next;
        }
    }

    /// Returns 0 where upstream returns NULL.
    fn alloc_units_rare(&mut self, indx: u32) -> u32 {
        if self.glue_count == 0 {
            self.glue_free_blocks();
            if self.fl(indx) != 0 {
                return self.remove_node(indx);
            }
        }
        let mut i = indx;
        loop {
            i += 1;
            if i == NI {
                let num_bytes = Self::u2b(self.i2u(indx));
                self.glue_count = self.glue_count.wrapping_sub(1);
                return if self.units_start.wrapping_sub(self.text) > num_bytes {
                    self.units_start = self.units_start.wrapping_sub(num_bytes);
                    self.units_start
                } else {
                    0
                };
            }
            if self.fl(i) != 0 {
                break;
            }
        }
        let ret = self.remove_node(i);
        self.split_block(ret, i, indx);
        ret
    }

    fn alloc_units(&mut self, indx: u32) -> u32 {
        if self.fl(indx) != 0 {
            return self.remove_node(indx);
        }
        let num_bytes = Self::u2b(self.i2u(indx));
        if num_bytes <= self.hi_unit.wrapping_sub(self.lo_unit) {
            let ret = self.lo_unit;
            self.lo_unit = self.lo_unit.wrapping_add(num_bytes);
            return ret;
        }
        self.alloc_units_rare(indx)
    }

    fn shrink_units(&mut self, old_ptr: u32, old_nu: u32, new_nu: u32) -> u32 {
        let i0 = self.u2i(old_nu);
        let i1 = self.u2i(new_nu);
        if i0 == i1 {
            return old_ptr;
        }
        if self.fl(i1) != 0 {
            let ptr = self.remove_node(i1);
            self.a.copy(ptr, old_ptr, Self::u2b(new_nu));
            self.insert_node(old_ptr, i0);
            return ptr;
        }
        self.split_block(old_ptr, i0, i1);
        old_ptr
    }

    fn restart_model(&mut self) {
        self.free_list = [0; PPMD_NUM_INDEXES];
        self.text = self.align_offset;
        self.hi_unit = self.text.wrapping_add(self.size);
        self.units_start = self
            .hi_unit
            .wrapping_sub(self.size / 8 / UNIT_SIZE * 7 * UNIT_SIZE);
        self.lo_unit = self.units_start;
        self.glue_count = 0;

        self.order_fall = self.max_order;
        self.init_rl = -(self.max_order.min(12) as i32) - 1;
        self.run_length = self.init_rl;
        self.prev_success = 0;

        self.hi_unit = self.hi_unit.wrapping_sub(UNIT_SIZE); // AllocContext(p)
        let root = self.hi_unit;
        self.min_context = root;
        self.max_context = root;
        self.a.w32(root.wrapping_add(CTX_SUFFIX), 0);
        self.a.w16(root, 256);
        self.a.w16(root.wrapping_add(CTX_SUMM_FREQ), 256 + 1);
        // AllocUnits(p, PPMD_NUM_INDEXES - 1)
        self.found_state = self.lo_unit;
        self.lo_unit = self.lo_unit.wrapping_add(Self::u2b(256 / 2));
        self.a.w32(root.wrapping_add(CTX_STATS), self.found_state);
        for i in 0..256u32 {
            let s = self.found_state + i * STATE_SIZE;
            self.a.set_state(s, [i as u8, 1, 0, 0, 0, 0]);
        }

        for (i, row) in self.bin_summ.iter_mut().enumerate() {
            for (k, esc) in K_INIT_BIN_ESC.iter().enumerate() {
                let val = (PPMD_BIN_SCALE - u32::from(*esc) / (i as u32 + 2)) as u16;
                for m in (0..64).step_by(8) {
                    row[k + m] = val;
                }
            }
        }

        for i in 0..25 {
            for see in &mut self.see[i * 16..(i + 1) * 16] {
                see.shift = (PPMD_PERIOD_BITS - 4) as u8;
                see.summ = ((5 * i as u32 + 10) << see.shift) as u16;
                see.count = 4;
            }
        }
    }

    /// `Ppmd7_Init`.
    pub fn init(&mut self, max_order: u32) {
        self.max_order = max_order;
        self.a.clear_bad();
        self.restart_model();
        self.see[DUMMY_SEE] = See {
            summ: 0, // unused
            shift: PPMD_PERIOD_BITS as u8,
            count: 64, // unused
        };
    }

    /// Returns 0 where upstream returns NULL.
    fn create_successors(&mut self, skip: bool) -> u32 {
        let found = self.found_state;
        let f_sym = self.a.sym(found);
        let mut c = self.min_context;
        let up_branch = self.a.succ(found);
        let mut ps = [0u32; PPMD7_MAX_ORDER as usize];
        let mut num_ps = 0;

        if !skip {
            ps[0] = found;
            num_ps = 1;
        }

        while self.suffix(c) != 0 {
            c = self.suffix(c);
            let s = if self.num_stats(c) != 1 {
                self.a.find_state(self.stats(c), self.num_stats(c), f_sym)
            } else {
                c.wrapping_add(ONE_STATE)
            };
            let successor = self.a.succ(s);
            if successor != up_branch {
                c = successor;
                if num_ps == 0 {
                    return c;
                }
                break;
            }
            match ps.get_mut(num_ps) {
                Some(slot) => *slot = s,
                None => {
                    self.a.fail();
                    return 0;
                }
            }
            num_ps += 1;
        }

        let up_sym = self.a.r8(up_branch);
        let up_succ = up_branch.wrapping_add(1);
        let up_freq = if self.num_stats(c) == 1 {
            self.a.freq(c.wrapping_add(ONE_STATE))
        } else {
            let s = self.a.find_state(self.stats(c), self.num_stats(c), up_sym);
            let cf = u32::from(self.a.freq(s)).wrapping_sub(1);
            let s0 = self
                .summ_freq(c)
                .wrapping_sub(self.num_stats(c))
                .wrapping_sub(cf);
            let v = if cf.wrapping_mul(2) <= s0 {
                u32::from(cf.wrapping_mul(5) > s0)
            } else {
                cf.wrapping_mul(2)
                    .wrapping_add(s0.wrapping_mul(3))
                    .wrapping_sub(1)
                    .checked_div(s0.wrapping_mul(2))
                    .unwrap_or(0)
            };
            (1u32.wrapping_add(v)) as u8
        };
        let [su0, su1, su2, su3] = up_succ.to_le_bytes();
        let up_state = [up_sym, up_freq, su0, su1, su2, su3];

        while num_ps != 0 {
            // Create child: AllocContext(p).
            let c1;
            if self.hi_unit != self.lo_unit {
                self.hi_unit = self.hi_unit.wrapping_sub(UNIT_SIZE);
                c1 = self.hi_unit;
            } else if self.fl(0) != 0 {
                c1 = self.remove_node(0);
            } else {
                c1 = self.alloc_units_rare(0);
                if c1 == 0 {
                    return 0;
                }
            }
            self.a.w16(c1, 1);
            self.a.set_state(c1.wrapping_add(ONE_STATE), up_state);
            self.a.w32(c1.wrapping_add(CTX_SUFFIX), c);
            num_ps -= 1;
            self.a.set_succ(ps[num_ps], c1);
            c = c1;
        }
        c
    }

    fn update_model(&mut self) {
        let found = self.found_state;
        let f_sym = self.a.sym(found);
        let mut f_successor = self.a.succ(found);
        let min = self.min_context;

        if u32::from(self.a.freq(found)) < MAX_FREQ / 4 && self.suffix(min) != 0 {
            let c = self.suffix(min);
            if self.num_stats(c) == 1 {
                let s = c.wrapping_add(ONE_STATE);
                if self.a.freq(s) < 32 {
                    self.a.add_freq(s, 1);
                }
            } else {
                let mut s = self.stats(c);
                if self.a.sym(s) != f_sym {
                    s = self.a.find_state(s, self.num_stats(c), f_sym);
                    let prev = s.wrapping_sub(STATE_SIZE);
                    if self.a.freq(s) >= self.a.freq(prev) {
                        self.a.swap_states(s, prev);
                        s = prev;
                    }
                }
                if u32::from(self.a.freq(s)) < MAX_FREQ - 9 {
                    self.a.add_freq(s, 2);
                    self.add_summ_freq(c, 2);
                }
            }
        }

        if self.order_fall == 0 {
            let c = self.create_successors(true);
            self.min_context = c;
            self.max_context = c;
            if c == 0 {
                self.restart_model();
                return;
            }
            self.a.set_succ(self.found_state, c);
            return;
        }

        self.a.w8(self.text, f_sym);
        self.text = self.text.wrapping_add(1);
        let mut successor = self.text;
        if self.text >= self.units_start {
            self.restart_model();
            return;
        }

        if f_successor != 0 {
            if f_successor <= successor {
                let cs = self.create_successors(false);
                if cs == 0 {
                    self.restart_model();
                    return;
                }
                f_successor = cs;
            }
            self.order_fall = self.order_fall.wrapping_sub(1);
            if self.order_fall == 0 {
                successor = f_successor;
                self.text = self
                    .text
                    .wrapping_sub(u32::from(self.max_context != self.min_context));
            }
        } else {
            self.a.set_succ(self.found_state, successor);
            f_successor = self.min_context;
        }

        let ns = self.num_stats(min);
        let f_freq = u32::from(self.a.freq(self.found_state));
        let s0 = self
            .summ_freq(min)
            .wrapping_sub(ns)
            .wrapping_sub(f_freq.wrapping_sub(1));

        let mut c = self.max_context;
        while c != self.min_context {
            if c == 0 {
                self.a.fail();
                return;
            }
            let ns1 = self.num_stats(c);
            if ns1 != 1 {
                if ns1 & 1 == 0 {
                    // Expand for one UNIT.
                    let old_nu = ns1 >> 1;
                    let i = self.u2i(old_nu);
                    if i != self.u2i(old_nu + 1) {
                        let ptr = self.alloc_units(i + 1);
                        if ptr == 0 {
                            self.restart_model();
                            return;
                        }
                        let old_ptr = self.stats(c);
                        self.a.copy(ptr, old_ptr, Self::u2b(old_nu));
                        self.insert_node(old_ptr, i);
                        self.a.w32(c.wrapping_add(CTX_STATS), ptr);
                    }
                }
                let sf = self.summ_freq(c);
                let d = u32::from(2 * ns1 < ns) + 2 * u32::from((4 * ns1 <= ns) & (sf <= 8 * ns1));
                self.add_summ_freq(c, d);
            } else {
                let s = self.alloc_units(0);
                if s == 0 {
                    self.restart_model();
                    return;
                }
                let one = self.a.state(c.wrapping_add(ONE_STATE));
                self.a.set_state(s, one);
                self.a.w32(c.wrapping_add(CTX_STATS), s);
                let f = u32::from(self.a.freq(s));
                let f = if f < MAX_FREQ / 4 - 1 {
                    f << 1
                } else {
                    MAX_FREQ - 4
                };
                self.a.set_freq(s, f as u8);
                let sf = f + self.init_esc + u32::from(ns > 3);
                self.a.w16(c.wrapping_add(CTX_SUMM_FREQ), sf as u16);
            }
            let sf0 = self.summ_freq(c);
            let mut cf = 2 * f_freq * (sf0 + 6);
            let sf = s0.wrapping_add(sf0);
            if cf < 6 * sf {
                cf = 1 + u32::from(cf > sf) + u32::from(cf >= 4 * sf);
                self.add_summ_freq(c, 3);
            } else {
                cf = 4
                    + u32::from(cf >= 9 * sf)
                    + u32::from(cf >= 12 * sf)
                    + u32::from(cf >= 15 * sf);
                self.add_summ_freq(c, cf);
            }
            let s = self.stats(c).wrapping_add(ns1 * STATE_SIZE);
            self.a.set_succ(s, successor);
            self.a.w8(s, f_sym);
            self.a.set_freq(s, cf as u8);
            self.a.w16(c, (ns1 + 1) as u16);
            c = self.suffix(c);
        }
        self.max_context = f_successor;
        self.min_context = f_successor;
    }

    fn rescale(&mut self) {
        let min = self.min_context;
        let stats = self.stats(min);
        let mut s = self.found_state;
        // Move the found state to the front.
        {
            let tmp = self.a.state(s);
            if s < stats || !(s - stats).is_multiple_of(STATE_SIZE) {
                self.a.fail();
                return;
            }
            while s != stats {
                let prev = self.a.state(s - STATE_SIZE);
                self.a.set_state(s, prev);
                s = s.wrapping_sub(STATE_SIZE);
            }
            self.a.set_state(s, tmp);
        }
        let mut esc_freq = self.summ_freq(min).wrapping_sub(u32::from(self.a.freq(s)));
        self.a.add_freq(s, 4);
        let adder = u32::from(self.order_fall != 0);
        let f = ((u32::from(self.a.freq(s)) + adder) >> 1) as u8;
        self.a.set_freq(s, f);
        let mut sum_freq = u32::from(f);

        let ns = self.num_stats(min);
        for _ in 1..ns {
            s = s.wrapping_add(STATE_SIZE);
            esc_freq = esc_freq.wrapping_sub(u32::from(self.a.freq(s)));
            let f = ((u32::from(self.a.freq(s)) + adder) >> 1) as u8;
            self.a.set_freq(s, f);
            sum_freq += u32::from(f);
            if f > self.a.freq(s - STATE_SIZE) {
                let mut s1 = s;
                let tmp = self.a.state(s1);
                loop {
                    let prev = self.a.state(s1 - STATE_SIZE);
                    self.a.set_state(s1, prev);
                    s1 -= STATE_SIZE;
                    if s1 == stats || tmp[1] <= self.a.freq(s1 - STATE_SIZE) {
                        break;
                    }
                }
                self.a.set_state(s1, tmp);
            }
        }

        if self.a.freq(s) == 0 {
            let num_stats = ns;
            let mut i = 0;
            loop {
                i += 1;
                s = s.wrapping_sub(STATE_SIZE);
                if self.a.freq(s) != 0 || i >= num_stats {
                    break;
                }
            }
            esc_freq = esc_freq.wrapping_add(i);
            let new_ns = num_stats.wrapping_sub(i) & 0xFFFF;
            self.a.w16(min, new_ns as u16);
            if new_ns == 1 {
                let mut tmp = self.a.state(stats);
                loop {
                    tmp[1] -= tmp[1] >> 1;
                    esc_freq >>= 1;
                    if esc_freq <= 1 {
                        break;
                    }
                }
                let indx = self.u2i((num_stats + 1) >> 1);
                self.insert_node(stats, indx);
                self.found_state = min.wrapping_add(ONE_STATE);
                self.a.set_state(self.found_state, tmp);
                return;
            }
            let n0 = (num_stats + 1) >> 1;
            let n1 = (new_ns + 1) >> 1;
            if n0 != n1 {
                let p = self.shrink_units(stats, n0, n1);
                self.a.w32(min.wrapping_add(CTX_STATS), p);
            }
        }
        let sf = sum_freq.wrapping_add(esc_freq).wrapping_sub(esc_freq >> 1);
        self.a.w16(min.wrapping_add(CTX_SUMM_FREQ), sf as u16);
        self.found_state = self.stats(min);
    }

    /// Returns the index of the SEE context and the escape frequency.
    fn make_esc_freq(&mut self, num_masked: u32) -> (usize, u32) {
        let min = self.min_context;
        let ns = self.num_stats(min);
        if ns != 256 {
            let non_masked = ns.wrapping_sub(num_masked);
            let row =
                usize::from(self.ns2indx[(non_masked.wrapping_sub(1) & 255) as usize]).min(24);
            let col = u32::from(non_masked < self.num_stats(self.suffix(min)).wrapping_sub(ns))
                + 2 * u32::from(self.summ_freq(min) < 11 * ns)
                + 4 * u32::from(num_masked > non_masked)
                + self.hi_bits_flag;
            let see = row * 16 + (col & 15) as usize;
            (see, self.see[see].take_esc_freq())
        } else {
            (DUMMY_SEE, 1)
        }
    }

    fn next_context(&mut self) {
        let c = self.a.succ(self.found_state);
        if self.order_fall == 0 && c > self.text {
            self.min_context = c;
            self.max_context = c;
        } else {
            self.update_model();
        }
    }

    fn update1(&mut self) {
        let s = self.found_state;
        self.a.add_freq(s, 4);
        self.add_summ_freq(self.min_context, 4);
        let prev = s.wrapping_sub(STATE_SIZE);
        if self.a.freq(s) > self.a.freq(prev) {
            self.a.swap_states(s, prev);
            self.found_state = prev;
            if u32::from(self.a.freq(prev)) > MAX_FREQ {
                self.rescale();
            }
        }
        self.next_context();
    }

    fn update1_0(&mut self) {
        let s = self.found_state;
        self.prev_success =
            u32::from(2 * u32::from(self.a.freq(s)) > self.summ_freq(self.min_context));
        self.run_length = self.run_length.wrapping_add(self.prev_success as i32);
        self.add_summ_freq(self.min_context, 4);
        if u32::from(self.a.add_freq(s, 4)) > MAX_FREQ {
            self.rescale();
        }
        self.next_context();
    }

    fn update_bin(&mut self) {
        let s = self.found_state;
        let f = self.a.freq(s);
        self.a.set_freq(s, f + u8::from(f < 128));
        self.prev_success = 1;
        self.run_length = self.run_length.wrapping_add(1);
        self.next_context();
    }

    fn update2(&mut self) {
        let s = self.found_state;
        self.add_summ_freq(self.min_context, 4);
        if u32::from(self.a.add_freq(s, 4)) > MAX_FREQ {
            self.rescale();
        }
        self.run_length = self.init_rl;
        self.update_model();
    }

    /// `Ppmd7_DecodeSymbol`: the next byte, -1 at the end mark, or -2 for
    /// data the model can't have produced.
    pub fn decode_symbol<B: ByteIn + ?Sized>(
        &mut self,
        rc: &mut Ppmd7RangeDec,
        src: &mut B,
    ) -> i32 {
        let r = if self.a.is_bad() {
            -2
        } else {
            self.decode_symbol_inner(rc, src)
        };
        if self.a.is_bad() || rc.failed { -2 } else { r }
    }

    fn decode_symbol_inner<B: ByteIn + ?Sized>(
        &mut self,
        rc: &mut Ppmd7RangeDec,
        src: &mut B,
    ) -> i32 {
        // 0xFF for symbols still possible, 0 for masked ones; set up on the
        // first escape, as upstream does, to keep the common path short.
        let mut char_mask: [u8; 256];
        let min = self.min_context;
        let ns = self.num_stats(min);
        if ns != 1 {
            let mut s = self.stats(min);
            let summ = self.summ_freq(min);
            let count = rc.get_threshold(summ);
            let mut hi_cnt = u32::from(self.a.freq(s));
            if count < hi_cnt {
                rc.decode(src, 0, hi_cnt);
                self.found_state = s;
                let symbol = self.a.sym(s);
                self.update1_0();
                return i32::from(symbol);
            }
            self.prev_success = 0;
            for _ in 1..ns {
                s = s.wrapping_add(STATE_SIZE);
                let f = u32::from(self.a.freq(s));
                hi_cnt += f;
                if hi_cnt > count {
                    rc.decode(src, hi_cnt - f, f);
                    self.found_state = s;
                    let symbol = self.a.sym(s);
                    self.update1();
                    return i32::from(symbol);
                }
            }
            if count >= summ {
                return -2;
            }
            self.hi_bits_flag = u32::from(self.hb2flag[usize::from(self.a.sym(self.found_state))]);
            rc.decode(src, hi_cnt, summ - hi_cnt);
            char_mask = [0xFF; 256];
            char_mask[usize::from(self.a.sym(s))] = 0;
            for _ in 1..ns {
                s = s.wrapping_sub(STATE_SIZE);
                char_mask[usize::from(self.a.sym(s))] = 0;
            }
        } else {
            let one = min.wrapping_add(ONE_STATE);
            let hb = u32::from(self.hb2flag[usize::from(self.a.sym(self.found_state))]);
            self.hi_bits_flag = hb;
            let suffix_ns = self.num_stats(self.suffix(min));
            let row = (u32::from(self.a.freq(one)).wrapping_sub(1) & 127) as usize;
            let col = self.prev_success
                + u32::from(self.ns2bsindx[(suffix_ns.wrapping_sub(1) & 255) as usize])
                + hb
                + 2 * u32::from(self.hb2flag[usize::from(self.a.sym(one))])
                + ((self.run_length >> 26) & 0x20) as u32;
            let col = (col & 63) as usize;
            let prob = self.bin_summ[row][col];
            if rc.decode_bit(src, u32::from(prob)) == 0 {
                self.bin_summ[row][col] = update_prob_0(prob);
                self.found_state = one;
                let symbol = self.a.sym(one);
                self.update_bin();
                return i32::from(symbol);
            }
            let prob = update_prob_1(prob);
            self.bin_summ[row][col] = prob;
            self.init_esc = u32::from(K_EXP_ESCAPE[usize::from(prob >> 10) & 15]);
            char_mask = [0xFF; 256];
            char_mask[usize::from(self.a.sym(one))] = 0;
            self.prev_success = 0;
        }
        let mut ps = [0u32; 256];
        loop {
            let num_masked = self.num_stats(self.min_context);
            loop {
                self.order_fall = self.order_fall.wrapping_add(1);
                let suffix = self.suffix(self.min_context);
                if suffix == 0 {
                    return -1;
                }
                self.min_context = suffix;
                if self.num_stats(suffix) != num_masked {
                    break;
                }
            }
            let min = self.min_context;
            let ns = self.num_stats(min);
            let mut hi_cnt = 0;
            let mut s = self.stats(min);
            let num = ns.wrapping_sub(num_masked) as usize;
            let mut i = 0;
            // The unmasked states are all among the context's first `ns`.
            for _ in 0..ns {
                if i == num {
                    break;
                }
                let k = char_mask[usize::from(self.a.sym(s))];
                hi_cnt += u32::from(self.a.freq(s) & k);
                ps[i & 255] = s;
                s = s.wrapping_add(STATE_SIZE);
                i += usize::from(k & 1);
            }
            if i != num {
                self.a.fail();
                return -2;
            }

            let (see, esc_freq) = self.make_esc_freq(num_masked);
            let freq_sum = esc_freq + hi_cnt;
            let count = rc.get_threshold(freq_sum);

            if count < hi_cnt {
                let mut hi = 0;
                let mut found = ps[0];
                for &p in &ps[..num & 255] {
                    found = p;
                    hi += u32::from(self.a.freq(p));
                    if hi > count {
                        break;
                    }
                }
                let f = u32::from(self.a.freq(found));
                rc.decode(src, hi - f, f);
                self.see[see].update();
                self.found_state = found;
                let symbol = self.a.sym(found);
                self.update2();
                return i32::from(symbol);
            }
            if count >= freq_sum {
                return -2;
            }
            rc.decode(src, hi_cnt, freq_sum - hi_cnt);
            let see = &mut self.see[see];
            see.summ = see.summ.wrapping_add(freq_sum as u16);
            for &p in &ps[..num & 255] {
                char_mask[usize::from(self.a.sym(p))] = 0;
            }
        }
    }
}

/// The range decoder of `CPpmd7z_RangeDec`, for 7z or for RAR.
pub struct Ppmd7RangeDec {
    range: u32,
    code: u32,
    low: u32,
    bottom: u32,
    rar: bool,
    /// Set when the stream drives the decoder into a division by zero
    /// (upstream crashes); symbols decode as -2 from then on.
    failed: bool,
}

impl Ppmd7RangeDec {
    /// `Ppmd7z_RangeDec_CreateVTable`.
    pub fn new_7z() -> Ppmd7RangeDec {
        Self::new(false)
    }

    /// `PpmdRAR_RangeDec_CreateVTable`.
    pub fn new_rar() -> Ppmd7RangeDec {
        Self::new(true)
    }

    fn new(rar: bool) -> Ppmd7RangeDec {
        Ppmd7RangeDec {
            range: 0,
            code: 0,
            low: 0,
            bottom: 0,
            rar,
            failed: false,
        }
    }

    /// `Ppmd7z_RangeDec_Init` / `PpmdRAR_RangeDec_Init`: false if the
    /// stream doesn't start like a PPMd stream.
    pub fn init<B: ByteIn + ?Sized>(&mut self, src: &mut B) -> bool {
        self.failed = false;
        if !self.rar && src.read_byte() != 0 {
            return false;
        }
        self.low = 0;
        self.bottom = 0;
        self.range = 0xFFFF_FFFF;
        for _ in 0..4 {
            self.code = (self.code << 8) | u32::from(src.read_byte());
        }
        if self.code == 0xFFFF_FFFF {
            return false;
        }
        if self.rar {
            self.bottom = 0x8000;
        }
        true
    }

    /// `Ppmd7z_RangeDec_IsFinishedOK`.
    pub fn is_finished_ok(&self) -> bool {
        self.code == 0
    }

    fn get_threshold(&mut self, total: u32) -> u32 {
        match self.range.checked_div(total) {
            Some(r) if r != 0 => {
                self.range = r;
                self.code.wrapping_sub(self.low) / r
            }
            _ => {
                self.failed = true;
                u32::MAX
            }
        }
    }

    fn normalize<B: ByteIn + ?Sized>(&mut self, src: &mut B) {
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= K_TOP_VALUE {
                if self.range >= self.bottom {
                    break;
                }
                self.range = self.low.wrapping_neg() & (self.bottom - 1);
            }
            if self.range == 0 {
                // Never ends: every shift leaves it zero.
                self.failed = true;
                break;
            }
            self.code = (self.code << 8) | u32::from(src.read_byte());
            self.range <<= 8;
            self.low <<= 8;
        }
    }

    fn decode<B: ByteIn + ?Sized>(&mut self, src: &mut B, start: u32, size: u32) {
        if self.rar {
            self.low = self.low.wrapping_add(start.wrapping_mul(self.range));
        } else {
            self.code = self.code.wrapping_sub(start.wrapping_mul(self.range));
        }
        self.range = self.range.wrapping_mul(size);
        self.normalize(src);
    }

    fn decode_bit<B: ByteIn + ?Sized>(&mut self, src: &mut B, size0: u32) -> u32 {
        if self.rar {
            let value = self.get_threshold(PPMD_BIN_SCALE);
            if value < size0 {
                self.decode(src, 0, size0);
                0
            } else {
                self.decode(src, size0, PPMD_BIN_SCALE - size0);
                1
            }
        } else {
            let new_bound = (self.range >> 14).wrapping_mul(size0);
            let bit = if self.code < new_bound {
                self.range = new_bound;
                0
            } else {
                self.code = self.code.wrapping_sub(new_bound);
                self.range = self.range.wrapping_sub(new_bound);
                1
            };
            self.normalize(src);
            bit
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ppmd::testutil::{mutations, text, unhex};

    // Streams made by upstream's Ppmd7 encoder (the 7zip writer's), which
    // is also where the RAR one comes from: the same model with RAR's
    // carryless range coder. The text is `text(n)`.
    const A_7Z_O32_M64K: &str = "\
0079ed7d975d6b29600adf2a2524d4d8a52b3718476ed7da56f269a00202610a\
1e500189edbdbf74de0b1dd93bd2a75f1f357f3ddd4373d87df0aad738167c79\
36edd83586da14f745668c4a8fd7021b27ce66ad9ace396198ca400441d11ee0\
35ea81d4326924a8ffce98ed2d1358cbea60cfce08b4f7a32737c6ebb780e9ec\
f55b3006f309414d7fe773380301d43c72b6142db6e26df55851d51c72b3eb9a\
ce002ca89f379d468035a91017401e38da44194fdd43cac83cb424e99b4a90c4\
f1f15280348dc3c42c6da35eea57d4c0f5239514e3ad0c6200d865aed48e5753\
84081ac260a698bdbcf815b8193c2b6447d6fc02eb28d8ee35dfe9951a672063\
54199226665fe454efba0a8e7157d5030f05da510970da6f7706bceadd0bb8a8\
e03263e56b325f59ae4be014d1106ec2a6c9c978bf05924ca0f0ad218d7ffadb\
e9cf2a58f723332374dda6828bc4342396fd3b1fd4a783ffec8408dd206e48c5\
510e915626e9de23c2eaaec04cc79f960ec8182a5b696aa0897fc26e504babfe\
cfb0338e765570edb06551f0b3e6fb5fd5885071981af15be6376e1f73bc2f19\
0e0ed18ffe290c7092260c15aa84473f1884182f01d7c0874d92b220e902cb85\
9b00";
    const B_7Z_O6_M2K: &str = "\
0079ed7d975d6b29600adf2a2524d4d8a52b3718476ed7da56f269a00202610a\
1e500189edbdc05bc3090fe2d96e6a69d6998e5fd8996f91f21d1ce58c1b9872\
dcdbe1e7fe56ec1e348fa2a3e3b0dca1b08128f83a34835f91485c66a672de49\
f2d2da1c21d43f3ea9e338e379e0ededf0cdf570e7481c2e6fdadcddf271dc13\
ab2ce4e07447602c9493cf0cc21d702ca92c916fa721fa0b75dd05029370a8ef\
1f055312f79c972436ff966bdf42df5d5da7de8e7b50e94a7bf7efdbd0526b53\
03e520bbfc8e7263f03371a63aed8eaed0b78e353020d2de00a082eb3d49f546\
55b50291399ad2ea1adab7bdb4bbc069d3bc7883b23660e35d3cddd232679ce4\
90fb2b054f3bd1b23d4bdcf2db95427e25f884ea4253a8f486cb4822fd00c776\
3aa990880a3231709af7dd6e539019f27bd1781cb13abb4acde7bc0fa1b907be\
5dad78167d69f2922c1f4cb4f64849bc802f4c08f52f81ad1e893ae4ec28f5dc\
e0907ecbe3e0bd9c2012ab6ca9ba0122eb0a36fed68db40227ff373828a9d5fe\
300671a2a1c319c8aa57e021e268befafd3ffc24994d7b6ce1a361ff9d3070df\
882b591ce417781882c324f3bf4a632766f069e84c84499ecd6d26ffddce10a5\
efc7f881119468631f6b019d3d22d835ceefecf1786f10fddc1c3960d924668b\
493cd41a35ccdff255d7b10a7dd9b0f53c13e2f1dc20bb86e14e78c3a3e235db\
46c6d352236f8acfe262166e4481b1d4db4d2f7a09b31b1e3c124b5135628431\
f2aeceef712aac64f68667734eae4a1a32b858e2bc723ead80743d2ebc687388\
7638d25e884675ea7fc01eb7375bc58e7aad831a038a2047ab6e544b700bcf4c\
0f92bd9b324f09f759cb855e9c0f51105c85e99cf4c55787acaeafab2eb76a19\
d0257fd226fb5992ffc4e310634acdb420d3f0bbdcf145e51882424c8ba5741e\
d6e6d6ab9657835326e46eb2f0ee5727ee247c1d76fab20e9f2f19aac444e951\
25e843f3cc0ea43eba3700bd33e4659436e163702c53446f36c881f865c7b769\
a08588529360786255ec0c55c73f0a4595fc46a6e838a74fd2a7ef23173def17\
30bcc24926fe2e26e2dc6d04ba30b6c37d44538ec5f196d33034566baf078bba\
616cd4aa7aa253430724ccfb9fa1d989291a9fc51a6a7af18ff526d0c1bef2d6\
8d1c61faba3a579d2d4f4ba51ee1b63bfe464a0da6631a886055a91288c136e1\
64c0f95475e16a34fceb3ed7035728a6b300c8265678a450a96dae7890e2dc4c\
056ac5d48e5b53ff27c550f1dec97afae4263d807c1f563310b9a593729a00";
    const C_RAR_O8_M4K: &str = "\
79ed7d6d2d0f98062f16ef87de0b8bd9adf55d7117034a42d202734664ab0b89\
6e27be0085e1ecc06fc41d9bda1487b096d781bacc368f3f96d647c8ccf095ea\
c343af7530f0008aef0bd25c2d9471a7704e105cc185a94bffe996953c07d31c\
7ffcece814ff707f0ba72c566be4b3beb8cf84a44ea54f73a43979070c78526d\
cbccd564826a45710fba6ae3cd03a980f93e5803e78ffcc1e756653eb08ff2ec\
e4d6d4cb7a1a3dfcb6a1a2e5c48038edb24d51cdaa23f3c6ac4a3ee3f85adcad\
9abf7262d271a55085d8691d1cf13e4f6242d273000c75d4f8731270dcb8e2c4\
b347c0706d53e8f9ded286c13689d502129fbf14725723f6b6f869986a17e22c\
4c9017838e52ed2ead55184d3379eae6a69c51655135d9090e8be477b08cb7d4\
12cdcda1a009f5980f39be9db52824a02599af90131f26c559ba065219e783e3\
a77f9fe0f9b6d46a2248f3eca0ad3bb44927c4c5931111fd4bbc7f296cc8276e\
45e458bdf370c033a6499bb4db240d31db74343363eda5f7490fd28f9dc3deaf\
566f77e69ae0df9219da30d595ac0f109e324ed06fd946417b090139c37b6c76\
34d629ce985fce55e0bc62067b7d574ecd3ad88d42605b50fe5d76c46c40e8ea\
71e363b5eb599b83e707eaf53f9481752d0ca05f3316c8e42883a95df04245c7\
69766408c37394120c6acc63570eecca334c897127ea3cdee13a2bec0dc52474\
47ecb22cfc758c1802d859e070e43a67b9bfbf31d563e75912ca63c7060b2c49\
0b3abf8250a1e4ebfc752baa279688a224749632ac4df24080339ef3c96fa4dd\
395a7435c9377345df98371fc9035b2a1423efebc4948b57ed9030ff33a3ff01\
2802299fbd9bd7f413fa16fd48ec205a853b6689aed2851e9f4d1ae3cc1e277b\
9ade99996dc03e4703593622c6896925dc57b1b143125c3c0ba5ae5b6f7e00";
    fn decode(
        stream: &[u8],
        mut rc: Ppmd7RangeDec,
        order: u32,
        mem: u32,
        max: usize,
    ) -> (Vec<u8>, i32, bool) {
        let mut pos = 0;
        let mut src = || {
            pos += 1;
            stream.get(pos - 1).copied().unwrap_or(0)
        };
        let mut p = Ppmd7::new();
        assert!(p.alloc(mem));
        let ok = rc.init(&mut src);
        p.init(order);
        let (mut out, mut last) = (Vec::new(), 0);
        while ok && out.len() < max {
            last = p.decode_symbol(&mut rc, &mut src);
            if last < 0 {
                break;
            }
            out.push(last as u8);
        }
        (out, last, ok && rc.is_finished_ok())
    }

    #[test]
    fn decodes_7z_streams() {
        for (hex, order, mem, n) in [
            (A_7Z_O32_M64K, 32, 1 << 16, 2500),
            (B_7Z_O6_M2K, 6, 2048, 1200),
        ] {
            let (out, last, finished) = decode(&unhex(hex), Ppmd7RangeDec::new_7z(), order, mem, n);
            assert_eq!(out, text(n));
            assert_eq!(last, i32::from(*out.last().unwrap()));
            assert!(finished);
        }
    }

    #[test]
    fn decodes_rar_stream() {
        let (out, ..) = decode(
            &unhex(C_RAR_O8_M4K),
            Ppmd7RangeDec::new_rar(),
            8,
            4096,
            1200,
        );
        assert_eq!(out, text(1200));
    }

    #[test]
    fn rejects_streams_that_do_not_start_like_ppmd() {
        let mut src = || 1;
        assert!(!Ppmd7RangeDec::new_7z().init(&mut src));
        let mut src = || 0xFF;
        assert!(!Ppmd7RangeDec::new_rar().init(&mut src));
    }

    #[test]
    fn alloc_follows_upstream() {
        let mut p = Ppmd7::new();
        assert!(!p.alloc(UNIT_SIZE - 1));
        assert!(!p.was_allocated());
        assert!(p.alloc(PPMD7_MIN_MEM_SIZE));
        assert!(p.was_allocated());
        p.free();
        assert!(!p.was_allocated());
    }

    #[test]
    fn corrupt_streams_do_not_panic() {
        let streams = [
            (A_7Z_O32_M64K, false, 32, 1 << 16),
            (B_7Z_O6_M2K, false, 6, 2048),
            (C_RAR_O8_M4K, true, 8, 4096),
        ];
        for (hex, rar, order, mem) in streams {
            for stream in mutations(&unhex(hex), 100) {
                // Decode with the other coder too: noise either way.
                for rar in [rar, !rar] {
                    let rc = if rar {
                        Ppmd7RangeDec::new_rar()
                    } else {
                        Ppmd7RangeDec::new_7z()
                    };
                    let (out, last, _) = decode(&stream, rc, order, mem, 20_000);
                    assert!(out.len() <= 20_000 && last >= -2);
                }
            }
        }
    }
}

/// The 7-Zip range encoder of Ppmd7Enc.c. Bytes can be drained between symbols.
pub(crate) struct Ppmd7RangeEnc {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u64,
    pub output: Vec<u8>,
}
impl Ppmd7RangeEnc {
    pub(crate) fn new() -> Self {
        Self {
            low: 0,
            range: u32::MAX,
            cache: 0,
            cache_size: 1,
            output: Vec::new(),
        }
    }
    fn shift_low(&mut self) {
        if (self.low as u32) < 0xff000000 || self.low >> 32 != 0 {
            let mut temp = self.cache;
            loop {
                self.output.push(temp.wrapping_add((self.low >> 32) as u8));
                temp = 0xff;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = (self.low as u32 >> 24) as u8;
        }
        self.cache_size += 1;
        self.low = u64::from((self.low as u32).wrapping_shl(8));
    }
    fn normalize(&mut self) {
        while self.range < 1 << 24 {
            self.range <<= 8;
            self.shift_low();
        }
    }
    fn encode(&mut self, start: u32, size: u32, total: u32) -> bool {
        if total == 0 || size == 0 {
            return false;
        }
        self.range /= total;
        self.low += u64::from(start) * u64::from(self.range);
        self.range = self.range.wrapping_mul(size);
        if self.range == 0 {
            return false;
        }
        self.normalize();
        true
    }
    fn bit(&mut self, prob: u32, one: bool) {
        let bound = (self.range >> 14) * prob;
        if one {
            self.low += u64::from(bound);
            self.range -= bound;
        } else {
            self.range = bound;
        }
        self.normalize();
    }
    pub(crate) fn finish(&mut self) {
        for _ in 0..5 {
            self.shift_low();
        }
    }
}
impl Ppmd7 {
    pub(crate) fn encode_symbol(&mut self, rc: &mut Ppmd7RangeEnc, symbol: i32) -> bool {
        if self.a.is_bad() {
            return false;
        }
        let ok = self.encode_symbol_inner(rc, symbol);
        ok && !self.a.is_bad()
    }
    fn encode_symbol_inner(&mut self, rc: &mut Ppmd7RangeEnc, symbol: i32) -> bool {
        let mut mask = [0xffu8; 256];
        let min = self.min_context;
        let ns = self.num_stats(min);
        if ns != 1 {
            let mut s = self.stats(min);
            let mut sum = 0;
            for i in 0..ns {
                let freq = u32::from(self.a.freq(s));
                if i32::from(self.a.sym(s)) == symbol {
                    if !rc.encode(sum, freq, self.summ_freq(min)) {
                        return false;
                    }
                    self.found_state = s;
                    if i == 0 {
                        self.update1_0()
                    } else {
                        self.update1()
                    }
                    return true;
                }
                if i == 0 {
                    self.prev_success = 0
                }
                sum += freq;
                mask[usize::from(self.a.sym(s))] = 0;
                s = s.wrapping_add(STATE_SIZE);
            }
            self.hi_bits_flag = u32::from(self.hb2flag[usize::from(self.a.sym(self.found_state))]);
            let total = self.summ_freq(min);
            if sum >= total || !rc.encode(sum, total - sum, total) {
                return false;
            }
        } else {
            let one = min.wrapping_add(ONE_STATE);
            let hb = u32::from(self.hb2flag[usize::from(self.a.sym(self.found_state))]);
            self.hi_bits_flag = hb;
            let suffix_ns = self.num_stats(self.suffix(min));
            let row = (u32::from(self.a.freq(one)).wrapping_sub(1) & 127) as usize;
            let col = (self.prev_success
                + u32::from(self.ns2bsindx[(suffix_ns.wrapping_sub(1) & 255) as usize])
                + hb
                + 2 * u32::from(self.hb2flag[usize::from(self.a.sym(one))])
                + ((self.run_length >> 26) & 0x20) as u32)
                & 63;
            let prob = self.bin_summ[row][col as usize];
            if i32::from(self.a.sym(one)) == symbol {
                rc.bit(u32::from(prob), false);
                self.bin_summ[row][col as usize] = update_prob_0(prob);
                self.found_state = one;
                self.update_bin();
                return true;
            }
            rc.bit(u32::from(prob), true);
            let prob = update_prob_1(prob);
            self.bin_summ[row][col as usize] = prob;
            self.init_esc = u32::from(K_EXP_ESCAPE[usize::from(prob >> 10) & 15]);
            mask[usize::from(self.a.sym(one))] = 0;
            self.prev_success = 0;
        }
        loop {
            let masked = self.num_stats(self.min_context);
            loop {
                self.order_fall = self.order_fall.wrapping_add(1);
                let suffix = self.suffix(self.min_context);
                if suffix == 0 {
                    return symbol == -1;
                }
                self.min_context = suffix;
                if self.num_stats(suffix) != masked {
                    break;
                }
            }
            let (see, escape) = self.make_esc_freq(masked);
            let mut states = Vec::new();
            let mut s = self.stats(self.min_context);
            let mut sum = 0;
            let mut found = None;
            for _ in 0..self.num_stats(self.min_context) {
                if mask[usize::from(self.a.sym(s))] != 0 {
                    let freq = u32::from(self.a.freq(s));
                    if i32::from(self.a.sym(s)) == symbol {
                        found = Some((s, sum, freq));
                    }
                    sum += freq;
                    states.push(s);
                }
                s = s.wrapping_add(STATE_SIZE);
            }
            let total = sum + escape;
            if let Some((s, low, freq)) = found {
                if !rc.encode(low, freq, total) {
                    return false;
                }
                self.see[see].update();
                self.found_state = s;
                self.update2();
                return true;
            }
            if !rc.encode(sum, escape, total) {
                return false;
            }
            self.see[see].summ = self.see[see].summ.wrapping_add(total as u16);
            for s in states {
                mask[usize::from(self.a.sym(s))] = 0;
            }
        }
    }
}

#[cfg(test)]
mod encoder_tests {
    use super::*;
    #[test]
    fn encoder_round_trip_restarts_and_escapes() {
        let input: Vec<u8> = (0..25_000)
            .map(|i| ((i * 19 + i / 77) % 256) as u8)
            .collect();
        for memory in [2048, 1 << 20] {
            let mut model = Ppmd7::new();
            assert!(model.alloc(memory));
            model.init(6);
            let mut encoder = Ppmd7RangeEnc::new();
            for &b in &input {
                assert!(model.encode_symbol(&mut encoder, b.into()));
            }
            assert!(model.encode_symbol(&mut encoder, -1));
            encoder.finish();
            let stream = encoder.output;
            let mut at = 0;
            let mut src = || {
                let b = stream.get(at).copied().unwrap_or(0);
                at += 1;
                b
            };
            let mut decoder = Ppmd7RangeDec::new_7z();
            assert!(decoder.init(&mut src));
            let mut model = Ppmd7::new();
            assert!(model.alloc(memory));
            model.init(6);
            for &b in &input {
                assert_eq!(model.decode_symbol(&mut decoder, &mut src), i32::from(b));
            }
            assert_eq!(model.decode_symbol(&mut decoder, &mut src), -1);
            assert!(decoder.is_finished_ok());
        }
    }
}

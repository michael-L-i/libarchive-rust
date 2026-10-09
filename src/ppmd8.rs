/* Ppmd8.c -- PPMdI codec
2016-05-21 : Igor Pavlov : Public domain
This code is based on PPMd var.I (2002): Dmitry Shkarin : Public domain */

// Ported from libarchive/archive_ppmd8.c (decoder side).
#![allow(dead_code)] // the zip reader leaves some of the API unused

//! PPMd var. I decoder, with its carryless range decoder.
//!
//! The zip reader holds one long-lived [`Ppmd8`] and calls, as upstream
//! does: `free` / `alloc`, `range_dec_init`, `init`, then `decode_symbol`.
//! `free` keeps the escape estimate `InitEsc`, which upstream's `Free` and
//! `Construct` leave alone, so a second stream starts from the first's.

use crate::ppmd::{
    Arena, ByteIn, K_EXP_ESCAPE, K_INIT_BIN_ESC, MAX_FREQ, PPMD_BIN_SCALE, PPMD_NUM_INDEXES,
    PPMD_PERIOD_BITS, STATE_SIZE, See, UNIT_SIZE, unit_tables, update_prob_0, update_prob_1,
};

pub const PPMD8_MIN_ORDER: u32 = 2;
pub const PPMD8_MAX_ORDER: u32 = 16;
/// The restore method that cuts the model off instead of restarting it.
/// (Upstream's FREEZE method is not supported.)
pub const PPMD8_RESTORE_METHOD_RESTART: u32 = 0;
pub const PPMD8_RESTORE_METHOD_CUT_OFF: u32 = 1;

const K_TOP: u32 = 1 << 24;
const K_BOT: u32 = 1 << 15;
const EMPTY_NODE: u32 = 0xFFFF_FFFF;
const DUMMY_SEE: usize = 24 * 32;
const NI: u32 = PPMD_NUM_INDEXES as u32;

// A context (`CPpmd8_Context`) at `c`: NumStats u8 (count - 1), Flags u8,
// SummFreq u16, Stats u32, Suffix u32. With one state, that state sits
// at `c + 2`. A free node: Stamp u32 (EMPTY_NODE if free), Next u32, NU u32.
const CTX_FLAGS: u32 = 1;
const CTX_SUMM_FREQ: u32 = 2;
const CTX_STATS: u32 = 4;
const CTX_SUFFIX: u32 = 8;
const ONE_STATE: u32 = 2;
const NODE_NEXT: u32 = 4;
const NODE_NU: u32 = 8;

/// A link to patch: a free list head or the `Next` of a node.
#[derive(Clone, Copy)]
enum Link {
    FreeList(u32),
    Next(u32),
}

pub struct Ppmd8 {
    a: Arena,
    min_context: u32,
    max_context: u32,
    found_state: u32,
    order_fall: u32,
    init_esc: u32,
    prev_success: u32,
    max_order: u32,
    run_length: i32,
    init_rl: i32,
    size: u32,
    glue_count: u32,
    lo_unit: u32,
    hi_unit: u32,
    text: u32,
    units_start: u32,
    align_offset: u32,
    restore_method: u32,
    range: u32,
    code: u32,
    low: u32,
    /// Set when the stream drives the range decoder into a division by
    /// zero (upstream crashes); symbols decode as -2 from then on.
    failed: bool,
    indx2units: [u8; PPMD_NUM_INDEXES],
    units2indx: [u8; 128],
    free_list: [u32; PPMD_NUM_INDEXES],
    stamps: [u32; PPMD_NUM_INDEXES],
    ns2bsindx: [u8; 256],
    ns2indx: [u8; 260],
    /// `See[24][32]`, then the dummy one.
    see: [See; 24 * 32 + 1],
    bin_summ: [[u16; 64]; 25],
}

impl Default for Ppmd8 {
    fn default() -> Self {
        Self::new()
    }
}

impl Ppmd8 {
    /// `Ppmd8_Construct`.
    pub fn new() -> Ppmd8 {
        let (indx2units, units2indx) = unit_tables();
        let mut ns2bsindx = [3 << 1; 256];
        ns2bsindx[0] = 0;
        ns2bsindx[1] = 1 << 1;
        ns2bsindx[2..11].fill(2 << 1);

        let mut ns2indx = [0u8; 260];
        for (i, v) in ns2indx.iter_mut().enumerate().take(5) {
            *v = i as u8;
        }
        let (mut m, mut k) = (5u32, 1u32);
        for v in ns2indx.iter_mut().skip(5) {
            *v = m as u8;
            k -= 1;
            if k == 0 {
                m += 1;
                k = m - 4;
            }
        }

        Ppmd8 {
            a: Arena::default(),
            min_context: 0,
            max_context: 0,
            found_state: 0,
            order_fall: 0,
            init_esc: 0,
            prev_success: 0,
            max_order: 0,
            run_length: 0,
            init_rl: 0,
            size: 0,
            glue_count: 0,
            lo_unit: 0,
            hi_unit: 0,
            text: 0,
            units_start: 0,
            align_offset: 0,
            restore_method: 0,
            range: 0,
            code: 0,
            low: 0,
            failed: false,
            indx2units,
            units2indx,
            free_list: [0; PPMD_NUM_INDEXES],
            stamps: [0; PPMD_NUM_INDEXES],
            ns2bsindx,
            ns2indx,
            see: [See::default(); 24 * 32 + 1],
            bin_summ: [[0; 64]; 25],
        }
    }

    /// `Ppmd8_Free`.
    pub fn free(&mut self) {
        self.a = Arena::default();
        self.size = 0;
    }

    pub fn was_allocated(&self) -> bool {
        self.a.is_allocated()
    }

    /// `Ppmd8_Alloc`: false if the memory isn't available.
    pub fn alloc(&mut self, size: u32) -> bool {
        if !self.a.is_allocated() || self.size != size {
            self.free();
            self.align_offset = 4 - (size & 3);
            match Arena::alloc(u64::from(self.align_offset) + u64::from(size)) {
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

    fn add_stamps(&mut self, indx: u32, d: u32) {
        match self.stamps.get_mut(indx as usize) {
            Some(s) => *s = s.wrapping_add(d),
            None => self.a.fail(),
        }
    }

    // Context fields.

    fn num_stats(&self, c: u32) -> u32 {
        u32::from(self.a.r8(c))
    }

    fn flags(&self, c: u32) -> u32 {
        u32::from(self.a.r8(c.wrapping_add(CTX_FLAGS)))
    }

    fn set_flags(&mut self, c: u32, v: u32) {
        self.a.w8(c.wrapping_add(CTX_FLAGS), v as u8);
    }

    fn summ_freq(&self, c: u32) -> u32 {
        u32::from(self.a.r16(c.wrapping_add(CTX_SUMM_FREQ)))
    }

    fn add_summ_freq(&mut self, c: u32, d: u32) -> u32 {
        let v = self
            .a
            .r16(c.wrapping_add(CTX_SUMM_FREQ))
            .wrapping_add(d as u16);
        self.a.w16(c.wrapping_add(CTX_SUMM_FREQ), v);
        u32::from(v)
    }

    fn stats(&self, c: u32) -> u32 {
        self.a.r32(c.wrapping_add(CTX_STATS))
    }

    fn set_stats(&mut self, c: u32, v: u32) {
        self.a.w32(c.wrapping_add(CTX_STATS), v);
    }

    fn suffix(&self, c: u32) -> u32 {
        self.a.r32(c.wrapping_add(CTX_SUFFIX))
    }

    /// `Flags` bit for a symbol of the upper half of the alphabet.
    fn high(&self, s: u32) -> u32 {
        u32::from(self.a.sym(s) >= 0x40)
    }

    // Free-block bookkeeping.

    fn insert_node(&mut self, node: u32, indx: u32) {
        self.a.w32(node, EMPTY_NODE);
        self.a.w32(node.wrapping_add(NODE_NEXT), self.fl(indx));
        self.a.w32(node.wrapping_add(NODE_NU), self.i2u(indx));
        self.set_fl(indx, node);
        self.add_stamps(indx, 1);
    }

    fn remove_node(&mut self, indx: u32) -> u32 {
        let node = self.fl(indx);
        let next = self.a.r32(node.wrapping_add(NODE_NEXT));
        self.set_fl(indx, next);
        self.add_stamps(indx, u32::MAX);
        node
    }

    fn get_link(&self, l: Link) -> u32 {
        match l {
            Link::FreeList(i) => self.fl(i),
            Link::Next(n) => self.a.r32(n.wrapping_add(NODE_NEXT)),
        }
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
        let mut head = 0;
        // Where the next kept node gets linked: the head, or a node's Next.
        let mut prev: Option<u32> = None;
        // Every node is visited at most once in a sound model.
        let mut budget = self.size / UNIT_SIZE + 2;

        self.glue_count = 1 << 13;
        self.stamps = [0; PPMD_NUM_INDEXES];

        // Order-0 context is always at top UNIT, so we don't need guard
        // NODE at the end. All blocks up to LoUnit can be free, so we need
        // guard NODE at LoUnit.
        if self.lo_unit != self.hi_unit {
            self.a.w32(self.lo_unit, 0);
        }

        // Glue free blocks.
        for i in 0..NI {
            let mut next = self.fl(i);
            self.set_fl(i, 0);
            while next != 0 {
                budget = budget.saturating_sub(1);
                if budget == 0 || self.a.is_bad() {
                    self.a.fail();
                    return;
                }
                let node = next;
                if self.a.r32(node.wrapping_add(NODE_NU)) != 0 {
                    match prev {
                        None => head = next,
                        Some(p) => self.a.w32(p.wrapping_add(NODE_NEXT), next),
                    }
                    prev = Some(node);
                    loop {
                        let nu = self.a.r32(node.wrapping_add(NODE_NU));
                        let node2 = node.wrapping_add(Self::u2b(nu));
                        if self.a.r32(node2) != EMPTY_NODE || self.a.is_bad() {
                            break;
                        }
                        let nu2 = self.a.r32(node2.wrapping_add(NODE_NU));
                        self.a.w32(node.wrapping_add(NODE_NU), nu.wrapping_add(nu2));
                        self.a.w32(node2.wrapping_add(NODE_NU), 0);
                        budget = budget.saturating_sub(1);
                        if budget == 0 {
                            self.a.fail();
                            return;
                        }
                    }
                }
                next = self.a.r32(node.wrapping_add(NODE_NEXT));
            }
        }
        match prev {
            None => head = 0,
            Some(p) => self.a.w32(p.wrapping_add(NODE_NEXT), 0),
        }

        // Fill lists of free blocks.
        while head != 0 {
            budget = budget.saturating_sub(1);
            if budget == 0 || self.a.is_bad() {
                self.a.fail();
                return;
            }
            let mut node = head;
            head = self.a.r32(node.wrapping_add(NODE_NEXT));
            let mut nu = self.a.r32(node.wrapping_add(NODE_NU));
            if nu == 0 {
                continue;
            }
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

    fn free_units(&mut self, ptr: u32, nu: u32) {
        let indx = self.u2i(nu);
        self.insert_node(ptr, indx);
    }

    fn special_free_unit(&mut self, ptr: u32) {
        if ptr != self.units_start {
            self.insert_node(ptr, 0);
        } else {
            self.units_start = self.units_start.wrapping_add(UNIT_SIZE);
        }
    }

    fn move_units_up(&mut self, old_ptr: u32, nu: u32) -> u32 {
        let indx = self.u2i(nu);
        if old_ptr > self.units_start.wrapping_add(16 * 1024) || old_ptr > self.fl(indx) {
            return old_ptr;
        }
        let ptr = self.remove_node(indx);
        self.a.copy(ptr, old_ptr, Self::u2b(nu));
        if old_ptr != self.units_start {
            self.insert_node(old_ptr, indx);
        } else {
            self.units_start = self.units_start.wrapping_add(Self::u2b(self.i2u(indx)));
        }
        ptr
    }

    fn expand_text_area(&mut self) {
        let mut count = [0u32; PPMD_NUM_INDEXES];
        let mut budget = self.size / UNIT_SIZE + 2;
        if self.lo_unit != self.hi_unit {
            self.a.w32(self.lo_unit, 0);
        }

        let mut node = self.units_start;
        while self.a.r32(node) == EMPTY_NODE {
            let nu = self.a.r32(node.wrapping_add(NODE_NU));
            budget = budget.saturating_sub(1);
            if nu == 0 || budget == 0 || self.a.is_bad() {
                self.a.fail();
                return;
            }
            self.a.w32(node, 0);
            let i = self.u2i(nu) as usize;
            count[i] += 1;
            node = node.wrapping_add(Self::u2b(nu));
        }
        self.units_start = node;

        for i in 0..NI {
            let mut next = Link::FreeList(i);
            while count[i as usize] != 0 {
                let mut node = self.get_link(next);
                loop {
                    budget = budget.saturating_sub(1);
                    if node == 0 || budget == 0 || self.a.is_bad() {
                        self.a.fail();
                        return;
                    }
                    if self.a.r32(node) != 0 {
                        break;
                    }
                    let n = self.a.r32(node.wrapping_add(NODE_NEXT));
                    match next {
                        Link::FreeList(i) => self.set_fl(i, n),
                        Link::Next(p) => self.a.w32(p.wrapping_add(NODE_NEXT), n),
                    }
                    node = n;
                    self.add_stamps(i, u32::MAX);
                    count[i as usize] -= 1;
                    if count[i as usize] == 0 {
                        break;
                    }
                }
                next = Link::Next(node);
            }
        }
    }

    fn restart_model(&mut self) {
        self.free_list = [0; PPMD_NUM_INDEXES];
        self.stamps = [0; PPMD_NUM_INDEXES];
        self.reset_text(0);
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
        self.a.w8(root, 255);
        self.set_flags(root, 0);
        self.a.w16(root.wrapping_add(CTX_SUMM_FREQ), 256 + 1);
        // AllocUnits(p, PPMD_NUM_INDEXES - 1)
        self.found_state = self.lo_unit;
        self.lo_unit = self.lo_unit.wrapping_add(Self::u2b(256 / 2));
        self.set_stats(root, self.found_state);
        for i in 0..256u32 {
            let s = self.found_state.wrapping_add(i * STATE_SIZE);
            self.a.set_state(s, [i as u8, 1, 0, 0, 0, 0]);
        }

        let mut i = 0;
        for m in 0..25 {
            while usize::from(self.ns2indx[i]) == m {
                i += 1;
            }
            for (k, esc) in K_INIT_BIN_ESC.iter().enumerate() {
                let val = (PPMD_BIN_SCALE - u32::from(*esc) / (i as u32 + 1)) as u16;
                for r in (0..64).step_by(8) {
                    self.bin_summ[m][k + r] = val;
                }
            }
        }

        let mut i = 0;
        for m in 0..24 {
            while usize::from(self.ns2indx[i + 3]) == m + 3 {
                i += 1;
            }
            for see in &mut self.see[m * 32..(m + 1) * 32] {
                see.shift = (PPMD_PERIOD_BITS - 4) as u8;
                see.summ = ((2 * i as u32 + 5) << see.shift) as u16;
                see.count = 7;
            }
        }
    }

    fn reset_text(&mut self, offs: u32) {
        self.text = self.align_offset.wrapping_add(offs);
    }

    /// `Ppmd8_Init`.
    pub fn init(&mut self, max_order: u32, restore_method: u32) {
        self.max_order = max_order;
        self.restore_method = restore_method;
        self.a.clear_bad();
        self.restart_model();
        self.see[DUMMY_SEE] = See {
            summ: 0, // unused
            shift: PPMD_PERIOD_BITS as u8,
            count: 64, // unused
        };
    }

    fn refresh(&mut self, ctx: u32, old_nu: u32, scale: u32) {
        let mut i = self.num_stats(ctx);
        let mut s = self.shrink_units(self.stats(ctx), old_nu, (i + 2) >> 1);
        self.set_stats(ctx, s);
        let mut flags = (self.flags(ctx) & (0x10 + 0x04 * scale)) + 0x08 * self.high(s);
        let mut esc_freq = self.summ_freq(ctx).wrapping_sub(u32::from(self.a.freq(s)));
        let f = ((u32::from(self.a.freq(s)) + scale) >> scale) as u8;
        self.a.set_freq(s, f);
        let mut sum_freq = u32::from(f);
        while i != 0 {
            i -= 1;
            s = s.wrapping_add(STATE_SIZE);
            esc_freq = esc_freq.wrapping_sub(u32::from(self.a.freq(s)));
            let f = ((u32::from(self.a.freq(s)) + scale) >> scale) as u8;
            self.a.set_freq(s, f);
            sum_freq += u32::from(f);
            flags |= 0x08 * self.high(s);
        }
        let sf = sum_freq.wrapping_add(esc_freq.wrapping_add(scale) >> scale);
        self.a.w16(ctx.wrapping_add(CTX_SUMM_FREQ), sf as u16);
        self.set_flags(ctx, flags);
    }

    /// Returns the new reference of `ctx`, or 0 if it was freed.
    fn cut_off(&mut self, ctx: u32, order: u32) -> u32 {
        if self.num_stats(ctx) == 0 {
            let s = ctx.wrapping_add(ONE_STATE);
            if self.a.succ(s) >= self.units_start {
                if order < self.max_order {
                    let r = self.cut_off(self.a.succ(s), order + 1);
                    self.a.set_succ(s, r);
                } else {
                    self.a.set_succ(s, 0);
                }
                if self.a.succ(s) != 0 || order <= 9 {
                    // O_BOUND
                    return ctx;
                }
            }
            self.special_free_unit(ctx);
            return 0;
        }

        let tmp = (self.num_stats(ctx) + 2) >> 1;
        let stats = self.move_units_up(self.stats(ctx), tmp);
        self.set_stats(ctx, stats);

        let mut i = self.num_stats(ctx) as i32;
        let mut s = stats.wrapping_add(i as u32 * STATE_SIZE);
        while s >= stats {
            if self.a.succ(s) < self.units_start {
                let s2 = stats.wrapping_add(i as u32 * STATE_SIZE);
                i -= 1;
                self.a.set_succ(s, 0);
                self.a.swap_states(s, s2);
            } else if order < self.max_order {
                let r = self.cut_off(self.a.succ(s), order + 1);
                self.a.set_succ(s, r);
            } else {
                self.a.set_succ(s, 0);
            }
            if s < STATE_SIZE {
                break;
            }
            s -= STATE_SIZE;
        }

        if i != self.num_stats(ctx) as i32 && order != 0 {
            self.a.w8(ctx, i as u8);
            let s = self.stats(ctx);
            if i < 0 {
                self.free_units(s, tmp);
                self.special_free_unit(ctx);
                return 0;
            }
            if i == 0 {
                let flags = (self.flags(ctx) & 0x10) + 0x08 * self.high(s);
                self.set_flags(ctx, flags);
                let st = self.a.state(s);
                self.a.set_state(ctx.wrapping_add(ONE_STATE), st);
                self.free_units(s, tmp);
                let one = ctx.wrapping_add(ONE_STATE);
                let f = (u32::from(self.a.freq(one)) + 11) >> 3;
                self.a.set_freq(one, f as u8);
            } else {
                let scale = u32::from(self.summ_freq(ctx) > 16 * i as u32);
                self.refresh(ctx, tmp, scale);
            }
        }
        ctx
    }

    fn get_used_memory(&self) -> u32 {
        let mut v = 0u32;
        for i in 0..NI {
            v = v.wrapping_add(self.stamps[i as usize].wrapping_mul(self.i2u(i)));
        }
        self.size
            .wrapping_sub(self.hi_unit.wrapping_sub(self.lo_unit))
            .wrapping_sub(self.units_start.wrapping_sub(self.text))
            .wrapping_sub(Self::u2b(v))
    }

    fn restore_model(&mut self, c1: u32) {
        self.reset_text(0);
        let mut c = self.max_context;
        while c != c1 {
            if c == 0 {
                self.a.fail();
                return;
            }
            let ns = self.num_stats(c).wrapping_sub(1) & 0xFF;
            self.a.w8(c, ns as u8);
            if ns == 0 {
                let s = self.stats(c);
                let flags = (self.flags(c) & 0x10) + 0x08 * self.high(s);
                self.set_flags(c, flags);
                let st = self.a.state(s);
                self.a.set_state(c.wrapping_add(ONE_STATE), st);
                self.special_free_unit(s);
                let one = c.wrapping_add(ONE_STATE);
                let f = (u32::from(self.a.freq(one)) + 11) >> 3;
                self.a.set_freq(one, f as u8);
            } else {
                self.refresh(c, (ns + 3) >> 1, 0);
            }
            c = self.suffix(c);
        }

        while c != self.min_context {
            if c == 0 {
                self.a.fail();
                return;
            }
            let ns = self.num_stats(c);
            if ns == 0 {
                let one = c.wrapping_add(ONE_STATE);
                let f = self.a.freq(one);
                self.a.set_freq(one, f - (f >> 1));
            } else if self.add_summ_freq(c, 4) > 128 + 4 * ns {
                self.refresh(c, (ns + 2) >> 1, 1);
            }
            c = self.suffix(c);
        }

        if self.restore_method == PPMD8_RESTORE_METHOD_RESTART
            || self.get_used_memory() < (self.size >> 1)
        {
            self.restart_model();
        } else {
            while self.suffix(self.max_context) != 0 {
                self.max_context = self.suffix(self.max_context);
            }
            // The loop ends once enough is freed. Bound it so a model that
            // can't be cut down restarts instead of spinning.
            for _ in 0..1000 {
                self.cut_off(self.max_context, 0);
                self.expand_text_area();
                if self.get_used_memory() <= 3 * (self.size >> 2) || self.a.is_bad() {
                    self.glue_count = 0;
                    self.order_fall = self.max_order;
                    return;
                }
            }
            self.restart_model();
        }
    }

    /// Returns 0 where upstream returns NULL. `s1` is 0 for NULL.
    fn create_successors(&mut self, skip: bool, mut s1: u32, mut c: u32) -> u32 {
        let found = self.found_state;
        let f_sym = self.a.sym(found);
        let up_branch = self.a.succ(found);
        // PPMD8_MAX_ORDER + 1: fixed over Shkarin's code.
        let mut ps = [0u32; PPMD8_MAX_ORDER as usize + 1];
        let mut num_ps = 0;

        if !skip {
            ps[0] = found;
            num_ps = 1;
        }

        while self.suffix(c) != 0 {
            c = self.suffix(c);
            let s;
            if s1 != 0 {
                s = s1;
                s1 = 0;
            } else if self.num_stats(c) != 0 {
                s = self
                    .a
                    .find_state(self.stats(c), self.num_stats(c) + 1, f_sym);
                if u32::from(self.a.freq(s)) < MAX_FREQ - 9 {
                    self.a.add_freq(s, 1);
                    self.add_summ_freq(c, 1);
                }
            } else {
                s = c.wrapping_add(ONE_STATE);
                let d =
                    u32::from(self.num_stats(self.suffix(c)) == 0) & u32::from(self.a.freq(s) < 24);
                self.a.add_freq(s, d as u8);
            }
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
        let flags = 0x10 * u32::from(f_sym >= 0x40) + 0x08 * u32::from(up_sym >= 0x40);

        let up_freq = if self.num_stats(c) == 0 {
            self.a.freq(c.wrapping_add(ONE_STATE))
        } else {
            let s = self
                .a
                .find_state(self.stats(c), self.num_stats(c) + 1, up_sym);
            let cf = u32::from(self.a.freq(s)).wrapping_sub(1);
            let s0 = self
                .summ_freq(c)
                .wrapping_sub(self.num_stats(c))
                .wrapping_sub(cf);
            let v = if cf.wrapping_mul(2) <= s0 {
                u32::from(cf.wrapping_mul(5) > s0)
            } else {
                cf.wrapping_add(s0.wrapping_mul(2))
                    .wrapping_sub(3)
                    .checked_div(s0)
                    .unwrap_or(0)
            };
            1u32.wrapping_add(v) as u8
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
            self.a.w8(c1, 0);
            self.set_flags(c1, flags);
            self.a.set_state(c1.wrapping_add(ONE_STATE), up_state);
            self.a.w32(c1.wrapping_add(CTX_SUFFIX), c);
            num_ps -= 1;
            self.a.set_succ(ps[num_ps], c1);
            c = c1;
        }
        c
    }

    /// Returns 0 where upstream returns NULL. `s1` is 0 for NULL.
    fn reduce_order(&mut self, mut s1: u32, mut c: u32) -> u32 {
        let mut s;
        let c1 = c;
        let up_branch = self.text;
        let found = self.found_state;
        let f_sym = self.a.sym(found);

        self.a.set_succ(found, up_branch);
        self.order_fall = self.order_fall.wrapping_add(1);

        loop {
            if s1 != 0 {
                c = self.suffix(c);
                s = s1;
                s1 = 0;
            } else {
                if self.suffix(c) == 0 {
                    return c;
                }
                c = self.suffix(c);
                if self.num_stats(c) != 0 {
                    s = self.stats(c);
                    if self.a.sym(s) != f_sym {
                        s = self.a.find_state(s, self.num_stats(c) + 1, f_sym);
                    }
                    if u32::from(self.a.freq(s)) < MAX_FREQ - 9 {
                        self.a.add_freq(s, 2);
                        self.add_summ_freq(c, 2);
                    }
                } else {
                    s = c.wrapping_add(ONE_STATE);
                    self.a.add_freq(s, u8::from(self.a.freq(s) < 32));
                }
            }
            if c == 0 {
                self.a.fail();
                return 0;
            }
            if self.a.succ(s) != 0 {
                break;
            }
            self.a.set_succ(s, up_branch);
            self.order_fall = self.order_fall.wrapping_add(1);
        }

        if self.a.succ(s) <= up_branch {
            let s2 = self.found_state;
            self.found_state = s;
            let successor = self.create_successors(false, 0, c);
            self.a.set_succ(s, successor);
            self.found_state = s2;
        }

        if self.order_fall == 1 && c1 == self.max_context {
            self.a.set_succ(self.found_state, self.a.succ(s));
            self.text = self.text.wrapping_sub(1);
        }
        self.a.succ(s)
    }

    fn update_model(&mut self) {
        let found = self.found_state;
        let mut f_successor = self.a.succ(found);
        let f_freq = u32::from(self.a.freq(found));
        let f_sym = self.a.sym(found);
        let mut s = 0;

        if f_freq < MAX_FREQ / 4 && self.suffix(self.min_context) != 0 {
            let c = self.suffix(self.min_context);
            if self.num_stats(c) == 0 {
                s = c.wrapping_add(ONE_STATE);
                if self.a.freq(s) < 32 {
                    self.a.add_freq(s, 1);
                }
            } else {
                s = self.stats(c);
                if self.a.sym(s) != f_sym {
                    s = self.a.find_state(s, self.num_stats(c) + 1, f_sym);
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

        let mut c = self.max_context;
        if self.order_fall == 0 && f_successor != 0 {
            let cs = self.create_successors(true, s, self.min_context);
            if cs == 0 {
                self.a.set_succ(self.found_state, 0);
                self.restore_model(c);
            } else {
                self.a.set_succ(self.found_state, cs);
                self.max_context = cs;
            }
            return;
        }

        self.a.w8(self.text, f_sym);
        self.text = self.text.wrapping_add(1);
        let mut successor = self.text;
        if self.text >= self.units_start {
            self.restore_model(c);
            return;
        }

        if f_successor == 0 {
            let cs = self.reduce_order(s, self.min_context);
            if cs == 0 {
                self.restore_model(c);
                return;
            }
            f_successor = cs;
        } else if f_successor < self.units_start {
            let cs = self.create_successors(false, s, self.min_context);
            if cs == 0 {
                self.restore_model(c);
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

        let min = self.min_context;
        let ns = self.num_stats(min);
        let s0 = self.summ_freq(min).wrapping_sub(ns).wrapping_sub(f_freq);
        let flag = 0x08 * u32::from(f_sym >= 0x40);

        while c != min {
            if c == 0 {
                self.a.fail();
                return;
            }
            let ns1 = self.num_stats(c);
            if ns1 != 0 {
                if ns1 & 1 != 0 {
                    // Expand for one UNIT.
                    let old_nu = (ns1 + 1) >> 1;
                    let i = self.u2i(old_nu);
                    if i != self.u2i(old_nu + 1) {
                        let ptr = self.alloc_units(i + 1);
                        if ptr == 0 {
                            self.restore_model(c);
                            return;
                        }
                        let old_ptr = self.stats(c);
                        self.a.copy(ptr, old_ptr, Self::u2b(old_nu));
                        self.insert_node(old_ptr, i);
                        self.set_stats(c, ptr);
                    }
                }
                self.add_summ_freq(c, u32::from(3 * ns1 + 1 < ns));
            } else {
                let s2 = self.alloc_units(0);
                if s2 == 0 {
                    self.restore_model(c);
                    return;
                }
                let one = self.a.state(c.wrapping_add(ONE_STATE));
                self.a.set_state(s2, one);
                self.set_stats(c, s2);
                let f = u32::from(self.a.freq(s2));
                let f = if f < MAX_FREQ / 4 - 1 {
                    f << 1
                } else {
                    MAX_FREQ - 4
                };
                self.a.set_freq(s2, f as u8);
                let sf = f + self.init_esc + u32::from(ns > 2);
                self.a.w16(c.wrapping_add(CTX_SUMM_FREQ), sf as u16);
            }
            let sf0 = self.summ_freq(c);
            let mut cf = 2 * f_freq * (sf0 + 6);
            let sf = s0.wrapping_add(sf0);
            if cf < 6 * sf {
                cf = 1 + u32::from(cf > sf) + u32::from(cf >= 4 * sf);
                self.add_summ_freq(c, 4);
            } else {
                cf = 4 + u32::from(cf > 9 * sf) + u32::from(cf > 12 * sf) + u32::from(cf > 15 * sf);
                self.add_summ_freq(c, cf);
            }
            let s2 = self.stats(c).wrapping_add((ns1 + 1) * STATE_SIZE);
            self.a.set_succ(s2, successor);
            self.a.w8(s2, f_sym);
            self.a.set_freq(s2, cf as u8);
            let flags = self.flags(c) | flag;
            self.set_flags(c, flags);
            self.a.w8(c, (ns1 + 1) as u8);
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
            if s < stats || !(s - stats).is_multiple_of(STATE_SIZE) {
                self.a.fail();
                return;
            }
            let tmp = self.a.state(s);
            while s != stats {
                let prev = self.a.state(s - STATE_SIZE);
                self.a.set_state(s, prev);
                s -= STATE_SIZE;
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
        for _ in 0..ns {
            s = s.wrapping_add(STATE_SIZE);
            esc_freq = esc_freq.wrapping_sub(u32::from(self.a.freq(s)));
            let f = ((u32::from(self.a.freq(s)) + adder) >> 1) as u8;
            self.a.set_freq(s, f);
            sum_freq += u32::from(f);
            if f > self.a.freq(s.wrapping_sub(STATE_SIZE)) {
                let mut s1 = s;
                let tmp = self.a.state(s1);
                loop {
                    let prev = self.a.state(s1.wrapping_sub(STATE_SIZE));
                    self.a.set_state(s1, prev);
                    s1 = s1.wrapping_sub(STATE_SIZE);
                    if s1 == stats || tmp[1] <= self.a.freq(s1.wrapping_sub(STATE_SIZE)) {
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
                if self.a.freq(s) != 0 || i > num_stats {
                    break;
                }
            }
            esc_freq = esc_freq.wrapping_add(i);
            let new_ns = num_stats.wrapping_sub(i) & 0xFF;
            self.a.w8(min, new_ns as u8);
            if new_ns == 0 {
                let mut tmp = self.a.state(stats);
                tmp[1] = ((2 * u32::from(tmp[1]))
                    .wrapping_add(esc_freq)
                    .wrapping_sub(1)
                    .checked_div(esc_freq)
                    .unwrap_or(0)) as u8;
                if u32::from(tmp[1]) > MAX_FREQ / 3 {
                    tmp[1] = (MAX_FREQ / 3) as u8;
                }
                let indx = self.u2i((num_stats + 2) >> 1);
                self.insert_node(stats, indx);
                let flags = (self.flags(min) & 0x10) + 0x08 * u32::from(tmp[0] >= 0x40);
                self.set_flags(min, flags);
                self.found_state = min.wrapping_add(ONE_STATE);
                self.a.set_state(self.found_state, tmp);
                return;
            }
            let n0 = (num_stats + 2) >> 1;
            let n1 = (new_ns + 2) >> 1;
            if n0 != n1 {
                let p = self.shrink_units(stats, n0, n1);
                self.set_stats(min, p);
            }
            let mut flags = self.flags(min) & !0x08;
            let mut s = self.stats(min);
            flags |= 0x08 * self.high(s);
            for _ in 0..new_ns {
                s = s.wrapping_add(STATE_SIZE);
                flags |= 0x08 * self.high(s);
            }
            self.set_flags(min, flags);
        }
        let sf = sum_freq.wrapping_add(esc_freq).wrapping_sub(esc_freq >> 1);
        self.a.w16(min.wrapping_add(CTX_SUMM_FREQ), sf as u16);
        let flags = self.flags(min) | 0x4;
        self.set_flags(min, flags);
        self.found_state = self.stats(min);
    }

    /// Returns the index of the SEE context and the escape frequency.
    fn make_esc_freq(&mut self, num_masked1: u32) -> (usize, u32) {
        let min = self.min_context;
        let ns = self.num_stats(min);
        if ns != 0xFF {
            let row = usize::from(self.ns2indx[(ns + 2) as usize])
                .wrapping_sub(3)
                .min(23);
            let col = u32::from(self.summ_freq(min) > 11 * (ns + 1))
                + 2 * u32::from(
                    2 * ns < self.num_stats(self.suffix(min)).wrapping_add(num_masked1),
                )
                + self.flags(min);
            let see = row * 32 + (col & 31) as usize;
            (see, self.see[see].take_esc_freq())
        } else {
            (DUMMY_SEE, 1)
        }
    }

    fn next_context(&mut self) {
        let c = self.a.succ(self.found_state);
        if self.order_fall == 0 && c >= self.units_start {
            self.min_context = c;
            self.max_context = c;
        } else {
            self.update_model();
            self.min_context = self.max_context;
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
            u32::from(2 * u32::from(self.a.freq(s)) >= self.summ_freq(self.min_context));
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
        self.a.set_freq(s, f + u8::from(f < 196));
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
        self.min_context = self.max_context;
    }

    /// `Ppmd8_RangeDec_Init`: false if the stream doesn't start like a
    /// PPMd stream.
    pub fn range_dec_init<B: ByteIn + ?Sized>(&mut self, src: &mut B) -> bool {
        self.failed = false;
        self.low = 0;
        self.range = 0xFFFF_FFFF;
        self.code = 0;
        for _ in 0..4 {
            self.code = (self.code << 8) | u32::from(src.read_byte());
        }
        self.code < 0xFFFF_FFFF
    }

    fn get_threshold(&mut self, total: u32) -> u32 {
        self.divide_range(total)
    }

    /// `Code / (Range /= total)`, or a failure where upstream divides by
    /// zero.
    fn divide_range(&mut self, total: u32) -> u32 {
        match self.range.checked_div(total) {
            Some(r) if r != 0 => {
                self.range = r;
                self.code / r
            }
            _ => {
                self.failed = true;
                u32::MAX
            }
        }
    }

    fn range_decode<B: ByteIn + ?Sized>(&mut self, src: &mut B, start: u32, size: u32) {
        let start = start.wrapping_mul(self.range);
        self.low = self.low.wrapping_add(start);
        self.code = self.code.wrapping_sub(start);
        self.range = self.range.wrapping_mul(size);

        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= K_TOP {
                if self.range >= K_BOT {
                    break;
                }
                self.range = self.low.wrapping_neg() & (K_BOT - 1);
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

    /// `Ppmd8_DecodeSymbol`: the next byte, -1 at the end mark, or -2 for
    /// data the model can't have produced.
    pub fn decode_symbol<B: ByteIn + ?Sized>(&mut self, src: &mut B) -> i32 {
        let r = if self.a.is_bad() || self.failed {
            -2
        } else {
            self.decode_symbol_inner(src)
        };
        if self.a.is_bad() || self.failed {
            -2
        } else {
            r
        }
    }

    fn decode_symbol_inner<B: ByteIn + ?Sized>(&mut self, src: &mut B) -> i32 {
        // 0xFF for symbols still possible, 0 for masked ones; set up on the
        // first escape, as upstream does, to keep the common path short.
        let mut char_mask: [u8; 256];
        let min = self.min_context;
        let ns = self.num_stats(min);
        if ns != 0 {
            let mut s = self.stats(min);
            let summ = self.summ_freq(min);
            let count = self.get_threshold(summ);
            let mut hi_cnt = u32::from(self.a.freq(s));
            if count < hi_cnt {
                self.range_decode(src, 0, hi_cnt);
                self.found_state = s;
                let symbol = self.a.sym(s);
                self.update1_0();
                return i32::from(symbol);
            }
            self.prev_success = 0;
            for _ in 0..ns {
                s = s.wrapping_add(STATE_SIZE);
                let f = u32::from(self.a.freq(s));
                hi_cnt += f;
                if hi_cnt > count {
                    self.range_decode(src, hi_cnt - f, f);
                    self.found_state = s;
                    let symbol = self.a.sym(s);
                    self.update1();
                    return i32::from(symbol);
                }
            }
            if count >= summ {
                return -2;
            }
            self.range_decode(src, hi_cnt, summ - hi_cnt);
            char_mask = [0xFF; 256];
            char_mask[usize::from(self.a.sym(s))] = 0;
            for _ in 0..ns {
                s = s.wrapping_sub(STATE_SIZE);
                char_mask[usize::from(self.a.sym(s))] = 0;
            }
        } else {
            let one = min.wrapping_add(ONE_STATE);
            let suffix_ns = self.num_stats(self.suffix(min));
            let row =
                usize::from(self.ns2indx[usize::from(self.a.freq(one).wrapping_sub(1))]).min(24);
            let col = u32::from(self.ns2bsindx[suffix_ns as usize])
                + self.prev_success
                + self.flags(min)
                + ((self.run_length >> 26) & 0x20) as u32;
            let col = (col & 63) as usize;
            let prob = self.bin_summ[row][col];
            let r = self.range >> 14;
            if r == 0 {
                self.failed = true;
                return -2;
            }
            self.range = r;
            if self.code / r < u32::from(prob) {
                self.range_decode(src, 0, u32::from(prob));
                self.bin_summ[row][col] = update_prob_0(prob);
                self.found_state = one;
                let symbol = self.a.sym(one);
                self.update_bin();
                return i32::from(symbol);
            }
            self.range_decode(src, u32::from(prob), (1 << 14) - u32::from(prob));
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
            // The unmasked states are all among the context's first `ns + 1`.
            for _ in 0..=ns {
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
            let count = self.get_threshold(freq_sum);

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
                self.range_decode(src, hi - f, f);
                self.see[see].update();
                self.found_state = found;
                let symbol = self.a.sym(found);
                self.update2();
                return i32::from(symbol);
            }
            if count >= freq_sum {
                return -2;
            }
            self.range_decode(src, hi_cnt, freq_sum - hi_cnt);
            let see = &mut self.see[see];
            see.summ = see.summ.wrapping_add(freq_sum as u16);
            for &p in &ps[..num & 255] {
                char_mask[usize::from(self.a.sym(p))] = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ppmd::testutil::{mutations, text, unhex};

    // The zip fixture test_read_format_zip_ppmd8.zipx (vimrc, order 8,
    // 1 MiB, CRC-32 0xba8e3baa) without its 2-byte header, and streams
    // made with upstream's model and Subbotin's encoder, ending in the
    // end mark. The text is `text(n)`.
    const VIMRC: &str = "\
21fdaaf086f11ef26db9c98002187a5a9e4dc6209bf29c23c89eafd53f2378d8\
0c903fc739cb0170221bf451da9a8980321cdce66c7ab27fa58cbe740db5bd2f\
f33118dd46387578d280f638cb196c5b9651c38e737777eecc98c2f5c8dd2521\
932747f184bb9900315df9571e17805578e0d2972d7183dc7443e262c27d62b5\
0687624164cef6ed210112c6f2a22b1b5f6473a60368dfa5420a72bd9a84dc6f\
3e85e95813ae75d47d74f040586293162c8b4f09dfcb4e0d95a0b4948a141ef9\
07fbdd05eb0a2173c46be13722736777a4a0c7140c39607d5e66685adcaa7a7f\
e6dabec7450fa6b4c7b65f5e11f575837ee9da72d20d89a35079f44cd12c17fb\
8c884f89d7946786474ee88a290d3ef40995d919c00b033f599cbc291db54275\
d01163594c7ae09f782fe30adce8e1cec119810b856d7f5fdef4aca58efbc36f\
375ac10097bb28e911691a01a4c7f0969c3732ec558e3e12ba3e4b175a02d15e\
01bc419d58be030882534daf66c266a694dbc9f165520eb904fba9a2a97ac055\
5f723e10af842d17f325ab16221219628fa1078a35a81cc1af384550ef5c0388\
8a395fbfc401445afb85b680b77ba64fc3eb673a9260b90de92a594be12a362d\
f95826e1bb092f1ad79ca92d99fabab3b0bc14846100";
    const E_P8_O8_M4K_CUT: &str = "\
79ed7d6d2d0f98062f16ef87de0b1060005677b00e07b183718c0a159d6837fc\
fbfd52708a1fa4da6b2ae24b5a0d73b8ffb9dc86d5ea06d7b93abe58a35fb47c\
c6d89e01580f6ffe92be68b39ff72791c9c059a063a9b222dd172d0d21ffa542\
2a49dddbfbc1cf033d4c0aaab59b2e3830a87ee248f345f894a0809e8327a375\
fd0ca29e2686f376a6c6987ae83ace9f96f2be5d0b88cf4da2b7aa93149feb6e\
643074fe355e192c0314753273d92c9d5aea765838dc2c0ec9cd639f6de3ac6e\
691a33aae3332ad258294b507abb11dbb94ffb124949bf5f0197117648139a7a\
493c591d3d61ffdbe568eb2dcf82c14534d6d5e98d7993261eaa1da249f6c988\
4933c83ae720b8fc3736ae64eba3b143da06ba63f7286dcf1bcde1271fbaee59\
bc52a2f2134f5839ff73552444537a12d23579d6ef4438557a32893d9c316a38\
d49e940a56160afa97992db9c3ef1570176043ff4ba68d30bdf9d7894feb0c39\
ab51bb7c75f9e966ca5ab8015f3de31333a8a093c741349cc20d2906c0f47d76\
7095ef2917f97e89a08f89b94ab785aa2eaaf2fa715196ec6521f156dd9dd5ed\
3fc136f26375641d4556ae11e4a45dd223652dba8e5eea219dacd9c6708261c5\
aaf6c591166e23cb1d2c456857409976a09af65b290412c3ea34d3aa7797147a\
6c30982d8b458d25407e5c7b37977c650b254d7ecd70b2758503692102091b92\
399c6729044704f0b02df3e2c68ed2085d03d67cc50ac694d6664fc55c651862\
e279db4638ce8cf72c9d9f6fd577f16ddb422ecb422e1309becd869caed01118\
d25e79b64a5163cd4bf3949830e2fbd3b16a0987335ad5f5f9ef65a53d28ba6f\
d00cc736581ef11a05f0a250e2b8fff85cf5c44f0c36327d11d5da7e8aa6bcdc\
657fe488e280c2d86c4cac4032dc1adada7f7e8b91dcee94c8ac153f0d560a8b\
e85413dea2dfbbef20924175cca2129ff1cb7a98ede67f975117001492cd0efb\
94d714b33fb6d5ee1f25948b684095c6eb4703a48e4d161a8a75559176a81502\
eb5c8610475c26e76340f6c810ffe10d07f29494ea42d414cb90a56adefbbba9\
d5e59c64dae557079f4cebfbfe1c9403626a06399a48bddf111d2d66f7a17a6a\
537a150b5ebfcef4503f140ad43272c0ff215c990e0e5e5611ecde90f753d7ee\
68b9124216fef24e13cb1b29a831b95933076706f84be7ecdf5a7ba2a1c66238\
0d4fb2bb7cc3f30d9744986aaf3003ca0f00";
    const F_P8_O4_M2K_RESTART: &str = "\
79ed7d6d2d0f98062f16ef87de0b1060005677b00e07b183718c0a159d6837fc\
fbfd52708a1fce896231cd597611c611d8936c47667a28c54faccb85cb2e85d4\
0d215a60e368ff475aab1402a904cc7d98287176bab3b2c52dc32fc4dd8198f7\
637543ecdd029f9850fff9bb6f09e8b65fa317a6b9f3dfaa1c450e25fa8c87b5\
c92cc7c00a1f09cf4514c4318f6f755ba5e2a486799f489b192895f7ca124dee\
c50ea763477593380e516ce468b61883a28f7e31de2055989c1ab6232a61106c\
8ec71281b7c488b7700cb2b8948279c0a0ea17dc95a9ea7555ad7b1d643d77bd\
12f281c7deb8b4ad1d121193c8d655098799465e91aead9a7f60538a676a7334\
5a91a447ae8c4fbc6127bc0c914bf096c2efddd061deb1853a11fb7a3a1bdf0a\
75718a471a6766e2d5d1a33f5ad76f4ba9cf32bf3ad6acdfba20cab1c67ab2c6\
86246047048808e6fdf912e3847baf37adf613aef66df9b1945121e62b1fac1c\
8c9f74cbe8a7fd49a5887b9c090375c262558da2058827af274c7c6daa924eb4\
492f7be0781e83b041772e0b7f99f92017a1ebb8addfbe4bef36175d66691948\
3209c30030523c85173e52407420296c68476d183f969d511b667feb35b5a947\
df2acd2a2be73da1d8ccaeb86d1df0a2b07709323f925a8b8278db64b703d349\
8734de99ceac0b8a161b5593b5a57a598ea88b519795eee674e75327c4d4ea07\
4d4a623a23f38d94ecca19fff0896fe234e921508f835a0645049cd626e138d2\
74e1c4cae21d73a5d2e68732f02a35efa3bb98d7879dcea47a33ea5cabc60768\
94a94501c711f7a1f84c8221862184978fdff001f96bd12249bb6c75fbb1d08a\
74d4d9256f6c9d2dcb89bf47915ada5307c47dba0b37706adf0f0f6b99565b48\
02cb539e8cd99dc8d3f460b423a459c843fa48ac42a8742392034673e8a31e83\
2ffeb9527728bc341f953d1c410d2b884852c57534bb9eb994ed457c2f38f8d3\
cd9d5870e029a49f65687bd5be3b4d4e96400ef1f9e054dd339189c10267e065\
511fa834fe87d3b657df888ce2b3d9f6d2370c896a33d78419955b00796f2a14\
947dd9d7c232c78d3d31542b90647ef4c80db9b49ccda60a7f6ae560c5a88e3e\
6c4dd75cd75ae384d140bc2b92ac5f9dbf31093ff19c647a904096abf28e1637\
83ebd71e7bf23ce5089bd3d42591dea3ea74ba6a4a7ff91b963953fb00c92db4\
a16ff1a1bbdc2ad258e52eba9d7fc0bffa78b26caac24eb8e205f5e00b8d3d07\
5bdd830075b800";
    fn decode(stream: &[u8], order: u32, mem: u32, restore: u32, max: usize) -> (Vec<u8>, i32) {
        let mut pos = 0;
        let mut src = || {
            pos += 1;
            stream.get(pos - 1).copied().unwrap_or(0)
        };
        let mut p = Ppmd8::new();
        assert!(p.alloc(mem));
        let ok = p.range_dec_init(&mut src);
        p.init(order, restore);
        let (mut out, mut last) = (Vec::new(), 0);
        while ok && out.len() < max {
            last = p.decode_symbol(&mut src);
            if last < 0 {
                break;
            }
            out.push(last as u8);
        }
        (out, last)
    }

    #[test]
    fn decodes_zip_fixture() {
        let (out, last) = decode(&unhex(VIMRC), 8, 1 << 20, 0, 100_000);
        assert_eq!((out.len(), last), (912, -1));
        assert_eq!(crc32fast::hash(&out), 0xba8e3baa);
    }

    #[test]
    fn decodes_streams_with_both_restore_methods() {
        for (hex, order, mem, restore, n) in [
            (E_P8_O8_M4K_CUT, 8, 4096, PPMD8_RESTORE_METHOD_CUT_OFF, 2500),
            (
                F_P8_O4_M2K_RESTART,
                4,
                2048,
                PPMD8_RESTORE_METHOD_RESTART,
                1200,
            ),
        ] {
            let (out, last) = decode(&unhex(hex), order, mem, restore, n + 10);
            assert_eq!((out, last), (text(n), -1));
        }
    }

    #[test]
    fn alloc_follows_upstream() {
        let mut p = Ppmd8::new();
        assert!(p.alloc(1 << 20));
        assert!(p.was_allocated());
        p.free();
        assert!(!p.was_allocated());
    }

    #[test]
    fn corrupt_streams_do_not_panic() {
        let streams = [
            (VIMRC, 8, 1 << 20, 0),
            (E_P8_O8_M4K_CUT, 8, 4096, 1),
            (F_P8_O4_M2K_RESTART, 4, 2048, 0),
        ];
        for (hex, order, mem, restore) in streams {
            for stream in mutations(&unhex(hex), 100) {
                let (out, last) = decode(&stream, order, mem, restore, 20_000);
                assert!(out.len() <= 20_000 && last >= -2);
            }
        }
    }
}

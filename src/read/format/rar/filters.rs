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

//! RAR's filters. The archive carries each as a program for RAR's virtual
//! machine; like upstream, we don't run programs but recognize the standard
//! ones by a fingerprint of their code and run native versions.

use crate::crc32::crc32;
use std::collections::VecDeque;

pub const VM_MEMORY_SIZE: usize = 0x40000;
const PROGRAM_WORK_SIZE: usize = 0x3C000;
const PROGRAM_SYSTEM_GLOBAL_ADDRESS: u32 = PROGRAM_WORK_SIZE as u32;
const PROGRAM_SYSTEM_GLOBAL_SIZE: u32 = 0x40;
const PROGRAM_USER_GLOBAL_SIZE: u32 = 0x2000 - PROGRAM_SYSTEM_GLOBAL_SIZE;

/// Reads bits, most significant first, from a block of bytes; past the end
/// it reads zeros and remembers it.
struct MemBr<'a> {
    bytes: &'a [u8],
    offset: usize,
    bits: u64,
    available: u32,
    at_eof: bool,
}

impl<'a> MemBr<'a> {
    fn new(bytes: &'a [u8], offset: usize) -> Self {
        MemBr {
            bytes,
            offset,
            bits: 0,
            available: 0,
            at_eof: false,
        }
    }

    fn fill(&mut self, bits: u32) -> bool {
        while self.available < bits {
            let Some(&b) = self.bytes.get(self.offset) else {
                break;
            };
            self.offset += 1;
            self.bits = (self.bits << 8) | u64::from(b);
            self.available += 8;
        }
        if bits > self.available {
            self.at_eof = true;
            return false;
        }
        true
    }

    fn bits(&mut self, bits: u32) -> u32 {
        if bits > self.available && (self.at_eof || !self.fill(bits)) {
            return 0;
        }
        self.available -= bits;
        ((self.bits >> self.available) & ((1u64 << bits) - 1)) as u32
    }

    /// `membr_next_rarvm_number`.
    fn next_rarvm_number(&mut self) -> u32 {
        match self.bits(2) {
            0 => self.bits(4),
            1 => {
                let val = self.bits(8);
                if val >= 16 {
                    val
                } else {
                    0xFFFF_FF00 | (val << 4) | self.bits(4)
                }
            }
            2 => self.bits(16),
            _ => self.bits(32),
        }
    }
}

/// A program, as far as it matters: which standard filter it is.
struct Program {
    fingerprint: u64,
    usage_count: u32,
    old_filter_length: u32,
}

impl Program {
    /// `compile_program`: `None` for code that isn't well formed.
    fn compile(bytes: &[u8]) -> Option<Program> {
        let (&first, rest) = bytes.split_first()?;
        if rest.iter().fold(0, |x, &b| x ^ b) != first {
            return None;
        }
        let mut br = MemBr::new(bytes, 1);
        // The static data is read and never used, but its length is checked.
        if br.bits(1) != 0 && br.next_rarvm_number() as usize >= VM_MEMORY_SIZE {
            return None;
        }
        Some(Program {
            fingerprint: u64::from(crc32(0, bytes)) | ((bytes.len() as u64) << 32),
            usage_count: 0,
            old_filter_length: 0,
        })
    }
}

/// A filter to apply to a block of the output.
#[derive(Clone)]
pub struct Filter {
    /// Tells filters apart; a program's index can't.
    id: u64,
    prog: usize,
    initial_registers: [u32; 8],
    pub block_start_pos: u64,
    pub block_length: u32,
    filtered_block_address: u32,
    filtered_block_length: u32,
}

/// What `run` leaves for the caller to hand out.
pub struct Filtered {
    pub address: usize,
    pub length: usize,
}

#[derive(Default)]
pub struct Filters {
    progs: Vec<Program>,
    pub stack: VecDeque<Filter>,
    next_id: u64,
    pub filter_start: i64,
    last_filter_num: u32,
    pub last_end: i64,
    pub vm_memory: Vec<u8>,
    /// The output of the last filter run, in `vm_memory`.
    pub bytes: usize,
    pub bytes_ready: usize,
}

impl Filters {
    /// `parse_filter`: adds the filter `bytes` describes, `flags` being the
    /// first byte of the block it came in. `position` is the LZSS position
    /// and `window_size` the size of the window. False if it is invalid.
    pub fn parse(
        &mut self,
        bytes: &[u8],
        flags: u8,
        position: i64,
        dictionary_size: u32,
        window_size: usize,
    ) -> bool {
        let mut br = MemBr::new(bytes, 0);
        let num_progs = self.progs.len() as u32;

        let mut num;
        if flags & 0x80 != 0 {
            num = br.next_rarvm_number();
            if num == 0 {
                self.stack.clear();
                self.progs.clear();
            } else {
                num -= 1;
            }
            if num > num_progs {
                return false;
            }
            self.last_filter_num = num;
        } else {
            num = self.last_filter_num;
        }

        let mut prog = self.progs.get(num as usize).map(|_| num as usize);
        if let Some(p) = prog.and_then(|p| self.progs.get_mut(p)) {
            p.usage_count = p.usage_count.wrapping_add(1);
        }

        let mut block_start_pos = u64::from(br.next_rarvm_number()).wrapping_add(position as u64);
        if flags & 0x40 != 0 {
            block_start_pos = block_start_pos.wrapping_add(258);
        }
        let block_length = if flags & 0x20 != 0 {
            br.next_rarvm_number()
        } else {
            prog.and_then(|p| self.progs.get(p))
                .map_or(0, |p| p.old_filter_length)
        };

        if block_length > dictionary_size || block_length as usize > window_size {
            return false;
        }

        let mut registers = [0u32; 8];
        registers[3] = PROGRAM_SYSTEM_GLOBAL_ADDRESS;
        registers[4] = block_length;
        registers[5] = prog
            .and_then(|p| self.progs.get(p))
            .map_or(0, |p| p.usage_count);
        registers[7] = VM_MEMORY_SIZE as u32;

        if flags & 0x10 != 0 {
            let mask = br.bits(7);
            for (i, reg) in registers.iter_mut().take(7).enumerate() {
                if mask & (1 << i) != 0 {
                    *reg = br.next_rarvm_number();
                }
            }
        }

        if prog.is_none() {
            let len = br.next_rarvm_number();
            if len == 0 || len > 0x10000 {
                return false;
            }
            let bytecode: Vec<u8> = (0..len).map(|_| br.bits(8) as u8).collect();
            let Some(compiled) = Program::compile(&bytecode) else {
                return false;
            };
            self.progs.push(compiled);
            prog = Some(self.progs.len() - 1);
        }
        let Some(program) = prog.and_then(|p| self.progs.get_mut(p)) else {
            return false;
        };
        program.old_filter_length = block_length;

        // The global data is read for its length, and so that running off
        // the end of the code is noticed. The filters we run don't use it.
        if flags & 0x08 != 0 {
            let global_data_len = br.next_rarvm_number();
            if global_data_len > PROGRAM_USER_GLOBAL_SIZE {
                return false;
            }
            for _ in 0..global_data_len {
                br.bits(8);
            }
        }

        if br.at_eof {
            return false;
        }

        self.next_id += 1;
        self.stack.push_back(Filter {
            id: self.next_id,
            prog: prog.unwrap_or(0),
            initial_registers: registers,
            block_start_pos,
            block_length,
            filtered_block_address: 0,
            filtered_block_length: 0,
        });
        if self.stack.len() == 1 {
            self.filter_start = i64::try_from(block_start_pos).unwrap_or(i64::MAX);
        }
        true
    }
}

impl Filters {
    /// The virtual machine's memory, allocated the first time a filter runs.
    /// False if there is no room.
    pub fn alloc_vm(&mut self) -> bool {
        if self.vm_memory.is_empty() {
            if self
                .vm_memory
                .try_reserve_exact(VM_MEMORY_SIZE + 4)
                .is_err()
            {
                return false;
            }
            self.vm_memory.resize(VM_MEMORY_SIZE + 4, 0);
        }
        true
    }

    /// `execute_filter`: runs the standard filter `filter` is, over the
    /// block at the start of the VM's memory, which is output at `position`
    /// of the file. `None` if its program isn't one of the standard ones;
    /// otherwise whether it ran.
    pub fn execute(&mut self, filter: &mut Filter, position: usize) -> Option<bool> {
        let fingerprint = self.progs.get(filter.prog)?.fingerprint;
        let mem = self.vm_memory.as_mut_slice();
        Some(match fingerprint {
            0x1D_0E06_077D => delta(filter, mem),
            0x35_AD57_6887 => e8(filter, mem, position, false),
            0x39_3CD7_E57E => e8(filter, mem, position, true),
            0x95_1C2C_5DC8 => rgb(filter, mem),
            0xD8_BC85_E701 => audio(filter, mem),
            _ => return None,
        })
    }
}

impl Filter {
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Where in the VM's memory the output is, and how long it is.
    pub fn output(&self) -> Filtered {
        Filtered {
            address: self.filtered_block_address as usize,
            length: self.filtered_block_length as usize,
        }
    }
}

fn read_u32(mem: &[u8], offset: usize) -> u32 {
    mem.get(offset..offset + 4)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

fn write_u32(mem: &mut [u8], offset: usize, value: u32) {
    if let Some(b) = mem.get_mut(offset..offset + 4) {
        b.copy_from_slice(&value.to_le_bytes());
    }
}

/// Records where the filter left its output and how long it is.
fn set_output(filter: &mut Filter, address: u32, length: u32) -> bool {
    filter.filtered_block_address = address;
    filter.filtered_block_length = length;
    true
}

fn delta(filter: &mut Filter, mem: &mut [u8]) -> bool {
    let length = filter.initial_registers[4] as usize;
    let num_channels = filter.initial_registers[0] as usize;
    if length > PROGRAM_WORK_SIZE / 2 || num_channels == 0 || num_channels > 128 {
        return false;
    }
    let (src, dst) = mem.split_at_mut(length);
    let mut src = src.iter();
    for i in 0..num_channels {
        let mut last_byte = 0u8;
        for idx in (i..length).step_by(num_channels) {
            let (Some(&s), Some(d)) = (src.next(), dst.get_mut(idx)) else {
                return false;
            };
            last_byte = last_byte.wrapping_sub(s);
            *d = last_byte;
        }
    }
    set_output(filter, length as u32, length as u32)
}

fn e8(filter: &mut Filter, mem: &mut [u8], position: usize, e9_also: bool) -> bool {
    let length = filter.initial_registers[4] as usize;
    let file_size: u32 = 0x100_0000;
    if length > PROGRAM_WORK_SIZE || length <= 4 {
        return false;
    }
    let mut i = 0;
    while i <= length - 5 {
        let op = mem.get(i).copied();
        if op == Some(0xE8) || (e9_also && op == Some(0xE9)) {
            let curr_pos = (position as u32).wrapping_add(i as u32).wrapping_add(1);
            let address = read_u32(mem, i + 1);
            if (address as i32) < 0 && curr_pos >= address.wrapping_neg() {
                write_u32(mem, i + 1, address.wrapping_add(file_size));
            } else if (address as i32) >= 0 && address < file_size {
                write_u32(mem, i + 1, address.wrapping_sub(curr_pos));
            }
            i += 4;
        }
        i += 1;
    }
    set_output(filter, 0, length as u32)
}

fn rgb(filter: &mut Filter, mem: &mut [u8]) -> bool {
    let stride = filter.initial_registers[0];
    let byte_offset = filter.initial_registers[1] as usize;
    let block_length = filter.initial_registers[4];
    let length = block_length as usize;
    if length > PROGRAM_WORK_SIZE / 2 || stride > block_length || length < 3 || byte_offset > 2 {
        return false;
    }
    let (src, dst) = mem.split_at_mut(length);
    let mut src = src.iter();
    let at = |dst: &[u8], i: i64| usize::try_from(i).ok().and_then(|i| dst.get(i).copied());
    for i in 0..3 {
        let mut byte = 0u8;
        let mut prev = i as i64 - i64::from(stride);
        for j in (i..length).step_by(3) {
            let Some(&s) = src.next() else {
                return false;
            };
            if prev >= 0 {
                let p3 = i32::from(at(dst, prev + 3).unwrap_or(0));
                let p0 = i32::from(at(dst, prev).unwrap_or(0));
                let b = i32::from(byte);
                let delta1 = (p3 - p0).unsigned_abs();
                let delta2 = (b - p0).unsigned_abs();
                let delta3 = (p3 - p0 + b - p0).unsigned_abs();
                if delta1 > delta2 || delta1 > delta3 {
                    byte = (if delta2 <= delta3 { p3 } else { p0 }) as u8;
                }
            }
            byte = byte.wrapping_sub(s);
            if let Some(d) = dst.get_mut(j) {
                *d = byte;
            }
            prev += 3;
        }
    }
    for i in (byte_offset..length - 2).step_by(3) {
        let green = dst.get(i + 1).copied().unwrap_or(0);
        for k in [i, i + 2] {
            if let Some(d) = dst.get_mut(k) {
                *d = d.wrapping_add(green);
            }
        }
    }
    set_output(filter, block_length, block_length)
}

#[derive(Default)]
struct AudioState {
    weight: [i32; 3],
    delta: [i32; 3],
    last_delta: i32,
    error: [i32; 7],
    count: u32,
    last_byte: u8,
}

fn audio(filter: &mut Filter, mem: &mut [u8]) -> bool {
    let length = filter.initial_registers[4] as usize;
    let num_channels = filter.initial_registers[0] as usize;
    if length > PROGRAM_WORK_SIZE / 2 || num_channels == 0 || num_channels > 128 {
        return false;
    }
    let (src, dst) = mem.split_at_mut(length);
    let mut src = src.iter();
    for i in 0..num_channels {
        let mut st = AudioState::default();
        for j in (i..length).step_by(num_channels) {
            let Some(&s) = src.next() else {
                return false;
            };
            let delta = i32::from(s as i8);
            st.delta[2] = st.delta[1];
            st.delta[1] = st.last_delta - st.delta[0];
            st.delta[0] = st.last_delta;
            let pred = (8 * i32::from(st.last_byte)
                + st.weight[0] * st.delta[0]
                + st.weight[1] * st.delta[1]
                + st.weight[2] * st.delta[2])
                >> 3;
            let byte = ((pred & 0xFF) - delta) as u8;
            let pred_error = delta * 8;
            st.error[0] += pred_error.abs();
            for k in 0..3 {
                st.error[2 * k + 1] += (pred_error - st.delta[k]).abs();
                st.error[2 * k + 2] += (pred_error + st.delta[k]).abs();
            }
            st.last_delta = i32::from(byte.wrapping_sub(st.last_byte) as i8);
            st.last_byte = byte;
            if let Some(d) = dst.get_mut(j) {
                *d = byte;
            }
            let count = st.count;
            st.count += 1;
            if count & 0x1F == 0 {
                let mut idx = 0;
                for k in 1..7 {
                    if st.error[k] < st.error[idx] {
                        idx = k;
                    }
                }
                st.error = [0; 7];
                if let Some(w) = st.weight.get_mut((idx.wrapping_sub(1)) / 2) {
                    if idx % 2 == 1 {
                        if *w >= -16 {
                            *w -= 1;
                        }
                    } else if *w < 16 {
                        *w += 1;
                    }
                }
            }
        }
    }
    set_output(filter, length as u32, length as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs the filter of fingerprint `kind` on a pseudo-random block as the
    /// reference program does (upstream's `execute_filter_*` compiled with
    /// the same generator), and returns the CRC of its output.
    fn run(kind: usize, case: u64) -> Option<u32> {
        const FINGERPRINTS: [u64; 5] = [
            0x1D_0E06_077D,
            0x35_AD57_6887,
            0x39_3CD7_E57E,
            0x95_1C2C_5DC8,
            0xD8_BC85_E701,
        ];
        let mut state = 1000 + kind as u64 * 100 + case;
        let mut rnd = move || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };
        let mut filters = Filters::default();
        assert!(filters.alloc_vm());
        let mut length = 3 + rnd() % 3000;
        if case == 5 {
            length = 0x1E000;
        }
        let mut registers = [0; 8];
        registers[4] = length;
        registers[0] = 1 + rnd() % 6;
        registers[1] = rnd() % 3;
        if kind == 3 {
            registers[0] = rnd() % 24;
        }
        for i in 0..length as usize {
            filters.vm_memory[i] = rnd() as u8;
        }
        if kind == 1 || kind == 2 {
            let mut i = 0;
            while i + 5 <= length as usize {
                filters.vm_memory[i] = if rnd() & 1 != 0 { 0xE8 } else { 0xE9 };
                filters.vm_memory[i + 4] = if rnd() & 1 != 0 { 0xFF } else { 0 };
                i += 1 + (rnd() % 40) as usize;
            }
        }
        let position = (rnd() % 100_000) as usize;

        filters.progs.push(Program {
            fingerprint: FINGERPRINTS[kind],
            usage_count: 0,
            old_filter_length: 0,
        });
        let mut filter = Filter {
            id: 1,
            prog: 0,
            initial_registers: registers,
            block_start_pos: 0,
            block_length: length,
            filtered_block_address: 0,
            filtered_block_length: 0,
        };
        if !filters.execute(&mut filter, position)? {
            return None;
        }
        let out = filter.output();
        Some(crc32(
            0,
            &filters.vm_memory[out.address..out.address + out.length],
        ))
    }

    /// CRCs of what upstream's `execute_filter_delta`, `_e8` (without and
    /// with E9), `_rgb` and `_audio` leave, from a C harness around the
    /// functions as they are in the pinned source: (filter, case, crc).
    #[test]
    fn standard_filters_match_upstream() {
        const EXPECTED: [(usize, u64, u32); 30] = [
            (0, 0, 0xe4bf7b6d),
            (0, 1, 0x8491e40f),
            (0, 2, 0xf90f0d15),
            (0, 3, 0x4d792ee9),
            (0, 4, 0x1b30d976),
            (0, 5, 0xd6c21261),
            (1, 0, 0x9d386696),
            (1, 1, 0xc3b808cf),
            (1, 2, 0x4f63e169),
            (1, 3, 0x30813bfc),
            (1, 4, 0xcf483f74),
            (1, 5, 0x86e39e73),
            (2, 0, 0x617c233b),
            (2, 1, 0x16e5615f),
            (2, 2, 0xbd3fdb32),
            (2, 3, 0x89e17578),
            (2, 4, 0x4a68b596),
            (2, 5, 0xa7eda879),
            (3, 0, 0x27bd1332),
            (3, 1, 0x84c366e0),
            (3, 2, 0xe6230cff),
            (3, 3, 0x910c5315),
            (3, 4, 0xd72436c3),
            (3, 5, 0xb9decc14),
            (4, 0, 0xd961ec59),
            (4, 1, 0xf57b1dfa),
            (4, 2, 0x8879ed31),
            (4, 3, 0xbcee3161),
            (4, 4, 0xf8443ebc),
            (4, 5, 0x80c521b5),
        ];
        for (kind, case, crc) in EXPECTED {
            assert_eq!(run(kind, case), Some(crc), "filter {kind}, case {case}");
        }
    }
}

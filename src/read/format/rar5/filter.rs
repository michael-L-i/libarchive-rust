//! The filters (DELTA, E8, E8E9 and ARM) that undo the compressor's
//! preprocessing of a range of the output.

use super::decompress::BitReader;
use super::*;

const FILTER_DELTA: u16 = 0;
const FILTER_E8: u16 = 1;
const FILTER_E8E9: u16 = 2;
const FILTER_ARM: u16 = 3;

#[derive(Clone, Copy)]
pub(super) struct Filter {
    kind: u16,
    channels: i32,
    pub(super) block_start: i64,
    block_length: i64,
}

/// Copies the circular buffer's `[start, end)` into `dst`.
fn circular_memcpy(dst: &mut [u8], window: &[u8], mask: i64, start: i64, end: i64) {
    let (s, e) = ((start & mask) as usize, (end & mask) as usize);
    if s > e {
        let len1 = (mask + 1) as usize - s;
        let (head, tail) = dst.split_at_mut(len1.min(dst.len()));
        head.copy_from_slice(window.get(s..s + head.len()).unwrap_or_default());
        let len2 = e.min(tail.len());
        tail[..len2].copy_from_slice(window.get(..len2).unwrap_or_default());
    } else {
        let len = ((end - start) as usize).min(dst.len());
        dst[..len].copy_from_slice(window.get(s..s + len).unwrap_or_default());
    }
}

fn read_filter_data(window: &[u8], mask: i64, offset: u32) -> u32 {
    let mut linear_buf = [0u8; 4];
    let offset = i64::from(offset);
    circular_memcpy(&mut linear_buf, window, mask, offset, offset + 4);
    u32::from_le_bytes(linear_buf)
}

fn write_filter_data(filtered: &mut [u8], offset: usize, value: u32) {
    if let Some(dst) = filtered.get_mut(offset..offset + 4) {
        dst.copy_from_slice(&value.to_le_bytes());
    }
}

impl CompState {
    fn run_delta_filter(&mut self, flt: &Filter, filtered: &mut [u8]) {
        let mut src_pos = 0;

        for i in 0..flt.channels as usize {
            let mut prev_byte = 0u8;
            for dest_pos in (i..flt.block_length as usize).step_by(flt.channels as usize) {
                let byte = self.window_byte(self.solid_offset + flt.block_start + src_pos);

                prev_byte = prev_byte.wrapping_sub(byte);
                if let Some(dst) = filtered.get_mut(dest_pos) {
                    *dst = prev_byte;
                }
                src_pos += 1;
            }
        }
    }

    fn window_byte(&self, idx: i64) -> u8 {
        self.window
            .get((idx & self.window_mask) as usize)
            .copied()
            .unwrap_or(0)
    }

    fn run_e8e9_filter(&mut self, flt: &Filter, filtered: &mut [u8], extended: bool) {
        const FILE_SIZE: u32 = 0x1000000;

        let base = self.solid_offset + flt.block_start;
        circular_memcpy(
            filtered,
            &self.window,
            self.window_mask,
            base,
            base + flt.block_length,
        );

        let mut i: i64 = 0;
        while i < flt.block_length - 4 {
            let b = self.window_byte(base + i);
            i += 1;

            // 0xE8 = x86's call <relative_addr_uint32> (function call)
            // 0xE9 = x86's jmp <relative_addr_uint32> (unconditional jump)
            if b == 0xE8 || (extended && b == 0xE9) {
                let offset = ((i + flt.block_start) % i64::from(FILE_SIZE)) as u32;

                let addr = read_filter_data(
                    &self.window,
                    self.window_mask,
                    ((base + i) as u32) & self.window_mask as u32,
                );

                if addr & 0x80000000 != 0 {
                    if addr.wrapping_add(offset) & 0x80000000 == 0 {
                        write_filter_data(filtered, i as usize, addr.wrapping_add(FILE_SIZE));
                    }
                } else if addr.wrapping_sub(FILE_SIZE) & 0x80000000 != 0 {
                    write_filter_data(filtered, i as usize, addr.wrapping_sub(offset));
                }

                i += 4;
            }
        }
    }

    fn run_arm_filter(&mut self, flt: &Filter, filtered: &mut [u8]) {
        let base = self.solid_offset + flt.block_start;
        circular_memcpy(
            filtered,
            &self.window,
            self.window_mask,
            base,
            base + flt.block_length,
        );

        let mut i: i64 = 0;
        while i < flt.block_length - 3 {
            // 0xEB = ARM's BL (branch + link) instruction.
            if self.window_byte(base + i + 3) == 0xEB {
                let mut offset = read_filter_data(
                    &self.window,
                    self.window_mask,
                    (base + i) as u32 & self.window_mask as u32,
                ) & 0x00ffffff;

                offset = offset.wrapping_sub(((i + flt.block_start) / 4) as u32);
                offset = (offset & 0x00ffffff) | 0xeb000000;
                write_filter_data(filtered, i as usize, offset);
            }
            i += 4;
        }
    }
}

impl Rar5 {
    fn run_filter(&mut self, a: &Base, flt: &Filter) -> Res<()> {
        self.cstate.dready = [None; 2];

        let mut filtered = Vec::new();
        let length = usize::try_from(flt.block_length).map_err(|_| silent_fatal())?;
        if filtered.try_reserve_exact(length).is_err() {
            return Err(fatal(libc::ENOMEM, "Can't allocate memory for filter data"));
        }
        filtered.resize(length, 0);

        match flt.kind {
            FILTER_DELTA => self.cstate.run_delta_filter(flt, &mut filtered),
            FILTER_E8 | FILTER_E8E9 => {
                self.cstate
                    .run_e8e9_filter(flt, &mut filtered, flt.kind == FILTER_E8E9)
            }
            FILTER_ARM => self.cstate.run_arm_filter(flt, &mut filtered),
            kind => {
                self.cstate.filtered = filtered;
                return Err(failed(
                    ARCHIVE_ERRNO_FILE_FORMAT,
                    format!("Unsupported filter type: 0x{kind:x}"),
                ));
            }
        }
        self.cstate.filtered = filtered;

        let last_write_ptr = self.cstate.last_write_ptr;
        if !self.push_data_ready(a, Buf::Filtered, 0, length, last_write_ptr) {
            return Err(fatal(
                ARCHIVE_ERRNO_PROGRAMMER,
                "Stack overflow when submitting unpacked data",
            ));
        }

        self.cstate.last_write_ptr += flt.block_length;
        Ok(())
    }

    /// Runs the first filter if the data it covers is unpacked, or submits
    /// the data before it. True if one of those happened, so the caller
    /// should look again; false if there is nothing to filter yet.
    pub(super) fn apply_filters(&mut self, a: &Base) -> Res<bool> {
        self.cstate.all_filters_applied = false;

        // Get the first filter that can be applied to our data. The data
        // needs to be fully unpacked before the filter can be run.
        if let Some(flt) = self.cstate.filters.front().copied() {
            let c = &self.cstate;
            // Check if our unpacked data fully covers this filter's range.
            if c.write_ptr > flt.block_start && c.write_ptr >= flt.block_start + flt.block_length {
                // Check if we have some data pending to be written right
                // before the filter's start offset.
                if c.last_write_ptr == flt.block_start {
                    // Run the filter specified by descriptor `flt`.
                    self.run_filter(a, &flt)?;

                    // Filter descriptor won't be needed anymore after it's
                    // used, so remove it from the filter list.
                    self.cstate.filters.pop_front();
                } else {
                    // We can't run filters yet, dump the memory right before
                    // the filter.
                    let last_write_ptr = c.last_write_ptr;
                    self.push_window_data(a, last_write_ptr, flt.block_start);
                }

                // Return 'filter applied or not needed' state to the caller.
                return Ok(true);
            }
        }

        self.cstate.all_filters_applied = true;
        Ok(false)
    }

    /// Function is used during sanity checking.
    fn is_valid_filter_block_start(&self, start: u32) -> bool {
        let c = &self.cstate;
        let block_start = i64::from(start) + c.write_ptr;

        if c.last_block_start == 0 || c.last_block_length == 0 {
            // We didn't have any filters yet, so accept this offset.
            return true;
        }

        // Current offset is bigger than last block's end offset, so accept
        // current offset. Any other case is not a normal situation and we
        // should fail.
        block_start >= c.last_block_start + c.last_block_length
    }

    /// Convenience function used during filter processing.
    fn parse_filter_data(a: &Base, br: &mut BitReader<'_>) -> Option<u32> {
        let bytes = br.read_consume_bits(a, 2)? + 1;

        let mut data = 0u32;
        for i in 0..bytes {
            let byte = br.read_bits_16(a)?;

            // Cast to uint32_t will ensure the shift operation will not
            // produce undefined result.
            data = data.wrapping_add((u32::from(byte) >> 8) << (i * 8));
            br.skip_bits(8);
        }

        Some(data)
    }

    /// The function will create a new filter, read its parameters from the
    /// input stream and add it to the filter collection.
    pub(super) fn parse_filter(&mut self, a: &Base, br: &mut BitReader<'_>) -> Res<()> {
        // Read the parameters from the input stream.
        let block_start = Self::parse_filter_data(a, br).ok_or_else(silent_fatal)?;
        let block_length = Self::parse_filter_data(a, br).ok_or_else(silent_fatal)?;
        let filter_type = br.read_bits_16(a).ok_or_else(silent_fatal)? >> 13;
        br.skip_bits(3);

        // Perform some sanity checks on this filter parameters.
        let c = &self.cstate;
        if !(4..=0x400000).contains(&block_length)
            || !self.is_valid_filter_block_start(block_start)
            || (c.window_size > 0 && i64::from(block_length) > c.window_size >> 1)
        {
            return Err(failed(
                ARCHIVE_ERRNO_FILE_FORMAT,
                "Invalid filter encountered",
            ));
        }

        // Allocate a new filter.
        let c = &mut self.cstate;
        if c.filters.len() >= MAX_FILTERS {
            return Err(fatal(
                libc::ENOMEM,
                "Can't allocate memory for a filter descriptor",
            ));
        }

        let flt = Filter {
            kind: filter_type,
            channels: 0,
            block_start: c.write_ptr + i64::from(block_start),
            block_length: i64::from(block_length),
        };
        c.last_block_start = flt.block_start;
        c.last_block_length = flt.block_length;
        c.filters.push_back(flt);

        // Read some more data in case this is a DELTA filter. Other filter
        // types don't require any additional data over what was already
        // read.
        if filter_type == FILTER_DELTA {
            let channels = br.read_consume_bits(a, 5).ok_or_else(silent_fatal)?;
            if let Some(flt) = c.filters.back_mut() {
                flt.channels = channels as i32 + 1;
            }
        }

        Ok(())
    }
}

// Ported from libarchive/archive_write_set_format_iso9660.c: making zisofs
// files, and unmaking a zisofs'ed boot image.

use super::descriptor::num_731;
use super::*;
use crate::read::ARCHIVE_ERRNO_FILE_FORMAT;
use deflate::{Flush, Status as DeflateStatus};
use miniz_oxide::inflate::stream::{InflateState, inflate};
use miniz_oxide::{DataFormat, MZFlush, MZStatus};

const ZISOFS_MAGIC: [u8; 8] = [0x37, 0xE4, 0x53, 0x96, 0xC9, 0xDB, 0xD6, 0x07];

const ZF_HEADER_SIZE: usize = 16; // zisofs header size.
const ZF_LOG2_BS: u8 = 15; // log2 block size; 32K bytes.
const ZF_BLOCK_SIZE: u64 = 1 << ZF_LOG2_BS;

fn le32(p: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(p.get(i..i + 4)?.try_into().ok()?))
}

/// The state of unmaking a zisofs file.
#[derive(Default)]
struct ZisofsExtract {
    pz_log2_bs: u8, // Log2 of block size
    pz_uncompressed_size: u64,
    uncompressed_buffer_size: usize,

    initialized: bool,
    header_passed: bool,

    pz_offset: u32,
    block_pointers: Vec<u8>,
    block_pointers_size: usize,
    block_pointers_avail: usize,
    block_off: usize,
    block_avail: u32,

    stream: Option<Box<InflateState>>,
}

fn illegal(msg: &str) -> Error {
    Error::fatal(ARCHIVE_ERRNO_FILE_FORMAT, msg)
}

impl Iso9660 {
    fn zisofs_init_zstream(&mut self) -> Result<(), Error> {
        self.zisofs.total_in = 0;
        match &mut self.zisofs.stream {
            Some(stream) => stream.reset(),
            None => {
                let stream = deflate::Deflate::new(self.zisofs.compression_level, 15, 8).ok_or_else(|| {
                    misc("Internal error initializing compression library: invalid setup parameter")
                })?;
                self.zisofs.stream = Some(stream);
            }
        }
        Ok(())
    }

    pub(super) fn zisofs_init(&mut self, out: &mut dyn Sink, file: FileId) -> Result<(), Error> {
        self.zisofs.detect_magic = false;
        self.zisofs.making = false;

        if self.opt.rr == 0 || !self.opt.zisofs {
            return Ok(());
        }

        let size = self.files[file].entry.size();
        if (24..MULTI_EXTENT_SIZE).contains(&size) {
            // Acceptable file size for zisofs.
            self.zisofs.detect_magic = true;
            self.zisofs.magic_cnt = 0;
        }
        if !self.zisofs.detect_magic {
            return Ok(());
        }

        // The number of Logical Blocks which uncompressed data will use in
        // iso-image file is the same as the number of Logical Blocks which
        // zisofs(compressed) data will use in ISO-image file. It won't
        // reduce iso-image file size.
        if size <= LOGICAL_BLOCK_SIZE as i64 {
            return Ok(());
        }

        // Initialize compression library
        self.zisofs_init_zstream()?;

        // Mark file->zisofs to create RRIP 'ZF' Use Entry.
        let zisofs = ZisofsHeader {
            header_size: (ZF_HEADER_SIZE >> 2) as u8,
            log2_bs: ZF_LOG2_BS,
            uncompressed_size: size as u32,
        };
        self.files[file].zisofs = zisofs;

        // Calculate a size of Block Pointers of zisofs.
        let ceil = (u64::from(zisofs.uncompressed_size) + (ZF_BLOCK_SIZE - 1)) >> zisofs.log2_bs;
        self.zisofs.block_pointers_cnt = ceil as i32 + 1;
        self.zisofs.block_pointers_idx = 0;

        // Ensure a buffer size used for Block Pointers
        let bpsize = self.zisofs.block_pointers_cnt as usize * 4;
        if self.zisofs.block_pointers.len() < bpsize {
            let mut bp = Vec::new();
            bp.try_reserve_exact(bpsize)
                .map_err(|_| Error::fatal(libc::ENOMEM, "Can't allocate data"))?;
            bp.resize(bpsize, 0);
            self.zisofs.block_pointers = bp;
        }

        // Skip zisofs header and Block Pointers, which we will write after
        // all compressed data of a file written to the temporary file.
        let tsize = ZF_HEADER_SIZE + bpsize;
        self.write_null(out, tsize)?;

        // Initialize some variables to make zisofs.
        self.zisofs.block_pointers[..4].copy_from_slice(&(tsize as u32).to_le_bytes());
        self.zisofs.remaining = i64::from(zisofs.uncompressed_size);
        self.zisofs.making = true;
        self.zisofs.allzero = true;
        self.zisofs.block_offset = tsize as i64;
        self.zisofs.total_size = tsize as i64;
        self.cur_content()?.size = tsize as i64;

        Ok(())
    }

    pub(super) fn zisofs_detect_magic(&mut self, buff: &[u8]) {
        let Some(f) = self.cur_file else {
            return;
        };
        let entry_size = self.files[f].entry.size();
        let z = &mut self.zisofs;
        let magic_max = if (z.magic_buffer.len() as i64) > entry_size {
            entry_size as usize
        } else {
            z.magic_buffer.len()
        };

        let magic_buff: &[u8] = if z.magic_cnt == 0 && buff.len() >= magic_max {
            // It's unnecessary we copy buffer.
            buff
        } else {
            let cnt = z.magic_cnt as usize;
            if cnt < magic_max {
                let l = (z.magic_buffer.len() - cnt).min(buff.len());
                z.magic_buffer[cnt..cnt + l].copy_from_slice(&buff[..l]);
                z.magic_cnt += l as i32;
                if (z.magic_cnt as usize) < magic_max {
                    return;
                }
            }
            &z.magic_buffer
        };
        z.detect_magic = false;
        let p = &magic_buff[..magic_max.min(magic_buff.len())];

        // Check the magic code of zisofs.
        if p.get(..8) != Some(&ZISOFS_MAGIC[..]) {
            // This is not zisofs file which made by mkzftree.
            return;
        }

        // Read a zisofs header.
        let (Some(uncompressed_size), Some(&header_size), Some(&log2_bs)) =
            (le32(p, 8), p.get(12), p.get(13))
        else {
            return;
        };
        if uncompressed_size < 24 || header_size != 4 || !(7..=30).contains(&log2_bs) {
            return; // Invalid or not supported header.
        }

        // Calculate a size of Block Pointers of zisofs.
        let mut ceil = (u64::from(uncompressed_size) + (1u64 << log2_bs) - 1) >> log2_bs;
        let mut doff = (ceil + 1) * 4 + 16;
        if entry_size < doff as i64 {
            return; // Invalid data.
        }

        // Check every Block Pointer has valid value.
        let mut i = 16;
        while ceil != 0 && i + 8 <= p.len() {
            let (Some(bst), Some(bed)) = (le32(p, i), le32(p, i + 4)) else {
                return;
            };
            if u64::from(bst) != doff {
                return; // Invalid data.
            }
            i += 4;
            if bed < bst || i64::from(bed) > entry_size {
                return; // Invalid data.
            }
            doff += u64::from(bed - bst);
            ceil -= 1;
        }

        self.files[f].zisofs = ZisofsHeader {
            header_size,
            log2_bs,
            uncompressed_size,
        };

        // Disable making a zisofs image.
        self.zisofs.making = false;
    }

    pub(super) fn zisofs_check_magic(
        &mut self,
        out: &mut dyn Sink,
        buff: &[u8],
    ) -> Result<(), Error> {
        let making = self.zisofs.making;
        let previous = self.zisofs.magic_cnt.max(0) as usize;
        self.zisofs_detect_magic(buff);
        if making && !self.zisofs.making {
            // The original bytes are already zisofs: discard the reserved
            // new header and any compression done before detection finished.
            let offset = self.cur_content()?.offset_of_temp;
            self.wb_set_offset(out, offset)?;
            let prefix = self
                .zisofs
                .magic_buffer
                .get(..previous)
                .ok_or_else(|| misc("Invalid zisofs magic length"))?
                .to_vec();
            self.wb_write_to_temp(out, &prefix)?;
            self.cur_content()?.size = previous as i64;
        }
        Ok(())
    }

    /// Compress data and write it to a temporary file.
    pub(super) fn zisofs_write_to_temp(
        &mut self,
        out: &mut dyn Sink,
        buff: &[u8],
    ) -> Result<(), Error> {
        let mut b = 0;
        let mut s = buff.len();
        loop {
            let mut avail = (ZF_BLOCK_SIZE - self.zisofs.total_in) as usize;
            let mut flush = if s < avail {
                avail = s;
                Flush::None
            } else {
                Flush::Finish
            };
            self.zisofs.remaining -= avail as i64;
            if self.zisofs.remaining <= 0 {
                flush = Flush::Finish;
            }

            let mut next_in = b;
            let mut avail_in = avail;

            // Check if current data block are all zero.
            if self.zisofs.allzero && buff[b..b + avail].iter().any(|&c| c != 0) {
                self.zisofs.allzero = false;
            }
            b += avail;
            s -= avail;

            // If current data block are all zero, we do not use compressed
            // data.
            let hole = flush == Flush::Finish
                && self.zisofs.allzero
                && avail as u64 + self.zisofs.total_in == ZF_BLOCK_SIZE;
            if hole {
                let c = *self.cur_content()?;
                if self.zisofs.block_offset != c.size {
                    self.wb_set_offset(out, c.offset_of_temp + self.zisofs.block_offset)?;
                    let diff = c.size - self.zisofs.block_offset;
                    self.cur_content()?.size -= diff;
                    self.zisofs.total_size -= diff;
                }
                avail_in = 0;
            }

            // Compress file data.
            let mut stream_end = false;
            while avail_in > 0 || (flush == Flush::Finish && !hole && !stream_end) {
                // An all-zero block may have moved the write position.
                let next_out = self.wb_buffptr();
                let avail_out = self.wbuff_remaining;
                let (z, wbuff) = (&mut self.zisofs, &mut self.wbuff);
                let stream = z
                    .stream
                    .as_mut()
                    .ok_or_else(|| misc("Missing compressor"))?;
                let r = stream.deflate(
                    &buff[next_in..next_in + avail_in],
                    &mut wbuff[next_out..next_out + avail_out],
                    flush,
                );
                match r {
                    Ok((status, used, csize)) => {
                        stream_end = status == DeflateStatus::StreamEnd;
                        if used == 0 && csize == 0 && !stream_end {
                            return Err(misc("Compression failed: deflate() made no progress"));
                        }
                        next_in += used;
                        avail_in -= used;
                        z.total_in += used as u64;
                        self.wb_consume(out, csize)?;
                        self.zisofs.total_size += csize as i64;
                        self.cur_content()?.size += csize as i64;
                    }
                    Err(e) => {
                        return Err(misc(format!(
                            "Compression failed: deflate() call returned status {}",
                            e.code()
                        )));
                    }
                }
            }

            if flush == Flush::Finish {
                // Save the information of one zisofs block.
                self.zisofs.block_pointers_idx += 1;
                let i = self.zisofs.block_pointers_idx as usize * 4;
                let total = (self.zisofs.total_size as u32).to_le_bytes();
                self.zisofs
                    .block_pointers
                    .get_mut(i..i + 4)
                    .ok_or_else(|| misc("Too many zisofs blocks"))?
                    .copy_from_slice(&total);
                self.zisofs_init_zstream()?;
                self.zisofs.allzero = true;
                self.zisofs.block_offset = self.cur_content()?.size;
            }
            if s == 0 {
                break;
            }
        }

        Ok(())
    }

    pub(super) fn zisofs_finish_entry(&mut self, _out: &mut dyn Sink) -> Result<(), Error> {
        let f = self.cur_file.ok_or_else(|| misc("No current file"))?;

        // Direct temp file stream to zisofs temp file stream.
        self.files[f].entry.set_size(self.zisofs.total_size);

        // Make a header.
        //
        // +-----------------+----------------+-----------------+
        // | Header 16 bytes | Block Pointers | Compressed data |
        // +-----------------+----------------+-----------------+
        // 0                16               +X
        // Block Pointers :
        //   4 * (((Uncompressed file size + block_size -1) / block_size) + 1)
        //
        // Write zisofs header.
        //    Magic number
        // +----+----+----+----+----+----+----+----+
        // | 37 | E4 | 53 | 96 | C9 | DB | D6 | 07 |
        // +----+----+----+----+----+----+----+----+
        // 0    1    2    3    4    5    6    7    8
        //
        // +------------------------+------------------+
        // | Uncompressed file size | header_size >> 2 |
        // +------------------------+------------------+
        // 8                       12                 13
        //
        // +-----------------+----------------+
        // | log2 block_size | Reserved(0000) |
        // +-----------------+----------------+
        // 13               14               16
        let file = &self.files[f];
        let mut buff = [0u8; 16];
        buff[..8].copy_from_slice(&ZISOFS_MAGIC);
        buff[8..12].copy_from_slice(&num_731(file.zisofs.uncompressed_size));
        buff[12] = file.zisofs.header_size;
        buff[13] = file.zisofs.log2_bs;
        // Reserved: 14 and 15

        // Patch bytes already flushed in the temporary file, and bytes
        // still buffered in place. Seeking the write buffer backwards
        // would discard the compressed tail.
        let mut offset = file.content[0].offset_of_temp;
        let buffer_offset = self.wbuff_offset;
        let used = self.wb_buffptr();
        let mut patch = |mut bytes: &[u8]| -> Result<(), Error> {
            if offset < buffer_offset {
                let n = bytes.len().min((buffer_offset - offset) as usize);
                let temp = self
                    .temp
                    .as_mut()
                    .ok_or_else(|| misc("Couldn't create temporary file"))?;
                let pos =
                    u64::try_from(offset).map_err(|_| misc("Invalid zisofs header offset"))?;
                temp.seek(SeekFrom::Start(pos))
                    .map_err(|e| misc(e.to_string()))?;
                temp.write_all(&bytes[..n])
                    .map_err(|e| misc(e.to_string()))?;
                temp.seek(SeekFrom::Start(buffer_offset as u64))
                    .map_err(|e| misc(e.to_string()))?;
                offset += n as i64;
                bytes = &bytes[n..];
            }
            if !bytes.is_empty() {
                let at = usize::try_from(offset - buffer_offset)
                    .map_err(|_| misc("Invalid zisofs header offset"))?;
                let end = at
                    .checked_add(bytes.len())
                    .filter(|&end| end <= used)
                    .ok_or_else(|| misc("Invalid zisofs header offset"))?;
                self.wbuff
                    .get_mut(at..end)
                    .ok_or_else(|| misc("Invalid zisofs header offset"))?
                    .copy_from_slice(bytes);
                offset += bytes.len() as i64;
            }
            Ok(())
        };
        patch(&buff)?;
        let s = self.zisofs.block_pointers_cnt as usize * 4;
        let pointers = self
            .zisofs
            .block_pointers
            .get(..s)
            .ok_or_else(|| misc("Too many zisofs blocks"))?;
        patch(pointers)?;

        Ok(())
    }

    fn zisofs_extract_init(zisofs: &mut ZisofsExtract, mut p: &[u8]) -> Result<usize, Error> {
        let mut avail = p.len();

        // Allocate block pointers buffer.
        let log2_bs = u32::from(zisofs.pz_log2_bs);
        let ceil = (zisofs.pz_uncompressed_size + (1u64 << log2_bs) - 1) >> log2_bs;
        let xsize = ((ceil + 1) * 4) as usize;
        if zisofs.block_pointers.is_empty() {
            let alloc = ((xsize >> 10) + 1) << 10;
            let mut bp = Vec::new();
            bp.try_reserve_exact(alloc)
                .map_err(|_| Error::fatal(libc::ENOMEM, "No memory for zisofs decompression"))?;
            bp.resize(alloc, 0);
            zisofs.block_pointers = bp;
        }
        zisofs.block_pointers_size = xsize;

        // Allocate uncompressed data buffer.
        zisofs.uncompressed_buffer_size = 1 << log2_bs;

        // Read the file header, and check the magic code of zisofs.
        if !zisofs.header_passed {
            if avail < 16 {
                return Err(illegal("Illegal zisofs file body"));
            }

            if p[..8] != ZISOFS_MAGIC
                || le32(p, 8).map(u64::from) != Some(zisofs.pz_uncompressed_size)
                || p[12] != 4
                || p[13] != zisofs.pz_log2_bs
            {
                return Err(illegal("Illegal zisofs file body"));
            }
            avail -= 16;
            p = &p[16..];
            zisofs.header_passed = true;
        }

        // Read block pointers.
        if zisofs.header_passed && zisofs.block_pointers_avail < zisofs.block_pointers_size {
            let xsize = (zisofs.block_pointers_size - zisofs.block_pointers_avail).min(avail);
            let at = zisofs.block_pointers_avail;
            zisofs.block_pointers[at..at + xsize].copy_from_slice(&p[..xsize]);
            zisofs.block_pointers_avail += xsize;
            avail -= xsize;
            if zisofs.block_pointers_avail == zisofs.block_pointers_size {
                // We've got all block pointers and initialize related
                // variables.
                zisofs.block_off = 0;
                zisofs.block_avail = 0;
                // Complete a initialization
                zisofs.initialized = true;
            }
        }
        Ok(avail)
    }

    fn zisofs_extract(
        &mut self,
        out: &mut dyn Sink,
        zisofs: &mut ZisofsExtract,
        p: &[u8],
    ) -> Result<usize, Error> {
        let bytes = p.len();
        let mut avail;
        let mut start = 0;

        if !zisofs.initialized {
            let rs = Self::zisofs_extract_init(zisofs, p)?;
            if !zisofs.initialized {
                // We need more data.
                zisofs.pz_offset = zisofs.pz_offset.wrapping_add(bytes as u32);
                return Ok(bytes);
            }
            avail = rs;
            start = bytes - avail;
        } else {
            avail = bytes;
        }

        // Get block offsets from block pointers.
        if zisofs.block_avail == 0 {
            if zisofs.block_off + 4 >= zisofs.block_pointers_size {
                // There isn't a pair of offsets.
                return Err(illegal("Illegal zisofs block pointers"));
            }
            let bst = le32(&zisofs.block_pointers, zisofs.block_off).unwrap_or(0);
            if u64::from(bst) != u64::from(zisofs.pz_offset) + (bytes - avail) as u64 {
                return Err(illegal("Illegal zisofs block pointers(cannot seek)"));
            }
            let bed = le32(&zisofs.block_pointers, zisofs.block_off + 4).unwrap_or(0);
            if bed < bst {
                return Err(illegal("Illegal zisofs block pointers"));
            }
            zisofs.block_avail = bed - bst;
            zisofs.block_off += 4;

            // Initialize compression library for new block.
            match &mut zisofs.stream {
                Some(stream) => stream.reset(DataFormat::Zlib),
                None => zisofs.stream = Some(InflateState::new_boxed(DataFormat::Zlib)),
            }
        }

        // Make uncompressed data.
        if zisofs.block_avail == 0 {
            // It's basically 32K bytes NUL data.
            let mut size = zisofs.uncompressed_buffer_size;
            while size > 0 {
                let wb = self.wb_buffptr();
                let wsize = size.min(self.wbuff_remaining);
                self.wbuff[wb..wb + wsize].fill(0);
                self.wb_consume(out, wsize)?;
                size -= wsize;
            }
        } else {
            let n = avail.min(zisofs.block_avail as usize);
            let stream = zisofs
                .stream
                .as_mut()
                .ok_or_else(|| misc("Can't initialize zisofs decompression"))?;
            let wb = self.wb_buffptr();
            let res = inflate(
                stream,
                &p[start..start + n],
                &mut self.wbuff[wb..],
                MZFlush::None,
            );
            let failed = |code: i32| misc(format!("zisofs decompression failed ({code})"));
            match res.status {
                // Decompressor made some progress, or found the end of the
                // stream.
                Ok(MZStatus::Ok | MZStatus::StreamEnd) => {}
                Ok(MZStatus::NeedDict) => return Err(failed(2)),
                Err(e) => return Err(failed(e as i32)),
            }
            avail -= res.bytes_consumed;
            zisofs.block_avail -= res.bytes_consumed as u32;
            self.wb_consume(out, res.bytes_written)?;
        }
        zisofs.pz_offset = zisofs.pz_offset.wrapping_add(bytes as u32);
        Ok(bytes - avail)
    }

    /// zisofs_rewind_boot_file(): uncompress a zisofs'ed boot image to the
    /// end of the temporary file. Like upstream, each read of the file
    /// goes to zisofs_extract() once, which drops what it leaves unused.
    pub(super) fn zisofs_rewind_boot_file(&mut self, out: &mut dyn Sink) -> Result<(), Error> {
        let boot = self
            .el_torito
            .boot
            .ok_or_else(|| misc("Missing boot image"))?;
        let file = self.ents[boot].file;
        let header = self.files[file].zisofs;

        // There is nothing to do if this boot file does not have zisofs
        // header.
        if header.header_size == 0 {
            return Ok(());
        }

        // Uncompress the zisofs'ed file contents.
        let mut zext = ZisofsExtract {
            pz_uncompressed_size: u64::from(header.uncompressed_size),
            pz_log2_bs: header.log2_bs,
            ..ZisofsExtract::default()
        };

        let new_offset = self.wb_offset();
        let content = self.files[file].content[0];
        let mut read_offset = content.offset_of_temp;
        let mut remaining = content.size as usize;
        let rbuff_size = remaining.min(1024 * 32);

        let mut rbuff = vec![0u8; rbuff_size];
        let mut ret = Ok(());
        while remaining > 0 {
            // Get the current file pointer.
            let write_offset = self
                .temp
                .as_mut()
                .and_then(|f| f.stream_position().ok())
                .map_or(-1, |p| p as i64);

            // Change the file pointer to read.
            temp_seek(&mut self.temp, read_offset);

            let rsize = rbuff_size.min(remaining);
            let rs = match temp_read(&mut self.temp, &mut rbuff[..rsize]) {
                Ok(0) => Err(read_error(0, 0)),
                Ok(rs) => Ok(rs),
                Err((rs, errno)) => Err(read_error(rs, errno)),
            };
            let rs = match rs {
                Ok(rs) => rs,
                Err(e) => {
                    ret = Err(e);
                    break;
                }
            };
            remaining -= rs;
            read_offset += rs as i64;

            // Put the file pointer back to write.
            temp_seek(&mut self.temp, write_offset);

            if let Err(e) = self.zisofs_extract(out, &mut zext, &rbuff[..rs]) {
                ret = Err(e);
                break;
            }
        }

        if ret.is_ok() {
            // Change the boot file content from zisofs'ed data to plain
            // data.
            let size = i64::from(header.uncompressed_size);
            let f = &mut self.files[file];
            f.content[0].offset_of_temp = new_offset;
            f.content[0].size = size;
            f.entry.set_size(size);
            // Set to be no zisofs.
            f.zisofs = ZisofsHeader::default();
            ret = self.wb_write_padding_to_temp(out, size);
        }
        ret
    }
}

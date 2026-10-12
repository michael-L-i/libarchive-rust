// Ported from libarchive/archive_write_set_format_iso9660.c: El Torito
// boot images and the boot catalog.

use super::descriptor::{num_721, num_731};
use super::*;

const FD_1_2M_SIZE: i64 = 1024 * 1200;
const FD_1_44M_SIZE: i64 = 1024 * 1440;
const FD_2_88M_SIZE: i64 = 1024 * 2880;

/// If a media type is floppy, return its image size. otherwise return 0.
pub(super) fn fd_boot_image_size(media_type: u8) -> i64 {
    match media_type {
        BOOT_MEDIA_1_2M_DISKETTE => FD_1_2M_SIZE,
        BOOT_MEDIA_1_44M_DISKETTE => FD_1_44M_SIZE,
        BOOT_MEDIA_2_88M_DISKETTE => FD_2_88M_SIZE,
        _ => 0,
    }
}

impl Iso9660 {
    pub(super) fn isoent_find_out_boot_file(&mut self) -> Result<(), Error> {
        // Find a isoent of the boot file.
        self.el_torito.boot =
            self.isoent_find_entry(self.primary.rootent, &self.el_torito.boot_filename);
        let Some(boot) = self.el_torito.boot else {
            let msg = [
                b"Can't find the boot image file ``",
                &self.el_torito.boot_filename[..],
                b"''",
            ]
            .concat();
            return Err(misc(msg));
        };
        self.files[self.ents[boot].file].boot = Boot::Image;
        Ok(())
    }

    pub(super) fn isoent_create_boot_catalog(&mut self) -> Result<(), Error> {
        // Create the entry which is the "boot.catalog" file.
        let file = self.isofile_new(None);
        let (uid, gid) = crate::ffi::sys::user_ids();
        let birth_time = self.birth_time;
        let e = &mut self.files[file].entry;
        e.set_pathname(&self.el_torito.catalog_filename);
        e.set_size(LOGICAL_BLOCK_SIZE as i64);
        e.set_mtime(birth_time, 0);
        e.set_atime(birth_time, 0);
        e.set_ctime(birth_time, 0);
        e.set_uid(uid.into());
        e.set_gid(gid.into());
        e.set_mode(AE_IFREG | 0o444);
        e.set_nlink(1);

        self.isofile_gen_utility_names(None, file)?;
        let f = &mut self.files[file];
        f.boot = Boot::Catalog;
        f.content[0].size = LOGICAL_BLOCK_SIZE as i64;

        let isoent = self.isoent_new(file);
        self.ents[isoent].r#virtual = true;

        // Add the "boot.catalog" entry into tree
        let isoent = self.isoent_tree(isoent).map_err(|e| Error {
            code: ARCHIVE_FATAL,
            ..e
        })?;

        self.el_torito.catalog = Some(isoent);
        let boot = self
            .el_torito
            .boot
            .ok_or_else(|| misc("Missing boot image"))?;
        let size = self.files[self.ents[boot].file].entry.size();
        // Get a boot media type.
        self.el_torito.media_type = match self.opt.boot_type {
            OPT_BOOT_TYPE_NO_EMU => BOOT_MEDIA_NO_EMULATION,
            OPT_BOOT_TYPE_HARD_DISK => BOOT_MEDIA_HARD_DISK,
            OPT_BOOT_TYPE_FD => {
                if size <= FD_1_2M_SIZE {
                    BOOT_MEDIA_1_2M_DISKETTE
                } else if size <= FD_1_44M_SIZE {
                    BOOT_MEDIA_1_44M_DISKETTE
                } else if size <= FD_2_88M_SIZE {
                    BOOT_MEDIA_2_88M_DISKETTE
                } else {
                    let msg = [
                        b"Boot image file(``",
                        &self.el_torito.boot_filename[..],
                        b"'') size is too big for fd type",
                    ]
                    .concat();
                    return Err(misc(msg));
                }
            }
            // Try detecting a media type of the boot image.
            _ => match size {
                FD_1_2M_SIZE => BOOT_MEDIA_1_2M_DISKETTE,
                FD_1_44M_SIZE => BOOT_MEDIA_1_44M_DISKETTE,
                FD_2_88M_SIZE => BOOT_MEDIA_2_88M_DISKETTE,
                // We cannot decide whether the boot image is hard-disk.
                _ => BOOT_MEDIA_NO_EMULATION,
            },
        };

        // Get a system type.
        // TODO: `El Torito' specification says "A copy of byte 5 from the
        //       Partition Table found in the boot image".
        self.el_torito.system_type = 0;

        // Get an ID.
        if self.opt.publisher {
            self.el_torito.id = self.publisher_identifier.clone();
        }

        Ok(())
    }

    /// Make a boot catalog image data.
    pub(super) fn make_boot_catalog(&mut self, out: &mut dyn Sink) -> Result<(), Error> {
        let et = &self.el_torito;
        let mut block = [0u8; LOGICAL_BLOCK_SIZE];

        // Validation Entry
        // Header ID
        block[0] = 1;
        // Platform ID
        block[1] = et.platform_id;
        // Reserved: 2 and 3
        // ID
        let id = &et.id[..strlen(&et.id)];
        let n = id.len().min(23);
        block[4..4 + n].copy_from_slice(&id[..n]);
        // Checksum: 28 and 29
        // Key
        block[30] = 0x55;
        block[31] = 0xAA;

        let sum = block[..32].chunks_exact(2).fold(0u16, |sum, w| {
            sum.wrapping_add(u16::from_le_bytes([w[0], w[1]]))
        });
        block[28..30].copy_from_slice(&num_721((!sum).wrapping_add(1)));

        // Initial/Default Entry
        let no_emulation = et.media_type == BOOT_MEDIA_NO_EMULATION;
        let p = &mut block[32..64];
        // Boot Indicator
        p[0] = 0x88;
        // Boot media type
        p[1] = et.media_type;
        // Load Segment
        p[2..4].copy_from_slice(&num_721(if no_emulation { et.boot_load_seg } else { 0 }));
        // System Type
        p[4] = et.system_type;
        // Unused: 5
        // Sector Count
        p[6..8].copy_from_slice(&num_721(if no_emulation { et.boot_load_size } else { 1 }));
        // Load RBA
        let boot = et.boot.ok_or_else(|| misc("Missing boot image"))?;
        let location = self.files[self.ents[boot].file].content[0].location;
        block[40..44].copy_from_slice(&num_731(location));
        // Unused: 12 to 31 of the entry

        self.wb_put_block(out, &block)
    }

    /// setup_boot_information(): the boot information table, written over
    /// bytes 8 to 64 of the boot image in the temporary file.
    pub(super) fn setup_boot_information(&mut self) -> Result<(), Error> {
        let np = self
            .el_torito
            .boot
            .ok_or_else(|| misc("Missing boot image"))?;
        let file = self.ents[np].file;
        let content = self.files[file].content[0];
        let entry_size = self.files[file].entry.size();

        temp_seek(&mut self.temp, content.offset_of_temp + 64);
        let mut size = entry_size.wrapping_sub(64);
        if size <= 0 {
            return Err(Error::fatal(
                0,
                format!("Boot file({}) is too small", size.wrapping_add(64)),
            ));
        }
        // The buffer outlives each read: upstream sums whole words, so the
        // tail of a read that ends inside a word takes the bytes the
        // previous read left there. Before any read they are zero here,
        // where upstream's are uninitialized.
        let mut buff = [0u8; 4096];
        let mut sum: u32 = 0;
        while size > 0 {
            let rsize = size.min(buff.len() as i64) as usize;
            let rs = match temp_read(&mut self.temp, &mut buff[..rsize]) {
                Ok(0) => return Err(read_error(0, 0)),
                Ok(rs) => rs,
                Err((rs, errno)) => return Err(read_error(rs, errno)),
            };
            for w in buff[..rs.div_ceil(4) * 4].chunks_exact(4) {
                sum = sum.wrapping_add(u32::from_le_bytes([w[0], w[1], w[2], w[3]]));
            }
            size -= rs as i64;
        }

        let mut size = fd_boot_image_size(self.el_torito.media_type);
        if size == 0 {
            size = entry_size;
        }
        // Upstream truncates a size its 32-bit field can't hold.
        let size = u32::try_from(size).map_err(|_| {
            Error::fatal(
                libc::EOVERFLOW,
                "Boot image size exceeds its information table",
            )
        })?;
        let mut table = [0u8; 56];
        // Set the location of Primary Volume Descriptor.
        table[0..4].copy_from_slice(&num_731(SYSTEM_AREA_BLOCK as u32));
        // Set the location of the boot file.
        table[4..8].copy_from_slice(&num_731(content.location));
        // Set the size of the boot file.
        table[8..12].copy_from_slice(&num_731(size));
        // Set the sum of the boot file.
        table[12..16].copy_from_slice(&num_731(sum));
        // Clear reserved bytes: 16 to 56.

        // Overwrite the boot file.
        temp_seek(&mut self.temp, content.offset_of_temp + 8);
        write_to_temp(&mut self.temp, &table)
    }
}

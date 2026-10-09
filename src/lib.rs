#![deny(unsafe_code)]

mod acl;
mod archive;
mod blake2s_ref;
#[allow(dead_code)] // used by the rar5 reader (phase 4)
mod blake2sp_ref;
mod check_magic;
mod cmdline;
mod crc32;
mod cryptor;
mod digest;
mod entry;
mod entry_copy_stat;
mod entry_link_resolver;
mod entry_sparse;
mod entry_stat;
mod entry_strmode;
mod entry_xattr;
mod ffi;
mod hmac;
mod options;
mod pack_dev;
mod ppmd;
mod ppmd7;
mod ppmd8;
mod read;
mod read_add_passphrase;
mod read_append_filter;
mod read_data_into_fd;
mod read_open_fd;
mod read_open_file;
mod read_open_filename;
mod read_open_memory;
mod read_set_format;
mod read_set_options;
mod string;
mod string_composition;
#[allow(dead_code)] // used by the zip, 7zip, rar, rar5 and lha readers (phase 4)
mod time;
mod util;
mod version_details;
mod r#virtual;

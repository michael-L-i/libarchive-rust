//! Opt-in processing budgets. These measure work, not resident heap memory.

use crate::util::Error;
use std::cell::Cell;

/// Optional resource limits for one archive read handle.
///
/// Configure before opening the archive. `None` preserves the existing C
/// behavior and hard safety caps; `Some(0)` permits no work in that category.
/// Exceeding a budget returns `Status::Fatal`, `EFBIG`, and an error beginning
/// with `Archive resource limit exceeded:`. A failure is persistent until close.
/// Decoder memory rejection uses the existing codec error (`ENOMEM` where
/// available), which may also describe malformed compressed input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadLimits {
    /// Sum of newly produced source blocks, filter outputs and instrumented
    /// format decoder outputs, including intermediate layers, headers, skips
    /// and rereads. Buffer copies are not charged. A producer may finish one
    /// bounded output block before the limit is detected.
    pub decoded_bytes: Option<u64>,
    /// Maximum returned entries and eagerly parsed entry-table members.
    pub entries: Option<u64>,
    /// Aggregate bytes consumed during format bidding/header parsing, plus
    /// instrumented decoded/retained metadata. This includes syntax and parsing
    /// overhead; it is a processing budget rather than an exact heap bound.
    pub metadata_bytes: Option<u64>,
    /// Maximum number of outer filter layers, in addition to the source.
    /// The existing hard maximum of 25 automatically detected filters remains.
    pub filter_depth: Option<usize>,
    /// Per-decoder cap in bytes for supported decoder dictionaries/windows.
    /// Applies to XZ/LZMA/lzip outer filters; LZMA/XZ/Zstd/PPMd in ZIP,
    /// LZMA/LZMA2/Zstd/PPMd in 7-Zip; XZ/LZMA in XAR; RAR windows and
    /// PPMd models; and RAR5 windows. Zstd limits the window, PPMd the model
    /// arena, and raw LZMA/lzip the dictionary; decoder overhead and other
    /// codecs are outside this cap. Existing hard caps remain. This is not
    /// an aggregate heap-memory limit.
    pub decoder_memory: Option<u64>,
}

#[derive(Clone, Copy)]
enum Exceeded {
    Decoded,
    Entries,
    Metadata,
    Depth,
}

impl Exceeded {
    fn error(self) -> Error {
        let name = match self {
            Self::Decoded => "decoded bytes",
            Self::Entries => "entries",
            Self::Metadata => "metadata bytes",
            Self::Depth => "filter depth",
        };
        Error::fatal(
            libc::EFBIG,
            format!("Archive resource limit exceeded: {name}"),
        )
    }
}

#[derive(Default)]
pub(super) struct Budget {
    pub limits: ReadLimits,
    decoded: Cell<u64>,
    metadata: Cell<u64>,
    entries: Cell<u64>,
    failure: Cell<Option<Exceeded>>,
}

impl Budget {
    pub fn reset(&self) {
        self.decoded.set(0);
        self.metadata.set(0);
        self.entries.set(0);
        self.failure.set(None);
    }

    pub fn check(&self) -> Result<(), Error> {
        self.failure.get().map_or(Ok(()), |e| Err(e.error()))
    }

    fn fail(&self, e: Exceeded) -> Error {
        let first = self.failure.get().unwrap_or(e);
        self.failure.set(Some(first));
        first.error()
    }

    fn charge(
        &self,
        count: &Cell<u64>,
        max: Option<u64>,
        n: impl TryInto<u64>,
        e: Exceeded,
    ) -> Result<(), Error> {
        self.check()?;
        // Unlimited categories need no counter, preserving compatibility even
        // for a theoretical stream longer than u64::MAX.
        let Some(max) = max else { return Ok(()) };
        let total = n.try_into().ok().and_then(|n| count.get().checked_add(n));
        let Some(total) = total.filter(|&n| n <= max) else {
            return Err(self.fail(e));
        };
        count.set(total);
        Ok(())
    }

    pub fn decoded(&self, n: impl TryInto<u64>) -> Result<(), Error> {
        self.charge(
            &self.decoded,
            self.limits.decoded_bytes,
            n,
            Exceeded::Decoded,
        )
    }

    pub fn check_metadata(&self, n: impl TryInto<u64>) -> Result<(), Error> {
        self.check()?;
        if self.limits.metadata_bytes.is_some_and(|max| {
            n.try_into()
                .ok()
                .and_then(|n| self.metadata.get().checked_add(n))
                .is_none_or(|n| n > max)
        }) {
            return Err(self.fail(Exceeded::Metadata));
        }
        Ok(())
    }

    pub fn metadata(&self, n: impl TryInto<u64>) -> Result<(), Error> {
        self.charge(
            &self.metadata,
            self.limits.metadata_bytes,
            n,
            Exceeded::Metadata,
        )
    }

    pub fn entry(&self) -> Result<(), Error> {
        self.charge(&self.entries, self.limits.entries, 1u64, Exceeded::Entries)
    }

    pub fn check_entries(&self, n: impl TryInto<u64>) -> Result<(), Error> {
        self.check()?;
        if self
            .limits
            .entries
            .is_some_and(|max| n.try_into().ok().is_none_or(|n| n > max))
        {
            return Err(self.fail(Exceeded::Entries));
        }
        Ok(())
    }

    pub fn filter_depth(&self, n: usize) -> Result<(), Error> {
        self.check()?;
        if self.limits.filter_depth.is_some_and(|max| n > max) {
            return Err(self.fail(Exceeded::Depth));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{ARCHIVE_FATAL, ARCHIVE_OK, Base, READ_MAGIC};
    use crate::read::{Client, Read};
    use crate::read_open_memory::Memory;

    fn error(a: &Base) -> String {
        a.error_string()
            .map_or_else(String::new, |m| String::from_utf8_lossy(&m).into_owned())
    }

    #[test]
    fn limits_source_skips_and_buffer_copies_share_one_budget() {
        let a = Base::new(READ_MAGIC);
        let mut r = Read::default();
        assert_eq!(
            r.set_limits(
                &a,
                ReadLimits {
                    decoded_bytes: Some(10),
                    ..ReadLimits::default()
                }
            ),
            ARCHIVE_OK
        );
        r.open_client(&a, Box::new(Memory::new([0; 100], 4)))
            .unwrap();
        let mut rd = r.reader(&a);
        assert_eq!(rd.peek_available(5).unwrap().len(), 5);
        for _ in 0..3 {
            assert_eq!(rd.peek_available(1).unwrap().len(), 5);
        }
        assert!(rd.consume(100).is_err());
        assert_eq!(rd.budget.check().unwrap_err().errno, libc::EFBIG);
        assert_eq!(rd.budget.decoded.get(), 8);
    }

    struct Broken;
    impl Client for Broken {
        fn read(&mut self, _: &Base, _: usize) -> Result<(), Error> {
            Err(Error::fatal(libc::EIO, "client read failed"))
        }
        fn block(&self) -> &[u8] {
            &[]
        }
        fn can_skip(&self) -> bool {
            true
        }
        fn skip(&mut self, a: &Base, _: usize, _: i64) -> Result<i64, Error> {
            a.set_error(libc::EIO, Some(b"client skip failed"));
            Err(Error::recorded(ARCHIVE_FATAL))
        }
    }

    #[test]
    fn limits_preserve_default_consume_error_translation() {
        let a = Base::new(READ_MAGIC);
        let mut r = Read::default();
        r.open_client(&a, Box::new(Broken)).unwrap();
        assert!(r.reader(&a).consume(7).is_err());
        assert_eq!(
            error(&a),
            "Truncated input file (needed 7 bytes, only 0 available)"
        );
        let mut r = Read::default();
        r.open_client(&a, Box::new(Broken)).unwrap();
        r.chain[0].can_skip = false;
        assert!(r.reader(&a).consume(9).is_err());
        assert_eq!(
            error(&a),
            "Truncated input file (needed 9 bytes, only 0 available)"
        );
    }

    #[test]
    fn limits_counters_check_overflow_and_reset_all_categories() {
        let budget = Budget {
            limits: ReadLimits {
                decoded_bytes: Some(u64::MAX),
                entries: Some(1),
                ..ReadLimits::default()
            },
            ..Budget::default()
        };
        budget.decoded(u64::MAX).unwrap();
        assert_eq!(budget.decoded(1u64).unwrap_err().errno, libc::EFBIG);
        assert!(budget.entry().is_err());
        budget.reset();
        budget.decoded(1u64).unwrap();
        budget.entry().unwrap();
        assert!(budget.entry().is_err());
        budget.reset();
        budget.entry().unwrap();
    }

    #[test]
    fn limits_delayed_header_consumption_is_counted_once() {
        let a = Base::new(READ_MAGIC);
        let mut r = Read::default();
        assert_eq!(
            r.set_limits(
                &a,
                ReadLimits {
                    metadata_bytes: Some(4),
                    ..ReadLimits::default()
                }
            ),
            ARCHIVE_OK
        );
        r.open_client(&a, Box::new(Memory::new([0; 8], 8))).unwrap();
        let mut rd = r.reader(&a);
        rd.metadata = true;
        let later = rd.consume_later();
        rd.peek_available(4).unwrap();
        later.consume(4);
        rd.flush().unwrap();
        assert_eq!(rd.budget.metadata.get(), 4);
        rd.metadata = false;
        rd.consume(4).unwrap();
        assert_eq!(rd.budget.metadata.get(), 4);
    }
}

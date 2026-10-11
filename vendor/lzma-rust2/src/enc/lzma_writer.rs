use super::{
    LzmaOptions,
    encoder::{LzmaEncoder, Settings, new_mf},
    lz::{Action, Mf},
};
use crate::{AutoFinish, AutoFinisher, Write, error_invalid_input, error_unsupported};

/// A single-threaded LZMA compressor.
pub struct LzmaWriter<W: Write> {
    inner: W,
    mf: Mf,
    lzma: LzmaEncoder,
    current_uncompressed_size: u64,
    expected_uncompressed_size: Option<u64>,
    props: u8,
}

impl<W: Write> LzmaWriter<W> {
    /// Creates a new LZMA writer with full control over formatting options.
    pub fn new(
        mut out: W,
        options: &LzmaOptions,
        use_header: bool,
        use_end_marker: bool,
        expected_uncompressed_size: Option<u64>,
    ) -> crate::Result<LzmaWriter<W>> {
        if use_header && options.preset_dict.is_some() {
            return Err(error_unsupported(
                "header is not supported with preset dict",
            ));
        }
        let settings = Settings::new(options);
        let mf = new_mf(options, &settings, false);
        let lzma = LzmaEncoder::new(options, &settings, use_end_marker);
        let props = lzma.lclppb();

        if use_header {
            // Round up to the next 2^n or 2^n + 2^(n - 1) depending on which
            // one is the next unless it is u32::MAX, as liblzma's
            // `lzma_alone_encoder()` does to keep its decoder accepting the
            // resulting files.
            let mut d = settings.dict_size - 1;
            d |= d >> 2;
            d |= d >> 3;
            d |= d >> 4;
            d |= d >> 8;
            d |= d >> 16;
            d = d.saturating_add(1);
            out.write_all(&[props])?;
            out.write_all(&d.to_le_bytes())?;
            out.write_all(&expected_uncompressed_size.unwrap_or(u64::MAX).to_le_bytes())?;
        }

        Ok(LzmaWriter {
            inner: out,
            mf,
            lzma,
            current_uncompressed_size: 0,
            expected_uncompressed_size,
            props,
        })
    }

    /// Creates a new LZMA writer that includes a .lzma header with the specified input size.
    #[inline]
    pub fn new_use_header(
        out: W,
        options: &LzmaOptions,
        input_size: Option<u64>,
    ) -> crate::Result<Self> {
        Self::new(out, options, true, input_size.is_none(), input_size)
    }

    /// Creates a new LZMA writer without a .lzma header.
    #[inline]
    pub fn new_no_header(
        out: W,
        options: &LzmaOptions,
        use_end_marker: bool,
    ) -> crate::Result<Self> {
        Self::new(out, options, false, use_end_marker, None)
    }

    /// Returns a wrapper around `self` that will finish the stream on drop.
    pub fn auto_finish(self) -> AutoFinisher<Self> {
        AutoFinisher(Some(self))
    }

    /// Returns the LZMA properties byte.
    #[inline]
    pub fn props(&self) -> u8 {
        self.props
    }

    /// Returns the number of uncompressed bytes written so far.
    #[inline]
    pub fn get_uncompressed_size(&self) -> u64 {
        self.current_uncompressed_size
    }

    /// Unwraps the writer, returning the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Returns a reference to the inner writer.
    pub fn inner(&self) -> &W {
        &self.inner
    }

    /// Returns a mutable reference to the inner writer.
    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Runs the encoder and moves its output to the inner writer. Returns
    /// true once the stream is finished.
    fn encode(&mut self) -> crate::Result<bool> {
        let finished = self.lzma.encode(&mut self.mf, None);
        self.inner.write_all(&self.lzma.rc.out)?;
        self.lzma.rc.out.clear();
        Ok(finished)
    }

    /// Finishes the compression and returns the underlying writer.
    pub fn finish(mut self) -> crate::Result<W> {
        if let Some(exp) = self.expected_uncompressed_size {
            if exp != self.current_uncompressed_size {
                return Err(error_invalid_input(
                    "expected compressed size does not match actual compressed size",
                ));
            }
        }
        loop {
            if self.mf.action == Action::Run && self.mf.read_pos >= self.mf.read_limit {
                self.mf.fill_window(&[], Action::Finish);
            }
            if self.encode()? {
                return Ok(self.inner);
            }
        }
    }
}

impl<W: Write> Write for LzmaWriter<W> {
    fn write(&mut self, buf: &[u8]) -> crate::Result<usize> {
        if let Some(exp) = self.expected_uncompressed_size {
            if exp < self.current_uncompressed_size + buf.len() as u64 {
                return Err(error_invalid_input(
                    "expected compressed size does not match actual compressed size",
                ));
            }
        }
        self.current_uncompressed_size += buf.len() as u64;
        let mut pos = 0;
        while pos < buf.len() {
            // Read more data to the history buffer if needed.
            if self.mf.action == Action::Run && self.mf.read_pos >= self.mf.read_limit {
                pos += self.mf.fill_window(&buf[pos..], Action::Run);
            }
            self.encode()?;
        }
        Ok(pos)
    }

    fn flush(&mut self) -> crate::Result<()> {
        Ok(())
    }
}

impl<W: Write> AutoFinish for LzmaWriter<W> {
    fn finish_ignore_error(self) {
        let _ = self.finish();
    }
}

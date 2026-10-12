#![no_main]
harness::libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    harness::writer::roundtrip(data, harness::writer::Format::Iso);
});

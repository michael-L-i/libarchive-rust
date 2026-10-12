#![no_main]
harness::libfuzzer_sys::fuzz_target!(|data: &[u8]| harness::writer::all(data));

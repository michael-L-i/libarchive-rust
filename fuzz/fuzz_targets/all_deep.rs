#![no_main]
harness::libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    harness::run_deep(
        data,
        &[
            harness::archive_read_support_format_all,
            harness::archive_read_support_filter_all,
        ],
    );
});

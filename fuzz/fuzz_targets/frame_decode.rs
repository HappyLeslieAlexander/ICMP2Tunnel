#![no_main]

use icmp2tunnel_proto::{decode_frame, decode_header};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }

    let _ = decode_header(data);
    let _ = decode_frame(data);
});

#![no_main]

use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 64 * 1024;

fn parse_socks5(data: &[u8]) {
    if data.len() < 3 || data[0] != 0x05 {
        return;
    }

    let nmethods = usize::from(data[1]);
    if data.len() < 2 + nmethods {
        return;
    }

    let req = &data[2 + nmethods..];
    if req.len() < 4 || req[0] != 0x05 {
        return;
    }

    let atyp = req[3];
    match atyp {
        0x01 => {
            if req.len() >= 10 {
                let _ip = &req[4..8];
                let _port = u16::from_be_bytes([req[8], req[9]]);
            }
        }
        0x03 => {
            if req.len() >= 5 {
                let host_len = usize::from(req[4]);
                if req.len() >= 5 + host_len + 2 {
                    let _host = &req[5..5 + host_len];
                    let _port = u16::from_be_bytes([req[5 + host_len], req[6 + host_len]]);
                }
            }
        }
        0x04 => {
            if req.len() >= 22 {
                let _ip6 = &req[4..20];
                let _port = u16::from_be_bytes([req[20], req[21]]);
            }
        }
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    parse_socks5(data);
});

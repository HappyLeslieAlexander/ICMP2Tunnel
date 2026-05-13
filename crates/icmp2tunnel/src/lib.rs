#![forbid(unsafe_code)]
#![deny(warnings)]

/// Returns a short marker indicating the bootstrap crate is wired.
#[must_use]
pub const fn bootstrap_marker() -> &'static str {
    "icmp2tunnel-bootstrap"
}

#[cfg(test)]
mod tests {
    use super::bootstrap_marker;

    #[test]
    fn marker_is_stable() {
        assert_eq!(bootstrap_marker(), "icmp2tunnel-bootstrap");
    }
}

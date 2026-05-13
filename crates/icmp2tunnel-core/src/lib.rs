#![forbid(unsafe_code)]
#![deny(warnings)]

/// Placeholder core crate for milestone 4 wiring.
#[must_use]
pub const fn core_marker() -> &'static str {
    "icmp2tunnel-core"
}

#[cfg(test)]
mod tests {
    use super::core_marker;

    #[test]
    fn marker_is_stable() {
        assert_eq!(core_marker(), "icmp2tunnel-core");
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source address keying with configurable IPv6 prefix masking.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An opaque, hashable identifier for a source after prefix masking.
///
/// IPv4 addresses are always keyed on their full `/32`. IPv6 addresses
/// are masked to the configured `ipv6_prefix_len` before being stored,
/// so two addresses within the same configured prefix produce identical
/// keys. The masking defends against IPv6 exhaustion attacks where an
/// attacker cycles through their own `/64` to generate unlimited
/// distinct source addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceKey {
    discriminator: Discriminator,
    bytes: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Discriminator {
    V4,
    V6,
}

impl SourceKey {
    /// Constructs a new `SourceKey` from an `IpAddr`, applying IPv6
    /// prefix masking.
    ///
    /// `ipv6_prefix_len` must be in `1..=128`; values outside this
    /// range are clamped (config validation ensures the caller never
    /// passes an out-of-range value in practice).
    #[must_use]
    pub fn from_ip(ip: IpAddr, ipv6_prefix_len: u8) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::from_ipv4(v4),
            IpAddr::V6(v6) => Self::from_ipv6_masked(v6, ipv6_prefix_len),
        }
    }

    fn from_ipv4(v4: Ipv4Addr) -> Self {
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(&v4.octets());
        Self {
            discriminator: Discriminator::V4,
            bytes,
        }
    }

    fn from_ipv6_masked(v6: Ipv6Addr, prefix_len: u8) -> Self {
        let prefix_len = prefix_len.clamp(1, 128);
        let mut bytes = v6.octets();
        // Zero all bits past `prefix_len`. A prefix of N bits means we
        // keep the leading N bits and zero the remaining 128 - N.
        let full_bytes = (prefix_len / 8) as usize;
        let remaining_bits = prefix_len % 8;
        // Bits inside the partial byte at index `full_bytes`: we keep
        // the top `remaining_bits` and clear the rest.
        if full_bytes < 16 {
            if remaining_bits > 0 {
                let mask: u8 = 0xFFu8 << (8 - remaining_bits);
                bytes[full_bytes] &= mask;
                for b in bytes.iter_mut().skip(full_bytes + 1) {
                    *b = 0;
                }
            } else {
                for b in bytes.iter_mut().skip(full_bytes) {
                    *b = 0;
                }
            }
        }
        Self {
            discriminator: Discriminator::V6,
            bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_full_address_keys_exactly() {
        let a = SourceKey::from_ip("10.0.0.1".parse().unwrap(), 64);
        let b = SourceKey::from_ip("10.0.0.1".parse().unwrap(), 64);
        let c = SourceKey::from_ip("10.0.0.2".parse().unwrap(), 64);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn ipv4_ignores_ipv6_prefix_len_parameter() {
        let a = SourceKey::from_ip("10.0.0.1".parse().unwrap(), 1);
        let b = SourceKey::from_ip("10.0.0.1".parse().unwrap(), 128);
        assert_eq!(a, b, "IPv6 prefix length must not affect IPv4 keys");
    }

    #[test]
    fn ipv4_and_ipv6_with_same_bytes_are_distinct() {
        // 0.0.0.0 (IPv4) and :: (IPv6) should NOT collide even though
        // their raw bytes are identical — the discriminator must keep
        // them apart.
        let v4 = SourceKey::from_ip("0.0.0.0".parse().unwrap(), 64);
        let v6 = SourceKey::from_ip("::".parse().unwrap(), 64);
        assert_ne!(v4, v6);
    }

    #[test]
    fn ipv6_slash_64_collapses_addresses_in_same_subnet() {
        let a = SourceKey::from_ip("2001:db8::1".parse().unwrap(), 64);
        let b = SourceKey::from_ip("2001:db8::abcd:1234".parse().unwrap(), 64);
        let c = SourceKey::from_ip("2001:db8::ffff:ffff:ffff:ffff".parse().unwrap(), 64);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn ipv6_slash_64_separates_addresses_in_different_subnets() {
        let a = SourceKey::from_ip("2001:db8::1".parse().unwrap(), 64);
        let d = SourceKey::from_ip("2001:db8:0:1::1".parse().unwrap(), 64);
        assert_ne!(a, d, "different /64 subnets must not collide");
    }

    #[test]
    fn ipv6_slash_128_keeps_addresses_distinct() {
        let a = SourceKey::from_ip("2001:db8::1".parse().unwrap(), 128);
        let b = SourceKey::from_ip("2001:db8::2".parse().unwrap(), 128);
        assert_ne!(a, b);
    }

    #[test]
    fn ipv6_slash_48_masks_more_aggressively() {
        let a = SourceKey::from_ip("2001:db8:0:1::1".parse().unwrap(), 48);
        let b = SourceKey::from_ip("2001:db8:0:2::1".parse().unwrap(), 48);
        assert_eq!(a, b, "under /48 both addresses share the same prefix");
    }

    #[test]
    fn ipv6_odd_prefix_length_masks_correctly() {
        // /65 means: keep 64 bits + 1 more bit. Two addresses that
        // differ only in bit 65 should be distinct, but differ only
        // in bit 66 should collapse.
        let a = SourceKey::from_ip("2001:db8::8000:0:0:0".parse().unwrap(), 65);
        let b = SourceKey::from_ip("2001:db8::C000:0:0:0".parse().unwrap(), 65);
        // a has bit 65 set (0x8000), b has bits 65 and 66 set (0xC000).
        // Both have bit 65 set, so under /65 they should be equal.
        assert_eq!(a, b);
        let c = SourceKey::from_ip("2001:db8::".parse().unwrap(), 65);
        // c has neither bit 65 nor 66 set. Under /65 it differs from
        // a by bit 65.
        assert_ne!(a, c);
    }

    #[test]
    fn source_key_is_copy_and_hash() {
        // Compile-time assertion that the type is Copy + Hash.
        fn assert_copy_hash<T: Copy + std::hash::Hash>() {}
        assert_copy_hash::<SourceKey>();
    }
}

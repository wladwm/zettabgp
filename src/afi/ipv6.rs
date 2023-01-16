// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module describes NLRI data structures for ipv6

use crate::afi::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;

/// ipv6 prefix unicast/multicast NLRI
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpAddrV6 {
    /// network prefix
    pub addr: Ipv6Addr,
    /// prefix length 0..128
    pub prefixlen: u8,
}
impl Default for BgpAddrV6 {
    fn default() -> Self {
        BgpAddrV6 {
            addr: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            prefixlen: 128,
        }
    }
}
impl BgpAddrV6 {
    /// Constructs new ipv6 prefix
    /// ```
    /// use std::net::Ipv6Addr;
    /// use zettabgp::prelude::BgpAddrV6;
    ///
    /// let pfx = BgpAddrV6::new(Ipv6Addr::new(0x2a02,0,0,0,0,0,0,0),32);
    /// ```
    pub fn new(address: Ipv6Addr, prefix_len: u8) -> BgpAddrV6 {
        BgpAddrV6 {
            addr: address,
            prefixlen: prefix_len,
        }
    }
    /// if given subnet is in this subnet
    /// ```
    /// use std::net::Ipv6Addr;
    /// use zettabgp::prelude::BgpAddrV6;
    ///
    /// assert!(BgpAddrV6::new(Ipv6Addr::new(0x2a02,0,0,0,0,0,0,0),32).contains(&BgpAddrV6::new(Ipv6Addr::new(0x2a02,0,0,0,0,0,0,1),128)));
    /// ```
    pub fn contains(&self, a: &BgpAddrV6) -> bool {
        if self.prefixlen < 1 {
            true
        } else if self.prefixlen > a.prefixlen {
            false
        } else if self.prefixlen == a.prefixlen {
            self.addr == a.addr
        } else {
            (getn_u128(&self.addr.octets()) & (!((1 << (128 - self.prefixlen)) - 1)))
                == (getn_u128(&a.addr.octets()) & (!((1 << (128 - self.prefixlen)) - 1)))
        }
    }
    fn norm_subnet_u128(&self) -> u128 {
        getn_u128(&self.addr.octets())
            & (((1 << (128 - self.prefixlen)) - 1) ^ 0xffffffffffffffffffffffffffffffff)
    }
    /// Check if IP in this subnet
    /// ```
    /// use zettabgp::prelude::BgpAddrV6;
    /// use std::net::Ipv6Addr;
    ///
    /// assert!(BgpAddrV6::new(Ipv6Addr::new(0x2a02,0,0,0,0,0,0,0),32).in_subnet(&Ipv6Addr::new(0x2a02,0,0,0,0,0,0,1)));
    /// ```
    pub fn in_subnet(&self, a: &std::net::Ipv6Addr) -> bool {
        if self.prefixlen > 127 {
            getn_u128(&self.addr.octets()) == getn_u128(&a.octets())
        } else {
            let lv = self.norm_subnet_u128();
            let lh = lv + ((1 << (128 - self.prefixlen)) - 1);
            let va = getn_u128(&a.octets());
            (va >= lv) && (va < lh)
        }
    }
    /// Returns first IP address (network address) from subnet
    /// ```
    /// use std::net::Ipv6Addr;
    /// use zettabgp::prelude::BgpAddrV6;
    ///
    /// assert_eq!(BgpAddrV6::new(Ipv6Addr::new(0x2a02,0,0,0,0,0,0,0x100),32).range_first() , Ipv6Addr::new(0x2a02,0,0,0,0,0,0,0) );
    /// ```
    pub fn range_first(&self) -> std::net::Ipv6Addr {
        let lv = self.norm_subnet_u128();
        std::net::Ipv6Addr::new(
            (lv >> 112) as u16,
            (lv >> 96) as u16,
            (lv >> 80) as u16,
            (lv >> 64) as u16,
            (lv >> 48) as u16,
            (lv >> 32) as u16,
            (lv >> 16) as u16,
            (lv & 0xffff) as u16,
        )
    }
    /// Returns last inclusive IP address for subnet
    /// ```
    /// use std::net::Ipv6Addr;
    /// use zettabgp::prelude::BgpAddrV6;
    ///
    /// assert_eq!(BgpAddrV6::new(Ipv6Addr::new(0x2a02,0,0,0,0,0,0,0x100),112).range_last() , Ipv6Addr::new(0x2a02,0,0,0,0,0,0,0xffff) );
    /// ```
    pub fn range_last(&self) -> std::net::Ipv6Addr {
        if self.prefixlen < 1 {
            std::net::Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            )
        } else if self.prefixlen > 127 {
            self.range_first()
        } else {
            let lv = self.norm_subnet_u128() + ((1 << (128 - self.prefixlen)) - 1);
            std::net::Ipv6Addr::new(
                (lv >> 112) as u16,
                (lv >> 96) as u16,
                (lv >> 80) as u16,
                (lv >> 64) as u16,
                (lv >> 48) as u16,
                (lv >> 32) as u16,
                (lv >> 16) as u16,
                (lv & 0xffff) as u16,
            )
        }
    }
    /// Check if given address is multicast
    pub fn is_multicast(&self) -> bool {
        self.addr.octets()[0] == 255
    }
    pub fn from_bits(bits: u8, buf: &[u8]) -> Result<(BgpAddrV6, usize), BgpError> {
        let bytes = ((bits + 7) / 8) as usize;
        if bits > 128 || buf.len() < bytes {
            return Err(BgpError::from_string(format!(
                "Invalid FEC length: {:?}",
                bits
            )));
        }
        let mut bf = [0_u8; 16];
        if bits == 0 {
            return Ok((
                BgpAddrV6 {
                    addr: decode_addrv6_from(&bf)?,
                    prefixlen: 0,
                },
                0,
            ));
        }
        bf[0..bytes].clone_from_slice(&buf[0..bytes]);
        Ok((
            BgpAddrV6 {
                addr: decode_addrv6_from(&bf)?,
                prefixlen: bits,
            },
            bytes,
        ))
    }
    pub fn to_bits(&self, buf: &mut [u8]) -> Result<(u8, usize), BgpError> {
        if self.prefixlen == 0 {
            return Ok((0, 0));
        }
        let mut bf = [0_u8; 16];
        bf.clone_from_slice(&self.addr.octets());
        let bytes = ((self.prefixlen + 7) / 8) as usize;
        buf[0..bytes].clone_from_slice(&bf[0..bytes]);
        Ok((self.prefixlen, bytes))
    }
}
impl std::str::FromStr for BgpAddrV6 {
    type Err = std::net::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() < 2 {
            Ok(BgpAddrV6 {
                addr: parts[0].parse::<std::net::Ipv6Addr>()?,
                prefixlen: 128,
            })
        } else {
            Ok(BgpAddrV6 {
                addr: parts[0].parse::<std::net::Ipv6Addr>()?,
                prefixlen: parts[1].parse::<u8>().unwrap_or(128),
            })
        }
    }
}
impl BgpItem<BgpAddrV6> for BgpAddrV6 {
    fn extract_bits_from(bits: u8, buf: &[u8]) -> Result<(BgpAddrV6, usize), BgpError> {
        BgpAddrV6::from_bits(bits, buf)
    }
    fn set_bits_to(&self, buf: &mut [u8]) -> Result<(u8, usize), BgpError> {
        self.to_bits(buf)
    }
    fn prefixlen(&self) -> usize {
        self.prefixlen as usize
    }
}
impl std::fmt::Display for BgpAddrV6 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}/{:?}", self.addr, self.prefixlen)
    }
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpIPv6RD {
    pub rd: BgpRD,
    pub addr: std::net::Ipv6Addr,
}
impl std::fmt::Display for BgpIPv6RD {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.rd.is_zero() {
            self.addr.fmt(f)
        } else {
            write!(f, "<{}>{}", self.rd, self.addr)
        }
    }
}
impl BgpAddrItem<BgpIPv6RD> for BgpIPv6RD {
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(BgpIPv6RD, usize), BgpError> {
        if buf.len() >= 24 {
            let rdp = BgpRD::decode_from(mode, &buf[0..8])?;
            Ok((
                BgpIPv6RD {
                    rd: rdp.0,
                    addr: match decode_addr_from(&buf[(rdp.1)..(rdp.1 + 16)])? {
                        std::net::IpAddr::V6(n) => n,
                        _ => return Err(BgpError::static_str("Invalid address kind")),
                    },
                },
                rdp.1 + 16,
            ))
        } else {
            Err(BgpError::static_str("Invalid BgpIPv6RD buffer len"))
        }
    }
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let pos = self.rd.encode_to(mode, buf)?;
        let p2 = encode_addrv6_to(&self.addr, &mut buf[pos..])?;
        Ok(pos + p2)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_parse() {
        assert_eq!(
            "2a02::/32".parse::<BgpAddrV6>(),
            Ok(BgpAddrV6::new(
                Ipv6Addr::new(0x2a02, 0, 0, 0, 0, 0, 0, 0),
                32
            ))
        );
        assert_eq!(
            "2a02::1".parse::<BgpAddrV6>(),
            Ok(BgpAddrV6::new(
                Ipv6Addr::new(0x2a02, 0, 0, 0, 0, 0, 0, 1),
                128
            ))
        );
    }

    #[test]
    fn test_ipv6_in_subnet() {
        assert!(
            BgpAddrV6::new(Ipv6Addr::new(0x2a02, 0, 0, 0, 0, 0, 0, 0), 32)
                .in_subnet(&Ipv6Addr::new(0x2a02, 0, 0, 0, 0, 0, 0, 1))
        );
        assert!(
            !BgpAddrV6::new(Ipv6Addr::new(0x2a02, 0, 0, 0, 0, 0, 0, 0), 32)
                .in_subnet(&Ipv6Addr::new(0x2a01, 0, 0, 0, 0, 0, 0, 1))
        );
        assert!(
            BgpAddrV6::new(Ipv6Addr::new(0x2a02, 0, 0, 0, 0, 0, 0, 0), 32).contains(
                &BgpAddrV6::new(Ipv6Addr::new(0x2a02, 0, 0, 0, 0, 0, 0, 0), 33)
            )
        );
    }
    #[test]
    fn test_ipv6_ranges() {
        assert_eq!(
            BgpAddrV6::new(Ipv6Addr::new(0x2a02, 0, 0, 0, 0, 0, 0, 0), 120).range_first(),
            Ipv6Addr::new(0x2a02, 0, 0, 0, 0, 0, 0, 0)
        );
        assert_eq!(
            BgpAddrV6::new(Ipv6Addr::new(0x2a02, 0, 0, 0, 0, 0, 0, 0), 120).range_last(),
            Ipv6Addr::new(0x2a02, 0, 0, 0, 0, 0, 0, 0xff)
        );
    }
}

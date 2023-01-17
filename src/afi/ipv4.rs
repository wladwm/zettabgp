// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module describes NLRI data structures for ipv4

use crate::afi::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};
use std::default::Default;
use std::net::Ipv4Addr;

/// ipv4 prefix unicast/multicast NLRI
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpAddrV4 {
    /// network prefix
    pub addr: Ipv4Addr,
    /// prefix length 0..32
    pub prefixlen: u8,
}
impl Default for BgpAddrV4 {
    fn default() -> Self {
        BgpAddrV4 {
            addr: Ipv4Addr::new(127, 0, 0, 1),
            prefixlen: 32,
        }
    }
}
impl BgpAddrV4 {
    /// Constructs new ipv4 prefix
    /// ```
    /// use zettabgp::prelude::BgpAddrV4;
    /// use std::net::Ipv4Addr;
    ///
    /// let pfx = BgpAddrV4::new(Ipv4Addr::new(192,168,0,0),16);
    /// ```
    pub fn new(address: Ipv4Addr, prefix_len: u8) -> BgpAddrV4 {
        BgpAddrV4 {
            addr: address,
            prefixlen: prefix_len,
        }
    }
    fn norm_subnet_u32(&self) -> u32 {
        getn_u32(&self.addr.octets()) & (((1 << (32 - self.prefixlen)) - 1) ^ 0xffffffff)
    }
    /// Check if IP in subnet
    /// ```
    /// use zettabgp::prelude::BgpAddrV4;
    /// use std::net::Ipv4Addr;
    ///
    /// assert!(BgpAddrV4::new(Ipv4Addr::new(192,168,0,0),16).in_subnet(&Ipv4Addr::new(192,168,0,1)))
    /// ```
    pub fn in_subnet(&self, a: &Ipv4Addr) -> bool {
        if self.prefixlen == 0 {
            true
        } else if self.prefixlen > 31 {
            getn_u32(&self.addr.octets()) == getn_u32(&a.octets())
        } else {
            let lv = self.norm_subnet_u32();
            let lh = lv + ((1 << (32 - self.prefixlen)) - 1);
            let va = getn_u32(&a.octets());
            (va >= lv) && (va <= lh)
        }
    }
    /// Returns first IP address (network address) from subnet
    /// ```
    /// use std::net::Ipv4Addr;
    /// use zettabgp::prelude::BgpAddrV4;
    ///
    /// assert_eq!(BgpAddrV4::new(Ipv4Addr::new(192,168,120,130),16).range_first() , Ipv4Addr::new(192,168,0,0) );
    /// ```
    pub fn range_first(&self) -> Ipv4Addr {
        let lv = self.norm_subnet_u32();
        Ipv4Addr::new(
            (lv >> 24) as u8,
            (lv >> 16) as u8,
            (lv >> 8) as u8,
            (lv & 0xff) as u8,
        )
    }
    /// Returns last inclusive IP address for subnet
    /// ```
    /// use std::net::Ipv4Addr;
    /// use zettabgp::prelude::BgpAddrV4;
    ///
    /// assert_eq!(BgpAddrV4::new(Ipv4Addr::new(192,168,120,130),16).range_last() , Ipv4Addr::new(192,168,255,255) );
    /// ```
    pub fn range_last(&self) -> std::net::Ipv4Addr {
        if self.prefixlen < 1 {
            std::net::Ipv4Addr::new(255, 255, 255, 255)
        } else if self.prefixlen > 31 {
            self.range_first()
        } else {
            let lv = self.norm_subnet_u32() + ((1 << (32 - self.prefixlen)) - 1);
            std::net::Ipv4Addr::new(
                (lv >> 24) as u8,
                (lv >> 16) as u8,
                (lv >> 8) as u8,
                (lv & 0xff) as u8,
            )
        }
    }
    /// Check if given subnet is in this subnet
    /// ```
    /// use std::net::Ipv4Addr;
    /// use zettabgp::prelude::BgpAddrV4;
    ///
    /// assert!(BgpAddrV4::new(Ipv4Addr::new(192,168,0,0),16).contains(&BgpAddrV4::new(Ipv4Addr::new(192,168,0,0),24)));
    /// ```
    pub fn contains(&self, a: &BgpAddrV4) -> bool {
        if self.prefixlen < 1 {
            true
        } else if self.prefixlen > a.prefixlen {
            false
        } else if self.prefixlen == a.prefixlen {
            self.addr == a.addr
        } else {
            self.in_subnet(&a.range_first()) && self.in_subnet(&a.range_last())
        }
    }
    /// Check if given address is multicast
    pub fn is_multicast(&self) -> bool {
        (self.addr.octets() != [255, 255, 255, 255]) && self.addr.octets()[0] >= 224
    }
    pub fn from_bits(bits: u8, buf: &[u8]) -> Result<(BgpAddrV4, usize), BgpError> {
        if bits > 32 {
            return Err(BgpError::from_string(format!(
                "Invalid ipv4 FEC length: {:?}",
                bits
            )));
        }
        let mut bf = [0_u8; 4];
        if bits == 0 {
            return Ok((
                BgpAddrV4 {
                    addr: decode_addrv4_from(&bf)?,
                    prefixlen: 0,
                },
                0,
            ));
        }
        let bytes = ((bits + 7) / 8) as usize;
        bf[0..bytes].clone_from_slice(&buf[0..bytes]);
        Ok((
            BgpAddrV4 {
                addr: decode_addrv4_from(&bf)?,
                prefixlen: bits,
            },
            bytes,
        ))
    }
    pub fn to_bits(&self, buf: &mut [u8]) -> Result<(u8, usize), BgpError> {
        if self.prefixlen == 0 {
            return Ok((0, 0));
        }
        let mut bf = [0_u8; 4];
        bf.clone_from_slice(&self.addr.octets());
        let bytes = ((self.prefixlen + 7) / 8) as usize;
        buf[0..bytes].clone_from_slice(&bf[0..bytes]);
        Ok((self.prefixlen, bytes))
    }
}
impl std::str::FromStr for BgpAddrV4 {
    type Err = std::net::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() < 2 {
            Ok(BgpAddrV4 {
                addr: parts[0].parse::<std::net::Ipv4Addr>()?,
                prefixlen: 32,
            })
        } else {
            Ok(BgpAddrV4 {
                addr: parts[0].parse::<std::net::Ipv4Addr>()?,
                prefixlen: parts[1].parse::<u8>().unwrap_or(32),
            })
        }
    }
}
impl BgpItem<BgpAddrV4> for BgpAddrV4 {
    fn extract_bits_from(bits: u8, buf: &[u8]) -> Result<(BgpAddrV4, usize), BgpError> {
        BgpAddrV4::from_bits(bits, buf)
    }
    fn set_bits_to(&self, buf: &mut [u8]) -> Result<(u8, usize), BgpError> {
        self.to_bits(buf)
    }
    fn prefixlen(&self) -> usize {
        self.prefixlen as usize
    }
}
impl std::fmt::Display for BgpAddrV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefixlen)
    }
}
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpIPv4RD {
    pub rd: BgpRD,
    pub addr: std::net::Ipv4Addr,
}
impl BgpIPv4RD {
    pub fn new(crd: BgpRD, adr: std::net::Ipv4Addr) -> BgpIPv4RD {
        BgpIPv4RD { rd: crd, addr: adr }
    }
}
impl std::fmt::Display for BgpIPv4RD {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.rd.is_zero() {
            self.addr.fmt(f)
        } else {
            write!(f, "<{}>{}", self.rd, self.addr)
        }
    }
}
impl BgpAddrItem<BgpIPv4RD> for BgpIPv4RD {
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(BgpIPv4RD, usize), BgpError> {
        if buf.len() >= 12 {
            let p = BgpRD::decode_from(mode, &buf[0..8])?;
            Ok((
                BgpIPv4RD {
                    rd: p.0,
                    addr: match decode_addr_from(&buf[(p.1)..(p.1 + 4)])? {
                        std::net::IpAddr::V4(n) => n,
                        _ => return Err(BgpError::static_str("Invalid address kind")),
                    },
                },
                p.1 + 4,
            ))
        } else {
            Err(BgpError::static_str("Invalid BgpIPv4RD buffer len"))
        }
    }
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let pos = self.rd.encode_to(mode, buf)?;
        let p2 = encode_addrv4_to(&self.addr, &mut buf[pos..])?;
        Ok(pos + p2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_parse() {
        assert_eq!(
            "10.0.0.0".parse::<BgpAddrV4>(),
            Ok(BgpAddrV4::new(Ipv4Addr::new(10, 0, 0, 0), 32))
        );
        assert_eq!(
            "10.0.0.0/8".parse::<BgpAddrV4>(),
            Ok(BgpAddrV4::new(Ipv4Addr::new(10, 0, 0, 0), 8))
        );
    }

    #[test]
    fn test_ipv4_in_subnet() {
        assert!(BgpAddrV4::new(Ipv4Addr::new(192, 168, 0, 0), 16)
            .in_subnet(&Ipv4Addr::new(192, 168, 0, 1)));
        assert!(BgpAddrV4::new(Ipv4Addr::new(192, 168, 0, 0), 16)
            .contains(&BgpAddrV4::new(Ipv4Addr::new(192, 168, 0, 0), 24)));
    }
    #[test]
    fn test_ipv4_ranges() {
        assert_eq!(
            BgpAddrV4::new(Ipv4Addr::new(192, 168, 120, 130), 16).range_first(),
            Ipv4Addr::new(192, 168, 0, 0)
        );
        assert_eq!(
            BgpAddrV4::new(Ipv4Addr::new(192, 168, 120, 130), 16).range_last(),
            Ipv4Addr::new(192, 168, 255, 255)
        );
    }
}

// Copyright 2021-2022 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module describes NLRI data structures for mdt (multicast distribution tree) safi for ipv4 and ipv6

use crate::afi::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};
use std::default::Default;
use std::net::{Ipv4Addr, Ipv6Addr};

/// ipv4 mdt NLRI
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpMdtV4 {
    /// network prefix
    pub addr: BgpAddrV4,
    /// mdt group
    pub group: Ipv4Addr,
}
impl Default for BgpMdtV4 {
    fn default() -> Self {
        BgpMdtV4 {
            addr: BgpAddrV4::default(),
            group: Ipv4Addr::new(224, 0, 0, 0),
        }
    }
}
impl BgpMdtV4 {
    /// Constructs new mdtv4 prefix
    /// ```
    /// use zettabgp::prelude::{BgpAddrV4,BgpMdtV4};
    /// use std::net::Ipv4Addr;
    ///
    /// let pfx = BgpMdtV4::new(BgpAddrV4::new(Ipv4Addr::new(192,168,0,0),16),Ipv4Addr::new(224,0,0,0));
    /// ```
    pub fn new(addr: BgpAddrV4, group: Ipv4Addr) -> BgpMdtV4 {
        BgpMdtV4 { addr, group }
    }
}
impl std::str::FromStr for BgpMdtV4 {
    type Err = BgpError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr_grp: Vec<&str> = s.split('@').collect();
        if addr_grp.len() != 2 {
            return Err(BgpError::static_str("Invalid MDT"));
        };
        Ok(BgpMdtV4 {
            addr: addr_grp[0].parse()?,
            group: addr_grp[1].parse()?,
        })
    }
}
impl BgpItem<BgpMdtV4> for BgpMdtV4 {
    fn extract_bits_from(bits: u8, buf: &[u8]) -> Result<(BgpMdtV4, usize), BgpError> {
        if !(32..=128).contains(&bits) {
            return Err(BgpError::from_string(format!(
                "Invalid BgpMdtV4 FEC length: {:?}",
                bits
            )));
        }
        let mut bf = [0_u8; 4];
        if bits == 32 {
            return Ok((
                BgpMdtV4 {
                    addr: BgpAddrV4 {
                        addr: decode_addrv4_from(&bf)?,
                        prefixlen: 0,
                    },
                    group: decode_addrv4_from(buf)?,
                },
                4,
            ));
        }
        let bytes = (((bits - 32) + 7) / 8) as usize;
        bf[0..bytes].clone_from_slice(&buf[0..bytes]);
        Ok((
            BgpMdtV4 {
                addr: BgpAddrV4 {
                    addr: decode_addrv4_from(&bf)?,
                    prefixlen: bits - 32,
                },
                group: decode_addrv4_from(&buf[bytes..])?,
            },
            bytes + 4,
        ))
    }
    fn set_bits_to(&self, buf: &mut [u8]) -> Result<(u8, usize), BgpError> {
        let bytes = if self.addr.prefixlen > 0 {
            let mut bf = [0_u8; 4];
            bf.clone_from_slice(&self.addr.addr.octets());
            let bytes = ((self.addr.prefixlen + 7) / 8) as usize;
            buf[0..bytes].clone_from_slice(&bf[0..bytes]);
            bytes
        } else {
            0
        };
        buf[bytes..(bytes + 4)].clone_from_slice(&self.group.octets());
        Ok((self.addr.prefixlen + 32, bytes + 4))
    }
    fn prefixlen(&self) -> usize {
        self.addr.prefixlen as usize
    }
}
impl std::fmt::Display for BgpMdtV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}@{}", self.addr, self.group)
    }
}

/// ipv6 mdt NLRI
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpMdtV6 {
    /// network prefix
    pub addr: BgpAddrV6,
    /// mdt group
    pub group: Ipv6Addr,
}
impl Default for BgpMdtV6 {
    fn default() -> Self {
        BgpMdtV6 {
            addr: Default::default(),
            group: Ipv6Addr::new(0xfe00, 0, 0, 0, 0, 0, 0, 0),
        }
    }
}
impl BgpMdtV6 {
    /// Constructs new mdtv6 prefix
    /// ```
    /// use zettabgp::prelude::{BgpAddrV6,BgpMdtV6};
    /// use std::net::Ipv6Addr;
    ///
    /// let pfx = BgpMdtV6::new(BgpAddrV6::new(Ipv6Addr::new(0,0,0,0,0,0,0,1),128),Ipv6Addr::new(0xfe00,0,0,0,0,0,0,0));
    /// ```
    pub fn new(addr: BgpAddrV6, group: Ipv6Addr) -> BgpMdtV6 {
        BgpMdtV6 { addr, group }
    }
}
impl std::str::FromStr for BgpMdtV6 {
    type Err = BgpError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr_grp: Vec<&str> = s.split('@').collect();
        if addr_grp.len() != 2 {
            return Err(BgpError::static_str("Invalid MDT"));
        };
        Ok(BgpMdtV6 {
            addr: addr_grp[0].parse()?,
            group: addr_grp[1].parse()?,
        })
    }
}
impl BgpItem<BgpMdtV6> for BgpMdtV6 {
    fn extract_bits_from(bits: u8, buf: &[u8]) -> Result<(BgpMdtV6, usize), BgpError> {
        if !(128..=254).contains(&bits) {
            return Err(BgpError::from_string(format!(
                "Invalid BgpMdtV6 FEC length: {:?}",
                bits
            )));
        }
        let mut bf = [0_u8; 16];
        if bits == 128 {
            return Ok((
                BgpMdtV6 {
                    addr: BgpAddrV6 {
                        addr: decode_addrv6_from(&bf)?,
                        prefixlen: 0,
                    },
                    group: decode_addrv6_from(buf)?,
                },
                16,
            ));
        }
        let bytes = (((bits - 128) + 7) / 8) as usize;
        bf[0..bytes].clone_from_slice(&buf[0..bytes]);
        Ok((
            BgpMdtV6 {
                addr: BgpAddrV6 {
                    addr: decode_addrv6_from(&bf)?,
                    prefixlen: bits - 128,
                },
                group: decode_addrv6_from(&buf[bytes..])?,
            },
            bytes + 16,
        ))
    }
    fn set_bits_to(&self, buf: &mut [u8]) -> Result<(u8, usize), BgpError> {
        let bytes = if self.addr.prefixlen > 0 {
            let mut bf = [0_u8; 16];
            bf.clone_from_slice(&self.addr.addr.octets());
            let bytes = ((self.addr.prefixlen + 7) / 8) as usize;
            buf[0..bytes].clone_from_slice(&bf[0..bytes]);
            bytes
        } else {
            0
        };
        buf[bytes..(bytes + 16)].clone_from_slice(&self.group.octets());
        Ok((self.addr.prefixlen + 128, bytes + 16))
    }
    fn prefixlen(&self) -> usize {
        self.addr.prefixlen as usize
    }
}
impl std::fmt::Display for BgpMdtV6 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}@{}", self.addr, self.group)
    }
}

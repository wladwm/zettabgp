// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module describes NLRI data structures for mac address

use crate::afi::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

/// Six-byte ethernet mac address. Used in EVPN.
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct MacAddress {
    pub mac_address: [u8; 6],
}
impl MacAddress {
    /// Construct new zero mac address.
    pub fn new() -> MacAddress {
        MacAddress {
            mac_address: [0_u8; 6],
        }
    }
    /// Construct new mac address from 6 bytes in network order.
    pub fn from_network_bytes(b: &[u8]) -> MacAddress {
        MacAddress {
            mac_address: [b[5], b[4], b[3], b[2], b[1], b[0]],
        }
    }
    /// Write the mac address to the buffer in network order.
    pub fn write_to_network_bytes(&self, b: &mut [u8]) {
        let [b0, b1, b2, b3, b4, b5] = self.mac_address;
        b.copy_from_slice(&[b5, b4, b3, b2, b1, b0]);
    }
    /// Construct new mac address from u64.
    pub fn from_u64(s: u64) -> MacAddress {
        let mut a = [0_u8; 6];
        a[0] = (s & 0xff) as u8;
        a[1] = ((s >> 8) & 0xff) as u8;
        a[2] = ((s >> 16) & 0xff) as u8;
        a[3] = ((s >> 24) & 0xff) as u8;
        a[4] = ((s >> 32) & 0xff) as u8;
        a[5] = ((s >> 40) & 0xff) as u8;
        MacAddress { mac_address: a }
    }
    /// Pack to u64.
    pub fn to_u64(&self) -> u64 {
        (self.mac_address[5] as u64) << 40
            | (self.mac_address[4] as u64) << 32
            | (self.mac_address[3] as u64) << 24
            | (self.mac_address[2] as u64) << 16
            | (self.mac_address[1] as u64) << 8
            | (self.mac_address[0] as u64)
    }
}
impl Default for MacAddress {
    fn default() -> Self {
        Self::new()
    }
}
impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac_address[5],
            self.mac_address[4],
            self.mac_address[3],
            self.mac_address[2],
            self.mac_address[1],
            self.mac_address[0],
        )
    }
}
impl std::fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac_address[5],
            self.mac_address[4],
            self.mac_address[3],
            self.mac_address[2],
            self.mac_address[1],
            self.mac_address[0]
        ))
    }
}
impl std::str::FromStr for MacAddress {
    type Err = BgpError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut mac: u64 = 0;
        let mut cnt: usize = 0;
        for c in s.chars() {
            if let Some(d) = c.to_digit(16) {
                mac = (mac << 4) | (d as u64);
                cnt += 1;
            }
        }
        if cnt < 1 {
            return Err(BgpError::static_str("Invalid mac address"));
        }
        Ok(MacAddress::from_u64(mac))
    }
}
/// ipv4 prefix unicast/multicast NLRI
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BgpAddrMac {
    /// mac prefix
    pub addr: MacAddress,
    /// prefix length 0..48
    pub prefixlen: u8,
}
impl BgpAddrMac {
    /// Constructs new MAC prefix
    /// ```
    /// use zettabgp::afi::mac::MacAddress;
    /// use zettabgp::prelude::BgpAddrMac;
    ///
    /// let pfx = BgpAddrMac::new(MacAddress::from_u64(0x121314151600),40);
    /// ```
    pub fn new(address: MacAddress, prefix_len: u8) -> BgpAddrMac {
        BgpAddrMac {
            addr: address,
            prefixlen: prefix_len,
        }
    }
    fn norm_subnet_u48(&self) -> u64 {
        self.addr.to_u64() & (((1 << (48 - self.prefixlen)) - 1) ^ 0xffffffffffff)
    }
    /// Check if mac in subnet
    /// ```
    /// use zettabgp::afi::mac::MacAddress;
    /// use zettabgp::prelude::BgpAddrMac;
    ///
    /// assert!(BgpAddrMac::new(MacAddress::from_u64(0x121314151600),40).in_subnet(&MacAddress::from_u64(0x121314151601)))
    /// ```
    pub fn in_subnet(&self, a: &MacAddress) -> bool {
        if self.prefixlen == 0 {
            true
        } else if self.prefixlen > 47 {
            self.addr.to_u64() == a.to_u64()
        } else {
            let lv = self.norm_subnet_u48();
            let lh = lv + ((1 << (48 - self.prefixlen)) - 1);
            let va = a.to_u64();
            (va >= lv) && (va <= lh)
        }
    }
    /// Returns first mac address (network address) from subnet
    /// ```
    /// use zettabgp::afi::mac::MacAddress;
    /// use zettabgp::prelude::BgpAddrMac;
    ///
    /// assert_eq!(BgpAddrMac::new(MacAddress::from_u64(0x1213141516ab),40).range_first() , MacAddress::from_u64(0x121314151600) );
    /// ```
    pub fn range_first(&self) -> MacAddress {
        MacAddress::from_u64(self.norm_subnet_u48())
    }
    /// Returns last inclusive mac address for subnet
    /// ```
    /// use zettabgp::afi::mac::MacAddress;
    /// use zettabgp::prelude::BgpAddrMac;
    ///
    /// assert_eq!(BgpAddrMac::new(MacAddress::from_u64(0x1213141516ab),40).range_last() , MacAddress::from_u64(0x1213141516ff));
    /// ```
    pub fn range_last(&self) -> MacAddress {
        if self.prefixlen < 1 {
            MacAddress::from_u64(0xffffffffffff)
        } else if self.prefixlen > 47 {
            self.range_first()
        } else {
            let lv = self.norm_subnet_u48() + ((1 << (48 - self.prefixlen)) - 1);
            MacAddress::from_u64(lv)
        }
    }
    /// Check if given subnet is in this subnet
    /// ```
    /// use zettabgp::afi::mac::MacAddress;
    /// use zettabgp::prelude::BgpAddrMac;
    ///
    /// assert!(BgpAddrMac::new(MacAddress::from_u64(0x121314150000),32).contains(&BgpAddrMac::new(MacAddress::from_u64(0x121314151600),40)));
    /// ```
    pub fn contains(&self, a: &BgpAddrMac) -> bool {
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
}
impl std::str::FromStr for BgpAddrMac {
    type Err = BgpError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() < 2 {
            Ok(BgpAddrMac {
                addr: parts[0].parse::<MacAddress>()?,
                prefixlen: 48,
            })
        } else {
            Ok(BgpAddrMac {
                addr: parts[0].parse::<MacAddress>()?,
                prefixlen: parts[1].parse::<u8>().unwrap_or(48),
            })
        }
    }
}
impl std::fmt::Display for BgpAddrMac {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefixlen)
    }
}

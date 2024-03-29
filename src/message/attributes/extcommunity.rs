// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP "extended community list" path attribute

use crate::message::attributes::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

/// BGP extended community - element for BgpExtCommunityList path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpExtCommunity {
    pub ctype: u8,
    pub subtype: u8,
    pub a: u16,
    pub b: u32,
}
impl BgpExtCommunity {
    /// creates route-target with AS + number
    pub fn rt_asn(asn: u16, val: u32) -> BgpExtCommunity {
        BgpExtCommunity {
            ctype: 0,
            subtype: 2,
            a: asn,
            b: val,
        }
    }
    /// creates route-target with IP + number
    pub fn rt_ipn(ipa: std::net::Ipv4Addr, val: u16) -> BgpExtCommunity {
        let octs = ipa.octets();
        BgpExtCommunity {
            ctype: 1,
            subtype: 2,
            a: (octs[0] as u16) << 8 | (octs[1] as u16),
            b: (octs[2] as u32) << 24 | (octs[3] as u32) << 16 | (val as u32),
        }
    }
    pub fn decode_from(buf: &[u8]) -> Result<BgpExtCommunity, BgpError> {
        match buf.len() {
            8 => Ok(BgpExtCommunity {
                ctype: buf[0],
                subtype: buf[1],
                a: getn_u16(&buf[2..4]),
                b: getn_u32(&buf[4..8]),
            }),
            _ => Err(BgpError::static_str("Invalid BgpExtCommunity item length")),
        }
    }
    pub fn encode_to(&self, buf: &mut [u8]) -> Result<usize, BgpError> {
        if buf.len() < 8 {
            return Err(BgpError::insufficient_buffer_size());
        }
        buf[0] = self.ctype;
        buf[1] = self.subtype;
        setn_u16(self.a, &mut buf[2..4]);
        setn_u32(self.b, &mut buf[4..8]);
        Ok(8)
    }
    /// extracts encoded ipv4
    pub fn get_ipv4(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::new(
            ((self.a >> 8) & 0xff) as u8,
            (self.a & 0xff) as u8,
            ((self.b >> 24) & 0xff) as u8,
            ((self.b >> 16) & 0xff) as u8,
        )
    }
    /// extracts encoded number
    pub fn get_num(&self) -> u16 {
        (self.b & 0xffff) as u16
    }
}
impl std::fmt::Debug for BgpExtCommunity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpExtCommunity")
            .field("ctype", &self.ctype)
            .field("subtype", &self.subtype)
            .field("a", &self.a)
            .field("b", &self.b)
            .finish()
    }
}
impl std::fmt::Display for BgpExtCommunity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.subtype == 2 && self.ctype == 0 {
            //rt AS-based
            write!(f, "ext-target:{}:{}", self.a, self.b)
        } else if self.subtype == 2 && self.ctype == 1 {
            //rt ip-based
            write!(f, "ext-target:{}:{}", self.get_ipv4(), self.get_num())
        } else if self.subtype == 2 && self.ctype == 2 {
            //rt ?
            write!(f, "ext-target:{}:{}:{}", self.ctype, self.a, self.b)
        } else if self.subtype == 3 && self.ctype == 1 {
            write!(f, "ext-origin:{}:{}", self.get_ipv4(), self.get_num())
        } else if self.subtype == 3 && self.ctype < 3 {
            write!(f, "ext-origin:{}:{}:{}", self.ctype, self.a, self.b)
        } else if self.subtype == 9 {
            write!(f, "ext-src-as:{}:{}:{}", self.ctype, self.a, self.b)
        } else if self.subtype == 11 && self.ctype == 1 {
            write!(f, "ext-rt-import:{}:{}", self.get_ipv4(), self.get_num())
        } else if self.subtype == 11 && self.ctype < 3 {
            write!(f, "ext-rt-import:{}:{}:{}", self.ctype, self.a, self.b)
        } else if self.ctype == 0 || self.ctype == 0x40 {
            //as-specific
            write!(
                f,
                "ext-as-specific:0x{:x}:0x{:x}:0x{:x}:0x{:x}",
                self.ctype, self.subtype, self.a, self.b
            )
        } else if self.subtype == 10 && (self.ctype == 1 || self.ctype == 0x41) {
            write!(f, "ext-import-rt:{}:{}", self.get_ipv4(), self.get_num())
        } else if self.ctype == 1 || self.ctype == 0x41 {
            //ipv4-specific
            write!(
                f,
                "ext-ipv4a-specific:0x{:x}:0x{:x}:0x{:x}:0x{:x}",
                self.ctype, self.subtype, self.a, self.b
            )
        } else if self.ctype == 3 && self.subtype == 12 {
            write!(f, "encapsulation:0x{:x}", self.b)
        } else if self.ctype == 6 && self.subtype == 0x4 {
            //evpn-l2-attr
            write!(f, "evpn-l2-info:cf={}:mtu={}", self.a, self.b >> 16)
        } else if self.ctype == 6 && self.subtype == 1 {
            //esi-label
            write!(
                f,
                "esi-label:{}:label={}:{}",
                self.a,
                self.b >> 8,
                self.b & 0xff
            )
        } else if self.ctype == 3 || self.ctype == 0x43 {
            //opaque
            write!(
                f,
                "ext-opaque:0x{:02x}:0x{:02x}:0x{:x}:0x{:x}",
                self.ctype, self.subtype, self.a, self.b
            )
        } else {
            write!(
                f,
                "ext-unknown:0x{:02x}:0x{:02x}:0x{:x}:0x{:x}",
                self.ctype, self.subtype, self.a, self.b
            )
        }
    }
}
impl std::convert::From<u64> for BgpExtCommunity {
    fn from(value: u64) -> Self {
        let buf = value.to_be_bytes();
        Self {
            ctype: buf[0],
            subtype: buf[1],
            a: getn_u16(&buf[2..4]),
            b: getn_u32(&buf[4..8]),
        }
    }
}

/// BGP extended community list path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpExtCommunityList {
    pub value: std::collections::BTreeSet<BgpExtCommunity>,
}
impl BgpExtCommunityList {
    pub fn new() -> BgpExtCommunityList {
        BgpExtCommunityList {
            value: std::collections::BTreeSet::new(),
        }
    }
    pub fn from_vec(v: Vec<BgpExtCommunity>) -> BgpExtCommunityList {
        let mut vs = std::collections::BTreeSet::new();
        for i in v {
            vs.insert(i);
        }
        BgpExtCommunityList { value: vs }
    }
    pub fn decode_from(buf: &[u8]) -> Result<BgpExtCommunityList, BgpError> {
        let mut v = std::collections::BTreeSet::new();
        let mut pos: usize = 0;
        while (pos + 7) < buf.len() {
            v.insert(BgpExtCommunity::decode_from(&buf[pos..(pos + 8)])?);
            pos += 8;
        }
        Ok(BgpExtCommunityList { value: v })
    }
}
impl Default for BgpExtCommunityList {
    fn default() -> Self {
        Self::new()
    }
}
impl std::fmt::Debug for BgpExtCommunityList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpExtCommunityList")
            .field("value", &self.value)
            .finish()
    }
}
impl std::fmt::Display for BgpExtCommunityList {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BgpExtCommunityList {:?}", self.value)
    }
}
impl BgpAttr for BgpExtCommunityList {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 16,
            flags: 192,
        }
    }
    fn encode_to(&self, _peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut pos: usize = 0;
        for c in &self.value {
            let ln = c.encode_to(&mut buf[pos..])?;
            pos += ln;
        }
        Ok(pos)
    }
}

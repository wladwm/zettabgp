// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP "extended community list" path attribute

use std::net::Ipv4Addr;

use crate::message::attributes::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

/// BGP extended community - element for BgpExtCommunityList path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialization", derive(Serialize))]
pub struct BgpExtCommunity {
    pub ctype: u8,
    pub subtype: u8,
    pub a: u16,
    pub b: u32,
}
impl BgpExtCommunity {
    /// creates extcommunity
    pub fn new(ctype: u8, subtype: u8, a: u16, b: u32) -> BgpExtCommunity {
        BgpExtCommunity {
            ctype,
            subtype,
            a,
            b,
        }
    }
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
    /// RFC8955 flowspec traffic-rate-bytes
    pub fn fs_rate_bytes(rate: f32, as_num: u16) -> BgpExtCommunity {
        BgpExtCommunity {
            ctype: 128,
            subtype: 6,
            a: as_num,
            b: rate.to_bits(),
        }
    }
    /// RFC8955 flowspec traffic-action
    pub fn fs_action(sample: bool, terminal_action: bool) -> BgpExtCommunity {
        BgpExtCommunity {
            ctype: 128,
            subtype: 7,
            a: 0,
            b: if terminal_action { 0x8000 } else { 0 } | if sample { 0x4000 } else { 0 },
        }
    }
    /// RFC8955 flowspec traffic-rate-packets
    pub fn fs_rate_packets(rate: f32, as_num: u16) -> BgpExtCommunity {
        BgpExtCommunity {
            ctype: 128,
            subtype: 12,
            a: as_num,
            b: rate.to_bits(),
        }
    }
    /// RFC8955 flowspec redirect to route-target ASN:NNN
    pub fn fs_redirect_rt_asn(asn: u16, val: u32) -> BgpExtCommunity {
        BgpExtCommunity {
            ctype: 128,
            subtype: 8,
            a: asn,
            b: val,
        }
    }
    /// RFC8955 flowspec redirect to route-target with IP + number
    pub fn fs_redirect_rt_ipn(ipa: std::net::Ipv4Addr, val: u16) -> BgpExtCommunity {
        let octs = ipa.octets();
        BgpExtCommunity {
            ctype: 128,
            subtype: 8,
            a: (octs[0] as u16) << 8 | (octs[1] as u16),
            b: (octs[2] as u32) << 24 | (octs[3] as u32) << 16 | (val as u32),
        }
    }
    /// RFC8955 flowspec remark dscp
    pub fn fs_redirect_remark_dscp(dscp: u8) -> BgpExtCommunity {
        BgpExtCommunity {
            ctype: 128,
            subtype: 9,
            a: 0,
            b: (dscp as u32) << 24,
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
            return Err(BgpError::InsufficientBufferSize(file!(), line!()));
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
        } else if self.subtype == 128 && self.ctype == 6 {
            write!(
                f,
                "fs-traffic-rate-bytes:{}:AS{}",
                f32::from_bits(self.b),
                self.a
            )
        } else if self.subtype == 128 && self.ctype == 7 {
            write!(f, "fs-traffic-action:{}:{}", self.a, self.b)
        } else if self.subtype == 128 && self.ctype == 8 {
            write!(f, "fs-rt-redirect:{}:{}", self.a, self.b)
        } else if self.subtype == 128 && self.ctype == 9 {
            write!(f, "fs-remark:{}:{}", self.a, self.b)
        } else if self.subtype == 128 && self.ctype == 12 {
            write!(
                f,
                "fs-traffic-rate-packets:{}:AS{}",
                f32::from_bits(self.b),
                self.a
            )
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
impl std::str::FromStr for BgpExtCommunity {
    type Err = BgpError;
    fn from_str(ss: &str) -> Result<Self, Self::Err> {
        let s = ss.trim();
        if let Ok(n) = s.parse::<u64>() {
            return Ok(BgpExtCommunity::from(n));
        }
        let parts: Vec<_> = s.split(':').collect();
        if parts.len() < 2 {
            return Err(format!("Unable to parse BgpExtCommunity: '{}'", s).into());
        }
        match parts[0] {
            "ext-target" | "rt" | "route-target" => {
                if parts.len() == 4 {
                    //self.ctype, self.a, self.b
                    return Ok(BgpExtCommunity {
                        subtype: 2,
                        ctype: parts[1].parse()?,
                        a: parts[2].parse()?,
                        b: parts[3].parse()?,
                    });
                }
                if parts.len() == 3 {
                    //AS-based or IP-based
                    if let Ok(ipn) = parts[1].parse::<Ipv4Addr>() {
                        return Ok(BgpExtCommunity::rt_ipn(ipn, parts[2].parse()?));
                    }
                    return Ok(BgpExtCommunity::rt_asn(
                        parts[1].parse()?,
                        parts[2].parse()?,
                    ));
                }
            }
            "ext-origin" => {
                if parts.len() == 4 {
                    //self.ctype, self.a, self.b
                    return Ok(BgpExtCommunity {
                        subtype: 3,
                        ctype: parts[1].parse()?,
                        a: parts[2].parse()?,
                        b: parts[3].parse()?,
                    });
                }
                if parts.len() == 3 {
                    if let Ok(ipn) = parts[1].parse::<Ipv4Addr>() {
                        let mut ret = BgpExtCommunity::rt_ipn(ipn, parts[2].parse()?);
                        ret.subtype = 3;
                        return Ok(ret);
                    }
                    let mut ret = BgpExtCommunity::rt_asn(parts[1].parse()?, parts[2].parse()?);
                    ret.subtype = 3;
                    return Ok(ret);
                }
            }
            "fs-traffic-rate-bytes" => {
                if parts.len() == 3 && parts[2].starts_with("AS") {
                    if let (Ok(rate), Ok(as_num)) =
                        (parts[1].parse::<f32>(), parts[2][2..].parse::<u16>())
                    {
                        return Ok(BgpExtCommunity::fs_rate_bytes(rate, as_num));
                    }
                }
            }
            "fs-traffic-rate-packets" => {
                if parts.len() == 3 && parts[2].starts_with("AS") {
                    if let (Ok(rate), Ok(as_num)) =
                        (parts[1].parse::<f32>(), parts[2][2..].parse::<u16>())
                    {
                        return Ok(BgpExtCommunity::fs_rate_packets(rate, as_num));
                    }
                }
            }
            "fs-traffic-action" => {
                if parts.len() == 3 {
                    if let (Ok(a), Ok(b)) = (parts[1].parse(), parts[2].parse()) {
                        return Ok(BgpExtCommunity {
                            a,
                            b,
                            ctype: 7,
                            subtype: 128,
                        });
                    }
                }
            }
            "fs-rt-redirect" => {
                if parts.len() == 3 {
                    if let (Ok(a), Ok(b)) = (parts[1].parse(), parts[2].parse()) {
                        return Ok(BgpExtCommunity {
                            a,
                            b,
                            ctype: 8,
                            subtype: 128,
                        });
                    }
                }
            }
            "fs-remark" => {
                if parts.len() == 3 {
                    if let (Ok(a), Ok(b)) = (parts[1].parse(), parts[2].parse()) {
                        return Ok(BgpExtCommunity {
                            a,
                            b,
                            ctype: 9,
                            subtype: 128,
                        });
                    }
                }
            }
            "ext-src-as" => {
                if parts.len() == 4 {
                    return Ok(BgpExtCommunity {
                        subtype: 9,
                        ctype: parts[1].parse()?,
                        a: parts[2].parse()?,
                        b: parts[3].parse()?,
                    });
                }
            }
            "ext-rt-import" => {
                if parts.len() == 4 {
                    return Ok(BgpExtCommunity {
                        subtype: 11,
                        ctype: parts[1].parse()?,
                        a: parts[2].parse()?,
                        b: parts[3].parse()?,
                    });
                }
                if parts.len() == 3 {
                    if let Ok(ipn) = parts[1].parse::<Ipv4Addr>() {
                        let mut ret = BgpExtCommunity::rt_ipn(ipn, parts[2].parse()?);
                        ret.subtype = 11;
                        return Ok(ret);
                    }
                    let mut ret = BgpExtCommunity::rt_asn(parts[1].parse()?, parts[2].parse()?);
                    ret.subtype = 11;
                    return Ok(ret);
                }
            }
            "ext-opaque" | "ext-unknown" => {
                if parts.len() == 5 {
                    return Ok(BgpExtCommunity {
                        ctype: parts[1].parse()?,
                        subtype: parts[2].parse()?,
                        a: parts[3].parse()?,
                        b: parts[4].parse()?,
                    });
                }
            }
            _ => {}
        };
        Err(format!("Unable to parse BgpExtCommunity: '{}'", s).into())
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
#[cfg(feature = "serialization")]
pub(crate) struct BgpExtCommunityVisitor;
#[cfg(feature = "serialization")]
impl<'de> serde::de::Visitor<'de> for BgpExtCommunityVisitor {
    type Value = BgpExtCommunity;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("BgpExtCommunity")
    }
    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(s.parse::<BgpExtCommunity>()
            .map_err(|e| serde::de::Error::custom(e))?)
    }
    fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
    where
        V: serde::de::MapAccess<'de>,
    {
        #[derive(Clone, Debug, Serialize, Deserialize)]
        #[allow(non_camel_case_types)]
        enum Field {
            ctype,
            subtype,
            a,
            b,
        };
        const FIELDS: [&'static str; 4] = ["ctype", "subtype", "a", "b"];
        let mut ctype = None;
        let mut subtype = None;
        let mut a = None;
        let mut b = None;
        while let Some(key) = map.next_key::<Field>()? {
            match key {
                Field::ctype => {
                    if ctype.is_some() {
                        return Err(serde::de::Error::duplicate_field(FIELDS[0]));
                    }
                    ctype = Some(map.next_value()?);
                }
                Field::subtype => {
                    if subtype.is_some() {
                        return Err(serde::de::Error::duplicate_field(FIELDS[1]));
                    }
                    subtype = Some(map.next_value()?);
                }
                Field::a => {
                    if a.is_some() {
                        return Err(serde::de::Error::duplicate_field(FIELDS[2]));
                    }
                    a = Some(map.next_value()?);
                }
                Field::b => {
                    if b.is_some() {
                        return Err(serde::de::Error::duplicate_field(FIELDS[3]));
                    }
                    b = Some(map.next_value()?);
                }
            }
        }

        let ctype = ctype.ok_or_else(|| serde::de::Error::missing_field(FIELDS[0]))?;
        let subtype = subtype.ok_or_else(|| serde::de::Error::missing_field(FIELDS[1]))?;
        let a = a.ok_or_else(|| serde::de::Error::missing_field(FIELDS[2]))?;
        let b = b.ok_or_else(|| serde::de::Error::missing_field(FIELDS[3]))?;
        Ok(BgpExtCommunity {
            ctype,
            subtype,
            a,
            b,
        })
    }
}
#[cfg(feature = "serialization")]
impl<'de> serde::de::Deserialize<'de> for BgpExtCommunity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserializer.deserialize_any(BgpExtCommunityVisitor)
    }
}
/// BGP extended community list path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serialization", serde(transparent))]
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
impl std::convert::From<BgpExtCommunity> for BgpExtCommunityList {
    fn from(v: BgpExtCommunity) -> Self {
        let mut value = std::collections::BTreeSet::new();
        value.insert(v);
        BgpExtCommunityList { value }
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
        crate::util::fmt_vec(self.value.iter(), ',', f)
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

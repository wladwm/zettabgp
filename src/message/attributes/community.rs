// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP "community list" path attributes

use crate::message::attributes::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// no-export well-known community
pub const NO_EXPORT: BgpCommunity = BgpCommunity{ value:0xffffff01 };
/// no-advertise well-known community
pub const NO_ADVERTISE: BgpCommunity = BgpCommunity{ value:0xffffff02 };
/// no-export-subconfed well-known community
pub const NO_EXPORT_SUBCONFED: BgpCommunity = BgpCommunity{ value:0xffffff03 };
/// no-peer well-known community
pub const NOPEER: BgpCommunity = BgpCommunity{ value:0xffffff04 };

/// BGP community - element for BgpCommunityList path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpCommunity {
    pub value: u32,
}
/// BGP community list path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpCommunityList {
    pub value: std::collections::BTreeSet<BgpCommunity>,
}

/// BGP large community - element for BgpLargeCommunityList path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpLargeCommunity {
    pub ga: u32,
    pub ldp1: u32,
    pub ldp2: u32,
}
/// BGP <large> community list path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpLargeCommunityList {
    pub value: std::collections::BTreeSet<BgpLargeCommunity>,
}
impl BgpLargeCommunity {
    pub fn decode_from(buf: &[u8]) -> Result<BgpLargeCommunity, BgpError> {
        match buf.len() {
            12 => Ok(BgpLargeCommunity {
                ga: getn_u32(&buf[0..4]),
                ldp1: getn_u32(&buf[4..8]),
                ldp2: getn_u32(&buf[8..12]),
            }),
            _ => Err(BgpError::static_str(
                "Invalid BgpLargeCommunity item length",
            )),
        }
    }
    pub fn encode_to(&self, buf: &mut [u8]) -> Result<usize, BgpError> {
        if buf.len() < 12 {
            return Err(BgpError::insufficient_buffer_size());
        }
        setn_u32(self.ga, buf);
        setn_u32(self.ldp1, &mut buf[4..8]);
        setn_u32(self.ldp2, &mut buf[8..12]);
        Ok(12)
    }
}
impl std::fmt::Debug for BgpLargeCommunity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Community")
            .field("ga", &self.ga)
            .field("ldp1", &self.ldp1)
            .field("ldp2", &self.ldp2)
            .finish()
    }
}
impl std::fmt::Display for BgpLargeCommunity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.ga, self.ldp1, self.ldp2)
    }
}
impl BgpLargeCommunityList {
    pub fn new() -> BgpLargeCommunityList {
        BgpLargeCommunityList {
            value: std::collections::BTreeSet::new(),
        }
    }
    pub fn decode_from(buf: &[u8]) -> Result<BgpLargeCommunityList, BgpError> {
        let mut pos: usize = 0;
        let mut v = std::collections::BTreeSet::new();
        while pos < buf.len() {
            v.insert(BgpLargeCommunity::decode_from(&buf[pos..(pos + 12)])?);
            pos += 12;
        }
        Ok(BgpLargeCommunityList { value: v })
    }
}
impl std::fmt::Debug for BgpLargeCommunityList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpLargeCommunityList")
            .field("value", &self.value)
            .finish()
    }
}
impl std::fmt::Display for BgpLargeCommunityList {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BgpLargeCommunityList {:?}", self.value)
    }
}
impl BgpAttr for BgpLargeCommunityList {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 32,
            flags: 224,
        }
    }
    fn encode_to(&self, _peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut pos: usize = 0;
        for i in &self.value {
            pos += i.encode_to(&mut buf[pos..])?;
        }
        Ok(pos)
    }
}
impl Default for BgpLargeCommunityList {
    fn default() -> Self {
        Self::new()
    }
}
impl BgpCommunity {
    const NO_EXPORT_STR0:&str="no_export";
    const NO_EXPORT_STR1:&str="noexport";
    const NO_EXPORT_STR2:&str="no-export";
    const NO_ADVERTISE_STR0:&str="no_advertise";
    const NO_ADVERTISE_STR1:&str="no-advertise";
    const NO_EXPORT_SUBCONFED_STR:&str="no_export_subconfed";
    const NOPEER_STR0:&str="nopeer";
    const NOPEER_STR1:&str="no-peer";
    pub fn new(v: u32) -> BgpCommunity {
        BgpCommunity { value: v }
    }
    pub fn from(h: u16, l: u16) -> BgpCommunity {
        BgpCommunity {
            value: ((h as u32) << 16) | (l as u32),
        }
    }
    pub fn decode_from(buf: &[u8]) -> Result<BgpCommunity, BgpError> {
        match buf.len() {
            4 => Ok(BgpCommunity {
                value: getn_u32(buf),
            }),
            _ => Err(BgpError::static_str("Invalid BgpCommunity item length")),
        }
    }
    fn encode_to(&self, buf: &mut [u8]) -> Result<usize, BgpError> {
        if buf.len() < 4 {
            return Err(BgpError::insufficient_buffer_size());
        };
        setn_u32(self.value, buf);
        Ok(4)
    }
}
impl std::fmt::Debug for BgpCommunity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Community")
            .field("value", &self.value)
            .finish()
    }
}
impl std::fmt::Display for BgpCommunity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            &NO_EXPORT => f.write_str(Self::NO_EXPORT_STR0),
            &NO_ADVERTISE => f.write_str(Self::NO_ADVERTISE_STR0),
            &NO_EXPORT_SUBCONFED => f.write_str(Self::NO_EXPORT_SUBCONFED_STR),
            &NOPEER => f.write_str(Self::NOPEER_STR0),
            _ => write!(
                f,
                "{}:{}",
                (self.value >> 16) as u16,
                (self.value & 0xffff) as u16
                )
        }
    }
}
impl FromStr for BgpCommunity {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NO_EXPORT_STR0 | Self::NO_EXPORT_STR1 | Self::NO_EXPORT_STR2 => return Ok(NO_EXPORT.clone()),
            Self::NO_ADVERTISE_STR0 | Self::NO_ADVERTISE_STR1 => return Ok(NO_ADVERTISE.clone()),
            Self::NO_EXPORT_SUBCONFED_STR => return Ok(NO_EXPORT_SUBCONFED.clone()),
            Self::NOPEER_STR0 | Self::NOPEER_STR1 => return Ok(NOPEER.clone()),
            _ => {}
        };
        let parts: Vec<&str> = s.trim().split(':').collect();
        if parts.len() < 2 {
            Ok(BgpCommunity {
                value: parts[0].parse()?,
            })
        } else if parts.len() < 3 {
            Ok(BgpCommunity {
                value: (parts[0].parse::<u16>()? as u32) << 16 | (parts[1].parse::<u16>()? as u32),
            })
        } else {
            Ok(BgpCommunity { value: s.parse()? })
        }
    }
}

/// BGP community list path attribute
impl BgpCommunityList {
    pub fn new() -> BgpCommunityList {
        BgpCommunityList {
            value: std::collections::BTreeSet::new(),
        }
    }
    pub fn from_vec(v: Vec<BgpCommunity>) -> BgpCommunityList {
        BgpCommunityList {
            value: v.into_iter().collect(),
        }
    }
}
impl Default for BgpCommunityList {
    fn default() -> Self {
        Self::new()
    }
}
impl BgpCommunityList {
    pub fn decode_from(buf: &[u8]) -> Result<BgpCommunityList, BgpError> {
        let mut pos: usize = 0;
        let mut v = std::collections::BTreeSet::new();
        while pos < buf.len() {
            v.insert(BgpCommunity::decode_from(&buf[pos..(pos + 4)])?);
            pos += 4;
        }
        Ok(BgpCommunityList { value: v })
    }
}
impl std::fmt::Debug for BgpCommunityList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpCommunityList")
            .field("value", &self.value)
            .finish()
    }
}
impl std::fmt::Display for BgpCommunityList {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BgpCommunityList {:?}", self.value)
    }
}
impl FromStr for BgpCommunityList {
    type Err = BgpError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let strs: Vec<&str> = s.split(&[',', ' ', '\t'][..]).collect();
        let mut v = std::collections::BTreeSet::new();
        for s in strs.iter() {
            if let Ok(c) = s.parse() {
                v.insert(c);
            }
        }
        Ok(BgpCommunityList { value: v })
    }
}
impl BgpAttr for BgpCommunityList {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 8,
            flags: 192,
        }
    }
    fn encode_to(&self, _peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        if buf.len() < self.value.len() * 4 {
            return Err(BgpError::insufficient_buffer_size());
        }
        let mut curpos: usize = 0;
        for c in &self.value {
            let lng = c.encode_to(&mut buf[curpos..])?;
            curpos += lng;
        }
        Ok(curpos)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_community_parse() {
        assert_eq!(
            "no_export".parse::<BgpCommunity>(),
            Ok(NO_EXPORT.clone())
        );
        assert_eq!(
            "23:45".parse::<BgpCommunity>(),
            Ok(BgpCommunity{ value: 0x0017002d })
        );
    }
    #[test]
    fn test_community_format() {
        assert_eq!(
            format!("{}",BgpCommunity{ value:0xffffff01 }),
            "no_export".to_string()
        );
    }
}

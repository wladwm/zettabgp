// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP "community list" path attributes

use crate::*;
use crate::message::attributes::*;
use std::str::FromStr;
#[cfg(feature = "serialization")]
use serde::ser::{SerializeSeq};

/// BGP community - element for BgpCommunityList path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BgpCommunity {
    pub value: u32,
}
/// BGP community list path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BgpCommunityList {
    pub value: std::collections::BTreeSet<BgpCommunity>,
}

/// BGP large community - element for BgpLargeCommunityList path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BgpLargeCommunity {
    pub ga: u32,
    pub ldp1: u32,
    pub ldp2: u32,
}
/// BGP <large> community list path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
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
    pub fn encode_to(&self,buf: &mut [u8]) -> Result<usize, BgpError> {
        if buf.len()<12 {
            return Err(BgpError::insufficient_buffer_size());
        }
        setn_u32(self.ga,buf);
        setn_u32(self.ldp1,&mut buf[4..8]);
        setn_u32(self.ldp2,&mut buf[8..12]);
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
    fn encode_to(
        &self,
        _peer: &BgpSessionParams,
        buf: &mut [u8],
    ) -> Result<usize, BgpError> {
        let mut pos: usize = 0;
        for i in &self.value {
            pos+=i.encode_to(&mut buf[pos..])?;
        }
        Ok(pos)
    }
}
impl BgpCommunity {
    pub fn new(v: u32) -> BgpCommunity {
        BgpCommunity {
            value: v
        }
    }
    pub fn from(h: u16, l: u16) -> BgpCommunity {
        BgpCommunity {
            value: ((h as u32) << 16) | (l as u32),
        }
    }
    pub fn decode_from(buf: &[u8]) -> Result<BgpCommunity, BgpError> {
        match buf.len() {
            4 => Ok(BgpCommunity {
                value: getn_u32(&buf),
            }),
            _ => Err(BgpError::static_str(
                "Invalid BgpCommunity item length",
            )),
        }
    }
    fn encode_to(
        &self,
        buf: &mut [u8],
    ) -> Result<usize, BgpError> {
        if buf.len()<4 {
            return Err(BgpError::insufficient_buffer_size())
        };
        setn_u32(self.value,buf);
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
        write!(
            f,
            "{}:{}",
            (self.value >> 16) as u16,
            (self.value & 0xffff) as u16
        )
    }
}
impl FromStr for BgpCommunity {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.trim().split(':').collect();
        if parts.len() < 2 {
            Ok(BgpCommunity{value:parts[0].parse()?})
        } else if parts.len()<3 {
            Ok(BgpCommunity{value:(parts[0].parse::<u16>()? as u32) << 16 | (parts[1].parse::<u16>()? as u32)})
        } else {
            Ok(BgpCommunity{value:s.parse()?})
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
            value: v.into_iter().collect()
        }
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
        let strs:Vec::<&str>=s.split(&[',', ' ', '\t'][..]).collect();
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
    fn encode_to(
        &self,
        _peer: &BgpSessionParams,
        buf: &mut [u8],
    ) -> Result<usize, BgpError> {
        if buf.len()<self.value.len()*4 {
            return Err(BgpError::insufficient_buffer_size());
        }
        let mut curpos: usize = 0;
        for c in &self.value {
            let lng=c.encode_to(&mut buf[curpos..])?;
            curpos+=lng;
        }
        Ok(curpos)
    }
}

#[cfg(feature = "serialization")]
impl serde::Serialize for BgpCommunity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(format!("{}", self).as_str())
    }
}
#[cfg(feature = "serialization")]
impl serde::Serialize for BgpCommunityList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_seq(Some(self.value.len()))?;
        for l in self.value.iter() {
            state.serialize_element(&l)?;
        }
        state.end()
    }
}
#[cfg(feature = "serialization")]
impl serde::Serialize for BgpLargeCommunity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}
#[cfg(feature = "serialization")]
impl serde::Serialize for BgpLargeCommunityList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_seq(Some(self.value.len()))?;
        for l in self.value.iter() {
            state.serialize_element(&l)?;
        }
        state.end()
    }
}
// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP "ASpath" path attribute

use crate::message::attributes::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};

/// BGP AS - element of aspath
#[derive(Clone, Copy, Debug)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpAS {
    pub value: u32,
}

impl BgpAS {
    pub fn new(v: u32) -> BgpAS {
        BgpAS { value: v }
    }
    pub fn tonumb(&self) -> u32 {
        if (self.value & 0xffff) == 0 {
            self.value >> 16
        } else {
            self.value
        }
    }
}
impl From<u32> for BgpAS {
    fn from(v: u32) -> Self {
        BgpAS { value: v }
    }
}
impl PartialEq for BgpAS {
    fn eq(&self, other: &Self) -> bool {
        self.tonumb() == other.tonumb()
    }
}
impl Eq for BgpAS {}
impl PartialOrd for BgpAS {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.value.partial_cmp(&other.value)
    }
}
impl Ord for BgpAS {
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.cmp(&other.value)
    }
}
impl Hash for BgpAS {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state)
    }
}
impl std::fmt::Display for BgpAS {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if (self.value & 0xffff) == 0 {
            write!(f, "{}", self.value >> 16)
        } else {
            write!(f, "{}", self.value)
        }
    }
}
/// BGP AS_SEQUENCE - element of aspath
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpASseq {
    pub value: Vec<BgpAS>,
}
impl BgpASseq {
    pub fn len(&self) -> usize {
        self.value.len()
    }
}
impl From<u32> for BgpASseq {
    fn from(v: u32) -> Self {
        BgpASseq {
            value: vec![BgpAS { value: v }],
        }
    }
}
/// BGP AS_SET - element of aspath
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpASset {
    pub value: BTreeSet<BgpAS>,
}
impl BgpASset {
    pub fn len(&self) -> usize {
        self.value.len()
    }
}

/// BGP as path item - common element of aspath
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub enum BgpASitem {
    Seq(BgpASseq),
    Set(BgpASset),
}
impl From<u32> for BgpASitem {
    fn from(v: u32) -> Self {
        BgpASitem::Seq(v.into())
    }
}
impl From<BgpASseq> for BgpASitem {
    fn from(v: BgpASseq) -> Self {
        BgpASitem::Seq(v)
    }
}
impl From<BgpASset> for BgpASitem {
    fn from(v: BgpASset) -> Self {
        BgpASitem::Set(v)
    }
}
impl BgpASitem {
    pub fn len(&self) -> usize {
        match self {
            BgpASitem::Seq(ref s) => s.len(),
            BgpASitem::Set(ref s) => s.len(),
        }
    }
    pub fn encode_to(&self, peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        let lng = self.len() * (if peer.has_as32bit { 4 } else { 2 }) + 2;
        if buf.len() < lng || self.len() > 255 {
            return Err(BgpError::InsufficientBufferSize);
        }
        let mut pos: usize;
        match self {
            BgpASitem::Seq(ref s) => {
                buf[0] = 1;
                buf[1] = self.len() as u8;
                pos = 2;
                for q in s.value.iter() {
                    if peer.has_as32bit {
                        setn_u32(q.value, &mut buf[pos..pos + 4]);
                        pos += 4;
                    } else {
                        setn_u16(q.value as u16, &mut buf[pos..pos + 2]);
                        pos += 2;
                    }
                }
            }
            BgpASitem::Set(ref s) => {
                buf[0] = 2;
                buf[1] = self.len() as u8;
                pos = 2;
                for q in s.value.iter() {
                    if peer.has_as32bit {
                        setn_u32(q.value, &mut buf[pos..pos + 4]);
                        pos += 4;
                    } else {
                        setn_u16(q.value as u16, &mut buf[pos..pos + 2]);
                        pos += 2;
                    }
                }
            }
        }
        Ok(lng)
    }
    pub fn decode_from(
        peer: &BgpSessionParams,
        buf: &[u8],
    ) -> Result<(BgpASitem, usize), BgpError> {
        if buf.len() < 2 {
            return Ok((BgpASitem::Seq(BgpASseq { value: Vec::new() }), 0));
        }
        let mut pos = 2usize;
        let mut cnt = buf[1];
        match buf[0] {
            1 => {
                //as_set
                let mut v = BTreeSet::<BgpAS>::new();
                let itemsize=if peer.has_as32bit {4usize} else {2};
                while pos <= (buf.len()-itemsize) && cnt > 0 {
                    if peer.has_as32bit {
                        v.insert(getn_u32(&buf[pos..(pos + itemsize)]).into());
                    } else {
                        v.insert((getn_u16(&buf[pos..(pos + itemsize)]) as u32).into());
                    }
                    pos += itemsize;
                    cnt -= 1;
                }
                Ok((BgpASitem::Set(BgpASset { value: v }), pos))
            }
            2 => {
                //as_sequence
                let mut v = Vec::<BgpAS>::new();
                let itemsize=if peer.has_as32bit {4usize} else {2};
                while pos <= (buf.len()-itemsize) && cnt > 0 {
                    if peer.has_as32bit {
                        v.push(getn_u32(&buf[pos..(pos + itemsize)]).into());
                    } else {
                        v.push((getn_u16(&buf[pos..(pos + itemsize)]) as u32).into());
                    }
                    pos += itemsize;
                    cnt -= 1;
                }
                Ok((BgpASitem::Seq(BgpASseq { value: v }), pos))
            }
            _ => Err(BgpError::ProtocolError),
        }
    }
}
/// BGP as-path path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpASpath {
    pub value: Vec<BgpASitem>,
}

impl<T, I> From<T> for BgpASpath
where
    T: IntoIterator<Item = I>,
    I: Into<BgpASitem>,
{
    fn from(v: T) -> Self {
        BgpASpath { value: v.into_iter().map(|q| q.into()).collect() }
    }
}

impl BgpASpath {
    pub fn new() -> BgpASpath {
        BgpASpath { value: Vec::new() }
    }
    pub fn decode_from(peer: &BgpSessionParams, buf: &[u8]) -> Result<BgpASpath, BgpError> {
        if buf.len() < 2 {
            return Ok(BgpASpath { value: Vec::new() });
        }
        let mut pos = 0usize;
        let mut v: Vec<BgpASitem> = Vec::new();
        while pos < buf.len() {
            let r = BgpASitem::decode_from(peer, &buf[pos..])?;
            v.push(r.0);
            pos += r.1;
        }
        Ok(BgpASpath { value: v })
    }
}
impl Default for BgpASpath {
    fn default() -> Self {
        Self::new()
    }
}
impl std::fmt::Debug for BgpASpath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpASpath")
            .field("value", &self.value)
            .finish()
    }
}
impl std::fmt::Display for BgpASpath {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ASPath {:?}", self.value)
    }
}
impl BgpAttr for BgpASpath {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 2,
            flags: 0x50,
        }
    }
    fn encode_to(&self, peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut pos = 0usize;
        if self.value.is_empty() {
            return Ok(0);
        }
        for i in &self.value {
            pos += i.encode_to(peer, &mut buf[pos..])?;
        }
        Ok(pos)
    }
}

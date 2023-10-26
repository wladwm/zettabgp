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
use std::hash::{Hash, Hasher};

/// BGP AS - element of aspath
#[derive(Clone, Copy, Debug)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpAS {
    pub value: u32,
}
/// BGP as-path path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpASpath {
    pub value: Vec<BgpAS>,
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
impl BgpASpath {
    pub fn new() -> BgpASpath {
        BgpASpath { value: Vec::new() }
    }
    pub fn from<T: std::convert::Into<BgpAS>>(sv: Vec<T>) -> BgpASpath {
        BgpASpath {
            value: sv.into_iter().map(|q| q.into()).collect(),
        }
    }
    pub fn decode_from(peer: &BgpSessionParams, buf: &[u8]) -> Result<BgpASpath, BgpError> {
        if buf.len() < 2 {
            return Ok(BgpASpath { value: Vec::new() });
        }
        let mut pos: usize;
        if peer.has_as32bit {
            pos = buf.len() % 4;
        } else {
            pos = buf.len() % 2;
        }
        let mut v: Vec<BgpAS> = Vec::new();
        while pos < buf.len() {
            if peer.has_as32bit {
                v.push(getn_u32(&buf[pos..(pos + 4)]).into());
                pos += 4;
            } else {
                v.push((getn_u16(&buf[pos..(pos + 2)]) as u32).into());
                pos += 2;
            }
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
        let mut pos: usize;
        if self.value.is_empty() {
            return Ok(0);
        }
        if peer.has_as32bit {
            if buf.len() < (2 + self.value.len() * 4) {
                return Err(BgpError::insufficient_buffer_size());
            }
            buf[0] = 2; //as-sequence
            buf[1] = self.value.len() as u8;
            pos = 2;
        } else {
            if buf.len() < (2 + self.value.len() * 2) {
                return Err(BgpError::insufficient_buffer_size());
            }
            buf[0] = 2; //as-sequence
            buf[1] = self.value.len() as u8;
            pos = 2;
        }
        for i in &self.value {
            if peer.has_as32bit {
                setn_u32(i.value, &mut buf[pos..(pos + 4)]);
                pos += 4;
            } else {
                setn_u16(i.value as u16, &mut buf[pos..(pos + 2)]);
                pos += 2;
            }
        }
        Ok(pos)
    }
}

// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP "cluster list" path attribute

use crate::message::attributes::*;
#[cfg(feature = "serialization")]
use serde::ser::SerializeSeq;

/// BGP clustr list path attribute struct
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BgpClusterList {
    pub value: Vec<std::net::IpAddr>,
}
impl BgpClusterList {
    pub fn decode_from(peer: &BgpSessionParams, buf: &[u8]) -> Result<BgpClusterList, BgpError> {
        let mut pos: usize = 0;
        let mut v = Vec::new();
        let itemsize = match peer.peer_mode {
            BgpTransportMode::IPv4 => 4,
            BgpTransportMode::IPv6 => 16,
        };
        while (pos + itemsize) <= buf.len() {
            v.push(decode_addr_from(&buf[pos..(pos + itemsize)])?);
            pos += itemsize;
        }
        Ok(BgpClusterList { value: v })
    }
}
impl std::fmt::Debug for BgpClusterList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpClusterList")
            .field("value", &self.value)
            .finish()
    }
}
impl std::fmt::Display for BgpClusterList {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BgpClusterList {:?}", self.value)
    }
}
impl BgpAttr for BgpClusterList {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 10,
            flags: 80,
        }
    }
    fn encode_to(&self, _peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut pos: usize = 0;
        for i in &self.value {
            pos += encode_addr_to(i, &mut buf[pos..])?;
        }
        Ok(pos)
    }
}
#[cfg(feature = "serialization")]
impl serde::Serialize for BgpClusterList {
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

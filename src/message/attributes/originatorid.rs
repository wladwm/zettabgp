// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP originator id path attribute

use crate::message::attributes::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// BGP originator id path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpOriginatorID {
    pub value: IpAddr,
}
impl BgpOriginatorID {
    pub fn new(o: IpAddr) -> BgpOriginatorID {
        BgpOriginatorID { value: o }
    }
    pub fn decode_from(peer: &BgpSessionParams, buf: &[u8]) -> Result<BgpOriginatorID, BgpError> {
        match peer.peer_mode {
            BgpTransportMode::IPv4 => Ok(BgpOriginatorID {
                value: decode_addr_from(&buf[..4])?,
            }),
            BgpTransportMode::IPv6 => Ok(BgpOriginatorID {
                value: if buf.len() < 16 {
                    decode_addr_from(&buf[..4])?
                } else {
                    decode_addr_from(&buf[..16])?
                },
            }),
        }
    }
}
impl std::fmt::Debug for BgpOriginatorID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpOriginatorID")
            .field("value", &self.value)
            .finish()
    }
}
impl std::fmt::Display for BgpOriginatorID {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BgpOriginatorID {}", self.value)
    }
}
impl BgpAttr for BgpOriginatorID {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 9,
            flags: 64,
        }
    }
    fn encode_to(&self, peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        match peer.peer_mode {
            BgpTransportMode::IPv4 => {
                if let IpAddr::V4(ref a) = self.value {
                    encode_addrv4_to(a, buf)
                } else {
                    Err(BgpError::static_str("Invalid originatorid kind"))
                }
            }
            BgpTransportMode::IPv6 => {
                if let IpAddr::V6(ref a) = self.value {
                    encode_addrv6_to(a, buf)
                } else {
                    Err(BgpError::static_str("Invalid originatorid kind"))
                }
            }
        }
    }
}

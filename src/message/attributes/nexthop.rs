// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP nexthop path attribute

use crate::message::attributes::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

/// BGP nexthop
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpNextHop {
    /// next hop itself
    pub value: std::net::IpAddr,
}
impl BgpNextHop {
    pub fn new(v: std::net::IpAddr) -> BgpNextHop {
        BgpNextHop { value: v }
    }
    pub fn decode_from(peer: &BgpSessionParams, buf: &[u8]) -> Result<BgpNextHop, BgpError> {
        if peer.peer_mode == BgpTransportMode::IPv6 && buf.len() >= 16 {
            return Ok(BgpNextHop {
                value: std::net::IpAddr::V6(decode_addrv6_from(buf)?),
            });
        }
        if peer.peer_mode == BgpTransportMode::IPv4 && buf.len() >= 4 {
            return Ok(BgpNextHop {
                value: std::net::IpAddr::V4(decode_addrv4_from(buf)?),
            });
        }
        Err(BgpError::static_str("Invalid nexthop length"))
    }
}
impl std::fmt::Debug for BgpNextHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpNextHop")
            .field("value", &self.value)
            .finish()
    }
}
impl std::fmt::Display for BgpNextHop {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "NextHop {:?}", self.value)
    }
}
impl BgpAttr for BgpNextHop {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 3,
            flags: 64,
        }
    }
    fn encode_to(&self, peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        if let std::net::IpAddr::V6(v) = self.value {
            if peer.peer_mode == BgpTransportMode::IPv6 && buf.len() >= 16 {
                return encode_addrv6_to(&v, buf);
            }
        };
        if let std::net::IpAddr::V4(v) = self.value {
            if peer.peer_mode == BgpTransportMode::IPv4 && buf.len() >= 4 {
                return encode_addrv4_to(&v, buf);
            }
        };
        Err(BgpError::static_str("Invalid nexthop type"))
    }
}

// Copyright 2021-2022 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP "connector" path attribute

use crate::message::attributes::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// BGP local preference path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpConnector {
    pub asn: u32,
    pub addr: Ipv4Addr,
    pub orig: Ipv4Addr,
}
impl BgpConnector {
    pub fn new(asn: u32, addr: Ipv4Addr, orig: Ipv4Addr) -> BgpConnector {
        BgpConnector { asn, addr, orig }
    }
    pub fn decode_from(buf: &[u8]) -> Result<BgpConnector, BgpError> {
        if buf.len() >= 14 {
            if getn_u16(buf) != 1 {
                return Err(BgpError::static_str("Unknown Connector type"));
            }
            Ok(BgpConnector {
                asn: getn_u32(&buf[2..6]),
                addr: decode_addrv4_from(&buf[6..10])?,
                orig: decode_addrv4_from(&buf[10..14])?,
            })
        } else {
            Err(BgpError::static_str("Invalid Connector length"))
        }
    }
}
impl std::fmt::Debug for BgpConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpConnector")
            .field("asn", &self.asn)
            .field("addr", &self.addr)
            .field("orig", &self.orig)
            .finish()
    }
}
impl std::fmt::Display for BgpConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "BgpConnector({:?}:{:?} @{:?})",
            self.asn, self.addr, self.orig
        )
    }
}
impl BgpAttr for BgpConnector {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 20,
            flags: 192,
        }
    }
    fn encode_to(&self, _peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        if buf.len() >= 14 {
            setn_u16(1, buf);
            setn_u32(self.asn, &mut buf[2..6]);
            encode_addrv4_to(&self.addr, &mut buf[6..10])?;
            encode_addrv4_to(&self.orig, &mut buf[10..14])?;
            Ok(14)
        } else {
            Err(BgpError::static_str("Invalid localpref length"))
        }
    }
}

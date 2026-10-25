// Copyright 2026 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::*;

/// BGP route-refresh message
pub struct BgpRouterefreshMessage {
    /// address family identifier
    pub afi: u16,
    /// sub-address family identifier
    pub safi: u8,
    /// message subtype
    pub subtype: u8,
}

impl BgpRouterefreshMessage {
    /// constructs new empty message
    pub fn new() -> BgpRouterefreshMessage {
        BgpRouterefreshMessage {
            afi: 0,
            safi: 0,
            subtype: 0,
        }
    }
    pub fn capability(&self) -> Option<BgpCapability> {
        BgpCapability::from_afi_safi(self.afi, self.safi)
    }
}
impl std::fmt::Debug for BgpRouterefreshMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpRouterefreshMessage")
            .field("afi", &self.afi)
            .field("safi", &self.safi)
            .field("subtype", &self.subtype)
            .finish()
    }
}
impl std::fmt::Display for BgpRouterefreshMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "BgpRouterefreshMessage afi={} safi={} subtype={}",
            self.afi, self.safi, self.subtype
        )
    }
}
impl Default for BgpRouterefreshMessage {
    fn default() -> Self {
        Self::new()
    }
}
impl BgpMessage for BgpRouterefreshMessage {
    fn decode_from(&mut self, _peer: &BgpSessionParams, buf: &[u8]) -> Result<(), BgpError> {
        if buf.len() < 4 {
            return Err(BgpError::static_str("Invalid route-refresh message length"));
        }
        self.afi = getn_u16(buf);
        self.safi = buf[3];
        self.subtype = buf[2];
        Ok(())
    }
    fn encode_to(&self, _peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        if buf.len() < 4 {
            return Err(BgpError::static_str("Invalid route-refresh message length"));
        }
        setn_u16(self.afi, &mut buf[..2]);
        buf[2] = self.subtype;
        buf[3] = self.safi;
        Ok(4)
    }
}

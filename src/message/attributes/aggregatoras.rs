// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP "Aggregator AS" path attribute

use crate::message::attributes::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

/// BGP "Aggregator AS" path attribute struct
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpAggregatorAS {
    /// Autonomous system number
    pub asn: u32,
    /// Aggregation router ID
    pub addr: std::net::Ipv4Addr,
}
impl BgpAggregatorAS {
    pub fn decode_from(_peer: &BgpSessionParams, buf: &[u8]) -> Result<BgpAggregatorAS, BgpError> {
        if buf.len() == 8 {
            Ok(BgpAggregatorAS {
                asn: getn_u32(buf),
                addr: decode_addrv4_from(&buf[4..8])?,
            })
        } else if buf.len() == 6 {
            Ok(BgpAggregatorAS {
                asn: getn_u16(buf) as u32,
                addr: decode_addrv4_from(&buf[2..6])?,
            })
        } else {
            Err(BgpError::static_str("Invalid AggregatorAS length"))
        }
    }
}
impl std::fmt::Debug for BgpAggregatorAS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpAggregatorAS")
            .field("asn", &self.asn)
            .field("addr", &self.addr)
            .finish()
    }
}
impl std::fmt::Display for BgpAggregatorAS {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BgpAggregatorAS {:?} {:?}", self.asn, self.addr)
    }
}
impl BgpAttr for BgpAggregatorAS {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 7,
            flags: 64,
        }
    }
    fn encode_to(&self, peer: &BgpSessionParams, _buf: &mut [u8]) -> Result<usize, BgpError> {
        Ok(if peer.has_as32bit { 4 } else { 2 })
    }
}

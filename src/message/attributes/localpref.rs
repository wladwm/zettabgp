// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP "local preference" path attribute

use crate::message::attributes::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

/// BGP local preference path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpLocalpref {
    pub value: u32,
}
impl BgpLocalpref {
    pub fn new(v: u32) -> BgpLocalpref {
        BgpLocalpref { value: v }
    }
    pub fn decode_from(buf: &[u8]) -> Result<BgpLocalpref, BgpError> {
        if buf.len() >= 4 {
            Ok(BgpLocalpref {
                value: getn_u32(buf),
            })
        } else {
            Err(BgpError::static_str("Invalid localpref length"))
        }
    }
}
impl std::fmt::Debug for BgpLocalpref {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpLocalpref")
            .field("value", &self.value)
            .finish()
    }
}
impl std::fmt::Display for BgpLocalpref {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BgpLocalpref {:?}", self.value)
    }
}
impl BgpAttr for BgpLocalpref {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 5,
            flags: 64,
        }
    }
    fn encode_to(&self, _peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        if buf.len() >= 4 {
            setn_u32(self.value, buf);
            Ok(4)
        } else {
            Err(BgpError::static_str("Invalid localpref length"))
        }
    }
}

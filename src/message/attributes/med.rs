// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP "multi-exit discriminator" path attribute

use crate::message::attributes::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

/// BGP MED (multi-exit discriminator) path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpMED {
    pub value: u32,
}
impl BgpMED {
    pub fn new(v: u32) -> BgpMED {
        BgpMED { value: v }
    }
    pub fn decode_from(buf: &[u8]) -> Result<BgpMED, BgpError> {
        if buf.len() >= 4 {
            Ok(BgpMED {
                value: getn_u32(buf),
            })
        } else {
            Err(BgpError::static_str("Invalid MED length"))
        }
    }
}
impl std::fmt::Debug for BgpMED {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpMED")
            .field("value", &self.value)
            .finish()
    }
}
impl std::fmt::Display for BgpMED {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BgpMED {:?}", self.value)
    }
}
impl BgpAttr for BgpMED {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 4,
            flags: 128,
        }
    }
    fn encode_to(&self, _peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        if buf.len() >= 4 {
            setn_u32(self.value, buf);
            Ok(4)
        } else {
            Err(BgpError::static_str("Invalid MED length"))
        }
    }
}

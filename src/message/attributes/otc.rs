// Copyright 2026 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP "Only to customer" path attribute

use crate::message::attributes::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

/// BGP Atmic aggregate path attribute
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpOTC {
    pub value: u32,
}
impl BgpOTC {
    pub fn decode_from(
        _peer: &BgpSessionParams,
        buf: &[u8],
    ) -> Result<BgpOTC, BgpError> {
        Ok(BgpOTC {
            value: if buf.is_empty() {
                0
            } else {
                getn_u32(buf)
            },
        })
    }
}
impl std::fmt::Debug for BgpOTC {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpOTC")
            .field("value", &self.value)
            .finish()
    }
}
impl std::fmt::Display for BgpOTC {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.value.fmt(f)
    }
}
impl BgpAttr for BgpOTC {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 35,
            flags: 224,
        }
    }
    fn encode_to(&self, _peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        setn_u32(self.value, buf);
        Ok(4)
    }
}

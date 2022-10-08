// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP origin path attribute

use crate::message::attributes::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

/// BGP origin value
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub enum BgpAttrOrigin {
    Igp,
    Egp,
    Incomplete,
}
impl std::fmt::Display for BgpAttrOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BgpAttrOrigin::Igp => f.write_str("Igp"),
            BgpAttrOrigin::Egp => f.write_str("Egp"),
            BgpAttrOrigin::Incomplete => f.write_str("Incomplete"),
        }
    }
}

/// BGP origin path attribute
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpOrigin {
    pub value: BgpAttrOrigin,
}
impl BgpOrigin {
    pub fn new(v: BgpAttrOrigin) -> BgpOrigin {
        BgpOrigin { value: v }
    }
    pub fn decode_from(buf: &[u8]) -> Result<BgpOrigin, BgpError> {
        if buf.is_empty() {
            Err(BgpError::InsufficientBufferSize)
        } else {
            match buf[0] {
                0 => Ok(BgpOrigin {
                    value: BgpAttrOrigin::Igp,
                }),
                1 => Ok(BgpOrigin {
                    value: BgpAttrOrigin::Egp,
                }),
                2 => Ok(BgpOrigin {
                    value: BgpAttrOrigin::Incomplete,
                }),
                _ => Err(BgpError::static_str("Invalid value for BgpOrigin")),
            }
        }
    }
}
impl std::fmt::Debug for BgpOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpOrigin")
            .field("value", &self.value)
            .finish()
    }
}
impl std::fmt::Display for BgpOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.value {
            BgpAttrOrigin::Igp => {
                write!(f, "origin igp")
            }
            BgpAttrOrigin::Egp => {
                write!(f, "origin egp")
            }
            BgpAttrOrigin::Incomplete => {
                write!(f, "origin incomplete")
            }
        }
    }
}

impl BgpAttr for BgpOrigin {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 1,
            flags: 64,
        }
    }
    fn encode_to(&self, _peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        if buf.is_empty() {
            Err(BgpError::InsufficientBufferSize)
        } else {
            match self.value {
                BgpAttrOrigin::Igp => {
                    buf[0] = 0;
                    Ok(1)
                }
                BgpAttrOrigin::Egp => {
                    buf[0] = 1;
                    Ok(1)
                }
                BgpAttrOrigin::Incomplete => {
                    buf[0] = 2;
                    Ok(1)
                }
            }
        }
    }
}

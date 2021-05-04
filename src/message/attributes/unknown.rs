// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP unsupported path attributes

use crate::*;
use crate::message::attributes::*;
#[cfg(feature = "serialization")]
use serde::ser::{SerializeStruct};

/// Unsupported BGP path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BgpAttrUnknown {
    /// PA typecode&flags
    pub params: BgpAttrParams,
    /// byte code "meat"
    pub value: Vec<u8>,
}
impl BgpAttrUnknown {
    pub fn new(tc: u8, flg: u8) -> Box<dyn BgpAttr> {
        Box::new(BgpAttrUnknown {
            params: BgpAttrParams {
                typecode: tc,
                flags: flg,
            },
            value: Vec::new(),
        })
    }
    pub fn decode_from(
        tc: u8,
        flg: u8,
        buf: &[u8],
    ) -> Result<BgpAttrUnknown, BgpError> {
        let mut ret = BgpAttrUnknown {
            params: BgpAttrParams {
                typecode: tc,
                flags: flg,
            },
            value: Vec::new(),
        };
        ret.value.resize(buf.len(), 0);
        ret.value.copy_from_slice(buf);
        Ok(ret)
    }
}
impl std::fmt::Debug for BgpAttrUnknown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpAttrUnknown")
            .field("params", &self.params)
            .field("value", &self.value)
            .finish()
    }
}
impl std::fmt::Display for BgpAttrUnknown {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "PA unknown(tc={:?},flg={:?} {:?})",
            self.params.typecode, self.params.flags, self.value
        )
    }
}
impl BgpAttr for BgpAttrUnknown {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 1,
            flags: 64,
        }
    }
    fn encode_to(
        &self,
        _peer: &BgpSessionParams,
        buf: &mut [u8],
    ) -> Result<usize, BgpError> {
        buf[0..self.value.len()].clone_from_slice(self.value.as_slice());
        Ok(self.value.len())
    }
}

#[cfg(feature = "serialization")]
impl serde::Serialize for BgpAttrParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("BgpAttrParams", 2)?;
        state.serialize_field("typecode", &self.typecode)?;
        state.serialize_field("flags", &self.flags)?;
        state.end()
    }
}
#[cfg(feature = "serialization")]
impl serde::Serialize for BgpAttrUnknown {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("BgpAttrUnknown", 2)?;
        state.serialize_field("params", &self.params)?;
        state.serialize_field("value", &self.value)?;
        state.end()
    }
}
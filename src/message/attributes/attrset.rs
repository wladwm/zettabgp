// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP attribute set path attribute

use crate::message::attributes::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

/// BGP attribute set path attribute struct
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpAttrSet {
    /// Originating autonomous system number
    pub asn: u32,
    /// Carried path attributes
    pub attrs: Vec<BgpAttrItem>,
}
impl BgpAttrSet {
    pub fn decode_from(peer: &BgpSessionParams, buf: &[u8]) -> Result<BgpAttrSet, BgpError> {
        if !peer.has_as32bit {
            return Err(BgpError::static_str(
                "Invalid BgpAttrSet without 32-bit AS support",
            ));
        }
        if buf.len() < 4 {
            return Err(BgpError::static_str("Invalid BgpAttrSet buffer length"));
        }
        let mut attrs = Vec::<BgpAttrItem>::new();
        let mut curpos = 4;
        while curpos < buf.len() {
            let flags = buf[curpos];
            let tc = buf[curpos + 1];
            let attrlen = if (flags & 16) > 0 {
                curpos += 4;
                getn_u16(&buf[(curpos - 2)..curpos]) as usize
            } else {
                curpos += 3;
                buf[curpos - 1] as usize
            };
            if (curpos + attrlen) > buf.len() {
                return Err(BgpError::static_str("Protocol error"));
            };
            attrs.push(BgpAttrItem::decode_from(
                peer,
                tc,
                flags,
                attrlen,
                &buf[curpos..(curpos + attrlen)],
            )?);
            curpos += attrlen;
        }
        Ok(BgpAttrSet {
            asn: getn_u32(buf),
            attrs,
        })
    }
}
impl std::fmt::Debug for BgpAttrSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpAttrSet")
            .field("asn", &self.asn)
            .field("attrs", &self.attrs)
            .finish()
    }
}
impl std::fmt::Display for BgpAttrSet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BgpAttrSet AS{} {:?}", self.asn, self.attrs)
    }
}
impl BgpAttr for BgpAttrSet {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 128,
            flags: 224,
        }
    }
    fn encode_to(&self, _peer: &BgpSessionParams, _buf: &mut [u8]) -> Result<usize, BgpError> {
        unimplemented!()
    }
}

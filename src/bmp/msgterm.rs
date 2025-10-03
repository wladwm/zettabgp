// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BMP termination message

use crate::*;

/// BMP termination message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BmpMessageTermination {
    /// reason string
    pub str0: Option<String>,
    /// reason code
    pub reason: Option<u16>,
}

impl BmpMessageTermination {
    pub fn new() -> BmpMessageTermination {
        BmpMessageTermination {
            str0: None,
            reason: None,
        }
    }
    pub fn decode_from(buf: &[u8]) -> Result<(BmpMessageTermination, usize), BgpError> {
        let mut pos: usize = 0;
        let mut ret: BmpMessageTermination = BmpMessageTermination::new();
        while buf.len() - pos >= 4 {
            let infotype = getn_u16(&buf[pos..]);
            let infolen = getn_u16(&buf[pos + 2..]) as usize;
            pos += 4;
            if buf.len() - pos < infolen {
                return Err(BgpError::InsufficientBufferSize);
            }
            match infotype {
                0 => ret.str0 = Some(core::str::from_utf8(&buf[pos..pos + infolen])?.to_string()),
                1 => ret.reason = Some(getn_u16(&buf[pos..])),
                _ => {}
            }
            pos += infolen;
        }
        Ok((ret, pos))
    }
    pub fn encode_to(&self, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut curpos: usize = 0;
        if let Some(str0) = &self.str0 {
            let str0 = str0.as_bytes();
            if buf.len() - curpos < 4 + str0.len() {
                return Err(BgpError::InsufficientBufferSize);
            }
            setn_u16(0, &mut buf[curpos..]);
            curpos += 2;
            setn_u16(str0.len() as u16, &mut buf[curpos..]);
            curpos += 2;
            buf[curpos..curpos + str0.len()].copy_from_slice(str0);
            curpos += str0.len();
        }
        if let Some(reason) = self.reason {
            if buf.len() - curpos < 6 {
                return Err(BgpError::InsufficientBufferSize);
            }
            setn_u16(1, &mut buf[curpos..]);
            curpos += 2;
            setn_u16(2, &mut buf[curpos..]);
            curpos += 2;
            setn_u16(reason, &mut buf[curpos..]);
            curpos += 2;
        }
        Ok(curpos)
    }
}
impl Default for BmpMessageTermination {
    fn default() -> Self {
        Self::new()
    }
}

// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BMP init message

use crate::*;

/// information value
pub struct BmpInfoVal {
    /// information type
    pub infotype: u16,
    /// information string
    pub info: String,
}

impl BmpInfoVal {
    fn decode_from(buf: &[u8]) -> Result<(BmpInfoVal, usize), BgpError> {
        if buf.len() < 4 {
            return Err(BgpError::insufficient_buffer_size());
        };
        let tp = getn_u16(buf);
        let ln = getn_u16(&buf[2..4]) as usize;
        if ln > (buf.len() - 4) {
            return Err(BgpError::insufficient_buffer_size());
        };
        Ok((
            BmpInfoVal {
                infotype: tp,
                info: core::str::from_utf8(&buf[4..4 + ln])?.to_string(),
            },
            ln + 4,
        ))
    }
    fn encode_to(&self, buf: &mut [u8]) -> Result<usize, BgpError> {
        if buf.len() < 4 {
            return Err(BgpError::insufficient_buffer_size());
        };
        let mut curpos = 0;
        setn_u16(self.infotype, &mut buf[curpos..]);
        curpos += 2;
        let info = self.info.as_bytes();
        setn_u16(info.len() as u16, &mut buf[curpos..]);
        curpos += 2;
        buf[curpos..curpos + info.len()].copy_from_slice(info);
        curpos += info.len();
        Ok(curpos)
    }
}

/// BMP init message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BmpMessageInitiation {
    /// string
    pub str0: Option<String>,
    /// system description
    pub sys_descr: Option<String>,
    /// system name
    pub sys_name: Option<String>,
}

impl BmpMessageInitiation {
    pub fn new() -> BmpMessageInitiation {
        BmpMessageInitiation {
            str0: None,
            sys_descr: None,
            sys_name: None,
        }
    }
    pub fn decode_from(buf: &[u8]) -> Result<(BmpMessageInitiation, usize), BgpError> {
        let mut pos: usize = 0;
        let mut ret: BmpMessageInitiation = BmpMessageInitiation::new();
        while pos < buf.len() {
            let c = BmpInfoVal::decode_from(&buf[pos..])?;
            match c.0.infotype {
                0 => ret.str0 = Some(c.0.info),
                1 => ret.sys_descr = Some(c.0.info),
                2 => ret.sys_name = Some(c.0.info),
                _ => {}
            };
            pos += c.1;
        }
        Ok((ret, pos))
    }
    pub fn encode_to(&self, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut curpos: usize = 0;
        if let Some(str0) = &self.str0 {
            curpos += (BmpInfoVal {
                infotype: 0,
                info: str0.clone(),
            })
            .encode_to(&mut buf[curpos..])?;
        }
        if let Some(sys_descr) = &self.sys_descr {
            curpos += (BmpInfoVal {
                infotype: 0,
                info: sys_descr.clone(),
            })
            .encode_to(&mut buf[curpos..])?;
        }
        if let Some(sys_name) = &self.sys_name {
            curpos += (BmpInfoVal {
                infotype: 0,
                info: sys_name.to_string(),
            })
            .encode_to(&mut buf[curpos..])?;
        }
        Ok(curpos)
    }
}
impl Default for BmpMessageInitiation {
    fn default() -> Self {
        Self::new()
    }
}

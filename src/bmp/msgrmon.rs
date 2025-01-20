// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BMP route monitoring message

use crate::bmp::bmputl::*;
use crate::message::update::BgpUpdateMessage;
use crate::message::*;
use crate::{BgpError, BgpMessage, BgpSessionParams};

/// BMP route monitoring message
#[derive(Debug)]
pub struct BmpMessageRouteMonitoring {
    /// peer header
    pub peer: BmpMessagePeerHeader,
    /// incapsulated BGP update message
    pub update: BgpUpdateMessage,
}

impl BmpMessageRouteMonitoring {
    pub fn decode_from(buf: &[u8]) -> Result<(BmpMessageRouteMonitoring, usize), BgpError> {
        if buf.len() < 62 {
            return Err(BgpError::InsufficientBufferSize);
        }
        let pm = BmpMessagePeerHeader::decode_from(buf)?;
        let mut pos = pm.1;
        let sesspars: &BgpSessionParams = &(&pm.0).into();
        let msgt = sesspars.decode_message_head(&buf[pos..])?;
        pos += 19;
        if msgt.0 != BgpMessageType::Update {
            return Err(BgpError::static_str(
                "Invalid BGP message type for BmpMessageRouteMonitoring",
            ));
        }
        let mut upd = BgpUpdateMessage::new();
        upd.decode_from(sesspars, &buf[pos..pos + msgt.1])?;
        pos += msgt.1;
        Ok((
            BmpMessageRouteMonitoring {
                peer: pm.0,
                update: upd,
            },
            pos,
        ))
    }
    pub fn encode_to(&self, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut curpos: usize = 0;
        if buf.len() < 62 {
            return Err(BgpError::InsufficientBufferSize);
        }
        curpos += self.peer.encode_to(buf)?;
        let sesspars: &BgpSessionParams = &(&self.peer).into();

        let messagelen = self.update.encode_to(sesspars, &mut buf[curpos + 19..])?;
        let blen =
            sesspars.prepare_message_buf(&mut buf[curpos..], BgpMessageType::Update, messagelen)?;
        curpos += blen;

        Ok(curpos)
    }
}

// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::bmp::bmputl::*;
use crate::message::notification::BgpNotificationMessage;
use crate::message::open::BgpOpenMessage;
use crate::message::*;
use crate::util::*;
use crate::{BgpError, BgpMessage, BgpSessionParams};

use std::convert::TryInto;

#[derive(Debug, Clone)]
pub struct BmpMessagePeerUp {
    pub peer: BmpMessagePeerHeader,
    pub localaddress: std::net::IpAddr,
    pub localport: u16,
    pub remoteport: u16,
    pub msg1: BgpOpenMessage,
    pub msg2: BgpOpenMessage,
}

#[derive(Debug)]
pub enum BmpMessagePeerDownReason {
    AdministrativelyClosed(BgpNotificationMessage), // 1
    LocalSystemState(u16),                          // 2
    RemoteNotification(BgpNotificationMessage),     // 3
    Remote,                                         // 4
    BmpDisabled,                                    // 5
}

#[derive(Debug)]
pub struct BmpMessagePeerDown {
    pub peer: BmpMessagePeerHeader,
    pub reason: BmpMessagePeerDownReason,
}

impl BmpMessagePeerUp {
    pub fn decode_from(buf: &[u8]) -> Result<(BmpMessagePeerUp, usize), BgpError> {
        if buf.len() < 62 {
            return Err(BgpError::InsufficientBufferSize);
        }
        let pm = BmpMessagePeerHeader::decode_from(buf)?;
        let mut ret = BmpMessagePeerUp {
            peer: pm.0,
            localaddress: decode_bmp_addr_from(&buf[pm.1..])?,
            localport: getn_u16(&buf[pm.1 + 16..]),
            remoteport: getn_u16(&buf[pm.1 + 18..]),
            msg1: BgpOpenMessage::new(),
            msg2: BgpOpenMessage::new(),
        };
        let sesspars = BgpSessionParams::from(&ret.peer);
        let mut pos: usize = pm.1 + 20;
        let msgt = sesspars.decode_message_head(&buf[pos..])?;
        pos += 19;
        if msgt.0 != BgpMessageType::Open {
            return Err(BgpError::static_str("Invalid BGP message type #1"));
        }
        ret.msg1.decode_from(&sesspars, &buf[pos..pos + msgt.1])?;
        pos += msgt.1;
        let msgt = sesspars.decode_message_head(&buf[pos..])?;
        pos += 19;
        if msgt.0 != BgpMessageType::Open {
            return Err(BgpError::static_str("Invalid BGP message type #2"));
        }
        ret.msg2.decode_from(&sesspars, &buf[pos..pos + msgt.1])?;
        pos += msgt.1;
        Ok((ret, pos))
    }
    pub fn encode_to(&self, buf: &mut [u8]) -> Result<usize, BgpError> {
        if buf.len() < 62 {
            return Err(BgpError::InsufficientBufferSize);
        }
        let mut curpos: usize = 0;
        curpos += self.peer.encode_to(buf)?;

        encode_bmp_addr_to(&self.localaddress, &mut buf[curpos..])?;
        curpos += 16;
        setn_u16(self.localport, &mut buf[curpos..]);
        curpos += 2;
        setn_u16(self.remoteport, &mut buf[curpos..]);
        curpos += 2;

        let sesspars: &BgpSessionParams = &(&self.peer).into();

        let messagelen = self.msg1.encode_to(sesspars, &mut buf[curpos + 19..])?;
        let blen =
            sesspars.prepare_message_buf(&mut buf[curpos..], BgpMessageType::Open, messagelen)?;
        curpos += blen;

        let messagelen = self.msg2.encode_to(sesspars, &mut buf[curpos + 19..])?;
        let blen =
            sesspars.prepare_message_buf(&mut buf[curpos..], BgpMessageType::Open, messagelen)?;
        curpos += blen;

        Ok(curpos)
    }
}

impl BmpMessagePeerDown {
    pub fn decode_from(buf: &[u8]) -> Result<(BmpMessagePeerDown, usize), BgpError> {
        if buf.len() < 43 {
            return Err(BgpError::InsufficientBufferSize);
        }
        let pm = BmpMessagePeerHeader::decode_from(buf)?;
        let mut pos = pm.1;
        let reason_code = buf[pos];
        pos += 1;
        let reason = match reason_code {
            1 => {
                let sesspars = BgpSessionParams::from(&pm.0);
                let msgt = sesspars.decode_message_head(&buf[pos..])?;
                pos += 19;
                if msgt.0 != BgpMessageType::Notification {
                    return Err(BgpError::static_str("Invalid BGP message type"));
                }
                let mut msg = BgpNotificationMessage::new();
                msg.decode_from(&sesspars, &buf[pos..pos + msgt.1])?;
                pos += msgt.1;
                BmpMessagePeerDownReason::AdministrativelyClosed(msg)
            }
            2 => {
                if buf.len() - pos < 2 {
                    return Err(BgpError::InsufficientBufferSize);
                }
                let state = u16::from_be_bytes((&buf[pos..pos + 2]).try_into().unwrap());
                pos += 2;
                BmpMessagePeerDownReason::LocalSystemState(state)
            }
            3 => {
                let sesspars = BgpSessionParams::from(&pm.0);
                let msgt = sesspars.decode_message_head(&buf[pos..])?;
                pos += 19;
                if msgt.0 != BgpMessageType::Notification {
                    return Err(BgpError::static_str("Invalid BGP message type"));
                }
                let mut msg = BgpNotificationMessage::new();
                msg.decode_from(&sesspars, &buf[pos..pos + msgt.1])?;
                pos += msgt.1;
                BmpMessagePeerDownReason::RemoteNotification(msg)
            }
            4 => BmpMessagePeerDownReason::Remote,
            5 => BmpMessagePeerDownReason::BmpDisabled,
            _ => return Err(BgpError::static_str("Unknown BMP Peer Down Reason Type")),
        };
        Ok((BmpMessagePeerDown { peer: pm.0, reason }, pos))
    }
    pub fn encode_to(&self, buf: &mut [u8]) -> Result<usize, BgpError> {
        if buf.len() < 43 {
            return Err(BgpError::InsufficientBufferSize);
        }
        let mut curpos: usize = 0;
        curpos += self.peer.encode_to(buf)?;

        match &self.reason {
            BmpMessagePeerDownReason::AdministrativelyClosed(msg) => {
                buf[curpos] = 1;
                curpos += 1;

                if buf.len() - curpos < 19 {
                    return Err(BgpError::InsufficientBufferSize);
                }

                let sesspars: &BgpSessionParams = &(&self.peer).into();
                let messagelen = msg.encode_to(sesspars, &mut buf[curpos + 19..])?;
                let blen = sesspars.prepare_message_buf(
                    &mut buf[curpos..],
                    BgpMessageType::Notification,
                    messagelen,
                )?;
                curpos += blen;
            }
            BmpMessagePeerDownReason::LocalSystemState(state) => {
                buf[curpos] = 2;
                curpos += 1;

                if buf.len() - curpos < 2 {
                    return Err(BgpError::InsufficientBufferSize);
                }
                setn_u16(*state, &mut buf[curpos..]);
                curpos += 2;
            }
            BmpMessagePeerDownReason::RemoteNotification(msg) => {
                buf[curpos] = 3;
                curpos += 1;

                if buf.len() - curpos < 19 {
                    return Err(BgpError::InsufficientBufferSize);
                }

                let sesspars: &BgpSessionParams = &(&self.peer).into();
                let messagelen = msg.encode_to(sesspars, &mut buf[curpos + 19..])?;
                let blen = sesspars.prepare_message_buf(
                    &mut buf[curpos..],
                    BgpMessageType::Notification,
                    messagelen,
                )?;
                curpos += blen;
            }
            BmpMessagePeerDownReason::Remote => {
                buf[curpos] = 4;
                curpos += 1;
            }
            BmpMessagePeerDownReason::BmpDisabled => {
                buf[curpos] = 5;
                curpos += 1;
            }
        }

        Ok(curpos)
    }
}

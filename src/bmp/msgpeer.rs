// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::*;
use crate::message::*;
use crate::bmp::bmputl::*;

#[derive(Debug)]
pub struct BmpMessagePeerUp {
    pub peer: BmpMessagePeerHeader,
    pub localaddress: std::net::IpAddr,
    pub localport: u16,
    pub remoteport: u16,
    pub msg1: BgpOpenMessage,
    pub msg2: BgpOpenMessage
}
impl BmpMessagePeerUp {
    pub fn decode_from(
        buf: &[u8]
    ) -> Result<(BmpMessagePeerUp,usize), BgpError> {
        if buf.len()<62 {
            return Err(BgpError::insufficient_buffer_size());
        }
        let pm = BmpMessagePeerHeader::decode_from(buf)?;
        let mut ret=BmpMessagePeerUp{
            peer: pm.0,
            localaddress: decode_bmp_addr_from(&buf[pm.1..])?,
            localport: getn_u16(&buf[pm.1+16..]),
            remoteport: getn_u16(&buf[pm.1+18..]),
            msg1: BgpOpenMessage::new(),
            msg2: BgpOpenMessage::new(),
        };
        let sesspars=BgpSessionParams::new(ret.peer.asnum, 180, ret.peer.peeraddress.into(), ret.peer.routerid, Vec::new());
        let mut pos:usize=pm.1+20;
        let msgt=sesspars.decode_message_head(&buf[pos..])?;
        pos+=19;
        if msgt.0!=BgpMessageType::Open {
            return Err(BgpError::static_str("Invalid BGP message type #1"))
        }
        ret.msg1.decode_from(&sesspars, &buf[pos..pos+msgt.1])?;
        pos+=msgt.1;
        let msgt=sesspars.decode_message_head(&buf[pos..])?;
        pos+=19;
        if msgt.0!=BgpMessageType::Open {
            return Err(BgpError::static_str("Invalid BGP message type #2"))
        }
        ret.msg2.decode_from(&sesspars, &buf[pos..pos+msgt.1])?;
        pos+=msgt.1;
        Ok((ret,pos))
    }
}

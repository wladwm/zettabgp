// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP Monitoring Protocol (BMP) processing - https://tools.ietf.org/html/rfc7854

mod bmputl;
mod msginit;
mod msgpeer;
mod msgrmon;
mod msgterm;
pub mod prelude;

use crate::prelude::*;
use bmputl::*;
use msginit::BmpMessageInitiation;
use msgpeer::{BmpMessagePeerUp, BmpMessagePeerDown};
use msgrmon::BmpMessageRouteMonitoring;
use msgterm::BmpMessageTermination;
use std::collections::BTreeMap;

impl From<core::str::Utf8Error> for BgpError {
    #[inline]
    fn from(error: core::str::Utf8Error) -> Self {
        BgpError::Other(Box::new(error))
    }
}

///BGP session key
#[derive(Debug, PartialEq, PartialOrd, Eq, Ord)]
pub struct BgpSessionKey {
    pub peer_rd: BgpRD,
    pub peer_ip: std::net::IpAddr,
}
impl BgpSessionKey {
    pub fn new(peer_rd: BgpRD, peer_ip: std::net::IpAddr) -> BgpSessionKey {
        BgpSessionKey { peer_rd, peer_ip }
    }
}
impl From<&BmpMessagePeerHeader> for BgpSessionKey {
    fn from(peer: &BmpMessagePeerHeader) -> BgpSessionKey {
        BgpSessionKey {
            peer_rd: peer.peerdistinguisher.clone(),
            peer_ip: peer.peeraddress,
        }
    }
}
///BMP Session
#[derive(Default)]
pub struct BMPSession {
    pub sessions: BTreeMap<BgpSessionKey, BmpMessagePeerUp>,
}
impl BMPSession {
    pub fn decode_from(&mut self, buf: &[u8]) -> Result<BmpMessage, BgpError> {
        let msgtype = buf[0];
        match msgtype {
            0 => {
                let rm = self.decode_rm(&buf[1..])?;
                Ok(BmpMessage::RouteMonitoring(rm))
            }
            1 => Ok(BmpMessage::StatisticsReport),
            2 => {
                let peerdown = BmpMessagePeerDown::decode_from(&buf[1..])?.0;
                self.sessions.remove(&BgpSessionKey::from(&peerdown.peer));
                Ok(BmpMessage::PeerDownNotification(peerdown))
            }
            3 => {
                let peerup = BmpMessagePeerUp::decode_from(&buf[1..])?.0;
                self.sessions
                    .insert(BgpSessionKey::from(&peerup.peer), peerup.clone());
                Ok(BmpMessage::PeerUpNotification(peerup))
            }
            4 => Ok(BmpMessage::Initiation(
                BmpMessageInitiation::decode_from(&buf[1..])?.0,
            )),
            5 => Ok(BmpMessage::Termination(
                BmpMessageTermination::decode_from(&buf[1..])?.0,
            )),
            6 => Ok(BmpMessage::RouteMirroring),
            _ => Err(BgpError::static_str("Invalid BMP message type")),
        }
    }
    fn decode_rm(&self, buf: &[u8]) -> Result<BmpMessageRouteMonitoring, BgpError> {
        if buf.len() < 62 {
            return Err(BgpError::InsufficientBufferSize);
        }
        let pm = BmpMessagePeerHeader::decode_from(buf)?;
        let mut pos = pm.1;
        let sesskey = BgpSessionKey::from(&pm.0);
        let sesspars: BgpSessionParams = match self.sessions.get(&sesskey) {
            None => (&pm.0).into(),
            Some(peer) => {
                if peer.peer.routerid == peer.msg1.router_id {
                    BgpSessionParams::from(&peer.msg1)
                } else {
                    BgpSessionParams::from(&peer.msg2)
                }
            }
        };
        let msgt = sesspars.decode_message_head(&buf[pos..])?;
        pos += 19;
        if msgt.0 != BgpMessageType::Update {
            return Err(BgpError::static_str(
                "Invalid BGP message type for BmpMessageRouteMonitoring",
            ));
        }
        let mut upd = BgpUpdateMessage::new();
        upd.decode_from(&sesspars, &buf[pos..pos + msgt.1])?;
        //pos += msgt.1;
        Ok(BmpMessageRouteMonitoring {
            peer: pm.0,
            update: upd,
        })
    }
}
/// BMP message
#[derive(Debug)]
pub enum BmpMessage {
    RouteMonitoring(BmpMessageRouteMonitoring), //0
    StatisticsReport,                           //1
    PeerDownNotification(BmpMessagePeerDown),   //2
    PeerUpNotification(BmpMessagePeerUp),       //3
    Initiation(BmpMessageInitiation),           //4
    Termination(BmpMessageTermination),         //5
    RouteMirroring,                             //6
}

/// BMP message header
#[derive(Debug)]
pub struct BmpMessageHeader {
    /// version - always 3
    pub version: u8,
    /// total message length in bytes
    pub msglength: usize,
}

impl BmpMessageHeader {
    pub fn decode_from(buf: &[u8]) -> Result<(BmpMessageHeader, usize), BgpError> {
        if buf.len() < 5 {
            return Err(BgpError::insufficient_buffer_size());
        }
        if buf[0] != 3 {
            return Err(BgpError::static_str("BMP packet version != 3"));
        }
        Ok((
            BmpMessageHeader {
                version: buf[0],
                msglength: getn_u32(&buf[1..5]) as usize,
            },
            5,
        ))
    }
}

impl BmpMessage {
    pub fn decode_from(buf: &[u8]) -> Result<BmpMessage, BgpError> {
        let msgtype = buf[0];
        match msgtype {
            0 => Ok(BmpMessage::RouteMonitoring(
                BmpMessageRouteMonitoring::decode_from(&buf[1..])?.0,
            )),
            1 => Ok(BmpMessage::StatisticsReport),
            2 => Ok(BmpMessage::PeerDownNotification(
                BmpMessagePeerDown::decode_from(&buf[1..])?.0,
            )),
            3 => Ok(BmpMessage::PeerUpNotification(
                BmpMessagePeerUp::decode_from(&buf[1..])?.0,
            )),
            4 => Ok(BmpMessage::Initiation(
                BmpMessageInitiation::decode_from(&buf[1..])?.0,
            )),
            5 => Ok(BmpMessage::Termination(
                BmpMessageTermination::decode_from(&buf[1..])?.0,
            )),
            6 => Ok(BmpMessage::RouteMirroring),
            _ => Err(BgpError::static_str("Invalid BMP message type")),
        }
    }
}

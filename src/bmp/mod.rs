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

use crate::*;
use msginit::BmpMessageInitiation;
use msgpeer::BmpMessagePeerUp;
use msgrmon::BmpMessageRouteMonitoring;
use msgterm::BmpMessageTermination;

impl From<core::str::Utf8Error> for BgpError {
    #[inline]
    fn from(error: core::str::Utf8Error) -> Self {
        BgpError::Other(Box::new(error))
    }
}

/// BMP message
#[derive(Debug)]
pub enum BmpMessage {
    RouteMonitoring(BmpMessageRouteMonitoring), //0
    StatisticsReport,                           //1
    PeerDownNotification,                       //2
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
            2 => Ok(BmpMessage::PeerDownNotification),
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

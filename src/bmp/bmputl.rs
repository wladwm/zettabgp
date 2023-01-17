// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Some BMP utilities

use crate::afi::*;
use crate::*;
use std::cmp::Ordering;

pub fn decode_bmp_addr_from(buf: &[u8]) -> Result<std::net::IpAddr, BgpError> {
    if buf.len() < 16 {
        return Err(BgpError::insufficient_buffer_size());
    }
    if buf[0] == 0
        && buf[1] == 0
        && buf[2] == 0
        && buf[3] == 0
        && buf[4] == 0
        && buf[5] == 0
        && buf[6] == 0
        && buf[7] == 0
        && buf[8] == 0
        && buf[9] == 0
        && buf[10] == 0
        && buf[11] == 0
    {
        Ok(std::net::IpAddr::V4(decode_addrv4_from(&buf[12..])?))
    } else {
        Ok(std::net::IpAddr::V6(decode_addrv6_from(buf)?))
    }
}

/// peer header
#[derive(Debug, Clone)]
pub struct BmpMessagePeerHeader {
    /// peer type code
    pub peertype: u8,
    /// flags
    pub flags: u8,
    /// route distinguisher of VRF of this peer
    pub peerdistinguisher: BgpRD,
    /// peer IP address
    pub peeraddress: std::net::IpAddr,
    /// peer AS number
    pub asnum: u32,
    /// peer router ID
    pub routerid: std::net::Ipv4Addr,
    /// timestamp
    pub timestamp: u64,
}

impl BmpMessagePeerHeader {
    pub fn decode_from(buf: &[u8]) -> Result<(BmpMessagePeerHeader, usize), BgpError> {
        if buf.len() < 42 {
            return Err(BgpError::InsufficientBufferSize);
        }
        Ok((
            BmpMessagePeerHeader {
                peertype: buf[0],
                flags: buf[1],
                peerdistinguisher: BgpRD::decode_from(BgpTransportMode::IPv4, &buf[2..])?.0,
                peeraddress: decode_bmp_addr_from(&buf[10..])?,
                asnum: getn_u32(&buf[26..]),
                routerid: decode_addrv4_from(&buf[30..])?,
                timestamp: getn_u64(&buf[34..]),
            },
            42,
        ))
    }
}
impl PartialOrd for BmpMessagePeerHeader {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if let Some(pc) = self.peertype.partial_cmp(&other.peertype) {
            match pc {
                Ordering::Less => return Some(Ordering::Less),
                Ordering::Greater => return Some(Ordering::Greater),
                Ordering::Equal => {}
            }
        };
        if let Some(pc) = self.flags.partial_cmp(&other.flags) {
            match pc {
                Ordering::Less => return Some(Ordering::Less),
                Ordering::Greater => return Some(Ordering::Greater),
                Ordering::Equal => {}
            }
        };
        if let Some(pc) = self.peerdistinguisher.partial_cmp(&other.peerdistinguisher) {
            match pc {
                Ordering::Less => return Some(Ordering::Less),
                Ordering::Greater => return Some(Ordering::Greater),
                Ordering::Equal => {}
            }
        };
        if let Some(pc) = self.peeraddress.partial_cmp(&other.peeraddress) {
            match pc {
                Ordering::Less => return Some(Ordering::Less),
                Ordering::Greater => return Some(Ordering::Greater),
                Ordering::Equal => {}
            }
        };
        if let Some(pc) = self.asnum.partial_cmp(&other.asnum) {
            match pc {
                Ordering::Less => return Some(Ordering::Less),
                Ordering::Greater => return Some(Ordering::Greater),
                Ordering::Equal => {}
            }
        };
        self.routerid.partial_cmp(&other.routerid)
    }
}
impl Ord for BmpMessagePeerHeader {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.peertype.cmp(&other.peertype) {
            Ordering::Equal => {}
            x => return x,
        };
        match self.flags.cmp(&other.flags) {
            Ordering::Equal => {}
            x => return x,
        };
        match self.peerdistinguisher.cmp(&other.peerdistinguisher) {
            Ordering::Equal => {}
            x => return x,
        };
        match self.peeraddress.cmp(&other.peeraddress) {
            Ordering::Equal => {}
            x => return x,
        };
        match self.asnum.cmp(&other.asnum) {
            Ordering::Equal => {}
            x => return x,
        };
        self.routerid.cmp(&other.routerid)
    }
}

impl PartialEq for BmpMessagePeerHeader {
    fn eq(&self, other: &Self) -> bool {
        self.peertype == other.peertype
            && self.flags == other.flags
            && self.peerdistinguisher == other.peerdistinguisher
            && self.peeraddress == other.peeraddress
            && self.asnum == other.asnum
            && self.routerid == other.routerid
    }
}
impl Eq for BmpMessagePeerHeader {}
impl From<&BmpMessagePeerHeader> for BgpSessionParams {
    #[inline]
    fn from(bmph: &BmpMessagePeerHeader) -> BgpSessionParams {
        BgpSessionParams::new(
            bmph.asnum,
            0,
            bmph.peeraddress.into(),
            bmph.routerid,
            Vec::new(),
        )
    }
}

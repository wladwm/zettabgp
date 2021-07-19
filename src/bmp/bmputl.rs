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
        return Ok(std::net::IpAddr::V4(decode_addrv4_from(&buf[12..])?));
    }
    return Ok(std::net::IpAddr::V6(decode_addrv6_from(buf)?));
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
impl From<&BmpMessagePeerHeader> for BgpSessionParams {
    #[inline]
    fn from(bmph: &BmpMessagePeerHeader) -> BgpSessionParams {
        BgpSessionParams::new(
            bmph.asnum,
            0,
            bmph.peeraddress.into(),
            bmph.routerid,
            std::collections::HashSet::new(),
        )
    }
}
impl BmpMessagePeerHeader {
    pub fn decode_from(buf: &[u8]) -> Result<(BmpMessagePeerHeader, usize), BgpError> {
        if buf.len() < 42 {
            return Err(BgpError::insufficient_buffer_size());
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

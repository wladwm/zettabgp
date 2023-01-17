// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module contains some internal utilities

use crate::error::BgpError;

/// Gets ipv4 address from the buffer.
pub fn decode_addrv4_from(buf: &[u8]) -> Result<std::net::Ipv4Addr, BgpError> {
    if buf.len() < 4 {
        return Err(BgpError::static_str("Invalid addrv4 length"));
    }
    Ok(std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]))
}
/// Stores ipv4 address into the buffer.
pub fn encode_addrv4_to(addr: &std::net::Ipv4Addr, buf: &mut [u8]) -> Result<usize, BgpError> {
    if buf.len() < 4 {
        return Err(BgpError::static_str("Invalid addrv4 length"));
    }
    buf[0..4].clone_from_slice(&addr.octets());
    Ok(4)
}
/// Gets ipv6 address from the buffer.
pub fn decode_addrv6_from(buf: &[u8]) -> Result<std::net::Ipv6Addr, BgpError> {
    if buf.len() < 16 {
        return Err(BgpError::static_str("Invalid addrv6 length"));
    }
    Ok(std::net::Ipv6Addr::new(
        getn_u16(&buf[0..2]),
        getn_u16(&buf[2..4]),
        getn_u16(&buf[4..6]),
        getn_u16(&buf[6..8]),
        getn_u16(&buf[8..10]),
        getn_u16(&buf[10..12]),
        getn_u16(&buf[12..14]),
        getn_u16(&buf[14..16]),
    ))
}
/// Stores ipv6 address into the buffer.
pub fn encode_addrv6_to(addr: &std::net::Ipv6Addr, buf: &mut [u8]) -> Result<usize, BgpError> {
    if buf.len() < 16 {
        return Err(BgpError::static_str("Invalid addrv6 length"));
    }
    buf[0..16].clone_from_slice(&addr.octets());
    Ok(16)
}
/// Gets ipv4/ipv6 address from the buffer. Address type determined by buffer length.
pub fn decode_addr_from(buf: &[u8]) -> Result<std::net::IpAddr, BgpError> {
    match buf.len() {
        16 => Ok(std::net::IpAddr::V6(decode_addrv6_from(buf)?)),
        4 => Ok(std::net::IpAddr::V4(decode_addrv4_from(buf)?)),
        _ => Err(BgpError::static_str("Invalid addr length")),
    }
}
/// Stores ipv4/ipv6 address into the buffer.
pub fn encode_addr_to(addr: &std::net::IpAddr, buf: &mut [u8]) -> Result<usize, BgpError> {
    match addr {
        std::net::IpAddr::V4(a) => encode_addrv4_to(a, buf),
        std::net::IpAddr::V6(a) => encode_addrv6_to(a, buf),
    }
}
pub fn ntoh16(a: u16) -> u16 {
    (a >> 8) | ((a & 0xff) << 8)
}
pub fn setn_u16(s: u16, a: &mut [u8]) {
    a[0] = (s >> 8) as u8;
    a[1] = (s & 0xff) as u8;
}
pub fn getn_u16(a: &[u8]) -> u16 {
    (a[0] as u16) << 8 | (a[1] as u16)
}
pub fn getn_u32(a: &[u8]) -> u32 {
    (a[0] as u32) << 24 | (a[1] as u32) << 16 | (a[2] as u32) << 8 | (a[3] as u32)
}
pub fn setn_u32(s: u32, a: &mut [u8]) {
    a[0] = (s >> 24) as u8;
    a[1] = ((s >> 16) & 0xff) as u8;
    a[2] = ((s >> 8) & 0xff) as u8;
    a[3] = (s & 0xff) as u8;
}
pub fn getn_u64(a: &[u8]) -> u64 {
    ((getn_u32(a) as u64) << 32) | (getn_u32(&a[4..8]) as u64)
}
pub fn getn_u128(a: &[u8]) -> u128 {
    ((getn_u64(a) as u128) << 64) | (getn_u64(&a[8..16]) as u128)
}
pub(crate) fn is_addpath_nlri(b:&[u8]) -> bool {
    if b.len()<5 {
        false
    } else {
        b[0]==0 && b[1]==0
    }
}

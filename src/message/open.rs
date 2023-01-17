// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{ntoh16, BgpCapability, BgpError, BgpMessage, BgpSessionParams};
use std::vec::Vec;
/// BGP open message
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BgpOpenMessage {
    /// Autonomous system number
    pub as_num: u32,
    /// Hold time in seconds
    pub hold_time: u16,
    /// router Id
    pub router_id: std::net::Ipv4Addr,
    /// Capability set
    pub caps: Vec<BgpCapability>,
}

#[repr(C, packed)]
struct BgpOpenHead {
    as_num: u16,
    hold_time: u16,
    routerid: [u8; 4],
    caplen: u8,
}

impl BgpMessage for BgpOpenMessage {
    fn decode_from(&mut self, _peer: &BgpSessionParams, buf: &[u8]) -> Result<(), BgpError> {
        if buf[0] != 4 {
            return Err(BgpError::static_str("Invalid BGP version <> 4"));
        }
        if buf.len() < 10 {
            return Err(BgpError::InsufficientBufferSize);
        }
        let ptr: *const u8 = buf[1..].as_ptr();
        let ptr: *const BgpOpenHead = ptr as *const BgpOpenHead;
        let ptr: &BgpOpenHead = unsafe { &*ptr };
        self.as_num = ntoh16(ptr.as_num) as u32;
        self.hold_time = ntoh16(ptr.hold_time);
        self.router_id = std::net::Ipv4Addr::new(
            ptr.routerid[0],
            ptr.routerid[1],
            ptr.routerid[2],
            ptr.routerid[3],
        );
        self.caps.clear();
        let mut pos: usize = 10;
        while pos < buf.len() {
            if buf[pos] != 2 {
                return Err(BgpError::from_string(format!(
                    "Invalid optional parameter in BGP open message {:?}!",
                    buf[pos]
                )));
            }
            let mut optlen = buf[pos + 1] as usize;
            pos += 2;
            while optlen > 0 {
                let maybe_cap = BgpCapability::from_buffer(&buf[pos..pos+optlen])?;
                optlen -= maybe_cap.1;
                pos += maybe_cap.1;
                match maybe_cap.0 {
                    Ok(cap) => self.caps.push(cap),
                    Err((captype, data)) => eprintln!("warning: unknown capability code {} data {:x?}", captype, data),
                }
            }
        }
        Ok(())
    }
    fn encode_to(&self, _peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        let ptr: *mut u8 = buf[1..].as_mut_ptr();
        let ptr: *mut BgpOpenHead = ptr as *mut BgpOpenHead;
        let ptr: &mut BgpOpenHead = unsafe { &mut *ptr };
        buf[0] = 4;
        ptr.as_num = ntoh16(if self.as_num < 65536 {
            self.as_num as u16
        } else {
            23456
        });
        ptr.hold_time = ntoh16(self.hold_time);
        ptr.routerid = self.router_id.octets();
        ptr.caplen = self
            .caps
            .iter()
            .fold(0u32, |sum, i| sum + (i.bytes_len() as u32) + 2) as u8;
        let mut pos: usize = 10;
        for cp in self.caps.iter() {
            let caplen = cp.bytes_len();
            buf[pos] = 2; //capability
            buf[pos + 1] = caplen as u8;
            cp.fill_buffer(&mut buf[(pos + 2)..(caplen + pos + 2)])?;
            pos += 2 + caplen;
        }
        Ok(pos)
    }
}
impl BgpOpenMessage {
    pub fn new() -> BgpOpenMessage {
        BgpOpenMessage {
            as_num: 0,
            hold_time: 180,
            router_id: std::net::Ipv4Addr::new(127, 0, 0, 1),
            caps: Vec::new(),
        }
    }
}
impl Default for BgpOpenMessage {
    fn default() -> Self {
        Self::new()
    }
}

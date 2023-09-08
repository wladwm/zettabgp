// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{ntoh16, slice, slice_mut, BgpCapability, BgpError, BgpMessage, BgpSessionParams};
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
        if buf.len() < 10 {
            return Err(BgpError::InsufficientBufferSize);
        }
        if buf[0] != 4 {
            return Err(BgpError::static_str("Invalid BGP version <> 4"));
        }
        let ptr: *const u8 = slice(buf, 1, buf.len())?.as_ptr();
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
        while pos + 1 < buf.len() {
            if buf[pos] != 2 {
                return Err(BgpError::from_string(format!(
                    "Invalid optional parameter in BGP open message {:?}!",
                    buf[pos]
                )));
            }
            let mut optlen = buf[pos + 1] as usize;
            pos += 2;
            while optlen > 0 {
                let maybe_cap = BgpCapability::from_buffer(slice(buf, pos, pos + optlen)?)?;
                optlen -= maybe_cap.1;
                pos += maybe_cap.1;
                match maybe_cap.0 {
                    Ok(cap) => self.caps.push(cap),
                    Err((captype, data)) => log::trace!(
                        "ignoring unknown capability code {} data {:x?}",
                        captype,
                        data
                    ),
                }
            }
        }
        Ok(())
    }
    fn encode_to(&self, _peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        if buf.len() < 10 {
            return Err(BgpError::InsufficientBufferSize);
        }
        let ptr: *mut u8 = slice_mut(buf, 1, buf.len())?.as_mut_ptr();
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
            cp.fill_buffer(slice_mut(buf, pos + 2, caplen + pos + 2)?)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BgpTransportMode;

    #[test]
    fn test_good_open() {
        // Setup
        let mut buf = vec![0_u8; 4096];
        let caps = vec![
            BgpCapability::SafiIPv4u,
            BgpCapability::CapRR,
            BgpCapability::CapASN32(65450),
        ];
        let params = BgpSessionParams::new(
            65001,
            30,
            BgpTransportMode::IPv4,
            "10.0.0.1".parse().unwrap(),
            caps.clone(),
        );
        let msg = BgpOpenMessage {
            as_num: 200,
            router_id: "10.0.0.1".parse().unwrap(),
            caps,
            hold_time: 180,
        };

        let encode = msg.encode_to(&params, &mut buf);
        assert!(encode.is_ok());

        let mut decode_msg = BgpOpenMessage::new();

        // Trucate to fit encoded message length
        buf.truncate(encode.unwrap());

        let decode = decode_msg.decode_from(&params, &buf);
        match decode {
            Ok(_) => {
                assert_eq!(decode_msg.as_num, msg.as_num);
                assert_eq!(decode_msg.hold_time, msg.hold_time);
                assert_eq!(decode_msg.router_id, msg.router_id,);
                assert_eq!(decode_msg.caps.len(), msg.caps.len());
                for c in decode_msg.caps.iter() {
                    assert!(msg.caps.contains(c));
                }
            }
            _ => panic!("incorrect decode: {:?}", decode),
        }
    }

    #[test]
    fn test_concatenated_open() {
        // Setup
        let mut buf = vec![0_u8; 4096];
        let caps = vec![
            BgpCapability::SafiIPv4u,
            BgpCapability::CapRR,
            BgpCapability::CapASN32(65450),
        ];
        let params = BgpSessionParams::new(
            65001,
            30,
            BgpTransportMode::IPv4,
            "10.0.0.1".parse().unwrap(),
            caps.clone(),
        );
        let msg = BgpOpenMessage {
            as_num: 200,
            router_id: "10.0.0.1".parse().unwrap(),
            caps,
            hold_time: 180,
        };

        let encode = msg.encode_to(&params, &mut buf);
        assert!(encode.is_ok());

        let encode = msg.encode_to(&params, &mut buf);
        assert!(encode.is_ok());

        // Trucate to fit encoded message length
        buf.truncate(encode.unwrap());

        let mut decode_msg = BgpOpenMessage::new();
        let decode = decode_msg.decode_from(&params, &buf);
        match decode {
            Ok(_) => {
                assert_eq!(decode_msg.as_num, msg.as_num);
                assert_eq!(decode_msg.hold_time, msg.hold_time);
                assert_eq!(decode_msg.router_id, msg.router_id);
                assert_eq!(decode_msg.caps.len(), msg.caps.len());
                for c in decode_msg.caps.iter() {
                    assert!(params.caps.contains(c), "caps.contains(): {:?}", c);
                }
            }
            _ => panic!("incorrect decode: {:?}", decode),
        }

        let mut decode_msg = BgpOpenMessage::new();
        let decode = decode_msg.decode_from(&params, &buf);
        match decode {
            Ok(_) => {
                assert_eq!(decode_msg.as_num, msg.as_num);
                assert_eq!(decode_msg.hold_time, msg.hold_time);
                assert_eq!(decode_msg.router_id, msg.router_id);
                assert_eq!(decode_msg.caps.len(), msg.caps.len());
                for c in decode_msg.caps.iter() {
                    assert!(params.caps.contains(c), "caps.contains(): {:?}", c);
                }
            }
            _ => panic!("incorrect decode: {:?}", decode),
        }
    }

    #[test]
    fn test_bad_open_decode_length() {
        // Setup
        let mut buf = vec![0_u8; 4096];
        let caps = vec![
            BgpCapability::SafiIPv4u,
            BgpCapability::CapRR,
            BgpCapability::CapASN32(65450),
        ];
        let params = BgpSessionParams::new(
            65001,
            30,
            BgpTransportMode::IPv4,
            "10.0.0.1".parse().unwrap(),
            caps.clone(),
        );
        let mut msg = BgpOpenMessage {
            as_num: 200,
            router_id: "10.0.0.1".parse().unwrap(),
            caps,
            hold_time: 180,
        };

        let encode = msg.encode_to(&params, &mut buf);
        assert!(encode.is_ok());

        // Truncate encoded cap data
        let truncate_amount = 3;
        buf.truncate(encode.unwrap() - truncate_amount as usize);
        let decode = msg.decode_from(&params, &buf);
        assert!(matches!(decode, Err(BgpError::InsufficientBufferSize)));
    }

    #[test]
    fn test_bad_open_bgp_version() {
        // Setup
        let mut buf = vec![0_u8; 4096];
        let caps = vec![
            BgpCapability::SafiIPv4u,
            BgpCapability::CapRR,
            BgpCapability::CapASN32(65450),
        ];
        let params = BgpSessionParams::new(
            65001,
            30,
            BgpTransportMode::IPv4,
            "10.0.0.1".parse().unwrap(),
            caps.clone(),
        );
        let msg = BgpOpenMessage {
            as_num: 200,
            router_id: "10.0.0.1".parse().unwrap(),
            caps,
            hold_time: 180,
        };

        let encode = msg.encode_to(&params, &mut buf);
        assert!(encode.is_ok());

        // Set bgp version to be 3
        buf[0] = 3;

        let mut decode_msg = BgpOpenMessage::new();
        let decode = decode_msg.decode_from(&params, &buf);
        assert!(matches!(
            decode,
            Err(BgpError::Static("Invalid BGP version <> 4"))
        ));
    }

    #[test]
    fn test_bad_open_decode_empty() {
        // Setup
        let buf = vec![0_u8; 0];
        let caps = vec![
            BgpCapability::SafiIPv4u,
            BgpCapability::CapRR,
            BgpCapability::CapASN32(65450),
        ];
        let params = BgpSessionParams::new(
            65001,
            30,
            BgpTransportMode::IPv4,
            "10.0.0.1".parse().unwrap(),
            caps,
        );

        let mut decode_msg = BgpOpenMessage::new();
        let decode = decode_msg.decode_from(&params, &buf);
        assert!(matches!(decode, Err(BgpError::InsufficientBufferSize)));
    }

    #[test]
    fn test_bad_open_missing_optlen() {
        // Setup
        let mut buf = vec![0_u8; 4096];
        let caps = vec![
            BgpCapability::SafiIPv4u,
            BgpCapability::CapRR,
            BgpCapability::CapASN32(65450),
        ];
        let params = BgpSessionParams::new(
            65001,
            30,
            BgpTransportMode::IPv4,
            "10.0.0.1".parse().unwrap(),
            caps.clone(),
        );
        let msg = BgpOpenMessage {
            as_num: 200,
            router_id: "10.0.0.1".parse().unwrap(),
            caps,
            hold_time: 180,
        };

        let encode = msg.encode_to(&params, &mut buf);
        assert!(encode.is_ok());

        // Truncate to remove optlen
        buf.truncate(10_usize);

        let mut decode_msg = BgpOpenMessage::new();
        let decode = decode_msg.decode_from(&params, &buf);
        assert!(decode.is_ok());
    }

    #[test]
    fn test_bad_open_encode_empty() {
        // Setup
        let mut buf = vec![0_u8; 0];
        let caps = vec![
            BgpCapability::SafiIPv4u,
            BgpCapability::CapRR,
            BgpCapability::CapASN32(65450),
        ];
        let params = BgpSessionParams::new(
            65001,
            30,
            BgpTransportMode::IPv4,
            "10.0.0.1".parse().unwrap(),
            caps.clone(),
        );
        let msg = BgpOpenMessage {
            as_num: 200,
            router_id: "10.0.0.1".parse().unwrap(),
            caps,
            hold_time: 180,
        };

        let encode = msg.encode_to(&params, &mut buf);
        assert!(matches!(encode, Err(BgpError::InsufficientBufferSize)));
    }

    #[test]
    fn test_bad_open_encode_length() {
        // Setup
        let mut buf = vec![0_u8; 20];
        let caps = vec![
            BgpCapability::SafiIPv4u,
            BgpCapability::CapRR,
            BgpCapability::CapASN32(65450),
        ];
        let params = BgpSessionParams::new(
            65001,
            30,
            BgpTransportMode::IPv4,
            "10.0.0.1".parse().unwrap(),
            caps.clone(),
        );
        let msg = BgpOpenMessage {
            as_num: 200,
            router_id: "10.0.0.1".parse().unwrap(),
            caps,
            hold_time: 180,
        };

        let encode = msg.encode_to(&params, &mut buf);
        assert!(matches!(encode, Err(BgpError::InsufficientBufferSize)));
    }
}

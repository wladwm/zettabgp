// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This is a BGP and BMP protocols driver library for Rust.
//!
//!  * BGP - Border Gateway Protocol version 4.
//!  * BMP - BGP Monitoring Protocol version 3.
//!
//! ## Supported BGP message types
//!  * Open
//!  * Notification
//!  * Keepalive
//!  * Update
//!
//! ## Supported BMP message types
//!  * Initiation
//!  * Termination
//!  * PeerUpNotification
//!  * RouteMonitoring
//!
//! ## Supported address families NLRI (network layer reachability information)
//!  * ipv4 unicast
//!  * ipv4 labeled-unicast
//!  * ipv4 multicast
//!  * ipv4 mvpn
//!  * vpnv4 unicast
//!  * vpnv4 multicast
//!  * ipv6 unicast
//!  * ipv6 labeled-unicast
//!  * ipv6 multicast
//!  * vpnv6 unicast
//!  * vpnv6 multicast
//!  * vpls
//!  * evpn
//!  * flowspec ipv4
//!  * flowspec ipv6
//!
//! ## Supported path attributes
//!  * MED
//!  * Origin
//!  * Local preference
//!  * AS path
//!  * Communities
//!  * Extended communities
//!  * Aggregator AS
//!  * Atomic aggregate
//!  * Cluster list
//!  * Originator ID
//!  * Attribute set
//!  * some PMSI tunnels
//!
//! # Quick Start
//!
//! Library allow you to parse protocol messages (as binary buffers) into Rust data structures to frther processing.
//! Or generate valid protocol messages from Rust data structure.
//! So it can be use in any environment (synrchronous or asynchronous) to make a BGP RR, monitoring system or BGP analytics.
//!
//! ```
//! use zettabgp::prelude::*;
//! use std::io::{Read,Write};
//! let mut socket = match std::net::TcpStream::connect("127.0.0.1:179") {
//!  Ok(sck) => sck,
//!  Err(e) => {eprintln!("Unable to connect to BGP neighbor: {}",e);return;}
//! };
//! let params=BgpSessionParams::new(64512,180,BgpTransportMode::IPv4,std::net::Ipv4Addr::new(1,1,1,1),vec![BgpCapability::SafiIPv4u].into_iter().collect());
//! let mut buf = [0 as u8; 32768];
//! let mut open_my = params.open_message();
//! let open_sz = open_my.encode_to(&params, &mut buf[19..]).unwrap();
//! let tosend = params.prepare_message_buf(&mut buf, BgpMessageType::Open, open_sz).unwrap();
//! socket.write_all(&buf[0..tosend]).unwrap();//send my open message
//! socket.read_exact(&mut buf[0..19]).unwrap();//read response message head
//! let messagehead=params.decode_message_head(&buf).unwrap();//decode message head
//! if messagehead.0 == BgpMessageType::Open {
//!   socket.read_exact(&mut buf[0..messagehead.1]).unwrap();//read message body
//!   let mut bom = BgpOpenMessage::new();
//!   bom.decode_from(&params, &buf[0..messagehead.1]).unwrap();//decode received message body
//!   eprintln!("BGP Open message received: {:?}", bom);
//! }
//! ```
//!
#[cfg(feature = "serialization")]
extern crate serde;

pub mod afi;
pub mod bmp;
pub mod error;
pub mod message;
pub mod prelude;
pub mod util;

use error::*;
use message::open::*;
use util::*;

/// BGP session transport - ipv4 or ipv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpTransportMode {
    IPv4,
    IPv6,
}

impl From<std::net::IpAddr> for BgpTransportMode {
    #[inline]
    fn from(addr: std::net::IpAddr) -> Self {
        match addr {
            std::net::IpAddr::V4(_) => BgpTransportMode::IPv4,
            std::net::IpAddr::V6(_) => BgpTransportMode::IPv6,
        }
    }
}

/// This trait represens BGP protocol message.
pub trait BgpMessage {
    /// Decode from buffer.
    fn decode_from(&mut self, peer: &BgpSessionParams, buf: &[u8]) -> Result<(), BgpError>;
    /// Encode to buffer. Returns consumed buffer length, or error.
    fn encode_to(&self, peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError>;
}

/// This trait represens NLRI which have sequental chain encoding with opaque length.
pub trait BgpAddrItem<T: std::marker::Sized> {
    /// Decode from buffer. Returns entity and consumed buffer length, or error.
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(T, usize), BgpError>;
    /// Encode entity into the buffer. Returns consumed buffer length, or error.
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError>;
}

/// BGP capability GR
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BgpCapGR {
    pub afi: u16,
    pub safi: u8,
    pub forwarding_state: bool,
}

fn afisafi_from_cap(cap: BgpCapability) -> Result<(u16, u8), BgpError> {
    let (afi, safi) = match cap {
        BgpCapability::SafiIPv4u => (1, 1),
        BgpCapability::SafiIPv4m => (1, 2),
        BgpCapability::SafiIPv4mvpn => (1, 5),
        BgpCapability::SafiIPv4mdt => (1, 66),
        BgpCapability::SafiVPNv4u => (1, 128),
        BgpCapability::SafiVPNv4m => (1, 129),
        BgpCapability::SafiIPv4lu => (1, 4),
        BgpCapability::SafiIPv6u => (2, 1),
        BgpCapability::SafiIPv6lu => (2, 4),
        BgpCapability::SafiIPv6mdt => (2, 66),
        BgpCapability::SafiVPNv6u => (2, 128),
        BgpCapability::SafiVPNv6m => (2, 129),
        BgpCapability::SafiVPLS => (25, 65),
        BgpCapability::SafiEVPN => (25, 70),
        _ => return Err(BgpError::static_str("Invalid base capability")),
    };
    Ok((afi, safi))
}

impl BgpCapGR {
    pub fn new_from_cap(
        base_safi: BgpCapability,
        forwarding_state: bool,
    ) -> Result<BgpCapGR, BgpError> {
        let afisafi: (u16, u8) = afisafi_from_cap(base_safi)?;
        Ok(BgpCapGR {
            afi: afisafi.0,
            safi: afisafi.1,
            forwarding_state,
        })
    }
    pub fn encode_to(&self, buf: &mut [u8]) -> Result<(), BgpError> {
        if buf.len() < 4 {
            return Err(BgpError::insufficient_buffer_size());
        }
        setn_u16(self.afi, &mut buf[0..2]);
        buf[2] = self.safi;
        buf[3] = 0;
        if self.forwarding_state {
            buf[3] |= 128;
        }
        Ok(())
    }
    pub fn decode_from(buf: &[u8]) -> Result<BgpCapGR, BgpError> {
        if buf.len() < 4 {
            return Err(BgpError::insufficient_buffer_size());
        }
        Ok(BgpCapGR {
            afi: getn_u16(&buf[0..2]),
            safi: buf[2],
            forwarding_state: buf[3] & 128 != 0,
        })
    }
}
/// BGP capability LLGR
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BgpCapLLGR {
    pub afi: u16,
    pub safi: u8,
    pub flags: u8,
    pub stale_time: u32,
}

impl BgpCapLLGR {
    pub fn new_from_cap(
        base_safi: BgpCapability,
        flags: u8,
        stale_time: u32,
    ) -> Result<BgpCapLLGR, BgpError> {
        let afisafi: (u16, u8) = afisafi_from_cap(base_safi)?;
        if stale_time.leading_zeros() < 8 {
            return Err(BgpError::static_str("stale_time must fit into 24 bits"));
        }
        Ok(BgpCapLLGR {
            afi: afisafi.0,
            safi: afisafi.1,
            flags,
            stale_time,
        })
    }
    pub fn encode_to(&self, buf: &mut [u8]) -> Result<(), BgpError> {
        if buf.len() < 7 {
            return Err(BgpError::insufficient_buffer_size());
        }
        if self.stale_time.leading_zeros() < 8 {
            return Err(BgpError::static_str("stale_time must fit into 24 bits"));
        }
        setn_u16(self.afi, &mut buf[0..2]);
        buf[2] = self.safi;
        buf[3] = self.flags;
        buf[4..7].copy_from_slice(&self.stale_time.to_be_bytes()[1..]);
        Ok(())
    }
    pub fn decode_from(buf: &[u8]) -> Result<BgpCapLLGR, BgpError> {
        if buf.len() < 7 {
            return Err(BgpError::insufficient_buffer_size());
        }
        Ok(BgpCapLLGR {
            afi: getn_u16(&buf[0..2]),
            safi: buf[2],
            flags: buf[3],
            stale_time: ((buf[4] as u32) << 16) + getn_u16(&buf[5..7]) as u32,
        })
    }
}
/// BGP capability AddPath.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BgpCapAddPath {
    pub afi: u16,
    pub safi: u8,
    pub send: bool,
    pub receive: bool,
}
impl BgpCapAddPath {
    pub fn response(src: &BgpCapAddPath) -> BgpCapAddPath {
        BgpCapAddPath {
            afi: src.afi,
            safi: src.safi,
            send: src.receive,
            receive: src.send,
        }
    }
    pub fn new_from_cap(
        base_safi: BgpCapability,
        send: bool,
        receive: bool,
    ) -> Result<BgpCapAddPath, BgpError> {
        let afisafi: (u16, u8) = afisafi_from_cap(base_safi)?;
        Ok(BgpCapAddPath {
            afi: afisafi.0,
            safi: afisafi.1,
            send,
            receive,
        })
    }
    pub fn encode_to(&self, buf: &mut [u8]) -> Result<(), BgpError> {
        if buf.len() < 4 {
            return Err(BgpError::insufficient_buffer_size());
        }
        setn_u16(self.afi, &mut buf[0..2]);
        buf[2] = self.safi;
        buf[3] = u8::from(self.receive) | (u8::from(self.send) << 1);
        Ok(())
    }
    pub fn decode_from(buf: &[u8]) -> Result<BgpCapAddPath, BgpError> {
        if buf.len() < 4 {
            return Err(BgpError::insufficient_buffer_size());
        }
        Ok(BgpCapAddPath {
            afi: getn_u16(&buf[0..2]),
            safi: buf[2],
            send: (buf[3] & 2) > 0,
            receive: (buf[3] & 1) > 0,
        })
    }
}
// capability codes https://www.iana.org/assignments/capability-codes/capability-codes.xhtml
/// BGP capability for OPEN message.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BgpCapability {
    /// BGP capability ipv4 unicast.
    SafiIPv4u,
    /// BGP capability ipv4 multicast.
    SafiIPv4m,
    /// BGP capability ipv4 mvpn.
    SafiIPv4mvpn,
    /// BGP capability ipv4 flowspec.
    SafiIPv4fu,
    /// BGP capability vpnv4 unicast.
    SafiVPNv4u,
    /// BGP capability vpnv4 flowspec.
    SafiVPNv4fu,
    /// BGP capability vpnv4 multicast.
    SafiVPNv4m,
    /// BGP capability ipv4 labeled unicast.
    SafiIPv4lu,
    /// BGP capability ipv4 mdt.
    SafiIPv4mdt,
    /// BGP capability ipv6 unicast.
    SafiIPv6u,
    /// BGP capability ipv6 labeled unicast.
    SafiIPv6lu,
    /// BGP capability ipv6 flowspec.
    SafiIPv6fu,
    /// BGP capability vpnv6 unicast.
    SafiVPNv6u,
    /// BGP capability vpnv6 multicast.
    SafiVPNv6m,
    /// BGP capability ipv6 mdt.
    SafiIPv6mdt,
    /// BGP capability VPLS.
    SafiVPLS,
    /// BGP capability EVPN.
    SafiEVPN,
    /// BGP Capability Graceful Restart
    CapGR {
        restart_time: u16,
        restart_state: bool,
        afis: Vec<BgpCapGR>,
    },
    /// BGP capability 32-bit AS numbers.
    CapASN32(u32),
    /// BGP capability route-refresh.
    CapRR,
    /// BGP Capability AddPath
    CapAddPath(Vec<BgpCapAddPath>),
    /// BGP Capability Enhanced Route Refresh Capability (RFC7313)
    CapEnhancedRR,
    /// BGP Capability Long-Lived Graceful Restart (draft-uttaro-idr-bgp-persistence)
    CapLLGR(Vec<BgpCapLLGR>),
    /// BGP Capability speaker hostname (draft-walton-bgp-hostname-capability)
    CapFQDN(String, String),
    /// BGP Capability BFD Strict-Mode (draft-ietf-idr-bgp-bfd-strict-mode)
    CapBFD,
}

impl BgpCapability {
    /// Bytes needed to encode capability in OPEN message.
    fn bytes_len(&self) -> usize {
        match self {
            BgpCapability::SafiIPv4u => 6,
            BgpCapability::SafiIPv4fu => 6,
            BgpCapability::SafiIPv4m => 6,
            BgpCapability::SafiIPv4mvpn => 6,
            BgpCapability::SafiVPNv4u => 6,
            BgpCapability::SafiVPNv4fu => 6,
            BgpCapability::SafiVPNv4m => 6,
            BgpCapability::SafiIPv4lu => 6,
            BgpCapability::SafiIPv4mdt => 6,
            BgpCapability::SafiIPv6u => 6,
            BgpCapability::SafiIPv6lu => 6,
            BgpCapability::SafiIPv6fu => 6,
            BgpCapability::SafiIPv6mdt => 6,
            BgpCapability::SafiVPNv6u => 6,
            BgpCapability::SafiVPNv6m => 6,
            BgpCapability::SafiVPLS => 6,
            BgpCapability::SafiEVPN => 6,
            BgpCapability::CapGR { afis, .. } => 4 + afis.len() * 4,
            BgpCapability::CapASN32(_) => 6,
            BgpCapability::CapRR => 2,
            BgpCapability::CapAddPath(v) => 2 + v.len() * 4,
            BgpCapability::CapEnhancedRR => 2,
            BgpCapability::CapLLGR(v) => 2 + v.len() * 7,
            BgpCapability::CapFQDN(hostname, domainname) => {
                4 + hostname.as_bytes().len() + domainname.as_bytes().len()
            }
            BgpCapability::CapBFD => 2,
        }
    }
    /// Store capability code into the given buffer.
    fn fill_buffer(&self, buf: &mut [u8]) -> Result<(), BgpError> {
        if buf.len() < self.bytes_len() {
            return Err(BgpError::insufficient_buffer_size());
        }
        match self {
            BgpCapability::SafiIPv4u => {
                buf.clone_from_slice(&[1, 4, 0, 1, 0, 1]);
            }
            BgpCapability::SafiIPv4fu => {
                buf.clone_from_slice(&[1, 4, 0, 1, 0, 133]);
            }
            BgpCapability::SafiIPv4m => {
                buf.clone_from_slice(&[1, 4, 0, 1, 0, 4]);
            }
            BgpCapability::SafiIPv4mvpn => {
                buf.clone_from_slice(&[1, 4, 0, 1, 0, 5]);
            }
            BgpCapability::SafiVPNv4u => {
                buf.clone_from_slice(&[1, 4, 0, 1, 0, 128]);
            }
            BgpCapability::SafiVPNv4fu => {
                buf.clone_from_slice(&[1, 4, 0, 1, 0, 134]);
            }
            BgpCapability::SafiVPNv4m => {
                buf.clone_from_slice(&[1, 4, 0, 1, 0, 129]);
            }
            BgpCapability::SafiIPv4lu => {
                buf.clone_from_slice(&[1, 4, 0, 1, 0, 2]);
            }
            BgpCapability::SafiIPv4mdt => {
                buf.clone_from_slice(&[1, 4, 0, 1, 0, 66]);
            }
            BgpCapability::SafiIPv6u => {
                buf.clone_from_slice(&[1, 4, 0, 2, 0, 1]);
            }
            BgpCapability::SafiIPv6fu => {
                buf.clone_from_slice(&[1, 4, 0, 2, 0, 133]);
            }
            BgpCapability::SafiIPv6lu => {
                buf.clone_from_slice(&[1, 4, 0, 2, 0, 4]);
            }
            BgpCapability::SafiIPv6mdt => {
                buf.clone_from_slice(&[1, 4, 0, 2, 0, 66]);
            }
            BgpCapability::SafiVPNv6u => {
                buf.clone_from_slice(&[1, 4, 0, 2, 0, 128]);
            }
            BgpCapability::SafiVPNv6m => {
                buf.clone_from_slice(&[1, 4, 0, 2, 0, 129]);
            }
            BgpCapability::SafiVPLS => {
                buf.clone_from_slice(&[1, 4, 0, 25, 0, 65]);
            }
            BgpCapability::SafiEVPN => {
                buf.clone_from_slice(&[1, 4, 0, 25, 0, 70]);
            }
            BgpCapability::CapGR {
                restart_time,
                restart_state,
                afis,
            } => {
                buf[0] = 64;
                buf[1] = (2 + 4 * afis.len()) as u8;
                if restart_time.leading_zeros() < 4 {
                    return Err(BgpError::static_str("restart_time must fit into 12 bits"));
                }
                setn_u16(*restart_time, &mut buf[2..4]);
                if *restart_state {
                    buf[2] |= 128;
                }
                let mut cp: usize = 4;
                for cap in afis {
                    cap.encode_to(&mut buf[cp..cp + 4])?;
                    cp += 4;
                }
            }
            BgpCapability::CapASN32(as_num) => {
                buf.clone_from_slice(&[
                    65,
                    4,
                    (as_num >> 24) as u8,
                    ((as_num >> 16) & 0xff) as u8,
                    ((as_num >> 8) & 0xff) as u8,
                    (as_num & 0xff) as u8,
                ]);
            }
            BgpCapability::CapRR => {
                buf.clone_from_slice(&[2, 0]);
            }
            BgpCapability::CapAddPath(vap) => {
                buf[0] = 69;
                buf[1] = (4 * vap.len()) as u8;
                let mut cp: usize = 2;
                for ap in vap.iter() {
                    ap.encode_to(&mut buf[cp..cp + 4])?;
                    cp += 4;
                }
            }
            BgpCapability::CapEnhancedRR => {
                buf.clone_from_slice(&[70, 0]);
            }
            BgpCapability::CapLLGR(v) => {
                buf[0] = 71;
                buf[1] = (7 * v.len()) as u8;
                let mut cp: usize = 2;
                for cap in v {
                    cap.encode_to(&mut buf[cp..cp + 7])?;
                    cp += 7;
                }
            }
            BgpCapability::CapFQDN(hostname, domainname) => {
                buf[0] = 73;
                buf[1] = hostname.as_bytes().len() as u8;
                let mut pos = 1;
                buf[pos..pos + hostname.as_bytes().len()].copy_from_slice(hostname.as_bytes());
                pos += hostname.as_bytes().len();
                buf[pos] = domainname.as_bytes().len() as u8;
                pos += 1;
                buf[pos..pos + domainname.as_bytes().len()].copy_from_slice(domainname.as_bytes());
            }
            BgpCapability::CapBFD => {
                buf.clone_from_slice(&[74, 0]);
            }
        };
        Ok(())
    }

    fn from_type_and_data(captype: u8, data: &[u8]) -> Result<Option<BgpCapability>, BgpError> {
        let cap = match captype {
            1 => {
                if data.len() != 4 {
                    return Err(BgpError::static_str("Invalid capability"));
                }
                let bytes: &[_; 4] = std::convert::TryFrom::try_from(data).unwrap();
                match *bytes {
                    [0, 1, 0, 1] => BgpCapability::SafiIPv4u,
                    [0, 1, 0, 133] => BgpCapability::SafiIPv4fu,
                    [0, 1, 0, 4] => BgpCapability::SafiIPv4m,
                    [0, 1, 0, 5] => BgpCapability::SafiIPv4mvpn,
                    [0, 1, 0, 128] => BgpCapability::SafiVPNv4u,
                    [0, 1, 0, 134] => BgpCapability::SafiVPNv4fu,
                    [0, 1, 0, 129] => BgpCapability::SafiVPNv4m,
                    [0, 1, 0, 2] => BgpCapability::SafiIPv4lu,
                    [0, 1, 0, 66] => BgpCapability::SafiIPv4mdt,
                    [0, 2, 0, 1] => BgpCapability::SafiIPv6u,
                    [0, 2, 0, 133] => BgpCapability::SafiIPv6fu,
                    [0, 2, 0, 4] => BgpCapability::SafiIPv6lu,
                    [0, 2, 0, 66] => BgpCapability::SafiIPv6mdt,
                    [0, 2, 0, 128] => BgpCapability::SafiVPNv6u,
                    [0, 2, 0, 129] => BgpCapability::SafiVPNv6m,
                    [0, 25, 0, 65] => BgpCapability::SafiVPLS,
                    [0, 25, 0, 70] => BgpCapability::SafiEVPN,
                    _ => return Ok(None),
                }
            }
            2 => {
                if !data.is_empty() {
                    return Err(BgpError::static_str("Invalid capability"));
                }
                BgpCapability::CapRR
            }
            64 => {
                if data.len() < 2 || (data.len() - 2) % 4 != 0 {
                    return Err(BgpError::static_str("Invalid GR capability"));
                }
                let restart_state = data[0] & 128 != 0;
                let restart_time = getn_u16(&data[0..2]) & 0x0f_ff;
                let mut afis = Vec::new();
                let mut cp: usize = 2;
                while cp < data.len() {
                    afis.push(BgpCapGR::decode_from(&data[cp..cp + 4])?);
                    cp += 4;
                }
                BgpCapability::CapGR {
                    restart_state,
                    restart_time,
                    afis,
                }
            }
            65 => {
                if data.len() != 4 {
                    return Err(BgpError::static_str("Invalid capability"));
                }
                BgpCapability::CapASN32(getn_u32(data))
            }
            69 => {
                if data.len() & 3 != 0 {
                    return Err(BgpError::static_str("Invalid addpath capability"));
                }
                let mut v = Vec::new();
                let mut cp: usize = 0;
                while cp < data.len() {
                    v.push(BgpCapAddPath::decode_from(&data[cp..cp + 4])?);
                    cp += 4;
                }
                BgpCapability::CapAddPath(v)
            }
            70 => {
                if !data.is_empty() {
                    return Err(BgpError::static_str("Invalid capability"));
                }
                BgpCapability::CapEnhancedRR
            }
            71 => {
                if data.len() % 7 != 0 {
                    return Err(BgpError::static_str("Invalid LLGR capability"));
                }
                let mut v = Vec::new();
                let mut cp: usize = 0;
                while cp < data.len() {
                    v.push(BgpCapLLGR::decode_from(&data[cp..cp + 7])?);
                    cp += 7;
                }
                BgpCapability::CapLLGR(v)
            }
            73 => {
                let mut pos = 0;
                if data[pos..].is_empty() {
                    return Err(BgpError::static_str("Invalid capability"));
                }
                let hostname_len = data[pos] as usize;
                pos += 1;
                if data[pos..].len() < hostname_len {
                    return Err(BgpError::static_str("Invalid capability"));
                }
                let hostname = std::str::from_utf8(&data[pos..pos + hostname_len])?.to_string();
                pos += hostname_len;
                if data[pos..].is_empty() {
                    return Err(BgpError::static_str("Invalid capability"));
                }
                let domainname_len = data[pos] as usize;
                pos += 1;
                if data[pos..].len() < domainname_len {
                    return Err(BgpError::static_str("Invalid capability"));
                }
                let domainname = std::str::from_utf8(&data[pos..pos + domainname_len])?.to_string();
                if !data[pos..].is_empty() {
                    return Err(BgpError::static_str("Invalid capability"));
                }

                BgpCapability::CapFQDN(hostname, domainname)
            }
            74 => {
                if !data.is_empty() {
                    return Err(BgpError::static_str("Invalid capability"));
                }
                BgpCapability::CapBFD
            }
            _ => return Ok(None),
        };
        Ok(Some(cap))
    }

    /// Decode capability code from given buffer. Returns capability and consumed buffer length.
    #[allow(clippy::type_complexity)]
    pub fn from_buffer(
        buf: &[u8],
    ) -> Result<(Result<BgpCapability, (u8, Vec<u8>)>, usize), BgpError> {
        if buf.len() < 2 {
            return Err(BgpError::InsufficientBufferSize);
        }
        let captype = buf[0];
        let datalength = buf[1] as usize;
        if buf.len() < datalength + 2 {
            return Err(BgpError::InsufficientBufferSize);
        }
        let data = &buf[2..2 + datalength];

        let cap_res = match Self::from_type_and_data(captype, data)? {
            Some(cap) => Ok(cap),
            None => Err((captype, data.to_vec())),
        };
        Ok((cap_res, 2 + datalength))
    }
}

/// BGP session parameters - AS, hold time, capabilities etc.
#[derive(Debug, Clone)]
pub struct BgpSessionParams {
    /// Autonomous system number.
    pub as_num: u32,
    /// Hold time in seconds.
    pub hold_time: u16,
    /// IP transport mode.
    pub peer_mode: BgpTransportMode,
    /// Flag that session has 32-bit AS numbers capability.
    pub has_as32bit: bool,
    /// Router ID.
    pub router_id: std::net::Ipv4Addr,
    /// Capability set for this session.
    pub caps: Vec<BgpCapability>,
    /// Try to detect pathid
    pub fuzzy_pathid: bool,
}

impl BgpSessionParams {
    pub fn new(
        asnum: u32,
        holdtime: u16,
        peermode: BgpTransportMode,
        routerid: std::net::Ipv4Addr,
        cps: Vec<BgpCapability>,
    ) -> BgpSessionParams {
        BgpSessionParams {
            as_num: asnum,
            hold_time: holdtime,
            peer_mode: peermode,
            has_as32bit: true,
            router_id: routerid,
            caps: cps,
            fuzzy_pathid: true,
        }
    }
    /// Constructs BGP OPEN message from params.
    pub fn open_message(&self) -> BgpOpenMessage {
        let mut bom = BgpOpenMessage::new();
        bom.as_num = self.as_num;
        bom.router_id = self.router_id;
        bom.caps = self.caps.clone();
        bom.hold_time = self.hold_time;
        bom
    }
    /// Check capability set and validates has_as32bit flag.
    pub fn check_caps(&mut self) {
        self.has_as32bit = false;
        for cap in self.caps.iter() {
            if let BgpCapability::CapASN32(n) = cap {
                self.has_as32bit = true;
                if self.as_num != 0 && self.as_num != 23456 && self.as_num != *n {
                    log::trace!(
                        "Capability 32-bit AS mismatch AS number: {:?}!={:?}",
                        self.as_num,
                        *n
                    );
                }
                self.as_num = *n;
            }
        }
    }
    fn match_addpath_caps(vcaps: &[BgpCapAddPath], rcaps: &[BgpCapAddPath]) -> Vec<BgpCapAddPath> {
        vcaps
            .iter()
            .map(|vq| {
                rcaps
                    .iter()
                    .find(|rq| vq.afi == rq.afi && vq.safi == rq.safi)
            })
            .filter(|x| x.is_some())
            .map(|x| BgpCapAddPath::response(x.unwrap()))
            .collect()
    }
    /// Match capability set
    pub fn match_caps(&mut self, rcaps: &[BgpCapability]) {
        self.has_as32bit = false;
        let nv = self
            .caps
            .iter()
            .filter_map(|x| match x {
                BgpCapability::CapASN32(_) => {
                    if rcaps
                        .iter()
                        .any(|q| matches!(q, BgpCapability::CapASN32(_)))
                    {
                        Some((*x).clone())
                    } else {
                        None
                    }
                }
                BgpCapability::CapAddPath(cap) => {
                    match rcaps
                        .iter()
                        .find(|q| matches!(q, BgpCapability::CapAddPath(_)))
                    {
                        Some(BgpCapability::CapAddPath(icap)) => Some(BgpCapability::CapAddPath(
                            Self::match_addpath_caps(cap, icap),
                        )),
                        _ => None,
                    }
                }
                _ => {
                    if rcaps.iter().any(|q| *q == *x) {
                        Some((*x).clone())
                    } else {
                        None
                    }
                }
            })
            .collect();
        self.caps = nv;
        self.check_caps();
    }
    /// Search for specified addpath capability.
    pub fn find_addpath(&self, afi: u16, safi: u8) -> Option<&BgpCapAddPath> {
        for cap in self.caps.iter() {
            if let BgpCapability::CapAddPath(mcap) = cap {
                if let Some(r) = mcap.iter().find(|ap| ap.afi == afi && ap.safi == safi) {
                    return Some(r);
                }
            }
        }
        None
    }
    /// Search for specified addpath send capability.
    pub fn check_addpath_send(&self, afi: u16, safi: u8) -> bool {
        match self.find_addpath(afi, safi) {
            None => false,
            Some(x) => x.send,
        }
    }
    /// Search for specified addpath receive capability.
    pub fn check_addpath_receive(&self, afi: u16, safi: u8) -> bool {
        match self.find_addpath(afi, safi) {
            None => false,
            Some(x) => x.receive,
        }
    }
    /// Check for capability
    pub fn check_capability(&self, cp: &BgpCapability) -> bool {
        self.caps.iter().any(|x| x == cp)
    }
    /// Remove capability
    pub fn remove_capability(&mut self, cp: &BgpCapability) {
        match cp {
            BgpCapability::CapASN32(_) => self
                .caps
                .retain(|x| !matches!(x, BgpCapability::CapASN32(_))),
            BgpCapability::CapAddPath(vc) => {
                match self
                    .caps
                    .iter_mut()
                    .find(|x| matches!(x, BgpCapability::CapAddPath(_)))
                {
                    None => return,
                    Some(ref mut q) => {
                        if let BgpCapability::CapAddPath(ref mut cvc) = q {
                            for cp in vc.iter() {
                                cvc.retain(|x| *x != *cp)
                            }
                        };
                    }
                };
                self.caps.retain(|x| match x {
                    BgpCapability::CapAddPath(vc) => !vc.is_empty(),
                    _ => true,
                })
            }
            n => self.caps.retain(|x| *x != *n),
        }
    }
    pub fn remove_capability_addpath(&mut self) {
        self.caps
            .retain(|x| !matches!(x, BgpCapability::CapAddPath(_)));
    }
    /// Decode message head from buffer. Returns following message kind and length.
    pub fn decode_message_head(
        &self,
        buf: &[u8],
    ) -> Result<(message::BgpMessageType, usize), BgpError> {
        if buf.len() < 19 {
            return Err(BgpError::static_str("Invalid message header size!"));
        }
        for q in buf[0..16].iter() {
            if (*q) != 255 {
                return Err(BgpError::static_str(
                    "Invalid header content, MD5 is not supported!",
                ));
            }
        }
        let messagetype = message::BgpMessageType::decode_from(buf[18])?;
        Ok((messagetype, (getn_u16(&buf[16..18]) - 19) as usize))
    }
    /// Receive message head from buffer. Returns following message kind and length.
    pub fn recv_message_head(
        &mut self,
        rdsrc: &mut impl std::io::Read,
    ) -> Result<(message::BgpMessageType, usize), BgpError> {
        let mut buf = [0_u8; 19];
        rdsrc.read_exact(&mut buf)?;
        self.decode_message_head(&buf)
    }
    /// Stores BGP message head (19 bytes) into the buffer.
    pub fn prepare_message_buf(
        &self,
        buf: &mut [u8],
        messagetype: message::BgpMessageType,
        messagelen: usize,
    ) -> Result<usize, BgpError> {
        if buf.len() < (messagelen + 19) {
            return Err(BgpError::insufficient_buffer_size());
        }
        buf[0..16].clone_from_slice(&[255_u8; 16]);
        let lng: u16 = (messagelen as u16) + 19;
        buf[16] = (lng >> 8) as u8;
        buf[17] = (lng & 0xff) as u8;
        buf[18] = messagetype.encode();
        Ok(lng as usize)
    }
    /// Writes buffer with BGP message into the target.
    pub fn send_message_buf(
        &mut self,
        wrdst: &mut impl std::io::Write,
        buf: &mut [u8],
        messagetype: message::BgpMessageType,
        messagelen: usize,
    ) -> Result<(), BgpError> {
        if buf.len() < (messagelen + 19) {
            return Err(BgpError::insufficient_buffer_size());
        }
        buf[0..16].clone_from_slice(&[255_u8; 16]);
        let lng: u16 = (messagelen as u16) + 19;
        buf[16] = (lng >> 8) as u8;
        buf[17] = (lng & 0xff) as u8;
        buf[18] = messagetype.encode();
        match wrdst.write_all(&buf[0..(lng as usize)]) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
impl From<&BgpOpenMessage> for BgpSessionParams {
    fn from(bom: &BgpOpenMessage) -> BgpSessionParams {
        let mut ret = BgpSessionParams {
            as_num: bom.as_num,
            hold_time: bom.hold_time,
            peer_mode: BgpTransportMode::IPv4,
            has_as32bit: true,
            router_id: bom.router_id,
            caps: bom.caps.clone(),
            fuzzy_pathid: false,
        };
        ret.check_caps();
        ret
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities_remove() {
        let mut params = BgpSessionParams::new(
            64512,
            180,
            BgpTransportMode::IPv4,
            std::net::Ipv4Addr::new(1, 1, 1, 1),
            vec![
                BgpCapability::SafiIPv4u,
                BgpCapability::CapAddPath(vec![
                    BgpCapAddPath {
                        afi: 1,
                        safi: 1,
                        send: true,
                        receive: true,
                    },
                    BgpCapAddPath {
                        afi: 1,
                        safi: 2,
                        send: true,
                        receive: true,
                    },
                ]),
            ]
            .into_iter()
            .collect(),
        );
        assert_eq!(params.caps.len(), 2);
        params.remove_capability(&BgpCapability::SafiIPv4u);
        assert_eq!(params.caps.len(), 1);
        params.remove_capability(&BgpCapability::SafiIPv4u);
        assert_eq!(params.caps.len(), 1);
        params.remove_capability(&BgpCapability::CapAddPath(vec![BgpCapAddPath {
            afi: 1,
            safi: 1,
            send: true,
            receive: true,
        }]));
        assert_eq!(params.caps.len(), 1);
        params.remove_capability(&BgpCapability::CapAddPath(vec![BgpCapAddPath {
            afi: 1,
            safi: 2,
            send: true,
            receive: true,
        }]));
        assert_eq!(params.caps.len(), 0);
    }
}

// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module describes NLRI data structures for multicast vpn

use crate::afi::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

/// BGP MVPN type 1 - Intra AS I-PMSI AD
/// for example 1:10.255.170.100:1:10.255.170.100
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpMVPN1 {
    pub rd: BgpRD,
    pub originator: std::net::IpAddr,
}
impl std::fmt::Display for BgpMVPN1 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}", self.rd, self.originator)
    }
}
impl BgpAddrItem<BgpMVPN1> for BgpMVPN1 {
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(BgpMVPN1, usize), BgpError> {
        let rdp = BgpRD::decode_from(mode, buf)?;
        if mode == BgpTransportMode::IPv4 && buf.len() >= 12 {
            return Ok((
                BgpMVPN1 {
                    rd: rdp.0,
                    originator: decode_addr_from(&buf[(rdp.1)..(rdp.1 + 4)])?,
                },
                rdp.1 + 4,
            ));
        }
        if mode == BgpTransportMode::IPv6 && buf.len() >= 24 {
            return Ok((
                BgpMVPN1 {
                    rd: rdp.0,
                    originator: decode_addr_from(&buf[(rdp.1)..(rdp.1 + 16)])?,
                },
                rdp.1 + 16,
            ));
        }
        Err(BgpError::static_str("Invalid BgpMVPN1 buffer len"))
    }
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let p1 = self.rd.encode_to(mode, buf)?;
        let p2 = encode_addr_to(&self.originator, &mut buf[p1..])?;
        Ok(p1 + p2)
    }
}
/// BGP MVPN type 2 - Inter AS I-PMSI AD
/// for example 2:10.255.170.100:1:65000
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpMVPN2 {
    pub rd: BgpRD,
    pub asn: u32,
}
impl std::fmt::Display for BgpMVPN2 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}", self.rd, self.asn)
    }
}
impl BgpAddrItem<BgpMVPN2> for BgpMVPN2 {
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(BgpMVPN2, usize), BgpError> {
        if buf.len() >= 12 {
            let rdp = BgpRD::decode_from(mode, buf)?;
            return Ok((
                BgpMVPN2 {
                    rd: rdp.0,
                    asn: getn_u32(&buf[8..12]),
                },
                rdp.1 + 4,
            ));
        }
        Err(BgpError::static_str("Invalid BgpMVPN2 buffer len"))
    }
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let p1 = self.rd.encode_to(mode, buf)?;
        setn_u32(self.asn, &mut buf[p1..]);
        Ok(p1 + 4)
    }
}
/// BGP MVPN type 3 - S-PMSI AD
/// for example 3:10.255.170.100:1:32:192.168.194.2:32:224.1.2.3:10.255.170.100
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpMVPN3 {
    pub rd: BgpRD,
    pub source: std::net::IpAddr,
    pub group: std::net::IpAddr,
    pub originator: std::net::IpAddr,
}
impl std::fmt::Display for BgpMVPN3 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.rd, self.source, self.group, self.originator
        )
    }
}
impl BgpAddrItem<BgpMVPN3> for BgpMVPN3 {
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(BgpMVPN3, usize), BgpError> {
        let rdp = BgpRD::decode_from(mode, buf)?;
        if mode == BgpTransportMode::IPv4 && buf.len() >= 22 {
            if buf[8] != 32 || buf[13] != 32 {
                return Err(BgpError::from_string(format!(
                    "Invalid BgpMVPN3 v4 prefix len: {:?}",
                    buf
                )));
            }
            return Ok((
                BgpMVPN3 {
                    rd: rdp.0,
                    source: decode_addr_from(&buf[9..13])?,
                    group: decode_addr_from(&buf[14..18])?,
                    originator: decode_addr_from(&buf[18..22])?,
                },
                22,
            ));
        }
        if mode == BgpTransportMode::IPv6 && buf.len() >= 58 {
            if buf[8] != 128 || buf[25] != 128 {
                return Err(BgpError::static_str("Invalid BgpMVPN3 v6 prefix len"));
            }
            return Ok((
                BgpMVPN3 {
                    rd: rdp.0,
                    source: decode_addr_from(&buf[9..25])?,
                    group: decode_addr_from(&buf[26..42])?,
                    originator: decode_addr_from(&buf[42..58])?,
                },
                58,
            ));
        }
        Err(BgpError::static_str("Invalid BgpMVPN3 buffer len"))
    }
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut p1 = self.rd.encode_to(mode, buf)?;
        p1 += encode_addr_to(&self.source, &mut buf[p1..])?;
        p1 += encode_addr_to(&self.group, &mut buf[p1..])?;
        p1 += encode_addr_to(&self.originator, &mut buf[p1..])?;
        Ok(p1)
    }
}
/// BGP MVPN type 4 - Leaf AD
/// for example 4:3:10.255.170.100:1:32:192.168.194.2:32:224.1.2.3:10.255.170.100:10.255.170.98
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpMVPN4 {
    pub spmsi: BgpMVPN3,
    pub originator: std::net::IpAddr,
}
impl std::fmt::Display for BgpMVPN4 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}", self.spmsi, self.originator)
    }
}
impl BgpAddrItem<BgpMVPN4> for BgpMVPN4 {
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(BgpMVPN4, usize), BgpError> {
        if buf[0] != 3 || buf[1] != 22 {
            return Err(BgpError::from_string(format!(
                "BgpMVPN4 decode error: {:?}",
                buf
            )));
        }
        match BgpMVPN3::decode_from(mode, &buf[2..]) {
            Err(e) => Err(BgpError::from_string(format!(
                "BgpMVPN4 decode error for MVPNV3: {}, buf: {:?}",
                e, buf
            ))),
            Ok(s) => Ok((
                BgpMVPN4 {
                    spmsi: s.0,
                    originator: decode_addr_from(&buf[(2 + s.1)..])?,
                },
                s.1 + 6,
            )),
        }
    }
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut p1 = self.spmsi.encode_to(mode, buf)?;
        p1 += encode_addr_to(&self.originator, &mut buf[p1..])?;
        Ok(p1)
    }
}
/// BGP MVPN type 5 - Source Active AD
/// for example 5:10.255.170.100:1:32:192.168.194.2:32:224.1.2.3
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpMVPN5 {
    pub rd: BgpRD,
    pub source: std::net::IpAddr,
    pub group: std::net::IpAddr,
}
impl std::fmt::Display for BgpMVPN5 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.rd, self.source, self.group)
    }
}
impl BgpAddrItem<BgpMVPN5> for BgpMVPN5 {
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(BgpMVPN5, usize), BgpError> {
        let rdp = BgpRD::decode_from(mode, buf)?;
        if mode == BgpTransportMode::IPv4 && buf.len() >= 18 {
            if buf[8] != 32 || buf[13] != 32 {
                return Err(BgpError::static_str("Invalid BgpMVPN3 v4 prefix len"));
            }
            return Ok((
                BgpMVPN5 {
                    rd: rdp.0,
                    source: decode_addr_from(&buf[9..13])?,
                    group: decode_addr_from(&buf[14..18])?,
                },
                18,
            ));
        }
        if mode == BgpTransportMode::IPv6 && buf.len() >= 42 {
            if buf[8] != 128 || buf[25] != 128 {
                return Err(BgpError::static_str("Invalid BgpMVPN3 v6 prefix len"));
            }
            return Ok((
                BgpMVPN5 {
                    rd: rdp.0,
                    source: decode_addr_from(&buf[9..15])?,
                    group: decode_addr_from(&buf[26..42])?,
                },
                42,
            ));
        }
        Err(BgpError::static_str("Invalid BgpMVPN5 buffer len"))
    }
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut p1 = self.rd.encode_to(mode, buf)?;
        p1 += encode_addr_to(&self.source, &mut buf[p1..])?;
        p1 += encode_addr_to(&self.group, &mut buf[p1..])?;
        Ok(p1)
    }
}
/// BGP MVPN type 6 - Shared Tree Join or type 7 - Source Tree Join
/// for example 6:10.255.170.100:1:65000:32:10.12.53.12:32:224.1.2.3
///   7:10.255.170.100:1:65000:32:192.168.194.2:32:224.1.2.3
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpMVPN67 {
    pub rd: BgpRD,
    pub asn: u32,
    pub rp: std::net::IpAddr,
    pub group: std::net::IpAddr,
}
impl std::fmt::Display for BgpMVPN67 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}:{}:{}", self.rd, self.asn, self.rp, self.group)
    }
}
impl BgpAddrItem<BgpMVPN67> for BgpMVPN67 {
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(BgpMVPN67, usize), BgpError> {
        let rdp = BgpRD::decode_from(mode, buf)?;
        if mode == BgpTransportMode::IPv4 && buf.len() >= 22 {
            if buf[12] != 32 || buf[17] != 32 {
                return Err(BgpError::static_str("Invalid BgpMVPN67 v4 prefix len"));
            }
            return Ok((
                BgpMVPN67 {
                    rd: rdp.0,
                    asn: getn_u32(&buf[8..12]),
                    rp: decode_addr_from(&buf[13..17])?,
                    group: decode_addr_from(&buf[18..22])?,
                },
                22,
            ));
        }
        if mode == BgpTransportMode::IPv6 && buf.len() >= 46 {
            if buf[12] != 128 || buf[29] != 128 {
                return Err(BgpError::static_str("Invalid BgpMVPN67 v6 prefix len"));
            }
            return Ok((
                BgpMVPN67 {
                    rd: rdp.0,
                    asn: getn_u32(&buf[8..12]),
                    rp: decode_addr_from(&buf[13..29])?,
                    group: decode_addr_from(&buf[30..46])?,
                },
                46,
            ));
        }
        Err(BgpError::static_str("Invalid BgpMVPN67 buffer len"))
    }
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut p1 = self.rd.encode_to(mode, buf)?;
        setn_u32(self.asn, &mut buf[p1..]);
        p1 += 4;
        p1 += encode_addr_to(&self.rp, &mut buf[p1..])?;
        p1 += encode_addr_to(&self.group, &mut buf[p1..])?;
        Ok(p1)
    }
}
// BGP Multicast VPN NLRI
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub enum BgpMVPN {
    T1(BgpMVPN1),  //Intra AS I-PMSI AD  1:10.255.170.100:1:10.255.170.100
    T2(BgpMVPN2),  //Inter AS I-PMSI AD  2:10.255.170.100:1:65000
    T3(BgpMVPN3), //S-PMSI AD           3:10.255.170.100:1:32:192.168.194.2:32:224.1.2.3:10.255.170.100
    T4(BgpMVPN4), //Leaf AD             4:3:10.255.170.100:1:32:192.168.194.2:32:224.1.2.3:10.255.170.100:10.255.170.98
    T5(BgpMVPN5), //Source Active AD    5:10.255.170.100:1:32:192.168.194.2:32:224.1.2.3
    T6(BgpMVPN67), //Shared Tree Join    6:10.255.170.100:1:65000:32:10.12.53.12:32:224.1.2.3
    T7(BgpMVPN67), //Source Tree Join    7:10.255.170.100:1:65000:32:192.168.194.2:32:224.1.2.3
}
impl std::fmt::Display for BgpMVPN {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BgpMVPN::T1(s) => write!(f, "1:{}", s),
            BgpMVPN::T2(s) => write!(f, "2:{}", s),
            BgpMVPN::T3(s) => write!(f, "3:{}", s),
            BgpMVPN::T4(s) => write!(f, "4:{}", s),
            BgpMVPN::T5(s) => write!(f, "5:{}", s),
            BgpMVPN::T6(s) => write!(f, "6:{}", s),
            BgpMVPN::T7(s) => write!(f, "7:{}", s),
        }
    }
}
impl BgpAddrItem<BgpMVPN> for BgpMVPN {
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(BgpMVPN, usize), BgpError> {
        let mvpntype = buf[0];
        let routelen = buf[1] as usize;
        match mvpntype {
            1 => {
                let r = BgpMVPN1::decode_from(mode, &buf[2..(2 + routelen)])?;
                Ok((BgpMVPN::T1(r.0), r.1 + 2))
            }
            2 => {
                let r = BgpMVPN2::decode_from(mode, &buf[2..(2 + routelen)])?;
                Ok((BgpMVPN::T2(r.0), r.1 + 2))
            }
            3 => {
                let r = BgpMVPN3::decode_from(mode, &buf[2..(2 + routelen)])?;
                Ok((BgpMVPN::T3(r.0), r.1 + 2))
            }
            4 => {
                let r = BgpMVPN4::decode_from(mode, &buf[2..(2 + routelen)])?;
                Ok((BgpMVPN::T4(r.0), r.1 + 2))
            }
            5 => {
                let r = BgpMVPN5::decode_from(mode, &buf[2..(2 + routelen)])?;
                Ok((BgpMVPN::T5(r.0), r.1 + 2))
            }
            6 => {
                let r = BgpMVPN67::decode_from(mode, &buf[2..(2 + routelen)])?;
                Ok((BgpMVPN::T6(r.0), r.1 + 2))
            }
            7 => {
                let r = BgpMVPN67::decode_from(mode, &buf[2..(2 + routelen)])?;
                Ok((BgpMVPN::T7(r.0), r.1 + 2))
            }
            _ => Err(BgpError::from_string(format!(
                "Invalid BgpMVPN route type: {:?}",
                buf
            ))),
        }
    }
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let sz = match self {
            BgpMVPN::T1(r) => {
                buf[0] = 1;
                r.encode_to(mode, &mut buf[2..])?
            }
            BgpMVPN::T2(r) => {
                buf[0] = 2;
                r.encode_to(mode, &mut buf[2..])?
            }
            BgpMVPN::T3(r) => {
                buf[0] = 3;
                r.encode_to(mode, &mut buf[2..])?
            }
            BgpMVPN::T4(r) => {
                buf[0] = 4;
                r.encode_to(mode, &mut buf[2..])?
            }
            BgpMVPN::T5(r) => {
                buf[0] = 5;
                r.encode_to(mode, &mut buf[2..])?
            }
            BgpMVPN::T6(r) => {
                buf[0] = 6;
                r.encode_to(mode, &mut buf[2..])?
            }
            BgpMVPN::T7(r) => {
                buf[0] = 7;
                r.encode_to(mode, &mut buf[2..])?
            }
        };
        buf[1] = sz as u8;
        Ok(sz + 2)
    }
}

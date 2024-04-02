// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module describes NLRI data structures for evpn <https://tools.ietf.org/html/rfc7432>

use std::net::IpAddr;

use crate::afi::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

///EVPN ESI field
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct EVPNESI {
    pub v: Vec<u8>,
}
impl EVPNESI {
    pub fn empty() -> EVPNESI {
        EVPNESI { v: Vec::new() }
    }
    pub fn new(src: &[u8]) -> EVPNESI {
        EVPNESI { v: src.to_vec() }
    }
    pub fn is_zero(&self) -> bool {
        !self.v.iter().any(|x| (*x) != 0)
    }
}
impl std::fmt::Display for EVPNESI {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.is_zero() {
            Ok(())
        } else {
            for vl in self.v.iter() {
                write!(f, "{:02x}", vl)?;
            }
            Ok(())
        }
    }
}
//EVPN Ethernet Auto-Discovery (A-D) route
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpEVPN1 {
    pub rd: BgpRD,
    pub esi_type: u8,
    pub esi: EVPNESI,
    pub ether_tag: u32,
    pub labels: MplsLabels,
}
impl BgpAddrItem<BgpEVPN1> for BgpEVPN1 {
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(BgpEVPN1, usize), BgpError> {
        let rdp = BgpRD::decode_from(mode, buf)?;
        let esitype = buf[rdp.1];
        let esib = &buf[rdp.1 + 1..rdp.1 + 10];
        let etag = getn_u32(&buf[rdp.1 + 10..rdp.1 + 14]);
        let lbls = MplsLabels::extract_bits_from(
            (8 * (buf.len() - rdp.1 - 14)) as u8,
            &buf[rdp.1 + 14..],
        )?;
        Ok((
            BgpEVPN1 {
                rd: rdp.0,
                esi_type: esitype,
                esi: EVPNESI::new(esib),
                ether_tag: etag,
                labels: lbls.0,
            },
            rdp.1 + 14 + lbls.1,
        ))
    }
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut pos = self.rd.encode_to(mode, buf)?;
        if self.esi.v.len() == 9 {
            buf[pos] = self.esi_type;
            buf[pos + 1..pos + 10].copy_from_slice(self.esi.v.as_slice());
            pos += 10;
        } else {
            return Err(BgpError::static_str("l2vpn esi len != 9"));
        }
        setn_u32(self.ether_tag, &mut buf[pos..pos + 4]);
        pos += 4;
        let lbls = self.labels.set_bits_to(&mut buf[pos..])?;
        Ok(pos + lbls.1)
    }
}
impl std::fmt::Display for BgpEVPN1 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:", self.rd)?;
        if self.esi_type != 0 {
            write!(f, "{}:", self.esi_type)?;
        }
        write!(f, "{}:{:08x} {}", self.esi, self.ether_tag, self.labels)
    }
}

//EVPN MAC/IP Advertisement Route
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpEVPN2 {
    pub rd: BgpRD,
    pub esi_type: u8,
    pub esi: EVPNESI,
    pub ether_tag: u32,
    pub mac: MacAddress,
    pub ip: Option<std::net::IpAddr>,
    pub labels: MplsLabels,
}
impl BgpAddrItem<BgpEVPN2> for BgpEVPN2 {
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(BgpEVPN2, usize), BgpError> {
        let rdp = BgpRD::decode_from(mode, buf)?;
        let mut sz = rdp.1;
        let esitype = buf[sz];
        let esib = &buf[sz + 1..sz + 10];
        sz += 10;
        let etag = getn_u32(&buf[sz..sz + 4]);
        sz += 4;
        if buf[sz] != 48 {
            return Err(BgpError::from_string(format!(
                "Invalid mac address size: {}",
                buf[sz]
            )));
        };
        sz += 1;
        let mc = MacAddress::from(&buf[sz..sz + 6]);
        sz += 6;
        let addrtype = buf[sz];
        sz += 1;
        let beg = sz;
        let tip = match addrtype {
            0 => None,
            32 => {
                sz += 4;
                Some(std::net::IpAddr::V4(decode_addrv4_from(&buf[beg..])?))
            }
            128 => {
                sz += 16;
                Some(std::net::IpAddr::V6(decode_addrv6_from(&buf[beg..])?))
            }
            _ => {
                return Err(BgpError::from_string(format!(
                    "Invalid ip address size: {}",
                    addrtype
                )));
            }
        };
        let lbls = MplsLabels::extract_bits_from((8 * (buf.len() - sz)) as u8, &buf[sz..])?;
        Ok((
            BgpEVPN2 {
                rd: rdp.0,
                esi_type: esitype,
                esi: EVPNESI::new(esib),
                ether_tag: etag,
                mac: mc,
                ip: tip,
                labels: lbls.0,
            },
            sz + lbls.1,
        ))
    }
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut pos = self.rd.encode_to(mode, buf)?;
        if self.esi.v.len() == 9 {
            buf[pos] = self.esi_type;
            buf[pos + 1..pos + 10].copy_from_slice(self.esi.v.as_slice());
            pos += 10;
        } else {
            return Err(BgpError::static_str("l2vpn esi len != 9"));
        }
        setn_u32(self.ether_tag, &mut buf[pos..pos + 4]);
        pos += 4;
        buf[pos] = 48;
        pos += 1; //mac length
        buf[pos..pos + 6].copy_from_slice(&self.mac.mac_address);
        pos += 6;
        match self.ip {
            None => {
                buf[pos] = 0;
                pos += 1;
            }
            Some(s) => match s {
                std::net::IpAddr::V4(a) => {
                    buf[pos] = 32;
                    pos += 1;
                    encode_addrv4_to(&a, &mut buf[pos..pos + 4])?;
                    pos += 4;
                }
                std::net::IpAddr::V6(a) => {
                    buf[pos] = 128;
                    pos += 1;
                    encode_addrv6_to(&a, &mut buf[pos..pos + 16])?;
                    pos += 16;
                }
            },
        }
        let lbls = self.labels.set_bits_to(&mut buf[pos..])?;
        Ok(pos + lbls.1)
    }
}
impl std::fmt::Display for BgpEVPN2 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:", self.rd)?;
        if self.esi_type != 0 {
            write!(f, "{}:", self.esi_type)?;
        }
        write!(f, "{}:{:08x}::{}::", self.esi, self.ether_tag, self.mac)?;
        if let Some(ip) = self.ip {
            ip.fmt(f)?;
        };
        write!(f, " {}", self.labels)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
// EVPN Inclusive Multicast Ethernet Tag route
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpEVPN3 {
    pub rd: BgpRD,
    pub ether_tag: u32,
    pub ip: std::net::IpAddr,
}
impl BgpAddrItem<BgpEVPN3> for BgpEVPN3 {
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(BgpEVPN3, usize), BgpError> {
        let rdp = BgpRD::decode_from(mode, buf)?;
        let etag = getn_u32(&buf[rdp.1..rdp.1 + 4]);
        let mut sz = rdp.1 + 5;
        let epaddr = match buf[rdp.1 + 4] {
            32 => {
                sz += 4;
                std::net::IpAddr::V4(decode_addrv4_from(&buf[rdp.1 + 5..])?)
            }
            128 => {
                sz += 16;
                std::net::IpAddr::V6(decode_addrv6_from(&buf[rdp.1 + 5..])?)
            }
            _ => {
                return Err(BgpError::from_string(format!(
                    "Invalid address size: {}",
                    buf[rdp.1 + 4]
                )));
            }
        };
        Ok((
            BgpEVPN3 {
                rd: rdp.0,
                ether_tag: etag,
                ip: epaddr,
            },
            sz,
        ))
    }
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut pos = self.rd.encode_to(mode, buf)?;
        setn_u32(self.ether_tag, &mut buf[pos..pos + 4]);
        pos += 4;
        match self.ip {
            IpAddr::V4(ip) => {
                buf[pos] = 32;
                pos += 1;
                encode_addrv4_to(&ip, &mut buf[pos..])?;
                pos += 4;
            }
            IpAddr::V6(ip) => {
                buf[pos] = 128;
                pos += 1;
                encode_addrv6_to(&ip, &mut buf[pos..])?;
                pos += 16;
            }
        }
        Ok(pos)
    }
}
impl std::fmt::Display for BgpEVPN3 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{:08x}:{}", self.rd, self.ether_tag, self.ip)
    }
}

/// EVPN Ethernet Segment Route
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpEVPN4 {
    pub rd: BgpRD,
    pub esi_type: u8,
    pub esi: EVPNESI,
    pub ip: std::net::IpAddr,
}
impl BgpAddrItem<BgpEVPN4> for BgpEVPN4 {
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(BgpEVPN4, usize), BgpError> {
        let rdp = BgpRD::decode_from(mode, buf)?;
        let mut sz = rdp.1;
        let esitype = buf[sz];
        let esib = &buf[sz + 1..sz + 10];
        sz += 11;
        let beg = sz;
        let epaddr = match buf[sz - 1] {
            32 => {
                sz += 4;
                std::net::IpAddr::V4(decode_addrv4_from(&buf[beg..])?)
            }
            128 => {
                sz += 16;
                std::net::IpAddr::V6(decode_addrv6_from(&buf[beg..])?)
            }
            _ => {
                return Err(BgpError::from_string(format!(
                    "Invalid address size: {}",
                    buf[sz - 1]
                )));
            }
        };
        Ok((
            BgpEVPN4 {
                rd: rdp.0,
                esi_type: esitype,
                esi: EVPNESI::new(esib),
                ip: epaddr,
            },
            sz,
        ))
    }
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut pos = self.rd.encode_to(mode, buf)?;
        if self.esi.v.len() == 9 {
            buf[pos] = self.esi_type;
            buf[pos + 1..pos + 10].copy_from_slice(self.esi.v.as_slice());
            pos += 10;
        } else {
            return Err(BgpError::static_str("l2vpn esi len != 9"));
        }
        match self.ip {
            IpAddr::V4(ip) => {
                buf[pos] = 32;
                pos += 1;
                encode_addrv4_to(&ip, &mut buf[pos..])?;
                pos += 4;
            }
            IpAddr::V6(ip) => {
                buf[pos] = 128;
                pos += 1;
                encode_addrv6_to(&ip, &mut buf[pos..])?;
                pos += 16;
            }
        }
        Ok(pos)
    }
}
impl std::fmt::Display for BgpEVPN4 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}:{}:{}", self.rd, self.esi_type, self.esi, self.ip)
    }
}

/// EVPN Prefix Advertisement Route
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpEVPN5 {
    pub rd: BgpRD,
    pub esi_type: u8,
    pub esi: EVPNESI,
    pub ether_tag: u32,
    pub len: u8,
    pub prefix: IpAddr,
    pub gw_ip: IpAddr,
    pub labels: MplsLabels,
}
impl BgpAddrItem<BgpEVPN5> for BgpEVPN5 {
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(BgpEVPN5, usize), BgpError> {
        let (rd, mut pos) = BgpRD::decode_from(mode, buf)?;
        let esi_type = buf[pos];
        let esib = &buf[pos + 1..pos + 10];
        pos += 10;
        let etag = getn_u32(&buf[pos..]);
        pos += 4;
        let len = buf[pos];
        pos += 1;
        let pfx;
        let gw;
        if buf.len() == 34 {
            pfx = decode_addrv4_from(&buf[pos..])?.into();
            gw = decode_addrv4_from(&buf[pos + 4..])?.into();
            pos += 8;
        } else if buf.len() == 58 {
            pfx = decode_addrv4_from(&buf[pos..])?.into();
            gw = decode_addrv4_from(&buf[pos + 16..])?.into();
            pos += 32;
        } else {
            return Err(BgpError::from_string(format!(
                "Expected an EVPN type-5 route of length 34 or 58, found {}",
                buf.len()
            )));
        }
        let lbls = MplsLabels::extract_bits_from((8 * (buf.len() - pos)) as u8, &buf[pos..])?;
        Ok((
            BgpEVPN5 {
                rd,
                esi_type,
                esi: EVPNESI::new(esib),
                ether_tag: etag,
                len,
                prefix: pfx,
                gw_ip: gw,
                labels: lbls.0,
            },
            pos + lbls.1,
        ))
    }
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut pos = self.rd.encode_to(mode, buf)?;
        if self.esi.v.len() == 9 {
            buf[pos] = self.esi_type;
            buf[pos + 1..pos + 10].copy_from_slice(self.esi.v.as_slice());
            pos += 10;
        } else {
            return Err(BgpError::static_str("l2vpn esi len != 9"));
        }
        setn_u32(self.ether_tag, &mut buf[pos..pos + 4]);
        pos += 4;
        buf[pos] = self.len;
        pos += 1;
        match (self.prefix, self.gw_ip) {
            (IpAddr::V4(prefix), IpAddr::V4(gw)) => {
                encode_addrv4_to(&prefix, &mut buf[pos..])?;
                encode_addrv4_to(&gw, &mut buf[pos + 4..])?;
                pos += 8;
            }
            (IpAddr::V6(prefix), IpAddr::V6(gw)) => {
                encode_addrv6_to(&prefix, &mut buf[pos..])?;
                encode_addrv6_to(&gw, &mut buf[pos + 16..])?;
                pos += 16;
            }
            _ => {
                return Err(BgpError::static_str(
                    "prefix and gateway ip are of different address families",
                ))
            }
        }
        let lbls = self.labels.set_bits_to(&mut buf[pos..])?;
        Ok(pos + lbls.1)
    }
}
impl std::fmt::Display for BgpEVPN5 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:", self.rd)?;
        if self.esi_type != 0 {
            write!(f, "{}:", self.esi_type)?;
        }
        write!(
            f,
            "{}:{}:{}/{}:{}:{}",
            self.esi, self.ether_tag, self.prefix, self.len, self.gw_ip, self.labels
        )
    }
}

/// EVPN route NLRI
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub enum BgpEVPN {
    EVPN1(BgpEVPN1),
    EVPN2(BgpEVPN2),
    EVPN3(BgpEVPN3),
    EVPN4(BgpEVPN4),
    EVPN5(BgpEVPN5),
}
impl std::fmt::Display for BgpEVPN {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BgpEVPN::EVPN1(s) => write!(f, "1:{}", s),
            BgpEVPN::EVPN2(s) => write!(f, "2:{}", s),
            BgpEVPN::EVPN3(s) => write!(f, "3:{}", s),
            BgpEVPN::EVPN4(s) => write!(f, "4:{}", s),
            BgpEVPN::EVPN5(s) => write!(f, "5:{}", s),
        }
    }
}
impl BgpAddrItem<BgpEVPN> for BgpEVPN {
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(BgpEVPN, usize), BgpError> {
        let evpntype = buf[0];
        let routelen = buf[1] as usize;
        if buf.len() < (routelen + 2) {
            return Err(BgpError::from_string(format!(
                "Invalid EVPN NLRI len: {}<{}",
                buf.len(),
                routelen + 2
            )));
        };
        match evpntype {
            1 => {
                let r = BgpEVPN1::decode_from(mode, &buf[2..(2 + routelen)])?;
                Ok((BgpEVPN::EVPN1(r.0), r.1 + 2))
            }
            2 => {
                let r = BgpEVPN2::decode_from(mode, &buf[2..(2 + routelen)])?;
                Ok((BgpEVPN::EVPN2(r.0), r.1 + 2))
            }
            3 => {
                let r = BgpEVPN3::decode_from(mode, &buf[2..(2 + routelen)])?;
                Ok((BgpEVPN::EVPN3(r.0), r.1 + 2))
            }
            4 => {
                let r = BgpEVPN4::decode_from(mode, &buf[2..(2 + routelen)])?;
                Ok((BgpEVPN::EVPN4(r.0), r.1 + 2))
            }
            5 => {
                let r = BgpEVPN5::decode_from(mode, &buf[2..(2 + routelen)])?;
                Ok((BgpEVPN::EVPN5(r.0), r.1 + 2))
            }
            _ => Err(BgpError::from_string(format!(
                "Unsupported EVPN route type: {:?}",
                buf
            ))),
        }
    }
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let pos = match self {
            Self::EVPN1(r) => {
                buf[0] = 1;
                r.encode_to(mode, &mut buf[2..])?
            }
            Self::EVPN2(r) => {
                buf[0] = 2;
                r.encode_to(mode, &mut buf[2..])?
            }
            Self::EVPN3(r) => {
                buf[0] = 3;
                r.encode_to(mode, &mut buf[2..])?
            }
            Self::EVPN4(r) => {
                buf[0] = 4;
                r.encode_to(mode, &mut buf[2..])?
            }
            Self::EVPN5(r) => {
                buf[0] = 5;
                r.encode_to(mode, &mut buf[2..])?
            }
        };
        match pos {
            0..=0xff => buf[1] = pos as u8,
            _ => return Err(BgpError::TooManyData),
        }

        Ok(pos + 2)
    }
}

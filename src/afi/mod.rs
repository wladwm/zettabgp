// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module describes NLRI data structures
use crate::util::*;
use crate::*;
#[cfg(feature = "serialization")]
use serde::de::{self, Visitor};
#[cfg(feature = "serialization")]
use serde::{ser::SerializeStruct, Deserialize, Serialize};

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
pub mod ipv4;
pub use ipv4::*;
pub mod ipv6;
pub use ipv6::*;
pub mod mac;
pub use mac::*;
pub mod mvpn;
pub use mvpn::*;
pub mod vpls;
pub use vpls::*;
pub mod evpn;
pub use evpn::*;
pub mod flowspec;
pub use flowspec::*;
pub mod mdt;
pub use mdt::*;

/// NLRI with bits length
pub trait BgpItem<T: std::marker::Sized> {
    fn extract_bits_from(bits: u8, buf: &[u8]) -> Result<(T, usize), BgpError>;
    fn set_bits_to(&self, buf: &mut [u8]) -> Result<(u8, usize), BgpError>;
    fn prefixlen(&self) -> usize;
}
/// NLRI with 2-byte length on each item
pub trait BgpItemLong<T: std::marker::Sized> {
    fn extract_from(size: usize, buf: &[u8]) -> Result<T, BgpError>;
    fn pack_to(&self, _buf: &mut [u8]) -> Result<usize, BgpError> {
        unimplemented!()
    }
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub enum BgpAddr {
    None,
    V4(std::net::Ipv4Addr),
    V6(std::net::Ipv6Addr),
    V4RD(BgpIPv4RD),
    V6RD(BgpIPv6RD),
    L2(BgpL2),
    MVPN(BgpMVPN),
}

/// Any kind of prefix - v4 or v6
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum BgpNet {
    /// ipv4 prefix
    V4(BgpAddrV4),
    /// ipv6 prefix
    V6(BgpAddrV6),
    /// mac prefix
    MAC(BgpAddrMac),
}

impl BgpNet {
    /// New net
    pub fn new(addr: std::net::IpAddr, prefixlen: u8) -> BgpNet {
        match addr {
            std::net::IpAddr::V4(ip4) => BgpNet::V4(BgpAddrV4::new(ip4, prefixlen)),
            std::net::IpAddr::V6(ip6) => BgpNet::V6(BgpAddrV6::new(ip6, prefixlen)),
        }
    }
    /// Check if given subnet is in this subnet
    pub fn contains(&self, a: &BgpNet) -> bool {
        match self {
            BgpNet::V4(s4) => match a {
                BgpNet::V4(a4) => s4.contains(a4),
                _ => false,
            },
            BgpNet::V6(s6) => match a {
                BgpNet::V6(a6) => s6.contains(a6),
                _ => false,
            },
            BgpNet::MAC(sm) => match a {
                BgpNet::MAC(am) => sm.contains(am),
                _ => false,
            },
        }
    }
}

impl std::str::FromStr for BgpNet {
    type Err = BgpError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(ip4) = s.parse::<BgpAddrV4>() {
            return Ok(BgpNet::V4(ip4));
        };
        if let Ok(ip6) = s.parse::<BgpAddrV6>() {
            return Ok(BgpNet::V6(ip6));
        };
        Ok(BgpNet::MAC(s.parse::<BgpAddrMac>()?))
    }
}
impl std::fmt::Display for BgpNet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BgpNet::V4(s4) => s4.fmt(f),
            BgpNet::V6(s6) => s6.fmt(f),
            BgpNet::MAC(sm) => sm.fmt(f),
        }
    }
}
#[cfg(feature = "serialization")]
impl serde::Serialize for BgpNet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}
#[cfg(feature = "serialization")]
struct BgpNetVisitor;

#[cfg(feature = "serialization")]
impl<'de> Visitor<'de> for BgpNetVisitor {
    type Value = BgpNet;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a ipv4/ipv6/mac prefix")
    }
    fn visit_str<E>(self, value: &str) -> Result<BgpNet, E>
    where
        E: serde::de::Error,
    {
        value.parse::<BgpNet>().map_err(de::Error::custom)
    }
}
#[cfg(feature = "serialization")]
impl<'de> serde::Deserialize<'de> for BgpNet {
    fn deserialize<D>(deserializer: D) -> Result<BgpNet, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_string(BgpNetVisitor)
    }
}

/// Represents variance of NLRI collections
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub enum BgpAddrs {
    None,
    IPV4U(Vec<BgpAddrV4>),
    IPV4M(Vec<BgpAddrV4>),
    IPV4LU(Vec<Labeled<BgpAddrV4>>),
    VPNV4U(Vec<Labeled<WithRd<BgpAddrV4>>>),
    VPNV4M(Vec<Labeled<WithRd<BgpAddrV4>>>),
    IPV4MDT(Vec<WithRd<BgpMdtV4>>),
    IPV4MDTP(Vec<WithPathId<WithRd<BgpMdtV4>>>),
    IPV6U(Vec<BgpAddrV6>),
    IPV6M(Vec<BgpAddrV6>),
    IPV6LU(Vec<Labeled<BgpAddrV6>>),
    VPNV6U(Vec<Labeled<WithRd<BgpAddrV6>>>),
    VPNV6M(Vec<Labeled<WithRd<BgpAddrV6>>>),
    IPV6MDT(Vec<WithRd<BgpMdtV6>>),
    IPV6MDTP(Vec<WithPathId<WithRd<BgpMdtV6>>>),
    L2VPLS(Vec<BgpAddrL2>),
    MVPN(Vec<BgpMVPN>),
    EVPN(Vec<BgpEVPN>),
    FS4U(Vec<BgpFlowSpec<BgpAddrV4>>),
    FS6U(Vec<BgpFlowSpec<FS6>>),
    FSV4U(Vec<BgpFlowSpec<FSV4U>>),
    IPV4UP(Vec<WithPathId<BgpAddrV4>>),
    IPV4MP(Vec<WithPathId<BgpAddrV4>>),
    IPV4LUP(Vec<WithPathId<Labeled<BgpAddrV4>>>),
    VPNV4UP(Vec<WithPathId<Labeled<WithRd<BgpAddrV4>>>>),
    VPNV4MP(Vec<WithPathId<Labeled<WithRd<BgpAddrV4>>>>),
    IPV6UP(Vec<WithPathId<BgpAddrV6>>),
    IPV6MP(Vec<WithPathId<BgpAddrV6>>),
    IPV6LUP(Vec<WithPathId<Labeled<BgpAddrV6>>>),
    VPNV6UP(Vec<WithPathId<Labeled<WithRd<BgpAddrV6>>>>),
    VPNV6MP(Vec<WithPathId<Labeled<WithRd<BgpAddrV6>>>>),
}

pub fn decode_bgpitem_from<T: BgpItem<T>>(buf: &[u8]) -> Result<(T, usize), BgpError> {
    let bits = buf[0];
    let r = T::extract_bits_from(bits, &buf[1..])?;
    Ok((r.0, r.1 + 1))
}
pub fn decode_bgpitems_from<T: BgpItem<T>>(buf: &[u8]) -> Result<(Vec<T>, usize), BgpError> {
    let mut v = Vec::<T>::new();
    let mut curpos = 0;
    while curpos < buf.len() {
        let nlri = decode_bgpitem_from(&buf[curpos..])?;
        v.push(nlri.0);
        curpos += nlri.1;
    }
    Ok((v, curpos))
}
pub fn encode_bgpitems_to<T: BgpItem<T>>(v: &[T], buf: &mut [u8]) -> Result<usize, BgpError> {
    let mut curpos = 0;
    for i in v.iter() {
        let r = i.set_bits_to(&mut buf[curpos + 1..])?;
        buf[curpos] = r.0;
        curpos += r.1 + 1;
    }
    Ok(curpos)
}
pub fn decode_bgpaddritems_from<T: BgpAddrItem<T>>(
    peermode: BgpTransportMode,
    buf: &[u8],
) -> Result<(Vec<T>, usize), BgpError> {
    let mut v = Vec::<T>::new();
    let mut curpos = 0;
    while curpos < buf.len() {
        let nlri = T::decode_from(peermode, &buf[curpos..])?;
        v.push(nlri.0);
        curpos += nlri.1;
    }
    Ok((v, curpos))
}
pub fn encode_bgpaddritems_to<T: BgpAddrItem<T>>(
    v: &[T],
    peermode: BgpTransportMode,
    buf: &mut [u8],
) -> Result<usize, BgpError> {
    let mut curpos = 0;
    for i in v {
        curpos += i.encode_to(peermode, &mut buf[curpos..])?;
    }
    Ok(curpos)
}
pub fn decode_long_bgpitems_from<T: BgpItemLong<T>>(
    buf: &[u8],
) -> Result<(Vec<T>, usize), BgpError> {
    let mut v = Vec::<T>::new();
    let mut curpos = 0;
    while curpos < buf.len() {
        let itemlen = getn_u16(&buf[curpos..(curpos + 2)]) as usize;
        v.push(T::extract_from(
            itemlen,
            &buf[curpos + 2..(curpos + itemlen + 2)],
        )?);
        curpos += itemlen + 2;
    }
    Ok((v, curpos))
}
pub fn encode_long_bgpitems_to<T: BgpItemLong<T>>(
    v: &[T],
    buf: &mut [u8],
) -> Result<usize, BgpError> {
    let mut curpos = 0;
    for i in v {
        let sz = i.pack_to(&mut buf[curpos + 2..])?;
        setn_u16(sz as u16, &mut buf[curpos..curpos + 2]);
        curpos += sz;
    }
    Ok(curpos)
}
pub fn decode_pathid_bgpitems_from<T: BgpItem<T> + Clone + PartialEq + Eq + PartialOrd>(
    buf: &[u8],
) -> Result<(Vec<WithPathId<T>>, usize), BgpError> {
    let mut v = Vec::<WithPathId<T>>::new();
    let mut curpos = 0;
    while (curpos + 4) < buf.len() {
        let pathid = getn_u32(&buf[curpos..]);
        curpos += 4;
        let nlri = decode_bgpitem_from(&buf[curpos..])?;
        v.push(WithPathId::<T>::new(pathid, nlri.0));
        curpos += nlri.1;
    }
    Ok((v, curpos))
}
pub fn encode_pathid_bgpitems_to<T: BgpItem<T> + Clone + PartialEq + Eq + PartialOrd>(
    v: &[WithPathId<T>],
    buf: &mut [u8],
) -> Result<usize, BgpError> {
    let mut curpos = 0;
    for i in v.iter() {
        setn_u32(i.pathid, &mut buf[curpos..]);
        curpos += 4;
        let r = i.nlri.set_bits_to(&mut buf[curpos + 1..])?;
        buf[curpos] = r.0;
        curpos += r.1 + 1;
    }
    Ok(curpos)
}
/// BGP VPN route distinguisher
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpRD {
    /// high-order part
    pub rdh: u32,
    /// low-order part
    pub rdl: u32,
}
impl BgpRD {
    /// Creates a new RD from a pair of numbers
    pub fn new(h: u32, l: u32) -> BgpRD {
        BgpRD { rdh: h, rdl: l }
    }
    /// Checks that RD is zero
    pub fn is_zero(&self) -> bool {
        (self.rdh == 0) && (self.rdl == 0)
    }
    /// decodes RD from bytes
    pub fn decode_rd_from(buf: &[u8]) -> Result<(BgpRD, usize), BgpError> {
        if buf.len() >= 8 {
            Ok((
                BgpRD {
                    rdh: getn_u32(&buf[0..4]),
                    rdl: getn_u32(&buf[4..8]),
                },
                8,
            ))
        } else {
            Err(BgpError::static_str("Invalid RD buffer len"))
        }
    }
    /// encodes RD into the buffer
    pub fn encode_rd_to(&self, buf: &mut [u8]) -> Result<usize, BgpError> {
        setn_u32(self.rdh, buf);
        setn_u32(self.rdl, &mut buf[4..8]);
        Ok(8)
    }
}
impl std::str::FromStr for BgpRD {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 2 {
            Ok(BgpRD {
                rdh: parts[0].parse::<u32>()?,
                rdl: 0,
            })
        } else {
            Ok(BgpRD {
                rdh: parts[0].parse::<u32>()?,
                rdl: parts[1].parse::<u32>()?,
            })
        }
    }
}
impl BgpAddrItem<BgpRD> for BgpRD {
    fn decode_from(_mode: BgpTransportMode, buf: &[u8]) -> Result<(BgpRD, usize), BgpError> {
        BgpRD::decode_rd_from(buf)
    }
    fn encode_to(&self, _mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        self.encode_rd_to(buf)
    }
}
impl std::fmt::Display for BgpRD {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if (self.rdh >> 16) == 1 {
            write!(
                f,
                "{}.{}.{}.{}:{}",
                (self.rdh >> 8) & 0xff,
                self.rdh & 0xff,
                (self.rdl >> 24) & 0xff,
                (self.rdl >> 16) & 0xff,
                self.rdl & 0xffff
            )
        } else {
            write!(f, "{}:{}", self.rdh, self.rdl)
        }
    }
}

impl std::fmt::Display for BgpAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BgpAddr::None => write!(f, "<>"),
            BgpAddr::V4(s) => write!(f, "{}", s),
            BgpAddr::V6(s) => write!(f, "{}", s),
            BgpAddr::V4RD(s) => write!(f, "{}", s),
            BgpAddr::V6RD(s) => write!(f, "{}", s),
            BgpAddr::L2(s) => write!(f, "{}", s),
            BgpAddr::MVPN(s) => write!(f, "{}", s),
        }
    }
}
/// MPLS labels as NLRI component
#[derive(Debug, Clone)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct MplsLabels {
    pub labels: Vec<u32>,
}
impl MplsLabels {
    /// creates a new empty label stack
    pub fn new() -> MplsLabels {
        MplsLabels { labels: Vec::new() }
    }
    /// creates a new label stack from vector
    pub fn fromvec(lbls: Vec<u32>) -> MplsLabels {
        MplsLabels { labels: lbls }
    }
}
impl Default for MplsLabels {
    fn default() -> Self {
        Self::new()
    }
}
impl Hash for MplsLabels {
    fn hash<H: Hasher>(&self, _state: &mut H) {
        //self.prefix.hash(state) //labels does not produce unique FEC
    }
}
impl PartialOrd for MplsLabels {
    fn partial_cmp(&self, _other: &Self) -> Option<std::cmp::Ordering> {
        None //labels does not produce unique FEC
    }
}
impl Ord for MplsLabels {
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        std::cmp::Ordering::Equal //labels does not produce unique FEC
    }
}
impl PartialEq for MplsLabels {
    fn eq(&self, _other: &Self) -> bool {
        true //labels does not produce unique FEC
    }
}
impl Eq for MplsLabels {}
impl std::fmt::Display for MplsLabels {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        //write!(f, "{:?}", self.labels)
        let mut first: bool = true;
        for l in self.labels.iter() {
            if !first {
                ",".fmt(f)?;
            }
            l.fmt(f)?;
            first = false;
        }
        Ok(())
    }
}

impl BgpItem<MplsLabels> for MplsLabels {
    fn extract_bits_from(bits: u8, buf: &[u8]) -> Result<(MplsLabels, usize), BgpError> {
        let mut lbls = Vec::<u32>::new();
        let mut curpos: usize = 0;
        let mut leftbits = bits;
        while leftbits > 0 {
            let labelval = (buf[curpos] as u32) << 12
                | (buf[curpos + 1] as u32) << 4
                | (buf[curpos + 2] as u32) >> 4;
            lbls.push(labelval);
            curpos += 3;
            leftbits -= 24;
            // special values ends stack
            match labelval {
                524288 => break, //withdraw
                0 => break,      //ExplicitNull
                2 => break,      //ExplicitNull6
                3 => break,      //ImplicitNull
                _ => {}
            }
            if (buf[curpos - 1] & 1) != 0 {
                break;
            }
        }
        Ok((MplsLabels { labels: lbls }, curpos))
    }
    fn set_bits_to(&self, buf: &mut [u8]) -> Result<(u8, usize), BgpError> {
        if self.labels.is_empty() {
            return Ok((0, 0));
        }
        let mut curpos: usize = 0;
        for l in self.labels.iter() {
            buf[curpos] = (l >> 12) as u8;
            buf[curpos + 1] = ((l >> 4) & 0xff) as u8;
            buf[curpos + 2] = ((l << 4) & 0xff) as u8;
            curpos += 3;
        }
        buf[curpos - 1] |= 1;
        Ok(((curpos * 8) as u8, curpos))
    }
    fn prefixlen(&self) -> usize {
        self.labels.len() * 24
    }
}
/// Labeled NLRI
#[derive(Debug, Clone)]
pub struct Labeled<T: BgpItem<T>> {
    /// underlying NLRI
    pub prefix: T,
    /// label stack
    pub labels: MplsLabels,
}
impl<T: BgpItem<T>> Labeled<T> {
    /// creates a new labeled NLRI
    pub fn new(lb: MplsLabels, inner: T) -> Labeled<T> {
        Labeled {
            labels: lb,
            prefix: inner,
        }
    }
    /// creates a new labeled NLRI with no labels
    pub fn new_nl(inner: T) -> Labeled<T> {
        Labeled {
            labels: MplsLabels::new(),
            prefix: inner,
        }
    }
}
impl<T: BgpItem<T> + PartialEq> PartialEq for Labeled<T> {
    fn eq(&self, other: &Self) -> bool {
        self.prefix.eq(&other.prefix)
    }
}
impl<T: BgpItem<T> + Eq> Eq for Labeled<T> {}
impl<T: BgpItem<T> + Hash> Hash for Labeled<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.prefix.hash(state) //labels does not produce unique FEC
    }
}
impl<T: BgpItem<T> + PartialOrd> PartialOrd for Labeled<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.prefix.partial_cmp(&other.prefix)
    }
}
impl<T: BgpItem<T> + Ord> Ord for Labeled<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.prefix.cmp(&other.prefix)
    }
}
impl<T: BgpItem<T>> BgpItem<Labeled<T>> for Labeled<T> {
    fn extract_bits_from(bits: u8, buf: &[u8]) -> Result<(Labeled<T>, usize), BgpError> {
        let l = MplsLabels::extract_bits_from(bits, buf)?;
        let p = T::extract_bits_from(bits - ((l.1 * 8) as u8), &buf[l.1..])?;
        Ok((
            Labeled {
                labels: l.0,
                prefix: p.0,
            },
            l.1 + p.1,
        ))
    }
    fn set_bits_to(&self, buf: &mut [u8]) -> Result<(u8, usize), BgpError> {
        let lblp = self.labels.set_bits_to(buf)?;
        let pfxp = self.prefix.set_bits_to(&mut buf[lblp.1..])?;
        Ok((lblp.0 + pfxp.0, lblp.1 + pfxp.1))
    }
    fn prefixlen(&self) -> usize {
        self.labels.prefixlen() + self.prefix.prefixlen()
    }
}
impl<T: BgpItem<T> + std::fmt::Display> std::fmt::Display for Labeled<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.labels.labels.is_empty() {
            write!(f, "{}", self.prefix)
        } else {
            write!(f, "<l:{}> {}", self.labels, self.prefix)
        }
    }
}
/// NRI with Route distinguisher
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct WithRd<T: BgpItem<T>> {
    pub prefix: T,
    pub rd: BgpRD,
}
impl<T: BgpItem<T>> WithRd<T> {
    pub fn new(rd: BgpRD, prefix: T) -> WithRd<T> {
        WithRd { rd, prefix }
    }
}
impl<T: BgpItem<T> + PartialOrd> PartialOrd for WithRd<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.prefix.partial_cmp(&other.prefix) {
            None => self.rd.partial_cmp(&other.rd),
            Some(pc) => match pc {
                Ordering::Less => Some(Ordering::Less),
                Ordering::Greater => Some(Ordering::Greater),
                Ordering::Equal => self.rd.partial_cmp(&other.rd),
            },
        }
    }
}
impl<T: BgpItem<T> + Ord> Ord for WithRd<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.prefix.cmp(&other.prefix) {
            Ordering::Less => Ordering::Less,
            Ordering::Greater => Ordering::Greater,
            Ordering::Equal => self.rd.cmp(&other.rd),
        }
    }
}
impl<T: BgpItem<T>> BgpItem<WithRd<T>> for WithRd<T> {
    fn extract_bits_from(bits: u8, buf: &[u8]) -> Result<(WithRd<T>, usize), BgpError> {
        if buf.len() < 8 {
            return Err(BgpError::InsufficientBufferSize);
        }
        let r = BgpRD::decode_from(BgpTransportMode::IPv4, &buf[0..8])?;
        let p = T::extract_bits_from(bits - ((r.1 * 8) as u8), &buf[r.1..])?;
        Ok((
            WithRd {
                rd: r.0,
                prefix: p.0,
            },
            r.1 + p.1,
        ))
    }
    fn set_bits_to(&self, buf: &mut [u8]) -> Result<(u8, usize), BgpError> {
        let rdpos = self.rd.encode_to(BgpTransportMode::IPv4, buf)?;
        let pfxp = self.prefix.set_bits_to(&mut buf[rdpos..])?;
        Ok(((((rdpos * 8) as u8) + pfxp.0), rdpos + pfxp.1))
    }
    fn prefixlen(&self) -> usize {
        64 + self.prefix.prefixlen()
    }
}
impl<T: BgpItem<T> + std::fmt::Debug> std::fmt::Debug for WithRd<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WithRd")
            .field("rd", &self.rd)
            .field("prefix", &self.prefix)
            .finish()
    }
}
impl<T: BgpItem<T> + std::fmt::Display> std::fmt::Display for WithRd<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.rd.is_zero() {
            write!(f, "{}", self.prefix)
        } else {
            write!(f, "<rd:{}> {}", self.rd, self.prefix)
        }
    }
}
pub type BgpPathId = u32;
/// NRI with PathId
#[derive(Clone)]
pub struct WithPathId<T: Clone + PartialEq + Eq + PartialOrd> {
    pub pathid: BgpPathId,
    pub nlri: T,
}
impl<T: Clone + PartialEq + Eq + PartialOrd> PartialEq for WithPathId<T> {
    fn eq(&self, other: &Self) -> bool {
        self.pathid.eq(&other.pathid) && self.nlri.eq(&other.nlri)
    }
}
impl<T: Clone + PartialEq + Eq + PartialOrd> Eq for WithPathId<T> {}
impl<T: Clone + PartialEq + Eq + PartialOrd + Hash> Hash for WithPathId<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pathid.hash(state);
        self.nlri.hash(state);
    }
}
impl<T: Clone + PartialEq + Eq + PartialOrd> WithPathId<T> {
    pub fn new(pathid: BgpPathId, nlri: T) -> WithPathId<T> {
        WithPathId { pathid, nlri }
    }
}
impl<T: Clone + PartialEq + Eq + PartialOrd> PartialOrd for WithPathId<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.nlri.partial_cmp(&other.nlri) {
            None => self.pathid.partial_cmp(&other.pathid),
            Some(pc) => match pc {
                Ordering::Less => Some(Ordering::Less),
                Ordering::Greater => Some(Ordering::Greater),
                Ordering::Equal => self.pathid.partial_cmp(&other.pathid),
            },
        }
    }
}
impl<T: Clone + PartialEq + Eq + Ord> Ord for WithPathId<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.nlri.cmp(&other.nlri) {
            Ordering::Less => Ordering::Less,
            Ordering::Greater => Ordering::Greater,
            Ordering::Equal => self.pathid.cmp(&other.pathid),
        }
    }
}
impl<T: Clone + PartialEq + Eq + PartialOrd + std::fmt::Debug> std::fmt::Debug for WithPathId<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WithPathId")
            .field("pathid", &self.pathid)
            .field("nlri", &self.nlri)
            .finish()
    }
}
impl<T: Clone + PartialEq + Eq + PartialOrd + std::fmt::Display> std::fmt::Display
    for WithPathId<T>
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.pathid == 0 {
            self.nlri.fmt(f)
        } else {
            write!(f, "<pathid:{}> {}", self.pathid, self.nlri)
        }
    }
}
impl Default for BgpAddrs {
    fn default() -> Self {
        Self::new()
    }
}
impl BgpAddrs {
    /// creates a new empty BgpAddrs
    pub fn new() -> BgpAddrs {
        BgpAddrs::None
    }
    pub fn is_empty(&self) -> bool {
        match self {
            BgpAddrs::None => true,
            BgpAddrs::IPV4U(v) => v.is_empty(),
            BgpAddrs::IPV4M(v) => v.is_empty(),
            BgpAddrs::IPV4LU(v) => v.is_empty(),
            BgpAddrs::VPNV4U(v) => v.is_empty(),
            BgpAddrs::VPNV4M(v) => v.is_empty(),
            BgpAddrs::IPV6U(v) => v.is_empty(),
            BgpAddrs::IPV6M(v) => v.is_empty(),
            BgpAddrs::IPV6LU(v) => v.is_empty(),
            BgpAddrs::VPNV6U(v) => v.is_empty(),
            BgpAddrs::VPNV6M(v) => v.is_empty(),
            BgpAddrs::L2VPLS(v) => v.is_empty(),
            BgpAddrs::MVPN(v) => v.is_empty(),
            BgpAddrs::EVPN(v) => v.is_empty(),
            BgpAddrs::FS4U(v) => v.is_empty(),
            BgpAddrs::FS6U(v) => v.is_empty(),
            BgpAddrs::FSV4U(v) => v.is_empty(),
            BgpAddrs::IPV4UP(v) => v.is_empty(),
            BgpAddrs::IPV4MP(v) => v.is_empty(),
            BgpAddrs::IPV4LUP(v) => v.is_empty(),
            BgpAddrs::VPNV4UP(v) => v.is_empty(),
            BgpAddrs::VPNV4MP(v) => v.is_empty(),
            BgpAddrs::IPV6UP(v) => v.is_empty(),
            BgpAddrs::IPV6MP(v) => v.is_empty(),
            BgpAddrs::IPV6LUP(v) => v.is_empty(),
            BgpAddrs::VPNV6UP(v) => v.is_empty(),
            BgpAddrs::VPNV6MP(v) => v.is_empty(),
            BgpAddrs::IPV4MDT(v) => v.is_empty(),
            BgpAddrs::IPV4MDTP(v) => v.is_empty(),
            BgpAddrs::IPV6MDT(v) => v.is_empty(),
            BgpAddrs::IPV6MDTP(v) => v.is_empty(),
        }
    }
    /// returns collection length
    pub fn len(&self) -> usize {
        match self {
            BgpAddrs::None => 0,
            BgpAddrs::IPV4U(v) => v.len(),
            BgpAddrs::IPV4M(v) => v.len(),
            BgpAddrs::IPV4LU(v) => v.len(),
            BgpAddrs::VPNV4U(v) => v.len(),
            BgpAddrs::VPNV4M(v) => v.len(),
            BgpAddrs::IPV6U(v) => v.len(),
            BgpAddrs::IPV6M(v) => v.len(),
            BgpAddrs::IPV6LU(v) => v.len(),
            BgpAddrs::VPNV6U(v) => v.len(),
            BgpAddrs::VPNV6M(v) => v.len(),
            BgpAddrs::L2VPLS(v) => v.len(),
            BgpAddrs::MVPN(v) => v.len(),
            BgpAddrs::EVPN(v) => v.len(),
            BgpAddrs::FS4U(v) => v.len(),
            BgpAddrs::FS6U(v) => v.len(),
            BgpAddrs::FSV4U(v) => v.len(),
            BgpAddrs::IPV4UP(v) => v.len(),
            BgpAddrs::IPV4MP(v) => v.len(),
            BgpAddrs::IPV4LUP(v) => v.len(),
            BgpAddrs::VPNV4UP(v) => v.len(),
            BgpAddrs::VPNV4MP(v) => v.len(),
            BgpAddrs::IPV6UP(v) => v.len(),
            BgpAddrs::IPV6MP(v) => v.len(),
            BgpAddrs::IPV6LUP(v) => v.len(),
            BgpAddrs::VPNV6UP(v) => v.len(),
            BgpAddrs::VPNV6MP(v) => v.len(),
            BgpAddrs::IPV4MDT(v) => v.len(),
            BgpAddrs::IPV4MDTP(v) => v.len(),
            BgpAddrs::IPV6MDT(v) => v.len(),
            BgpAddrs::IPV6MDTP(v) => v.len(),
        }
    }
    /// returns BGP afi+safi codes
    pub fn get_afi_safi(&self) -> (u16, u8) {
        match &self {
            BgpAddrs::None => (0, 0),
            BgpAddrs::IPV4U(_) => (1, 1),
            BgpAddrs::IPV4M(_) => (1, 2),
            BgpAddrs::IPV4LU(_) => (1, 4),
            BgpAddrs::MVPN(_) => (1, 5),
            BgpAddrs::VPNV4U(_) => (1, 128),
            BgpAddrs::VPNV4M(_) => (1, 129),
            BgpAddrs::FS4U(_) => (1, 133),
            BgpAddrs::FSV4U(_) => (1, 134),
            BgpAddrs::FS6U(_) => (2, 133),
            BgpAddrs::IPV6U(_) => (2, 1),
            BgpAddrs::IPV6M(_) => (2, 2),
            BgpAddrs::IPV6LU(_) => (2, 4),
            BgpAddrs::VPNV6U(_) => (2, 128),
            BgpAddrs::VPNV6M(_) => (2, 129),
            BgpAddrs::L2VPLS(_) => (25, 65),
            BgpAddrs::EVPN(_) => (25, 70),
            BgpAddrs::IPV4UP(_) => (1, 1),
            BgpAddrs::IPV4MP(_) => (1, 2),
            BgpAddrs::IPV4LUP(_) => (1, 4),
            BgpAddrs::VPNV4UP(_) => (1, 128),
            BgpAddrs::VPNV4MP(_) => (1, 129),
            BgpAddrs::IPV6UP(_) => (2, 1),
            BgpAddrs::IPV6MP(_) => (2, 2),
            BgpAddrs::IPV6LUP(_) => (2, 4),
            BgpAddrs::VPNV6UP(_) => (2, 128),
            BgpAddrs::VPNV6MP(_) => (2, 129),
            BgpAddrs::IPV4MDT(_) => (1, 66),
            BgpAddrs::IPV4MDTP(_) => (1, 66),
            BgpAddrs::IPV6MDT(_) => (2, 66),
            BgpAddrs::IPV6MDTP(_) => (2, 66),
        }
    }
    pub fn decode_from(
        peer: &BgpSessionParams,
        afi: u16,
        safi: u8,
        buf: &[u8],
    ) -> Result<(BgpAddrs, usize), BgpError> {
        match afi {
            1 => {
                //ipv4
                match safi {
                    1 => {
                        //unicast
                        if peer.check_addpath_receive(afi, safi) || (peer.fuzzy_pathid && is_addpath_nlri(buf)) {
                            let r = decode_pathid_bgpitems_from(buf)?;
                            Ok((BgpAddrs::IPV4UP(r.0), r.1))
                        } else {
                            let r = decode_bgpitems_from(buf)?;
                            Ok((BgpAddrs::IPV4U(r.0), r.1))
                        }
                    }
                    2 => {
                        //multicast
                        if peer.check_addpath_receive(afi, safi) || (peer.fuzzy_pathid && is_addpath_nlri(buf)) {
                            let r = decode_pathid_bgpitems_from(buf)?;
                            Ok((BgpAddrs::IPV4MP(r.0), r.1))
                        } else {
                            let r = decode_bgpitems_from(buf)?;
                            Ok((BgpAddrs::IPV4M(r.0), r.1))
                        }
                    }
                    4 => {
                        //labeled unicast
                        if peer.check_addpath_receive(afi, safi) || (peer.fuzzy_pathid && is_addpath_nlri(buf)) {
                            let r = decode_pathid_bgpitems_from(buf)?;
                            Ok((BgpAddrs::IPV4LUP(r.0), r.1))
                        } else {
                            let r = decode_bgpitems_from(buf)?;
                            Ok((BgpAddrs::IPV4LU(r.0), r.1))
                        }
                    }
                    5 => {
                        //mvpn v4
                        match decode_bgpaddritems_from(BgpTransportMode::IPv4, buf) {
                            Ok(r) => Ok((BgpAddrs::MVPN(r.0), r.1)),
                            Err(e) => {
                                log::debug!("MVPN decode error: {:?}\nbuf:{:?}", e, buf);
                                Err(e)
                            }
                        }
                    }
                    66 => {
                        //mdt
                        if peer.check_addpath_receive(afi, safi) || (peer.fuzzy_pathid && is_addpath_nlri(buf)) {
                            let r = decode_pathid_bgpitems_from(buf)?;
                            Ok((BgpAddrs::IPV4MDTP(r.0), r.1))
                        } else {
                            let r = decode_bgpitems_from(buf)?;
                            Ok((BgpAddrs::IPV4MDT(r.0), r.1))
                        }
                    }
                    128 => {
                        //vpnv4 unicast
                        if peer.check_addpath_receive(afi, safi) || (peer.fuzzy_pathid && is_addpath_nlri(buf)) {
                            let r = decode_pathid_bgpitems_from(buf)?;
                            Ok((BgpAddrs::VPNV4UP(r.0), r.1))
                        } else {
                            let r = decode_bgpitems_from(buf)?;
                            Ok((BgpAddrs::VPNV4U(r.0), r.1))
                        }
                    }
                    129 => {
                        //vpnv4 multicast
                        if peer.check_addpath_receive(afi, safi) || (peer.fuzzy_pathid && is_addpath_nlri(buf)) {
                            let r = decode_pathid_bgpitems_from(buf)?;
                            Ok((BgpAddrs::VPNV4MP(r.0), r.1))
                        } else {
                            let r = decode_bgpitems_from(buf)?;
                            Ok((BgpAddrs::VPNV4M(r.0), r.1))
                        }
                    }
                    133 => {
                        //ip4u flowspec
                        let r = decode_bgpaddritems_from(peer.peer_mode, buf)?;
                        Ok((BgpAddrs::FS4U(r.0), r.1))
                    }
                    134 => {
                        //vpn4u flowspec
                        let r = decode_bgpaddritems_from(peer.peer_mode, buf)?;
                        Ok((BgpAddrs::FSV4U(r.0), r.1))
                    }
                    n => Err(BgpError::from_string(format!(
                        "Unknown safi for ipv4 {:?}",
                        n
                    ))),
                }
            }
            2 => {
                //ipv6
                match safi {
                    1 => {
                        //unicast
                        if peer.check_addpath_receive(afi, safi) || (peer.fuzzy_pathid && is_addpath_nlri(buf)) {
                            let r = decode_pathid_bgpitems_from(buf)?;
                            Ok((BgpAddrs::IPV6UP(r.0), r.1))
                        } else {
                            let r = decode_bgpitems_from(buf)?;
                            Ok((BgpAddrs::IPV6U(r.0), r.1))
                        }
                    }
                    2 => {
                        //multicast
                        if peer.check_addpath_receive(afi, safi) || (peer.fuzzy_pathid && is_addpath_nlri(buf)) {
                            let r = decode_pathid_bgpitems_from(buf)?;
                            Ok((BgpAddrs::IPV6MP(r.0), r.1))
                        } else {
                            let r = decode_bgpitems_from(buf)?;
                            Ok((BgpAddrs::IPV6M(r.0), r.1))
                        }
                    }
                    4 => {
                        //labeled unicast
                        if peer.check_addpath_receive(afi, safi) || (peer.fuzzy_pathid && is_addpath_nlri(buf)) {
                            let r = decode_pathid_bgpitems_from(buf)?;
                            Ok((BgpAddrs::IPV6LUP(r.0), r.1))
                        } else {
                            let r = decode_bgpitems_from(buf)?;
                            Ok((BgpAddrs::IPV6LU(r.0), r.1))
                        }
                    }
                    66 => {
                        //mdt
                        if peer.check_addpath_receive(afi, safi) || (peer.fuzzy_pathid && is_addpath_nlri(buf)) {
                            let r = decode_pathid_bgpitems_from(buf)?;
                            Ok((BgpAddrs::IPV6MDTP(r.0), r.1))
                        } else {
                            let r = decode_bgpitems_from(buf)?;
                            Ok((BgpAddrs::IPV6MDT(r.0), r.1))
                        }
                    }
                    128 => {
                        //vpnv6 unicast
                        if peer.check_addpath_receive(afi, safi) || (peer.fuzzy_pathid && is_addpath_nlri(buf)) {
                            let r = decode_pathid_bgpitems_from(buf)?;
                            Ok((BgpAddrs::VPNV6UP(r.0), r.1))
                        } else {
                            let r = decode_bgpitems_from(buf)?;
                            Ok((BgpAddrs::VPNV6U(r.0), r.1))
                        }
                    }
                    129 => {
                        //vpnv6 multicast
                        if peer.check_addpath_receive(afi, safi) || (peer.fuzzy_pathid && is_addpath_nlri(buf)) {
                            let r = decode_pathid_bgpitems_from(buf)?;
                            Ok((BgpAddrs::VPNV6MP(r.0), r.1))
                        } else {
                            let r = decode_bgpitems_from(buf)?;
                            Ok((BgpAddrs::VPNV6M(r.0), r.1))
                        }
                    }
                    133 => {
                        //ip6u flowspec
                        let r = decode_bgpaddritems_from(peer.peer_mode, buf)?;
                        Ok((BgpAddrs::FS6U(r.0), r.1))
                    }
                    n => Err(BgpError::from_string(format!(
                        "Unknown safi for ipv6 {:?}",
                        n
                    ))),
                }
            }
            25 => {
                //l2
                match safi {
                    65 => {
                        //vpls
                        let r = decode_long_bgpitems_from(buf)?;
                        Ok((BgpAddrs::L2VPLS(r.0), r.1))
                    }
                    70 => {
                        //evpn
                        let r = decode_bgpaddritems_from(peer.peer_mode, buf)?;
                        Ok((BgpAddrs::EVPN(r.0), r.1))
                    }
                    n => Err(BgpError::from_string(format!(
                        "Unknown safi for l2 {:?}",
                        n
                    ))),
                }
            }
            n => Err(BgpError::from_string(format!("Unknown afi {:?}", n))),
        }
    }
    pub fn encode_to(&self, peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        match &self {
            BgpAddrs::None => Ok(0),
            BgpAddrs::IPV4U(v) => encode_bgpitems_to(v, buf),
            BgpAddrs::IPV4M(v) => encode_bgpitems_to(v, buf),
            BgpAddrs::IPV4LU(v) => encode_bgpitems_to(v, buf),
            BgpAddrs::MVPN(v) => encode_bgpaddritems_to(v, peer.peer_mode, buf),
            BgpAddrs::VPNV4U(v) => encode_bgpitems_to(v, buf),
            BgpAddrs::VPNV4M(v) => encode_bgpitems_to(v, buf),
            BgpAddrs::FS4U(v) => encode_bgpaddritems_to(v, peer.peer_mode, buf),
            BgpAddrs::FSV4U(v) => encode_bgpaddritems_to(v, peer.peer_mode, buf),
            BgpAddrs::FS6U(v) => encode_bgpaddritems_to(v, peer.peer_mode, buf),
            BgpAddrs::IPV6U(v) => encode_bgpitems_to(v, buf),
            BgpAddrs::IPV6M(v) => encode_bgpitems_to(v, buf),
            BgpAddrs::IPV6LU(v) => encode_bgpitems_to(v, buf),
            BgpAddrs::VPNV6U(v) => encode_bgpitems_to(v, buf),
            BgpAddrs::VPNV6M(v) => encode_bgpitems_to(v, buf),
            BgpAddrs::L2VPLS(v) => encode_long_bgpitems_to(v, buf),
            BgpAddrs::EVPN(v) => encode_bgpaddritems_to(v, peer.peer_mode, buf),
            BgpAddrs::IPV4UP(v) => encode_pathid_bgpitems_to(v, buf),
            BgpAddrs::IPV4MP(v) => encode_pathid_bgpitems_to(v, buf),
            BgpAddrs::IPV4LUP(v) => encode_pathid_bgpitems_to(v, buf),
            BgpAddrs::VPNV4UP(v) => encode_pathid_bgpitems_to(v, buf),
            BgpAddrs::VPNV4MP(v) => encode_pathid_bgpitems_to(v, buf),
            BgpAddrs::IPV6UP(v) => encode_pathid_bgpitems_to(v, buf),
            BgpAddrs::IPV6MP(v) => encode_pathid_bgpitems_to(v, buf),
            BgpAddrs::IPV6LUP(v) => encode_pathid_bgpitems_to(v, buf),
            BgpAddrs::VPNV6UP(v) => encode_pathid_bgpitems_to(v, buf),
            BgpAddrs::VPNV6MP(v) => encode_pathid_bgpitems_to(v, buf),
            BgpAddrs::IPV4MDT(v) => encode_bgpitems_to(v, buf),
            BgpAddrs::IPV4MDTP(v) => encode_pathid_bgpitems_to(v, buf),
            BgpAddrs::IPV6MDT(v) => encode_bgpitems_to(v, buf),
            BgpAddrs::IPV6MDTP(v) => encode_pathid_bgpitems_to(v, buf),
        }
    }
}
impl std::fmt::Display for BgpAddrs {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BgpAddrs {:?}", self)
    }
}

#[cfg(feature = "serialization")]
mod ser {
    use super::*;
    impl<T: BgpItem<T> + std::fmt::Debug + serde::Serialize> serde::Serialize for WithRd<T> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut state = serializer.serialize_struct("WithRd", 2)?;
            state.serialize_field("rd", &self.rd)?;
            state.serialize_field("prefix", &self.prefix)?;
            state.end()
        }
    }
    enum WithRdField {
        Rd,
        Prefix,
    }
    const WITHRD_FIELDS: [&str; 2] = ["rd", "prefix"];
    impl<'de> de::Deserialize<'de> for WithRdField {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            struct FieldVisitor;
            impl<'de> de::Visitor<'de> for FieldVisitor {
                type Value = WithRdField;
                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("`rd` or `prefix`")
                }
                fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<WithRdField, E> {
                    match value {
                        "rd" => Ok(WithRdField::Rd),
                        "prefix" => Ok(WithRdField::Prefix),
                        _ => Err(serde::de::Error::unknown_field(value, &WITHRD_FIELDS)),
                    }
                }
            }
            deserializer.deserialize_identifier(FieldVisitor)
        }
    }
    struct WithRdVisitor<T> {
        d: std::marker::PhantomData<T>,
    }
    impl<'de, T: BgpItem<T> + de::Deserialize<'de>> de::Visitor<'de> for WithRdVisitor<T> {
        type Value = WithRd<T>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("struct WithRd")
        }
        fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
        where
            V: serde::de::SeqAccess<'de>,
        {
            let rd = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(0, &self))?;
            let prefix = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(1, &self))?;
            Ok(WithRd::new(rd, prefix))
        }

        fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
        where
            V: serde::de::MapAccess<'de>,
        {
            let mut rd = None;
            let mut prefix = None;
            while let Some(key) = map.next_key()? {
                match key {
                    WithRdField::Rd => {
                        if rd.is_some() {
                            return Err(de::Error::duplicate_field(WITHRD_FIELDS[0]));
                        }
                        rd = Some(map.next_value()?);
                    }
                    WithRdField::Prefix => {
                        if prefix.is_some() {
                            return Err(de::Error::duplicate_field(WITHRD_FIELDS[1]));
                        }
                        prefix = Some(map.next_value()?);
                    }
                }
            }
            let rd = rd.ok_or_else(|| de::Error::missing_field(WITHRD_FIELDS[0]))?;
            let prefix = prefix.ok_or_else(|| de::Error::missing_field(WITHRD_FIELDS[1]))?;
            Ok(WithRd::new(rd, prefix))
        }
    }
    impl<'de, T: BgpItem<T> + de::Deserialize<'de>> de::Deserialize<'de> for WithRd<T> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            deserializer.deserialize_struct(
                "WithRd",
                &WITHRD_FIELDS,
                WithRdVisitor {
                    d: std::marker::PhantomData,
                },
            )
        }
    }
    impl<T: BgpItem<T> + serde::Serialize> serde::Serialize for Labeled<T> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut state = serializer.serialize_struct("Labeled", 2)?;
            state.serialize_field("labels", &self.labels)?;
            state.serialize_field("prefix", &self.prefix)?;
            state.end()
        }
    }
    enum LabeledField {
        Labels,
        Prefix,
    }
    const LABELED_FIELDS: [&str; 2] = ["labels", "prefix"];
    impl<'de> de::Deserialize<'de> for LabeledField {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            struct FieldVisitor;
            impl<'de> de::Visitor<'de> for FieldVisitor {
                type Value = LabeledField;
                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("`labels` or `prefix`")
                }
                fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<LabeledField, E> {
                    match value {
                        "labels" => Ok(LabeledField::Labels),
                        "prefix" => Ok(LabeledField::Prefix),
                        _ => Err(serde::de::Error::unknown_field(value, &LABELED_FIELDS)),
                    }
                }
            }
            deserializer.deserialize_identifier(FieldVisitor)
        }
    }
    struct LabeledVisitor<T> {
        d: std::marker::PhantomData<T>,
    }
    impl<'de, T: BgpItem<T> + de::Deserialize<'de>> de::Visitor<'de> for LabeledVisitor<T> {
        type Value = Labeled<T>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("struct Labeled")
        }
        fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
        where
            V: serde::de::SeqAccess<'de>,
        {
            let labels = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(0, &self))?;
            let prefix = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(1, &self))?;
            Ok(Labeled::new(labels, prefix))
        }

        fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
        where
            V: serde::de::MapAccess<'de>,
        {
            let mut labels = None;
            let mut prefix = None;
            while let Some(key) = map.next_key()? {
                match key {
                    LabeledField::Labels => {
                        if labels.is_some() {
                            return Err(de::Error::duplicate_field(LABELED_FIELDS[0]));
                        }
                        labels = Some(map.next_value()?);
                    }
                    LabeledField::Prefix => {
                        if prefix.is_some() {
                            return Err(de::Error::duplicate_field(LABELED_FIELDS[1]));
                        }
                        prefix = Some(map.next_value()?);
                    }
                }
            }
            let labels = labels.ok_or_else(|| de::Error::missing_field(LABELED_FIELDS[0]))?;
            let prefix = prefix.ok_or_else(|| de::Error::missing_field(LABELED_FIELDS[1]))?;
            Ok(Labeled::new(labels, prefix))
        }
    }
    impl<'de, T: BgpItem<T> + de::Deserialize<'de>> de::Deserialize<'de> for Labeled<T> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            deserializer.deserialize_struct(
                "Labeled",
                &LABELED_FIELDS,
                LabeledVisitor {
                    d: std::marker::PhantomData,
                },
            )
        }
    }
    impl<T: BgpItem<T> + serde::Serialize + Clone + PartialEq + Eq + PartialOrd> serde::Serialize
        for WithPathId<T>
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut state = serializer.serialize_struct("WithPathId", 2)?;
            state.serialize_field("pathid", &self.pathid)?;
            state.serialize_field("nlri", &self.nlri)?;
            state.end()
        }
    }
    enum WithPathIdField {
        Pathid,
        Nlri,
    }
    const WITHPATHID_FIELDS: [&str; 2] = ["pathid", "nlri"];
    impl<'de> de::Deserialize<'de> for WithPathIdField {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            struct FieldVisitor;
            impl<'de> de::Visitor<'de> for FieldVisitor {
                type Value = WithPathIdField;
                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("`pathid` or `nlri`")
                }
                fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<WithPathIdField, E> {
                    match value {
                        "pathid" => Ok(WithPathIdField::Pathid),
                        "nlri" => Ok(WithPathIdField::Nlri),
                        _ => Err(serde::de::Error::unknown_field(value, &WITHPATHID_FIELDS)),
                    }
                }
            }
            deserializer.deserialize_identifier(FieldVisitor)
        }
    }
    struct WithPathIdVisitor<T> {
        d: std::marker::PhantomData<T>,
    }
    impl<'de, T: Clone + PartialEq + Eq + PartialOrd + de::Deserialize<'de>> de::Visitor<'de>
        for WithPathIdVisitor<T>
    {
        type Value = WithPathId<T>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("struct WithRd")
        }
        fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
        where
            V: serde::de::SeqAccess<'de>,
        {
            let pathid = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(0, &self))?;
            let nlri = seq
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(1, &self))?;
            Ok(WithPathId::new(pathid, nlri))
        }

        fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
        where
            V: serde::de::MapAccess<'de>,
        {
            let mut pathid = None;
            let mut nlri = None;
            while let Some(key) = map.next_key()? {
                match key {
                    WithPathIdField::Pathid => {
                        if pathid.is_some() {
                            return Err(de::Error::duplicate_field(WITHPATHID_FIELDS[0]));
                        }
                        pathid = Some(map.next_value()?);
                    }
                    WithPathIdField::Nlri => {
                        if nlri.is_some() {
                            return Err(de::Error::duplicate_field(WITHPATHID_FIELDS[1]));
                        }
                        nlri = Some(map.next_value()?);
                    }
                }
            }
            let pathid = pathid.ok_or_else(|| de::Error::missing_field(WITHRD_FIELDS[0]))?;
            let nlri = nlri.ok_or_else(|| de::Error::missing_field(WITHRD_FIELDS[1]))?;
            Ok(WithPathId::new(pathid, nlri))
        }
    }
    impl<'de, T: Clone + PartialEq + Eq + PartialOrd + de::Deserialize<'de>> de::Deserialize<'de>
        for WithPathId<T>
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            deserializer.deserialize_struct(
                "WithPathId",
                &WITHPATHID_FIELDS,
                WithPathIdVisitor {
                    d: std::marker::PhantomData,
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmp_ipv4() {
        assert!(std::net::Ipv4Addr::new(10, 6, 7, 8) == std::net::Ipv4Addr::new(10, 6, 7, 8));
        assert!(std::net::Ipv4Addr::new(10, 0, 0, 1) < std::net::Ipv4Addr::new(11, 0, 0, 1));
    }
    #[test]
    fn test_cmp_rd() {
        assert!(BgpRD::new(1, 1) == BgpRD::new(1, 1));
        assert!(BgpRD::new(1, 1) < BgpRD::new(1, 2));
        assert!(BgpRD::new(2, 1) > BgpRD::new(1, 2));
    }
    #[test]
    fn test_cmp_bgpv4() {
        assert!(
            BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 32)
                == BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 32)
        );
        assert!(
            BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 30)
                < BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 32)
        );
        assert!(
            BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 30)
                > BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 6, 0), 32)
        );
    }
    #[test]
    fn test_cmp_bgpv4rd() {
        assert!(
            WithRd::<BgpAddrV4>::new(
                BgpRD::new(1, 1),
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 32)
            ) == WithRd::<BgpAddrV4>::new(
                BgpRD::new(1, 1),
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 32)
            )
        );
        assert!(
            WithRd::<BgpAddrV4>::new(
                BgpRD::new(1, 1),
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 32)
            ) != WithRd::<BgpAddrV4>::new(
                BgpRD::new(1, 2),
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 32)
            )
        );
        assert!(
            WithRd::<BgpAddrV4>::new(
                BgpRD::new(1, 1),
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 30)
            ) < WithRd::<BgpAddrV4>::new(
                BgpRD::new(1, 1),
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 32)
            )
        );
        assert!(
            WithRd::<BgpAddrV4>::new(
                BgpRD::new(1, 1),
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 30)
            ) > WithRd::<BgpAddrV4>::new(
                BgpRD::new(1, 1),
                BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 6, 0), 32)
            )
        );
    }
    #[test]
    fn test_cmp_bgpv4lb() {
        assert!(
            Labeled::<BgpAddrV4>::new_nl(BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 32))
                == Labeled::<BgpAddrV4>::new_nl(BgpAddrV4::new(
                    std::net::Ipv4Addr::new(10, 6, 7, 0),
                    32
                ))
        );
        assert!(
            Labeled::<BgpAddrV4>::new_nl(BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 30))
                < Labeled::<BgpAddrV4>::new_nl(BgpAddrV4::new(
                    std::net::Ipv4Addr::new(10, 6, 7, 0),
                    32
                ))
        );
        assert!(
            Labeled::<BgpAddrV4>::new_nl(BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 30))
                > Labeled::<BgpAddrV4>::new_nl(BgpAddrV4::new(
                    std::net::Ipv4Addr::new(10, 6, 6, 0),
                    32
                ))
        );
        assert!(
            Labeled::<BgpAddrV4>::new_nl(BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 32))
                == Labeled::<BgpAddrV4>::new(
                    MplsLabels::fromvec(vec![1, 2, 3, 4]),
                    BgpAddrV4::new(std::net::Ipv4Addr::new(10, 6, 7, 0), 32)
                )
        );
        assert!(
            Labeled::<BgpAddrV4>::new_nl(BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), 32))
                < Labeled::<BgpAddrV4>::new_nl(BgpAddrV4::new(
                    std::net::Ipv4Addr::new(11, 0, 0, 1),
                    32
                ))
        );
        assert!(
            Labeled::<BgpAddrV4>::new_nl(BgpAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 24))
                < Labeled::<BgpAddrV4>::new_nl(BgpAddrV4::new(
                    std::net::Ipv4Addr::new(11, 0, 0, 1),
                    32
                ))
        );
    }
}

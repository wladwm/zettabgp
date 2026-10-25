// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module describes NLRI data structures for flowspec <https://tools.ietf.org/html/rfc5575>
use std::fmt::Write;

use crate::afi::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

/// FlowSpec NLRI item trait
pub trait FSItem<T: std::marker::Sized> {
    fn decode_from_fs(buf: &[u8]) -> Result<(T, usize), BgpError>;
    fn encode_to_fs(&self, buf: &mut [u8]) -> Result<(), BgpError>;
    fn prefixlen(&self) -> usize;
    fn get_store_size(&self) -> usize;
}
impl FSItem<BgpAddrV4> for BgpAddrV4 {
    fn decode_from_fs(buf: &[u8]) -> Result<(BgpAddrV4, usize), BgpError> {
        let r = BgpAddrV4::from_bits(buf[0], &buf[1..])?;
        Ok((r.0, r.1 + 1))
    }
    fn encode_to_fs(&self, buf: &mut [u8]) -> Result<(), BgpError> {
        buf[0] = self.prefixlen;
        let _r = self.to_bits(&mut buf[1..])?;
        Ok(())
    }
    fn prefixlen(&self) -> usize {
        self.prefixlen as usize
    }
    fn get_store_size(&self) -> usize {
        1 + (((self.prefixlen as usize) + 7) / 8)
    }
}

/// FlowSpec NLRI ipv6 unicast
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
pub struct FS6 {
    pub ipv6: BgpAddrV6,
    pub offset: u8,
}
impl FS6 {
    pub fn new(offset: u8, ipv6: BgpAddrV6) -> FS6 {
        FS6 { ipv6, offset }
    }
}
impl std::convert::From<BgpAddrV6> for FS6 {
    fn from(ipv6: BgpAddrV6) -> FS6 {
        FS6 { ipv6, offset: 0 }
    }
}
impl FSItem<FS6> for FS6 {
    fn decode_from_fs(buf: &[u8]) -> Result<(FS6, usize), BgpError> {
        let v6 = BgpAddrV6::from_bits(buf[0], &buf[2..])?;
        Ok((
            FS6 {
                ipv6: v6.0,
                offset: buf[1],
            },
            v6.1 + 2,
        ))
    }
    fn encode_to_fs(&self, buf: &mut [u8]) -> Result<(), BgpError> {
        buf[0] = self.ipv6.prefixlen;
        buf[1] = self.offset;
        let _r = self.ipv6.to_bits(&mut buf[2..])?;
        Ok(())
    }
    fn prefixlen(&self) -> usize {
        self.ipv6.prefixlen as usize
    }
    fn get_store_size(&self) -> usize {
        2 + (((self.ipv6.prefixlen as usize) + 7) / 8)
    }
}
impl std::fmt::Display for FS6 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.ipv6.fmt(f)?;
        if self.offset != 0 {
            write!(f, "(offset={})", self.offset)?;
        }
        Ok(())
    }
}
impl std::str::FromStr for FS6 {
    type Err = BgpError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.ends_with(')') {
            let f = match s.find('(') {
                Some(q) => q,
                None => {
                    return Err(BgpError::DynStr(format!("Unable to parse: {}", s)));
                }
            };
            if !s[f..].starts_with("(offset=") {
                return Err(BgpError::DynStr(format!("Invalid offset: {}", s)));
            }
            let offset = s[(f + 8)..(s.len() - 1)]
                .parse()
                .map_err(|_| BgpError::DynStr(format!("Invalid offset: {}", s)))?;
            let ipv6 = s[..f].parse()?;
            return Ok(FS6 { ipv6, offset });
        }
        Ok(FS6 {
            ipv6: s.parse()?,
            offset: 0,
        })
    }
}
pub trait FSOperItem: Clone + PartialEq + Eq + PartialOrd + Ord {
    fn getbyteslen(&self) -> usize;
    fn encode_to(&self, buf: &mut [u8]) -> Result<usize, BgpError>;
    fn decode_from(buf: &[u8]) -> Result<(Self, usize), BgpError>;
}
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
pub struct FSOperValItem {
    pub and_bit: bool,
    pub lt_cmp: bool,
    pub gt_cmp: bool,
    pub eq_cmp: bool,
    pub value: u32,
}
impl FSOperValItem {
    pub fn new(v: u32, b_and: bool, b_lt: bool, b_gt: bool, b_eq: bool) -> FSOperValItem {
        FSOperValItem {
            and_bit: b_and,
            lt_cmp: b_lt,
            gt_cmp: b_gt,
            eq_cmp: b_eq,
            value: v,
        }
    }
}
impl std::fmt::Display for FSOperValItem {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{} {}",
            String::new()
                + (if self.and_bit { "&&" } else { " " })
                + (if self.lt_cmp { "<" } else { "" })
                + (if self.eq_cmp { "=" } else { "" })
                + (if self.gt_cmp { ">" } else { "" }),
            self.value
        )
    }
}
impl std::str::FromStr for FSOperValItem {
    type Err = std::num::ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut ret = FSOperValItem {
            and_bit: false,
            lt_cmp: false,
            gt_cmp: false,
            eq_cmp: false,
            value: 0,
        };
        let mut rest = s.strip_prefix(' ').unwrap_or(s);
        loop {
            if rest.starts_with("&&") {
                ret.and_bit = true;
                rest = &rest[2..];
                rest = rest.strip_prefix(' ').unwrap_or(rest);
                continue;
            };
            if rest.starts_with("<") {
                ret.lt_cmp = true;
                rest = &rest[1..];
                rest = rest.strip_prefix(' ').unwrap_or(rest);
                continue;
            };
            if rest.starts_with("=") {
                ret.eq_cmp = true;
                rest = &rest[1..];
                rest = rest.strip_prefix(' ').unwrap_or(rest);
                continue;
            };
            if rest.starts_with(">") {
                ret.gt_cmp = true;
                rest = &rest[1..];
                rest = rest.strip_prefix(' ').unwrap_or(rest);
                continue;
            };
            break;
        }
        ret.value = rest.parse()?;
        Ok(ret)
    }
}
impl FSOperItem for FSOperValItem {
    fn getbyteslen(&self) -> usize {
        if self.value > 0xffff {
            5
        } else if self.value > 0xff {
            3
        } else {
            1
        }
    }
    fn encode_to(&self, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut opbyte: u8 = 0;
        if self.and_bit {
            opbyte |= 64;
        };
        if self.lt_cmp {
            opbyte |= 4;
        }
        if self.gt_cmp {
            opbyte |= 2;
        }
        if self.eq_cmp {
            opbyte |= 1;
        }
        if self.value > 0xffff {
            opbyte |= 2 << 4;
            buf[0] = opbyte;
            setn_u32(self.value, &mut buf[1..]);
            Ok(5)
        } else if self.value > 0xff {
            opbyte |= 1 << 4;
            buf[0] = opbyte;
            setn_u16(self.value as u16, &mut buf[1..]);
            Ok(3)
        } else {
            buf[0] = opbyte;
            buf[1] = self.value as u8;
            Ok(2)
        }
    }
    fn decode_from(buf: &[u8]) -> Result<(Self, usize), BgpError> {
        let lng: usize;
        let vl: u32;
        if buf.len() < 2 {
            return Err(BgpError::ProtocolError(file!(), line!()));
        }
        match (buf[0] >> 4) & 0x3 {
            0 => {
                lng = 2;
                vl = buf[1] as u32;
            }
            1 => {
                if buf.len() < 3 {
                    return Err(BgpError::ProtocolError(file!(), line!()));
                }
                lng = 3;
                vl = getn_u16(&buf[1..]) as u32;
            }
            2 => {
                if buf.len() < 5 {
                    return Err(BgpError::ProtocolError(file!(), line!()));
                }
                lng = 5;
                vl = getn_u32(&buf[1..]);
            }
            _ => {
                return Err(BgpError::static_str(
                    "flowspec FSOperValItem invalid value len",
                ))
            }
        };
        Ok((
            FSOperValItem {
                and_bit: (buf[0] & 64) != 0,
                lt_cmp: (buf[0] & 4) != 0,
                gt_cmp: (buf[0] & 2) != 0,
                eq_cmp: (buf[0] & 1) != 0,
                value: vl,
            },
            lng,
        ))
    }
}
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct FSOperVec<T: FSOperItem> {
    items: Vec<T>,
}
impl<T: FSOperItem> std::default::Default for FSOperVec<T> {
    fn default() -> Self {
        Self { items: Vec::new() }
    }
}
impl<T: FSOperItem> FSOperVec<T> {
    pub fn new_empty() -> Self {
        Self { items: Vec::new() }
    }
    pub fn new(v: Vec<T>) -> Self {
        Self { items: v }
    }
    pub fn push(&mut self, i: T) {
        self.items.push(i)
    }
    pub fn iter<'s>(&'s self) -> std::slice::Iter<'s, T> {
        self.items.iter()
    }
    /*
    fn getbyteslen(&self) -> usize {
        let mut a: usize = 0;
        for c in &self.items {
            a += c.getbyteslen();
        }
        a
    }
    */
    fn encode_to(&self, buf: &mut [u8]) -> Result<usize, BgpError> {
        if self.items.is_empty() {
            return Ok(0);
        }
        let mut pos: usize = 0;
        let mut lpos: usize = 0;
        for c in &self.items {
            lpos = pos;
            pos += c.encode_to(&mut buf[pos..])?;
        }
        buf[lpos] |= 128;
        Ok(pos)
    }
    fn decode_from(buf: &[u8]) -> Result<(Self, usize), BgpError> {
        let mut v = Vec::<T>::new();
        let mut pos: usize = 0;
        while pos < buf.len() {
            let i = T::decode_from(&buf[pos..])?;
            v.push(i.0);
            let q = buf[pos];
            pos += i.1;
            if q & 128 > 0 {
                break;
            }
        }
        Ok((Self { items: v }, pos))
    }
}
impl<T: FSOperItem + std::fmt::Display> std::fmt::Display for FSOperVec<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_char('(')?;
        util::fmt_vec(self.items.iter(), ' ', f)?;
        f.write_char(')')
    }
}
impl<T: FSOperItem + std::str::FromStr> std::str::FromStr for FSOperVec<T> {
    type Err = BgpError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with('(') || !s.ends_with(')') {
            return Err(BgpError::Static("Invalid FSOperVec string to parse"));
        }
        let mut items = Vec::new();
        let mut beg = 1usize;
        let mut state = 0u8;
        let b = s.as_bytes();
        for i in 1..=b.len() {
            match state {
                0 => {
                    if i == b.len() {
                        break;
                    }
                    if b[i] == b' ' {
                        continue;
                    }
                    beg = i;
                    state = 1;
                    continue;
                }
                1 => {
                    if i == b.len() {
                        break;
                    }
                    if b[i] >= b'0' && b[i] <= b'9' {
                        state = 2;
                        continue;
                    }
                    continue;
                }
                2 => {
                    if i < b.len() && b[i] >= b'0' && b[i] <= b'9' {
                        continue;
                    }
                    match String::from_utf8_lossy(&b[beg..i]).parse() {
                        Ok(q) => items.push(q),
                        Err(_) => {
                            return Err(BgpError::DynStr(format!(
                                "Unable to parse '{}'",
                                String::from_utf8_lossy(&b[beg..i])
                            )))
                        }
                    }
                    state = 0;
                }
                _ => {}
            }
        }
        Ok(Self { items })
    }
}
#[cfg(feature = "serialization")]
impl<T: FSOperItem + serde::Serialize> serde::Serialize for FSOperVec<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.items.serialize(serializer)
    }
}
#[cfg(feature = "serialization")]
impl<'de, T: FSOperItem + de::Deserialize<'de>> de::Deserialize<'de> for FSOperVec<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Ok(FSOperVec {
            items: Vec::deserialize(deserializer)?,
        })
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
pub struct FSOperMaskItem {
    pub and_bit: bool,
    pub bit_not: bool,
    pub bit_match: bool,
    pub value: u32,
}
impl FSOperMaskItem {
    pub fn new(v: u32, b_and: bool, b_not: bool, b_match: bool) -> FSOperMaskItem {
        FSOperMaskItem {
            and_bit: b_and,
            bit_not: b_not,
            bit_match: b_match,
            value: v,
        }
    }
}
impl std::fmt::Display for FSOperMaskItem {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{} {}",
            String::new()
                + (if self.and_bit { "&&" } else { "||" })
                + (if self.bit_not { "!" } else { "" })
                + (if self.bit_match { "==" } else { "" }),
            self.value
        )
    }
}
impl std::str::FromStr for FSOperMaskItem {
    type Err = std::num::ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut ret = FSOperMaskItem {
            and_bit: false,
            bit_not: false,
            bit_match: false,
            value: 0,
        };
        let mut rest = s.strip_prefix(' ').unwrap_or(s);
        loop {
            if rest.starts_with("&&") {
                ret.and_bit = true;
                rest = &rest[2..];
                rest = rest.strip_prefix(' ').unwrap_or(rest);
                continue;
            };
            if rest.starts_with("||") {
                ret.and_bit = false;
                rest = &rest[2..];
                rest = rest.strip_prefix(' ').unwrap_or(rest);
                continue;
            };
            if rest.starts_with("!") {
                ret.bit_not = true;
                rest = &rest[1..];
                rest = rest.strip_prefix(' ').unwrap_or(rest);
                continue;
            };
            if rest.starts_with("==") {
                ret.bit_match = true;
                rest = &rest[2..];
                rest = rest.strip_prefix(' ').unwrap_or(rest);
                continue;
            };
            break;
        }
        ret.value = rest.parse()?;
        Ok(ret)
    }
}
impl FSOperItem for FSOperMaskItem {
    fn getbyteslen(&self) -> usize {
        if self.value > 0xffffff {
            5
        } else if self.value > 0xffff {
            3
        } else if self.value > 0xff {
            2
        } else {
            1
        }
    }
    fn encode_to(&self, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut opbyte: u8 = 0;
        if self.and_bit {
            opbyte |= 64;
        };
        if self.bit_not {
            opbyte |= 2;
        }
        if self.bit_match {
            opbyte |= 1;
        }
        if self.value > 0xffff {
            opbyte |= 2 << 4;
            buf[0] = opbyte;
            setn_u32(self.value, &mut buf[1..]);
            Ok(5)
        } else if self.value > 0xff {
            opbyte |= 1 << 4;
            buf[0] = opbyte;
            setn_u16(self.value as u16, &mut buf[1..]);
            Ok(3)
        } else {
            buf[0] = opbyte;
            buf[1] = self.value as u8;
            Ok(2)
        }
    }
    fn decode_from(buf: &[u8]) -> Result<(Self, usize), BgpError> {
        let lng: usize;
        let vl: u32;
        match (buf[0] >> 4) & 0x3 {
            0 => {
                lng = 2;
                vl = buf[1] as u32;
            }
            1 => {
                lng = 3;
                vl = getn_u16(&buf[1..]) as u32;
            }
            2 => {
                lng = 5;
                vl = getn_u32(&buf[1..]);
            }
            _ => {
                return Err(BgpError::static_str(
                    "flowspec FSOperMaskItem invalid value len",
                ))
            }
        };
        Ok((
            FSOperMaskItem {
                and_bit: (buf[0] & 64) != 0,
                bit_not: (buf[0] & 2) != 0,
                bit_match: (buf[0] & 1) != 0,
                value: vl,
            },
            lng,
        ))
    }
}
pub type FSCmpValOpers = FSOperVec<FSOperValItem>;
pub type FSCmpMaskOpers = FSOperVec<FSOperMaskItem>;
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum BgpFlowSpecItem<T: FSItem<T>> {
    PrefixDst(T),
    PrefixSrc(T),
    Proto(FSCmpValOpers),
    PortAny(FSCmpValOpers),
    PortDst(FSCmpValOpers),
    PortSrc(FSCmpValOpers),
    IcmpType(FSCmpValOpers),
    IcmpCode(FSCmpValOpers),
    TcpFlags(FSCmpMaskOpers),
    PacketLength(FSCmpValOpers),
    Dscp(FSCmpValOpers),
    Fragment(FSCmpMaskOpers),
    FlowLabel(FSCmpValOpers),
}
const BFSI_PDST: &'static str = "dst ";
const BFSI_PSRC: &'static str = "src ";
const BFSI_PROTO: &'static str = "proto ";
const BFSI_PORT: &'static str = "port ";
const BFSI_PORTDST: &'static str = "portdst ";
const BFSI_PORTSRC: &'static str = "portsrc ";
const BFSI_ICMPTYPE: &'static str = "icmptype ";
const BFSI_ICMPCODE: &'static str = "icmpcode ";
const BFSI_TCPFLAGS: &'static str = "tcpflags ";
const BFSI_LEN: &'static str = "len ";
const BFSI_DSCP: &'static str = "dscp ";
const BFSI_FRAG: &'static str = "frag ";
const BFSI_FLOWLABEL: &'static str = "flowlabel ";
impl<T: FSItem<T> + std::fmt::Display> std::fmt::Display for BgpFlowSpecItem<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use BgpFlowSpecItem::*;
        match self {
            PrefixDst(v) => {
                f.write_str(BFSI_PDST)?;
                v.fmt(f)
            }
            PrefixSrc(v) => {
                f.write_str(BFSI_PSRC)?;
                v.fmt(f)
            }
            Proto(v) => {
                f.write_str(BFSI_PROTO)?;
                v.fmt(f)
            }
            PortAny(v) => {
                f.write_str(BFSI_PORT)?;
                v.fmt(f)
            }
            PortDst(v) => {
                f.write_str(BFSI_PORTDST)?;
                v.fmt(f)
            }
            PortSrc(v) => {
                f.write_str(BFSI_PORTSRC)?;
                v.fmt(f)
            }
            IcmpType(v) => {
                f.write_str(BFSI_ICMPTYPE)?;
                v.fmt(f)
            }
            IcmpCode(v) => {
                f.write_str(BFSI_ICMPCODE)?;
                v.fmt(f)
            }
            TcpFlags(v) => {
                f.write_str(BFSI_TCPFLAGS)?;
                v.fmt(f)
            }
            PacketLength(v) => {
                f.write_str(BFSI_LEN)?;
                v.fmt(f)
            }
            Dscp(v) => {
                f.write_str(BFSI_DSCP)?;
                v.fmt(f)
            }
            Fragment(v) => {
                f.write_str(BFSI_FRAG)?;
                v.fmt(f)
            }
            FlowLabel(v) => {
                f.write_str(BFSI_FLOWLABEL)?;
                v.fmt(f)
            }
        }
    }
}
impl<T> std::str::FromStr for BgpFlowSpecItem<T>
where
    T: FSItem<T> + std::str::FromStr,
    T::Err: std::error::Error,
{
    type Err = BgpError;
    fn from_str(ss: &str) -> Result<Self, Self::Err> {
        let s = ss.trim();
        if s.starts_with(BFSI_PDST) {
            return Ok(BgpFlowSpecItem::PrefixDst(
                s[BFSI_PDST.len()..]
                    .parse()
                    .map_err(|e| BgpError::DynStr(format!("{}", e)))?,
            ));
        }
        if s.starts_with(BFSI_PSRC) {
            return Ok(BgpFlowSpecItem::PrefixSrc(
                s[BFSI_PSRC.len()..]
                    .parse()
                    .map_err(|e| BgpError::DynStr(format!("{}", e)))?,
            ));
        }
        if s.starts_with(BFSI_PROTO) {
            return Ok(BgpFlowSpecItem::Proto(s[BFSI_PROTO.len()..].parse()?));
        }
        if s.starts_with(BFSI_PORT) {
            return Ok(BgpFlowSpecItem::PortAny(s[BFSI_PORT.len()..].parse()?));
        }
        if s.starts_with(BFSI_PORTDST) {
            return Ok(BgpFlowSpecItem::PortDst(s[BFSI_PORTDST.len()..].parse()?));
        }
        if s.starts_with(BFSI_PORTSRC) {
            return Ok(BgpFlowSpecItem::PortSrc(s[BFSI_PORTSRC.len()..].parse()?));
        }
        if s.starts_with(BFSI_ICMPTYPE) {
            return Ok(BgpFlowSpecItem::IcmpType(s[BFSI_ICMPTYPE.len()..].parse()?));
        }
        if s.starts_with(BFSI_ICMPCODE) {
            return Ok(BgpFlowSpecItem::IcmpCode(s[BFSI_ICMPCODE.len()..].parse()?));
        }
        if s.starts_with(BFSI_TCPFLAGS) {
            return Ok(BgpFlowSpecItem::TcpFlags(s[BFSI_TCPFLAGS.len()..].parse()?));
        }
        if s.starts_with(BFSI_LEN) {
            return Ok(BgpFlowSpecItem::PacketLength(s[BFSI_LEN.len()..].parse()?));
        }
        if s.starts_with(BFSI_DSCP) {
            return Ok(BgpFlowSpecItem::Dscp(s[BFSI_DSCP.len()..].parse()?));
        }
        if s.starts_with(BFSI_FRAG) {
            return Ok(BgpFlowSpecItem::Fragment(s[BFSI_FRAG.len()..].parse()?));
        }
        if s.starts_with("flowlabel ") {
            return Ok(BgpFlowSpecItem::FlowLabel(
                s[BFSI_FLOWLABEL.len()..].parse()?,
            ));
        }
        Err(BgpError::DynStr(format!("Unable to parse: '{}'", s)))
    }
}
impl<T: FSItem<T>> BgpAddrItem<BgpFlowSpecItem<T>> for BgpFlowSpecItem<T> {
    fn decode_from(_mode: BgpTransportMode, buf: &[u8]) -> Result<(Self, usize), BgpError> {
        let pos = 0usize;
        if buf.len() < 2 {
            return Err(BgpError::InsufficientBufferSize(file!(), line!()));
        };
        match buf[pos] {
            1 => {
                let r = T::decode_from_fs(&buf[pos + 1..])?;
                Ok((BgpFlowSpecItem::PrefixDst(r.0), pos + 1 + r.1))
            }
            2 => {
                let r = T::decode_from_fs(&buf[pos + 1..])?;
                Ok((BgpFlowSpecItem::PrefixSrc(r.0), pos + 1 + r.1))
            }
            3 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..])?;
                Ok((BgpFlowSpecItem::Proto(r.0), r.1 + pos + 1))
            }
            4 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..])?;
                Ok((BgpFlowSpecItem::PortAny(r.0), r.1 + pos + 1))
            }
            5 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..])?;
                Ok((BgpFlowSpecItem::PortDst(r.0), r.1 + pos + 1))
            }
            6 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..])?;
                Ok((BgpFlowSpecItem::PortSrc(r.0), r.1 + pos + 1))
            }
            7 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..])?;
                Ok((BgpFlowSpecItem::IcmpType(r.0), r.1 + pos + 1))
            }
            8 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..])?;
                Ok((BgpFlowSpecItem::IcmpCode(r.0), r.1 + pos + 1))
            }
            9 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..])?;
                Ok((BgpFlowSpecItem::TcpFlags(r.0), r.1 + pos + 1))
            }
            10 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..])?;
                Ok((BgpFlowSpecItem::PacketLength(r.0), r.1 + pos + 1))
            }
            11 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..])?;
                Ok((BgpFlowSpecItem::Dscp(r.0), r.1 + pos + 1))
            }
            12 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..])?;
                Ok((BgpFlowSpecItem::Fragment(r.0), r.1 + pos + 1))
            }
            13 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..])?;
                Ok((BgpFlowSpecItem::FlowLabel(r.0), r.1 + pos + 1))
            }
            _ => Err(BgpError::from_string(format!(
                "Unknown flowspec typecode {}",
                buf[pos]
            ))),
            //_ => Err(BgpError::static_str("Unknown flowspec typecode")),
        }
    }
    fn encode_to(&self, _mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let pos = 0;
        let tail = match self {
            BgpFlowSpecItem::PrefixDst(a) => {
                buf[pos] = 1;
                a.encode_to_fs(&mut buf[pos + 1..])?;
                pos + a.get_store_size() + 1
            }
            BgpFlowSpecItem::PrefixSrc(a) => {
                buf[pos] = 2;
                a.encode_to_fs(&mut buf[pos + 1..])?;
                pos + a.get_store_size() + 1
            }
            BgpFlowSpecItem::Proto(v) => {
                buf[pos] = 3;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpecItem::PortAny(v) => {
                buf[pos] = 4;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpecItem::PortDst(v) => {
                buf[pos] = 5;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpecItem::PortSrc(v) => {
                buf[pos] = 6;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpecItem::IcmpType(v) => {
                buf[pos] = 7;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpecItem::IcmpCode(v) => {
                buf[pos] = 8;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpecItem::TcpFlags(v) => {
                buf[pos] = 9;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpecItem::PacketLength(v) => {
                buf[pos] = 10;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpecItem::Dscp(v) => {
                buf[pos] = 11;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpecItem::Fragment(v) => {
                buf[pos] = 12;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpecItem::FlowLabel(v) => {
                buf[pos] = 13;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
        };
        Ok(tail)
    }
}
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BgpFlowSpec<T: FSItem<T>> {
    pub items: Vec<BgpFlowSpecItem<T>>,
}
impl<T: FSItem<T>> BgpFlowSpec<T> {
    pub fn new(items: Vec<BgpFlowSpecItem<T>>) -> Self {
        Self { items }
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}
impl<T: FSItem<T>> std::default::Default for BgpFlowSpec<T> {
    fn default() -> Self {
        Self { items: Vec::new() }
    }
}
impl<T: FSItem<T>> std::convert::From<BgpFlowSpecItem<T>> for BgpFlowSpec<T> {
    fn from(f: BgpFlowSpecItem<T>) -> Self {
        Self { items: vec![f] }
    }
}
impl<T: FSItem<T> + std::fmt::Display> std::fmt::Display for BgpFlowSpec<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        util::fmt_vec(self.items.iter(), " && ", f)
    }
}
impl<T> std::str::FromStr for BgpFlowSpec<T>
where
    T: FSItem<T> + std::str::FromStr,
    T::Err: std::error::Error,
{
    type Err = BgpError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut items = Vec::new();
        let sb = s.trim().as_bytes();
        let mut state = 0u8;
        let mut prvpos = 0usize;
        for ps in 0..=sb.len() {
            match state {
                0 => {
                    if ps >= sb.len() || sb[ps..].starts_with(b"&&") {
                        items.push(String::from_utf8_lossy(&sb[prvpos..ps]).parse()?);
                        prvpos = ps + 2;
                    }
                    if ps >= sb.len() {
                        break;
                    }
                    if sb[ps] == b'(' {
                        state = 1;
                    }
                }
                1 => {
                    if ps >= sb.len() {
                        return Err(BgpError::DynStr(format!("Mismatch open brace in '{}'", s)));
                    }
                    if sb[ps] == b')' {
                        state = 0;
                    }
                }
                _ => {}
            }
        }
        Ok(Self { items })
    }
}
impl<T: FSItem<T>> BgpAddrItem<BgpFlowSpec<T>> for BgpFlowSpec<T> {
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(Self, usize), BgpError> {
        let mut pos: usize;
        let nlen = if (buf[0] & 0xf0) == 0xf0 {
            pos = 2;
            ((getn_u16(buf) & 0xfff) as usize) + pos
        } else {
            pos = 1;
            (buf[0] as usize) + pos
        };
        let mut items = Vec::new();
        while pos < nlen {
            let q = BgpFlowSpecItem::<T>::decode_from(mode, &buf[pos..])?;
            items.push(q.0);
            pos += q.1;
        }
        Ok((Self { items }, pos))
    }
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut pos = 2usize;
        for i in self.items.iter() {
            pos += i.encode_to(mode, &mut buf[pos..])?;
        }
        if pos > 0xfff {
            return Err(BgpError::InsufficientBufferSize(file!(), line!()));
        }
        if (pos - 2) < 240 {
            for n in 0..(pos - 2) {
                buf[n + 1] = buf[n + 2];
            }
            pos = pos - 1;
            buf[0] = (pos - 1) as u8;
        } else {
            setn_u16(pos as u16, buf);
            buf[0] = buf[0] | 0xf0;
        }
        Ok(pos)
    }
}
#[cfg(feature = "serialization")]
impl<T: FSItem<T> + serde::Serialize> serde::Serialize for BgpFlowSpec<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.items.serialize(serializer)
    }
}
#[cfg(feature = "serialization")]
impl<'de, T: FSItem<T> + de::Deserialize<'de>> de::Deserialize<'de> for BgpFlowSpec<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Ok(BgpFlowSpec {
            items: Vec::deserialize(deserializer)?,
        })
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BgpFlowSpecRD<T: FSItem<T>> {
    pub rd: BgpRD,
    pub items: Vec<BgpFlowSpecItem<T>>,
}
impl<T: FSItem<T>> BgpFlowSpecRD<T> {
    pub fn new(rd: BgpRD, items: Vec<BgpFlowSpecItem<T>>) -> Self {
        Self { rd, items }
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}
impl<T: FSItem<T>> std::default::Default for BgpFlowSpecRD<T> {
    fn default() -> Self {
        Self {
            rd: BgpRD::new(0, 0),
            items: Vec::new(),
        }
    }
}
impl<T: FSItem<T> + std::fmt::Display> std::fmt::Display for BgpFlowSpecRD<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "<rd:{}> ", self.rd)?;
        util::fmt_vec(self.items.iter(), " && ", f)
    }
}
impl<T> std::str::FromStr for BgpFlowSpecRD<T>
where
    T: FSItem<T> + std::str::FromStr,
    T::Err: std::error::Error,
{
    type Err = BgpError;
    fn from_str(ss: &str) -> Result<Self, Self::Err> {
        let s = ss.trim();
        if !s.starts_with("<rd:") {
            return Err(format!("Invalid BgpFlowSpecRD: '{}'", s).into());
        }
        let endrd = match s[4..].find('>') {
            None => return Err(format!("Invalid BgpFlowSpecRD: '{}'", s).into()),
            Some(p) => p,
        };
        let rd = s[4..(4 + endrd)].parse::<BgpRD>()?;

        let mut items = Vec::new();
        let sb = s[endrd + 5..].trim().as_bytes();
        let mut state = 0u8;
        let mut prvpos = 0usize;
        for ps in 0..=sb.len() {
            match state {
                0 => {
                    if ps >= sb.len() || sb[ps..].starts_with(b"&&") {
                        items.push(String::from_utf8_lossy(&sb[prvpos..ps]).parse()?);
                        prvpos = ps + 2;
                    }
                    if ps >= sb.len() {
                        break;
                    }
                    if sb[ps] == b'(' {
                        state = 1;
                    }
                }
                1 => {
                    if ps >= sb.len() {
                        return Err(BgpError::DynStr(format!("Mismatch open brace in '{}'", s)));
                    }
                    if sb[ps] == b')' {
                        state = 0;
                    }
                }
                _ => {}
            }
        }
        Ok(Self { rd, items })
    }
}
impl<T: FSItem<T>> BgpAddrItem<BgpFlowSpecRD<T>> for BgpFlowSpecRD<T> {
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(Self, usize), BgpError> {
        let mut pos: usize;
        let nlen = if (buf[0] & 0xf0) == 0xf0 {
            pos = 2;
            ((getn_u16(buf) & 0xfff) as usize) + pos
        } else {
            pos = 1;
            (buf[0] as usize) + pos
        };
        let (rd, nps) = BgpRD::decode_rd_from(&buf[pos..])?;
        pos += nps;
        let mut items = Vec::new();
        while pos < nlen {
            let q = BgpFlowSpecItem::<T>::decode_from(mode, &buf[pos..])?;
            items.push(q.0);
            pos += q.1;
        }
        Ok((Self { rd, items }, pos))
    }
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut pos = 10usize;
        let _ = self.rd.encode_rd_to(&mut buf[2..])?;
        for i in self.items.iter() {
            pos += i.encode_to(mode, &mut buf[pos..])?;
        }
        if pos > 0xfff {
            return Err(BgpError::InsufficientBufferSize(file!(), line!()));
        }
        if (pos - 2) < 240 {
            for n in 0..(pos - 2) {
                buf[n + 1] = buf[n + 2];
            }
            pos = pos - 1;
            buf[0] = (pos - 1) as u8;
        } else {
            setn_u16(pos as u16, buf);
            buf[0] = buf[0] | 0xf0;
        }
        Ok(pos)
    }
}
#[cfg(feature = "serialization")]
mod ser {
    use std::marker::PhantomData;

    use super::*;
    const BFS_N: &str = "BgpFlowSpecItem";
    const BFS_VARS: [&str; 13] = [
        "PrefixDst",
        "PrefixSrc",
        "Proto",
        "PortAny",
        "PortDst",
        "PortSrc",
        "IcmpType",
        "IcmpCode",
        "TcpFlags",
        "PacketLength",
        "DSCP",
        "Fragment",
        "FlowLabel",
    ];
    impl<T: FSItem<T> + serde::Serialize> serde::Serialize for BgpFlowSpecItem<T> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            match self {
                BgpFlowSpecItem::PrefixDst(a) => {
                    serializer.serialize_newtype_variant(BFS_N, 0, BFS_VARS[0], a)
                }
                BgpFlowSpecItem::PrefixSrc(a) => {
                    serializer.serialize_newtype_variant(BFS_N, 1, BFS_VARS[1], a)
                }
                BgpFlowSpecItem::Proto(a) => {
                    serializer.serialize_newtype_variant(BFS_N, 2, BFS_VARS[2], a)
                }
                BgpFlowSpecItem::PortAny(a) => {
                    serializer.serialize_newtype_variant(BFS_N, 3, BFS_VARS[3], a)
                }
                BgpFlowSpecItem::PortDst(a) => {
                    serializer.serialize_newtype_variant(BFS_N, 4, BFS_VARS[4], a)
                }
                BgpFlowSpecItem::PortSrc(a) => {
                    serializer.serialize_newtype_variant(BFS_N, 5, BFS_VARS[5], a)
                }
                BgpFlowSpecItem::IcmpType(a) => {
                    serializer.serialize_newtype_variant(BFS_N, 6, BFS_VARS[6], a)
                }
                BgpFlowSpecItem::IcmpCode(a) => {
                    serializer.serialize_newtype_variant(BFS_N, 7, BFS_VARS[7], a)
                }
                BgpFlowSpecItem::TcpFlags(a) => {
                    serializer.serialize_newtype_variant(BFS_N, 8, BFS_VARS[8], a)
                }
                BgpFlowSpecItem::PacketLength(a) => {
                    serializer.serialize_newtype_variant(BFS_N, 9, BFS_VARS[9], a)
                }
                BgpFlowSpecItem::Dscp(a) => {
                    serializer.serialize_newtype_variant(BFS_N, 10, BFS_VARS[10], a)
                }
                BgpFlowSpecItem::Fragment(a) => {
                    serializer.serialize_newtype_variant(BFS_N, 11, BFS_VARS[11], a)
                }
                BgpFlowSpecItem::FlowLabel(a) => {
                    serializer.serialize_newtype_variant(BFS_N, 12, BFS_VARS[12], a)
                }
            }
        }
    }
    enum BgpFlowSpecVariant {
        PrefixDst,
        PrefixSrc,
        Proto,
        PortAny,
        PortDst,
        PortSrc,
        IcmpType,
        IcmpCode,
        TcpFlags,
        PacketLength,
        Dscp,
        Fragment,
        FlowLabel,
    }
    impl<'de> de::Deserialize<'de> for BgpFlowSpecVariant {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            struct VariantVisitor;
            impl<'de> de::Visitor<'de> for VariantVisitor {
                type Value = BgpFlowSpecVariant;
                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    write!(formatter, "expecting one of: {:?}", BFS_VARS)
                }
                fn visit_str<E: serde::de::Error>(
                    self,
                    value: &str,
                ) -> Result<BgpFlowSpecVariant, E> {
                    match value {
                        "PrefixDst" => Ok(BgpFlowSpecVariant::PrefixDst),
                        "PrefixSrc" => Ok(BgpFlowSpecVariant::PrefixSrc),
                        "Proto" => Ok(BgpFlowSpecVariant::Proto),
                        "PortAny" => Ok(BgpFlowSpecVariant::PortAny),
                        "PortDst" => Ok(BgpFlowSpecVariant::PortDst),
                        "PortSrc" => Ok(BgpFlowSpecVariant::PortSrc),
                        "IcmpType" => Ok(BgpFlowSpecVariant::IcmpType),
                        "IcmpCode" => Ok(BgpFlowSpecVariant::IcmpCode),
                        "TcpFlags" => Ok(BgpFlowSpecVariant::TcpFlags),
                        "PacketLength" => Ok(BgpFlowSpecVariant::PacketLength),
                        "DSCP" => Ok(BgpFlowSpecVariant::Dscp),
                        "Fragment" => Ok(BgpFlowSpecVariant::Fragment),
                        "FlowLabel" => Ok(BgpFlowSpecVariant::FlowLabel),
                        _ => Err(serde::de::Error::unknown_field(value, &BFS_VARS)),
                    }
                }
            }
            deserializer.deserialize_identifier(VariantVisitor)
        }
    }
    struct BgpFlowSpecVisitor<T: FSItem<T>> {
        d: std::marker::PhantomData<T>,
    }
    impl<'de, T: FSItem<T> + de::Deserialize<'de>> de::Visitor<'de> for BgpFlowSpecVisitor<T> {
        type Value = BgpFlowSpecItem<T>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("enum BgpFlowSpec")
        }
        fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
        where
            V: serde::de::MapAccess<'de>,
        {
            if let Some(key) = map.next_key()? {
                match key {
                    BgpFlowSpecVariant::PrefixDst => {
                        Ok(BgpFlowSpecItem::PrefixDst(map.next_value()?))
                    }
                    BgpFlowSpecVariant::PrefixSrc => {
                        Ok(BgpFlowSpecItem::PrefixSrc(map.next_value()?))
                    }
                    BgpFlowSpecVariant::Proto => Ok(BgpFlowSpecItem::Proto(map.next_value()?)),
                    BgpFlowSpecVariant::PortAny => Ok(BgpFlowSpecItem::PortAny(map.next_value()?)),
                    BgpFlowSpecVariant::PortDst => Ok(BgpFlowSpecItem::PortDst(map.next_value()?)),
                    BgpFlowSpecVariant::PortSrc => Ok(BgpFlowSpecItem::PortSrc(map.next_value()?)),
                    BgpFlowSpecVariant::IcmpType => {
                        Ok(BgpFlowSpecItem::IcmpType(map.next_value()?))
                    }
                    BgpFlowSpecVariant::IcmpCode => {
                        Ok(BgpFlowSpecItem::IcmpCode(map.next_value()?))
                    }
                    BgpFlowSpecVariant::TcpFlags => {
                        Ok(BgpFlowSpecItem::TcpFlags(map.next_value()?))
                    }
                    BgpFlowSpecVariant::PacketLength => {
                        Ok(BgpFlowSpecItem::PacketLength(map.next_value()?))
                    }
                    BgpFlowSpecVariant::Dscp => Ok(BgpFlowSpecItem::Dscp(map.next_value()?)),
                    BgpFlowSpecVariant::Fragment => {
                        Ok(BgpFlowSpecItem::Fragment(map.next_value()?))
                    }
                    BgpFlowSpecVariant::FlowLabel => {
                        Ok(BgpFlowSpecItem::FlowLabel(map.next_value()?))
                    }
                }
            } else {
                Err(de::Error::missing_field(BFS_VARS[0]))
            }
        }
    }
    impl<'de, T: FSItem<T> + de::Deserialize<'de>> de::Deserialize<'de> for BgpFlowSpecItem<T> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            deserializer.deserialize_enum(
                BFS_N,
                &BFS_VARS,
                BgpFlowSpecVisitor {
                    d: std::marker::PhantomData,
                },
            )
        }
    }
    impl<T: FSItem<T> + serde::Serialize> serde::Serialize for BgpFlowSpecRD<T> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut map = serializer.serialize_struct("BgpFlowSpecRD", 2)?;
            map.serialize_field("rd", &self.rd)?;
            map.serialize_field("items", &self.items)?;
            map.end()
        }
    }

    impl<'de, T: FSItem<T> + serde::de::Deserialize<'de>> serde::de::Deserialize<'de>
        for BgpFlowSpecRD<T>
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::de::Deserializer<'de>,
        {
            #[derive(Clone, Debug, Serialize, Deserialize)]
            #[allow(non_camel_case_types)]
            enum BgpFlowSpecRDField {
                rd,
                items,
            }
            const BFSRDF_VARS: [&str; 2] = ["rd", "items"];

            struct BgpFlowSpecRDVisitor<Q> {
                phantom: std::marker::PhantomData<Q>,
            }
            impl<'de, Q: FSItem<Q> + serde::de::Deserialize<'de>> serde::de::Visitor<'de>
                for BgpFlowSpecRDVisitor<Q>
            {
                type Value = BgpFlowSpecRD<Q>;
                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("struct BgpFlowSpecRD")
                }
                fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
                where
                    V: serde::de::SeqAccess<'de>,
                {
                    let rd = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                    let items = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                    Ok(Self::Value { rd, items })
                }

                fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
                where
                    V: serde::de::MapAccess<'de>,
                {
                    let mut rd = None;
                    let mut items = None;
                    while let Some(key) = map.next_key()? {
                        match key {
                            BgpFlowSpecRDField::rd => {
                                if rd.is_some() {
                                    return Err(serde::de::Error::duplicate_field(BFSRDF_VARS[0]));
                                }
                                rd = Some(map.next_value()?);
                            }
                            BgpFlowSpecRDField::items => {
                                if items.is_some() {
                                    return Err(serde::de::Error::duplicate_field(BFSRDF_VARS[1]));
                                }
                                items = Some(map.next_value()?);
                            }
                        }
                    }

                    let rd = rd.ok_or_else(|| serde::de::Error::missing_field(BFSRDF_VARS[0]))?;
                    let items =
                        items.ok_or_else(|| serde::de::Error::missing_field(BFSRDF_VARS[1]))?;

                    Ok(Self::Value { rd, items })
                }
            }
            deserializer.deserialize_struct(
                "BgpFlowSpecRD",
                &BFSRDF_VARS,
                BgpFlowSpecRDVisitor {
                    phantom: std::marker::PhantomData,
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fs1_parse() {
        assert_eq!(
            "=1024".parse::<FSOperValItem>().unwrap(),
            FSOperValItem {
                and_bit: false,
                lt_cmp: false,
                gt_cmp: false,
                eq_cmp: true,
                value: 1024
            }
        );
        assert_eq!(
            " = 1024".parse::<FSOperValItem>().unwrap(),
            FSOperValItem {
                and_bit: false,
                lt_cmp: false,
                gt_cmp: false,
                eq_cmp: true,
                value: 1024
            }
        );
        assert_eq!(
            ">1024".parse::<FSOperValItem>().unwrap(),
            FSOperValItem {
                and_bit: false,
                lt_cmp: false,
                gt_cmp: true,
                eq_cmp: false,
                value: 1024
            }
        );
        assert_eq!(
            ">=1024".parse::<FSOperValItem>().unwrap(),
            FSOperValItem {
                and_bit: false,
                lt_cmp: false,
                gt_cmp: true,
                eq_cmp: true,
                value: 1024
            }
        );
        assert_eq!(
            "<= 1024".parse::<FSOperValItem>().unwrap(),
            FSOperValItem {
                and_bit: false,
                lt_cmp: true,
                gt_cmp: false,
                eq_cmp: true,
                value: 1024
            }
        );
        assert_eq!(
            "&&=> 1024".parse::<FSOperValItem>().unwrap(),
            FSOperValItem {
                and_bit: true,
                lt_cmp: false,
                gt_cmp: true,
                eq_cmp: true,
                value: 1024
            }
        );
    }
    //FSOperVec
    #[test]
    fn test_fs2_parse() {
        let v1 = FSOperVec::new(vec![
            FSOperValItem {
                and_bit: false,
                lt_cmp: true,
                gt_cmp: false,
                eq_cmp: true,
                value: 2048,
            },
            FSOperValItem {
                and_bit: true,
                lt_cmp: false,
                gt_cmp: true,
                eq_cmp: true,
                value: 1024,
            },
        ]);
        assert_eq!(
            "(<= 2048 &&=> 1024)"
                .parse::<FSOperVec<FSOperValItem>>()
                .unwrap(),
            v1
        );
    }
    #[test]
    fn test_fs3_parse() {
        let ds4 = BgpFlowSpec::<BgpAddrV4>::new(vec![
            BgpFlowSpecItem::<BgpAddrV4>::PrefixDst(BgpAddrV4::new(
                std::net::Ipv4Addr::new(188, 128, 45, 219),
                32,
            )),
            BgpFlowSpecItem::<BgpAddrV4>::Proto(FSOperVec::new(vec![FSOperValItem::new(
                17, false, false, false, true,
            )])),
            BgpFlowSpecItem::<BgpAddrV4>::PortSrc(FSOperVec::new(vec![
                FSOperValItem::new(0, false, false, false, true),
                FSOperValItem::new(17, false, false, false, true),
                FSOperValItem::new(19, false, false, false, true),
            ])),
        ]);
        assert_eq!(
            ds4,
            "  dst 188.128.45.219/32 && proto ( =17) && portsrc (=0 =17 =19) "
                .parse::<BgpFlowSpec<BgpAddrV4>>()
                .unwrap()
        );
    }
    #[test]
    fn test_fs4_parse() {
        let ds6 = BgpFlowSpec::<FS6>::new(vec![
            BgpFlowSpecItem::<FS6>::PrefixDst(FS6::new(
                0,
                BgpAddrV6::new(
                    std::net::Ipv6Addr::new(0x2a02, 0xdead, 0xb00b, 0, 0, 0, 0, 1),
                    128,
                ),
            )),
            BgpFlowSpecItem::<FS6>::Proto(FSOperVec::new(vec![FSOperValItem::new(
                17, false, false, false, true,
            )])),
            BgpFlowSpecItem::<FS6>::PortSrc(FSOperVec::new(vec![
                FSOperValItem::new(0, false, false, false, true),
                FSOperValItem::new(17, false, false, false, true),
                FSOperValItem::new(19, false, false, false, true),
            ])),
        ]);
        assert_eq!(
            ds6,
            "  dst 2a02:dead:b00b::1/128 && proto ( =17) && portsrc (=0 =17 =19) "
                .parse::<BgpFlowSpec<FS6>>()
                .unwrap()
        );
    }
    #[test]
    fn test_fs5_parse() {
        let ds6 = BgpFlowSpec::<FS6>::new(vec![
            BgpFlowSpecItem::<FS6>::PrefixDst(FS6::new(
                8,
                BgpAddrV6::new(
                    std::net::Ipv6Addr::new(0x2a02, 0xdead, 0xbeef, 0xb00b, 0, 0, 0, 1),
                    128,
                ),
            )),
            BgpFlowSpecItem::<FS6>::Proto(FSOperVec::new(vec![FSOperValItem::new(
                17, false, false, false, true,
            )])),
            BgpFlowSpecItem::<FS6>::PortSrc(FSOperVec::new(vec![
                FSOperValItem::new(0, false, false, false, true),
                FSOperValItem::new(17, false, false, false, true),
                FSOperValItem::new(19, false, false, false, true),
            ])),
        ]);
        assert_eq!(
            ds6,
            "  dst 2a02:dead:beef:b00b::1/128(offset=8) && proto ( =17) && portsrc (=0 =17 =19) "
                .parse::<BgpFlowSpec<FS6>>()
                .unwrap()
        );
    }
}

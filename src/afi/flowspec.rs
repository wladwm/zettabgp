// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module describes NLRI data structures for flowspec https://tools.ietf.org/html/rfc5575
use crate::afi::*;

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
pub struct FS6 {
    pub ipv6: BgpAddrV6,
    pub offset: u8,
}
impl FS6 {
    pub fn new(ofs: u8, v6: BgpAddrV6) -> FS6 {
        FS6 {
            ipv6: v6,
            offset: ofs,
        }
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

/// FlowSpec NLRI vpnv4 unicast
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct FSV4U {
    pub prefix: WithRd<BgpAddrV4>,
}
impl FSV4U {
    pub fn new(p: WithRd<BgpAddrV4>) -> FSV4U {
        FSV4U { prefix: p }
    }
}
impl FSItem<FSV4U> for FSV4U {
    fn decode_from_fs(buf: &[u8]) -> Result<(FSV4U, usize), BgpError> {
        let rd = BgpRD::decode_rd_from(&buf[1..])?;
        let pf = BgpAddrV4::from_bits(buf[0] - 64, &buf[rd.1 + 1..])?;
        Ok((
            FSV4U {
                prefix: WithRd::<BgpAddrV4>::new(rd.0, pf.0),
            },
            rd.1 + pf.1 + 1,
        ))
    }
    fn encode_to_fs(&self, buf: &mut [u8]) -> Result<(), BgpError> {
        buf[0] = 0;
        buf[1] = 0;
        let _r = self.prefix.set_bits_to(&mut buf[2..])?;
        Ok(())
    }
    fn prefixlen(&self) -> usize {
        (self.prefix.prefix.prefixlen as usize) + 64
    }
    fn get_store_size(&self) -> usize {
        10 + (((self.prefix.prefix.prefixlen as usize) + 7) / 8)
    }
}

pub trait FSOperItem: Clone + PartialEq + Eq + PartialOrd + Ord {
    fn getbyteslen(&self) -> usize;
    fn encode_to(&self, buf: &mut [u8]) -> Result<usize, BgpError>;
    fn decode_from(buf: &[u8]) -> Result<(Self, usize), BgpError>;
}
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
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
                + (if self.and_bit { "&&" } else { "||" })
                + (if self.lt_cmp { "<" } else { "" })
                + (if self.eq_cmp { "=" } else { "" })
                + (if self.gt_cmp { ">" } else { "" }),
            self.value
        )
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
    fn getbyteslen(&self) -> usize {
        let mut a: usize = 0;
        for c in &self.items {
            a += c.getbyteslen();
        }
        a
    }
    fn encode_to(&self, buf: &mut [u8]) -> Result<usize, BgpError> {
        if self.items.len() < 1 {
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
            pos += i.1;
        }
        Ok((Self { items: v }, pos))
    }
}
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
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
type FSCmpValOpers = FSOperVec<FSOperValItem>;
type FSCmpMaskOpers = FSOperVec<FSOperMaskItem>;
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum BgpFlowSpec<T: FSItem<T>> {
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
    DSCP(FSCmpValOpers),
    Fragment(FSCmpMaskOpers),
    FlowLabel(FSCmpValOpers),
}
impl<T: FSItem<T> + std::fmt::Debug> std::fmt::Display for BgpFlowSpec<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl<T: FSItem<T>> BgpAddrItem<BgpFlowSpec<T>> for BgpFlowSpec<T> {
    fn decode_from(_mode: BgpTransportMode, buf: &[u8]) -> Result<(Self, usize), BgpError> {
        let pos: usize;
        let nlen = if (buf[0] & 0xf0) == 0xf0 {
            pos = 2;
            ((getn_u16(buf) & 0xfff) as usize) + pos
        } else {
            pos = 1;
            (buf[0] as usize) + pos
        };
        match buf[pos] {
            1 => {
                let r = T::decode_from_fs(&buf[pos + 1..nlen])?;
                Ok((BgpFlowSpec::PrefixDst(r.0), pos + 2 + r.1))
            }
            2 => {
                let r = T::decode_from_fs(&buf[pos + 1..nlen])?;
                Ok((BgpFlowSpec::PrefixSrc(r.0), pos + 2 + r.1))
            }
            3 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..nlen])?;
                Ok((BgpFlowSpec::Proto(r.0), r.1 + pos + 1))
            }
            4 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..nlen])?;
                Ok((BgpFlowSpec::PortAny(r.0), r.1 + pos + 1))
            }
            5 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..nlen])?;
                Ok((BgpFlowSpec::PortDst(r.0), r.1 + pos + 1))
            }
            6 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..nlen])?;
                Ok((BgpFlowSpec::PortSrc(r.0), r.1 + pos + 1))
            }
            7 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..nlen])?;
                Ok((BgpFlowSpec::IcmpType(r.0), r.1 + pos + 1))
            }
            8 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..nlen])?;
                Ok((BgpFlowSpec::IcmpCode(r.0), r.1 + pos + 1))
            }
            9 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..nlen])?;
                Ok((BgpFlowSpec::TcpFlags(r.0), r.1 + pos + 1))
            }
            10 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..nlen])?;
                Ok((BgpFlowSpec::PacketLength(r.0), r.1 + pos + 1))
            }
            11 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..nlen])?;
                Ok((BgpFlowSpec::DSCP(r.0), r.1 + pos + 1))
            }
            12 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..nlen])?;
                Ok((BgpFlowSpec::Fragment(r.0), r.1 + pos + 1))
            }
            13 => {
                let r = FSOperVec::decode_from(&buf[pos + 1..nlen])?;
                Ok((BgpFlowSpec::FlowLabel(r.0), r.1 + pos + 1))
            }
            _ => Err(BgpError::static_str("Unknown flowspec typecode")),
        }
    }
    fn encode_to(&self, _mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let pos;
        let nlen = match self {
            BgpFlowSpec::PrefixDst(a) => 1 + a.get_store_size(),
            BgpFlowSpec::PrefixSrc(a) => 1 + a.get_store_size(),
            BgpFlowSpec::Proto(v) => 2 + v.getbyteslen(),
            BgpFlowSpec::PortAny(v) => 2 + v.getbyteslen(),
            BgpFlowSpec::PortDst(v) => 2 + v.getbyteslen(),
            BgpFlowSpec::PortSrc(v) => 2 + v.getbyteslen(),
            BgpFlowSpec::IcmpType(v) => 2 + v.getbyteslen(),
            BgpFlowSpec::IcmpCode(v) => 2 + v.getbyteslen(),
            BgpFlowSpec::TcpFlags(v) => 2 + v.getbyteslen(),
            BgpFlowSpec::PacketLength(v) => 2 + v.getbyteslen(),
            BgpFlowSpec::DSCP(v) => 2 + v.getbyteslen(),
            BgpFlowSpec::Fragment(v) => 2 + v.getbyteslen(),
            BgpFlowSpec::FlowLabel(v) => 2 + v.getbyteslen(),
        };
        if nlen > 4094 {
            return Err(BgpError::insufficient_buffer_size());
        };
        if nlen < 240 {
            if buf.len() < (nlen + 1) {
                return Err(BgpError::insufficient_buffer_size());
            }
            buf[0] = nlen as u8;
            pos = 1;
        } else {
            if buf.len() < (nlen + 2) {
                return Err(BgpError::insufficient_buffer_size());
            }
            setn_u16(nlen as u16, buf);
            buf[0] |= 0xf0;
            pos = 2;
        };
        let tail = match self {
            BgpFlowSpec::PrefixDst(a) => {
                buf[pos] = 1;
                a.encode_to_fs(&mut buf[pos + 1..])?;
                pos + a.get_store_size() + 1
            }
            BgpFlowSpec::PrefixSrc(a) => {
                buf[pos] = 2;
                a.encode_to_fs(&mut buf[pos + 1..])?;
                pos + a.get_store_size() + 1
            }
            BgpFlowSpec::Proto(v) => {
                buf[pos] = 3;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpec::PortAny(v) => {
                buf[pos] = 4;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpec::PortDst(v) => {
                buf[pos] = 5;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpec::PortSrc(v) => {
                buf[pos] = 6;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpec::IcmpType(v) => {
                buf[pos] = 7;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpec::IcmpCode(v) => {
                buf[pos] = 8;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpec::TcpFlags(v) => {
                buf[pos] = 9;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpec::PacketLength(v) => {
                buf[pos] = 10;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpec::DSCP(v) => {
                buf[pos] = 11;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpec::Fragment(v) => {
                buf[pos] = 12;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
            BgpFlowSpec::FlowLabel(v) => {
                buf[pos] = 13;
                pos + 1 + v.encode_to(&mut buf[pos + 1..])?
            }
        };
        Ok(tail)
    }
}

#[cfg(feature = "serialization")]
impl serde::Serialize for FSOperValItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(format!("{}", self).as_str())
    }
}
#[cfg(feature = "serialization")]
impl serde::Serialize for FSOperMaskItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(format!("{}", self).as_str())
    }
}
#[cfg(feature = "serialization")]
impl<T: FSItem<T> + std::fmt::Debug> serde::Serialize for BgpFlowSpec<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(format!("{}", self).as_str())
    }
}

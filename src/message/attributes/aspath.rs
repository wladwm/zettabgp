// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP "ASpath" path attribute

use crate::message::attributes::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt::Write;
use std::hash::{Hash, Hasher};
use std::num::ParseIntError;

/// BGP AS - element of aspath
#[derive(Clone, Copy, Debug)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpAS {
    pub value: u32,
}

impl BgpAS {
    pub fn new(v: u32) -> BgpAS {
        BgpAS { value: v }
    }
    pub fn tonumb(&self) -> u32 {
        if (self.value & 0xffff) == 0 {
            self.value >> 16
        } else {
            self.value
        }
    }
}
impl From<u32> for BgpAS {
    fn from(v: u32) -> Self {
        BgpAS { value: v }
    }
}
impl std::str::FromStr for BgpAS {
    type Err=ParseIntError;
    fn from_str(s:&str) -> Result<BgpAS,Self::Err> {
        Ok(BgpAS{value:u32::from_str(s)?})
    }
}
impl PartialEq for BgpAS {
    fn eq(&self, other: &Self) -> bool {
        self.tonumb() == other.tonumb()
    }
}
impl Eq for BgpAS {}
impl PartialOrd for BgpAS {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.value.partial_cmp(&other.value)
    }
}
impl Ord for BgpAS {
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.cmp(&other.value)
    }
}
impl Hash for BgpAS {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state)
    }
}
impl std::fmt::Display for BgpAS {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if (self.value & 0xffff) == 0 {
            write!(f, "{}", self.value >> 16)
        } else {
            write!(f, "{}", self.value)
        }
    }
}
/// BGP AS_SEQUENCE - element of aspath
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpASseq {
    pub value: Vec<BgpAS>,
}
impl BgpASseq {
    pub fn len(&self) -> usize {
        self.value.len()
    }
    pub fn contains(&self, other:&[BgpAS]) -> bool {
        if other.len() > self.value.len() {
            return false;
        }
        if other.len() == self.value.len() {
            return other==self.value;
        }
        for idx in 0..(self.value.len() - other.len() + 1) {
            if &self.value[idx..(idx + other.len())] == other {
                return true;
            }
        }
        false
    }
    pub fn starts_with(&self, other:&[BgpAS]) -> bool {
        if other.len() > self.value.len() {
            return false;
        }
        if other.len() == self.value.len() {
            return other==self.value;
        }
        &self.value[0..other.len()] == other
    }
    pub fn ends_with(&self, other:&[BgpAS]) -> bool {
        if other.len() > self.value.len() {
            return false;
        }
        if other.len() == self.value.len() {
            return other==self.value;
        }
        &self.value[self.value.len()-other.len()..self.value.len()] == other
    }
}
impl From<u32> for BgpASseq {
    fn from(v: u32) -> Self {
        BgpASseq {
            value: vec![BgpAS { value: v }],
        }
    }
}
impl std::str::FromStr for BgpASseq {
    type Err=ParseIntError;
    fn from_str(s:&str) -> Result<BgpASseq,Self::Err> {
        let mut value=Vec::new();
        for cs in s.split(&[',',' ']) {
            if cs.len()>0 {
                value.push(cs.parse()?);
            }
        }
        Ok(BgpASseq{value})
    }
}
impl<A:Into<BgpAS>> std::iter::Extend<A> for BgpASseq {
    fn extend<T:IntoIterator<Item=A>>(&mut self, iter:T) {
        for q in iter.into_iter() {
            self.value.push(q.into());
        }
    }
}
/// BGP AS_SET - element of aspath
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpASset {
    pub value: BTreeSet<BgpAS>,
}
impl BgpASset {
    pub fn len(&self) -> usize {
        self.value.len()
    }
    pub fn contains_all<A:std::borrow::Borrow<BgpAS>,I:Iterator<Item=A>>(&self, other:I) -> bool {
        for n in other {
            if !self.value.contains(n.borrow()) {
                return false;
            }
        }
        true
    }
    pub fn contains_any<A:std::borrow::Borrow<BgpAS>,I:Iterator<Item=A>>(&self, other:I) -> bool {
        for n in other {
            if self.value.contains(n.borrow()) {
                return true;
            }
        }
        false
    }
}
impl<A:Into<BgpAS>> std::iter::Extend<A> for BgpASset {
    fn extend<T:IntoIterator<Item=A>>(&mut self, iter:T) {
        for q in iter.into_iter() {
            self.value.insert(q.into());
        }
    }
}
impl std::str::FromStr for BgpASset {
    type Err=ParseIntError;
    fn from_str(s:&str) -> Result<BgpASset,Self::Err> {
        let mut value=BTreeSet::new();
        for cs in s.split(&[',',' ']) {
            if cs.len()>0 {
                value.insert(cs.parse()?);
            }
        }
        Ok(BgpASset{value})
    }
}
/// BGP as path item - common element of aspath
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub enum BgpASitem {
    Seq(BgpASseq),
    Set(BgpASset),
}
impl From<u32> for BgpASitem {
    fn from(v: u32) -> Self {
        BgpASitem::Seq(v.into())
    }
}
impl From<BgpASseq> for BgpASitem {
    fn from(v: BgpASseq) -> Self {
        BgpASitem::Seq(v)
    }
}
impl From<BgpASset> for BgpASitem {
    fn from(v: BgpASset) -> Self {
        BgpASitem::Set(v)
    }
}
impl std::str::FromStr for BgpASitem {
    type Err=ParseIntError;
    fn from_str(s:&str) -> Result<BgpASitem,Self::Err> {
        if s.starts_with('{') && s.ends_with('}') {
            Ok(BgpASitem::Set(s[1..(s.len()-1)].parse()?))
        } else {
            Ok(BgpASitem::Seq(s.parse()?))
        }
    }
}
impl BgpASitem {
    pub fn len(&self) -> usize {
        match self {
            BgpASitem::Seq(ref s) => s.len(),
            BgpASitem::Set(ref s) => s.len(),
        }
    }
    pub fn is_seq(&self) -> bool {
        match self {
            BgpASitem::Seq(_) => true,
            _ => false
        }
    }
    pub fn contains(&self, other:&BgpASitem) -> bool {
        match self {
            BgpASitem::Seq(ref s) => {
                match other {
                    BgpASitem::Seq(ref o) => s.contains(&o.value),
                    BgpASitem::Set(_) => false
                }
            }
            BgpASitem::Set(ref s) => {
                match other {
                    BgpASitem::Seq(ref o) => s.contains_any(o.value.iter()),
                    BgpASitem::Set(ref o) => s.contains_any(o.value.iter())
                }
            }
        }
    }
    pub fn starts_with(&self, other:&BgpASitem) -> bool {
        match self {
            BgpASitem::Seq(ref s) => {
                match other {
                    BgpASitem::Seq(ref o) => s.starts_with(&o.value),
                    BgpASitem::Set(_) => false
                }
            }
            BgpASitem::Set(ref s) => {
                match other {
                    BgpASitem::Seq(ref o) => s.contains_all(o.value.iter()),
                    BgpASitem::Set(ref o) => s.contains_all(o.value.iter())
                }
            }
        }
    }
    pub fn ends_with(&self, other:&BgpASitem) -> bool {
        match self {
            BgpASitem::Seq(ref s) => {
                match other {
                    BgpASitem::Seq(ref o) => s.ends_with(&o.value),
                    BgpASitem::Set(_) => false
                }
            }
            BgpASitem::Set(ref s) => {
                match other {
                    BgpASitem::Seq(ref o) => s.contains_all(o.value.iter()),
                    BgpASitem::Set(ref o) => s.contains_all(o.value.iter())
                }
            }
        }
    }
    pub fn encode_to(&self, peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        let lng = self.len() * (if peer.has_as32bit { 4 } else { 2 }) + 2;
        if buf.len() < lng || self.len() > 255 {
            return Err(BgpError::InsufficientBufferSize(file!(), line!()));
        }
        let mut pos: usize;
        match self {
            BgpASitem::Seq(ref s) => {
                buf[0] = 1;
                buf[1] = self.len() as u8;
                pos = 2;
                for q in s.value.iter() {
                    if peer.has_as32bit {
                        setn_u32(q.value, &mut buf[pos..pos + 4]);
                        pos += 4;
                    } else {
                        setn_u16(q.value as u16, &mut buf[pos..pos + 2]);
                        pos += 2;
                    }
                }
            }
            BgpASitem::Set(ref s) => {
                buf[0] = 2;
                buf[1] = self.len() as u8;
                pos = 2;
                for q in s.value.iter() {
                    if peer.has_as32bit {
                        setn_u32(q.value, &mut buf[pos..pos + 4]);
                        pos += 4;
                    } else {
                        setn_u16(q.value as u16, &mut buf[pos..pos + 2]);
                        pos += 2;
                    }
                }
            }
        }
        Ok(lng)
    }
    pub fn decode_from(
        peer: &BgpSessionParams,
        buf: &[u8],
    ) -> Result<(BgpASitem, usize), BgpError> {
        if buf.len() < 2 {
            return Ok((BgpASitem::Seq(BgpASseq { value: Vec::new() }), 0));
        }
        let mut pos = 2usize;
        let mut cnt = buf[1];
        match buf[0] {
            1 => {
                //as_set
                let mut v = BTreeSet::<BgpAS>::new();
                let itemsize = if peer.has_as32bit { 4usize } else { 2 };
                while pos <= (buf.len() - itemsize) && cnt > 0 {
                    if peer.has_as32bit {
                        v.insert(getn_u32(&buf[pos..(pos + itemsize)]).into());
                    } else {
                        v.insert((getn_u16(&buf[pos..(pos + itemsize)]) as u32).into());
                    }
                    pos += itemsize;
                    cnt -= 1;
                }
                Ok((BgpASitem::Set(BgpASset { value: v }), pos))
            }
            2 => {
                //as_sequence
                let mut v = Vec::<BgpAS>::new();
                let itemsize = if peer.has_as32bit { 4usize } else { 2 };
                while pos <= (buf.len() - itemsize) && cnt > 0 {
                    if peer.has_as32bit {
                        v.push(getn_u32(&buf[pos..(pos + itemsize)]).into());
                    } else {
                        v.push((getn_u16(&buf[pos..(pos + itemsize)]) as u32).into());
                    }
                    pos += itemsize;
                    cnt -= 1;
                }
                Ok((BgpASitem::Seq(BgpASseq { value: v }), pos))
            }
            _ => Err(BgpError::ProtocolError(file!(), line!())),
        }
    }
}
impl std::fmt::Display for BgpASitem {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BgpASitem::Seq(s) => crate::util::fmt_vec(s.value.iter(), ',', f),
            BgpASitem::Set(s) => {
                f.write_char('{')?;
                crate::util::fmt_vec(s.value.iter(), ',', f)?;
                f.write_char('}')
            }
        }
    }
}
/// BGP as-path path attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpASpath {
    pub value: Vec<BgpASitem>,
}

impl<T, I> From<T> for BgpASpath
where
    T: IntoIterator<Item = I>,
    I: Into<BgpASitem>,
{
    fn from(v: T) -> Self {
        BgpASpath {
            value: v.into_iter().map(|q| q.into()).collect(),
        }.flatten()
    }
}
impl std::str::FromStr for BgpASpath {
    type Err=ParseIntError;
    fn from_str(s:&str) -> Result<BgpASpath,Self::Err> {
        if s.contains('{') {
            let bs=s.as_bytes();
            let mut pcb = 0usize;
            let mut i=0usize;
            let mut mode = 0u8;
            let mut value=Vec::new();
            while i<bs.len() {
                match mode {
                    0 => {
                        if bs[i]==b'{' {
                            value.push(String::from_utf8_lossy(&bs[pcb..i]).parse()?);
                            mode=1;
                            pcb=i;
                            i+=1;
                            continue;
                        }
                    },
                    1 => {
                        if bs[i]==b'}' {
                            value.push(String::from_utf8_lossy(&bs[pcb..=i]).parse()?);
                            mode=0;
                            i+=1;
                            pcb=i;
                            continue;
                        }
                    }
                    _ => {}
                }
                i+=1;
            }
            if pcb<i {
                value.push(String::from_utf8_lossy(&bs[pcb..i]).parse()?);
            }
            Ok(BgpASpath{value}.flatten())
        } else {
            Ok(BgpASpath{value:vec![s.parse()?]})
        }
    }
}
impl BgpASpath {
    pub fn new() -> BgpASpath {
        BgpASpath { value: Vec::new() }
    }
    pub fn len(&self) -> usize {
        self.value.len()
    }
    pub fn decode_from(peer: &BgpSessionParams, buf: &[u8]) -> Result<BgpASpath, BgpError> {
        if buf.len() < 2 {
            return Ok(BgpASpath { value: Vec::new() });
        }
        let mut pos = 0usize;
        let mut v: Vec<BgpASitem> = Vec::new();
        while pos < buf.len() {
            let r = BgpASitem::decode_from(peer, &buf[pos..])?;
            v.push(r.0);
            pos += r.1;
        }
        Ok(BgpASpath { value: v })
    }
    pub fn contains(&self, other:&BgpASpath) -> bool {
        if other.value.len() > self.value.len() {
            return false;
        }
        if other.value.len() == self.value.len() {
            return self.value.iter().zip(other.value.iter()).all(|(a,b)| a.contains(b));
        }
        for idx in 0..(self.value.len() - other.len() + 1) {
            if self.value[idx..(idx + other.len())].iter().zip(other.value.iter()).all(|(a,b)| a.contains(b)) {
                return true;
            }
        }
        false
    }
    pub fn starts_with(&self, other:&BgpASpath) -> bool {
        if other.value.len() > self.value.len() {
            return false;
        }
        if other.value.len() == self.value.len() {
            return self.value.iter().zip(other.value.iter()).all(|(a,b)| a.starts_with(b));
        }
        return self.value.iter().take(other.len()).zip(other.value.iter()).all(|(a,b)| a.starts_with(b));
    }
    pub fn ends_with(&self, other:&BgpASpath) -> bool {
        if other.value.len() > self.value.len() {
            return false;
        }
        if other.value.len() == self.value.len() {
            return self.value.iter().zip(other.value.iter()).all(|(a,b)| a.ends_with(b));
        }
        return self.value[self.value.len()-other.len()..self.value.len()].iter().zip(other.value.iter()).all(|(a,b)| a.ends_with(b));
    }
    /// concatenate sequental sequences
    pub fn flatten(mut self) -> Self {
        let mut lng = self.value.len();
        if lng<2 {
            return self;
        }
        let mut i=0usize;
        while i<(lng-1) {
            if self.value[i].is_seq() && self.value[i+1].is_seq() {
                let mut f=self.value.remove(i+1);
                lng-=1;
                match &mut self.value[i] {
                    BgpASitem::Set(_) => panic!(""),
                    BgpASitem::Seq(s) => {
                        match &mut f {
                            BgpASitem::Set(_) => panic!(""),
                            BgpASitem::Seq(fs) => {
                                s.value.append(&mut fs.value);
                            }
                        }
                    }
                }
            } else {
                i+=1;
            }
        };
        self
    }
}
impl Default for BgpASpath {
    fn default() -> Self {
        Self::new()
    }
}
impl std::fmt::Debug for BgpASpath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpASpath")
            .field("value", &self.value)
            .finish()
    }
}
impl std::fmt::Display for BgpASpath {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        crate::util::fmt_vec(self.value.iter(), ',', f)
    }
}
impl BgpAttr for BgpASpath {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 2,
            flags: 0x50,
        }
    }
    fn encode_to(&self, peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut pos = 0usize;
        if self.value.is_empty() {
            return Ok(0);
        }
        for i in &self.value {
            pos += i.encode_to(peer, &mut buf[pos..])?;
        }
        Ok(pos)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_aspath() {
        let p1=BgpASpath::from([1,2,3,4]).flatten();
        assert_eq!(p1.value.len(),1);
        let p2=BgpASpath::from([1,2,3,4]).flatten();
        assert_eq!(p1,p2);
        let p2=BgpASpath::from([1,2,3]).flatten();
        assert_ne!(p1,p2);
    }
    #[test]
    fn test_parse_aspath() {
        let p1=BgpASpath::from([1,2,3,4]).flatten();
        assert_eq!(p1.value.len(),1);
        let p2="1,2,3,4".parse().unwrap();
        assert_eq!(p1,p2);
    }
   #[test]
    fn test_aspath_contains() {
        let p1="1,2,3,4".parse::<BgpASpath>().unwrap();
        let p2="2,3".parse::<BgpASpath>().unwrap();
        assert!(p1.contains(&p2));
        let p3="1,2".parse::<BgpASpath>().unwrap();
        assert!(p1.starts_with(&p3));
    }
   #[test]
    fn test_aspath_starts_with() {
        let p1="1,2,3,4".parse::<BgpASpath>().unwrap();
        let p2="2,3".parse::<BgpASpath>().unwrap();
        eprintln!("p1={:?}, p2={:?}", p1, p2);
        assert!(!p1.starts_with(&p2));
        let p3="1,2".parse::<BgpASpath>().unwrap();
        assert!(p1.starts_with(&p3));
    }
 
 }
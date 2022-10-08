// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module contains BGP update message - most important one, which carries roting information.

use crate::prelude::*;
use crate::*;

/// BGP update message, which carries routing information.
#[derive(Debug)]
pub struct BgpUpdateMessage {
    /// NLRI updates
    pub updates: BgpAddrs,
    /// NLRI withdraws
    pub withdraws: BgpAddrs,
    /// path attributes
    pub attrs: Vec<BgpAttrItem>,
}
impl BgpUpdateMessage {
    /// counstructs new empty update message.
    pub fn new() -> BgpUpdateMessage {
        BgpUpdateMessage {
            updates: BgpAddrs::None,
            withdraws: BgpAddrs::None,
            attrs: Vec::new(),
        }
    }
    /// returns origin attribute.
    pub fn get_attr_origin(&self) -> Option<&BgpOrigin> {
        for i in self.attrs.iter() {
            if let BgpAttrItem::Origin(n) = i {
                return Some(n);
            }
        }
        None
    }
    /// returns aspath attribute.
    pub fn get_attr_aspath(&self) -> Option<&BgpASpath> {
        for i in self.attrs.iter() {
            if let BgpAttrItem::ASPath(n) = i {
                return Some(n);
            }
        }
        None
    }
    /// returns community list attribute.
    pub fn get_attr_communitylist(&self) -> Option<&BgpCommunityList> {
        for i in self.attrs.iter() {
            if let BgpAttrItem::CommunityList(n) = i {
                return Some(n);
            }
        }
        None
    }
    /// returns large community list attribute.
    pub fn get_attr_largecommunitylist(&self) -> Option<&BgpLargeCommunityList> {
        for i in self.attrs.iter() {
            if let BgpAttrItem::LargeCommunityList(n) = i {
                return Some(n);
            }
        }
        None
    }
    /// returns extended community list attribute.
    pub fn get_attr_extcommunitylist(&self) -> Option<&BgpExtCommunityList> {
        for i in self.attrs.iter() {
            if let BgpAttrItem::ExtCommunityList(n) = i {
                return Some(n);
            }
        }
        None
    }
    /// returns next hop attribute.
    pub fn get_attr_nexthop(&self) -> Option<&BgpNextHop> {
        for i in self.attrs.iter() {
            if let BgpAttrItem::NextHop(n) = i {
                return Some(n);
            }
        }
        None
    }
    /// returns MPUpdates
    pub fn get_mpupdates(&self) -> Option<&BgpMPUpdates> {
        for i in self.attrs.iter() {
            if let BgpAttrItem::MPUpdates(n) = i {
                return Some(n);
            }
        }
        None
    }
    /// returns MPWithdraws
    pub fn get_mpwithdraws(&self) -> Option<&BgpMPWithdraws> {
        for i in self.attrs.iter() {
            if let BgpAttrItem::MPWithdraws(n) = i {
                return Some(n);
            }
        }
        None
    }
}
impl Default for BgpUpdateMessage {
    fn default() -> Self {
        Self::new()
    }
}
impl BgpMessage for BgpUpdateMessage {
    fn decode_from(&mut self, peer: &BgpSessionParams, buf: &[u8]) -> Result<(), BgpError> {
        let mut curpos: usize = 0;
        let withdraws_length = getn_u16(&buf[curpos..(curpos + 2)]) as usize;
        curpos += 2;
        let withdraws_end = curpos + withdraws_length;
        match peer.peer_mode {
            BgpTransportMode::IPv4 => {
                if peer.check_addpath_receive(1, 1) {
                    let r = decode_pathid_bgpitems_from(&buf[curpos..withdraws_end])?;
                    self.withdraws = BgpAddrs::IPV4UP(r.0);
                } else {
                    let r = decode_bgpitems_from(&buf[curpos..withdraws_end])?;
                    self.withdraws = BgpAddrs::IPV4U(r.0);
                }
            }
            BgpTransportMode::IPv6 => {
                if peer.check_addpath_receive(2, 1) {
                    let r = decode_pathid_bgpitems_from(&buf[curpos..withdraws_end])?;
                    self.withdraws = BgpAddrs::IPV6UP(r.0);
                } else {
                    let r = decode_bgpitems_from(&buf[curpos..withdraws_end])?;
                    self.withdraws = BgpAddrs::IPV6U(r.0);
                }
            }
        };
        curpos = withdraws_end;
        let pathattr_len = getn_u16(&buf[curpos..(curpos + 2)]) as usize;
        curpos += 2;
        //println!("Path attributes length: {:?}", pathattr_len);
        let pathattr_end = curpos + pathattr_len;
        if pathattr_end > buf.len() {
            return Err(BgpError::protocol_error());
        }
        while curpos < pathattr_end {
            //flags 0
            //tc 1
            let flags = buf[curpos];
            let tc = buf[curpos + 1];
            let attrlen = if (flags & 16) > 0 {
                curpos += 4;
                getn_u16(&buf[(curpos - 2)..curpos]) as usize
            } else {
                curpos += 3;
                buf[curpos - 1] as usize
            };
            if (curpos + attrlen) > pathattr_end {
                return Err(BgpError::protocol_error());
            }
            //println!("PA flags {:?} TC {:?} len {:?}", flags, tc, attrlen);
            //https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml
            self.attrs.push(BgpAttrItem::decode_from(
                peer,
                tc,
                flags,
                attrlen,
                &buf[curpos..(curpos + attrlen)],
            )?);
            curpos += attrlen;
        }
        match peer.peer_mode {
            BgpTransportMode::IPv4 => {
                if peer.check_addpath_receive(1, 1) {
                    let r = decode_pathid_bgpitems_from(&buf[curpos..])?;
                    self.updates = BgpAddrs::IPV4UP(r.0);
                } else {
                    let r = decode_bgpitems_from(&buf[curpos..])?;
                    self.updates = BgpAddrs::IPV4U(r.0);
                }
            }
            BgpTransportMode::IPv6 => {
                if peer.check_addpath_receive(2, 1) {
                    let r = decode_pathid_bgpitems_from(&buf[curpos..])?;
                    self.updates = BgpAddrs::IPV6UP(r.0);
                } else {
                    let r = decode_bgpitems_from(&buf[curpos..])?;
                    self.updates = BgpAddrs::IPV6U(r.0);
                }
            }
        };
        //println!("Update: {:?}", self);
        Ok(())
    }
    fn encode_to(&self, peer: &BgpSessionParams, buf: &mut [u8]) -> Result<usize, BgpError> {
        let mut curpos: usize = 0;
        //withdraws main
        match peer.peer_mode {
            BgpTransportMode::IPv4 => match self.withdraws {
                BgpAddrs::IPV4U(ref wdrw) => {
                    let wlen = encode_bgpitems_to(wdrw, &mut buf[curpos + 2..])?;
                    if wlen > 65535 {
                        return Err(BgpError::too_many_data());
                    }
                    setn_u16(wlen as u16, &mut buf[curpos..]);
                    curpos += 2 + wlen;
                }
                BgpAddrs::IPV4UP(ref wdrw) => {
                    let wlen = encode_pathid_bgpitems_to(wdrw, &mut buf[curpos + 2..])?;
                    if wlen > 65535 {
                        return Err(BgpError::too_many_data());
                    }
                    setn_u16(wlen as u16, &mut buf[curpos..]);
                    curpos += 2 + wlen;
                }
                _ => {
                    setn_u16(0, buf);
                    curpos = 2;
                }
            },
            BgpTransportMode::IPv6 => match self.withdraws {
                BgpAddrs::IPV6U(ref wdrw) => {
                    let wlen = encode_bgpitems_to(wdrw, &mut buf[curpos + 2..])?;
                    if wlen > 65535 {
                        return Err(BgpError::too_many_data());
                    }
                    setn_u16(wlen as u16, &mut buf[curpos..]);
                    curpos += 2 + wlen;
                }
                BgpAddrs::IPV6UP(ref wdrw) => {
                    let wlen = encode_pathid_bgpitems_to(wdrw, &mut buf[curpos + 2..])?;
                    if wlen > 65535 {
                        return Err(BgpError::too_many_data());
                    }
                    setn_u16(wlen as u16, &mut buf[curpos..]);
                    curpos += 2 + wlen;
                }
                _ => {
                    setn_u16(0, buf);
                    curpos = 2;
                }
            },
        };
        let pathattrlen_pos = curpos;
        curpos += 2;
        for paitem in self.attrs.iter() {
            if (curpos - pathattrlen_pos) > 65535 {
                return Err(BgpError::static_str("Invalid path attribute length"));
            }
            curpos += paitem.encode_to(peer, &mut buf[curpos..])?
        }
        setn_u16(
            (curpos - pathattrlen_pos - 2) as u16,
            &mut buf[pathattrlen_pos..(pathattrlen_pos + 2)],
        );
        match peer.peer_mode {
            BgpTransportMode::IPv4 => match self.updates {
                BgpAddrs::IPV4U(ref upds) => {
                    curpos += encode_bgpitems_to(upds, &mut buf[curpos..])?;
                }
                BgpAddrs::IPV4UP(ref upds) => {
                    curpos += encode_pathid_bgpitems_to(upds, &mut buf[curpos..])?;
                }
                _ => {}
            },
            BgpTransportMode::IPv6 => match self.updates {
                BgpAddrs::IPV6U(ref upds) => {
                    curpos += encode_bgpitems_to(upds, &mut buf[curpos..])?;
                }
                BgpAddrs::IPV6UP(ref upds) => {
                    curpos += encode_pathid_bgpitems_to(upds, &mut buf[curpos..])?;
                }
                _ => {}
            },
        };
        Ok(curpos)
    }
}

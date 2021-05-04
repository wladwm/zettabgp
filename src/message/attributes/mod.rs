// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module contains BGP path attributes
use crate::*;
pub mod aggregatoras;
pub mod aspath;
pub mod atomicaggregate;
pub mod attrset;
pub mod clusterlist;
pub mod community;
pub mod extcommunity;
pub mod localpref;
pub mod med;
pub mod multiproto;
pub mod nexthop;
pub mod origin;
pub mod originatorid;
pub mod pmsitunnelattr;
pub mod unknown;
#[cfg(feature = "serialization")]
use serde::ser::SerializeMap;

use aggregatoras::BgpAggregatorAS;
use aspath::BgpASpath;
use atomicaggregate::BgpAtomicAggregate;
use attrset::BgpAttrSet;
use clusterlist::BgpClusterList;
use community::{BgpCommunityList, BgpLargeCommunityList};
use extcommunity::BgpExtCommunityList;
use localpref::BgpLocalpref;
use med::BgpMED;
use multiproto::{BgpMPUpdates, BgpMPWithdraws};
use nexthop::BgpNextHop;
use origin::BgpOrigin;
use originatorid::BgpOriginatorID;
use pmsitunnelattr::BgpPMSITunnel;
use unknown::BgpAttrUnknown;

/// BGP path attribute mandatory parameters - typecode and flags
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BgpAttrParams {
    pub typecode: u8,
    pub flags: u8,
}

pub trait BgpAttr: std::fmt::Display + std::fmt::Debug {
    fn encode_to(
        &self,
        peer: &BgpSessionParams,
        buf: &mut [u8],
    ) -> Result<usize, BgpError>;
    fn attr(&self) -> BgpAttrParams;
}

/// BGP path attribute
#[derive(Debug,Hash,PartialOrd,Ord,PartialEq,Eq)]
pub enum BgpAttrItem {
    Origin(BgpOrigin),
    ASPath(BgpASpath),
    NextHop(BgpNextHop),
    MED(BgpMED),
    LocalPref(BgpLocalpref),
    AtomicAggregate(BgpAtomicAggregate),
    AggregatorAS(BgpAggregatorAS),
    CommunityList(BgpCommunityList),
    OriginatorID(BgpOriginatorID),
    ClusterList(BgpClusterList),
    MPUpdates(BgpMPUpdates),
    MPWithdraws(BgpMPWithdraws),
    ExtCommunityList(BgpExtCommunityList),
    LargeCommunityList(BgpLargeCommunityList),
    PMSITunnel(BgpPMSITunnel),
    AttrSet(BgpAttrSet),
    Unknown(BgpAttrUnknown),
}

impl BgpAttrItem {
    pub fn decode_from(
        peer: &BgpSessionParams,
        typecode: u8,
        flags: u8,
        attrlen: usize,
        buf: &[u8],
    ) -> Result<BgpAttrItem, BgpError> {
        match typecode {
            1 => Ok(BgpAttrItem::Origin(BgpOrigin::decode_from(buf)?)),
            2 => Ok(BgpAttrItem::ASPath(BgpASpath::decode_from(peer, buf)?)),
            3 => Ok(BgpAttrItem::NextHop(BgpNextHop::decode_from(peer, buf)?)),
            4 => Ok(BgpAttrItem::MED(BgpMED::decode_from(buf)?)),
            5 => Ok(BgpAttrItem::LocalPref(BgpLocalpref::decode_from(buf)?)),
            6 => Ok(BgpAttrItem::AtomicAggregate(
                BgpAtomicAggregate::decode_from(peer, buf)?,
            )),
            7 => Ok(BgpAttrItem::AggregatorAS(BgpAggregatorAS::decode_from(
                peer, buf,
            )?)),
            8 => Ok(BgpAttrItem::CommunityList(BgpCommunityList::decode_from(
                buf,
            )?)),
            9 => Ok(BgpAttrItem::OriginatorID(BgpOriginatorID::decode_from(
                peer, buf,
            )?)),
            10 => Ok(BgpAttrItem::ClusterList(BgpClusterList::decode_from(
                peer, buf,
            )?)),
            14 => Ok(BgpAttrItem::MPUpdates(BgpMPUpdates::decode_from(
                peer, buf,
            )?)),
            15 => Ok(BgpAttrItem::MPWithdraws(BgpMPWithdraws::decode_from(
                peer, buf,
            )?)),
            16 => Ok(BgpAttrItem::ExtCommunityList(
                BgpExtCommunityList::decode_from(buf)?,
            )),
            22 => Ok(BgpAttrItem::PMSITunnel(BgpPMSITunnel::decode_from(
                peer, buf,
            )?)),
            32 => Ok(BgpAttrItem::LargeCommunityList(
                BgpLargeCommunityList::decode_from(buf)?,
            )),
            20 | 21 =>
            //deprecated
            {
                Ok(BgpAttrItem::Unknown(BgpAttrUnknown::decode_from(
                    typecode,
                    flags,
                    &buf[0..attrlen],
                )?))
            }
            128 => Ok(BgpAttrItem::AttrSet(BgpAttrSet::decode_from(peer, buf)?)),
            _ => {
                /*
                eprintln!(
                    "Unknown PA TC={:?} flags={:?} len={:?}: {:?}",
                    typecode,
                    flags,
                    attrlen,
                    &buf[0..attrlen]
                );
                */
                Ok(BgpAttrItem::Unknown(BgpAttrUnknown::decode_from(
                    typecode,
                    flags,
                    &buf[0..attrlen],
                )?))
            }
        }
    }
    fn encode_bgpattr(
        attr: &impl BgpAttr,
        peer: &BgpSessionParams,
        buf: &mut [u8],
    ) -> Result<usize, BgpError> {
        let attrparams = attr.attr();
        buf[0] = attrparams.flags;
        buf[1] = attrparams.typecode;
        let mut curpos: usize = 2;
        if (attrparams.flags & 16) > 0 {
            curpos += 2;
        } else {
            curpos += 1;
        }
        let attrlen = attr.encode_to(peer, &mut buf[curpos..])?;
        if (attrparams.flags & 16) > 0 {
            if attrlen > 65535 {
                return Err(BgpError::static_str(
                    "Invalid path attribute length",
                ));
            }
            setn_u16(attrlen as u16, &mut buf[2..4]);
        } else {
            if attrlen > 255 {
                return Err(BgpError::static_str(
                    "Invalid path attribute length",
                ));
            }
            buf[2] = attrlen as u8;
        }
        Ok(curpos + attrlen)
    }
    pub fn encode_to(
        &self,
        peer: &BgpSessionParams,
        buf: &mut [u8],
    ) -> Result<usize, BgpError> {
        match self {
            BgpAttrItem::Origin(pa) => BgpAttrItem::encode_bgpattr(pa, peer, buf),
            BgpAttrItem::ASPath(pa) => BgpAttrItem::encode_bgpattr(pa, peer, buf),
            BgpAttrItem::NextHop(pa) => BgpAttrItem::encode_bgpattr(pa, peer, buf),
            BgpAttrItem::MED(pa) => BgpAttrItem::encode_bgpattr(pa, peer, buf),
            BgpAttrItem::LocalPref(pa) => BgpAttrItem::encode_bgpattr(pa, peer, buf),
            BgpAttrItem::AtomicAggregate(pa) => BgpAttrItem::encode_bgpattr(pa, peer, buf),
            BgpAttrItem::AggregatorAS(pa) => BgpAttrItem::encode_bgpattr(pa, peer, buf),
            BgpAttrItem::CommunityList(pa) => BgpAttrItem::encode_bgpattr(pa, peer, buf),
            BgpAttrItem::OriginatorID(pa) => BgpAttrItem::encode_bgpattr(pa, peer, buf),
            BgpAttrItem::ClusterList(pa) => BgpAttrItem::encode_bgpattr(pa, peer, buf),
            BgpAttrItem::MPUpdates(pa) => BgpAttrItem::encode_bgpattr(pa, peer, buf),
            BgpAttrItem::MPWithdraws(pa) => BgpAttrItem::encode_bgpattr(pa, peer, buf),
            BgpAttrItem::ExtCommunityList(pa) => BgpAttrItem::encode_bgpattr(pa, peer, buf),
            BgpAttrItem::LargeCommunityList(pa) => BgpAttrItem::encode_bgpattr(pa, peer, buf),
            BgpAttrItem::PMSITunnel(pa) => BgpAttrItem::encode_bgpattr(pa, peer, buf),
            BgpAttrItem::AttrSet(pa) => BgpAttrItem::encode_bgpattr(pa, peer, buf),
            BgpAttrItem::Unknown(pa) => BgpAttrItem::encode_bgpattr(pa, peer, buf),
        }
    }
}

#[cfg(feature = "serialization")]
impl serde::Serialize for BgpAttrItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_map(Some(1))?;
        match self {
            BgpAttrItem::Origin(pa) => state.serialize_entry("Origin",pa)?,
            BgpAttrItem::ASPath(pa) => state.serialize_entry("ASPath",pa)?,
            BgpAttrItem::NextHop(pa) => state.serialize_entry("NextHop",pa)?,
            BgpAttrItem::MED(pa) => state.serialize_entry("MED",pa)?,
            BgpAttrItem::LocalPref(pa) => state.serialize_entry("LocalPref",pa)?,
            BgpAttrItem::AtomicAggregate(pa) => state.serialize_entry("AtomicAggregate",pa)?,
            BgpAttrItem::AggregatorAS(pa) => state.serialize_entry("AggregatorAS",pa)?,
            BgpAttrItem::CommunityList(pa) => state.serialize_entry("CommunityList",pa)?,
            BgpAttrItem::OriginatorID(pa) => state.serialize_entry("OriginatorID",pa)?,
            BgpAttrItem::ClusterList(pa) => state.serialize_entry("ClusterList",pa)?,
            //BgpAttrItem::MPUpdates(pa) => state.serialize_entry("MPUpdates",pa),
            //BgpAttrItem::MPWithdraws(pa) => state.serialize_entry("MPWithdraws",pa),
            BgpAttrItem::ExtCommunityList(pa) => state.serialize_entry("ExtCommunityList",pa)?,
            BgpAttrItem::LargeCommunityList(pa) => state.serialize_entry("LargeCommunityList",pa)?,
            BgpAttrItem::PMSITunnel(pa) => state.serialize_entry("PMSITunnel",pa)?,
            BgpAttrItem::AttrSet(pa) => state.serialize_entry("AttrSet",pa)?,
            BgpAttrItem::Unknown(pa) => state.serialize_entry("Unknown",pa)?,
            _ => {}
        };
        state.end()
    }
}

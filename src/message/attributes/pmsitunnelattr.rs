// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP PMSI tunnel path attribute - used for MVPN and EVPN

use crate::afi::{BgpItem, MplsLabels};
use crate::message::attributes::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpPMSITaRSVP {
    pub ext_tunnel_id: std::net::Ipv4Addr,
    pub reserved: u16,
    pub tunnel_id: u16,
    pub p2mp_id: std::net::Ipv4Addr,
}
impl std::fmt::Display for BgpPMSITaRSVP {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "RSVP-TE P2MP LSP:{}:{}:{}:{}",
            self.ext_tunnel_id, self.reserved, self.tunnel_id, self.p2mp_id
        )
    }
}
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct BgpPMSITaIngressRepl {
    pub endpoint: std::net::Ipv4Addr,
}
impl std::fmt::Display for BgpPMSITaIngressRepl {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Ingress replication:{}", self.endpoint)
    }
}
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpPMSITaMLDP {
    pub rootnode: std::net::IpAddr,
    pub opaque: Vec<u8>,
}
impl std::fmt::Display for BgpPMSITaMLDP {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "mLDP P2MP LSP:{}", self.rootnode)
    }
}
/// PMSI tunnel attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub enum BgpPMSITunnelAttr {
    None,
    RSVPTe(BgpPMSITaRSVP),
    IngressRepl(BgpPMSITaIngressRepl),
    MLDP(BgpPMSITaMLDP),
}
impl std::fmt::Display for BgpPMSITunnelAttr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BgpPMSITunnelAttr::None => "".fmt(f),
            BgpPMSITunnelAttr::RSVPTe(r) => r.fmt(f),
            BgpPMSITunnelAttr::IngressRepl(r) => r.fmt(f),
            BgpPMSITunnelAttr::MLDP(r) => r.fmt(f),
        }
    }
}

/// BGP Path attribute for PMSI tunnel RFC6514
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpPMSITunnel {
    pub flags: u8,
    pub tunnel_type: u8,
    pub label: MplsLabels,
    pub tunnel_attribute: BgpPMSITunnelAttr,
}
/*
    tunnel_type
      + 0 - No tunnel information present
      + 1 - RSVP-TE P2MP LSP
      + 2 - mLDP P2MP LSP
      + 3 - PIM-SSM Tree
      + 4 - PIM-SM Tree
      + 5 - BIDIR-PIM Tree
      + 6 - Ingress Replication
      + 7 - mLDP MP2MP LSP
*/
impl BgpPMSITunnel {
    pub fn decode_from(_peer: &BgpSessionParams, buf: &[u8]) -> Result<BgpPMSITunnel, BgpError> {
        if buf.len() < 5 {
            return Err(BgpError::static_str("Invalid PMSI buffer length"));
        }
        let lbls = MplsLabels::extract_bits_from(24, &buf[2..])?;
        let curpos = 2 + lbls.1;
        Ok(BgpPMSITunnel {
            flags: buf[0],
            tunnel_type: buf[1],
            label: lbls.0,
            tunnel_attribute: match buf[1] {
                0 => BgpPMSITunnelAttr::None,
                1 =>
                //RSVP-TE P2MP LSP
                {
                    BgpPMSITunnelAttr::RSVPTe(BgpPMSITaRSVP {
                        ext_tunnel_id: std::net::Ipv4Addr::new(
                            buf[curpos],
                            buf[curpos + 1],
                            buf[curpos + 2],
                            buf[curpos + 3],
                        ),
                        reserved: getn_u16(&buf[curpos + 4..]),
                        tunnel_id: getn_u16(&buf[curpos + 6..]),
                        p2mp_id: std::net::Ipv4Addr::new(
                            buf[curpos + 8],
                            buf[curpos + 9],
                            buf[curpos + 10],
                            buf[curpos + 11],
                        ),
                    })
                }
                2 => {
                    if buf[5] != 6 {
                        return Err(BgpError::from_string(format!(
                            "Unknown PMSI tunnel type mLDP p2mp: {}",
                            buf[5]
                        )));
                    }
                    if buf.len() < 16 {
                        return Err(BgpError::from_string(format!(
                            "PMSI tunnel type mLDP p2mp too short: {}",
                            buf.len()
                        )));
                    }
                    if getn_u16(&buf[6..8]) != 1 {
                        return Err(BgpError::Static("Invalid root node address family"));
                    }
                    if buf[8] != 4 {
                        return Err(BgpError::Static("Invalid root node address length"));
                    }
                    let rootnode = decode_addr_from(&buf[9..13])?;
                    let opaquelen = getn_u16(&buf[13..15]) as usize;
                    if buf.len() < (15 + opaquelen) {
                        return Err(BgpError::from_string(format!(
                            "PMSI tunnel type mLDP p2mp too short: {} < 15+{}",
                            buf.len(),
                            opaquelen
                        )));
                    }
                    BgpPMSITunnelAttr::MLDP(BgpPMSITaMLDP {
                        rootnode,
                        opaque: buf[15..(15 + opaquelen)].to_vec(),
                    })
                }
                6 =>
                //Ingress replication
                {
                    BgpPMSITunnelAttr::IngressRepl(BgpPMSITaIngressRepl {
                        endpoint: std::net::Ipv4Addr::new(
                            buf[curpos],
                            buf[curpos + 1],
                            buf[curpos + 2],
                            buf[curpos + 3],
                        ),
                    })
                }
                _ => {
                    return Err(BgpError::from_string(format!(
                        "Unknown PMSI tunnel type: {}, flags {}, buf: {:?}",
                        buf[1], buf[0], buf
                    )));
                }
            },
        })
    }
}
impl std::fmt::Debug for BgpPMSITunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpPMSITunnel")
            .field("flags", &self.flags)
            .field("tunnel_type", &self.tunnel_type)
            .field("label", &self.label)
            .field("tunnel_attribute", &self.tunnel_attribute)
            .finish()
    }
}
impl std::fmt::Display for BgpPMSITunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "BgpPMSITunnel flags={} type={} label={} attribute={}",
            self.flags, self.tunnel_type, self.label, self.tunnel_attribute
        )
    }
}
impl BgpAttr for BgpPMSITunnel {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 22,
            flags: 192,
        }
    }
    fn encode_to(&self, _peer: &BgpSessionParams, _buf: &mut [u8]) -> Result<usize, BgpError> {
        unimplemented!();
    }
}

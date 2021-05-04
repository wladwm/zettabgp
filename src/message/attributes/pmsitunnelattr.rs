// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP PMSI tunnel path attribute - used for MVPN and EVPN

use crate::*;
use crate::message::attributes::*;
use crate::afi::{BgpItem,MplsLabels};

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
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
            "RSVP tunnel:{}:{}:{}:{}",
            self.ext_tunnel_id, self.reserved, self.tunnel_id, self.p2mp_id
        )
    }
}
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct BgpPMSITaIngressRepl {
    pub endpoint: std::net::Ipv4Addr,
}
impl std::fmt::Display for BgpPMSITaIngressRepl {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Ingress replication:{}",
            self.endpoint
        )
    }
}

/// PMSI tunnel attribute
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum BgpPMSITunnelAttr {
    None,
    RSVPTe(BgpPMSITaRSVP),
    IngressRepl(BgpPMSITaIngressRepl)
}
impl std::fmt::Display for BgpPMSITunnelAttr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BgpPMSITunnelAttr::None => "".fmt(f),
            BgpPMSITunnelAttr::RSVPTe(r) => r.fmt(f),
            BgpPMSITunnelAttr::IngressRepl(r) => r.fmt(f),
        }
    }
}

/// BGP Path attribute for PMSI tunnel
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BgpPMSITunnel {
    pub flags: u8,
    pub tunnel_type: u8,
    pub label: MplsLabels,
    pub tunnel_attribute: BgpPMSITunnelAttr,
}
impl BgpPMSITunnel {
    pub fn decode_from(
        _peer: &BgpSessionParams,
        buf: &[u8],
    ) -> Result<BgpPMSITunnel, BgpError> {
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
                6 =>
                //Ingress replication
                {
                    BgpPMSITunnelAttr::IngressRepl(BgpPMSITaIngressRepl {
                        endpoint: std::net::Ipv4Addr::new(
                            buf[curpos],
                            buf[curpos + 1],
                            buf[curpos + 2],
                            buf[curpos + 3],
                        )
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
            "BgpPMSITunnel flags={} type={} label={:?} attribute={}",
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
    fn encode_to(
        &self,
        _peer: &BgpSessionParams,
        _buf: &mut [u8],
    ) -> Result<usize, BgpError> {
        unimplemented!();
    }
}

#[cfg(feature = "serialization")]
impl serde::Serialize for BgpPMSITunnel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(format!("{}", self).as_str())
        /*
        let mut state = serializer.serialize_struct("BgpPMSITunnel", 2)?;
        state.serialize_field("flags", &self.flags)?;
        state.serialize_field("tunnel_type", &self.tunnel_type)?;
        state.end()
        */
    }
}

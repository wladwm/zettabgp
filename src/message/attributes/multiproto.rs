// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! BGP multiprotocol update and withdraw path attributes, which carries routing information with mp-bgp
 
use crate::*;
use crate::prelude::*;

/// BGP multiprotocol updates
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BgpMPUpdates {
    /// next hop for this updates
    pub nexthop: BgpAddr,
    /// NLRI
    pub addrs: BgpAddrs,
}
impl BgpMPUpdates {
    /// Creates update for VPNv4 unicast
    pub fn s4vpnv4u(nhop: BgpIPv4RD, nlri: Vec<Labeled<WithRd<BgpAddrV4>>>) -> BgpMPUpdates {
        BgpMPUpdates {
            nexthop: BgpAddr::V4RD(nhop),
            addrs: BgpAddrs::VPNV4U(nlri)
        }
    }
    /// Creates update for VPNv4 multicast
    pub fn s4vpnv4m(nhop: BgpIPv4RD, nlri: Vec<Labeled<WithRd<BgpAddrV4>>>) -> BgpMPUpdates {
        BgpMPUpdates {
            nexthop: BgpAddr::V4RD(nhop),
            addrs: BgpAddrs::VPNV4M(nlri)
        }
    }
    /// Creates update for IPv4 labeled unicast
    pub fn s4ip4lu(nhop: std::net::Ipv4Addr, nlri: Vec<Labeled<BgpAddrV4>>) -> BgpMPUpdates {
        BgpMPUpdates {
            nexthop: BgpAddr::V4(nhop),
            addrs: BgpAddrs::IPV4LU(nlri)
        }
    }
    /// Creates update for IPv6 labeled unicast
    pub fn s4ip6lu(nhop: std::net::Ipv4Addr, nlri: Vec<Labeled<BgpAddrV6>>) -> BgpMPUpdates {
        BgpMPUpdates {
            nexthop: BgpAddr::V4(nhop),
            addrs: BgpAddrs::IPV6LU(nlri)
        }
    }
    /// Creates update for VPNv6 unicast
    pub fn s4vpnv6u(nhop: BgpIPv4RD, nlri: Vec<Labeled<WithRd<BgpAddrV6>>>) -> BgpMPUpdates {
        BgpMPUpdates {
            nexthop: BgpAddr::V4RD(nhop),
            addrs: BgpAddrs::VPNV6U(nlri)
        }
    }
    /// Creates update for VPNv6 multicast
    pub fn s4vpnv6m(nhop: BgpIPv4RD, nlri: Vec<Labeled<WithRd<BgpAddrV6>>>) -> BgpMPUpdates {
        BgpMPUpdates {
            nexthop: BgpAddr::V4RD(nhop),
            addrs: BgpAddrs::VPNV6M(nlri)
        }
    }
    pub fn decode_from(
        peer: &BgpSessionParams,
        buf: &[u8],
    ) -> Result<BgpMPUpdates, BgpError> {
        let afi = getn_u16(&buf);
        let safi = buf[2];
        let mut curpos: usize = 4;
        let nh: BgpAddr;
        let nhlen = buf[3] as usize;
        match afi {
            1 => {
                //ipv4
                match safi {
                    1 | 2 | 4 | 5 | 133 => {
                        //unicast|multicast|labeled unicast|mvpn|flow
                        nh = BgpAddr::V4(decode_addrv4_from(&buf[curpos..(curpos + nhlen)])?);
                        curpos += nhlen;
                    }
                    128 | 129 | 134 => {
                        //vpnv4u|vpnv4m|flow
                        let r = BgpIPv4RD::decode_from(peer.peer_mode, &buf[curpos..])?;
                        nh = BgpAddr::V4RD(r.0);
                        curpos += r.1;
                    }
                    n => {
                        eprintln!("AFI/SAFI {}/{} {:?}",afi,safi,&buf[curpos..]);
                        return Err(BgpError::from_string(format!(
                            "Unknown safi for ipv4 code {:?}",
                            n
                        )))
                    }
                }
            }
            2 => {
                //ipv6
                match safi {
                    1 | 2 | 4 => {
                        //unicast|multicast|labeled unicast
                        nh = BgpAddr::V6(decode_addrv6_from(&buf[curpos..(curpos + nhlen)])?);
                        curpos += nhlen;
                    }
                    128 | 129 => {
                        //vpnv6u|vpnv6m
                        let r = BgpIPv6RD::decode_from(peer.peer_mode, &buf[curpos..])?;
                        nh = BgpAddr::V6RD(r.0);
                        curpos += r.1;
                    }
                    n => {
                        return Err(BgpError::from_string(format!(
                            "Unknown safi for ipv6: {:?}",
                            n
                        )))
                    }
                }
            }
            25 => {
                //l2
                match safi {
                    65 | 70 => {
                        //vpls + evpn
                        nh = BgpAddr::V4(decode_addrv4_from(&buf[curpos..])?);
                        curpos += nhlen;
                    }
                    n => {
                        return Err(BgpError::from_string(format!(
                            "Unknown safi for l2: {:?}",
                            n
                        )))
                    }
                }
            }
            n => {
                return Err(BgpError::from_string(format!(
                    "Unknown afi code {:?}",
                    n
                )))
            }
        }
        let snpa_count = buf[curpos];
        curpos += 1;
        for _ in 0..snpa_count {
            let snpa_len = buf[curpos] as usize;
            curpos += 1 + snpa_len;
        }
        let ap = BgpAddrs::decode_from(peer, afi, safi, &buf[curpos..])?;
        Ok(BgpMPUpdates {
            nexthop: nh,
            addrs: ap.0,
        })
    }
}

impl std::fmt::Debug for BgpMPUpdates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpMPUpdates")
            .field("nexthop", &self.nexthop)
            .field("addrs", &self.addrs)
            .finish()
    }
}
impl std::fmt::Display for BgpMPUpdates {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BgpMPUpdates ({:?} {:?})", self.nexthop, self.addrs)
    }
}
impl BgpAttr for BgpMPUpdates {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 14,
            flags: 144,
        }
    }
    fn encode_to(
        &self,
        peer: &BgpSessionParams,
        buf: &mut [u8],
    ) -> Result<usize, BgpError> {
        let afisafi=self.addrs.get_afi_safi();
        setn_u16(afisafi.0,&mut buf[..2]);
        buf[2]=afisafi.1;
        let mut curpos: usize = 4;
        let nhl=match &self.nexthop {
            BgpAddr::V4(a) => {
                encode_addrv4_to(&a, &mut buf[curpos..])?
            }
            BgpAddr::V6(a) => {
                encode_addrv6_to(&a, &mut buf[curpos..])?
            }
            BgpAddr::V4RD(a) => {
                a.encode_to(peer.peer_mode,&mut buf[curpos..])?
            }
            BgpAddr::V6RD(a) => {
                a.encode_to(peer.peer_mode,&mut buf[curpos..])?
            }
            _ => return Err(BgpError::static_str("Invalid nexthop kind"))
        };
        buf[3]=nhl as u8;
        curpos+=nhl;
        buf[curpos]=0;//snpa
        curpos += 1;
        let ps=self.addrs.encode_to(peer,&mut buf[curpos..])?;
        curpos+=ps;
        Ok(curpos)
    }
}

/// BGP multiprotocol withdraws
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct BgpMPWithdraws {
    /// NLRI
    pub addrs: BgpAddrs,
}
impl BgpMPWithdraws {
    pub fn decode_from(
        peer: &BgpSessionParams,
        buf: &[u8],
    ) -> Result<BgpMPWithdraws, BgpError> {
        let afi = getn_u16(&buf);
        let safi = buf[2];
        let a = BgpAddrs::decode_from(peer, afi, safi, &buf[3..])?;
        Ok(BgpMPWithdraws { addrs: a.0 })
    }
}
impl std::fmt::Debug for BgpMPWithdraws {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpMPWithdraws")
            .field("addrs", &self.addrs)
            .finish()
    }
}
impl std::fmt::Display for BgpMPWithdraws {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "BgpMPWithdraws ({:?})", self.addrs)
    }
}
impl BgpAttr for BgpMPWithdraws {
    fn attr(&self) -> BgpAttrParams {
        BgpAttrParams {
            typecode: 15,
            flags: 144,
        }
    }
    fn encode_to(
        &self,
        peer: &BgpSessionParams,
        buf: &mut [u8],
    ) -> Result<usize, BgpError> {
        let afisafi=self.addrs.get_afi_safi();
        setn_u16(afisafi.0,&mut buf[..2]);
        buf[2]=afisafi.1;
        let mut curpos: usize = 3;
        let ps=self.addrs.encode_to(peer,&mut buf[curpos..])?;
        curpos+=ps;
        Ok(curpos)
    }
}

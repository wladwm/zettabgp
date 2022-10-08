// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module describes NLRI data structures for vpls

use crate::afi::*;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

/// BGP VPLS NLRI
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpAddrL2 {
    pub rd: BgpRD,
    pub site: u16,
    pub offset: u16,
    pub range: u16,
    pub labels: MplsLabels,
}
impl BgpItemLong<BgpAddrL2> for BgpAddrL2 {
    fn extract_from(size: usize, buf: &[u8]) -> Result<BgpAddrL2, BgpError> {
        if size < 17 {
            return Err(BgpError::from_string(format!(
                "Invalid FEC length for BgpAddrL2: {:?} bytes",
                size
            )));
        }
        let srd = BgpRD::decode_from(BgpTransportMode::IPv4, buf)?;
        let lbls = MplsLabels::extract_bits_from(((size - 14) * 8) as u8, &buf[14..])?;
        Ok(BgpAddrL2 {
            rd: srd.0,
            site: getn_u16(&buf[8..10]),
            offset: getn_u16(&buf[10..12]),
            range: getn_u16(&buf[12..14]),
            labels: lbls.0,
        })
    }
    fn pack_to(&self, buf: &mut [u8]) -> Result<usize, BgpError> {
        if buf.len() < 15 {
            return Err(BgpError::insufficient_buffer_size());
        }
        self.rd.encode_rd_to(buf)?;
        setn_u16(self.site, &mut buf[8..10]);
        setn_u16(self.offset, &mut buf[10..12]);
        setn_u16(self.range, &mut buf[12..14]);
        let r = self.labels.set_bits_to(&mut buf[14..])?;
        Ok(r.1 + 14)
    }
}
impl std::fmt::Display for BgpAddrL2 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "<{}> {}::{}..{}",
            self.rd, self.site, self.offset, self.range
        )
    }
}
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[cfg(feature = "serialization")]
#[derive(Serialize, Deserialize)]
pub struct BgpL2 {
    pub rd: BgpRD,
    pub site: u16,
    pub offset: u16,
    pub range: u16,
}
impl BgpL2 {
    pub fn new(srd: BgpRD, st: u16, ofs: u16, rng: u16) -> BgpL2 {
        BgpL2 {
            rd: srd,
            site: st,
            offset: ofs,
            range: rng,
        }
    }
}
impl std::fmt::Display for BgpL2 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "<{}>site {}-{}..{}",
            self.rd, self.site, self.offset, self.range
        )
    }
}
impl BgpAddrItem<BgpL2> for BgpL2 {
    fn decode_from(mode: BgpTransportMode, buf: &[u8]) -> Result<(BgpL2, usize), BgpError> {
        if buf.len() >= 14 {
            let rdp = BgpRD::decode_from(mode, &buf[0..8])?;
            Ok((
                BgpL2 {
                    rd: rdp.0,
                    site: getn_u16(&buf[8..10]),
                    offset: getn_u16(&buf[10..12]),
                    range: getn_u16(&buf[12..14]),
                },
                14,
            ))
        } else {
            Err(BgpError::static_str("Invalid BgpL2 buffer len"))
        }
    }
    fn encode_to(&self, mode: BgpTransportMode, buf: &mut [u8]) -> Result<usize, BgpError> {
        let pos = self.rd.encode_to(mode, buf)?;
        setn_u16(self.site, &mut buf[pos..]);
        setn_u16(self.offset, &mut buf[pos + 2..]);
        setn_u16(self.range, &mut buf[pos + 4..]);
        Ok(pos + 6)
    }
}

// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::*;

/// BGP keepalive message
#[derive(Debug)]
pub struct BgpKeepaliveMessage {}

impl BgpMessage for BgpKeepaliveMessage {
    fn decode_from(&mut self, _peer: &BgpSessionParams, _buf: &[u8]) -> Result<(), BgpError> {
        Ok(())
    }
    fn encode_to(&self, _peer: &BgpSessionParams, _buf: &mut [u8]) -> Result<usize, BgpError> {
        Ok(0)
    }
}

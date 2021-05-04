// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module contains BGP messages

use crate::*;
use crate::error::*;

pub mod open;
pub mod update;
pub mod notification;
pub mod keepalive;
pub mod attributes;

/// trait BgpMessage represents BGP protocol message
pub trait BgpMessage {
    fn decode_from(
        &mut self,
        peer: &BgpSessionParams,
        buf: &[u8],
    ) -> Result<(), BgpError>;
    fn encode_to(
        &self,
        peer: &BgpSessionParams,
        buf: &mut [u8],
    ) -> Result<usize, BgpError>;
}

/// Bgp message type: open, update, notification or keepalive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpMessageType {
    Open,
    Update,
    Notification,
    Keepalive,
}

impl BgpMessageType {
    /// decodes BGP message type from byte code
    pub fn decode_from(code: u8) -> Result<BgpMessageType, BgpError> {
        match code {
            1 => Ok(BgpMessageType::Open),
            2 => Ok(BgpMessageType::Update),
            3 => Ok(BgpMessageType::Notification),
            4 => Ok(BgpMessageType::Keepalive),
            _ => Err(BgpError::static_str("Invalid message type")),
        }
    }
    /// encodes BGP message type into the byte code
    pub fn encode(&self) -> u8 {
        match self {
            BgpMessageType::Open => 1,
            BgpMessageType::Update => 2,
            BgpMessageType::Notification => 3,
            BgpMessageType::Keepalive => 4,
        }
    }
}


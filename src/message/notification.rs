// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{BgpError, BgpMessage, BgpSessionParams};

/// BGP notification message
pub struct BgpNotificationMessage {
/// error code
    pub error_code: u8,
/// error sub-code
    pub error_subcode: u8,
/// extra data
    pub data: u16,
}
impl BgpNotificationMessage {
    /// constructs new empty message
    pub fn new() -> BgpNotificationMessage {
        BgpNotificationMessage {
            error_code: 0,
            error_subcode: 0,
            data: 0,
        }
    }
    /// returns human-friendly error interpretation.
    pub fn error_text(&self) -> String {
        match self.error_code {
            1 => {
                String::from("Message Header Error: ")
                    + (match self.error_subcode {
                        1 => String::from("Connection not synchronized"),
                        2 => String::from("Bad Message Length"),
                        3 => String::from("Bad Message Type"),
                        n => String::from(" subcode ") + n.to_string().as_str(),
                    })
                    .as_str()
            }
            2 => {
                String::from("OPEN Message Error: ")
                    + (match self.error_subcode {
                        1 => String::from("Unsupported Version Number"),
                        2 => String::from("Bad Peer AS"),
                        3 => String::from("Bad BGP Identifier"),
                        4 => String::from("Unsupported Optional Parameter"),
                        5 => String::from("Deprecated(5)"),
                        6 => String::from("Unacceptable Hold Time"),
                        n => String::from(" subcode ") + n.to_string().as_str(),
                    })
                    .as_str()
            }
            3 => {
                String::from("Update Message Error: ")
                    + (match self.error_subcode {
                        1 => String::from("Malformed Attribute List"),
                        2 => String::from("Unrecognized Well-known Attribute"),
                        3 => String::from("Missing Well-known Attribute"),
                        4 => String::from("Attribute Flags Error"),
                        5 => String::from("Attribute Length Error"),
                        6 => String::from("Invalid ORIGIN Attribute"),
                        7 => String::from("Deprecated(7)"),
                        8 => String::from("Invalid NEXT_HOP Attribute"),
                        9 => String::from("Optional Attribute Error"),
                        10 => String::from("Invalid Network Field"),
                        11 => String::from("Malformed AS_PATH"),
                        n => String::from(" subcode ") + n.to_string().as_str(),
                    })
                    .as_str()
            }
            4 => {
                String::from("Hold Timer Expired")
                    + (if self.error_subcode != 0 {
                        String::from(" subcode ") + self.error_subcode.to_string().as_str()
                    } else {
                        String::from("(0)")
                    })
                    .as_str()
            }
            5 => {
                String::from("Finite State Machine Error")
                    + (if self.error_subcode != 0 {
                        String::from(" subcode ") + self.error_subcode.to_string().as_str()
                    } else {
                        String::from("(0)")
                    })
                    .as_str()
            }
            6 => {
                String::from("Cease")
                    + (if self.error_subcode != 0 {
                        String::from(" subcode ") + self.error_subcode.to_string().as_str()
                    } else {
                        String::from("(0)")
                    })
                    .as_str()
            }
            n => {
                String::from("Unknown code ")
                    + n.to_string().as_str()
                    + " subcode "
                    + self.error_subcode.to_string().as_str()
            }
        }
    }
}
impl std::fmt::Debug for BgpNotificationMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgpNotificationMessage")
            .field("error_code", &self.error_code)
            .field("error_subcode", &self.error_subcode)
            .field("data", &self.data)
            .finish()
    }
}
impl std::fmt::Display for BgpNotificationMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "BgpNotificationMessage {:?} code={:?} subcode={:?} data={:?})",
            self.error_text(),
            self.error_code,
            self.error_subcode,
            self.data
        )
    }
}
impl BgpMessage for BgpNotificationMessage {
    fn decode_from(
        &mut self,
        _peer: &BgpSessionParams,
        buf: &[u8],
    ) -> Result<(), BgpError> {
        if buf.len() < 2 {
            return Err(BgpError::static_str(
                "Invalid notification message length",
            ));
        }
        self.error_code = buf[0];
        self.error_subcode = buf[1];
        if buf.len() == 3 {
            self.data = buf[2] as u16;
        }
        if buf.len() > 3 {
            self.data = ((buf[2] as u16) << 8) | (buf[3] as u16);
        }
        Ok(())
    }
    fn encode_to(
        &self,
        _peer: &BgpSessionParams,
        buf: &mut [u8],
    ) -> Result<usize, BgpError> {
        if buf.len() < 4 {
            return Err(BgpError::static_str(
                "Invalid notification message length",
            ));
        }
        buf[0] = self.error_code;
        buf[1] = self.error_subcode;
        buf[2] = (self.data >> 8) as u8;
        buf[3] = (self.data & 0xff) as u8;
        Ok(4)
    }
}

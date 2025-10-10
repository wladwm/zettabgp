// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This module contains error struct

/// This is represents standard library error.
///
/// # Generic usage
///
/// All library methods that can cause errors returns Result<...,BgpError>.
///
#[derive(Debug)]
pub enum BgpError {
    Static(&'static str),
    InsufficientBufferSize,
    ProtocolError,
    TooManyData,
    DynStr(std::string::String),
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl BgpError {
    /// Wraps static string error message.
    #[inline]
    pub fn static_str(ms: &'static str) -> BgpError {
        BgpError::Static(ms)
    }
    /// Wraps std String error message.
    #[inline]
    pub fn from_string(s: std::string::String) -> BgpError {
        BgpError::DynStr(s)
    }
    /// Wraps any error implements std::error::Error. In Box.
    #[inline]
    pub fn from_error(e: Box<dyn std::error::Error + Send + Sync>) -> BgpError {
        BgpError::Other(e)
    }
    /// Just says that buffer size is too small.
    #[inline]
    pub fn insufficient_buffer_size() -> BgpError {
        BgpError::InsufficientBufferSize
    }
    /// Just says that we have common protocol error.
    #[inline]
    pub fn protocol_error() -> BgpError {
        BgpError::ProtocolError
    }
    /// Just says that data size is too big to be encoded.
    #[inline]
    pub fn too_many_data() -> BgpError {
        BgpError::TooManyData
    }
}
impl std::fmt::Display for BgpError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BgpError::InsufficientBufferSize => write!(f, "BgpError InsufficientBufferSize"),
            BgpError::ProtocolError => write!(f, "BgpError ProtocolError"),
            BgpError::TooManyData => write!(f, "BgpError TooManyData"),
            BgpError::Static(s) => write!(f, "BgpError {}", s),
            BgpError::DynStr(s) => write!(f, "BgpError {}", s),
            BgpError::Other(e) => write!(f, "BgpError {}", e),
        }
    }
}
impl std::error::Error for BgpError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        match self {
            BgpError::Other(e) => Some(e.as_ref()),
            _ => None
        }
    }
}

impl From<std::io::Error> for BgpError {
    #[inline]
    fn from(error: std::io::Error) -> Self {
        BgpError::Other(Box::new(error))
    }
}

impl From<std::net::AddrParseError> for BgpError {
    #[inline]
    fn from(error: std::net::AddrParseError) -> Self {
        BgpError::Other(Box::new(error))
    }
}

impl From<std::str::Utf8Error> for BgpError {
    #[inline]
    fn from(error: std::str::Utf8Error) -> Self {
        BgpError::Other(Box::new(error))
    }
}

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
    DynStr(std::string::String),
    Other(Box<dyn std::error::Error>)
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
    pub fn from_error(e: Box<dyn std::error::Error>) -> BgpError {
        BgpError::Other(e)
    }
    /// Just says that buffer size is too small.
    pub fn insufficient_buffer_size() -> BgpError {
        BgpError::Static("Insufficient buffer size")
    }
    /// Just says that we have common protocol error.
    pub fn protocol_error() -> BgpError {
        BgpError::Static("Protocol error")
    }
    /// Just says that data size is too big to be encoded.
    pub fn too_many_data() -> BgpError {
        BgpError::Static("Too many data")
    }
}
impl std::fmt::Display for BgpError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BgpError::Static(s) => write!(f, "BgpError {}", s),
            BgpError::DynStr(s) => write!(f, "BgpError {}", s),
            BgpError::Other(e)  => write!(f, "BgpError {}",e)
        }
    }
}
impl std::error::Error for BgpError {}

impl From<std::io::Error> for BgpError {
    #[inline]
    fn from(error: std::io::Error) -> Self {
        BgpError::Other(Box::new(error))
    }
}


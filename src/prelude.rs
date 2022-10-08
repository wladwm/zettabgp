// Copyright 2021 Vladimir Melnikov.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Convenience re-export of common members
//!
//! Like the standard library's prelude, this module simplifies importing of
//! common items. Unlike the standard prelude, the contents of this module must
//! be imported manually:
//!
//! ```
//! use zettabgp::prelude::*;
//! ```

pub use crate::afi::evpn::*;
pub use crate::afi::flowspec::*;
pub use crate::afi::ipv4::*;
pub use crate::afi::ipv6::*;
pub use crate::afi::mvpn::*;
pub use crate::afi::vpls::*;
pub use crate::afi::*;
pub use crate::error::*;
pub use crate::util::*;
pub use crate::*;

pub use crate::message::keepalive::*;
pub use crate::message::notification::*;
pub use crate::message::open::*;
pub use crate::message::update::*;
pub use crate::message::*;
pub use crate::BgpMessage;

pub use crate::message::attributes::aggregatoras::*;
pub use crate::message::attributes::aspath::*;
pub use crate::message::attributes::atomicaggregate::*;
pub use crate::message::attributes::attrset::*;
pub use crate::message::attributes::clusterlist::*;
pub use crate::message::attributes::community::*;
pub use crate::message::attributes::extcommunity::*;
pub use crate::message::attributes::localpref::*;
pub use crate::message::attributes::med::*;
pub use crate::message::attributes::multiproto::*;
pub use crate::message::attributes::nexthop::*;
pub use crate::message::attributes::origin::*;
pub use crate::message::attributes::originatorid::*;
pub use crate::message::attributes::pmsitunnelattr::*;
pub use crate::message::attributes::unknown::*;
pub use crate::message::attributes::*;

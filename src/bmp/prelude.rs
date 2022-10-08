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
//! use zettabgp::bmp::prelude::*;
//! ```

pub use crate::bmp::bmputl::*;
pub use crate::bmp::msginit::*;
pub use crate::bmp::msgpeer::*;
pub use crate::bmp::msgrmon::*;
pub use crate::bmp::msgterm::*;
pub use crate::bmp::*;

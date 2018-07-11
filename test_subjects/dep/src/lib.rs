// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate log;
pub extern crate simplelog as d2;

use d2::*;
use log::Log;
use log::*;

/// This test subject is used to make sure the multi_dep has two different dependencies on `simplelog`.
/// In this function, a call to `TermLogger::new` of version 0.4.4 is made.
#[inline(never)]
pub fn baz() {
    let logger = TermLogger::new(LogLevelFilter::Info, Config::default());
}

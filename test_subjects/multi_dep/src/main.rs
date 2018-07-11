// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate dep;
extern crate log;
extern crate simplelog as d1;

/// When we build this test subject, we have a binary that uses 2 different versions of simplelog
/// (0.5.2 as direct dependency, and 0.4.0 as indirect dependency provided by dep.
/// This is used to test function whitelisting on different versions in /panic_analysis/test/function_whitelists.rs
#[inline(never)]
fn main() {
    bar();
}

fn bar() {
    baz();
    dep::baz()
}

#[inline(never)]
fn baz() {
    use d1::*;
    use log::*;

    let logger = TermLogger::new(LevelFilter::Info, Config::default());
    dep::baz();
}

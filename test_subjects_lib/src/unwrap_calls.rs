// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub fn call_unwrap() {
    let option: Option<()> = None;
    option.unwrap();
}

pub fn call_expect() {
    let option: Result<(), ()> = Err(());
    option.expect("No value given");
}

pub fn call_option_expect() {
    let option: Option<()> = None;
    option.expect("Custom error message for expect call on an option");
}

pub fn call_unwrap_deep() {
    call_unwrap_deep_2()
}

fn call_unwrap_deep_2() {
    call_unwrap_deep_3()
}

fn call_unwrap_deep_3() {
    let option: Option<()> = None;
    option.unwrap();
}
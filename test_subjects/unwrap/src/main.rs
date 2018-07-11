// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate test_subjects_lib;

/// This test subject builds to en executable that calls `unwrap` and expect in several different ways.
/// It is used in the /panic_analysis/tests/recognize_unwrap.rs integration tests
fn main() {
    call_unwrap();
    call_expect();
    call_option_expect();
    call_unwrap_deep();
    panic_otherwise();
}

fn call_unwrap() {
    test_subjects_lib::unwrap_calls::call_unwrap();
}

fn call_expect() {
    test_subjects_lib::unwrap_calls::call_expect();
}

fn call_option_expect() {
    test_subjects_lib::unwrap_calls::call_option_expect();
}

fn call_unwrap_deep() {
    test_subjects_lib::unwrap_calls::call_unwrap_deep();
}

fn panic_otherwise() {
    panic!("Custom panic")
}

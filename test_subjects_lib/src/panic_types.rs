// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub fn standard_panic() {
    panic!();
}

pub fn integer_overflow() {
    let possible_overflow = 1 + 1;
}

pub fn index_out_of_bounds() {
    let v = vec![0, 1, 2];
    let oob = v[3];
}

pub fn unwrap_none() {
    let option: Option<usize> = None;
    option.unwrap();
}

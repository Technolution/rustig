// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate test_subjects_lib;

/// This test subject builds to en executable that indexes a `Vec` in several different ways.
/// It is used in the /panic_analysis/tests/recognize_indexing.rs integration tests
fn main() {
    let vec = Vec::new();
    call_index(vec);
    call_correct();
}

#[inline(never)]
fn call_index(vec: Vec<usize>) -> usize {
    vec[3]
}

#[inline(never)]
fn call_correct() -> usize {
    let vec_other = vec![2, 3, 7];
    vec_other[1]
}

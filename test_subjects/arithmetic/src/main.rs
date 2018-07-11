// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate test_subjects_lib;

use test_subjects_lib::arithmetic;

fn main() {
    let a = arithmetic::add(2, 4); // 6
    let b = arithmetic::subtract(42, a); // 36
    let c = arithmetic::divide(b, 2); // 18
    let d = arithmetic::remainder(c, 10); // 8
    let e = arithmetic::shl(d, 2); // 2
    let f = arithmetic::shr(e, 3); // 16
    let g = match arithmetic::divide_no_overflow(f, 4) {
        Some(val) => val,
        None => 4,
    }; // 4
    let h = match arithmetic::remainder_no_overflow(g, 3) {
        Some(val) => val,
        None => 1,
    }; // 1
    let i = arithmetic::multiply(h, 16); // 16
    let j = match arithmetic::remainder_safe(i, 10) {
        Some(val) => val,
        None => 6,
    }; // 6
    let l = match arithmetic::divide_safe(j, 3) {
        Some(val) => val,
        None => 2,
    }; // 2
    arithmetic::equal(l, 2);
}

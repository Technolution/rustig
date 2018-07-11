// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

trait Call {
    #[inline(never)]
    fn maybe_panic(&self);

    #[inline(never)]
    fn maybe_panic2(&self);
}

struct S1;
struct S2 {
    s1: S1,
}

impl Call for S1 {
    #[inline(never)]
    fn maybe_panic(&self) { }

    fn maybe_panic2(&self) {
        panic!()
    }
}

/// Should not panic
#[inline(never)]
pub fn maybe_panic() {
    let s1 = S1{};
    let s = &s1 as &Call;
    s.maybe_panic2();
}

/// Should panic
#[inline(never)]
pub fn maybe_panic2() {
    let s1 = S1{};
    let s = &s1 as &Call;
    s.maybe_panic();
}

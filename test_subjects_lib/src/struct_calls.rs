// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

struct StructCalls;

impl StructCalls {
    #[inline(never)]
    fn struct_call() {
        panic!();
    }

    #[inline(never)]
    fn struct_call_with_self(&self) {
        panic!();
    }
}

#[inline(never)]
pub fn struct_call() {
    StructCalls::struct_call();
}

#[inline(never)]
pub fn struct_call_with_self() {
    StructCalls::struct_call_with_self(&StructCalls);
}

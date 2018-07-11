// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

struct Calls;

trait TraitCalls {
    #[inline(never)]
    fn trait_call();
    #[inline(never)]
    fn trait_call_with_self(&self);
}

impl TraitCalls for Calls {
    #[inline(never)]
    fn trait_call() {
        panic!();
    }
    #[inline(never)]
    fn trait_call_with_self(&self) {
        panic!();
    }
}

#[inline(never)]
pub fn simple_call() {
    Calls::trait_call();
}

#[inline(never)]
pub fn simple_call2() {
    Calls::trait_call_with_self(&Calls);
}

#[inline(never)]
pub fn simple_call3() {
    Calls.trait_call_with_self();
}

#[inline(never)]
pub fn simple_call4() {
    <Calls as TraitCalls>::trait_call();
}
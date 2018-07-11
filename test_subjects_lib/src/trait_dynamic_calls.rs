// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

struct Calls;

trait TraitCallsWithReceiver {
    #[inline(never)]
    fn call_with_self(&self);
}

trait TraitCallsWithReceiverDup {
    #[inline(never)]
    fn call_with_self(&self);
}

impl TraitCallsWithReceiver for Calls {
    #[inline(never)]
    fn call_with_self(&self) {
        panic!();
    }
}

impl TraitCallsWithReceiverDup for Calls {
    #[inline(never)]
    fn call_with_self(&self) {
        panic!();
    }
}

impl Calls {
    #[inline(never)]
    fn call_with_self(&self) {
        panic!();
    }
}

#[inline(never)]
pub fn dynamic_call() {
    let call: &TraitCallsWithReceiver = &Calls;
    call.call_with_self();
}

#[inline(never)]
pub fn dynamic_call_2() {
    let call: &TraitCallsWithReceiver = &Calls;
    TraitCallsWithReceiver::call_with_self(call);
}

#[inline(never)]
pub fn reference_call() {
    let call = &Calls;
    call.call_with_self();
}

// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

struct Calls;

trait TraitCalls {
    #[inline(never)]
    fn trait_call_with_self(&self);
}

impl TraitCalls for Calls {
    #[inline(never)]
    fn trait_call_with_self(&self) {
        panic!()
    }
}

#[inline(never)]
fn ret_lambda() -> fn() {
    || panic!()
}

#[inline(never)]
fn call_unsized<T: TraitCalls + ?Sized>(call: &T) {
    call.trait_call_with_self();
}

#[inline(never)]
fn call_with_reference<T: TraitCalls>(call: T) {
    call.trait_call_with_self();
}

#[inline(never)]
pub fn reference_call() {
    call_with_reference(Calls);
}

#[inline(never)]
pub fn unsized_call() {
    call_unsized(&Calls);
}

#[inline(never)]
pub fn unsized_call_trait() {
    let calls: &TraitCalls = &Calls;
    call_unsized(calls);
}

#[inline(never)]
pub fn panic_lambda() {
    let panic_lambda = ret_lambda();
    panic_lambda();
}

#[inline(never)]
pub fn panic_lambda_local() {
    let panic_lambda_2 = || panic!();
    panic_lambda_2();
}

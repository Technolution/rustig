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
fn ret_trait_box() -> Box<TraitCalls> {
    Box::new(Calls {})
}

#[inline(never)]
pub fn call_panic_box() {
    let returned_box_trait = ret_trait_box();

    returned_box_trait.trait_call_with_self();
}

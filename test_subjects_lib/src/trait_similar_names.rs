// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

struct Calls;

trait SimilarTraitCalls {
    #[inline(never)]
    fn trait_call_dup();
    #[inline(never)]
    fn trait_call_with_self_dup(&self);
}

trait SimilarTraitCalls2 {
    #[inline(never)]
    fn trait_call_dup();
    #[inline(never)]
    fn trait_call_with_self_dup(&self);
}

impl SimilarTraitCalls for Calls {
    #[inline(never)]
    fn trait_call_dup() {
    }
    #[inline(never)]
    fn trait_call_with_self_dup(&self) {
    }
}

impl SimilarTraitCalls2 for Calls {
    #[inline(never)]
    fn trait_call_dup() {
        panic!();
    }
    #[inline(never)]
    fn trait_call_with_self_dup(&self) {
        panic!();
    }
}

#[inline(never)]
pub fn trait_call_dup1() {
    <Calls as SimilarTraitCalls>::trait_call_dup();
}

#[inline(never)]
pub fn trait_call_dup_with_self() {
    <Calls as SimilarTraitCalls>::trait_call_with_self_dup(&Calls);
}

#[inline(never)]
pub fn duplicate_trait_call() {
    SimilarTraitCalls::trait_call_with_self_dup(&Calls);
}

#[inline(never)]
pub fn trait_call_dup2() {
    <Calls as SimilarTraitCalls2>::trait_call_dup();
}

#[inline(never)]
pub fn trait_call_dup_with_self2() {
    <Calls as SimilarTraitCalls2>::trait_call_with_self_dup(&Calls);
}

#[inline(never)]
pub fn duplicate_trait_call2() {
    SimilarTraitCalls2::trait_call_with_self_dup(&Calls);
}

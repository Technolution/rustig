// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

struct CallsWithFn<'a, T: 'a>
where
    T: Fn(),
{
    lambda: &'a T,
}

trait TraitCallsWithFn {
    #[inline(never)]
    fn call_inner_lambda(&self);
}

impl<'a, T> TraitCallsWithFn for CallsWithFn<'a, T>
where
    T: Fn(),
{
    #[inline(never)]
    fn call_inner_lambda(&self) {
        let lambda = &self.lambda;
        lambda();
    }
}

#[inline(never)]
fn ret_lambda() -> fn() {
    || panic!()
}

#[inline(never)]
pub fn lambda_call() {
    let panic_lambda_struct = CallsWithFn {
        lambda: &ret_lambda(),
    };
    panic_lambda_struct.call_inner_lambda();
}

/// This is a difficult construction:
/// we get a box which contains a trait which calls a function that calls a generic reference to an anonymous function
#[inline(never)]
pub fn lambda_struct_as_trait_call() {
    let lambda = ret_lambda();
    let panic_lambda_struct_as_trait: Box<TraitCallsWithFn> =
        Box::new(CallsWithFn { lambda: &lambda });
    panic_lambda_struct_as_trait.call_inner_lambda();
}
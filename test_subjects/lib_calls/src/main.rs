// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate test_subjects_lib;

fn call_box_trait_panics() {
    use test_subjects_lib::box_traits::*;
    call_panic_box()
}

fn call_impl_trait_panics() {
    use test_subjects_lib::impl_traits::*;
    call_impl_trait_panic()
}

fn call_lambda_struct_panics() {
    use test_subjects_lib::lambda_structs::*;
    lambda_call();
    lambda_struct_as_trait_call();
}

fn call_panic_types() {
    use test_subjects_lib::panic_types::*;
    standard_panic();
    integer_overflow();
    index_out_of_bounds();
    unwrap_none();
}

fn call_reference_calls() {
    use test_subjects_lib::reference_calls::*;
    unsized_call_trait();
    panic_lambda();
    panic_lambda_local();
}

fn call_struct_calls() {
    use test_subjects_lib::struct_calls::*;
    struct_call();
    struct_call_with_self();
}

fn call_trait_dynamic_calls() {
    use test_subjects_lib::trait_dynamic_calls::*;
    dynamic_call();
    dynamic_call_2();
    reference_call();
}

fn call_trait_similar_names() {
    use test_subjects_lib::trait_similar_names::*;
    trait_call_dup1();
    trait_call_dup_with_self();
    duplicate_trait_call();
    trait_call_dup2();
    trait_call_dup_with_self2();
    duplicate_trait_call2();
}

fn call_trait_simple_calls() {
    use test_subjects_lib::trait_simple_calls::*;
    simple_call();
    simple_call2();
    simple_call3();
    simple_call4();
}

fn call_same_vtable() {
    use test_subjects_lib::same_vtable::*;

    // False positive
    maybe_panic();
}

fn main() {
    call_box_trait_panics();
    call_impl_trait_panics();
    call_lambda_struct_panics();
    call_panic_types();
    call_reference_calls();
    call_struct_calls();
    call_trait_dynamic_calls();
    call_trait_similar_names();
    call_trait_simple_calls();
    call_same_vtable();
}

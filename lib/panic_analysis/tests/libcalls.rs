// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(test)]
mod test {
    extern crate panic_analysis;
    extern crate test_common;

    use self::panic_analysis::AnalysisOptions;
    use self::test_common::TestSubjectType;

    static ANALYZED_TEST_SUBJECT: &str = "lib_calls";

    /// Run panic_analysis on `crate_name` and check if there is a `procedure_name` in it
    fn backtrace_has_procedure_with_name(
        subject_type: &TestSubjectType,
        crate_name: &str,
        procedure_name: &str,
    ) -> bool {
        backtrace_has_procedure_with_name_with_count(subject_type, crate_name, procedure_name, 1)
    }

    /// Run panic_analysis on `crate_name` and check if there is `count` amount of `procedure_name` in it
    fn backtrace_has_procedure_with_name_with_count(
        subject_type: &TestSubjectType,
        crate_name: &str,
        procedure_name: &str,
        count: usize,
    ) -> bool {
        let name = crate_name;
        let options = create_options(
            test_common::get_test_subject_path(name, subject_type)
                .to_str()
                .unwrap()
                .to_string(),
        );
        let panics = panic_analysis::find_panics(&options).unwrap();

        let panic_count = panics
            .calls
            .iter()
            .filter(|call| {
                call.backtrace
                    .iter()
                    .any(|node| node.procedure.borrow().name == procedure_name)
            })
            .count();

        panic_count == count
    }

    fn create_options(subject: String) -> AnalysisOptions {
        AnalysisOptions {
            binary_path: Some(subject),
            crate_names: vec!["test_subjects".to_string()],
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            whitelisted_functions: vec![],
            full_crate_analysis: false,
        }
    }

    /// Run panic_analysis on `crate_name` and check if there are `procedure_names` in it
    fn assert_backtrace_has_procedure_with_name(
        subject_type: &TestSubjectType,
        crate_name: &str,
        procedure_names: &[&str],
    ) {
        procedure_names.iter().for_each(|procedure_name| {
            assert!(
                backtrace_has_procedure_with_name(subject_type, crate_name, procedure_name),
                "procedure with name: {} not found in panic traces of test_subject {}",
                procedure_name,
                crate_name
            );
        })
    }

    /// The macro lib_test allows for easy definition of tests that check whether a certain panic trace is present in some crate.
    /// Example usage: to test whether a test subject `t` contains a call to `s1` and `s2` in release mode, use the following:
    /// lib_tests! { t_contains_s: (TestSubjectType::Release, "t", ["s1", "s2"])
    macro_rules! lib_tests {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (subject_type, procedure_names) = $value;
                assert_backtrace_has_procedure_with_name(&subject_type, ANALYZED_TEST_SUBJECT, &procedure_names);
            }
        )*
        }
    }

    /// Debug mode tests
    lib_tests! {
        test_lib_calls_box: (TestSubjectType::Debug, ["call_panic_box"]),
        test_lib_calls_impl_traits: (TestSubjectType::Debug, ["call_impl_trait_panic"]),
        test_lib_calls_lambda_struct: (TestSubjectType::Debug, ["lambda_call", "lambda_struct_as_trait_call"]),
        // Note that integer overflow can be detected in debug, but not in release
        test_lib_calls_panic_types: (TestSubjectType::Debug, ["standard_panic", "integer_overflow", "index_out_of_bounds","unwrap_none"]),
        test_lib_calls_reference_calls: (TestSubjectType::Debug, ["unsized_call_trait", "panic_lambda", "panic_lambda_local"]),
        test_lib_calls_structs: (TestSubjectType::Debug, ["struct_call", "struct_call_with_self"]),
        test_lib_calls_trait_dynamic: (TestSubjectType::Debug, ["trait_call_dup2", "trait_call_dup_with_self2", "duplicate_trait_call2"]),
        test_lib_calls_traits_similar_names: (TestSubjectType::Debug, ["call_impl_trait_panic"]),
        test_lib_calls_traits_simple: (TestSubjectType::Debug, ["simple_call", "simple_call2", "simple_call3", "simple_call4"]),
        // THIS IS A FALSE POSITIVE!
        test_same_vtable: (TestSubjectType::Debug, ["maybe_panic2"]),
    }

    /// Release mode tests
    lib_tests! {
        test_lib_calls_box_release: (TestSubjectType::Release, ["call_panic_box"]),
        test_lib_calls_impl_traits_release: (TestSubjectType::Release, ["call_impl_trait_panic"]),
        test_lib_calls_lambda_struct_release: (TestSubjectType::Release, ["lambda_call", "lambda_struct_as_trait_call"]),
        // Note that integer overflow can be detected in debug, but not in release
        test_lib_calls_panic_types_release: (TestSubjectType::Release, ["standard_panic", "index_out_of_bounds","unwrap_none"]),
        test_lib_calls_reference_calls_release: (TestSubjectType::Release, ["unsized_call_trait", "panic_lambda", "panic_lambda_local"]),
        test_lib_calls_structs_release: (TestSubjectType::Release, ["struct_call", "struct_call_with_self"]),
        test_lib_calls_trait_dynamic_release: (TestSubjectType::Release, ["trait_call_dup2", "trait_call_dup_with_self2", "duplicate_trait_call2"]),
        test_lib_calls_traits_similar_names_release: (TestSubjectType::Release, ["call_impl_trait_panic"]),
        test_lib_calls_traits_simple_release: (TestSubjectType::Release, ["simple_call", "simple_call2", "simple_call3", "simple_call4"]),
        // THIS IS A FALSE POSITIVE!
        test_same_vtable_release: (TestSubjectType::Release, ["maybe_panic2"]),
    }
}

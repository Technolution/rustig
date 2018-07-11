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

    use self::panic_analysis::*;
    use self::test_common::*;

    /// Test if we can retrieve a message on a call to `core::panicking::panic` in debug builds.
    /// Since the `panic!` macro in code without `#![no_std]` will use `std::panicking::begin_panic`, we use 'unwrap' here.
    #[test]
    pub fn test_find_core_message() {
        let path = test_common::get_test_subject_path("unwrap", &TestSubjectType::Debug);
        let binary_path = path.to_str().map(|x| x.to_string());

        let options = AnalysisOptions {
            binary_path,
            crate_names: vec!["test_subjects".to_string()],
            full_crate_analysis: false,
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            whitelisted_functions: vec![],
        };

        let calls = find_panics(&options).unwrap();
        let unwrap_call = calls
            .calls
            .iter()
            .find(|trace| {
                trace.backtrace[0].procedure.borrow().linkage_name_demangled
                    == "unwrap::call_unwrap"
            })
            .expect("No trace starting at unwrap::call_unwrap found");

        assert_eq!(
            unwrap_call.message,
            Some("called `Option::unwrap()` on a `None` value".to_string())
        );
        assert_eq!(
            unwrap_call
                .backtrace
                .last()
                .unwrap()
                .procedure
                .borrow()
                .linkage_name_demangled,
            "core::panicking::panic"
        );
    }

    /// Test if we can retrieve a message on a call to `core::panicking::panic` in release builds.
    /// Since the `panic!` macro in code without `#![no_std]` will use `std::panicking::begin_panic`, we use 'unwrap' here.
    #[test]
    pub fn test_find_core_message_release() {
        let path = test_common::get_test_subject_path("unwrap", &TestSubjectType::Release);
        let binary_path = path.to_str().map(|x| x.to_string());

        let options = AnalysisOptions {
            binary_path,
            crate_names: vec!["test_subjects".to_string()],
            full_crate_analysis: false,
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            whitelisted_functions: vec![],
        };

        let calls = find_panics(&options).unwrap();
        let unwrap_call = calls
            .calls
            .iter()
            .find(|trace| {
                trace.backtrace[0].procedure.borrow().linkage_name_demangled
                    == "unwrap::call_unwrap"
            })
            .expect("No trace starting at unwrap::call_unwrap found");

        assert_eq!(
            unwrap_call.message,
            Some("called `Option::unwrap()` on a `None` value".to_string())
        );
        assert_eq!(
            unwrap_call
                .backtrace
                .last()
                .unwrap()
                .procedure
                .borrow()
                .linkage_name_demangled,
            "core::panicking::panic"
        );
    }

    /// Test if we can retrieve a message on a call to `std::panicking::begin_panic` in debug builds.
    #[test]
    pub fn test_find_std_message() {
        let path = test_common::get_test_subject_path("direct", &TestSubjectType::Debug);
        let binary_path = path.to_str().map(|x| x.to_string());

        let options = AnalysisOptions {
            binary_path,
            crate_names: vec!["test_subjects".to_string()],
            full_crate_analysis: false,
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            whitelisted_functions: vec![],
        };

        let calls = find_panics(&options).unwrap();
        assert_eq!(
            calls.calls.len(),
            1,
            "Expected 1 trace from 'direct' test subject"
        );

        let direct_call = &calls.calls[0];

        assert_eq!(direct_call.message, Some("Panic from bar".to_string()));
        assert_eq!(
            direct_call
                .backtrace
                .last()
                .unwrap()
                .procedure
                .borrow()
                .linkage_name_demangled,
            "std::panicking::begin_panic"
        );
    }

    /// Test if we can retrieve a message on a call to `std::panicking::begin_panic` in release builds.
    #[test]
    pub fn test_find_std_message_release() {
        let path = test_common::get_test_subject_path("direct", &TestSubjectType::Release);
        let binary_path = path.to_str().map(|x| x.to_string());

        let options = AnalysisOptions {
            binary_path,
            crate_names: vec!["test_subjects".to_string()],
            full_crate_analysis: false,
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            whitelisted_functions: vec![],
        };

        let calls = find_panics(&options).unwrap();
        assert_eq!(
            calls.calls.len(),
            1,
            "Expected 1 trace from 'direct' test subject"
        );

        let direct_call = &calls.calls[0];

        assert_eq!(direct_call.message, Some("Panic from bar".to_string()));
        assert_eq!(
            direct_call
                .backtrace
                .last()
                .unwrap()
                .procedure
                .borrow()
                .linkage_name_demangled,
            "std::panicking::begin_panic"
        );
    }

    /// Test if we can retrieve a message on a call to `Option::expect` in release builds.
    /// Unfortunately, due to complex assembly code, we can not retrieve them in debug.
    #[test]
    pub fn test_find_option_expect_message_release() {
        let path = test_common::get_test_subject_path("unwrap", &TestSubjectType::Release);
        let binary_path = path.to_str().map(|x| x.to_string());

        let options = AnalysisOptions {
            binary_path,
            crate_names: vec!["test_subjects".to_string()],
            full_crate_analysis: false,
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            whitelisted_functions: vec![],
        };

        let calls = find_panics(&options).unwrap();
        let expect_call = calls
            .calls
            .iter()
            .find(|trace| {
                trace.backtrace[0].procedure.borrow().linkage_name_demangled
                    == "unwrap::call_option_expect"
            })
            .expect("No trace starting at unwrap::call_option_expect found");

        assert_eq!(
            expect_call.message,
            Some("Custom error message for expect call on an option".to_string())
        );
        assert!(
            expect_call.backtrace.len() > 3,
            "Backtrace too short to originate from expect call"
        );
        assert_eq!(
            &expect_call.backtrace[2]
                .procedure
                .borrow()
                .linkage_name_demangled,
            "<core::option::Option<T>>::expect"
        );
    }

    /// Test if we can retrieve a message on a call to `Result::expect` in release builds.
    /// Unfortunately, due to complex assembly code, we can not retrieve them in debug.
    #[test]
    pub fn test_find_result_expect_message_release() {
        let path = test_common::get_test_subject_path("unwrap", &TestSubjectType::Release);
        let binary_path = path.to_str().map(|x| x.to_string());

        let options = AnalysisOptions {
            binary_path,
            crate_names: vec!["test_subjects".to_string()],
            full_crate_analysis: false,
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            whitelisted_functions: vec![],
        };

        let calls = find_panics(&options).unwrap();
        let expect_call = calls
            .calls
            .iter()
            .find(|trace| {
                trace.backtrace[0].procedure.borrow().linkage_name_demangled
                    == "unwrap::call_expect"
            })
            .expect("No trace starting at unwrap::call_expect found");

        assert_eq!(expect_call.message, Some("No value given".to_string()));
        assert!(
            expect_call.backtrace.len() > 3,
            "Backtrace too short to originate from expect call"
        );
        assert_eq!(
            &expect_call.backtrace[2]
                .procedure
                .borrow()
                .linkage_name_demangled,
            "<core::result::Result<T, E>>::expect"
        );
    }

}

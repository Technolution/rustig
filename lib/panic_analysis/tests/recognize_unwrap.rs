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

    /// In this integration test we look at the 'unwrap' test subject
    /// This library has a dependency on test_subjects_lib::unwrap, which does calls to `Option::unwrap()`, `Option::expect`, `Result::unwrap()` and a direct panic call
    /// We test if these 4 traces are found, and categorized correctly.
    #[test]
    pub fn test_recognize_unwraps() {
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

        let unwrap_panics = calls
            .calls
            .iter()
            .filter(|c| *c.pattern.borrow() == PanicPattern::Unwrap)
            .collect::<Vec<_>>();
        let other_panics = calls
            .calls
            .iter()
            .filter(|c| *c.pattern.borrow() != PanicPattern::Unwrap)
            .collect::<Vec<_>>();

        assert_eq!(calls.calls.len(), 5);
        assert_eq!(unwrap_panics.len(), 4);
        assert_eq!(other_panics.len(), 1);

        let unwrap_traces = unwrap_panics
            .iter()
            .map(|x| {
                x.backtrace
                    .iter()
                    .map(|entry| entry.procedure.borrow().linkage_name_demangled.to_owned())
                    .take_while(|x| !x.starts_with("core"))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        assert!(unwrap_traces.iter().any(|x| x == &vec![
            "unwrap::call_unwrap",
            "test_subjects_lib::unwrap_calls::call_unwrap",
            "<core::option::Option<T>>::unwrap",
        ]));
        assert!(unwrap_traces.iter().any(|x| x == &vec![
            "unwrap::call_expect",
            "test_subjects_lib::unwrap_calls::call_expect",
            "<core::result::Result<T, E>>::expect",
        ]));
        assert!(unwrap_traces.iter().any(|x| x == &vec![
            "unwrap::call_option_expect",
            "test_subjects_lib::unwrap_calls::call_option_expect",
            "<core::option::Option<T>>::expect",
        ]));
        assert!(unwrap_traces.iter().any(|x| x == &vec![
            "unwrap::call_unwrap_deep",
            "test_subjects_lib::unwrap_calls::call_unwrap_deep",
            "test_subjects_lib::unwrap_calls::call_unwrap_deep_2",
            "test_subjects_lib::unwrap_calls::call_unwrap_deep_3",
            "<core::option::Option<T>>::unwrap",
        ]));

        let other_trace = other_panics[0]
            .backtrace
            .iter()
            .map(|entry| entry.procedure.borrow().linkage_name_demangled.to_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            vec!["unwrap::panic_otherwise", "std::panicking::begin_panic"],
            other_trace
        );
    }
}

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

    /// In this integration test we look at the 'direct' test subject
    /// This test subject has a main, in which 2 functions (foo and bar) are inlined.
    /// Also, bar panics. We test if this trace is found, with correct inline frames, and recognized as direct panic.
    #[test]
    pub fn test_recognize_inlined_direct_panics() {
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
        assert_eq!(calls.calls.len(), 1);

        let direct_trace = &calls.calls[0];
        assert_eq!(*direct_trace.pattern.borrow(), PanicPattern::DirectCall);

        let direct_outer_frames = direct_trace
            .backtrace
            .iter()
            .map(|x| x.procedure.borrow().linkage_name_demangled.to_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            direct_outer_frames,
            vec!["direct::main", "std::panicking::begin_panic"]
        );

        let direct_inline_frames = direct_trace.backtrace[0]
            .outgoing_invocation
            .as_ref()
            .unwrap()
            .borrow()
            .frames
            .iter()
            .rev()
            .map(|inline| inline.function_name.to_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            direct_inline_frames,
            vec!["direct::main", "direct::foo", "direct::bar"]
        );
    }

    /// In this integration test we look at the 'indirect' test subject
    /// This test subject has a main, in which 2 functions form a library (call_panic_indirect and call_panic_direct) are inlined.
    /// Also, call_panic_direct panics. We test if this trace is found, with correct inline frames, and but not recognized as direct panic.
    #[test]
    pub fn test_not_recognize_inlined_indirect_panics() {
        let path = test_common::get_test_subject_path("indirect", &TestSubjectType::Debug);
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
        assert_eq!(calls.calls.len(), 1);

        let indirect_trace = &calls.calls[0];
        assert_ne!(*indirect_trace.pattern.borrow(), PanicPattern::DirectCall);

        let indirect_outer_frames = indirect_trace
            .backtrace
            .iter()
            .map(|x| x.procedure.borrow().linkage_name_demangled.to_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            indirect_outer_frames,
            vec!["indirect::main", "std::panicking::begin_panic"]
        );

        let indirect_inline_frames = indirect_trace.backtrace[0]
            .outgoing_invocation
            .as_ref()
            .unwrap()
            .borrow()
            .frames
            .iter()
            .rev()
            .map(|inline| inline.function_name.to_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            indirect_inline_frames,
            vec![
                "indirect::main",
                "test_subjects_lib::inline::call_panic_indirect",
                "test_subjects_lib::inline::call_panic_direct",
            ]
        );
    }

    /// In this integration test we look at the 'direct' test subject
    /// This test subject has a main, in which 2 functions (foo and bar) are inlined.
    /// Also, bar panics. We test if this trace is found, with correct inline frames, and recognized as direct panic.
    #[test]
    pub fn test_recognize_inlined_direct_panics_release() {
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
        assert_eq!(calls.calls.len(), 1);

        let direct_trace = &calls.calls[0];
        assert_eq!(*direct_trace.pattern.borrow(), PanicPattern::DirectCall);

        let direct_outer_frames = direct_trace
            .backtrace
            .iter()
            .map(|x| x.procedure.borrow().linkage_name_demangled.to_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            direct_outer_frames,
            vec!["direct::main", "std::panicking::begin_panic"]
        );

        let direct_inline_frames = direct_trace.backtrace[0]
            .outgoing_invocation
            .as_ref()
            .unwrap()
            .borrow()
            .frames
            .iter()
            .rev()
            .map(|inline| inline.function_name.to_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            direct_inline_frames,
            vec!["direct::main", "direct::foo", "direct::bar"]
        );
    }

    /// In this integration test we look at the 'indirect' test subject
    /// This test subject has a main, in which 2 functions form a library (call_panic_indirect and call_panic_direct) are inlined.
    /// Also, call_panic_direct panics. We test if this trace is found, with correct inline frames, and but not recognized as direct panic.
    #[test]
    pub fn test_not_recognize_inlined_indirect_panics_release() {
        let path = test_common::get_test_subject_path("indirect", &TestSubjectType::Release);
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
        assert_eq!(calls.calls.len(), 1);

        let indirect_trace = &calls.calls[0];
        assert_ne!(*indirect_trace.pattern.borrow(), PanicPattern::DirectCall);

        let indirect_outer_frames = indirect_trace
            .backtrace
            .iter()
            .map(|x| x.procedure.borrow().linkage_name_demangled.to_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            indirect_outer_frames,
            vec!["indirect::main", "std::panicking::begin_panic"]
        );

        let indirect_inline_frames = indirect_trace.backtrace[0]
            .outgoing_invocation
            .as_ref()
            .unwrap()
            .borrow()
            .frames
            .iter()
            .rev()
            .map(|inline| inline.function_name.to_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            indirect_inline_frames,
            vec![
                "indirect::main",
                "test_subjects_lib::inline::call_panic_indirect",
                "test_subjects_lib::inline::call_panic_direct",
            ]
        );
    }
}

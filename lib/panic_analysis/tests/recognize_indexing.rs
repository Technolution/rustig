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

    /// In this integration test we look at the 'indexing' test subject
    /// This library has a dependency on test_subjects_lib::indexing, which does calls to `core::slice::SliceIndex<[T]>>::index`.
    /// We test if these 1 traces is found, and categorized correctly.
    #[test]
    pub fn test_recognize_indexing() {
        let path = test_common::get_test_subject_path("indexing", &TestSubjectType::Release);
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

        let index_panics = calls
            .calls
            .iter()
            .filter(|c| *c.pattern.borrow() == PanicPattern::Indexing)
            .collect::<Vec<_>>();

        let other_panics = calls
            .calls
            .iter()
            .filter(|c| *c.pattern.borrow() != PanicPattern::Indexing)
            .collect::<Vec<_>>();

        assert_eq!(calls.calls.len(), 1);
        assert_eq!(index_panics.len(), 1);
        assert_eq!(other_panics.len(), 0);

        let index_traces = index_panics
            .iter()
            .map(|x| {
                x.backtrace
                    .iter()
                    .map(|entry| entry.procedure.borrow().linkage_name_demangled.to_owned())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let outgoing_invoc = &index_panics[0].backtrace[0].outgoing_invocation;
        let inlines = &outgoing_invoc.as_ref().unwrap().borrow().frames;

        println!("{:?}", index_traces);

        assert!(index_traces.iter().any(|x| {
            let mut iter = x.iter();
            iter.next().unwrap() == "indexing::call_index"
                && iter.next().unwrap() == "core::panicking::panic_bounds_check"
                && iter.next().unwrap() == "core::panicking::panic_fmt"
        }));

        let inline_names: Vec<String> = inlines.iter().map(|x| x.function_name.clone()).collect();

        assert_eq!(
            inline_names,
            vec![
                "<usize as core::slice::SliceIndex<[T]>>::index",
                "core::slice::<impl core::ops::index::Index<I> for [T]>::index",
                "<alloc::vec::Vec<T> as core::ops::index::Index<I>>::index",
                "indexing::call_index",
            ]
        )
    }
}

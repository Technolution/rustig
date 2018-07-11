// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// This module contains several integration tests regarding function whitelisting
/// For this, we created a sample project that depends on 2 different versions of a crate.
/// The callgraph of this project looks as follows:
/// +-------------------------------+   +-------------------+   +------------+
/// | multi_dep                     |   |simplelog@5.2.2    |   |std         |
/// |   +----+    +---+     +---+   |   | +---------------+ |   |            |
/// |   |main+---->bar+----->baz+--------->TermLogger::new+-----------+      |
/// |   +-+--+    +---+     +-+-+   |   | +---------------+ |   |     |      |
/// |               |         |     |   |                   |   |     |      |
/// +-------------------------------+   +-------------------+   |  +--v---+  |
///                 |         |                                 |  |panic!|  |
///                 |    +---------+    +-------------------+   |  +--^---+  |
///                 |    |dep |    |    |simplelog@0.4.4    |   |     |      |
///                 |    |  +-v-+  |    | +---------------+ |   |     |      |
///                 +------->baz+--------->TermLogger::new+-----------+      |
///                      |  +---+  |    | +---------------+ |   |            |
///                      |         |    |                   |   |            |
///                      +---------+    +-------------------+   +------------+
/// Here both the multi_dep and dep crates are in the test_subjects workspace, and hence have test_subjects as crate name
/// Usually, these are seen as the analysis target, while simplelog and std are external code
#[cfg(test)]
mod test {
    extern crate panic_analysis;
    extern crate test_common;

    use self::panic_analysis::AnalysisOptions;
    use self::test_common::*;

    use self::panic_analysis::FunctionWhiteListEntry;
    use self::panic_analysis::FunctionWhitelistCrateVersion;

    /// This is not really a whitelisting test, but it asserts that if nothing is whitelisted, 2 paths are found
    /// (This is an assumption in th other tests, where it is not verified)
    #[test]
    fn test_multiple_versions_all_paths() {
        let binary_path = test_common::get_test_subject_path("multi_dep", &TestSubjectType::Debug);

        let options = AnalysisOptions {
            binary_path: Some(binary_path.to_str().unwrap().to_string()),
            crate_names: vec!["test_subjects".to_string()],
            whitelisted_functions: vec![],
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            full_crate_analysis: false,
        };

        let panic_calls = panic_analysis::find_panics(&options).unwrap();

        assert_eq!(panic_calls.calls.len(), 2);

        let traces = panic_calls
            .calls
            .iter()
            .map(|trace| {
                trace
                    .backtrace
                    .iter()
                    .take(2)
                    .map(|x| x.procedure.borrow().linkage_name_demangled.clone())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // Assert that both traces are found
        assert!(traces.iter().any(|trace| trace
            == &vec![
                "multi_dep::baz",
                "simplelog::loggers::termlog::TermLogger::new",
            ]));
        assert!(traces.iter().any(
            |trace| trace == &vec!["dep::baz", "simplelog::loggers::termlog::TermLogger::new"]
        ));
    }

    /// We now ignore the simplelog-0.4.4::TermLogger::new (dependency of dep)
    /// We assert that the path through simplelog-0.5.2::TermLogger::new (through multi_dep) is still found.
    #[test]
    fn test_multiple_versions_v1_ignored() {
        let binary_path = test_common::get_test_subject_path("multi_dep", &TestSubjectType::Debug);

        let options = AnalysisOptions {
            binary_path: Some(binary_path.to_str().unwrap().to_string()),
            crate_names: vec!["test_subjects".to_string()],
            whitelisted_functions: vec![FunctionWhiteListEntry {
                function_name: "TermLogger::new".to_string(),
                crate_name: Some("simplelog".to_string()),
                crate_version: FunctionWhitelistCrateVersion::Strict("0.4.4".to_string()),
            }],
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            full_crate_analysis: false,
        };

        let panic_calls = panic_analysis::find_panics(&options).unwrap();

        assert_eq!(panic_calls.calls.len(), 1);

        let trace_names = panic_calls.calls[0]
            .backtrace
            .iter()
            .take(2)
            .map(|x| x.procedure.borrow().linkage_name_demangled.clone())
            .collect::<Vec<_>>();

        assert_eq!(
            trace_names,
            vec![
                "multi_dep::baz",
                "simplelog::loggers::termlog::TermLogger::new",
            ]
        )
    }

    /// We now ignore TermLogger::new not regarding the version. We assert that both paths are filtered away now.
    #[test]
    fn test_multiple_versions_all_ignored() {
        let binary_path = test_common::get_test_subject_path("multi_dep", &TestSubjectType::Debug);

        let options = AnalysisOptions {
            binary_path: Some(binary_path.to_str().unwrap().to_string()),
            crate_names: vec!["test_subjects".to_string()],
            whitelisted_functions: vec![FunctionWhiteListEntry {
                function_name: "TermLogger::new".to_string(),
                crate_name: Some("simplelog".to_string()),
                crate_version: FunctionWhitelistCrateVersion::None,
            }],
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            full_crate_analysis: false,
        };

        let panic_calls = panic_analysis::find_panics(&options).unwrap();

        assert_eq!(panic_calls.calls.len(), 0);
    }

    /// We now ignore the multi_dep::bar function. This is in user code.
    /// Since all paths originate from this function, we expect all of them to be ignored
    #[test]
    fn test_whitelist_indirect_called_ignored() {
        let binary_path = test_common::get_test_subject_path("multi_dep", &TestSubjectType::Debug);

        let options = AnalysisOptions {
            binary_path: Some(binary_path.to_str().unwrap().to_string()),
            crate_names: vec!["test_subjects".to_string()],
            whitelisted_functions: vec![FunctionWhiteListEntry {
                function_name: "multi_dep::bar".to_string(),
                crate_name: Some("test_subjects".to_string()),
                crate_version: FunctionWhitelistCrateVersion::None,
            }],
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            full_crate_analysis: false,
        };

        let panic_calls = panic_analysis::find_panics(&options).unwrap();

        assert_eq!(panic_calls.calls.len(), 0);
    }

    /// We now ignore the multi_dep::baz function. This is in user code.
    /// This function does a direct call to Termlogger::new, and an indirect call (via dep::baz)
    /// We expect both of them to be filtered, but the multi_dep::bar -> dep::baz -> TermLogger::new to be still present
    #[test]
    fn test_whitelist_indirect_called_ignored_other_present() {
        let binary_path = test_common::get_test_subject_path("multi_dep", &TestSubjectType::Debug);

        let options = AnalysisOptions {
            binary_path: Some(binary_path.to_str().unwrap().to_string()),
            crate_names: vec!["test_subjects".to_string()],
            whitelisted_functions: vec![FunctionWhiteListEntry {
                function_name: "multi_dep::baz".to_string(),
                crate_name: Some("test_subjects".to_string()),
                crate_version: FunctionWhitelistCrateVersion::None,
            }],
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            full_crate_analysis: false,
        };

        let panic_calls = panic_analysis::find_panics(&options).unwrap();

        assert_eq!(panic_calls.calls.len(), 1);
    }

    /// We now ignore the multi_dep::bar function. However, we set the full_crate_analysis flag to true
    /// Therefore, we expect both traces to be still given, since they are indirect
    #[test]
    fn test_whitelist_indirect_called_not_ignored_if_full_crate_analysis() {
        let binary_path = test_common::get_test_subject_path("multi_dep", &TestSubjectType::Debug);

        let options = AnalysisOptions {
            binary_path: Some(binary_path.to_str().unwrap().to_string()),
            crate_names: vec!["test_subjects".to_string()],
            whitelisted_functions: vec![FunctionWhiteListEntry {
                function_name: "multi_dep::bar".to_string(),
                crate_name: Some("test_subjects".to_string()),
                crate_version: FunctionWhitelistCrateVersion::None,
            }],
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            full_crate_analysis: true,
        };

        let panic_calls = panic_analysis::find_panics(&options).unwrap();

        assert_eq!(panic_calls.calls.len(), 2);

        let traces = panic_calls
            .calls
            .iter()
            .map(|trace| {
                trace
                    .backtrace
                    .iter()
                    .take(2)
                    .map(|x| x.procedure.borrow().linkage_name_demangled.clone())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // Assert that both traces are found
        assert!(traces.iter().any(|trace| trace
            == &vec![
                "multi_dep::baz",
                "simplelog::loggers::termlog::TermLogger::new",
            ]));
        assert!(traces.iter().any(
            |trace| trace == &vec!["dep::baz", "simplelog::loggers::termlog::TermLogger::new"]
        ));
    }

    /// In this test, we ignore multi_dep::baz again
    /// Since there is still a path via multi_dep::bar, we expect 1 trace to be given
    #[test]
    fn test_whitelist_indirect_called_otherwise_not_ignored() {
        let binary_path = test_common::get_test_subject_path("multi_dep", &TestSubjectType::Debug);

        let options = AnalysisOptions {
            binary_path: Some(binary_path.to_str().unwrap().to_string()),
            crate_names: vec!["test_subjects".to_string()],
            whitelisted_functions: vec![FunctionWhiteListEntry {
                function_name: "multi_dep::baz".to_string(),
                crate_name: Some("test_subjects".to_string()),
                crate_version: FunctionWhitelistCrateVersion::None,
            }],
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            full_crate_analysis: false,
        };

        let panic_calls = panic_analysis::find_panics(&options).unwrap();

        assert_eq!(panic_calls.calls.len(), 1);

        let trace_names = panic_calls.calls[0]
            .backtrace
            .iter()
            .take(2)
            .map(|x| x.procedure.borrow().linkage_name_demangled.clone())
            .collect::<Vec<_>>();

        assert_eq!(
            trace_names,
            vec!["dep::baz", "simplelog::loggers::termlog::TermLogger::new"]
        )
    }

    /// In this test, we ignore multi_dep::baz and simplelog-0.5.2::TermLogger::new
    /// Since these are entries on the same path, we still expect 1 trace (via 0.4.4) to be given
    #[test]
    fn test_two_whitelists() {
        let binary_path = test_common::get_test_subject_path("multi_dep", &TestSubjectType::Debug);

        let options = AnalysisOptions {
            binary_path: Some(binary_path.to_str().unwrap().to_string()),
            crate_names: vec!["test_subjects".to_string()],
            whitelisted_functions: vec![
                FunctionWhiteListEntry {
                    function_name: "multi_dep::baz".to_string(),
                    crate_name: Some("test_subjects".to_string()),
                    crate_version: FunctionWhitelistCrateVersion::None,
                },
                FunctionWhiteListEntry {
                    function_name: "TermLogger::new".to_string(),
                    crate_name: Some("simplelog".to_string()),
                    crate_version: FunctionWhitelistCrateVersion::Strict("0.5.2".to_string()),
                },
            ],
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            full_crate_analysis: false,
        };

        let panic_calls = panic_analysis::find_panics(&options).unwrap();

        assert_eq!(panic_calls.calls.len(), 1);

        let trace_names = panic_calls.calls[0]
            .backtrace
            .iter()
            .take(2)
            .map(|x| x.procedure.borrow().linkage_name_demangled.clone())
            .collect::<Vec<_>>();

        assert_eq!(
            trace_names,
            vec!["dep::baz", "simplelog::loggers::termlog::TermLogger::new"]
        )
    }

    /// In this test, we ignore multi_dep::baz and simplelog-0.4.4::TermLogger::new
    /// Since these are entries on different paths, we still no traces to be given
    #[test]
    fn test_two_whitelists_all_paths_ignored() {
        let binary_path = test_common::get_test_subject_path("multi_dep", &TestSubjectType::Debug);

        let options = AnalysisOptions {
            binary_path: Some(binary_path.to_str().unwrap().to_string()),
            crate_names: vec!["test_subjects".to_string()],
            whitelisted_functions: vec![
                FunctionWhiteListEntry {
                    function_name: "multi_dep::baz".to_string(),
                    crate_name: Some("test_subjects".to_string()),
                    crate_version: FunctionWhitelistCrateVersion::None,
                },
                FunctionWhiteListEntry {
                    function_name: "TermLogger::new".to_string(),
                    crate_name: Some("simplelog".to_string()),
                    crate_version: FunctionWhitelistCrateVersion::Strict("0.4.4".to_string()),
                },
            ],
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            full_crate_analysis: false,
        };

        let panic_calls = panic_analysis::find_panics(&options).unwrap();

        assert_eq!(panic_calls.calls.len(), 0);
    }
}

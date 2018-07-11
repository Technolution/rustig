// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use callgraph::Context;
use patterns::PatternFinder;

use AnalysisOptions;

use std::collections::HashMap;

use PanicCallsCollection;
use PanicPattern;
use PanicPattern::Indexing;
use PanicPattern::Unwrap;

/// Implementation of the `PatternFinder` to find unwrap calls causing a panic.
struct FunctionPatternFinder<'a> {
    // A hashmap that maps the name of function to the pattern the trace should be recognized as.
    function_pattern_mapping: HashMap<&'a str, PanicPattern>,
}

impl<'a> PatternFinder for FunctionPatternFinder<'a> {
    fn find_patterns(&self, _ctx: &Context, panic_calls: &PanicCallsCollection) {
        panic_calls.calls.iter().for_each(|call| {
            call.backtrace
                .iter()
                .flat_map(|bt_entry| {
                    // Fetch names of inline frames
                    let mut names = bt_entry
                        .outgoing_invocation
                        .as_ref()
                        .map(|inv| {
                            inv.borrow()
                                .frames
                                .iter()
                                .map(|frame| frame.function_name.to_owned())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_else(|| vec![]);
                    // Add procedure name
                    names.push(
                        bt_entry
                            .procedure
                            .borrow()
                            .linkage_name_demangled
                            .to_owned(),
                    );
                    names
                })
                .filter_map(|name| {
                    self.function_pattern_mapping
                        .iter()
                        .find(|(function, _)| name.ends_with(*function))
                        .map(|(_, pattern)| *pattern)
                })
                .next()
                .map(|pattern| call.pattern.replace(pattern));
        });
    }
}

pub fn get_function_names_pattern_finder(_options: &AnalysisOptions) -> Box<PatternFinder> {
    let mut function_map = HashMap::new();
    function_map.insert("::unwrap", Unwrap);
    function_map.insert("::expect", Unwrap);
    function_map.insert("::index", Indexing);
    Box::new(FunctionPatternFinder {
        function_pattern_mapping: function_map,
    })
}

#[cfg(test)]
mod tests {
    extern crate capstone;
    extern crate test_common;

    use self::capstone::arch::BuildsCapstone;

    use self::test_common::*;
    use super::*;

    use BackTraceEntry;
    use IntermediateBacktrace::NoTrace;

    use PanicCall;
    use PanicPattern;
    use RDPInvocationMetaData;
    use RDPProcedureMetaData;

    use callgraph::Crate;
    use callgraph::Invocation;
    use callgraph::InvocationType;
    use callgraph::Procedure;

    use callgraph::InlineFunctionFrame;
    use callgraph::Location;
    use std::cell::Cell;
    use std::cell::RefCell;
    use std::rc::Rc;

    use test_utils::*;

    /// Helper method for creating a vector of procedures
    fn create_proc_vec(proc_info_slice: &[(&str, &str, &[(&str)])]) -> Vec<BackTraceEntry> {
        let mut proc_list = vec![];

        for (procedure_name, crate_name, inline_frames) in proc_info_slice {
            proc_list.push(BackTraceEntry {
                procedure: Rc::new(RefCell::new(Procedure {
                    name: procedure_name.to_string(),
                    linkage_name: format!("{}::{}", crate_name, procedure_name),
                    linkage_name_demangled: format!("{}::{}", crate_name, procedure_name),
                    defining_crate: Crate {
                        name: crate_name.to_string(),
                        version: Some("0.0.1".to_string()),
                    },
                    start_address: 0x6450,
                    size: 0x200,
                    location: None,
                    attributes: RDPProcedureMetaData {
                        analysis_target: Cell::new(false),
                        entry_point: Cell::new(false),
                        is_panic: Cell::new(true),
                        is_panic_origin: Cell::new(false),
                        intermediate_panic_calls: RefCell::new(NoTrace),
                        visited: Cell::new(true),
                        reachable_from_entry_point: Cell::new(true),
                        whitelisted: Cell::new(false),
                    },
                    disassembly: capstone::Capstone::new()
                        .x86()
                        .mode(capstone::arch::x86::ArchMode::Mode64)
                        .build()
                        .unwrap()
                        .disasm_all(&vec![], 0)
                        .unwrap(),
                })),
                outgoing_invocation: Some(Rc::new(RefCell::new(Invocation {
                    instruction_address: 0x144562,
                    invocation_type: InvocationType::Direct,
                    frames: inline_frames
                        .iter()
                        .map(|name| InlineFunctionFrame {
                            location: Location {
                                line: 32,
                                file: "lib.rs".to_owned(),
                            },
                            function_name: name.to_string(),
                            defining_crate: Crate {
                                name: "crate".to_string(),
                                version: Some("1.2.3".to_string()),
                            },
                            attributes: Default::default(),
                        })
                        .collect(),
                    attributes: RDPInvocationMetaData {
                        ..Default::default()
                    },
                }))),
            });
        }
        proc_list
    }

    /// Tests if `FunctionPatternFinder` marks a trace with an `unwrap` function correctly.
    #[test]
    fn test_find_unwrap() {
        let file_content =
            load_test_binary_as_bytes("hello_world", &TestSubjectType::Debug).unwrap();
        let context = parse_context(&file_content);

        let proc_trace = create_proc_vec(&vec![
            ("main", "test", &vec![][..]),
            ("Result::unwrap", "std::result", &vec![][..]),
            ("begin_panic", "std::panicking", &vec![][..]),
        ]);

        let collection = PanicCallsCollection {
            calls: vec![PanicCall {
                backtrace: proc_trace,
                pattern: RefCell::new(PanicPattern::Unrecognized),
                contains_dynamic_invocation: false,
                message: None,
            }],
        };

        let mut function_map = HashMap::new();
        function_map.insert("::unwrap", Unwrap);
        function_map.insert("::expect", Unwrap);

        let finder = FunctionPatternFinder {
            function_pattern_mapping: function_map,
        };
        finder.find_patterns(&context, &collection);

        assert_eq!(*collection.calls[0].pattern.borrow(), PanicPattern::Unwrap);
    }

    /// Test if `FunctionPatternFinder` recognizes an unwrap if the unwrap function is inlined.
    #[test]
    fn test_find_unwrap_inline() {
        let file_content =
            load_test_binary_as_bytes("hello_world", &TestSubjectType::Debug).unwrap();
        let context = parse_context(&file_content);

        let proc_trace = create_proc_vec(&vec![
            ("main", "test", &vec![][..]),
            (
                "main::foo",
                "test",
                &vec!["main::bar", "Result::unwrap"][..],
            ),
            ("begin_panic", "std::panicking", &vec![][..]),
        ]);

        let collection = PanicCallsCollection {
            calls: vec![PanicCall {
                backtrace: proc_trace,
                pattern: RefCell::new(PanicPattern::Unrecognized),
                contains_dynamic_invocation: false,
                message: None,
            }],
        };

        let mut function_map = HashMap::new();
        function_map.insert("::unwrap", Unwrap);
        function_map.insert("::expect", Unwrap);

        let finder = FunctionPatternFinder {
            function_pattern_mapping: function_map,
        };
        finder.find_patterns(&context, &collection);

        assert_eq!(*collection.calls[0].pattern.borrow(), PanicPattern::Unwrap);
    }

    /// Tests if `FunctionPatternFinder` marks a trace with an `expect` function correctly.
    #[test]
    fn test_find_expect() {
        let file_content =
            load_test_binary_as_bytes("hello_world", &TestSubjectType::Debug).unwrap();
        let context = parse_context(&file_content);

        let proc_trace = create_proc_vec(&vec![
            ("main", "test", &vec![][..]),
            ("Result::expect", "std::result", &vec![][..]),
            ("begin_panic", "std::panicking", &vec![][..]),
        ]);

        let collection = PanicCallsCollection {
            calls: vec![PanicCall {
                backtrace: proc_trace,
                pattern: RefCell::new(PanicPattern::Unrecognized),
                contains_dynamic_invocation: false,
                message: None,
            }],
        };

        let mut function_map = HashMap::new();
        function_map.insert("::unwrap", Unwrap);
        function_map.insert("::expect", Unwrap);

        let finder = FunctionPatternFinder {
            function_pattern_mapping: function_map,
        };
        finder.find_patterns(&context, &collection);

        assert_eq!(*collection.calls[0].pattern.borrow(), PanicPattern::Unwrap);
    }

    /// Tests if `FunctionPatternFinder` does not mark a trace that does not contain a function
    /// that has `unwrap` or `expect` as full name.
    #[test]
    fn test_not_find_other() {
        let file_content =
            load_test_binary_as_bytes("hello_world", &TestSubjectType::Debug).unwrap();
        let context = parse_context(&file_content);

        let proc_trace = create_proc_vec(&vec![
            ("main", "test", &vec![][..]),
            ("Result::expectunwrap", "std::result", &vec![][..]),
            ("begin_panic", "std::panicking", &vec![][..]),
        ]);

        let collection = PanicCallsCollection {
            calls: vec![PanicCall {
                backtrace: proc_trace,
                pattern: RefCell::new(PanicPattern::Unrecognized),
                contains_dynamic_invocation: false,
                message: None,
            }],
        };

        let mut function_map = HashMap::new();
        function_map.insert("::unwrap", Unwrap);
        function_map.insert("::expect", Unwrap);

        let finder = FunctionPatternFinder {
            function_pattern_mapping: function_map,
        };
        finder.find_patterns(&context, &collection);

        assert_eq!(
            *collection.calls[0].pattern.borrow(),
            PanicPattern::Unrecognized
        );
    }

    /// Tests if `FunctionPatternFinder` marks a trace with an `unwrap` function correctly, if the trace is somewhat longer
    #[test]
    fn test_not_find_unwrap_deep() {
        let file_content =
            load_test_binary_as_bytes("hello_world", &TestSubjectType::Debug).unwrap();
        let context = parse_context(&file_content);

        let proc_trace = create_proc_vec(&vec![
            ("main", "test", &vec![][..]),
            ("foo", "cfoo", &vec![][..]),
            ("bar", "cbar", &vec![][..]),
            ("Result::unwrap", "std::result", &vec![][..]),
            ("begin_panic", "std::panicking", &vec![][..]),
        ]);

        let collection = PanicCallsCollection {
            calls: vec![PanicCall {
                backtrace: proc_trace,
                pattern: RefCell::new(PanicPattern::Unrecognized),
                contains_dynamic_invocation: false,
                message: None,
            }],
        };

        let mut function_map = HashMap::new();
        function_map.insert("::unwrap", Unwrap);
        function_map.insert("::expect", Unwrap);

        let finder = FunctionPatternFinder {
            function_pattern_mapping: function_map,
        };
        finder.find_patterns(&context, &collection);

        assert_eq!(*collection.calls[0].pattern.borrow(), PanicPattern::Unwrap);
    }
}

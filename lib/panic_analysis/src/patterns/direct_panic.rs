// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use callgraph::Context;
use patterns::PatternFinder;
use AnalysisOptions;
use PanicCallsCollection;
use PanicPattern::DirectCall;

/// Implementation of the `PatternFinder` to direct calls to panic in a `PanicCallsCollection`.
struct DirectPanicPatternFinder;

impl PatternFinder for DirectPanicPatternFinder {
    fn find_patterns(&self, _ctx: &Context, panic_calls: &PanicCallsCollection) {
        panic_calls.calls.iter().for_each(|calls| {
            // We know we can safely access the next node since the backtrace has at least 2 entries.
            let destination_node = &calls.backtrace[1];
            let panic_origin = destination_node
                .procedure
                .borrow()
                .attributes
                .is_panic_origin
                .get();

            let invocation = calls.backtrace[0]
                    .outgoing_invocation
                    .as_ref()
                    .unwrap() // Only the last entry in the backtrace has None, so unwrap is safe
                    .borrow();

            let no_external_inline = invocation
                .frames
                .iter()
                .next()
                .expect("A invocation backtrace should contain at least one frame")
                .attributes
                .analysis_target
                .get();

            // If there is only 1 frame, no functions are inlined here (The 1 frame is the outer function)
            // Therefore this call is direct
            if panic_origin && no_external_inline {
                calls.pattern.replace(DirectCall);
            }
        });
    }
}

pub fn get_direct_panic_pattern_finder(_options: &AnalysisOptions) -> Box<PatternFinder> {
    Box::new(DirectPanicPatternFinder)
}

#[cfg(test)]
mod test {
    extern crate capstone;
    extern crate test_common;

    use super::*;

    use std::cell::Cell;
    use std::cell::RefCell;
    use std::rc::Rc;

    use RDPInvocationMetaData;
    use RDPProcedureMetaData;

    use BackTraceEntry;
    use IntermediateBacktrace::NoTrace;

    use self::capstone::arch::BuildsCapstone;

    use callgraph::Crate;
    use callgraph::InlineFunctionFrame;
    use callgraph::Invocation;
    use callgraph::InvocationType::Direct;
    use callgraph::Location;
    use callgraph::Procedure;

    use PanicCall;
    use PanicCallsCollection;
    use PanicPattern::Unrecognized;
    use RDPInlineFrameMetaData;

    use test_utils;

    /// Helper method for creating procedures
    fn create_procedure(
        procedure_name: String,
        panic_origin: bool,
    ) -> Procedure<RDPProcedureMetaData> {
        let current_address = 0x1000;
        let proc_size = 0x200;

        Procedure {
            name: procedure_name.to_string(),
            linkage_name: procedure_name.to_string(),
            linkage_name_demangled: procedure_name.to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: Some("0.0.1".to_string()),
            },
            start_address: current_address,
            size: proc_size,
            location: None,
            attributes: RDPProcedureMetaData {
                analysis_target: Cell::new(false),
                entry_point: Cell::new(false),
                is_panic: Cell::new(true),
                is_panic_origin: Cell::new(panic_origin),
                intermediate_panic_calls: RefCell::new(NoTrace),
                visited: Cell::new(false),
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
        }
    }

    /// test to ensure that the direct panic is correctly found.
    #[test]
    fn test_correct_pattern_found() {
        let procedure_origin = create_procedure("Foo".to_string(), false);
        let procedure_destination = create_procedure("Bar".to_string(), true);

        let invocation_foo_bar = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x144562,
            invocation_type: Direct,
            frames: vec![InlineFunctionFrame {
                function_name: "crate::Foo".to_string(),
                location: Location {
                    line: 1234,
                    file: "lib.rs".to_string(),
                },
                defining_crate: Crate {
                    name: "crate".to_string(),
                    version: Some("1.2.3".to_string()),
                },
                attributes: RDPInlineFrameMetaData {
                    analysis_target: Cell::new(true),
                },
            }],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        let entry_foo = BackTraceEntry {
            procedure: Rc::new(RefCell::new(procedure_origin)),
            outgoing_invocation: Some(invocation_foo_bar),
        };

        let entry_bar = BackTraceEntry {
            procedure: Rc::new(RefCell::new(procedure_destination)),
            outgoing_invocation: None,
        };

        let result = RefCell::new(Unrecognized);

        let panic_call = PanicCall {
            backtrace: vec![entry_foo, entry_bar],
            pattern: result.clone(),
            contains_dynamic_invocation: false,
            message: None,
        };

        let collection = PanicCallsCollection {
            calls: vec![panic_call],
        };

        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(file_content);

        DirectPanicPatternFinder.find_patterns(&context, &collection);

        let result = *collection.calls[0].pattern.borrow();
        assert_eq!(result, DirectCall)
    }

    /// Test to ensure that no pattern is found when the panic origin is not immediately after the origin.
    #[test]
    fn test_no_pattern_found() {
        let procedure_origin = create_procedure("Foo".to_string(), false);
        let procedure_destination = create_procedure("Bar".to_string(), false);
        let procedure_panic_origin = create_procedure("Buz".to_string(), false);

        let invocation = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x144562,
            invocation_type: Direct,
            frames: vec![InlineFunctionFrame {
                function_name: "crate::Foo".to_string(),
                location: Location {
                    line: 1234,
                    file: "lib.rs".to_string(),
                },
                defining_crate: Crate {
                    name: "crate".to_string(),
                    version: Some("1.2.3".to_string()),
                },
                attributes: Default::default(),
            }],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        let entry_foo = BackTraceEntry {
            procedure: Rc::new(RefCell::new(procedure_origin)),
            outgoing_invocation: Some(invocation.clone()),
        };

        let entry_bar = BackTraceEntry {
            procedure: Rc::new(RefCell::new(procedure_destination)),
            outgoing_invocation: Some(invocation.clone()),
        };

        let entry_buz = BackTraceEntry {
            procedure: Rc::new(RefCell::new(procedure_panic_origin)),
            outgoing_invocation: None,
        };

        let result = RefCell::new(Unrecognized);

        let panic_call = PanicCall {
            backtrace: vec![entry_foo, entry_bar, entry_buz],
            pattern: result.clone(),
            contains_dynamic_invocation: false,
            message: None,
        };

        let collection = PanicCallsCollection {
            calls: vec![panic_call],
        };

        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(file_content);

        DirectPanicPatternFinder.find_patterns(&context, &collection);

        let result = *collection.calls[0].pattern.borrow();
        assert_eq!(result, Unrecognized)
    }

    /// Test to ensure that a direct panic is not reported when an inline function is found.
    #[test]
    fn test_no_pattern_found_inline() {
        let procedure_origin = create_procedure("Foo".to_string(), false);
        let procedure_destination = create_procedure("Bar".to_string(), true);

        let invocation_foo_bar = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x144562,
            invocation_type: Direct,
            frames: vec![
                InlineFunctionFrame {
                    function_name: "crate::Foo".to_string(),
                    location: Location {
                        line: 1234,
                        file: "lib.rs".to_string(),
                    },
                    defining_crate: Crate {
                        name: "crate".to_string(),
                        version: Some("1.2.3".to_string()),
                    },
                    attributes: RDPInlineFrameMetaData {
                        analysis_target: Cell::new(false),
                    },
                },
                InlineFunctionFrame {
                    function_name: "std::inline_function".to_string(),
                    location: Location {
                        line: 1234,
                        file: "mod.rs".to_string(),
                    },
                    defining_crate: Crate {
                        name: "crate".to_string(),
                        version: Some("1.2.3".to_string()),
                    },
                    attributes: RDPInlineFrameMetaData {
                        analysis_target: Cell::new(true),
                    },
                },
            ],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        let entry_foo = BackTraceEntry {
            procedure: Rc::new(RefCell::new(procedure_origin)),
            outgoing_invocation: Some(invocation_foo_bar),
        };

        let entry_bar = BackTraceEntry {
            procedure: Rc::new(RefCell::new(procedure_destination)),
            outgoing_invocation: None,
        };

        let result = RefCell::new(Unrecognized);

        let panic_call = PanicCall {
            backtrace: vec![entry_foo, entry_bar],
            pattern: result.clone(),
            contains_dynamic_invocation: false,
            message: None,
        };

        let collection = PanicCallsCollection {
            calls: vec![panic_call],
        };

        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(file_content);

        DirectPanicPatternFinder.find_patterns(&context, &collection);

        let result = *collection.calls[0].pattern.borrow();
        assert_eq!(result, Unrecognized)
    }

    /// Test to ensure that a direct panic is reported when all inline functions are analysis target.
    #[test]
    fn test_pattern_found_inline() {
        let procedure_origin = create_procedure("Foo".to_string(), false);
        let procedure_destination = create_procedure("Bar".to_string(), true);

        let invocation_foo_bar = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x144562,
            invocation_type: Direct,
            frames: vec![
                InlineFunctionFrame {
                    function_name: "crate::Foo".to_string(),
                    location: Location {
                        line: 1234,
                        file: "lib.rs".to_string(),
                    },
                    defining_crate: Crate {
                        name: "crate".to_string(),
                        version: Some("1.2.3".to_string()),
                    },
                    attributes: RDPInlineFrameMetaData {
                        analysis_target: Cell::new(true),
                    },
                },
                InlineFunctionFrame {
                    function_name: "std::inline_function".to_string(),
                    location: Location {
                        line: 1234,
                        file: "mod.rs".to_string(),
                    },
                    defining_crate: Crate {
                        name: "crate".to_string(),
                        version: Some("1.2.3".to_string()),
                    },
                    attributes: RDPInlineFrameMetaData {
                        analysis_target: Cell::new(true),
                    },
                },
            ],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        let entry_foo = BackTraceEntry {
            procedure: Rc::new(RefCell::new(procedure_origin)),
            outgoing_invocation: Some(invocation_foo_bar),
        };

        let entry_bar = BackTraceEntry {
            procedure: Rc::new(RefCell::new(procedure_destination)),
            outgoing_invocation: None,
        };

        let result = RefCell::new(Unrecognized);

        let panic_call = PanicCall {
            backtrace: vec![entry_foo, entry_bar],
            pattern: result.clone(),
            contains_dynamic_invocation: false,
            message: None,
        };

        let collection = PanicCallsCollection {
            calls: vec![panic_call],
        };

        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(file_content);

        DirectPanicPatternFinder.find_patterns(&context, &collection);

        let result = *collection.calls[0].pattern.borrow();
        assert_eq!(result, DirectCall)
    }
}

// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use AnalysisOptions;
use RustigCallGraph;

use callgraph::Context;

use marker::CodeMarker;

/// Implementation of the `CodeMarker` to mark code which should be analyzed for paths to panic, as specified by the crates field
#[derive(Debug)]
struct DefaultPanicAnalysisTargetMarker {
    crates: Vec<String>,
}

impl CodeMarker for DefaultPanicAnalysisTargetMarker {
    fn mark_code(&self, call_graph: &RustigCallGraph, _context: &Context) {
        call_graph
            .graph
            .node_indices()
            .map(|index| call_graph.graph[index].borrow())
            .filter(|node| self.crates.contains(&node.defining_crate.name))
            .for_each(|node| {
                node.attributes.analysis_target.replace(true);
            });

        call_graph
            .graph
            .edge_indices()
            .map(|index| call_graph.graph[index].borrow())
            .for_each(|invocation| {
                invocation
                    .frames
                    .iter()
                    .filter(|frame| {
                        let in_analysis_crate = self.crates.contains(&frame.defining_crate.name);

                        // When a macro from an external crate, is inlined into an function in the analysis target
                        // its filename will end with '<panic macros>', or similar for other macros.
                        // Addr2line will give an incorrect location file in that case,
                        // therefore, we exclude it here.
                        // (And yeah, it is a dirty hack)
                        let last_frame_is_inline_macro = frame.location.file.ends_with(" macros>");

                        in_analysis_crate && !last_frame_is_inline_macro
                    })
                    .for_each(|frame| {
                        frame.attributes.analysis_target.replace(true);
                    });
            });
    }
    #[cfg(test)]
    fn get_type_name(&self) -> &str {
        "DefaultPanicAnalysisTargetMarker"
    }
}

/// `CodeMarker` that marks procedures in the same crate as the entry points as analysis target.
/// Depends on the entry point marker to have run first
#[derive(Debug)]
struct EntryPointAnalysisTargetMarker;

impl CodeMarker for EntryPointAnalysisTargetMarker {
    fn mark_code(&self, call_graph: &RustigCallGraph, context: &Context) {
        let indices = call_graph.graph.node_indices();

        // Loop over all entry points, and map to their respective crates
        let crates = indices
            .map(|index| call_graph.graph[index].borrow())
            .filter(|node| node.attributes.entry_point.get())
            .map(|node| node.defining_crate.name.to_owned())
            .collect::<Vec<_>>();

        // Use default implementation to mark all analysis target functions
        DefaultPanicAnalysisTargetMarker { crates }.mark_code(&call_graph, &context)
    }
    #[cfg(test)]
    fn get_type_name(&self) -> &str {
        "EntryPointAnalysisTargetMarker"
    }
}

pub fn get_panic_analysis_target_marker(options: &AnalysisOptions) -> Box<CodeMarker> {
    let a = &options.crate_names[..];
    match a {
        [] => Box::new(EntryPointAnalysisTargetMarker),
        _ => Box::new(DefaultPanicAnalysisTargetMarker {
            crates: options.crate_names.clone(),
        }),
    }
}

#[cfg(test)]
mod test {
    extern crate callgraph;
    extern crate capstone;
    extern crate gimli;
    extern crate object;
    extern crate std;
    extern crate test_common;

    use self::capstone::arch::BuildsCapstone;
    use self::capstone::Capstone;

    use super::*;

    use callgraph::Crate;
    use callgraph::InlineFunctionFrame;
    use callgraph::Invocation;
    use callgraph::InvocationType;
    use callgraph::Location;
    use callgraph::Procedure;

    use RDPInlineFrameMetaData;
    use RDPInvocationMetaData;
    use RDPProcedureMetaData;

    use std::cell::Cell;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    use AnalysisOptions;
    use IntermediateBacktrace::NoTrace;

    use test_utils;

    /// Helper function to create a procedure with a given name and crate name
    fn create_procedure_with_name(
        name: String,
        crate_name: String,
        entry_point: bool,
    ) -> Procedure<RDPProcedureMetaData> {
        let capstone = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");

        let empty_vec = Vec::new();

        Procedure {
            name: name.clone(),
            linkage_name: "linkage_name".to_string(),
            linkage_name_demangled: format!("{}_demangled", name).to_string(),
            defining_crate: Crate {
                name: crate_name,
                version: Some("3.0.0".to_string()),
            },
            start_address: 32,
            size: 64,
            location: None,
            attributes: RDPProcedureMetaData {
                analysis_target: Cell::new(false),
                entry_point: Cell::new(entry_point),
                is_panic: Cell::new(false),
                is_panic_origin: Cell::new(false),
                intermediate_panic_calls: RefCell::new(NoTrace),
                visited: Cell::new(true),
                whitelisted: Cell::new(false),
                reachable_from_entry_point: Cell::new(true),
            },
            disassembly: capstone.disasm_all(&empty_vec, 0x1000).unwrap(),
        }
    }

    /// Test to ensure attributes are marked correctly as analysis target
    #[test]
    fn test_marks_correctly() {
        let procedure_foo =
            create_procedure_with_name("Foo".to_string(), "CrateFoo".to_string(), false);
        let procedure_bar =
            create_procedure_with_name("Bar".to_string(), "CrateBar".to_string(), false);
        let procedure_baz =
            create_procedure_with_name("Baz".to_string(), "CrateBaz".to_string(), false);

        let mut og = callgraph::petgraph::stable_graph::StableGraph::new();
        let a = og.add_node(Rc::new(RefCell::new(procedure_foo)));
        let b = og.add_node(Rc::new(RefCell::new(procedure_bar)));
        let c = og.add_node(Rc::new(RefCell::new(procedure_baz)));

        let call_graph = RustigCallGraph {
            graph: og,
            proc_index: HashMap::new(),
            call_index: HashMap::new(),
        };

        let crates = vec!["CrateBar".to_string(), "CrateBaz".to_string()];

        let marker = DefaultPanicAnalysisTargetMarker { crates };

        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(file_content);

        marker.mark_code(&call_graph, &context);

        let value_a = &call_graph.graph[a].borrow().attributes.analysis_target;
        let value_b = &call_graph.graph[b].borrow().attributes.analysis_target;
        let value_c = &call_graph.graph[c].borrow().attributes.analysis_target;

        assert_eq!(value_a.get(), false);
        assert_eq!(value_b.get(), true);
        assert_eq!(value_c.get(), true);
    }

    /// Test to ensure attributes are marked correctly when no crates are given as input.
    #[test]
    fn test_marks_unknown_crates_correctly() {
        let procedure_foo =
            create_procedure_with_name("Foo".to_string(), "CrateFoo".to_string(), true);
        let procedure_bar =
            create_procedure_with_name("Bar".to_string(), "CrateBar".to_string(), false);
        let procedure_baz =
            create_procedure_with_name("Baz".to_string(), "CrateBaz".to_string(), false);

        let mut og = callgraph::petgraph::stable_graph::StableGraph::new();
        let a = og.add_node(Rc::new(RefCell::new(procedure_foo)));
        let b = og.add_node(Rc::new(RefCell::new(procedure_bar)));
        let c = og.add_node(Rc::new(RefCell::new(procedure_baz)));

        let call_graph = RustigCallGraph {
            graph: og,
            proc_index: HashMap::new(),
            call_index: HashMap::new(),
        };

        let marker = EntryPointAnalysisTargetMarker;

        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(file_content);

        marker.mark_code(&call_graph, &context);

        let value_a = &call_graph.graph[a].borrow().attributes.analysis_target;
        let value_b = &call_graph.graph[b].borrow().attributes.analysis_target;
        let value_c = &call_graph.graph[c].borrow().attributes.analysis_target;

        assert_eq!(value_a.get(), true);
        assert_eq!(value_b.get(), false);
        assert_eq!(value_c.get(), false);
    }

    /// Test to ensure invocation frames are marked correctly
    #[test]
    fn test_marks_inlines_correctly() {
        let procedure_foo =
            create_procedure_with_name("Foo".to_string(), "CrateFoo".to_string(), false);
        let procedure_bar =
            create_procedure_with_name("Bar".to_string(), "CrateBar".to_string(), false);

        let invocation_foo_bar = Invocation {
            instruction_address: 0x144562,
            invocation_type: InvocationType::Direct,
            frames: vec![
                InlineFunctionFrame {
                    function_name: "analysis_target_function".to_string(),
                    location: Location {
                        file: "mod.rs".to_string(),
                        line: 234,
                    },
                    defining_crate: Crate {
                        name: "analysis_target".to_string(),
                        version: None,
                    },
                    attributes: RDPInlineFrameMetaData {
                        analysis_target: Cell::new(false),
                    },
                },
                InlineFunctionFrame {
                    function_name: "not_analysis_target_function".to_string(),
                    location: Location {
                        file: "mod.rs".to_string(),
                        line: 234,
                    },
                    defining_crate: Crate {
                        name: "not_analysis_target".to_string(),
                        version: None,
                    },
                    attributes: RDPInlineFrameMetaData {
                        analysis_target: Cell::new(false),
                    },
                },
            ],
            attributes: RDPInvocationMetaData::default(),
        };

        let mut og = callgraph::petgraph::stable_graph::StableGraph::new();
        let a = og.add_node(Rc::new(RefCell::new(procedure_foo)));
        let b = og.add_node(Rc::new(RefCell::new(procedure_bar)));
        let inv_index = og.add_edge(a, b, Rc::new(RefCell::new(invocation_foo_bar)));

        let call_graph = RustigCallGraph {
            graph: og,
            proc_index: HashMap::new(),
            call_index: HashMap::new(),
        };

        let crates = vec!["analysis_target".to_string()];

        let marker = DefaultPanicAnalysisTargetMarker { crates };

        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(file_content);

        marker.mark_code(&call_graph, &context);

        let value_a = &call_graph.graph[a].borrow().attributes.analysis_target;
        let value_b = &call_graph.graph[b].borrow().attributes.analysis_target;
        let frames = &call_graph.graph[inv_index].borrow().frames;

        assert_eq!(value_a.get(), false);
        assert_eq!(value_b.get(), false);
        assert!(frames[0].attributes.analysis_target.get());
        assert!(!frames[1].attributes.analysis_target.get());
    }

    /// Test to ensure macro frames are ignored correctly
    #[test]
    fn test_marks_inlines_correctly_macro() {
        let procedure_foo =
            create_procedure_with_name("Foo".to_string(), "CrateFoo".to_string(), false);
        let procedure_bar =
            create_procedure_with_name("Bar".to_string(), "CrateBar".to_string(), false);

        let invocation_foo_bar = Invocation {
            instruction_address: 0x144562,
            invocation_type: InvocationType::Direct,
            frames: vec![
                InlineFunctionFrame {
                    function_name: "analysis_target_function".to_string(),
                    location: Location {
                        file: "analysis_target/src/module/<panic macros>".to_string(),
                        line: 234,
                    },
                    defining_crate: Crate {
                        name: "analysis_target".to_string(),
                        version: None,
                    },
                    attributes: RDPInlineFrameMetaData {
                        analysis_target: Cell::new(false),
                    },
                },
                InlineFunctionFrame {
                    function_name: "not_analysis_target_function".to_string(),
                    location: Location {
                        file: "mod.rs".to_string(),
                        line: 234,
                    },
                    defining_crate: Crate {
                        name: "not_analysis_target".to_string(),
                        version: None,
                    },
                    attributes: RDPInlineFrameMetaData {
                        analysis_target: Cell::new(false),
                    },
                },
            ],
            attributes: RDPInvocationMetaData::default(),
        };

        let mut og = callgraph::petgraph::stable_graph::StableGraph::new();
        let a = og.add_node(Rc::new(RefCell::new(procedure_foo)));
        let b = og.add_node(Rc::new(RefCell::new(procedure_bar)));
        let inv_index = og.add_edge(a, b, Rc::new(RefCell::new(invocation_foo_bar)));

        let call_graph = RustigCallGraph {
            graph: og,
            proc_index: HashMap::new(),
            call_index: HashMap::new(),
        };

        let crates = vec!["analysis_target".to_string()];

        let marker = DefaultPanicAnalysisTargetMarker { crates };

        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(file_content);

        marker.mark_code(&call_graph, &context);

        let value_a = &call_graph.graph[a].borrow().attributes.analysis_target;
        let value_b = &call_graph.graph[b].borrow().attributes.analysis_target;
        let frames = &call_graph.graph[inv_index].borrow().frames;

        assert_eq!(value_a.get(), false);
        assert_eq!(value_b.get(), false);
        assert!(!frames[0].attributes.analysis_target.get());
        assert!(!frames[1].attributes.analysis_target.get());
    }

    /// Test if a `DefaultPanicAnalysisTargetMarker` is returned if analysis target crates are given.
    #[test]
    fn get_panic_analysis_target_marker_default() {
        let options = AnalysisOptions {
            binary_path: Some("".to_string()),
            crate_names: vec!["std".to_string(), "core".to_string()],
            whitelisted_functions: vec![],
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            full_crate_analysis: false,
        };

        let marker = super::get_panic_analysis_target_marker(&options);

        assert_eq!(marker.get_type_name(), "DefaultPanicAnalysisTargetMarker");
    }

    ///  Test if a `EntryPointAnalysisTargetMarker` is returned if no analysis target crates are given.
    #[test]
    fn get_panic_analysis_target_marker_null() {
        let options = AnalysisOptions {
            binary_path: Some("".to_string()),
            crate_names: vec![],
            whitelisted_functions: vec![],
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            full_crate_analysis: false,
        };

        let marker = super::get_panic_analysis_target_marker(&options);

        assert_eq!(marker.get_type_name(), "EntryPointAnalysisTargetMarker");
    }
}

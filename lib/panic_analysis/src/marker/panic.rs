// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use AnalysisOptions;
use RustigCallGraph;
use RustigGraph;

use callgraph::petgraph::prelude::NodeIndex;
use callgraph::petgraph::Incoming;
use callgraph::Context;

use marker::CodeMarker;

static PANIC_HANDLERS: &[&str] = &[
    "std::panicking::begin_panic",
    "std::panicking::begin_panic_fmt",
    "core::panicking::panic",
    "core::panicking::panic_fmt",
];

/// Implementation of the `CodeMarker` to mark procedures as panicking.
#[derive(Debug)]
struct DefaultPanicMarker;

impl CodeMarker for DefaultPanicMarker {
    fn mark_code(&self, call_graph: &RustigCallGraph, _context: &Context) {
        call_graph
            .graph
            .node_indices()
            .filter(|index| {
                let name = &call_graph.graph[*index].borrow().linkage_name_demangled;
                PANIC_HANDLERS.contains(&name.as_str())
            })
            .for_each(|index| {
                call_graph.graph[index]
                    .borrow()
                    .attributes
                    .is_panic_origin
                    .set(true);
                self.traverse_graph(index, &call_graph.graph);
            });
    }
    #[cfg(test)]
    fn get_type_name(&self) -> &str {
        "DefaultPanicMarker"
    }
}

impl DefaultPanicMarker {
    fn traverse_graph(&self, index: NodeIndex<u32>, graph: &RustigGraph) {
        let procedure = graph[index].borrow();

        // If function is whitelisted, ignore it
        if procedure.attributes.whitelisted.get() {
            return;
        }

        procedure.attributes.is_panic.set(true);

        // Check whether this node has any neighbors, if not return
        let neighbors = graph.neighbors_directed(index, Incoming);

        // Iterate over all neighbors.
        for neighbor_idx in neighbors {
            let neighbor = graph[neighbor_idx].borrow();

            // Check whether neighbor has been visited yet, if not visit it before we continue (DFS)
            if !neighbor.attributes.is_panic.get() {
                self.traverse_graph(neighbor_idx, graph);
            }
        }
    }
}

pub fn get_panic_marker(_options: &AnalysisOptions) -> Box<CodeMarker> {
    Box::new(DefaultPanicMarker)
}

#[cfg(test)]
mod test {
    extern crate callgraph;
    extern crate capstone;
    extern crate gimli;
    extern crate object;
    extern crate test_common;

    use super::*;

    use self::capstone::arch::BuildsCapstone;

    use callgraph::Crate;
    use callgraph::InvocationType::Direct;
    use callgraph::Procedure;

    use std::cell::Cell;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    use callgraph::Invocation;
    use IntermediateBacktrace::NoTrace;
    use RDPInvocationMetaData;
    use RDPProcedureMetaData;

    use test_utils;

    /// Helper method for creating procedures
    fn create_procedure(
        procedure_name: String,
        entry_point: bool,
        panic: bool,
        analysis_target: bool,
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
                analysis_target: Cell::new(analysis_target),
                entry_point: Cell::new(entry_point),
                is_panic: Cell::new(panic),
                is_panic_origin: Cell::new(false),
                intermediate_panic_calls: RefCell::new(NoTrace),
                visited: Cell::new(false),
                whitelisted: Cell::new(false),
                reachable_from_entry_point: Cell::new(true),
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

    #[test]
    fn test_marks_correctly() {
        let procedure_panic = create_procedure(
            "std::panicking::begin_panic".to_string(),
            false,
            false,
            false,
        );
        let procedure_non_panic = create_procedure(
            "std::panicking::dont_begin_panic".to_string(),
            false,
            false,
            false,
        );

        let mut graph = callgraph::petgraph::stable_graph::StableGraph::new();
        let panic = graph.add_node(Rc::new(RefCell::new(procedure_panic)));
        let non_panic = graph.add_node(Rc::new(RefCell::new(procedure_non_panic)));

        let call_graph = RustigCallGraph {
            graph: graph,
            proc_index: HashMap::new(),
            call_index: HashMap::new(),
        };

        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(file_content);

        DefaultPanicMarker.mark_code(&call_graph, &context);

        let panic_attr = &call_graph.graph[panic].borrow().attributes;
        let non_panic_attr = &call_graph.graph[non_panic].borrow().attributes;

        assert!(panic_attr.is_panic.get());
        assert!(panic_attr.is_panic_origin.get());
        assert!(!non_panic_attr.is_panic.get());
        assert!(!non_panic_attr.is_panic_origin.get());
    }

    /// Test to ensure that when a part of the graph is completely disconnected from any entry points,
    /// then panics are still marked correctly.
    #[test]
    fn test_disconnected_from_entry_code_panic() {
        let procedure_foo = create_procedure("Foo".to_string(), true, false, true);
        let procedure_bar = create_procedure(
            "std::panicking::begin_panic".to_string(),
            false,
            false,
            false,
        );

        let procedure_baz = create_procedure("Baz".to_string(), false, false, true);
        let procedure_buz = create_procedure(
            "std::panicking::begin_panic_fmt".to_string(),
            false,
            false,
            false,
        );

        let mut graph = callgraph::petgraph::stable_graph::StableGraph::new();
        let foo = graph.add_node(Rc::new(RefCell::new(procedure_foo)));
        let bar = graph.add_node(Rc::new(RefCell::new(procedure_bar)));
        let baz = graph.add_node(Rc::new(RefCell::new(procedure_baz)));
        let buz = graph.add_node(Rc::new(RefCell::new(procedure_buz)));

        let invocation = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x144562,
            invocation_type: Direct,
            frames: vec![],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        graph.add_edge(foo, bar, invocation.clone());
        graph.add_edge(baz, buz, invocation.clone());

        let call_graph = RustigCallGraph {
            graph: graph,
            proc_index: HashMap::new(),
            call_index: HashMap::new(),
        };

        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(file_content);

        DefaultPanicMarker.mark_code(&call_graph, &context);

        let foo_attr = &call_graph.graph[foo].borrow().attributes;
        let bar_attr = &call_graph.graph[bar].borrow().attributes;
        let baz_attr = &call_graph.graph[baz].borrow().attributes;
        let buz_attr = &call_graph.graph[buz].borrow().attributes;

        assert_eq!(foo_attr.is_panic.get(), true);
        assert_eq!(bar_attr.is_panic.get(), true);
        assert_eq!(baz_attr.is_panic.get(), true);
        assert_eq!(buz_attr.is_panic.get(), true);
    }

    /// Test to ensure that a panic is correctly propagated to the main node.
    #[test]
    fn test_trace_basic_panic() {
        let procedure_foo = create_procedure("Foo".to_string(), true, false, true);
        let procedure_bar = create_procedure("Bar".to_string(), false, true, true);
        let procedure_baz = create_procedure("Baz".to_string(), false, false, true);

        let mut graph = callgraph::petgraph::stable_graph::StableGraph::new();
        let foo = graph.add_node(Rc::new(RefCell::new(procedure_foo)));
        let bar = graph.add_node(Rc::new(RefCell::new(procedure_bar)));
        let baz = graph.add_node(Rc::new(RefCell::new(procedure_baz)));

        let invocation = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x144562,
            invocation_type: Direct,
            frames: vec![],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        graph.add_edge(foo, bar, invocation.clone());

        graph.add_edge(foo, baz, invocation.clone());

        DefaultPanicMarker.traverse_graph(bar, &graph);

        assert_eq!(graph[foo].borrow().attributes.is_panic.get(), true);
        assert_eq!(graph[bar].borrow().attributes.is_panic.get(), true);
        assert_eq!(graph[baz].borrow().attributes.is_panic.get(), false);
    }

    /// Test to ensure that a loop in the graph does not cause an infinite loop.
    #[test]
    fn test_trace_loop_panic() {
        let procedure_foo = create_procedure("Foo".to_string(), true, false, true);
        let procedure_bar = create_procedure("Bar".to_string(), false, false, true);
        let procedure_baz = create_procedure("Baz".to_string(), false, false, true);
        let procedure_buz = create_procedure("Buz".to_string(), false, true, true);

        let mut graph = callgraph::petgraph::stable_graph::StableGraph::new();

        let foo = graph.add_node(Rc::new(RefCell::new(procedure_foo)));
        let bar = graph.add_node(Rc::new(RefCell::new(procedure_bar)));
        let baz = graph.add_node(Rc::new(RefCell::new(procedure_baz)));
        let buz = graph.add_node(Rc::new(RefCell::new(procedure_buz)));

        let invocation = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x144562,
            invocation_type: Direct,
            frames: vec![],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        graph.add_edge(foo, bar, invocation.clone());
        graph.add_edge(bar, baz, invocation.clone());
        graph.add_edge(baz, foo, invocation.clone());
        graph.add_edge(baz, buz, invocation.clone());

        DefaultPanicMarker.traverse_graph(buz, &graph);

        assert_eq!(graph[foo].borrow().attributes.is_panic.get(), true);
        assert_eq!(graph[bar].borrow().attributes.is_panic.get(), true);
        assert_eq!(graph[baz].borrow().attributes.is_panic.get(), true);
        assert_eq!(graph[buz].borrow().attributes.is_panic.get(), true);
    }

    /// Test to ensure that traces behind a whitelisted function are ignored.
    #[test]
    fn test_trace_ignore_whitelisted() {
        let procedure_foo = create_procedure("Foo".to_string(), true, false, true);
        let procedure_bar = create_procedure("Bar".to_string(), false, false, false);
        let procedure_baz = create_procedure("Baz".to_string(), false, false, false);
        let procedure_buz = create_procedure("Buz".to_string(), false, true, false);
        procedure_baz.attributes.whitelisted.set(true);

        let mut graph = callgraph::petgraph::stable_graph::StableGraph::new();

        let foo = graph.add_node(Rc::new(RefCell::new(procedure_foo)));
        let bar = graph.add_node(Rc::new(RefCell::new(procedure_bar)));
        let baz = graph.add_node(Rc::new(RefCell::new(procedure_baz)));
        let buz = graph.add_node(Rc::new(RefCell::new(procedure_buz)));

        let invocation = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x144562,
            invocation_type: Direct,
            frames: vec![],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        graph.add_edge(foo, bar, invocation.clone());
        graph.add_edge(bar, baz, invocation.clone());
        graph.add_edge(baz, foo, invocation.clone());
        graph.add_edge(baz, buz, invocation.clone());

        DefaultPanicMarker.traverse_graph(buz, &graph);

        assert_eq!(graph[foo].borrow().attributes.is_panic.get(), false);
        assert_eq!(graph[bar].borrow().attributes.is_panic.get(), false);
        assert_eq!(graph[baz].borrow().attributes.is_panic.get(), false);
        assert_eq!(graph[buz].borrow().attributes.is_panic.get(), true);
    }

    /// Test to ensure recursion does not cause an infinite loop.
    #[test]
    fn test_trace_recursive_panic() {
        let procedure_foo = create_procedure("Foo".to_string(), true, false, true);
        let procedure_bar = create_procedure("Bar".to_string(), false, true, true);

        let mut graph = callgraph::petgraph::stable_graph::StableGraph::new();
        let foo = graph.add_node(Rc::new(RefCell::new(procedure_foo)));
        let bar = graph.add_node(Rc::new(RefCell::new(procedure_bar)));

        let invocation = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x144562,
            invocation_type: Direct,
            frames: vec![],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        graph.add_edge(foo, foo, invocation.clone());
        graph.add_edge(foo, bar, invocation.clone());

        DefaultPanicMarker.traverse_graph(bar, &graph);

        assert_eq!(graph[foo].borrow().attributes.is_panic.get(), true);
        assert_eq!(graph[bar].borrow().attributes.is_panic.get(), true);
    }

    /// Test to ensure that 2 outputs are given when 2 paths lead to the same panic.
    #[test]
    fn test_trace_2paths_panic() {
        let procedure_foo = create_procedure("Foo".to_string(), true, false, true);
        let procedure_bar = create_procedure("Bar".to_string(), false, false, true);
        let procedure_baz = create_procedure("Baz".to_string(), false, false, true);
        let procedure_buz = create_procedure("Buz".to_string(), false, true, true);

        let mut graph = callgraph::petgraph::stable_graph::StableGraph::new();
        let foo = graph.add_node(Rc::new(RefCell::new(procedure_foo)));
        let bar = graph.add_node(Rc::new(RefCell::new(procedure_bar)));
        let baz = graph.add_node(Rc::new(RefCell::new(procedure_baz)));
        let buz = graph.add_node(Rc::new(RefCell::new(procedure_buz)));

        let invocation = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x144562,
            invocation_type: Direct,
            frames: vec![],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        graph.add_edge(foo, bar, invocation.clone());
        graph.add_edge(foo, baz, invocation.clone());
        graph.add_edge(bar, baz, invocation.clone());
        graph.add_edge(baz, buz, invocation.clone());

        DefaultPanicMarker.traverse_graph(buz, &graph);

        assert_eq!(graph[foo].borrow().attributes.is_panic.get(), true);
        assert_eq!(graph[bar].borrow().attributes.is_panic.get(), true);
        assert_eq!(graph[baz].borrow().attributes.is_panic.get(), true);
        assert_eq!(graph[buz].borrow().attributes.is_panic.get(), true);
    }

    /// Test to ensure that 2 paths are given when 2 paths to 2 different panics can be found.
    #[test]
    fn test_trace_double_panic() {
        let procedure_foo = create_procedure("Foo".to_string(), true, false, true);
        let procedure_bar = create_procedure("Bar".to_string(), false, false, true);
        let procedure_baz = create_procedure("Baz".to_string(), false, true, true);
        let procedure_buz = create_procedure("Buz".to_string(), false, true, true);

        let mut graph = callgraph::petgraph::stable_graph::StableGraph::new();
        let foo = graph.add_node(Rc::new(RefCell::new(procedure_foo)));
        let bar = graph.add_node(Rc::new(RefCell::new(procedure_bar)));
        let baz = graph.add_node(Rc::new(RefCell::new(procedure_baz)));
        let buz = graph.add_node(Rc::new(RefCell::new(procedure_buz)));

        let invocation = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x144562,
            invocation_type: Direct,
            frames: vec![],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        graph.add_edge(foo, bar, invocation.clone());
        graph.add_edge(bar, baz, invocation.clone());
        graph.add_edge(foo, buz, invocation.clone());

        DefaultPanicMarker.traverse_graph(baz, &graph);
        DefaultPanicMarker.traverse_graph(buz, &graph);

        assert_eq!(graph[foo].borrow().attributes.is_panic.get(), true);
        assert_eq!(graph[bar].borrow().attributes.is_panic.get(), true);
        assert_eq!(graph[baz].borrow().attributes.is_panic.get(), true);
        assert_eq!(graph[buz].borrow().attributes.is_panic.get(), true);
    }
}

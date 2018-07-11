// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

mod panic_message;

use PanicCallsCollection;

use AnalysisOptions;

use callgraph::petgraph::prelude::Direction::Incoming;
use callgraph::petgraph::stable_graph::EdgeIndex;
use callgraph::petgraph::stable_graph::NodeIndex;

use callgraph::Context;
use callgraph::InvocationType;

use std::cell::RefCell;
use std::collections::VecDeque;

use BackTraceEntry;
use IntermediateBacktrace::UpwardTrace;
use PanicCall;
use PanicPattern::Unrecognized;
use RustigCallGraph;
use RustigGraph;

use panic_calls::panic_message::PanicMessageFinder;

/// Trait marking objects are able to find calls to panic in a call graph
pub trait PanicCallsFinder {
    fn find_panics(&self, call_graph: &RustigCallGraph, contex: &Context) -> PanicCallsCollection;
}

/// Implementation of the `PanicCallsFinder` to find a trace from an analysis target to a panic.
struct DefaultPanicCallsFinder {
    message_finders: Vec<Box<PanicMessageFinder>>,
}

impl PanicCallsFinder for DefaultPanicCallsFinder {
    fn find_panics(&self, call_graph: &RustigCallGraph, context: &Context) -> PanicCallsCollection {
        self.traverse_graph(&call_graph.graph);

        let panic_calls = call_graph
            .graph
            .edge_indices()
            // Find all edges crossing the line between analysis targets and library code
            .filter(|edge_index| {
                DefaultPanicCallsFinder::leaves_analysis_target(&call_graph, *edge_index)
            })
            // For each of these edges, add the full backtrace to panic_calls
            .map(|edge_index| {
                // Can be safely unwrapped since the previous filter ensures the edge exists.
                let endpoints = &call_graph.graph.edge_endpoints(edge_index);
                let (index_source, index_target) = endpoints.unwrap();

                // Get the backtrace of the first node in the library code to the nearest panic.
                let procedure_target = &call_graph.graph[index_target].borrow();
                let mut backtrace_target = procedure_target
                    .attributes
                    .intermediate_panic_calls
                    .borrow()
                    .clone()
                    .into_backtrace_vec();
                backtrace_target.push(index_source);

                // Reverse backtrace, since backtrace is currently bottom up and this should be top down.
                backtrace_target.reverse();

                // Problem:
                // If 2 nodes have multiple edges between them, The petgraph::stable_graph::find_edge() function only provides you with one of these edges.
                // However, for every edge crossing the analysis target to library code line should have a distinct backtrace.
                //
                // Solution:
                // This edge is provided by the edges iterator, which iterates over ALL edges.
                // This means that even if there are 2 different edges between 2 of the same nodes, they should both provide a different stacktrace.
                // Therefore we are adding this edge to the backtrace before entering the while loop which uses petgraph::stable_graph::find_edge().
                let (backtrace, contains_dynamic_invocation) =
                    self.build_full_backtrace(&call_graph, edge_index, &backtrace_target);

                let message: Option<String> = self.message_finders
                    .iter()
                    .filter_map(|finder| finder.find_panic_message(&backtrace, &call_graph, &context))
                    .next();

                PanicCall {
                    backtrace,
                    message,
                    pattern: RefCell::new(Unrecognized),
                    contains_dynamic_invocation,
                }
            })
            .collect::<Vec<_>>();

        PanicCallsCollection { calls: panic_calls }
    }
}

impl DefaultPanicCallsFinder {
    fn traverse_graph(&self, graph: &RustigGraph) {
        let mut queue: VecDeque<NodeIndex<u32>> = VecDeque::new();

        // Find all edges which are the origin of a panic, these should be added to the queue
        graph
            .node_indices()
            .filter(|index| graph[*index].borrow().attributes.is_panic_origin.get())
            .for_each(|index| {
                graph[index].borrow().attributes.visited.set(true);
                graph[index]
                    .borrow()
                    .attributes
                    .intermediate_panic_calls
                    .replace(UpwardTrace(vec![index]));
                queue.push_back(index);
            });

        DefaultPanicCallsFinder::update_shortest_path_bfs(graph, queue)
    }

    fn update_shortest_path_bfs(graph: &RustigGraph, mut queue: VecDeque<NodeIndex<u32>>) -> () {
        // BFS to find the shortest paths from a panic to every node.
        while let Some(node_index) = queue.pop_front() {
            let neighbors_iter = graph.neighbors_directed(node_index, Incoming);

            neighbors_iter.for_each(|neighbor_index| {
                let attributes = &graph[neighbor_index].borrow().attributes;

                // Only visit a node if it has not yet been visited and is not an analysis target.
                if !attributes.visited.get() && !attributes.analysis_target.get() {
                    let current_node = graph[node_index].borrow();
                    let mut calls = current_node
                        .attributes
                        .intermediate_panic_calls
                        .borrow()
                        .clone()
                        .into_backtrace_vec();

                    // Add the neighbor to the shortest paths.
                    calls.push(neighbor_index);

                    // Give the new backtrace to the neighbor.
                    attributes
                        .intermediate_panic_calls
                        .replace(UpwardTrace(calls));
                    attributes.visited.set(true);

                    queue.push_back(neighbor_index);
                }
            });
        }
    }
}

impl DefaultPanicCallsFinder {
    fn leaves_analysis_target(call_graph: &RustigCallGraph, edge_index: EdgeIndex<u32>) -> bool {
        let endpoints = &call_graph.graph.edge_endpoints(edge_index);
        let (index_source, index_target) = endpoints.unwrap();
        let procedure_source_is_analysis_target = call_graph.graph[index_source]
            .borrow()
            .attributes
            .analysis_target
            .get();
        let procedure_target_is_not_analysis_target = !call_graph.graph[index_target]
            .borrow()
            .attributes
            .analysis_target
            .get();
        let procedure_target_is_visited = call_graph.graph[index_target]
            .borrow()
            .attributes
            .visited
            .get();
        procedure_source_is_analysis_target
            && procedure_target_is_not_analysis_target
            && procedure_target_is_visited
    }

    fn build_full_backtrace(
        &self,
        call_graph: &RustigCallGraph,
        edge_index: EdgeIndex<u32>,
        backtrace_target: &[NodeIndex<u32>],
    ) -> (Vec<BackTraceEntry>, bool) {
        let mut backtrace_iter = backtrace_target.iter().peekable();

        // Can safely unwrap since we are certain this node exists.
        let start_node_index = backtrace_iter.next().unwrap();

        let mut contains_dynamic_invocation = false;

        let mut full_backtrace = vec![BackTraceEntry {
            procedure: call_graph.graph[*start_node_index].clone(),
            outgoing_invocation: Some(call_graph.graph[edge_index].clone()),
        }];
        while let Some(node_index) = backtrace_iter.next() {
            let next_node_index_option = backtrace_iter.peek();
            let procedure = &call_graph.graph[*node_index];
            let outgoing_invocation = match next_node_index_option {
                // Get the invocation between two consecutive procedures.
                Some(next_node_index) => {
                    // This edge will never be None, because it always exists based on the bottomup BFS algorithm.
                    call_graph
                        .graph
                        .find_edge(*node_index, **next_node_index)
                        .map(|index| {
                            let invocation = call_graph.graph[index].clone();
                            let invocation_type = invocation.borrow().invocation_type;

                            if invocation_type == InvocationType::VTable
                                || invocation_type == InvocationType::ProcedureReference
                            {
                                contains_dynamic_invocation = true;
                            }
                            invocation
                        })
                }
                None => None,
            };

            full_backtrace.push(BackTraceEntry {
                procedure: procedure.clone(),
                outgoing_invocation,
            });
        }
        (full_backtrace, contains_dynamic_invocation)
    }
}

pub fn get_panic_call_finder(options: &AnalysisOptions) -> Box<PanicCallsFinder> {
    Box::new(DefaultPanicCallsFinder {
        message_finders: panic_message::get_panic_message_finders(options),
    })
}

#[cfg(test)]
mod test {
    extern crate callgraph;
    extern crate capstone;
    extern crate test_common;

    use super::*;

    use self::capstone::arch::BuildsCapstone;

    use RDPProcedureMetaData;

    use callgraph::Crate;
    use callgraph::InvocationType::Direct;
    use callgraph::Procedure;

    use std::cell::Cell;
    use std::cell::RefCell;

    use callgraph::Invocation;
    use std::collections::HashMap;
    use std::rc::Rc;
    use test_utils;
    use IntermediateBacktrace::NoTrace;
    use RDPInvocationMetaData;

    /// Helper method for creating procedures
    fn create_procedure(
        procedure_name: String,
        entry_point: bool,
        analysis_target: bool,
        panic_origin: bool,
        whitelisted: bool,
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
                is_panic: Cell::new(true),
                is_panic_origin: Cell::new(panic_origin),
                intermediate_panic_calls: RefCell::new(NoTrace),
                visited: Cell::new(false),
                whitelisted: Cell::new(whitelisted),
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

    /// Test to ensure that a panic collection is correctly created.
    #[test]
    fn test_full_panic_trace() {
        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(&file_content);

        let procedure_foo = create_procedure("Foo".to_string(), true, true, false, false);
        let procedure_bar = create_procedure("Bar".to_string(), false, false, false, false);
        let procedure_baz = create_procedure("Baz".to_string(), false, false, false, false);
        let procedure_buz = create_procedure("Buz".to_string(), false, false, true, false);

        let mut graph = callgraph::petgraph::stable_graph::StableGraph::new();
        let foo = graph.add_node(Rc::new(RefCell::new(procedure_foo)));
        let bar = graph.add_node(Rc::new(RefCell::new(procedure_bar)));
        let baz = graph.add_node(Rc::new(RefCell::new(procedure_baz)));
        let buz = graph.add_node(Rc::new(RefCell::new(procedure_buz)));

        let invocation_foo_bar = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x135564,
            invocation_type: Direct,
            frames: vec![],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        let invocation_bar_baz = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x135564,
            invocation_type: Direct,
            frames: vec![],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        let invocation_baz_buz = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x135564,
            invocation_type: Direct,
            frames: vec![],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        graph.add_edge(foo, bar, invocation_foo_bar.clone());
        graph.add_edge(bar, baz, invocation_bar_baz.clone());
        graph.add_edge(baz, buz, invocation_baz_buz.clone());

        let call_graph = RustigCallGraph {
            graph,
            proc_index: HashMap::new(),
            call_index: HashMap::new(),
        };

        let panics = DefaultPanicCallsFinder {
            message_finders: vec![],
        }.find_panics(&call_graph, &context);

        let trace: Vec<_> = panics.calls[0]
            .backtrace
            .iter()
            .map(|back_trace_entry| back_trace_entry.procedure.borrow().name.clone())
            .collect();

        let calls: Vec<_> = panics.calls[0]
            .clone()
            .backtrace
            .into_iter()
            .map(|back_trace_entry| back_trace_entry.outgoing_invocation)
            .collect::<Vec<_>>();

        assert_eq!(trace, vec!["Foo", "Bar", "Baz", "Buz"]);

        assert!(Rc::ptr_eq(&calls[0].clone().unwrap(), &invocation_foo_bar));
        assert!(Rc::ptr_eq(&calls[1].clone().unwrap(), &invocation_bar_baz));
        assert!(Rc::ptr_eq(&calls[2].clone().unwrap(), &invocation_baz_buz));
        assert!(calls[3].is_none());
    }

    /// Test to ensure that multiple edges between two procedures return different panic traces.
    #[test]
    fn test_two_edges_one_procedure_trace() {
        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(&file_content);

        let procedure_foo = create_procedure("Foo".to_string(), true, true, false, false);
        let procedure_bar = create_procedure("Bar".to_string(), false, false, true, false);

        let mut graph = callgraph::petgraph::stable_graph::StableGraph::new();
        let foo = graph.add_node(Rc::new(RefCell::new(procedure_foo)));
        let bar = graph.add_node(Rc::new(RefCell::new(procedure_bar)));

        let invocation_foo_bar_1 = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x135564,
            invocation_type: Direct,
            frames: vec![],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        let invocation_foo_bar_2 = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x135564,
            invocation_type: Direct,
            frames: vec![],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        graph.add_edge(foo, bar, invocation_foo_bar_1.clone());
        graph.add_edge(foo, bar, invocation_foo_bar_2.clone());

        let call_graph = RustigCallGraph {
            graph,
            proc_index: HashMap::new(),
            call_index: HashMap::new(),
        };

        let panics = DefaultPanicCallsFinder {
            message_finders: vec![],
        }.find_panics(&call_graph, &context);

        let trace: Vec<_> = panics.calls[0]
            .backtrace
            .iter()
            .map(|back_trace_entry| back_trace_entry.procedure.borrow().name.clone())
            .collect();

        let call_1 = panics.calls[0]
            .clone()
            .backtrace
            .into_iter()
            .next()
            .unwrap()
            .outgoing_invocation;

        let call_2 = panics.calls[1]
            .clone()
            .backtrace
            .into_iter()
            .next()
            .unwrap()
            .outgoing_invocation;

        assert_eq!(trace, vec!["Foo", "Bar"]);

        assert!(Rc::ptr_eq(&call_1.unwrap(), &invocation_foo_bar_1));
        assert!(Rc::ptr_eq(&call_2.unwrap(), &invocation_foo_bar_2));
    }

    /// Test to ensure that a BFS does return the correct results and does not contain procedures marked as analysis_target.
    #[test]
    fn test_trace_basic_panic() {
        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(&file_content);

        let procedure_foo = create_procedure("Foo".to_string(), true, true, false, false);
        let procedure_bar = create_procedure("Bar".to_string(), false, false, false, false);
        let procedure_baz = create_procedure("Baz".to_string(), false, false, true, false);

        let mut graph = callgraph::petgraph::stable_graph::StableGraph::new();
        let foo = graph.add_node(Rc::new(RefCell::new(procedure_foo)));
        let bar = graph.add_node(Rc::new(RefCell::new(procedure_bar)));
        let baz = graph.add_node(Rc::new(RefCell::new(procedure_baz)));

        let invocation = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x135564,
            invocation_type: Direct,
            frames: vec![],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        graph.add_edge(foo, bar, invocation.clone());
        graph.add_edge(bar, baz, invocation.clone());

        let call_graph = RustigCallGraph {
            graph,
            proc_index: HashMap::new(),
            call_index: HashMap::new(),
        };

        DefaultPanicCallsFinder {
            message_finders: vec![],
        }.find_panics(&call_graph, &context);

        assert_eq!(
            call_graph.graph[foo].borrow().attributes.is_panic.get(),
            true
        );
        assert_eq!(
            call_graph.graph[bar].borrow().attributes.is_panic.get(),
            true
        );
        assert_eq!(
            call_graph.graph[baz].borrow().attributes.is_panic.get(),
            true
        );

        let bar_attributes = &call_graph.graph[bar].borrow().attributes;
        let bar_result = bar_attributes
            .intermediate_panic_calls
            .borrow()
            .clone()
            .into_backtrace_vec();

        let foo_attributes = &call_graph.graph[foo].borrow().attributes;
        let foo_result = foo_attributes
            .intermediate_panic_calls
            .borrow()
            .clone()
            .into_backtrace_vec();

        assert_eq!(bar_result, vec![baz, bar]);
        assert_eq!(foo_result, vec![]);
    }

    /// Test to ensure that a BFS does loop infinitely on a recursive call.
    #[test]
    fn test_recursive_call() {
        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(&file_content);

        let procedure_foo = create_procedure("Foo".to_string(), true, true, false, false);
        let procedure_bar = create_procedure("Bar".to_string(), false, false, false, false);
        let procedure_baz = create_procedure("Baz".to_string(), false, false, true, false);

        let mut graph = callgraph::petgraph::stable_graph::StableGraph::new();
        let foo = graph.add_node(Rc::new(RefCell::new(procedure_foo)));
        let bar = graph.add_node(Rc::new(RefCell::new(procedure_bar)));
        let baz = graph.add_node(Rc::new(RefCell::new(procedure_baz)));

        let invocation = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x135564,
            invocation_type: Direct,
            frames: vec![],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        graph.add_edge(foo, bar, invocation.clone());
        graph.add_edge(bar, baz, invocation.clone());
        graph.add_edge(bar, bar, invocation.clone());

        let call_graph = RustigCallGraph {
            graph,
            proc_index: HashMap::new(),
            call_index: HashMap::new(),
        };

        DefaultPanicCallsFinder {
            message_finders: vec![],
        }.find_panics(&call_graph, &context);

        assert_eq!(
            call_graph.graph[foo].borrow().attributes.is_panic.get(),
            true
        );
        assert_eq!(
            call_graph.graph[bar].borrow().attributes.is_panic.get(),
            true
        );
        assert_eq!(
            call_graph.graph[baz].borrow().attributes.is_panic.get(),
            true
        );

        let b_attributes = &call_graph.graph[bar].borrow().attributes;
        let b_result = b_attributes
            .intermediate_panic_calls
            .borrow()
            .clone()
            .into_backtrace_vec();

        let a_attributes = &call_graph.graph[foo].borrow().attributes;
        let a_result = a_attributes
            .intermediate_panic_calls
            .borrow()
            .clone()
            .into_backtrace_vec();

        assert_eq!(b_result, vec![baz, bar]);
        assert_eq!(a_result, vec![]);
    }

    /// Test to ensure that the shortest path is indeed returned.
    #[test]
    fn test_shortest_path() {
        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(&file_content);

        let procedure_foo = create_procedure("Foo".to_string(), true, false, false, false);
        let procedure_bar = create_procedure("Bar".to_string(), false, false, false, false);
        let procedure_baz = create_procedure("Baz".to_string(), false, false, true, false);

        let mut graph = callgraph::petgraph::stable_graph::StableGraph::new();
        let foo = graph.add_node(Rc::new(RefCell::new(procedure_foo)));
        let bar = graph.add_node(Rc::new(RefCell::new(procedure_bar)));
        let baz = graph.add_node(Rc::new(RefCell::new(procedure_baz)));

        let invocation = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x135564,
            invocation_type: Direct,
            frames: vec![],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        graph.add_edge(foo, bar, invocation.clone());
        graph.add_edge(bar, baz, invocation.clone());
        graph.add_edge(foo, baz, invocation.clone());

        let call_graph = RustigCallGraph {
            graph,
            proc_index: HashMap::new(),
            call_index: HashMap::new(),
        };

        DefaultPanicCallsFinder {
            message_finders: vec![],
        }.find_panics(&call_graph, &context);

        let foo_attributes = &call_graph.graph[foo].borrow().attributes;
        let foo_result = foo_attributes
            .intermediate_panic_calls
            .borrow()
            .clone()
            .into_backtrace_vec();

        let bar_attributes = &call_graph.graph[bar].borrow().attributes;
        let bar_result = bar_attributes
            .intermediate_panic_calls
            .borrow()
            .clone()
            .into_backtrace_vec();

        assert_eq!(foo_result, vec![baz, foo]);
        assert_eq!(bar_result, vec![baz, bar]);
    }

    /// Test to ensure loops in the graph do still return the correct paths.
    #[test]
    fn test_loop_path() {
        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(&file_content);

        let procedure_foo = create_procedure("Foo".to_string(), true, false, false, false);
        let procedure_bar = create_procedure("Bar".to_string(), false, false, false, false);
        let procedure_baz = create_procedure("Baz".to_string(), false, false, true, false);

        let mut graph = callgraph::petgraph::stable_graph::StableGraph::new();
        let foo = graph.add_node(Rc::new(RefCell::new(procedure_foo)));
        let bar = graph.add_node(Rc::new(RefCell::new(procedure_bar)));
        let baz = graph.add_node(Rc::new(RefCell::new(procedure_baz)));

        let invocation = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x135564,
            invocation_type: Direct,
            frames: vec![],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        graph.add_edge(foo, bar, invocation.clone());
        graph.add_edge(bar, baz, invocation.clone());
        graph.add_edge(baz, foo, invocation.clone());

        let call_graph = RustigCallGraph {
            graph,
            proc_index: HashMap::new(),
            call_index: HashMap::new(),
        };

        DefaultPanicCallsFinder {
            message_finders: vec![],
        }.find_panics(&call_graph, &context);

        let foo_attributes = &call_graph.graph[foo].borrow().attributes;
        let foo_result = foo_attributes
            .intermediate_panic_calls
            .borrow()
            .clone()
            .into_backtrace_vec();

        let bar_attributes = &call_graph.graph[bar].borrow().attributes;
        let bar_result = bar_attributes
            .intermediate_panic_calls
            .borrow()
            .clone()
            .into_backtrace_vec();

        let baz_attributes = &call_graph.graph[baz].borrow().attributes;
        let baz_result = baz_attributes
            .intermediate_panic_calls
            .borrow()
            .clone()
            .into_backtrace_vec();

        assert_eq!(baz_result, vec![baz]);
        assert_eq!(bar_result, vec![baz, bar]);
        assert_eq!(foo_result, vec![baz, bar, foo])
    }

    /// Test to ensure multiple panics return the correct shortest path.
    #[test]
    fn test_multiple_panics() {
        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(&file_content);

        let procedure_foo = create_procedure("Foo".to_string(), true, false, false, false);
        let procedure_bar = create_procedure("Bar".to_string(), false, false, false, false);
        let procedure_baz = create_procedure("Baz".to_string(), false, false, false, false);
        let procedure_buz = create_procedure("Buz".to_string(), false, false, true, false);
        let procedure_quz = create_procedure("Quz".to_string(), false, false, true, false);

        let mut graph = callgraph::petgraph::stable_graph::StableGraph::new();
        let foo = graph.add_node(Rc::new(RefCell::new(procedure_foo)));
        let bar = graph.add_node(Rc::new(RefCell::new(procedure_bar)));
        let baz = graph.add_node(Rc::new(RefCell::new(procedure_baz)));
        let buz = graph.add_node(Rc::new(RefCell::new(procedure_buz)));
        let quz = graph.add_node(Rc::new(RefCell::new(procedure_quz)));

        let invocation = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x135564,
            invocation_type: Direct,
            frames: vec![],
            attributes: RDPInvocationMetaData {
                ..Default::default()
            },
        }));

        graph.add_edge(foo, quz, invocation.clone());
        graph.add_edge(bar, quz, invocation.clone());
        graph.add_edge(bar, baz, invocation.clone());
        graph.add_edge(baz, buz, invocation.clone());

        let call_graph = RustigCallGraph {
            graph,
            proc_index: HashMap::new(),
            call_index: HashMap::new(),
        };

        DefaultPanicCallsFinder {
            message_finders: vec![],
        }.find_panics(&call_graph, &context);

        let foo_attributes = &call_graph.graph[foo].borrow().attributes;
        let foo_result = foo_attributes
            .intermediate_panic_calls
            .borrow()
            .clone()
            .into_backtrace_vec();

        let bar_attributes = &call_graph.graph[bar].borrow().attributes;
        let bar_result = bar_attributes
            .intermediate_panic_calls
            .borrow()
            .clone()
            .into_backtrace_vec();

        let baz_attributes = &call_graph.graph[baz].borrow().attributes;
        let baz_result = baz_attributes
            .intermediate_panic_calls
            .borrow()
            .clone()
            .into_backtrace_vec();

        assert_eq!(baz_result, vec![buz, baz]);
        assert_eq!(bar_result, vec![quz, bar]);
        assert_eq!(foo_result, vec![quz, foo])
    }
}

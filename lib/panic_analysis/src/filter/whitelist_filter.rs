// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use AnalysisOptions;
use RustigCallGraph;
use RustigGraph;

use callgraph::Context;

use filter::NodeFilter;
use filter::NullNodeFilter;

use callgraph::petgraph::prelude::Direction::Outgoing;
use callgraph::petgraph::stable_graph::NodeIndex;
use callgraph::petgraph::visit::EdgeRef;

#[derive(Debug)]
struct WhiteListFunctionFilter;

impl WhiteListFunctionFilter {
    fn traverse_graph(&self, index: NodeIndex<u32>, graph: &RustigGraph) {
        let procedure = graph[index].borrow();

        // If function is whitelisted, ignore it
        if procedure.attributes.whitelisted.get() {
            return;
        }

        procedure.attributes.reachable_from_entry_point.set(true);

        // Check whether this node has any neighbors, if not return
        graph
            .edges_directed(index, Outgoing)
            .filter(|edge| !edge.weight().borrow().attributes.whitelisted.get())
            .map(|edge| edge.target())
            .for_each(|neighbor_idx| {
                let neighbor = graph[neighbor_idx].borrow();

                // Check whether neighbor has been visited yet, if not visit it before we continue (DFS)
                if !neighbor.attributes.reachable_from_entry_point.get() {
                    self.traverse_graph(neighbor_idx, graph);
                }
            });
    }
}

impl NodeFilter for WhiteListFunctionFilter {
    fn filter_nodes(&self, call_graph: &mut RustigCallGraph, _context: &Context) {
        // Mark all nodes that are reachable from main
        {
            let node_indices = call_graph.graph.node_indices();
            node_indices
                .filter(|idx| call_graph.graph[*idx].borrow().attributes.entry_point.get())
                .for_each(|entry_point_idx| {
                    self.traverse_graph(entry_point_idx, &call_graph.graph)
                });
        }

        call_graph.graph.retain_nodes(|grp, node_idx| {
            let node = grp[node_idx].borrow();
            !node.attributes.analysis_target.get()
                || node.attributes.reachable_from_entry_point.get()
        });

        call_graph.graph.retain_edges(|grp, edge_idx| {
            let edge = grp[edge_idx].borrow();
            !edge.attributes.whitelisted.get()
        });
    }
    #[cfg(test)]
    fn get_type_name(&self) -> &str {
        "WhiteListFunctionFilter"
    }
}

pub fn get_whitelist_filter(options: &AnalysisOptions) -> Box<NodeFilter> {
    if options.full_crate_analysis {
        Box::new(NullNodeFilter)
    } else {
        Box::new(WhiteListFunctionFilter)
    }
}

#[cfg(test)]
mod tests {
    extern crate callgraph;
    extern crate capstone;
    extern crate test_common;

    use super::*;
    use callgraph::Crate;
    use callgraph::Procedure;

    use self::capstone::arch::BuildsCapstone;
    use self::capstone::prelude::Capstone;

    use std::cell::Cell;
    use std::cell::RefCell;

    use callgraph::Invocation;
    use callgraph::InvocationType;
    use std::collections::HashMap;
    use std::rc::Rc;
    use IntermediateBacktrace::NoTrace;
    use RDPInvocationMetaData;
    use RDPProcedureMetaData;

    use test_utils;

    /// Helper function to create a procedure with a given name and crate name
    fn create_procedure_with_name(
        name: String,
        crate_name: String,
        is_entry: bool,
        whitelisted: bool,
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
                analysis_target: Cell::new(true),
                entry_point: Cell::new(is_entry),
                is_panic: Cell::new(true),
                is_panic_origin: Cell::new(false),
                intermediate_panic_calls: RefCell::new(NoTrace),
                visited: Cell::new(false),
                whitelisted: Cell::new(whitelisted),
                reachable_from_entry_point: Cell::new(false),
            },
            disassembly: capstone.disasm_all(&empty_vec, 0x1000).unwrap(),
        }
    }

    fn create_callgraph(
        reachable_from_main: bool,
        whitelist_bar: bool,
        whitelist_edge: bool,
    ) -> RustigCallGraph {
        let procedure_foo =
            create_procedure_with_name("foo".to_string(), "CrateFoo".to_string(), true, false);

        let procedure_bar = create_procedure_with_name(
            "bar".to_string(),
            "CrateFoo".to_string(),
            false,
            whitelist_bar,
        );

        let mut og = callgraph::petgraph::stable_graph::StableGraph::new();
        let i_foo = og.add_node(Rc::new(RefCell::new(procedure_foo)));
        let i_bar = og.add_node(Rc::new(RefCell::new(procedure_bar)));

        let invocation = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x144562,
            invocation_type: InvocationType::Direct,
            frames: Vec::new(),
            attributes: RDPInvocationMetaData {
                whitelisted: Cell::new(whitelist_edge),
            },
        }));

        if reachable_from_main {
            og.add_edge(i_foo, i_bar, invocation);
        }

        let cg = RustigCallGraph {
            graph: og,
            proc_index: HashMap::new(),
            call_index: HashMap::new(),
        };

        cg
    }

    /// Check if the correct type of panic filter is returned
    #[test]
    fn correct_whitelist_filter_type() {
        let options = AnalysisOptions {
            binary_path: None,
            crate_names: Vec::new(),
            full_crate_analysis: false,
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            whitelisted_functions: Vec::new(),
        };

        let filter = get_whitelist_filter(&options);

        assert_eq!(filter.get_type_name(), "WhiteListFunctionFilter");
    }

    /// Check if the correct type of panic filter is returned
    #[test]
    fn correct_whitelist_filter_full_crate_type() {
        let options = AnalysisOptions {
            binary_path: None,
            crate_names: Vec::new(),
            full_crate_analysis: true,
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            whitelisted_functions: Vec::new(),
        };

        let filter = get_whitelist_filter(&options);

        assert_eq!(filter.get_type_name(), "NullNodeFilter");
    }

    macro_rules! whitelist_test {
        ($($name:ident: $reachable:expr, $whitelist:expr, $whitelist_edge:expr => $node_count:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let options = AnalysisOptions {
                    binary_path: None,
                    crate_names: Vec::new(),
                    full_crate_analysis: false,
                    output_full_callgraph: false,
                    output_filtered_callgraph: false,
                    whitelisted_functions: Vec::new(),
                };

                let filter = get_whitelist_filter(&options);

                let mut cg = create_callgraph($reachable, $whitelist, $whitelist_edge);
                let file = test_common::load_test_binary_as_bytes(
                    "hello_world",
                    &test_common::TestSubjectType::Debug,
                ).unwrap();
                let context = test_utils::parse_context(&file);

                assert_eq!(cg.graph.node_indices().count(), 2);

                filter.filter_nodes(&mut cg, &context);

                assert_eq!(cg.graph.node_indices().count(), $node_count);
            }
        )*
        }
    }

    /// The whitelist test have four inputs which decide how a call graph for the test is built.
    /// The graph always has two nodes - `foo` and `bar`.
    /// First input decides whether the two nodes of the callgraph should be connected
    /// Second input decides whether the `bar` node should be filtered
    /// Third input decides whether the `foo-bar` edge should be filtered
    /// Fourth input is the expected value of the amount of nodes after filtering, either 1 or 2
    whitelist_test!{
        // Filter reachable edge and node
        filter_both_reachable: true, true, true => 1,

        // Filter reachable node
        whitelist_edge_reachable: true, true, false => 1,

        // Filter reachable edge
        whitelist_node_reachable: true, false, true => 1,

        // Don't filter unreachable nodes
        no_whitelist_filtering: true, false, false => 2,

        // NOTE: All unreachable nodes are filtered and so all the tests below get filtered.
        // Filter unreachable node and edge
        whitelist_both_unreachable: false, true, true => 1,
        // Filter unreachable edge
        whitelist_edge_unreachable: false, true, false => 1,
        // Filter unreachable node
        whitelist_node_unreachable: false, false, true => 1,
        // Don't filter unreachable node or edge
        unreachable_no_whitelist_filtering: false, false, false => 1,
    }
}

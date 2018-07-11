// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use AnalysisOptions;
use RustigCallGraph;

use callgraph::Context;

use filter::NodeFilter;

#[derive(Debug)]
struct NonPanicFilter;

impl NodeFilter for NonPanicFilter {
    fn filter_nodes(&self, call_graph: &mut RustigCallGraph, _context: &Context) {
        call_graph
            .graph
            .retain_nodes(|graph, node| graph[node].borrow().attributes.is_panic.get());
    }
    #[cfg(test)]
    fn get_type_name(&self) -> &str {
        "NonPanicFilter"
    }
}

pub fn get_panic_filter(_options: &AnalysisOptions) -> Box<NodeFilter> {
    Box::new(NonPanicFilter)
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

    use callgraph::CallGraph;
    use std::collections::HashMap;
    use std::rc::Rc;
    use IntermediateBacktrace::NoTrace;
    use RDPProcedureMetaData;
    use RustigCallGraph;

    use test_utils;

    /// Helper function to create a procedure with a given name and crate name
    fn create_procedure_with_name(
        name: String,
        crate_name: String,
        is_panic: bool,
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
                entry_point: Cell::new(false),
                is_panic: Cell::new(is_panic),
                is_panic_origin: Cell::new(false),
                intermediate_panic_calls: RefCell::new(NoTrace),
                visited: Cell::new(true),
                whitelisted: Cell::new(false),
                reachable_from_entry_point: Cell::new(true),
            },
            disassembly: capstone.disasm_all(&empty_vec, 0x1000).unwrap(),
        }
    }

    /// Create callgraph with a (possibly panicking) procedure with some specific name
    fn create_callgraph(proc_name: &str, with_panic: bool) -> RustigCallGraph {
        let procedure_foo =
            create_procedure_with_name(proc_name.to_string(), "CrateFoo".to_string(), with_panic);

        let mut og = callgraph::petgraph::stable_graph::StableGraph::new();
        og.add_node(Rc::new(RefCell::new(procedure_foo)));

        let cg: RustigCallGraph = CallGraph {
            graph: og,
            proc_index: HashMap::new(),
            call_index: HashMap::new(),
        };

        cg
    }

    /// Check if the correct type of panic filter is returned
    #[test]
    fn correct_panic_filter_type() {
        let options = AnalysisOptions {
            binary_path: None,
            crate_names: Vec::new(),
            full_crate_analysis: false,
            output_full_callgraph: false,
            output_filtered_callgraph: false,
            whitelisted_functions: Vec::new(),
        };

        let filter = get_panic_filter(&options);

        assert_eq!(filter.get_type_name(), "NonPanicFilter");
    }

    /// Test whether non-panicking nodes are filtered away
    #[test]
    fn panic_filtering() {
        let mut cg = create_callgraph("foo", false);

        let file = test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(&file);

        assert_eq!(1, cg.graph.node_indices().count());

        NonPanicFilter.filter_nodes(&mut cg, &context);

        assert_eq!(0, cg.graph.node_indices().count());
    }

    /// Test whether panicking nodes are not filtered away
    #[test]
    fn non_panic_filtering() {
        let mut cg = create_callgraph("foo", true);

        let file = test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(&file);

        assert_eq!(1, cg.graph.node_indices().count());

        NonPanicFilter.filter_nodes(&mut cg, &context);

        assert_eq!(1, cg.graph.node_indices().count());
    }
}

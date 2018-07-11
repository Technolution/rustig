// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

mod panic_filter;
mod whitelist_filter;

use AnalysisOptions;
use RustigCallGraph;

use callgraph::Context;

use std::fmt::Debug;

/// Trait used to filter nodes from call graph
pub trait NodeFilter: Debug {
    fn filter_nodes(&self, call_graph: &mut RustigCallGraph, context: &Context);
    #[cfg(test)]
    fn get_type_name(&self) -> &str;
}

/// Combination of multiple node filters
#[derive(Debug)]
struct CombinedNodeFilter {
    filters: Vec<Box<NodeFilter>>,
}

impl NodeFilter for CombinedNodeFilter {
    fn filter_nodes(&self, call_graph: &mut RustigCallGraph, context: &Context) {
        self.filters
            .iter()
            .for_each(|filter| filter.filter_nodes(call_graph, context));
    }
    #[cfg(test)]
    fn get_type_name(&self) -> &str {
        "CombinedNodeFilter"
    }
}

#[derive(Debug)]
pub struct NullNodeFilter;

impl NodeFilter for NullNodeFilter {
    fn filter_nodes(&self, _call_graph: &mut RustigCallGraph, _context: &Context) {}
    #[cfg(test)]
    fn get_type_name(&self) -> &str {
        "NullNodeFilter"
    }
}

pub fn get_node_filters(options: &AnalysisOptions) -> Box<NodeFilter> {
    let filters: Vec<Box<NodeFilter>> = vec![
        panic_filter::get_panic_filter(&options),
        whitelist_filter::get_whitelist_filter(&options),
    ];

    Box::new(CombinedNodeFilter { filters })
}

#[cfg(test)]
mod tests {
    extern crate callgraph;
    extern crate test_common;

    use super::*;
    use callgraph::CallGraph;
    use std::cell::Cell;
    use std::collections::HashMap;
    use std::rc::Rc;

    use test_utils;

    /// Filter used as a mock of NodeFilter
    #[derive(Debug)]
    struct FakeNodeFilter {
        pub filter_nodes_calls: Rc<Cell<usize>>,
    }

    /// Whenever filter_nodes is called, increment the call counter
    impl NodeFilter for FakeNodeFilter {
        fn filter_nodes(&self, _call_graph: &mut RustigCallGraph, _context: &Context) {
            let current = self.filter_nodes_calls.replace(0 as usize);

            self.filter_nodes_calls.replace(current + 1 as usize);
        }
        #[cfg(test)]
        fn get_type_name(&self) -> &str {
            "FakeNodeFilter"
        }
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

        let filter = get_node_filters(&options);

        assert_eq!(filter.get_type_name(), "CombinedNodeFilter");
    }

    /// Check if combined filter calls its children
    #[test]
    fn combined_filter_works() {
        let counter1 = Rc::new(Cell::new(0 as usize));
        let counter2 = Rc::new(Cell::new(0 as usize));

        let fake_filter1 = Box::new(FakeNodeFilter {
            filter_nodes_calls: counter1.clone(),
        });

        let fake_filter2 = Box::new(FakeNodeFilter {
            filter_nodes_calls: counter2.clone(),
        });

        let fake_filters: Vec<Box<NodeFilter>> = vec![fake_filter1, fake_filter2];

        let combined_filter = CombinedNodeFilter {
            filters: fake_filters,
        };

        let graph = callgraph::petgraph::stable_graph::StableGraph::new();

        let mut cg = CallGraph {
            graph,
            proc_index: HashMap::new(),
            call_index: HashMap::new(),
        };

        let file = test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();

        let context = test_utils::parse_context(&file);

        combined_filter.filter_nodes(&mut cg, &context);

        assert_eq!(counter1.get(), 1);
        assert_eq!(counter2.get(), 1);
    }

}

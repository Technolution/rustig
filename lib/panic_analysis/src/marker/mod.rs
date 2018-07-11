// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

mod analysis_target;
mod entry_point;
mod function_whitelist;
mod panic;

use AnalysisOptions;
use RustigCallGraph;

use callgraph::Context;

use std::fmt::Debug;

use marker::analysis_target::get_panic_analysis_target_marker;
use marker::entry_point::get_entry_points_marker;
use marker::panic::get_panic_marker;

pub trait CodeMarker: Debug {
    fn mark_code(&self, call_graph: &RustigCallGraph, context: &Context);
    #[cfg(test)]
    fn get_type_name(&self) -> &str;
}

/// Combination of multiple `CodeMarker` implementations.
#[derive(Debug)]
struct CombinedCodeMarker {
    markers: Vec<Box<CodeMarker>>,
}

impl CodeMarker for CombinedCodeMarker {
    fn mark_code(&self, call_graph: &RustigCallGraph, context: &Context) {
        self.markers
            .iter()
            .for_each(|marker| marker.mark_code(call_graph, context));
    }
    #[cfg(test)]
    fn get_type_name(&self) -> &str {
        "CombinedCodeMarker"
    }
}

/// Implementation of the `CodeMarker` to not mark anything
#[derive(Debug)]
// Since `EntryPointAnalysisTargetMarker` is implemented, this struct is not used anymore
// We might still keep it here for future reference
#[allow(dead_code)]
struct NullMarker;

impl CodeMarker for NullMarker {
    fn mark_code(&self, _call_graph: &RustigCallGraph, _context: &Context) {
        return;
    }
    #[cfg(test)]
    fn get_type_name(&self) -> &str {
        "NullMarker"
    }
}

pub fn get_code_markers(options: &AnalysisOptions) -> Box<CodeMarker> {
    let panic_analysis_target_marker = get_panic_analysis_target_marker(options);
    let main_code_marker = get_entry_points_marker(options);
    let panic_marker = get_panic_marker(options);

    let mut markers = vec![main_code_marker, panic_marker, panic_analysis_target_marker];

    if !options.whitelisted_functions.is_empty() {
        let whitelists = options.whitelisted_functions.to_vec();

        markers.insert(
            0,
            Box::new(function_whitelist::FunctionWhitelistMarker { whitelists }),
        )
    }

    Box::new(CombinedCodeMarker { markers })
}

#[cfg(test)]
mod test {
    extern crate callgraph;
    extern crate capstone;
    extern crate gimli;
    extern crate object;
    extern crate std;
    extern crate test_common;

    use super::*;

    use std::cell::Cell;
    use std::collections::HashMap;

    use std::rc::Rc;

    use test_utils;

    #[derive(Debug)]
    struct FakeCodeMarker {
        called: Rc<Cell<bool>>,
    }

    impl CodeMarker for FakeCodeMarker {
        fn mark_code(&self, _call_graph: &RustigCallGraph, _context: &Context) {
            self.called.replace(true);
        }
        #[cfg(test)]
        fn get_type_name(&self) -> &str {
            "FakeCodeMarker"
        }
    }

    /// Verify that `CombinedCodeMarker` calls all it's children when .`mark_code` is executed
    #[test]
    fn test_markers_calls() {
        let og = callgraph::petgraph::stable_graph::StableGraph::new();

        let call_graph = RustigCallGraph {
            graph: og,
            proc_index: HashMap::new(),
            call_index: HashMap::new(),
        };

        let cell1 = Rc::new(Cell::new(false));
        let cell1_rc = cell1.clone();
        let marker1 = Box::new(FakeCodeMarker { called: cell1 });

        let cell2 = Rc::new(Cell::new(false));
        let cell2_rc = cell2.clone();
        let marker2 = Box::new(FakeCodeMarker { called: cell2 });

        let markers: Vec<Box<CodeMarker>> = vec![marker1, marker2];
        let all_markers = CombinedCodeMarker { markers };

        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(file_content);

        all_markers.mark_code(&call_graph, &context);

        assert!(cell1_rc.get());
        assert!(cell2_rc.get());
    }
}

// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate callgraph;
extern crate fallible_iterator;
extern crate gimli;

use AnalysisOptions;
use RustigCallGraph;

use callgraph::Context;

use self::fallible_iterator::FallibleIterator;

use marker::CodeMarker;

use callgraph::dwarf_utils;

use gimli::CompilationUnitHeader;
use gimli::EndianBuf;
use gimli::LittleEndian;

/// Implementation of the `CodeMarker` to mark the main entry procedure
#[derive(Debug)]
struct MainEntryCodeMarker;

impl CodeMarker for MainEntryCodeMarker {
    fn mark_code(&self, call_graph: &RustigCallGraph, context: &Context) {
        context
            .dwarf_info
            .units()
            .iterator()
            .map(Result::unwrap)
            .for_each(|unit| {
                // Find entries in compilation unit
                self.mark_entry_point(call_graph, &context, unit)
            })
    }
    #[cfg(test)]
    fn get_type_name(&self) -> &str {
        "MainEntryCodeMarker"
    }
}

impl MainEntryCodeMarker {
    fn mark_entry_point(
        &self,
        call_graph: &RustigCallGraph,
        context: &Context,
        unit: CompilationUnitHeader<EndianBuf<LittleEndian>>,
    ) -> () {
        let abbrevs = unit.abbreviations(&context.dwarf_abbrev).unwrap();
        let mut entries = unit.entries(&abbrevs);
        // Iterate over the entries
        while let Some((_, entry)) = entries.next_dfs().unwrap() {
            // If we find an entry for a function that has DW_AT_main_subprogram set ot true
            // We mark the corresponding procedure as entry point.
            if entry.tag() == gimli::DW_TAG_subprogram {
                if let Some(gimli::AttributeValue::Flag(true)) =
                    entry.attr_value(gimli::DW_AT_main_subprogram).unwrap()
                {
                    let start_address =
                        dwarf_utils::get_attr_addr_value(&entry, gimli::DW_AT_low_pc)
                            .expect("No DW_AT_low_pc attribute found for function");

                    let node_index = call_graph.proc_index[&start_address];
                    call_graph.graph[node_index]
                        .borrow()
                        .attributes
                        .entry_point
                        .replace(true);
                }
            }
        }
    }
}

pub fn get_entry_points_marker(_options: &AnalysisOptions) -> Box<CodeMarker> {
    Box::new(MainEntryCodeMarker)
}

#[cfg(test)]
mod test {
    extern crate capstone;
    extern crate gimli;
    extern crate object;
    extern crate std;
    extern crate test_common;

    use self::capstone::arch::BuildsCapstone;
    use self::capstone::Capstone;

    use super::*;

    use callgraph::Crate;
    use callgraph::Procedure;

    use RDPProcedureMetaData;

    use std::cell::Cell;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    use IntermediateBacktrace::NoTrace;

    use test_utils;

    /// Helper function to create a procedure with a given name, crate name and address
    fn create_procedure_with_name(
        name: String,
        crate_name: String,
        starting_address: u64,
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
            start_address: starting_address,
            size: 64,
            location: None,
            attributes: RDPProcedureMetaData {
                analysis_target: Cell::new(false),
                entry_point: Cell::new(false),
                is_panic: Cell::new(false),
                is_panic_origin: Cell::new(false),
                intermediate_panic_calls: RefCell::new(NoTrace),
                visited: Cell::new(false),
                whitelisted: Cell::new(false),
                reachable_from_entry_point: Cell::new(true),
            },
            disassembly: capstone.disasm_all(&empty_vec, 0x1000).unwrap(),
        }
    }

    // Given some specific context, find the address of main
    fn find_main_address(context: &Context) -> u64 {
        let mut iter = context.dwarf_info.units();
        let mut start_address: u64 = 0x0;
        while let Some(unit) = iter.next().unwrap() {
            // Parse the abbreviations for this compilation unit.
            let abbrevs = unit.abbreviations(&context.dwarf_abbrev).unwrap();

            // Iterate over all of this compilation unit's entries.
            let mut entries = unit.entries(&abbrevs);
            while let Some((_, entry)) = entries.next_dfs().unwrap() {
                // If we find an entry for a function, print it.
                if let Some(gimli::AttributeValue::Flag(true)) =
                    entry.attr_value(gimli::DW_AT_main_subprogram).unwrap()
                {
                    start_address = dwarf_utils::get_attr_addr_value(&entry, gimli::DW_AT_low_pc)
                        .expect("No DW_AT_low_pc attribute found for function");
                }
            }
        }

        start_address
    }

    /// Test to ensure attributes are marked correctly as entry points
    #[test]
    fn test_marks_correctly() {
        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();
        let context = test_utils::parse_context(file_content);

        let main_addr = find_main_address(&context);
        let motmain_addr = 0x126;

        let procedure_main =
            create_procedure_with_name("main".to_string(), "mycrate".to_string(), main_addr);
        let procedure_not_main =
            create_procedure_with_name("notmain".to_string(), "mycrate".to_string(), motmain_addr);

        let mut og = callgraph::petgraph::stable_graph::StableGraph::new();
        let node_index_main = og.add_node(Rc::new(RefCell::new(procedure_main)));
        let node_index_notmain = og.add_node(Rc::new(RefCell::new(procedure_not_main)));

        let mut proc_index = HashMap::new();
        proc_index.insert(main_addr, node_index_main);
        proc_index.insert(motmain_addr, node_index_notmain);

        let call_graph = RustigCallGraph {
            graph: og,
            proc_index,
            call_index: HashMap::new(),
        };

        let marker = MainEntryCodeMarker;
        marker.mark_code(&call_graph, &context);

        let value_main = &call_graph.graph[node_index_main]
            .borrow()
            .attributes
            .entry_point;
        let value_notmain = &call_graph.graph[node_index_notmain]
            .borrow()
            .attributes
            .entry_point;

        assert!(value_main.get());
        assert!(!value_notmain.get());
    }
}

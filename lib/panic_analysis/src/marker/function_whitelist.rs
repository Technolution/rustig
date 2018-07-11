// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate callgraph;
extern crate fallible_iterator;
extern crate gimli;

use FunctionWhiteListEntry;
use RustigCallGraph;

use callgraph::Context;

use marker::CodeMarker;

/// `CodeMarker` that sets the field `RDPProcedureMetaData.whitelisted` to the correct value.
#[derive(Debug)]
pub struct FunctionWhitelistMarker {
    pub whitelists: Vec<FunctionWhiteListEntry>,
}

impl CodeMarker for FunctionWhitelistMarker {
    fn mark_code(&self, call_graph: &RustigCallGraph, _context: &Context) {
        let node_indices: Vec<_> = call_graph.graph.node_indices().collect();

        node_indices.iter().for_each(|idx| {
            let prc = &call_graph.graph[*idx];
            let prc = prc.borrow();
            let matches_any_filter = self.whitelists.iter().any(|wl| wl.matches_procedure(&prc));
            if matches_any_filter {
                prc.attributes.whitelisted.set(true)
            }

            call_graph.graph.edges(*idx).for_each(|edge| {
                let matches_any_filter = self.whitelists
                    .iter()
                    .any(|wl| wl.matches_invocation(&prc, &edge.weight().borrow()));
                if matches_any_filter {
                    edge.weight().borrow().attributes.whitelisted.set(true)
                }
            })
        })
    }
    #[cfg(test)]
    fn get_type_name(&self) -> &str {
        "FunctionWhitelistMarker"
    }
}

#[cfg(test)]
mod tests {
    extern crate capstone;
    extern crate gimli;
    extern crate object;
    extern crate std;
    extern crate test_common;

    use self::capstone::arch::BuildsCapstone;
    use self::capstone::Capstone;

    use super::*;

    use callgraph::Context;
    use callgraph::Crate;
    use callgraph::InlineFunctionFrame;
    use callgraph::Invocation;
    use callgraph::InvocationType;
    use callgraph::Location;
    use callgraph::Procedure;

    use callgraph::addr2line::Context as Addr2LineContext;

    use RDPInlineFrameMetaData;
    use RDPInvocationMetaData;
    use RDPProcedureMetaData;

    use std::cell::Cell;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io::Read;
    use std::rc::Rc;

    use self::gimli::DebugAbbrev;
    use self::gimli::DebugInfo;
    use self::gimli::DebugLine;
    use self::gimli::DebugStr;

    use self::object::ElfFile;
    use self::object::File;
    use self::object::Object;

    use IntermediateBacktrace::NoTrace;

    use FunctionWhitelistCrateVersion;

    /// Local helper function to create a Context
    fn parse<'a>(file_content: &'a [u8]) -> Context<'a> {
        let elf = ElfFile::parse(&file_content).expect("Failed to parse file content");
        let file = File::parse(&file_content).expect("Failed to parse file content to File format");
        let file_context =
            Addr2LineContext::new(&file).expect("Could not construct context from file");

        let endianness = gimli::LittleEndian;
        let mode = capstone::arch::x86::ArchMode::Mode64;

        let debug_info_data = elf.section_data_by_name(".debug_info")
            .expect("No .debug_info section in binary");
        let dwarf_info = DebugInfo::new(debug_info_data, endianness);

        let debug_abbrev_data = elf.section_data_by_name(".debug_abbrev")
            .expect("No .debug_abbrev section in binary");
        let dwarf_abbrev = DebugAbbrev::new(debug_abbrev_data, endianness);

        let debug_str_data = elf.section_data_by_name(".debug_str")
            .expect("No .debug_str section in binary");
        let dwarf_strings = DebugStr::new(debug_str_data, endianness);

        let debug_line_data = elf.section_data_by_name(".debug_line")
            .expect("No .debug_line section in binary");
        let dwarf_line = DebugLine::new(debug_line_data, endianness);

        let mut capstone = Capstone::new()
            .x86()
            .mode(mode)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");
        capstone
            .set_detail(true)
            .expect("Failed to enable detailed mode");

        Context {
            elf,
            file_context,
            dwarf_info,
            dwarf_abbrev,
            dwarf_strings,
            dwarf_line,
            capstone,
        }
    }

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
            linkage_name: format!("linkage_name::{}", name).to_string(),
            linkage_name_demangled: format!("linkage_name_demangled::{}", name).to_string(),
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

    #[test]
    fn test_marks_whitelist_correctly() {
        let mut test_file = self::test_common::load_test_binary(
            "hello_world",
            &self::test_common::TestSubjectType::Debug,
        ).unwrap();

        let mut file_content = Vec::<u8>::new();
        test_file
            .read_to_end(&mut file_content)
            .expect("something went wrong reading the file");

        let ctx = parse(&file_content);
        let main_addr = 0x6410;
        let motmain_addr = 0x1243;

        let procedure_main =
            create_procedure_with_name("main".to_string(), "mycrate".to_string(), main_addr);
        let procedure_not_main =
            create_procedure_with_name("foo".to_string(), "mycrate".to_string(), motmain_addr);

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

        let marker = FunctionWhitelistMarker {
            whitelists: vec![FunctionWhiteListEntry {
                function_name: "main".to_string(),
                crate_name: Some("mycrate".to_string()),
                crate_version: FunctionWhitelistCrateVersion::None,
            }],
        };

        marker.mark_code(&call_graph, &ctx);

        assert!(
            call_graph.graph[node_index_main]
                .borrow()
                .attributes
                .whitelisted
                .get()
        );
        assert!(!call_graph.graph[node_index_notmain]
            .borrow()
            .attributes
            .whitelisted
            .get());
    }

    #[test]
    fn test_marks_invocation_whitelist_correctly() {
        let mut test_file = self::test_common::load_test_binary(
            "hello_world",
            &self::test_common::TestSubjectType::Debug,
        ).unwrap();

        let mut file_content = Vec::<u8>::new();
        test_file
            .read_to_end(&mut file_content)
            .expect("something went wrong reading the file");

        let ctx = parse(&file_content);
        let main_addr = 0x6410;
        let motmain_addr = 0x1243;

        let procedure_main =
            create_procedure_with_name("main".to_string(), "mycrate".to_string(), main_addr);
        let procedure_not_main =
            create_procedure_with_name("foo".to_string(), "mycrate".to_string(), motmain_addr);

        let inv = Rc::new(RefCell::new(Invocation {
            instruction_address: 0x144562,
            invocation_type: InvocationType::Direct,
            frames: vec![InlineFunctionFrame {
                function_name: "mod1::mod2::inline_func".to_string(),
                location: Location {
                    file: "my/file.rs".to_string(),
                    line: 123,
                },
                defining_crate: Crate {
                    name: "crate".to_string(),
                    version: Some("1.2.3".to_string()),
                },
                attributes: RDPInlineFrameMetaData::default(),
            }],
            attributes: RDPInvocationMetaData {
                whitelisted: Cell::new(false),
            },
        }));

        let mut og = callgraph::petgraph::stable_graph::StableGraph::new();
        let node_index_main = og.add_node(Rc::new(RefCell::new(procedure_main)));
        let node_index_notmain = og.add_node(Rc::new(RefCell::new(procedure_not_main)));

        og.add_edge(node_index_main, node_index_notmain, inv.clone());

        let mut proc_index = HashMap::new();
        proc_index.insert(main_addr, node_index_main);
        proc_index.insert(motmain_addr, node_index_notmain);

        let call_graph = RustigCallGraph {
            graph: og,
            proc_index,
            call_index: HashMap::new(),
        };

        let marker = FunctionWhitelistMarker {
            whitelists: vec![FunctionWhiteListEntry {
                function_name: "inline_func".to_string(),
                crate_name: Some("mycrate".to_string()),
                crate_version: FunctionWhitelistCrateVersion::None,
            }],
        };

        marker.mark_code(&call_graph, &ctx);

        assert!(inv.borrow().attributes.whitelisted.get());
    }
}

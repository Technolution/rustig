// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate byteorder;
extern crate capstone;

use Context;
use InlineFunctionFrame;
use Invocation;
use InvocationType;
use Procedure;

use byteorder::{LittleEndian, ReadBytesExt};

use callgraph::fallible_iterator::FallibleIterator;
use callgraph::InvocationFinder;

use capstone::arch::x86::X86OpMem;
use capstone::arch::x86::X86OperandType;
use capstone::arch::ArchOperand;
use capstone::Insn;
use capstone::InsnDetail;
use capstone::RegId;

use object::ElfSection;
use object::Object;
use object::ObjectSection;

use std::cell::RefCell;
use std::io::Cursor;
use std::ops::Deref;
use std::rc::Rc;

use callgraph::CompilationInfo;
use petgraph::stable_graph::NodeIndex;
use petgraph::stable_graph::StableGraph;
use std::collections::HashMap;
use std::marker::PhantomData;

static WORD_SIZE: usize = 8;

/// Implementation of `InvocationFinder` that assumes that all functions for which the address
/// to that function is loaded using an `lea` instruction are called.
pub struct LEABasedDynamicInvocationFinder<P, I, F> {
    pub phantom: PhantomData<(P, I, F)>,
}

impl<P, I, F> Default for LEABasedDynamicInvocationFinder<P, I, F> {
    fn default() -> Self {
        LEABasedDynamicInvocationFinder {
            phantom: PhantomData,
        }
    }
}

impl<P, I: Default, F: Default> LEABasedDynamicInvocationFinder<P, I, F> {
    /// Returns the dynamic calls for a LEA instruction.
    /// In the case the LEA references a function, a vector with length 1 is returned, containing metadata referencing that function.
    /// In the case the LEA reference a vtable, a vector with metadata referencing all functions in the tabel is returned.
    /// When the reference could not be traced to a function or vtable, an empty vector is returned.
    ///
    /// ## Return value
    /// Returns a vector of tuples. If `res` is a return tuple of this function, the fields denote:
    ///     `res.0`: address of the lea instruction
    ///     `res.1`: address of the called function
    ///     `res.2`: type of invocation (either `InvocationType::ProcedureReference` or `InvocationType::VTable`
    fn find_mem_value(
        &self,
        insn: &Insn,
        mem_operand: &X86OpMem,
        graph: &StableGraph<Rc<RefCell<Procedure<P>>>, Rc<RefCell<Invocation<I, F>>>>,
        proc_index: &HashMap<u64, NodeIndex>,
        ctx: &Context,
        prc: &Procedure<P>,
    ) -> Vec<(u64, u64, InvocationType)> {
        let lea_address = insn.address();
        // Try to calculate memory operand value

        // We cannot determine the value of an index register accurately
        // Therefore, we can also no determine the exact memory location
        // so return an empty vector in that case
        if mem_operand.index() != RegId(0) {
            return vec![];
        }

        // Calculate target mem_location
        // Formula: mem_location = base_reg_value + displacement
        let base_reg_value = match mem_operand.base() {
            RegId(0) => 0, // No base register specified, so target is absolute
            RegId(41) => lea_address + insn.bytes().len() as u64, // register rip (which is updated before instruction is executed, therefore + .bytes().len()
            _ => return vec![], // // Other register, for which we can not determine the value
        };

        // base_reg_value + displacement
        let mem_location = (base_reg_value as i64 + mem_operand.disp()) as u64;

        let text_section = ctx.elf
            .sections()
            .find(|section| section.name() == Some(".text"))
            .expect("No text section in elf");

        if text_section.address() <= mem_location
            && text_section.address() + text_section.size() > mem_location
        {
            // memory location is in .text section
            // Try to find function at that address

            if proc_index.contains_key(&mem_location) {
                return vec![(
                    lea_address,
                    mem_location,
                    InvocationType::ProcedureReference,
                )];
            }

            return vec![];
        }

        // vtables are always located at the 'data.rel.ro' section
        let vtable_section = ctx.elf
            .sections()
            .find(|section| section.name() == Some(".data.rel.ro"))
            .expect("No data.rel.ro section in elf");

        // If pointer is in vtable return entries for vtable
        if vtable_section.address() <= mem_location
            && vtable_section.address() + vtable_section.size() > mem_location
        {
            self.get_vtable_pointers(
                graph,
                proc_index,
                prc,
                lea_address,
                mem_location,
                &vtable_section,
            )
        } else {
            // Pointer not in .text, nor .data.rel.ro, so return no edges.
            vec![]
        }
    }

    /// Internal function that returns metadata of all functions in the vtable at address `mem_location`
    ///
    /// ## Return value
    /// Returns a vector of tuples. If `res` is a return tuple of this function, the fields denote:
    ///     `res.0`: address of the lea instruction
    ///     `res.1`: address of the called function
    ///     `res.2`: type of invocation (either `InvocationType::ProcedureReference` or `InvocationType::VTable`
    fn get_vtable_pointers(
        &self,
        graph: &StableGraph<Rc<RefCell<Procedure<P>>>, Rc<RefCell<Invocation<I, F>>>>,
        proc_index: &HashMap<u64, NodeIndex<u32>>,
        prc: &Procedure<P>,
        lea_address: u64,
        mem_location: u64,
        vtable_section: &ElfSection,
    ) -> Vec<(u64, u64, InvocationType)> {
        // memory location is in .data.rel.ro section
        // In that case we assume it is a vtable
        // Tricky part of this is that the size of the vtable is unknown.
        // We know the vtable has the following layout
        // ****************************
        // <destructor pointer>
        // <size>
        // <align>
        // <trait function 1>
        // ...
        // <trait function n>
        // ****************************
        // In the loop below, the first 3 fields are skipped
        // After that, we will push items, until we find a destructor (which we assume is of the next vtable)
        // or find a pointer that does not map to a procedure (there we assume some other data is meant)

        // First do en early return if the first entry of the assumed vtable is not a destructor
        let (mut offset, vtable_data, vtable_first_entry, is_destructor) =
            self.get_vtable_metadata(graph, proc_index, mem_location, &vtable_section);

        if !is_destructor {
            return vec![];
        }

        // The first entry if the vtable is a pointer to a destructor
        // If there does not exist a static call to that destructor form the calling function
        // we assume it will be called dynamically somewhere
        let mut result: Vec<(u64, u64, InvocationType)> = vec![];
        let destructor = vtable_first_entry.unwrap();
        let destructor = destructor.borrow();
        let vtable_data_length = vtable_data.len();

        let calling_proc_index = proc_index[&prc.start_address];
        let dest_proc_index = proc_index[&destructor.start_address];

        // If edge to the destructor does not yet exist, add it
        if graph
            .find_edge(calling_proc_index, dest_proc_index)
            .is_none()
        {
            result.push((
                lea_address,
                destructor.start_address,
                InvocationType::VTable,
            ));
        }

        // Skip destructor + size + align fields
        offset += WORD_SIZE * 3;

        // Iterate all entries in the vtable, until we find a pointer to something different than a procedure
        // or to a destructor (which signifies a new vtable)
        while offset < vtable_data_length {
            let procedure = self.get_pointed_proc(offset, vtable_data, graph, proc_index);

            // Procedure not found, assume we are in some other data structure
            if procedure.is_none() {
                break;
            }

            // Unwrap is safe, because is_none check above
            let procedure = procedure.unwrap();
            let procedure: &Procedure<P> = &procedure.deref().borrow();

            if procedure.name.contains("drop_in_place") {
                // In new vtable, so quit here
                break;
            }

            // If an edge of this kind is not yet present, add it
            let edge_existing = result.iter().any(|x: &(u64, u64, InvocationType)| {
                x.1 == procedure.start_address && x.2 == InvocationType::VTable
            });

            if !edge_existing {
                result.push((lea_address, procedure.start_address, InvocationType::VTable));
            }

            offset += WORD_SIZE;
        }
        result
    }

    /// Internal function that returns metadata about the vtable at `mem_location`.
    ///
    /// ## Return value
    /// Returns a tuple. If `res` is a return tuple of this function, the fields denote:
    ///     `res.0`: offset of the vtable in the '.data.rel.ro' section.
    ///     `res.1`: the data of the vtable section ('.data.rel.ro')
    ///     `res.2`: The (optional) procedure that denotes the destructor that is pointed to by the first entry in the vtable
    ///     `res.3`: A boolean indicating if the destructor is indeed a destructor.
    fn get_vtable_metadata<'a>(
        &self,
        graph: &StableGraph<Rc<RefCell<Procedure<P>>>, Rc<RefCell<Invocation<I, F>>>>,
        proc_index: &HashMap<u64, NodeIndex<u32>>,
        mem_location: u64,
        vtable_section: &'a ElfSection,
    ) -> (usize, &'a [u8], Option<Rc<RefCell<Procedure<P>>>>, bool) {
        let offset = (mem_location - vtable_section.address()) as usize;
        let vtable_data = vtable_section.data();
        let vtable_data_length = vtable_data.len();
        assert_eq!(
            vtable_data_length,
            vtable_section.size() as usize,
            ".data.rel.ro data slice length ({:x}) does not match size header ({:x})",
            vtable_data_length,
            vtable_section.size()
        );
        // If not pointing to a destructor, we assume this is not a vtable
        let vtable_first_entry = self.get_pointed_proc(offset, vtable_data, graph, proc_index);
        let is_destructor = vtable_first_entry
            .as_ref()
            .map(|prc| {
                let p: &Procedure<P> = &prc.deref().borrow();
                p.name.contains("drop_in_place")
            })
            .unwrap_or(false);
        (offset, vtable_data, vtable_first_entry, is_destructor)
    }

    /// Internal function that returns invocation details for all LEA instuctions in `prc`.
    ///
    /// ## Return value
    /// Returns a vector of tuples. If `res` is a return tuple of this function, the fields denote:
    ///     `res.0`: address of the lea instruction
    ///     `res.1`: address of the called function
    ///     `res.2`: type of invocation (either `InvocationType::ProcedureReference` or `InvocationType::VTable`
    fn find_dynamic_invocations_for_procedure(
        &self,
        graph: &mut StableGraph<Rc<RefCell<Procedure<P>>>, Rc<RefCell<Invocation<I, F>>>>,
        proc_index: &mut HashMap<u64, NodeIndex<u32>>,
        ctx: &Context,
        prc: &Procedure<P>,
    ) -> Vec<(u64, u64, InvocationType)> {
        prc
            .disassembly
            .iter()
            // Filter lea instructions
            .filter(|instr| instr.mnemonic().unwrap_or_default().starts_with("lea"))
            // Map all instructions to the function addresses they point to
            .filter_map(|lea_instr| {
                // Decode details
                ctx.capstone.insn_detail(&lea_instr).ok()
                    // Extract X86 operands
                    .as_ref()
                    .and_then(get_source_operand)
                    // Map to memory locations
                    .map(|source_operand| match source_operand {
                        // Direct memory location (often a non-capturing closure, or function reference)
                        X86OperandType::Imm(value)
                        if proc_index.contains_key(&(value as u64)) =>
                            vec!((lea_instr.address(), value as u64,
                                  InvocationType::ProcedureReference)),
                        // Register offset (often a vtable)
                        X86OperandType::Mem(op) =>
                            self.find_mem_value(&lea_instr, &op, &graph,
                                                &proc_index, &ctx, &prc),
                        _ => vec!()
                    }) // Finish pipeline
            })
            .flat_map(|x| x)
            .collect::<Vec<_>>()
    }

    /// Internal function that returns edges for all dynamic invocations.
    ///
    /// ## Return value
    /// Returns a vector of tuples. If `res` is a return tuple of this function, the fields denote:
    ///     `res.0`: address of the lea instruction
    ///     `res.1`: address of the called function
    ///     `res.2`: type of invocation (either `InvocationType::ProcedureReference` or `InvocationType::VTable`
    fn create_dynamic_edges(
        &self,
        graph: &mut StableGraph<Rc<RefCell<Procedure<P>>>, Rc<RefCell<Invocation<I, F>>>>,
        proc_index: &mut HashMap<u64, NodeIndex<u32>>,
        ctx: &Context,
        idx: NodeIndex<u32>,
        dest_indices: &[(u64, u64, InvocationType)],
        compilation_info: &CompilationInfo,
    ) {
        dest_indices
            .iter()
            .for_each(|(lea_addr, target_addr, invocation_type)| {
                let frames = ctx.file_context
                    .find_frames(*lea_addr)
                    .unwrap_or_else(|_| {
                        panic!("Creating iterator over dynamic function frames of the given virtual memory address: {:X} failed", *lea_addr)
                    })
                    .iterator()
                    .filter_map(|frame_res| frame_res.ok())
                    .map(|frame| {
                        InlineFunctionFrame::convert_frame(
                            &frame,
                            compilation_info.compilation_dirs,
                            compilation_info.rust_version.to_owned(),
                        )
                    })
                    .collect();
                graph.add_edge(
                    idx,
                    proc_index[&target_addr],
                    Rc::new(RefCell::new(Invocation {
                        invocation_type: *invocation_type,
                        instruction_address: *lea_addr,
                        frames,
                        attributes: I::default(),
                    })),
                );
            });
    }

    /// Function that returns an (optional) `Procedure` at `offset` in the '.data.rel.ro' section.
    fn get_pointed_proc(
        &self,
        offset: usize,
        vtable_data: &[u8],
        graph: &StableGraph<Rc<RefCell<Procedure<P>>>, Rc<RefCell<Invocation<I, F>>>>,
        proc_index: &HashMap<u64, NodeIndex>,
    ) -> Option<Rc<RefCell<Procedure<P>>>> {
        // Copy pointer data
        let mut buffer: [u8; 8] = Default::default();
        buffer.copy_from_slice(&vtable_data[offset..(offset + WORD_SIZE)]);

        let mut reader = Cursor::new(buffer);
        let fn_address = reader.read_u64::<LittleEndian>().unwrap();

        // In the calling function we checked whether the key exists, so this graph index is safe
        proc_index.get(&fn_address).map(|idx| graph[*idx].clone())
    }
}

/// Returns an optional operand for instruction `det`.
/// If the instruction is an x86 instruction, `Some(operand)` is returned.
/// If the instructionset is different, `None` is returned.
fn get_source_operand(det: &InsnDetail) -> Option<X86OperandType> {
    let operands: &[ArchOperand] = &det.arch_detail().operands();
    match operands {
        [_, ArchOperand::X86Operand(operand)] => Some(operand.op_type.clone()),
        _ => None,
    }
}

impl<P, I: Default, F: Default> InvocationFinder<P, I, F>
    for LEABasedDynamicInvocationFinder<P, I, F>
{
    /// Adds all dynamic invocations, either by procedure reference, or vtable reference, to the call graph.
    fn find_invocations(
        &self,
        graph: &mut StableGraph<Rc<RefCell<Procedure<P>>>, Rc<RefCell<Invocation<I, F>>>>,
        proc_index: &mut HashMap<u64, NodeIndex>,
        _call_index: &mut HashMap<u64, NodeIndex>,
        ctx: &Context,
        compilation_info: CompilationInfo,
    ) {
        let nodes_indices = graph.node_indices().collect::<Vec<_>>();

        nodes_indices.iter().for_each(|idx| {
            let prc = graph[*idx].clone();
            let prc = prc.borrow();
            let dest_indices =
                self.find_dynamic_invocations_for_procedure(graph, proc_index, &ctx, &prc);

            self.create_dynamic_edges(
                graph,
                proc_index,
                ctx,
                *idx,
                &dest_indices,
                &compilation_info,
            );
        });
    }
}

#[cfg(test)]
pub mod tests {
    extern crate capstone;
    extern crate elf;
    extern crate gimli;
    extern crate object;
    extern crate test_common;

    use super::*;

    use Context;
    use Crate;

    use addr2line::demangle;
    use addr2line::Context as Addr2LineContext;

    use capstone::arch::BuildsCapstone;
    use capstone::Capstone;

    use gimli::DebugAbbrev;
    use gimli::DebugInfo;
    use gimli::DebugLine;
    use gimli::DebugStr;

    use object::ElfFile;
    use object::File;
    use object::Object;

    use petgraph::graph::NodeIndex;
    use petgraph::Directed;

    use std::collections::hash_map::RandomState;
    use std::collections::HashMap;

    /// Local helper function to create a Context
    fn parse<'a>(file_content: &'a [u8]) -> Context<'a> {
        let elf = ElfFile::parse(&file_content).expect("Failed to parse file content");
        let file = File::parse(&file_content).expect("Failed to parse file content");
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

    /// Adds a node for a specific function in the target binary
    fn add_node(
        name: &str,
        demangled_name: &str,
        graph: &mut StableGraph<Rc<RefCell<Procedure<()>>>, Rc<RefCell<Invocation<(), ()>>>>,
        proc_index: &mut HashMap<u64, NodeIndex>,
        ctx: &Context,
    ) -> NodeIndex {
        // Get symbol of the procedure
        let (address, size) = ctx.elf
            .symbols()
            .filter(|s| s.name().is_some())
            .find(|s| {
                if let Some(dm) = demangle(s.name().unwrap(), gimli::DW_LANG_Rust) {
                    return dm.starts_with(demangled_name);
                }
                false
            })
            .map(|s| (s.address(), s.size()))
            .expect(&format!(
                "No symbol for function main with expected (demangled) name: '{}'",
                demangled_name
            ));

        add_raw_node(name, demangled_name, graph, proc_index, ctx, address, size)
    }

    /// Add a node to the graph with parameter values
    fn add_raw_node(
        name: &str,
        demangled_name: &str,
        graph: &mut StableGraph<
            Rc<RefCell<Procedure<()>>>,
            Rc<RefCell<Invocation<(), ()>>>,
            Directed,
            u32,
        >,
        proc_index: &mut HashMap<u64, NodeIndex<u32>, RandomState>,
        ctx: &Context,
        address: u64,
        size: u64,
    ) -> NodeIndex<u32> {
        // Get code of the procedure
        let text_section = ctx.elf
            .sections()
            .find(|s| s.name() == Some(".text"))
            .unwrap();
        let text_section_address = text_section.address();
        let text_section_data = text_section.data();
        let code = &text_section_data[(address - text_section_address) as usize
                                          ..(address - text_section_address + size) as usize];
        let node = Procedure {
            name: name.to_string(),
            linkage_name: demangled_name.to_string(),
            linkage_name_demangled: name.to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: Some("1.2.3".to_string()),
            },
            location: None,
            start_address: address,
            size,
            attributes: (),
            disassembly: ctx.capstone.disasm_all(code, address).unwrap(),
        };
        let index = graph.add_node(Rc::new(RefCell::new(node)));
        proc_index.insert(address, index);
        index
    }

    fn add_procs_with_name(
        name: &str,
        ctx: &Context,
        mut graph: &mut StableGraph<
            Rc<RefCell<Procedure<()>>>,
            Rc<RefCell<Invocation<(), ()>>>,
            Directed,
            u32,
        >,
        mut proc_index: &mut HashMap<u64, NodeIndex<u32>, RandomState>,
    ) {
        ctx.elf
            .symbols()
            .filter(|sym| {
                sym.name()
                    .and_then(|name| demangle(name, gimli::DW_LANG_Rust))
                    .map(|x| x.contains(name))
                    .unwrap_or(false)
            })
            .enumerate()
            .for_each(|(i, sym)| {
                add_node(
                    &format!("{}_{}", name, i),
                    &demangle(sym.name().unwrap(), gimli::DW_LANG_Rust).unwrap(),
                    &mut graph,
                    &mut proc_index,
                    &ctx,
                );
            });
    }

    /// Disassemble file and find a dynamic call to a parameter with a trait formal type
    #[test]
    pub fn test_find_trait_invocation_calls() {
        // Parse context
        let file_content = &test_common::load_test_binary_as_bytes(
            "trait_invocation",
            &test_common::TestSubjectType::Debug,
        ).unwrap();

        let ctx = parse(&file_content);

        let mut graph = Default::default();
        let mut proc_index = HashMap::new();
        let mut call_index = HashMap::new();

        // Create partial call graph, with three functions
        let main_name_demangled = "trait_invocation::main";
        let qux_name_demangled = "trait_invocation::qux";
        let m5_name_demangled = "<trait_invocation::Foo as trait_invocation::Baz>::m5";
        let m6_name_demangled = "<trait_invocation::Foo as trait_invocation::Baz>::m6";

        let main_index = add_node(
            "main",
            main_name_demangled,
            &mut graph,
            &mut proc_index,
            &ctx,
        );
        let m5_index = add_node("m5", m5_name_demangled, &mut graph, &mut proc_index, &ctx);
        let m6_index = add_node("m6", m6_name_demangled, &mut graph, &mut proc_index, &ctx);
        add_node("qux", qux_name_demangled, &mut graph, &mut proc_index, &ctx);

        // Add all drop_in_place options
        add_procs_with_name("drop_in_place", &ctx, &mut graph, &mut proc_index);

        // Find dynamic invocations
        LEABasedDynamicInvocationFinder::default().find_invocations(
            &mut graph,
            &mut proc_index,
            &mut call_index,
            &ctx,
            CompilationInfo {
                rust_version: "1.0.0",
                compilation_dirs: &[],
            },
        );

        // Assert that 3 dynamic invocations (main -> m5), (main -> m6), (main -> drop_in_place) are found
        assert_eq!(graph.edge_indices().count(), 3);

        let main_m5_edge_index = graph.find_edge(main_index, m5_index);
        let main_m6_edge_index = graph.find_edge(main_index, m6_index);

        // Assert edges from main to m5 and from main to m6 exists
        assert!(main_m5_edge_index.is_some());
        assert!(main_m6_edge_index.is_some());
        // Assert both have invocation type vtable

        let m5_node = graph[main_m5_edge_index.unwrap()].borrow();
        let m6_node = graph[main_m6_edge_index.unwrap()].borrow();

        assert!(!m5_node.frames.is_empty());
        assert!(!m6_node.frames.is_empty());

        assert_eq!(m5_node.invocation_type, InvocationType::VTable);
        assert_eq!(m6_node.invocation_type, InvocationType::VTable);

        let m5_location = &m5_node.frames[0].location;
        let m6_location = &m6_node.frames[0].location;

        // assert file location is set correctly
        assert!(
            m5_location
                .file
                .ends_with("/test_subjects/trait_invocation/src/main.rs")
        );

        assert_eq!(m5_location.line, 30u64);

        assert!(
            m6_location
                .file
                .ends_with("/test_subjects/trait_invocation/src/main.rs")
        );
        assert_eq!(m6_location.line, 30u64);
    }

    /// Disassemble file and find a dynamic call into a capturing procedure
    #[test]
    pub fn test_find_capturing_closure_calls() {
        // Parse context
        let file_content = &test_common::load_test_binary_as_bytes(
            "capturing_closure_invocation",
            &test_common::TestSubjectType::Debug,
        ).unwrap();

        let ctx = parse(&file_content);

        let mut graph = Default::default();
        let mut proc_index = HashMap::new();
        let mut call_index = HashMap::new();

        // Create partial call graph, with three functions
        let main_name_demangled = "capturing_closure_invocation::main";
        let clos_name_demangled = "capturing_closure_invocation::main::{{closure}}";
        let invoke_clos_name_demangled = "capturing_closure_invocation::invoke_clos";

        let main_index = add_node(
            "main",
            main_name_demangled,
            &mut graph,
            &mut proc_index,
            &ctx,
        );
        let clos_index = add_node(
            "main::{{closure}}",
            clos_name_demangled,
            &mut graph,
            &mut proc_index,
            &ctx,
        );
        add_node(
            "invoke_clos",
            invoke_clos_name_demangled,
            &mut graph,
            &mut proc_index,
            &ctx,
        );

        // Add all call_once options
        add_procs_with_name("call_once", &ctx, &mut graph, &mut proc_index);
        // Add all drop_in_place options
        add_procs_with_name("drop_in_place", &ctx, &mut graph, &mut proc_index);

        // Find dynamic invocations
        LEABasedDynamicInvocationFinder::default().find_invocations(
            &mut graph,
            &mut proc_index,
            &mut call_index,
            &ctx,
            CompilationInfo {
                rust_version: "1.0.0",
                compilation_dirs: &[],
            },
        );

        // Assert that the following dynamic invocations are found
        // - (main -> main::{{closure}})
        // - (main -> call_once)
        // - (main -> drop_in_place)
        assert_eq!(graph.edge_indices().count(), 3);

        let main_fn_once_index = graph
            .neighbors(main_index)
            .filter(|x| {
                graph[*x]
                    .borrow()
                    .linkage_name
                    .starts_with("core::ops::function::FnOnce::call_once")
            })
            .nth(0)
            .unwrap();

        let main_clos_edge_index = graph.find_edge(main_index, clos_index);
        let main_fn_once_edge_index = graph.find_edge(main_index, main_fn_once_index);

        // Assert edges from main to closure and from main to call_once exists
        assert!(main_fn_once_edge_index.is_some());
        assert!(main_clos_edge_index.is_some());

        // Assert both have invocation type vtable
        assert_eq!(
            graph[main_fn_once_edge_index.unwrap()]
                .borrow()
                .invocation_type,
            InvocationType::VTable
        );
        assert_eq!(
            graph[main_clos_edge_index.unwrap()]
                .borrow()
                .invocation_type,
            InvocationType::VTable
        );
    }

    /// Disassemble file and find a dynamic call into a trait parameter
    /// Every rust program has such an invocation, from <main> to the crate main
    /// Therefore, we use hello_world for this test
    #[test]
    pub fn test_find_procedure_reference_calls() {
        // Parse context
        let file_content = &test_common::load_test_binary_as_bytes(
            "hello_world",
            &test_common::TestSubjectType::Debug,
        ).unwrap();

        let ctx = parse(&file_content);

        let mut graph = Default::default();
        let mut proc_index = HashMap::new();
        let mut call_index = HashMap::new();

        // Create partial call graph
        let crate_main_name_mangled = "hello_world::main";

        let main_symbol = ctx.elf
            .symbols()
            .find(|sym| sym.name() == Some("main"))
            .unwrap();

        let main_index = add_raw_node(
            "main",
            "main",
            &mut graph,
            &mut proc_index,
            &ctx,
            main_symbol.address(),
            main_symbol.size(),
        );

        let crate_main_index = add_node(
            "hello_world::main",
            crate_main_name_mangled,
            &mut graph,
            &mut proc_index,
            &ctx,
        );

        // Find dynamic invocations
        LEABasedDynamicInvocationFinder::default().find_invocations(
            &mut graph,
            &mut proc_index,
            &mut call_index,
            &ctx,
            CompilationInfo {
                rust_version: "1.0.0",
                compilation_dirs: &[],
            },
        );

        // Assert that dynamic invocation (main -> hello_world::main) is found
        assert_eq!(graph.edge_indices().count(), 1);

        // Assert edges exist
        let main_hello_world_main_edge_index = graph.find_edge(main_index, crate_main_index);
        assert!(main_hello_world_main_edge_index.is_some());

        // Assert have invocation type procedure reference
        assert_eq!(
            graph[main_hello_world_main_edge_index.unwrap()]
                .borrow()
                .invocation_type,
            InvocationType::ProcedureReference
        );
    }
}

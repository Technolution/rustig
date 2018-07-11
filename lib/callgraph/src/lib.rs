// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub extern crate addr2line;
pub extern crate byteorder;
pub extern crate capstone;
extern crate core;
pub extern crate gimli;
pub extern crate object;
pub extern crate petgraph;
#[macro_use]
extern crate error_chain;

mod binary_read;
mod callgraph;
pub mod crate_utils;
pub mod dwarf_utils;
mod parse;
use errors::*;

use addr2line::Context as Addr2LineContext;
use addr2line::Frame as Addr2LineFrame;
use addr2line::Location as Addr2LineLocation;

use capstone::prelude::Capstone;
use capstone::Instructions;

use gimli::DebugAbbrev;
use gimli::DebugInfo;
use gimli::DebugLine;
use gimli::DebugStr;
use gimli::EndianBuf;
use gimli::LittleEndian;
use gimli::RunTimeEndian;

use core::fmt;

use object::ElfFile;

use petgraph::dot::{Config, Dot};
use petgraph::graph::NodeIndex;
use petgraph::prelude::StableGraph;

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::path::Path;
use std::rc::Rc;

/// Struct identifying a particular binary
#[derive(Debug, Clone)]
pub struct Binary<'a> {
    pub path: &'a Path,
}

/// Configuration to be passed to the call-graph builder
#[derive(Debug, Clone)]
pub struct CallGraphOptions<'a> {
    pub binary: Binary<'a>, // And many, many more
}

/// Crate metadata
#[derive(Debug, Clone)]
pub struct Crate {
    /// The name of the crate
    pub name: String,
    // Version of the crate, if known
    pub version: Option<String>,
}

impl Display for Crate {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{}{}",
            self.name,
            self.version
                .as_ref()
                .map_or("".to_string(), |v| format!("@{}", v)),
        )
    }
}

/// Struct representing a procedure in assembly
///
/// Note that it has a type parameter MetaData. This can be used to add custom metadata to the procedure, of which the callgraph library is agnostic.
pub struct Procedure<MetaData> {
    /// Value of DW_AT_name DWARF attribute
    pub name: String,
    /// Value of DW_AT_linkage_name DWARF attribute
    pub linkage_name: String,
    /// Demangled value of DW_AT_linkage_name DWARF attribute
    pub linkage_name_demangled: String,
    pub defining_crate: Crate,
    pub start_address: u64, // Why u64: see Addr entry in https://docs.rs/gimli/0.15.0/gimli/enum.AttributeValue.html
    pub size: u64, // Not pretty sure about this data type yet. On the other hand, it will not be problematic to change it later on
    pub location: Option<Location>,
    pub attributes: MetaData,
    /// Procedure disassembly
    pub disassembly: Instructions,
}

impl<MetaData> Display for Procedure<MetaData> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{} ({})",
            self.linkage_name_demangled, self.defining_crate,
        )
    }
}

impl<MetaData: Debug> Debug for Procedure<MetaData> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "Procedure {{ name: {:x?}, linkage_name: {:x?}, address: {:x?}, crate: {:x?}, attributes: {:x?} }}",
            self.name, self.linkage_name, self.start_address, self.defining_crate, self.attributes
        )
    }
}

/// Invocation metadata
pub struct Invocation<MetaData, InlineFunctionFrameMetaData> {
    pub invocation_type: InvocationType,
    pub frames: Vec<InlineFunctionFrame<InlineFunctionFrameMetaData>>,
    pub instruction_address: u64,
    pub attributes: MetaData,
}

/// `Display` implementation for `Invocation`
/// The width format specifier sets the indentation level in the alternate (pretty) formatting mode
impl<MetaData, InlineFunctionMetaData> Display for Invocation<MetaData, InlineFunctionMetaData> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if f.alternate() {
            let indentation = f.width().unwrap_or(0);
            let mut trace_string = String::new();
            let mut frame_iter = self.frames.iter().rev();
            if let Some(frame) = frame_iter.next() {
                trace_string.push_str(&format!(
                    "{: >indentation$}at {}",
                    "",
                    frame.location,
                    indentation = indentation
                ));
            }
            frame_iter.for_each(|frame| {
                trace_string.push_str(&format!(
                    "\n{: >indentation$}{}",
                    "",
                    frame,
                    indentation = indentation
                ));
            });
            write!(f, "{}", trace_string)
        } else {
            write!(
                f,
                "at {}",
                match self.frames.iter().rev().next() {
                    Some(frame) => frame.location.to_string(),
                    None => "unknown location".to_string(),
                }
            )
        }
    }
}

impl<MetaData: Debug, InlineFunctionFrameMetaData: Debug> Debug
    for Invocation<MetaData, InlineFunctionFrameMetaData>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Invocation {{ invocation_type: {:?}, frames: {:?}, attributes: {:x?} }}",
            self.invocation_type, self.frames, self.attributes
        )
    }
}

/// Struct representing a function frame for functions that may be inlined
#[derive(Debug, Clone)]
pub struct InlineFunctionFrame<InlineFunctionFrameMetaData> {
    pub function_name: String,
    pub location: Location,
    pub defining_crate: Crate,
    pub attributes: InlineFunctionFrameMetaData,
}

impl<InlineFunctionFrameMetaData> Display for InlineFunctionFrame<InlineFunctionFrameMetaData> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "<inline {} at {} >", self.function_name, self.location,)
    }
}

/// Convert an `Addr2LineFrame` (from addr2line crate) to our `InlineFunctionFrame` type.
impl<'a, InlineFunctionFrameMetaData: Default> InlineFunctionFrame<InlineFunctionFrameMetaData> {
    fn convert_frame(
        frame: &Addr2LineFrame<EndianBuf<'a, RunTimeEndian>>,
        compilation_dirs: &[&str],
        rust_version: String,
    ) -> InlineFunctionFrame<InlineFunctionFrameMetaData> {
        InlineFunctionFrame {
            function_name: frame
                .function
                .as_ref()
                .and_then(|mangled_fun| {
                    mangled_fun
                        .demangle()
                        .ok()
                        .map(|demangled_fun| demangled_fun.to_string())
                })
                // Remove hash at the end of the function name
                .map(|fun| {
                    let hash_location = fun.rfind("::").unwrap_or_else(|| fun.chars().count());
                    fun[..hash_location].to_string()
                })
                .unwrap_or_else(|| "unknown_function_name".to_string()),

            // Convert `addr2line::Location` to our `Location` type
            location: frame.location.as_ref().map_or(
                Location {
                    file: "unknown_file".to_string(),
                    line: 0,
                },
                Location::from,
            ),
            defining_crate: crate_utils::get_crate_for_inlined_functions(
                &frame,
                compilation_dirs,
                rust_version,
            ),
            attributes: InlineFunctionFrameMetaData::default(),
        }
    }
}

/// Struct representing the location of a statement in source code
#[derive(Debug, Clone)]
pub struct Location {
    pub file: String,
    pub line: u64,
}

impl Display for Location {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.file, self.line)
    }
}

/// Conversion from `Addr2LineLocation`, so that we can convert to `Location` anywhere in a predicatable way.
impl<'a> From<&'a Addr2LineLocation> for Location {
    fn from(location: &'a Addr2LineLocation) -> Location {
        Location {
            // Convert file option to string
            file: location
                .file
                .as_ref()
                .and_then(|file_path| {
                    file_path
                        .to_str()
                        .and_then(|file_str| Some(file_str.to_string()))
                })
                .unwrap_or_else(|| "unknown_file".to_string()),
            // Copy location line
            line: location.line.unwrap_or(0),
        }
    }
}

impl From<Addr2LineLocation> for Location {
    fn from(location: Addr2LineLocation) -> Location {
        Location::from(&location)
    }
}

/// Call graph of the binary
///
/// Here the nodes represent Procedures in assembly, while the edges represent invocations.
pub struct CallGraph<PMetadata, IMetadata, FMetadata> {
    pub graph: StableGraph<
        Rc<RefCell<Procedure<PMetadata>>>,
        Rc<RefCell<Invocation<IMetadata, FMetadata>>>,
    >,
    /// Index mapping all function start addresses to their respective node index.
    pub proc_index: HashMap<u64, NodeIndex<u32>>,
    /// Index mapping all call and jump instruction addresses to the node index of the procedure they are defined in.
    pub call_index: HashMap<u64, NodeIndex<u32>>,
}

impl<PMetadata, IMetadata, FMetadata> CallGraph<PMetadata, IMetadata, FMetadata> {
    pub fn get_procedure(&self, address: u64) -> Option<Rc<RefCell<Procedure<PMetadata>>>> {
        self.proc_index
            .get(&address)
            .map(|idx| self.graph[idx.to_owned()].clone())
    }
}

impl<PMetadata: Debug, IMetadata: Debug, FMetadata: Debug>
    CallGraph<PMetadata, IMetadata, FMetadata>
{
    /// Return dot representation of the graph
    pub fn dot(
        &self,
    ) -> Dot<
        &StableGraph<
            Rc<RefCell<Procedure<PMetadata>>>,
            Rc<RefCell<Invocation<IMetadata, FMetadata>>>,
        >,
    > {
        Dot::with_config(&self.graph, &[Config::EdgeNoLabel])
    }
}

/// Parsed information about the binary
pub struct Context<'a> {
    pub elf: ElfFile<'a>,
    pub file_context: Addr2LineContext<EndianBuf<'a, RunTimeEndian>>,
    pub dwarf_info: DebugInfo<EndianBuf<'a, LittleEndian>>,
    pub dwarf_abbrev: DebugAbbrev<EndianBuf<'a, LittleEndian>>,
    pub dwarf_strings: DebugStr<EndianBuf<'a, LittleEndian>>,
    pub dwarf_line: DebugLine<EndianBuf<'a, LittleEndian>>,
    pub capstone: Capstone,
}

// `file_context` does not implement `Debug`, so write a custom implementation, omitting that field, here
impl<'a> Debug for Context<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Context {{ elf: {:?}, dwarf_info: {:?}, dwarf_abbrev: {:?}, dwarf_strings: {:?}, dwarf_line: {:?}, capstone: {:?} }}",
               self.elf,
               self.dwarf_info,
               self.dwarf_abbrev,
               self.dwarf_strings,
               self.dwarf_line,
               self.capstone
        )
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum InvocationType {
    Direct,
    ProcedureReference,
    VTable,
    Jump,
}

pub fn read_file(callgraph_options: &CallGraphOptions) -> Result<Vec<u8>> {
    let reader = binary_read::get_reader(&callgraph_options);
    reader.read(&callgraph_options.binary)
}

/// Checks whether the callgraph contains other crates than stdlib.
/// If this is not the case, it means the binary has not been compiled with debug information.
pub fn check_debug_information<PMetadata, IMetadata, FMetadata>(
    callgraph: &CallGraph<PMetadata, IMetadata, FMetadata>,
) -> Result<()> {
    let std_lib_name = "stdlib";
    let number_of_crates = callgraph
        .graph
        .node_indices()
        .map(|node| {
            let node = callgraph.graph[node].borrow();
            node.defining_crate.name.clone()
        })
        .filter(|crate_name| crate_name != std_lib_name)
        .count();

    if number_of_crates == 0 {
        Err(ErrorKind::ParseError(
            "No DWARF debugging information found. Was the binary compiled with debug information enabled?"
                .to_string(),
        ).into())
    } else {
        Ok(())
    }
}

pub fn build_call_graph<
    'a,
    PMetadata: Default + Debug + 'static,
    IMetadata: Default + Debug + 'static,
    FMetadata: Default + Debug + 'static,
>(
    callgraph_options: &'a CallGraphOptions,
    file_content: &'a [u8],
) -> Result<(CallGraph<PMetadata, IMetadata, FMetadata>, Context<'a>)> {
    let parser = parse::get_parser(&callgraph_options);
    let context = parser.parse(&file_content)?;

    let call_graph_builder = callgraph::get_call_graph_builder(&callgraph_options, &context)?;
    let call_graph = call_graph_builder.build_call_graph(&context);

    check_debug_information(&call_graph)?;

    Ok((call_graph, context))
}

// AZ: error_chain uses #[allow(unused_doc_comment)], which has been rename to #[allow(unused_doc_comments)]
#[allow(renamed_and_removed_lints)]
pub mod errors {
    error_chain!{
        errors{
            NotSupported(functionality: String) {
                    description("A binary was passed that requires unimplemented functionality.")
                    display("Analysis aborted: binary contains {}, which is not supported. ", functionality)
            }
            ParseError(reason: String) {
                    description("A file could not be parsed correctly.")
                    display("Unable to parse file: {}", reason)
            }
            ReadError(path: String) {
                    description("A file could not be read correctly.")
                    display("Unable to read file `{}`", path)
            }
            IOError(path: String) {
                    description("Binary file not found.")
                    display("File not found `{}`", path)
            }
        }
    }
}

#[cfg(test)]
mod test {
    extern crate capstone;

    use super::*;

    use std::cell::RefCell;
    use std::rc::Rc;

    use Crate;
    use Procedure;

    use capstone::arch::BuildsCapstone;

    /// Helper function to create a procedure with a given name and crate name
    fn create_procedure_with_name(name: String) -> Procedure<()> {
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
                name: "mycrate".to_string(),
                version: Some("3.0.0".to_string()),
            },
            start_address: 32,
            size: 64,
            location: None,
            attributes: (),
            disassembly: capstone.disasm_all(&empty_vec, 0x1000).unwrap(),
        }
    }

    /// Test implementation `Display` trait for `Location`
    #[test]
    fn test_location_display() {
        let loc = Location {
            file: "src/libstd/panicking.rs".to_string(),
            line: 325,
        };
        assert_eq!(loc.to_string(), "src/libstd/panicking.rs:325");
    }

    /// Test implementation `Display` trait for `InlineFunctionFrame`
    #[test]
    fn test_inline_function_frame_display() {
        let inline_function_frame = InlineFunctionFrame {
            function_name: "core::fmt::Formatter::run".to_string(),
            location: Location {
                file: "src/libcore/fmt/mod.rs".to_string(),
                line: 1096,
            },
            defining_crate: Crate {
                name: "stdlib".to_string(),
                version: Some("1.27.0".to_string()),
            },
            attributes: (),
        };
        assert_eq!(
            inline_function_frame.to_string(),
            "<inline core::fmt::Formatter::run at src/libcore/fmt/mod.rs:1096 >"
        );
    }

    /// Test implementation `Display` trait for `Crate`
    #[test]
    fn test_crate_display() {
        let crate_serde = Crate {
            name: "serde".to_string(),
            version: Some("1.0.64".to_string()),
        };
        let crate_rustig = Crate {
            name: "rustig".to_string(),
            version: None,
        };
        assert_eq!(crate_serde.to_string(), "serde@1.0.64");
        assert_eq!(crate_rustig.to_string(), "rustig");
    }

    /// Test implementation `Display` trait for `Procedure`
    #[test]
    fn test_procedure_display() {
        let procedure = Procedure {
            name: String::new(),
            linkage_name: String::new(),
            linkage_name_demangled: "<core::option::Option<T>>::unwrap".to_string(),
            defining_crate: Crate {
                name: "stdlib".to_string(),
                version: Some("1.27.0".to_string()),
            },
            start_address: 1000,
            size: 200,
            location: None,
            attributes: (),
            disassembly: capstone::Capstone::new()
                .x86()
                .mode(capstone::arch::x86::ArchMode::Mode64)
                .build()
                .unwrap()
                .disasm_all(&vec![], 0)
                .unwrap(),
        };
        assert_eq!(
            procedure.to_string(),
            "<core::option::Option<T>>::unwrap (stdlib@1.27.0)"
        )
    }

    /// Test implementation `Display` trait for `Invocation` with 2 inlined functions
    #[test]
    fn test_invocation_inline_display() {
        let invocation = Invocation {
            invocation_type: InvocationType::Direct,
            instruction_address: 0x136656,
            frames: vec![
                InlineFunctionFrame {
                    function_name: "alloc::slice::hack::to_vec".to_string(),
                    location: Location {
                        file: "/checkout/src/liballoc/slice.rs".to_string(),
                        line: 169,
                    },
                    defining_crate: Crate {
                        name: "stdlib".to_string(),
                        version: Some("1.27.0".to_string()),
                    },
                    attributes: (),
                },
                InlineFunctionFrame {
                    function_name: "alloc::slice::<impl [T]>::to_vec".to_string(),
                    location: Location {
                        file: "/checkout/src/liballoc/slice.rs".to_string(),
                        line: 1770,
                    },
                    defining_crate: Crate {
                        name: "stdlib".to_string(),
                        version: Some("1.27.0".to_string()),
                    },
                    attributes: (),
                },
                InlineFunctionFrame {
                    function_name: "alloc::slice::<impl alloc::borrow::ToOwned for [T]>::to_owned"
                        .to_string(),
                    location: Location {
                        file: "/checkout/src/liballoc/slice.rs".to_string(),
                        line: 1995,
                    },
                    defining_crate: Crate {
                        name: "stdlib".to_string(),
                        version: Some("1.27.0".to_string()),
                    },
                    attributes: (),
                },
            ],
            attributes: (),
        };

        // pretty no indent
        assert_eq!(
            format!("{:#}", invocation),
            "\
             at /checkout/src/liballoc/slice.rs:1995\n\
             <inline alloc::slice::<impl [T]>::to_vec at /checkout/src/liballoc/slice.rs:1770 >\n\
             <inline alloc::slice::hack::to_vec at /checkout/src/liballoc/slice.rs:169 >\
             "
        );

        // pretty indent
        assert_eq!(
            format!("{:#2}", invocation),
            "  \
             at /checkout/src/liballoc/slice.rs:1995\n  \
             <inline alloc::slice::<impl [T]>::to_vec at /checkout/src/liballoc/slice.rs:1770 >\n  \
             <inline alloc::slice::hack::to_vec at /checkout/src/liballoc/slice.rs:169 >\
             "
        );

        // normal
        assert_eq!(
            invocation.to_string(),
            "at /checkout/src/liballoc/slice.rs:1995"
        );
    }

    /// Test implementation `Display` trait for `Invocation` without inlined functions
    #[test]
    fn test_invocation_no_inline_display() {
        let invocation = Invocation {
            invocation_type: InvocationType::Direct,
            instruction_address: 0x136656,
            frames: vec![InlineFunctionFrame {
                function_name: "rust_begin_unwind".to_string(),
                location: Location {
                    file: "/checkout/src/libstd/panicking.rs".to_string(),
                    line: 328,
                },
                defining_crate: Crate {
                    name: "stdlib".to_string(),
                    version: Some("1.27.0".to_string()),
                },
                attributes: (),
            }],
            attributes: (),
        };

        let invocation_string = "at /checkout/src/libstd/panicking.rs:328";
        assert_eq!(invocation.to_string(), invocation_string);

        let invocation_string_indent = "  at /checkout/src/libstd/panicking.rs:328";
        assert_eq!(format!("{:#2}", invocation), invocation_string_indent);
    }

    #[test]
    fn test_dot_output() {
        let procedure_foo = create_procedure_with_name("Foo".to_string());
        let procedure_bar = create_procedure_with_name("Bar".to_string());
        let procedure_baz = create_procedure_with_name("Baz".to_string());

        let mut og = petgraph::stable_graph::StableGraph::new();
        og.add_node(Rc::new(RefCell::new(procedure_foo)));
        og.add_node(Rc::new(RefCell::new(procedure_bar)));
        og.add_node(Rc::new(RefCell::new(procedure_baz)));

        let call_graph: CallGraph<(), (), ()> = CallGraph {
            graph: og,
            proc_index: HashMap::new(),
            call_index: HashMap::new(),
        };

        let dot = call_graph.dot();
        let dot_str = format!("{:?}", dot);

        assert_eq!(dot_str, "digraph {\n    0 [label=\"RefCell { value: Procedure { name: \\\"Foo\\\", linkage_name: \\\"linkage_name\\\", address: 20, crate: Crate { name: \\\"mycrate\\\", version: Some(\\\"3.0.0\\\") }, attributes: () } }\"]\n    1 [label=\"RefCell { value: Procedure { name: \\\"Bar\\\", linkage_name: \\\"linkage_name\\\", address: 20, crate: Crate { name: \\\"mycrate\\\", version: Some(\\\"3.0.0\\\") }, attributes: () } }\"]\n    2 [label=\"RefCell { value: Procedure { name: \\\"Baz\\\", linkage_name: \\\"linkage_name\\\", address: 20, crate: Crate { name: \\\"mycrate\\\", version: Some(\\\"3.0.0\\\") }, attributes: () } }\"]\n}\n");
    }
}

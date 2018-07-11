// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

mod binary;
mod filter;
mod graph_output;
mod marker;
mod panic_calls;
mod patterns;

#[cfg(test)]
pub mod test_utils;

extern crate callgraph;

#[macro_use]
extern crate error_chain;

extern crate gimli;

use callgraph::*;

use callgraph::petgraph::prelude::NodeIndex;
use callgraph::petgraph::stable_graph::StableGraph;
use std::cell::Cell;
use std::cell::RefCell;
use std::rc::Rc;

use errors::*;
use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;

#[derive(Debug, Clone)]
pub enum IntermediateBacktrace {
    UpwardTrace(Vec<NodeIndex<u32>>),
    NoTrace,
}

impl Default for IntermediateBacktrace {
    fn default() -> IntermediateBacktrace {
        IntermediateBacktrace::NoTrace
    }
}

impl IntermediateBacktrace {
    fn into_backtrace_vec(self) -> Vec<NodeIndex<u32>> {
        match self {
            IntermediateBacktrace::UpwardTrace(vec) => vec,
            IntermediateBacktrace::NoTrace => vec![],
        }
    }
}

#[derive(Debug, Clone)]
/// Enum for defining the crate version for which a function should be whitelisted.
pub enum FunctionWhitelistCrateVersion {
    /// Matching crate if version parameter matches crate version.
    Strict(String),
    /// Matching crate if version parameter matches crate version, _or the crate version is not known_.
    Loose(String),
    /// Match any crate version.
    None,
}

impl FunctionWhitelistCrateVersion {
    /// Helper function that checks if `FunctionWhitelistCrateVersion` instance matches an (optional) version
    fn matches_version(&self, version: &Option<String>) -> bool {
        match self {
            &FunctionWhitelistCrateVersion::None => true,
            FunctionWhitelistCrateVersion::Strict(ref self_version) => {
                version.as_ref().map(|v| self_version == v).unwrap_or(false)
            }
            FunctionWhitelistCrateVersion::Loose(ref self_version) => {
                version.as_ref().map(|v| self_version == v).unwrap_or(true)
            }
        }
    }
}

/// Entry for maintaining function whitelist data
#[derive(Debug, Clone)]
pub struct FunctionWhiteListEntry {
    /// The name of the function to whitelist.
    ///
    /// This name may include namespaces. However, both the name and the namespace should be complete.
    /// For example, if a function has name `core::fmt::format`, the names `format`, `fmt::format` and `core::fmt::format` would match,
    /// but `ormat` or `mt::format` would not.
    pub function_name: String,
    /// The version filter of the crate.
    ///
    /// If no version filter is needed, use `FunctionWhitelistCrateVersion::None`.
    pub crate_name: Option<String>,
    pub crate_version: FunctionWhitelistCrateVersion,
}

fn fn_names_match(filter_name: &str, procedure_name: &str) -> bool {
    procedure_name.ends_with(&format!("::{}", &filter_name)) || procedure_name == filter_name
}

impl FunctionWhiteListEntry {
    /// Function that checks if an `FunctionWhiteList` matches a `Procedure`
    fn matches_procedure<P>(&self, prc: &Procedure<P>) -> bool {
        // Compare by linkage name, since it contains more information than name
        // e.g. name can be `new`: then it is not clear on which struct it was defined.
        if !fn_names_match(&self.function_name, &prc.linkage_name_demangled) {
            return false;
        }

        // If no crate specified, return true
        if self.crate_name.is_none() {
            return true;
        }

        if self.crate_name.as_ref().unwrap() != &prc.defining_crate.name {
            return false;
        }

        self.crate_version
            .matches_version(&prc.defining_crate.version)
    }
    /// Function that checks if an `FunctionWhiteList` matches an `Invocation` from a given `Procedure`
    fn matches_invocation<P, I, F>(
        &self,
        caller: &Procedure<P>,
        invocation: &Invocation<I, F>,
    ) -> bool {
        // Iterate all frames, to see if a function matches
        if !invocation
            .frames
            .iter()
            .any(|frame| fn_names_match(&self.function_name, &frame.function_name))
        {
            return false;
        }
        // If no crate specified, return true
        if self.crate_name.is_none() {
            return true;
        }

        if self.crate_name.as_ref().unwrap() != &caller.defining_crate.name {
            return false;
        }

        self.crate_version
            .matches_version(&caller.defining_crate.version)
    }
}

/// Struct containing all the options that can be passed to [find_panics].
///
/// For more information on the effect of certain options, see the command line options for the equally named options in the [cli documentation](index.html#options).
#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    /// The path to the binary we want to analyze.
    ///
    /// This is an `Option`, because we might implement building a cargo project itself. However, for now, the library will return an error if it is set to `None`.
    pub binary_path: Option<String>,
    /// The list of crates which belong to the analysis target.
    pub crate_names: Vec<String>,
    /// Flag indicating if all functions in the analysis target should be checked
    pub full_crate_analysis: bool,
    /// If `true`, the unfiltered callgraph will be written to a dot file in the present working directory
    pub output_full_callgraph: bool,
    /// If `true`, the filtered callgraph will be written to a dot file in the present working directory. This call graph will only contain nodes that eventually lead to a panic
    pub output_filtered_callgraph: bool,
    /// List of whitelisted functions.
    pub whitelisted_functions: Vec<FunctionWhiteListEntry>, // Add all options to the tool here :-)
                                                            // Make sure to implement correct argument parsing in /bin/cli as well
}

/// Metadata to incorporate in the call graph nodes
#[derive(Debug, Clone, Default)]
pub struct RDPProcedureMetaData {
    /// Flag indicating if the procedure should be analyzed for paths to panic
    pub analysis_target: Cell<bool>,
    /// Flag indicating if the procedure is an analysis entry point
    pub entry_point: Cell<bool>,
    /// Flag indicating if the procedure leads to a panic
    pub is_panic: Cell<bool>,
    /// Flag indicating if the procedure itself is the cause of a panic (e.g., begin_panic())
    pub is_panic_origin: Cell<bool>,
    /// Backtrace from a procedure to the nearest panic
    pub intermediate_panic_calls: RefCell<IntermediateBacktrace>,
    /// Flag indicating a procedure has been visited during the panic flag algorithm
    pub visited: Cell<bool>,
    /// Flag indicating if the function is whitelisted
    pub whitelisted: Cell<bool>,
    /// Flag indicating if a node is reachable from an entry point, without going through an whitelisted node
    pub reachable_from_entry_point: Cell<bool>,
}

/// Metadata on the inline function frames.
#[derive(Debug, Clone, Default)]
pub struct RDPInlineFrameMetaData {
    /// Flag indicating if the procedure should be analyzed for paths to panic
    pub analysis_target: Cell<bool>,
}

/// Metadata to incorporate in the call graph edges
#[derive(Debug, Clone, Default)]
pub struct RDPInvocationMetaData {
    /// Flag that is set when a whitelist filter matches an inline frame of this invocation
    pub whitelisted: Cell<bool>,
}

#[derive(Debug, Clone)]
pub struct BackTraceEntry {
    pub procedure: Rc<RefCell<Procedure<RDPProcedureMetaData>>>,
    pub outgoing_invocation:
        Option<Rc<RefCell<Invocation<RDPInvocationMetaData, RDPInlineFrameMetaData>>>>,
}

impl Display for BackTraceEntry {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let indentation = f.width().unwrap_or(0);
        write!(
            f,
            "{}{}",
            self.procedure.borrow(),
            match self.outgoing_invocation {
                Some(ref inv) => format!(
                    "\n{:#indentation$}",
                    inv.borrow(),
                    indentation = indentation
                ),
                None => "".to_string(),
            }
        )
    }
}

/// Struct containing information about a possible path to a panic call
#[derive(Debug, Clone)]
pub struct PanicCall {
    /// Information where the panic call originates from, in pairs of (procedure, outgoing invocation to next procedure)
    pub backtrace: Vec<BackTraceEntry>,
    /// The reason for this panic call
    pub pattern: RefCell<PanicPattern>,
    /// Boolean value telling whether the `backtrace` of this `PanicCall` contains 1 or more dynamic invocations
    pub contains_dynamic_invocation: bool,
    /// Message that is passed to this panic, if known.
    pub message: Option<String>,
}

impl Display for PanicCall {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if f.alternate() {
            let mut call_string = format!(
                "-- Pattern: {:?}{}{}\n\n",
                self.pattern.borrow(),
                if self.contains_dynamic_invocation {
                    " -- Trace contains dynamic invocation(s)"
                } else {
                    ""
                },
                self.message
                    .as_ref()
                    .map_or("".to_string(), |msg| format!(" -- Message: '{}'", msg))
            );
            for (i, entry) in self.backtrace.iter().enumerate() {
                call_string.push_str(&format!("{:2}: {:#6}\n", i, entry));
            }
            write!(f, "{}", call_string)
        } else if self.backtrace.len() >= 2 {
            write!(
                f,
                "{} calls {} {}",
                self.backtrace[0].procedure.borrow(),
                self.backtrace[1].procedure.borrow(),
                match self.backtrace[0].outgoing_invocation {
                    Some(ref inv) => inv.borrow().to_string(),
                    None => "at unknown location".to_string(),
                },
            )
        } else {
            // This should never happen, as backtraces are created with at least 2 entries
            write!(f, "Trace of panic call consisted out of 1 or less procedures and could not be displayed")
        }
    }
}

#[derive(Debug, Clone)]
pub struct PanicCallsCollection {
    pub calls: Vec<PanicCall>,
}

/// Enum representing different explicit pattern we can recognize in the call graph.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PanicPattern {
    /// Default: Indicates no patterns was recognized in the _panic_ trace.
    Unrecognized,
    /// The `panic!` macro, or one of its derivatives, like `assert!` or `unreachable!` were used in analysis target code.
    DirectCall,
    /// The panic is caused by an overflow/underflow check.
    Arithmetic,
    /// The panic is caused by a call to `Result::unwrap`, `Result::expect`, `Option::unwrap` or `Option::expect`.
    Unwrap,
    /// The panic is caused by an array index.
    Indexing,
}

pub type RustigGraph = StableGraph<
    Rc<RefCell<Procedure<RDPProcedureMetaData>>>,
    Rc<RefCell<Invocation<RDPInvocationMetaData, RDPInlineFrameMetaData>>>,
>;
pub type RustigCallGraph =
    CallGraph<RDPProcedureMetaData, RDPInvocationMetaData, RDPInlineFrameMetaData>;

/// Main entry point of the `panic_analysis` crate.
///
/// This function accepts some options [AnalysisOptions](struct.AnalysisOptions.html), and returns a [PanicCallsCollection](struct.PanicCallsCollection.html) as output.
///
/// This PanicCallsCollection contains all traces to _panic_ ([PanicCall](struct.PanicCall.html)) that were found in the binary.
///
/// This function can be used in conjunction with [print_results](../panic_calls_output/fn.print_results.html) in [panic_call_output](../panic_calls_output/index.html) to format and print results.
///
/// # Errors
/// * If [`options`.binary_path](struct.AnalysisOptions.html#structfield.binary_path) is `None`.
/// * If the file to be analyzed was not found, or could not be read.
/// * If the file is not a valid x86 or x86_64 ELF file.
///
pub fn find_panics(options: &AnalysisOptions) -> Result<PanicCallsCollection> {
    let builder = binary::get_builder(&options)?;

    let markers = marker::get_code_markers(&options);
    let filters = filter::get_node_filters(&options);

    let panic_calls_finder = panic_calls::get_panic_call_finder(&options);
    let pattern_finder = patterns::get_pattern_finder(&options);

    let graph_output_full = graph_output::get_graph_output_full(&options);
    let graph_output_filtered = graph_output::get_graph_output_filtered(&options);

    // Build and parse binary
    let binary = builder.build()?;

    // Create callgraph
    let cg_options = CallGraphOptions { binary };
    let file_content = &callgraph::read_file(&cg_options)?;
    let (mut call_graph, context): (RustigCallGraph, Context) =
        callgraph::build_call_graph(&cg_options, file_content)?;

    graph_output_full.write_graph(&call_graph);

    markers.mark_code(&call_graph, &context);
    filters.filter_nodes(&mut call_graph, &context);

    graph_output_filtered.write_graph(&call_graph);

    // Detect panic calls
    let panic_calls = panic_calls_finder.find_panics(&call_graph, &context);

    // Find patterns in call graph
    pattern_finder.find_patterns(&context, &panic_calls);

    Ok(panic_calls)
}

// AZ: error_chain uses #[allow(unused_doc_comment)], which has been rename to #[allow(unused_doc_comments)]
#[allow(renamed_and_removed_lints)]
pub mod errors {
    error_chain!{
        links {
            CallGraph(::callgraph::errors::Error, ::callgraph::errors::ErrorKind);
        }

        errors {
            IOError(path: String) {
                        description("Binary file not found.")
                        display("File not found `{}`", path)
                }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate capstone;

    use super::*;
    use callgraph::InlineFunctionFrame;
    use callgraph::Procedure;
    use tests::capstone::arch::BuildsCapstone;
    use tests::capstone::prelude::Capstone;
    use RDPProcedureMetaData;

    /// Test implementation `Display` trait for `BacktraceEntry` without outgoing invocation
    #[test]
    fn test_backtrace_entry_display() {
        let entry = BackTraceEntry {
            procedure: Rc::new(RefCell::new(Procedure {
                name: "panic".to_string(),
                linkage_name: "panic12345".to_string(),
                linkage_name_demangled: "std::panicking::begin_panic_fmt".to_string(),
                defining_crate: Crate {
                    name: "stdlib".to_string(),
                    version: Some("1.27.0".to_string()),
                },
                start_address: 0x1240,
                size: 0x40,
                location: None,
                attributes: RDPProcedureMetaData::default(),
                disassembly: capstone::Capstone::new()
                    .x86()
                    .mode(capstone::arch::x86::ArchMode::Mode64)
                    .build()
                    .unwrap()
                    .disasm_all(&vec![], 0x1240)
                    .unwrap(),
            })),
            outgoing_invocation: None,
        };
        assert_eq!(
            entry.to_string(),
            "std::panicking::begin_panic_fmt (stdlib@1.27.0)"
        )
    }

    /// Test implementation `Display` trait for `BacktraceEntry` with outgoing invocation
    #[test]
    fn test_backtrace_entry_display_outgoing() {
        let entry = BackTraceEntry {
            procedure: Rc::new(RefCell::new(Procedure {
                name: "from".to_string(),
                linkage_name: "alloc::from12345".to_string(),
                linkage_name_demangled:
                    "<alloc::string::String as core::convert::From<&'a str>>::from".to_string(),
                defining_crate: Crate {
                    name: "stdlib".to_string(),
                    version: Some("1.27.0".to_string()),
                },
                start_address: 0x1240,
                size: 0x40,
                location: None,
                attributes: RDPProcedureMetaData::default(),
                disassembly: capstone::Capstone::new()
                    .x86()
                    .mode(capstone::arch::x86::ArchMode::Mode64)
                    .build()
                    .unwrap()
                    .disasm_all(&vec![], 0x1240)
                    .unwrap(),
            })),
            outgoing_invocation: Some(Rc::new(RefCell::new(Invocation {
                instruction_address: 0x144562,
                invocation_type: InvocationType::Direct,
                frames: vec![
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
                        attributes: RDPInlineFrameMetaData::default(),
                    },
                    InlineFunctionFrame {
                        function_name:
                            "alloc::slice::<impl alloc::borrow::ToOwned for [T]>::to_owned"
                                .to_string(),
                        location: Location {
                            file: "/checkout/src/liballoc/slice.rs".to_string(),
                            line: 1995,
                        },
                        defining_crate: Crate {
                            name: "stdlib".to_string(),
                            version: Some("1.27.0".to_string()),
                        },
                        attributes: RDPInlineFrameMetaData::default(),
                    },
                ],
                attributes: RDPInvocationMetaData::default(),
            }))),
        };
        assert_eq!(
            format!("{:#4}", entry), "\
            <alloc::string::String as core::convert::From<&'a str>>::from (stdlib@1.27.0)\
            \n    at /checkout/src/liballoc/slice.rs:1995\
            \n    <inline alloc::slice::<impl [T]>::to_vec at /checkout/src/liballoc/slice.rs:1770 >\
            "
        )
    }

    /// Test to ensure that an unspecified version filter matches an unspecified version
    #[test]
    fn fn_whitelist_none_matches_none() {
        let wlv = FunctionWhitelistCrateVersion::None;
        assert!(wlv.matches_version(&None))
    }

    /// Test to ensure that an unspecified version filter matches an specified version
    #[test]
    fn fn_whitelist_none_matches_some() {
        let wlv = FunctionWhitelistCrateVersion::None;
        assert!(wlv.matches_version(&Some("1.2.3".to_string())))
    }

    /// Test to ensure that an loose version filter matches an unspecified version
    #[test]
    fn fn_whitelist_loose_matches_none() {
        let wlv = FunctionWhitelistCrateVersion::Loose("1.2.3".to_string());
        assert!(wlv.matches_version(&None))
    }

    /// Test to ensure that a loose version filter matches a specified version if the versions are equal
    #[test]
    fn fn_whitelist_loose_matches_some_equal() {
        let wlv = FunctionWhitelistCrateVersion::Loose("1.2.3".to_string());
        assert!(wlv.matches_version(&Some("1.2.3".to_string())))
    }

    /// Test to ensure that a loose version filter does not match a specified version if the versions do not match
    #[test]
    fn fn_whitelist_loose_not_matches_some_different() {
        let wlv = FunctionWhitelistCrateVersion::Loose("1.2.3".to_string());
        assert!(!wlv.matches_version(&Some("1.2.4".to_string())))
    }

    /// Test to ensure that a strict version filter does not match an unspecified version
    #[test]
    fn fn_whitelist_strict_matches_none() {
        let wlv = FunctionWhitelistCrateVersion::Strict("1.2.3".to_string());
        assert!(!wlv.matches_version(&None))
    }

    /// Test to ensure that a strict version filter does matches a specified version if the versions are equal
    #[test]
    fn fn_whitelist_strict_matches_some_equal() {
        let wlv = FunctionWhitelistCrateVersion::Strict("1.2.3".to_string());
        assert!(wlv.matches_version(&Some("1.2.3".to_string())))
    }

    /// Test to ensure that a strict version filter does not match a specified version if the versions are not equal
    #[test]
    fn fn_whitelist_strict_not_matches_some_different() {
        let wlv = FunctionWhitelistCrateVersion::Strict("1.2.3".to_string());
        assert!(!wlv.matches_version(&Some("1.2.4".to_string())))
    }

    /// Test to ensure that a `FunctionWhiteListEntry` does not match a `Procedure` if the names differ
    #[test]
    fn fn_whitelist_not_matching_different_name() {
        let capstone = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");

        let prc = Procedure {
            name: "some_name".to_string(),
            linkage_name: "linkage_name".to_string(),
            linkage_name_demangled: "linkage_name_demangled".to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: None,
            },
            start_address: 0x1240,
            size: 0x40,
            location: None,
            attributes: (),
            disassembly: capstone.disasm_all(&[], 0x1240).unwrap(),
        };

        let whitelist_filter = FunctionWhiteListEntry {
            function_name: "other_name".to_string(),
            crate_name: Some("crate".to_string()),
            crate_version: FunctionWhitelistCrateVersion::None,
        };

        assert!(!whitelist_filter.matches_procedure(&prc));
    }

    /// Test to ensure that a `FunctionWhiteListEntry` does not match a `Procedure`
    /// if the name is not fully given
    #[test]
    fn fn_whitelist_not_matching_invalid_suffix() {
        let capstone = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");

        let prc = Procedure {
            name: "some_name".to_string(),
            linkage_name: "a::b::name".to_string(),
            linkage_name_demangled: "linkage_name_demangled".to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: None,
            },
            start_address: 0x1240,
            size: 0x40,
            location: None,
            attributes: (),
            disassembly: capstone.disasm_all(&[], 0x1240).unwrap(),
        };

        let whitelist_filter = FunctionWhiteListEntry {
            function_name: "ame".to_string(),
            crate_name: Some("crate".to_string()),
            crate_version: FunctionWhitelistCrateVersion::None,
        };

        assert!(!whitelist_filter.matches_procedure(&prc));
    }

    /// Test to ensure that a `FunctionWhiteListEntry` matches a `Procedure`
    /// when the full name is given
    #[test]
    fn fn_whitelist_matching_valid_suffix() {
        let capstone = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");

        let prc = Procedure {
            name: "some_name".to_string(),
            linkage_name: "a::b::name".to_string(),
            linkage_name_demangled: "a::b::name".to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: None,
            },
            start_address: 0x1240,
            size: 0x40,
            location: None,
            attributes: (),
            disassembly: capstone.disasm_all(&[], 0x1240).unwrap(),
        };

        let whitelist_filter = FunctionWhiteListEntry {
            function_name: "name".to_string(),
            crate_name: Some("crate".to_string()),
            crate_version: FunctionWhitelistCrateVersion::None,
        };

        assert!(whitelist_filter.matches_procedure(&prc));
    }

    /// Test to ensure that a `FunctionWhiteListEntry` matches a `Procedure`
    /// when the no crate name is geven
    #[test]
    fn fn_whitelist_matching_no_crate() {
        let capstone = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");

        let prc = Procedure {
            name: "some_name".to_string(),
            linkage_name: "a::b::name".to_string(),
            linkage_name_demangled: "a::b::name".to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: None,
            },
            start_address: 0x1240,
            size: 0x40,
            location: None,
            attributes: (),
            disassembly: capstone.disasm_all(&[], 0x1240).unwrap(),
        };

        let whitelist_filter = FunctionWhiteListEntry {
            function_name: "name".to_string(),
            crate_name: None,
            crate_version: FunctionWhitelistCrateVersion::None,
        };

        assert!(whitelist_filter.matches_procedure(&prc));
    }

    /// Test to ensure that a `FunctionWhiteListEntry` matches a `Procedure`
    /// when the full name with a module is given
    #[test]
    fn fn_whitelist_matching_full_name() {
        let capstone = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");

        let prc = Procedure {
            name: "some_name".to_string(),
            linkage_name: "a::b::name".to_string(),
            linkage_name_demangled: "a::b::name".to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: None,
            },
            start_address: 0x1240,
            size: 0x40,
            location: None,
            attributes: (),
            disassembly: capstone.disasm_all(&[], 0x1240).unwrap(),
        };

        let whitelist_filter = FunctionWhiteListEntry {
            function_name: "b::name".to_string(),
            crate_name: Some("crate".to_string()),
            crate_version: FunctionWhitelistCrateVersion::None,
        };

        assert!(whitelist_filter.matches_procedure(&prc));
    }

    /// Test to ensure that a `FunctionWhiteListEntry` matches a `Procedure`
    /// when the full name with all modules is given
    #[test]
    fn fn_whitelist_matching_invalid_full_suffix() {
        let capstone = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");

        let prc = Procedure {
            name: "some_name".to_string(),
            linkage_name: "a::b::name".to_string(),
            linkage_name_demangled: "a::b::name".to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: None,
            },
            start_address: 0x1240,
            size: 0x40,
            location: None,
            attributes: (),
            disassembly: capstone.disasm_all(&[], 0x1240).unwrap(),
        };

        let whitelist_filter = FunctionWhiteListEntry {
            function_name: "a::b::name".to_string(),
            crate_name: Some("crate".to_string()),
            crate_version: FunctionWhitelistCrateVersion::None,
        };

        assert!(whitelist_filter.matches_procedure(&prc));
    }

    /// Test to ensure that a `FunctionWhiteListEntry` does not match a `Procedure`
    /// when the a different crate name is given
    #[test]
    fn fn_whitelist_not_matching_different_crate() {
        let capstone = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");

        let prc = Procedure {
            name: "name".to_string(),
            linkage_name: "linkage_name".to_string(),
            linkage_name_demangled: "linkage_name_demangled".to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: None,
            },
            start_address: 0x1240,
            size: 0x40,
            location: None,
            attributes: (),
            disassembly: capstone.disasm_all(&[], 0x1240).unwrap(),
        };

        let whitelist_filter = FunctionWhiteListEntry {
            function_name: "name".to_string(),
            crate_name: Some("other_crate".to_string()),
            crate_version: FunctionWhitelistCrateVersion::None,
        };

        assert!(!whitelist_filter.matches_procedure(&prc));
    }

    /// Test to ensure that a `FunctionWhiteListEntry` does not match a `Procedure`
    /// when a different version is specified
    #[test]
    fn fn_whitelist_not_matching_different_version() {
        let capstone = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");

        let prc = Procedure {
            name: "name".to_string(),
            linkage_name: "linkage_name".to_string(),
            linkage_name_demangled: "linkage_name_demangled".to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: Some("1.2.3".to_string()),
            },
            start_address: 0x1240,
            size: 0x40,
            location: None,
            attributes: (),
            disassembly: capstone.disasm_all(&[], 0x1240).unwrap(),
        };

        let whitelist_filter = FunctionWhiteListEntry {
            function_name: "name".to_string(),
            crate_name: Some("crate".to_string()),
            crate_version: FunctionWhitelistCrateVersion::Loose("1.2.4".to_string()),
        };

        assert!(!whitelist_filter.matches_procedure(&prc));
    }

    /// Test to ensure that a `FunctionWhiteListEntry` does not match a `Procedure`
    /// when all fields are matching
    #[test]
    fn fn_whitelist_matching_same_version() {
        let capstone = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");

        let prc = Procedure {
            name: "name".to_string(),
            linkage_name: "linkage_name::name".to_string(),
            linkage_name_demangled: "linkage_name_demangled::name".to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: Some("1.2.3".to_string()),
            },
            start_address: 0x1240,
            size: 0x40,
            location: None,
            attributes: (),
            disassembly: capstone.disasm_all(&[], 0x1240).unwrap(),
        };

        let whitelist_filter = FunctionWhiteListEntry {
            function_name: "name".to_string(),
            crate_name: Some("crate".to_string()),
            crate_version: FunctionWhitelistCrateVersion::Loose("1.2.3".to_string()),
        };

        assert!(whitelist_filter.matches_procedure(&prc));
    }

    /// Test to ensure that a `FunctionWhiteListEntry` does not match a `Procedure` if the names differ
    #[test]
    fn fn_inv_whitelist_not_matching_different_name() {
        let capstone = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");

        let prc = Procedure {
            name: "some_name".to_string(),
            linkage_name: "linkage_name".to_string(),
            linkage_name_demangled: "linkage_name_demangled".to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: None,
            },
            start_address: 0x1240,
            size: 0x40,
            location: None,
            attributes: (),
            disassembly: capstone.disasm_all(&[], 0x1240).unwrap(),
        };

        let inv = Invocation {
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
                    version: None,
                },
                attributes: (),
            }],
            attributes: (),
        };

        let whitelist_filter = FunctionWhiteListEntry {
            function_name: "other_name".to_string(),
            crate_name: Some("crate".to_string()),
            crate_version: FunctionWhitelistCrateVersion::None,
        };

        assert!(!whitelist_filter.matches_invocation(&prc, &inv));
    }

    /// Test to ensure that a `FunctionWhiteListEntry` does not match a `Procedure`
    /// if the name is not fully given
    #[test]
    fn fn_inv_whitelist_not_matching_invalid_suffix() {
        let capstone = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");

        let prc = Procedure {
            name: "some_name".to_string(),
            linkage_name: "a::b::name".to_string(),
            linkage_name_demangled: "linkage_name_demangled".to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: None,
            },
            start_address: 0x1240,
            size: 0x40,
            location: None,
            attributes: (),
            disassembly: capstone.disasm_all(&[], 0x1240).unwrap(),
        };

        let inv = Invocation {
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
                    version: None,
                },
                attributes: (),
            }],
            attributes: (),
        };

        let whitelist_filter = FunctionWhiteListEntry {
            function_name: "ine_func".to_string(),
            crate_name: Some("crate".to_string()),
            crate_version: FunctionWhitelistCrateVersion::None,
        };

        assert!(!whitelist_filter.matches_invocation(&prc, &inv));
    }

    /// Test to ensure that a `FunctionWhiteListEntry` matches a `Procedure`
    /// when the full name is given
    #[test]
    fn fn_inv_whitelist_matching_valid_suffix() {
        let capstone = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");

        let prc = Procedure {
            name: "some_name".to_string(),
            linkage_name: "a::b::name".to_string(),
            linkage_name_demangled: "a::b::name".to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: None,
            },
            start_address: 0x1240,
            size: 0x40,
            location: None,
            attributes: (),
            disassembly: capstone.disasm_all(&[], 0x1240).unwrap(),
        };

        let inv = Invocation {
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
                    version: None,
                },
                attributes: (),
            }],
            attributes: (),
        };

        let whitelist_filter = FunctionWhiteListEntry {
            function_name: "inline_func".to_string(),
            crate_name: Some("crate".to_string()),
            crate_version: FunctionWhitelistCrateVersion::None,
        };

        assert!(whitelist_filter.matches_invocation(&prc, &inv));
    }

    /// Test to ensure that a `FunctionWhiteListEntry` matches a `Procedure`
    /// when the full name with a module is given
    #[test]
    fn fn_inv_whitelist_matching_full_name() {
        let capstone = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");

        let prc = Procedure {
            name: "some_name".to_string(),
            linkage_name: "a::b::name".to_string(),
            linkage_name_demangled: "a::b::name".to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: None,
            },
            start_address: 0x1240,
            size: 0x40,
            location: None,
            attributes: (),
            disassembly: capstone.disasm_all(&[], 0x1240).unwrap(),
        };

        let inv = Invocation {
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
                    version: None,
                },
                attributes: (),
            }],
            attributes: (),
        };

        let whitelist_filter = FunctionWhiteListEntry {
            function_name: "mod2::inline_func".to_string(),
            crate_name: Some("crate".to_string()),
            crate_version: FunctionWhitelistCrateVersion::None,
        };

        assert!(whitelist_filter.matches_invocation(&prc, &inv));
    }

    /// Test to ensure that a `FunctionWhiteListEntry` matches a `Procedure`
    /// when the full name with all modules is given
    #[test]
    fn fn_inv_whitelist_matching_invalid_full_suffix() {
        let capstone = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");

        let prc = Procedure {
            name: "some_name".to_string(),
            linkage_name: "a::b::name".to_string(),
            linkage_name_demangled: "a::b::name".to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: None,
            },
            start_address: 0x1240,
            size: 0x40,
            location: None,
            attributes: (),
            disassembly: capstone.disasm_all(&[], 0x1240).unwrap(),
        };

        let inv = Invocation {
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
                    version: None,
                },
                attributes: (),
            }],
            attributes: (),
        };

        let whitelist_filter = FunctionWhiteListEntry {
            function_name: "mod1::mod2::inline_func".to_string(),
            crate_name: Some("crate".to_string()),
            crate_version: FunctionWhitelistCrateVersion::None,
        };

        assert!(whitelist_filter.matches_invocation(&prc, &inv));
    }

    /// Test to ensure that a `FunctionWhiteListEntry` does not match a `Procedure`
    /// when the a different crate name is given
    #[test]
    fn fn_inv_whitelist_not_matching_different_crate() {
        let capstone = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");

        let prc = Procedure {
            name: "name".to_string(),
            linkage_name: "linkage_name".to_string(),
            linkage_name_demangled: "linkage_name_demangled".to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: None,
            },
            start_address: 0x1240,
            size: 0x40,
            location: None,
            attributes: (),
            disassembly: capstone.disasm_all(&[], 0x1240).unwrap(),
        };

        let inv = Invocation {
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
                    version: None,
                },
                attributes: (),
            }],
            attributes: (),
        };

        let whitelist_filter = FunctionWhiteListEntry {
            function_name: "inline_func".to_string(),
            crate_name: Some("other_crate".to_string()),
            crate_version: FunctionWhitelistCrateVersion::None,
        };

        assert!(!whitelist_filter.matches_invocation(&prc, &inv));
    }

    /// Test to ensure that a `FunctionWhiteListEntry` does not match a `Procedure`
    /// when a different version is specified
    #[test]
    fn fn_inv_whitelist_not_matching_different_version() {
        let capstone = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");

        let prc = Procedure {
            name: "name".to_string(),
            linkage_name: "linkage_name".to_string(),
            linkage_name_demangled: "linkage_name_demangled".to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: Some("1.2.3".to_string()),
            },
            start_address: 0x1240,
            size: 0x40,
            location: None,
            attributes: (),
            disassembly: capstone.disasm_all(&[], 0x1240).unwrap(),
        };

        let inv = Invocation {
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
                    version: None,
                },
                attributes: (),
            }],
            attributes: (),
        };

        let whitelist_filter = FunctionWhiteListEntry {
            function_name: "name".to_string(),
            crate_name: Some("crate".to_string()),
            crate_version: FunctionWhitelistCrateVersion::Loose("1.2.4".to_string()),
        };

        assert!(!whitelist_filter.matches_invocation(&prc, &inv));
    }

    /// Test to ensure that a `FunctionWhiteListEntry` does not match a `Procedure`
    /// when all fields are matching
    #[test]
    fn fn_inv_whitelist_matching_same_version() {
        let capstone = Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");

        let prc = Procedure {
            name: "name".to_string(),
            linkage_name: "linkage_name::name".to_string(),
            linkage_name_demangled: "linkage_name_demangled::name".to_string(),
            defining_crate: Crate {
                name: "crate".to_string(),
                version: Some("1.2.3".to_string()),
            },
            start_address: 0x1240,
            size: 0x40,
            location: None,
            attributes: (),
            disassembly: capstone.disasm_all(&[], 0x1240).unwrap(),
        };

        let inv = Invocation {
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
                    version: None,
                },
                attributes: (),
            }],
            attributes: (),
        };

        let whitelist_filter = FunctionWhiteListEntry {
            function_name: "inline_func".to_string(),
            crate_name: Some("crate".to_string()),
            crate_version: FunctionWhitelistCrateVersion::Loose("1.2.3".to_string()),
        };

        assert!(whitelist_filter.matches_invocation(&prc, &inv));
    }
}

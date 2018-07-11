// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use callgraph;
use callgraph::addr2line::Context as Addr2LineContext;
use callgraph::capstone::arch::BuildsCapstone;
use callgraph::capstone::Capstone;
use callgraph::gimli::{DebugAbbrev, DebugInfo, DebugLine, DebugStr, EndianBuf, LittleEndian};
use callgraph::object::{ElfFile, File as ObjectFile, Object};
use callgraph::Context;

/// Parse the contents of a file into a callgraph::Context
pub fn parse_context(file_content: &[u8]) -> Context {
    let elf = ElfFile::parse(&file_content).expect("Failed to parse file content");
    let file =
        ObjectFile::parse(&file_content).expect("Failed to parse file content to File format");
    let file_context = Addr2LineContext::new(&file).expect("Could not construct context from file");

    let mode = callgraph::capstone::arch::x86::ArchMode::Mode64;

    let (dwarf_info, dwarf_abbrev, dwarf_strings, dwarf_line) = parse_debug_info(&elf);

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

/// Extracts various different types of DWARF debugging information.
fn parse_debug_info<'a>(
    elf: &ElfFile<'a>,
) -> (
    DebugInfo<EndianBuf<'a, LittleEndian>>,
    DebugAbbrev<EndianBuf<'a, LittleEndian>>,
    DebugStr<EndianBuf<'a, LittleEndian>>,
    DebugLine<EndianBuf<'a, LittleEndian>>,
) {
    let debug_info_data = elf.section_data_by_name(".debug_info")
        .expect("No .debug_info section in binary");
    let dwarf_info = DebugInfo::new(debug_info_data, LittleEndian);

    let debug_abbrev_data = elf.section_data_by_name(".debug_abbrev")
        .expect("No .debug_abbrev section in binary");
    let dwarf_abbrev = DebugAbbrev::new(debug_abbrev_data, LittleEndian);

    let debug_str_data = elf.section_data_by_name(".debug_str")
        .expect("No .debug_str section in binary");
    let dwarf_strings = DebugStr::new(debug_str_data, LittleEndian);

    let debug_line_data = elf.section_data_by_name(".debug_line")
        .expect("No .debug_line section in binary");
    let dwarf_line = DebugLine::new(debug_line_data, LittleEndian);

    (dwarf_info, dwarf_abbrev, dwarf_strings, dwarf_line)
}

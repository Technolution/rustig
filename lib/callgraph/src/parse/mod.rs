// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate addr2line;
extern crate capstone;
extern crate elf;
extern crate gimli;
extern crate goblin;
extern crate object;
extern crate std;

use errors::ResultExt;
use errors::*;

use CallGraphOptions;
use Context;

use addr2line::Context as Addr2LineContext;

use capstone::arch::BuildsCapstone;
use capstone::Capstone;

use gimli::DebugAbbrev;
use gimli::DebugInfo;
use gimli::DebugLine;
use gimli::DebugStr;
use gimli::EndianBuf;
use gimli::LittleEndian;

use object::ElfFile;
use object::File;
use object::Object;

// This import was falsely flagged as unused by the rust compiler.
#[allow(unused_imports)]
use object::ObjectSection;

/// Trait marking objects that are able to parse a binary into appropriate ELF/DWARF/Disassembled information
pub trait Parser {
    fn parse<'a>(&self, file_content: &'a [u8]) -> Result<Context<'a>>;
}

// Implementation of `Parser` that does parsing without any extraordinary processing.
struct DefaultParser;

/// Wrapper data structure for debug info
type DebugData<'a> = (
    DebugInfo<EndianBuf<'a, LittleEndian>>,
    DebugAbbrev<EndianBuf<'a, LittleEndian>>,
    DebugStr<EndianBuf<'a, LittleEndian>>,
    DebugLine<EndianBuf<'a, LittleEndian>>,
);

impl Parser for DefaultParser {
    fn parse<'a>(&self, file_content: &'a [u8]) -> Result<Context<'a>> {
        let elf = ElfFile::parse(&file_content)
            .map_err(|message| Error::from(ErrorKind::ParseError(message.to_string())))?;

        let file = File::parse(&file_content)
            .map_err(|message| Error::from(ErrorKind::ParseError(message.to_string())))?;

        let file_context = Addr2LineContext::new(&file).map_err(|message| {
            Error::from(ErrorKind::ParseError(format!(
                "Could not construct addr2line context from file: {}",
                message.to_string()
            )))
        })?;

        let data_byte = elf.elf()
            .header
            .endianness()
            .chain_err(|| ErrorKind::ParseError("Invalid endianness specifier".to_string()))?;
        let mode_byte = elf.elf().header.e_ident[elf::types::EI_CLASS];

        let endianness = gimli::LittleEndian;
        let mode = match mode_byte {
            1 => capstone::arch::x86::ArchMode::Mode32,
            2 => capstone::arch::x86::ArchMode::Mode64,
            _ => {
                return Err(
                    ErrorKind::ParseError("ELF file has invalid mode bit".to_string()).into(),
                )
            }
        };

        if data_byte == goblin::container::Endian::Big {
            return Err(
                ErrorKind::NotSupported("Big endian files not supported yet".to_string()).into(),
            );
        }

        let (dwarf_info, dwarf_abbrev, dwarf_strings, dwarf_line) =
            self.parse_dwarf_info(&elf, endianness)?;

        let mut capstone = Capstone::new()
            .x86()
            .mode(mode)
            .detail(true)
            .build()
            .expect("Failed to construct disassembler");
        capstone
            .set_detail(true)
            .expect("Failed to enable detailed mode");

        Ok(Context {
            elf,
            file_context,
            dwarf_info,
            dwarf_abbrev,
            dwarf_strings,
            dwarf_line,
            capstone,
        })
    }
}

impl DefaultParser {
    fn parse_dwarf_info<'a>(
        &self,
        elf: &ElfFile<'a>,
        endianness: LittleEndian,
    ) -> Result<DebugData<'a>> {
        let debug_info_data = elf.section_data_by_name(".debug_info")
            .chain_err(|| ErrorKind::ParseError("No .debug_info section in binary".to_string()))?;
        let dwarf_info = DebugInfo::new(debug_info_data, endianness);

        let debug_abbrev_data = elf.section_data_by_name(".debug_abbrev")
            .chain_err(|| ErrorKind::ParseError("No .debug_abbrev section in binary".to_string()))?;
        let dwarf_abbrev = DebugAbbrev::new(debug_abbrev_data, endianness);

        let debug_str_data = elf.section_data_by_name(".debug_str")
            .chain_err(|| ErrorKind::ParseError("No .debug_str section in binary".to_string()))?;
        let dwarf_strings = DebugStr::new(debug_str_data, endianness);

        let debug_line_data = elf.section_data_by_name(".debug_line")
            .chain_err(|| ErrorKind::ParseError("No .debug_line section in binary".to_string()))?;
        let dwarf_line = DebugLine::new(debug_line_data, endianness);

        Ok((dwarf_info, dwarf_abbrev, dwarf_strings, dwarf_line))
    }
}

pub fn get_parser(_cmd_args: &CallGraphOptions) -> Box<Parser> {
    Box::new(DefaultParser)
}

#[cfg(test)]
mod test {
    use super::*;
    use gimli::AttributeValue::DebugStrRef;
    use gimli::*;
    extern crate test_common;

    /// Test if the function panics if the passed byte array is not a valid elf file
    #[test]
    pub fn test_invalid_file_content() {
        assert!(DefaultParser.parse(&[]).is_err());
    }

    /// Test if the `DefaultParser` parses debug abbreviations correctly.
    /// We validate this by checking the tag, children and an attribute for 2 DIE's.
    #[test]
    pub fn test_example_binary_debug_abbrev() {
        let file_content = &test_common::load_test_binary_as_bytes(
            "threads",
            &test_common::TestSubjectType::DebugStableRustc,
        ).unwrap();

        let context = DefaultParser.parse(file_content).unwrap();
        // In order to compare debug sections, we will select a subset of abbreviations, and validate if they match
        let abbreviations = context
            .dwarf_abbrev
            .abbreviations(DebugAbbrevOffset(0))
            .expect("Error parsing abbreviations");

        let compile_unit_abbrev = abbreviations.get(1).expect("No abbreviation for code 1");
        let compile_unit_attributes = compile_unit_abbrev.attributes();
        let cu_attr_4 = compile_unit_attributes[3];

        assert_eq!(compile_unit_abbrev.code(), 1);
        assert_eq!(compile_unit_abbrev.tag(), DW_TAG_compile_unit);
        assert_eq!(compile_unit_abbrev.has_children(), true);

        assert_eq!(compile_unit_attributes.len(), 8);

        assert_eq!(cu_attr_4.name(), DW_AT_stmt_list);
        assert_eq!(cu_attr_4.form(), DW_FORM_sec_offset);

        let formal_param_abbrev = abbreviations.get(9).expect("No abbreviation for code 9");
        let formal_param_attributes = formal_param_abbrev.attributes();
        let fp_attr_5 = formal_param_attributes[3];

        assert_eq!(formal_param_abbrev.code(), 9);
        assert_eq!(formal_param_abbrev.tag(), DW_TAG_member);
        assert_eq!(formal_param_abbrev.has_children(), false);

        assert_eq!(formal_param_attributes.len(), 4);

        assert_eq!(fp_attr_5.name(), DW_AT_data_member_location);
        assert_eq!(fp_attr_5.form(), DW_FORM_data1);
    }

    /// Test if the `DefaultParser` parses debug info correctly.
    /// We validate this by checking the name attribute of an DIE.
    #[test]
    pub fn test_example_binary_debug_info() {
        let file_content = &test_common::load_test_binary_as_bytes(
            "threads",
            &test_common::TestSubjectType::DebugStableRustc,
        ).unwrap();

        let context = DefaultParser.parse(file_content).unwrap();

        // Next, we will inspect some of the debug info entries, and check if they match
        let unit_1 = context.dwarf_info.units().next().unwrap().unwrap();

        assert_eq!(unit_1.header_size(), 11);

        let abbr = context
            .dwarf_abbrev
            .abbreviations(DebugAbbrevOffset(0))
            .expect("Failed to parse abbreviations");
        let mut cursor = unit_1.entries(&abbr);
        cursor.next_dfs().expect("Failed to mode to initial entry");

        let (_, entry_1) = cursor.next_dfs().unwrap().unwrap();

        let name_value_ref = match entry_1.attr(DW_AT_name).unwrap().unwrap().value() {
            DebugStrRef(offset) => offset,
            _ => panic!("No DebugStrRef return type"),
        };
        let name_value = context.dwarf_strings.get_str(name_value_ref).unwrap();

        assert_eq!(entry_1.tag(), DW_TAG_namespace);
        assert_eq!(name_value, EndianBuf::new(b"core", LittleEndian));
    }

    /// Test if the `DefaultParser` parses debug info correctly.
    /// We validate this by checking the first instruction of the text section.
    #[test]
    pub fn test_example_binary_disassembly() {
        let file_content = &test_common::load_test_binary_as_bytes(
            "threads",
            &test_common::TestSubjectType::DebugStableRustc,
        ).unwrap();

        let context = DefaultParser.parse(file_content).unwrap();
        // Test 42th instruction
        let instr = context
            .capstone
            .disasm_all(context.elf.section_data_by_name(".text").unwrap(), 0x6210)
            .unwrap()
            .iter()
            .next()
            .unwrap();

        assert_eq!(instr.address(), 0x6210);
        assert_eq!(instr.bytes(), &[65 as u8, 87 as u8]);
        assert_eq!(instr.mnemonic(), Some("push"));
        assert_eq!(instr.op_str(), Some("r15"));
    }
}

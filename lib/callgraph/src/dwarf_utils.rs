// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate addr2line;
extern crate fallible_iterator;
extern crate gimli;

use std::string::String;

use self::fallible_iterator::FallibleIterator;

use gimli::Abbreviations;
use gimli::AttributeValue::*;
use gimli::CompilationUnitHeader;
use gimli::DebugStr;
use gimli::DebuggingInformationEntry;
use gimli::DwAt;
use gimli::Expression;
use gimli::Reader;
use gimli::ReaderOffset;

use Context;

/// Function that returns a string value from an entry's attribute.
/// If no string was found, or an error occured
/// an error message will be returned.
pub fn get_attr_string_value_safe<R: Reader>(
    entry: &DebuggingInformationEntry<R, R::Offset>,
    attr: DwAt,
    strings: &DebugStr<R>,
) -> String {
    entry.attr(attr).expect("Error reading attributes") // Note that, if no attribute is present Ok(None) is returned.
        .map(|attrib| {
            let tmp: Option<String> = attrib.string_value(strings)
                .map(|x: R| x.to_string().unwrap_or_else(|_| panic!("Failed to convert {} value to string", attr)).to_string());
            tmp.unwrap_or_else(|| format!("<{} is not a string>", attr).to_string())
        })
        .unwrap_or_else(|| format!("<no {} attribute given>", attr).to_string())
}

/// Function that returns the buffer of a string value from an entries attribute. If no string valute was found, `None` will be returned
pub fn get_attr_string_buf<R: Reader>(
    entry: &DebuggingInformationEntry<R, R::Offset>,
    attr: DwAt,
    strings: &DebugStr<R>,
) -> Option<R> {
    entry
        .attr(attr)
        .ok()
        .and_then(|att_opt| att_opt.and_then(|att| att.string_value(strings)))
}

/// Function that returns a string value from an entries attribute. If no string was found, `None` will be returned
pub fn get_attr_string_value<R: Reader>(
    entry: &DebuggingInformationEntry<R, R::Offset>,
    attr: DwAt,
    strings: &DebugStr<R>,
) -> Option<String> {
    get_attr_string_buf(entry, attr, strings).map(|buf| buf.to_string().unwrap().to_string())
}

/// Returns a byte buffer representing the attribute value.
/// Returns `None` if no such attribute was found, or the value was not `Block`, `Exprloc` or `String`.
#[allow(dead_code)]
pub fn get_attr_buf<R: Reader>(
    entry: &DebuggingInformationEntry<R, R::Offset>,
    attr: DwAt,
) -> Option<R> {
    match entry
        .attr(attr)
        .map(|att_opt| att_opt.map(|att| att.value()))
    {
        Ok(Some(value)) => match value {
            Block(v) | Exprloc(Expression(v)) | String(v) => Some(v),
            _ => None,
        },
        _ => None,
    }
}

/// If the attribute has an data value, it will be returned. Else `None` will be given.
pub fn get_attr_u64_value<R: Reader>(
    entry: &DebuggingInformationEntry<R, R::Offset>,
    attr: DwAt,
) -> Option<u64> {
    entry
        .attr(attr)
        .ok()
        .and_then(|att_opt| att_opt.and_then(|att| att.udata_value()))
}

/// If the attribute has an Addr value, it will be returned. Else `None` will be given.
pub fn get_attr_addr_value<R: Reader>(
    entry: &DebuggingInformationEntry<R, R::Offset>,
    attr: DwAt,
) -> Option<u64> {
    match entry
        .attr(attr)
        .map(|att_opt| att_opt.map(|att| att.value()))
    {
        Ok(Some(Addr(value))) => Some(value),
        _ => None,
    }
}

/// Function demangling assembly symbol names.
pub fn demangle_symbol(linkage_name: &str) -> String {
    let demangled = addr2line::demangle(linkage_name, gimli::DW_LANG_Rust)
        .unwrap_or_else(|| linkage_name.to_string());

    // Every demangled linkage name contain a hash at the end of the string
    // These calls take care to remove that
    let last_crate_index = demangled
        .rfind("::")
        .unwrap_or_else(|| demangled.chars().count());
    demangled[..last_crate_index].to_string()
}

/// Prints detailed information of an entry (fo debugging purposes)
#[allow(dead_code)]
pub fn print_entry_details<R: Reader>(
    entry: &DebuggingInformationEntry<R, R::Offset>,
    strings: &DebugStr<R>,
) {
    let offset = entry.offset().0.into_u64();
    let name = get_attr_string_value_safe(entry, gimli::DW_AT_name, &strings);
    let linkage_name = get_attr_string_value_safe(entry, gimli::DW_AT_linkage_name, &strings);

    println!(
        "Entry details: offset: {:x}, name: {}, linkage_name: {}, present attributes:",
        offset, name, linkage_name
    );
    let _t: Vec<_> = entry
        .attrs()
        .iterator()
        .map(|x| x.unwrap())
        .inspect(|val| {
            println!("  - {}", val.name());
        })
        .collect();
}

/// Function that determines the Rust version that was used to compile the binary in `ctx`.
pub fn get_rust_version(ctx: &Context) -> Option<String> {
    ctx.dwarf_info
        .units()
        .iterator()
        .filter_map(|unit_header| {
            let unit_header = unit_header.unwrap();
            let abbrevs = unit_header.abbreviations(&ctx.dwarf_abbrev).unwrap();
            let mut entries = unit_header.entries(&abbrevs);

            let (_, entry) = entries
                .next_dfs()
                .expect("First compilation unit could not be selected")
                .unwrap();

            let producer = get_attr_string_value(&entry, gimli::DW_AT_producer, &ctx.dwarf_strings);

            // Assume producer is in a format like 'clang LLVM (rustc version 1.26.0 (a77568041 2018-05-07))'
            producer.map(|p| {
                p.rsplit("rustc version")
                    .next()
                    .expect("Unexpected producer string format")
                    .trim()
                    .split_whitespace()
                    .next()
                    .expect("Unexpected producer string format")
                    .to_string()
            })
        })
        .next()
}

/// Function getting an attribute string value. If the attribute is not present, but an DW_AT_abstract_origin
/// attribute is present, the references entry will be checked for the desired attribute.
pub fn get_attr_str_with_origin_traversal<R: Reader>(
    cu: &CompilationUnitHeader<R, R::Offset>,
    entry: &DebuggingInformationEntry<R, R::Offset>,
    attr: DwAt,
    abbrev: &Abbreviations,
    strings: &DebugStr<R>,
) -> String {
    match get_attr_string_value(entry, attr, strings) {
        Some(name) => name,
        _ => match entry.attr_value(gimli::DW_AT_abstract_origin) {
            Ok(Some(UnitRef(offset))) => {
                let mut origin_cursor = cu.entries_at_offset(abbrev, offset).unwrap();
                let (_, origin) = origin_cursor.next_dfs().unwrap().unwrap();
                get_attr_string_value_safe(origin, attr, strings)
            }
            oth => panic!("DW_AT_abstract_origin is not UnitRef, but {:x?}", oth),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test demangling a symbol with a hash
    #[test]
    pub fn test_demangle_symbol() {
        assert_eq!(demangle_symbol(&"sym::hash".to_string()), "sym".to_string());
    }

    /// Test demangling a symbol without a hash
    #[test]
    pub fn test_demangle_symbol_no_double_dot() {
        assert_eq!(demangle_symbol(&"123".to_string()), "123".to_string());
    }
}

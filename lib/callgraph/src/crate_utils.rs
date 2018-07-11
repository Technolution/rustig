// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use addr2line::Frame;

use dwarf_utils;

use Context;
use Crate;

use gimli;
use gimli::DebuggingInformationEntry;
use gimli::EndianBuf;
use gimli::LittleEndian;
use gimli::RunTimeEndian;

/// Function that returns a `Crate` instance from the compilation dir.
/// Usually, for an external crate, the direactory has the format '/path/to/checkout/<crate-name>-<version>
/// In that case, `Crate { name: "<crate-name>", version: Some("<version>") }` is returned.
/// Some special cases are:
///   - When there is no numeric char after the crate name, it is assumed the version in not known.
///         In that case, the `version` field is `None`.
///   - When the checkout dir is '/checkout/src/`, then it is stdlib code
///         In that case `Crate { name: "stdlib", version: Some("<rust version>") }` is returned
///
pub fn get_crate_from_comp_dir(comp_dir: Option<&str>, rust_version: String) -> Crate {
    let comp_dir = match comp_dir {
        Some(dir) => dir,
        None => {
            return Crate {
                name: "<unknown compilation directory>".to_string(),
                version: None,
            }
        }
    };

    // In /checkout/src, the standard library is stored.
    // So return stdlib-rust-version
    if comp_dir == "/checkout/src" {
        return Crate {
            name: "stdlib".to_string(),
            version: Some(rust_version),
        };
    }

    let crate_name_version = comp_dir.rsplit('/').next().expect("No / in path");
    let mut crate_name_split: Vec<_> = crate_name_version.rsplit('-').collect();

    // Splitting a string always returns at least one element, so we can safely assert this.
    assert!(!crate_name_split.is_empty());

    let (name, version) =
        if crate_name_split.len() == 1 || !crate_name_version.chars().any(|x| x.is_numeric()) {
            crate_name_split.reverse();
            (crate_name_split.join("-").to_string(), None)
        } else {
            let version = crate_name_split.remove(0);
            crate_name_split.reverse();
            (crate_name_split.join("-"), Some(version.to_string()))
        };

    Crate { name, version }
}

/// Gets the crate details for a compilation unit
pub fn get_crate_details(
    _address: u64,
    defining_file: Option<&str>,
    cu_die: &DebuggingInformationEntry<EndianBuf<LittleEndian>>,
    ctx: &Context,
    compilation_unit_dirs: &[&str],
) -> Crate {
    let producer =
        dwarf_utils::get_attr_string_value(&cu_die, gimli::DW_AT_producer, &ctx.dwarf_strings)
            .expect("No producer for compilation unit");

    // Assume producer is in a format like 'clang LLVM (rustc version 1.26.0 (a77568041 2018-05-07))'
    let rust_version = producer
        .rsplit("rustc version")
        .next()
        .expect("Unexpected producer string format")
        .trim()
        .split_whitespace()
        .next()
        .expect("Unexpected producer string format")
        .to_string();

    // Find a match between the compilation unit directories and the file.
    // If no match is found, set crate name to "Unknown".
    let comp_dir = match defining_file {
        Some(defining_file) => compilation_unit_dirs
            .iter()
            .find(|compilation_unit| defining_file.starts_with(**compilation_unit))
            .map(|string| *string),
        None => None,
    };

    get_crate_from_comp_dir(comp_dir, rust_version)
}

/// Returns the crate for inlined functions
pub fn get_crate_for_inlined_functions(
    frame: &Frame<EndianBuf<RunTimeEndian>>,
    compilation_dirs: &[&str],
    rust_version: String,
) -> Crate {
    let default_crate = Crate {
        name: "<unknown compilation directory>".to_string(),
        version: None,
    };

    if frame.location.is_none() {
        return default_crate;
    }

    // Safe unwrap: is_none check before
    let location = frame.location.as_ref().unwrap();

    if location.file.is_none() {
        return default_crate;
    }

    // Safe unwrap: is_none check before
    let file_path = location.file.as_ref().unwrap();

    let frame_comp_dir = compilation_dirs
        .iter()
        .find(|comp_dir| file_path.starts_with(comp_dir));
    get_crate_from_comp_dir(frame_comp_dir.map(|x| x.to_owned()), rust_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test `get_crate_from_comp_dir` with an usual 3-rd party crate name
    #[test]
    pub fn test_get_crate_from_comp_dir() {
        let crt =
            get_crate_from_comp_dir(Some("/home/test/crate-name-0.1.2.2"), "1.26".to_string());

        assert_eq!(crt.name, "crate-name");
        assert_eq!(crt.version, Some("0.1.2.2".to_string()));
    }

    /// Test `get_crate_from_comp_dir` for an stdlib compilation unit
    #[test]
    pub fn test_get_crate_stdlib() {
        let crt = get_crate_from_comp_dir(Some("/checkout/src"), "1.26".to_string());

        assert_eq!(crt.name, "stdlib");
        assert_eq!(crt.version, Some("1.26".to_string()));
    }

    /// Test `get_crate_from_comp_dir` when no version is specified.
    #[test]
    pub fn test_get_crate_no_version() {
        let crt = get_crate_from_comp_dir(Some("/home/test/crate-name"), "1.26".to_string());

        assert_eq!(crt.name, "crate-name");
        assert_eq!(crt.version, None);
    }
    /// Test `get_crate_from_comp_dir` when "Unknown" is used.
    #[test]
    pub fn test_get_crate_unknown() {
        let crt = get_crate_from_comp_dir(None, "1.26".to_string());

        assert_eq!(crt.name, "<unknown compilation directory>");
        assert_eq!(crt.version, None);
    }
}

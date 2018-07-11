// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This is the command-line interface to the panic_analysis crate. Details about the command-line options can be 
//! obtained by running `rustig --help` on a build or by visiting the 
//! [Github documentation](https://github.com/Technolution/rustig).
//! 
#[macro_use]
extern crate serde_derive;
extern crate panic_analysis;
extern crate toml;
#[macro_use]
extern crate error_chain;

mod cmd_args;
mod config_file;
mod output;

// AZ: error_chain uses #[allow(unused_doc_comment)], which has been rename to #[allow(unused_doc_comments)]
#[allow(renamed_and_removed_lints)]
pub mod errors {
    error_chain!{
        errors{
            ConfigLoad(path: String, reason: Option<String>) {
                description("Config file not found")
                display("Unable to read config file `{}`{}", path, reason.as_ref().map(|x| format!(": {}", x)).unwrap_or_else(|| "".to_string()))
            }
        }
    }
}

use std::process;
use std::result::Result::Ok;

/// CLI entrypoint
pub fn main() {
    // Parse cmd arguments
    let (cmd_args, output_options) = match cmd_args::get_args() {
        Err(e) => {
            println!("{}", e);
            process::exit(101);
        }
        Ok(r) => r,
    };

    // Execute analysis
    match panic_analysis::find_panics(&cmd_args) {
        Err(e) => {
            println!("{}", e);
            process::exit(101);
        }
        Ok(collection) => {
            output::print_results(&output_options, &collection);

            // If a panic path is found, we exit with code 1
            // This enables integration with CI tools
            if !collection.calls.is_empty() {
                process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod test {
    extern crate assert_cli;
    extern crate test_common;

    /// Test if correct exit code 1 is returned when 1 or more panics are found
    #[test]
    fn test_panics_found() {
        let path =
            test_common::get_test_subject_path("lib_calls", &test_common::TestSubjectType::Debug)
                .to_str()
                .unwrap()
                .to_string();

        assert_cli::Assert::main_binary()
            .with_args(&["-b", &path, "-c", "test_subjects", "-s"])
            .fails_with(1)
            .unwrap();
    }

    /// Test if correct exit code 0 is returned when no panics are found
    #[test]
    fn test_no_panics_found() {
        let path =
            test_common::get_test_subject_path("empty", &test_common::TestSubjectType::Debug)
                .to_str()
                .unwrap()
                .to_string();

        assert_cli::Assert::main_binary()
            .with_args(&["-b", &path, "-c", "test_subjects", "-s"])
            .succeeds()
            .unwrap();
    }
}

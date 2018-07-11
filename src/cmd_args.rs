// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate clap;
extern crate panic_analysis;
extern crate std;

use config_file::parse_config;
use errors::*;

use self::panic_analysis::AnalysisOptions;

use self::clap::App;
use self::clap::Arg;
use self::clap::ArgMatches;
use self::clap::ErrorKind;

use output::OutputOptions;

use std::option::Option::Some;

static CALL_GRAPH_BUILD_MODES: [&'static str; 2] = ["full", "filtered"];

fn parse_multiple_args(cmd_matches: &ArgMatches, name: &str) -> Vec<String> {
    match cmd_matches.values_of(name) {
        Some(x) => x.into_iter().map(|x| x.to_string()).collect(),
        None => Vec::new(),
    }
}

pub fn get_args() -> Result<(AnalysisOptions, OutputOptions)> {
    let cmd_matches_opt = get_app_definition().get_matches_safe();

    let cmd_matches = match cmd_matches_opt {
        Ok(matches) => matches,
        Err(error) => {
            eprintln!("{}", error.message);
            match error.kind {
                ErrorKind::HelpDisplayed => std::process::exit(0),
                ErrorKind::VersionDisplayed => std::process::exit(0),
                _ => std::process::exit(101),
            }
        }
    };

    let crate_names = parse_multiple_args(&cmd_matches, "crates");

    let callgraph_outputs = parse_multiple_args(&cmd_matches, "callgraph");

    let config_opt = cmd_matches.value_of("config");
    let required = config_opt.is_some();

    let file_options = parse_config(config_opt.unwrap_or("rustig.toml"), required)?;

    let rdp_options = AnalysisOptions {
        binary_path: Some(cmd_matches.value_of("binary").unwrap().to_string()), // Required by clap, can safely be unwrapped.
        crate_names,
        whitelisted_functions: file_options.function_whitelists,
        output_filtered_callgraph: callgraph_outputs.iter().any(|output| output == "filtered"),
        output_full_callgraph: callgraph_outputs.iter().any(|output| output == "full"),
        full_crate_analysis: cmd_matches.is_present("full_crate_analysis"),
    };

    let output_options = OutputOptions {
        verbose: cmd_matches.is_present("verbose"),
        silent: cmd_matches.is_present("silent"),
    };

    Ok((rdp_options, output_options))
}

fn get_app_definition<'a, 'b>() -> App<'a, 'b> {
    App::new("Rust don't panic")
        // Argument accepting the path to the binary to analyze
        // Note that this is a parameter, since we might build from Cargo projects in the future
        // In that case this argument will not be required anymore.
        // To maintain compatibility, we decided to make it an parameter immediately
        .arg(
            Arg::with_name("binary")
                .short("b")
                .long("binary")
                .value_name("FILE")
                .help("Path to binary file to analyze")
                .required(true) // Needs to be removed if we decide to compile our own binaries in the future.
                .takes_value(true),
        )
        // Right now, crates are printed in the output
        // Maybe we should once make a subcommand that prints all crates and versions
        .arg(
            Arg::with_name("crates")
                .multiple(true)
                .short("c")
                .long("crates")
                .value_name("CRATES")
                .help("Names of the compilation unit which should be analyzed. If not provided, the crate of the entry points will be used"),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .conflicts_with("silent")
                .help("Turn on verbose mode for full stack traces of panic calls"),
        )
        .arg(
            Arg::with_name("config")
                .long("config")
                .help("Path to RDP configuration file (default: rdp.toml)")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("full_crate_analysis")
                .short("f")
                .long("full-crate-analysis")
                .help("Analyze all functions in analysis target, instead of entry points only"),
        )
        .arg(
            Arg::with_name("silent")
                .short("s")
                .long("silent")
                .conflicts_with("verbose")
                .help("Turn on silent mode to not print anything"),
        )
        .arg(
            Arg::with_name("callgraph")
                .multiple(true)
                .min_values(1)
                .value_name("CALLGRAPH")
                .long("callgraph")
                .short("g")
                .help("Write a callgraph of the given binary to a file. The output filename will be: `rdp-callgraph-{projectname}-{type}`, where `type` is either `full` or `filtered`. The full callgraph contains all function calls that are detected by RDP, while filtered callgraph only contains paths that possibly lead to panic calls")
                .possible_values(&CALL_GRAPH_BUILD_MODES),
        )
}

#[cfg(test)]
mod test {
    extern crate assert_cli;

    /// Test that an error is printed if no '--binary' command line parameter is given
    #[test]
    fn test_no_binary_provided() {
        // Execute our build with no cmd parameters
        assert_cli::Assert::main_binary()
            // Assert that the tool indicates the '--binary' argument is not given
            .stderr().contains("error: The following required arguments were not provided:")
            .stderr().contains("--binary <FILE>")
            .fails_with(101)
            .unwrap();
    }
}

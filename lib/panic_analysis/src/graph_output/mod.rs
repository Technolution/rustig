// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use AnalysisOptions;

use RustigCallGraph;

use std::fmt::Debug;

use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use std::path::Path;

/// Trait representing some output format of the graph
pub trait GraphOutput: Debug {
    fn write_graph(&self, call_graph: &RustigCallGraph);
    #[cfg(test)]
    fn get_type_name(&self) -> &str;
}

/// Struct that represents a graph output that dumps a .dot file
#[derive(Debug)]
struct DotGraphOutput {
    stage: String,
    filename: String,
}

impl GraphOutput for DotGraphOutput {
    fn write_graph(&self, call_graph: &RustigCallGraph) {
        let dot = call_graph.dot();
        let filename = format!("rdp-callgraph-{}-{}.dot", self.filename, self.stage);
        let write_file = File::create(&filename)
            .unwrap_or_else(|_| panic!("The file {} could not be created", filename));
        let mut writer = BufWriter::new(&write_file);

        let dot_out = format!("{:?}", dot);
        let dot_out = dot_out.replace("\\\\", "\\");

        let success = write!(&mut writer, "{}", dot_out);
        if success.is_err() {
            panic!("Could not write dot file");
        }
    }
    #[cfg(test)]
    fn get_type_name(&self) -> &str {
        "DotGraphOutput"
    }
}

/// Struct that represents graph output that does nothing
#[derive(Debug)]
struct NoGraphOutput;

impl GraphOutput for NoGraphOutput {
    fn write_graph(&self, _call_graph: &RustigCallGraph) {}
    #[cfg(test)]
    fn get_type_name(&self) -> &str {
        "NoGraphOutput"
    }
}

fn get_boxed_output(active: bool, stage: String, filename: String) -> Box<GraphOutput> {
    if active {
        return Box::new(DotGraphOutput { stage, filename });
    }
    Box::new(NoGraphOutput)
}

fn get_name_from_options(options: &AnalysisOptions) -> String {
    match options.binary_path {
        Some(ref path) => Path::new(&path)
            .file_stem()
            .expect("Could not extract file stem")
            .to_os_string()
            .into_string()
            .expect("Could not convert binary file stem to string"),
        None => "unknown-filename".to_string(),
    }
}

/// Graph output for filtered graph
pub fn get_graph_output_filtered(options: &AnalysisOptions) -> Box<GraphOutput> {
    get_boxed_output(
        options.output_filtered_callgraph,
        "filtered".to_string(),
        get_name_from_options(&options),
    )
}

/// Graph output for unfiltered, full graph
pub fn get_graph_output_full(options: &AnalysisOptions) -> Box<GraphOutput> {
    get_boxed_output(
        options.output_full_callgraph,
        "full".to_string(),
        get_name_from_options(&options),
    )
}

#[cfg(test)]
mod test {
    extern crate test_common;

    use self::test_common::*;
    use super::*;

    use AnalysisOptions;

    fn create_options(path: Option<String>, full: bool, filtered: bool) -> AnalysisOptions {
        AnalysisOptions {
            binary_path: path,
            crate_names: vec![],
            full_crate_analysis: true,
            output_full_callgraph: full,
            output_filtered_callgraph: filtered,
            whitelisted_functions: vec![],
        }
    }

    /// Test whether the graph_output type is correct for the situation where `full` graph is made
    #[test]
    fn test_proper_graph_output_type_full() {
        let possibilities = vec![
            (false, false, "NoGraphOutput"),
            (true, false, "DotGraphOutput"),
            (false, true, "NoGraphOutput"),
            (true, true, "DotGraphOutput"),
        ];

        possibilities.iter().for_each(|poss| {
            let output = get_graph_output_full(&create_options(None, poss.0, poss.1));
            assert_eq!(
                poss.2,
                output.get_type_name(),
                "The combination {:?} produced output {}, while {} was expected",
                poss,
                output.get_type_name(),
                poss.2
            );
        })
    }

    /// Test whether the graph_output type is correct for the situation where `filtered` graph is made
    #[test]
    fn test_proper_graph_output_type_filtered() {
        let possibilities = vec![
            (false, false, "NoGraphOutput"),
            (true, false, "NoGraphOutput"),
            (false, true, "DotGraphOutput"),
            (true, true, "DotGraphOutput"),
        ];

        possibilities.iter().for_each(|poss| {
            let output = get_graph_output_filtered(&create_options(None, poss.0, poss.1));
            assert_eq!(
                poss.2,
                output.get_type_name(),
                "The combination {:?} produced output {}, while {} was expected",
                poss,
                output.get_type_name(),
                poss.2
            );
        })
    }

    /// Check whether the correct file stem is generated from a test subject
    /// File stem is the name of the file, without its extension
    /// Stem of `/home/rdp.dot` would be `rdp`
    #[test]
    fn test_file_stem() {
        let path = get_test_subject_path("hello_world", &TestSubjectType::Debug)
            .to_str()
            .unwrap()
            .to_string();
        let options = create_options(Some(path), false, false);
        assert_eq!(get_name_from_options(&options), "hello_world")
    }
}

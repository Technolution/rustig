// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use callgraph::Binary;
use errors::*;
use std::path::Path;
use AnalysisOptions;

/// Trait marking objects that are able to make sure there is a binary to analyze
pub trait BinaryBuilder {
    fn build(&self) -> Result<Binary>;
}

/// Implementation of BinaryBuilder that consumes a pre-existing binary
#[derive(Debug, Clone)]
struct ExistingBinaryBuilder {
    path: String,
}

impl BinaryBuilder for ExistingBinaryBuilder {
    fn build(&self) -> Result<Binary> {
        let path = Path::new(&self.path);
        if path.exists() {
            Ok(Binary { path })
        } else {
            Err(ErrorKind::IOError(self.path.to_string()).into())
        }
    }
}

/// Function providing a correct implementation of BinaryBuilder, based on the provided options
pub fn get_builder(options: &AnalysisOptions) -> Result<Box<BinaryBuilder>> {
    let path = options
        .binary_path
        .clone()
        .ok_or("No path to binary provided.")?;
    Ok(Box::new(ExistingBinaryBuilder { path }))
}

#[cfg(test)]
mod test {
    extern crate std;
    extern crate test_common;

    use self::test_common::TestSubjectType;
    use binary::*;

    /// Test that a file exists at the given binary path
    #[test]
    fn test_binary_exists() {
        let path = test_common::get_test_subject_path("hello_world", &TestSubjectType::Debug);

        let path_string = path.to_str().unwrap().to_string();
        let builder = ExistingBinaryBuilder { path: path_string };
        let b = builder.build().unwrap();

        assert_eq!(b.path, path);
    }

    /// Test that a panic is thrown when the binary file is not found
    #[test]
    fn test_binary_does_not_exist() {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("res/resource_should_not_exist");

        let path_string = path.to_str().unwrap().to_string();
        let builder = ExistingBinaryBuilder { path: path_string };
        assert!(builder.build().is_err());
    }
}

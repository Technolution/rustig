// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate std;

use Binary;
use CallGraphOptions;

use errors::*;
use std::io::Read;

/// Trait marking objects that can read a binary file, and return the content as a `Vec<u8>`.
pub trait BinaryReader {
    fn read<'a>(&self, binary: &'a Binary) -> Result<(Vec<u8>)>;
}

/// Default implementation of `BinaryReader`, that reads the file, without any extraordinary processing.
struct DefaultBinaryReader;

impl BinaryReader for DefaultBinaryReader {
    fn read<'a>(&self, binary: &'a Binary) -> Result<(Vec<u8>)> {
        let mut file_content = Vec::new();
        let mut file = std::fs::File::open(binary.path)
            .chain_err(|| ErrorKind::IOError(binary.path.to_str().unwrap().to_string()))?;

        file.read_to_end(&mut file_content)
            .chain_err(|| ErrorKind::ReadError(binary.path.to_str().unwrap().to_string()))?;

        Ok(file_content)
    }
}

/// Function that returns a `BinaryReader` implementation based on the passed parameters.
pub fn get_reader(_options: &CallGraphOptions) -> Box<BinaryReader> {
    Box::new(DefaultBinaryReader)
}

#[cfg(test)]
mod test {
    extern crate test_common;

    use self::test_common::TestSubjectType;
    use super::*;

    /// Test whether the correct number of bytes is read by the binary reader.
    #[test]
    fn test_binary_reader() {
        let path =
            test_common::get_test_subject_path("hello_world", &TestSubjectType::DebugStableRustc);

        let binary = Binary { path: &path };

        let vec = DefaultBinaryReader.read(&binary);

        assert!(!vec.unwrap().is_empty())
    }
}

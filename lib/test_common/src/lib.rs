// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate capstone;
extern crate gimli;
extern crate object;

use std::fs::File;
use std::io::Error;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

pub enum TestSubjectType {
    Debug,
    Release,
    DebugStableRustc,
    ReleaseStableRustc,
}

impl TestSubjectType {
    fn get_test_subject_path(&self) -> &str {
        match *self {
            TestSubjectType::Debug => "test_subjects/target/x86_64-unknown-linux-gnu/debug",
            TestSubjectType::Release => "test_subjects/target/x86_64-unknown-linux-gnu/release",
            TestSubjectType::DebugStableRustc => "test_subjects_stable_rustc/target/x86_64-unknown-linux-gnu/debug",
            TestSubjectType::ReleaseStableRustc => "test_subjects_stable_rustc/target/x86_64-unknown-linux-gnu/release",
        }
    }
}

/// Prepare the path of the executable of test subject `subject`
pub fn get_test_subject_path(subject: &str, subject_type: &TestSubjectType) -> PathBuf {
    let current_dir = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    let current_grandparent = current_dir
        .parent()
        .expect("Current executable path has no parent")
        .parent()
        .expect("Current executable path has no grandparent");

    let executable_path = Path::join(current_grandparent, subject_type.get_test_subject_path());

    Path::join(executable_path.as_path(), subject)
}

/// Load a test subject executable. Must be one of the crates in `test_subjects`
pub fn load_test_binary(subject: &str, subject_type: &TestSubjectType) -> Result<File, Error> {
    let executable = get_test_subject_path(subject, subject_type);

    File::open(executable)
}

/// Load a test subject executable as a byte vector. Must be one of the crates in `test_subjects`
pub fn load_test_binary_as_bytes(
    subject: &str,
    subject_type: &TestSubjectType,
) -> Result<Vec<u8>, Error> {
    let mut file = load_test_binary(subject, subject_type)?;

    let mut file_content = Vec::<u8>::new();

    file.read_to_end(&mut file_content)?;

    Ok(file_content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_test_subject_succeeds() {
        let result = load_test_binary(&"hello_world", &TestSubjectType::Debug);
        assert!(result.is_ok());
    }

    #[test]
    fn load_test_subject_fails() {
        let result = load_test_binary(&"nonexistent_subject", &TestSubjectType::Debug);
        assert!(result.is_err());
    }
}

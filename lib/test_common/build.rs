// (C) COPYRIGHT 2018 TECHNOLUTION BV, GOUDA NL

// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// This build script ensures the binaries of the test subjects (programs that are used as input for the tests)
/// are build. Currently, we build 2 types of tests
/// ## `test_subjects`
/// The projects in this workspace build against the default toolchain. These subjects are
/// used in tests that verify the tool works on a (new) particular Rust version. These tests perform regression testing on
/// the tool itself as well as the Rust compiler. Changes in the Rust compiler that break the tool should be detected by tests
/// on these projects.
/// ## `test_subjects_stable_rustc`
/// These tests build against a particular Rust version ('stable-2018-05-10'). Tests against these subjects may have stronger
/// assumptions on the created binary. These tests do no regression testing on the Rust compiler (since the version is fixed)
/// but do regression testing on the tool.
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

static RES_PATH: &str = "test_subjects";
static RES_PATH_STABLE_RUSTC: &str = "test_subjects_stable_rustc";
static STABLE_RUSTC_VERSION: &str = "stable-2018-05-10"; // 1.26.0

static BUILD_MODE_ARGS: &[Option<&str>] = &[None, Some("--release")];

fn main() {
    // Build test_subjects on default toolchain for compiler regression testing
    build_subjects(RES_PATH, None);
    // Build test_subjects on toolchain 'stable-2018-05-10' for tool regression testing
    build_subjects(RES_PATH_STABLE_RUSTC, Some(STABLE_RUSTC_VERSION));
}

/// Get the full path of `test_subjects` directory
fn test_subject_dir(endpath: &str) -> PathBuf {
    // '${PWD}/lib/test_common'
    let current_dir = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    let grandparent_dir = current_dir
        .parent()
        .expect("Current directory has no parent")
        .parent()
        .expect("Current directory has no grandparent");

    // '${PWD}/<endpath>
    Path::join(grandparent_dir, Path::new(endpath))
}

fn build_subjects(endpath: &str, fixed_cargo_version: Option<&str>) {
    let subjects = test_subject_dir(&endpath);
    let subjects = subjects.to_str().unwrap();
    clean(subjects);
    build(subjects, fixed_cargo_version);
}

fn clean(subjects: &str) {
    let subjects_clean_status = Command::new("cargo")
        .current_dir(&subjects)
        .arg("clean")
        .status()
        .expect("Cleaning test subject dir did not produce any output");

    if !subjects_clean_status.success() {
        panic!("Could not clean test subjects, manual intervention needed");
    }
}

fn build(subjects: &str, fixed_cargo_version: Option<&str>) {
    BUILD_MODE_ARGS.iter().for_each(|arg| {
        let mut cargo = Command::new("cargo");

        cargo.current_dir(&subjects);

        if let Some(ref version) = fixed_cargo_version {
            cargo.env("RUSTUP_TOOLCHAIN", version);
        }

        cargo.arg("build");
	cargo.arg("--target");
	cargo.arg("x86_64-unknown-linux-gnu");

        if let Some(arg) = arg {
            cargo.arg(arg);
        }

        let subjects_build_status = cargo
            .status()
            .expect("Building of test subjects did not produce any output");

        if !subjects_build_status.success() {
            panic!("Could not build test subjects, manual intervention needed");
        }
    })
}

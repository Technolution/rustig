#!/bin/sh

# The purpose of this script is to clean not only the 'rustig' software, but also
# clean out all test subjects. Running 'cargo clean' on the top-level directory does
# not do this.
cargo clean
cd test_subjects && cargo clean && cd ..
cd test_subjects_stable_rustc && cargo clean && cd ..

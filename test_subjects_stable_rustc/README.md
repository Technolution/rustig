# Test subjects with stable rustc
This project is a workspace that contains multiple projects used for testing of the `rustig` crate. These projects should be compiled with a specific `rustc` version: `stable-2018-05-10`. The build step responsible for enforcing this can be found in: `rustig/lib/callgraph/build.rs`


## Adding new projects
In order to add a new project, use the command: `cargo new --bin $projectname$`, where `$projectname$` is the name of the new test subject.

Additionally, the project needs to be added to the `Cargo.toml` file. In order to do this, extend the `Cargo.toml` file by adding a new value to the `members` field, with the value of `"$projectname$"`.

Note that adding, removing or changing a test subject requires a clean build to work properly.

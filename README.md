Rustig!
================

This software can be used to check whether your Rust software has any paths leading to the _panic_ handler. 

This tool is intended to be used by developers during coding and on CI systems to continuously check for possible 
_panic_'s.

## The name
The name _rustig!_ comes from the Dutch word _rustig_. Which translates to 'calm down' or equivalent in English. 
See it as the opposite of 'panic'. **Don't panic!**.

## Background

Software written in Rust has a panic handler. When the panic handler is called the current thread will be terminated 
(or the process will be exited, determined by rustc's build flag 'panic'). Certain conditions in Rust software trigger 
this panic handler. Accessing an array out of bounds is an example of such a trigger. 

This tool will analyze the ELF executable, generate a callgraph from the debug info in the executable, and report the 
paths leading from your code to the panic handler. 

## History
The idea for this tool was born while we were on some code for Cortex-M processors. Using `objdump` and `grep` you can 
easily prove that there is no `panic!` in the code, because the optimizer has removed those functions from the resulting 
binary. For non `#[no_std]` targets the optimizer cannot remove them because the binary is statically linked to the
Rust standard libary which contains those functions. We wanted this tool to be able to prove the abscence
of paths to `panic!` in Rust binaries that contain the standard libary. See the [Results](#Results) section to see 
why this turned out to be not so easy. 

## Who
This tool was written by four students from Delft University doing their _Bachelor End Project_ at 
[Technolution](https://technolution.eu/en/) in the Netherlands. The initial idea was provided by Erwin Gribnau who 
mentored this project on behalf of Technolution. On behalf of Delft University, this project was mentored by 
[Robbert Krebbers](https://robbertkrebbers.nl/). 

Their thesis about this project can be found in the repo at Delft University: 
[link](http://resolver.tudelft.nl/uuid:c4e95618-390d-4210-a76f-ce23640a194d).

## Installing the latest version from source
You can use *cargo* to install our binary directly from the sources in the Git-repository:
```
cargo install --git https://github.com/Technolution/rustig rustig
```
## Using the tool

The tool accepts various command line flags and options:

### Options
* `--binary` (`-b`): The path of the binary to analyze, relative to the present working directory. This should be an
executable in [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) format. The executable should be 
compiled for x86 or x86_64 architectures, with debug information enabled.

* `--config`: Path to a configuration file, relative to the present working directory. Defaults to 'rustig.toml'.
If the default file does not exist, no configuration file is used. However, if this argument is passed explicitly, but 
the file does not exist, the tool will exit with an error. Currently, this file is only used for whitelisting, which is 
explained in the section on [whitelisting](#whitelisting).

* `--crates` (`-c`): Option to mark crates as analysis target (more on analysis target in the 
[how it works](#how-it-works) section). By default, the crate in which the `main` function is defined is used as 
analysis target.

* `--callgraph` (`-g`): Option to dump the callgraph in [dot](https://en.wikipedia.org/wiki/DOT_(graph_description_language)) 
format. It takes one or more of 2 values:
    * `full`: Writes the full call graph, without metadata, to 'rdp-callgraph-{projectname}-full.dot'
    * `filtered`: Writes the call graph containing only the nodes that lead to a panic, with metadata, to 
    'rdp-callgraph-{projectname}-filtered.dot'

### Flags
* `--full-crate-analysis` (`-f`): Analyses all functions in the analysis target, instead of only the main function. 
  (More about this flag in the in the section on [whitelisting](#whitelisting)).
* `--silent` (`-s`): Print no output to stdout.
* `--verbose` (`-v`): Print detailed panic traces to stdout.

### Exit codes
* 0: No errors during execution, and no _panic_ traces found.
* 1: No errors during execution, but _panic_ traces were found.
* 101: Internal error during execution.

## How it works

Internally, the tool builds a call graph from the binary. (This call graph can be dumped with the `--callgraph` 
flag). After that the tool wil print all calls from a function in the same crate as the main function (or the crates given by the 
`--crates` flag) to a function outside this crate that might lead to a _panic!_.

## Whitelisting

It is possible to whitelist functions. When a function is whitelisted, traces that would contain that function are 
ignored.

Whitelisting can be done in the configuration file. An example, to whitelist formatting, could be:
```text
whitelisted_functions = [
  {
    function_name = "fmt::format",
    crate_name = "stdlib",
    crate_version="1.26.2",
    strict = true
  }
]
```

The whitelisted functions are defined in an array with key `whitelisted_functions`. The objects in the array contain 
the following fields:
* `function_name` (required): The name of the function to whitelist. This name may be prepended with an arbitrary 
  number of namespaces. However, partial namespaces are not accepted. For example, if a function has name 
  `core::fmt::format`, the names `format`, `fmt::format` and `core::fmt::format` would match, but `ormat` or 
  `mt::format` would not.
* `crate_name`: (required) The name of the crate the function is defined in. When executing the tool, this is usually 
  printed between brackets in the output.
* `crate_version`: (optional) The version of the crate the function is defined in. If another version of the crate is 
  detected, the function will not be whitelisted.
* `strict`: (optional) If `true`, crates for which the name matches, but the version could not be determined, are not 
  matched. If `false`, the crate will be matched. The default is `false`.

### Full crate analysis

Normally, when function `foo` is whitelisted, only traces through functions that are called via `foo` *only* will be 
ignored. This behaviour can be disabled by setting the `--full-crate-analysis` flag.

For example, for the following function trace: 
`crate::main` -> `crate::whitelisted_function` -> `crate::foo` -> `std::panic::panic` no trace would be reported by 
default. When the `--full-crate-analysis` flag is set, a trace (`crate::foo` -> `std::panic::panic`) would be reported.


## Limitations
For dynamic invocations this tool makes assumptions. The assumption made is that when the address of a trait 
implementation is loaded using the Load Effective Address call, all functions in that trait are considered used. All 
paths leading to panic! from one of those functions (whether actually used or not) will be reported. 


## Results

As a test case for this tool some well-known crates from the Rust community were used. The results are shown below:

| Crate      | Lines of Code | Number of panic paths |
|------------|--------------:|----------------------:|
| Servo      |        219806 |                 50881 |
| cargo      |         25892 |                  9439 |
| cargo-make |          8243 |                  1195 |
| cargo-edit |           671 |                   237 |

The output of the tool in your terminal is overwhelming considering the numbers of paths shown. To reduce the output
the whitelisting option is used. Using whitelisting you can drill down on the results showing only the paths you care 
about.

Again, for some well-known crates this is performed, the results are shown below:

In this table, the column **Total** denotes all the panic traces in the program. 
In the column **Project specific**, we whitelisted some functions that were explicitly
meant to panic if something went wrong in the setup or teardown phase. In the subsequent columns
**Format**, **Allocation** and **Indexing**, we disabled traces for string formatting, memory allocation and
array indexing respectively. We whitelisted these because, based on our experience, they are very
unlikely to panic . These whitelists are added on top of the project-specific whitelists. In the **All** column,
we combined all of these whitelisting configurations. The traces in this output did not have a cause that was 
easiy to identify, and would require more investigation. In the last two columns, we identified how many
of the traces in the **All** column were caused by an unwrap or by use of the panic macro itself.

| Crate        | Total | Project specific | Format | Allocation| Indexing | All | Unwrap | Direct |
|--------------|------:|-----------------:|-------:|----------:|---------:|----:|-------:|-------:|
|cargo         |  9439 |             7782 |4833 |5514 |6758 |2238 |738 |49
|cargo-make    |  1195 |             1136 |695 |697 |1030 |148 |71 |8
|cargo-add     |   388 |              283 |201 |209 |236 |95 |17 |4
|cargo-rm      |   126 |              108 |64 |91 |97 |37 |5 |0
|cargo-upgrade |   415 |              298 |204 |231 |267 |112 |16 |2

Based on these results, we tried to estimate the impact of this output. It turned out that many panics
were difficult to trigger, since they are very environment-specific. However, in the cargo-make project,
we were able to trigger two panics after trying for just half an hour. One panic occures when you remove
the read permissions for the current user on input files for cargo-make. The other panic occures when such
an input file is not formatted correctly. This demonstrates it is possible to find bugs with the tool; 
however, it certainly requires some effort. We would like to point out, that this particalur bug is not
a serious problem for a command-line program. But, when bugs like these can be triggered on applications
connected to the Internet, you can execute a denial-of-service attack against such an application. 

## License
MIT or APACHE-2.0 (see the LICENSE files in the repository).

## Developer notes
To test this tool a series of binaries is generated (in test_subjects and test_subjects_stable_rustc). 
The binaries in the latter directory are generated using a specific version of the Rust compiler. 
See build.rs in test_common for details. 

### Warning for RLS users
If you use the Rust Language Server (i.e. Visual Studio Code with Rust plugin), the generated binary 
is overwritten by a version compiled with the default compiler settings. This will cause some tests to fail!

The tests that are known to fail in that case are:
`parse::test::test_example_binary_debug_abbrev` and `callgraph::test::test_call_graph_creation`.

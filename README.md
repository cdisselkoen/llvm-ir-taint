# `llvm-ir-taint`: Taint tracking for LLVM IR

[![crates.io](https://img.shields.io/crates/v/llvm-ir-taint.svg)](https://crates.io/crates/llvm-ir-taint)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/cdisselkoen/llvm-ir-taint/main/LICENSE)

This crate provides static taint-tracking for LLVM IR.

## Getting started

`llvm-ir-taint` is on [crates.io](https://crates.io/crates/llvm-ir-taint),
so you can simply add it as a dependency in your `Cargo.toml`, selecting the
feature corresponding to the LLVM version you want:
```toml
[dependencies]
llvm-ir-taint = { version = "0.1.1", features = ["llvm-13"] }
```
Currently, the supported LLVM versions are `llvm-8`, `llvm-9`, `llvm-10`,
`llvm-11`, `llvm-12`, and `llvm-13`.
The corresponding LLVM library must be available on your system; see the
[`llvm-sys`] README for more details and instructions.

You'll also need some LLVM IR to analyze, in the form of one or more [`llvm-ir`]
[`Module`]s.
This can be easily generated from an LLVM bitcode file; for more detailed
instructions, see [`llvm-ir`'s README](https://crates.io/crates/llvm-ir).

Once you have one or more `Module`s, you can call
[`do_taint_analysis_on_function()`] to analyze a single function (and all
functions it calls, including transitively), or
[`do_taint_analysis_on_module()`] to analyze all the functions in an LLVM
module.
```rust
let module = Module::from_bc_path(...)?;
let taint_result = do_taint_analysis_on_function(&[module], ...);
```
Either of these functions return a [`TaintResult`], from which you can get
information about the result of an analysis, such as which variables are
tainted.

For more details, see the [docs](https://docs.rs/llvm-ir-taint).

[`llvm-ir`]: https://crates.io/crates/llvm-ir
[`llvm-sys`]: https://crates.io/crates/llvm-sys
[`Module`]: https://docs.rs/llvm-ir/0.8.1/llvm_ir/module/struct.Module.html
[`do_taint_analysis_on_function()`]: https://docs.rs/llvm-ir-taint/latest/llvm_ir_taint/fn.do_taint_analysis_on_function.html
[`do_taint_analysis_on_module()`]: https://docs.rs/llvm-ir-taint/latest/llvm_ir_taint/fn.do_taint_analysis_on_module.html
[`TaintResult`]: https://docs.rs/llvm-ir-taint/latest/llvm_ir_taint/struct.TaintResult.html

pub mod config;
mod function_summary;
mod function_taint_state;
mod globals;
mod modules;
mod named_structs;
mod pointee;
mod taint_result;
mod taint_state;
mod tainted_type;
mod worklist;

pub use config::Config;
pub use tainted_type::TaintedType;
pub use pointee::Pointee;
pub use taint_result::TaintResult;
pub use named_structs::NamedStructInitialDef;

use llvm_ir::{Module, Name};
use taint_state::TaintState;
use std::collections::HashMap;

/// The main function in this module. Given an LLVM module or modules and the
/// name of a function to analyze, returns a `TaintResult` with data on that
/// function and all functions it calls, directly or transitively.
///
/// `args`: the `TaintedType` to assign to each argument of the start function.
/// If this is not provided, all arguments (and everything they point to, etc)
/// will be marked untainted.
///
/// `nonargs`: (optional) Initial `TaintedType`s for any nonargument variables in
/// the start function. For instance, you can use this to set some variable in
/// the middle of the function to tainted. If this map is empty, all
/// `TaintedType`s will simply be inferred normally from the argument
/// `TaintedType`s.
pub fn do_taint_analysis_on_function<'m>(
    modules: impl IntoIterator<Item = &'m Module>,
    config: &'m Config,
    start_fn_name: &str,
    args: Option<Vec<TaintedType>>,
    nonargs: HashMap<Name, TaintedType>,
    named_structs: HashMap<String, NamedStructInitialDef>,
) -> TaintResult<'m> {
    TaintState::do_analysis_single_function(modules, config, start_fn_name, args, nonargs, named_structs)
        .into_taint_result()
}

/// Like `do_taint_analysis_on_function`, but analyzes all functions in the
/// `Module`, rather than only a start function and the functions it calls.
///
/// `args`: Map of LLVM function name to a vector specifying the `TaintedType`s
/// to assign to each argument of that function.
/// For functions not included in `args`, all arguments will be assumed to be
/// untainted, unless inferred otherwise from the taint-tracking process.
///
/// `nonargs`: Map of LLVM function name to a map of nonargument variable name to
/// initial `TaintedType` for that variable. For instance, you can use this to
/// set some variable in the middle of some function to tainted. All variables
/// not specified this way will simply be inferred normally from the argument
/// `TaintedType`s.
pub fn do_taint_analysis_on_module<'m>(
    modules: impl IntoIterator<Item = &'m Module>,
    config: &'m Config,
    args: HashMap<&'m str, Vec<TaintedType>>,
    nonargs: HashMap<&'m str, HashMap<Name, TaintedType>>,
    named_structs: HashMap<String, NamedStructInitialDef>,
) -> TaintResult<'m> {
    TaintState::do_analysis_multiple_functions(modules, config, args, nonargs, named_structs)
        .into_taint_result()
}

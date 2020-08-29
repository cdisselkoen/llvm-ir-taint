pub mod config;
mod function_summary;
mod function_taint_state;
mod globals;
mod module_taint_result;
mod module_taint_state;
mod named_structs;
mod pointee;
mod tainted_type;
mod worklist;

pub use config::Config;
pub use tainted_type::TaintedType;
pub use module_taint_result::ModuleTaintResult;

use llvm_ir::{Module, Name};
use module_taint_state::ModuleTaintState;
use std::collections::HashMap;

/// The main function in this module. Given an LLVM module and the name of a
/// function to analyze, returns a `ModuleTaintResult` with data on that function
/// and all functions it calls, directly or transitively.
///
/// `args`: the `TaintedType` to assign to each argument of the start function.
///
/// `nonargs`: (optional) Initial `TaintedType`s for any nonargument variables in
/// the start function. For instance, you can use this to set some variable in
/// the middle of the function to tainted. If this map is empty, all
/// `TaintedType`s will simply be inferred normally from the argument
/// `TaintedType`s.
pub fn do_taint_analysis<'m>(
    module: &'m Module,
    config: &'m Config,
    start_fn_name: &str,
    args: Vec<TaintedType>,
    nonargs: HashMap<Name, TaintedType>,
) -> ModuleTaintResult<'m> {
    let f = module.get_func_by_name(start_fn_name).unwrap_or_else(|| {
        panic!(
            "Failed to find function named {:?} in the given module",
            start_fn_name
        )
    });
    assert_eq!(args.len(), f.parameters.len());
    let mut initial_taintmap = nonargs;
    for (name, ty) in f
        .parameters
        .iter()
        .map(|p| p.name.clone())
        .zip(args.into_iter())
    {
        initial_taintmap.insert(name, ty);
    }
    ModuleTaintState::do_analysis(module, config, &f.name, initial_taintmap)
        .into_module_taint_result()
}

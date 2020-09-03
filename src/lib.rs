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

use itertools::Itertools;
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
pub fn do_taint_analysis_on_function<'m>(
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
    let mut initial_taintmap = nonargs;
    for (name, ty) in f
        .parameters
        .iter()
        .map(|p| p.name.clone())
        .zip_eq(args.into_iter())
    {
        initial_taintmap.insert(name, ty);
    }
    ModuleTaintState::do_analysis_single_function(module, config, &f.name, initial_taintmap)
        .into_module_taint_result()
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
    module: &'m Module,
    config: &'m Config,
    args: HashMap<&'m str, Vec<TaintedType>>,
    nonargs: HashMap<&'m str, HashMap<Name, TaintedType>>,
) -> ModuleTaintResult<'m> {
    let mut initial_fn_taint_maps = nonargs;
    for (funcname, argtypes) in args.into_iter() {
        let func = module.get_func_by_name(&funcname).unwrap_or_else(|| {
            panic!(
                "Failed to find function named {:?} in the given module",
                funcname
            );
        });
        let initial_fn_taint_map: &mut HashMap<Name, TaintedType> = initial_fn_taint_maps.entry(funcname.clone()).or_default();
        for (name, ty) in func.parameters.iter().map(|p| p.name.clone()).zip_eq(argtypes.into_iter()) {
            initial_fn_taint_map.insert(name, ty);
        }
    }
    let module_fns = module.functions.iter().map(|f| f.name.as_str());
    ModuleTaintState::do_analysis_multiple_functions(module, config, module_fns, initial_fn_taint_maps)
        .into_module_taint_result()
}

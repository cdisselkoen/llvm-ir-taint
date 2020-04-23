use llvm_ir::{Module, Name};
use llvm_ir_taint::*;
use std::path::Path;

fn get_module() -> Module {
    let modname = "../haybale/tests/bcfiles/struct.bc";
    Module::from_bc_path(&Path::new(modname))
        .unwrap_or_else(|e| panic!("Failed to parse module {:?}: {}", modname, e))
}

#[test]
fn one_int() {
    let funcname = "one_int";
    let module = get_module();
    let func = module
        .get_func_by_name(funcname)
        .unwrap_or_else(|| panic!("Failed to find function named {:?}", funcname));

    // Tainting the input should cause the output to be tainted, after being
    // written into the struct field and then read back out
    let taintmap = get_taint_map_for_function(
        func,
        vec![TaintedType::TaintedValue],
        std::iter::once((Name::from(8), TaintedType::TaintedValue)).collect(),
    );
    assert_eq!(
        taintmap.get(&Name::from(9)),
        Some(&TaintedType::TaintedValue)
    );
}

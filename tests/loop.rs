use llvm_ir::{Module, Name};
use llvm_ir_taint::*;
use std::path::Path;

fn get_module() -> Module {
    let modname = "../haybale/tests/bcfiles/loop.bc";
    Module::from_bc_path(&Path::new(modname))
        .unwrap_or_else(|e| panic!("Failed to parse module {:?}: {}", modname, e))
}

#[test]
fn while_loop() {
    let funcname = "while_loop";
    let module = get_module();
    let func = module.get_func_by_name(funcname).unwrap_or_else(|| panic!("Failed to find function named {:?}", funcname));

    // Mark %8 tainted, manually. This should mean that although %7 was marked
    // untainted on the first pass, at fixpoint it should be marked tainted.
    let taintmap = get_taint_map_for_function(
        func,
        vec![TaintedType::UntaintedValue],
        std::iter::once((Name::from(8), TaintedType::TaintedValue)).collect(),
    );
    assert_eq!(taintmap.get(&Name::from(7)), Some(&TaintedType::TaintedValue));
}

#[test]
fn for_loop() {
    let funcname = "for_loop";
    let module = get_module();
    let func = module.get_func_by_name(funcname).unwrap_or_else(|| panic!("Failed to find function named {:?}", funcname));

    // Mark %12 tainted, manually. This should mean that %8 (the return value)
    // ends up tainted at fixpoint.
    let taintmap = get_taint_map_for_function(
        func,
        vec![TaintedType::UntaintedValue],
        std::iter::once((Name::from(12), TaintedType::TaintedValue)).collect(),
    );
    assert_eq!(taintmap.get(&Name::from(8)), Some(&TaintedType::TaintedValue));
}

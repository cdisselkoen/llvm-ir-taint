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

    // Mark %8 tainted, manually. This should mean that although %7 was marked
    // untainted on the first pass, at fixpoint it should be marked tainted.
    let taintmap = get_taint_map_for_function(
        &module,
        funcname,
        vec![TaintedType::UntaintedValue],
        std::iter::once((Name::from(8), TaintedType::TaintedValue)).collect(),
    );
    assert_eq!(
        taintmap.get(&Name::from(7)),
        Some(&TaintedType::TaintedValue)
    );
}

#[test]
fn for_loop() {
    let funcname = "for_loop";
    let module = get_module();

    // Mark %12 tainted, manually. This should mean that %8 (the return value)
    // ends up tainted at fixpoint.
    let taintmap = get_taint_map_for_function(
        &module,
        funcname,
        vec![TaintedType::UntaintedValue],
        std::iter::once((Name::from(12), TaintedType::TaintedValue)).collect(),
    );
    assert_eq!(
        taintmap.get(&Name::from(8)),
        Some(&TaintedType::TaintedValue)
    );
}

#[test]
fn loop_over_array() {
    let funcname = "loop_over_array";
    let module = get_module();

    // Tainting %12 should be sufficient to taint %8 on a subsequent pass, and
    // %11 should be marked as pointer-to-tainted.
    // Then, the final return value %6 should also be marked tainted.
    let taintmap = get_taint_map_for_function(
        &module,
        funcname,
        vec![TaintedType::UntaintedValue],
        std::iter::once((Name::from(12), TaintedType::TaintedValue)).collect(),
    );
    assert_eq!(
        taintmap.get(&Name::from(8)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(11)),
        Some(&TaintedType::untainted_ptr_to(TaintedType::TaintedValue))
    );
    assert_eq!(
        taintmap.get(&Name::from(6)),
        Some(&TaintedType::TaintedValue)
    );
}

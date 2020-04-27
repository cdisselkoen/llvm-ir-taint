use llvm_ir::{Module, Name};
use llvm_ir_taint::*;
use std::collections::HashMap;
use std::path::Path;

fn get_module() -> Module {
    let modname = "../haybale/tests/bcfiles/call.bc";
    Module::from_bc_path(&Path::new(modname))
        .unwrap_or_else(|e| panic!("Failed to parse module {:?}: {}", modname, e))
}

#[test]
fn simple_call() {
    let module = get_module();

    // test basic taint tracking through a called function
    let mts = get_taint_maps_for_function(
        &module,
        "simple_caller",
        vec![TaintedType::TaintedValue],
        HashMap::new(),
    );
    let caller_taintmap = mts.get_function_taint_map("simple_caller");
    let callee_taintmap = mts.get_function_taint_map("simple_callee");
    assert_eq!(callee_taintmap.get(&Name::from(0)), Some(&TaintedType::TaintedValue));
    assert_eq!(callee_taintmap.get(&Name::from(1)), Some(&TaintedType::UntaintedValue));
    assert_eq!(callee_taintmap.get(&Name::from(3)), Some(&TaintedType::TaintedValue));
    assert_eq!(caller_taintmap.get(&Name::from(2)), Some(&TaintedType::TaintedValue));
}

#[test]
fn nested_call() {
    let module = get_module();

    // test basic taint tracking through two calls
    let mts = get_taint_maps_for_function(
        &module,
        "nested_caller",
        vec![TaintedType::TaintedValue, TaintedType::UntaintedValue],
        HashMap::new(),
    );
    let nested_caller_taintmap = mts.get_function_taint_map("nested_caller");
    let callee_taintmap = mts.get_function_taint_map("simple_callee");
    assert_eq!(callee_taintmap.get(&Name::from(0)), Some(&TaintedType::TaintedValue));
    assert_eq!(callee_taintmap.get(&Name::from(1)), Some(&TaintedType::UntaintedValue));
    assert_eq!(callee_taintmap.get(&Name::from(3)), Some(&TaintedType::TaintedValue));
    assert_eq!(nested_caller_taintmap.get(&Name::from(4)), Some(&TaintedType::TaintedValue));
}

#[test]
fn call_in_loop() {
    let module = get_module();

    // untainted function input, but manually mark %13 as tainted.
    // on the first pass, the call appears to have untainted arguments.
    // but on the second pass, it becomes clear that the call has tainted arguments.
    let mts = get_taint_maps_for_function(
        &module,
        "caller_with_loop",
        vec![TaintedType::UntaintedValue],
        std::iter::once((Name::from(13), TaintedType::TaintedValue)).collect(),
    );
    let caller_taintmap = mts.get_function_taint_map("caller_with_loop");
    let callee_taintmap = mts.get_function_taint_map("simple_callee");
    assert_eq!(callee_taintmap.get(&Name::from(0)), Some(&TaintedType::TaintedValue));
    assert_eq!(callee_taintmap.get(&Name::from(1)), Some(&TaintedType::UntaintedValue));
    assert_eq!(callee_taintmap.get(&Name::from(3)), Some(&TaintedType::TaintedValue));
    assert_eq!(caller_taintmap.get(&Name::from(12)), Some(&TaintedType::TaintedValue));
    assert_eq!(caller_taintmap.get(&Name::from(9)), Some(&TaintedType::TaintedValue));
}

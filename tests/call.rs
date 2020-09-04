use llvm_ir::{Module, Name};
use llvm_ir_taint::*;
use std::collections::HashMap;
use std::path::Path;

fn init_logging() {
    // capture log messages with test harness
    let _ = env_logger::builder().is_test(true).try_init();
}

fn get_module() -> Module {
    let modname = "../haybale/tests/bcfiles/call.bc";
    Module::from_bc_path(&Path::new(modname))
        .unwrap_or_else(|e| panic!("Failed to parse module {:?}: {}", modname, e))
}

#[test]
fn simple_call() {
    init_logging();
    let module = get_module();
    let config = Config::default();

    // test basic taint tracking through a called function
    let mtr = do_taint_analysis_on_function(
        &module,
        &config,
        "simple_caller",
        Some(vec![TaintedType::TaintedValue]),
        HashMap::new(),
        HashMap::new(),
    );
    let caller_taintmap = mtr.get_function_taint_map("simple_caller");
    let callee_taintmap = mtr.get_function_taint_map("simple_callee");
    assert_eq!(
        callee_taintmap.get(&Name::from(0)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        callee_taintmap.get(&Name::from(1)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        callee_taintmap.get(&Name::from(3)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        caller_taintmap.get(&Name::from(2)),
        Some(&TaintedType::TaintedValue)
    );
}

#[test]
fn nested_call() {
    init_logging();
    let module = get_module();
    let config = Config::default();

    // test basic taint tracking through two calls
    let mtr = do_taint_analysis_on_function(
        &module,
        &config,
        "nested_caller",
        Some(vec![TaintedType::TaintedValue, TaintedType::UntaintedValue]),
        HashMap::new(),
        HashMap::new(),
    );
    let nested_caller_taintmap = mtr.get_function_taint_map("nested_caller");
    let callee_taintmap = mtr.get_function_taint_map("simple_callee");
    assert_eq!(
        callee_taintmap.get(&Name::from(0)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        callee_taintmap.get(&Name::from(1)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        callee_taintmap.get(&Name::from(3)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        nested_caller_taintmap.get(&Name::from(4)),
        Some(&TaintedType::TaintedValue)
    );
}

#[test]
fn call_in_loop() {
    init_logging();
    let module = get_module();
    let config = Config::default();

    // untainted function input, but manually mark %13 as tainted.
    // on the first pass, the call appears to have untainted arguments.
    // but on the second pass, it becomes clear that the call has tainted arguments.
    let mtr = do_taint_analysis_on_function(
        &module,
        &config,
        "caller_with_loop",
        Some(vec![TaintedType::UntaintedValue]),
        std::iter::once((Name::from(13), TaintedType::TaintedValue)).collect(),
        HashMap::new(),
    );
    let caller_taintmap = mtr.get_function_taint_map("caller_with_loop");
    let callee_taintmap = mtr.get_function_taint_map("simple_callee");
    assert_eq!(
        callee_taintmap.get(&Name::from(0)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        callee_taintmap.get(&Name::from(1)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        callee_taintmap.get(&Name::from(3)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        caller_taintmap.get(&Name::from(12)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        caller_taintmap.get(&Name::from(9)),
        Some(&TaintedType::TaintedValue)
    );
}

#[test]
fn recursive_call() {
    init_logging();
    let module = get_module();
    let config = Config::default();
    let funcname = "recursive_simple";

    // untainted function input, but we mark %2 tainted, so the function input
    // should be marked tainted at fixpoint
    let mtr = do_taint_analysis_on_function(
        &module,
        &config,
        funcname,
        Some(vec![TaintedType::UntaintedValue]),
        std::iter::once((Name::from(2), TaintedType::TaintedValue)).collect(),
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(0)),
        Some(&TaintedType::TaintedValue)
    );
}

#[test]
fn mutually_recursive_call() {
    init_logging();
    let module = get_module();
    let config = Config::default();
    let funcname = "mutually_recursive_a";

    // untainted function input, but we mark %4 tainted, so after recursion,
    // the function input should eventually be marked tainted
    let mtr = do_taint_analysis_on_function(
        &module,
        &config,
        funcname,
        Some(vec![TaintedType::UntaintedValue]),
        std::iter::once((Name::from(4), TaintedType::TaintedValue)).collect(),
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(0)),
        Some(&TaintedType::TaintedValue)
    );
}

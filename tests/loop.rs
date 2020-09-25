use llvm_ir::{Module, Name};
use llvm_ir_taint::*;
use std::collections::HashMap;

fn init_logging() {
    // capture log messages with test harness
    let _ = env_logger::builder().is_test(true).try_init();
}

fn get_module() -> Module {
    let modname = "../haybale/tests/bcfiles/loop.bc";
    Module::from_bc_path(modname)
        .unwrap_or_else(|e| panic!("Failed to parse module {:?}: {}", modname, e))
}

#[test]
fn while_loop() {
    init_logging();
    let funcname = "while_loop";
    let module = get_module();
    let modules = [module];
    let config = Config::default();

    // Mark %8 tainted, manually. This should mean that although %7 was marked
    // untainted on the first pass, at fixpoint it should be marked tainted.
    let taint_result = do_taint_analysis_on_function(
        &modules,
        &config,
        funcname,
        Some(vec![TaintedType::UntaintedValue]),
        std::iter::once((Name::from(8), TaintedType::TaintedValue)).collect(),
        HashMap::new(),
    );
    let taintmap = taint_result.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(7)),
        Some(&TaintedType::TaintedValue)
    );
}

#[test]
fn for_loop() {
    init_logging();
    let funcname = "for_loop";
    let module = get_module();
    let modules = [module];
    let config = Config::default();

    // Mark %12 tainted, manually. This should mean that %8 (the return value)
    // ends up tainted at fixpoint.
    let taint_result = do_taint_analysis_on_function(
        &modules,
        &config,
        funcname,
        Some(vec![TaintedType::UntaintedValue]),
        std::iter::once((Name::from(12), TaintedType::TaintedValue)).collect(),
        HashMap::new(),
    );
    let taintmap = taint_result.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(8)),
        Some(&TaintedType::TaintedValue)
    );
}

#[test]
fn loop_with_cond() {
    init_logging();
    let funcname = "loop_with_cond";
    let module = get_module();
    let modules = [module];
    let config = Config::default();

    // This tests that tainted control flow works properly.
    // Tainting the input (%0) means that %19 gets tainted; %19 influences the
    // control flow out of block %16, so the value stored to %2 in block %13
    // should be tainted, and since the value stored at %2 is marked tainted,
    // the value loaded into %14 should also be marked tainted.
    // Likewise, again due to tainted control flow, the value stored to %3 in
    // block %16 should be tainted, so the value loaded into (for instance) %17
    // should also be marked tainted.
    let taint_result = do_taint_analysis_on_function(
        &modules,
        &config,
        funcname,
        Some(vec![TaintedType::TaintedValue]),
        HashMap::new(),
        HashMap::new(),
    );
    let taintmap = taint_result.get_function_taint_map(funcname);
    for (name, ty) in taintmap {
        println!("{}: {}", name, ty);
    }
    assert_eq!(
        taintmap.get(&Name::from(0)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(19)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(14)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(17)),
        Some(&TaintedType::TaintedValue)
    );
}

#[test]
fn loop_over_array() {
    init_logging();
    let funcname = "loop_over_array";
    let module = get_module();
    let modules = [module];
    let config = Config::default();

    // Tainting %12 should be sufficient to taint %8 on a subsequent pass, and
    // %11 should be marked as pointer-to-tainted.
    // Then, the final return value %6 should also be marked tainted.
    let taint_result = do_taint_analysis_on_function(
        &modules,
        &config,
        funcname,
        Some(vec![TaintedType::UntaintedValue]),
        std::iter::once((Name::from(12), TaintedType::TaintedValue)).collect(),
        HashMap::new(),
    );
    let taintmap = taint_result.get_function_taint_map(funcname);
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

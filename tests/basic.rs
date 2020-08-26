use llvm_ir::{Module, Name};
use llvm_ir_taint::*;
use std::collections::HashMap;
use std::path::Path;

fn get_basic_module() -> Module {
    let modname = "../haybale/tests/bcfiles/basic.bc";
    Module::from_bc_path(&Path::new(modname))
        .unwrap_or_else(|e| panic!("Failed to parse module {:?}: {}", modname, e))
}

fn get_memory_module() -> Module {
    let modname = "../haybale/tests/bcfiles/memory.bc";
    Module::from_bc_path(&Path::new(modname))
        .unwrap_or_else(|e| panic!("Failed to parse module {:?}: {}", modname, e))
}

#[test]
fn basic_operation() {
    let funcname = "two_args";
    let module = get_basic_module();

    // with both arguments tainted
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![TaintedType::TaintedValue, TaintedType::TaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(0)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(1)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(3)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(4)),
        Some(&TaintedType::TaintedValue)
    );

    // with neither argument tainted
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![TaintedType::UntaintedValue, TaintedType::UntaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(0)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(1)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(3)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(4)),
        Some(&TaintedType::UntaintedValue)
    );

    // with just the first argument tainted
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![TaintedType::TaintedValue, TaintedType::UntaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(0)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(1)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(3)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(4)),
        Some(&TaintedType::TaintedValue)
    );

    // with just the second argument tainted
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![TaintedType::UntaintedValue, TaintedType::TaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(0)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(1)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(3)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(4)),
        Some(&TaintedType::TaintedValue)
    );
}

#[test]
fn binops() {
    let funcname = "binops";
    let module = get_basic_module();

    // with both arguments tainted
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![TaintedType::TaintedValue, TaintedType::TaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(0)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(1)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(3)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(4)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(5)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(6)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(7)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(8)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(9)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(10)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(11)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(12)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(13)),
        Some(&TaintedType::TaintedValue)
    );

    // with neither argument tainted
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![TaintedType::UntaintedValue, TaintedType::UntaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(0)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(1)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(3)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(4)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(5)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(6)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(7)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(8)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(9)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(10)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(11)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(12)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(13)),
        Some(&TaintedType::UntaintedValue)
    );

    // with just the second argument tainted
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![TaintedType::UntaintedValue, TaintedType::TaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(0)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(1)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(3)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(4)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(5)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(6)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(7)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(8)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(9)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(10)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(11)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(12)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(13)),
        Some(&TaintedType::TaintedValue)
    );

    // with %8 manually tainted, and nothing else
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![TaintedType::UntaintedValue, TaintedType::UntaintedValue],
        std::iter::once((Name::from(8), TaintedType::TaintedValue)).collect(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(0)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(1)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(3)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(4)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(5)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(6)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(7)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(8)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(9)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(10)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(11)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(12)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(13)),
        Some(&TaintedType::TaintedValue)
    );
}

#[test]
fn phi() {
    let funcname = "conditional_nozero";
    let module = get_basic_module();

    // with both arguments untainted
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![TaintedType::UntaintedValue, TaintedType::UntaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(0)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(1)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(3)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(7)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(15)),
        Some(&TaintedType::UntaintedValue)
    );

    // with second argument tainted
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![TaintedType::UntaintedValue, TaintedType::TaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(0)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(1)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(3)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(7)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(15)),
        Some(&TaintedType::TaintedValue)
    ); // some phi options are tainted and some not; result of phi should be tainted in this case
}

#[test]
fn load_and_store() {
    let funcname = "load_and_store";
    let module = get_memory_module();

    // with both arguments untainted
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![
            TaintedType::untainted_ptr_to(TaintedType::UntaintedValue),
            TaintedType::UntaintedValue,
        ],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(0)),
        Some(&TaintedType::untainted_ptr_to(TaintedType::UntaintedValue))
    );
    assert_eq!(
        taintmap.get(&Name::from(1)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(3)),
        Some(&TaintedType::UntaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(4)),
        Some(&TaintedType::UntaintedValue)
    );

    // with value tainted: make sure that we correctly load a tainted value
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![
            TaintedType::untainted_ptr_to(TaintedType::UntaintedValue),
            TaintedType::TaintedValue,
        ],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(0)),
        Some(&TaintedType::untainted_ptr_to(TaintedType::TaintedValue))
    ); // %0 should have been updated to be pointer-to-tainted
    assert_eq!(
        taintmap.get(&Name::from(1)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(3)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(4)),
        Some(&TaintedType::TaintedValue)
    );
}

#[test]
fn alloca() {
    let funcname = "local_ptr";
    let module = get_memory_module();

    // with the argument untainted
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![TaintedType::UntaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(5)),
        Some(&TaintedType::UntaintedValue)
    ); // load untainted value from the alloca'd space

    // with the argument tainted
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![TaintedType::TaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(5)),
        Some(&TaintedType::TaintedValue)
    ); // load tainted value from the alloca'd space
    assert_eq!(
        taintmap.get(&Name::from(2)),
        Some(&TaintedType::untainted_ptr_to(TaintedType::TaintedValue))
    ); // also, the alloca pointer should have type pointer-to-tainted
}

#[test]
fn overwrite() {
    let funcname = "overwrite";
    let module = get_memory_module();

    // with both arguments untainted
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![
            TaintedType::untainted_ptr_to(TaintedType::UntaintedValue),
            TaintedType::UntaintedValue,
        ],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(4)),
        Some(&TaintedType::UntaintedValue)
    );

    // with the second argument tainted
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![
            TaintedType::untainted_ptr_to(TaintedType::UntaintedValue),
            TaintedType::TaintedValue,
        ],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(4)),
        Some(&TaintedType::TaintedValue)
    );
}

#[test]
fn load_and_store_mult() {
    let funcname = "load_and_store_mult";
    let module = get_memory_module();

    // with both arguments untainted
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![
            TaintedType::untainted_ptr_to(TaintedType::UntaintedValue),
            TaintedType::UntaintedValue,
        ],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(7)),
        Some(&TaintedType::UntaintedValue)
    );

    // with the second argument tainted
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![
            TaintedType::untainted_ptr_to(TaintedType::UntaintedValue),
            TaintedType::TaintedValue,
        ],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(7)),
        Some(&TaintedType::TaintedValue)
    );
}

#[test]
fn array() {
    let funcname = "load_and_store_mult";
    let module = get_memory_module();

    // with both arguments untainted
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![
            TaintedType::untainted_ptr_to(TaintedType::UntaintedValue),
            TaintedType::UntaintedValue,
        ],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(6)),
        Some(&TaintedType::UntaintedValue)
    );

    // with the second argument tainted
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![
            TaintedType::untainted_ptr_to(TaintedType::UntaintedValue),
            TaintedType::TaintedValue,
        ],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(6)),
        Some(&TaintedType::TaintedValue)
    );

    // with %5 tainted but %3 not. In this case we want to ensure that the
    // (tainted) store to %0 doesn't affect the load from %4, which should
    // remain untainted.
    let mtr = do_taint_analysis(
        &module,
        funcname,
        vec![
            TaintedType::untainted_ptr_to(TaintedType::UntaintedValue),
            TaintedType::UntaintedValue,
        ],
        std::iter::once((Name::from(5), TaintedType::TaintedValue)).collect(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(6)),
        Some(&TaintedType::TaintedValue)
    );
}

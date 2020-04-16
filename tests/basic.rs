use llvm_ir::{Module, Name};
use llvm_ir_taint::*;
use std::path::Path;

fn get_module() -> Module {
    let modname = "../haybale/tests/bcfiles/basic.bc";
    Module::from_bc_path(&Path::new(modname))
        .unwrap_or_else(|e| panic!("Failed to parse module {:?}: {}", modname, e))
}

#[test]
fn basic_operation() {
    let funcname = "two_args";
    let module = get_module();
    let func = module.get_func_by_name(funcname).unwrap_or_else(|| panic!("Failed to find function named {:?}", funcname));

    // with both arguments tainted
    let taintmap = get_taint_map_for_function(
        &func,
        vec![TaintedType::TaintedValue, TaintedType::TaintedValue],
    );
    assert_eq!(taintmap.get(&Name::from(0)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(1)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(3)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(4)), Some(&TaintedType::TaintedValue));

    // with neither argument tainted
    let taintmap = get_taint_map_for_function(
        &func,
        vec![TaintedType::UntaintedValue, TaintedType::UntaintedValue],
    );
    assert_eq!(taintmap.get(&Name::from(0)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(1)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(3)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(4)), Some(&TaintedType::UntaintedValue));

    // with just the first argument tainted
    let taintmap = get_taint_map_for_function(
        &func,
        vec![TaintedType::TaintedValue, TaintedType::UntaintedValue],
    );
    assert_eq!(taintmap.get(&Name::from(0)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(1)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(3)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(4)), Some(&TaintedType::TaintedValue));

    // with just the second argument tainted
    let taintmap = get_taint_map_for_function(
        &func,
        vec![TaintedType::UntaintedValue, TaintedType::TaintedValue],
    );
    assert_eq!(taintmap.get(&Name::from(0)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(1)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(3)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(4)), Some(&TaintedType::TaintedValue));
}

#[test]
fn binops() {
    let funcname = "binops";
    let module = get_module();
    let func = module.get_func_by_name(funcname).unwrap_or_else(|| panic!("Failed to find function named {:?}", funcname));

    // with both arguments tainted
    let taintmap = get_taint_map_for_function(
        &func,
        vec![TaintedType::TaintedValue, TaintedType::TaintedValue],
    );
    assert_eq!(taintmap.get(&Name::from(0)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(1)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(3)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(4)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(5)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(6)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(7)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(8)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(9)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(10)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(11)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(12)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(13)), Some(&TaintedType::TaintedValue));

    // with neither argument tainted
    let taintmap = get_taint_map_for_function(
        &func,
        vec![TaintedType::UntaintedValue, TaintedType::UntaintedValue],
    );
    assert_eq!(taintmap.get(&Name::from(0)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(1)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(3)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(4)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(5)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(6)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(7)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(8)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(9)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(10)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(11)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(12)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(13)), Some(&TaintedType::UntaintedValue));

    // with just the second argument tainted
    let taintmap = get_taint_map_for_function(
        &func,
        vec![TaintedType::UntaintedValue, TaintedType::TaintedValue],
    );
    assert_eq!(taintmap.get(&Name::from(0)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(1)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(3)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(4)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(5)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(6)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(7)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(8)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(9)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(10)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(11)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(12)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(13)), Some(&TaintedType::TaintedValue));
}

#[test]
fn phi() {
    let funcname = "conditional_nozero";
    let module = get_module();
    let func = module.get_func_by_name(funcname).unwrap_or_else(|| panic!("Failed to find function named {:?}", funcname));

    // with both arguments untainted
    let taintmap = get_taint_map_for_function(
        &func,
        vec![TaintedType::UntaintedValue, TaintedType::UntaintedValue],
    );
    assert_eq!(taintmap.get(&Name::from(0)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(1)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(3)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(7)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(15)), Some(&TaintedType::UntaintedValue));

    // with second argument tainted
    let taintmap = get_taint_map_for_function(
        &func,
        vec![TaintedType::UntaintedValue, TaintedType::TaintedValue],
    );
    assert_eq!(taintmap.get(&Name::from(0)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(1)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(3)), Some(&TaintedType::UntaintedValue));
    assert_eq!(taintmap.get(&Name::from(7)), Some(&TaintedType::TaintedValue));
    assert_eq!(taintmap.get(&Name::from(15)), Some(&TaintedType::TaintedValue));  // some phi options are tainted and some not; result of phi should be tainted in this case
}

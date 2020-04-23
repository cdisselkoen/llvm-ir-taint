use llvm_ir::{Module, Name};
use llvm_ir_taint::*;
use std::collections::HashMap;
use std::path::Path;

fn get_module() -> Module {
    let modname = "../haybale/tests/bcfiles/struct.bc";
    Module::from_bc_path(&Path::new(modname))
        .unwrap_or_else(|e| panic!("Failed to parse module {:?}: {}", modname, e))
}

#[test]
fn one_struct_element() {
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

#[test]
fn two_struct_elements() {
    let funcname = "two_ints_second";
    let module = get_module();
    let func = module
        .get_func_by_name(funcname)
        .unwrap_or_else(|| panic!("Failed to find function named {:?}", funcname));

    // Tainting the input should cause the output to be tainted, just as in the
    // above test.
    // This time we check the type of %3 to ensure that the first field wasn't
    // tainted, only the second
    let taintmap =
        get_taint_map_for_function(func, vec![TaintedType::TaintedValue], HashMap::new());
    assert_eq!(
        taintmap.get(&Name::from(9)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(3)),
        Some(&TaintedType::untainted_ptr_to(TaintedType::struct_of(
            vec![TaintedType::UntaintedValue, TaintedType::TaintedValue]
        )))
    );
}

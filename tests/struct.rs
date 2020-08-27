use llvm_ir::{Module, Name};
use llvm_ir_taint::*;
use std::collections::HashMap;
use std::path::Path;

fn get_module() -> Module {
    let modname = "../haybale/tests/bcfiles/struct.bc";
    Module::from_bc_path(&Path::new(modname))
        .unwrap_or_else(|e| panic!("Failed to parse module {:?}: {}", modname, e))
}

#[allow(non_snake_case)]
fn get_O3_module() -> Module {
    let modname = "../haybale/tests/bcfiles/struct-O3.bc";
    Module::from_bc_path(&Path::new(modname))
        .unwrap_or_else(|e| panic!("Failed to parse module {:?}: {}", modname, e))
}

#[test]
fn one_struct_element() {
    let funcname = "one_int";
    let module = get_module();
    let config = Config::default();

    // Tainting the input should cause the output to be tainted, after being
    // written into the struct field and then read back out
    let mtr = do_taint_analysis(
        &module,
        &config,
        funcname,
        vec![TaintedType::TaintedValue],
        std::iter::once((Name::from(8), TaintedType::TaintedValue)).collect(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(9)),
        Some(&TaintedType::TaintedValue)
    );
}

#[test]
fn two_struct_elements() {
    let funcname = "two_ints_second";
    let module = get_module();
    let config = Config::default();

    // Tainting the input should cause the output to be tainted, just as in the
    // above test.
    // This time we check the type of %3 to ensure that the first field wasn't
    // tainted, only the second
    let mtr = do_taint_analysis(
        &module,
        &config,
        funcname,
        vec![TaintedType::TaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(9)),
        Some(&TaintedType::TaintedValue)
    );
    assert_eq!(
        taintmap.get(&Name::from(3)),
        Some(&TaintedType::untainted_ptr_to(TaintedType::NamedStruct("struct.TwoInts".into())))
    );
    assert_eq!(
        mtr.get_named_struct_type("struct.TwoInts"),
        &TaintedType::struct_of(vec![
            TaintedType::UntaintedValue,
            TaintedType::TaintedValue,
        ])
    );
}

#[test]
fn zero_initialize() {
    let funcname = "zero_initialize";
    let module = get_module();
    let config = Config::default();

    // With tainted input, we should have tainted output, but none of the struct
    // fields should be tainted, and neither should %21
    let mtr = do_taint_analysis(
        &module,
        &config,
        funcname,
        vec![TaintedType::TaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(26)),
        Some(&TaintedType::TaintedValue),
    );
    assert_eq!(
        taintmap.get(&Name::from(3)),
        Some(&TaintedType::untainted_ptr_to(TaintedType::NamedStruct("struct.ThreeInts".into())))
    );
    assert_eq!(
        mtr.get_named_struct_type("struct.ThreeInts"),
        &TaintedType::struct_of(vec![
            TaintedType::UntaintedValue,
            TaintedType::UntaintedValue,
            TaintedType::UntaintedValue
        ])
    );
    assert_eq!(
        taintmap.get(&Name::from(21)),
        Some(&TaintedType::UntaintedValue),
    );
}

#[test]
fn nested_struct() {
    let module = get_module();
    let config = Config::default();

    // For nested_first, we just check that tainted input results in tainted output
    let mtr = do_taint_analysis(
        &module,
        &config,
        "nested_first",
        vec![TaintedType::TaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map("nested_first");
    assert_eq!(
        taintmap.get(&Name::from(16)),
        Some(&TaintedType::TaintedValue),
    );

    // For nested_all, we let the first argument be untainted and the second tainted.
    // We expect that n.mm.el1, i.e. %26 and %38, remains untainted, while the
    // final output is tainted.
    let mtr = do_taint_analysis(
        &module,
        &config,
        "nested_all",
        vec![TaintedType::UntaintedValue, TaintedType::TaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map("nested_all");
    assert_eq!(
        taintmap.get(&Name::from(26)),
        Some(&TaintedType::UntaintedValue),
    );
    assert_eq!(
        taintmap.get(&Name::from(38)),
        Some(&TaintedType::UntaintedValue),
    );
    assert_eq!(
        taintmap.get(&Name::from(57)),
        Some(&TaintedType::TaintedValue),
    );
}

#[test]
fn with_array() {
    let funcname = "with_array";
    let module = get_module();
    let config = Config::default();

    // We check the inferred TaintedType for the struct, %3, given tainted input
    let mtr = do_taint_analysis(
        &module,
        &config,
        funcname,
        vec![TaintedType::TaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(3)),
        Some(&TaintedType::untainted_ptr_to(TaintedType::NamedStruct("struct.WithArray".into())))
    );
    assert_eq!(
        mtr.get_named_struct_type("struct.WithArray"),
        &TaintedType::struct_of(vec![
            TaintedType::NamedStruct("struct.Mismatched".into()),
            TaintedType::TaintedValue,
            TaintedType::NamedStruct("struct.Mismatched".into()),
        ])
    );
    assert_eq!(
        mtr.get_named_struct_type("struct.Mismatched"),
        &TaintedType::struct_of(vec![
            TaintedType::UntaintedValue,
            TaintedType::UntaintedValue,
            TaintedType::UntaintedValue,
        ])
    );
}

#[test]
fn structptr() {
    let module = get_module();
    let config = Config::default();

    // For these two functions, we just check that tainted input causes tainted output

    let mtr = do_taint_analysis(
        &module,
        &config,
        "structptr",
        vec![TaintedType::TaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map("structptr");
    assert_eq!(
        taintmap.get(&Name::from(21)),
        Some(&TaintedType::TaintedValue)
    );

    let mtr = do_taint_analysis(
        &module,
        &config,
        "structelptr",
        vec![TaintedType::TaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map("structelptr");
    assert_eq!(
        taintmap.get(&Name::from(16)),
        Some(&TaintedType::TaintedValue)
    );
}

#[test]
fn changeptr() {
    let funcname = "changeptr";
    let module = get_module();
    let config = Config::default();

    // For this function, given tainted input, we check that the final inferred
    // TaintedType for ti is a pointer to a ThreeInts with the second element
    // tainted
    let mtr = do_taint_analysis(
        &module,
        &config,
        funcname,
        vec![TaintedType::TaintedValue],
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(5)),
        Some(&TaintedType::untainted_ptr_to(TaintedType::untainted_ptr_to(TaintedType::NamedStruct("struct.ThreeInts".into())))),
    );
    assert_eq!(
        mtr.get_named_struct_type("struct.ThreeInts"),
        &TaintedType::struct_of(vec![
            TaintedType::UntaintedValue,
            TaintedType::TaintedValue,
            TaintedType::UntaintedValue,
        ]),
    );
}

#[test]
fn with_ptr() {
    let funcname = "with_ptr";
    let module = get_O3_module();
    let mut config = Config::default();
    config.ext_functions.insert("malloc".into(), ExternalFunctionHandling::IgnoreAndReturnUntainted);

    // For this function, given tainted input, check that the final inferred
    // TaintedType for struct TwoInts is (untainted, tainted)
    // and that the final inferred TaintedType for struct WithPointer has the
    // appropriate structure
    let mtr = do_taint_analysis(
        &module,
        &config,
        funcname,
        vec![TaintedType::TaintedValue],
        HashMap::new(),
    );
    assert_eq!(
        mtr.get_named_struct_type("struct.TwoInts"),
        &TaintedType::struct_of(vec![
            TaintedType::UntaintedValue,
            TaintedType::TaintedValue,
        ]),
    );
    assert_eq!(
        mtr.get_named_struct_type("struct.WithPointer"),
        &TaintedType::struct_of(vec![
            TaintedType::NamedStruct("struct.TwoInts".into()),
            TaintedType::untainted_ptr_to(TaintedType::untainted_ptr_to(TaintedType::NamedStruct("struct.TwoInts".into()))),
        ]),
    );
}

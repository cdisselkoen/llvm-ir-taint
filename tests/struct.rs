use llvm_ir::{Module, Name};
use llvm_ir_taint::*;
use llvm_ir_taint::config::ExternalFunctionHandling;
use std::collections::HashMap;

fn init_logging() {
    // capture log messages with test harness
    let _ = env_logger::builder().is_test(true).try_init();
}

fn get_module() -> Module {
    let modname = "../haybale/tests/bcfiles/struct.bc";
    Module::from_bc_path(modname)
        .unwrap_or_else(|e| panic!("Failed to parse module {:?}: {}", modname, e))
}

#[allow(non_snake_case)]
fn get_O3_module() -> Module {
    let modname = "../haybale/tests/bcfiles/struct-O3.bc";
    Module::from_bc_path(modname)
        .unwrap_or_else(|e| panic!("Failed to parse module {:?}: {}", modname, e))
}

fn get_addl_module() -> Module {
    let modname = "tests/additional_bcfiles/struct.bc";
    Module::from_bc_path(modname)
        .unwrap_or_else(|e| panic!("Failed to parse module {:?}: {}", modname, e))
}

#[test]
fn one_struct_element() {
    init_logging();
    let funcname = "one_int";
    let module = get_module();
    let config = Config::default();

    // Tainting the input should cause the output to be tainted, after being
    // written into the struct field and then read back out
    let mtr = do_taint_analysis_on_function(
        &module,
        &config,
        funcname,
        Some(vec![TaintedType::TaintedValue]),
        std::iter::once((Name::from(8), TaintedType::TaintedValue)).collect(),
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map(funcname);
    assert_eq!(
        taintmap.get(&Name::from(9)),
        Some(&TaintedType::TaintedValue)
    );
}

#[test]
fn two_struct_elements() {
    init_logging();
    let funcname = "two_ints_second";
    let module = get_module();
    let config = Config::default();

    // Tainting the input should cause the output to be tainted, just as in the
    // above test.
    // This time we check the type of %3 to ensure that the first field wasn't
    // tainted, only the second
    let mtr = do_taint_analysis_on_function(
        &module,
        &config,
        funcname,
        Some(vec![TaintedType::TaintedValue]),
        HashMap::new(),
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
    init_logging();
    let funcname = "zero_initialize";
    let module = get_module();
    let config = Config::default();

    // With tainted input, we should have tainted output, but none of the struct
    // fields should be tainted, and neither should %21
    let mtr = do_taint_analysis_on_function(
        &module,
        &config,
        funcname,
        Some(vec![TaintedType::TaintedValue]),
        HashMap::new(),
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
    init_logging();
    let module = get_module();
    let config = Config::default();

    // For nested_first, we just check that tainted input results in tainted output
    let mtr = do_taint_analysis_on_function(
        &module,
        &config,
        "nested_first",
        Some(vec![TaintedType::TaintedValue]),
        HashMap::new(),
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
    let mtr = do_taint_analysis_on_function(
        &module,
        &config,
        "nested_all",
        Some(vec![TaintedType::UntaintedValue, TaintedType::TaintedValue]),
        HashMap::new(),
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
    init_logging();
    let funcname = "with_array";
    let module = get_module();
    let config = Config::default();

    // We check the inferred TaintedType for the struct, %3, given tainted input
    let mtr = do_taint_analysis_on_function(
        &module,
        &config,
        funcname,
        Some(vec![TaintedType::TaintedValue]),
        HashMap::new(),
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
            TaintedType::array_or_vec_of(TaintedType::TaintedValue),
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
    init_logging();
    let module = get_module();
    let config = Config::default();

    // For these two functions, we just check that tainted input causes tainted output

    let mtr = do_taint_analysis_on_function(
        &module,
        &config,
        "structptr",
        Some(vec![TaintedType::TaintedValue]),
        HashMap::new(),
        HashMap::new(),
    );
    let taintmap = mtr.get_function_taint_map("structptr");
    assert_eq!(
        taintmap.get(&Name::from(21)),
        Some(&TaintedType::TaintedValue)
    );

    let mtr = do_taint_analysis_on_function(
        &module,
        &config,
        "structelptr",
        Some(vec![TaintedType::TaintedValue]),
        HashMap::new(),
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
    init_logging();
    let funcname = "changeptr";
    let module = get_module();
    let config = Config::default();

    // For this function, given tainted input, we check that the final inferred
    // TaintedType for ti is a pointer to a ThreeInts with the second element
    // tainted
    let mtr = do_taint_analysis_on_function(
        &module,
        &config,
        funcname,
        Some(vec![TaintedType::TaintedValue]),
        HashMap::new(),
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
    init_logging();
    let funcname = "with_ptr";
    let module = get_O3_module();
    let mut config = Config::default();
    config.ext_functions.insert("malloc".into(), ExternalFunctionHandling::IgnoreAndReturnUntainted);

    // For this function, given tainted input, check that the final inferred
    // TaintedType for struct TwoInts is (untainted, tainted)
    // and that the final inferred TaintedType for struct WithPointer has the
    // appropriate structure
    let mtr = do_taint_analysis_on_function(
        &module,
        &config,
        funcname,
        Some(vec![TaintedType::TaintedValue]),
        HashMap::new(),
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

#[test]
fn addl_structtest() {
    init_logging();
    let funcname = "caller";
    let module = get_addl_module();
    let config = Config::default();

    // For this function, given tainted input, we check that the final inferred
    // TaintedType for struct.ThreeInts is (tainted, untainted, tainted)
    // and that the final type for %8 in caller() is tainted
    // Importantly, this requires that the change to struct.ThreeInts' type made
    // in called() actually puts caller() back on the worklist
    let mtr = do_taint_analysis_on_function(
        &module,
        &config,
        funcname,
        Some(vec![TaintedType::TaintedValue]),
        HashMap::new(),
        HashMap::new(),
    );
    assert_eq!(
        mtr.get_named_struct_type("struct.ThreeInts"),
        &TaintedType::struct_of(vec![
            TaintedType::TaintedValue,
            TaintedType::UntaintedValue,
            TaintedType::TaintedValue,
        ]),
    );
    assert_eq!(
        mtr.get_function_taint_map("caller").get(&Name::Number(8)),
        Some(&TaintedType::TaintedValue),
    );
}

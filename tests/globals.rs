use llvm_ir::{Module, Name};
use llvm_ir_taint::*;
use std::collections::HashMap;

fn init_logging() {
    // capture log messages with test harness
    let _ = env_logger::builder().is_test(true).try_init();
}

fn get_module() -> Module {
    let modname = "../haybale/tests/bcfiles/globals.bc";
    Module::from_bc_path(modname)
        .unwrap_or_else(|e| panic!("Failed to parse module {:?}: {}", modname, e))
}

#[test]
fn globals() {
    init_logging();
    let funcname = "dont_confuse_globals";
    let module = get_module();
    let config = Config::default();

    // Tainting the input should cause the output to be tainted, after being
    // written into the global and then read back out
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
        taintmap.get(&Name::from(4)),
        Some(&TaintedType::TaintedValue)
    );
}

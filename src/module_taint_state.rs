use crate::config::{self, Config};
use crate::function_summary::FunctionSummary;
use crate::function_taint_state::FunctionTaintState;
use crate::globals::Globals;
use crate::module_taint_result::ModuleTaintResult;
use crate::named_structs::{Index, NamedStructs};
use crate::tainted_type::TaintedType;
use crate::worklist::Worklist;
use either::Either;
use llvm_ir::instruction::{groups, BinaryOp, HasResult, UnaryOp};
use llvm_ir::*;
use log::debug;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::collections::hash_map::Entry;
use std::convert::TryInto;
use std::rc::Rc;

pub(crate) struct ModuleTaintState<'m> {
    /// llvm-ir `Module`
    module: &'m Module,

    /// The configuration for the analysis
    config: &'m Config,

    /// Map from function name to the `FunctionTaintState` for that function
    fn_taint_states: HashMap<String, FunctionTaintState<'m>>,

    /// Map from function name to the `FunctionSummary` for that function
    fn_summaries: HashMap<String, FunctionSummary>,

    /// Named structs used in the module, and their definitions (taint statuses)
    named_struct_defs: Rc<RefCell<NamedStructs<'m>>>,

    /// Globals used in the module, and their definitions (taint statuses)
    globals: Rc<RefCell<Globals<'m>>>,

    /// Map from function name to the names of its callers.
    /// Whenever a function summary changes, we add its callers to the worklist
    /// because the new summary could affect inferred types in its callers.
    callers: HashMap<String, HashSet<&'m str>>,

    /// Set of functions which need to be processed again because there's been a
    /// change to taint information which might be relevant to them
    worklist: Rc<RefCell<Worklist<'m>>>,

    /// Name of the function currently being processed
    cur_fn: &'m str,
}

impl<'m> ModuleTaintState<'m> {
    /// Compute the tainted state of all variables using our fixpoint algorithm,
    /// and return the resulting `ModuleTaintState`.
    ///
    /// `start_fn`: name of the function to start the analysis in
    ///
    /// `start_fn_taint_map`: Map from variable names (in `start_fn`) to the
    /// initial `TaintedType`s of those variables. Must include types for the
    /// function parameters; may optionally include types for other variables in
    /// the function.
    pub fn do_analysis(
        module: &'m Module,
        config: &'m Config,
        start_fn: &'m str,
        start_fn_taint_map: HashMap<Name, TaintedType>,
    ) -> Self {
        let mut mts = Self::new(module, config, start_fn, start_fn_taint_map);
        mts.compute();
        mts
    }

    fn new(
        module: &'m Module,
        config: &'m Config,
        start_fn: &'m str,
        start_fn_taint_map: HashMap<Name, TaintedType>,
    ) -> Self {
        let named_struct_defs = Rc::new(RefCell::new(NamedStructs::new(module)));
        let globals = Rc::new(RefCell::new(Globals::new()));
        let worklist = Rc::new(RefCell::new(std::iter::once(start_fn).collect()));
        Self {
            module,
            config,
            fn_taint_states: std::iter::once((
                start_fn.into(),
                FunctionTaintState::from_taint_map(
                    start_fn,
                    start_fn_taint_map,
                    module,
                    named_struct_defs.clone(),
                    globals.clone(),
                    worklist.clone()
                ),
            ))
            .collect(),
            fn_summaries: HashMap::new(),
            named_struct_defs,
            globals,
            callers: HashMap::new(),
            worklist,
            cur_fn: start_fn,
        }
    }

    pub(crate) fn into_module_taint_result(self) -> ModuleTaintResult<'m> {
        ModuleTaintResult {
            fn_taint_states: self.fn_taint_states,
            named_struct_types: self
                .named_struct_defs
                .borrow()
                .all_named_struct_types()
                .map(|(name, ty)| (name.clone(), ty.clone()))
                .collect(),
        }
    }

    /// Run the fixpoint algorithm to completion.
    fn compute(&mut self) {
        // We use a worklist fixpoint algorithm where `self.worklist` contains
        // names of functions which need another pass because of changes made to
        // the `TaintedType` of variables that may affect that function's analysis.
        //
        // Within a function, we simply do a pass over all instructions in the
        // function. More sophisticated would be an instruction-level worklist
        // approach, but that would require having instruction dependency
        // information so that we know what things to put on the worklist when a
        // given variable's taint changes.
        //
        // In either case, this is guaranteed to converge because we only ever
        // change things from untainted to tainted. In the limit, everything becomes
        // tainted, and then nothing can change so the algorithm must terminate.
        loop {
            let fn_name = match self.worklist.borrow_mut().pop() {
                Some(fn_name) => fn_name,
                None => break,
            };
            debug!("Popped {:?} from worklist", fn_name);
            let changed = match self.module.get_func_by_name(fn_name) {
                Some(func) => {
                    // internal function (defined in the current module):
                    // process it normally
                    self
                        .process_function(func)
                        .unwrap_or_else(|e| panic!("In function {:?}: {}", fn_name, e))
                },
                None => {
                    // external function (not defined in the current module):
                    // see how we're configured to handle this function
                    use config::ExternalFunctionHandling;
                    match self.config.ext_functions.get(fn_name) {
                        Some(ExternalFunctionHandling::IgnoreAndReturnUntainted) => {
                            // no need to do anything
                            false
                        },
                        Some(ExternalFunctionHandling::IgnoreAndReturnTainted) => {
                            // mark the return value tainted, if it wasn't already
                            // we require that anyone who places an external
                            // function on the worklist is responsible for
                            // making sure it has at least a default summary in
                            // place, so we can assume here that there is a
                            // summary
                            let summary = self.fn_summaries.get_mut(fn_name).unwrap_or_else(|| panic!("Internal invariant violated: External function {:?} on the worklist has no summary", fn_name));
                            summary.taint_ret()
                        },
                        Some(ExternalFunctionHandling::PropagateTaint) => {
                            unimplemented!("ExternalFunctionHandling::PropagateTaint")
                        },
                        None | Some(ExternalFunctionHandling::Panic) => {
                            panic!("Call of a function named {:?} not found in the module", fn_name)
                        },
                    }
                },
            };
            if changed {
                self.worklist.borrow_mut().add(fn_name);
            }
        }
    }

    fn get_cur_fn(&mut self) -> &mut FunctionTaintState<'m> {
        let cur_fn_name: &str = &self.cur_fn;
        self.fn_taint_states
            .get_mut(cur_fn_name.into())
            .unwrap_or_else(|| {
                panic!(
                    "get_cur_fn: no taint state found for function {:?}",
                    cur_fn_name
                )
            })
    }

    /// Get the `TaintedType` for the given struct name.
    /// Marks the current function as a user of this named struct.
    /// Creates an untainted `TaintedType` for this named struct if no type
    /// previously existed for it.
    pub fn get_named_struct_type(&mut self, struct_name: impl Into<String>) -> TaintedType {
        self.named_struct_defs.borrow_mut().get_named_struct_type(struct_name.into(), &self.cur_fn).clone()
    }

    /// Is this type tainted (or, for structs, is any element of the struct tainted)
    pub fn is_type_tainted(&mut self, ty: &TaintedType) -> bool {
        self.named_struct_defs.borrow_mut().is_type_tainted(ty, &self.cur_fn)
    }

    /// Process the given `Function`.
    ///
    /// Returns `true` if a change was made to the function's taint state, or `false` if not.
    fn process_function(&mut self, f: &'m Function) -> Result<bool, String> {
        debug!("Processing function {:?}", &f.name);
        self.cur_fn = &f.name;

        // get the taint state for the current function, creating a new one if necessary
        let module = self.module; // this is for the borrow checker - allows us to access `module` without needing to borrow `self`
        let named_struct_defs: &Rc<_> = &self.named_struct_defs; // similarly for the borrow checker - see note on above line
        let worklist: &Rc<_> = &self.worklist; // similarly for the borrow checker - see note on above line
        let globals: &Rc<_> = &self.globals; // similarly for the borrow checker - see note on above line
        let cur_fn = self
            .fn_taint_states
            .entry(f.name.clone())
            .or_insert_with(|| {
                FunctionTaintState::from_taint_map(
                    &f.name,
                    f.parameters
                        .iter()
                        .map(|p| {
                            (p.name.clone(), TaintedType::from_llvm_type(&module.type_of(p)))
                        })
                        .collect(),
                    module,
                    Rc::clone(named_struct_defs),
                    Rc::clone(globals),
                    Rc::clone(worklist),
                )
            });

        let summary = match self.fn_summaries.entry(f.name.clone()) {
            Entry::Vacant(ventry) => {
                // no summary: make a starter one, assuming everything is untainted
                let param_llvm_types = f.parameters.iter().map(|p| module.type_of(p));
                let ret_llvm_type = &f.return_type;
                ventry.insert(FunctionSummary::new_untainted(
                    param_llvm_types,
                    ret_llvm_type,
                ))
            },
            Entry::Occupied(oentry) => oentry.into_mut(),
        };
        // update the function parameter types from the current summary
        debug_assert_eq!(f.parameters.len(), summary.get_params().count());
        for (param, param_ty) in f.parameters.iter().zip(summary.get_params()) {
            let _: bool = cur_fn.update_var_taintedtype(param.name.clone(), param_ty.clone()).map_err(|e| {
                format!("Encountered this error:\n  {}\nwhile processing the parameters for this function:\n  {:?}", e, &f.name)
            })?;
            // we throw away the `bool` return value of
            // `update_var_taintedtype` here: we don't care if this was
            // a change. If this was the only change from this pass,
            // there's no need to re-add this function to the worklist.
            // If a change here causes any change to the status of
            // non-parameter variables, that will result in returning
            // `true` below.
        }

        // now do a pass over the function to propagate taints
        let mut changed = false;
        for bb in &f.basic_blocks {
            for inst in &bb.instrs {
                changed |= self.process_instruction(inst).map_err(|e| {
                    format!(
                        "Encountered this error:\n  {}\nwhile processing this instruction:\n  {:?}",
                        e, inst
                    )
                })?;
            }
            changed |= self.process_terminator(&bb.term).map_err(|e| {
                format!(
                    "Encountered this error:\n  {}\nwhile processing this terminator:\n  {:?}",
                    e, &bb.term
                )
            })?;
        }
        Ok(changed)
    }

    /// Process the given `Instruction`, updating the current function's
    /// `FunctionTaintState` if appropriate.
    ///
    /// Returns `true` if a change was made to the `FunctionTaintState`, or `false` if not.
    fn process_instruction(&mut self, inst: &'m Instruction) -> Result<bool, String> {
        if inst.is_binary_op() {
            let cur_fn = self.get_cur_fn();
            let bop: groups::BinaryOp = inst.clone().try_into().unwrap();
            let op0_ty = cur_fn.get_type_of_operand(bop.get_operand0())?;
            let op1_ty = cur_fn.get_type_of_operand(bop.get_operand1())?;
            let result_ty = op0_ty.join(&op1_ty)?;
            cur_fn.update_var_taintedtype(bop.get_result().clone(), result_ty)
        } else {
            match inst {
                // the unary ops which output the same type they input, in our type system
                Instruction::AddrSpaceCast(_)
                | Instruction::FNeg(_)
                | Instruction::FPExt(_)
                | Instruction::FPToSI(_)
                | Instruction::FPToUI(_)
                | Instruction::FPTrunc(_)
                | Instruction::SExt(_)
                | Instruction::SIToFP(_)
                | Instruction::Trunc(_)
                | Instruction::UIToFP(_)
                | Instruction::ZExt(_) => {
                    let cur_fn = self.get_cur_fn();
                    let uop: groups::UnaryOp = inst.clone().try_into().unwrap();
                    let op_ty = cur_fn.get_type_of_operand(uop.get_operand())?;
                    cur_fn.update_var_taintedtype(uop.get_result().clone(), op_ty)
                },
                Instruction::BitCast(bc) => {
                    let cur_fn = self.get_cur_fn();
                    let from_ty = cur_fn.get_type_of_operand(&bc.operand)?;
                    let result_ty = match from_ty {
                        TaintedType::UntaintedValue | TaintedType::UntaintedFnPtr => {
                            TaintedType::from_llvm_type(&bc.to_type)
                        },
                        TaintedType::TaintedValue | TaintedType::TaintedFnPtr => {
                            TaintedType::from_llvm_type(&bc.to_type).to_tainted()
                        },
                        TaintedType::UntaintedPointer(pointee) => match bc.to_type.as_ref() {
                            Type::PointerType { pointee_type, .. } => {
                                let result_pointee_type = if self.is_type_tainted(&pointee.ty()) {
                                    TaintedType::from_llvm_type(&pointee_type).to_tainted()
                                } else {
                                    TaintedType::from_llvm_type(&pointee_type)
                                };
                                TaintedType::untainted_ptr_to(result_pointee_type)
                            },
                            _ => return Err("Bitcast from pointer to non-pointer".into()), // my reading of the LLVM 9 LangRef disallows this
                        },
                        TaintedType::TaintedPointer(pointee) => match bc.to_type.as_ref() {
                            Type::PointerType { pointee_type, .. } => {
                                let result_pointee_type = if self.is_type_tainted(&pointee.ty()) {
                                    TaintedType::from_llvm_type(&pointee_type).to_tainted()
                                } else {
                                    TaintedType::from_llvm_type(&pointee_type)
                                };
                                TaintedType::tainted_ptr_to(result_pointee_type)
                            },
                            _ => return Err("Bitcast from pointer to non-pointer".into()), // my reading of the LLVM 9 LangRef disallows this
                        },
                        from_ty @ TaintedType::Struct(_) => {
                            if self.is_type_tainted(&from_ty) {
                                TaintedType::from_llvm_type(&bc.to_type).to_tainted()
                            } else {
                                TaintedType::from_llvm_type(&bc.to_type)
                            }
                        },
                        TaintedType::NamedStruct(name) => {
                            self.get_named_struct_type(name).clone()
                        },
                    };
                    self.get_cur_fn().update_var_taintedtype(bc.get_result().clone(), result_ty)
                },
                Instruction::ExtractElement(ee) => {
                    let cur_fn = self.get_cur_fn();
                    let result_ty = if cur_fn.is_scalar_operand_tainted(&ee.index)? {
                        TaintedType::TaintedValue
                    } else {
                        cur_fn.get_type_of_operand(&ee.vector)? // in our type system, the type of a vector and the type of one of its elements are the same
                    };
                    cur_fn.update_var_taintedtype(ee.get_result().clone(), result_ty)
                },
                Instruction::InsertElement(ie) => {
                    let cur_fn = self.get_cur_fn();
                    let result_ty = if cur_fn.is_scalar_operand_tainted(&ie.index)?
                        || cur_fn.is_scalar_operand_tainted(&ie.element)?
                    {
                        TaintedType::TaintedValue
                    } else {
                        cur_fn.get_type_of_operand(&ie.vector)? // in our type system, inserting an untainted element does't change the type of the vector
                    };
                    cur_fn.update_var_taintedtype(ie.get_result().clone(), result_ty)
                },
                Instruction::ShuffleVector(sv) => {
                    // Vector operands are still scalars in our type system
                    let cur_fn = self.get_cur_fn();
                    let op0_ty = cur_fn.get_type_of_operand(&sv.operand0)?;
                    let op1_ty = cur_fn.get_type_of_operand(&sv.operand1)?;
                    let result_ty = op0_ty.join(&op1_ty)?;
                    cur_fn.update_var_taintedtype(sv.get_result().clone(), result_ty)
                },
                Instruction::ExtractValue(ev) => {
                    let cur_fn = self.get_cur_fn();
                    let ptr_to_struct =
                        TaintedType::untainted_ptr_to(cur_fn.get_type_of_operand(&ev.aggregate)?);
                    let element_ptr_ty = self.get_element_ptr(&ptr_to_struct, &ev.indices)?;
                    let element_ty = match element_ptr_ty {
                        TaintedType::UntaintedPointer(pointee) => pointee.ty().clone(),
                        _ => return Err("ExtractValue: expected get_element_ptr to return an UntaintedPointer here".into()),
                    };
                    self.get_cur_fn().update_var_taintedtype(ev.get_result().clone(), element_ty)
                },
                Instruction::InsertValue(iv) => {
                    let cur_fn = self.get_cur_fn();
                    let mut aggregate = cur_fn.get_type_of_operand(&iv.aggregate)?;
                    let element_to_insert = cur_fn.get_type_of_operand(&iv.element)?;
                    insert_value_into_struct(
                        &mut aggregate,
                        iv.indices.iter().copied(),
                        element_to_insert,
                    );
                    cur_fn.update_var_taintedtype(iv.get_result().clone(), aggregate)
                },
                Instruction::Alloca(alloca) => {
                    let cur_fn = self.get_cur_fn();
                    let result_ty = if cur_fn.is_scalar_operand_tainted(&alloca.num_elements)? {
                        TaintedType::TaintedValue
                    } else {
                        TaintedType::untainted_ptr_to(TaintedType::from_llvm_type(
                            &alloca.allocated_type,
                        ))
                    };
                    cur_fn.update_var_taintedtype(alloca.get_result().clone(), result_ty)
                },
                Instruction::Load(load) => {
                    let cur_fn = self.get_cur_fn();
                    let result_ty = match cur_fn.get_type_of_operand(&load.address)? {
                        TaintedType::UntaintedValue | TaintedType::TaintedValue => {
                            return Err(format!(
                                "Load: address is not a pointer: {:?}",
                                &load.address
                            ));
                        },
                        TaintedType::UntaintedFnPtr | TaintedType::TaintedFnPtr => {
                            return Err("Loading from a function pointer".into());
                        },
                        TaintedType::Struct(_) | TaintedType::NamedStruct(_) => {
                            return Err(format!(
                                "Load: address is not a pointer: {:?}",
                                &load.address
                            ));
                        },
                        TaintedType::UntaintedPointer(pointee) => {
                            pointee.ty().clone()
                        },
                        TaintedType::TaintedPointer(pointee) => {
                            // we allow loading untainted data through a tainted
                            // pointer, for this analysis. Caller is welcome to
                            // do post-processing to taint every result of a
                            // load from a tainted address and then rerun the
                            // tainting algorithm.
                            pointee.ty().clone()
                        },
                    };
                    cur_fn.update_var_taintedtype(load.get_result().clone(), result_ty)
                },
                Instruction::Store(store) => {
                    let cur_fn = self.get_cur_fn();
                    match cur_fn.get_type_of_operand(&store.address)? {
                        TaintedType::UntaintedValue | TaintedType::TaintedValue => {
                            Err(format!(
                                "Store: address is not a pointer: {:?}",
                                &store.address
                            ))
                        },
                        TaintedType::UntaintedFnPtr | TaintedType::TaintedFnPtr => {
                            Err("Storing to a function pointer".into())
                        },
                        TaintedType::Struct(_) | TaintedType::NamedStruct(_) => Err(format!(
                            "Store: address is not a pointer: {:?}",
                            &store.address
                        )),
                        TaintedType::UntaintedPointer(mut pointee) | TaintedType::TaintedPointer(mut pointee) => {
                            // update the store address's type based on the value being stored through it.
                            // specifically, update the pointee in that address type:
                            // e.g., if we're storing a tainted value, we want
                            // to update the address type to "pointer to tainted"
                            let new_value_type = cur_fn.get_type_of_operand(&store.value)?;
                            cur_fn.update_pointee_taintedtype(&mut pointee, new_value_type)
                        },
                    }
                },
                Instruction::Fence(_) => Ok(false),
                Instruction::GetElementPtr(gep) => {
                    let cur_fn = self.get_cur_fn();
                    let ptr = cur_fn.get_type_of_operand(&gep.address)?;
                    let result_ty = self.get_element_ptr(&ptr, &gep.indices)?;
                    self.get_cur_fn().update_var_taintedtype(gep.get_result().clone(), result_ty)
                },
                Instruction::PtrToInt(pti) => {
                    let cur_fn = self.get_cur_fn();
                    match cur_fn.get_type_of_operand(&pti.operand)? {
                        TaintedType::UntaintedPointer(_) | TaintedType::UntaintedFnPtr => {
                            cur_fn.update_var_taintedtype(pti.get_result().clone(), TaintedType::UntaintedValue)
                        },
                        TaintedType::TaintedPointer(_) | TaintedType::TaintedFnPtr => {
                            cur_fn.update_var_taintedtype(pti.get_result().clone(), TaintedType::TaintedValue)
                        },
                        TaintedType::UntaintedValue => {
                            Err(format!("PtrToInt on an UntaintedValue: {:?}", &pti.operand))
                        },
                        TaintedType::TaintedValue => {
                            Err(format!("PtrToInt on an TaintedValue: {:?}", &pti.operand))
                        },
                        TaintedType::Struct(_) | TaintedType::NamedStruct(_) => {
                            Err(format!("PtrToInt on a struct: {:?}", &pti.operand))
                        },
                    }
                },
                Instruction::ICmp(icmp) => {
                    let cur_fn = self.get_cur_fn();
                    let op0_ty = cur_fn.get_type_of_operand(&icmp.operand0)?;
                    let op1_ty = cur_fn.get_type_of_operand(&icmp.operand1)?;
                    let result_ty = op0_ty.join(&op1_ty)?;
                    cur_fn.update_var_taintedtype(icmp.get_result().clone(), result_ty)
                },
                Instruction::FCmp(fcmp) => {
                    let cur_fn = self.get_cur_fn();
                    let op0_ty = cur_fn.get_type_of_operand(&fcmp.operand0)?;
                    let op1_ty = cur_fn.get_type_of_operand(&fcmp.operand1)?;
                    let result_ty = op0_ty.join(&op1_ty)?;
                    cur_fn.update_var_taintedtype(fcmp.get_result().clone(), result_ty)
                },
                Instruction::Phi(phi) => {
                    let cur_fn = self.get_cur_fn();
                    let mut incoming_types = phi
                        .incoming_values
                        .iter()
                        .map(|(op, _)| cur_fn.get_type_of_operand(op))
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter();
                    let mut result_ty = incoming_types.next().expect("Phi with no incoming values");
                    for ty in incoming_types {
                        result_ty = result_ty.join(&ty)?;
                    }
                    cur_fn.update_var_taintedtype(phi.get_result().clone(), result_ty)
                },
                Instruction::Select(select) => {
                    let cur_fn = self.get_cur_fn();
                    let result_ty = if cur_fn.is_scalar_operand_tainted(&select.condition)? {
                        TaintedType::TaintedValue
                    } else {
                        let true_ty = cur_fn.get_type_of_operand(&select.true_value)?;
                        let false_ty = cur_fn.get_type_of_operand(&select.false_value)?;
                        true_ty.join(&false_ty)?
                    };
                    cur_fn.update_var_taintedtype(select.get_result().clone(), result_ty)
                },
                Instruction::Call(call) => {
                    match &call.function {
                        Either::Right(Operand::ConstantOperand(cref)) => match cref.as_ref() {
                            Constant::GlobalReference { name: Name::Name(name), .. } => {
                                if name.starts_with("llvm.lifetime")
                                    || name.starts_with("llvm.invariant")
                                    || name.starts_with("llvm.launder.invariant")
                                    || name.starts_with("llvm.strip.invariant")
                                    || name.starts_with("llvm.dbg")
                                {
                                    Ok(false) // these are all safe to ignore
                                } else if name.starts_with("llvm.memset") {
                                    // update the address type as appropriate, just like for Store
                                    let cur_fn = self.get_cur_fn();
                                    let address_operand = call.arguments.get(0).map(|(op, _)| op).ok_or_else(|| format!("Expected llvm.memset to have at least three arguments, but it has {}", call.arguments.len()))?;
                                    let value_operand = call.arguments.get(1).map(|(op, _)| op).ok_or_else(|| format!("Expected llvm.memset to have at least three arguments, but it has {}", call.arguments.len()))?;
                                    let address_ty = cur_fn.get_type_of_operand(address_operand)?;
                                    let value_ty = cur_fn.get_type_of_operand(value_operand)?;
                                    let mut pointee = match address_ty {
                                        TaintedType::UntaintedPointer(pointee) | TaintedType::TaintedPointer(pointee) => pointee,
                                        _ => return Err(format!("llvm.memset: expected first argument to be a pointer, but it was {:?}", address_ty)),
                                    };
                                    cur_fn.update_pointee_taintedtype(&mut pointee, value_ty)
                                } else {
                                    self.process_function_call(call, name)
                                }
                            },
                            Constant::GlobalReference{ name, .. } => {
                                unimplemented!("Call of a function with a numbered name: {:?}", name)
                            },
                            _ => unimplemented!("Call of a function pointer"),
                        },
                        Either::Right(_) => unimplemented!("Call of a function pointer"),
                        Either::Left(_) => unimplemented!("inline assembly"),
                    }
                },
                _ => unimplemented!("instruction {:?}", inst),
            }
        }
    }

    /// Process the a call of a function with the given name.
    fn process_function_call(
        &mut self,
        call: &instruction::Call,
        funcname: &'m String,
    ) -> Result<bool, String> {
        let module = self.module;
        // mark this function as a caller of the called function.
        // This ensures that if the summary of the called function is ever updated,
        // the current function will be put back on the worklist.
        let callers = self.callers.entry(funcname.clone()).or_default();
        callers.insert(&self.cur_fn);
        // Get the function summary for the called function
        let summary = match self.fn_summaries.entry(funcname.clone()) {
            Entry::Occupied(oentry) => oentry.into_mut(),
            Entry::Vacant(ventry) => {
                // no summary: start with the default one (nothing tainted) and add the
                // called function to the worklist so that we can compute a better one
                self.worklist.borrow_mut().add(funcname);
                ventry.insert(FunctionSummary::new_untainted(
                    call.arguments.iter().map(|(arg, _)| module.type_of(arg)),
                    &module.type_of(call),
                ))
            },
        };
        // use the `TaintedType`s of the provided arguments to update the
        // `TaintedType`s of the parameters in the function summary, if appropriate
        let cur_fn = {
            // have to inline self.get_cur_fn() here to convince the borrow checker
            // that we only need to borrow self.fn_taint_states and not all of self,
            // so the concurrent (mutable) borrow of self.fn_summaries is OK.
            let cur_fn_name: &str = self.cur_fn.clone();
            self.fn_taint_states
                .get(cur_fn_name)
                .unwrap_or_else(|| panic!("no taint state found for function {:?}", cur_fn_name,))
        };
        let arg_types = call
            .arguments
            .iter()
            .map(|(arg, _)| cur_fn.get_type_of_operand(arg))
            .collect::<Result<_, _>>()?;
        if summary.update_params(arg_types)? {
            // summary changed: put all callers of the called function on the worklist
            for caller in self.callers.get(funcname).unwrap().iter() {
                self.worklist.borrow_mut().add(caller);
            }
            // and also put the called function itself on the worklist
            self.worklist.borrow_mut().add(funcname);
        }
        // and finally, for non-void calls, use the return type in the summary to
        // update the type of the result in this function
        let summary_ret_ty = summary.get_ret_ty().clone(); // this should end the life of `summary` and therefore its mutable borrow of `self.fn_summaries`
        let cur_fn = self.get_cur_fn();
        match &call.dest {
            Some(varname) => {
                cur_fn.update_var_taintedtype(varname.clone(), summary_ret_ty.unwrap())
            },
            None => Ok(false), // nothing changed in the current function
        }
    }

    /// Process the given `Terminator`, updating taint states if appropriate.
    fn process_terminator(&mut self, term: &Terminator) -> Result<bool, String> {
        match term {
            Terminator::Ret(ret) => {
                match self.fn_summaries.get_mut(self.cur_fn) {
                    None => {
                        // no summary: no use making one until we know we need one
                        Ok(false)
                    },
                    Some(summary) => {
                        let cur_fn = {
                            // have to inline self.get_cur_fn() here to convince the borrow checker
                            // that we only need to borrow self.fn_taint_states and not all of self,
                            // so the concurrent (mutable) borrow of self.fn_summaries is OK.
                            let cur_fn_name: &str = self.cur_fn.clone();
                            self.fn_taint_states.get(cur_fn_name).unwrap_or_else(|| {
                                panic!("no taint state found for function {:?}", cur_fn_name,)
                            })
                        };
                        let ty = ret
                            .return_operand
                            .as_ref()
                            .map(|op| cur_fn.get_type_of_operand(op))
                            .transpose()?;
                        if summary.update_ret(&ty.as_ref())? {
                            // summary changed: put all our callers on the worklist
                            for caller in self
                                .callers
                                .get(self.cur_fn)
                                .into_iter()
                                .map(|hs| hs.iter())
                                .flatten()
                            {
                                self.worklist.borrow_mut().add(caller);
                            }
                            Ok(true)
                        } else {
                            Ok(false)
                        }
                    },
                }
            },
            Terminator::Br(_)
            | Terminator::CondBr(_)
            | Terminator::Switch(_)
            | Terminator::IndirectBr(_)
            | Terminator::Unreachable(_) => Ok(false), // we don't need to do anything for any of these terminators
            _ => unimplemented!("terminator {:?}", term),
        }
    }

    fn get_element_ptr<'a, 'b, I: Index + 'b>(
        &mut self,
        parent_ptr: &'a TaintedType,
        indices: impl IntoIterator<Item = &'b I>,
    ) -> Result<TaintedType, String> {
        self.named_struct_defs.borrow_mut().get_element_ptr(&self.cur_fn, parent_ptr, indices)
    }
}

/// Given a struct type and a list of indices for recursive descent, change the indicated element to be the given TaintedType
fn insert_value_into_struct(
    _aggregate: &mut TaintedType,
    _indices: impl IntoIterator<Item = u32>,
    _element_type: TaintedType,
) {
    unimplemented!()
    /*
    match indices.into_iter().next() {
        None => *aggregate = element,
    }
    */
}

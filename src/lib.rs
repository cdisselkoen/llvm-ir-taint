use either::Either;
use llvm_ir::instruction::{groups, BinaryOp, HasResult, UnaryOp};
use llvm_ir::*;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fmt::Debug;
use std::rc::Rc;

/// The main function in this module. Given an LLVM module and the name of a
/// function to analyze, returns a `ModuleTaintState` with data on that function
/// and all functions it calls, directly or transitively.
///
/// `args`: the `TaintedType` to assign to each function argument.
///
/// `nonargs`: (optional) Initial `TaintedType`s for any nonargument variables in
/// the function. For instance, you can use this to set some variable in the
/// middle of the function to tainted. If this map is empty, all `TaintedType`s
/// will simply be inferred normally from the argument `TaintedType`s.
pub fn get_taint_map_for_function(
    module: &Module,
    fn_name: &str,
    args: Vec<TaintedType>,
    nonargs: HashMap<Name, TaintedType>,
) -> HashMap<Name, TaintedType> {
    let mts = get_taint_maps_for_function(module, fn_name, args, nonargs);
    mts.get_function_taint_map(fn_name)
}

/// Like `get_taint_map_for_function`, but returns a `ModuleTaintState`
/// containing info on that function and all functions it calls, directly or
/// transitively.
pub fn get_taint_maps_for_function<'m>(
    module: &'m Module,
    fn_name: &str,
    args: Vec<TaintedType>,
    nonargs: HashMap<Name, TaintedType>,
) -> ModuleTaintState<'m> {
    let f = module.get_func_by_name(fn_name).unwrap_or_else(|| {
        panic!(
            "Failed to find function named {:?} in the given module",
            fn_name
        )
    });
    assert_eq!(args.len(), f.parameters.len());
    let mut initial_taintmap = nonargs;
    for (name, ty) in f
        .parameters
        .iter()
        .map(|p| p.name.clone())
        .zip(args.into_iter())
    {
        initial_taintmap.insert(name, ty);
    }
    ModuleTaintState::do_analysis(module, &f.name, initial_taintmap)
}

/// The type system which we use for this analysis
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum TaintedType {
    /// An untainted value which is not a pointer or struct.
    /// This may also be a (first-class) array or vector with an untainted element type.
    UntaintedValue,
    /// A tainted value which is not a pointer or struct.
    /// This may also be a (first-class) array or vector with a tainted element type.
    TaintedValue,
    /// An untainted pointer to either a scalar or an array. The inner type is the
    /// pointed-to type, or the element type of the array.
    ///
    /// `Rc<RefCell<>>` allows us to have multiple pointers to the same
    /// underlying type.
    UntaintedPointer(Rc<RefCell<TaintedType>>),
    /// A tainted pointer to either a scalar or an array. The inner type is the
    /// pointed-to type, or the element type of the array.
    ///
    /// `Rc<RefCell<>>` allows us to have multiple pointers to the same
    /// underlying type.
    TaintedPointer(Rc<RefCell<TaintedType>>),
    /// A struct, with the given element types
    Struct(Vec<Rc<RefCell<TaintedType>>>),
}

impl TaintedType {
    /// Create a (fresh, unaliased) pointer to the given `TaintedType`
    pub fn untainted_ptr_to(pointee: TaintedType) -> Self {
        Self::UntaintedPointer(Rc::new(RefCell::new(pointee)))
    }

    /// Create a (fresh, unaliased) tainted pointer to the given `TaintedType`
    pub fn tainted_ptr_to(pointee: TaintedType) -> Self {
        Self::TaintedPointer(Rc::new(RefCell::new(pointee)))
    }

    /// Create a struct of the given elements, assuming that no pointers to those
    /// elements already exist
    pub fn struct_of(elements: impl IntoIterator<Item = TaintedType>) -> Self {
        Self::Struct(
            elements
                .into_iter()
                .map(|ty| Rc::new(RefCell::new(ty)))
                .collect(),
        )
    }

    /// Produce the equivalent (untainted) `TaintedType` for a given LLVM type.
    /// Pointers will point to fresh `TaintedType`s to represent their element
    /// types; they will be assumed not to point to existing variables.
    fn from_llvm_type(llvm_ty: &Type) -> Self {
        match llvm_ty {
            Type::IntegerType { .. } => TaintedType::UntaintedValue,
            Type::PointerType { pointee_type, .. } => {
                TaintedType::untainted_ptr_to(TaintedType::from_llvm_type(&**pointee_type))
            },
            Type::FPType(_) => TaintedType::UntaintedValue,
            Type::VectorType { element_type, .. } => TaintedType::from_llvm_type(&**element_type),
            Type::ArrayType { element_type, .. } => TaintedType::from_llvm_type(&**element_type),
            Type::StructType { element_types, .. } => {
                TaintedType::struct_of(element_types.iter().map(TaintedType::from_llvm_type))
            },
            Type::NamedStructType { name, ty } => match ty {
                None => panic!(
                    "TaintedType::from_llvm_type on an opaque struct named {:?}",
                    name
                ),
                Some(ty) => TaintedType::from_llvm_type(
                    &ty.upgrade()
                        .expect("Failed to upgrade weak reference")
                        .read()
                        .unwrap(),
                ),
            },
            Type::X86_MMXType => TaintedType::UntaintedValue,
            Type::MetadataType => TaintedType::UntaintedValue,
            _ => unimplemented!("TaintedType::from_llvm_type on {:?}", llvm_ty),
        }
    }

    /// Get the `TaintedType` of a `Constant`.
    /// If the `Constant` is a `GlobalReference`, we'll create a fresh
    /// `TaintedType` for the global being referenced; we'll assume the global
    /// hasn't been created yet.
    fn from_constant(constant: &Constant) -> Self {
        match constant {
            Constant::Int { .. } => TaintedType::UntaintedValue,
            Constant::Float(_) => TaintedType::UntaintedValue,
            Constant::Null(ty) => TaintedType::from_llvm_type(ty),
            Constant::AggregateZero(ty) => TaintedType::from_llvm_type(ty),
            Constant::Struct { values, .. } => {
                TaintedType::struct_of(values.iter().map(|v| Self::from_constant(v)))
            },
            Constant::Array { element_type, .. } => TaintedType::from_llvm_type(element_type),
            Constant::Vector(vec) => {
                // all elements should be the same type, so we do the type of the first one
                TaintedType::from_llvm_type(
                    &vec.get(0)
                        .expect("Constant::Vector should not be empty")
                        .get_type(),
                )
            },
            Constant::Undef(ty) => TaintedType::from_llvm_type(ty),
            Constant::GlobalReference { ty, .. } => {
                TaintedType::untainted_ptr_to(TaintedType::from_llvm_type(ty))
            },
            _ => unimplemented!("TaintedType::from_constant on {:?}", constant),
        }
    }

    /// Is this type one of the tainted types
    pub fn is_tainted(&self) -> bool {
        match self {
            TaintedType::UntaintedValue => false,
            TaintedType::TaintedValue => true,
            TaintedType::UntaintedPointer(_) => false,
            TaintedType::TaintedPointer(_) => true,
            TaintedType::Struct(elements) => {
                // a struct is tainted if any of its elements are
                elements.iter().any(|e| e.borrow().is_tainted())
            },
        }
    }

    fn to_tainted(&self) -> Self {
        match self {
            TaintedType::UntaintedValue => TaintedType::TaintedValue,
            TaintedType::TaintedValue => TaintedType::TaintedValue,
            TaintedType::UntaintedPointer(rc) => TaintedType::TaintedPointer(rc.clone()),
            TaintedType::TaintedPointer(rc) => TaintedType::TaintedPointer(rc.clone()),
            TaintedType::Struct(elements) => {
                TaintedType::struct_of(elements.iter().map(|e| e.borrow().to_tainted()))
            },
        }
    }

    /// Compute the join of two `TaintedType`s. For instance, joining a tainted
    /// and an untainted produces a tainted; joining a type with itself produces
    /// itself back.
    ///
    /// Joining two pointers will produce a fresh pointer to the join of their
    /// elements; we'll assume that the join of their elements hadn't been
    /// created yet.
    fn join(&self, other: &Self) -> Result<Self, String> {
        use TaintedType::*;
        match (self, other) {
            (UntaintedValue, UntaintedValue) => Ok(UntaintedValue),
            (UntaintedValue, TaintedValue) => Ok(TaintedValue),
            (TaintedValue, UntaintedValue) => Ok(TaintedValue),
            (TaintedValue, TaintedValue) => Ok(TaintedValue),
            (UntaintedPointer(pointee1), UntaintedPointer(pointee2)) => Ok(Self::untainted_ptr_to(
                pointee1.borrow().join(&*pointee2.borrow())?,
            )),
            (UntaintedPointer(pointee1), TaintedPointer(pointee2)) => Ok(Self::tainted_ptr_to(
                pointee1.borrow().join(&*pointee2.borrow())?,
            )),
            (TaintedPointer(pointee1), UntaintedPointer(pointee2)) => Ok(Self::tainted_ptr_to(
                pointee1.borrow().join(&*pointee2.borrow())?,
            )),
            (TaintedPointer(pointee1), TaintedPointer(pointee2)) => Ok(Self::tainted_ptr_to(
                pointee1.borrow().join(&*pointee2.borrow())?,
            )),
            (Struct(elements1), Struct(elements2)) => {
                assert_eq!(
                    elements1.len(),
                    elements2.len(),
                    "join: type mismatch: struct of {} elements with struct of {} elements",
                    elements1.len(),
                    elements2.len()
                );
                Ok(Self::struct_of(
                    elements1
                        .iter()
                        .zip(elements2.iter())
                        .map(|(el1, el2)| el1.borrow().join(&el2.borrow()))
                        .collect::<Result<Vec<_>, String>>()?
                        .into_iter(),
                ))
            },
            _ => Err(format!("join: type mismatch: {:?} vs. {:?}", self, other)),
        }
    }
}

#[derive(Clone)]
struct FunctionTaintState {
    /// Map from `Name`s of variables to their (currently believed) types.
    map: HashMap<Name, TaintedType>,
}

impl FunctionTaintState {
    fn from_taint_map(taintmap: HashMap<Name, TaintedType>) -> Self {
        Self { map: taintmap }
    }

    fn into_taint_map(self) -> HashMap<Name, TaintedType> {
        self.map
    }

    /// Get the `TaintedType` of the given `Operand`, according to the current state.
    fn get_type_of_operand(&self, op: &Operand) -> TaintedType {
        match op {
            Operand::ConstantOperand(constant) => TaintedType::from_constant(constant),
            Operand::MetadataOperand => TaintedType::UntaintedValue,
            Operand::LocalOperand { name, .. } => match self.map.get(name) {
                Some(ty) => ty.clone(),
                None => {
                    // We can end up with this case (operand doesn't exist in
                    // the type map yet) due to loops and other things, because
                    // we process basic blocks in the order they appear in the
                    // LLVM file, we may not yet have processed the block
                    // containing the instruction which defines this operand.
                    // (This can even happen without phi instructions: one
                    // example is the variable %14 used in bb %6 in the function
                    // caller_with_loop in haybale's call.bc.)
                    //
                    // In this case, we'll just assume an appropriate untainted
                    // value, and continue. If it's actually tainted, that will
                    // be corrected on a future pass. (And we'll definitely have
                    // a future pass, because that variable becoming defined
                    // counts as a change for the fixpoint algorithm.)
                    TaintedType::from_llvm_type(&op.get_type())
                },
            },
        }
    }

    /// Return `true` if the given `op` has been marked tainted, otherwise `false`.
    /// This function should only be called on scalars, not pointers, arrays, or structs.
    fn is_scalar_operand_tainted(&self, op: &Operand) -> Result<bool, String> {
        match self.get_type_of_operand(op) {
            TaintedType::UntaintedValue => Ok(false),
            TaintedType::TaintedValue => Ok(true),
            TaintedType::UntaintedPointer(_) => Err(format!(
                "is_scalar_operand_tainted(): operand has pointer type: {:?}",
                op
            )),
            TaintedType::TaintedPointer(_) => Err(format!(
                "is_scalar_operand_tainted(): operand has pointer type: {:?}",
                op
            )),
            TaintedType::Struct(_) => Err(format!(
                "is_scalar_operand_tainted(): operand has struct type: {:?}",
                op
            )),
        }
    }

    /// Update the given variable with the given `TaintedType`.
    /// This perfoms a `join` of the given `TaintedType` and the previous
    /// `TaintedType` assigned to the variable (if any).
    ///
    /// Returns `true` if the variable's `TaintedType` changed (the variable was
    /// previously a different `TaintedType`, or we previously didn't have data
    /// on it)
    fn update_var_taintedtype(
        &mut self,
        name: Name,
        taintedtype: TaintedType,
    ) -> Result<bool, String> {
        match self.map.entry(name) {
            Entry::Occupied(mut oentry) => {
                let joined = oentry.get().join(&taintedtype)?;
                if oentry.get() == &joined {
                    Ok(false)
                } else {
                    oentry.insert(joined);
                    Ok(true)
                }
            },
            Entry::Vacant(ventry) => {
                ventry.insert(taintedtype);
                Ok(true)
            },
        }
    }

    /// Update the given pointee to the given `TaintedType`.
    /// This performs a `join` just like `update_var_taintedtype`.
    /// `pointee` should be the `Rc` from inside a
    /// `TaintedType::UntaintedPointer` or `TaintedType::TaintedPointer`.
    ///
    /// Returns `true` if the pointee's `TaintedType` changed, accounting for the
    /// join operation.
    fn update_pointee_taintedtype(
        &self,
        pointee: &Rc<RefCell<TaintedType>>,
        new_pointee: TaintedType,
    ) -> Result<bool, String> {
        let mut pointee = pointee.borrow_mut();
        let joined_pointee_type = new_pointee.join(&pointee)?;
        if &*pointee == &joined_pointee_type {
            // no change is necessary
            Ok(false)
        } else {
            // update the address type.
            // Storing to the `Rc` ensures that other pointers to the same type will
            // automatically be updated as well. For instance, if we have a pointer to
            // an array, then GEP to get pointer to 3rd element, then store a tainted
            // value to that 3rd element, we want to update _both pointers_ (the original
            // array pointer, and the element pointer) to have type pointer-to-tainted.
            *pointee = joined_pointee_type;
            Ok(true)
        }
    }
}

pub struct ModuleTaintState<'m> {
    /// llvm-ir `Module`
    module: &'m Module,

    /// Map from function name to the `FunctionTaintState` for that function
    fn_taint_states: HashMap<String, FunctionTaintState>,

    /// Map from function name to the `FunctionSummary` for that function
    fn_summaries: HashMap<String, FunctionSummary>,

    /// Map from function name to the names of its callers.
    /// Whenever a function summary changes, we add its callers to the worklist
    /// because the new summary could affect inferred types in its callers.
    callers: HashMap<String, HashSet<&'m str>>,

    /// Set of functions which need to be processed again because there's been a
    /// change to taint information which might be relevant to them
    fn_worklist: HashSet<&'m str>,

    /// Name of the function currently being processed
    cur_fn: &'m str,
}

struct FunctionSummary {
    /// `TaintedType`s of the function parameters
    params: Vec<TaintedType>,

    /// `TaintedType` of the return type, or `None` for void return type
    ret: Option<TaintedType>,
}

impl FunctionSummary {
    fn new_untainted(
        param_llvm_types: impl IntoIterator<Item = Type>,
        ret_llvm_type: &Type,
    ) -> Self {
        Self {
            params: param_llvm_types
                .into_iter()
                .map(|ty| TaintedType::from_llvm_type(&ty))
                .collect(),
            ret: match ret_llvm_type {
                Type::VoidType => None,
                ty => Some(TaintedType::from_llvm_type(ty)),
            },
        }
    }

    /// Update the `TaintedType`s of the function parameters.
    /// Performs a `join` of each type with the corresponding existing type.
    ///
    /// Returns `true` if a change was made to the `FunctionSummary`.
    fn update_params(&mut self, new_params: Vec<TaintedType>) -> Result<bool, String> {
        if new_params.len() != self.params.len() {
            Err(format!(
                "trying to update function from {} parameter(s) to {} parameter(s)",
                self.params.len(),
                new_params.len(),
            ))
        } else {
            let mut retval = false;
            for (param, new_param) in self.params.iter_mut().zip(new_params.into_iter()) {
                let joined = param.join(&new_param)?;
                if param != &joined {
                    retval = true;
                    *param = joined;
                }
            }
            Ok(retval)
        }
    }

    /// Update the `TaintedType` representing the function return type.
    /// Performs a `join` of the given type and the existing return type.
    ///
    /// Returns `true` if a change was made to the `FunctionSummary`.
    fn update_ret(&mut self, new_ret: &Option<&TaintedType>) -> Result<bool, String> {
        match new_ret {
            None => match &self.ret {
                Some(ret) => Err(format!("update_ret: trying to update function from non-void to void. Old return type: {:?}", ret)),
                None => Ok(false),
            },
            Some(new_ret) => {
                let current_ret = self.ret.as_mut().unwrap_or_else(|| panic!("update_ret: trying to update function from void to this non-void type: {:?}", new_ret));
                let joined = new_ret.join(current_ret)?;
                if current_ret == &joined {
                    Ok(false)
                } else {
                    *current_ret = joined;
                    Ok(true)
                }
            },
        }
    }
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
    fn do_analysis(
        module: &'m Module,
        start_fn: &'m str,
        start_fn_taint_map: HashMap<Name, TaintedType>,
    ) -> Self {
        let mut mts = Self::new(module, start_fn, start_fn_taint_map);
        mts.compute();
        mts
    }

    fn new(
        module: &'m Module,
        start_fn: &'m str,
        start_fn_taint_map: HashMap<Name, TaintedType>,
    ) -> Self {
        Self {
            module,
            fn_taint_states: std::iter::once((
                start_fn.into(),
                FunctionTaintState::from_taint_map(start_fn_taint_map),
            ))
            .collect(),
            fn_summaries: HashMap::new(),
            callers: HashMap::new(),
            fn_worklist: std::iter::once(start_fn).collect(),
            cur_fn: start_fn,
        }
    }

    /// Given a function name, returns a map from variable name to `TaintedType`
    /// for all the variables in that function.
    pub fn get_function_taint_map(&self, fn_name: &str) -> HashMap<Name, TaintedType> {
        self.fn_taint_states
            .get(fn_name)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "get_function_taint_map: no taint map found for function {:?}",
                    fn_name
                )
            })
            .into_taint_map()
    }

    /// Run the fixpoint algorithm to completion.
    fn compute(&mut self) {
        // We use a worklist fixpoint algorithm where `self.fn_worklist` contains
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
        while !self.fn_worklist.is_empty() {
            let fn_name = self.pop_from_worklist();
            let func = self.module.get_func_by_name(fn_name).unwrap_or_else(|| {
                panic!(
                    "Function name {:?} found in worklist but not found in module",
                    fn_name
                )
            });
            let changed = self
                .process_function(func)
                .unwrap_or_else(|e| panic!("In function {:?}: {}", fn_name, e));
            if changed {
                self.fn_worklist.insert(fn_name);
            }
        }
    }

    fn pop_from_worklist(&mut self) -> &'m str {
        let fn_name: &'m str = self
            .fn_worklist
            .iter()
            .next()
            .expect("pop_from_worklist: empty worklist")
            .clone();
        self.fn_worklist.remove(fn_name);
        fn_name
    }

    fn get_cur_fn<'a>(&'a mut self) -> &'a mut FunctionTaintState {
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

    /// Process the given `Function`.
    ///
    /// Returns `true` if a change was made to the function's taint state, or `false` if not.
    fn process_function(&mut self, f: &'m Function) -> Result<bool, String> {
        self.cur_fn = &f.name;

        // get the taint state for the current function, creating a new one if necessary
        let cur_fn = self
            .fn_taint_states
            .entry(f.name.clone())
            .or_insert_with(|| {
                FunctionTaintState::from_taint_map(
                    f.parameters
                        .iter()
                        .map(|p| (p.name.clone(), TaintedType::from_llvm_type(&p.get_type())))
                        .collect(),
                )
            });

        let summary = match self.fn_summaries.entry(f.name.clone()) {
            Entry::Vacant(ventry) => {
                // no summary: make a starter one, assuming everything is untainted
                let param_llvm_types = f.parameters.iter().map(|p| p.get_type());
                let ret_llvm_type = &f.return_type;
                ventry.insert(FunctionSummary::new_untainted(
                    param_llvm_types,
                    ret_llvm_type,
                ))
            },
            Entry::Occupied(oentry) => oentry.into_mut(),
        };
        // update the function parameter types from the current summary
        assert_eq!(f.parameters.len(), summary.params.len());
        for (param, param_ty) in f.parameters.iter().zip(summary.params.iter()) {
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
    fn process_instruction(&mut self, inst: &Instruction) -> Result<bool, String> {
        if inst.is_binary_op() {
            let cur_fn = self.get_cur_fn();
            let bop: groups::BinaryOp = inst.clone().try_into().unwrap();
            let op0_ty = cur_fn.get_type_of_operand(bop.get_operand0());
            let op1_ty = cur_fn.get_type_of_operand(bop.get_operand1());
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
                    let op_ty = cur_fn.get_type_of_operand(uop.get_operand());
                    cur_fn.update_var_taintedtype(uop.get_result().clone(), op_ty)
                },
                Instruction::BitCast(bc) => {
                    let cur_fn = self.get_cur_fn();
                    let from_ty = cur_fn.get_type_of_operand(&bc.operand);
                    let result_ty = match from_ty {
                        TaintedType::UntaintedValue => TaintedType::from_llvm_type(&bc.to_type),
                        TaintedType::TaintedValue => {
                            TaintedType::from_llvm_type(&bc.to_type).to_tainted()
                        },
                        TaintedType::UntaintedPointer(rc) => match &bc.to_type {
                            Type::PointerType { pointee_type, .. } => {
                                let result_pointee_type = if rc.borrow().is_tainted() {
                                    TaintedType::from_llvm_type(&**pointee_type).to_tainted()
                                } else {
                                    TaintedType::from_llvm_type(&**pointee_type)
                                };
                                TaintedType::untainted_ptr_to(result_pointee_type)
                            },
                            _ => return Err("Bitcast from pointer to non-pointer".into()), // my reading of the LLVM 9 LangRef disallows this
                        },
                        TaintedType::TaintedPointer(rc) => match &bc.to_type {
                            Type::PointerType { pointee_type, .. } => {
                                let result_pointee_type = if rc.borrow().is_tainted() {
                                    TaintedType::from_llvm_type(&**pointee_type).to_tainted()
                                } else {
                                    TaintedType::from_llvm_type(&**pointee_type)
                                };
                                TaintedType::tainted_ptr_to(result_pointee_type)
                            },
                            _ => return Err("Bitcast from pointer to non-pointer".into()), // my reading of the LLVM 9 LangRef disallows this
                        },
                        from_ty @ TaintedType::Struct(_) => {
                            if from_ty.is_tainted() {
                                TaintedType::from_llvm_type(&bc.to_type).to_tainted()
                            } else {
                                TaintedType::from_llvm_type(&bc.to_type)
                            }
                        },
                    };
                    cur_fn.update_var_taintedtype(bc.get_result().clone(), result_ty)
                },
                Instruction::ExtractElement(ee) => {
                    let cur_fn = self.get_cur_fn();
                    let result_ty = if cur_fn.is_scalar_operand_tainted(&ee.index)? {
                        TaintedType::TaintedValue
                    } else {
                        cur_fn.get_type_of_operand(&ee.vector) // in our type system, the type of a vector and the type of one of its elements are the same
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
                        cur_fn.get_type_of_operand(&ie.vector) // in our type system, inserting an untainted element does't change the type of the vector
                    };
                    cur_fn.update_var_taintedtype(ie.get_result().clone(), result_ty)
                },
                Instruction::ShuffleVector(sv) => {
                    // Vector operands are still scalars in our type system
                    let cur_fn = self.get_cur_fn();
                    let op0_ty = cur_fn.get_type_of_operand(&sv.operand0);
                    let op1_ty = cur_fn.get_type_of_operand(&sv.operand1);
                    let result_ty = op0_ty.join(&op1_ty)?;
                    cur_fn.update_var_taintedtype(sv.get_result().clone(), result_ty)
                },
                Instruction::ExtractValue(ev) => {
                    let cur_fn = self.get_cur_fn();
                    let ptr_to_struct =
                        TaintedType::untainted_ptr_to(cur_fn.get_type_of_operand(&ev.aggregate));
                    let element_ptr_ty = get_element_ptr(&ptr_to_struct, &ev.indices)?;
                    let element_ty = match element_ptr_ty {
                        TaintedType::UntaintedPointer(rc) => rc.borrow().clone(),
                        _ => return Err("ExtractValue: expected get_element_ptr to return an UntaintedPointer here".into()),
                    };
                    cur_fn.update_var_taintedtype(ev.get_result().clone(), element_ty)
                },
                Instruction::InsertValue(iv) => {
                    let cur_fn = self.get_cur_fn();
                    let mut aggregate = cur_fn.get_type_of_operand(&iv.aggregate);
                    let element_to_insert = cur_fn.get_type_of_operand(&iv.element);
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
                    let result_ty = match cur_fn.get_type_of_operand(&load.address) {
                        TaintedType::UntaintedValue => {
                            return Err(format!(
                                "Load: address is not a pointer: {:?}",
                                &load.address
                            ));
                        },
                        TaintedType::TaintedValue => {
                            return Err(format!(
                                "Load: address is not a pointer: {:?}",
                                &load.address
                            ));
                        },
                        TaintedType::Struct(_) => {
                            return Err(format!(
                                "Load: address is not a pointer: {:?}",
                                &load.address
                            ));
                        },
                        TaintedType::UntaintedPointer(pointee_type) => {
                            pointee_type.borrow().clone()
                        },
                        TaintedType::TaintedPointer(pointee_type) => pointee_type.borrow().clone(), // we allow loading untainted data through a tainted pointer, for this analysis. Caller is welcome to do post-processing to taint every result of a load from a tainted address and then rerun the tainting algorithm.
                    };
                    cur_fn.update_var_taintedtype(load.get_result().clone(), result_ty)
                },
                Instruction::Store(store) => {
                    let cur_fn = self.get_cur_fn();
                    match cur_fn.get_type_of_operand(&store.address) {
                        TaintedType::UntaintedValue => Err(format!(
                            "Store: address is not a pointer: {:?}",
                            &store.address
                        )),
                        TaintedType::TaintedValue => Err(format!(
                            "Store: address is not a pointer: {:?}",
                            &store.address
                        )),
                        TaintedType::Struct(_) => Err(format!(
                            "Store: address is not a pointer: {:?}",
                            &store.address
                        )),
                        TaintedType::UntaintedPointer(rc) | TaintedType::TaintedPointer(rc) => {
                            // update the store address's type based on the value being stored through it.
                            // specifically, update the pointee in that address type:
                            // e.g., if we're storing a tainted value, we want
                            // to update the address type to "pointer to tainted"
                            let new_value_type = cur_fn.get_type_of_operand(&store.value);
                            cur_fn.update_pointee_taintedtype(&rc, new_value_type)
                        },
                    }
                },
                Instruction::Fence(_) => Ok(false),
                Instruction::GetElementPtr(gep) => {
                    let cur_fn = self.get_cur_fn();
                    let result_ty =
                        get_element_ptr(&cur_fn.get_type_of_operand(&gep.address), &gep.indices)?;
                    cur_fn.update_var_taintedtype(gep.get_result().clone(), result_ty)
                },
                Instruction::PtrToInt(pti) => {
                    let cur_fn = self.get_cur_fn();
                    match cur_fn.get_type_of_operand(&pti.operand) {
                        TaintedType::UntaintedPointer(_) => cur_fn.update_var_taintedtype(
                            pti.get_result().clone(),
                            TaintedType::UntaintedValue,
                        ),
                        TaintedType::TaintedPointer(_) => cur_fn.update_var_taintedtype(
                            pti.get_result().clone(),
                            TaintedType::TaintedValue,
                        ),
                        TaintedType::UntaintedValue => {
                            Err(format!("PtrToInt on an UntaintedValue: {:?}", &pti.operand))
                        },
                        TaintedType::TaintedValue => {
                            Err(format!("PtrToInt on an TaintedValue: {:?}", &pti.operand))
                        },
                        TaintedType::Struct(_) => {
                            Err(format!("PtrToInt on a struct: {:?}", &pti.operand))
                        },
                    }
                },
                Instruction::ICmp(icmp) => {
                    let cur_fn = self.get_cur_fn();
                    let op0_ty = cur_fn.get_type_of_operand(&icmp.operand0);
                    let op1_ty = cur_fn.get_type_of_operand(&icmp.operand1);
                    let result_ty = op0_ty.join(&op1_ty)?;
                    cur_fn.update_var_taintedtype(icmp.get_result().clone(), result_ty)
                },
                Instruction::FCmp(fcmp) => {
                    let cur_fn = self.get_cur_fn();
                    let op0_ty = cur_fn.get_type_of_operand(&fcmp.operand0);
                    let op1_ty = cur_fn.get_type_of_operand(&fcmp.operand1);
                    let result_ty = op0_ty.join(&op1_ty)?;
                    cur_fn.update_var_taintedtype(fcmp.get_result().clone(), result_ty)
                },
                Instruction::Phi(phi) => {
                    let cur_fn = self.get_cur_fn();
                    let mut incoming_types = phi
                        .incoming_values
                        .iter()
                        .map(|(op, _)| cur_fn.get_type_of_operand(op));
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
                        let true_ty = cur_fn.get_type_of_operand(&select.true_value);
                        let false_ty = cur_fn.get_type_of_operand(&select.false_value);
                        true_ty.join(&false_ty)?
                    };
                    cur_fn.update_var_taintedtype(select.get_result().clone(), result_ty)
                },
                Instruction::Call(call) => {
                    match &call.function {
                        Either::Right(Operand::ConstantOperand(Constant::GlobalReference {
                            name: Name::Name(name),
                            ..
                        })) => {
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
                                let address_ty = cur_fn.get_type_of_operand(address_operand);
                                let value_ty = cur_fn.get_type_of_operand(value_operand);
                                let pointee_ty = match address_ty {
                                    TaintedType::UntaintedPointer(rc) | TaintedType::TaintedPointer(rc) => rc,
                                    _ => return Err(format!("llvm.memset: expected first argument to be a pointer, but it was {:?}", address_ty)),
                                };
                                cur_fn.update_pointee_taintedtype(&pointee_ty, value_ty)
                            } else {
                                match self.module.get_func_by_name(name) {
                                    Some(func) => self.process_function_call(call, func),
                                    None => panic!(
                                        "Call of a function named {:?} not found in the module",
                                        name
                                    ),
                                }
                            }
                        },
                        Either::Right(Operand::ConstantOperand(Constant::GlobalReference {
                            name,
                            ..
                        })) => {
                            unimplemented!("Call of a function with a numbered name: {:?}", name)
                        },
                        Either::Right(_) => unimplemented!("Call of a function pointer"),
                        Either::Left(_) => unimplemented!("inline assembly"),
                    }
                },
                _ => unimplemented!("instruction {:?}", inst),
            }
        }
    }

    /// Process a call of the given `Function`.
    fn process_function_call(
        &mut self,
        call: &instruction::Call,
        func: &'m Function,
    ) -> Result<bool, String> {
        // mark this function as a caller of the called function.
        // This ensures that if the summary of the called function is ever updated,
        // the current function will be put back on the worklist.
        let callers = self.callers.entry(func.name.clone()).or_default();
        callers.insert(&self.cur_fn);
        // use the `TaintedType`s of the provided arguments to update the
        // `TaintedType`s of the parameters in the function summary, if appropriate
        let summary = match self.fn_summaries.entry(func.name.clone()) {
            Entry::Occupied(oentry) => oentry.into_mut(),
            Entry::Vacant(ventry) => {
                // no summary: start with the default one (nothing tainted) and add the
                // called function to the worklist so that we can compute a better one
                self.fn_worklist.insert(&func.name);
                ventry.insert(FunctionSummary::new_untainted(
                    call.arguments.iter().map(|(arg, _)| arg.get_type()),
                    &call.get_type(),
                ))
            },
        };
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
            .collect();
        if summary.update_params(arg_types)? {
            // summary changed: put all callers of the called function on the worklist
            for caller in self.callers.get(&func.name).unwrap().iter() {
                self.fn_worklist.insert(caller);
            }
            // and also put the called function itself on the worklist
            self.fn_worklist.insert(&func.name);
        }
        // and finally, for non-void calls, use the return type in the summary to
        // update the type of the result in this function
        let summary_ret_ty = summary.ret.clone(); // this should end the life of `summary` and therefore its mutable borrow of `self.fn_summaries`
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
                            .map(|op| cur_fn.get_type_of_operand(op));
                        if summary.update_ret(&ty.as_ref())? {
                            // summary changed: put all our callers on the worklist
                            for caller in self
                                .callers
                                .get(self.cur_fn)
                                .into_iter()
                                .map(|hs| hs.iter())
                                .flatten()
                            {
                                self.fn_worklist.insert(caller);
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
}

/// Trait representing things which can be used as struct/array indices.
/// Namely, `Operand`s and constants.
trait Index: Debug {
    /// Convert into a constant value, or `None` if it
    /// doesn't represent a constant value
    fn as_constant(&self) -> Option<u64>;
}

impl Index for Operand {
    fn as_constant(&self) -> Option<u64> {
        match self {
            Operand::LocalOperand { .. } => None,
            Operand::ConstantOperand(Constant::Int { value, .. }) => Some(*value),
            Operand::MetadataOperand => None,
            _ => unimplemented!("as_constant on {:?}", self),
        }
    }
}

impl Index for u32 {
    fn as_constant(&self) -> Option<u64> {
        Some((*self).into())
    }
}

impl Index for &u32 {
    fn as_constant(&self) -> Option<u64> {
        Some((**self).into())
    }
}

impl Index for u64 {
    fn as_constant(&self) -> Option<u64> {
        Some(*self)
    }
}

impl Index for &u64 {
    fn as_constant(&self) -> Option<u64> {
        Some(**self)
    }
}

fn get_element_ptr<'a, 'b, I: Index + 'b>(
    parent_ptr: &'a TaintedType,
    indices: impl IntoIterator<Item = &'b I>,
) -> Result<TaintedType, String> {
    _get_element_ptr(parent_ptr, indices.into_iter().peekable())
}

fn _get_element_ptr<'a, 'b, I: Index + 'b>(
    parent_ptr: &'a TaintedType,
    mut indices: std::iter::Peekable<impl Iterator<Item = &'b I>>,
) -> Result<TaintedType, String> {
    // we 'pop' an index from the list. This represents choosing an element of
    // the "array" pointed to by the pointer.
    let _index = match indices.next() {
        Some(index) => index,
        None => return Err("get_element_ptr: called with no indices".into()),
    };
    // now the rest of this is just for dealing with subsequent indices
    match parent_ptr {
        TaintedType::UntaintedValue => {
            Err("get_element_ptr: address is not a pointer, or too many indices".into())
        },
        TaintedType::TaintedValue => {
            Err("get_element_ptr: address is not a pointer, or too many indices".into())
        },
        TaintedType::Struct(_) => {
            Err("get_element_ptr: address is not a pointer, or too many indices".into())
        },
        TaintedType::UntaintedPointer(rc) | TaintedType::TaintedPointer(rc) => {
            let pointee: &TaintedType = &rc.borrow();
            match pointee {
                TaintedType::TaintedValue | TaintedType::UntaintedValue => {
                    // We expect that indices.peek() would give None in this
                    // case. However, there may be an extra index due to
                    // selecting an element of a first-class array or vector
                    // (which are TaintedValue or UntaintedValue in our type
                    // system). So we just ignore any extra indices.
                    if parent_ptr.is_tainted() {
                        Ok(TaintedType::TaintedPointer(rc.clone()))
                    } else {
                        Ok(TaintedType::UntaintedPointer(rc.clone()))
                    }
                },
                inner_ptr @ TaintedType::TaintedPointer(_)
                | inner_ptr @ TaintedType::UntaintedPointer(_) => {
                    // We'll taint the resulting element ptr depending on the
                    // taint status of the inner_ptr, ignoring the taint status
                    // of the parent_ptr. I believe this is correct for most use
                    // cases.
                    match indices.peek() {
                        None if inner_ptr.is_tainted() => {
                            Ok(TaintedType::TaintedPointer(rc.clone()))
                        },
                        None => Ok(TaintedType::UntaintedPointer(rc.clone())),
                        Some(_) => _get_element_ptr(inner_ptr, indices),
                    }
                },
                TaintedType::Struct(elements) => {
                    match indices.next() {
                        None => {
                            // this case is like the TaintedValue / UntaintedValue
                            // case. The return type is a pointer-to-struct, we
                            // just picked a particular struct from an array of
                            // structs.
                            Ok(parent_ptr.clone())
                        },
                        Some(index) => {
                            // in this case, the new `index` is actually selecting an
                            // element within the struct
                            let index = index.as_constant().expect(
                                "get_element_ptr: indexing into a struct at non-Constant index",
                            );
                            let pointee = elements.get(index as usize).ok_or_else(|| {
                                format!(
                                    "get_element_ptr: index out of range: index {:?} in struct {:?}",
                                    index, pointee
                                )
                            })?;
                            match indices.peek() {
                                None => {
                                    if parent_ptr.is_tainted() {
                                        Ok(TaintedType::TaintedPointer(pointee.clone()))
                                    } else {
                                        Ok(TaintedType::UntaintedPointer(pointee.clone()))
                                    }
                                },
                                Some(_) => _get_element_ptr(&pointee.borrow(), indices),
                            }
                        },
                    }
                },
            }
        },
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

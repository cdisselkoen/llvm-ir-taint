use either::Either;
use llvm_ir::instruction::{groups, BinaryOp, HasResult, UnaryOp};
use llvm_ir::*;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt::Debug;
use std::rc::Rc;

/// The main function in this module. Given an LLVM function, returns a map from
/// variable `Name` to the `TaintedType` of that variable.
///
/// `args`: the `TaintedType` to assign to each function argument. This should be
/// a vector of the same length as `f.parameters`.
///
/// `nonargs`: (optional) Initial `TaintedType`s for any nonargument variables in
/// the function. For instance, you can use this to set some variable in the
/// middle of the function to tainted. If this map is empty, all `TaintedType`s
/// will simply be inferred normally from the argument `TaintedType`s.
pub fn get_taint_map_for_function(
    f: &Function,
    args: Vec<TaintedType>,
    nonargs: HashMap<Name, TaintedType>,
) -> HashMap<Name, TaintedType> {
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
    let mut taintstate = TaintState::from_taint_map(initial_taintmap);
    let mut changed = true;
    // We use a simple fixpoint algorithm where we simply do a pass over all
    // instructions in the function, and if anything changed, do another pass,
    // until fixpoint. More sophisticated would be a worklist approach, but that
    // would require having dependency information so that we know what things
    // to put on the worklist when a given variable's taint changes.
    //
    // In either case, this is guaranteed to converge because we only ever
    // change things from untainted to tainted. In the limit, everything becomes
    // tainted, and then nothing can change so the algorithm must terminate.
    while changed {
        changed = false;
        for bb in &f.basic_blocks {
            for inst in &bb.instrs {
                changed |= taintstate.process_instruction(inst).unwrap_or_else(|e| {
                    panic!(
                        "Encountered this error:\n  {}\nwhile processing this instruction:\n  {:?}",
                        e, inst
                    )
                });
            }
        }
    }
    return taintstate.into_taint_map();
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

struct TaintState {
    /// Map from `Name`s of variables to their (currently believed) types.
    map: HashMap<Name, TaintedType>,
}

impl TaintState {
    fn from_taint_map(taintmap: HashMap<Name, TaintedType>) -> Self {
        Self { map: taintmap }
    }

    fn into_taint_map(self) -> HashMap<Name, TaintedType> {
        self.map
    }

    /// Get the `TaintedType` of the given `Operand`, according to the current state.
    /// Returns an `Err` message if the `Operand` refers to a variable which has
    /// not been defined.
    fn get_type_of_operand(&self, op: &Operand) -> Result<TaintedType, String> {
        self.get_type_of_operand_fallible(op).map_err(|name| {
            format!(
                "get_type_of_operand: operand has not been typed yet: {:?}",
                name
            )
        })
    }

    /// Same as `get_type_of_operand()`, but if it refers to a variable which has not
    /// been defined, returns an `Err` with the name of the undefined variable
    fn get_type_of_operand_fallible<'o>(&self, op: &'o Operand) -> Result<TaintedType, &'o Name> {
        match op {
            Operand::LocalOperand { name, .. } => self.map.get(name).cloned().ok_or(name),
            Operand::ConstantOperand(constant) => Ok(TaintedType::from_constant(constant)),
            Operand::MetadataOperand => Ok(TaintedType::UntaintedValue),
        }
    }

    /// Return `true` if the given `op` has been marked tainted, otherwise `false`.
    /// This function should only be called on scalars, not pointers, arrays, or structs.
    fn is_scalar_operand_tainted(&self, op: &Operand) -> Result<bool, String> {
        match self.get_type_of_operand(op)? {
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
            // Using `rc.replace()` ensures that other pointers to the same type will
            // automatically be updated as well. For instance, if we have a pointer to
            // an array, then GEP to get pointer to 3rd element, then store a tainted
            // value to that 3rd element, we want to update _both pointers_ (the original
            // array pointer, and the element pointer) to have type pointer-to-tainted.
            *pointee = joined_pointee_type;
            Ok(true)
        }
    }

    /// process the given `Instruction`, updating the `TaintState` if appropriate.
    ///
    /// Returns `true` if a change was made to the `TaintState`, or `false` if not.
    fn process_instruction(&mut self, inst: &Instruction) -> Result<bool, String> {
        if inst.is_binary_op() {
            let bop: groups::BinaryOp = inst.clone().try_into().unwrap();
            let op0_ty = self.get_type_of_operand(bop.get_operand0())?;
            let op1_ty = self.get_type_of_operand(bop.get_operand1())?;
            let result_ty = op0_ty.join(&op1_ty)?;
            self.update_var_taintedtype(bop.get_result().clone(), result_ty)
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
                    let uop: groups::UnaryOp = inst.clone().try_into().unwrap();
                    let op_ty = self.get_type_of_operand(uop.get_operand())?;
                    self.update_var_taintedtype(uop.get_result().clone(), op_ty)
                },
                Instruction::BitCast(bc) => {
                    let from_ty = self.get_type_of_operand(&bc.operand)?;
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
                    self.update_var_taintedtype(bc.get_result().clone(), result_ty)
                },
                Instruction::ExtractElement(ee) => {
                    let result_ty = if self.is_scalar_operand_tainted(&ee.index)? {
                        TaintedType::TaintedValue
                    } else {
                        self.get_type_of_operand(&ee.vector)? // in our type system, the type of a vector and the type of one of its elements are the same
                    };
                    self.update_var_taintedtype(ee.get_result().clone(), result_ty)
                },
                Instruction::InsertElement(ie) => {
                    let result_ty = if self.is_scalar_operand_tainted(&ie.index)?
                        || self.is_scalar_operand_tainted(&ie.element)?
                    {
                        TaintedType::TaintedValue
                    } else {
                        self.get_type_of_operand(&ie.vector)? // in our type system, inserting an untainted element does't change the type of the vector
                    };
                    self.update_var_taintedtype(ie.get_result().clone(), result_ty)
                },
                Instruction::ShuffleVector(sv) => {
                    // Vector operands are still scalars in our type system
                    let op0_ty = self.get_type_of_operand(&sv.operand0)?;
                    let op1_ty = self.get_type_of_operand(&sv.operand1)?;
                    let result_ty = op0_ty.join(&op1_ty)?;
                    self.update_var_taintedtype(sv.get_result().clone(), result_ty)
                },
                Instruction::ExtractValue(ev) => {
                    let ptr_to_struct =
                        TaintedType::untainted_ptr_to(self.get_type_of_operand(&ev.aggregate)?);
                    let element_ptr_ty = get_element_ptr(&ptr_to_struct, &ev.indices)?;
                    let element_ty = match element_ptr_ty {
                        TaintedType::UntaintedPointer(rc) => rc.borrow().clone(),
                        _ => return Err("ExtractValue: expected get_element_ptr to return an UntaintedPointer here".into()),
                    };
                    self.update_var_taintedtype(ev.get_result().clone(), element_ty)
                },
                Instruction::InsertValue(iv) => {
                    let mut aggregate = self.get_type_of_operand(&iv.aggregate)?;
                    let element_to_insert = self.get_type_of_operand(&iv.element)?;
                    insert_value_into_struct(
                        &mut aggregate,
                        iv.indices.iter().copied(),
                        element_to_insert,
                    );
                    self.update_var_taintedtype(iv.get_result().clone(), aggregate)
                },
                Instruction::Alloca(alloca) => {
                    let result_ty = if self.is_scalar_operand_tainted(&alloca.num_elements)? {
                        TaintedType::TaintedValue
                    } else {
                        TaintedType::untainted_ptr_to(TaintedType::from_llvm_type(
                            &alloca.allocated_type,
                        ))
                    };
                    self.update_var_taintedtype(alloca.get_result().clone(), result_ty)
                },
                Instruction::Load(load) => {
                    let result_ty = match self.get_type_of_operand(&load.address)? {
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
                    self.update_var_taintedtype(load.get_result().clone(), result_ty)
                },
                Instruction::Store(store) => {
                    match self.get_type_of_operand(&store.address)? {
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
                            let new_value_type = self.get_type_of_operand(&store.value)?;
                            self.update_pointee_taintedtype(&rc, new_value_type)
                        },
                    }
                },
                Instruction::Fence(_) => Ok(false),
                Instruction::GetElementPtr(gep) => {
                    let result_ty =
                        get_element_ptr(&self.get_type_of_operand(&gep.address)?, &gep.indices)?;
                    self.update_var_taintedtype(gep.get_result().clone(), result_ty)
                },
                Instruction::PtrToInt(pti) => match self.get_type_of_operand(&pti.operand)? {
                    TaintedType::UntaintedPointer(_) => self.update_var_taintedtype(
                        pti.get_result().clone(),
                        TaintedType::UntaintedValue,
                    ),
                    TaintedType::TaintedPointer(_) => self.update_var_taintedtype(
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
                },
                Instruction::ICmp(icmp) => {
                    let op0_ty = self.get_type_of_operand(&icmp.operand0)?;
                    let op1_ty = self.get_type_of_operand(&icmp.operand1)?;
                    let result_ty = op0_ty.join(&op1_ty)?;
                    self.update_var_taintedtype(icmp.get_result().clone(), result_ty)
                },
                Instruction::FCmp(fcmp) => {
                    let op0_ty = self.get_type_of_operand(&fcmp.operand0)?;
                    let op1_ty = self.get_type_of_operand(&fcmp.operand1)?;
                    let result_ty = op0_ty.join(&op1_ty)?;
                    self.update_var_taintedtype(fcmp.get_result().clone(), result_ty)
                },
                Instruction::Phi(phi) => {
                    let mut incoming_types = phi
                        .incoming_values
                        .iter()
                        .map(|(op, _)| self.get_type_of_operand_fallible(op))
                        .map(|ty| ty.unwrap_or(TaintedType::from_llvm_type(&phi.to_type))); // In the case that one of the possible incoming values isn't defined yet, we'll just assume an appropriate untainted value, and continue. If it's actually tainted, that will be corrected on a future pass. (And we'll definitely have a future pass, because that variable becoming defined counts as a change for the fixpoint algorithm.)
                    let mut result_ty = incoming_types.next().expect("Phi with no incoming values");
                    for ty in incoming_types {
                        result_ty = result_ty.join(&ty)?;
                    }
                    self.update_var_taintedtype(phi.get_result().clone(), result_ty)
                },
                Instruction::Select(select) => {
                    let result_ty = if self.is_scalar_operand_tainted(&select.condition)? {
                        TaintedType::TaintedValue
                    } else {
                        let true_ty = self.get_type_of_operand(&select.true_value)?;
                        let false_ty = self.get_type_of_operand(&select.false_value)?;
                        true_ty.join(&false_ty)?
                    };
                    self.update_var_taintedtype(select.get_result().clone(), result_ty)
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
                                let address_operand = call.arguments.get(0).map(|(op, _)| op).ok_or_else(|| format!("Expected llvm.memset to have at least three arguments, but it has {}", call.arguments.len()))?;
                                let value_operand = call.arguments.get(1).map(|(op, _)| op).ok_or_else(|| format!("Expected llvm.memset to have at least three arguments, but it has {}", call.arguments.len()))?;
                                let address_ty = self.get_type_of_operand(address_operand)?;
                                let value_ty = self.get_type_of_operand(value_operand)?;
                                let pointee_ty = match address_ty {
                                    TaintedType::UntaintedPointer(rc) | TaintedType::TaintedPointer(rc) => rc,
                                    _ => return Err(format!("llvm.memset: expected first argument to be a pointer, but it was {:?}", address_ty)),
                                };
                                self.update_pointee_taintedtype(&pointee_ty, value_ty)
                            } else {
                                unimplemented!("Call of a function named {}", name)
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
                            let index = index
                                .as_constant()
                                .expect("get_element_ptr: indexing into a struct at non-Constant index");
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

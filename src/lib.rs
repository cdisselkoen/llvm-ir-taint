use llvm_ir::*;
use llvm_ir::instruction::{groups, BinaryOp, HasResult, UnaryOp};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::convert::TryInto;
use std::fmt::Debug;

/// The main function in this module. Given an LLVM function, returns a map from
/// variable `Name` to the `TaintedType` of that variable.
///
/// `args`: the `TaintedType` to assign to each function argument. This should be
/// a vector of the same length as `f.parameters`.
pub fn get_taint_map_for_function(f: &Function, args: Vec<TaintedType>) -> HashMap<Name, TaintedType> {
    assert_eq!(args.len(), f.parameters.len());
    let mut taintstate = TaintState::from_taint_map(f.parameters.iter().map(|p| p.name.clone()).zip(args.into_iter()).collect());
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
                changed |= taintstate.process_instruction(inst);
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
    /// A tainted value.  May be a scalar value or pointer (to anything)
    TaintedValue,
    /// An untainted pointer to either a scalar or an array. The inner type is the
    /// pointed-to type, or the element type of the array.
    UntaintedPointer(Box<TaintedType>),
    /// A struct, with the given element types
    Struct(Vec<TaintedType>),
}

impl TaintedType {
    fn from_llvm_type(llvm_ty: &Type) -> Self {
        match llvm_ty {
            Type::IntegerType { .. } => TaintedType::UntaintedValue,
            Type::PointerType { pointee_type, .. } => TaintedType::UntaintedPointer(Box::new(TaintedType::from_llvm_type(&**pointee_type))),
            Type::FPType(_) => TaintedType::UntaintedValue,
            Type::VectorType { element_type, .. } => TaintedType::from_llvm_type(&**element_type),
            Type::ArrayType { element_type, .. } => TaintedType::from_llvm_type(&**element_type),
            Type::StructType { element_types, .. } => TaintedType::Struct(element_types.iter().map(TaintedType::from_llvm_type).collect()),
            Type::X86_MMXType => TaintedType::UntaintedValue,
            Type::MetadataType => TaintedType::UntaintedValue,
            _ => unimplemented!("TaintedType::from_llvm_type on {:?}", llvm_ty),
        }
    }

    fn from_constant(constant: &Constant) -> Self {
        match constant {
            Constant::Int { .. } => TaintedType::UntaintedValue,
            Constant::Float(_) => TaintedType::UntaintedValue,
            Constant::Null(ty) => TaintedType::from_llvm_type(ty),
            Constant::AggregateZero(ty) => TaintedType::from_llvm_type(ty),
            Constant::Struct { values, .. } => {
                TaintedType::Struct(values.iter().map(|v| Self::from_constant(v)).collect())
            },
            Constant::Array { element_type, .. } => TaintedType::from_llvm_type(element_type),
            Constant::Vector(vec) => {
                // all elements should be the same type, so we do the type of the first one
                TaintedType::from_llvm_type(&vec.get(0).expect("Constant::Vector should not be empty").get_type())
            },
            Constant::Undef(ty) => TaintedType::from_llvm_type(ty),
            Constant::GlobalReference { ty, .. } => TaintedType::UntaintedPointer(Box::new(TaintedType::from_llvm_type(ty))),
            _ => unimplemented!("TaintedType::from_constant on {:?}", constant),
        }
    }

    fn join(&self, other: &Self) -> Self {
        use TaintedType::*;
        match (self, other) {
            (UntaintedValue, UntaintedValue) => UntaintedValue,
            (UntaintedValue, TaintedValue) => TaintedValue,
            (TaintedValue, UntaintedValue) => TaintedValue,
            (TaintedValue, TaintedValue) => TaintedValue,
            (UntaintedPointer(pointee1), UntaintedPointer(pointee2)) => UntaintedPointer(Box::new(pointee1.join(&*pointee2))),
            (Struct(elements1), Struct(elements2)) => {
                assert_eq!(elements1.len(), elements2.len());
                Struct(elements1.iter().zip(elements2.iter()).map(|(el1, el2)| el1.join(el2)).collect())
            },
            _ => panic!("join: type mismatch: {:?} vs. {:?}", self, other),
        }
    }
}

struct TaintState {
    /// Map from `Name`s of variables to their (currently believed) types.
    map: HashMap<Name, TaintedType>,
}

impl TaintState {
    fn from_taint_map(taintmap: HashMap<Name, TaintedType>) -> Self {
        Self {
            map: taintmap,
        }
    }

    fn into_taint_map(self) -> HashMap<Name, TaintedType> {
        self.map
    }

    /// Get the `TaintedType` of the given `Operand`, according to the current state
    fn get_type_of_operand(&self, op: &Operand) -> TaintedType {
        match op {
            Operand::LocalOperand { name, .. } => {
                self.map.get(name).unwrap_or_else(|| panic!("get_type_of_operand: operand has not been typed yet: {:?}", name)).clone()
            },
            Operand::ConstantOperand(constant) => TaintedType::from_constant(constant),
            Operand::MetadataOperand => TaintedType::UntaintedValue,
        }
    }

    /// Return `true` if the given `op` has been marked tainted, otherwise `false`.
    /// This function should only be called on scalars, not pointers, arrays, or structs.
    fn is_scalar_operand_tainted(&self, op: &Operand) -> bool {
        match self.get_type_of_operand(op) {
            TaintedType::UntaintedValue => false,
            TaintedType::TaintedValue => true,
            TaintedType::UntaintedPointer(_) => panic!("is_scalar_operand_tainted(): operand has pointer type: {:?}", op),
            TaintedType::Struct(_) => panic!("is_scalar_operand_tainted(): operand has struct type: {:?}", op),
        }
    }

    /// Update the given variable with the given `TaintedType`.
    /// This perfoms a `join` of the given `TaintedType` and the previous
    /// `TaintedType` assigned to the variable (if any).
    ///
    /// Returns `true` if the variable's `TaintedType` changed (the variable was
    /// previously a different `TaintedType`, or we previously didn't have data
    /// on it)
    fn update_var_taintedtype(&mut self, name: Name, taintedtype: TaintedType) -> bool {
        match self.map.entry(name) {
            Entry::Occupied(mut oentry) => {
                let joined = oentry.get().join(&taintedtype);
                if oentry.get() == &joined {
                    false
                } else {
                    oentry.insert(joined);
                    true
                }
            },
            Entry::Vacant(ventry) => {
                ventry.insert(taintedtype);
                true
            },
        }
    }

    /// process the given `Instruction`, updating the `TaintState` if appropriate.
    ///
    /// Returns `true` if a change was made to the `TaintState`, or `false` if not.
    fn process_instruction(&mut self, inst: &Instruction) -> bool {
        if inst.is_binary_op() {
            let bop: groups::BinaryOp = inst.clone().try_into().unwrap();
            let op0_ty = self.get_type_of_operand(bop.get_operand0());
            let op1_ty = self.get_type_of_operand(bop.get_operand1());
            let result_ty = op0_ty.join(&op1_ty);
            self.update_var_taintedtype(bop.get_result().clone(), result_ty)
        } else {
            match inst {
                // the unary ops which have scalar input and scalar output
                Instruction::AddrSpaceCast(_)
                | Instruction::BitCast(_)
                | Instruction::FNeg(_)
                | Instruction::FPExt(_)
                | Instruction::FPToSI(_)
                | Instruction::FPToUI(_)
                | Instruction::FPTrunc(_)
                | Instruction::SExt(_)
                | Instruction::SIToFP(_)
                | Instruction::Trunc(_)
                | Instruction::UIToFP(_)
                | Instruction::ZExt(_)
                => {
                    let uop: groups::UnaryOp = inst.clone().try_into().unwrap();
                    let op_ty = self.get_type_of_operand(uop.get_operand());
                    self.update_var_taintedtype(uop.get_result().clone(), op_ty)
                },
                Instruction::ExtractElement(ee) => {
                    if self.is_scalar_operand_tainted(&ee.index) {
                        self.update_var_taintedtype(ee.get_result().clone(), TaintedType::TaintedValue)
                    } else {
                        let element_ty = self.get_type_of_operand(&ee.vector);  // in our type system, the type of a vector and the type of one of its elements are the same
                        self.update_var_taintedtype(ee.get_result().clone(), element_ty)
                    }
                },
                Instruction::InsertElement(ie) => {
                    if self.is_scalar_operand_tainted(&ie.index)
                        || self.is_scalar_operand_tainted(&ie.element)
                    {
                        self.update_var_taintedtype(ie.get_result().clone(), TaintedType::TaintedValue)
                    } else {
                        let vector_ty = self.get_type_of_operand(&ie.vector);
                        self.update_var_taintedtype(ie.get_result().clone(), vector_ty)  // in our type system, inserting an untainted element does't change the type of the vector
                    }
                },
                Instruction::ShuffleVector(sv) => {
                    // Vector operands are still scalars in our type system
                    let op0_ty = self.get_type_of_operand(&sv.operand0);
                    let op1_ty = self.get_type_of_operand(&sv.operand1);
                    let result_ty = op0_ty.join(&op1_ty);
                    self.update_var_taintedtype(sv.get_result().clone(), result_ty)
                },
                Instruction::ExtractValue(ev) => {
                    let aggregate = self.get_type_of_operand(&ev.aggregate);
                    self.update_var_taintedtype(ev.get_result().clone(), extract_value_from_struct_or_array(&aggregate, ev.indices.iter()).clone())
                },
                Instruction::InsertValue(iv) => {
                    let mut aggregate = self.get_type_of_operand(&iv.aggregate);
                    let element_to_insert = self.get_type_of_operand(&iv.element);
                    insert_value_into_struct(&mut aggregate, iv.indices.iter().copied(), element_to_insert);
                    self.update_var_taintedtype(iv.get_result().clone(), aggregate)
                },
                Instruction::Alloca(alloca) => {
                    if self.is_scalar_operand_tainted(&alloca.num_elements) {
                        self.update_var_taintedtype(alloca.get_result().clone(), TaintedType::TaintedValue)
                    } else {
                        self.update_var_taintedtype(alloca.get_result().clone(), TaintedType::UntaintedPointer(Box::new(TaintedType::from_llvm_type(&alloca.allocated_type))))
                    }
                },
                Instruction::Load(load) => {
                    match self.get_type_of_operand(&load.address) {
                        TaintedType::TaintedValue => {
                            self.update_var_taintedtype(load.get_result().clone(), TaintedType::TaintedValue)
                        },
                        TaintedType::UntaintedValue => panic!("Load: address is not a pointer: {:?}", &load.address),
                        TaintedType::Struct(_) => panic!("Load: address is not a pointer: {:?}", &load.address),
                        TaintedType::UntaintedPointer(pointee_type) => {
                            self.update_var_taintedtype(load.get_result().clone(), *pointee_type)
                        },
                    }
                },
                Instruction::Store(store) => {
                    match self.get_type_of_operand(&store.address) {
                        TaintedType::TaintedValue => unimplemented!("store with tainted address; address is {:?}", &store.address),
                        TaintedType::UntaintedValue => panic!("Store: address is not a pointer: {:?}", &store.address),
                        TaintedType::Struct(_) => panic!("Store: address is not a pointer: {:?}", &store.address),
                        TaintedType::UntaintedPointer(_) => {
                            match self.get_type_of_operand(&store.value) {
                                // if we're storing a tainted value through a pointer-to-untainted, update the pointer type to be pointer-to-tainted
                                TaintedType::TaintedValue => {
                                    let address_name = match &store.address {
                                        Operand::LocalOperand { name , .. } => name.clone(),
                                        _ => panic!("Store: storing a tainted value to a constant address"),
                                    };
                                    self.update_var_taintedtype(address_name, TaintedType::UntaintedPointer(Box::new(TaintedType::TaintedValue)))
                                },
                                _ => false,
                            }
                        },
                    }
                },
                Instruction::Fence(_) => false,
                Instruction::GetElementPtr(gep) => {
                    match self.get_type_of_operand(&gep.address) {
                        TaintedType::TaintedValue => {
                            self.update_var_taintedtype(gep.get_result().clone(), TaintedType::TaintedValue)
                        },
                        TaintedType::UntaintedValue => panic!("GEP: address is not a pointer: {:?}", &gep.address),
                        TaintedType::Struct(_) => panic!("GEP: address is not a pointer: {:?}", &gep.address),
                        t@TaintedType::UntaintedPointer(_) => {
                            let eltype = extract_value_from_struct_or_array(&t, gep.indices.iter()).clone();
                            let elptr = TaintedType::UntaintedPointer(Box::new(eltype));
                            self.update_var_taintedtype(gep.get_result().clone(), elptr)
                        }
                    }
                },
                Instruction::PtrToInt(pti) => {
                    match self.get_type_of_operand(&pti.operand) {
                        TaintedType::TaintedValue => false,
                        TaintedType::UntaintedPointer(_) => {
                            self.update_var_taintedtype(pti.get_result().clone(), TaintedType::UntaintedValue)
                        },
                        TaintedType::UntaintedValue => {
                            panic!("PtrToInt on an UntaintedValue: {:?}", &pti.operand);
                        },
                        TaintedType::Struct(_) => {
                            panic!("PtrToInt on a struct: {:?}", &pti.operand);
                        }
                    }
                },
                Instruction::ICmp(icmp) => {
                    let op0_ty = self.get_type_of_operand(&icmp.operand0);
                    let op1_ty = self.get_type_of_operand(&icmp.operand1);
                    let result_ty = op0_ty.join(&op1_ty);
                    self.update_var_taintedtype(icmp.get_result().clone(), result_ty)
                },
                Instruction::FCmp(fcmp) => {
                    let op0_ty = self.get_type_of_operand(&fcmp.operand0);
                    let op1_ty = self.get_type_of_operand(&fcmp.operand1);
                    let result_ty = op0_ty.join(&op1_ty);
                    self.update_var_taintedtype(fcmp.get_result().clone(), result_ty)
                },
                Instruction::Phi(phi) => {
                    let mut incoming_types = phi.incoming_values.iter().map(|(op, _)| self.get_type_of_operand(op));
                    let mut result_ty = incoming_types.next().expect("Phi with no incoming values");
                    for ty in incoming_types {
                        result_ty = result_ty.join(&ty);
                    }
                    self.update_var_taintedtype(phi.get_result().clone(), result_ty)
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

/// Given a struct type (or element type of an array) and a list of indices for
/// recursive descent, return the type of the indicated element
fn extract_value_from_struct_or_array<'a, 'b, I: Index + 'b>(aggregate: &'a TaintedType, mut indices: impl Iterator<Item = &'b I>) -> &'a TaintedType {
    match indices.next() {
        None => aggregate,
        Some(index) => match aggregate {
            TaintedType::Struct(elements) => {
                let index = index.as_constant().unwrap_or_else(|| panic!("indexing a struct by nonconstant index; index {:?} in struct {:?}", index, aggregate));
                let chosen_element = elements.get(index as usize).unwrap_or_else(|| panic!("struct index out of range: index {:?} in struct {:?}", index, aggregate));
                extract_value_from_struct_or_array(chosen_element, indices)
            },
            t@TaintedType::UntaintedValue => match indices.next() {
                Some(_) => panic!("extract_value_from_struct_or_array: more indices than expected, dereferencing a scalar"),
                None => t,
            },
            t@TaintedType::TaintedValue => match indices.next() {
                Some(_) => panic!("extract_value_from_struct_or_array: more indices than expected, dereferencing a scalar"),
                None => t,
            },
            TaintedType::UntaintedPointer(pointee_type) => {
                extract_value_from_struct_or_array(pointee_type, indices)
            },
        },
    }
}

/// Given a struct type and a list of indices for recursive descent, change the indicated element to be the given TaintedType
fn insert_value_into_struct(_aggregate: &mut TaintedType, _indices: impl IntoIterator<Item = u32>, _element_type: TaintedType) {
    unimplemented!()
    /*
    match indices.into_iter().next() {
        None => *aggregate = element,
    }
    */
}

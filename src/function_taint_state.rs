use crate::globals::Globals;
use crate::named_structs::NamedStructs;
use crate::pointee::Pointee;
use crate::tainted_type::TaintedType;
use crate::worklist::Worklist;
use llvm_ir::*;
use llvm_ir::constant::ConstBinaryOp;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::rc::Rc;

#[derive(Clone)]
pub struct FunctionTaintState<'m> {
    /// Name of the function
    name: &'m str,
    /// Map from `Name`s of variables to their (currently believed) types.
    map: HashMap<Name, TaintedType>,
    /// Reference to the llvm-ir `Module`
    module: &'m Module,
    /// Reference to the module's named struct types
    pub(crate) named_structs: Rc<RefCell<NamedStructs<'m>>>,
    /// Reference to the module's globals
    pub(crate) globals: Rc<RefCell<Globals<'m>>>,
    /// Reference to the module's worklist
    pub(crate) worklist: Rc<RefCell<Worklist<'m>>>,
}

impl<'m> FunctionTaintState<'m> {
    pub(crate) fn from_taint_map(
        name: &'m str,
        taintmap: HashMap<Name, TaintedType>,
        module: &'m Module,
        named_structs: Rc<RefCell<NamedStructs<'m>>>,
        globals: Rc<RefCell<Globals<'m>>>,
        worklist: Rc<RefCell<Worklist<'m>>>,
    ) -> Self {
        Self {
            name,
            map: taintmap,
            module,
            named_structs,
            globals,
            worklist,
        }
    }

    pub(crate) fn get_taint_map(&self) -> &HashMap<Name, TaintedType> {
        &self.map
    }

    /// Get the `TaintedType` of the given `Operand`, according to the current state.
    pub(crate) fn get_type_of_operand(&self, op: &Operand) -> Result<TaintedType, String> {
        match op {
            Operand::ConstantOperand(constant) => self.get_type_of_constant(constant),
            Operand::MetadataOperand => Ok(TaintedType::UntaintedValue),
            Operand::LocalOperand { name, .. } => match self.map.get(name) {
                Some(ty) => Ok(ty.clone()),
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
                    Ok(TaintedType::from_llvm_type(&self.module.type_of(op)))
                },
            },
        }
    }

    /// Return `true` if the given `op` has been marked tainted, otherwise `false`.
    /// This function should only be called on scalars, not pointers, arrays, or structs.
    pub(crate) fn is_scalar_operand_tainted(&self, op: &Operand) -> Result<bool, String> {
        match self.get_type_of_operand(op)? {
            TaintedType::UntaintedValue => Ok(false),
            TaintedType::TaintedValue => Ok(true),
            TaintedType::UntaintedFnPtr => Ok(false),
            TaintedType::TaintedFnPtr => Ok(true),
            TaintedType::UntaintedPointer(_) => Err(format!(
                "is_scalar_operand_tainted(): operand has pointer type: {:?}",
                op
            )),
            TaintedType::TaintedPointer(_) => Err(format!(
                "is_scalar_operand_tainted(): operand has pointer type: {:?}",
                op
            )),
            TaintedType::ArrayOrVector(_) => Err(format!(
                "is_scalar_operand_tainted(): operand has array or vector type: {:?}",
                op
            )),
            TaintedType::Struct(_) | TaintedType::NamedStruct(_) => Err(format!(
                "is_scalar_operand_tainted(): operand has struct type: {:?}",
                op
            )),
        }
    }

    /// Get the `TaintedType` of a `Constant`.
    pub(crate) fn get_type_of_constant(&self, constant: &Constant) -> Result<TaintedType, String> {
        match constant {
            Constant::Int { .. } => Ok(TaintedType::UntaintedValue),
            Constant::Float(_) => Ok(TaintedType::UntaintedValue),
            Constant::Null(ty) => Ok(TaintedType::from_llvm_type(ty)),
            Constant::AggregateZero(ty) => Ok(TaintedType::from_llvm_type(ty)),
            Constant::Struct { values, .. } => {
                let elements = values
                    .iter()
                    .map(|v| self.get_type_of_constant(v))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(TaintedType::struct_of(elements))
            },
            Constant::Array { element_type, .. } => Ok(TaintedType::from_llvm_type(element_type)),
            Constant::Vector(vec) => {
                // all elements should be the same type, so we do the type of the first one
                Ok(TaintedType::from_llvm_type(
                    &self.module.type_of(vec.get(0).expect("Constant::Vector should not be empty"))
                ))
            },
            Constant::Undef(ty) => Ok(TaintedType::from_llvm_type(ty)),
            Constant::BlockAddress => Ok(TaintedType::UntaintedValue), // technically a pointer, but for our purposes an opaque constant
            Constant::GlobalReference { name, ty } => {
                match ty.as_ref() {
                    Type::FuncType { .. } => Ok(TaintedType::UntaintedFnPtr),
                    _ => {
                        let mut globals = self.globals.borrow_mut();
                        Ok(globals.get_type_of_global(name.clone(), ty, &self.name).clone())
                    },
                }
            },
            Constant::Add(a) => self.get_type_of_constant_binop(a),
            Constant::Sub(s) => self.get_type_of_constant_binop(s),
            Constant::Mul(m) => self.get_type_of_constant_binop(m),
            Constant::UDiv(u) => self.get_type_of_constant_binop(u),
            Constant::SDiv(s) => self.get_type_of_constant_binop(s),
            Constant::URem(u) => self.get_type_of_constant_binop(u),
            Constant::SRem(s) => self.get_type_of_constant_binop(s),
            Constant::And(a) => self.get_type_of_constant_binop(a),
            Constant::Or(o) => self.get_type_of_constant_binop(o),
            Constant::Xor(x) => self.get_type_of_constant_binop(x),
            Constant::LShr(l) => self.get_type_of_constant_binop(l),
            Constant::AShr(a) => self.get_type_of_constant_binop(a),
            Constant::Shl(s) => self.get_type_of_constant_binop(s),
            Constant::FAdd(f) => self.get_type_of_constant_binop(f),
            Constant::FSub(f) => self.get_type_of_constant_binop(f),
            Constant::FMul(f) => self.get_type_of_constant_binop(f),
            Constant::FDiv(f) => self.get_type_of_constant_binop(f),
            Constant::FRem(f) => self.get_type_of_constant_binop(f),
            Constant::Trunc(t) => self.get_type_of_constant(&t.operand),
            Constant::BitCast(b) => self.get_type_of_constant(&b.operand),
            Constant::AddrSpaceCast(a) => self.get_type_of_constant(&a.operand),
            Constant::ZExt(z) => self.get_type_of_constant(&z.operand),
            Constant::SExt(s) => self.get_type_of_constant(&s.operand),
            Constant::UIToFP(u) => self.get_type_of_constant(&u.operand),
            Constant::SIToFP(s) => self.get_type_of_constant(&s.operand),
            Constant::FPExt(f) => self.get_type_of_constant(&f.operand),
            Constant::FPTrunc(f) => self.get_type_of_constant(&f.operand),
            Constant::FPToUI(f) => self.get_type_of_constant(&f.operand),
            Constant::FPToSI(f) => self.get_type_of_constant(&f.operand),
            Constant::IntToPtr(itp) => {
                let int_type = self.get_type_of_constant(&itp.operand)?;
                let ptr_type = TaintedType::from_llvm_type(&self.module.type_of(itp));
                if int_type.is_tainted_nonamedstruct() {
                    Ok(self.named_structs.borrow_mut().to_tainted(&ptr_type))
                } else {
                    Ok(ptr_type)
                }
            },
            Constant::PtrToInt(pti) => {
                let ptr_type = self.get_type_of_constant(&pti.operand)?;
                let int_type = TaintedType::from_llvm_type(&self.module.type_of(pti));
                if ptr_type.is_tainted(Rc::clone(&self.named_structs), self.name) {
                    Ok(self.named_structs.borrow_mut().to_tainted(&int_type))
                } else {
                    Ok(int_type)
                }
            },
            Constant::GetElementPtr(gep) => {
                let parent_ptr = self.get_type_of_constant(&gep.address)?;
                self.named_structs.borrow_mut().get_element_ptr(&self.name, &parent_ptr, &gep.indices)
            },
            _ => unimplemented!("get_type_of_constant on {:?}", constant),
        }
    }

    /// For `ConstBinaryOp`s where the two operands and the result are all the same LLVM type
    pub(crate) fn get_type_of_constant_binop(&self, bop: &impl ConstBinaryOp) -> Result<TaintedType, String> {
        self.get_type_of_constant(&bop.get_operand0())?
            .join(&self.get_type_of_constant(&bop.get_operand1())?)
    }

    /// Update the given variable with the given `TaintedType`.
    /// This perfoms a `join` of the given `TaintedType` and the previous
    /// `TaintedType` assigned to the variable (if any).
    ///
    /// Returns `true` if the variable's `TaintedType` changed (the variable was
    /// previously a different `TaintedType`, or we previously didn't have data
    /// on it)
    pub(crate) fn update_var_taintedtype(
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
    ///
    /// Returns `true` if the pointee's `TaintedType` changed, accounting for the
    /// join operation.
    pub(crate) fn update_pointee_taintedtype(
        &self,
        pointee: &mut Pointee,
        new_pointee: &TaintedType,
    ) -> Result<bool, String> {
        pointee.update(new_pointee, &self)
    }
}

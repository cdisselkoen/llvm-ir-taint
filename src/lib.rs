use either::Either;
use llvm_ir::constant::ConstBinaryOp;
use llvm_ir::instruction::{groups, BinaryOp, HasResult, UnaryOp};
use llvm_ir::types::NamedStructDef;
use llvm_ir::*;
use log::debug;
use std::cell::{Ref, RefCell};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fmt;
use std::fmt::Debug;
use std::iter::FromIterator;
use std::rc::Rc;

#[non_exhaustive]
pub struct Config {
    /// How to handle external functions -- that is, functions not defined in the
    /// `Module`.
    /// If we encounter an external function with a name not found in this map,
    /// we will panic.
    pub ext_functions: HashMap<String, ExternalFunctionHandling>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ext_functions: HashMap::new(),
        }
    }
}

pub enum ExternalFunctionHandling {
    /// Ignore the call to the external function, and assume it returns fully
    /// untainted data.
    IgnoreAndReturnUntainted,
    /// Ignore the call to the external function, and assume it returns tainted
    /// data.
    IgnoreAndReturnTainted,
    /// Assume that the external function returns tainted data if and only if any
    /// of its parameters are tainted or point to tainted data (potentially
    /// recursively).
    PropagateTaint,
    /// Panic if we encounter a call to this external function.
    Panic,
}

/// The main function in this module. Given an LLVM module and the name of a
/// function to analyze, returns a `ModuleTaintResult` with data on that function
/// and all functions it calls, directly or transitively.
///
/// `args`: the `TaintedType` to assign to each argument of the start function.
///
/// `nonargs`: (optional) Initial `TaintedType`s for any nonargument variables in
/// the start function. For instance, you can use this to set some variable in
/// the middle of the function to tainted. If this map is empty, all
/// `TaintedType`s will simply be inferred normally from the argument
/// `TaintedType`s.
pub fn do_taint_analysis<'m>(
    module: &'m Module,
    config: &'m Config,
    start_fn_name: &str,
    args: Vec<TaintedType>,
    nonargs: HashMap<Name, TaintedType>,
) -> ModuleTaintResult<'m> {
    let f = module.get_func_by_name(start_fn_name).unwrap_or_else(|| {
        panic!(
            "Failed to find function named {:?} in the given module",
            start_fn_name
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
    ModuleTaintState::do_analysis(module, config, &f.name, initial_taintmap)
        .into_module_taint_result()
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
    /// An untainted pointer to either a scalar or an array.
    UntaintedPointer(Pointee),
    /// A tainted pointer to either a scalar or an array.
    TaintedPointer(Pointee),
    /// A struct, with the given element types
    Struct(Vec<Pointee>),
    /// A named struct, with the given name. To get the actual type of the named
    /// struct's contents, use `get_named_struct_type` in the `ModuleTaintState`
    /// or `ModuleTaintResult`. (This avoids infinite recursion in
    /// `TaintedType`.)
    NamedStruct(String),
    /// An untainted function pointer
    UntaintedFnPtr,
    /// A tainted function pointer
    TaintedFnPtr,
}

/// A `Pointee` represents the `TaintedType` which a pointer points to.
/// A `Pointee` may represent either a scalar or an array, or an element of a
/// struct (either named or not).
///
/// Cloning a `Pointee` gives another reference to the _same_ `Pointee`; if one
/// clone is updated with `update()` or `taint()`, all clones will be updated.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Pointee {
    /// The pointed-to type, or the element type of the array.
    /// `Rc<RefCell<>>` allows us to have multiple pointers to the same
    /// underlying type.
    ty: Rc<RefCell<TaintedType>>,

    /// If this is a pointer to an element of a _named_ struct, here is the name
    /// of that named struct.
    ///
    /// We have this so that if a change is made to the Pointee type, we know
    /// that the users of this named struct need to be re-added to the worklist.
    named_struct: Option<String>,

    /// If this is a pointer to all or part of the contents of a global, here is
    /// the name of that global.
    ///
    /// We have this so that if a change is made to the Pointee type, we know
    /// that the users of this global need to be re-added to the worklist.
    global: Option<Name>,
}

impl Pointee {
    /// Construct a new pointee with the given `TaintedType` for its contents.
    /// This will be assumed to be distinct from all previously created
    /// `Pointee`s -- that is, no pointer aliasing.
    fn new(pointee_ty: TaintedType) -> Self {
        Self {
            ty: Rc::new(RefCell::new(pointee_ty)),
            named_struct: None,
            global: None,
        }
    }

    /// Construct a new pointee representing an element of the named struct with
    /// the given name.
    /// This will be assumed to be distinct from all previously created
    /// `Pointee`s -- that is, no pointer aliasing.
    #[allow(dead_code)]
    fn new_named_struct_element(element_ty: TaintedType, struct_name: String) -> Self {
        Self {
            ty: Rc::new(RefCell::new(element_ty)),
            named_struct: Some(struct_name),
            global: None,
        }
    }

    /// Construct a new pointee representing the contents of the global with
    /// the given name.
    /// This will be assumed to be distinct from all previously created
    /// `Pointee`s -- that is, no pointer aliasing.
    #[allow(dead_code)]
    fn new_global_contents(contents_ty: TaintedType, global_name: Name) -> Self {
        Self {
            ty: Rc::new(RefCell::new(contents_ty)),
            named_struct: None,
            global: Some(global_name),
        }
    }

    /// Get a `Ref` to the `TaintedType` representing the pointee's contents
    pub fn ty(&self) -> Ref<TaintedType> {
        self.ty.borrow()
    }

    /// Mark the pointee as being an element of the given named struct.
    ///
    /// If the pointee is later updated with `update()` or `taint()`, we will
    /// re-add all users of this named struct to the worklist.
    fn set_struct_name(&mut self, struct_name: String) -> Result<(), String> {
        match &mut self.named_struct {
            ns @ None => {
                *ns = Some(struct_name);
                Ok(())
            },
            Some(old_name) if &struct_name == old_name => Ok(()), // no change
            Some(old_name) => Err(format!(
                "Setting pointee struct name to {:?}, but it already was set to {:?}",
                struct_name, old_name
            )),
        }
    }

    /// Mark the pointee as being all or part of the given global.
    ///
    /// If the pointee is later updated with `update()` or `taint()`, we will
    /// re-add all users of this global to the worklist.
    fn set_global_name(&mut self, global_name: Name) -> Result<(), String> {
        match &mut self.global {
            g @ None => {
                *g = Some(global_name);
                Ok(())
            },
            Some(old_name) if &global_name == old_name => Ok(()), // no change
            Some(old_name) => Err(format!(
                "Setting pointee global name to {:?}, but it was already set to {:?}",
                global_name, old_name
            )),
        }
    }

    /// Update the `TaintedType` representing the pointed-to contents with the
    /// given `TaintedType`.
    /// This perfoms a `join` of the given `TaintedType` and the previous
    /// `TaintedType` assigned to the contents (if any).
    ///
    /// Returns `true` if the contents' `TaintedType` changed, accounting for the
    /// join operation.
    //
    // Note that currently we don't add named struct users or global users to
    // the worklist in this function directly. That's done in
    // `FunctionTaintState::update_pointee_taintedtype()`, which we assume all
    // callers of `update()` go through. (This is true as of this writing.)
    fn update(&mut self, new_pointee_ty: TaintedType) -> Result<bool, String> {
        let mut pointee_ty = self.ty.borrow_mut();
        let joined_pointee_ty = pointee_ty.join(&new_pointee_ty)?;
        if &*pointee_ty == &joined_pointee_ty {
            // no change is necessary
            Ok(false)
        } else {
            // update the type.
            // Note that updating the `Pointee` like this updates all the
            // pointers to this `Pointee`.
            // For instance, if we have a pointer to an array, then GEP to get
            // pointer to 3rd element, then store a tainted value to that 3rd
            // element, we want to update _both pointers_ (the original array
            // pointer, and the element pointer) to have type
            // pointer-to-tainted.
            *pointee_ty = joined_pointee_ty;
            Ok(true)
        }
    }

    /// Mark the pointed-to contents as tainted.
    ///
    /// Returns `true` if the contents' `TaintedType` changed.
    #[allow(dead_code)]
    fn taint(&mut self) -> bool {
        let mut pointee_ty = self.ty.borrow_mut();
        let tainted_ty = pointee_ty.to_tainted();
        if &*pointee_ty == &tainted_ty {
            // no change is necessary
            false
        } else {
            // update the type.
            // See notes on and inside `update()`
            *pointee_ty = tainted_ty;
            true
        }
    }
}

impl TaintedType {
    /// Create a (fresh, unaliased) pointer to the given `TaintedType`
    pub fn untainted_ptr_to(pointee: TaintedType) -> Self {
        Self::UntaintedPointer(Pointee::new(pointee))
    }

    /// Create a (fresh, unaliased) tainted pointer to the given `TaintedType`
    pub fn tainted_ptr_to(pointee: TaintedType) -> Self {
        Self::TaintedPointer(Pointee::new(pointee))
    }

    /// Create a pointer to the given `Pointee`
    pub fn untainted_ptr_to_pointee(pointee: Pointee) -> Self {
        Self::UntaintedPointer(pointee)
    }

    /// Create a tainted pointer to the given `Pointee`
    pub fn tainted_ptr_to_pointee(pointee: Pointee) -> Self {
        Self::TaintedPointer(pointee)
    }

    /// Create a struct of the given elements, assuming that no pointers to those
    /// elements already exist
    pub fn struct_of(elements: impl IntoIterator<Item = TaintedType>) -> Self {
        Self::Struct(
            elements
                .into_iter()
                .map(|ty| Pointee::new(ty))
                .collect(),
        )
    }

    /// Create a struct of the given `Pointee`s
    pub fn struct_of_pointees(elements: impl IntoIterator<Item = Pointee>) -> Self {
        Self::Struct(elements.into_iter().collect())
    }

    /// Produce the equivalent (untainted) `TaintedType` for a given LLVM type.
    /// Pointers will point to fresh `TaintedType`s to represent their element
    /// types; they will be assumed not to point to existing variables.
    pub fn from_llvm_type(llvm_ty: &Type) -> Self {
        match llvm_ty {
            Type::IntegerType { .. } => TaintedType::UntaintedValue,
            Type::PointerType { pointee_type, .. } => {
                TaintedType::untainted_ptr_to(TaintedType::from_llvm_type(&pointee_type))
            },
            Type::FPType(_) => TaintedType::UntaintedValue,
            Type::VectorType { element_type, .. } => TaintedType::from_llvm_type(&element_type),
            Type::ArrayType { element_type, .. } => TaintedType::from_llvm_type(&element_type),
            Type::StructType { element_types, .. } => {
                TaintedType::struct_of(element_types.iter().map(|ty| TaintedType::from_llvm_type(ty)))
            },
            Type::NamedStructType { name } => TaintedType::NamedStruct(name.into()),
            Type::FuncType { .. } => TaintedType::UntaintedFnPtr,
            Type::X86_MMXType => TaintedType::UntaintedValue,
            Type::MetadataType => TaintedType::UntaintedValue,
            _ => unimplemented!("TaintedType::from_llvm_type on {:?}", llvm_ty),
        }
    }

    /// Is this type tainted?
    ///
    /// This function only works on non-struct types. For a more generic function
    /// that works on all types, use `ModuleTaintState::is_type_tainted()` or
    /// `ModuleTaintResult::is_type_tainted()`.
    pub fn is_tainted_nonstruct(&self) -> bool {
        match self {
            TaintedType::UntaintedValue => false,
            TaintedType::TaintedValue => true,
            TaintedType::UntaintedPointer(_) => false,
            TaintedType::TaintedPointer(_) => true,
            TaintedType::UntaintedFnPtr => false,
            TaintedType::TaintedFnPtr => true,
            TaintedType::Struct(_) | TaintedType::NamedStruct(_) => {
                panic!("is_tainted_nonstruct on a struct type")
            },
        }
    }

    pub fn to_tainted(&self) -> Self {
        match self {
            TaintedType::UntaintedValue => TaintedType::TaintedValue,
            TaintedType::TaintedValue => TaintedType::TaintedValue,
            TaintedType::UntaintedPointer(pointee) => TaintedType::TaintedPointer(pointee.clone()),
            TaintedType::TaintedPointer(pointee) => TaintedType::TaintedPointer(pointee.clone()),
            TaintedType::Struct(_elements) => {
                unimplemented!("to_tainted on a struct")
                /*
                for element in elements {
                    element.taint();
                }
                TaintedType::struct_of_pointees(elements.clone())
                */
            },
            TaintedType::NamedStruct(_) => unimplemented!("to_tainted on a named struct"),
            TaintedType::UntaintedFnPtr => TaintedType::TaintedFnPtr,
            TaintedType::TaintedFnPtr => TaintedType::TaintedFnPtr,
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
                pointee1.ty().join(&*pointee2.ty())?,
            )),
            (UntaintedPointer(pointee1), TaintedPointer(pointee2)) => Ok(Self::tainted_ptr_to(
                pointee1.ty().join(&*pointee2.ty())?,
            )),
            (TaintedPointer(pointee1), UntaintedPointer(pointee2)) => Ok(Self::tainted_ptr_to(
                pointee1.ty().join(&*pointee2.ty())?,
            )),
            (TaintedPointer(pointee1), TaintedPointer(pointee2)) => Ok(Self::tainted_ptr_to(
                pointee1.ty().join(&*pointee2.ty())?,
            )),
            (Struct(elements1), Struct(elements2)) => {
                if elements1.len() != elements2.len() {
                    Err(format!(
                        "join: type mismatch: struct of {} elements with struct of {} elements",
                        elements1.len(),
                        elements2.len()
                    ))
                } else {
                    Ok(Self::struct_of(
                        elements1
                            .iter()
                            .zip(elements2.iter())
                            .map(|(el1, el2)| el1.ty().join(&el2.ty()))
                            .collect::<Result<Vec<_>, String>>()?
                            .into_iter(),
                    ))
                }
            },
            (NamedStruct(name1), NamedStruct(name2)) => {
                if name1 == name2 {
                    Ok(Self::NamedStruct(name1.clone()))
                } else {
                    Err(format!("join: type mismatch: struct named {:?} with struct named {:?}", name1, name2))
                }
            },
            (UntaintedFnPtr, UntaintedFnPtr) => Ok(UntaintedFnPtr),
            (UntaintedFnPtr, TaintedFnPtr) => Ok(TaintedFnPtr),
            (TaintedFnPtr, UntaintedFnPtr) => Ok(TaintedFnPtr),
            (TaintedFnPtr, TaintedFnPtr) => Ok(TaintedFnPtr),
            _ => Err(format!("join: type mismatch: {:?} vs. {:?}", self, other)),
        }
    }
}

#[derive(Clone)]
struct FunctionTaintState<'m> {
    /// Name of the function
    name: &'m str,
    /// Map from `Name`s of variables to their (currently believed) types.
    map: HashMap<Name, TaintedType>,
    /// Reference to the llvm-ir `Module`
    module: &'m Module,
    /// Reference to the module's named struct types
    named_struct_defs: Rc<RefCell<NamedStructDefs<'m>>>,
    /// Reference to the module's globals
    globals: Rc<RefCell<Globals<'m>>>,
    /// Reference to the module's worklist
    worklist: Rc<RefCell<Worklist<'m>>>,
}

impl<'m> FunctionTaintState<'m> {
    fn from_taint_map(
        name: &'m str,
        taintmap: HashMap<Name, TaintedType>,
        module: &'m Module,
        named_struct_defs: Rc<RefCell<NamedStructDefs<'m>>>,
        globals: Rc<RefCell<Globals<'m>>>,
        worklist: Rc<RefCell<Worklist<'m>>>,
    ) -> Self {
        Self {
            name,
            map: taintmap,
            module,
            named_struct_defs,
            globals,
            worklist,
        }
    }

    pub fn get_taint_map(&self) -> &HashMap<Name, TaintedType> {
        &self.map
    }

    /// Get the `TaintedType` of the given `Operand`, according to the current state.
    fn get_type_of_operand(&self, op: &Operand) -> Result<TaintedType, String> {
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
    fn is_scalar_operand_tainted(&self, op: &Operand) -> Result<bool, String> {
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
            TaintedType::Struct(_) | TaintedType::NamedStruct(_) => Err(format!(
                "is_scalar_operand_tainted(): operand has struct type: {:?}",
                op
            )),
        }
    }

    /// Get the `TaintedType` of a `Constant`.
    fn get_type_of_constant(&self, constant: &Constant) -> Result<TaintedType, String> {
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
                let mut globals = self.globals.borrow_mut();
                Ok(globals.get_type_of_global(name.clone(), ty, &self.name).clone())
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
                if int_type.is_tainted_nonstruct() {
                    Ok(ptr_type.to_tainted())
                } else {
                    Ok(ptr_type)
                }
            },
            Constant::PtrToInt(pti) => {
                let ptr_type = self.get_type_of_constant(&pti.operand)?;
                let int_type = TaintedType::from_llvm_type(&self.module.type_of(pti));
                if ptr_type.is_tainted_nonstruct() {
                    Ok(int_type.to_tainted())
                } else {
                    Ok(int_type)
                }
            },
            Constant::GetElementPtr(gep) => {
                let parent_ptr = self.get_type_of_constant(&gep.address)?;
                self.named_struct_defs.borrow_mut().get_element_ptr(&self.name, &parent_ptr, &gep.indices)
            },
            _ => unimplemented!("get_type_of_constant on {:?}", constant),
        }
    }

    /// For `ConstBinaryOp`s where the two operands and the result are all the same LLVM type
    fn get_type_of_constant_binop(&self, bop: &impl ConstBinaryOp) -> Result<TaintedType, String> {
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
    ///
    /// Returns `true` if the pointee's `TaintedType` changed, accounting for the
    /// join operation.
    fn update_pointee_taintedtype(
        &self,
        pointee: &mut Pointee,
        new_pointee: TaintedType,
    ) -> Result<bool, String> {
        if pointee.update(new_pointee)? {
            if let Some(struct_name) = &pointee.named_struct {
                let mut worklist = self.worklist.borrow_mut();
                for user in self.named_struct_defs.borrow().get_named_struct_users(struct_name) {
                    worklist.add(user);
                }
            }
            if let Some(global_name) = &pointee.global {
                let mut worklist = self.worklist.borrow_mut();
                for user in self.globals.borrow().get_global_users(global_name) {
                    worklist.add(user);
                }
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

struct ModuleTaintState<'m> {
    /// llvm-ir `Module`
    module: &'m Module,

    /// The configuration for the analysis
    config: &'m Config,

    /// Map from function name to the `FunctionTaintState` for that function
    fn_taint_states: HashMap<String, FunctionTaintState<'m>>,

    /// Map from function name to the `FunctionSummary` for that function
    fn_summaries: HashMap<String, FunctionSummary>,

    /// Named structs used in the module, and their definitions (taint statuses)
    named_struct_defs: Rc<RefCell<NamedStructDefs<'m>>>,

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

struct FunctionSummary {
    /// `TaintedType`s of the function parameters
    params: Vec<TaintedType>,

    /// `TaintedType` of the return type, or `None` for void return type
    ret: Option<TaintedType>,
}

impl FunctionSummary {
    fn new_untainted(
        param_llvm_types: impl IntoIterator<Item = TypeRef>,
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

    /// Taint the return type.
    ///
    /// Returns `true` if a change was made to the `FunctionSummary`.
    fn taint_ret(&mut self) -> bool {
        match &mut self.ret {
            None => false,
            Some(ret) => {
                let tainted = ret.to_tainted();
                if ret == &tainted {
                    false
                } else {
                    *ret = tainted;
                    true
                }
            }
        }
    }
}

#[derive(Clone)]
struct NamedStructDefs<'m> {
    /// Map from the name of a named struct, to the (currently believed) type for
    /// that struct's contents.
    named_struct_types: HashMap<String, TaintedType>,

    /// Map from the name of a named struct, to the names of functions that use
    /// that named struct.
    /// Whenever the type of a named struct changes, we add all of the functions
    /// that use it to the worklist, because the new type could affect inferred
    /// types in those functions.
    named_struct_users: HashMap<String, HashSet<&'m str>>,

    /// Reference to the llvm-ir `Module`
    module: &'m Module,
}

impl<'m> NamedStructDefs<'m> {
    fn new(module: &'m Module) -> Self {
        Self {
            named_struct_types: HashMap::new(),
            named_struct_users: HashMap::new(),
            module,
        }
    }

    /// Get the `TaintedType` for the given struct name.
    /// Marks the current function (whose name is provided as an argument) as a
    /// user of this named struct.
    /// Creates an untainted `TaintedType` for this named struct if no type
    /// previously existed for it.
    fn get_named_struct_type(&mut self, struct_name: String, cur_fn: &'m str) -> &TaintedType {
        let module = self.module; // this is for the borrow checker - allows us to access `module` without needing to borrow `self`
        self.named_struct_users.entry(struct_name.clone()).or_default().insert(cur_fn.into());
        self.named_struct_types.entry(struct_name.clone()).or_insert_with(|| {
            match module.types.named_struct_def(&struct_name) {
                None => panic!("get_named_struct_type on unknown named struct: name {:?}", &struct_name),
                Some(NamedStructDef::Opaque) => panic!(
                    "get_named_struct_type on an opaque struct named {:?}",
                    &struct_name
                ),
                Some(NamedStructDef::Defined(ty)) => TaintedType::from_llvm_type(&ty),
            }
        })
    }

    /// Get the names of the functions which are currently known to use the named
    /// struct with the given name.
    fn get_named_struct_users(&self, struct_name: &str) -> impl IntoIterator<Item = &'m str> {
        match self.named_struct_users.get(struct_name) {
            None => vec![],
            Some(users) => users.iter().copied().collect::<Vec<&'m str>>(),
        }
    }

    /// Is this type tainted (or, for structs, is any element of the struct tainted)
    fn is_type_tainted(&mut self, ty: &TaintedType, cur_fn: &'m str) -> bool {
        match ty {
            TaintedType::UntaintedValue => false,
            TaintedType::TaintedValue => true,
            TaintedType::UntaintedPointer(_) => false,
            TaintedType::TaintedPointer(_) => true,
            TaintedType::Struct(elements) => {
                // a struct is tainted if any of its elements are
                elements.iter().any(|e| self.is_type_tainted(&e.ty(), cur_fn))
            },
            TaintedType::NamedStruct(name) => {
                let inner_ty = self.get_named_struct_type(name.into(), cur_fn).clone();
                self.is_type_tainted(&inner_ty, cur_fn)
            },
            TaintedType::UntaintedFnPtr => false,
            TaintedType::TaintedFnPtr => true,
        }
    }

    fn get_element_ptr<'a, 'b, I: Index + 'b>(
        &mut self,
        cur_fn: &'m str,
        parent_ptr: &'a TaintedType,
        indices: impl IntoIterator<Item = &'b I>,
    ) -> Result<TaintedType, String> {
        let mut indices = indices.into_iter();
        // we 'pop' an index from the list. This represents choosing an element of
        // the "array" pointed to by the pointer.
        let _index = match indices.next() {
            Some(index) => index,
            None => return Err("get_element_ptr: called with no indices".into()),
        };
        // now the rest of this is just for dealing with subsequent indices
        self._get_element_ptr(cur_fn, parent_ptr, indices.peekable())
    }

    fn _get_element_ptr<'a, 'b, I: Index + 'b>(
        &mut self,
        cur_fn: &'m str,
        parent_ptr: &'a TaintedType,
        mut indices: std::iter::Peekable<impl Iterator<Item = &'b I>>,
    ) -> Result<TaintedType, String> {
        match parent_ptr {
            TaintedType::UntaintedValue | TaintedType::TaintedValue => {
                Err("get_element_ptr: address is not a pointer, or too many indices".into())
            },
            TaintedType::UntaintedFnPtr | TaintedType::TaintedFnPtr => {
                Err("get_element_ptr on a function pointer".into())
            },
            TaintedType::Struct(_) | TaintedType::NamedStruct(_) => {
                Err("get_element_ptr: address is not a pointer, or too many indices".into())
            },
            TaintedType::UntaintedPointer(pointee) | TaintedType::TaintedPointer(pointee) => {
                let pointee_ty: &TaintedType = &pointee.ty();
                let existing_struct_name = &pointee.named_struct;
                let existing_global = &pointee.global;
                match pointee_ty {
                    TaintedType::TaintedValue | TaintedType::UntaintedValue => {
                        // We expect that indices.peek() would give None in this
                        // case. However, there may be an extra index due to
                        // selecting an element of a first-class array or vector
                        // (which are TaintedValue or UntaintedValue in our type
                        // system). So we just ignore any extra indices.
                        if self.is_type_tainted(parent_ptr, cur_fn) {
                            Ok(TaintedType::TaintedPointer(pointee.clone()))
                        } else {
                            Ok(TaintedType::UntaintedPointer(pointee.clone()))
                        }
                    },
                    TaintedType::TaintedFnPtr | TaintedType::UntaintedFnPtr => {
                        match indices.peek() {
                            None if self.is_type_tainted(parent_ptr, cur_fn) => {
                                Ok(TaintedType::TaintedPointer(pointee.clone()))
                            },
                            None => {
                                Ok(TaintedType::UntaintedPointer(pointee.clone()))
                            },
                            Some(_) => {
                                Err("get_element_ptr on a function pointer, or too many indices".into())
                            },
                        }
                    },
                    inner_ptr @ TaintedType::TaintedPointer(_)
                    | inner_ptr @ TaintedType::UntaintedPointer(_) => {
                        // We'll taint the resulting element ptr depending on the
                        // taint status of the inner_ptr, ignoring the taint status
                        // of the parent_ptr. I believe this is correct for most use
                        // cases.
                        match indices.next() {
                            None if self.is_type_tainted(inner_ptr, cur_fn) => {
                                Ok(TaintedType::TaintedPointer(pointee.clone()))
                            },
                            None => Ok(TaintedType::UntaintedPointer(pointee.clone())),
                            Some(_) => self._get_element_ptr(cur_fn, inner_ptr, indices),
                        }
                    },
                    TaintedType::Struct(_) | TaintedType::NamedStruct(_) => {
                        let (elements, struct_name) = match pointee_ty {
                            TaintedType::Struct(elements) => (elements, None),
                            TaintedType::NamedStruct(name) => match self.get_named_struct_type(name.into(), cur_fn) {
                                TaintedType::Struct(elements) => (elements, Some(name.clone())),
                                ty => panic!("expected get_named_struct_type to return TaintedType::Struct; got {:?}", ty),
                            },
                            _ => panic!("Only expected Struct or NamedStruct case here"),
                        };
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
                                        "get_element_ptr: index out of range: index {:?} in struct {:?} with {} elements",
                                        index, pointee, elements.len()
                                    )
                                })?;
                                let mut pointee = pointee.clone(); // release the borrow of `self` due to `elements`
                                if let Some(struct_name) = struct_name {
                                    // we just entered a new named struct, that's our name
                                    pointee.set_struct_name(struct_name)?;
                                } else if let Some(struct_name) = existing_struct_name {
                                    // inherit the parent pointer's named struct tag
                                    pointee.set_struct_name(struct_name.clone())?;
                                }
                                if let Some(global_name) = existing_global {
                                    // inherit the parent pointer's global name
                                    pointee.set_global_name(global_name.clone())?;
                                }
                                let pointer_to_element = {
                                    if self.is_type_tainted(parent_ptr, cur_fn) {
                                        TaintedType::TaintedPointer(pointee)
                                    } else {
                                        TaintedType::UntaintedPointer(pointee)
                                    }
                                };
                                match indices.peek() {
                                    None => Ok(pointer_to_element),
                                    Some(_) => self._get_element_ptr(cur_fn, &pointer_to_element, indices),
                                }
                            },
                        }
                    },
                }
            },
        }
    }
}

impl<'m> Debug for NamedStructDefs<'m> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{NamedStructDefs for module {:?}, with {} definitions}}", &self.module.name, self.named_struct_types.keys().count())
    }
}

struct Globals<'m> {
    /// Map from the name of a global, to the (currently believed) type for
    /// that global. This type will always be a pointer type.
    global_types: HashMap<Name, TaintedType>,

    /// Map from the name of a global, to the names of functions that use that
    /// global.
    /// Whenever the type of a global changes, we add all of the functions that
    /// use it to the worklist, because the new type could affect inferred types
    /// in those functions.
    global_users: HashMap<Name, HashSet<&'m str>>,
}

impl<'m> Globals<'m> {
    fn new() -> Self {
        Self {
            global_types: HashMap::new(),
            global_users: HashMap::new(),
        }
    }

    /// Get the (currently believed) `TaintedType` of the global with the given
    /// name and LLVM `Type`. This `TaintedType` will always be a pointer type.
    ///
    /// `llvm_pointee_ty` should be the pointee type, not including the implicit
    /// pointer.
    ///
    /// Marks the current function (whose name is provided as an argument) as a
    /// user of this global.
    ///
    /// Creates an untainted `TaintedType` for this global if no type previously
    /// existed for it.
    fn get_type_of_global(&mut self, name: Name, llvm_pointee_ty: &Type, cur_fn: &'m str) -> &mut TaintedType {
        self.global_users.entry(name.clone()).or_default().insert(cur_fn.into());
        self.global_types.entry(name.clone()).or_insert_with(|| {
            let pointee = Pointee::new_global_contents(TaintedType::from_llvm_type(llvm_pointee_ty), name);
            TaintedType::untainted_ptr_to_pointee(pointee)
        })
    }

    /// Get the names of the functions which are currently known to use the
    /// global with the given name.
    fn get_global_users(&self, global_name: &Name) -> impl IntoIterator<Item = &'m str> {
        match self.global_users.get(global_name) {
            None => vec![],
            Some(users) => users.iter().copied().collect::<Vec<&'m str>>(),
        }
    }
}

/// Keeps track of the set of functions which need to be processed again because
/// there's been a change to taint information which might be relevant to them.
///
/// To construct a `Worklist`, use its `FromIterator` implementation (i.e., use
/// `.collect()` on an iterator)
struct Worklist<'m> {
    fn_names: HashSet<&'m str>,
}

impl<'m> Worklist<'m> {
    /// Adds the given function name to the worklist
    fn add(&mut self, fn_name: &'m str) {
        debug!("Adding {:?} to worklist", fn_name);
        self.fn_names.insert(fn_name);
    }

    /// Gets an arbitrary function name on the worklist, removes it from the
    /// worklist, and returns it
    ///
    /// Returns `None` if the worklist was empty
    fn pop(&mut self) -> Option<&'m str> {
        let fn_name: &'m str = self
            .fn_names
            .iter()
            .next()?
            .clone();
        self.fn_names.remove(fn_name);
        Some(fn_name)
    }
}

impl<'m> FromIterator<&'m str> for Worklist<'m> {
    fn from_iter<I: IntoIterator<Item = &'m str>>(iter: I) -> Self {
        Self {
            fn_names: iter.into_iter().collect(),
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
        let named_struct_defs = Rc::new(RefCell::new(NamedStructDefs::new(module)));
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

    fn into_module_taint_result(self) -> ModuleTaintResult<'m> {
        ModuleTaintResult {
            fn_taint_states: self.fn_taint_states,
            named_struct_types: self.named_struct_defs.borrow().named_struct_types.clone(),
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

pub struct ModuleTaintResult<'m> {
    /// Map from function name to the `FunctionTaintState` for that function
    fn_taint_states: HashMap<String, FunctionTaintState<'m>>,

    /// Map from the name of a named struct, to the type for that struct's
    /// contents.
    named_struct_types: HashMap<String, TaintedType>,
}

impl<'m> ModuleTaintResult<'m> {
    /// Given a function name, returns a map from variable name to `TaintedType`
    /// for all the variables in that function.
    pub fn get_function_taint_map(&self, fn_name: &str) -> &HashMap<Name, TaintedType> {
        self.fn_taint_states
            .get(fn_name)
            .unwrap_or_else(|| {
                panic!(
                    "get_function_taint_map: no taint map found for function {:?}",
                    fn_name
                )
            })
            .get_taint_map()
    }

    /// Get the `TaintedType` for the given struct name.
    pub fn get_named_struct_type(&self, struct_name: &str) -> &TaintedType {
        self.named_struct_types.get(struct_name).unwrap_or_else(|| panic!("get_named_struct_type: unknown named struct: name {:?}", struct_name))
    }

    /// Iterate over all function names for which we have a taint map
    pub fn get_function_names<'s: 'm>(&'s self) -> impl Iterator<Item = &'s String> {
        self.fn_taint_states.keys()
    }

    /// Is this type one of the tainted types
    pub fn is_type_tainted(&self, ty: &TaintedType) -> bool {
        match ty {
            TaintedType::UntaintedValue => false,
            TaintedType::TaintedValue => true,
            TaintedType::UntaintedPointer(_) => false,
            TaintedType::TaintedPointer(_) => true,
            TaintedType::Struct(elements) => {
                // a struct is tainted if any of its elements are
                elements.iter().any(|e| self.is_type_tainted(&e.ty()))
            },
            TaintedType::NamedStruct(name) => {
                let inner_ty = self.get_named_struct_type(name);
                self.is_type_tainted(inner_ty)
            },
            TaintedType::UntaintedFnPtr => false,
            TaintedType::TaintedFnPtr => true,
        }
    }

    /// Get the `TaintedType` of a variable by name
    pub fn get_var_type(&self, funcname: &str, varname: &Name) -> &TaintedType {
        &self.fn_taint_states[funcname].map[varname]
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
            Operand::ConstantOperand(cref) => cref.as_constant(),
            Operand::MetadataOperand => None,
        }
    }
}

impl Index for Constant {
    fn as_constant(&self) -> Option<u64> {
        match self {
            Constant::Int { value, .. } => Some(*value),
            _ => unimplemented!("as_constant on {:?}", self),
        }
    }
}

impl Index for ConstantRef {
    fn as_constant(&self) -> Option<u64> {
        self.as_ref().as_constant()
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

use crate::pointee::Pointee;
use llvm_ir::Type;

/// The type system which we use for taint-tracking
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum TaintedType {
    /// An untainted value which is not a pointer, struct, array, or vector.
    UntaintedValue,
    /// A tainted value which is not a pointer, struct, array, or vector.
    TaintedValue,
    /// An untainted pointer to either a scalar or an (implicit) array.
    /// By implicit we mean that this represents LLVM `i8*`, not LLVM `[300 x i8]*`.
    UntaintedPointer(Pointee),
    /// A tainted pointer to either a scalar or an (implicit) array.
    /// By implicit we mean that this represents LLVM `i8*`, not LLVM `[300 x i8]*`.
    TaintedPointer(Pointee),
    /// An array or vector, with the given element type (and any number of
    /// elements).
    /// All elements are assumed to have the same type, which means that if any
    /// of them is tainted, all of them are tainted.
    ArrayOrVector(Pointee),
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

    /// Create an array or vector with the given element type, assuming that no
    /// pointers to the elements already exist
    pub fn array_or_vec_of(element_ty: TaintedType) -> Self {
        Self::ArrayOrVector(Pointee::new(element_ty))
    }

    /// Create an array or vector with the given `Pointee` as its element type
    pub fn array_or_vec_of_pointee(pointee: Pointee) -> Self {
        Self::ArrayOrVector(pointee)
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
                match pointee_type.as_ref() {
                    Type::FuncType { .. } => TaintedType::UntaintedFnPtr,
                    _ => TaintedType::untainted_ptr_to(TaintedType::from_llvm_type(&pointee_type))
                }
            },
            Type::FPType(_) => TaintedType::UntaintedValue,
            Type::ArrayType { element_type, .. }
            | Type::VectorType { element_type, .. } => {
                TaintedType::array_or_vec_of(TaintedType::from_llvm_type(&element_type))
            },
            Type::StructType { element_types, .. } => {
                TaintedType::struct_of(element_types.iter().map(|ty| TaintedType::from_llvm_type(ty)))
            },
            Type::NamedStructType { name } => TaintedType::NamedStruct(name.into()),
            Type::X86_MMXType => TaintedType::UntaintedValue,
            Type::MetadataType => TaintedType::UntaintedValue,
            _ => unimplemented!("TaintedType::from_llvm_type on {:?}", llvm_ty),
        }
    }

    /// Is this type tainted?
    ///
    /// This function only works on non-struct types. (It does work on array or
    /// vector types, as long as the element type isn't a struct type.)
    ///
    /// For a more generic function that works on all types, use
    /// `ModuleTaintState::is_type_tainted()` or
    /// `ModuleTaintResult::is_type_tainted()`.
    pub fn is_tainted_nonstruct(&self) -> bool {
        match self {
            TaintedType::UntaintedValue => false,
            TaintedType::TaintedValue => true,
            TaintedType::UntaintedPointer(_) => false,
            TaintedType::TaintedPointer(_) => true,
            TaintedType::UntaintedFnPtr => false,
            TaintedType::TaintedFnPtr => true,
            TaintedType::ArrayOrVector(pointee) => pointee.ty().is_tainted_nonstruct(),
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
            TaintedType::ArrayOrVector(_pointee) => {
                unimplemented!("to_tainted on an array or vector")
            },
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
    pub(crate) fn join(&self, other: &Self) -> Result<Self, String> {
        use TaintedType::*;
        match (self, other) {
            (UntaintedValue, UntaintedValue) => Ok(UntaintedValue),
            (UntaintedValue, TaintedValue) => Ok(TaintedValue),
            (TaintedValue, UntaintedValue) => Ok(TaintedValue),
            (TaintedValue, TaintedValue) => Ok(TaintedValue),
            (UntaintedPointer(pointee1), UntaintedPointer(pointee2)) => Ok(Self::untainted_ptr_to(
                pointee1.ty().join(&pointee2.ty())?,
            )),
            (UntaintedPointer(pointee1), TaintedPointer(pointee2)) => Ok(Self::tainted_ptr_to(
                pointee1.ty().join(&pointee2.ty())?,
            )),
            (TaintedPointer(pointee1), UntaintedPointer(pointee2)) => Ok(Self::tainted_ptr_to(
                pointee1.ty().join(&pointee2.ty())?,
            )),
            (TaintedPointer(pointee1), TaintedPointer(pointee2)) => Ok(Self::tainted_ptr_to(
                pointee1.ty().join(&pointee2.ty())?,
            )),
            (ArrayOrVector(element1), ArrayOrVector(element2)) => Ok(Self::array_or_vec_of(
                element1.ty().join(&element2.ty())?,
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

use crate::named_structs::NamedStructs;
use crate::pointee::Pointee;
use llvm_ir::Type;
use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;

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
    /// struct's contents, use `get_named_struct_type` in the `TaintState` or
    /// `TaintResult`. (This avoids infinite recursion in `TaintedType`.)
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
    /// This function panics on named struct types. (It does work on array,
    /// vector, and anonymous struct types, as long as the element type isn't a
    /// named struct type.)
    ///
    /// For a more generic function that works on all types, use
    /// `TaintedType::is_tainted()` (below), `TaintState::is_type_tainted()`, or
    /// `TaintResult::is_type_tainted()`.
    pub fn is_tainted_nonamedstruct(&self) -> bool {
        match self {
            TaintedType::UntaintedValue => false,
            TaintedType::TaintedValue => true,
            TaintedType::UntaintedPointer(_) => false,
            TaintedType::TaintedPointer(_) => true,
            TaintedType::UntaintedFnPtr => false,
            TaintedType::TaintedFnPtr => true,
            TaintedType::ArrayOrVector(pointee) => pointee.ty().is_tainted_nonamedstruct(),
            TaintedType::Struct(elements) => {
                // a struct is tainted if any of its elements are
                elements.iter().any(|p| p.ty().is_tainted_nonamedstruct())
            }
            TaintedType::NamedStruct(_) => panic!("is_tainted_nonamedstruct on a named struct type"),
        }
    }

    /// Is this type tainted?
    ///
    /// This function handles all types, including named struct types.
    ///
    /// Alternately you can also use `TaintState::is_type_tainted()` or
    /// `TaintResult::is_type_tainted()`.
    pub fn is_tainted<'m>(&self, named_structs: Rc<RefCell<NamedStructs<'m>>>, cur_fn: &'m str) -> bool {
        match self {
            TaintedType::NamedStruct(name) => {
                let mut named_structs = named_structs.borrow_mut();
                let structty = named_structs.get_named_struct_type(name.clone(), cur_fn);
                structty.is_tainted_nonamedstruct()
            },
            TaintedType::ArrayOrVector(pointee) => pointee.ty().is_tainted(named_structs, cur_fn),
            TaintedType::Struct(elements) => {
                // a struct is tainted if any of its elements are
                elements.iter().any(|p| p.ty().is_tainted(named_structs.clone(), cur_fn))
            },
            _ => self.is_tainted_nonamedstruct(),
        }
    }

    /// Mark everything pointed to by this pointer as tainted.
    ///
    /// Recurses into structs/arrays/vectors, but not pointers:
    /// - if this pointer points to a struct/array/vector, we will taint all
    /// elements of that struct/array/vector
    /// - if this pointer points to another pointer P, we will taint P, but not
    /// things pointed to by P. Of course, if
    /// `config.dereferencing_tainted_ptr_gives_tainted` is `true`, then things
    /// pointed to by P will also become tainted if they are ever loaded through
    /// P.
    pub fn taint_contents<'m>(&self, named_structs: &mut NamedStructs<'m>) {
        match self {
            TaintedType::UntaintedPointer(pointee) | TaintedType::TaintedPointer(pointee) => {
                pointee.taint(named_structs);
            },
            TaintedType::UntaintedFnPtr | TaintedType::TaintedFnPtr => {
                panic!("taint_contents on a function pointer")
            },
            _ => panic!("taint_contents: not a pointer: {}", self),
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
                    Err(format!("join: type mismatch: struct named {:?} vs. struct named {:?}", name1, name2))
                }
            },
            (UntaintedFnPtr, UntaintedFnPtr) => Ok(UntaintedFnPtr),
            (UntaintedFnPtr, TaintedFnPtr) => Ok(TaintedFnPtr),
            (TaintedFnPtr, UntaintedFnPtr) => Ok(TaintedFnPtr),
            (TaintedFnPtr, TaintedFnPtr) => Ok(TaintedFnPtr),
            _ => Err(format!("join: type mismatch: {} vs. {}", self, other)),
        }
    }
}

impl fmt::Display for TaintedType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TaintedType::UntaintedValue => write!(f, "UntaintedValue"),
            TaintedType::TaintedValue => write!(f, "TaintedValue"),
            TaintedType::UntaintedFnPtr => write!(f, "UntaintedFnPtr"),
            TaintedType::TaintedFnPtr => write!(f, "TaintedFnPtr"),
            TaintedType::UntaintedPointer(p) => {
                write!(f, "(UntaintedPointer to {})", p)
            },
            TaintedType::TaintedPointer(p) => {
                write!(f, "(TaintedPointer to {})", p)
            },
            TaintedType::ArrayOrVector(p) => {
                write!(f, "(ArrayOrVector of {})", p)
            },
            TaintedType::Struct(elements) => {
                write!(f, "(Struct of {{")?;
                for element in elements {
                    write!(f, "{}, ", element)?;
                }
                write!(f, "}})")
            }
            TaintedType::NamedStruct(name) => {
                write!(f, "(NamedStruct with name {:?})", name)
            }
        }
    }
}

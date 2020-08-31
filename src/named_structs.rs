use crate::tainted_type::TaintedType;
use llvm_ir::{Constant, ConstantRef, Module, Operand};
use llvm_ir::types::NamedStructDef;
use std::collections::{HashMap, HashSet};
use std::fmt;

#[derive(Clone)]
pub struct NamedStructs<'m> {
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

impl<'m> NamedStructs<'m> {
    pub fn new(module: &'m Module) -> Self {
        Self {
            named_struct_types: HashMap::new(),
            named_struct_users: HashMap::new(),
            module,
        }
    }

    /// Iterate over all the (struct name, `TaintedType`) pairs
    pub(crate) fn all_named_struct_types<'s>(&'s self) -> impl Iterator<Item = (&'s String, &'s TaintedType)> {
        self.named_struct_types.iter()
    }

    /// Get the `TaintedType` for the given struct name.
    /// Marks the current function (whose name is provided as an argument) as a
    /// user of this named struct.
    /// Creates an untainted `TaintedType` for this named struct if no type
    /// previously existed for it.
    pub fn get_named_struct_type(&mut self, struct_name: String, cur_fn: &'m str) -> &TaintedType {
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
    pub fn get_named_struct_users(&self, struct_name: &str) -> impl IntoIterator<Item = &'m str> {
        match self.named_struct_users.get(struct_name) {
            None => vec![],
            Some(users) => users.iter().copied().collect::<Vec<&'m str>>(),
        }
    }

    /// Is this type tainted (or, for structs, is any element of the struct tainted)
    pub fn is_type_tainted(&mut self, ty: &TaintedType, cur_fn: &'m str) -> bool {
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

    pub(crate) fn get_element_ptr<'a, 'b, I: Index + 'b>(
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
                let existing_struct_name = pointee.get_struct_name();
                let existing_global = pointee.get_global_name();
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
                                        "get_element_ptr: index out of range: index {:?} in struct with type {:?} (which has {} elements)",
                                        index, pointee_ty, elements.len()
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

impl<'m> fmt::Debug for NamedStructs<'m> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{NamedStructs for module {:?}, with {} definitions}}", &self.module.name, self.named_struct_types.keys().count())
    }
}

/// Trait representing things which can be used as struct/array indices.
/// Namely, `Operand`s and constants.
pub(crate) trait Index: fmt::Debug {
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

use crate::pointee::Pointee;
use crate::tainted_type::TaintedType;
use llvm_ir::{Name, Type};
use std::collections::{HashMap, HashSet};

pub struct Globals<'m> {
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
    pub fn new() -> Self {
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
    pub fn get_type_of_global(&mut self, name: Name, llvm_pointee_ty: &Type, cur_fn: &'m str) -> &mut TaintedType {
        self.global_users.entry(name.clone()).or_default().insert(cur_fn.into());
        self.global_types.entry(name.clone()).or_insert_with(|| {
            let pointee = Pointee::new_global_contents(TaintedType::from_llvm_type(llvm_pointee_ty), name);
            TaintedType::untainted_ptr_to_pointee(pointee)
        })
    }

    /// Get the names of the functions which are currently known to use the
    /// global with the given name.
    pub fn get_global_users(&self, global_name: &Name) -> impl IntoIterator<Item = &'m str> {
        match self.global_users.get(global_name) {
            None => vec![],
            Some(users) => users.iter().copied().collect::<Vec<&'m str>>(),
        }
    }
}

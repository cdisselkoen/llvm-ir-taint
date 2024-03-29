use crate::function_taint_state::FunctionTaintState;
use crate::named_structs::{NamedStructs, TaintedNamedStructs};
use crate::tainted_type::TaintedType;
use llvm_ir::Name;
use log::debug;
use std::cell::{Ref, RefCell};
use std::fmt;
use std::rc::Rc;

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
    pub fn new(pointee_ty: TaintedType) -> Self {
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
    pub fn new_named_struct_element(element_ty: TaintedType, struct_name: String) -> Self {
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
    pub fn new_global_contents(contents_ty: TaintedType, global_name: Name) -> Self {
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

    /// If this pointee is an element of a named struct, get the name of that
    /// struct.
    pub(crate) fn get_struct_name(&self) -> &Option<String> {
        &self.named_struct
    }

    /// Mark the pointee as being an element of the given named struct.
    ///
    /// If the pointee is later updated with `update()` or `taint()`, we will
    /// re-add all users of this named struct to the worklist.
    pub(crate) fn set_struct_name(&mut self, struct_name: String) -> Result<(), String> {
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

    /// If this pointee represents all or part of the contents of a global, get
    /// the name of that global.
    pub(crate) fn get_global_name(&self) -> &Option<Name> {
        &self.global
    }

    /// Mark the pointee as being all or part of the given global.
    ///
    /// If the pointee is later updated with `update()` or `taint()`, we will
    /// re-add all users of this global to the worklist.
    pub(crate) fn set_global_name(&mut self, global_name: Name) -> Result<(), String> {
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
    pub(crate) fn update(&mut self, new_pointee_ty: &TaintedType, fts: &FunctionTaintState) -> Result<bool, String> {
        let mut pointee_ty = self.ty.borrow_mut();
        let joined_pointee_ty = pointee_ty.join(new_pointee_ty)?;
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
            debug!("Updating pointee {:?} to {}", self.as_ptr(), joined_pointee_ty);
            *pointee_ty = joined_pointee_ty;
            // If we just updated an element of a named struct, add all the
            // users of that named struct to the worklist
            if let Some(struct_name) = &self.named_struct {
                let mut worklist = fts.worklist.borrow_mut();
                for user in fts.named_structs.borrow().get_named_struct_users(struct_name) {
                    worklist.add(user);
                }
            }
            // If we just updated all or part of the contents of a global, add
            // all the users of that global to the worklist
            if let Some(global_name) = &self.global {
                let mut worklist = fts.worklist.borrow_mut();
                for user in fts.globals.borrow().get_global_users(global_name) {
                    worklist.add(user);
                }
            }
            Ok(true)
        }
    }

    /// Mark the pointed-to contents as tainted.
    ///
    /// Returns `true` if the contents' `TaintedType` changed.
    pub(crate) fn taint<'m>(&self, named_structs: &mut NamedStructs<'m>) -> bool {
        self.taint_with_tns(&mut named_structs.tainted_named_structs)
    }

    pub(crate) fn taint_with_tns<'m>(&self, tns: &mut TaintedNamedStructs) -> bool {
        let mut pointee_ty = self.ty.borrow_mut();
        let tainted_ty = tns.to_tainted(&pointee_ty);
        if &*pointee_ty == &tainted_ty {
            // no change is necessary
            false
        } else {
            // update the type.
            // See notes on and inside `update()`
            debug!("Updating pointee {:?} to {}", self.as_ptr(), tainted_ty);
            *pointee_ty = tainted_ty;
            true
        }
    }

    /// Intended for use in debugging. Allows you to distinguish which `Pointee`s
    /// are linked (in that updating one updates the others) because they return
    /// the same pointer here
    pub(crate) fn as_ptr(&self) -> *const TaintedType {
        self.ty.as_ptr()
    }
}

impl fmt::Display for Pointee {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.ty())
    }
}

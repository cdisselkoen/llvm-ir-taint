use crate::named_structs::NamedStructs;
use crate::tainted_type::TaintedType;
use llvm_ir::{Type, TypeRef};
use std::cell::RefCell;
use std::rc::Rc;

pub struct FunctionSummary<'m> {
    /// `TaintedType`s of the function parameters
    params: Vec<TaintedType>,

    /// `TaintedType` of the return type, or `None` for void return type
    ret: Option<TaintedType>,

    /// Reference to the module's named struct types
    named_structs: Rc<RefCell<NamedStructs<'m>>>,
}

impl<'m> FunctionSummary<'m> {
    pub fn new_untainted(
        param_llvm_types: impl IntoIterator<Item = TypeRef>,
        ret_llvm_type: &Type,
        named_structs: Rc<RefCell<NamedStructs<'m>>>,
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
            named_structs,
        }
    }

    /// Iterate over the parameters of the function
    pub fn get_params<'s>(&'s self) -> impl Iterator<Item = &'s TaintedType> {
        self.params.iter()
    }

    /// Get the `TaintedType` of the return type, or `None` for void return type
    pub fn get_ret_ty(&self) -> &Option<TaintedType> {
        &self.ret
    }

    /// Update the `TaintedType`s of the function parameters.
    /// Performs a `join` of each type with the corresponding existing type.
    ///
    /// Returns `true` if a change was made to the `FunctionSummary`.
    pub fn update_params(&mut self, new_params: Vec<TaintedType>) -> Result<bool, String> {
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
    pub fn update_ret(&mut self, new_ret: &Option<&TaintedType>) -> Result<bool, String> {
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
    pub fn taint_ret(&mut self) -> bool {
        match &mut self.ret {
            None => false,
            Some(ret) => {
                let tainted = self.named_structs.borrow_mut().to_tainted(ret);
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

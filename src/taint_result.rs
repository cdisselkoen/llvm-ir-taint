use crate::function_taint_state::FunctionTaintState;
use crate::tainted_type::TaintedType;
use llvm_ir::Name;
use std::collections::HashMap;

/// The result of taint-tracking analysis on LLVM module(s)
pub struct TaintResult<'m> {
    /// Map from function name to the `FunctionTaintState` for that function
    pub(crate) fn_taint_states: HashMap<&'m str, FunctionTaintState<'m>>,

    /// Map from the name of a named struct, to the type for that struct's
    /// contents.
    pub(crate) named_struct_types: HashMap<String, TaintedType>,
}

impl<'m> TaintResult<'m> {
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
    pub fn get_function_names<'s: 'm>(&'s self) -> impl Iterator<Item = &'s &'m str> {
        self.fn_taint_states.keys()
    }

    /// Is this type one of the tainted types
    pub fn is_type_tainted(&self, ty: &TaintedType) -> bool {
        match ty {
            TaintedType::UntaintedValue => false,
            TaintedType::TaintedValue => true,
            TaintedType::UntaintedPointer(_) => false,
            TaintedType::TaintedPointer(_) => true,
            TaintedType::ArrayOrVector(element) => self.is_type_tainted(&element.ty()),
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
        &self.fn_taint_states[funcname].get_taint_map()[varname]
    }
}

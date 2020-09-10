use std::collections::HashMap;

#[non_exhaustive]
pub struct Config {
    /// If `true`, then dereferencing a tainted pointer always gives tainted
    /// data.
    /// If `false`, then dereferencing a tainted pointer works just like
    /// dereferencing an untainted pointer. Values computed from the tainted
    /// pointer (e.g. via pointer arithmetic) will be tainted, but values
    /// resulting from dereferencing the tainted pointer will not be tainted
    /// merely for that reason alone.
    ///
    /// Default is `true`.
    pub dereferencing_tainted_ptr_gives_tainted: bool,

    /// How to handle external functions -- that is, functions not defined in the
    /// `Module`.
    /// This is a map from LLVM function name to the handling that should be used
    /// for that function.
    pub ext_functions: HashMap<String, ExternalFunctionHandling>,

    /// How to handle external functions which _aren't_ present in the
    /// `ext_functions` map above; or function pointers where no valid target for
    /// the function pointer exists in the `Module`.
    pub ext_functions_default: ExternalFunctionHandling,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dereferencing_tainted_ptr_gives_tainted: true,
            ext_functions: HashMap::new(),
            ext_functions_default: ExternalFunctionHandling::Panic,
        }
    }
}

pub enum ExternalFunctionHandling {
    /// Ignore the call to the function, and assume it returns fully untainted
    /// data.
    IgnoreAndReturnUntainted,
    /// Ignore the call to the function, and assume it returns tainted data.
    IgnoreAndReturnTainted,
    /// Assume that the function returns tainted data if and only if any of its
    /// parameters are tainted. This looks only at the shallow types of
    /// parameters -- for instance, for pointers, it looks only at whether the
    /// pointer value itself is tainted, not whether any of the pointed-to data
    /// is tainted. Likewise, this only taints the return value shallowly -- if
    /// the return value is a pointer, this will taint the pointer value itself,
    /// but not any of the pointed-to data.
    PropagateTaintShallow,
    /// Assume that the function returns tainted data if and only if any of its
    /// parameters are tainted or point to tainted data.
    /// This looks at the deep types of parameters -- for instance, for pointers,
    /// it looks at whether the pointer value itself _or any of the pointed-to
    /// data_ is tainted, potentially recursively. Likewise, this taints the return
    /// value deeply -- if the return value is a pointer, this will taint not only
    /// the pointer value itself, but also _all_ of the data it points to.
    PropagateTaintDeep,
    /// Panic if we encounter a call to this function.
    Panic,
}

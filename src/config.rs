use std::collections::HashMap;

#[non_exhaustive]
pub struct Config {
    /// How to handle external functions -- that is, functions not defined in the
    /// `Module`.
    /// If we encounter an external function with a name not found in this map,
    /// we will panic.
    pub ext_functions: HashMap<String, ExternalFunctionHandling>,

    /// How to handle calls to function pointers.
    /// This is pretty limited, and ideally we'd have a better way to match
    /// function pointers to the actual functions which they could possibly call.
    pub fn_pointers: ExternalFunctionHandling,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ext_functions: HashMap::new(),
            fn_pointers: ExternalFunctionHandling::Panic,
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
    /// parameters are tainted or point to tainted data (potentially
    /// recursively).
    PropagateTaint,
    /// Panic if we encounter a call to this function.
    Panic,
}

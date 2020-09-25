use llvm_ir::{Function, Module};
use llvm_ir::types::NamedStructDef;
use std::iter::FromIterator;

/// Stores references to all of the `Module`(s) which we're working with
pub struct Modules<'m> {
    modules: Vec<&'m Module>,
}

impl<'m> Modules<'m> {
    /// Iterate over the `Module`(s) in the `Modules`
    pub fn iter<'s>(&'s self) -> impl Iterator<Item = &'m Module> + 's {
        self.modules.iter().copied()
    }

    /// Iterate over all of the `Function`s in the `Modules`.
    /// Gives pairs which also indicate the `Module` the `Function` is defined in.
    //
    // This function mostly lifted from `haybale`'s project.rs
    pub fn all_functions<'s>(&'s self) -> impl Iterator<Item = (&'m Function, &'m Module)> + 's {
        self.iter()
            .map(|m| m.functions.iter().zip(std::iter::repeat(m)))
            .flatten()
    }

    /// Get the `NamedStructDef` for a named struct.
    /// Returns both the definition, and the module that definition was found in.
    ///
    /// Returns `None` if neither a definition nor declaration for a named struct
    /// type with the given name was found in any of the modules.
    ///
    /// If the named struct type is defined in multiple modules, this returns one
    /// of them arbitrarily. However, it will only return
    /// `NamedStructDef::Opaque` if _all_ definitions are opaque; that is, it
    /// will attempt to return some non-opaque definition if one exists, before
    /// returning an opaque definition.
    //
    // This function mostly lifted from `haybale`'s project.rs
    pub fn named_struct_def<'s>(&'s self, name: &str) -> Option<(&'s NamedStructDef, &'m Module)> {
        let mut retval: Option<(&'s NamedStructDef, &'m Module)> = None;
        for module in self.iter() {
            if let Some(def) = module.types.named_struct_def(name) {
                match (retval, def) {
                    (None, def) => retval = Some((def, module)), // first definition we've found
                    (Some(_), NamedStructDef::Opaque) => {}, // this is an opaque definition, and we already had a definition (opaque or not)
                    (Some((NamedStructDef::Opaque, _)), def @ NamedStructDef::Defined(_)) => retval = Some((def, module)), // found an actual definition, replace previous opaque definition
                    (Some((NamedStructDef::Defined(_), _)), NamedStructDef::Defined(_)) => {
                        // do nothing, arbitrarily choosing the definition we already had
                    },
                }
            }
        }
        retval
    }
}

impl<'m> FromIterator<&'m Module> for Modules<'m> {
    fn from_iter<I: IntoIterator<Item = &'m Module>>(iter: I) -> Self {
        Self {
            modules: iter.into_iter().collect()
        }
    }
}

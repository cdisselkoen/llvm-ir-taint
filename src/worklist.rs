use log::debug;
use std::collections::HashSet;
use std::iter::FromIterator;

/// Keeps track of the set of functions which need to be processed again because
/// there's been a change to taint information which might be relevant to them.
///
/// To construct a `Worklist`, use its `FromIterator` implementation (i.e., use
/// `.collect()` on an iterator)
pub struct Worklist<'m> {
    fn_names: HashSet<&'m str>,
}

impl<'m> Worklist<'m> {
    /// Adds the given function name to the worklist
    pub fn add(&mut self, fn_name: &'m str) {
        debug!("Adding {:?} to worklist", fn_name);
        self.fn_names.insert(fn_name);
    }

    /// Gets an arbitrary function name on the worklist, removes it from the
    /// worklist, and returns it
    ///
    /// Returns `None` if the worklist was empty
    pub fn pop(&mut self) -> Option<&'m str> {
        let fn_name: &'m str = self
            .fn_names
            .iter()
            .next()?
            .clone();
        self.fn_names.remove(fn_name);
        Some(fn_name)
    }
}

impl<'m> FromIterator<&'m str> for Worklist<'m> {
    fn from_iter<I: IntoIterator<Item = &'m str>>(iter: I) -> Self {
        Self {
            fn_names: iter.into_iter().collect(),
        }
    }
}

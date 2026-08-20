//! Syntax readers more than one walk needs.
//!
//! One copy per reading, because two copies of a reader is how the walks
//! start seeing different programs.

/// The author's own name for the `index`-th declared parameter, or
/// `None` past the list — each caller supplies its own stand-in, and the
/// divergence is visible at the call sites rather than buried in two
/// same-named helpers.
pub fn param_ident(index: u32, params: &[(String, syn::Type)]) -> Option<syn::Ident> {
    params
        .get(index as usize)
        .map(|(name, _)| syn::Ident::new(name, proc_macro2::Span::call_site()))
}

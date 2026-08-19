//! Syntax readers more than one walk needs.
//!
//! One copy per reading, because two copies of a reader is how the walks
//! start seeing different programs: the blueprint walk and the lowering
//! both read byte-string literals and parameter names, and each fact has
//! exactly one definition here.

/// A byte-string literal's bytes, through any references around it.
pub fn byte_literal(expr: &syn::Expr) -> Option<Vec<u8>> {
    match expr {
        syn::Expr::Lit(lit) => match &lit.lit {
            syn::Lit::ByteStr(bytes) => Some(bytes.value()),
            _ => None,
        },
        syn::Expr::Reference(reference) => byte_literal(&reference.expr),
        _ => None,
    }
}

/// The author's own name for the `index`-th declared parameter, or
/// `None` past the list — each caller supplies its own stand-in, and the
/// divergence is visible at the call sites rather than buried in two
/// same-named helpers.
pub fn param_ident(index: u32, params: &[(String, syn::Type)]) -> Option<syn::Ident> {
    params
        .get(index as usize)
        .map(|(name, _)| syn::Ident::new(name, proc_macro2::Span::call_site()))
}

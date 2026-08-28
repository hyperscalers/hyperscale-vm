//! Private methods splice into their callers before lowering.
//!
//! A non-`pub` method on the state impl is an inlining site rather than
//! an export. A call to one binds each argument to a fresh local, binds
//! the parameters from those, and substitutes the body in place with
//! `self` left as `self`. The spliced whole lowers under the ordinary
//! walk, so admissibility does not move — what is refused inline is
//! refused spliced, at the helper's own spans.

use std::collections::BTreeMap;

use proc_macro2::Span;
use quote::format_ident;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::visit_mut::VisitMut;

use crate::lower::{Field, is_self};

/// The state impls' private methods by name, each held to the bounds
/// splicing needs: a name no accessor owns, plain-ident parameters, and
/// a body that yields its tail rather than `return`ing.
pub fn helpers(
    items: &[syn::Item],
    state_name: &syn::Ident,
    accessors: &BTreeMap<String, Field>,
) -> syn::Result<BTreeMap<String, syn::ImplItemFn>> {
    let mut found = BTreeMap::new();
    let mut errors = Vec::new();
    for item in items {
        let syn::Item::Impl(block) = item else {
            continue;
        };
        // A trait impl's methods are the trait's, resolved by Rust's own
        // rules — capturing them as helpers would splice a trait body where
        // the author's text named an inherent method of the same name, and
        // refuse a `return` in a trait method nothing here even calls.
        if block.trait_.is_some() {
            continue;
        }
        if !matches!(&*block.self_ty, syn::Type::Path(p) if p.path.is_ident(state_name)) {
            continue;
        }
        for item in &block.items {
            let syn::ImplItem::Fn(method) = item else {
                continue;
            };
            if matches!(method.vis, syn::Visibility::Public(_)) || method.sig.receiver().is_none() {
                continue;
            }
            let name = method.sig.ident.to_string();
            if accessors.contains_key(&name) {
                errors.push(syn::Error::new(
                    method.sig.ident.span(),
                    format!(
                        "`{name}` is an accessor of every component, so a private method \
                         cannot take the name — every `self.{name}(..)` in a body is the \
                         vocabulary's"
                    ),
                ));
            }
            for arg in &method.sig.inputs {
                let syn::FnArg::Typed(arg) = arg else {
                    continue; // the receiver
                };
                if !matches!(&*arg.pat, syn::Pat::Ident(ident) if ident.subpat.is_none()) {
                    errors.push(syn::Error::new(
                        arg.pat.span(),
                        "a helper's parameter must be a plain name, like an export's — \
                         inlining binds each argument to its name",
                    ));
                }
            }
            Returns {
                errors: &mut errors,
            }
            .visit_block(&method.block);
            found.insert(name, method.clone());
        }
    }
    combined(errors)?;
    Ok(found)
}

/// `method` with every call to a helper replaced by the helper's body.
pub fn splice(
    method: &syn::ImplItemFn,
    helpers: &BTreeMap<String, syn::ImplItemFn>,
) -> syn::Result<syn::ImplItemFn> {
    if helpers.is_empty() {
        return Ok(method.clone());
    }
    let mut spliced = method.clone();
    let mut inliner = Inliner {
        helpers,
        stack: Vec::new(),
        fresh: 0,
        errors: Vec::new(),
    };
    inliner.visit_block_mut(&mut spliced.block);
    combined(inliner.errors)?;
    Ok(spliced)
}

fn combined(errors: Vec<syn::Error>) -> syn::Result<()> {
    errors
        .into_iter()
        .reduce(|mut all, error| {
            all.combine(error);
            all
        })
        .map_or(Ok(()), Err)
}

/// Refuses `return` inside a helper: a helper yields its tail, so an
/// early return would return from whatever export it splices into. A
/// closure's `return` is the closure's own and a nested item's body is
/// not the helper's, so neither is walked.
struct Returns<'e> {
    errors: &'e mut Vec<syn::Error>,
}

impl<'ast> Visit<'ast> for Returns<'_> {
    fn visit_expr_return(&mut self, ret: &'ast syn::ExprReturn) {
        self.errors.push(syn::Error::new(
            ret.span(),
            "a helper yields its tail expression — a `return` here would return from \
             the export the helper splices into",
        ));
        syn::visit::visit_expr_return(self, ret);
    }

    fn visit_expr_closure(&mut self, _: &'ast syn::ExprClosure) {}

    fn visit_item(&mut self, _: &'ast syn::Item) {}
}

struct Inliner<'a> {
    helpers: &'a BTreeMap<String, syn::ImplItemFn>,
    /// The helpers currently being substituted, each with the call that
    /// entered it — the substitution depth, and the cycle report.
    stack: Vec<(String, Span)>,
    /// Numbers the fresh argument locals, one round per spliced call.
    fresh: usize,
    errors: Vec<syn::Error>,
}

impl VisitMut for Inliner<'_> {
    fn visit_expr_mut(&mut self, expr: &mut syn::Expr) {
        syn::visit_mut::visit_expr_mut(self, expr);
        let syn::Expr::MethodCall(call) = expr else {
            return;
        };
        if !is_self(&call.receiver) {
            return;
        }
        let name = call.method.to_string();
        let Some(helper) = self.helpers.get(&name) else {
            return;
        };
        if let Some(block) = self.splice_call(&name, helper, call) {
            *expr = syn::Expr::Block(syn::ExprBlock {
                attrs: Vec::new(),
                label: None,
                block,
            });
        }
    }
}

impl Inliner<'_> {
    fn splice_call(
        &mut self,
        name: &str,
        helper: &syn::ImplItemFn,
        call: &syn::ExprMethodCall,
    ) -> Option<syn::Block> {
        if let Some((_, entered)) = self.stack.iter().find(|(on, _)| on == name) {
            self.errors.push(syn::Error::new(
                call.method.span(),
                format!(
                    "this call re-enters `{name}` — a helper cannot call into a cycle of itself"
                ),
            ));
            self.errors.push(syn::Error::new(
                *entered,
                format!("`{name}` began inlining at this call"),
            ));
            return None;
        }
        let params: Vec<&syn::PatIdent> = helper
            .sig
            .inputs
            .iter()
            .filter_map(|arg| match arg {
                syn::FnArg::Typed(arg) => match &*arg.pat {
                    syn::Pat::Ident(ident) => Some(ident),
                    _ => None,
                },
                syn::FnArg::Receiver(_) => None,
            })
            .collect();
        if params.len() != call.args.len() {
            self.errors.push(syn::Error::new(
                call.args.span(),
                format!(
                    "this call does not match `{name}`'s parameters — a helper splices \
                     only a call its signature admits"
                ),
            ));
            return None;
        }
        if let Some(arg) = call.args.iter().find(|arg| is_self(arg)) {
            self.errors.push(syn::Error::new(
                arg.span(),
                "the component reference cannot be passed on — a helper's body reads \
                 `self` where it stands",
            ));
            return None;
        }
        let mut body = helper.block.clone();
        self.stack.push((name.to_owned(), call.method.span()));
        self.visit_block_mut(&mut body);
        self.stack.pop();

        // Each argument binds to a fresh local before any parameter
        // does, so `helper(b, a)` cannot read a parameter where the
        // caller's own name was meant. A straight `let` keeps a key
        // derivable through the hop; the parameter rebinding is another.
        let round = self.fresh;
        self.fresh += 1;
        let mut stmts: Vec<syn::Stmt> = Vec::new();
        let mut bound: Vec<syn::Ident> = Vec::new();
        for (index, arg) in call.args.iter().enumerate() {
            let fresh = format_ident!("__inline{}_{}", round, index);
            stmts.push(syn::parse_quote!(let #fresh = #arg;));
            bound.push(fresh);
        }
        for (param, fresh) in params.iter().zip(&bound) {
            let mutability = &param.mutability;
            let ident = &param.ident;
            stmts.push(syn::parse_quote!(let #mutability #ident = #fresh;));
        }
        stmts.append(&mut body.stmts);
        Some(syn::Block {
            brace_token: body.brace_token,
            stmts,
        })
    }
}

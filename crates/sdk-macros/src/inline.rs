//! Private methods splice into their callers before lowering.
//!
//! A non-`pub` method on the state impl is an inlining site rather than
//! an export. A call to one binds each argument to a fresh local, binds
//! the parameters from those, and substitutes the body in place with
//! `self` left as `self`. The spliced whole lowers under the ordinary
//! walk, so admissibility does not move — what is refused inline is
//! refused spliced, at the helper's own spans.
//!
//! A helper's exits are its own. A body with no early exit substitutes
//! bare, so its tail is read where the call stood: a key it computes is
//! still derived, and a bucket it takes is still the caller's output.
//! A body with a `return` or a `?` substitutes as a labelled block
//! typed at the helper's return type, its exits rewritten into breaks
//! to that label — control flow, which the walk reads as a body and
//! never as a value.

use std::collections::BTreeMap;

use proc_macro2::Span;
use quote::format_ident;
use syn::spanned::Spanned;
use syn::visit_mut::VisitMut;

use crate::lower::{Field, is_self};

/// The state impls' private methods by name, each held to the bounds
/// splicing needs: a name no accessor owns, plain-ident parameters, and
/// a return type the exit shape can annotate where the body exits early.
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
            // Judged here rather than at a call, so a helper nothing
            // calls is held to the same bounds as one every export uses.
            let mut body = method.block.clone();
            let exits = Rewriter::rewrite(&exit_label(0), &mut errors, &mut body);
            if exits
                && let syn::ReturnType::Type(_, ty) = &method.sig.output
                && matches!(**ty, syn::Type::ImplTrait(_))
            {
                errors.push(syn::Error::new(
                    ty.span(),
                    "a helper that exits early hands its result through a binding typed \
                     at its return type, which `impl Trait` cannot annotate — name the \
                     type",
                ));
            }
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

/// The label a spliced body's exits break to, numbered by the round
/// that spliced it so nested splices cannot capture each other's.
fn exit_label(round: usize) -> syn::Lifetime {
    syn::Lifetime::new(&format!("'__inline{round}"), Span::call_site())
}

/// Rewrites a helper body's early exits into exits of the labelled
/// block it splices as: `return e` becomes `break 'label e`. A `?` is
/// the same early return spelled on an error arm and is refused. A
/// closure's `return` is the closure's own and a nested item's body is
/// not the helper's, so neither is walked.
struct Rewriter<'e> {
    label: &'e syn::Lifetime,
    /// Whether the body had an exit to rewrite, which is what decides
    /// its splice shape.
    rewrote: bool,
    errors: &'e mut Vec<syn::Error>,
}

impl<'e> Rewriter<'e> {
    /// Rewrite `body` in place; whether it had any exit to rewrite.
    fn rewrite(
        label: &'e syn::Lifetime,
        errors: &'e mut Vec<syn::Error>,
        body: &mut syn::Block,
    ) -> bool {
        let mut rewriter = Self {
            label,
            rewrote: false,
            errors,
        };
        rewriter.visit_block_mut(body);
        rewriter.rewrote
    }
}

impl VisitMut for Rewriter<'_> {
    fn visit_expr_mut(&mut self, expr: &mut syn::Expr) {
        if matches!(expr, syn::Expr::Closure(_)) {
            return;
        }
        syn::visit_mut::visit_expr_mut(self, expr);
        match expr {
            syn::Expr::Return(ret) => {
                self.rewrote = true;
                *expr = syn::Expr::Break(syn::ExprBreak {
                    attrs: std::mem::take(&mut ret.attrs),
                    break_token: syn::Token![break](ret.return_token.span),
                    label: Some(self.label.clone()),
                    expr: ret.expr.take(),
                });
            }
            syn::Expr::Try(tried) => {
                self.errors.push(syn::Error::new(
                    tried.question_token.span(),
                    "a helper yields its tail expression — a `?` here would return from \
                     the export the helper splices into",
                ));
            }
            _ => {}
        }
    }

    fn visit_item_mut(&mut self, _: &mut syn::Item) {}
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
        // This round's label is fixed before the body is entered: the
        // exits rewritten here are this helper's, against this helper's
        // return type, and the calls spliced under them take rounds of
        // their own.
        let round = self.fresh;
        self.fresh += 1;
        let label = exit_label(round);
        let mut body = helper.block.clone();
        let exits = Rewriter::rewrite(&label, &mut self.errors, &mut body);
        self.stack.push((name.to_owned(), call.method.span()));
        self.visit_block_mut(&mut body);
        self.stack.pop();

        // Each argument binds to a fresh local before any parameter
        // does, so `helper(b, a)` cannot read a parameter where the
        // caller's own name was meant. A straight `let` keeps a key
        // derivable through the hop; the parameter rebinding is another.
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
        if exits {
            // The binding's type is what lets an exit's value infer —
            // `Err(From::from(e))` under a caller's `?` has no other
            // anchor — and the block behind it is control flow the walk
            // reads as a body.
            let result = format_ident!("__inline{}", round);
            let ty: syn::Type = match &helper.sig.output {
                syn::ReturnType::Default => syn::parse_quote!(()),
                syn::ReturnType::Type(_, ty) => (**ty).clone(),
            };
            stmts.push(syn::parse_quote!(let #result: #ty = #label: #body;));
            stmts.push(syn::Stmt::Expr(syn::parse_quote!(#result), None));
        } else {
            stmts.append(&mut body.stmts);
        }
        Some(syn::Block {
            brace_token: body.brace_token,
            stmts,
        })
    }
}

#[cfg(test)]
mod tests {
    use quote::ToTokens;

    use super::*;

    /// The `pub` method of `source`'s `impl Contract`, spliced.
    fn spliced(source: &str) -> String {
        let file: syn::File = syn::parse_str(source).expect("the fixture parses");
        let state = syn::Ident::new("Contract", Span::call_site());
        let helpers = helpers(&file.items, &state, &BTreeMap::new())
            .unwrap_or_else(|error| panic!("the helpers are admitted: {error}"));
        let export = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Impl(block) => Some(&block.items),
                _ => None,
            })
            .flatten()
            .find_map(|item| match item {
                syn::ImplItem::Fn(method) if matches!(method.vis, syn::Visibility::Public(_)) => {
                    Some(method)
                }
                _ => None,
            })
            .expect("the fixture has an export");
        splice(export, &helpers)
            .expect("the export splices")
            .block
            .to_token_stream()
            .to_string()
    }

    #[test]
    fn a_body_without_an_exit_splices_bare() {
        let out = spliced(
            "impl Contract {
                pub fn drain(&mut self) -> u64 { self.poll(1) }
                fn poll(&self, floor: u64) -> u64 { self.held + floor }
            }",
        );
        assert!(!out.contains("__inline0 :"), "no labelled block: {out}");
        assert!(
            out.contains("let floor = __inline0_0 ;"),
            "the parameter rebinds: {out}"
        );
        assert!(
            out.contains("self . held + floor }"),
            "the tail is read in place: {out}"
        );
    }

    #[test]
    fn a_body_with_an_exit_splices_as_a_labelled_typed_block() {
        let out = spliced(
            "impl Contract {
                pub fn drain(&mut self) -> u64 { self.poll(1) }
                fn poll(&self, floor: u64) -> u64 {
                    if self.held == 0 { return floor; }
                    self.held
                }
            }",
        );
        assert!(
            out.contains("let __inline0 : u64 = '__inline0 : {"),
            "the block is typed at the return type and labelled: {out}"
        );
        assert!(
            out.contains("break '__inline0 floor ;"),
            "the return breaks: {out}"
        );
        assert!(
            out.ends_with("; __inline0 } }"),
            "the binding is the tail: {out}"
        );
    }

    #[test]
    fn a_closure_keeps_its_own_return() {
        let out = spliced(
            "impl Contract {
                pub fn drain(&mut self) -> u64 { self.poll() }
                fn poll(&self) -> u64 { let f = |x: u64| { return x; }; f(self.held) }
            }",
        );
        assert!(
            out.contains("return x ;"),
            "the closure's return stands: {out}"
        );
        assert!(
            !out.contains("'__inline"),
            "and it is not an exit of the helper: {out}"
        );
    }

    #[test]
    fn nested_splices_break_to_their_own_labels() {
        let out = spliced(
            "impl Contract {
                pub fn drain(&mut self) -> u64 { self.outer() }
                fn outer(&self) -> u64 {
                    if self.held == 0 { return 0; }
                    self.inner()
                }
                fn inner(&self) -> u64 {
                    if self.held == 1 { return 1; }
                    self.held
                }
            }",
        );
        assert!(
            out.contains("break '__inline0 0 ;"),
            "outer exits to round 0: {out}"
        );
        assert!(
            out.contains("break '__inline1 1 ;"),
            "inner exits to round 1: {out}"
        );
    }
}

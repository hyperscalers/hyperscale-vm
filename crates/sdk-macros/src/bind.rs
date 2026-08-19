//! What an export takes, in the order it takes it.
//!
//! One walk over the lowering — handles, then values, then the grant —
//! producing the parameter list every target binds from. Computed once
//! rather than per target: which position carries which capability is the
//! declaration's answer, and two walks that agreed today would be two
//! walks that could stop agreeing. A native call that bound them in a
//! different order would pass its own tests while the artifact it stands
//! for did something else.

use crate::lower::{Lowered, Need, flag_ident, handle_ident, value_ident};
use crate::term::Term;
use crate::wit::{Param, Shape};

/// What one export parameter carries.
pub enum Carries {
    /// A materialized capability, at the resource its clause declares.
    Handle(&'static str),
    /// A value edge, under the author's own name for it.
    Edge {
        /// The name the method's signature gave the parameter.
        name: syn::Ident,
    },
    /// A value the body reads, in the shape its parameter names.
    Value,
    /// A branch's verdict, as the declaration reached it.
    Flag,
    /// This invocation's authority to issue.
    Issuer,
}

/// One export parameter: what the world calls it, and what a target has
/// to bind for the body to read it.
pub struct Binding {
    /// The parameter the WIT document declares.
    pub param: Param,
    /// The identifier the parameter arrives under.
    pub ident: syn::Ident,
    /// What it carries.
    pub carries: Carries,
}

/// How the guest reads the value carrying `need`.
///
/// A `u64` crosses as itself, an address as the world's record and an id
/// set as the ids it is; everything else crosses as the kernel's cell
/// representation and is decoded through [`Cellular`], which is the same
/// vocabulary a substate value uses.
///
/// [`Cellular`]: hyperscale_vm_sdk::state::Cellular
fn value_shape(
    need: &Need,
    params: &[(String, syn::Type)],
    config: &[(String, syn::Type)],
) -> Shape {
    let scalar = |ty: &syn::Type| matches!(ty, syn::Type::Path(p) if p.path.is_ident("u64"));
    let address = |ty: &syn::Type| matches!(ty, syn::Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "Address"));
    let id_set = |ty: &syn::Type| matches!(ty, syn::Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "Ids"));
    let named = |ty: &syn::Type| {
        if scalar(ty) {
            Shape::Scalar
        } else if address(ty) {
            Shape::Address
        } else if id_set(ty) {
            Shape::Ids
        } else {
            Shape::Cell(Box::new(ty.clone()))
        }
    };
    match need {
        // A value edge crosses as the handle the kernel holds it behind.
        Need::Amount(_) => Shape::Bucket,
        // An order key crosses at the kernel's own 128-bit cell width,
        // whatever the logical key it was derived from.
        Need::Derived(Term::OrderKey { .. }) => Shape::Cell(Box::new(syn::parse_quote!(
            ::hyperscale_vm_sdk::state::OrderKey
        ))),
        // A resource is an address however it was derived.
        Need::Derived(Term::SelfResource(_) | Term::ResourceOf(_)) => Shape::Address,
        Need::Derived(Term::Arg(index)) => params
            .get(*index as usize)
            .map_or(Shape::Scalar, |(_, ty)| named(ty)),
        Need::Derived(Term::Config(index)) => config
            .get(*index as usize)
            .map_or(Shape::Scalar, |(_, ty)| named(ty)),
        // A fresh id is a `u64`, and so is anything else the evaluator
        // reduces to a scalar.
        Need::Derived(_) => Shape::Scalar,
    }
}

/// The author's own name for the `index`-th declared parameter.
fn param_ident(index: u32, params: &[(String, syn::Type)]) -> syn::Ident {
    params.get(index as usize).map_or_else(
        || syn::Ident::new("__edge", proc_macro2::Span::call_site()),
        |(name, _)| syn::Ident::new(name, proc_macro2::Span::call_site()),
    )
}

/// Everything one export takes, in the order it takes it.
///
/// Handles first, in declaration order, then the branch verdicts, then
/// the values the body could not compute, then the issuance grant where
/// the method issues. The
/// grant sits last because it is granted per invocation rather than
/// declared, so nothing about the clause list moves when a method gains
/// or loses one.
pub fn bindings(
    lowered: &Lowered,
    params: &[(String, syn::Type)],
    config: &[(String, syn::Type)],
) -> Vec<Binding> {
    let mut bindings = Vec::new();

    for (position, site) in lowered.handles.iter().copied().enumerate() {
        let resource = lowered
            .sites
            .get(site)
            .and_then(crate::lower::Site::resource)
            .unwrap_or("read-cell");
        bindings.push(Binding {
            param: Param {
                name: format!("handle-{position}"),
                shape: Shape::Handle(resource),
            },
            ident: handle_ident(site),
            carries: Carries::Handle(resource),
        });
    }

    for position in 0..lowered.flags.len() {
        bindings.push(Binding {
            param: Param {
                name: format!("flag-{position}"),
                shape: Shape::Flag,
            },
            ident: flag_ident(position),
            carries: Carries::Flag,
        });
    }

    for (position, need) in lowered.values.iter().enumerate() {
        let shape = value_shape(need, params, config);
        let carries = match need {
            Need::Amount(param) => Carries::Edge {
                name: param_ident(*param, params),
            },
            Need::Derived(_) => Carries::Value,
        };
        bindings.push(Binding {
            param: Param {
                name: format!("value-{position}"),
                shape,
            },
            ident: value_ident(position),
            carries,
        });
    }

    if lowered.issues.is_some() {
        bindings.push(Binding {
            param: Param {
                name: "issuer".to_owned(),
                shape: Shape::Issuer,
            },
            ident: syn::Ident::new("__issuer_handle", proc_macro2::Span::call_site()),
            carries: Carries::Issuer,
        });
    }

    bindings
}

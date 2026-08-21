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
use crate::mode::HandleMode;
use crate::term::Term;
use crate::wit::{Param, Shape};
use crate::{is_address, is_named};

/// What one export parameter carries.
pub enum Carries {
    /// A materialized capability, at the resource its clause declares.
    Handle(HandleMode),
    /// A value edge, under the author's own name for it.
    Edge {
        /// The name the method's signature gave the parameter.
        name: syn::Ident,
        /// Whether the parameter is declared `NfBucket`, which is the
        /// type the prologue rebuilds it as.
        nf: bool,
    },
    /// A value the body reads, in the shape its parameter names.
    Value {
        /// The class-typed form the body reads an address as, where the
        /// declared type names one narrower than `Address`.
        narrow: Option<Box<syn::Type>>,
    },
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
    match need {
        // A value edge crosses as the handle the kernel holds it behind.
        Need::Amount(_) => Shape::Bucket,
        // A selection whose arms disagree was refused where it was
        // written, so nothing derivable reaches here without a shape.
        Need::Derived(term) => derived_shape(term, params, config).unwrap_or(Shape::Scalar),
    }
}

/// The family name a type narrows as: its last path segment, which is
/// the identity the whole walk matches the address vocabulary by.
fn family_name(ty: &syn::Type) -> Option<&syn::Ident> {
    match ty {
        syn::Type::Path(path) => path.path.segments.last().map(|s| &s.ident),
        _ => None,
    }
}

/// The class-typed form the body reads an address-shaped term as, where
/// the type it was declared at — or the accessor it came from — names one
/// narrower than `Address`.
fn narrow_type(
    term: &Term,
    params: &[(String, syn::Type)],
    config: &[(String, syn::Type)],
) -> Option<syn::Type> {
    let named = |ty: &syn::Type| (!is_named(ty, "Address") && is_address(ty)).then(|| ty.clone());
    match term {
        // A resource is a denomination however it was derived, which is
        // the type `issued()` and `Bucket::resource()` hand the body.
        Term::SelfResource(..) | Term::ResourceOf(_) => {
            Some(syn::parse_quote!(::hyperscale_vm_sdk::ResourceAddr))
        }
        Term::Arg(index) => params.get(*index as usize).and_then(|(_, ty)| named(ty)),
        Term::Config(index) => config.get(*index as usize).and_then(|(_, ty)| named(ty)),
        Term::Lookup { map, .. } => match &**map {
            Term::Config(index) => config
                .get(*index as usize)
                .and_then(|(_, ty)| table_value(ty))
                .and_then(|value| named(&value)),
            _ => None,
        },
        // A selection narrows only where both arms read at one type. The
        // arms may spell it under different paths, so the comparison is
        // by family name — the same identity the vocabulary matches by.
        Term::If {
            then, otherwise, ..
        } => {
            let taken = narrow_type(then, params, config)?;
            let untaken = narrow_type(otherwise, params, config)?;
            (family_name(&taken) == family_name(&untaken)).then_some(taken)
        }
        _ => None,
    }
}

/// The shape a derived term crosses the boundary as, or `None` where a
/// selection's arms cross as different shapes — no one export parameter
/// can carry what such a term chooses, and the lowering refuses it on
/// the line that wrote the selection.
pub fn derived_shape(
    term: &Term,
    params: &[(String, syn::Type)],
    config: &[(String, syn::Type)],
) -> Option<Shape> {
    let scalar = |ty: &syn::Type| matches!(ty, syn::Type::Path(p) if p.path.is_ident("u64"));
    let address = is_address;
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
    Some(match term {
        // An order key crosses at the kernel's own 128-bit cell width,
        // whatever the logical key it was derived from.
        Term::OrderKey { .. } => Shape::Cell(Box::new(syn::parse_quote!(
            ::hyperscale_vm_sdk::state::OrderKey
        ))),
        // A resource is an address however it was derived.
        Term::SelfResource(..) | Term::ResourceOf(_) => Shape::Address,
        // The record crosses as the leaf's own bytes, which is the cell
        // representation it is.
        Term::SelfRecord => Shape::Cell(Box::new(syn::parse_quote!(::std::vec::Vec<u8>))),
        Term::Arg(index) => params
            .get(*index as usize)
            .map_or(Shape::Scalar, |(_, ty)| named(ty)),
        Term::Config(index) => config
            .get(*index as usize)
            .map_or(Shape::Scalar, |(_, ty)| named(ty)),
        // A lookup crosses as the table's value, whose type is written
        // on the configured field holding the table.
        Term::Lookup { map, .. } => match &**map {
            Term::Config(index) => config
                .get(*index as usize)
                .and_then(|(_, ty)| table_value(ty))
                .map_or(Shape::Scalar, |value| named(&value)),
            _ => Shape::Scalar,
        },
        // A selection crosses as its arms do, so it has a shape only
        // where they share one.
        Term::If {
            then, otherwise, ..
        } => {
            let taken = derived_shape(then, params, config)?;
            let untaken = derived_shape(otherwise, params, config)?;
            if same_shape(&taken, &untaken) {
                taken
            } else {
                return None;
            }
        }
        // A fresh id is a `u64`, and so is anything else the evaluator
        // reduces to a scalar.
        _ => Shape::Scalar,
    })
}

/// The value type of a configured `Table<K, V>`, where `ty` is one.
fn table_value(ty: &syn::Type) -> Option<syn::Type> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    if segment.ident != "Table" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    match args.args.iter().nth(1)? {
        syn::GenericArgument::Type(value) => Some(value.clone()),
        _ => None,
    }
}

/// Whether two shapes cross the boundary identically. Cell types compare
/// by their tokens, which is what the emitted prologue is made of.
fn same_shape(a: &Shape, b: &Shape) -> bool {
    match (a, b) {
        (Shape::Scalar, Shape::Scalar)
        | (Shape::Address, Shape::Address)
        | (Shape::Ids, Shape::Ids)
        | (Shape::Flag, Shape::Flag)
        | (Shape::Bucket, Shape::Bucket)
        | (Shape::Issuer, Shape::Issuer) => true,
        (Shape::Cell(left), Shape::Cell(right)) => {
            quote::quote!(#left).to_string() == quote::quote!(#right).to_string()
        }
        (Shape::Handle(left), Shape::Handle(right)) => left == right,
        _ => false,
    }
}

/// The author's own name for the `index`-th declared parameter, with a
/// stand-in for an edge past the list.
fn param_ident(index: u32, params: &[(String, syn::Type)]) -> syn::Ident {
    crate::syntax::param_ident(index, params)
        .unwrap_or_else(|| syn::Ident::new("__edge", proc_macro2::Span::call_site()))
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
            .unwrap_or(HandleMode::ReadCell);
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
                nf: params
                    .get(*param as usize)
                    .is_some_and(|(_, ty)| is_named(ty, "NfBucket")),
            },
            Need::Derived(term) => Carries::Value {
                narrow: matches!(shape, Shape::Address)
                    .then(|| narrow_type(term, params, config))
                    .flatten()
                    .map(Box::new),
            },
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

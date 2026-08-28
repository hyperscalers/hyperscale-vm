//! The gate grammar: who a method requires, and what it proves.
//!
//! `#[requires(…)]` and `#[proves(…)]` over the leaf grammar in
//! [`rule`](super::rule), plus what a gate lowers to — the declared
//! reads its rule needs provisioned, and the shape check that holds a
//! body's parameters to the gate it was written with.

use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::spanned::Spanned as _;

use crate::Declared;
use crate::client::Serves;
use crate::lower::{self};
use crate::resource::Resource;
use crate::rule::{RuleAst, calls, config_slot, diagnose_bare_name, parse_rule};
use crate::state::holds_rule;
use crate::term::emit_kind;

/// Whose authority naming a method requires, as its own attribute says.
pub enum Gate {
    /// Anyone may name it.
    Public,
    /// A rule over identities the target itself names.
    Guarded {
        /// The rule, as a tracer call answering a `Requirement`.
        rule: TokenStream2,
    },
    /// The target's own stored rule, read at the named field's cell.
    Authorizing(u16),
    /// The rule stored at a declared cell, or — while nothing is stored
    /// there — the identity that address itself derives.
    Governed(u16),
    /// The target's rule and its possession of the badge a parameter
    /// names: the field the rule is stored at, and the parameter's index.
    Custodial {
        /// The slot of the state field holding the target's stored rule.
        rule: u16,
        /// The parameter naming the badge.
        badge: u32,
        /// The parameter naming which instance of it, where the badge is
        /// non-fungible. Absent for a fungible badge, whose possession
        /// is an amount rather than a named thing.
        id: Option<u32>,
    },
}

/// The rule a `#[guarded]` method requires, as a tracer call answering a
/// `Requirement`.
///
/// Rust's own operators carry the algebra: `||` is a count of one, `&&`
/// a count of every branch, and `n_of(k, …)` the threshold no operator
/// expresses. Precedence and grouping are the language's, so an author
/// reads a gate the way they read any other condition — and a chain of
/// one operator flattens into one threshold rather than nesting, because
/// depth is the cap that binds first.
///
/// Answers the rule alone: how many claims meeting it takes, and whose,
/// is the judge's business at the call rather than a shape carried here.
pub fn guarded_rule(
    expr: &syn::Expr,
    config_fields: &[(String, syn::Type)],
    resources: &[Resource],
    params: &[(String, syn::Type)],
    depth: usize,
) -> syn::Result<TokenStream2> {
    let rule = parse_rule(expr, "a gate", depth, &mut |leaf| {
        guarded_identity(leaf, config_fields, resources, params)
    })?;
    Ok(match &rule {
        RuleAst::Leaf((identity, _)) => quote!(__t.claim(&#identity)),
        node @ RuleAst::CountOf { .. } => emit_guarded(node),
    })
}

/// A gate's rule, as a tracer call answering a `Requirement`.
pub fn emit_guarded(rule: &RuleAst<(TokenStream2, bool)>) -> TokenStream2 {
    match rule {
        RuleAst::Leaf((identity, _)) => quote!(__t.claim(&#identity)),
        RuleAst::CountOf { count, branches } => {
            let lowered = branches.iter().map(emit_guarded);
            quote!(__t.n_of(#count, ::std::vec![#(#lowered),*]))
        }
    }
}

/// The identity a `#[guarded]` method requires, as a tracer call.
///
/// Every identity a method can require is one the target itself names.
/// A caller who names the identity they must present can always present
/// it, so a gate over an argument reads as guarded and admits everyone —
/// which is the refusal `check_abi` makes at publish, made here on the
/// line that wrote it.
pub fn guarded_identity(
    identity: &syn::Expr,
    config_fields: &[(String, syn::Type)],
    resources: &[Resource],
    params: &[(String, syn::Type)],
) -> syn::Result<(TokenStream2, bool)> {
    // Possession has its own authoring surface, and `#[requires]` is
    // not it: a rule is a match over presented claims, and a `holds`
    // anywhere in one — beside a rule under a conjunction as much as
    // within it under a disjunction — would make authority a predicate
    // engine, which is the fence this grammar keeps.
    if let syn::Expr::Call(call) = identity
        && matches!(call.func.as_ref(), syn::Expr::Path(path) if path.path.is_ident("holds"))
    {
        return Err(syn::Error::new(
            identity.span(),
            "a `#[requires]` rule names claims only; possession is spelled \
             `#[proves(badge)]`, and what a vault holds is the state field's own \
             `#[holds(..)]`",
        ));
    }
    let refuse = || {
        syn::Error::new(
            identity.span(),
            "a guarded method names `self`, `config.<field>`, or `issued(<Resource>)`",
        )
    };
    match identity {
        syn::Expr::Path(path) if path.path.is_ident("self") => Ok((quote!(__t.self_addr()), true)),
        // A bare name is not a leaf; the shared diagnosis says which
        // spelling the author meant. The one bare name this grammar
        // alone must catch first is a parameter, because admitting it
        // would gate on something the caller supplies.
        syn::Expr::Path(path) if path.path.get_ident().is_some() => {
            let name = path.path.get_ident().expect("checked").to_string();
            if params.iter().any(|(p, _)| *p == name) {
                return Err(syn::Error::new(
                    identity.span(),
                    "the authority this method requires is one its caller names, so \
                     the gate would admit everyone — name `self`, `config.<field>`, \
                     or `issued(<Resource>)` instead",
                ));
            }
            Err(diagnose_bare_name(
                identity.span(),
                &name,
                resources.iter().map(|r| r.name.as_str()),
                config_fields.iter().map(|(f, _)| f.as_str()),
            )
            .unwrap_or_else(refuse))
        }
        // Creation-fixed, so the claim is the target's own: an object
        // whose address derives from no key admits somebody by naming
        // them where it was created.
        syn::Expr::Field(access) => {
            let Some(slot) = config_slot(access, config_fields.iter().map(|(f, _)| f.as_str()))
            else {
                return Err(refuse());
            };
            let slot = slot?;
            Ok((
                quote!(__t.config::<::hyperscale_vm_sdk::Addr>(#slot)),
                false,
            ))
        }
        // A badge the instance issues: holding it is operating the
        // instance, and it derives from the address rather than from
        // anything a caller supplies. `issued(Name)` names a declared
        // `#[resource]` struct, because the derivation folds the kind
        // and the declaration is where a kind is stated.
        syn::Expr::Call(call) => {
            let named = match &*call.func {
                syn::Expr::Path(path) => path
                    .path
                    .segments
                    .last()
                    .is_some_and(|s| s.ident == "issued"),
                _ => false,
            };
            let resolved = call
                .args
                .first()
                .and_then(|arg| match arg {
                    syn::Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
                    _ => None,
                })
                .and_then(|name| resources.iter().find(|r| r.name == name));
            match (named, resolved) {
                (true, Some(issued)) => {
                    let kind = emit_kind(issued.kind);
                    let mark = syn::LitByteStr::new(&issued.mark, identity.span());
                    Ok((quote!(__t.self_resource(#kind, #mark)), false))
                }
                _ => Err(refuse()),
            }
        }
        _ => Err(refuse()),
    }
}

/// The `#[requires(<rule>)]` grammar: the stored-rule form
/// `governs(<field>)`, or a rule over claims the declaration names.
pub fn parse_requires(
    attr: &syn::Attribute,
    declared: &Declared<'_>,
    params: &[(String, syn::Type)],
) -> syn::Result<Gate> {
    let written: syn::Expr = attr.parse_args()?;
    // The stored-rule form: `governs(<field>)` names the cell whose rule
    // governs, which is the address's own `auth` cell or one a package
    // keeps itself. What governs while nothing is stored there is the
    // rule's own second branch rather than anything the kernel supplies.
    if let syn::Expr::Call(call) = &written
        && calls(&call.func, "governs")
    {
        let named = match call.args.first() {
            Some(syn::Expr::Path(path)) => path.path.require_ident()?,
            _ => {
                return Err(syn::Error::new(
                    call.span(),
                    "`governs(..)` names the cell whose stored rule governs",
                ));
            }
        };
        let name = named.to_string();
        let Some(field) = declared
            .accessors
            .get(&name)
            .or_else(|| declared.fields.get(&name))
        else {
            return Err(syn::Error::new(
                named.span(),
                "not a cell of this package — `governs(auth)` names the address's own \
                 governing rule, and a package keeping others names one of its fields",
            ));
        };
        if !holds_rule(field) {
            return Err(syn::Error::new(
                named.span(),
                "this cell does not hold a rule — a stored rule lives in a \
                 `Cell<Option<RuleBytes>>` field",
            ));
        }
        return Ok(Gate::Governed(field.slot));
    }
    let rule = guarded_rule(
        &written,
        declared.config_fields,
        declared.resources,
        params,
        0,
    )?;
    Ok(Gate::Guarded { rule })
}

/// The named parameter's position, held to the type the emitted read
/// gives it: the runtime reads a badge as an address and an instance id
/// as a `u64`, so a parameter declared anything else would compile here
/// and trap at the first call, spanning nothing.
fn parameter_position(
    params: &[(String, syn::Type)],
    named: &syn::Ident,
    admits: fn(&syn::Type) -> bool,
    expected: &str,
) -> syn::Result<u32> {
    let index = params
        .iter()
        .position(|(p, _)| named == p.as_str())
        .ok_or_else(|| {
            syn::Error::new(
                named.span(),
                format!(
                    "`{named}` is not a parameter of this method — a gate reads the \
                     badge and its id off the method's own parameters"
                ),
            )
        })?;
    let (_, ty) = &params[index];
    if !admits(ty) {
        let declared = quote!(#ty);
        return Err(syn::Error::new(
            named.span(),
            format!("`{named}` is declared `{declared}`, and {expected}"),
        ));
    }
    Ok(u32::try_from(index).expect("a parameter list is shorter than u32"))
}

/// Read a method's gate off its attributes.
pub fn parse_gate(
    method: &syn::ImplItemFn,
    declared: &Declared<'_>,
    params: &[(String, syn::Type)],
) -> syn::Result<Gate> {
    // A gate names the cell its rule lives in the way a body would, and a
    // body reaches the protocol's own cells by accessor.
    let cell = |name: &syn::Ident| {
        declared
            .fields
            .get(&name.to_string())
            .or_else(|| declared.accessors.get(&name.to_string()))
            .map(|f| f.slot)
            .ok_or_else(|| {
                syn::Error::new(
                    name.span(),
                    "not a cell of the component's state — name a declared field or one of \
                     the protocol's own cells",
                )
            })
    };
    // Collected before any is read, because a method's gate is one gate:
    // reading the first and stopping would take a second attribute's word
    // for nothing while `strip` removed it, and a declaration that is
    // silently smaller than what the author wrote is the failure this
    // derivation must not have.
    let mut gates = method
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("requires") || attr.path().is_ident("proves"));
    let Some(attr) = gates.next() else {
        return Ok(Gate::Public);
    };
    if let Some(second) = gates.next() {
        let mut refusal = syn::Error::new_spanned(
            second,
            "a method carries one gate — combine what it asks into a single `#[requires(…)]`",
        );
        refusal.combine(syn::Error::new_spanned(
            attr,
            "the gate this method already carries",
        ));
        return Err(refusal);
    }
    if attr.path().is_ident("requires") {
        return parse_requires(attr, declared, params);
    }
    let claim: syn::Expr = attr.parse_args()?;
    // `proves(self)`: satisfying one's own stored rule, proving
    // one's own identity.
    if let syn::Expr::Path(path) = &claim
        && path.path.is_ident("self")
    {
        let auth = syn::Ident::new("auth", claim.span());
        return Ok(Gate::Authorizing(cell(&auth)?));
    }
    let auth = syn::Ident::new("auth", claim.span());
    let rule = cell(&auth)?;
    let position = |named: &syn::Ident, admits: fn(&syn::Type) -> bool, expected: &str| {
        parameter_position(params, named, admits, expected)
    };
    let badge_position =
        |named: &syn::Ident| position(named, crate::is_address, "a badge is an address");
    // `proves(badge)` and `proves(badge[id])`: the stored rule,
    // possession of the badge, and the badge's mint.
    match &claim {
        syn::Expr::Path(badge) => {
            let badge = badge.path.require_ident()?;
            Ok(Gate::Custodial {
                rule,
                badge: badge_position(badge)?,
                id: None,
            })
        }
        syn::Expr::Index(index) => {
            let (syn::Expr::Path(badge), syn::Expr::Path(id)) =
                (index.expr.as_ref(), index.index.as_ref())
            else {
                return Err(syn::Error::new(
                    index.span(),
                    "an instance claim is written `badge[id]`, both parameters of \
                     this method",
                ));
            };
            Ok(Gate::Custodial {
                rule,
                badge: badge_position(badge.path.require_ident()?)?,
                id: Some(position(
                    id.path.require_ident()?,
                    |ty| crate::is_named(ty, "u64"),
                    "an instance id is a `u64`",
                )?),
            })
        }
        _ => Err(syn::Error::new(
            claim.span(),
            "a call proves `self`, a badge parameter, or `badge[id]`",
        )),
    }
}

/// The tracer calls a gate becomes.
///
/// A gate's clauses are its own, declared beside whatever the body
/// declares: the kernel reads an authorizing method's stored rule
/// before the export runs, so the read is declared here and no handle
/// is bound for it.
pub fn gate_calls(gate: &Gate, lowered: &lower::Lowered, serves: Serves) -> TokenStream2 {
    match gate {
        Gate::Public => quote!(),
        Gate::Guarded { rule, .. } => quote!({
            let __rule = #rule;
            __t.guarded_by(__rule);
        }),
        // A principal's sign-in reads the stored rule; a component has
        // no rule anyone can store and no signature yields a claim on a
        // derived address, so its identity is its code — the claim is
        // declared bare and the body is the gate.
        Gate::Authorizing(_) if matches!(serves, Serves::Instances) => quote!({
            __t.proving();
        }),
        Gate::Authorizing(slot) => quote!({
            let __owner = __t.self_addr();
            let __key = __owner.child(::hyperscale_vm_sdk::SlotId(#slot), &[]);
            __t.point(&__key).read();
            __t.authorizing();
        }),
        // A governing gate declares its own read — unless the body
        // already reaches the cell, in which case the gate rides the
        // body's own clause: one cell is one clause, and two declarations
        // of it would be a self-conflict.
        Gate::Governed(slot) => {
            if lowered.point_site(*slot).is_some() {
                quote!(__t.governed_by_what_it_writes(::hyperscale_vm_sdk::SlotId(#slot));)
            } else {
                quote!({
                    let __owner = __t.self_addr();
                    let __key = __owner.child(::hyperscale_vm_sdk::SlotId(#slot), &[]);
                    __t.point(&__key).read();
                    __t.governed_by();
                })
            }
        }
        // A custody gate is two reads and neither is the body's: the
        // kernel judges the holder's stored rule and their possession of
        // the badge before the export runs, so what the clauses do is
        // provision the cells it reads. The possession read is pinned to
        // the protocol's own slot, keyed by exactly the expressions the
        // mint names — which is what ties what is minted to what is
        // held. It says what it holds too: a vault is a value cell in
        // every mode it is reached in, and a read that said nothing
        // would be a read of bytes.
        Gate::Custodial {
            rule,
            badge,
            id: None,
        } => quote!({
            let __owner = __t.self_addr();
            let __badge = __t.arg::<::hyperscale_vm_sdk::Addr>(#badge);
            let __material = [__badge.clone().cast::<::hyperscale_vm_sdk::Opaque>()];
            let __rule = __owner.child(::hyperscale_vm_sdk::SlotId(#rule), &[]);
            __t.point(&__rule).read();
            let __vault = __owner.child(::hyperscale_vm_sdk::VAULT, &__material);
            __t.point(&__vault).holding(&__badge).read();
            __t.custodial(&__badge);
        }),
        Gate::Custodial {
            rule,
            badge,
            id: Some(id),
        } => quote!({
            let __owner = __t.self_addr();
            let __badge = __t.arg::<::hyperscale_vm_sdk::Addr>(#badge);
            let __id = __t
                .arg::<::hyperscale_vm_sdk::U64>(#id)
                .cast::<::hyperscale_vm_sdk::U128>();
            let __material = [__badge.clone().cast::<::hyperscale_vm_sdk::Opaque>()];
            let __rule = __owner.child(::hyperscale_vm_sdk::SlotId(#rule), &[]);
            __t.point(&__rule).read();
            // The entry at the instance's own id: holding that one, not
            // holding any.
            __t.entry(
                &__owner,
                ::hyperscale_vm_sdk::NF_VAULT,
                &__material,
                &__id,
            )
            .holding(&__badge)
            .read();
            __t.custodial_instance(&__badge, &__id);
        }),
    }
}

/// Hold a gate to the declaration shape the publish gate pins for it.
///
/// The same rules `hyperscale_vm_effects::check_abi` applies to a
/// published artifact, applied to the body that would produce one — so an
/// author hears about it on the offending line rather than at the moment
/// they try to publish.
pub fn check_gate_shape(
    gate: &Gate,
    lowered: &lower::Lowered,
    method: &syn::ImplItemFn,
) -> syn::Result<()> {
    match gate {
        // A public method, a gate over claims, and a gate over a stored
        // rule all put no shape on the body: what governs a cell nothing
        // has written is the rule's own second branch, so a rewrite needs
        // no reading of what it replaces.
        Gate::Public | Gate::Guarded { .. } | Gate::Governed(_) => Ok(()),
        // An authorizing body is ordinary — banking a payment, burning a
        // receipt, marking a pass consumed — and may decline: the claim
        // is judged at admission, and a declined prover fails the
        // transaction wholesale, so nothing downstream ever ran with the
        // proof. Its one product is the claim, so an edge or an answer
        // is refused: either would reopen the call matrix, and a
        // composer reads a proving node as evidence, never as value
        // flow. Both live in the return type, which is what the error
        // underlines.
        Gate::Authorizing(_) => {
            if !lowered.outputs.is_empty() {
                Err(syn::Error::new(
                    method.sig.output.span(),
                    "a proving call's one product is the claim, so a `#[proves(self)]` body \
                     produces no edge — move the payout to a method the proof gates",
                ))
            } else if lowered.answer.is_some() {
                Err(syn::Error::new(
                    method.sig.output.span(),
                    "a proving call's one product is the claim, so a `#[proves(self)]` body \
                     answers nothing — a composer reads a proving node as evidence, never \
                     as a value",
                ))
            } else {
                Ok(())
            }
        }
        Gate::Custodial { .. } => {
            if lowered.sites.is_empty() {
                Ok(())
            } else {
                // The body is the offender, so the body is the span.
                Err(syn::Error::new(
                    method.block.span(),
                    "a custodial method declares two reads — its rule cell, and the \
                     badge-keyed vault or holdings entry its claim names — and the \
                     kernel makes both before the export runs. The body has nothing \
                     left to say, so it must be empty",
                ))
            }
        }
    }
}

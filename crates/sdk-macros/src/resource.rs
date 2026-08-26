//! The resource grammar: what a package issues, and what its entries
//! grant.
//!
//! `#[resource(…)]` over the leaf grammar in [`rule`](super::rule), and
//! the calling surface each declaration derives — the address, the
//! record creation, and whichever of the value, instance and reach
//! surfaces the resource's kind admits. A grant is refused here where
//! the behaviour its entry names does not admit the spelling it was
//! written with.

use hyperscale_vm_effects::{GrantedBehaviour, ResourceKind};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::spanned::Spanned;

use crate::kebab;
use crate::role::Role;
use crate::rule::{RuleAst, calls, config_slot, diagnose_bare_name, parse_rule};
use crate::state::distinct_band;
use crate::term::emit_behaviour;

/// The resources a package issues, by the name each is declared under.
///
/// A resource address is its minter over the material that separates one
/// of its resources from another, and that material is a hash preimage:
/// a mark typed one character differently is a different, perfectly
/// valid address that nothing holds and no gate can open. Naming it
/// makes the mark the item's, derived once, so a typo is an unresolved
/// path rather than a method unreachable for the life of an immutable
/// package.
///
/// The mark is the name as the protocol spells names everywhere else, so
/// what an author reads in a gate and what a consumer reads off the
/// emitted constant are one string derived once.
pub fn resources(items: &[syn::Item], config_fields: &[String]) -> syn::Result<Vec<Resource>> {
    let mut structs = Vec::new();
    for item in items {
        let syn::Item::Struct(item) = item else {
            continue;
        };
        let Some(attr) = item.attrs.iter().find(|a| a.path().is_ident("resource")) else {
            continue;
        };
        let ResourceAttr {
            kind,
            display_digits,
            initial,
            grants,
        } = resource_attr(attr)?;
        // Fields are an instance's data, and a fungible resource has no
        // instances — so a fielded fungible declaration states a schema
        // nothing could ever hold.
        if kind == ResourceKind::Fungible && !item.fields.is_empty() {
            return Err(syn::Error::new(
                item.fields.span(),
                "a fungible resource has no instances, so these fields describe nothing \
                 — drop them, or declare the resource `non_fungible`",
            ));
        }
        // A mark carrying a schema mints its instances through a method
        // that takes the record: what one holds is runtime data, and an
        // attribute is not the place for it.
        if initial.is_some() && !item.fields.is_empty() {
            return Err(syn::Error::new(
                item.fields.span(),
                "a mark carrying a schema states no initial supply — what its instance \
                 holds is runtime data, so it is minted through a method that takes \
                 the record",
            ));
        }
        structs.push((
            &item.ident,
            kind,
            display_digits,
            initial,
            grants,
            !item.fields.is_empty(),
        ));
    }
    let rendered = declared_grants(&structs, config_fields)?;
    let marks = distinct_band("resources", structs.iter().map(|(ident, ..)| *ident))?;
    let declared: Vec<Resource> = structs
        .into_iter()
        .zip(marks)
        .zip(rendered)
        .map(
            |(((ident, kind, display_digits, initial, _, schema), mark), grants)| Resource {
                name: ident.to_string(),
                mark: mark.into_bytes(),
                kind,
                display_digits,
                initial,
                grants,
                schema,
            },
        )
        .collect();
    Ok(declared)
}

/// What a declaration registers before it declares anything: the rules
/// each of the package's own marks grants.
///
/// Emitted once per method rather than at each site naming a resource,
/// because the address folds these rules — so one registration is what
/// keeps a gate, a key and a mint from deriving three addresses. A
/// package that grants nothing emits nothing.
pub fn grant_registrations(resources: &[Resource]) -> TokenStream2 {
    let registered = resources
        .iter()
        .filter(|r| !r.grants.behaviours.is_empty())
        .map(|r| {
            let mark = syn::LitByteStr::new(&r.mark, Span::call_site());
            let grants = &r.grants.rendered;
            quote!(__t.grant(#mark, #grants);)
        });
    quote!(#(#registered)*)
}

/// The granted-rule grammar: a behaviour, and the rule its resource's
/// address commits for it.
///
/// The same combinators `#[requires(..)]` takes — `||`, `&&`,
/// `n_of(k, …)` — over a closed leaf set, because a granted rule is
/// folded into an address rather than judged against a cell. What a leaf
/// may name is what the address already knows: the issuing instance,
/// a badge that instance also issues, or a configuration field.
pub fn granted_rules(
    attr: &syn::MetaList,
    resources: &[Nameable<'_>],
    config_fields: &[String],
) -> syn::Result<Grants> {
    let entries = attr.parse_args_with(
        syn::punctuated::Punctuated::<syn::MetaNameValue, syn::Token![,]>::parse_terminated,
    )?;
    let mut granted = Vec::new();
    let mut behaviours: Vec<GrantedBehaviour> = Vec::new();
    // Whether any leaf names configuration, which is what decides
    // whether the address is derivable from the handle alone.
    let mut reads_config = false;
    for entry in &entries {
        let behaviour = granted_behaviour(&entry.path)?;
        if behaviours.contains(&behaviour) {
            return Err(syn::Error::new(
                entry.path.span(),
                format!(
                    "`{}` is granted twice, and a resource grants one rule for each \
                         behaviour",
                    entry.path.get_ident().expect("matched an ident")
                ),
            ));
        }
        behaviours.push(behaviour);
        let (rule, names_config) = granted_entry(&entry.value, resources, config_fields)?;
        reads_config |= names_config;
        let path = emit_behaviour(behaviour);
        granted.push(quote!(__seals.set(#path, #rule);));
    }
    let rendered = quote!({
        let mut __seals = ::hyperscale_vm_sdk::GrantsExpr::new();
        #(#granted)*
        __seals
    });
    Ok(Grants {
        rendered,
        reads_config,
        behaviours,
    })
}

/// The behaviour a `grants(<behaviour> = …)` key names.
pub fn granted_behaviour(path: &syn::Path) -> syn::Result<GrantedBehaviour> {
    let named = path.get_ident().map(ToString::to_string);
    GrantedBehaviour::ALL
        .into_iter()
        .find(|b| named.as_deref() == Some(b.word()))
        .ok_or_else(|| {
            let spellings: Vec<String> = GrantedBehaviour::ALL
                .iter()
                .map(|b| format!("`{}`", b.word()))
                .collect();
            let (last, rest) = spellings
                .split_last()
                .expect("the behaviours are not empty");
            syn::Error::new(
                path.span(),
                format!("a granted behaviour is {}, or {last}", rest.join(", ")),
            )
        })
}

/// What a `#[resource]`'s `grants(…)` states, in the three shapes its
/// readers need it in.
///
/// One value rather than three returns, because the rendering, the
/// derivability flag and the behaviour list are one reading of one
/// attribute — and a resource whose address folded rules the lowering
/// did not think it granted would be the drift this exists to close.
#[derive(Clone)]
pub struct Grants {
    /// The rules its address commits, as the expression that builds
    /// them.
    pub rendered: TokenStream2,
    /// Whether those rules name configuration, which decides whether the
    /// address is derivable from a handle alone.
    pub reads_config: bool,
    /// The behaviours it states a rule for. What the lowering holds an
    /// operation on the mark to: a resource grants what it says it
    /// grants, and nothing else.
    pub behaviours: Vec<GrantedBehaviour>,
}

impl Grants {
    /// A resource whose attribute states no rules at all.
    fn none() -> Self {
        Self {
            rendered: quote!(::hyperscale_vm_sdk::GrantsExpr::new()),
            reads_config: false,
            behaviours: Vec::new(),
        }
    }
}

/// Every declared mark's granted set, rendered against the whole set.
///
/// Two passes, because a grant leaf names another of the package's own
/// marks and carries the rules that mark's address folds. The first
/// builds each mark's rules with nothing nameable, which succeeds exactly
/// for the marks that name no badge — the ones a leaf may name, the chain
/// being one link long. The second builds every mark against that,
/// splicing in what a named badge grants.
///
/// Order-independent: a mark declared after the one naming it is nameable
/// on the same terms as one declared before.
pub fn declared_grants(
    structs: &[DeclaredResource<'_>],
    config_fields: &[String],
) -> syn::Result<Vec<Grants>> {
    let unnameable: Vec<Nameable<'_>> = structs
        .iter()
        .map(|(ident, kind, ..)| Nameable {
            ident,
            kind: *kind,
            rules: None,
        })
        .collect();
    let named: Vec<Nameable<'_>> = structs
        .iter()
        .map(|(ident, kind, _, _, grants, _)| {
            let rules = match grants {
                None => Some(Grants::none()),
                Some(list) if names_a_badge(list)? => None,
                Some(list) => Some(granted_rules(list, &unnameable, config_fields)?),
            };
            Ok(Nameable {
                ident,
                kind: *kind,
                rules,
            })
        })
        .collect::<syn::Result<_>>()?;
    structs
        .iter()
        .map(|(_, _, _, _, grants, _)| {
            grants.as_ref().map_or_else(
                || Ok(Grants::none()),
                |list| granted_rules(list, &named, config_fields),
            )
        })
        .collect()
}

/// One `#[resource]` struct as the collecting pass reads it, before the
/// marks are banded and the grants rendered.
pub type DeclaredResource<'a> = (
    &'a syn::Ident,
    ResourceKind,
    u8,
    Option<syn::LitInt>,
    Option<syn::MetaList>,
    bool,
);

/// One of the package's own marks, as a grant leaf naming it needs it.
///
/// The rules ride here because a badge's address is the hash of its own
/// rules, so a leaf naming a mark has to carry them — and they are
/// [`Option`] because a mark whose rules name a badge is not nameable:
/// the chain one address folds is one link long.
pub struct Nameable<'a> {
    pub ident: &'a syn::Ident,
    pub kind: ResourceKind,
    /// The mark's own grants, where the mark is nameable at all.
    pub rules: Option<Grants>,
}

/// Whether a granted set names a badge anywhere in it, which is what
/// decides whether the mark it belongs to may itself be named from one.
///
/// Syntactic, and deliberately so: it answers before any lowering, so a
/// mark that does name a badge is unnameable without its own rules having
/// to render first — which is what keeps a malformed mark's verdict its
/// own rather than something a mark naming it reports instead. Where it
/// and the lowering could disagree, the second link is refused again at
/// publish and again at resolution.
pub fn names_a_badge(attr: &syn::MetaList) -> syn::Result<bool> {
    fn walk(expr: &syn::Expr) -> bool {
        match expr {
            syn::Expr::Paren(inner) => walk(&inner.expr),
            syn::Expr::Binary(binary) => walk(&binary.left) || walk(&binary.right),
            syn::Expr::Call(call) => calls(&call.func, "issued") || call.args.iter().any(walk),
            _ => false,
        }
    }
    let entries = attr.parse_args_with(
        syn::punctuated::Punctuated::<syn::MetaNameValue, syn::Token![,]>::parse_terminated,
    )?;
    Ok(entries.iter().any(|entry| walk(&entry.value)))
}

pub fn granted_rule(
    expr: &syn::Expr,
    resources: &[Nameable<'_>],
    config_fields: &[String],
    depth: usize,
) -> syn::Result<(TokenStream2, bool)> {
    let rule = parse_rule(expr, "a granted rule", depth, &mut |leaf| {
        granted_claim(leaf, resources, config_fields)
    })?;
    Ok((emit_granted(&rule), reads_config(&rule)))
}

/// A granted rule, as the expression an address folds.
pub fn emit_granted(rule: &RuleAst<(TokenStream2, bool)>) -> TokenStream2 {
    match rule {
        RuleAst::Leaf((claim, _)) => quote!(::hyperscale_vm_sdk::GrantRuleExpr::Require(#claim)),
        RuleAst::CountOf { count, branches } => {
            let lowered = branches.iter().map(emit_granted);
            quote!(::hyperscale_vm_sdk::GrantRuleExpr::CountOf {
                count: #count,
                rules: ::std::vec![#(#lowered),*],
            })
        }
    }
}

/// Whether any leaf reads the instance's configuration — which decides
/// whether the address is derivable from a handle alone.
pub fn reads_config(rule: &RuleAst<(TokenStream2, bool)>) -> bool {
    match rule {
        RuleAst::Leaf((_, reads)) => *reads,
        RuleAst::CountOf { branches, .. } => branches.iter().any(reads_config),
    }
}

/// One granted entry as written: `anyone`, `nobody`, or a rule.
///
/// The two constants are the threshold over nothing, so they are rules
/// like any other and no evaluator meets a value it has to recognise as
/// meaning something else. There is no separate credential spelling
/// either: which side a leaf asks about is the behaviour's answer and
/// the subject's, never a word of its own. An authority entry asks what
/// a caller presented, whatever it names. A movement entry asks what its
/// subject makes answerable — a badge can be held, so naming one asks a
/// standing fact about the party whose cell moves; an identity cannot,
/// so naming one asks whether this transaction carried a claim on it.
pub fn granted_entry(
    expr: &syn::Expr,
    resources: &[Nameable<'_>],
    config_fields: &[String],
) -> syn::Result<(TokenStream2, bool)> {
    if let syn::Expr::Path(path) = expr {
        match path.path.get_ident().map(ToString::to_string).as_deref() {
            Some("anyone") => return Ok((quote!(::hyperscale_vm_sdk::grant_anyone()), false)),
            Some("nobody") => return Ok((quote!(::hyperscale_vm_sdk::grant_nobody()), false)),
            _ => {}
        }
    }
    if let syn::Expr::Call(call) = expr
        && calls(&call.func, "held")
    {
        return Err(syn::Error::new(
            call.span(),
            "a granted rule names what it names, and which side the leaf asks about follows \
             from the behaviour and from what is named: every behaviour but `withdraw` and \
             `deposit` asks what a caller presented, and those two ask whether the moving \
             party holds a badge, or — where an identity is named, which nothing holds — \
             whether a claim on it was presented",
        ));
    }
    granted_rule(expr, resources, config_fields, 0)
}

/// The `issued(<Resource>)` leaf: a badge the issuing instance also
/// issues, optionally narrowed to one instance of it.
///
/// Beside the leaf, whether it reads the instance's configuration, on the
/// terms [`granted_claim`] states.
pub fn granted_badge(
    call: &syn::ExprCall,
    resources: &[Nameable<'_>],
) -> syn::Result<(TokenStream2, bool)> {
    let mut args = call.args.iter();
    let named = match args.next() {
        Some(syn::Expr::Path(path)) => path.path.get_ident().map(ToString::to_string),
        _ => None,
    }
    .ok_or_else(|| {
        syn::Error::new(
            call.span(),
            "`issued(..)` names a `#[resource]` struct of this package",
        )
    })?;
    let Some(badge) = resources.iter().find(|badge| *badge.ident == named) else {
        return Err(syn::Error::new(
            call.span(),
            format!("`{named}` is not a `#[resource]` of this package"),
        ));
    };
    // A badge's address is the hash of its own rules, so the leaf
    // carries them. What it may not carry is a badge of its own:
    // the chain one address folds is one link long, so a mark
    // whose rules name a badge is not nameable from one.
    let Some(granted) = badge.rules.as_ref() else {
        return Err(syn::Error::new(
            call.span(),
            format!(
                "`{named}` names a badge in its own granted rules, and a badge \
                     chain is one link long — the address a leaf derives folds the \
                     rules of the badge it names, so a second link would make one \
                     address a function of how deeply its author nested"
            ),
        ));
    };
    let (rules, reads_config) = (&granted.rendered, granted.reads_config);
    let mark = syn::LitByteStr::new(kebab(&named).as_bytes(), badge.ident.span());
    let kind = match badge.kind {
        ResourceKind::Fungible => quote!(::hyperscale_vm_sdk::ResourceKind::Fungible),
        ResourceKind::NonFungible => {
            quote!(::hyperscale_vm_sdk::ResourceKind::NonFungible)
        }
    };
    match (badge.kind, args.next()) {
        // Naming a badge without an instance is naming any of it,
        // whichever kind it is — the reading `#[requires(..)]`
        // already gives the same words.
        (_, None) => Ok((
            quote!(::hyperscale_vm_sdk::GrantClaim::SelfBadge {
                mark: #mark.to_vec(),
                kind: #kind,
                rules: #rules,
            }),
            reads_config,
        )),
        (ResourceKind::NonFungible, Some(id)) => Ok((
            quote!(::hyperscale_vm_sdk::GrantClaim::SelfInstance {
                mark: #mark.to_vec(),
                id: #id,
                rules: #rules,
            }),
            reads_config,
        )),
        (ResourceKind::Fungible, Some(id)) => Err(syn::Error::new(
            id.span(),
            format!("`{named}` is fungible, and a balance has no instance to name"),
        )),
    }
}

/// One grant leaf, as the closed vocabulary spells it.
///
/// Beside the leaf, whether it reads the instance's configuration —
/// which decides whether the address is derivable from a handle alone.
/// Read off the leaf actually built rather than off a second walk of the
/// syntax, so a spelling the two would have disagreed about cannot exist.
pub fn granted_claim(
    expr: &syn::Expr,
    resources: &[Nameable<'_>],
    config_fields: &[String],
) -> syn::Result<(TokenStream2, bool)> {
    let refuse = |span| {
        syn::Error::new(
            span,
            "a grant claim is `self`, `config.<field>`, `issued(<Resource>)` for a \
             fungible badge, or `issued(<Resource>, <id>)` for one instance of a \
             non-fungible one — a derivation the address already knows, never anything \
             a caller supplies",
        )
    };
    match expr {
        // The issuing instance, acting as itself.
        syn::Expr::Path(path) if path.path.is_ident("self") => {
            Ok((quote!(::hyperscale_vm_sdk::GrantClaim::SelfAddr), false))
        }
        // A bare name is not a leaf; the shared diagnosis says which
        // spelling the author meant.
        syn::Expr::Path(path) => {
            let name = path
                .path
                .get_ident()
                .map(ToString::to_string)
                .ok_or_else(|| refuse(path.span()))?;
            Err(diagnose_bare_name(
                path.span(),
                &name,
                resources.iter().map(|badge| badge.ident.to_string()),
                config_fields.iter().map(String::as_str),
            )
            .unwrap_or_else(|| refuse(path.span())))
        }
        // A configuration field, whose address class says which claim.
        syn::Expr::Field(access) => {
            let Some(slot) = config_slot(access, config_fields.iter().map(String::as_str)) else {
                return Err(refuse(access.span()));
            };
            let slot = slot?;
            Ok((quote!(::hyperscale_vm_sdk::GrantClaim::Config(#slot)), true))
        }
        // A badge the issuing instance also issues.
        syn::Expr::Call(call) if calls(&call.func, "issued") => granted_badge(call, resources),
        other => Err(refuse(other.span())),
    }
}

/// One `#[resource]` declaration, as everything downstream reads it.
#[derive(Clone)]
pub struct Resource {
    /// The struct's own name, which is what a body and a gate call it.
    pub name: String,
    /// The material separating it from the package's other resources.
    pub mark: Vec<u8>,
    /// The kind its attribute states.
    pub kind: ResourceKind,
    /// The display quantization its record carries. Meaningless on a
    /// non-fungible mark, where it is never read.
    pub display_digits: u8,
    /// The supply the component comes up holding, where its attribute
    /// states one: a quantity for a fungible mark, an instance id for a
    /// non-fungible one — the same split the mint itself takes.
    pub initial: Option<syn::LitInt>,
    /// What its attribute grants. Rendered once here because three sites
    /// emit it — a gate naming the resource, a term over it, and the
    /// grant that mints it — and an address they disagreed about would
    /// be three resources.
    pub grants: Grants,
    /// Whether the struct has fields, which is what makes it an
    /// instance's data schema and not only a bare mark.
    pub schema: bool,
}

/// The display quantization a fungible resource carries where its
/// attribute states none.
///
/// The width the protocol's own fee resource is recorded at, so a
/// package that says nothing is recorded like the one resource every
/// network already holds. Nothing on-chain consults it — a display width
/// is what a client renders with — which is why a default is a default
/// and not a guess with consequences.
pub const DEFAULT_DISPLAY_DIGITS: u8 = 18;

/// What a `#[resource]` attribute states about the resource beside its
/// name.
///
/// Stated in the source because the derivation and the record both fold
/// it: the mark constant a gate evaluates and the address a host derives
/// need the kind, and the record `instantiate` writes needs the display
/// width. The attribute is the one place all three read from.
pub struct ResourceAttr {
    pub kind: ResourceKind,
    pub display_digits: u8,
    pub initial: Option<syn::LitInt>,
    pub grants: Option<syn::MetaList>,
}

pub fn resource_attr(attr: &syn::Attribute) -> syn::Result<ResourceAttr> {
    let mut kind = None;
    let mut display_digits = None;
    let mut initial = None;
    let mut grants = None;
    if matches!(attr.meta, syn::Meta::List(_)) {
        let terms = attr.parse_args_with(
            syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
        )?;
        for term in &terms {
            match term {
                syn::Meta::Path(path) => {
                    let stated = match path.get_ident().map(ToString::to_string).as_deref() {
                        Some("fungible") => ResourceKind::Fungible,
                        Some("non_fungible") => ResourceKind::NonFungible,
                        _ => return Err(unknown_resource_term(path)),
                    };
                    if kind.replace(stated).is_some() {
                        return Err(syn::Error::new(
                            path.span(),
                            "a resource is one kind — the derivation folds it, so two \
                             spellings would be two addresses",
                        ));
                    }
                }
                syn::Meta::List(list) if list.path.is_ident("grants") => {
                    if grants.replace(list.clone()).is_some() {
                        return Err(syn::Error::new(list.path.span(), "grants, twice"));
                    }
                }
                syn::Meta::List(list) if list.path.is_ident("initial") => {
                    if initial.replace(list.parse_args::<syn::LitInt>()?).is_some() {
                        return Err(syn::Error::new(list.path.span(), "initial, twice"));
                    }
                }
                syn::Meta::NameValue(nv) if nv.path.is_ident("display_digits") => {
                    let syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Int(int),
                        ..
                    }) = &nv.value
                    else {
                        return Err(syn::Error::new(
                            nv.value.span(),
                            "a display width is a literal count of subunit digits",
                        ));
                    };
                    if display_digits.replace(int.base10_parse::<u8>()?).is_some() {
                        return Err(syn::Error::new(nv.path.span(), "display_digits, twice"));
                    }
                }
                other => return Err(unknown_resource_term(other)),
            }
        }
    }
    let kind = kind.unwrap_or(ResourceKind::Fungible);
    // Instances are whole by construction, so there is no quantity for a
    // quantization to be about.
    if kind == ResourceKind::NonFungible && display_digits.is_some() {
        return Err(syn::Error::new(
            attr.span(),
            "a non-fungible resource has no display width — its instances are whole, \
             and what a client renders is an id",
        ));
    }
    Ok(ResourceAttr {
        kind,
        display_digits: display_digits.unwrap_or(DEFAULT_DISPLAY_DIGITS),
        initial,
        grants,
    })
}

pub fn unknown_resource_term(at: &impl Spanned) -> syn::Error {
    syn::Error::new(
        at.span(),
        "a resource states `fungible` (the default) or `non_fungible`, the supply \
         its component comes up holding as `initial(<n>)`, the behaviours its \
         address grants as `grants(<behaviour> = <rule>, …)`, and — where it is \
         fungible — `display_digits = <digits>`",
    )
}

/// The constant naming each declared resource's mark.
///
/// Emitted rather than asked for, and read by everything outside the
/// package that has to derive the same address — so the mark a gate
/// evaluates and the mark a host names are one declaration rather than
/// two that agree by inspection.
pub fn resource_marks(declared: &[Resource], role: Role) -> Vec<syn::Item> {
    declared
        .iter()
        .flat_map(
            |Resource {
                 name,
                 mark,
                 kind,
                 schema,
                 ..
             }| {
                let ident = syn::Ident::new(&screaming(name), Span::call_site());
                let bytes = syn::LitByteStr::new(mark, Span::call_site());
                let doc =
                    format!("The mark separating `{name}` from this package's other resources.");
                let mark_const: syn::Item = syn::parse_quote!(
                    #[doc = #doc]
                    pub const #ident: &[u8] = #bytes;
                );
                let struct_ident = syn::Ident::new(name, Span::call_site());
                [
                    mark_const,
                    issuance(name, *kind, *schema, &struct_ident, role),
                ]
            },
        )
        .collect()
}

/// The issuance surface a mark carries: what bringing this resource into
/// existence, and taking it back out, is spelled as.
///
/// One word for both kinds, because the declaration already states which
/// one it is, and the shape the word takes is the shape that declaration
/// implies — a quantity for a fungible mark, an instance id for a
/// non-fungible one. Emitted per mark rather than offered as one generic
/// function, which is what makes the wrong shape a type error on the
/// argument rather than a refusal the macro has to phrase.
///
/// One instance per call, because one call is one declared cell — which
/// is what the lowering opens either way. Several at once is the edge
/// merge `NfBucket::put` already performs, so the batch the surface does
/// not offer costs a line rather than a vocabulary.
///
/// Bodies are the off-host stubs every contract surface has, and they sit
/// where the author's own `impl` block sits: off the guest. Every call is
/// rewritten by the lowering before either half of the emission sees one,
/// so what a guest build would compile here is an unreachable panic and
/// whatever that drags in.
pub fn issuance(
    name: &str,
    kind: ResourceKind,
    schema: bool,
    mark: &syn::Ident,
    role: Role,
) -> syn::Item {
    let stub = quote!(::core::unimplemented!("a contract body runs on the guest"));
    let mut methods = vec![
        record_creation(name, kind, &stub),
        resource_address(name, &stub),
    ];
    methods.extend(match kind {
        ResourceKind::Fungible => value_surface(name, &stub),
        ResourceKind::NonFungible => instance_surface(name, schema, &stub),
    });
    methods.extend(reach_surface(name, kind, &stub));
    let reading = role.reading();
    syn::parse_quote!(
        #reading
        impl #mark {
            #(#methods)*
        }
    )
}

/// Bringing the resource itself into existence.
///
/// The record states only what the address cannot carry, which for a
/// fungible resource is its display quantization and for a non-fungible
/// one is nothing at all.
pub fn resource_address(name: &str, stub: &TokenStream2) -> syn::ImplItemFn {
    let doc = format!(
        "The address `{name}` sits at: this instance's own, over the mark and the rules the \
         declaration grants."
    );
    syn::parse_quote!(
        #[doc = #doc]
        #[must_use]
        pub fn address() -> ::hyperscale_vm_sdk::ResourceAddr {
            #stub
        }
    )
}

pub fn record_creation(name: &str, kind: ResourceKind, stub: &TokenStream2) -> syn::ImplItemFn {
    let doc = format!("Bring `{name}` itself into existence, by writing its record.");
    match kind {
        ResourceKind::Fungible => syn::parse_quote!(
            #[doc = #doc]
            pub fn create(display_digits: u8) {
                let _ = display_digits;
                #stub
            }
        ),
        ResourceKind::NonFungible => syn::parse_quote!(
            #[doc = #doc]
            pub fn create() {
                #stub
            }
        ),
    }
}

/// The issuer's own side: reaching a holder's prefix under an entry the
/// resource itself grants.
///
/// On the mark for the reason every other operation is. What a reach
/// takes out of a holder's cell is a balance or named instances, and
/// which is the *declaration's* answer — so the mark chooses the
/// lowering and the edge type, and a body asking for the wrong shape
/// meets its own argument's type rather than a refusal the macro has to
/// phrase. The free `recall`/`recall_instances` beside these stay for
/// the resource a package does not issue, where there is no mark to ask.
///
/// `halt` and `unhalt` take no shape from the kind — a halt flag is one
/// leaf whatever the resource is — but they sit here anyway, because an
/// author naming the resource twice at one call site is a call site with
/// two chances to name a different one.
pub fn reach_surface(name: &str, kind: ResourceKind, stub: &TokenStream2) -> Vec<syn::ImplItemFn> {
    let halt_doc = format!("Stop `holder` moving `{name}`, wherever they hold it.");
    let unhalt_doc = format!("Let `holder` move `{name}` again, by ending the flag.");
    let recall_doc =
        format!("Take `{name}` out of the cell `holder` keeps it in at `slot`, as an edge.");
    let recall: syn::ImplItemFn = match kind {
        ResourceKind::Fungible => syn::parse_quote!(
            #[doc = #recall_doc]
            #[must_use]
            pub fn recall(
                holder: ::hyperscale_vm_sdk::Address,
                slot: u64,
                quantity: ::hyperscale_vm_sdk::state::Quantity,
            ) -> ::hyperscale_vm_sdk::state::Bucket {
                let _ = (holder, slot, quantity);
                #stub
            }
        ),
        ResourceKind::NonFungible => syn::parse_quote!(
            #[doc = #recall_doc]
            #[must_use]
            pub fn recall(
                holder: ::hyperscale_vm_sdk::Address,
                slot: u64,
                ids: ::hyperscale_vm_sdk::state::Ids,
            ) -> ::hyperscale_vm_sdk::state::NfBucket {
                let _ = (holder, slot, &ids);
                #stub
            }
        ),
    };
    vec![
        syn::parse_quote!(
            #[doc = #halt_doc]
            pub fn halt(holder: ::hyperscale_vm_sdk::Address) {
                let _ = holder;
                #stub
            }
        ),
        syn::parse_quote!(
            #[doc = #unhalt_doc]
            pub fn unhalt(holder: ::hyperscale_vm_sdk::Address) {
                let _ = holder;
                #stub
            }
        ),
        recall,
    ]
}

/// A fungible mark's surface: value in, and value out under the same
/// authority.
pub fn value_surface(name: &str, stub: &TokenStream2) -> Vec<syn::ImplItemFn> {
    let mint_doc = format!("Bring `{name}` into existence, as an edge.");
    let burn_doc = format!("Destroy `{name}`, which is `funds`' own resource.");
    vec![
        syn::parse_quote!(
            #[doc = #mint_doc]
            #[must_use]
            pub fn mint(
                quantity: ::hyperscale_vm_sdk::state::Quantity,
            ) -> ::hyperscale_vm_sdk::state::Bucket {
                let _ = quantity;
                #stub
            }
        ),
        syn::parse_quote!(
            #[doc = #burn_doc]
            pub fn burn(funds: ::hyperscale_vm_sdk::state::Bucket) {
                let _ = &funds;
                #stub
            }
        ),
    ]
}

/// A non-fungible mark's surface: an instance's whole life, and the
/// record it carries where it carries one.
///
/// A fielded mark's instance holds a record, so the mint takes one and
/// the mark reads, refiles and answers with it. A bare mark's cell holds
/// the presence byte, which is nothing to hand over and nothing to read
/// back — so a bare mark has the two ends and nothing between them.
pub fn instance_surface(name: &str, schema: bool, stub: &TokenStream2) -> Vec<syn::ImplItemFn> {
    let burn_doc =
        format!("Retire the one `{name}` instance `edge` carries, and the record it filed.");
    let burn: syn::ImplItemFn = syn::parse_quote!(
        #[doc = #burn_doc]
        pub fn burn(edge: ::hyperscale_vm_sdk::state::NfBucket) {
            let _ = &edge;
            #stub
        }
    );
    let mint_doc = format!("Bring `{name}` into existence, as an edge.");
    if !schema {
        return vec![
            syn::parse_quote!(
                #[doc = #mint_doc]
                #[must_use]
                pub fn mint(id: u64) -> ::hyperscale_vm_sdk::state::NfBucket {
                    let _ = id;
                    #stub
                }
            ),
            burn,
        ];
    }
    let at_doc = format!("The record filed for `{name}` instance `id`, where one was minted.");
    let held_doc = format!("The record filed for the one `{name}` instance `edge` carries.");
    let rewrite_doc = format!("Refile the record `{name}` instance `id` carries.");
    let each_doc =
        format!("The records filed for every `{name}` instance `edge` carries, in id order.");
    vec![
        syn::parse_quote!(
            #[doc = #mint_doc]
            #[must_use]
            pub fn mint(id: u64, data: Self) -> ::hyperscale_vm_sdk::state::NfBucket {
                let _ = (id, data);
                #stub
            }
        ),
        burn,
        syn::parse_quote!(
            #[doc = #at_doc]
            #[must_use]
            pub fn at(id: u64) -> ::core::option::Option<Self> {
                let _ = id;
                #stub
            }
        ),
        syn::parse_quote!(
            #[doc = #rewrite_doc]
            pub fn rewrite(id: u64, record: Self) {
                let _ = (id, record);
                #stub
            }
        ),
        syn::parse_quote!(
            #[doc = #held_doc]
            #[must_use]
            pub fn held(
                edge: &::hyperscale_vm_sdk::state::NfBucket,
            ) -> ::core::option::Option<Self> {
                let _ = edge;
                #stub
            }
        ),
        syn::parse_quote!(
            #[doc = #each_doc]
            #[must_use]
            pub fn each(
                edge: &::hyperscale_vm_sdk::state::NfBucket,
            ) -> ::std::vec::Vec<Self> {
                let _ = edge;
                #stub
            }
        ),
    ]
}

/// A Rust type name as the constant naming it: `OwnerBadge` is
/// `OWNER_BADGE`.
pub fn screaming(name: &str) -> String {
    kebab(name).replace('-', "_").to_uppercase()
}
